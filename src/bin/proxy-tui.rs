//! Proxy TUI - Terminal UI for monitoring proxy metrics.
//!
//! # UI Layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  [Nodes]  [Realtime]  [Connections]  [Top-N]    <- Tabs     │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │                    Tab Content Area                         │
//! │                                                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  q:quit  ←→:tabs  ↑↓:select  Enter:switch  a:add  <- Status │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Keyboard Controls
//!
//! - `q` / `Esc`: Quit
//! - `Tab` / `→`: Next tab
//! - `Shift+Tab` / `←`: Previous tab
//! - `↑` / `↓`: Select node (in Nodes tab)
//! - `Enter`: Switch to selected node (in Nodes tab)
//! - `a`: Add node (in Nodes tab)
//! - `d`: Delete selected node (in Nodes tab)
//! - `Esc`: Cancel server switch (during switching)

use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, enable_raw_mode},
};
use http_proxy::config::{CONTROL_SESSION_KEY, DEFAULT_SECRET_KEY};
use http_proxy::tui::{
    AppState, Cli, DataCommand, DataResult, TAB_COUNT,
    data_fetcher_task, draw_ui, handle_add_dialog_input, TerminalGuard,
};
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    // Set USE_LOCAL_GEOIP env var if flag is set
    if cli.use_local_geoip {
        unsafe { std::env::set_var("USE_LOCAL_GEOIP", "true") };
    }

    let session_key = cli
        .session_key
        .clone()
        .or_else(|| (*CONTROL_SESSION_KEY).clone())
        .or_else(|| std::env::var("SECRET_KEY").ok())
        .or_else(|| Some(DEFAULT_SECRET_KEY.to_string()));

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut state = AppState::new(&cli.server_host, cli.server_port);

    // Channels for async communication
    let (cmd_tx, cmd_rx) = mpsc::channel::<DataCommand>(16);
    let (data_tx, mut data_rx) = mpsc::channel::<Result<DataResult, String>>(4);

    // Spawn data fetcher task
    let cli_arc = Arc::new(cli);
    let cli_clone = cli_arc.clone();
    let fetcher_handle = tokio::spawn(async move {
        data_fetcher_task(cli_clone, session_key, cmd_rx, data_tx).await;
    });

    // Trigger initial fetch
    let _ = cmd_tx.send(DataCommand::Refresh).await;

    // Auto-refresh timer
    let refresh_interval = Duration::from_secs(cli_arc.refresh);
    let mut last_refresh = std::time::Instant::now();

    loop {
        state.anim_frame = state.anim_frame.wrapping_add(1);

        // Check for new data
        while let Ok(result) = data_rx.try_recv() {
            match result {
                Ok(DataResult::Data(data, server_addr)) => {
                    // Trigger geo query for new IPs
                    let uncached_ips: Vec<String> = data
                        .nodes
                        .iter()
                        .filter_map(|n| {
                            let ip = n.addr.split(':').next()?;
                            if state.geo_cache.contains_key(ip) {
                                None
                            } else {
                                Some(ip.to_string())
                            }
                        })
                        .collect();
                    if !uncached_ips.is_empty() {
                        let _ = cmd_tx.send(DataCommand::QueryGeo(uncached_ips)).await;
                    }

                    if let Some(addr) = server_addr {
                        if state.switching && state.switch_target.as_ref() == Some(&addr) {
                            state.current_server = addr;
                            state.data = Some(data);
                            state.switching = false;
                            state.switch_target = None;
                            state.selected_node = 0;
                        }
                    } else {
                        state.data = Some(data);
                    }
                    state.loading = false;
                    state.error = None;
                }
                Ok(DataResult::Geo(geo_map)) => {
                    state.geo_cache.extend(geo_map);
                    state.geo_error = None;
                }
                Ok(DataResult::GeoError(msg)) => {
                    state.geo_error = Some(msg);
                }
                Err(e) => {
                    state.loading = false;
                    state.switching = false;
                    state.switch_target = None;
                    state.error = Some(e);
                }
            }
        }

        // Draw UI
        terminal.draw(|f| draw_ui(f, &mut state))?;

        // Handle input
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if state.show_add_dialog {
                        handle_add_dialog_input(&mut state, key.code, &cmd_tx).await;
                    } else if state.switching {
                        if key.code == KeyCode::Esc {
                            state.switching = false;
                            state.switch_target = None;
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                let _ = cmd_tx.send(DataCommand::Shutdown).await;
                                break;
                            }
                            KeyCode::Tab | KeyCode::Right => {
                                state.tab_index = (state.tab_index + 1) % TAB_COUNT;
                            }
                            KeyCode::BackTab | KeyCode::Left => {
                                state.tab_index = (state.tab_index + TAB_COUNT - 1) % TAB_COUNT;
                            }
                            KeyCode::Up => {
                                if state.selected_node > 0 {
                                    state.selected_node -= 1;
                                }
                            }
                            KeyCode::Down => {
                                if let Some(data) = &state.data {
                                    if state.selected_node + 1 < data.nodes.len() {
                                        state.selected_node += 1;
                                    }
                                }
                            }
                            KeyCode::Char('a') if state.tab_index == 0 => {
                                state.show_add_dialog = true;
                                state.add_node_input.clear();
                                state.add_node_error = None;
                            }
                            KeyCode::Char('d') if state.tab_index == 0 => {
                                if let Some(data) = &state.data {
                                    if let Some(node) = data.nodes.get(state.selected_node) {
                                        let _ = cmd_tx
                                            .send(DataCommand::RemoveNode(node.node_id.clone()))
                                            .await;
                                        state.loading = true;
                                    }
                                }
                            }
                            KeyCode::Enter if state.tab_index == 0 => {
                                if let Some(data) = &state.data {
                                    if let Some(node) = data.nodes.get(state.selected_node) {
                                        let addr = node.addr.clone();
                                        let _ = cmd_tx
                                            .send(DataCommand::SwitchServer(addr.clone()))
                                            .await;
                                        state.switching = true;
                                        state.switch_target = Some(addr);
                                    }
                                }
                            }
                            KeyCode::Char('r') => {
                                let _ = cmd_tx.send(DataCommand::Refresh).await;
                                state.loading = true;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Auto-refresh
        if last_refresh.elapsed() >= refresh_interval && !state.loading && !state.switching {
            let _ = cmd_tx.send(DataCommand::Refresh).await;
            state.loading = true;
            last_refresh = std::time::Instant::now();
        }
    }

    fetcher_handle.abort();
    Ok(())
}
