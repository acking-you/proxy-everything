//! Proxy TUI - Terminal UI for monitoring proxy metrics.

use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
use proxy_core::config::{CONTROL_SESSION_KEY, DEFAULT_SECRET_KEY};
use proxy_tui::tui::{
    AppState, Cli, DataCommand, DataResult, InputDialogMode, TAB_COUNT, TerminalGuard,
    data_fetcher_task, draw_ui, handle_input_dialog_input,
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
    if cmd_tx.send(DataCommand::Refresh).await.is_err() {
        state.error = Some("Data fetcher task died".to_string());
    }

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
                    if !uncached_ips.is_empty()
                        && cmd_tx
                            .send(DataCommand::QueryGeo(uncached_ips))
                            .await
                            .is_err()
                    {
                        state.error = Some("Failed to send geo query command".to_string());
                    }

                    if let Some(addr) = server_addr {
                        if state.switching && state.switch_target.as_ref() == Some(&addr) {
                            state.current_server = addr;
                            state.data = Some(data);
                            state.switching = false;
                            state.switch_target = None;
                            state.selected_node = 0;
                            state.selected_group = 0;
                            state.selected_relay_target = 0;
                        } else if !state.switching {
                            // Normal refresh: update data without changing current_server
                            state.data = Some(data);
                        }
                    } else {
                        state.data = Some(data);
                    }
                    if let Some(ref data) = state.data {
                        if state.selected_node >= data.nodes.len() {
                            state.selected_node = data.nodes.len().saturating_sub(1);
                        }
                        if state.selected_group >= data.groups.len() {
                            state.selected_group = data.groups.len().saturating_sub(1);
                        }
                        let relay_len = data
                            .relay_status
                            .as_ref()
                            .map(|s| s.targets.len())
                            .or_else(|| data.relay_config.as_ref().map(|c| c.targets.len()))
                            .unwrap_or(0);
                        if state.selected_relay_target >= relay_len {
                            state.selected_relay_target = relay_len.saturating_sub(1);
                        }
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
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if state.show_input_dialog {
                handle_input_dialog_input(&mut state, key.code, &cmd_tx).await;
            } else if state.show_filter {
                match key.code {
                    KeyCode::Esc => {
                        state.show_filter = false;
                    }
                    KeyCode::Enter => {
                        state.show_filter = false;
                        state.page_offset = 0;
                    }
                    KeyCode::Backspace => {
                        state.filter_input.pop();
                    }
                    KeyCode::Char(c) => {
                        state.filter_input.push(c);
                    }
                    _ => {}
                }
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
                        state.page_offset = 0;
                    }
                    KeyCode::BackTab | KeyCode::Left => {
                        state.tab_index = (state.tab_index + TAB_COUNT - 1) % TAB_COUNT;
                        state.page_offset = 0;
                    }
                    KeyCode::Up => match state.tab_index {
                        0 => {
                            if state.selected_node > 0 {
                                state.selected_node -= 1;
                            }
                        }
                        1 => {
                            if state.selected_group > 0 {
                                state.selected_group -= 1;
                            }
                        }
                        2 => {
                            if state.selected_relay_target > 0 {
                                state.selected_relay_target -= 1;
                            }
                        }
                        _ => {}
                    },
                    KeyCode::Down => {
                        if let Some(data) = &state.data {
                            match state.tab_index {
                                0 => {
                                    if state.selected_node + 1 < data.nodes.len() {
                                        state.selected_node += 1;
                                    }
                                }
                                1 => {
                                    if state.selected_group + 1 < data.groups.len() {
                                        state.selected_group += 1;
                                    }
                                }
                                2 => {
                                    if let Some(status) = &data.relay_status {
                                        if state.selected_relay_target + 1 < status.targets.len() {
                                            state.selected_relay_target += 1;
                                        }
                                    } else if let Some(config) = &data.relay_config
                                        && state.selected_relay_target + 1 < config.targets.len()
                                    {
                                        state.selected_relay_target += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    KeyCode::Char('a') if state.tab_index == 0 => {
                        state.show_input_dialog = true;
                        state.input_mode = Some(InputDialogMode::AddNode);
                        state.input_value.clear();
                        state.input_error = None;
                    }
                    KeyCode::Char('a') if state.tab_index == 1 => {
                        state.show_input_dialog = true;
                        state.input_mode = Some(InputDialogMode::CreateGroup);
                        state.input_value.clear();
                        state.input_error = None;
                    }
                    KeyCode::Char('a') if state.tab_index == 2 => {
                        state.show_input_dialog = true;
                        state.input_mode = Some(InputDialogMode::AddRelayTarget);
                        state.input_value.clear();
                        state.input_error = None;
                    }
                    KeyCode::Char('d') if state.tab_index == 0 => {
                        if let Some(data) = &state.data
                            && let Some(node) = data.nodes.get(state.selected_node)
                        {
                            // Prevent removing the self node to avoid confusing behavior.
                            let is_self = node.addr == state.current_server
                                || data
                                    .nodes
                                    .iter()
                                    .filter(|n| n.node_id == node.node_id)
                                    .count()
                                    > 1;
                            if is_self {
                                state.error = Some(
                                    "Cannot remove self node (use NODE_ADVERTISE_ADDR to change)"
                                        .to_string(),
                                );
                            } else if cmd_tx
                                .send(DataCommand::RemoveNode(node.node_id.clone()))
                                .await
                                .is_err()
                            {
                                state.error =
                                    Some("Failed to send remove node command".to_string());
                            } else {
                                state.loading = true;
                            }
                        }
                    }
                    KeyCode::Char('d') if state.tab_index == 1 => {
                        if let Some(data) = &state.data
                            && let Some(group) = data.groups.get(state.selected_group)
                        {
                            if cmd_tx
                                .send(DataCommand::DeleteGroup(group.group_id.clone()))
                                .await
                                .is_err()
                            {
                                state.error =
                                    Some("Failed to send delete group command".to_string());
                            } else {
                                state.loading = true;
                            }
                        }
                    }
                    KeyCode::Char('d') if state.tab_index == 2 => {
                        if cmd_tx
                            .send(DataCommand::RemoveRelayTarget(state.selected_relay_target))
                            .await
                            .is_err()
                        {
                            state.error =
                                Some("Failed to send remove relay target command".to_string());
                        } else {
                            state.loading = true;
                        }
                    }
                    KeyCode::Char('g') if state.tab_index == 1 => {
                        if let Some(data) = &state.data
                            && let Some(group) = data.groups.get(state.selected_group)
                        {
                            state.show_input_dialog = true;
                            state.input_mode = Some(InputDialogMode::AddNodeToGroup {
                                group_id: group.group_id.clone(),
                            });
                            state.input_value.clear();
                            state.input_error = None;
                        }
                    }
                    KeyCode::Char('x') if state.tab_index == 1 => {
                        if let Some(data) = &state.data
                            && let Some(group) = data.groups.get(state.selected_group)
                        {
                            state.show_input_dialog = true;
                            state.input_mode = Some(InputDialogMode::RemoveNodeFromGroup {
                                group_id: group.group_id.clone(),
                            });
                            state.input_value.clear();
                            state.input_error = None;
                        }
                    }
                    KeyCode::Char('e') if state.tab_index == 2 => {
                        if let Some(data) = &state.data {
                            let enabled = data
                                .relay_config
                                .as_ref()
                                .map(|c| c.enabled)
                                .or_else(|| data.relay_status.as_ref().map(|s| s.enabled))
                                .unwrap_or(false);
                            if cmd_tx
                                .send(DataCommand::SetRelayEnabled(!enabled))
                                .await
                                .is_err()
                            {
                                state.error =
                                    Some("Failed to send relay enable command".to_string());
                            } else {
                                state.loading = true;
                            }
                        }
                    }
                    KeyCode::Char('l') if state.tab_index == 2 => {
                        if let Some(data) = &state.data {
                            let algo = data
                                .relay_config
                                .as_ref()
                                .map(|c| c.algo)
                                .or_else(|| data.relay_status.as_ref().map(|s| s.algo))
                                .unwrap_or(proxy_core::relay::LoadBalanceAlgo::RoundRobin);
                            let next = match algo {
                                proxy_core::relay::LoadBalanceAlgo::RoundRobin => {
                                    proxy_core::relay::LoadBalanceAlgo::Random
                                }
                                proxy_core::relay::LoadBalanceAlgo::Random => {
                                    proxy_core::relay::LoadBalanceAlgo::Weighted
                                }
                                proxy_core::relay::LoadBalanceAlgo::Weighted => {
                                    proxy_core::relay::LoadBalanceAlgo::LeastConn
                                }
                                proxy_core::relay::LoadBalanceAlgo::LeastConn => {
                                    proxy_core::relay::LoadBalanceAlgo::RoundRobin
                                }
                            };
                            if cmd_tx.send(DataCommand::SetRelayAlgo(next)).await.is_err() {
                                state.error = Some("Failed to send relay algo command".to_string());
                            } else {
                                state.loading = true;
                            }
                        }
                    }
                    KeyCode::Char('c') if state.tab_index == 2 => {
                        state.show_input_dialog = true;
                        state.input_mode = Some(InputDialogMode::SetRelayConfig);
                        state.input_value.clear();
                        state.input_error = None;
                    }
                    KeyCode::Enter if state.tab_index == 0 => {
                        if let Some(data) = &state.data
                            && let Some(node) = data.nodes.get(state.selected_node)
                        {
                            let addr = node.addr.clone();
                            if cmd_tx
                                .send(DataCommand::SwitchServer(addr.clone()))
                                .await
                                .is_err()
                            {
                                state.error =
                                    Some("Failed to send switch server command".to_string());
                            } else {
                                state.switching = true;
                                state.switch_target = Some(addr);
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        if cmd_tx.send(DataCommand::Refresh).await.is_err() {
                            state.error = Some("Failed to send refresh command".to_string());
                        } else {
                            state.loading = true;
                        }
                    }
                    KeyCode::Char('/') if state.tab_index == 4 || state.tab_index == 5 => {
                        state.show_filter = true;
                    }
                    KeyCode::PageUp if state.tab_index == 4 || state.tab_index == 5 => {
                        state.page_offset = state.page_offset.saturating_sub(state.page_size);
                    }
                    KeyCode::PageDown if state.tab_index == 4 || state.tab_index == 5 => {
                        state.page_offset += state.page_size;
                    }
                    _ => {}
                }
            }
        }

        // Auto-refresh
        if last_refresh.elapsed() >= refresh_interval && !state.loading && !state.switching {
            if cmd_tx.send(DataCommand::Refresh).await.is_err() {
                state.error = Some("Failed to send auto-refresh command".to_string());
            } else {
                state.loading = true;
                last_refresh = std::time::Instant::now();
            }
        }
    }

    fetcher_handle.abort();
    Ok(())
}
