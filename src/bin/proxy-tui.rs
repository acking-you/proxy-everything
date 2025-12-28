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
//! │  Nodes Tab:       List of cluster nodes                     │
//! │  Realtime Tab:    CPU, Memory, Active connections           │
//! │  Connections Tab: Recent connection records                 │
//! │  Top-N Tab:       Top hosts and IPs by traffic              │
//! │                                                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  q:quit  ←→:tabs  ↑↓:select  a:add node         <- Status   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Keyboard Controls
//!
//! - `q` / `Esc`: Quit
//! - `Tab` / `→`: Next tab
//! - `Shift+Tab` / `←`: Previous tab
//! - `↑` / `↓`: Select node (in Nodes tab)
//! - `a`: Add node (in Nodes tab)
//! - `d`: Delete selected node (in Nodes tab)

use std::io::{self, stdout};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use http_proxy::config::{CONTROL_SESSION_KEY, DEFAULT_SECRET_KEY, SERVER_PORT};
use http_proxy::control::ControlClient;
use http_proxy::metrics::{
    ConnectionRecord, Granularity, RealtimeSnapshot, TimeBucket, TopCategory,
};
use http_proxy::nodes::NodeInfo;
use ratatui::{
    Frame,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Tabs},
};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(author, version, about = "Proxy TUI - Terminal UI for monitoring")]
struct Cli {
    /// Proxy server host
    #[arg(short = 'H', long)]
    server_host: String,
    /// Proxy server port
    #[arg(short, long, default_value_t = *SERVER_PORT)]
    server_port: u16,
    /// Admin token
    #[arg(short, long)]
    token: Option<String>,
    /// Session key (defaults to same as server/client)
    #[arg(short = 'k', long)]
    session_key: Option<String>,
    /// Refresh interval in seconds
    #[arg(short, long, default_value = "2")]
    refresh: u64,
}

const TAB_COUNT: usize = 4;
const TAB_TITLES: [&str; TAB_COUNT] = ["Nodes", "Realtime", "Connections", "Top-N"];

/// Data fetched from server
#[derive(Default, Clone)]
struct FetchedData {
    nodes: Vec<NodeInfo>,
    realtime: Option<RealtimeSnapshot>,
    connections: Vec<ConnectionRecord>,
    buckets: Vec<TimeBucket>,
    top_hosts: Vec<(String, u64)>,
    top_ips: Vec<(String, u64)>,
}

/// UI state
#[derive(Default)]
struct AppState {
    tab_index: usize,
    selected_node: usize,
    data: Option<FetchedData>,
    loading: bool,
    error: Option<String>,
    // Add node dialog
    show_add_dialog: bool,
    add_node_input: String,
    add_node_error: Option<String>,
}

/// Commands from UI to data fetcher
enum DataCommand {
    Refresh,
    AddNode(String),
    RemoveNode(String),
    Shutdown,
}

/// RAII guard to restore terminal state on drop.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
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

    let mut state = AppState {
        loading: true,
        ..Default::default()
    };

    // Channels for async communication
    let (cmd_tx, cmd_rx) = mpsc::channel::<DataCommand>(16);
    let (data_tx, mut data_rx) = mpsc::channel::<Result<FetchedData, String>>(4);

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
        // Check for new data (non-blocking)
        while let Ok(result) = data_rx.try_recv() {
            state.loading = false;
            match result {
                Ok(data) => {
                    state.data = Some(data);
                    state.error = None;
                }
                Err(e) => {
                    state.error = Some(e);
                }
            }
        }

        // Draw UI
        terminal.draw(|f| draw_ui(f, &state))?;

        // Handle input with short timeout for responsive UI
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if state.show_add_dialog {
                        handle_add_dialog_input(&mut state, key.code, &cmd_tx).await;
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
        if last_refresh.elapsed() >= refresh_interval && !state.loading {
            let _ = cmd_tx.send(DataCommand::Refresh).await;
            state.loading = true;
            last_refresh = std::time::Instant::now();
        }
    }

    fetcher_handle.abort();
    Ok(())
}

async fn handle_add_dialog_input(state: &mut AppState, key: KeyCode, cmd_tx: &mpsc::Sender<DataCommand>) {
    match key {
        KeyCode::Esc => {
            state.show_add_dialog = false;
        }
        KeyCode::Enter => {
            let addr = state.add_node_input.trim().to_string();
            if addr.is_empty() {
                state.add_node_error = Some("Address cannot be empty".to_string());
            } else if !addr.contains(':') {
                state.add_node_error = Some("Format: host:port".to_string());
            } else {
                let _ = cmd_tx.send(DataCommand::AddNode(addr)).await;
                state.show_add_dialog = false;
                state.loading = true;
            }
        }
        KeyCode::Backspace => {
            state.add_node_input.pop();
            state.add_node_error = None;
        }
        KeyCode::Char(c) => {
            state.add_node_input.push(c);
            state.add_node_error = None;
        }
        _ => {}
    }
}

async fn data_fetcher_task(
    cli: Arc<Cli>,
    session_key: Option<String>,
    mut cmd_rx: mpsc::Receiver<DataCommand>,
    data_tx: mpsc::Sender<Result<FetchedData, String>>,
) {
    let mut client: Option<ControlClient> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            DataCommand::Shutdown => break,
            DataCommand::Refresh => {
                let result = fetch_data(&cli, &session_key, &mut client).await;
                let _ = data_tx.send(result).await;
            }
            DataCommand::AddNode(addr) => {
                let result = add_node(&cli, &session_key, &mut client, &addr).await;
                if let Err(e) = result {
                    let _ = data_tx.send(Err(e)).await;
                } else {
                    // Refresh after adding
                    let result = fetch_data(&cli, &session_key, &mut client).await;
                    let _ = data_tx.send(result).await;
                }
            }
            DataCommand::RemoveNode(node_id) => {
                let result = remove_node(&cli, &session_key, &mut client, &node_id).await;
                if let Err(e) = result {
                    let _ = data_tx.send(Err(e)).await;
                } else {
                    // Refresh after removing
                    let result = fetch_data(&cli, &session_key, &mut client).await;
                    let _ = data_tx.send(result).await;
                }
            }
        }
    }
}

async fn fetch_data(
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
) -> Result<FetchedData, String> {
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    match fetch_data_inner(cli, c).await {
        Ok((data, c)) => {
            *client = Some(c);
            Ok(data)
        }
        Err(e) => Err(e),
    }
}

async fn fetch_data_inner(
    cli: &Cli,
    mut client: ControlClient,
) -> Result<(FetchedData, ControlClient), String> {
    let mut data = FetchedData::default();

    data.nodes = client
        .list_nodes(cli.token.clone())
        .await
        .map_err(|e| e.to_string())?;

    data.realtime = client
        .get_realtime_stats(cli.token.clone())
        .await
        .map_err(|e| e.to_string())?;

    data.connections = client
        .get_recent_connections(cli.token.clone(), 50)
        .await
        .map_err(|e| e.to_string())?;

    data.buckets = client
        .get_time_buckets(cli.token.clone(), Granularity::Minute, 10)
        .await
        .map_err(|e| e.to_string())?;

    let top_hosts = client
        .get_top_n(cli.token.clone(), TopCategory::Hosts, 10)
        .await
        .map_err(|e| e.to_string())?;
    data.top_hosts = top_hosts
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    let top_ips = client
        .get_top_n(cli.token.clone(), TopCategory::Ips, 10)
        .await
        .map_err(|e| e.to_string())?;
    data.top_ips = top_ips
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    Ok((data, client))
}

async fn add_node(
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    addr: &str,
) -> Result<(), String> {
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.add_node(cli.token.clone(), addr.to_string()).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn remove_node(
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    node_id: &str,
) -> Result<(), String> {
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.remove_node(cli.token.clone(), node_id.to_string()).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

fn draw_ui(f: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    // Tabs
    let tabs = Tabs::new(TAB_TITLES.to_vec())
        .block(Block::default().borders(Borders::ALL).title("Proxy TUI"))
        .select(state.tab_index)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);

    // Content
    if state.loading && state.data.is_none() {
        draw_loading(f, chunks[1]);
    } else if let Some(data) = &state.data {
        match state.tab_index {
            0 => draw_nodes_tab(f, chunks[1], data, state.selected_node),
            1 => draw_realtime_tab(f, chunks[1], data),
            2 => draw_connections_tab(f, chunks[1], data),
            3 => draw_topn_tab(f, chunks[1], data),
            _ => {}
        }
    } else {
        draw_loading(f, chunks[1]);
    }

    // Status bar
    let loading_indicator = if state.loading { " ⟳" } else { "" };
    let status = if let Some(err) = &state.error {
        Span::styled(format!("Error: {}{}", err, loading_indicator), Style::default().fg(Color::Red))
    } else {
        let help = if state.tab_index == 0 {
            format!("q:quit  ←→:tabs  ↑↓:select  a:add  d:delete  r:refresh{}", loading_indicator)
        } else {
            format!("q:quit  ←→:tabs  r:refresh{}", loading_indicator)
        };
        Span::styled(help, Style::default().fg(Color::DarkGray))
    };
    let status_bar = Paragraph::new(Line::from(status));
    f.render_widget(status_bar, chunks[2]);

    // Add node dialog
    if state.show_add_dialog {
        draw_add_dialog(f, state);
    }
}

fn draw_loading(f: &mut Frame, area: Rect) {
    let loading = Paragraph::new(vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  Loading...",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Connecting to server",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(loading, area);
}

fn draw_add_dialog(f: &mut Frame, state: &AppState) {
    let area = f.area();
    let dialog_width = 50;
    let dialog_height = 7;
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let mut lines = vec![
        Line::from(""),
        Line::from(format!("  Address: {}_", state.add_node_input)),
        Line::from(""),
        Line::from(Span::styled(
            "  Format: host:port (e.g., 192.168.1.100:1081)",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    if let Some(err) = &state.add_node_error {
        lines.push(Line::from(Span::styled(
            format!("  Error: {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    let dialog = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Add Node (Enter to confirm, Esc to cancel)")
            .style(Style::default().bg(Color::DarkGray)),
    );
    f.render_widget(dialog, dialog_area);
}

fn draw_nodes_tab(f: &mut Frame, area: Rect, data: &FetchedData, selected: usize) {
    if data.nodes.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No nodes configured",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press 'a' to add a node",
                Style::default().fg(Color::Yellow),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title("Nodes"));
        f.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = data
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let style = if i == selected {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let marker = if node.node_id == node.addr { "●" } else { "○" };
            ListItem::new(format!("{} {} ({})", marker, node.node_id, node.addr)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Nodes"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(list, area);
}

fn draw_realtime_tab(f: &mut Frame, area: Rect, data: &FetchedData) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    // Process Stats (left)
    let process_text = if let Some(rt) = &data.realtime {
        vec![
            Line::from(format!("Active Connections: {}", rt.active_connections)),
            Line::from(format!("Process CPU: {:.2}%", rt.cpu_percent)),
            Line::from(format!("Process Memory: {}", format_bytes(rt.memory_bytes))),
            Line::from(format!("Uptime: {}s", rt.uptime_secs)),
        ]
    } else {
        vec![Line::from("No data")]
    };
    let process_stats = Paragraph::new(process_text)
        .block(Block::default().borders(Borders::ALL).title("Process Stats"));
    f.render_widget(process_stats, top_chunks[0]);

    // System Stats (right)
    let system_text = if let Some(rt) = &data.realtime {
        let mem_percent = if rt.sys_memory_total > 0 {
            rt.sys_memory_used as f64 / rt.sys_memory_total as f64 * 100.0
        } else {
            0.0
        };
        let disk_percent = if rt.sys_disk_total > 0 {
            rt.sys_disk_used as f64 / rt.sys_disk_total as f64 * 100.0
        } else {
            0.0
        };
        vec![
            Line::from(format!("System CPU: {:.1}%", rt.sys_cpu_percent)),
            Line::from(format!(
                "System Memory: {}/{} ({:.1}%)",
                format_bytes(rt.sys_memory_used),
                format_bytes(rt.sys_memory_total),
                mem_percent
            )),
            Line::from(format!(
                "Disk: {}/{} ({:.1}%)",
                format_bytes(rt.sys_disk_used),
                format_bytes(rt.sys_disk_total),
                disk_percent
            )),
            Line::from(format!(
                "Disk IO: R:{} W:{}",
                format_bytes(rt.sys_disk_read_bytes),
                format_bytes(rt.sys_disk_write_bytes)
            )),
        ]
    } else {
        vec![Line::from("No data")]
    };
    let system_stats = Paragraph::new(system_text)
        .block(Block::default().borders(Borders::ALL).title("System Stats"));
    f.render_widget(system_stats, top_chunks[1]);

    // Throughput (from buckets)
    let throughput_text: Vec<Line> = data
        .buckets
        .iter()
        .take(5)
        .map(|b| {
            let ts = chrono::DateTime::from_timestamp_millis(b.timestamp_ms)
                .map(|dt| dt.format("%H:%M").to_string())
                .unwrap_or_else(|| "??:??".to_string());
            Line::from(format!(
                "{}: ↑{} ↓{} ({} conn)",
                ts,
                format_bytes(b.total_bytes_up),
                format_bytes(b.total_bytes_down),
                b.total_connections
            ))
        })
        .collect();
    let throughput = Paragraph::new(throughput_text)
        .block(Block::default().borders(Borders::ALL).title("Recent Minutes"));
    f.render_widget(throughput, chunks[1]);
}

fn draw_connections_tab(f: &mut Frame, area: Rect, data: &FetchedData) {
    let header = Row::new(vec!["Time", "Client IP", "Destination", "↑", "↓", "ms"])
        .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = data
        .connections
        .iter()
        .take(20)
        .map(|c| {
            let ts = chrono::DateTime::from_timestamp_millis(c.started_at_ms)
                .map(|dt| dt.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "??:??:??".to_string());
            Row::new(vec![
                Cell::from(ts),
                Cell::from(c.client_ip.clone()),
                Cell::from(format!("{}:{}", c.dest_host, c.dest_port)),
                Cell::from(format_bytes(c.bytes_up)),
                Cell::from(format_bytes(c.bytes_down)),
                Cell::from(c.latency_ms.map(|l| l.to_string()).unwrap_or("-".to_string())),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Recent Connections"));
    f.render_widget(table, area);
}

fn draw_topn_tab(f: &mut Frame, area: Rect, data: &FetchedData) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Top Hosts
    let host_items: Vec<ListItem> = data
        .top_hosts
        .iter()
        .enumerate()
        .map(|(i, (host, bytes))| {
            ListItem::new(format!("{}. {} ({})", i + 1, host, format_bytes(*bytes)))
        })
        .collect();
    let hosts_list = List::new(host_items)
        .block(Block::default().borders(Borders::ALL).title("Top Hosts"));
    f.render_widget(hosts_list, chunks[0]);

    // Top IPs
    let ip_items: Vec<ListItem> = data
        .top_ips
        .iter()
        .enumerate()
        .map(|(i, (ip, bytes))| {
            ListItem::new(format!("{}. {} ({})", i + 1, ip, format_bytes(*bytes)))
        })
        .collect();
    let ips_list = List::new(ip_items)
        .block(Block::default().borders(Borders::ALL).title("Top IPs"));
    f.render_widget(ips_list, chunks[1]);
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}G", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}
