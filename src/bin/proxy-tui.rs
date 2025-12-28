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
//! │  q:quit  ←→:tabs  ↑↓:select                  <- Status Bar  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Keyboard Controls
//!
//! - `q` / `Esc`: Quit
//! - `Tab` / `→`: Next tab
//! - `Shift+Tab` / `←`: Previous tab
//! - `↑` / `↓`: Select node (in Nodes tab)

use std::io::{self, stdout};
use std::time::Duration;

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use http_proxy::config::{CONTROL_SESSION_KEY, SERVER_PORT};
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
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs},
};

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
    /// Session key
    #[arg(short = 'k', long)]
    session_key: Option<String>,
    /// Refresh interval in seconds
    #[arg(short, long, default_value = "2")]
    refresh: u64,
}

const TAB_COUNT: usize = 4;
const TAB_TITLES: [&str; TAB_COUNT] = ["Nodes", "Realtime", "Connections", "Top-N"];

#[derive(Default)]
struct AppState {
    tab_index: usize,
    nodes: Vec<NodeInfo>,
    selected_node: usize,
    realtime: Option<RealtimeSnapshot>,
    connections: Vec<ConnectionRecord>,
    buckets: Vec<TimeBucket>,
    top_hosts: Vec<(String, u64)>,
    top_ips: Vec<(String, u64)>,
    error: Option<String>,
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
        .or_else(|| std::env::var("SECRET_KEY").ok());

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalGuard; // Ensures terminal restore on panic/exit
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut state = AppState::default();
    let refresh_interval = Duration::from_secs(cli.refresh);

    // Reusable client connection
    let mut client: Option<ControlClient> = None;

    loop {
        // Fetch data with connection reuse
        match fetch_data_with_client(&cli, &session_key, &mut state, &mut client).await {
            Ok(()) => state.error = None,
            Err(e) => {
                state.error = Some(e.to_string());
                client = None; // Reset connection on error
            }
        }

        // Draw UI
        terminal.draw(|f| draw_ui(f, &state))?;

        // Handle input with timeout
        if event::poll(refresh_interval)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
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
                            if state.selected_node + 1 < state.nodes.len() {
                                state.selected_node += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // TerminalGuard handles cleanup via Drop
    Ok(())
}

async fn fetch_data_with_client(
    cli: &Cli,
    session_key: &Option<String>,
    state: &mut AppState,
    client: &mut Option<ControlClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Reuse existing connection or create new one
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone()).await?,
    };
    let result = fetch_data_inner(cli, state, c).await;
    match result {
        Ok(c) => {
            *client = Some(c);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn fetch_data_inner(
    cli: &Cli,
    state: &mut AppState,
    mut client: ControlClient,
) -> Result<ControlClient, Box<dyn std::error::Error>> {

    // Fetch nodes
    state.nodes = client.list_nodes(cli.token.clone()).await?;

    // Fetch realtime stats
    state.realtime = client.get_realtime_stats(cli.token.clone()).await?;

    // Fetch recent connections
    state.connections = client
        .get_recent_connections(cli.token.clone(), 50)
        .await?;

    // Fetch time buckets (last 10 minutes)
    state.buckets = client
        .get_time_buckets(cli.token.clone(), Granularity::Minute, 10)
        .await?;

    // Fetch top hosts
    let top_hosts = client
        .get_top_n(cli.token.clone(), TopCategory::Hosts, 10)
        .await?;
    state.top_hosts = top_hosts
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    // Fetch top IPs
    let top_ips = client
        .get_top_n(cli.token.clone(), TopCategory::Ips, 10)
        .await?;
    state.top_ips = top_ips
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    Ok(client)
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
    match state.tab_index {
        0 => draw_nodes_tab(f, chunks[1], state),
        1 => draw_realtime_tab(f, chunks[1], state),
        2 => draw_connections_tab(f, chunks[1], state),
        3 => draw_topn_tab(f, chunks[1], state),
        _ => {}
    }

    // Status bar
    let status = if let Some(err) = &state.error {
        Span::styled(format!("Error: {}", err), Style::default().fg(Color::Red))
    } else {
        Span::styled(
            "q:quit  ←→:tabs  ↑↓:select",
            Style::default().fg(Color::DarkGray),
        )
    };
    let status_bar = Paragraph::new(Line::from(status));
    f.render_widget(status_bar, chunks[2]);
}

fn draw_nodes_tab(f: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = state
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let style = if i == state.selected_node {
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

fn draw_realtime_tab(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Stats
    let stats_text = if let Some(rt) = &state.realtime {
        vec![
            Line::from(format!("Active Connections: {}", rt.active_connections)),
            Line::from(format!("CPU Usage: {:.1}%", rt.cpu_percent)),
            Line::from(format!("Memory: {} MB", rt.memory_bytes / 1024 / 1024)),
            Line::from(format!("Uptime: {}s", rt.uptime_secs)),
        ]
    } else {
        vec![Line::from("Loading...")]
    };
    let stats = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title("Realtime Stats"));
    f.render_widget(stats, chunks[0]);

    // Throughput (from buckets)
    let throughput_text: Vec<Line> = state
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

fn draw_connections_tab(f: &mut Frame, area: Rect, state: &AppState) {
    let header = Row::new(vec!["Time", "Client IP", "Destination", "↑", "↓", "ms"])
        .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = state
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

fn draw_topn_tab(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Top Hosts
    let host_items: Vec<ListItem> = state
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
    let ip_items: Vec<ListItem> = state
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
