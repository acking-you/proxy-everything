//! TUI rendering functions.

use std::collections::HashMap;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Tabs},
};

use proxy_core::geo::country_to_flag;

use proxy_core::relay::UpstreamTarget;

use super::types::{AppState, FetchedData, InputDialogMode, TAB_TITLES};
use super::utils::format_bytes;

pub const SPINNER_FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn draw_ui(f: &mut Frame, state: &mut AppState) {
    if state.switching {
        draw_switching_overlay(f, state);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Tabs
    let title = format!("Proxy TUI [{}]", state.current_server);
    let tabs = Tabs::new(TAB_TITLES.to_vec())
        .block(Block::default().borders(Borders::ALL).title(title))
        .select(state.tab_index)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    // Content
    if state.loading && state.data.is_none() {
        draw_loading(f, chunks[1], state.anim_frame);
    } else if let Some(data) = &state.data {
        match state.tab_index {
            0 => draw_nodes_tab(
                f,
                chunks[1],
                data,
                state.selected_node,
                &state.geo_cache,
                &state.current_server,
            ),
            1 => draw_groups_tab(f, chunks[1], data, state.selected_group),
            2 => draw_relay_tab(f, chunks[1], data, state.selected_relay_target),
            3 => draw_realtime_tab(f, chunks[1], data),
            4 => draw_connections_tab(f, chunks[1], data, state),
            5 => draw_topn_tab(f, chunks[1], data, state),
            _ => {}
        }
    } else {
        draw_loading(f, chunks[1], state.anim_frame);
    }

    // Status bar
    let loading_indicator = if state.loading { " ⟳" } else { "" };
    let status = if let Some(err) = &state.error {
        Span::styled(
            format!("Error: {}{}", err, loading_indicator),
            Style::default().fg(Color::Red),
        )
    } else if let Some(geo_err) = &state.geo_error {
        Span::styled(format!("⚠ {}", geo_err), Style::default().fg(Color::Yellow))
    } else {
        let help = match state.tab_index {
            0 => format!(
                "q:quit  ←→:tabs  ↑↓:select  Enter:switch  a:add  d:delete  r:refresh{}",
                loading_indicator
            ),
            1 => format!(
                "q:quit  ←→:tabs  ↑↓:select  a:create  d:delete  g:add-node  x:rm-node  r:refresh{}",
                loading_indicator
            ),
            2 => format!(
                "q:quit  ←→:tabs  ↑↓:select  a:add-target  d:remove  e:toggle  l:algo  c:set-config  r:refresh{}",
                loading_indicator
            ),
            4 | 5 => format!(
                "q:quit  ←→:tabs  /:filter  PgUp/PgDn:page  r:refresh{}",
                loading_indicator
            ),
            _ => format!("q:quit  ←→:tabs  r:refresh{}", loading_indicator),
        };
        Span::styled(help, Style::default().fg(Color::DarkGray))
    };
    f.render_widget(Paragraph::new(Line::from(status)), chunks[2]);

    if state.show_input_dialog {
        draw_input_dialog(f, state);
    }

    if state.show_filter {
        draw_filter_dialog(f, state);
    }
}

fn draw_switching_overlay(f: &mut Frame, state: &AppState) {
    let area = f.area();
    let spinner = SPINNER_FRAMES[state.anim_frame % SPINNER_FRAMES.len()];
    let target = state.switch_target.as_deref().unwrap_or("...");

    let text = vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {} Switching to {}", spinner, target),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press Esc to cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Connecting...");
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_loading(f: &mut Frame, area: Rect, anim_frame: usize) {
    let spinner = SPINNER_FRAMES[anim_frame % SPINNER_FRAMES.len()];
    let loading = Paragraph::new(vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {} Loading...", spinner),
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

fn draw_input_dialog(f: &mut Frame, state: &AppState) {
    let area = f.area();
    let dialog_width = 50;
    let dialog_height = 9;
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let (title, help) = match state.input_mode.as_ref() {
        Some(InputDialogMode::AddNode) => {
            ("Add Node", "Format: host:port (e.g., 192.168.1.100:1081)")
        }
        Some(InputDialogMode::CreateGroup) => ("Create Group", "Format: <group_id> <name>"),
        Some(InputDialogMode::AddNodeToGroup { .. }) => ("Add Node to Group", "Format: <node_id>"),
        Some(InputDialogMode::RemoveNodeFromGroup { .. }) => {
            ("Remove Node from Group", "Format: <node_id>")
        }
        Some(InputDialogMode::AddRelayTarget) => (
            "Add Relay Target",
            "node <host:port> [weight] | node_ref <id> [weight] | group_ref <group_id>",
        ),
        Some(InputDialogMode::SetRelayConfig) => (
            "Set Relay Config (JSON)",
            "Example: {\"enabled\":true,\"targets\":[],\"algo\":\"round_robin\",\"health_check_interval_secs\":30}",
        ),
        None => ("Input", ""),
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(format!("  Input: {}_", state.input_value)),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", help),
            Style::default().fg(Color::DarkGray),
        )),
    ];

    if let Some(err) = &state.input_error {
        lines.push(Line::from(Span::styled(
            format!("  Error: {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    let dialog = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("{title} (Enter to confirm, Esc to cancel)"))
            .style(Style::default().bg(Color::DarkGray)),
    );
    f.render_widget(dialog, dialog_area);
}

fn draw_filter_dialog(f: &mut Frame, state: &AppState) {
    let area = f.area();
    let dialog_width = 50;
    let dialog_height = 5;
    let x = (area.width.saturating_sub(dialog_width)) / 2;
    let y = (area.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    f.render_widget(Clear, dialog_area);

    let lines = vec![
        Line::from(""),
        Line::from(format!("  Filter: {}_", state.filter_input)),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter to apply, Esc to cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let dialog = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Filter by domain")
            .style(Style::default().bg(Color::DarkGray)),
    );
    f.render_widget(dialog, dialog_area);
}

fn draw_nodes_tab(
    f: &mut Frame,
    area: Rect,
    data: &FetchedData,
    selected: usize,
    geo_cache: &HashMap<String, String>,
    current_server: &str,
) {
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

    let mut id_counts: HashMap<&str, usize> = HashMap::new();
    for node in &data.nodes {
        *id_counts.entry(node.node_id.as_str()).or_insert(0) += 1;
    }

    let items: Vec<ListItem> = data
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let style = if i == selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            // Heuristic: self node typically matches the current server address
            // or appears with multiple addresses under the same node_id.
            let is_self = node.addr == current_server
                || id_counts
                    .get(node.node_id.as_str())
                    .map(|count| *count > 1)
                    .unwrap_or(false);
            let marker = if node.node_id == node.addr {
                "●"
            } else {
                "○"
            };
            let self_tag = if is_self { " [self]" } else { "" };
            let ip = node.addr.split(':').next().unwrap_or("");
            let geo_str = geo_cache
                .get(ip)
                .map(|code| format!("{} {} ", country_to_flag(code), code))
                .unwrap_or_default();
            ListItem::new(format!(
                "{} {}{} ({}){}",
                marker, geo_str, node.node_id, node.addr, self_tag
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Nodes"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(list, area);
}

fn draw_groups_tab(f: &mut Frame, area: Rect, data: &FetchedData, selected: usize) {
    if data.groups.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No groups configured",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press 'a' to create a group",
                Style::default().fg(Color::Yellow),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title("Groups"));
        f.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = data
        .groups
        .iter()
        .enumerate()
        .map(|(i, group)| {
            let style = if i == selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let nodes_preview = if group.node_ids.is_empty() {
                "no nodes".to_string()
            } else {
                let preview: Vec<String> = group.node_ids.iter().take(3).cloned().collect();
                if group.node_ids.len() > 3 {
                    format!("{}, ...", preview.join(", "))
                } else {
                    preview.join(", ")
                }
            };
            ListItem::new(format!(
                "{} ({}) [{}]",
                group.group_id, group.name, nodes_preview
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Groups"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(list, area);
}

fn draw_relay_tab(f: &mut Frame, area: Rect, data: &FetchedData, selected: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let (enabled, algo) = if let Some(status) = &data.relay_status {
        (status.enabled, Some(status.algo))
    } else if let Some(config) = &data.relay_config {
        (config.enabled, Some(config.algo))
    } else {
        (false, None)
    };

    let status_text = vec![
        Line::from(format!("Enabled: {}", enabled)),
        Line::from(format!(
            "Algorithm: {}",
            algo.map(|a| format!("{a:?}"))
                .unwrap_or_else(|| "-".to_string())
        )),
        Line::from(format!(
            "Targets: {}",
            data.relay_status
                .as_ref()
                .map(|s| s.targets.len())
                .or_else(|| data.relay_config.as_ref().map(|c| c.targets.len()))
                .unwrap_or(0)
        )),
    ];
    f.render_widget(
        Paragraph::new(status_text)
            .block(Block::default().borders(Borders::ALL).title("Relay Status")),
        chunks[0],
    );

    let mut rows: Vec<Row> = Vec::new();
    if let Some(status) = &data.relay_status {
        for (idx, target) in status.targets.iter().enumerate() {
            let style = if idx == selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            rows.push(
                Row::new(vec![
                    Cell::from(idx.to_string()),
                    Cell::from(target.addr.clone()),
                    Cell::from(target.weight.to_string()),
                    Cell::from(if target.healthy { "yes" } else { "no" }),
                    Cell::from(target.connections.to_string()),
                ])
                .style(style),
            );
        }
    } else if let Some(config) = &data.relay_config {
        for (idx, target) in config.targets.iter().enumerate() {
            let style = if idx == selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let label = match target {
                UpstreamTarget::Node { addr, weight } => format!("node:{addr} w={weight}"),
                UpstreamTarget::NodeRef { node_id, weight } => {
                    format!("node_ref:{node_id} w={weight}")
                }
                UpstreamTarget::GroupRef { group_id } => format!("group_ref:{group_id}"),
            };
            rows.push(
                Row::new(vec![
                    Cell::from(idx.to_string()),
                    Cell::from(label),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                ])
                .style(style),
            );
        }
    }

    if rows.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No relay targets configured",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press 'a' to add a target",
                Style::default().fg(Color::Yellow),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Relay Targets"),
        );
        f.render_widget(empty, chunks[1]);
        return;
    }

    let header = Row::new(vec!["#", "Target", "Weight", "Healthy", "Conn"])
        .style(Style::default().fg(Color::Yellow));
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Relay Targets"),
    );
    f.render_widget(table, chunks[1]);
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

    // Process Stats
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
    f.render_widget(
        Paragraph::new(process_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Process Stats"),
        ),
        top_chunks[0],
    );

    // System Stats
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
                "Net: ↓{}/s ↑{}/s (Total: ↓{} ↑{})",
                format_bytes(rt.sys_net_recv_rate),
                format_bytes(rt.sys_net_sent_rate),
                format_bytes(rt.sys_net_recv_bytes),
                format_bytes(rt.sys_net_sent_bytes)
            )),
        ]
    } else {
        vec![Line::from("No data")]
    };
    f.render_widget(
        Paragraph::new(system_text)
            .block(Block::default().borders(Borders::ALL).title("System Stats")),
        top_chunks[1],
    );

    // Throughput
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
    f.render_widget(
        Paragraph::new(throughput_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recent Minutes"),
        ),
        chunks[1],
    );
}

fn draw_connections_tab(f: &mut Frame, area: Rect, data: &FetchedData, state: &AppState) {
    // Filter connections
    let filtered: Vec<_> = if state.filter_input.is_empty() {
        data.connections.iter().collect()
    } else {
        let filter = state.filter_input.to_lowercase();
        data.connections
            .iter()
            .filter(|c| c.dest_host.to_lowercase().contains(&filter))
            .collect()
    };

    let total = filtered.len();
    let start = state.page_offset.min(total.saturating_sub(1));
    let end = (start + state.page_size).min(total);

    let header = Row::new(vec!["Time", "Client IP", "Destination", "↑", "↓", "ms"])
        .style(Style::default().fg(Color::Yellow));

    let rows: Vec<Row> = filtered[start..end]
        .iter()
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
                Cell::from(
                    c.latency_ms
                        .map(|l| l.to_string())
                        .unwrap_or("-".to_string()),
                ),
            ])
        })
        .collect();

    let title = if state.filter_input.is_empty() {
        format!("Connections [{}-{}/{}]", start + 1, end, total)
    } else {
        format!(
            "Connections [{}-{}/{}] filter: {}",
            start + 1,
            end,
            total,
            state.filter_input
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Min(20),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, area);
}

fn draw_topn_tab(f: &mut Frame, area: Rect, data: &FetchedData, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Filter and paginate hosts
    let filtered_hosts: Vec<_> = if state.filter_input.is_empty() {
        data.top_hosts.iter().collect()
    } else {
        let filter = state.filter_input.to_lowercase();
        data.top_hosts
            .iter()
            .filter(|(host, _)| host.to_lowercase().contains(&filter))
            .collect()
    };
    let total_hosts = filtered_hosts.len();
    let start_h = state.page_offset.min(total_hosts.saturating_sub(1));
    let end_h = (start_h + state.page_size).min(total_hosts);

    let host_items: Vec<ListItem> = filtered_hosts[start_h..end_h]
        .iter()
        .enumerate()
        .map(|(i, (host, bytes))| {
            ListItem::new(format!(
                "{}. {} ({})",
                start_h + i + 1,
                host,
                format_bytes(*bytes)
            ))
        })
        .collect();

    let host_title = if state.filter_input.is_empty() {
        format!("Top Hosts [{}-{}/{}]", start_h + 1, end_h, total_hosts)
    } else {
        format!(
            "Top Hosts [{}-{}/{}] filter: {}",
            start_h + 1,
            end_h,
            total_hosts,
            state.filter_input
        )
    };
    f.render_widget(
        List::new(host_items).block(Block::default().borders(Borders::ALL).title(host_title)),
        chunks[0],
    );

    // Top IPs (no filter, just pagination)
    let total_ips = data.top_ips.len();
    let start_i = state.page_offset.min(total_ips.saturating_sub(1));
    let end_i = (start_i + state.page_size).min(total_ips);

    let ip_items: Vec<ListItem> = data.top_ips[start_i..end_i]
        .iter()
        .enumerate()
        .map(|(i, (ip, bytes))| {
            ListItem::new(format!(
                "{}. {} ({})",
                start_i + i + 1,
                ip,
                format_bytes(*bytes)
            ))
        })
        .collect();

    let ip_title = format!("Top IPs [{}-{}/{}]", start_i + 1, end_i, total_ips);
    f.render_widget(
        List::new(ip_items).block(Block::default().borders(Borders::ALL).title(ip_title)),
        chunks[1],
    );
}
