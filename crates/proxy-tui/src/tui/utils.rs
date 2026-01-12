//! TUI utility functions.

use std::io::stdout;

use crossterm::{
    event::KeyCode,
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode},
};
use tokio::sync::mpsc;

use super::types::{AppState, DataCommand};

/// RAII guard to restore terminal state on drop.
pub struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

/// Parse address string into host and port.
pub fn parse_addr(addr: &str) -> Result<(String, u16), String> {
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid address: {}", addr));
    }
    let port = parts[0]
        .parse::<u16>()
        .map_err(|_| format!("Invalid port: {}", parts[0]))?;
    Ok((parts[1].to_string(), port))
}

/// Format bytes into human-readable string with proper units.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let b = bytes as f64;
    if b >= TB {
        format!("{:.2} TB", b / TB)
    } else if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Handle input in add node dialog.
pub async fn handle_add_dialog_input(
    state: &mut AppState,
    key: KeyCode,
    cmd_tx: &mpsc::Sender<DataCommand>,
) {
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
            } else if cmd_tx.send(DataCommand::AddNode(addr)).await.is_err() {
                state.add_node_error = Some("Failed to send add node command".to_string());
            } else {
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
