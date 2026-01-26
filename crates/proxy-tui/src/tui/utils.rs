//! TUI utility functions.

use std::io::stdout;

use crossterm::event::KeyCode;
use crossterm::execute;
use crossterm::terminal::{LeaveAlternateScreen, disable_raw_mode};
use proxy_core::relay::{RelayConfig, UpstreamTarget};
use tokio::sync::mpsc;

use super::types::{AppState, DataCommand, InputDialogMode};

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
pub async fn handle_input_dialog_input(
    state: &mut AppState,
    key: KeyCode,
    cmd_tx: &mpsc::Sender<DataCommand>,
) {
    match key {
        KeyCode::Esc => {
            state.show_input_dialog = false;
            state.input_mode = None;
            state.input_error = None;
        }
        KeyCode::Enter => {
            let input = state.input_value.trim().to_string();
            let Some(mode) = state.input_mode.clone() else {
                state.show_input_dialog = false;
                state.input_error = None;
                return;
            };
            let result = match mode {
                InputDialogMode::AddNode => {
                    if input.is_empty() {
                        Err("Address cannot be empty".to_string())
                    } else if !input.contains(':') {
                        Err("Format: host:port".to_string())
                    } else {
                        cmd_tx
                            .send(DataCommand::AddNode(input))
                            .await
                            .map_err(|_| "Failed to send add node command".to_string())
                    }
                }
                InputDialogMode::CreateGroup => {
                    let mut parts = input.splitn(2, char::is_whitespace);
                    let group_id = parts.next().unwrap_or("").trim();
                    let name = parts.next().unwrap_or("").trim();
                    if group_id.is_empty() || name.is_empty() {
                        Err("Format: <group_id> <name>".to_string())
                    } else {
                        cmd_tx
                            .send(DataCommand::CreateGroup {
                                group_id: group_id.to_string(),
                                name: name.to_string(),
                            })
                            .await
                            .map_err(|_| "Failed to send create group command".to_string())
                    }
                }
                InputDialogMode::AddNodeToGroup { group_id } => {
                    if input.is_empty() {
                        Err("Format: <node_id>".to_string())
                    } else {
                        cmd_tx
                            .send(DataCommand::AddNodeToGroup {
                                group_id,
                                node_id: input,
                            })
                            .await
                            .map_err(|_| "Failed to send add node to group command".to_string())
                    }
                }
                InputDialogMode::RemoveNodeFromGroup { group_id } => {
                    if input.is_empty() {
                        Err("Format: <node_id>".to_string())
                    } else {
                        cmd_tx
                            .send(DataCommand::RemoveNodeFromGroup {
                                group_id,
                                node_id: input,
                            })
                            .await
                            .map_err(|_| {
                                "Failed to send remove node from group command".to_string()
                            })
                    }
                }
                InputDialogMode::AddRelayTarget => match parse_relay_target(&input) {
                    Ok(target) => cmd_tx
                        .send(DataCommand::AddRelayTarget(target))
                        .await
                        .map_err(|_| "Failed to send add relay target command".to_string()),
                    Err(err) => Err(err),
                },
                InputDialogMode::SetRelayConfig => {
                    match serde_json::from_str::<RelayConfig>(&input) {
                        Ok(config) => cmd_tx
                            .send(DataCommand::SetRelayConfig(config))
                            .await
                            .map_err(|_| "Failed to send set relay config command".to_string()),
                        Err(err) => Err(format!("Invalid JSON: {err}")),
                    }
                }
            };

            match result {
                Ok(()) => {
                    state.show_input_dialog = false;
                    state.input_mode = None;
                    state.input_error = None;
                    state.loading = true;
                }
                Err(err) => {
                    state.input_error = Some(err);
                }
            }
        }
        KeyCode::Backspace => {
            state.input_value.pop();
            state.input_error = None;
        }
        KeyCode::Char(c) => {
            state.input_value.push(c);
            state.input_error = None;
        }
        _ => {}
    }
}

/// Parse a relay target spec from user input.
///
/// Supported formats:
/// - `node <host:port> [weight]`
/// - `node_ref <node_id> [weight]`
/// - `group_ref <group_id>`
fn parse_relay_target(input: &str) -> Result<UpstreamTarget, String> {
    let mut parts = input.split_whitespace();
    let kind = parts
        .next()
        .ok_or_else(|| "Target type required".to_string())?;
    match kind {
        "node" => {
            let addr = parts
                .next()
                .ok_or_else(|| "Format: node <host:port> [weight]".to_string())?;
            let weight = parts
                .next()
                .map(|v| {
                    v.parse::<u32>()
                        .map_err(|_| "Weight must be a positive integer".to_string())
                })
                .transpose()?
                .unwrap_or(1);
            Ok(UpstreamTarget::node_weighted(addr, weight))
        }
        "node_ref" => {
            let node_id = parts
                .next()
                .ok_or_else(|| "Format: node_ref <node_id> [weight]".to_string())?;
            let weight = parts
                .next()
                .map(|v| {
                    v.parse::<u32>()
                        .map_err(|_| "Weight must be a positive integer".to_string())
                })
                .transpose()?
                .unwrap_or(1);
            Ok(UpstreamTarget::NodeRef {
                node_id: node_id.to_string(),
                weight,
            })
        }
        "group_ref" => {
            let group_id = parts
                .next()
                .ok_or_else(|| "Format: group_ref <group_id>".to_string())?;
            Ok(UpstreamTarget::group_ref(group_id))
        }
        _ => Err("Unknown target type. Use: node | node_ref | group_ref".to_string()),
    }
}
