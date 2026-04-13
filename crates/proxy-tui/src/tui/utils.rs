//! TUI utility functions.

use std::io::stdout;

use crossterm::event::KeyCode;
use crossterm::execute;
use crossterm::terminal::{LeaveAlternateScreen, disable_raw_mode};
use proxy_core::relay::{ExternalProxyTarget, RelayConfig, UpstreamTarget};
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
/// - `proxy <proxy_url> [weight]`
/// - `<proxy_url> [weight]` where scheme is socks5, socks5h, or http
fn parse_relay_target(input: &str) -> Result<UpstreamTarget, String> {
    let mut parts = input.split_whitespace();
    let kind = parts
        .next()
        .ok_or_else(|| "Target type required".to_string())?;

    if looks_like_proxy_url(kind) {
        let weight = parse_weight(
            parts.next(),
            "Format: <proxy_url> [weight] (scheme: socks5, socks5h, http)",
        )?;
        ensure_no_extra_parts(parts)?;
        validate_proxy_url(kind)?;
        return Ok(UpstreamTarget::external_proxy(kind, weight));
    }

    match kind {
        "node" => {
            let addr = parts
                .next()
                .ok_or_else(|| "Format: node <host:port> [weight]".to_string())?;
            let weight = parse_weight(parts.next(), "Format: node <host:port> [weight]")?;
            ensure_no_extra_parts(parts)?;
            Ok(UpstreamTarget::node_weighted(addr, weight))
        }
        "node_ref" => {
            let node_id = parts
                .next()
                .ok_or_else(|| "Format: node_ref <node_id> [weight]".to_string())?;
            let weight = parse_weight(parts.next(), "Format: node_ref <node_id> [weight]")?;
            ensure_no_extra_parts(parts)?;
            Ok(UpstreamTarget::NodeRef {
                node_id: node_id.to_string(),
                weight,
            })
        }
        "group_ref" => {
            let group_id = parts
                .next()
                .ok_or_else(|| "Format: group_ref <group_id>".to_string())?;
            ensure_no_extra_parts(parts)?;
            Ok(UpstreamTarget::group_ref(group_id))
        }
        "proxy" => {
            let proxy_url = parts.next().ok_or_else(|| {
                "Format: proxy <proxy_url> [weight] (scheme: socks5, socks5h, http)".to_string()
            })?;
            let weight = parse_weight(
                parts.next(),
                "Format: proxy <proxy_url> [weight] (scheme: socks5, socks5h, http)",
            )?;
            ensure_no_extra_parts(parts)?;
            validate_proxy_url(proxy_url)?;
            Ok(UpstreamTarget::external_proxy(proxy_url, weight))
        }
        _ => Err(
            "Unknown target type. Use: node | node_ref | group_ref | proxy | <proxy_url>"
                .to_string(),
        ),
    }
}

fn looks_like_proxy_url(input: &str) -> bool {
    input.starts_with("socks5://")
        || input.starts_with("socks5h://")
        || input.starts_with("http://")
}

fn parse_weight(weight: Option<&str>, usage: &str) -> Result<u32, String> {
    match weight {
        Some(value) => {
            let weight = value
                .parse::<u32>()
                .map_err(|_| format!("Weight must be a positive integer. {usage}"))?;
            if weight == 0 {
                return Err(format!("Weight must be a positive integer. {usage}"));
            }
            Ok(weight)
        }
        None => Ok(1),
    }
}

fn ensure_no_extra_parts<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<(), String> {
    if parts.next().is_some() {
        Err("Too many arguments for relay target".to_string())
    } else {
        Ok(())
    }
}

fn validate_proxy_url(proxy_url: &str) -> Result<(), String> {
    ExternalProxyTarget::parse(proxy_url).map(|_| ())
}

#[cfg(test)]
mod tests {
    use proxy_core::relay::UpstreamTarget;

    use super::parse_relay_target;

    #[test]
    fn test_parse_relay_target_proxy_keyword() {
        let target = parse_relay_target("proxy socks5://user:secret@127.0.0.1:1080 2").unwrap();
        assert_eq!(
            target,
            UpstreamTarget::external_proxy("socks5://user:secret@127.0.0.1:1080", 2)
        );
    }

    #[test]
    fn test_parse_relay_target_bare_proxy_url() {
        let target = parse_relay_target("http://user:secret@127.0.0.1:8080").unwrap();
        assert_eq!(
            target,
            UpstreamTarget::external_proxy("http://user:secret@127.0.0.1:8080", 1)
        );
    }

    #[test]
    fn test_parse_relay_target_bare_proxy_url_with_weight() {
        let target = parse_relay_target("socks5h://user:secret@127.0.0.1:1080 4").unwrap();
        assert_eq!(
            target,
            UpstreamTarget::external_proxy("socks5h://user:secret@127.0.0.1:1080", 4)
        );
    }

    #[test]
    fn test_parse_relay_target_rejects_invalid_proxy_url() {
        let err = parse_relay_target("proxy socks4://127.0.0.1:1080").unwrap_err();
        assert!(err.contains("Unsupported proxy scheme"));
    }

    #[test]
    fn test_parse_relay_target_rejects_zero_weight() {
        let err = parse_relay_target("proxy socks5://127.0.0.1:1080 0").unwrap_err();
        assert!(err.contains("Weight must be a positive integer"));
    }
}
