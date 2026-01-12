//! Proxy-TUI: Terminal UI for monitoring proxy metrics.

pub mod tui;

// Re-export main types
pub use tui::{
    AppState, Cli, DataCommand, DataResult, TAB_COUNT, TerminalGuard, data_fetcher_task, draw_ui,
    handle_add_dialog_input,
};
