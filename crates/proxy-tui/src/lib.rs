//! Proxy-TUI: Terminal UI for monitoring proxy metrics.

pub mod tui;

// Re-export main types
pub use tui::{
    AppState, Cli, DataCommand, DataResult, InputDialogMode, TAB_COUNT, TerminalGuard,
    data_fetcher_task, draw_ui, handle_input_dialog_input,
};
