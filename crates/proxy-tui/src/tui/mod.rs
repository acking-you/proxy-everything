//! TUI module for proxy monitoring.

mod data_fetcher;
mod render;
mod types;
mod utils;

pub use data_fetcher::data_fetcher_task;
pub use render::draw_ui;
pub use types::*;
pub use utils::{TerminalGuard, format_bytes, handle_input_dialog_input, parse_addr};
