//! TUI module for proxy monitoring.

mod data_fetcher;
mod render;
mod types;
mod utils;

pub use data_fetcher::data_fetcher_task;
pub use render::draw_ui;
pub use types::*;
pub use utils::{format_bytes, handle_add_dialog_input, parse_addr, TerminalGuard};
