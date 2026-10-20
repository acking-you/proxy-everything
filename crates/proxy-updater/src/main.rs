#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    proxy_core::allocator::initialize();
    #[cfg(windows)]
    if let Err(error) = proxy_updater::windows::run(std::env::args_os().skip(1)) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("The standalone installer helper is only used on Windows");
        std::process::exit(1);
    }
}
