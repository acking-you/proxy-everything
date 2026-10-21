//! Native services shared by desktop and mobile frontends.
/// Per-app proxies exist only in the macOS and Windows desktop apps.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub mod app_proxies;
pub mod subscription;
