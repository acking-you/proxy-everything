//! Started by a generated app-proxy launcher: opens its app with the proxy
//! settings stored beside it, or explains why it cannot.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() {
    use proxy_ui_services::app_proxies::launch::{self, Outcome};

    let arguments = std::env::args().collect::<Vec<_>>();
    let Some(path) = launch::settings_path(&arguments) else {
        std::process::exit(2);
    };
    if arguments.iter().any(|argument| argument == "--check") {
        match launch::check(&path) {
            Ok(report) => println!("{report:#}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let zh = launch::chinese();
    let text = |zh_text: &str, en_text: &str| if zh { zh_text } else { en_text }.to_owned();
    let (title, detail) = match launch::run(&path) {
        Ok(Outcome::Launched | Outcome::Activated) => return,
        Ok(Outcome::ProxyUnavailable) => (
            text("请先开启本地代理", "Start the local proxy first"),
            text(
                "请在 CipherRelay 中连接节点，确保本地代理可用。无需开启 TUN。",
                "Connect to a node in CipherRelay so the local proxy is listening. TUN is not \
                 required.",
            ),
        ),
        Ok(Outcome::QuitFirst) => (
            text("请先完全退出目标应用", "Quit the target application first"),
            text(
                "运行中的应用无法接收新的代理和直连规则。请保存工作并完全退出它，再点击此启动器。",
                "A running app cannot receive new proxy or bypass settings. Save your work, quit \
                 it fully, then open this launcher again.",
            ),
        ),
        Err(error) => (
            text("启动失败", "Could not launch the application"),
            error.to_string(),
        ),
    };
    launch::message(&title, &detail);
    std::process::exit(1);
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() {}
