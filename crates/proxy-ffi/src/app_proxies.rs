//! Per-app proxies for the desktop UI. One service serializes every request;
//! the loopback router it starts for Claude runs on the shared control
//! runtime, so proxied traffic never passes through the UI isolate.
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use proxy_ui_services::app_proxies::{AppProxies, Entry, Paths};
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum Request {
    Initialize,
    List,
    Discover,
    Inspect {
        path: PathBuf,
    },
    SetUp {
        path: PathBuf,
        port: u16,
        suffix: String,
    },
    Save {
        entry: Entry,
    },
    Remove {
        entry: Entry,
    },
    Open {
        entry: Entry,
    },
    Reveal {
        entry: Entry,
    },
    Icons {
        paths: Vec<String>,
    },
}

fn service() -> Result<&'static Mutex<AppProxies>, String> {
    static SERVICE: OnceLock<Option<Mutex<AppProxies>>> = OnceLock::new();
    SERVICE
        .get_or_init(|| {
            let runtime = crate::runtime::control()?;
            Some(Mutex::new(AppProxies::new(
                Paths::for_user()?,
                runtime.handle().clone(),
            )))
        })
        .as_ref()
        .ok_or_else(|| "App proxies are unavailable".into())
}

pub(crate) fn execute(request: Request) -> Result<Value, String> {
    if let Request::Icons { paths } = &request {
        return Ok(json!({ "icons": icons(paths) }));
    }
    // A panic is reported once; later requests still reach the service.
    let mut service = service()?
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let result = match request {
        Request::Initialize => service.initialize().map(|()| json!({})),
        Request::List => service.list().map(|entries| json!({ "entries": entries })),
        Request::Discover => Ok(json!({ "applications": service.discover() })),
        Request::Inspect { path } => service
            .inspect(&path)
            .map(|application| json!({ "application": application })),
        Request::SetUp { path, port, suffix } => service
            .set_up(&path, port, &suffix)
            .map(|entry| json!({ "entry": entry })),
        Request::Save { entry } => service.save(entry).map(|entry| json!({ "entry": entry })),
        Request::Remove { entry } => service.remove(&entry).map(|()| json!({})),
        Request::Open { entry } => service.open(&entry).map(|()| json!({})),
        Request::Reveal { entry } => service.reveal(&entry).map(|()| json!({})),
        Request::Icons { .. } => unreachable!("answered above"),
    };
    result.map_err(|error| error.to_string())
}

/// Windows shell icons as base64 PNG. macOS draws icons with NSWorkspace in
/// the UI, where AppKit's rendering is available.
fn icons(paths: &[String]) -> Map<String, Value> {
    #[cfg(target_os = "windows")]
    {
        use base64::Engine;
        paths
            .iter()
            .filter_map(|path| {
                let png = proxy_client::client::executable_icon_png(std::path::Path::new(path))?;
                Some((
                    path.clone(),
                    Value::String(base64::engine::general_purpose::STANDARD.encode(png)),
                ))
            })
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = paths;
        Map::new()
    }
}
