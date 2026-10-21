//! Claude's native proxy setting.
//!
//! CipherRelay owns only Claude's two proxy keys. Other settings, credentials
//! included, are read and merged but never copied into CipherRelay's state.
//! Claude gives its agent one fixed proxy rather than evaluating PAC per
//! request, so the setting points at the [router], which applies the same host
//! rules to the app and its agent.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::router::{Router, Target};
use super::{Entry, Error, Mode, Result, apps, read_object, rules, write_json};

pub const ID: &str = "claude-native";
const KEYS: [&str; 2] = ["egressProxyUrl", "egressProxyPacUrl"];

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    schema_version: u32,
    configuration: Entry,
    router_port: u16,
    config_file: String,
    /// The proxy keys before CipherRelay changed them, restored on removal.
    original: Map<String, Value>,
    /// The proxy keys CipherRelay wrote; a mismatch means someone else edited
    /// them since.
    applied: Map<String, Value>,
}

pub struct ClaudeNative {
    directory: PathBuf,
    library: PathBuf,
    runtime: tokio::runtime::Handle,
    state: Option<State>,
    router: Option<Router>,
    loaded: bool,
    warning: Option<String>,
}

impl ClaudeNative {
    pub fn new(directory: PathBuf, library: PathBuf, runtime: tokio::runtime::Handle) -> Self {
        Self {
            directory,
            library,
            runtime,
            state: None,
            router: None,
            loaded: false,
            warning: None,
        }
    }

    fn state_file(&self) -> PathBuf {
        self.directory.join("claude-native.json")
    }

    pub fn initialize(&mut self) -> Result<()> {
        if self.loaded {
            return Ok(());
        }
        self.state = read_object(&self.state_file())?
            .map(|object| serde_json::from_value::<State>(Value::Object(object)))
            .transpose()
            .map_err(|_| {
                Error::new("Invalid app proxy state. Existing settings were preserved.")
            })?;
        self.loaded = true;
        if let Some(state) = &self.state {
            let started = self.runtime.block_on(Router::start(
                state.router_port,
                target(&state.configuration),
            ));
            match started {
                Ok(router) => self.router = Some(router),
                Err(error) => self.warning = Some(error.to_string()),
            }
        }
        Ok(())
    }

    pub fn configuration(&mut self) -> Result<Option<Entry>> {
        self.initialize()?;
        Ok(self.state.as_ref().map(|state| Entry {
            warning: self.warning.clone(),
            ..state.configuration.clone()
        }))
    }

    /// The profile Claude currently applies, created like Claude would when
    /// it has none yet.
    fn active_file(&self) -> Result<PathBuf> {
        let meta_file = self.library.join("_meta.json");
        let mut meta = read_object(&meta_file)?;
        if meta
            .as_ref()
            .is_some_and(|meta| meta.get("hybridPointer").is_some_and(|v| !v.is_null()))
        {
            return Err(Error::new(
                "Claude uses a managed deployment; its local proxy settings cannot be applied.",
            ));
        }
        if meta.is_none() {
            let id = super::new_id();
            write_json(&self.library.join(format!("{id}.json")), &json!({}))?;
            let created = json!({"appliedId": id, "entries": [{"id": id, "name": "Default"}]});
            write_json(&meta_file, &created)?;
            meta = created.as_object().cloned();
        }
        match meta.as_ref().and_then(|meta| meta.get("appliedId")) {
            Some(Value::String(id)) if super::is_id(id) => {
                Ok(self.library.join(format!("{id}.json")))
            }
            _ => Err(Error::new(
                "Claude has no valid active local configuration.",
            )),
        }
    }

    pub fn save(&mut self, input: Entry) -> Result<Entry> {
        self.initialize()?;
        if input.application_id.as_deref() != Some(apps::CLAUDE)
            || input.mode != Mode::ClaudeNative
            || input.port == 0
            || !rules::valid_name(&input.name)
            || !rules::valid_rules(&input.bypass_rules)
        {
            return Err(Error::new("Invalid Claude proxy settings."));
        }
        let file = self.active_file()?;
        let current = read_object(&file)?
            .ok_or_else(|| Error::new("Claude's active configuration is missing."))?;
        if let Some(state) = &self.state
            && (Path::new(&state.config_file) != file || !same_keys(&current, &state.applied))
        {
            return Err(Error::new(
                "Claude proxy settings changed outside CipherRelay. Remove this entry first; \
                 external changes will be preserved.",
            ));
        }
        let created = self.router.is_none();
        let router = match self.router.take() {
            Some(router) => router,
            None => self.runtime.block_on(Router::start(0, target(&input)))?,
        };
        if router.port() == input.port {
            self.restore_router(router, created);
            return Err(Error::new(
                "The upstream proxy port conflicts with the app routing port.",
            ));
        }
        let applied = Map::from_iter([
            (
                KEYS[0].into(),
                json!(format!("http://127.0.0.1:{}", router.port())),
            ),
            (KEYS[1].into(), Value::Null),
        ]);
        let saved = Entry {
            id: Some(ID.into()),
            launcher_path: Some(file.to_string_lossy().into_owned()),
            warning: None,
            ..input
        };
        let previous = self.state.clone();
        let state = State {
            schema_version: 1,
            configuration: saved.clone(),
            router_port: router.port(),
            config_file: file.to_string_lossy().into_owned(),
            original: previous
                .as_ref()
                .map(|previous| previous.original.clone())
                .unwrap_or_else(|| keys_of(&current)),
            applied: applied.clone(),
        };
        let written = (|| {
            // Persist the restoration record before touching another app's
            // settings, and re-read so unrelated changes are preserved.
            write_json(&self.state_file(), &state)?;
            let mut latest = read_object(&file)?
                .ok_or_else(|| Error::new("Claude's active configuration is missing."))?;
            if !same_keys(&latest, &keys_of(&current)) {
                return Err(Error::new(
                    "Claude proxy settings changed while saving. Try again.",
                ));
            }
            merge(&mut latest, &applied);
            write_json(&file, &latest)
        })();
        if let Err(error) = written {
            match &previous {
                None => {
                    let _ = std::fs::remove_file(self.state_file());
                }
                Some(previous) => {
                    let _ = write_json(&self.state_file(), previous);
                }
            }
            self.restore_router(router, created);
            return Err(error);
        }
        router.set_target(target(&saved));
        self.router = Some(router);
        self.state = Some(state);
        self.warning = None;
        Ok(saved)
    }

    fn restore_router(&mut self, router: Router, created: bool) {
        if created {
            self.runtime.block_on(router.stop());
        } else {
            self.router = Some(router);
        }
    }

    /// Restores the keys present before CipherRelay configured Claude, unless
    /// someone changed them since: then that newer setting stays as a whole,
    /// since restoring only an old PAC could override a newly chosen URL.
    pub fn remove(&mut self) -> Result<()> {
        self.initialize()?;
        let Some(state) = self.state.clone() else {
            return Ok(());
        };
        let file = PathBuf::from(&state.config_file);
        if file.parent() != Some(self.library.as_path()) {
            return Err(Error::new("Invalid native configuration path."));
        }
        if let Some(mut current) = read_object(&file)?
            && same_keys(&current, &state.applied)
        {
            merge(&mut current, &state.original);
            write_json(&file, &current)?;
        }
        std::fs::remove_file(self.state_file())?;
        self.close();
        self.state = None;
        self.warning = None;
        self.loaded = true;
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(router) = self.router.take() {
            self.runtime.block_on(router.stop());
        }
        self.loaded = false;
    }
}

fn target(entry: &Entry) -> Target {
    Target {
        upstream_port: entry.port,
        rules: entry.bypass_rules.clone(),
    }
}

fn keys_of(object: &Map<String, Value>) -> Map<String, Value> {
    KEYS.iter()
        .map(|&key| (key.into(), object.get(key).cloned().unwrap_or(Value::Null)))
        .collect()
}

fn same_keys(current: &Map<String, Value>, expected: &Map<String, Value>) -> bool {
    KEYS.iter().all(|&key| {
        current.get(key).unwrap_or(&Value::Null) == expected.get(key).unwrap_or(&Value::Null)
    })
}

fn merge(current: &mut Map<String, Value>, values: &Map<String, Value>) {
    for (key, value) in values {
        if value.is_null() {
            current.remove(key);
        } else {
            current.insert(key.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(port: u16, bypass: &[&str]) -> Entry {
        Entry {
            id: None,
            name: "Claude".into(),
            app_path: "/Applications/Claude.app".into(),
            mode: Mode::ClaudeNative,
            port,
            bypass_rules: bypass.iter().map(|rule| rule.to_string()).collect(),
            application_id: Some(apps::CLAUDE.into()),
            launcher_path: None,
            warning: None,
        }
    }

    fn read(path: &Path) -> Map<String, Value> {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn preserves_credentials_resumes_routing_and_restores_only_owned_keys() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let library = temporary.path().join("Claude/configLibrary");
        let state = temporary.path().join("CipherRelay");
        std::fs::create_dir_all(&library).unwrap();
        let profile = "12345678-1234-1234-1234-123456789abc";
        let file = library.join(format!("{profile}.json"));
        std::fs::write(
            library.join("_meta.json"),
            json!({"appliedId": profile, "entries": []}).to_string(),
        )
        .unwrap();
        let original = json!({
            "inferenceGatewayApiKey": "test-placeholder",
            "inferenceProvider": "gateway",
            "egressProxyUrl": "http://old.invalid:1234",
            "egressProxyPacUrl": "http://old.invalid/proxy.pac",
        });
        std::fs::write(&file, original.to_string()).unwrap();
        let open = || ClaudeNative::new(state.clone(), library.clone(), runtime.handle().clone());

        let mut store = open();
        let initial = store.save(settings(19876, &DEFAULTS)).unwrap();
        let configured = read(&file);
        let routing = configured["egressProxyUrl"].as_str().unwrap().to_owned();
        assert_eq!(configured["inferenceGatewayApiKey"], "test-placeholder");
        assert!(!configured.contains_key("egressProxyPacUrl"));
        let saved_state = std::fs::read_to_string(state.join("claude-native.json")).unwrap();
        assert!(!saved_state.contains("test-placeholder"));

        // A restart resumes routing; a second copy of the app cannot take it.
        store.close();
        let mut store = open();
        assert_eq!(store.configuration().unwrap().unwrap().port, 19876);
        let mut concurrent = open();
        assert!(
            concurrent
                .configuration()
                .unwrap()
                .unwrap()
                .warning
                .is_some()
        );
        let routing_port = routing.rsplit(':').next().unwrap().parse::<u16>().unwrap();
        std::net::TcpStream::connect(("127.0.0.1", routing_port)).unwrap();

        // Edits keep the routing address Claude already reads.
        let edited = store.save(settings(19877, &[".internal.example"])).unwrap();
        assert_eq!(read(&file)["egressProxyUrl"], routing.as_str());
        assert_eq!(edited.id, initial.id);
        store.remove().unwrap();
        assert_eq!(Value::Object(read(&file)), original);

        // A later external edit wins over both CipherRelay's and the original.
        store.save(settings(19877, &DEFAULTS)).unwrap();
        let mut external = read(&file);
        external.insert(
            "egressProxyUrl".into(),
            json!("http://external.invalid:2222"),
        );
        external.insert("unrelatedSetting".into(), json!("preserve"));
        std::fs::write(&file, Value::Object(external).to_string()).unwrap();
        assert!(store.save(settings(19878, &DEFAULTS)).is_err());
        store.remove().unwrap();
        let restored = read(&file);
        assert_eq!(restored["egressProxyUrl"], "http://external.invalid:2222");
        assert!(!restored.contains_key("egressProxyPacUrl"));
        assert_eq!(restored["unrelatedSetting"], "preserve");
        assert_eq!(restored["inferenceGatewayApiKey"], "test-placeholder");
        assert!(store.configuration().unwrap().is_none());
        concurrent.close();
        store.close();
    }

    #[test]
    fn rejects_malformed_metadata_and_profile_traversal_without_writing() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let library = temporary.path().join("configLibrary");
        std::fs::create_dir_all(&library).unwrap();
        let meta = library.join("_meta.json");
        std::fs::write(&meta, "not JSON").unwrap();
        let mut store = ClaudeNative::new(
            temporary.path().join("state"),
            library.clone(),
            runtime.handle().clone(),
        );
        assert!(store.save(settings(19876, &DEFAULTS)).is_err());
        assert_eq!(std::fs::read_to_string(&meta).unwrap(), "not JSON");
        std::fs::write(&meta, json!({"appliedId": "../outside"}).to_string()).unwrap();
        let error = store.save(settings(19876, &DEFAULTS)).unwrap_err();
        assert!(error.to_string().contains("no valid active"));
        assert!(!temporary.path().join("state/claude-native.json").exists());
        store.close();
    }

    const DEFAULTS: [&str; 3] = rules::DEFAULT_RULES;
}
