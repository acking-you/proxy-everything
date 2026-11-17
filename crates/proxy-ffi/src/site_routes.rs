use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use proxy_client::site_routes::{Store, StoreError, Target};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Edit {
    pub site: String,
    pub target: Option<Target>,
}

/// A stopped app can edit its profile before a native proxy handle exists.
/// Live handles using the same profile share the published route snapshot.
pub(crate) fn open(directory: &Path) -> Result<Arc<Store>, StoreError> {
    static PROFILES: LazyLock<Mutex<HashMap<PathBuf, Weak<Store>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let path = directory.join("website-rules.json");
    let mut profiles = PROFILES.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(store) = profiles.get(&path).and_then(Weak::upgrade) {
        return Ok(store);
    }
    profiles.retain(|_, entry| entry.strong_count() != 0);
    let store = Arc::new(Store::open(path.clone())?);
    profiles.insert(path, Arc::downgrade(&store));
    Ok(store)
}
