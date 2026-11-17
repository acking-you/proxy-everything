//! Website rules of the app's profile. One store per profile directory is
//! shared by the running proxy, the rules page and the local controller, so an
//! edit from any of them reaches new connections at once. The page can edit
//! rules while no proxy handle exists.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use proxy_client::controller::ApiError;
use proxy_client::site_rules::{Rule, RuleSet, RulesError, Site, SiteRules, Target};
use proxy_core::util::error_report;
use serde::Deserialize;

const FILE_NAME: &str = "website-rules.json";

pub(crate) fn open(directory: &Path) -> Result<Arc<SiteRules>, RulesError> {
    static PROFILES: LazyLock<Mutex<HashMap<PathBuf, Weak<SiteRules>>>> =
        LazyLock::new(Mutex::default);
    let path = directory.join(FILE_NAME);
    let mut profiles = PROFILES.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(rules) = profiles.get(&path).and_then(Weak::upgrade) {
        return Ok(rules);
    }
    profiles.retain(|_, rules| rules.strong_count() != 0);
    let rules = Arc::new(SiteRules::open(path.clone())?);
    profiles.insert(path, Arc::downgrade(&rules));
    Ok(rules)
}

/// A request from the rules page. A node target carries the endpoint the page
/// resolved from its catalogue.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum Change {
    List,
    Set { site: String, target: Target },
    Remove { site: String },
}

/// The rules after `change`, failing with the controller API's error kinds.
pub(crate) fn apply(directory: &Path, change: Change) -> Result<Arc<RuleSet>, ApiError> {
    let site = |site: String| site.parse::<Site>().map_err(|_| ApiError::InvalidRule);
    let edit = match change {
        Change::List => None,
        Change::Set {
            site: input,
            target,
        } => Some((site(input)?, Some(target))),
        Change::Remove { site: input } => Some((site(input)?, None)),
    };
    open(directory)
        .and_then(|rules| match edit {
            None => Ok(rules.snapshot()),
            Some((site, Some(target))) => rules.set(Rule { site, target }),
            Some((site, None)) => rules.remove(&site),
        })
        .map_err(|error| {
            tracing::warn!(error = %error_report(&error), "website rule operation failed");
            ApiError::from(error)
        })
}
