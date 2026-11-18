//! The CLI side of the local controller: a fixed catalogue from the profile,
//! and switching by replacing the runtime upstream of the running listener.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use proxy_client::client::tun::TunConfig;
use proxy_client::client::{ClientRuntimeConfig, ListenerDrain, serve_client_until_shutdown};
use proxy_client::controller::{
    Active, ApiError, Controller, Host, Node, Selection, Status, Token,
};
use proxy_client::site_rules::{NodeId, SiteRules};
use proxy_core::config::runtime;
use proxy_core::upstream::{Carrier, UpstreamAddress};
use tokio::net::TcpListener;

/// Names the initial endpoint when the profile lists no node for it.
const STARTUP_NODE: &str = "startup";

struct CliHost {
    catalogue: BTreeMap<NodeId, Vec<UpstreamAddress>>,
    local_port: u16,
    active: Mutex<(NodeId, UpstreamAddress)>,
    /// Held across route preparation, so a second switch is refused.
    switching: tokio::sync::Mutex<()>,
    drain: ListenerDrain,
    tun: Option<TunConfig>,
    #[cfg(windows)]
    udp: bool,
}

impl CliHost {
    fn active(&self) -> std::sync::MutexGuard<'_, (NodeId, UpstreamAddress)> {
        self.active.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn current(&self) -> Status {
        let (node_id, endpoint) = self.active().clone();
        Status {
            running: true,
            local_port: Some(self.local_port),
            active: Some(Active {
                node_id: Some(node_id),
                endpoint,
            }),
        }
    }

    /// A TUN capture holds a route exception for the upstream host, which has
    /// to move before new connections may use another host.
    async fn reroute(&self, from: &UpstreamAddress, to: &UpstreamAddress) -> Result<(), ApiError> {
        let Some(tun) = &self.tun else {
            return Ok(());
        };
        #[cfg(windows)]
        {
            let _ = from;
            tun.bypass
                .prepare_upstream(&to.qualified_host(), to.port, self.udp)
                .await
                .and_then(|prepared| prepared.commit())
                .map_err(|error| {
                    tracing::warn!(%error, "could not route the selected upstream around TUN");
                    ApiError::SwitchFailed
                })
        }
        #[cfg(not(windows))]
        {
            let _ = tun;
            if from.host.eq_ignore_ascii_case(&to.host) {
                Ok(())
            } else {
                tracing::warn!("stop CLI TUN capture before changing the upstream host");
                Err(ApiError::SwitchFailed)
            }
        }
    }
}

impl Host for CliHost {
    async fn nodes(&self) -> Result<Vec<Node>, ApiError> {
        Ok(self
            .catalogue
            .iter()
            .map(|(id, endpoints)| Node {
                id: id.clone(),
                endpoints: endpoints.clone(),
            })
            .collect())
    }

    async fn status(&self) -> Result<Status, ApiError> {
        Ok(self.current())
    }

    async fn switch(&self, selection: Selection) -> Result<Status, ApiError> {
        let Selection {
            node_id,
            transport,
            close_existing,
        } = selection;
        let _switching = self.switching.try_lock().map_err(|_| ApiError::Busy)?;
        let selected = self
            .catalogue
            .get(&node_id)
            .ok_or(ApiError::UnknownNode)?
            .iter()
            .find(|endpoint| endpoint.carrier == transport)
            .ok_or(ApiError::UnsupportedTransport)?
            .clone();
        let current = self.active().1.clone();
        if current != selected {
            self.reroute(&current, &selected).await?;
            runtime::set_server_endpoint(selected.qualified_host(), selected.port);
        }
        *self.active() = (node_id, selected);
        if close_existing {
            self.drain.drain();
        }
        Ok(self.current())
    }
}

/// Parse `[controller_nodes]`, at most one endpoint per carrier and node.
fn catalogue(
    configured: BTreeMap<NodeId, Vec<String>>,
) -> Result<BTreeMap<NodeId, Vec<UpstreamAddress>>> {
    configured
        .into_iter()
        .map(|(id, entries)| {
            ensure!(
                id.as_str() != STARTUP_NODE,
                "{STARTUP_NODE} is reserved for the initial CLI endpoint"
            );
            ensure!(!entries.is_empty(), "node {id} needs at least one endpoint");
            let mut endpoints: Vec<UpstreamAddress> = Vec::with_capacity(entries.len());
            for entry in entries {
                let endpoint = UpstreamAddress::parse(&entry)
                    .with_context(|| format!("invalid controller endpoint for {id}"))?;
                ensure!(
                    endpoints.iter().all(|e| e.carrier != endpoint.carrier),
                    "node {id} lists more than one {} endpoint",
                    match endpoint.carrier {
                        Carrier::Tcp => "TCP",
                        Carrier::Quic => "QUIC",
                    }
                );
                endpoints.push(endpoint);
            }
            Ok((id, endpoints))
        })
        .collect()
}

/// Serve the proxy on `listener` with the controller beside it, until shutdown.
pub(super) async fn run(
    port: u16,
    configured: BTreeMap<NodeId, Vec<String>>,
    listener: TcpListener,
    mut config: ClientRuntimeConfig,
    rules: Arc<SiteRules>,
) -> Result<()> {
    let token = std::env::var("CIPHERRELAY_CONTROLLER_TOKEN")
        .context("Set CIPHERRELAY_CONTROLLER_TOKEN before enabling the controller")?;
    let token = Token::try_from(token)?;
    let mut catalogue = catalogue(configured)?;
    let initial = runtime::server_endpoint();
    let initial = UpstreamAddress::from_host(&initial.host, initial.port)?;
    let active_id = match catalogue
        .iter()
        .find(|(_, endpoints)| endpoints.contains(&initial))
    {
        Some((id, _)) => id.clone(),
        None => {
            let id = NodeId::try_from(STARTUP_NODE.to_owned())?;
            catalogue.insert(id.clone(), vec![initial.clone()]);
            id
        }
    };
    let drain = ListenerDrain::default();
    config.drain = Some(drain.clone());
    let host = CliHost {
        catalogue,
        local_port: listener.local_addr()?.port(),
        active: Mutex::new((active_id, initial)),
        switching: tokio::sync::Mutex::new(()),
        drain,
        tun: config.tun.clone(),
        #[cfg(windows)]
        udp: config.client.enable_udp,
    };
    let controller = Controller::bind(port, token, host, rules).await?;
    eprintln!("Local controller: http://{}", controller.local_addr()?);
    tokio::select! {
        result = serve_client_until_shutdown(listener, Some(config)) => result?,
        () = controller.serve() => {}
    }
    Ok(())
}
