use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use proxy_client::client::tun::TunConfig;
use proxy_client::client::{ClientRuntimeConfig, ListenerSessions, serve_client_until_shutdown};
use proxy_client::controller::{Call, Command, Failure, NodeId, Reply, Selection, Server};
use proxy_core::config::runtime;
use proxy_core::upstream::UpstreamAddress;
use serde_json::{Value, json};
use tokio::net::TcpListener;

type Nodes = BTreeMap<NodeId, Vec<UpstreamAddress>>;

struct Client {
    nodes: Nodes,
    active_id: NodeId,
    active: UpstreamAddress,
    local_port: u16,
    sessions: ListenerSessions,
    sites: std::sync::Arc<proxy_client::site_routes::Store>,
    tun: Option<TunConfig>,
    #[cfg(windows)]
    udp: bool,
}

fn endpoint(address: &UpstreamAddress) -> Value {
    json!({"host":address.host, "port":address.port, "transport":address.carrier})
}

impl Client {
    fn status(&self) -> Value {
        json!({"running":true, "local_port":self.local_port, "active":{
            "node_id": self.active_id, "endpoint":endpoint(&self.active)
        }})
    }

    fn lookup(
        &self,
        id: &NodeId,
        carrier: proxy_core::upstream::Carrier,
    ) -> Result<&UpstreamAddress, Failure> {
        self.nodes
            .get(id)
            .ok_or(Failure::UnknownNode)?
            .iter()
            .find(|address| address.carrier == carrier)
            .ok_or(Failure::UnsupportedTransport)
    }

    async fn update_rule(
        &self,
        site: proxy_client::site_routes::Site,
        target: Option<proxy_client::site_routes::Target>,
    ) -> Reply {
        let sites = self.sites.clone();
        tokio::task::spawn_blocking(move || sites.update(site, target))
            .await
            .map_err(|_| Failure::Unavailable)?
            .map_err(Failure::from)
    }

    async fn dispatch(&mut self, command: Command) -> Reply {
        match command {
            Command::Rules => Ok(self.sites.view()),
            Command::SetRule(rule) => {
                use proxy_client::controller::RuleTarget;
                use proxy_client::site_routes::Target;
                let target = match rule.target {
                    RuleTarget::Direct => Target::Direct,
                    RuleTarget::Node { node_id, transport } => {
                        let endpoint = self.lookup(&node_id, transport)?.clone();
                        Target::Node { node_id, endpoint }
                    }
                };
                self.update_rule(rule.site, Some(target)).await
            }
            Command::RemoveRule { site } => self.update_rule(site, None).await,
            Command::Status => Ok(self.status()),
            Command::Nodes => Ok(json!({"nodes": self.nodes.iter().map(|(id, addresses)| {
                json!({"id": id, "endpoints": addresses.iter().map(endpoint).collect::<Vec<_>>()})
            }).collect::<Vec<_>>() })),
            Command::Switch(Selection {
                node_id,
                transport,
                close_existing,
            }) => {
                let selected = self.lookup(&node_id, transport)?;
                if self.active != *selected {
                    if let Some(tun) = &self.tun {
                        #[cfg(windows)]
                        {
                            let prepared = tun
                                .bypass
                                .prepare_upstream(
                                    &selected.qualified_host(),
                                    selected.port,
                                    self.udp,
                                )
                                .await
                                .and_then(|p| p.commit());
                            if let Err(error) = prepared {
                                tracing::warn!(?error, "failed to prepare upstream route");
                                return Err(Failure::SwitchFailed);
                            }
                        }
                        #[cfg(not(windows))]
                        {
                            let _ = tun;
                            if !self.active.host.eq_ignore_ascii_case(&selected.host) {
                                tracing::warn!(
                                    "stop CLI TUN capture before changing the upstream host"
                                );
                                return Err(Failure::SwitchFailed);
                            }
                        }
                    }
                    runtime::set_server_endpoint(selected.qualified_host(), selected.port);
                    self.active = selected.clone();
                }
                self.active_id = node_id;
                if close_existing {
                    self.sessions.close_existing();
                }
                Ok(self.status())
            }
        }
    }
}

pub(super) async fn run(
    port: u16,
    configured: BTreeMap<NodeId, Vec<String>>,
    listen_host: &str,
    client_port: u16,
    config: ClientRuntimeConfig,
    sites: std::sync::Arc<proxy_client::site_routes::Store>,
) -> Result<()> {
    let active = runtime::server_endpoint();
    let active = UpstreamAddress::from_host(&active.host, active.port)?;
    let mut nodes = Nodes::new();
    for (id, entries) in configured {
        ensure!(
            id != NodeId::startup(),
            "startup is reserved for the initial CLI endpoint"
        );
        ensure!(!entries.is_empty(), "node {id} needs at least one endpoint");
        let mut addresses = Vec::<UpstreamAddress>::new();
        for entry in entries {
            let address = UpstreamAddress::parse(&entry)
                .with_context(|| format!("invalid controller endpoint for {id}"))?;
            ensure!(
                addresses.iter().all(|a| a.carrier != address.carrier),
                "duplicate transport for node {id}"
            );
            addresses.push(address);
        }
        nodes.insert(id, addresses);
    }
    let active_id = nodes
        .iter()
        .find(|(_, entries)| entries.contains(&active))
        .map(|(id, _)| id.clone())
        .unwrap_or_else(|| {
            let id = NodeId::startup();
            nodes.insert(id.clone(), vec![active.clone()]);
            id
        });
    let token = std::env::var("CIPHERRELAY_CONTROLLER_TOKEN")
        .context("Set CIPHERRELAY_CONTROLLER_TOKEN before enabling the controller")?;
    let (server, mut calls) = Server::bind(port, token)
        .await
        .context("bind local controller")?;
    let listener = TcpListener::bind((listen_host, client_port))
        .await
        .context("bind local proxy")?;
    let mut sessions = ListenerSessions::default();
    sessions.sites = Some(sites.clone());
    let mut client = Client {
        nodes,
        active_id,
        active,
        local_port: listener.local_addr()?.port(),
        sessions: sessions.clone(),
        sites,
        tun: config.tun.clone(),
        #[cfg(windows)]
        udp: config.client.enable_udp,
    };
    eprintln!("Local controller: http://127.0.0.1:{}", server.port()?);
    let control = async {
        let dispatch = async {
            while let Some(Call { command, reply }) = calls.recv().await {
                if !reply.is_closed() {
                    let _ = reply.send(client.dispatch(command).await);
                }
            }
        };
        tokio::select! {
            result = server.serve() => if let Err(error) = result {
                tracing::error!(?error, "local controller stopped");
            },
            () = dispatch => {}
        }
    };
    let proxy = serve_client_until_shutdown(listener, Some(config), Some(sessions));
    tokio::pin!(proxy);
    tokio::select! {
        result = &mut proxy => result?,
        () = control => proxy.await?,
    }
    Ok(())
}
