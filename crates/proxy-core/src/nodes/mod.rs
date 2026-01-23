//! Node information persistence using JSON file.
//!
//! Stores node discovery information to disk for cluster awareness.
//!
//! # Node Sync Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Node Sync Flow                                   │
//! │                                                                         │
//! │  ┌─────────┐         ┌─────────┐         ┌─────────┐                   │
//! │  │ Node A  │◄───────►│ Node B  │◄───────►│ Node C  │                   │
//! │  └────┬────┘         └────┬────┘         └────┬────┘                   │
//! │       │                   │                   │                         │
//! │       ▼                   ▼                   ▼                         │
//! │  ┌─────────┐         ┌─────────┐         ┌─────────┐                   │
//! │  │nodes.json│        │nodes.json│        │nodes.json│                  │
//! │  └─────────┘         └─────────┘         └─────────┘                   │
//! │                                                                         │
//! │  Sync Protocol:                                                         │
//! │  1. Node starts → loads nodes.json                                      │
//! │  2. Change events broadcast SyncNodes to all known peers                │
//! │  3. Receives SyncNodes → merges peer list + blocked tombstones          │
//! │  4. Saves updated list to nodes.json (atomic write)                     │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # File Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "self": { "node_id": "...", "addr": "...", "started_at_ms": ... },
//!   "peers": [{ "node_id": "...", "addr": "...", "last_seen_ms": ... }],
//!   "blocked": ["node-id-a", "node-id-b"],
//!   "updated_at_ms": ...
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Node information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub addr: String,
    pub last_seen_ms: i64,
}

/// Node group for organizing nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeGroup {
    pub group_id: String,
    pub name: String,
    pub node_ids: Vec<String>,
    pub created_at_ms: i64,
}

/// Self node information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfNode {
    pub node_id: String,
    pub addr: String,
    pub started_at_ms: i64,
}

/// Persisted nodes file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodesFile {
    version: u32,
    #[serde(rename = "self")]
    self_node: Option<SelfNode>,
    peers: Vec<NodeInfo>,
    #[serde(default)]
    groups: Vec<NodeGroup>,
    #[serde(default)]
    blocked: Vec<String>,
    updated_at_ms: i64,
}

impl Default for NodesFile {
    fn default() -> Self {
        Self {
            version: 2,
            self_node: None,
            peers: Vec::new(),
            groups: Vec::new(),
            blocked: Vec::new(),
            updated_at_ms: current_time_ms(),
        }
    }
}

/// Node store with file persistence.
pub struct NodeStore {
    file_path: PathBuf,
    self_node: RwLock<Option<SelfNode>>,
    self_addrs: RwLock<Vec<String>>,
    peers: RwLock<HashMap<String, NodeInfo>>,
    groups: RwLock<HashMap<String, NodeGroup>>,
    /// Blocked peer node IDs to prevent re-sync from re-adding removed nodes.
    blocked: RwLock<HashSet<String>>,
    last_hash: RwLock<u64>,
}

impl NodeStore {
    /// Create a new node store with the given file path.
    pub fn new(file_path: impl AsRef<Path>) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
            self_node: RwLock::new(None),
            self_addrs: RwLock::new(Vec::new()),
            peers: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            blocked: RwLock::new(HashSet::new()),
            last_hash: RwLock::new(0),
        }
    }

    /// Create with default path (~/.proxy-everything/nodes.json).
    pub fn with_default_path() -> Self {
        let path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".proxy-everything")
            .join("nodes.json");
        Self::new(path)
    }

    /// Load nodes from disk.
    pub fn load(&self) -> std::io::Result<()> {
        if !self.file_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.file_path)?;
        let file: NodesFile = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        // Single write lock scope for self_node and self_addrs
        {
            let mut self_node = self.self_node.write().unwrap();
            let mut self_addrs = self.self_addrs.write().unwrap();
            *self_node = file.self_node;
            self_addrs.clear();
            if let Some(ref node) = *self_node {
                self_addrs.push(node.addr.clone());
            }
        }

        let mut peers = self.peers.write().unwrap();
        peers.clear();
        for peer in file.peers {
            peers.insert(peer.node_id.clone(), peer);
        }

        let mut groups = self.groups.write().unwrap();
        groups.clear();
        for group in file.groups {
            groups.insert(group.group_id.clone(), group);
        }

        let mut blocked = self.blocked.write().unwrap();
        blocked.clear();
        blocked.extend(file.blocked);

        Ok(())
    }

    /// Save nodes to disk (atomic write).
    ///
    /// Uses write-to-temp-then-rename pattern for atomicity.
    /// Cleans up temp file on failure.
    pub fn save(&self) -> std::io::Result<()> {
        let file = self.to_file();
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        // Check if content changed
        let hash = simple_hash(&content);
        {
            let mut last = self.last_hash.write().unwrap();
            if *last == hash {
                return Ok(());
            }
            *last = hash;
        }

        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Atomic write: write to temp file then rename
        let temp_path = self.file_path.with_extension("json.tmp");
        std::fs::write(&temp_path, &content)?;
        if let Err(e) = std::fs::rename(&temp_path, &self.file_path) {
            // Clean up temp file on rename failure
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }

        Ok(())
    }

    fn to_file(&self) -> NodesFile {
        let self_node = self.self_node.read().unwrap().clone();
        let peers: Vec<_> = self.peers.read().unwrap().values().cloned().collect();
        let groups: Vec<_> = self.groups.read().unwrap().values().cloned().collect();
        let blocked: Vec<_> = self.blocked.read().unwrap().iter().cloned().collect();
        NodesFile {
            version: 2,
            self_node,
            peers,
            groups,
            blocked,
            updated_at_ms: current_time_ms(),
        }
    }

    /// Set self node information.
    pub fn set_self(&self, node_id: String, addr: String) {
        let addr_clone = addr.clone();
        *self.self_node.write().unwrap() = Some(SelfNode {
            node_id,
            addr,
            started_at_ms: current_time_ms(),
        });
        let mut self_addrs = self.self_addrs.write().unwrap();
        self_addrs.clear();
        self_addrs.push(addr_clone);
    }

    /// Override self addresses (local/public). First address should be primary.
    pub fn set_self_addrs(&self, addrs: Vec<String>) {
        let mut unique = Vec::new();
        for addr in addrs {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                continue;
            }
            if unique.iter().any(|v| v == trimmed) {
                continue;
            }
            unique.push(trimmed.to_string());
        }
        let mut self_addrs = self.self_addrs.write().unwrap();
        self_addrs.clear();
        self_addrs.extend(unique);
    }

    /// Get self node information.
    pub fn get_self(&self) -> Option<SelfNode> {
        self.self_node.read().unwrap().clone()
    }

    /// Get self node ID.
    pub fn self_node_id(&self) -> Option<String> {
        self.self_node
            .read()
            .unwrap()
            .as_ref()
            .map(|n| n.node_id.clone())
    }

    /// Update or add a peer.
    pub fn upsert_peer(&self, peer: NodeInfo) {
        if self.is_self_addr(&peer.addr) {
            return;
        }
        if self.blocked.read().unwrap().contains(&peer.node_id) {
            return;
        }
        self.peers
            .write()
            .unwrap()
            .insert(peer.node_id.clone(), peer);
    }

    /// Update multiple peers.
    pub fn upsert_peers(&self, peers: Vec<NodeInfo>) {
        let self_id = self.self_node_id();
        let self_addrs = self.self_addrs.read().unwrap().clone();
        let blocked = self.blocked.read().unwrap().clone();
        let mut store = self.peers.write().unwrap();
        for mut peer in peers {
            // Don't store self as peer
            if self_id.as_ref() == Some(&peer.node_id) {
                continue;
            }
            if blocked.contains(&peer.node_id) {
                continue;
            }
            if self_addrs.iter().any(|addr| addr == &peer.addr) {
                continue;
            }
            // Update last_seen if newer
            if let Some(existing) = store.get(&peer.node_id)
                && existing.last_seen_ms > peer.last_seen_ms
            {
                peer.last_seen_ms = existing.last_seen_ms;
            }
            store.insert(peer.node_id.clone(), peer);
        }
    }

    /// Remove a peer.
    pub fn remove_peer(&self, node_id: &str) -> bool {
        self.peers.write().unwrap().remove(node_id).is_some()
    }

    /// Block a peer by node id and remove it from the active peer list.
    pub fn block_peer(&self, node_id: &str) -> bool {
        self.peers.write().unwrap().remove(node_id);
        for group in self.groups.write().unwrap().values_mut() {
            group.node_ids.retain(|id| id != node_id);
        }
        self.blocked.write().unwrap().insert(node_id.to_string())
    }

    /// Unblock a peer by node id so it can be re-added or synced again.
    pub fn unblock_peer(&self, node_id: &str) -> bool {
        self.blocked.write().unwrap().remove(node_id)
    }

    /// Check if a peer is blocked.
    pub fn is_blocked(&self, node_id: &str) -> bool {
        self.blocked.read().unwrap().contains(node_id)
    }

    /// Get a snapshot of blocked node IDs.
    pub fn blocked_list(&self) -> Vec<String> {
        self.blocked.read().unwrap().iter().cloned().collect()
    }

    /// Merge blocked node IDs and remove any matching peers/groups.
    pub fn merge_blocked(&self, blocked: Vec<String>) {
        if blocked.is_empty() {
            return;
        }
        let mut blocked_set = self.blocked.write().unwrap();
        let mut peers = self.peers.write().unwrap();
        let mut groups = self.groups.write().unwrap();
        for node_id in blocked {
            peers.remove(&node_id);
            for group in groups.values_mut() {
                group.node_ids.retain(|id| id != &node_id);
            }
            blocked_set.insert(node_id);
        }
    }

    /// Update peer's last_seen timestamp.
    pub fn update_peer_seen(&self, node_id: &str) {
        if let Some(peer) = self.peers.write().unwrap().get_mut(node_id) {
            peer.last_seen_ms = current_time_ms();
        }
    }

    /// List all peers.
    pub fn list_peers(&self) -> Vec<NodeInfo> {
        self.peers.read().unwrap().values().cloned().collect()
    }

    /// List all nodes (self + peers).
    pub fn list_all_nodes(&self) -> Vec<NodeInfo> {
        let mut nodes = Vec::new();
        if let Some(self_node) = self.self_node.read().unwrap().as_ref() {
            let self_addrs = self.self_addrs.read().unwrap().clone();
            let addrs = if self_addrs.is_empty() {
                vec![self_node.addr.clone()]
            } else {
                self_addrs
            };
            for addr in addrs {
                nodes.push(NodeInfo {
                    node_id: self_node.node_id.clone(),
                    addr,
                    last_seen_ms: current_time_ms(),
                });
            }
        }
        let self_addrs = self.self_addrs.read().unwrap().clone();
        nodes.extend(
            self.list_peers()
                .into_iter()
                .filter(|peer| !self_addrs.iter().any(|addr| addr == &peer.addr)),
        );
        nodes
    }

    /// Check if address belongs to this node.
    pub fn is_self_addr(&self, addr: &str) -> bool {
        self.self_addrs.read().unwrap().iter().any(|v| v == addr)
    }

    /// Clean up stale peers (not seen for given duration).
    pub fn cleanup_stale(&self, max_age_ms: i64) {
        let now = current_time_ms();
        let mut peers = self.peers.write().unwrap();
        peers.retain(|_, peer| now - peer.last_seen_ms < max_age_ms);
    }

    /// Get peer count.
    pub fn peer_count(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    // ========================================================================
    // Group management
    // ========================================================================

    /// Create a new group.
    pub fn create_group(&self, group_id: String, name: String) -> bool {
        let mut groups = self.groups.write().unwrap();
        if groups.contains_key(&group_id) {
            return false;
        }
        groups.insert(
            group_id.clone(),
            NodeGroup {
                group_id,
                name,
                node_ids: Vec::new(),
                created_at_ms: current_time_ms(),
            },
        );
        true
    }

    /// Delete a group.
    pub fn delete_group(&self, group_id: &str) -> bool {
        self.groups.write().unwrap().remove(group_id).is_some()
    }

    /// List all groups.
    pub fn list_groups(&self) -> Vec<NodeGroup> {
        self.groups.read().unwrap().values().cloned().collect()
    }

    /// Get a group by ID.
    pub fn get_group(&self, group_id: &str) -> Option<NodeGroup> {
        self.groups.read().unwrap().get(group_id).cloned()
    }

    /// Add a node to a group.
    pub fn add_node_to_group(&self, group_id: &str, node_id: String) -> bool {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            if !group.node_ids.contains(&node_id) {
                group.node_ids.push(node_id);
            }
            true
        } else {
            false
        }
    }

    /// Remove a node from a group.
    pub fn remove_node_from_group(&self, group_id: &str, node_id: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            let len_before = group.node_ids.len();
            group.node_ids.retain(|id| id != node_id);
            group.node_ids.len() != len_before
        } else {
            false
        }
    }

    /// Get all node addresses in a group.
    pub fn get_group_addrs(&self, group_id: &str) -> Vec<String> {
        let groups = self.groups.read().unwrap();
        let peers = self.peers.read().unwrap();
        let Some(group) = groups.get(group_id) else {
            return Vec::new();
        };
        group
            .node_ids
            .iter()
            .filter_map(|id| peers.get(id).map(|n| n.addr.clone()))
            .collect()
    }

    /// Get group count.
    pub fn group_count(&self) -> usize {
        self.groups.read().unwrap().len()
    }
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn simple_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn test_node_store() {
        let path = temp_dir().join("test_nodes.json");
        let store = NodeStore::new(&path);

        store.set_self("node-1".to_string(), "127.0.0.1:1081".to_string());
        store.upsert_peer(NodeInfo {
            node_id: "node-2".to_string(),
            addr: "127.0.0.2:1081".to_string(),
            last_seen_ms: current_time_ms(),
        });
        store.create_group("group-1".to_string(), "Group 1".to_string());
        store.add_node_to_group("group-1", "node-2".to_string());

        assert_eq!(store.self_node_id(), Some("node-1".to_string()));
        assert_eq!(store.peer_count(), 1);

        // Block peer and ensure it is removed.
        assert!(store.block_peer("node-2"));
        assert_eq!(store.peer_count(), 0);
        assert!(store.is_blocked("node-2"));
        let group = store.get_group("group-1").unwrap();
        assert!(group.node_ids.is_empty());

        store.save().unwrap();
        assert!(path.exists());

        // Load into new store
        let store2 = NodeStore::new(&path);
        store2.load().unwrap();
        assert_eq!(store2.self_node_id(), Some("node-1".to_string()));
        assert_eq!(store2.peer_count(), 0);
        assert!(store2.is_blocked("node-2"));

        // Unblock and re-add should succeed.
        assert!(store2.unblock_peer("node-2"));
        store2.upsert_peer(NodeInfo {
            node_id: "node-2".to_string(),
            addr: "127.0.0.2:1081".to_string(),
            last_seen_ms: current_time_ms(),
        });
        assert_eq!(store2.peer_count(), 1);

        std::fs::remove_file(&path).ok();
    }
}
