# Proxy Data Dir Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Isolate persisted server state per instance by adding `PROXY_DATA_DIR` support and teaching the systemd installer to assign a unique state directory for custom service names.

**Architecture:** Add one shared state-directory resolver in `proxy-core`, then route both node and relay persistence through it. Keep the legacy default path for the default `proxy-server` install, while the installer assigns per-service directories for non-default service names unless the operator overrides `PROXY_DATA_DIR`.

**Tech Stack:** Rust workspace, Bash systemd installer, Markdown docs

---

### Task 1: Add a shared state-directory resolver

**Files:**
- Modify: `crates/proxy-core/src/config/mod.rs`
- Test: `crates/proxy-core/src/config/mod.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn test_proxy_data_dir_override_wins() {
    // Set PROXY_DATA_DIR and assert the resolver returns it unchanged.
}

#[test]
fn test_proxy_data_dir_default_falls_back_to_home_proxy_everything() {
    // Clear PROXY_DATA_DIR and assert the resolver returns ~/.proxy-everything.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p proxy-core test_proxy_data_dir -- --nocapture`
Expected: FAIL because the shared resolver does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```rust
pub fn proxy_data_dir() -> Option<PathBuf> { ... }
pub fn default_state_dir() -> PathBuf { ... }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p proxy-core test_proxy_data_dir -- --nocapture`
Expected: PASS

### Task 2: Route node and relay persistence through the shared resolver

**Files:**
- Modify: `crates/proxy-core/src/nodes/mod.rs`
- Modify: `crates/proxy-server/src/server/relay.rs`

- [ ] **Step 1: Replace inline default-path logic**

```rust
let path = crate::config::default_state_dir().join("nodes.json");
```

```rust
fn default_config_dir() -> PathBuf {
    proxy_core::config::default_state_dir()
}
```

- [ ] **Step 2: Run targeted tests**

Run: `cargo test -p proxy-core test_proxy_data_dir -- --nocapture`
Expected: PASS

### Task 3: Make the systemd installer assign isolated state per service

**Files:**
- Modify: `scripts/install-proxy-server.sh`

- [ ] **Step 1: Compute the state directory**

```bash
if [ "$SERVICE_NAME" = "$DEFAULT_SERVICE_NAME" ]; then
  STATE_DIR="${PROXY_DATA_DIR:-${INSTALL_DIR}/conf/.proxy-everything}"
else
  STATE_DIR="${PROXY_DATA_DIR:-${INSTALL_DIR}/state/${SERVICE_NAME}}"
fi
```

- [ ] **Step 2: Export it to systemd**

```bash
Environment=PROXY_DATA_DIR=${STATE_DIR}
```

- [ ] **Step 3: Show operators the chosen state path**

```bash
info "  - State dir: $STATE_DIR"
```

### Task 4: Update docs and verify the end state

**Files:**
- Modify: `docs/server-deployment.md`
- Modify: `docs/systemd-deployment.md`

- [ ] **Step 1: Document `PROXY_DATA_DIR` and multi-instance behavior**

```md
| `PROXY_DATA_DIR` | No | `~/.proxy-everything` | Override persisted relay/node state directory |
```

- [ ] **Step 2: Run focused verification**

Run: `cargo test -p proxy-core test_proxy_data_dir -- --nocapture`
Expected: PASS

Run: `cargo test -p proxy-server relay::tests::test_relay_manager -- --nocapture`
Expected: PASS
