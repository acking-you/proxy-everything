# Batch node probes

Testing a node asks an echo service, through that node, where its traffic
leaves from and how long the round trip took (`crates/proxy-ffi/src/probe.rs`).
`proxy_probe_node_v3` does this for one node and blocks its caller until the
node answers or times out. The Flutter UI therefore ran every probe in its own
isolate: testing a country of 30 nodes meant 30 isolate spawns, and up to eight
VM threads parked in native code for the full timeout of every dead node.

`proxy_probe_nodes_v1` probes a whole batch without blocking:

```c
typedef void (*NodeProbeCallback)(uint64_t batch, uint32_t index,
                                  NodeProbeResult *result);

int32_t proxy_probe_nodes_v1(const char *const *hosts, const uint16_t *ports,
                             uint32_t count, uint32_t concurrency,
                             uint32_t timeout_ms, int32_t wire_protocol,
                             NodeProbeCallback callback, uint64_t batch);
void proxy_release_node_probe_result(NodeProbeResult *result);
```

- It copies the hosts and ports and returns at once: `0`, `-1` for invalid
  arguments, `-3` when no runtime is available. The callback is never invoked
  unless it returned `0`, and an empty batch returns `0` without callbacks.
- Probes are tasks on the shared control runtime, at most `concurrency`
  (clamped to 1..64) at a time, admitted in order by a fair semaphore. Each
  probe's `timeout_ms` (0 means the 10 s default) starts when it is admitted,
  so queueing never eats into a node's measured latency or its deadline.
- `callback` receives every index exactly once, in completion order, from a
  runtime thread. A delivery guard reports a failure for a probe that panics or
  whose task is dropped, so a caller counting results can never wait forever.
- Ownership of `result` moves to the callee, which releases it with
  `proxy_release_node_probe_result`. `batch` is the caller's own routing id.
- A null or non-UTF-8 host fails that index alone with the same message the
  single-node probe gives. At most 4,096 targets are accepted.
- Interior NUL bytes in an echoed address are dropped rather than aborting the
  process across the FFI boundary; this applies to the single-node probe too.

Dart keeps one `NativeCallable.listener` for the isolate's lifetime, like the
log callback, and routes results to each batch's stream by id. On a native
library without this export the UI falls back to the per-node isolate path,
eight at a time, so older libraries keep working.

```sh
cargo test -p proxy-ffi --lib probe
```

The batch tests use a local listener that accepts and never answers: every
index is delivered once, a null host fails alone, and with a limit of two the
third connection is accepted only after the first pair timed out. Invalid
arguments are rejected without a callback. See the UI's
`docs/galaxy-performance.md` for the end-to-end effect on rendering.
