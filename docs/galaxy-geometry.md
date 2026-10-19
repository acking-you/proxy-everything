# Galaxy geometry

`crates/galaxy-geometry` computes perspective projection, near-plane clipping and
Liang–Barsky viewport clipping for stable world-space orbit segments. Flutter
prepares the orbit meshes once per scene, reuses caller-owned buffers and submits
the visible results as GPU line batches. Sphere lighting, flags and halos are
cached as textures; equal-texture nodes use atlas batches. These paths are shared
by Windows, macOS, Linux, Android and iOS.

`proxy-ffi` exports `proxy_galaxy_project_segments_v1` without creating a proxy
handle, runtime, task or thread. The call does no allocation, locking, I/O or
callbacks, so Dart invokes it as a leaf FFI call. The input is bounded to 100,000
segments. All pointers must be aligned, valid for their declared lengths and
nonoverlapping; the caller retains ownership. A zero-length input accepts null
input/output pointers. The return value is the visible count, or -1 for invalid
arguments, -2 for insufficient output capacity, -3 for an invalid camera.

The versioned C layout is:

| Buffer | Layout | Bytes per entry |
| --- | --- | ---: |
| Camera | 20 doubles: eye, right, up, forward, center X/Y, focal, near, left/top/right/bottom | 160 |
| World segment | 6 doubles for endpoints, u32 group, u32 reserved (zero) | 56 |
| Screen segment | 4 floats for endpoints, u32 group, float midpoint depth | 24 |

Near-plane clipping precedes perspective division. Both endpoints outside the
viewport can still produce a visible crossing. Nonfinite segments are discarded;
invalid camera/capacity errors do not write partial results. Group IDs survive
clipping, and midpoint depth selects each orbit's front/back draw pass. Float64
projection prevents precision loss while clipping large offscreen coordinates;
Float32 output matches Flutter's GPU line buffers.

This is an additive FFI export with no proxy protocol, runtime or allocator
changes. Older native libraries use the tested Dart geometry fallback. Dart frees
only its own `calloc` buffers, on scene replacement, backgrounding and disposal.

```powershell
cargo test -p galaxy-geometry
cargo test -p proxy-ffi galaxy
cargo run -p galaxy-geometry --release --example bench_projection
$env:GALAXY_NATIVE_LIBRARY = "$PWD/target/release/http_proxy.dll"
Set-Location ui/flutter
fvm flutter test test/galaxy_geometry_test.dart
```

The integration test invokes the real Rust export and compares 2,001 segments
across 12 cameras with the Dart fallback. The compute benchmark excludes mesh
creation and allocation. On the development Windows host it measured 6.3 µs
for 512 segments, 48.6 µs for 4,096 and 140.1 µs for 16,384. These are compute
costs, not end-to-end frame times; rasterization remains the dominant cost.
Parallelism or SIMD dependencies should be evaluated against these workloads
before adding scheduling/packing overhead. See the UI's
`docs/galaxy-performance.md` for hierarchy and lifecycle measurements.
