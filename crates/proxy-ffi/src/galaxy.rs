//! Stateless UI math. The caller owns every buffer; no proxy runtime is needed.

use galaxy_geometry::{Camera, ProjectionError, ScreenSegment, WorldSegment, project_segments};

const MAX_SEGMENTS: usize = 100_000;

/// Project and clip a batch, returning its visible count, or -1 for invalid
/// arguments, -2 for insufficient output capacity, -3 for an invalid camera.
/// Work is bounded and allocation-free, so this is safe for Dart's leaf FFI.
///
/// # Safety
/// `camera` must point to one initialized, aligned Camera. For nonempty input,
/// `input` must contain `count` initialized WorldSegments and `output` must be
/// writable for `capacity` ScreenSegments. These regions must not overlap and
/// must remain valid for the call. The caller retains ownership of all memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_galaxy_project_segments_v1(
    camera: *const Camera,
    input: *const WorldSegment,
    count: u32,
    output: *mut ScreenSegment,
    capacity: u32,
) -> i32 {
    let count = count as usize;
    let capacity = capacity as usize;
    if camera.is_null() || !camera.is_aligned() || count > MAX_SEGMENTS || capacity > MAX_SEGMENTS {
        return -1;
    }
    if capacity < count {
        return -2;
    }
    // SAFETY: caller guarantees a valid initialized camera.
    let camera = unsafe { &*camera };
    if !camera.valid() {
        return -3;
    }
    if count == 0 {
        return 0;
    }
    if input.is_null() || output.is_null() || !input.is_aligned() || !output.is_aligned() {
        return -1;
    }
    // SAFETY: caller guarantees valid, nonoverlapping buffers. Only count
    // entries are needed; a larger output capacity is never accessed.
    let input = unsafe { std::slice::from_raw_parts(input, count) };
    let output = unsafe { std::slice::from_raw_parts_mut(output, count) };
    match project_segments(camera, input, output) {
        Ok(count) => count as i32,
        Err(ProjectionError::InvalidCamera) => -3,
        Err(ProjectionError::OutputTooSmall) => -2,
    }
}

#[cfg(test)]
mod tests {
    use galaxy_geometry::Vec3;

    use super::*;

    #[test]
    fn dart_buffer_layout_is_stable() {
        assert_eq!(size_of::<Camera>(), 160);
        assert_eq!(size_of::<WorldSegment>(), 56);
        assert_eq!(size_of::<ScreenSegment>(), 24);
        assert_eq!(std::mem::offset_of!(WorldSegment, group), 48);
        assert_eq!(std::mem::offset_of!(ScreenSegment, depth), 20);
    }

    #[test]
    fn ffi_rejects_invalid_buffers_and_projects_without_a_proxy_handle() {
        let camera = Camera {
            eye: Vec3::default(),
            right: Vec3 {
                x: 1.0,
                ..Vec3::default()
            },
            up: Vec3 {
                y: 1.0,
                ..Vec3::default()
            },
            forward: Vec3 {
                z: 1.0,
                ..Vec3::default()
            },
            center_x: 50.0,
            center_y: 50.0,
            focal: 50.0,
            near: 0.2,
            left: 0.0,
            top: 0.0,
            right_edge: 100.0,
            bottom: 100.0,
        };
        let input = WorldSegment {
            start: Vec3 {
                x: -10.0,
                z: 1.0,
                ..Vec3::default()
            },
            end: Vec3 {
                x: 10.0,
                z: 1.0,
                ..Vec3::default()
            },
            group: 7,
            reserved: 0,
        };
        let mut output = ScreenSegment::default();
        // SAFETY: all non-null arguments below refer to properly sized local
        // objects; invalid null inputs are rejected before dereference.
        unsafe {
            assert_eq!(
                proxy_galaxy_project_segments_v1(std::ptr::null(), &input, 1, &mut output, 1),
                -1
            );
            assert_eq!(
                proxy_galaxy_project_segments_v1(&camera, &input, 1, &mut output, 0),
                -2
            );
            assert_eq!(
                proxy_galaxy_project_segments_v1(&camera, std::ptr::null(), 1, &mut output, 1),
                -1
            );
            assert_eq!(
                proxy_galaxy_project_segments_v1(&camera, &input, 1, &mut output, 1),
                1
            );
            assert_eq!(
                proxy_galaxy_project_segments_v1(
                    &camera,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0
                ),
                0
            );
        }
        assert_eq!((output.x0, output.x1, output.group), (0.0, 100.0, 7));
    }
}
