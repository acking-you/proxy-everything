//! Bounded, allocation-free projection and viewport clipping for the galaxy UI.
//!
//! This crate has no proxy, platform, allocator or graphics dependencies. Callers
//! prepare stable world-space geometry once and reuse their output buffers.

pub mod bodies;
pub mod layout;

/// A world-space position, or a camera-space direction.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    fn dot(self, other: Self) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    fn relative_to(self, origin: Self) -> Self {
        Self {
            x: self.x - origin.x,
            y: self.y - origin.y,
            z: self.z - origin.z,
        }
    }

    fn lerp(self, other: Self, t: f64) -> Self {
        Self {
            x: self.x + (other.x - self.x) * t,
            y: self.y + (other.y - self.y) * t,
            z: self.z + (other.z - self.z) * t,
        }
    }

    fn finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }
}

/// The basis is orthonormal and points from the eye towards the camera target.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Camera {
    pub eye: Vec3,
    pub right: Vec3,
    pub up: Vec3,
    pub forward: Vec3,
    pub center_x: f64,
    pub center_y: f64,
    pub focal: f64,
    pub near: f64,
    pub left: f64,
    pub top: f64,
    pub right_edge: f64,
    pub bottom: f64,
}

impl Camera {
    pub fn valid(&self) -> bool {
        self.eye.finite()
            && self.right.finite()
            && self.up.finite()
            && self.forward.finite()
            && [
                self.center_x,
                self.center_y,
                self.focal,
                self.near,
                self.left,
                self.top,
                self.right_edge,
                self.bottom,
            ]
            .into_iter()
            .all(f64::is_finite)
            && self.near > 0.0
            && self.focal > 0.0
            && self.left < self.right_edge
            && self.top < self.bottom
    }

    fn camera_space(&self, point: Vec3) -> Vec3 {
        let p = point.relative_to(self.eye);
        Vec3 {
            x: p.dot(self.right),
            y: p.dot(self.up),
            z: p.dot(self.forward),
        }
    }

    fn screen(&self, p: Vec3) -> (f64, f64) {
        let scale = self.focal / p.z;
        (self.center_x + p.x * scale, self.center_y - p.y * scale)
    }
}

/// One independent world-space segment. Group is copied through clipping so
/// callers can draw an entire orbit/style using one GPU line batch.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WorldSegment {
    pub start: Vec3,
    pub end: Vec3,
    pub group: u32,
    pub reserved: u32,
}

/// Two endpoints clipped to the viewport. No offscreen path metrics are needed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ScreenSegment {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
    pub group: u32,
    /// Midpoint camera depth, for sorting orbit halves around their star.
    pub depth: f32,
}

/// Invalid inputs are rejected before writing; insufficient capacity cannot
/// produce a partial frame. Nonfinite individual segments are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    InvalidCamera,
    OutputTooSmall,
}

/// Project a batch with near-plane clipping followed by Liang–Barsky viewport
/// clipping. Work is linear in the input, regardless of magnification or the
/// size of the projected coordinates. No heap allocation, I/O, locks or waits.
pub fn project_segments(
    camera: &Camera,
    input: &[WorldSegment],
    output: &mut [ScreenSegment],
) -> Result<usize, ProjectionError> {
    if !camera.valid() {
        return Err(ProjectionError::InvalidCamera);
    }
    if output.len() < input.len() {
        return Err(ProjectionError::OutputTooSmall);
    }
    let mut count = 0;
    for segment in input {
        if let Some(projected) = project_segment(camera, segment) {
            output[count] = projected;
            count += 1;
        }
    }
    Ok(count)
}

fn project_segment(camera: &Camera, segment: &WorldSegment) -> Option<ScreenSegment> {
    if !segment.start.finite() || !segment.end.finite() {
        return None;
    }
    let mut a = camera.camera_space(segment.start);
    let mut b = camera.camera_space(segment.end);
    if a.z < camera.near && b.z < camera.near {
        return None;
    }
    if a.z < camera.near {
        a = a.lerp(b, (camera.near - a.z) / (b.z - a.z));
        a.z = camera.near;
    } else if b.z < camera.near {
        b = b.lerp(a, (camera.near - b.z) / (a.z - b.z));
        b.z = camera.near;
    }
    let (x0, y0) = camera.screen(a);
    let (x1, y1) = camera.screen(b);
    let dx = x1 - x0;
    let dy = y1 - y0;
    if ![x0, y0, dx, dy].into_iter().all(f64::is_finite) {
        return None;
    }
    let mut enter: f64 = 0.0;
    let mut leave: f64 = 1.0;
    for (p, q) in [
        (-dx, x0 - camera.left),
        (dx, camera.right_edge - x0),
        (-dy, y0 - camera.top),
        (dy, camera.bottom - y0),
    ] {
        if p == 0.0 {
            if q < 0.0 {
                return None;
            }
        } else {
            let t = q / p;
            if p < 0.0 {
                enter = enter.max(t);
            } else {
                leave = leave.min(t);
            }
            if enter > leave {
                return None;
            }
        }
    }
    Some(ScreenSegment {
        x0: (x0 + dx * enter).clamp(camera.left, camera.right_edge) as f32,
        y0: (y0 + dy * enter).clamp(camera.top, camera.bottom) as f32,
        x1: (x0 + dx * leave).clamp(camera.left, camera.right_edge) as f32,
        y1: (y0 + dy * leave).clamp(camera.top, camera.bottom) as f32,
        group: segment.group,
        depth: ((a.z + b.z) * 0.5) as f32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn camera() -> Camera {
        Camera {
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
        }
    }

    #[test]
    fn crossing_viewport_is_clipped_even_when_both_endpoints_are_outside() {
        let segment = WorldSegment {
            start: Vec3 {
                x: -1e6,
                y: 0.0,
                z: 1.0,
            },
            end: Vec3 {
                x: 1e6,
                y: 0.0,
                z: 1.0,
            },
            group: 17,
            reserved: 0,
        };
        let mut output = [ScreenSegment::default()];
        assert_eq!(project_segments(&camera(), &[segment], &mut output), Ok(1));
        assert_eq!(
            output[0],
            ScreenSegment {
                x0: 0.0,
                y0: 50.0,
                x1: 100.0,
                y1: 50.0,
                group: 17,
                depth: 1.0
            }
        );
    }

    #[test]
    fn near_plane_crossing_preserves_the_visible_part() {
        let segment = WorldSegment {
            start: Vec3 {
                x: -0.1,
                y: 0.0,
                z: -1.0,
            },
            end: Vec3 {
                x: 0.2,
                y: 0.0,
                z: 2.0,
            },
            ..WorldSegment::default()
        };
        let mut output = [ScreenSegment::default()];
        assert_eq!(project_segments(&camera(), &[segment], &mut output), Ok(1));
        assert_eq!((output[0].x0, output[0].x1), (55.0, 55.0));
    }

    #[test]
    fn fully_hidden_and_nonfinite_segments_are_discarded() {
        let input = [
            WorldSegment {
                start: Vec3 {
                    z: -1.0,
                    ..Vec3::default()
                },
                end: Vec3 {
                    z: -2.0,
                    ..Vec3::default()
                },
                ..WorldSegment::default()
            },
            WorldSegment {
                start: Vec3 {
                    x: f64::NAN,
                    z: 1.0,
                    ..Vec3::default()
                },
                end: Vec3 {
                    z: 1.0,
                    ..Vec3::default()
                },
                ..WorldSegment::default()
            },
            WorldSegment {
                start: Vec3 {
                    x: 8.0,
                    z: 1.0,
                    ..Vec3::default()
                },
                end: Vec3 {
                    x: 9.0,
                    z: 1.0,
                    ..Vec3::default()
                },
                ..WorldSegment::default()
            },
        ];
        assert_eq!(
            project_segments(&camera(), &input, &mut [ScreenSegment::default(); 3]),
            Ok(0)
        );
    }

    #[test]
    fn invalid_camera_and_short_output_do_not_write() {
        let mut camera = camera();
        let sentinel = ScreenSegment {
            group: 42,
            ..ScreenSegment::default()
        };
        let mut output = [sentinel];
        camera.near = 0.0;
        assert_eq!(
            project_segments(&camera, &[], &mut output),
            Err(ProjectionError::InvalidCamera)
        );
        assert_eq!(output[0], sentinel);
        camera.near = 0.2;
        assert_eq!(
            project_segments(&camera, &[WorldSegment::default(); 2], &mut output),
            Err(ProjectionError::OutputTooSmall)
        );
        assert_eq!(output[0], sentinel);
    }
}
