//! Orbit animation and camera projection in caller-owned reusable buffers.
use std::f64::consts::{PI, TAU};

use crate::{Camera, Vec3};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Body {
    pub center: Vec3,
    pub radius: f64,
    pub phase: f64,
    pub period: f64,
    pub tilt_axis: f64,
    pub tilt: f64,
    /// NaN means no entrance animation.
    pub appeared: f64,
    pub migration_from: Vec3,
    /// NaN means no migration animation.
    pub migrated: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PlacedBody {
    pub world: Vec3,
    pub x: f64,
    pub y: f64,
    pub scale: f64,
    pub depth: f64,
    pub appearance: f64,
}

fn add(left: Vec3, right: Vec3) -> Vec3 {
    Vec3 {
        x: left.x + right.x,
        y: left.y + right.y,
        z: left.z + right.z,
    }
}
fn mul(value: Vec3, scale: f64) -> Vec3 {
    Vec3 {
        x: value.x * scale,
        y: value.y * scale,
        z: value.z * scale,
    }
}

pub fn orbit(radius: f64, phase: f64, axis: f64, tilt: f64) -> Vec3 {
    let (sine, cosine) = phase.sin_cos();
    let flat = Vec3 {
        x: cosine * radius,
        y: 0.0,
        z: sine * radius,
    };
    let (axis_sine, axis_cosine) = axis.sin_cos();
    let k = Vec3 {
        x: axis_cosine,
        y: 0.0,
        z: axis_sine,
    };
    let (sine, cosine) = tilt.sin_cos();
    let cross = Vec3 {
        x: 0.0,
        y: k.z * flat.x - k.x * flat.z,
        z: 0.0,
    };
    add(
        add(mul(flat, cosine), mul(cross, sine)),
        mul(k, k.dot(flat) * (1.0 - cosine)),
    )
}

/// Each input has a corresponding output; a nonpositive scale means clipped or
/// invalid. Does not allocate, sort or retain caller data.
pub fn place_bodies(
    camera: &Camera,
    bodies: &[Body],
    output: &mut [PlacedBody],
    orbit_time: f64,
    time: f64,
) {
    for (body, placed) in bodies.iter().zip(output) {
        *placed = PlacedBody::default();
        if !body.period.is_finite() || body.period <= 0.0 {
            continue;
        }
        let appearance = if body.appeared.is_nan() {
            1.0
        } else {
            1.0 - (1.0 - ((time - body.appeared) / 1.6).clamp(0.0, 1.0)).powi(3)
        };
        let mut offset = orbit(
            body.radius,
            body.phase + orbit_time / body.period * TAU,
            body.tilt_axis,
            body.tilt,
        );
        if appearance < 1.0 {
            let (sine, cosine) = ((1.0 - appearance) * PI).sin_cos();
            offset = Vec3 {
                x: (offset.x * cosine - offset.z * sine) * appearance,
                y: offset.y * appearance + 0.25 * (1.0 - appearance),
                z: (offset.x * sine + offset.z * cosine) * appearance,
            };
        }
        let mut world = add(body.center, offset);
        if !body.migrated.is_nan() {
            let t = (time - body.migrated) / 1.8;
            if t < 1.0 {
                let t_ease = t.clamp(0.0, 1.0);
                let ease = if t_ease < 0.5 {
                    4.0 * t_ease.powi(3)
                } else {
                    1.0 - (-2.0 * t_ease + 2.0).powi(3) / 2.0
                };
                let relative = world.relative_to(body.migration_from);
                let lift = (t * PI).sin() * (0.6 + relative.dot(relative).sqrt() * 0.18);
                world = body.migration_from.lerp(world, ease);
                world.y += lift;
            }
        }
        if !world.finite() {
            continue;
        }
        let transformed = camera.camera_space(world);
        *placed = PlacedBody {
            world,
            depth: transformed.z,
            appearance,
            ..Default::default()
        };
        if transformed.z < camera.near {
            continue;
        }
        let (x, y) = camera.screen(transformed);
        if !x.is_finite() || !y.is_finite() {
            continue;
        }
        placed.x = x;
        placed.y = y;
        placed.scale = camera.focal / transformed.z;
    }
}

/// Input triples are unit x/y and parallax; output is interleaved pixel x/y.
pub fn place_stars(
    input: &[f32],
    output: &mut [f32],
    width: f64,
    height: f64,
    yaw: f64,
    tilt: f64,
) {
    for (star, out) in input.chunks_exact(3).zip(output.chunks_exact_mut(2)) {
        let parallax = star[2] as f64;
        let shift_x = yaw / TAU * width * parallax * 2.2;
        let shift_y = (tilt - 0.6) * height * parallax * 0.6;
        out[0] = (star[0] as f64 * width + shift_x).rem_euclid(width) as f32;
        out[1] = (star[1] as f64 * height + shift_y).rem_euclid(height) as f32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tilted_orbits_preserve_radius() {
        for i in 0..1000 {
            let value = orbit(3.0, i as f64 * 0.1, 1.2, -0.3);
            assert!((value.dot(value) - 9.0).abs() < 1e-12);
        }
    }
    #[test]
    fn negative_camera_motion_wraps_stars_inside_the_viewport() {
        let mut output = [0.0; 4];
        place_stars(
            &[0.1, 0.2, 0.5, 0.9, 0.8, 0.3],
            &mut output,
            800.0,
            600.0,
            -9.0,
            -3.0,
        );
        assert!(
            output
                .chunks_exact(2)
                .all(|p| (0.0..800.0).contains(&p[0]) && (0.0..600.0).contains(&p[1]))
        );
    }
}
