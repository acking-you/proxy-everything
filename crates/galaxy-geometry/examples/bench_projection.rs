//! Reproducible compute-only benchmark, excluding allocation and mesh creation.
//! Run: cargo run -p galaxy-geometry --release --example bench_projection
use std::hint::black_box;
use std::time::Instant;

use galaxy_geometry::{Camera, ScreenSegment, Vec3, WorldSegment, project_segments};

fn main() {
    let camera = Camera {
        eye: Vec3 {
            x: 0.0,
            y: 8.0,
            z: -16.0,
        },
        right: Vec3 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
        },
        up: Vec3 {
            x: 0.0,
            y: 0.8944271909999159,
            z: 0.4472135954999579,
        },
        forward: Vec3 {
            x: 0.0,
            y: -0.4472135954999579,
            z: 0.8944271909999159,
        },
        center_x: 640.0,
        center_y: 360.0,
        focal: 1008.0,
        near: 0.2,
        left: -2.0,
        top: -2.0,
        right_edge: 1282.0,
        bottom: 722.0,
    };
    for count in [512, 4096, 16384] {
        let input: Vec<_> = (0..count)
            .map(|i| {
                let angle = (i % 96) as f64 * std::f64::consts::TAU / 96.0;
                let next = angle + std::f64::consts::TAU / 96.0;
                let radius = (i / 96 + 1) as f64 * 0.3;
                WorldSegment {
                    start: Vec3 {
                        x: angle.cos() * radius,
                        y: 0.0,
                        z: angle.sin() * radius,
                    },
                    end: Vec3 {
                        x: next.cos() * radius,
                        y: 0.0,
                        z: next.sin() * radius,
                    },
                    group: (i / 96) as u32,
                    reserved: 0,
                }
            })
            .collect();
        let mut output = vec![ScreenSegment::default(); count];
        let start = Instant::now();
        for _ in 0..2000 {
            black_box(
                project_segments(
                    black_box(&camera),
                    black_box(&input),
                    black_box(&mut output),
                )
                .unwrap(),
            );
        }
        println!(
            "{count} segments: {:.1} us/batch",
            start.elapsed().as_secs_f64() * 1e6 / 2000.0
        );
    }
}
