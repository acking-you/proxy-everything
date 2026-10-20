//! Deterministic country placement. Country codes are zero or two ASCII bytes.
use std::f64::consts::TAU;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Seed {
    pub x: f64,
    pub z: f64,
    pub extent: f64,
    pub code: u32,
    pub reserved: u32,
}

fn pair_angle(a: u32, b: u32) -> f64 {
    let mut hash = 0x811c9dc5u32;
    for code in [a, u32::from(b'|'), b] {
        for byte in [(code >> 8) as u8, code as u8] {
            if byte != 0 {
                hash = (hash ^ u32::from(byte)).wrapping_mul(0x01000193);
            }
        }
    }
    f64::from(hash & 0xffffff) / 0x1000000 as f64 * TAU
}

/// Output is interleaved x/z, in the original sorted country order.
pub fn relax(seeds: &[Seed], output: &mut [f64]) {
    assert_eq!(output.len(), seeds.len() * 2);
    for (seed, point) in seeds.iter().zip(output.chunks_exact_mut(2)) {
        point.copy_from_slice(&[seed.x, seed.z]);
    }
    for _ in 0..240 {
        for (seed, point) in seeds.iter().zip(output.chunks_exact_mut(2)) {
            point[0] += (seed.x - point[0]) * 0.015;
            point[1] += (seed.z - point[1]) * 0.015;
            let radius = (point[0] * point[0] + point[1] * point[1]).sqrt();
            let minimum = seed.extent + 1.5;
            if radius < minimum {
                if radius < 1e-6 {
                    point[0] = minimum;
                    point[1] = 0.0;
                } else {
                    point[0] = point[0] * minimum / radius;
                    point[1] = point[1] * minimum / radius;
                }
            }
        }
        let mut moved = false;
        for i in 0..seeds.len() {
            for j in i + 1..seeds.len() {
                let mut dx = output[j * 2] - output[i * 2];
                let mut dz = output[j * 2 + 1] - output[i * 2 + 1];
                let mut distance = (dx * dx + dz * dz).sqrt();
                let need = seeds[i].extent + seeds[j].extent + 0.5;
                if distance >= need {
                    continue;
                }
                if distance < 1e-6 {
                    let (sin, cos) = pair_angle(seeds[i].code, seeds[j].code).sin_cos();
                    dx = cos;
                    dz = sin;
                    distance = 1.0;
                } else {
                    dx /= distance;
                    dz /= distance;
                }
                let push = (need - distance) / 2.0;
                output[i * 2] -= dx * push;
                output[i * 2 + 1] -= dz * push;
                output[j * 2] += dx * push;
                output[j * 2 + 1] += dz * push;
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coincident_countries_have_repeatable_finite_positions() {
        let seeds = [
            Seed {
                x: 0.0,
                z: 0.0,
                extent: 1.0,
                code: 0x4145,
                reserved: 0,
            },
            Seed {
                x: 0.0,
                z: 0.0,
                extent: 1.0,
                code: 0x504c,
                reserved: 0,
            },
        ];
        let mut first = [0.0; 4];
        let mut second = [0.0; 4];
        relax(&seeds, &mut first);
        relax(&seeds, &mut second);
        assert_eq!(first, second);
        assert!(first.iter().all(|value| value.is_finite()));
        assert!(((first[0] - first[2]).powi(2) + (first[1] - first[3]).powi(2)).sqrt() >= 2.49);
    }
}
