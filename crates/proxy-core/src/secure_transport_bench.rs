//! Run explicitly in release mode; excludes sockets and network latency.
use std::hint::black_box;
use std::time::Instant;

use tokio::io::AsyncWriteExt;

use super::*;

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

#[test]
#[ignore = "manual release-mode transport benchmark"]
fn records_and_setup() {
    futures::executor::block_on(async {
        let mut hello = [1; HELLO_LEN];
        hello[..8].copy_from_slice(b"PXY3\x03\0\0\0");
        let key = [7; 32];
        let response_salt = [2; 32];
        let new =
            || super::tests::configured(Vec::new(), &key, &hello, &response_salt, true).unwrap();
        let mut setup = Vec::new();
        for sample in 0..10 {
            let start = Instant::now();
            for _ in 0..20_000 {
                black_box(new());
            }
            if sample != 0 {
                setup.push(start.elapsed().as_nanos() as f64 / 20_000.0);
            }
        }
        println!("v3_setup_ns={:.2}", median(setup));
        for (size, iterations) in [(256, 100_000), (16 * 1024, 10_000)] {
            let data = vec![19; size];
            let mut output = vec![0; size];
            let mut writer = new();
            let mut reader = super::tests::configured(
                std::io::Cursor::new(Vec::new()),
                &key,
                &hello,
                &response_salt,
                false,
            )
            .unwrap();
            let mut samples = Vec::new();
            for sample in 0..10 {
                let start = Instant::now();
                for _ in 0..iterations {
                    writer.inner.clear();
                    writer.write_all(black_box(&data)).await.unwrap();
                    writer.flush().await.unwrap();
                    std::mem::swap(&mut writer.inner, reader.inner.get_mut());
                    reader.inner.set_position(0);
                    reader.read_exact(black_box(&mut output)).await.unwrap();
                    black_box(&output);
                }
                assert_eq!(output, data);
                if sample != 0 {
                    samples.push(start.elapsed().as_nanos() as f64 / iterations as f64);
                }
            }
            println!("v3_record_{size}_ns={:.2}", median(samples));
            println!(
                "buffers_{size}={}",
                writer.outgoing.capacity() + reader.incoming.capacity()
            );
        }
    });
}
