use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use drbg::thread::LocalCtrDrbg;
use std::time::Duration;

// Iterate without additional data.
fn ctr_drbg(buf: &mut [u8], drbg: &LocalCtrDrbg) {
    drbg.fill_bytes(buf, None).unwrap();
}

// Iterate with additional data.
fn ctr_drbg_adata(buf: &mut [u8], drbg: &LocalCtrDrbg) {
    let adata = vec![0u8; 8];
    drbg.fill_bytes(buf, Some(&adata)).unwrap();
}

fn ctr_drbg_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ctr_drbg");
    group.measurement_time(Duration::new(10, 0));
    //
    // Measure the latency for filling small buffers. This reflects
    // the use-case of generating symmetric encryption keys and or
    // nonces.
    //
    let len_steps = vec![16, 32];
    let drbg = LocalCtrDrbg::default();
    for len in &len_steps {
        let title = format!("{}_bytes", len);
        let mut buf = vec![0u8; *len];
        group.bench_function(&title, |b| b.iter(|| ctr_drbg(&mut buf, &drbg)));
    }
    for len in &len_steps {
        let title = format!("{}_bytes_additional_data", len);
        let mut buf = vec![0u8; *len];
        group.bench_function(&title, |b| b.iter(|| ctr_drbg_adata(&mut buf, &drbg)));
    }
    //
    // Measure the throughput for bulk random data.
    //
    let title = "1_MiB";
    let mut buf = vec![0u8; 1 << 20];
    group.throughput(Throughput::Bytes(buf.len() as u64));
    group.bench_function(title, |b| b.iter(|| ctr_drbg(&mut buf, &drbg)));
    let title = "1_MiB_additional_data";
    group.bench_function(title, |b| b.iter(|| ctr_drbg_adata(&mut buf, &drbg)));
}

criterion_group!(benches, ctr_drbg_benchmark);
criterion_main!(benches);
