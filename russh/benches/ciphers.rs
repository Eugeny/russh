use criterion::{criterion_group, criterion_main};
use russh::cipher::benchmark::bench;
criterion_group!(benches, bench);
criterion_main!(benches);
