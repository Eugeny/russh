use criterion::{Criterion, Throughput};
use rand::{Rng, rng};
use std::hint::black_box;

pub fn bench(c: &mut Criterion) {
    let mut rand_generator = black_box(rng());

    let mut packet_length = black_box(vec![0u8; 4]);

    for cipher_name in [super::CHACHA20_POLY1305, super::AES_256_GCM] {
        let cipher = super::CIPHERS.get(&cipher_name).unwrap();

        let mut key = vec![0; cipher.key_len()];
        rand_generator.fill_bytes(&mut key);
        let mut nonce = vec![0; cipher.nonce_len()];
        rand_generator.fill_bytes(&mut nonce);

        let mut sk = cipher
            .make_sealing_key(&key, &nonce, &[], &crate::mac::_NONE)
            .unwrap();
        let mut ok = cipher
            .make_opening_key(&key, &nonce, &[], &crate::mac::_NONE)
            .unwrap();

        let mut group = c.benchmark_group(format!("Cipher: {}", cipher_name.0));
        for size in [100usize, 1000, 10000] {
            let iterations = 10000 / size;

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(format!("Block size: {size}"), |b| {
                b.iter_with_setup(
                    || {
                        let mut in_out = black_box(vec![0u8; size]);
                        rand_generator.fill_bytes(&mut in_out);
                        rand_generator.fill_bytes(&mut packet_length);
                        in_out
                    },
                    |mut in_out| {
                        for _ in 0..iterations {
                            let len = in_out.len();
                            let (data, tag) = in_out.split_at_mut(len - sk.tag_len());
                            sk.seal(0, data, tag);
                            ok.open(0, &mut in_out).unwrap();
                        }
                    },
                );
            });
        }
        group.finish();
    }
}
