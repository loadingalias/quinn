use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::hmac;
use rand::{SeedableRng, TryRng, rngs::StdRng};
#[cfg(feature = "ring")]
use ring::hmac;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use super::default_provider;
use crate::{
    Endpoint, EndpointConfig, Instant,
    congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig},
};

#[test]
fn rustls_provider_entropy_seeds_the_endpoint() {
    #[derive(Debug)]
    struct Source {
        calls: AtomicUsize,
        failing: AtomicBool,
    }

    impl rustls::crypto::SecureRandom for Source {
        fn fill(&self, output: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            assert_eq!(output.len(), 32);
            self.calls.fetch_add(1, Ordering::Relaxed);
            output.fill(23);
            if self.failing.load(Ordering::Relaxed) {
                Err(rustls::crypto::GetRandomFailed)
            } else {
                Ok(())
            }
        }
    }

    static SOURCE: Source = Source {
        calls: AtomicUsize::new(0),
        failing: AtomicBool::new(false),
    };
    let mut provider = default_provider();
    provider.secure_random = &SOURCE;
    let reset_key = hmac::Key::new(hmac::HMAC_SHA256, &[0xab; 64]);
    let mut config = EndpointConfig::new(Arc::new(reset_key));
    config.random_source(Arc::new(provider.secure_random));
    let config = Arc::new(config);
    Endpoint::new(config.clone(), None, true).unwrap();
    assert_eq!(SOURCE.calls.load(Ordering::Relaxed), 1);
    SOURCE.failing.store(true, Ordering::Relaxed);
    assert!(matches!(
        Endpoint::new(config, None, true),
        Err(crate::crypto::GetRandomFailed)
    ));
    assert_eq!(SOURCE.calls.load(Ordering::Relaxed), 2);
}

struct CountingRng {
    inner: StdRng,
    bytes: usize,
}

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.bytes += 4;
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.bytes += 8;
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.bytes += dst.len();
        self.inner.try_fill_bytes(dst)
    }
}

#[test]
fn bbr_seeds_its_gain_cycle_from_the_connection_generator() {
    for (controller, expected) in [
        (
            Arc::new(CubicConfig::default()) as Arc<dyn ControllerFactory>,
            0,
        ),
        (Arc::new(NewRenoConfig::default()), 0),
        (Arc::new(BbrConfig::default()), 16),
    ] {
        let mut rng = CountingRng {
            inner: StdRng::seed_from_u64(0),
            bytes: 0,
        };
        controller.build(Instant::now(), 1200, &mut rng);
        assert_eq!(rng.bytes, expected);
    }
}
