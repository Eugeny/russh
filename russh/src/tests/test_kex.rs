use super::test_framework::*;
use crate::kex::ALL_KEX_ALGORITHMS;
use crate::tests::test_init;
use crate::tests::test_crypto::{test_crypto_with_config, CryptoTestConfig};

#[tokio::test]
async fn test_all_kex_algorithms() -> Result<(), TestError> {
    test_init();

    for &algorithm in ALL_KEX_ALGORITHMS {
        if algorithm == &crate::kex::NONE {
            continue;
        }

        println!("- {}", algorithm.as_ref());

        // Test basic functionality
        test_kex_algorithm(*algorithm)
            .await
            .map_err(|e| TestError::Client(format!("Failed testing {}: {}", algorithm.as_ref(), e)))
            .unwrap();
    }

    Ok(())
}

/// Test basic authentication and session setup with a specific kex algorithm
pub async fn test_kex_algorithm(kex_algorithm: crate::kex::Name) -> Result<(), TestError> {
    let mut preferred = crate::Preferred::default();
    preferred.kex = vec![kex_algorithm].into();
    
    test_crypto_with_config(CryptoTestConfig::with_preferred(preferred)).await
}
