//! Property tests for the composite signature format.
//!
//! Every property drives the public API only. Each case runs an ML-DSA-65
//! signature, so the whole file is excluded under miri for the same reason the
//! KEM unit tests are.
//!
//! The exhaustive byte sweep lives in the crate's own unit tests. What is added
//! here is the randomised version, plus the properties that only make sense
//! against a public entry point.

#![cfg(not(miri))]

use mili_core::{Error, SigningKey, VerifyingKey, SIGNATURE_SIZE, VERIFYING_KEY_SIZE};
use proptest::prelude::*;

fn key() -> SigningKey {
    let mut bytes = [0x5Au8; 64];
    for byte in &mut bytes[32..] {
        *byte = 0xA5;
    }
    SigningKey::from_bytes(bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any message signs and then verifies under the same key.
    #[test]
    fn round_trip(message in prop::collection::vec(any::<u8>(), 0..1024)) {
        let key = key();
        let signature = key.sign(&message)?;
        prop_assert_eq!(signature.len(), 6 + SIGNATURE_SIZE);
        key.verifying_key().verify(&message, &signature)?;
    }

    /// A different message never verifies against a signature.
    #[test]
    fn a_different_message_never_verifies(
        message in prop::collection::vec(any::<u8>(), 1..256),
        other in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        if message == other {
            return Ok(());
        }
        let key = key();
        let signature = key.sign(&message)?;
        prop_assert!(matches!(
            key.verifying_key().verify(&other, &signature),
            Err(Error::Failed)
        ));
    }

    /// Flipping any single bit of the signature body is always detected.
    #[test]
    fn a_single_bit_flip_in_the_body_is_always_detected(
        message in prop::collection::vec(any::<u8>(), 0..128),
        index in 6usize..4096,
        bit in 0u8..8,
    ) {
        let key = key();
        let mut signature = key.sign(&message)?;
        if index >= signature.len() {
            return Ok(());
        }
        signature[index] ^= 1 << bit;
        prop_assert!(matches!(
            key.verifying_key().verify(&message, &signature),
            Err(Error::Failed)
        ));
    }

    /// Every proper prefix of the signature file is rejected.
    #[test]
    fn every_truncation_is_detected(
        message in prop::collection::vec(any::<u8>(), 0..128),
        cut in 0usize..4096,
    ) {
        let key = key();
        let signature = key.sign(&message)?;
        if cut >= signature.len() {
            return Ok(());
        }
        prop_assert!(key.verifying_key().verify(&message, &signature[..cut]).is_err());
    }

    /// Appending to the signature file is detected. The format has no length
    /// field, so extra bytes land inside the component signature.
    #[test]
    fn appended_bytes_are_detected(
        message in prop::collection::vec(any::<u8>(), 0..128),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let key = key();
        let mut signature = key.sign(&message)?;
        signature.extend_from_slice(&extra);
        prop_assert!(matches!(
            key.verifying_key().verify(&message, &signature),
            Err(Error::Failed)
        ));
    }

    /// A key that is not the signer never verifies the signature.
    #[test]
    fn a_foreign_key_never_verifies(
        message in prop::collection::vec(any::<u8>(), 0..128),
        other in any::<[u8; 64]>(),
    ) {
        let key = key();
        let signature = key.sign(&message)?;
        let wrong = SigningKey::from_bytes(other);
        if wrong.verifying_key().to_bytes() == key.verifying_key().to_bytes() {
            return Ok(());
        }
        prop_assert!(matches!(
            wrong.verifying_key().verify(&message, &signature),
            Err(Error::Failed)
        ));
    }

    /// Arbitrary bytes never panic and never verify.
    #[test]
    fn arbitrary_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        let key = key();
        match key.verifying_key().verify(b"a message", &input) {
            Ok(()) => prop_assert!(false, "arbitrary bytes must never verify"),
            Err(_) => prop_assert!(true),
        }
    }

    /// A verifying key round trips through its byte encoding.
    #[test]
    fn verifying_keys_round_trip(bytes in any::<[u8; VERIFYING_KEY_SIZE]>()) {
        match VerifyingKey::from_bytes(&bytes) {
            Ok(key) => prop_assert_eq!(&key.to_bytes()[..], &bytes[..]),
            Err(Error::Failed) => prop_assert!(true),
            Err(_) => prop_assert!(false, "a verifying key must only fail with Error::Failed"),
        }
    }
}
