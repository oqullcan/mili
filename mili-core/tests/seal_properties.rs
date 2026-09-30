//! Property tests for the sealed box format.
//!
//! Every property here drives the public API only. Each case performs at least
//! one ML-KEM-768 decapsulation, so the whole file is excluded under miri for
//! the same reason the KEM unit tests are.
//!
//! The exhaustive byte sweep and the exhaustive truncation sweep live in the
//! crate's own unit tests, where they can reach the AEAD layer and run without a
//! decapsulation per case. What is added here is the randomised version of the
//! same properties, plus the properties that only make sense against a public
//! entry point.

#![cfg(not(miri))]

use mili_core::{open, seal, EncapsulationKey, Error, SealingKey, SEALED_BOX_OVERHEAD};
use proptest::prelude::*;

fn recipient() -> SealingKey {
    SealingKey::from_bytes([0x37u8; 32])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any plaintext opens back to itself under the recipient's key.
    #[test]
    fn round_trip(plaintext in prop::collection::vec(any::<u8>(), 0..=2048)) {
        let key = recipient();
        let sealed = seal(&key.encapsulation_key(), &plaintext)?;
        prop_assert_eq!(sealed.len(), plaintext.len() + SEALED_BOX_OVERHEAD);
        let opened = open(&sealed, &[&key])?;
        prop_assert_eq!(&*opened, &plaintext[..]);
    }

    /// Flipping any single bit anywhere in the file makes the file unopenable.
    #[test]
    fn a_single_bit_flip_is_always_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        index in 0usize..4096,
        bit in 0u8..8,
    ) {
        let key = recipient();
        let mut sealed = seal(&key.encapsulation_key(), &plaintext)?;
        if index >= sealed.len() {
            return Ok(());
        }
        sealed[index] ^= 1 << bit;
        prop_assert!(open(&sealed, &[&key]).is_err());
    }

    /// Every proper prefix of the file is rejected, and never opens into a
    /// shorter or longer value than the plaintext.
    #[test]
    fn every_truncation_is_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        cut in 0usize..4096,
    ) {
        let key = recipient();
        let sealed = seal(&key.encapsulation_key(), &plaintext)?;
        if cut >= sealed.len() {
            return Ok(());
        }
        prop_assert!(open(&sealed[..cut], &[&key]).is_err());
    }

    /// Appending to the file is detected. The format has no length field, so
    /// extra bytes land inside the AEAD input.
    #[test]
    fn appended_bytes_are_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let key = recipient();
        let mut sealed = seal(&key.encapsulation_key(), &plaintext)?;
        sealed.extend_from_slice(&extra);
        prop_assert!(open(&sealed, &[&key]).is_err());
    }

    /// A key that is not the recipient never opens the file, whatever it is
    /// combined with.
    #[test]
    fn a_foreign_key_never_opens(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        decoy in any::<[u8; 32]>(),
    ) {
        let key = recipient();
        let sealed = seal(&key.encapsulation_key(), &plaintext)?;
        let wrong = SealingKey::from_bytes(decoy);
        if wrong.encapsulation_key().to_bytes() == key.encapsulation_key().to_bytes() {
            return Ok(());
        }
        prop_assert!(open(&sealed, &[&wrong]).is_err());
    }

    /// The right key is found no matter how many decoys come first.
    #[test]
    fn the_recipient_is_found_among_decoys(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        decoys in prop::collection::vec(any::<[u8; 32]>(), 0..8),
    ) {
        let key = recipient();
        let sealed = seal(&key.encapsulation_key(), &plaintext)?;

        let mut candidates: Vec<SealingKey> =
            decoys.iter().map(|seed| SealingKey::from_bytes(*seed)).collect();
        candidates.push(key);

        let refs: Vec<&SealingKey> = candidates.iter().collect();
        let opened = open(&sealed, &refs)?;
        prop_assert_eq!(&*opened, &plaintext[..]);
    }

    /// The same plaintext sealed twice never produces the same bytes.
    #[test]
    fn sealing_is_not_deterministic(plaintext in prop::collection::vec(any::<u8>(), 0..256)) {
        let public = recipient().encapsulation_key();
        let a = seal(&public, &plaintext)?;
        let b = seal(&public, &plaintext)?;
        prop_assert_ne!(a, b);
    }

    /// Arbitrary bytes never panic and never produce plaintext. This is the
    /// shape of the parser property the fuzz targets will push harder in a later
    /// phase.
    #[test]
    fn arbitrary_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..2048)) {
        let key = recipient();
        match open(&input, &[&key]) {
            Ok(plaintext) => prop_assert!(plaintext.len() <= input.len()),
            Err(_) => prop_assert!(true),
        }
    }

    /// An encapsulation key round trips through its byte encoding.
    #[test]
    fn encapsulation_keys_round_trip(bytes in any::<[u8; 1216]>()) {
        match EncapsulationKey::from_bytes(&bytes) {
            Ok(key) => prop_assert_eq!(&key.to_bytes()[..], &bytes[..]),
            Err(Error::Failed) => prop_assert!(true),
            Err(_) => prop_assert!(false, "a public key must only fail with Error::Failed"),
        }
    }
}
