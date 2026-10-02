//! Property tests for the password wrapped key file.
//!
//! Every property here drives the public API only. The exhaustive byte sweep
//! and the exhaustive truncation sweep live in the crate's own unit tests, where
//! they can reach the AEAD layer and run without an Argon2 derivation per case.
//! What is added here is the randomised version of those properties, plus the
//! properties that only make sense against a public entry point.
//!
//! Argon2 at the documented profile costs about 120 ms per derivation, so the
//! properties are split into three blocks by how much derivation they do. The
//! first block never derives at all, because the parsing path rejects before any
//! memory is reserved. The later blocks run few cases, and say so: a property
//! whose data varies only in the password bytes is not made stronger by a
//! hundred more of them, and the structural guarantees are pinned exhaustively in
//! the unit tests instead.

// Argon2id at the documented profile touches 64 MiB three times per derivation,
// which is not something to interpret. Under miri this file would take hours
// rather than seconds, so it does not run there.
#![cfg(not(miri))]

use mili_core::{Error, SealingKey};
use proptest::prelude::*;

const PASSWORD: &[u8] = b"correct horse battery staple";

fn recipient(seed: u8) -> SealingKey {
    SealingKey::from_bytes([seed; 32])
}

/// A key file, as bytes.
///
/// Argon2 at the documented profile costs about 120 ms, so a file is built once
/// per test rather than once per case.
fn key_file_bytes() -> Vec<u8> {
    mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), PASSWORD)
        .expect("the profile parameters are inside the accepted range")
        .into_bytes()
}

// No derivations. `from_bytes` only checks the length, so these drive the whole
// parse path with input that carries no structure at all.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary bytes are either refused or opened, and never panic.
    ///
    /// `from_bytes` only checks the length, so this drives the whole parse path
    /// with input that carries no structure at all. For a random buffer the
    /// magic almost never matches, so no case reaches Argon2.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=400)) {
        if let Ok(file) = mili_core::keyfile::KeyFile::from_bytes(&bytes) {
            // A wrong password is the same error as a corrupt file, so either
            // answer is acceptable here. What is not acceptable is a panic.
            let _ = file.open_sealing_key(PASSWORD);
            let _ = file.open_symmetric_key(PASSWORD);
            let _ = file.open_signing_key(PASSWORD);
            let _ = file.rotate(PASSWORD);
        }
    }

    /// Bytes that are not one mili wrote are refused rather than accepted under
    /// some other reading of the header.
    #[test]
    fn a_file_without_the_mili_prefix_is_refused(
        suffix in prop::collection::vec(any::<u8>(), 0..=120),
    ) {
        let mut bytes = b"notmili".to_vec();
        bytes.extend_from_slice(&suffix);
        if let Ok(file) = mili_core::keyfile::KeyFile::from_bytes(&bytes) {
            prop_assert!(file.open_sealing_key(PASSWORD).is_err());
        }
    }

    /// Truncating a key file at any point makes it unopenable.
    #[test]
    fn a_truncation_is_never_openable(len in 0usize..4096) {
        let original = key_file_bytes();
        let len = len % original.len();
        if let Ok(file) = mili_core::keyfile::KeyFile::from_bytes(&original[..len]) {
            prop_assert!(file.open_sealing_key(PASSWORD).is_err());
        }
    }

    /// Appending anything to a key file makes it unopenable.
    #[test]
    fn an_append_is_never_openable(suffix in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut bytes = key_file_bytes();
        bytes.extend_from_slice(&suffix);
        let file = mili_core::keyfile::KeyFile::from_bytes(&bytes)
            .expect("appending keeps the length above the minimum");
        prop_assert!(file.open_sealing_key(PASSWORD).is_err());
    }
}

proptest! {
    // One derivation per case.
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Flipping a single bit anywhere in a key file is detected.
    #[test]
    fn a_single_bit_flip_is_always_detected(index in 0usize..4096, bit in 0u8..8) {
        let original = key_file_bytes();
        let mut bytes = original.clone();
        bytes[index % original.len()] ^= 1 << bit;
        let file = mili_core::keyfile::KeyFile::from_bytes(&bytes)
            .expect("a bit flip does not change the length");
        prop_assert!(file.open_sealing_key(PASSWORD).is_err());
    }

    /// A key file only opens with the password it was written under.
    #[test]
    fn a_wrong_password_never_opens(candidate in prop::collection::vec(any::<u8>(), 1..48)) {
        prop_assume!(candidate != PASSWORD.to_vec());
        let file = mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), PASSWORD)
            .expect("wraps");
        prop_assert!(matches!(file.open_sealing_key(&candidate), Err(Error::Failed)));
    }

    /// An empty password is refused on the way in and on the way out, so that
    /// Argon2 never derives a real key from nothing.
    #[test]
    fn an_empty_password_is_never_accepted(_ in prop::collection::vec(any::<u8>(), 0..4)) {
        prop_assert!(matches!(
            mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), b""),
            Err(Error::Failed)
        ));
        let file = mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), PASSWORD)
            .expect("wraps");
        prop_assert!(matches!(file.open_sealing_key(b""), Err(Error::Failed)));
    }

    /// Two wraps of the same key under the same password differ, because the
    /// salt is fresh each time.
    #[test]
    fn two_wraps_of_one_key_differ(_ in prop::collection::vec(any::<u8>(), 0..8)) {
        let key = recipient(0x31);
        let first = mili_core::keyfile::KeyFile::from_sealing_key(&key, PASSWORD)
            .expect("wraps");
        let second = mili_core::keyfile::KeyFile::from_sealing_key(&key, PASSWORD)
            .expect("wraps");
        prop_assert_ne!(first.as_bytes(), second.as_bytes());
    }
}

proptest! {
    // Three derivations per case.
    #![proptest_config(ProptestConfig::with_cases(6))]

    /// Rotation preserves the key, and writes different bytes, because
    /// `docs/SPEC.md` section 12.1 defines it as a fresh salt around the same payload
    /// under the same password.
    #[test]
    fn rotation_preserves_the_key(password in prop::collection::vec(any::<u8>(), 1..48)) {
        let expected = recipient(0x31).encapsulation_key().to_bytes();
        let file = mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), &password)
            .expect("wraps");
        let rotated = file.rotate(&password).expect("rotates");

        let reopened = rotated
            .open_sealing_key(&password)
            .expect("the password still opens the rotated file");
        prop_assert_eq!(reopened.encapsulation_key().to_bytes(), expected);
        prop_assert_ne!(rotated.as_bytes(), file.as_bytes());
    }

    /// Rotation returns a new file and leaves the original alone, so a rotation
    /// whose copy is never finished does not destroy the only copy of a key.
    #[test]
    fn rotation_does_not_consume_the_original(_ in prop::collection::vec(any::<u8>(), 0..8)) {
        let file = mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), PASSWORD)
            .expect("wraps");
        let rotated = file.rotate(PASSWORD).expect("rotates");

        prop_assert!(file.open_sealing_key(PASSWORD).is_ok());
        prop_assert!(rotated.open_sealing_key(PASSWORD).is_ok());
        prop_assert_ne!(file.as_bytes(), rotated.as_bytes());
    }

    /// Changing a key file's password is the composition of opening the key and
    /// wrapping it again, which is the only way to do it: `rotate` deliberately
    /// keeps the password, because that is what rotation means in
    /// `docs/SPEC.md` section 12.1.
    #[test]
    fn a_password_change_is_open_then_wrap(
        old in prop::collection::vec(any::<u8>(), 1..24),
        new in prop::collection::vec(any::<u8>(), 1..24),
    ) {
        prop_assume!(old != new);

        let file = mili_core::keyfile::KeyFile::from_sealing_key(&recipient(0x31), &old)
            .expect("wraps");
        let key = file.open_sealing_key(&old).expect("opens with the old password");
        let rewrapped = mili_core::keyfile::KeyFile::from_sealing_key(&key, &new)
            .expect("wraps under the new password");

        prop_assert!(matches!(rewrapped.open_sealing_key(&old), Err(Error::Failed)));
        prop_assert_eq!(
            rewrapped.open_sealing_key(&new).expect("opens with the new password")
                .encapsulation_key()
                .to_bytes(),
            key.encapsulation_key().to_bytes(),
        );
    }
}
