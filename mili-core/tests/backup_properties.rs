//! Property tests for the backup container.
//!
//! The exhaustive byte sweep and the exhaustive truncation sweep live in the
//! crate's own unit tests, where they can reach the AEAD layer and run without an
//! Argon2 derivation per case. What is added here is the randomised version of
//! those properties, plus the properties that only make sense against a public
//! entry point.
//!
//! Argon2 at the documented profile costs about 120 ms per derivation, so the
//! properties are split into blocks by how many derivations each case does. The
//! first block does none, because the parsing path rejects before any memory is
//! reserved and a duplicate identifier is found before the KDF runs. Later blocks
//! run fewer cases and say so: a property whose data varies only in the key
//! material is not made stronger by a hundred more of it, and the structural
//! guarantees are pinned exhaustively in the unit tests instead.

use mili_core::backup::{Backup, StoredKey};
use mili_core::{Error, SealingKey, SigningKey, SymmetricKey};
use proptest::prelude::*;

const PASSWORD: &[u8] = b"correct horse battery staple";

fn sealing(seed: u8) -> SealingKey {
    SealingKey::from_bytes([seed; 32])
}

fn signing(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&[seed; 32]);
    bytes[32..].copy_from_slice(&[seed.wrapping_add(1); 32]);
    SigningKey::from_bytes(bytes)
}

/// Keys whose identifiers are distinct, so `from_keys` accepts them.
///
/// `SymmetricKey::from_bytes` is crate-private on purpose, so the symmetric
/// entries are generated rather than built from chosen bytes. Two 256 bit
/// random keys colliding is not a thing these tests need to plan for.
fn distinct_keys(count: usize) -> Vec<StoredKey> {
    (0..count)
        .map(|index| match index % 3 {
            0 => StoredKey::Symmetric(
                SymmetricKey::generate().expect("the operating system has randomness"),
            ),
            1 => StoredKey::Signing(signing(index as u8)),
            _ => StoredKey::Sealing(sealing(index as u8)),
        })
        .collect()
}

fn backup_bytes(count: usize) -> Vec<u8> {
    Backup::from_keys(PASSWORD, distinct_keys(count))
        .expect("the keys have distinct identifiers")
        .into_bytes()
}

// No derivations. `from_bytes` only checks the length, so these drive the whole
// parse path with input that carries no structure at all.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary bytes are either refused or opened, and never panic.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=400)) {
        if let Ok(backup) = Backup::from_bytes(&bytes) {
            let _ = backup.open(PASSWORD);
        }
    }

    /// Bytes that are not one mili wrote are refused.
    #[test]
    fn a_file_without_the_mili_prefix_is_refused(
        suffix in prop::collection::vec(any::<u8>(), 0..=120),
    ) {
        let mut bytes = b"notmili".to_vec();
        bytes.extend_from_slice(&suffix);
        if let Ok(backup) = Backup::from_bytes(&bytes) {
            prop_assert!(backup.open(PASSWORD).is_err());
        }
    }

    /// Truncating a backup at any point makes it unopenable.
    #[test]
    fn a_truncation_is_never_openable(len in 0usize..4096) {
        let original = backup_bytes(1);
        let len = len % original.len();
        if let Ok(backup) = Backup::from_bytes(&original[..len]) {
            prop_assert!(backup.open(PASSWORD).is_err());
        }
    }

    /// Appending anything to a backup makes it unopenable.
    #[test]
    fn an_append_is_never_openable(suffix in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut bytes = backup_bytes(1);
        bytes.extend_from_slice(&suffix);
        let backup = Backup::from_bytes(&bytes)
            .expect("appending keeps the length above the minimum");
        prop_assert!(backup.open(PASSWORD).is_err());
    }

    /// A duplicate identifier is refused at build time rather than written.
    #[test]
    fn a_duplicate_identifier_is_refused(seed in 0u8..=255) {
        let result = Backup::from_keys(
            PASSWORD,
            vec![StoredKey::Sealing(sealing(seed)), StoredKey::Sealing(sealing(seed))],
        );
        prop_assert!(matches!(result, Err(Error::Failed)));
    }

    /// An empty password is refused on the way in, before any derivation.
    #[test]
    fn an_empty_password_is_refused_at_build_time(_ in prop::collection::vec(any::<u8>(), 0..4)) {
        prop_assert!(matches!(
            Backup::from_keys(b"", vec![StoredKey::Sealing(sealing(0x31))]),
            Err(Error::Failed)
        ));
    }
}

// One derivation per case.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Flipping a single bit anywhere in a backup is detected.
    #[test]
    fn a_single_bit_flip_is_always_detected(index in 0usize..4096, bit in 0u8..8) {
        let original = backup_bytes(1);
        let mut bytes = original.clone();
        bytes[index % original.len()] ^= 1 << bit;
        let backup = Backup::from_bytes(&bytes)
            .expect("a bit flip does not change the length");
        prop_assert!(backup.open(PASSWORD).is_err());
    }

    /// A backup only opens with the password it was written under.
    #[test]
    fn a_wrong_password_never_opens(candidate in prop::collection::vec(any::<u8>(), 1..48)) {
        prop_assume!(candidate != PASSWORD.to_vec());
        let backup = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("builds");
        prop_assert!(matches!(backup.open(&candidate), Err(Error::Failed)));
    }

    /// An empty password is refused on the way out too.
    #[test]
    fn an_empty_password_is_never_accepted(_ in prop::collection::vec(any::<u8>(), 0..4)) {
        let backup = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("builds");
        prop_assert!(matches!(backup.open(b""), Err(Error::Failed)));
    }

    /// Two backups of the same keys under the same password differ, because the
    /// salt is fresh each time.
    #[test]
    fn two_backups_of_one_key_set_differ(_ in prop::collection::vec(any::<u8>(), 0..8)) {
        // None of the key types are `Clone`, so the same key set is built twice.
        // That is also the point: the only difference between the two backups is
        // the fresh salt.
        let first = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("builds");
        let second = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("builds");
        prop_assert_ne!(first.as_bytes(), second.as_bytes());
    }

    /// The identifiers within one backup are distinct, so a reader can tell the
    /// entries apart without opening anything twice.
    #[test]
    fn identifiers_within_one_backup_are_distinct(count in 1usize..8) {
        let opened = Backup::from_keys(PASSWORD, distinct_keys(count))
            .expect("builds")
            .open(PASSWORD)
            .expect("opens");

        let mut seen: Vec<[u8; 16]> = opened.iter().map(|entry| entry.key_id).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        prop_assert_eq!(seen.len(), total);
    }
}

// Two derivations per case: one to build, one to open.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    /// The identifiers a backup writes are the ones a caller can compute, and
    /// they are stable across a round trip.
    #[test]
    fn identifiers_survive_a_container_round_trip(count in 1usize..6) {
        let keys = distinct_keys(count);
        let expected: Vec<_> = keys
            .iter()
            .map(|key| key.key_id().expect("computable"))
            .collect();

        let opened = Backup::from_keys(PASSWORD, keys)
            .expect("builds")
            .open(PASSWORD)
            .expect("opens");
        let found: Vec<_> = opened.iter().map(|entry| entry.key_id).collect();

        prop_assert_eq!(found, expected);
    }

    /// Keys come back with the types they were stored under.
    #[test]
    fn key_types_survive_a_round_trip(index in 0usize..3) {
        let opened = Backup::from_keys(PASSWORD, distinct_keys(index + 1))
            .expect("builds")
            .open(PASSWORD)
            .expect("opens");

        for (position, entry) in opened.iter().enumerate() {
            prop_assert!(
                matches!(
                    (&entry.key, position % 3),
                    (StoredKey::Symmetric(_), 0)
                        | (StoredKey::Signing(_), 1)
                        | (StoredKey::Sealing(_), 2)
                ),
                "entry {position} came back as the wrong type"
            );
        }
    }
}
