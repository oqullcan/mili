//! Property tests for the streaming format.
//!
//! Every case performs an ML-KEM-768 decapsulation, so the file is excluded
//! under miri. The unit tests in `stream.rs` cover the chunk boundaries, the
//! reorderings and the header bytes exhaustively; these cover the randomised
//! versions and the inputs no fixed case reaches.

#![cfg(not(miri))]

use mili_core::stream::{
    open_buffered, open_stream, seal_buffered, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE,
};
use mili_core::{Error, SealingKey};
use proptest::prelude::*;
use std::io::Read;

fn key() -> SealingKey {
    SealingKey::from_bytes([0x2Bu8; 32])
}

/// A plaintext that crosses at least one chunk boundary, so that the chunked
/// path is exercised rather than the single short chunk path.
fn payloads() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        1 => prop::collection::vec(any::<u8>(), 0..=64),
        1 => prop::collection::vec(any::<u8>(), (CHUNK_SIZE - 8)..CHUNK_SIZE + 8),
        3 => prop::collection::vec(any::<u8>(), 0..=(3 * CHUNK_SIZE)),
    ]
}

fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    seal_buffered(&key(), &mut out, plaintext).expect("seal");
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Any plaintext round trips through the streaming format.
    #[test]
    fn round_trip(plaintext in payloads()) {
        let file = encrypt(&plaintext);
        let opened = open_buffered(&file[..], &[&key()], 8 * CHUNK_SIZE)?;
        prop_assert_eq!(&*opened, &plaintext[..]);
    }

    /// The streaming reader and the buffered reader agree.
    #[test]
    fn both_readers_agree(plaintext in payloads()) {
        let file = encrypt(&plaintext);

        let buffered = open_buffered(&file[..], &[&key()], 8 * CHUNK_SIZE)?;
        let mut reader = open_stream(&file[..], &[&key()])?;
        let mut streamed = Vec::new();
        reader.read_to_end(&mut streamed)?;

        prop_assert_eq!(&*buffered, &plaintext[..]);
        prop_assert_eq!(&streamed[..], &plaintext[..]);
    }

    /// Flipping any single bit of any chunk is detected.
    #[test]
    fn a_single_bit_flip_is_always_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..CHUNK_SIZE + 64),
        index in 0usize..65536,
        bit in 0u8..8,
    ) {
        let mut file = encrypt(&plaintext);
        let offset = 1158 + index;
        if offset >= file.len() {
            return Ok(());
        }
        file[offset] ^= 1 << bit;
        prop_assert!(open_buffered(&file[..], &[&key()], 8 * CHUNK_SIZE).is_err());
    }

    /// Every proper prefix is rejected.
    #[test]
    fn every_truncation_is_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..CHUNK_SIZE + 64),
        cut in 0usize..65536,
    ) {
        let file = encrypt(&plaintext);
        if cut >= file.len() {
            return Ok(());
        }
        prop_assert!(open_buffered(&file[..cut], &[&key()], 8 * CHUNK_SIZE).is_err());
    }

    /// Appending to the file is rejected.
    #[test]
    fn appended_bytes_are_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        extra in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        let mut file = encrypt(&plaintext);
        file.extend_from_slice(&extra);
        prop_assert!(open_buffered(&file[..], &[&key()], 8 * CHUNK_SIZE).is_err());
    }

    /// Swapping two chunks is detected.
    #[test]
    fn swapping_two_chunks_is_detected(
        plaintext in prop::collection::vec(any::<u8>(), 0..=(2 * CHUNK_SIZE)),
        first in 0usize..8,
        second in 0usize..8,
    ) {
        let file = encrypt(&plaintext);
        let chunks: Vec<&[u8]> = file[1158..].chunks(ENCRYPTED_CHUNK_SIZE).collect();
        if chunks.len() < 2 || first >= chunks.len() || second >= chunks.len() || first == second {
            return Ok(());
        }

        let mut order: Vec<usize> = (0..chunks.len()).collect();
        order.swap(first, second);

        let mut tampered = file[..1158].to_vec();
        for index in order {
            tampered.extend_from_slice(chunks[index]);
        }
        prop_assert!(open_buffered(&tampered[..], &[&key()], 8 * CHUNK_SIZE).is_err());
    }

    /// A key that is not the recipient never opens the file.
    #[test]
    fn a_foreign_key_never_opens(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        other in any::<[u8; 32]>(),
    ) {
        let file = encrypt(&plaintext);
        let wrong = SealingKey::from_bytes(other);
        if wrong.encapsulation_key().to_bytes() == key().encapsulation_key().to_bytes() {
            return Ok(());
        }
        prop_assert!(matches!(
            open_buffered(&file[..], &[&wrong], 8 * CHUNK_SIZE),
            Err(Error::Failed)
        ));
    }

    /// The recipient is found no matter how many decoys come first.
    #[test]
    fn the_recipient_is_found_among_decoys(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        decoys in prop::collection::vec(any::<[u8; 32]>(), 0..6),
    ) {
        let file = encrypt(&plaintext);
        let mut candidates: Vec<SealingKey> =
            decoys.iter().map(|seed| SealingKey::from_bytes(*seed)).collect();
        candidates.push(key());
        let refs: Vec<&SealingKey> = candidates.iter().collect();

        let opened = open_buffered(&file[..], &refs, 8 * CHUNK_SIZE)?;
        prop_assert_eq!(&*opened, &plaintext[..]);
    }

    /// The buffered reader never returns more than its bound.
    #[test]
    fn the_buffered_reader_respects_its_bound(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        bound in 0usize..8192,
    ) {
        let file = encrypt(&plaintext);
        match open_buffered(&file[..], &[&key()], bound) {
            Ok(opened) => prop_assert!(opened.len() <= bound),
            Err(Error::Failed) => prop_assert!(plaintext.len() > bound),
            Err(_) => prop_assert!(false, "a bound may only fail with Error::Failed"),
        }
    }

    /// Arbitrary bytes never panic and never open.
    #[test]
    fn arbitrary_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        match open_buffered(&input[..], &[&key()], 1 << 20) {
            Ok(_) => prop_assert!(false, "arbitrary bytes must never open"),
            Err(_) => prop_assert!(true),
        }
    }
}
