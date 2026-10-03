#![no_main]

//! Fuzzes composite signature verification.
//!
//! The input is split into a verifying key, a message and a signature. A
//! verifying key that does not decode is skipped, because the interesting inputs
//! are the ones that reach the two component verifications.
//!
//! The property is the composite rule itself: `docs/SPEC.md` section 6 says a
//! composite signature is valid only if both component signatures verify against
//! the same message and context. Verifying twice must reach the same verdict, and
//! a signature must never be accepted for a message it was not made for.

use libfuzzer_sys::fuzz_target;
use mili_core::signature::{VerifyingKey, VERIFYING_KEY_SIZE};

fuzz_target!(|data: &[u8]| {
    if data.len() < VERIFYING_KEY_SIZE {
        return;
    }

    let Ok(verifying) = VerifyingKey::from_bytes(&data[..VERIFYING_KEY_SIZE]) else {
        return;
    };

    let body = &data[VERIFYING_KEY_SIZE..];
    // Split at a fuzzer-chosen point so the message and the signature both vary
    // in length, including the empty case on either side.
    let split = if body.is_empty() {
        0
    } else {
        (body[0] as usize) % (body.len() + 1)
    };
    let (message, signature) = body.split_at(split);

    let first = verifying.verify(message, signature).is_ok();
    let second = verifying.verify(message, signature).is_ok();
    assert_eq!(first, second, "verification was not deterministic");

    // A signature that verified for a message must not verify for that message
    // with one byte appended. Both component schemes bind the whole message, so
    // there is no length or extension property for this to have.
    if first && !message.is_empty() {
        let mut extended = message.to_vec();
        extended.push(0);
        assert!(
            verifying.verify(&extended, signature).is_err(),
            "a signature verified for a message one byte longer than the one it was made for"
        );
    }
});
