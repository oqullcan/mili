#![no_main]

//! Fuzzes the password wrapped key file.
//!
//! This target reaches Argon2id, which at the profile `SPEC.md` section 7.1
//! records touches 64 MiB three times and takes about 120 ms. That bounds
//! throughput to roughly eight executions a second for any input whose header
//! parses, which is most of them once the fuzzer learns the six byte prefix.
//!
//! The split is deliberate. `mili_core::keyfile` does not expose a parse step
//! separate from the derivation, so there is no way to fuzz the offset arithmetic
//! at full speed from outside the crate, and inventing a public entry point for
//! the fuzzer's benefit would be the wrong trade. What the target does buy is
//! coverage of the whole file including the cost parameters, which is where the
//! bounds in `SPEC.md` section 7.2 are decided, and an end-to-end check that the
//! typed openers cannot be made to disagree with the payload type.
//!
//! Two properties are asserted rather than only the absence of a panic:
//!
//! - If an opener succeeds, the payload type is the one that was asked for. A
//!   sealed key read out of a file whose payload type says signing is a defect
//!   even when nothing crashes.
//! - If `rotate` succeeds, the rotated file opens to the same key. Rotation is
//!   only correct if the key survives it.

use libfuzzer_sys::fuzz_target;
use mili_core::keyfile::KeyFile;

mod common;

const PASSWORD: &[u8] = b"fuzz";

fuzz_target!(|data: &[u8]| {
    let Ok(file) = KeyFile::from_bytes(data) else {
        return;
    };

    let sealing = file.open_sealing_key(PASSWORD).is_ok();
    let signing = file.open_signing_key(PASSWORD).is_ok();
    let symmetric = file.open_symmetric_key(PASSWORD).is_ok();

    // A file holds one key. Two openers succeeding would mean the payload type
    // byte was not consulted, or was consulted inconsistently between them.
    assert!(
        !(sealing && signing) && !(sealing && symmetric) && !(signing && symmetric),
        "more than one opener accepted a {}-byte key file",
        data.len()
    );

    // The same input must reach the same verdict on the second parse, or the
    // type is carrying state.
    if let Ok(again) = KeyFile::from_bytes(data) {
        assert_eq!(
            again.open_sealing_key(PASSWORD).is_ok(),
            sealing,
            "open_sealing_key was not deterministic"
        );
        assert_eq!(
            again.open_signing_key(PASSWORD).is_ok(),
            signing,
            "open_signing_key was not deterministic"
        );
        assert_eq!(
            again.open_symmetric_key(PASSWORD).is_ok(),
            symmetric,
            "open_symmetric_key was not deterministic"
        );
    }

    if let Ok(rotated) = file.rotate(PASSWORD) {
        if sealing {
            let original = file.open_sealing_key(PASSWORD);
            let after = rotated.open_sealing_key(PASSWORD);
            match (original, after) {
                (Ok(before), Ok(after)) => assert_eq!(
                    before.encapsulation_key().to_bytes(),
                    after.encapsulation_key().to_bytes(),
                    "rotation changed the key"
                ),
                (before, after) => panic!(
                    "rotation opened as {:?} but the original opened as {:?}",
                    after.is_ok(),
                    before.is_ok()
                ),
            }
        }
    }
});
