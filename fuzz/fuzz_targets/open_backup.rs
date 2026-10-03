#![no_main]

//! Fuzzes the backup container.
//!
//! This target reaches Argon2id once, for the whole container, so its cost does
//! not grow with the entry count. See `open_key_file` for why that is a
//! throughput concern rather than a correctness one.
//!
//! The property asserted beyond panic freedom is that the identifiers a container
//! reports are distinct. `docs/SPEC.md` section 8 refuses a container that holds two
//! entries with the same identifier, and a container that decoded into a list
//! with a repeat would break the only mechanism a caller has for telling its
//! backups apart.

use libfuzzer_sys::fuzz_target;
use mili_core::backup::Backup;

mod common;

const PASSWORD: &[u8] = b"fuzz";

fuzz_target!(|data: &[u8]| {
    let Ok(backup) = Backup::from_bytes(data) else {
        return;
    };

    let first = backup.open(PASSWORD);
    if let Ok(entries) = &first {
        let mut ids: Vec<[u8; 16]> = entries.iter().map(|entry| entry.key_id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            total,
            "a {}-byte container decoded to {total} entries with a repeated identifier",
            data.len()
        );
    }

    // A second open of the same bytes must reach the same verdict.
    if let Ok(again) = Backup::from_bytes(data) {
        match (first, again.open(PASSWORD)) {
            (Ok(a), Ok(b)) => assert_eq!(
                a.len(),
                b.len(),
                "open returned a different entry count for the same bytes"
            ),
            (Err(_), Err(_)) => {}
            (a, b) => panic!(
                "open returned Ok({}) and then Ok({}) for the same bytes",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }
});
