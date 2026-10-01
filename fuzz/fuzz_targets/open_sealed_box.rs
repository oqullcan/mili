#![no_main]

//! Fuzzes the single shot sealed box.
//!
//! The input is the file. The recipient key is fixed so that a crash is
//! reproducible from the input alone.
//!
//! The sealed box decrypts with X-Wing, which costs an ML-KEM-768
//! decapsulation per attempt. libFuzzer will spend most of its time on inputs
//! that fail the header checks, which is the intended cheap path; the
//! decapsulation only runs once the header is well formed, which the coverage
//! feedback reaches quickly from a seeded corpus.

use libfuzzer_sys::fuzz_target;
use mili_core::{open, SealingKey};

mod common;

fuzz_target!(|data: &[u8]| {
    let recipient = SealingKey::from_bytes(common::RECIPIENT_SEED);
    // A rejection is the expected outcome. A panic is the finding.
    let _ = open(data, &[&recipient]);
});
