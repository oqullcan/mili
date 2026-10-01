#![no_main]

//! Fuzzes the streaming file format through a `Cursor`, which returns everything
//! it has in one read.
//!
//! This is the case the unit tests already cover. The partial read paths are in
//! `open_stream_fragments`.

use libfuzzer_sys::fuzz_target;
use mili_core::stream::open_buffered;
use mili_core::SealingKey;
use std::io::Cursor;

mod common;

/// The plaintext cap `open_buffered` is given.
///
/// A cap keeps a target from allocating in proportion to the input when the input
/// is a long run of valid chunks, and it exercises the bound's own error path.
const MAXIMUM_PLAINTEXT: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let recipient = SealingKey::from_bytes(common::RECIPIENT_SEED);
    let _ = open_buffered(Cursor::new(data), &[&recipient], MAXIMUM_PLAINTEXT);
});
