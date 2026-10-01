#![no_main]

//! Fuzzes the streaming file format through a reader that returns short reads.
//!
//! This is the target for the code the buffer APIs cannot reach. `open_stream`
//! reads its 1174 byte header field by field and its chunks field by field, and
//! every one of those loops has a "the source gave me fewer bytes than the format
//! says are here" branch. A `Cursor` never produces a short read in the middle,
//! so those branches are dead under `cargo test` and under every other fuzz
//! target here.
//!
//! The second half of the input chooses the fragment sizes, so one target covers
//! everything from "one byte at a time" to "as much as asked for".

use libfuzzer_sys::fuzz_target;
use mili_core::stream::open_buffered;
use mili_core::SealingKey;

mod common;

const MAXIMUM_PLAINTEXT: usize = 1024 * 1024;

/// The number of trailing input bytes reserved for the fragment size schedule.
///
/// A schedule needs a byte per read call, so it is taken from the end of the
/// input rather than the front, which would put a constraint on the file's own
/// first byte and stop the fuzzer from ever producing a valid header.
const SCHEDULE_BYTES: usize = 64;

fuzz_target!(|data: &[u8]| {
    let (file, schedule) = if data.len() > SCHEDULE_BYTES {
        let split = data.len() - SCHEDULE_BYTES;
        (&data[..split], &data[split..])
    } else {
        (data, &data[data.len()..])
    };

    let recipient = SealingKey::from_bytes(common::RECIPIENT_SEED);
    let source = common::Fragmented::new(file, schedule);
    let _ = open_buffered(source, &[&recipient], MAXIMUM_PLAINTEXT);
});
