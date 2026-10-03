//! Shared helpers for the fuzz targets.
//!
//! Every target follows the same three rules, so they are stated once here rather
//! than repeated in each file.
//!
//! 1. The claim under test is panic freedom. `mili-core` is
//!    `#![forbid(unsafe_code)]` and every parse is length checked and fallible, so
//!    any panic reachable from these targets is a defect.
//!    `docs/THREAT_MODEL.md` section 2.10 claims the fuzz targets check this, and they
//!    are the only evidence for it.
//!
//! 2. A rejection is a success. Every target feeds attacker-shaped bytes in and
//!    treats `Err` as the expected outcome. A target that only failed on an
//!    accepted input would find nothing, because the formats are supposed to
//!    reject almost everything.
//!
//! 3. No target may loop on its input for an unbounded time. A parser that can be
//!    made to spin is as much a finding as one that panics, so the reader below is
//!    bounded and every target has a total byte budget.

// Each fuzz target is a separate binary and compiles this module separately, so
// every target sees the other targets' helpers as unused.
#![allow(dead_code)]

use std::io::{self, Read};

/// A `Read` that yields `data` in caller-chosen fragment sizes.
///
/// `StreamReader` is generic over `Read` and is normally driven by a `File` or a
/// `Cursor`. A `Cursor` returns everything it has in one call, so the partial
/// header and partial chunk handling, which is where a length check is easiest to
/// get wrong, is unreachable through the buffer APIs a caller would actually use.
/// This reader makes it reachable by returning at most `sizes[position % len]`
/// bytes per call.
pub struct Fragmented<'a> {
    data: &'a [u8],
    offset: usize,
    sizes: &'a [u8],
    position: usize,
    budget: usize,
}

/// The most bytes any target will read for one input.
///
/// This bounds the fragmented readers, which otherwise let the input decide how
/// many `read` calls happen. A megabyte is far above any mili header or chunk.
pub const BYTE_BUDGET: usize = 1024 * 1024;

impl<'a> Fragmented<'a> {
    /// Builds a reader over `data` that returns at most `sizes[position % len]`
    /// bytes per call.
    ///
    /// An empty `sizes` falls back to reading everything at once, which is the
    /// `Cursor` behaviour and therefore the case the unit tests already cover.
    pub fn new(data: &'a [u8], sizes: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            sizes,
            position: 0,
            budget: BYTE_BUDGET,
        }
    }
}

impl Read for Fragmented<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.budget == 0 {
            // End of input rather than an error: a target that reads to the end
            // must not spin, and the budget belongs to the harness, not to the
            // file.
            return Ok(0);
        }
        if self.offset >= self.data.len() || out.is_empty() {
            return Ok(0);
        }

        let take = if self.sizes.is_empty() {
            out.len()
        } else {
            let want = self.sizes[self.position % self.sizes.len()] as usize;
            self.position = self.position.wrapping_add(1);
            want
        };
        let take = take.max(1).min(out.len()).min(self.data.len() - self.offset);

        out[..take].copy_from_slice(&self.data[self.offset..self.offset + take]);
        self.offset += take;
        self.budget -= take;
        Ok(take)
    }
}

/// The recipient key the sealed box and stream targets seal to.
///
/// A fixed key rather than a generated one, so a finding is reproducible from the
/// crashing input alone: libFuzzer replays the input, and the input does not also
/// have to carry the key that was in use when it was found.
pub const RECIPIENT_SEED: [u8; 32] = [0x37u8; 32];
