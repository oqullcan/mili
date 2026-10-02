//! Streaming authenticated encryption.
//!
//! This is the `mili-stream-v1` format: the STREAM construction with 64 KiB
//! chunks, a 16 byte Poly1305 tag per chunk, and an explicit final chunk flag.
//! `docs/SPEC.md` section 5 has the layout and the key schedule byte by byte.
//!
//! # What the reader enforces
//!
//! - The chunk counter must advance by exactly one. A chunk presented out of
//!   order is decrypted with the wrong nonce and the wrong associated data.
//! - A chunk that is not the last must be exactly 65552 bytes.
//! - A stream must end with a chunk carrying the final flag. A stream that stops
//!   without one is truncated.
//! - After the final chunk the source must be at end of input. Trailing bytes are
//!   rejected.
//! - A zero length plaintext produces exactly one chunk of 16 bytes, which is a
//!   tag and no ciphertext.
//!
//! # Plaintext exposure
//!
//! A streaming reader releases the plaintext of chunk *i* once chunk *i* is
//! authenticated, before chunk *i+1* has been read. If a later chunk fails, the
//! plaintext of earlier chunks has already reached the caller and cannot be
//! recalled. This is inherent to the construction and is the same behaviour as
//! age and rage.
//!
//! [`StreamReader`] exposes that behaviour because files do not fit in memory.
//! [`open_buffered`] does not: it returns plaintext only after the final chunk
//! authenticates, at the cost of holding the whole message. Read
//! `docs/THREAT_MODEL.md` section 3.2 before choosing.
//!
//! # What the writer never does
//!
//! The writer emits a full length chunk as non-final only when more input
//! follows, so a message whose length is an exact multiple of 64 KiB does not
//! gain a trailing empty chunk. The counter never wraps: reaching `2^64` chunks
//! is an error, not a wrap-around.

use core::fmt;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

use crate::aead::{AeadKey, AeadNonce, NONCE_SIZE, TAG_SIZE};
use crate::error::Error;
use crate::format::{self, SALT_END, SALT_SIZE};
use crate::kdf::{self, Domain};
use crate::kem::{SealingKey, KEM_CIPHERTEXT_SIZE};

/// The `format_type` byte of a stream.
pub const FORMAT_TYPE: u8 = 0x02;

/// Plaintext bytes in a full chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Bytes one full chunk occupies on the wire: the plaintext and its tag.
pub const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Length of the authenticated header: the common prefix and the KEM ciphertext.
pub const HEADER_SIZE: usize = SALT_END + KEM_CIPHERTEXT_SIZE;

/// Bytes a stream adds to a message of `n` plaintext bytes, for `n` in chunks
/// `c`. Exposed so a caller can predict a file size without writing one.
///
/// Saturating, because this is a prediction and `usize::MAX` is the answer to a
/// size nobody can write. It is `const fn` so a caller can size a buffer at
/// compile time, and a wrapping result would be a smaller buffer than the caller
/// asked for, which is worse than a large one.
#[must_use]
pub const fn overhead_for_chunks(plaintext_len: usize, chunks: usize) -> usize {
    HEADER_SIZE
        .saturating_add(plaintext_len)
        .saturating_add(chunks.saturating_mul(TAG_SIZE))
}

/// The `final_flag` byte of a chunk that is not the last one.
const NOT_FINAL: u8 = 0x00;

/// The `final_flag` byte of the last chunk of a stream.
const FINAL: u8 = 0x01;

/// Starts a stream to `sink`, encrypting under `key`.
///
/// The returned writer buffers up to 64 KiB and must be finished with
/// [`StreamWriter::finish`], which writes the final chunk. Dropping it without
/// finishing leaves a truncated file, which any reader will reject; there is no
/// way to produce a file that looks complete but is not.
///
/// # Errors
///
/// [`Error::Failed`] if the operating system randomness source is unavailable.
///
/// # Examples
///
/// ```
/// use mili_core::{stream::seal_stream, SealingKey};
/// use std::io::Write;
///
/// # fn main() -> Result<(), mili_core::Error> {
/// let key = SealingKey::generate()?;
/// let mut file = Vec::new();
/// let mut writer = seal_stream(&key, &mut file)?;
/// writer.write_all(b"a message")?;
/// writer.finish()?;
/// # Ok(())
/// # }
/// ```
pub fn seal_stream<W: Write>(key: &SealingKey, mut sink: W) -> Result<StreamWriter<W>, Error> {
    let mut header = Vec::with_capacity(HEADER_SIZE);
    let salt = crate::rng::array::<SALT_SIZE>()?;
    format::write_fields(&mut header, FORMAT_TYPE);
    header.extend_from_slice(&salt);
    let (kem_ct, shared) = key.encapsulation_key().encapsulate();
    header.extend_from_slice(&kem_ct);

    sink.write_all(&header).map_err(Error::Io)?;

    let file_key = kdf::derive::<32>(Domain::Stream, shared.as_bytes(), &salt)?;
    Ok(StreamWriter {
        sink,
        aead: AeadKey::from_secret(&file_key)?,
        header,
        counter: 0,
        buffer: Vec::with_capacity(ENCRYPTED_CHUNK_SIZE),
        finished: false,
    })
}

/// Opens a stream from `source`, trying each candidate key in order.
///
/// The 1158 byte header is read first, then each key is tried. The first key
/// that authenticates the first chunk wins. The keys are not all tried: the
/// header alone does not authenticate, so the AEAD check on the first chunk is
/// what selects a key, and every candidate that fails it simply moves on.
///
/// A stream whose first chunk does not exist, that is, one shorter than a header
/// plus one tag, cannot authenticate and yields [`Error::Failed`].
///
/// # Errors
///
/// [`Error::UnsupportedVersion`] if the version byte names a version this build
/// does not implement. [`Error::Failed`] for a short read, a wrong magic, a
/// wrong `format_type`, no candidate key that authenticates, and any later chunk
/// that fails.
///
/// # Examples
///
/// ```
/// use mili_core::{stream::seal_stream, SealingKey};
/// use std::io::Write;
///
/// # fn main() -> Result<(), mili_core::Error> {
/// let key = SealingKey::generate()?;
/// let mut file = Vec::new();
/// let mut writer = seal_stream(&key, &mut file)?;
/// writer.write_all(b"a message")?;
/// writer.finish()?;
/// # Ok(())
/// # }
/// ```
pub fn open_stream<R: Read>(mut source: R, keys: &[&SealingKey]) -> Result<StreamReader<R>, Error> {
    let mut header = vec![0u8; HEADER_SIZE];
    read_full(&mut source, &mut header)?;

    let prefix = format::parse_with_salt(&header, FORMAT_TYPE, HEADER_SIZE)?;
    let kem_ct = &prefix.body[..KEM_CIPHERTEXT_SIZE];

    // The first chunk is read once, before the key loop. Reading it inside the
    // loop would consume the source on the first candidate and leave the next
    // candidate with nothing to read.
    let mut probe = vec![0u8; ENCRYPTED_CHUNK_SIZE];
    let filled = read_full(&mut source, &mut probe)?;
    if filled < TAG_SIZE {
        return Err(Error::Failed);
    }
    probe.truncate(filled);

    // Which flag to try is decided by the length, exactly as in
    // `StreamReader::fill`. A short chunk can only be the final one, so it is
    // tried once. A full length chunk may be a non-final chunk or the final
    // chunk of a message whose length is an exact multiple of the chunk size,
    // and the two are indistinguishable by length alone, so both are tried.
    let attempts: &[u8] = if filled < ENCRYPTED_CHUNK_SIZE {
        &[FINAL]
    } else {
        &[NOT_FINAL, FINAL]
    };

    for key in keys {
        let shared = key.decapsulate(kem_ct)?;
        let file_key = kdf::derive::<32>(Domain::Stream, shared.as_bytes(), &prefix.salt)?;
        let aead = AeadKey::from_secret(&file_key)?;

        for flag in attempts {
            let mut candidate = probe.clone();
            if open_chunk(&aead, &header, 0, &mut candidate, *flag).is_ok() {
                return Ok(StreamReader {
                    source,
                    aead,
                    header,
                    counter: 1,
                    buffer: candidate,
                    position: 0,
                    finished: *flag == FINAL,
                });
            }
        }
    }

    Err(Error::Failed)
}

/// Decrypts a whole stream into memory, returning plaintext only if the entire
/// stream authenticates.
///
/// `maximum_plaintext_len` bounds the result. A stream whose plaintext is longer
/// yields [`Error::Failed`] before the plaintext is completed, so a hostile file
/// cannot make this allocate without limit. The bound is the caller's, not
/// mili's: there is no default, because any default would be a policy decision
/// the caller has not made.
///
/// This is the correct entry point for a caller that can hold the message. It has
/// no partial plaintext exposure, which [`open_stream`] does have.
///
/// # Errors
///
/// As [`open_stream`], plus [`Error::Failed`] if the plaintext is longer than
/// `maximum_plaintext_len`.
pub fn open_buffered<R: Read>(
    mut source: R,
    keys: &[&SealingKey],
    maximum_plaintext_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut reader = open_stream(&mut source, keys)?;
    let mut out = Zeroizing::new(Vec::new());
    let mut block = vec![0u8; 8 * 1024];

    loop {
        let read = reader.read(&mut block)?;
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > maximum_plaintext_len {
            return Err(Error::Failed);
        }
        out.extend_from_slice(&block[..read]);
    }
}

/// Encrypts `source` into `sink` in one call.
pub fn seal_buffered<W: Write>(key: &SealingKey, sink: W, source: &[u8]) -> Result<W, Error> {
    let mut writer = seal_stream(key, sink)?;
    writer.write_all(source)?;
    writer.finish()
}

/// Authenticates and decrypts one chunk in place.
///
/// `counter` and `flag` go into both the nonce and the associated data. The nonce
/// alone would already make a mismatched index fail, because the keystream
/// differs; putting the same values in the associated data makes the failure an
/// explicit associated data mismatch rather than an implicit one.
fn open_chunk(
    aead: &AeadKey,
    header: &[u8],
    counter: u64,
    buffer: &mut Vec<u8>,
    flag: u8,
) -> Result<(), Error> {
    let mut aad = Vec::with_capacity(header.len().saturating_add(NONCE_SIZE));
    aad.extend_from_slice(header);
    aad.extend_from_slice(&counter_bytes(counter));
    aad.push(flag);
    aead.open_in_place(nonce(counter, flag), &aad, buffer)
}

/// The 11 byte big endian chunk counter.
fn counter_bytes(counter: u64) -> [u8; 11] {
    let mut out = [0u8; 11];
    // A u64 is 8 bytes into an 11 byte field, so the high three bytes are zero.
    out[3..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// The 12 byte chunk nonce: the counter then the final chunk flag.
fn nonce(counter: u64, flag: u8) -> AeadNonce {
    let mut bytes = [0u8; 12];
    bytes[..11].copy_from_slice(&counter_bytes(counter));
    bytes[11] = flag;
    AeadNonce::from_bytes(bytes)
}

/// Fills `buffer` from `source` and reports how many bytes were read.
///
/// `Read::read` may return less than asked for without being at end of input, so
/// a single call is not enough to tell a short chunk from a finished one. This
/// loops until the buffer is full or the source is at end of input.
///
/// A zero return means the source is exhausted. Any other error is the source's
/// own, mapped to [`Error::Io`].
fn read_full<R: Read>(source: &mut R, buffer: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            // `read` cannot return more than it was handed the space for, so this
            // cannot pass `buffer.len()` and end the loop by itself.
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(filled)
}

/// Encrypts a stream to a `Write` sink.
pub struct StreamWriter<W: Write> {
    sink: W,
    aead: AeadKey,
    header: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
    finished: bool,
}

impl<W: Write> StreamWriter<W> {
    /// Writes the final chunk and returns the sink.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the chunk counter would reach `2^64`, and
    /// [`Error::Io`] if the sink fails. Calling this twice fails, because a
    /// second final chunk would be trailing data in every reader.
    pub fn finish(mut self) -> Result<W, Error> {
        self.flush_chunk(FINAL)?;
        self.finished = true;
        Ok(self.sink)
    }

    /// Returns the sink without writing a final chunk.
    ///
    /// The file this produces is truncated and every mili reader rejects it. This
    /// exists so that a caller which has its own finalisation path is not forced
    /// to panic, not as a way to make a valid file.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Encrypts the buffered plaintext as one chunk and clears the buffer.
    fn flush_chunk(&mut self, flag: u8) -> Result<(), Error> {
        if self.counter == u64::MAX {
            // The counter would wrap and a nonce would repeat. Refusing here
            // rather than wrapping is the whole reason nonces are derived from a
            // counter that is checked.
            return Err(Error::Failed);
        }
        let chunk_counter = self.counter;
        self.counter = self.counter.checked_add(1).ok_or(Error::Failed)?;

        let mut aad = Vec::with_capacity(self.header.len().saturating_add(12));
        aad.extend_from_slice(&self.header);
        aad.extend_from_slice(&counter_bytes(chunk_counter));
        aad.push(flag);

        self.aead
            .seal_extend(nonce(chunk_counter, flag), &aad, &mut self.buffer)?;
        self.sink.write_all(&self.buffer).map_err(Error::Io)?;
        self.buffer.clear();
        Ok(())
    }
}

impl<W: Write> fmt::Debug for StreamWriter<W> {
    /// Redacted. The writer holds the file key, so nothing here prints it or the
    /// buffered plaintext.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamWriter")
            .field("chunks_written", &self.counter)
            .field("buffered_bytes", &self.buffer.len())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<W: Write> Write for StreamWriter<W> {
    /// # Errors
    ///
    /// [`Error::Failed`] if this writer has already been finished, or if the sink
    /// fails.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("mili: the stream is already finished"));
        }
        let mut remaining = data;
        while !remaining.is_empty() {
            // `buffer` only ever grows to `CHUNK_SIZE` and is cleared on flush, so
            // the subtraction cannot underflow. `checked_sub` says so instead of
            // leaving it to a reader three lines up.
            let room = CHUNK_SIZE
                .checked_sub(self.buffer.len())
                .ok_or(io::Error::other("mili: the chunk buffer is over full"))?;
            let take = room.min(remaining.len());
            self.buffer.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            // A full buffer is only flushed when more input follows. Flushing it
            // here unconditionally would give every message whose length is a
            // multiple of the chunk size a trailing empty final chunk.
            if self.buffer.len() == CHUNK_SIZE && !remaining.is_empty() {
                self.flush_chunk(NOT_FINAL)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
        }
        Ok(data.len())
    }

    /// # Errors
    ///
    /// As [`Write::write`].
    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// Decrypts a stream from a `Read` source.
pub struct StreamReader<R: Read> {
    source: R,
    aead: AeadKey,
    header: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
    position: usize,
    finished: bool,
}

impl<R: Read> StreamReader<R> {
    /// Reads and authenticates the next chunk into the plaintext buffer.
    ///
    /// Returns false at a clean end of input.
    fn fill(&mut self) -> Result<bool, Error> {
        if self.finished {
            // After the final chunk the source must be exhausted. One byte is
            // enough to tell, and trailing data of any length is rejected.
            let mut probe = [0u8; 1];
            return match read_full(&mut self.source, &mut probe)? {
                0 => Ok(false),
                _ => Err(Error::Failed),
            };
        }

        let mut chunk = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let filled = read_full(&mut self.source, &mut chunk)?;
        if filled == 0 {
            // The source ended without a final chunk. The stream is truncated.
            return Err(Error::Failed);
        }
        chunk.truncate(filled);

        let flag = if filled < ENCRYPTED_CHUNK_SIZE {
            // Only the final chunk may be short.
            FINAL
        } else {
            NOT_FINAL
        };

        if open_chunk(&self.aead, &self.header, self.counter, &mut chunk, flag).is_ok() {
            if flag == FINAL {
                self.finished = true;
            }
        } else if filled == ENCRYPTED_CHUNK_SIZE {
            // A full length chunk may be the final chunk of a message whose
            // length is an exact multiple of the chunk size.
            if open_chunk(&self.aead, &self.header, self.counter, &mut chunk, FINAL).is_ok() {
                self.finished = true;
            } else {
                return Err(Error::Failed);
            }
        } else {
            return Err(Error::Failed);
        }

        if self.counter == u64::MAX {
            return Err(Error::Failed);
        }
        self.counter = self.counter.checked_add(1).ok_or(Error::Failed)?;
        self.buffer = chunk;
        self.position = 0;
        Ok(true)
    }
}

impl<R: Read> fmt::Debug for StreamReader<R> {
    /// Redacted. The reader holds the file key and the decrypted buffer, so
    /// neither is printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamReader")
            .field("chunks_read", &self.counter)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Read for StreamReader<R> {
    /// # Errors
    ///
    /// [`Error::Io`] if the source fails, and [`Error::Failed`] if a chunk does
    /// not authenticate, the stream is truncated, the stream has trailing data,
    /// or the counter would wrap.
    ///
    /// A failure after some plaintext has already been returned is possible and
    /// is why `docs/THREAT_MODEL.md` section 3.2 says to discard everything on error.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.position < self.buffer.len() {
                let available =
                    self.buffer
                        .len()
                        .checked_sub(self.position)
                        .ok_or(io::Error::other(
                            "mili: the chunk position is past the buffer",
                        ))?;
                let take = available.min(out.len());
                let end = self
                    .position
                    .checked_add(take)
                    .ok_or(io::Error::other("mili: the chunk position overflowed"))?;
                let source = self
                    .buffer
                    .get(self.position..end)
                    .ok_or(io::Error::other("mili: the chunk slice is out of range"))?;
                out.get_mut(..take)
                    .ok_or(io::Error::other("mili: the output slice is too small"))?
                    .copy_from_slice(source);
                self.position = end;
                return Ok(take);
            }
            match self.fill() {
                Ok(true) => {}
                Ok(false) => return Ok(0),
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    ))
                }
            }
            if out.is_empty() {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        counter_bytes, nonce, overhead_for_chunks, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, FINAL,
        FORMAT_TYPE, HEADER_SIZE, NOT_FINAL,
    };
    #[cfg(not(miri))]
    use super::{open_buffered, open_stream, seal_buffered, seal_stream};
    use crate::aead::TAG_SIZE;
    #[cfg(not(miri))]
    use crate::{Error, SealingKey};
    #[cfg(not(miri))]
    use std::io::{Read, Write};

    // Tests that call ML-KEM-768 or X25519 arithmetic are excluded under miri.
    // Each decapsulation costs orders of magnitude more when miri interprets it.
    // The tests that are not excluded check mili's own counters, nonces and
    // associated data construction.
    #[cfg(not(miri))]
    fn key() -> SealingKey {
        SealingKey::from_bytes([0x17u8; 32])
    }

    #[cfg(not(miri))]
    fn encrypt(plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        seal_buffered(&key(), &mut out, plaintext).expect("seal");
        out
    }

    #[cfg(not(miri))]
    fn decrypt(file: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        open_buffered(file, &[&key()], 16 * 1024 * 1024)
    }

    #[cfg(not(miri))]
    fn chunk_boundaries() -> Vec<usize> {
        vec![
            0,
            1,
            TAG_SIZE - 1,
            TAG_SIZE,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 1,
            3 * CHUNK_SIZE - 1,
        ]
    }

    #[test]
    fn documented_sizes() {
        assert_eq!(FORMAT_TYPE, 0x02);
        assert_eq!(CHUNK_SIZE, 65536);
        assert_eq!(ENCRYPTED_CHUNK_SIZE, 65552);
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(HEADER_SIZE, 1158);
        assert_eq!(overhead_for_chunks(10, 1), 1158 + 10 + 16);
        assert_eq!(overhead_for_chunks(0, 1), 1158 + 16);
    }

    #[test]
    fn the_counter_is_eleven_bytes_big_endian() {
        assert_eq!(counter_bytes(0), [0u8; 11]);
        assert_eq!(counter_bytes(1)[10], 1);
        let big = counter_bytes(u64::MAX);
        assert_eq!(
            big[0..3],
            [0u8; 3],
            "a u64 must not fill the top three bytes"
        );
        assert_eq!(big[3..], u64::MAX.to_be_bytes());
    }

    #[test]
    fn the_nonce_is_the_counter_then_the_flag() {
        let non_final = nonce(7, NOT_FINAL);
        let final_chunk = nonce(7, FINAL);
        assert_eq!(non_final.as_bytes()[..11], counter_bytes(7));
        assert_eq!(non_final.as_bytes()[11], NOT_FINAL);
        assert_eq!(final_chunk.as_bytes()[11], FINAL);
        assert_ne!(non_final, final_chunk);
        assert_ne!(nonce(7, FINAL), nonce(8, FINAL));
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip_at_every_chunk_boundary() {
        for len in chunk_boundaries() {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let file = encrypt(&plaintext);
            let chunks = if len == 0 {
                1
            } else {
                len.div_ceil(CHUNK_SIZE)
            };
            assert_eq!(
                file.len(),
                overhead_for_chunks(len, chunks),
                "length {len}: wrong file size"
            );
            assert_eq!(*decrypt(&file).expect("open"), plaintext, "length {len}");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_zero_length_plaintext_is_one_tag_only_chunk() {
        let file = encrypt(b"");
        assert_eq!(file.len(), HEADER_SIZE + TAG_SIZE);
        let plaintext = decrypt(&file).expect("open");
        assert!(plaintext.is_empty());
    }

    #[test]
    #[cfg(not(miri))]
    fn a_message_that_is_an_exact_multiple_of_the_chunk_size_gets_no_empty_chunk() {
        for len in [CHUNK_SIZE, 2 * CHUNK_SIZE] {
            let plaintext = vec![0x5Au8; len];
            let file = encrypt(&plaintext);
            assert_eq!(
                file.len(),
                HEADER_SIZE + len + (len / CHUNK_SIZE) * TAG_SIZE,
                "length {len} gained a trailing empty chunk"
            );
            assert_eq!(*decrypt(&file).expect("open"), plaintext);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_header_is_where_the_specification_says() {
        let file = encrypt(b"x");
        assert_eq!(&file[0..4], b"mili");
        assert_eq!(file[4], 0x02);
        assert_eq!(file[5], 0x01);
        assert_eq!(file.len(), 1158 + 1 + 16);
    }

    #[test]
    #[cfg(not(miri))]
    fn every_truncation_is_rejected() {
        let plaintext: Vec<u8> = (0..CHUNK_SIZE + 100).map(|i| (i % 251) as u8).collect();
        let file = encrypt(&plaintext);

        // A dense pass over the first 64 lengths, a pass over every length
        // within a chunk of each chunk boundary, and a stride over the rest.
        // The exhaustive sweep is in the property tests; doing all ~66000
        // lengths here would mean ~66000 ML-KEM decapsulations.
        let mut lengths: Vec<usize> = (0..64.min(file.len())).collect();
        for boundary in [
            HEADER_SIZE,
            HEADER_SIZE + TAG_SIZE,
            HEADER_SIZE + ENCRYPTED_CHUNK_SIZE,
            file.len(),
        ] {
            let low = boundary.saturating_sub(24);
            lengths.extend(low..boundary.min(file.len()));
        }
        lengths.extend((0..file.len()).step_by(97));

        let mut seen = std::collections::BTreeSet::new();
        for len in lengths {
            if len >= file.len() || !seen.insert(len) {
                continue;
            }
            assert!(
                decrypt(&file[..len]).is_err(),
                "truncation to {len} bytes was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn appended_bytes_are_rejected() {
        let file = encrypt(b"a message");
        for extra in [1usize, 16, 100] {
            let mut tampered = file.clone();
            tampered.extend(std::iter::repeat_n(0u8, extra));
            assert!(
                decrypt(&tampered).is_err(),
                "appending {extra} bytes was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_key_is_rejected() {
        let file = encrypt(b"a message");
        let wrong = SealingKey::from_bytes([0x18u8; 32]);
        assert!(matches!(
            open_buffered(&file[..], &[&wrong], 1024),
            Err(Error::Failed)
        ));
        assert!(matches!(
            open_buffered(&file[..], &[], 1024),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn the_right_key_is_found_among_wrong_ones() {
        let file = encrypt(b"a message");
        let right = key();
        let others: Vec<SealingKey> = (0..4)
            .map(|i| SealingKey::from_bytes([i as u8; 32]))
            .collect();
        let mut candidates: Vec<&SealingKey> = others.iter().collect();
        candidates.push(&right);
        let plaintext = open_buffered(&file[..], &candidates, 1024).expect("open");
        assert_eq!(*plaintext, b"a message");
    }

    #[test]
    #[cfg(not(miri))]
    fn every_byte_of_the_header_is_authenticated() {
        let file = encrypt(b"a message");
        for index in 0..HEADER_SIZE {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            let result = decrypt(&tampered);
            assert!(result.is_err(), "header byte {index} was accepted");
            if index == 5 {
                assert!(matches!(result, Err(Error::UnsupportedVersion)));
            } else {
                assert!(matches!(result, Err(Error::Failed)), "header byte {index}");
            }
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn tampering_any_chunk_is_rejected() {
        let plaintext: Vec<u8> = (0..CHUNK_SIZE + 64).map(|i| (i % 251) as u8).collect();
        let file = encrypt(&plaintext);
        let body = &file[HEADER_SIZE..];

        // A stride across each chunk, plus every byte of the last 32, which
        // covers the final chunk's tag densely. The sealed box format has an
        // exhaustive sweep because its file is small enough; two 65552 byte
        // chunks are not, and 131000 decapsulations would dominate the run. The
        // property tests cover the stride gaps.
        let mut positions: Vec<usize> = (0..body.len()).step_by(61).collect();
        positions.extend(body.len().saturating_sub(32)..body.len());
        positions.push(body.len() - 1);

        for position in positions {
            let mut tampered = file.clone();
            tampered[HEADER_SIZE + position] ^= 0x01;
            assert!(
                decrypt(&tampered).is_err(),
                "body byte {position} was accepted after a bit flip"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn swapping_two_chunks_is_rejected() {
        let plaintext: Vec<u8> = (0..3 * CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
        let file = encrypt(&plaintext);
        let body = &file[HEADER_SIZE..];
        assert_eq!(body.len(), 3 * ENCRYPTED_CHUNK_SIZE);

        let first = body[..ENCRYPTED_CHUNK_SIZE].to_vec();
        let second = body[ENCRYPTED_CHUNK_SIZE..2 * ENCRYPTED_CHUNK_SIZE].to_vec();
        let third = body[2 * ENCRYPTED_CHUNK_SIZE..].to_vec();

        // Every ordered pair of distinct chunks, plus a rotation.
        for (a, b) in [(&second, &first), (&third, &first), (&third, &second)] {
            let mut tampered = file[..HEADER_SIZE].to_vec();
            tampered.extend_from_slice(a);
            tampered.extend_from_slice(b);
            tampered.extend_from_slice(if std::ptr::eq(a, &first) {
                &third
            } else {
                &first
            });
            assert!(decrypt(&tampered).is_err(), "a swap was accepted");
        }

        let mut rotated = file[..HEADER_SIZE].to_vec();
        rotated.extend_from_slice(&second);
        rotated.extend_from_slice(&third);
        rotated.extend_from_slice(&first);
        assert!(decrypt(&rotated).is_err(), "a rotation was accepted");
    }

    #[test]
    #[cfg(not(miri))]
    fn dropping_a_chunk_is_rejected() {
        let plaintext: Vec<u8> = (0..3 * CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
        let file = encrypt(&plaintext);
        let body = &file[HEADER_SIZE..];

        for index in 0..3 {
            let mut tampered = file[..HEADER_SIZE].to_vec();
            for (position, chunk) in body
                .chunks(ENCRYPTED_CHUNK_SIZE)
                .enumerate()
                .filter(|(position, _)| *position != index)
            {
                let _ = position;
                tampered.extend_from_slice(chunk);
            }
            assert!(
                decrypt(&tampered).is_err(),
                "dropping chunk {index} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn duplicating_the_final_chunk_is_rejected() {
        let plaintext: Vec<u8> = (0..CHUNK_SIZE + 10).map(|i| (i % 251) as u8).collect();
        let file = encrypt(&plaintext);
        let body = &file[HEADER_SIZE..];
        let final_chunk = &body[(body.len() - ENCRYPTED_CHUNK_SIZE)..];

        let mut tampered = file.clone();
        tampered.extend_from_slice(final_chunk);
        assert!(
            decrypt(&tampered).is_err(),
            "a duplicated final chunk was accepted"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_file_is_rejected() {
        let mut file = encrypt(b"a message");
        file[4] = 0x01;
        assert!(matches!(decrypt(&file), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_unknown_version_is_reported_as_such() {
        let mut file = encrypt(b"a message");
        file[5] = 0x02;
        assert!(matches!(decrypt(&file), Err(Error::UnsupportedVersion)));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_short_header_never_panics() {
        for len in [0usize, 1, 5, 38, 1157, 1158 + 15] {
            let buffer = vec![0u8; len];
            assert!(
                open_buffered(&buffer[..], &[&key()], 1024).is_err(),
                "length {len}"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_buffered_reader_enforces_its_bound() {
        let plaintext = vec![0x33u8; 4096];
        let file = encrypt(&plaintext);
        assert!(matches!(
            open_buffered(&file[..], &[&key()], 4095),
            Err(Error::Failed)
        ));
        assert_eq!(
            *open_buffered(&file[..], &[&key()], 4096).expect("open"),
            plaintext
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn the_streaming_reader_reproduces_the_message_byte_for_byte() {
        let plaintext: Vec<u8> = (0..5 * CHUNK_SIZE + 12345)
            .map(|i| (i % 251) as u8)
            .collect();
        let file = encrypt(&plaintext);

        let mut reader = open_stream(&file[..], &[&key()]).expect("open");
        let mut out = Vec::new();
        let mut block = vec![0u8; 997];
        loop {
            let read = reader.read(&mut block).expect("read");
            if read == 0 {
                break;
            }
            out.extend_from_slice(&block[..read]);
        }
        assert_eq!(out, plaintext);
    }

    #[test]
    #[cfg(not(miri))]
    fn the_streaming_reader_reports_a_corrupt_chunk_as_an_io_error() {
        let plaintext: Vec<u8> = (0..CHUNK_SIZE + 64).map(|i| (i % 251) as u8).collect();
        let mut file = encrypt(&plaintext);
        // The first chunk is consumed while the key is being selected, so a
        // corruption there fails in `open_stream` rather than here. Corrupt the
        // second chunk, which the reader reaches only after it has already
        // released plaintext.
        file[HEADER_SIZE + ENCRYPTED_CHUNK_SIZE + 5] ^= 0x01;

        let mut reader = open_stream(&file[..], &[&key()]).expect("open");
        let mut out = Vec::new();
        let result = std::io::copy(&mut reader, &mut out);
        assert!(result.is_err(), "a corrupt chunk was read without an error");
    }

    #[test]
    #[cfg(not(miri))]
    fn the_writer_hands_the_sink_back_on_finish() {
        let mut out = Vec::new();
        let mut writer = seal_stream(&key(), &mut out).expect("seal");
        writer.write_all(b"a message").expect("write");
        let sink = writer.finish().expect("finish");
        sink.write_all(b"")
            .expect("the sink is usable after finish");
        assert_eq!(*decrypt(&out).expect("open"), b"a message");
    }

    #[test]
    #[cfg(not(miri))]
    fn debug_is_redacted() {
        let file = encrypt(b"a message");
        let reader = open_stream(&file[..], &[&key()]).expect("open");
        let rendered = format!("{reader:?}");
        assert!(rendered.starts_with("StreamReader"), "{rendered}");
        assert!(
            !rendered.contains("a message"),
            "debug output leaked plaintext"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn two_streams_of_the_same_plaintext_differ() {
        let a = encrypt(b"the same message");
        let b = encrypt(b"the same message");
        assert_ne!(a, b);
    }
}
