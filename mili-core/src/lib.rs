//! mili: parameter selection and a misuse-resistant wrapper around third-party
//! Rust cryptography crates.
//!
//! mili implements no cryptographic primitive. Every cipher, key encapsulation
//! mechanism, signature scheme, key derivation function and random number
//! generator it uses comes from a crate written by someone else. What mili adds
//! is a choice of parameters, a key schedule with mandatory domain separation,
//! a versioned wire format, and an API shaped so that a wrong combination of
//! operations does not compile.
//!
//! # Suite
//!
//! | Purpose | Algorithm | Standard |
//! |---------|-----------|----------|
//! | Key encapsulation | X-Wing over X25519 and ML-KEM-768 | `draft-connolly-cfrg-xwing-kem`, not an RFC |
//! | Signature | ML-DSA-65 and Ed25519, valid only if both verify | `draft-ietf-lamps-pq-composite-sigs`, not an RFC |
//! | AEAD | ChaCha20-Poly1305 | RFC 8439 |
//! | Key derivation | HKDF-SHA256 | RFC 5869 |
//! | Password derivation | Argon2id, 64 MiB, 3 passes | RFC 9106 |
//! | Randomness | operating system CSPRNG | - |
//!
//! Symmetric keys are 256 bit. There is no algorithm selection, no runtime
//! option and no environment variable that changes any of the above.
//!
//! # Sealed boxes
//!
//! [`seal()`] encrypts one buffer to one recipient's [`EncapsulationKey`], and
//! [`open()`] decrypts it by trying a list of candidate [`SealingKey`] values. The
//! file names no recipient and no key identifier, so an observer cannot tell
//! which of a recipient's keys opened a file, or whether two files share a
//! recipient at all. `SPEC.md` section 10 records that trade-off.
//!
//! ```
//! use mili_core::{open, seal, SealingKey};
//!
//! # fn main() -> Result<(), mili_core::Error> {
//! let key = SealingKey::generate()?;
//! let sealed = seal(&key.encapsulation_key(), b"a message")?;
//! assert_eq!(*open(&sealed, &[&key])?, *b"a message");
//! # Ok(())
//! # }
//! ```
//!
//! # Streaming
//!
//! [`stream::seal_stream`] and [`stream::open_stream`] implement `mili-stream-v1`,
//! the STREAM construction with 64 KiB chunks. Truncation, reordering, appending
//! and single bit flips are all detected. [`stream::open_buffered`] is the form
//! with no partial plaintext exposure, at the cost of holding the whole message.
//! `SPEC.md` section 5 has the details.
//!
//! ```
//! use mili_core::stream::{open_buffered, seal_buffered};
//! use mili_core::SealingKey;
//!
//! # fn main() -> Result<(), mili_core::Error> {
//! let key = SealingKey::generate()?;
//! let mut file = Vec::new();
//! seal_buffered(&key, &mut file, b"a message")?;
//! assert_eq!(*open_buffered(&file[..], &[&key], 1024)?, *b"a message");
//! # Ok(())
//! # }
//! ```
//!
//! # What is not here yet
//!
//! Key files and the FFI are added in later phases, each under its own format
//! version as specified in `SPEC.md`.
//!
//! # Errors
//!
//! Every fallible operation returns [`Error`]. Authentication, key agreement
//! and cryptographic parse failures all return the same variant, [`Error::Failed`],
//! whose message is a fixed string with no detail about which check failed. This
//! is deliberate. Do not add a public accessor that reveals the failing check.
//!
//! # Examples
//!
//! ```
//! use mili_core::SymmetricKey;
//!
//! # fn main() -> Result<(), mili_core::Error> {
//! let key = SymmetricKey::generate()?;
//! assert_eq!(format!("{key:?}"), "SymmetricKey([REDACTED])");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
// Every arithmetic operation in the library states how it behaves when it wraps.
//
// This is a restriction lint rather than a style one. mili parses lengths, counts
// and offsets out of files an attacker controls, and a wrapping addition in that
// code produces a number the writer never wrote, which is how a length check
// turns into a length that passes. The `open_backup` fuzz target found exactly
// that: `HEADER_SIZE + entries_len + TAG_SIZE` wrapped for a length near
// `usize::MAX`, and on a release build without overflow checks the wrapped sum
// was small enough to compare equal to a real file length.
//
// The lint is not applied to the test modules, where `len % 256` and friends are
// arithmetic on values the test itself chose and there is nothing to wrap.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
// `must_use` on everything whose result a caller could drop and regret.
//
// `Result` already carries `#[must_use]`, so these are the accessors that hand
// back a key, a key identifier or a file's bytes as a plain value: a caller who
// calls `to_bytes()` and drops the result has a bug the compiler can see. The lint
// is scoped to the library because on test code "someone might ignore this" is
// not a bug.
#![cfg_attr(
    not(test),
    deny(clippy::must_use_candidate, clippy::return_self_not_must_use)
)]

mod aead;
pub mod backup;
pub mod error;
mod format;
pub mod kdf;
mod kem;
pub mod keyfile;
mod rng;
pub mod seal;
pub mod secret;
pub mod signature;
pub mod stream;

pub use crate::error::Error;
pub use crate::kem::{EncapsulationKey, SealingKey, ENCAPSULATION_KEY_SIZE, SEALING_KEY_SIZE};
pub use crate::seal::{open, seal, SEALED_BOX_OVERHEAD};
pub use crate::secret::{SymmetricKey, SYMMETRIC_KEY_SIZE};
pub use crate::signature::{
    SigningKey, VerifyingKey, SIGNATURE_PAYLOAD_SIZE, SIGNATURE_SIZE, SIGNING_KEY_SIZE,
    VERIFYING_KEY_SIZE,
};
