//! The C ABI for mili.
//!
//! `mili-ffi` is the only crate in this repository that contains `unsafe` code.
//! `mili-core` is `#![forbid(unsafe_code)]` and stays that way: this crate exists
//! precisely so that it can.
//!
//! # What the boundary looks like
//!
//! Six rules, and every exported function here follows all six.
//!
//! 1. **No pointer arithmetic leaves this crate.** Every exported function takes a
//!    pointer and a length, or a pointer to a fixed-size buffer whose size the
//!    caller got from one of the `*_size()` functions. Nothing is assumed about how
//!    long a buffer really is; the length is always stated.
//!
//! 2. **Output buffers are the caller's.** No exported function allocates memory
//!    the caller has to free, and none returns a pointer into Rust's heap. There is
//!    no `free` counterpart to get wrong, no mismatch between an allocator on one
//!    side of a language boundary and a different one on the other, and nothing for
//!    a caller to use after the library is unloaded.
//!
//! 3. **Every function returns an error code.** `MILI_OK` is zero and every
//!    failure is non-zero. A Go caller tests one value. Null is not used to report
//!    failure, so a null out-parameter is a bug in this crate and not a state the
//!    caller has to handle.
//!
//! 4. **A panic cannot cross the boundary.** Every entry point runs inside
//!    `call`, which catches an unwind and turns it into [`MILI_INTERNAL`].
//!    Unwinding into C is undefined behaviour, and mili-core already claims to have
//!    no reachable panic; this is the second of two independent reasons, and the one
//!    that holds if that claim is ever wrong.
//!
//! 5. **Every output takes a capacity and reports its length.** No function trusts
//!    the caller's buffer to be the size the documentation says, and none trusts a
//!    size constant to match what it will actually write. A function takes the
//!    caller's capacity, writes the length it used to a `*mut mili_size_t`, and a
//!    capacity that is too small fails with [`MILI_BUFFER_TOO_SMALL`] having written
//!    nothing.
//!
//!    That rule is here because of what happened without it. The first version of
//!    this crate had two conventions: a `deliver` that took a capacity, and a
//!    `deliver_fixed` that trusted the caller to have allocated
//!    `mili_signature_size()` bytes. `mili_sign` wrote a composite signature into it,
//!    and a composite signature is 3379 bytes, because mili's six byte header is part
//!    of it. It wrote six bytes past the end of the caller's buffer. The constant
//!    said 3373 and was named for the total; its value was the payload.
//!
//! 6. **Nothing here is negotiated, configured or reordered.** One suite per format
//!    version, exactly as `mili-core`. No function in this crate selects an
//!    algorithm, reads an environment variable, or takes a parameter the
//!    corresponding part of `docs/SPEC.md` does not define.
//!
//! # What the boundary does not do
//!
//! It does not clear the caller's memory. A key that `mili_sealing_key_to_bytes`
//! writes is in a Go slice that the garbage collector will copy and that nothing
//! will zero. That is the caller's to handle, `docs/DISCLAIMER.md` records it, and no
//! function here pretends otherwise.
//!
//! # Sizes
//!
//! Every size is reported by a `*_size()` function rather than written into the
//! header, so that a caller compiled against one version of this header and linked
//! against another asks the linked library rather than trusting a constant it baked
//! in. A caller that checks the reported size against what it allocated fails
//! cleanly when the two disagree, which is the only thing it can usefully do.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![warn(clippy::arithmetic_side_effects)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use mili_core::backup::{Backup, StoredKey};
use mili_core::error::Error;
use mili_core::keyfile::KeyFile;
use mili_core::signature::{SigningKey, VerifyingKey};
use mili_core::stream::{open_buffered, seal_buffered};
use mili_core::{EncapsulationKey, SealingKey, SymmetricKey};
use std::io::Cursor;

/// The type every length crosses the boundary as.
///
/// This is a C `size_t`. Go's cgo presents it as `C.size_t`, which is `uint64` on
/// every platform mili supports, so a length above `u32::MAX` is expressible and a
/// stream larger than 4 GiB is not truncated into a short buffer.
pub type Size = usize;

/// Success. Every other value is a failure, and a caller tests for zero.
pub const MILI_OK: i32 = 0;

/// The uniform failure.
///
/// `mili-core` returns this for a wrong key, a wrong password, a corrupted file, a
/// hostile length, a truncated file and an unknown payload type. Nothing
/// distinguishes them on either side of this boundary, because a caller that could
/// tell them apart would have an oracle.
pub const MILI_FAILED: i32 = 1;

/// The data names a format version this build does not implement.
///
/// The one failure that is not [`MILI_FAILED`], because it is a statement about the
/// caller's data rather than about its secrecy, and a caller that has a file from a
/// newer mili needs to be able to say so.
pub const MILI_UNSUPPORTED_VERSION: i32 = 2;

/// An internal invariant did not hold, or a panic was caught at the boundary.
///
/// Not expected to occur. It exists so that a caught panic is distinguishable from a
/// returned error when someone is debugging, rather than both being
/// [`MILI_FAILED`] and indistinguishable from a wrong password forever.
pub const MILI_INTERNAL: i32 = 3;

/// An I/O error from a caller-supplied reader or writer.
///
/// Also not a mili failure: it is the caller's file that failed.
pub const MILI_IO: i32 = 4;

/// The caller's output buffer is too small for the result.
///
/// Distinct from [`MILI_FAILED`] because it says nothing about the data: it is a
/// statement about the caller's own allocation, and a caller that gets it can
/// resize and retry without suspecting its key or its file.
pub const MILI_BUFFER_TOO_SMALL: i32 = 5;

/// Maps a `mili-core` error to an error code.
///
/// Exhaustive, so that adding a variant to `Error` fails this build rather than
/// being folded into [`MILI_FAILED`] by an arm that was never written.
fn code(error: &Error) -> i32 {
    match error {
        Error::Failed => MILI_FAILED,
        Error::UnsupportedVersion => MILI_UNSUPPORTED_VERSION,
        Error::Internal => MILI_INTERNAL,
        Error::Io(_) => MILI_IO,
    }
}

/// Runs `body` with an unwind caught, and maps its result to an error code.
///
/// # Panics
///
/// Does not propagate. A panic inside `body` becomes [`MILI_INTERNAL`], and the
/// panic's own message is deliberately not returned: a panic message can contain
/// whatever the panicking formatting site put in it, and a panic is not an error a
/// caller can act on.
///
/// The default panic hook still prints to stderr before the catch, because the hook
/// is process wide and this crate does not own it. A Go program that wants no panic
/// output installs its own hook, which is a reasonable thing to want.
/// Turns a mili error into an error code.
///
/// A closure body carries two kinds of failure: mili's own, and this crate's
/// boundary checks. Converting mili's here means a body can use `?` on both
/// without a second error type to thread through.
fn mili<T>(result: Result<T, Error>) -> Result<T, i32> {
    result.map_err(|error| code(&error))
}

/// Runs `body` with an unwind caught, and returns the code it produced.
///
/// Every entry point is this shape: they finish by writing into a caller buffer and
/// produce [`MILI_OK`] or a reason they did not.
fn call(body: impl FnOnce() -> Result<i32, i32>) -> i32 {
    // Both arms are already a code, so the interesting case is only the unwind.
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(result) => result.unwrap_or_else(|code| code),
        Err(_) => MILI_INTERNAL,
    }
}

/// Borrows `len` bytes at `bytes` as an immutable slice.
///
/// # Safety
///
/// When `len` is non-zero, `bytes` must be readable for `len` bytes for the
/// duration of the call.
fn input<'a>(bytes: *const u8, len: Size) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if bytes.is_null() {
        return Err(MILI_FAILED);
    }
    // SAFETY: the caller contract is that `bytes` is readable for `len` bytes, and
    // the null check above rules out the one case where no slice can be built. The
    // returned lifetime is tied to this call and is never stored.
    Ok(unsafe { core::slice::from_raw_parts(bytes, len) })
}

/// Borrows `len` bytes at `bytes` as a mutable slice.
///
/// # Safety
///
/// When `len` is non-zero, `bytes` must be writable for `len` bytes for the
/// duration of the call, and must not alias memory the caller reads or writes
/// concurrently.
fn output<'a>(bytes: *mut u8, len: Size) -> Result<&'a mut [u8], i32> {
    if len == 0 {
        return Ok(&mut []);
    }
    if bytes.is_null() {
        return Err(MILI_FAILED);
    }
    // SAFETY: as for `input`, plus the borrow is unique for the duration of the
    // call. Nothing derived from it is kept.
    Ok(unsafe { core::slice::from_raw_parts_mut(bytes, len) })
}

/// Copies `value` into the caller's buffer and reports the length used.
///
/// The `*mut Size` is written only on success, so a caller that ignores it after a
/// failure reads nothing rather than a length this crate never produced.
///
/// # Safety
///
/// `out` must be writable for `capacity` bytes and `out_len` for one `Size`, and
/// the two must not overlap.
unsafe fn deliver(value: &[u8], out: *mut u8, capacity: Size, out_len: *mut Size) -> i32 {
    if value.len() > capacity {
        return MILI_BUFFER_TOO_SMALL;
    }
    if out_len.is_null() {
        return MILI_FAILED;
    }
    let destination = match output(out, value.len()) {
        Ok(slice) => slice,
        Err(code) => return code,
    };
    destination.copy_from_slice(value);
    // SAFETY: the caller contract is that `out_len` is writable for one `Size` and
    // does not overlap `out`, which `output` only just borrowed mutably.
    unsafe { *out_len = value.len() };
    MILI_OK
}

/// Reports a constant size, for a caller that is allocating.
///
/// # Safety
///
/// `out` must be writable for one `Size`.
unsafe fn report(value: Size, out: *mut Size) -> i32 {
    if out.is_null() {
        return MILI_FAILED;
    }
    // SAFETY: the caller contract is that `out` is writable for one `Size`.
    unsafe { *out = value };
    MILI_OK
}

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

/// Reports the size in bytes of an X-Wing sealing key seed: `mili_sealing_key_size()`.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_sealing_key_size(out: *mut Size) -> i32 {
    unsafe { report(mili_core::SEALING_KEY_SIZE, out) }
}

/// Reports the size in bytes of an encapsulation key: `mili_encapsulation_key_size()`.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_encapsulation_key_size(out: *mut Size) -> i32 {
    unsafe { report(mili_core::ENCAPSULATION_KEY_SIZE, out) }
}

/// Reports the size in bytes of a composite signing key seed: `mili_signing_key_size()`.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_signing_key_size(out: *mut Size) -> i32 {
    unsafe { report(mili_core::signature::SIGNING_KEY_SIZE, out) }
}

/// Reports the size in bytes of a composite verifying key: `mili_verifying_key_size()`.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_verifying_key_size(out: *mut Size) -> i32 {
    unsafe { report(mili_core::signature::VERIFYING_KEY_SIZE, out) }
}

/// Reports the size in bytes of a whole composite signature, header included.
///
/// This is the value a caller allocates for [`mili_sign`]. It is the payload plus
/// mili's six byte signature header, and the distinction is not academic: an earlier
/// version of this crate reported the payload size here and handed callers a buffer
/// six bytes too short.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_signature_size(out: *mut Size) -> i32 {
    unsafe { report(mili_core::signature::SIGNATURE_SIZE, out) }
}

/// Reports the size in bytes of a symmetric key: `mili_symmetric_key_size()`.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_symmetric_key_size(out: *mut Size) -> i32 {
    unsafe { report(mili_core::secret::SYMMETRIC_KEY_SIZE, out) }
}

/// Reports the bytes a sealed box adds to a plaintext: `mili_sealed_box_overhead()`.
///
/// A caller sizing an output buffer for [`mili_seal`] adds this to the plaintext
/// length.
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_sealed_box_overhead(out: *mut Size) -> i32 {
    unsafe { report(mili_core::SEALED_BOX_OVERHEAD, out) }
}

/// Reports the bytes a stream adds to a plaintext of `plaintext_len`.
///
/// The plaintext length is a value the caller already has, so this is the whole
/// sizing story for [`mili_seal_stream`] and [`mili_open_stream`].
///
/// # Safety
///
/// `out` must be writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_stream_overhead(plaintext_len: Size, out: *mut Size) -> i32 {
    // The chunk count is a ceiling division: a plaintext of one byte still
    // occupies one chunk and one tag, and a plaintext of exactly one chunk's
    // worth of bytes also occupies exactly one. Only an empty plaintext needs
    // the special case, and it gets one chunk rather than zero. Rounding up is
    // what makes the reported figure a sufficient buffer size for every length
    // including one that is an exact multiple.
    let chunks = match plaintext_len {
        0 => 1,
        n => n.div_ceil(mili_core::stream::CHUNK_SIZE),
    };
    let overhead = mili_core::stream::overhead_for(chunks);
    unsafe { report(overhead, out) }
}

// ---------------------------------------------------------------------------
// Sealing keys
// ---------------------------------------------------------------------------

/// Writes a new X-Wing sealing key seed drawn from the operating system CSPRNG.
///
/// `out` must be writable for [`mili_sealing_key_size`] bytes.
///
/// # Safety
///
/// `out` must be writable for `capacity` bytes and `out_len` for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_sealing_key_generate(
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let key = mili(SealingKey::generate())?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&key.to_bytes(), out, capacity, out_len) })
    })
}

/// Writes a new composite signing key seed drawn from the operating system CSPRNG.
///
/// # Safety
///
/// `out` must be writable for `capacity` bytes and `out_len` for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_signing_key_generate(
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let key = mili(SigningKey::generate())?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&key.to_bytes(), out, capacity, out_len) })
    })
}

/// Writes a new symmetric key drawn from the operating system CSPRNG.
///
/// # Safety
///
/// `out` must be writable for `capacity` bytes and `out_len` for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_symmetric_key_generate(
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let key = mili(SymmetricKey::generate())?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&key.to_bytes(), out, capacity, out_len) })
    })
}

/// Derives the encapsulation key for a seed.
///
/// `out` must be writable for [`mili_encapsulation_key_size`] bytes.
///
/// # Safety
///
/// `seed` must be readable for [`mili_sealing_key_size`] bytes, `out` writable for
/// `capacity` bytes and `out_len` for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_encapsulation_key_from_seed(
    seed: *const u8,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(seed, mili_core::SEALING_KEY_SIZE)?;
        let seed: [u8; mili_core::SEALING_KEY_SIZE] = bytes.try_into().map_err(|_| MILI_FAILED)?;
        let public = SealingKey::from_bytes(seed).encapsulation_key();
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&public.to_bytes(), out, capacity, out_len) })
    })
}

// ---------------------------------------------------------------------------
// Sealed box
// ---------------------------------------------------------------------------

/// Encrypts `plaintext` to one encapsulation key.
///
/// `out` must be writable for at least `plaintext_len + mili_sealed_box_overhead()`
/// bytes; the exact length written goes to `out_len`.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `plaintext` or `recipient`.
#[no_mangle]
pub unsafe extern "C" fn mili_seal(
    recipient: *const u8,
    recipient_len: Size,
    plaintext: *const u8,
    plaintext_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let public_bytes = input(recipient, recipient_len)?;
        let public = mili(EncapsulationKey::from_bytes(public_bytes))?;
        let message = input(plaintext, plaintext_len)?;
        let sealed = mili(mili_core::seal::seal(&public, message))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&sealed, out, capacity, out_len) })
    })
}

/// Decrypts a sealed box with the first candidate seed that opens it.
///
/// A sealed box names no recipient, so a caller with several keys passes them all
/// and mili tries them in order. A caller that knows which key it sealed to may pass
/// only that one. The failure for a wrong key is [`MILI_FAILED`], the same as for a
/// corrupted file.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it. `keys` and `keys_len` must
/// describe `key_count` entries, and `out` must not overlap `sealed`.
#[no_mangle]
pub unsafe extern "C" fn mili_open(
    sealed: *const u8,
    sealed_len: Size,
    keys: *const u8,
    keys_len: *const Size,
    key_count: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let file = input(sealed, sealed_len)?;
        // SAFETY: the caller contract states both arrays and the count.
        let entries = unsafe { packed(keys, keys_len, key_count) }?;
        let candidates = sealing_keys(&entries)?;
        let borrowed: Vec<&SealingKey> = candidates.iter().collect();
        let opened = mili(mili_core::seal::open(file, &borrowed))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&opened, out, capacity, out_len) })
    })
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Signs `message` with a composite signing key seed.
///
/// `out` must be writable for [`mili_signature_size`] bytes.
///
/// # Safety
///
/// `seed` must be readable for [`mili_signing_key_size`] bytes, `out` writable for
/// `capacity` bytes, `out_len` for one [`Size`], and `out` must not overlap `message`.
#[no_mangle]
pub unsafe extern "C" fn mili_sign(
    seed: *const u8,
    message: *const u8,
    message_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(seed, mili_core::signature::SIGNING_KEY_SIZE)?;
        let seed: [u8; mili_core::signature::SIGNING_KEY_SIZE] =
            bytes.try_into().map_err(|_| MILI_FAILED)?;
        let key = SigningKey::from_bytes(seed);
        let message = input(message, message_len)?;
        let signature = mili(key.sign(message))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&signature, out, capacity, out_len) })
    })
}

/// Verifies a composite signature.
///
/// Verifies only if both component signatures verify for the same message, as
/// `docs/SPEC.md` section 6 requires. `verifying` is a public key and may be shared
/// freely.
///
/// # Safety
///
/// `verifying` must be readable for `mili_verifying_key_size()` bytes, `signature`
/// for `signature_len` bytes, and `message` for `message_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mili_verify(
    verifying: *const u8,
    message: *const u8,
    message_len: Size,
    signature: *const u8,
    signature_len: Size,
) -> i32 {
    call(|| {
        let key = input(verifying, mili_core::signature::VERIFYING_KEY_SIZE)?;
        let verifying = mili(VerifyingKey::from_bytes(key))?;
        let message = input(message, message_len)?;
        let signature = input(signature, signature_len)?;
        mili(verifying.verify(message, signature))?;
        Ok(MILI_OK)
    })
}

/// Derives the verifying key for a signing key seed.
///
/// `out` must be writable for [`mili_verifying_key_size`] bytes.
///
/// # Safety
///
/// `seed` must be readable for [`mili_signing_key_size`] bytes, `out` writable for
/// `capacity` bytes and `out_len` for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_verifying_key_from_seed(
    seed: *const u8,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(seed, mili_core::signature::SIGNING_KEY_SIZE)?;
        let seed: [u8; mili_core::signature::SIGNING_KEY_SIZE] =
            bytes.try_into().map_err(|_| MILI_FAILED)?;
        let public = SigningKey::from_bytes(seed).verifying_key();
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&public.to_bytes(), out, capacity, out_len) })
    })
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

/// Encrypts `plaintext` into a stream.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `plaintext`.
#[no_mangle]
pub unsafe extern "C" fn mili_seal_stream(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(key, mili_core::SEALING_KEY_SIZE)?;
        let key: [u8; mili_core::SEALING_KEY_SIZE] = bytes.try_into().map_err(|_| MILI_FAILED)?;
        let key = SealingKey::from_bytes(key);
        let message = input(plaintext, plaintext_len)?;
        let stream = mili(seal_buffered(&key, Vec::new(), message))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&stream, out, capacity, out_len) })
    })
}

/// Decrypts a stream with the first candidate seed that opens it.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it. `keys` and `keys_len` must
/// describe `key_count` entries, and `out` must not overlap `stream`.
#[no_mangle]
pub unsafe extern "C" fn mili_open_stream(
    stream: *const u8,
    stream_len: Size,
    keys: *const u8,
    keys_len: *const Size,
    key_count: Size,
    maximum_plaintext_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let file = input(stream, stream_len)?;
        // SAFETY: the caller contract states both arrays and the count.
        let entries = unsafe { packed(keys, keys_len, key_count) }?;
        let candidates = sealing_keys(&entries)?;
        let borrowed: Vec<&SealingKey> = candidates.iter().collect();
        // A `Cursor` over the caller's bytes, so no reader crosses the boundary and
        // no partial read is possible. `maximum_plaintext_len` is the caller's bound
        // on how much plaintext it is willing to accept from a hostile file, which
        // is the only defence `docs/SPEC.md` section 5.7 leaves for a stream.
        let opened = mili(open_buffered(
            Cursor::new(file),
            &borrowed,
            maximum_plaintext_len,
        ))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&opened, out, capacity, out_len) })
    })
}

/// The total length of `count` entries described by a length array.
///
/// Saturating, and a saturating sum is a sum that does not describe a buffer anybody
/// allocated: [`packed`] then fails the slice borrow rather than guessing.
fn total_length(lengths: &[Size]) -> Size {
    lengths
        .iter()
        .fold(0usize, |sum, length| sum.saturating_add(*length))
}

/// Reads one `size_t` out of its bytes.
///
/// Native endian, because these bytes are a C `size_t` array the caller wrote in this
/// same process a moment earlier. There is no conversion question to get wrong.
///
/// # Safety
///
/// `bytes` must be exactly [`size_of::<Size>`] bytes long.
fn read_size(bytes: &[u8]) -> Size {
    let mut array = [0u8; size_of::<Size>()];
    let take = bytes.len().min(array.len());
    if let (Some(slot), Some(source)) = (array.get_mut(..take), bytes.get(..take)) {
        slot.copy_from_slice(source);
    }
    Size::from_ne_bytes(array)
}

/// Borrows a caller's packed array of entries as slices.
///
/// This is the only place a raw pointer becomes a slice, and it does the whole
/// conversion in one borrow. The obvious alternative is `pointer.add(offset)` in a
/// loop over the caller's length array, which is exactly the pointer arithmetic this
/// crate's first rule is about: the offsets come from the caller, so an offset past
/// the end is a bounds panic here rather than a read of memory nobody handed over.
///
/// # Safety
///
/// `data` must be readable for the sum of `lengths`, and `lengths` must be readable
/// for `count` values.
unsafe fn packed<'a>(
    data: *const u8,
    lengths: *const Size,
    count: Size,
) -> Result<Vec<&'a [u8]>, i32> {
    if count == 0 {
        return Err(MILI_FAILED);
    }
    let raw = input(
        lengths.cast::<u8>(),
        count.saturating_mul(size_of::<Size>()),
    )?;
    let declared: Vec<Size> = raw.chunks_exact(size_of::<Size>()).map(read_size).collect();

    let whole = input(data, total_length(&declared))?;
    let mut out = Vec::with_capacity(declared.len());
    let mut offset = 0usize;
    for length in declared {
        let end = offset.checked_add(length).ok_or(MILI_FAILED)?;
        let entry = whole.get(offset..end).ok_or(MILI_FAILED)?;
        out.push(entry);
        offset = end;
    }
    Ok(out)
}

/// Reads `count` sealing key seeds out of a caller's packed array.
fn sealing_keys(packed: &[&[u8]]) -> Result<Vec<SealingKey>, i32> {
    let mut candidates = Vec::with_capacity(packed.len());
    for entry in packed {
        let seed: [u8; mili_core::SEALING_KEY_SIZE] =
            (*entry).try_into().map_err(|_| MILI_FAILED)?;
        candidates.push(SealingKey::from_bytes(seed));
    }
    Ok(candidates)
}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

/// Wraps a sealing key seed in a key file under `password`.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `seed` or `password`.
#[no_mangle]
pub unsafe extern "C" fn mili_key_file_wrap_sealing(
    seed: *const u8,
    password: *const u8,
    password_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(seed, mili_core::SEALING_KEY_SIZE)?;
        let seed: [u8; mili_core::SEALING_KEY_SIZE] = bytes.try_into().map_err(|_| MILI_FAILED)?;
        let password = input(password, password_len)?;
        let file = mili(KeyFile::from_sealing_key(
            &SealingKey::from_bytes(seed),
            password,
        ))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(file.as_bytes(), out, capacity, out_len) })
    })
}

/// Wraps a signing key seed in a key file under `password`.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `seed` or `password`.
#[no_mangle]
pub unsafe extern "C" fn mili_key_file_wrap_signing(
    seed: *const u8,
    password: *const u8,
    password_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(seed, mili_core::signature::SIGNING_KEY_SIZE)?;
        let seed: [u8; mili_core::signature::SIGNING_KEY_SIZE] =
            bytes.try_into().map_err(|_| MILI_FAILED)?;
        let password = input(password, password_len)?;
        let file = mili(KeyFile::from_signing_key(
            &SigningKey::from_bytes(seed),
            password,
        ))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(file.as_bytes(), out, capacity, out_len) })
    })
}

/// Opens a key file under `password` and writes the seed it holds back out.
///
/// `expected` is the `payload_type` the caller expects, one of the three values
/// `docs/SPEC.md` section 7 writes. It is an argument rather than something inferred from
/// the output buffer for a reason: a signing key file asked for as a sealing key
/// produces 64 bytes where the caller allocated 32, which the first version of this
/// function reported as a buffer problem, and 32 bytes where the caller allocated 64,
/// which it reported as success. The second of those is a key used as the wrong kind
/// of key, and the caller's own length check was the only thing that could catch it.
/// Stating the expectation makes the library the thing that checks.
///
/// A file whose payload type is not `expected` is refused with [`MILI_FAILED`], the
/// same as a wrong password, because the two are indistinguishable from outside.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `file` or `password`.
#[no_mangle]
pub unsafe extern "C" fn mili_key_file_unwrap(
    file: *const u8,
    file_len: Size,
    expected: u8,
    password: *const u8,
    password_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(file, file_len)?;
        let password = input(password, password_len)?;
        let key_file = mili(KeyFile::from_bytes(bytes))?;

        let payload = match mili(key_file.payload_type())? {
            mili_core::keyfile::PAYLOAD_SEALING
                if expected == mili_core::keyfile::PAYLOAD_SEALING =>
            {
                mili(key_file.open_sealing_key(password))?
                    .to_bytes()
                    .to_vec()
            }
            mili_core::keyfile::PAYLOAD_SIGNING
                if expected == mili_core::keyfile::PAYLOAD_SIGNING =>
            {
                mili(key_file.open_signing_key(password))?
                    .to_bytes()
                    .to_vec()
            }
            mili_core::keyfile::PAYLOAD_SYMMETRIC
                if expected == mili_core::keyfile::PAYLOAD_SYMMETRIC =>
            {
                mili(key_file.open_symmetric_key(password))?
                    .to_bytes()
                    .to_vec()
            }
            _ => return Err(MILI_FAILED),
        };
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&payload, out, capacity, out_len) })
    })
}

/// Reports which kind of key a key file holds, without a password.
///
/// Returns the same values `docs/SPEC.md` section 7 writes in `payload_type`: 1 sealing,
/// 2 signing, 3 symmetric. Reporting it does not authenticate the file: any bytes
/// have a payload type at a fixed offset, so a caller that treats this as proof of
/// anything is wrong. It is for a caller deciding which of its keys to try.
///
/// # Safety
///
/// `file` must be readable for `file_len` bytes and `out` writable for one [`Size`].
#[no_mangle]
pub unsafe extern "C" fn mili_key_file_payload_type(
    file: *const u8,
    file_len: Size,
    out: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(file, file_len)?;
        let key_file = mili(KeyFile::from_bytes(bytes))?;
        let payload_type = mili(key_file.payload_type())?;
        // SAFETY: the caller contract is a pointer to one `Size`.
        Ok(unsafe { report(usize::from(payload_type), out) })
    })
}

/// Rewrites a key file under the same password with a fresh salt.
///
/// `docs/SPEC.md` section 12.1 defines rotation as a new salt around the same payload
/// under the same parameters. Changing the password is not rotation: it is opening
/// the key and wrapping it again, which the caller can do with
/// [`mili_key_file_unwrap`] and [`mili_key_file_wrap_sealing`].
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `file` or `password`.
#[no_mangle]
pub unsafe extern "C" fn mili_key_file_rotate(
    file: *const u8,
    file_len: Size,
    password: *const u8,
    password_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(file, file_len)?;
        let password = input(password, password_len)?;
        let key_file = mili(KeyFile::from_bytes(bytes))?;
        let rotated = mili(key_file.rotate(password))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(rotated.as_bytes(), out, capacity, out_len) })
    })
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

/// Builds a backup container from a list of keys, under one password.
///
/// `keys` is `key_count` entries back to back, each preceded by its length as a
/// [`Size`], which is what `keys_len` describes. The first byte of each key entry
/// is its `payload_type`, as `docs/SPEC.md` section 8 writes it, so that a container
/// built here holds the same entries one built through `mili-core` holds.
///
/// Two entries with the same identifier are refused.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap any input.
#[no_mangle]
pub unsafe extern "C" fn mili_backup_create(
    keys: *const u8,
    keys_len: *const Size,
    key_count: Size,
    password: *const u8,
    password_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        // SAFETY: the caller contract states both arrays and the count.
        let entries = unsafe { packed(keys, keys_len, key_count) }?;
        let mut stored = Vec::with_capacity(entries.len());
        for entry in entries {
            stored.push(stored_key(entry)?);
        }
        let password = input(password, password_len)?;
        let backup = mili(Backup::from_keys(password, stored))?;
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(backup.as_bytes(), out, capacity, out_len) })
    })
}

/// Opens a backup container and writes its entries back out.
///
/// The output is the entries concatenated, each one:
///
/// ```text
/// ofs  len  field
/// 0    16   key_id
/// 16   1    payload_type      1 sealing, 2 signing, 3 symmetric
/// 17   n    key bytes        32, 64 or 32, by payload_type
/// ```
///
/// The length of each entry follows from its `payload_type` and from
/// [`mili_signing_key_size`], so a caller walks the array with the same sizes
/// [`mili_backup_create`] takes. There is no length prefix per entry: adding one
/// would mean a field the format does not have, and the format is the thing that
/// has to stay fixed.
///
/// # Safety
///
/// Every pointer must satisfy the length stated beside it, and `out` must not
/// overlap `backup` or `password`.
#[no_mangle]
pub unsafe extern "C" fn mili_backup_open(
    backup: *const u8,
    backup_len: Size,
    password: *const u8,
    password_len: Size,
    out: *mut u8,
    capacity: Size,
    out_len: *mut Size,
) -> i32 {
    call(|| {
        let bytes = input(backup, backup_len)?;
        let password = input(password, password_len)?;
        let container = mili(Backup::from_bytes(bytes)).and_then(|b| mili(b.open(password)))?;

        let mut entries = Vec::new();
        for entry in &container {
            entries.extend_from_slice(&entry.key_id);
            entries.extend_from_slice(&payload_of(&entry.key));
        }
        // SAFETY: the caller contract covers `out`, `capacity` and `out_len`.
        Ok(unsafe { deliver(&entries, out, capacity, out_len) })
    })
}

/// Encodes one stored key as `payload_type || key bytes`.
///
/// The type values are the ones `docs/SPEC.md` section 8 writes, and they are also the
/// ones `KeyFile::payload_type` reports, so a caller that has a key from either
/// direction can tell what it has.
fn payload_of(key: &StoredKey) -> Vec<u8> {
    let mut out = Vec::new();
    match key {
        StoredKey::Sealing(key) => {
            out.push(mili_core::keyfile::PAYLOAD_SEALING);
            out.extend_from_slice(&key.to_bytes());
        }
        StoredKey::Signing(key) => {
            out.push(mili_core::keyfile::PAYLOAD_SIGNING);
            out.extend_from_slice(&key.to_bytes());
        }
        StoredKey::Symmetric(key) => {
            out.push(mili_core::keyfile::PAYLOAD_SYMMETRIC);
            out.extend_from_slice(&key.to_bytes());
        }
    }
    out
}

/// Decodes one `payload_type || key bytes` entry for [`mili_backup_create`].
fn stored_key(entry: &[u8]) -> Result<StoredKey, i32> {
    // `split_first` rather than `split_at(1)`: the latter panics on an empty
    // slice, and a caller can produce one. `packed` will happily build a
    // zero length slice from `key_count = 1, keys_len = [0]`, and the panic
    // would be caught by `call` and reported as `MILI_INTERNAL`, which is
    // defined as mili catching a panic its own claims say is unreachable.
    // This is mili's own boundary panicking on caller input, so it is a caller
    // error and is reported as one.
    let Some((payload_type, bytes)) = entry.split_first() else {
        return Err(MILI_FAILED);
    };
    match payload_type {
        0x01 => {
            let seed: [u8; mili_core::SEALING_KEY_SIZE] =
                bytes.try_into().map_err(|_| MILI_FAILED)?;
            Ok(StoredKey::Sealing(SealingKey::from_bytes(seed)))
        }
        0x02 => {
            let seed: [u8; mili_core::signature::SIGNING_KEY_SIZE] =
                bytes.try_into().map_err(|_| MILI_FAILED)?;
            Ok(StoredKey::Signing(SigningKey::from_bytes(seed)))
        }
        0x03 => {
            let seed: [u8; mili_core::secret::SYMMETRIC_KEY_SIZE] =
                bytes.try_into().map_err(|_| MILI_FAILED)?;
            Ok(StoredKey::Symmetric(SymmetricKey::from_bytes(seed)))
        }
        _ => Err(MILI_FAILED),
    }
}
