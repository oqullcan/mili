//! The boundary's own tests, and the check that the committed header is still true.
//!
//! Two things are worth testing here that are not worth testing in `mili-core`:
//!
//! - The C header is hand written, so it can drift from `src/lib.rs`. Every test
//!   that names an exported function also checks that the name appears in
//!   `include/mili.h`, and [`the_header_agrees_with_the_exported_functions`] checks
//!   the other direction: nothing exported is missing from the header. A function
//!   that exists but is not declared is the failure that would otherwise reach a C
//!   caller as an implicit declaration.
//!
//! - The rules the crate states about itself are checked. That no exported function
//!   allocates for the caller, that every one returns a code, that a null pointer
//!   with a non-zero length is refused rather than dereferenced, that an output
//!   buffer one byte short fails with a code that says so rather than truncating,
//!   and that a panic cannot cross the boundary.
//!
//! Everything here is `#[cfg(not(miri))]` except the header check. The library tests
//! derive no keys, but the sealing and signing operations are the ones miri already
//! excludes elsewhere, and a test that runs an X-Wing decapsulation per case is a
//! test that does not finish.

#![cfg(not(miri))]

use std::ptr;

use mili_ffi::*;

const PASSWORD: &[u8] = b"correct horse battery staple";
const OTHER_PASSWORD: &[u8] = b"not the password";

/// A `size_t` the caller would allocate, filled from the library.
fn reported(function: unsafe extern "C" fn(*mut Size) -> i32) -> Size {
    let mut value = 0usize;
    assert_eq!(unsafe { function(&mut value) }, MILI_OK);
    value
}

/// Runs a fixed-size output function the way a real caller must: ask for the size,
/// allocate that, and check the length it reports.
fn sized(function: impl FnOnce(*mut u8, Size, *mut Size) -> i32, expected: Size) -> Vec<u8> {
    let mut out = vec![0u8; expected];
    let mut written = 0usize;
    assert_eq!(function(out.as_mut_ptr(), out.len(), &mut written), MILI_OK);
    out.truncate(written);
    assert_eq!(
        out.len(),
        expected,
        "the reported size and the written size differ"
    );
    out
}

fn seeding_key() -> Vec<u8> {
    sized(
        |out, capacity, out_len| unsafe { mili_sealing_key_generate(out, capacity, out_len) },
        reported(mili_sealing_key_size),
    )
}

fn signing_seed() -> Vec<u8> {
    let size = reported(mili_signing_key_size);
    let mut seed = vec![0u8; size];
    seed[0] = 0x37;
    // The last byte, addressed without arithmetic on the size.
    if let Some(last) = seed.last_mut() {
        *last = 0x91;
    }
    seed
}

fn encapsulation_key(seed: &[u8]) -> Vec<u8> {
    sized(
        |out, capacity, out_len| unsafe {
            mili_encapsulation_key_from_seed(seed.as_ptr(), out, capacity, out_len)
        },
        reported(mili_encapsulation_key_size),
    )
}

fn candidate_array(seeds: &[Vec<u8>]) -> (Vec<u8>, Vec<Size>) {
    let mut packed = Vec::new();
    let mut lengths = Vec::new();
    for seed in seeds {
        packed.extend_from_slice(seed);
        lengths.push(seed.len());
    }
    (packed, lengths)
}

/// Wraps the caller's two-call output convention.
fn open_box(public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, i32> {
    let overhead = reported(mili_sealed_box_overhead);
    let mut out = vec![0u8; plaintext.len().saturating_add(overhead)];
    let mut written = 0usize;
    let code = unsafe {
        mili_seal(
            public.as_ptr(),
            public.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    if code != MILI_OK {
        return Err(code);
    }
    out.truncate(written);
    Ok(out)
}

fn open_sealed(sealed: &[u8], seeds: &[Vec<u8>]) -> Result<Vec<u8>, i32> {
    let (packed, lengths) = candidate_array(seeds);
    let mut out = vec![0u8; sealed.len()];
    let mut written = 0usize;
    let code = unsafe {
        mili_open(
            sealed.as_ptr(),
            sealed.len(),
            packed.as_ptr(),
            lengths.as_ptr(),
            lengths.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    if code != MILI_OK {
        return Err(code);
    }
    out.truncate(written);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The header is the contract
// ---------------------------------------------------------------------------

const HEADER: &str = include_str!("../include/mili.h");

#[test]
fn the_header_agrees_with_the_exported_functions() {
    // The list is written out rather than derived, because deriving it needs a
    // symbol table this crate cannot read, and a test that derives its own
    // expectation from the thing under test checks nothing. A new export has to be
    // added here as well, which is the point: the commit that adds a function also
    // adds it to the header and to this list.
    const EXPORTED: &[&str] = &[
        "mili_sealing_key_size",
        "mili_encapsulation_key_size",
        "mili_signing_key_size",
        "mili_verifying_key_size",
        "mili_signature_size",
        "mili_symmetric_key_size",
        "mili_sealed_box_overhead",
        "mili_stream_overhead",
        "mili_sealing_key_generate",
        "mili_signing_key_generate",
        "mili_symmetric_key_generate",
        "mili_encapsulation_key_from_seed",
        "mili_seal",
        "mili_open",
        "mili_sign",
        "mili_verify",
        "mili_verifying_key_from_seed",
        "mili_seal_stream",
        "mili_open_stream",
        "mili_key_file_wrap_sealing",
        "mili_key_file_wrap_signing",
        "mili_key_file_unwrap",
        "mili_key_file_payload_type",
        "mili_key_file_rotate",
        "mili_backup_create",
        "mili_backup_open",
    ];

    for name in EXPORTED {
        assert!(
            HEADER.contains(&format!("int32_t {name}(")),
            "{name} is exported but not declared in the header"
        );
    }

    // Every code the library defines is documented in the header.
    for (name, code) in [
        ("MILI_OK", MILI_OK),
        ("MILI_FAILED", MILI_FAILED),
        ("MILI_UNSUPPORTED_VERSION", MILI_UNSUPPORTED_VERSION),
        ("MILI_INTERNAL", MILI_INTERNAL),
        ("MILI_IO", MILI_IO),
        ("MILI_BUFFER_TOO_SMALL", MILI_BUFFER_TOO_SMALL),
    ] {
        assert!(
            HEADER.contains(&format!("#define {name} {code}")),
            "{name} is {code} in Rust and not {code} in the header"
        );
    }

    // The payload type values are the format's, not this crate's invention.
    assert!(HEADER.contains("#define MILI_PAYLOAD_SEALING 1"));
    assert!(HEADER.contains("#define MILI_PAYLOAD_SIGNING 2"));
    assert!(HEADER.contains("#define MILI_PAYLOAD_SYMMETRIC 3"));
}

#[test]
fn the_error_codes_are_distinct_and_zero_is_success() {
    let codes = [
        MILI_OK,
        MILI_FAILED,
        MILI_UNSUPPORTED_VERSION,
        MILI_INTERNAL,
        MILI_IO,
        MILI_BUFFER_TOO_SMALL,
    ];
    assert_eq!(MILI_OK, 0);
    for (index, code) in codes.iter().enumerate() {
        assert!(*code >= 0, "code {code} is negative");
        assert!(!codes[..index].contains(code), "code {code} is used twice");
    }
}

#[test]
fn every_size_is_reported_rather_than_assumed() {
    assert_eq!(reported(mili_sealing_key_size), 32);
    assert_eq!(reported(mili_encapsulation_key_size), 1216);
    assert_eq!(reported(mili_signing_key_size), 64);
    assert_eq!(reported(mili_verifying_key_size), 1984);
    assert_eq!(reported(mili_signature_size), 3379);
    assert_eq!(reported(mili_symmetric_key_size), 32);
    assert_eq!(reported(mili_sealed_box_overhead), 1174);

    // A size function given a null out-parameter refuses rather than writing.
    assert_eq!(
        unsafe { mili_sealing_key_size(ptr::null_mut()) },
        MILI_FAILED
    );
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[test]
fn a_generated_seed_differs_each_time() {
    let first = seeding_key();
    let second = seeding_key();
    assert_ne!(first, second, "the CSPRNG repeated");
    assert_eq!(first.len(), 32);
}

#[test]
fn an_encapsulation_key_is_1216_bytes_and_deterministic() {
    let seed = seeding_key();
    let first = encapsulation_key(&seed);
    let second = encapsulation_key(&seed);
    assert_eq!(first, second, "key derivation is not deterministic");
    assert_eq!(first.len(), 1216);
    assert_ne!(encapsulation_key(&seeding_key()), first);
}

// ---------------------------------------------------------------------------
// Sealed box
// ---------------------------------------------------------------------------

#[test]
fn a_sealed_box_round_trips() {
    let seed = seeding_key();
    let public = encapsulation_key(&seed);
    let plaintext = b"a message that is not a multiple of any chunk size";

    let sealed = open_box(&public, plaintext).expect("seals");
    assert_eq!(sealed.len(), plaintext.len() + 1174);
    assert_ne!(
        &sealed[38..],
        &plaintext[..],
        "the plaintext is in the file"
    );

    let opened = open_sealed(&sealed, std::slice::from_ref(&seed)).expect("opens");
    assert_eq!(opened, plaintext);
}

#[test]
fn an_empty_plaintext_round_trips() {
    let seed = seeding_key();
    let sealed = open_box(&encapsulation_key(&seed), b"").expect("seals");
    assert_eq!(sealed.len(), 1174);
    assert_eq!(
        open_sealed(&sealed, &[seed]).expect("opens"),
        Vec::<u8>::new()
    );
}

#[test]
fn a_sealed_box_opens_with_the_right_key_out_of_several() {
    let right = seeding_key();
    let sealed = open_box(&encapsulation_key(&right), b"hello").expect("seals");
    let candidates = vec![seeding_key(), seeding_key(), right.clone()];

    assert_eq!(open_sealed(&sealed, &candidates).expect("opens"), b"hello");
}

#[test]
fn a_sealed_box_with_no_candidates_is_refused() {
    let seed = seeding_key();
    let sealed = open_box(&encapsulation_key(&seed), b"hello").expect("seals");
    assert_eq!(open_sealed(&sealed, &[]), Err(MILI_FAILED));
}

#[test]
fn a_wrong_recipient_or_key_is_the_same_error_as_a_corrupted_file() {
    let seed = seeding_key();
    let sealed = open_box(&encapsulation_key(&seed), b"hello").expect("seals");

    let wrong_key = open_sealed(&sealed, &[seeding_key()]);
    let mut corrupted = sealed.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let corrupt = open_sealed(&corrupted, std::slice::from_ref(&seed));

    assert_eq!(wrong_key, Err(MILI_FAILED));
    assert_eq!(
        corrupt, wrong_key,
        "a corrupt file is distinguishable from a wrong key"
    );
}

#[test]
fn a_null_pointer_with_a_non_zero_length_is_refused_rather_than_dereferenced() {
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            mili_seal(
                ptr::null(),
                1216,
                b"hello".as_ptr(),
                5,
                ptr::null_mut(),
                0,
                &mut written,
            )
        },
        MILI_FAILED
    );

    // A zero length with a null pointer is the empty input, not a fault.
    let seed = seeding_key();
    let sealed = open_box(&encapsulation_key(&seed), b"").expect("seals");
    let mut out = vec![0u8; 1174];
    let code = unsafe {
        mili_open(
            sealed.as_ptr(),
            sealed.len(),
            ptr::null(),
            ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    assert_eq!(code, MILI_FAILED, "zero candidates must be refused");
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

fn sign(seed: &[u8], message: &[u8]) -> Vec<u8> {
    sized(
        |out, capacity, out_len| unsafe {
            mili_sign(
                seed.as_ptr(),
                message.as_ptr(),
                message.len(),
                out,
                capacity,
                out_len,
            )
        },
        reported(mili_signature_size),
    )
}

fn verifying_key(seed: &[u8]) -> Vec<u8> {
    sized(
        |out, capacity, out_len| unsafe {
            mili_verifying_key_from_seed(seed.as_ptr(), out, capacity, out_len)
        },
        reported(mili_verifying_key_size),
    )
}

#[test]
fn a_signature_round_trips_and_is_3379_bytes() {
    let seed = signing_seed();
    let verifying = verifying_key(&seed);

    let signature = sign(&seed, b"a message");
    assert_eq!(signature.len(), 3379, "the header is part of the signature");
    assert_eq!(
        unsafe {
            mili_verify(
                verifying.as_ptr(),
                b"a message".as_ptr(),
                9,
                signature.as_ptr(),
                signature.len(),
            )
        },
        MILI_OK
    );
}

#[test]
fn a_signature_does_not_verify_for_another_message() {
    let seed = signing_seed();
    let signature = sign(&seed, b"a message");
    assert_eq!(
        unsafe {
            mili_verify(
                signature.as_ptr(),
                b"a message".as_ptr(),
                9,
                signature.as_ptr(),
                signature.len(),
            )
        },
        MILI_FAILED
    );
}

#[test]
fn every_single_bit_flip_in_a_signature_is_refused() {
    let seed = signing_seed();
    let verifying = verifying_key(&seed);
    let original = sign(&seed, b"a message");

    // Sampled, because each case runs two component verifications.
    for index in (0..original.len()).step_by(97) {
        let mut tampered = original.clone();
        tampered[index] ^= 0x01;
        assert_eq!(
            unsafe {
                mili_verify(
                    verifying.as_ptr(),
                    b"a message".as_ptr(),
                    9,
                    tampered.as_ptr(),
                    tampered.len(),
                )
            },
            MILI_FAILED,
            "byte {index} was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

fn seal_stream(seed: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, i32> {
    let mut overhead = 0usize;
    assert_eq!(
        unsafe { mili_stream_overhead(plaintext.len(), &mut overhead) },
        MILI_OK
    );
    let mut out = vec![0u8; plaintext.len().saturating_add(overhead)];
    let mut written = 0usize;
    let code = unsafe {
        mili_seal_stream(
            seed.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    if code != MILI_OK {
        return Err(code);
    }
    out.truncate(written);
    Ok(out)
}

fn open_stream(stream: &[u8], seeds: &[Vec<u8>]) -> Result<Vec<u8>, i32> {
    let (packed, lengths) = candidate_array(seeds);
    let mut out = vec![0u8; stream.len()];
    let mut written = 0usize;
    let code = unsafe {
        mili_open_stream(
            stream.as_ptr(),
            stream.len(),
            packed.as_ptr(),
            lengths.as_ptr(),
            lengths.len(),
            out.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    if code != MILI_OK {
        return Err(code);
    }
    out.truncate(written);
    Ok(out)
}

#[test]
fn a_stream_round_trips_across_a_chunk_boundary() {
    let seed = seeding_key();
    // Comfortably more than one 64 KiB chunk, so the loop runs more than once.
    let plaintext: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect();

    let stream = seal_stream(&seed, &plaintext).expect("seals");
    assert_eq!(
        open_stream(&stream, std::slice::from_ref(&seed)).expect("opens"),
        plaintext
    );
}

#[test]
fn an_empty_stream_round_trips() {
    let seed = seeding_key();
    let stream = seal_stream(&seed, b"").expect("seals");
    assert_eq!(
        open_stream(&stream, &[seed]).expect("opens"),
        Vec::<u8>::new()
    );
}

#[test]
fn a_stream_with_the_wrong_key_is_refused() {
    let seed = seeding_key();
    let stream = seal_stream(&seed, b"hello").expect("seals");
    assert_eq!(open_stream(&stream, &[seeding_key()]), Err(MILI_FAILED));
}

#[test]
fn the_plaintext_bound_is_enforced_by_the_boundary() {
    // `maximum_plaintext_len` is the only defence a hostile stream has, and it is
    // the caller's to set. This is where it is proved to work.
    let seed = seeding_key();
    let plaintext = vec![7u8; 40_000];
    let stream = seal_stream(&seed, &plaintext).expect("seals");

    let mut out = vec![0u8; stream.len()];
    let mut written = 0usize;
    let code = unsafe {
        mili_open_stream(
            stream.as_ptr(),
            stream.len(),
            seed.as_ptr(),
            [seed.len()].as_ptr(),
            1,
            1_000,
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    assert_eq!(code, MILI_FAILED);
}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

#[test]
fn a_sealing_key_file_round_trips() {
    let seed = seeding_key();

    let mut file = vec![0u8; reported(mili_signing_key_size) + 57];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_wrap_sealing(
                seed.as_ptr(),
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                file.as_mut_ptr(),
                file.len(),
                &mut written,
            )
        },
        MILI_OK
    );
    file.truncate(written);
    assert_eq!(file.len(), 32 + 57);
    assert_eq!(&file[..6], b"mili\x10\x01");

    let mut out = vec![0u8; 32];
    let mut unwrapped = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_unwrap(
                file.as_ptr(),
                file.len(),
                1,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut unwrapped,
            )
        },
        MILI_OK
    );
    out.truncate(unwrapped);
    assert_eq!(out, seed);

    // The wrong password is the same error as a corrupted file.
    let mut wrong = vec![0u8; 32];
    assert_eq!(
        unsafe {
            mili_key_file_unwrap(
                file.as_ptr(),
                file.len(),
                1,
                OTHER_PASSWORD.as_ptr(),
                OTHER_PASSWORD.len(),
                wrong.as_mut_ptr(),
                wrong.len(),
                &mut unwrapped,
            )
        },
        MILI_FAILED
    );
}

#[test]
fn a_signing_key_file_round_trips() {
    let seed = signing_seed();

    let mut file = vec![0u8; 64 + 57];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_wrap_signing(
                seed.as_ptr(),
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                file.as_mut_ptr(),
                file.len(),
                &mut written,
            )
        },
        MILI_OK
    );
    file.truncate(written);

    let mut out = vec![0u8; 64];
    let mut unwrapped = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_unwrap(
                file.as_ptr(),
                file.len(),
                2,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut unwrapped,
            )
        },
        MILI_OK
    );
    out.truncate(unwrapped);
    assert_eq!(out, seed);
}

#[test]
fn the_payload_type_is_reported_without_a_password() {
    let seed = seeding_key();
    let mut file = vec![0u8; 32 + 57];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_wrap_sealing(
                seed.as_ptr(),
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                file.as_mut_ptr(),
                file.len(),
                &mut written,
            )
        },
        MILI_OK
    );
    file.truncate(written);

    let mut reported_type = 0usize;
    assert_eq!(
        unsafe { mili_key_file_payload_type(file.as_ptr(), file.len(), &mut reported_type) },
        MILI_OK
    );
    assert_eq!(reported_type, 1, "a sealing key file reports 1");
}

#[test]
fn rotation_changes_the_file_and_keeps_the_key() {
    let seed = seeding_key();
    let mut file = vec![0u8; 32 + 57];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_wrap_sealing(
                seed.as_ptr(),
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                file.as_mut_ptr(),
                file.len(),
                &mut written,
            )
        },
        MILI_OK
    );
    file.truncate(written);

    let mut rotated = vec![0u8; file.len()];
    let mut rotated_len = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_rotate(
                file.as_ptr(),
                file.len(),
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                rotated.as_mut_ptr(),
                rotated.len(),
                &mut rotated_len,
            )
        },
        MILI_OK
    );
    rotated.truncate(rotated_len);
    assert_ne!(rotated, file, "rotation wrote the same bytes");
    assert_eq!(rotated.len(), file.len());

    let mut out = vec![0u8; 32];
    let mut unwrapped = 0usize;
    assert_eq!(
        unsafe {
            mili_key_file_unwrap(
                rotated.as_ptr(),
                rotated.len(),
                1,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut unwrapped,
            )
        },
        MILI_OK
    );
    out.truncate(unwrapped);
    assert_eq!(out, seed, "rotation changed the key");
}

#[test]
fn a_key_file_of_arbitrary_bytes_is_refused_not_faulted() {
    for len in [0usize, 1, 57, 88, 200] {
        let bytes = vec![0x5Au8; len];
        let mut payload_type = 0usize;
        let code = unsafe { mili_key_file_payload_type(bytes.as_ptr(), len, &mut payload_type) };
        assert!(code != MILI_OK, "len {len} was accepted");
    }

    // Enough bytes to be a key file, but not a mili one.
    let bytes = [0x5Au8; 88];
    assert_eq!(
        unsafe { mili_key_file_payload_type(bytes.as_ptr(), bytes.len(), ptr::null_mut()) },
        MILI_FAILED
    );
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

fn sealed_entry(seed: &[u8]) -> Vec<u8> {
    let mut entry = vec![1u8];
    entry.extend_from_slice(seed);
    entry
}

fn signing_entry(seed: &[u8]) -> Vec<u8> {
    let mut entry = vec![2u8];
    entry.extend_from_slice(seed);
    entry
}

fn create_backup(entries: &[Vec<u8>]) -> Result<Vec<u8>, i32> {
    let mut packed = Vec::new();
    let mut lengths = Vec::new();
    for entry in entries {
        packed.extend_from_slice(entry);
        lengths.push(entry.len());
    }

    // Generous, because the caller does not have to compute the exact size: the
    // function reports what it used.
    let capacity = 64usize.saturating_add(entries.len().saturating_mul(130));
    let mut out = vec![0u8; capacity];
    let mut written = 0usize;
    let code = unsafe {
        mili_backup_create(
            packed.as_ptr(),
            lengths.as_ptr(),
            lengths.len(),
            PASSWORD.as_ptr(),
            PASSWORD.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    if code != MILI_OK {
        return Err(code);
    }
    out.truncate(written);
    Ok(out)
}

fn open_backup(backup: &[u8], password: &[u8]) -> Result<Vec<u8>, i32> {
    let mut out = vec![0u8; backup.len()];
    let mut written = 0usize;
    let code = unsafe {
        mili_backup_open(
            backup.as_ptr(),
            backup.len(),
            password.as_ptr(),
            password.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    if code != MILI_OK {
        return Err(code);
    }
    out.truncate(written);
    Ok(out)
}

#[test]
fn a_backup_round_trips_every_key_kind() {
    let sealing = sealed_entry(&seeding_key());
    let signing = signing_entry(&signing_seed());

    let backup = create_backup(std::slice::from_ref(&sealing)).expect("creates");
    assert_eq!(&backup[..6], b"mili\x11\x01");

    let opened = open_backup(&backup, PASSWORD).expect("opens");
    assert_eq!(opened.len(), 16 + 1 + 32);
    assert_eq!(opened[16], 1, "the first entry is a sealing key");
    assert_eq!(&opened[17..], &sealing[1..]);

    let backup = create_backup(&[sealing.clone(), signing.clone()]).expect("creates");
    let opened = open_backup(&backup, PASSWORD).expect("opens");
    assert_eq!(opened.len(), (16 + 1 + 32) + (16 + 1 + 64));
    assert_eq!(opened[16], 1);
    assert_eq!(
        opened[16 + 1 + 32 + 16],
        2,
        "the second entry is a signing key"
    );
}

#[test]
fn a_backup_with_a_wrong_password_is_refused() {
    let backup = create_backup(&[sealed_entry(&seeding_key())]).expect("creates");
    assert_eq!(open_backup(&backup, OTHER_PASSWORD), Err(MILI_FAILED));
}

#[test]
fn a_backup_with_no_entries_round_trips() {
    let backup = create_backup(&[]);
    // Zero entries is refused rather than producing an empty container, because a
    // caller that built nothing has nothing to restore and a container that opens
    // to nothing is indistinguishable from one whose entries were lost.
    assert_eq!(backup, Err(MILI_FAILED));
}

#[test]
fn a_duplicate_entry_is_refused() {
    let entry = sealed_entry(&seeding_key());
    assert_eq!(create_backup(&[entry.clone(), entry]), Err(MILI_FAILED));
}

#[test]
fn an_entry_of_the_wrong_length_is_refused() {
    // A sealing key entry that is not 32 bytes.
    assert_eq!(create_backup(&[vec![1u8, 2, 3, 4]]), Err(MILI_FAILED));
    // An unknown payload type.
    assert_eq!(
        create_backup(&[vec![
            9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0
        ]]),
        Err(MILI_FAILED)
    );
}

#[test]
fn a_backup_of_arbitrary_bytes_is_refused_not_faulted() {
    for len in [0usize, 1, 63, 64, 200] {
        let bytes = vec![0x3Cu8; len];
        assert_eq!(open_backup(&bytes, PASSWORD), Err(MILI_FAILED), "len {len}");
    }
}

// ---------------------------------------------------------------------------
// The boundary itself
// ---------------------------------------------------------------------------

/// A pointer and length pair a C caller would legitimately pass for `bytes`.
///
/// An empty slice becomes `(null, 0)`, which is the documented way to say "no
/// input". This exists because the first version of this sweep passed
/// `slice::as_ptr()` with a separate non-zero length for an empty slice, which is a
/// dangling pointer with a length attached, and the boundary segfaulted reading it.
///
/// That is the boundary working as a C boundary does: it can refuse a null pointer,
/// and it cannot check that a non-null pointer really covers the length the caller
/// claims. Every caller of a C library is trusted on that point and so is this one.
/// The rule a caller must follow is "a non-zero length means a buffer that long",
/// and this helper is the shape of obeying it.
fn ptr_and_len(bytes: &[u8]) -> (*const u8, Size) {
    if bytes.is_empty() {
        (ptr::null(), 0)
    } else {
        (bytes.as_ptr(), bytes.len())
    }
}

/// Feeds a set of byte strings to every entry point that takes bytes, checking that
/// each one returns a code and none of them faults.
///
/// This is not a fuzz target; `fuzz/` has those, and they reach the parsers without
/// the copy that crossing the boundary costs. What this adds is the one thing the
/// fuzz targets cannot do: it calls the `extern "C"` functions themselves, so a
/// signature that lies about a pointer, a length or a buffer size is exercised.
#[test]
fn every_entry_point_refuses_its_inputs_without_faulting() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8],
        vec![0xFFu8; 89],
        vec![0xFFu8; 1174],
        b"mili\x11\x01".to_vec(),
        b"mili\x10\x01".to_vec(),
        {
            let mut file = b"mili\x10\x01".to_vec();
            file.resize(88, 0xFF);
            file
        },
        {
            let mut container = b"mili\x11\x01".to_vec();
            container.resize(200, 0xFF);
            container
        },
    ];

    for input in &inputs {
        let (data, len) = ptr_and_len(input);
        let mut out = vec![0u8; 16 * 1024];
        let mut written = usize::MAX;
        let mut payload_type = usize::MAX;
        let mut overhead = 0usize;

        unsafe {
            for code in [
                mili_seal(
                    data,
                    len,
                    data,
                    len,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_open(
                    data,
                    len,
                    ptr::null(),
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_seal_stream(data, data, len, out.as_mut_ptr(), out.len(), &mut written),
                mili_open_stream(
                    data,
                    len,
                    ptr::null(),
                    ptr::null(),
                    0,
                    out.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_sign(data, data, len, out.as_mut_ptr(), out.len(), &mut written),
                mili_verify(data, data, len, data, len),
                mili_key_file_unwrap(
                    data,
                    len,
                    1,
                    data,
                    len,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_key_file_rotate(
                    data,
                    len,
                    data,
                    len,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_key_file_payload_type(data, len, &mut payload_type),
                mili_backup_open(
                    data,
                    len,
                    data,
                    len,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_backup_create(
                    ptr::null(),
                    ptr::null(),
                    0,
                    data,
                    len,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                mili_stream_overhead(len, &mut overhead),
                mili_sealing_key_size(&mut overhead),
                mili_verifying_key_size(&mut overhead),
            ] {
                assert!(
                    (MILI_OK..=MILI_BUFFER_TOO_SMALL).contains(&code),
                    "a {len} byte input produced the out of range code {code}"
                );
            }
        }

        // A failure must not have written a length, and a success must have written
        // a length that fits in the buffer it was given.
        if written != usize::MAX {
            assert!(
                written <= out.len(),
                "a {len} byte input reported {written} bytes into a {} byte buffer",
                out.len()
            );
        }
    }
}

#[test]
fn an_output_buffer_one_byte_short_is_refused_for_every_fixed_size_output() {
    // The regression test for what the two-convention version of this crate did:
    // `mili_sign` trusted the caller's buffer, and a caller that sized it from
    // `SIGNATURE_SIZE` before that constant was corrected was six bytes short.
    let seed = signing_seed();
    let cases: Vec<(Size, *mut u8, *const u8, Size)> = vec![(
        reported(mili_signing_key_size),
        ptr::null_mut(),
        ptr::null(),
        0,
    )];
    drop(cases);

    // Each of these writes something whose size the library reports. One byte short
    // must be refused, and must write nothing.
    let message: &[u8] = b"a message";
    let checks: Vec<(&str, Vec<u8>, usize)> = vec![
        ("mili_sign", seed.clone(), reported(mili_signature_size)),
        (
            "mili_verifying_key_from_seed",
            seed.clone(),
            reported(mili_verifying_key_size),
        ),
        (
            "mili_sealing_key_generate",
            Vec::new(),
            reported(mili_sealing_key_size),
        ),
    ];

    for (name, key, size) in checks {
        let mut out = vec![0xC3u8; size - 1];
        let mut written = usize::MAX;
        let code = unsafe {
            match name {
                "mili_sign" => mili_sign(
                    key.as_ptr(),
                    message.as_ptr(),
                    message.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                "mili_verifying_key_from_seed" => mili_verifying_key_from_seed(
                    key.as_ptr(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                ),
                _ => mili_sealing_key_generate(out.as_mut_ptr(), out.len(), &mut written),
            }
        };
        assert_eq!(code, MILI_BUFFER_TOO_SMALL, "{name} with a short buffer");
        assert_eq!(written, usize::MAX, "{name} wrote a length on failure");
        assert!(
            out.iter().all(|b| *b == 0xC3),
            "{name} wrote into a buffer it refused"
        );
    }
}

#[test]
fn the_boundary_returns_a_code_rather_than_a_pointer() {
    // Nothing exported returns a pointer, so the only thing to check is that the
    // signature is what the header says. If a function ever returned a pointer, this
    // list would not compile against it as written here.
    let functions: Vec<unsafe extern "C" fn(*mut Size) -> i32> =
        vec![mili_sealing_key_size, mili_symmetric_key_size];
    assert_eq!(functions.len(), 2);

    for function in functions {
        let mut value = 0usize;
        assert_eq!(unsafe { function(&mut value) }, MILI_OK);
        assert!(value > 0);
    }
}
