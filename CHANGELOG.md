# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the version of the library.

## [Unreleased]

There is no release yet. `mili-core` is `publish = false` and no tag exists, so
this section records work that is committed but not released.

### Added

- `docs/` holds `docs/SPEC.md`, `docs/THREAT_MODEL.md`, `docs/DISCLAIMER.md` and `docs/SIGNING_KEYS.md`,
  with `docs/README.md` as a reading guide that routes a reader to one of them
  according to why they are here. `README.md` and `SECURITY.md` stay at the root,
  because that is where GitHub looks for them.
- `CONTRIBUTING.md`, including the four failures that have broken this repository's
  CI and the error message each one produced, since none of the messages name the
  cause.
- `SECURITY.md`, which points at GitHub private vulnerability reporting rather than
  at an address, so the reporting channel does not require an identity in it.
- `docs/SIGNING_KEYS.md`, which records that no key has signed a tag and how a tag is
  checked when one does.
- Licences: `LICENSE-APACHE` and `LICENSE-MIT`, offered as
  `Apache-2.0 OR MIT`.

### Fixed

- `chacha20poly1305` was compiled without its `zeroize` feature, so `ChaChaPoly1305`'s
  `Drop` was empty and the AEAD key was released to the allocator without being
  overwritten. That crate holds the key for all five formats, and for a key file
  or a backup it is `HKDF(Argon2id(password))`, so the key outlived the file it
  decrypted. `x-wing`, `ml-dsa`, `ed25519-dalek` and `argon2` all had the feature
  enabled and this one did not.
- `VerifyingKey::from_bytes` accepted an Ed25519 half that is a valid but small
  order point, including the identity. Such a key satisfies any transcript on
  that half, so a composite signed against it could be forged without any secret
  and the construction would silently reduce to ML-DSA-65 alone. Small order keys
  are now refused with the upstream's `is_weak`, and verification uses
  `verify_strict` as a second layer.
- The three typed key file openers checked `payload_type` but not the payload
  length, so a file declaring `PAYLOAD_SEALING` with a sixteen byte payload opened
  successfully and produced a `SealingKey` that was sixteen real bytes followed by
  sixteen zeros. `open_payload` now returns the real length, which the padding made
  otherwise unrecoverable, and each opener compares it against its own size.
- `Backup::open` did not enforce the no-duplicate-`key_id` rule that
  `Backup::from_keys` enforces when writing, so a container produced by another
  implementation could hold two entries under one identifier.
- `mili_backup_create` panicked inside the boundary on a zero length entry, via
  `split_at(1)` on an empty slice, and reported the panic as `MILI_INTERNAL`. That
  is mili's own code panicking on caller input, so it is now a caller error.
- `OpenStream` in the Go binding converted a negative `maximumPlaintext` to a
  huge `C.size_t`, which mili-core reads as no bound at all. Passing `-1` silently
  removed the only defence a hostile stream has. Neither Rust nor C can express
  the mistake; the Go layer now rejects it.
- `mili_stream_overhead` returned the total stream length rather than the
  overhead, and computed its chunk count with a floor division that under-counted
  by one tag for every plaintext that was an exact multiple of 64 KiB. A caller
  sizing a buffer from it got `MILI_BUFFER_TOO_SMALL` at those lengths. The
  `mili-core` function is now split into `total_for_chunks` and `overhead_for`, so
  the two quantities cannot be confused again.

### Changed

- Every crate on a production edge in `Cargo.lock` has an audit written from its
  source in `supply-chain/audits.toml`: 48 crates across 47 names. The remaining
  40 exemptions are all dev or build dependencies. `libc` and `curve25519-dalek`
  are partial, and both name a stopping point that is a checkable claim about
  reachability rather than about length.
- The `chacha20poly1305` audit note described the `_detached` AEAD forms and a
  `Buffer::<U16>::to_tag` call that mili does not make, and listed
  `universal-hash` as a dependency when it is `cipher` and `zeroize`. A note
  describing a different API surface than the code uses is worse than none when
  it is cited as evidence, so all three are corrected.
- `cargo-vet`, `cargo-deny` and `cargo-fuzz` are pinned in CI. All three were
  installed unpinned and two of them had already broken a build on a version
  difference.
- Code scanning is not enabled. `README.md` records the measurement behind that
  decision rather than asserting it.
- The fuzz targets take an explicit `--target x86_64-unknown-linux-gnu`.
- `docs/SPEC.md` section 5.1's chunk table had the ciphertext range ending at
  65552 where the chunk is 65552 bytes in total, and sections 5.2 and 15.2
  claimed an 88 bit chunk counter where the counter is a `u64`. Both are corrected;
  `counter_be(88)` remains, as age's name for the 88 bit field of which mili uses 64.
