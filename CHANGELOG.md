# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the version of the library.

## [Unreleased]

There is no release yet. `mili-core` is `publish = false` and no tag exists, so
this section records work that is committed but not released.

### Added

- `docs/AUDIT_SCOPE.md` records what an audit of mili would cover: the modules and
  their visibility, the entry points, the claims that need evidence rather than
  agreement, and what mili does not claim. It opens by saying no third party has
  audited mili. `mili-core/tests/audit_scope.rs` keeps that true and keeps the
  module table honest, so adding a module is a decision about the surface that
  cannot be made silently.
- A CI job builds the release artifacts twice into separate target directories and
  compares them byte for byte. `docs/SPEC.md` section 16 listed the conditions that
  are supposed to make a build reproducible and every one of them was an argument;
  this observes it. It is same-machine and same-toolchain twice, which catches a
  build embedding a timestamp, a path or a map iteration order, and it is not a
  claim of bit-reproducibility across toolchains.
- `Backup::info` reports what a backup container claims, without a password and
  without running a derivation: the Argon2 profile and the entry count. The README
  has listed "inspect" among a backup container's operations for several releases
  and no such operation existed. Reachable as `mili_backup_info` and `Backup.Info`.
- `mili_key_id` and `KeyID`, so the workflow `docs/SPEC.md` section 11 describes for
  checking that a backup holds the keys it means is implementable from C and Go.
  `mili_backup_open` returned the identifiers as bytes, but a caller had no way to
  compute the expected identifier for a key it held, so the two could not be
  compared. That is the reachable half of a feature being useless.
- `mili_key_file_wrap_symmetric` and `WrapSymmetricKeyFile`. `mili_key_file_unwrap`
  already handled the symmetric payload type, so a caller could open a symmetric
  key file but not create one, and a symmetric key could be put in a backup but not
  wrapped directly.
- `docs/` holds `SPEC.md`, `THREAT_MODEL.md`, `DISCLAIMER.md` and `SIGNING_KEYS.md`,
  with `docs/README.md` as a reading guide that routes a reader to one of them
  according to why they are here. `README.md` and `SECURITY.md` stay at the root,
  because that is where GitHub looks for them.
- `CONTRIBUTING.md`, including the four failures that have broken this repository's
  CI and the error message each one produced, since none of the messages name the
  cause, and the note that there are two lockfiles to refresh after any dependency
  change.
- `SECURITY.md`, which points at GitHub private vulnerability reporting rather than
  at an address, so the reporting channel does not require an identity in it.
- `SIGNING_KEYS.md`, which records that no key has signed a tag and how a tag is
  checked when one does.
- Licences: `LICENSE-APACHE` and `LICENSE-MIT`, offered as
  `Apache-2.0 OR MIT`.

### Fixed

- `StreamWriter::write` replaced a sink failure with mili's own message, so a
  caller writing to a full disk saw `mili: io error` instead of `ENOSPC`, and the
  same failure reported differently depending on whether it hit a middle chunk or
  the last one. The caller's `io::Error` is now preserved, which is the one error
  class `error.rs` says is not a secrecy statement.
- `StreamWriter` carried a `finished` flag that could never be true, because
  `finish` consumes `self`. The flag and its check are gone and the documentation
  says what actually prevents a second final chunk: the signature.
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

- Signing is randomised on the ML-DSA half, using `sign_randomized` and 32 bytes
  from mili's existing randomness source through a `TryRng` adapter rather than
  `OsRng`, so the library keeps its single source. This removes the
  deterministic-signer fault-attack surface and stops the ML-DSA half being a
  function of the key and the message alone. `THREAT_MODEL.md` section 3.6 had
  recorded randomised signing as unavailable because it needs `ml-dsa`'s `hazmat`
  feature; it does not, there is a `rand_core` feature, and the restriction was
  never real. An entropy failure now returns `Error::Failed` instead of being
  reachable as a panic. The encoding is unchanged: still `mili-sig-v1`, still the
  same length, still verified the same way.
- The composite signature is still linkable, and the documentation no longer
  implies otherwise. `mili-sig-v1` carries the Ed25519 half verbatim and Ed25519
  is deterministic, so those 64 bytes repeat between two signatures over the same
  message. Removing that means changing the composite construction, which forfeits
  the property that makes it worth carrying. The residual is now asserted by a
  test, so a future format change which did remove it has to update the threat
  model rather than quietly invalidate it.

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
- `docs/THREAT_MODEL.md` section 2.10 said no library path contains an explicit
  panic. One does, in `keyfile::derive_kek` behind `#[cfg(miri)]`, where it replaces
  a derivation that cannot be interpreted rather than guarding one. The claim is
  now the accurate one.
- The Go binding's key types were documented as making a symmetric-key-as-sealing-
  seed "a compile error". They do not: Go permits an explicit conversion between
  named types sharing an underlying type, and the binding's own test performs one.
  `keys.go`, `README.md` and `docs/SPEC.md` section 19 now say what the types
  actually buy, which is that the mismatch has to be written down rather than
  inferred from a length.
- `docs/SPEC.md` section 18.3 said every size is asked of the library, and the Go
  binding's three key sizes are Go constants. That is a real exception and now
  states why: a call cannot appear where a slice length must be a compile-time
  constant.
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
