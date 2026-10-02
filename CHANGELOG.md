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

- `parse_fields` required every caller to pass a `minimum_length` of at least 57
  for its unchecked reads of header bytes 0 through 5 to be safe. That was a
  property of the call sites rather than of the function. The guard now reads
  `minimum_length.max(FIELDS_OFFSET)`, so a caller that asks for less than a header
  gets an error instead of a panic.
- A test in `mili-core/src/kem.rs` read three items that are all `#[cfg(not(miri))]`, so miri
  failed to compile `mili-core` with three "cannot find" errors rather than
  skipping the test.

### Changed

- Every crate on a production edge in `Cargo.lock` has an audit written from its
  source in `supply-chain/audits.toml`: 48 crates across 47 names. The remaining
  40 exemptions are all dev or build dependencies. `libc` and `curve25519-dalek`
  are partial, and both name a stopping point that is a checkable claim about
  reachability rather than about length.
- `cargo-vet`, `cargo-deny` and `cargo-fuzz` are pinned in CI. All three were
  installed unpinned and two of them had already broken a build on a version
  difference.
- Code scanning is not enabled. `README.md` records the measurement behind that
  decision rather than asserting it.
- The fuzz targets take an explicit `--target x86_64-unknown-linux-gnu`.
