# mili fuzz targets

`cargo-fuzz` targets for every parser in `mili-core`, one per format, plus one
for signature verification. The claim they exist to support is
`THREAT_MODEL.md` section 2.10: `mili-core` is `#![forbid(unsafe_code)]`, every
parse is length checked and fallible, and no library path panics. The unit and
property tests cannot establish that on their own, because they only try the
inputs someone thought of. A fuzzer tries the ones nobody did.

## Running

```sh
cargo install cargo-fuzz                 # once
rustup toolchain install nightly         # libFuzzer needs a nightly compiler
cd fuzz

cargo +nightly fuzz run open_backup
cargo +nightly fuzz run open_key_file corpus/open_key_file
cargo +nightly fuzz tui open_stream      # if you have a terminal
```

A crash lands in `fuzz/artifacts/<target>/` and is replayed with:

```sh
cargo +nightly fuzz run open_backup artifacts/open_backup/crash-<hash>
```

Replay the committed regressions without fuzzing:

```sh
cargo +nightly fuzz run open_backup regressions/open_backup
```

The crate is deliberately outside the workspace, listed under `exclude` in the
root `Cargo.toml`. `cargo fuzz` builds every target with sanitizer flags that
belong to the fuzz invocation; if the crate were a member, a target could change
how `mili-core` is built for `cargo test`.

## Targets

| Target | Entry point | What it reaches |
|--------|-------------|-----------------|
| `open_sealed_box` | `mili_core::open` | sealed box header, X-Wing decapsulation, AEAD |
| `open_stream` | `stream::open_buffered` over a `Cursor` | stream header and chunk loop, whole-buffer reads |
| `open_stream_fragments` | `stream::open_buffered` over a short-reading reader | the partial header and partial chunk paths |
| `open_key_file` | `keyfile::KeyFile` | key file header, Argon2id bounds, typed openers, rotation |
| `open_backup` | `backup::Backup` | backup header, entry parser, container open |
| `verify_signature` | `signature::VerifyingKey::verify` | both component verifications |

`open_stream_fragments` is the one that earns its own file. `StreamReader` is
generic over `Read`, but every caller in practice hands it a `Cursor`, and a
`Cursor` returns everything it has in one call. Every "the source gave me fewer
bytes than the format says are here" branch in the header read and the chunk read
is therefore unreachable through the buffer APIs. The reader in
`fuzz_targets/common/mod.rs` returns at most a fuzzer-chosen number of bytes per
call and has a total byte budget, so one input covers everything from "one byte
at a time" to "as much as asked for", and the input cannot make the harness spin.

## What each target asserts

Panic freedom, everywhere. Beyond that, each target asserts the property that
would be violated by a parser that returned the wrong answer rather than the
wrong error:

- `open_sealed_box` — nothing beyond panic freedom. The AEAD and the KEM either
  authenticate or do not, and there is no second thing to check.
- `open_stream`, `open_stream_fragments` — nothing beyond panic freedom.
- `open_key_file` — at most one typed opener may accept a file, because a file
  holds one key and the payload type byte is what decides which; the same bytes
  must reach the same verdict twice; and rotation must produce a file that opens
  to the same key.
- `open_backup` — the identifiers a container reports must be distinct, because
  `SPEC.md` section 8 refuses a container holding two entries under one
  identifier; and the same bytes must reach the same verdict twice.
- `verify_signature` — verification must be deterministic, and a signature that
  verified for a message must not verify for that message with one byte appended.
  Both component schemes bind the whole message, so there is no extension
  property for this to have.

A rejection is a success. Every target treats `Err` as the expected outcome; a
target that only failed on an accepted input would find nothing, because the
formats are meant to reject nearly everything.

## Throughput

Measured on the machine this was written on, `-max_total_time=60`, no corpus:

| Target | exec/s | Note |
|--------|--------|------|
| `verify_signature` | ~800,000 | a rejected signature never reaches either component |
| `open_sealed_box` | ~550,000 | most inputs fail the header checks |
| `open_stream` | ~130,000 | |
| `open_stream_fragments` | ~960 | one input is many short reads |
| `open_backup` | ~1,700 | |
| `open_key_file` | ~19 | see below |

`open_key_file` is slow because Argon2id runs. At the profile `SPEC.md` section
7.1 records, one derivation touches 64 MiB three times, so a target that reaches
it runs at roughly eight executions a second. That is the honest cost of
fuzzing a format whose parameters are attacker-chosen, and it is why the target
takes flat bytes rather than structured input: a structured input would put a
well-formed header on every case and run at eight executions a second from the
first iteration instead of after the fuzzer finds the prefix. Flat input spends
its budget in the parser, which is where the panics are, and reaches Argon2
through coverage feedback.

There is no way to fuzz the offset arithmetic at full speed from outside the
crate, because `mili_core::keyfile` exposes no parse step separate from the
derivation, and adding a public entry point for the fuzzer's benefit would be
the wrong trade. If the parse layer grows a public API, this target should grow
a sibling that uses it.

## Regressions

`regressions/<target>/` holds inputs that found something. It is committed, and it
is separate from `corpus/` on purpose: `corpus/` is what a campaign grows and is
gitignored, while `regressions/` is the small set of inputs that have to fail the
build if the defect they found comes back.

There is one:

`regressions/open_backup/entries_len_overflow.bin` — a 64 byte container with a valid
prefix, the documented Argon2 profile, and an `entries_len` of `2^64 - 11`. The
header parser computed `HEADER_SIZE + entries_len + TAG_SIZE`, which wrapped to
53. Under `overflow-checks`, which the fuzz profile enables and which a debug
build always enables, that is a panic; without them it is a length the writer
never wrote. It was found by this target in about thirty seconds and was not
found by the unit tests, the property tests or the exhaustive byte sweeps,
because every one of those generates lengths near a real file's length rather
than near `usize::MAX`.

Reintroducing the unchecked addition makes the committed input panic again, which
was verified by reverting the fix and replaying it before this was committed.

That is how the set is kept honest. CI replays `regressions/` rather than running
a campaign, so a regression fails the build in seconds instead of waiting for
someone to fuzz for a while.

To add one: run the target until it crashes, then move the file from
`artifacts/<target>/` to `regressions/<target>/`, and say in the commit message
what it found. A regression entry without the defect it pins is noise.

## Profile

`[profile.release]` in `fuzz/Cargo.toml` sets `debug-assertions = true` and
`overflow-checks = true` and leaves `debug = 1`. Fuzzing an optimised build with
assertions off would leave exactly the class of bug these targets exist to find
unobserved: the offset arithmetic only asserted in debug would be trusted, and a
wrapping length would be invisible.

The profile is the fuzz build's, not `mili-core`'s. A consumer of the library
chooses its own profile, so mili does not and cannot turn overflow checks on for
them. What it does instead is deny `clippy::arithmetic_side_effects` over the
library, so every arithmetic operation states how it behaves when it wraps before
the code is written rather than after a fuzzer finds it.

## Adding a target

One target per parser. A new format gets one, and if it has a `Read` or `Write`
implementation that a `Cursor` cannot exercise, it gets a fragmented sibling too.
Keep the recipient key and the password fixed and public in the target, so a
crash replays from the input alone.
