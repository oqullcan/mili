# Audit scope

What an audit of mili covers, what it does not, and which of the project's claims
are assertions that need evidence rather than things to be taken on trust.

Read `THREAT_MODEL.md` first. This document assumes its categories and its
out-of-scope list, and does not restate them.

## Status

**No third party has audited mili.** Nothing in this repository should be read as
a claim otherwise, and `DISCLAIMER.md` section 3 says the same thing in the place
a reader will actually hit it. What follows is the scope an auditor would be
working to, written by the implementers, which is the most a project can honestly
offer before anyone has been paid to disagree with it.

Two things exist in place of an audit, and neither is one:

- **Reading.** Every crate on a production edge in `Cargo.lock` has a note in
  `../supply-chain/audits.toml` written from its source: line count, unsafe blocks,
  build script behaviour, and the specific property it was read for. The notes are
  review records, not approvals.
- **Checking.** `cargo deny` asks whether a crate is allowed at all. `cargo vet`
  asks whether the code in a crate is the code its publisher said it was. Passing
  means every crate is audited or exempted, and an exemption records that nobody
  looked rather than that a crate is fine.

`cargo vet check` passing is the one most often overread. It is not evidence of
correctness. It is evidence of a written-down position.

## The unit under audit

`mili-core` in its entirety, and nothing else:

| Module | Lines | Surface | What an auditor is looking at |
| --- | --- | --- | --- |
| `keyfile` | 1788 | `pub` | Password-wrapped key file: Argon2id, the key hierarchy, identifier derivation, every parse offset |
| `backup` | 1575 | `pub` | Backup container: multi-file encryption, the region table, resume, atomic finalisation |
| `signature` | 1374 | `pub` | Composite ML-DSA-65 plus Ed25519: transcript construction, key parsing, both verification halves |
| `stream` | 1334 | `pub` | Chunked encryption and decryption, the counter, framing, the failure paths |
| `kem` | 643 | private, re-exported | X-Wing encapsulation, trial decryption, the shared-secret comparison |
| `seal` | 531 | `pub` | One-shot sealed box |
| `aead` | 460 | private | The single AEAD construction every format goes through, and key handling |
| `kdf` | 367 | `pub` | HKDF derivation and the Argon2 profile |
| `format` | 297 | private | Shared header constants and the entry-parsing helpers |
| `secret` | 249 | `pub` | Symmetric key wrapper |
| `rng` | 137 | private | The only randomness source |
| `error` | 131 | `pub` | The uniform error surface |

`aead`, `format` and `rng` are private and entirely internal. `kem` is private, but
its items are re-exported, so a caller reaches it without the module ever being
public — which is why the "Entry points" list below is not simply the list of
public modules.

The crate root is not a module and has no row. What is in scope there is the lint
configuration, described below.

The lint configuration is in scope for a reason worth stating: `mili-core` denies
`unsafe_code` outright and denies `clippy::arithmetic_side_effects`. Those are
load-bearing claims about the whole crate, so an auditor is entitled to check that
they are declared and that they are not scoped away. Both live in `lib.rs` and both
are crate-level, not `cfg_attr(not(test))`.

## Adjacent, and separately assessed

These are not part of the audited unit. Listing them is so that nobody assumes
they were covered by a mili review.

- **`mili-ffi`** — the C ABI. A separate crate with its own surface, and the one
  place where a memory-safety question is genuinely different, because the caller
  supplies every buffer and every length. Its header is checked against the
  exports in both directions by `mili-ffi/tests/boundary.rs`.
- **`bindings/go`** — a Go binding over that ABI. A test failure here is usually a
  binding bug rather than a core bug, and the two are told apart by running the
  core tests.
- **`fuzz/`** — a separate crate with its own lockfile and its own CI job. It finds
  inputs; it makes no claim about them beyond reproducing.
- **`tests/vectors/`** — published vectors, read at compile time. Their provenance
  is in their own README.

## What the claims require

Each of these is a place where mili says something that would be expensive to be
wrong about. An audit that does not test them has not audited the interesting part.

**Confidentiality rests on a construction, not on an algorithm.** Every format
routes through one AEAD call in `aead.rs`, and the nonce is derived rather than
random. The claim to test is that no second path reaches a cipher directly, that
the nonce never repeats under one key, and that the KDF binds a derived key to its
context. A repeated nonce under one key is the failure that breaks everything at
once.

**Key separation rests on derivation, not on discipline.** A sealing key, a
signing key and a symmetric key come from separate HKDF labels over a master
secret. The claim to test is that no label is reused, that no label collides after
truncation, and that the domain separation survives the length of the labels.

**Uniqueness rests on the RNG.** `rng.rs` is one `getrandom` call with no fallback
and no caller-supplied alternative, and the composite signature and the
encapsulation both depend on it. The claim to test is that there is no second
source anywhere in the crate, including through a dependency that could supply
one, and that an entropy failure is an error rather than a panic or a silent
weakening.

**Failure is uniform on purpose.** `Error` has one variant per distinguishable
condition, and the parsers are supposed to collapse malformed input onto the same
one. An attacker learns from *which* error came back, so a parser that returns a
distinct error for a distinct malformation is a side channel even though no
secret is involved. This is easy to state and easy to regress, because every new
error path wants to be helpful.

**A signature that verified was signed by the key.** `verify_strict` refuses a
small-order Ed25519 point, and the composite requires both halves. The claim to
test is that neither half can be satisfied without the other, and that the
weak-point check cannot be bypassed by an alternative parse.

**The claims in the documentation are true.** `SPEC.md` is a normative document and
several of its statements are asserted by tests. The ones to spot-check are the
byte offsets in the header tables, the argument limits, and the statement that no
build script in the tree reads the network or the clock. The CI job `reproducible`
observes the last one rather than arguing it.

## Entry points

Everything a caller can reach, which is the whole of the attack surface:

- `keyfile`: create, open, wrap, unwrap, identifier, symmetric key file
- `backup`: create, open, append, finish, info
- `signature`: sign, verify, key generation, verifying key parse and serialise
- `seal`, `stream`: one-shot and chunked, reader and writer
- `kdf`: HKDF and Argon2id derivation
- `secret`: symmetric key generation and round trip
- `kem`: sealing key and encapsulation key generation, encapsulation, and trial
  decryption. Reachable through re-exports even though the module is private.
- `error`: the uniform error type. It is not an operation, but its shape is part of
  the contract — a caller can act on which error came back, so what it does and does
  not distinguish is itself a thing to review.

Any new `pub` module in `lib.rs` has to be added here, which is enforced by
`mili-core/tests/audit_scope.rs` rather than left to memory. Adding a public module
is a decision about the attack surface, and it should have to be written down
somewhere that a reader of this document will find.

## Method, and what would count as a finding

The useful order is what an auditor would reach for anyway: the parsers first,
because they take untrusted input and every one of them has an offset; then the
AEAD layer and the nonce derivation; then key handling and zeroisation; then the
claim list above.

Some things are cheap to check and worth doing before anything else:

- Exhaustively, the byte sweep and truncation sweep over every parser. These are in
  the crate's unit tests and can be run directly.
- Under `miri`, the byte-level code paths. `THREAT_MODEL.md` section 2.10 records
  what this does and does not reach, and the CI job runs it.
- The fuzz targets for an hour each. They have run clean, and a clean hour is
  evidence of nothing beyond that hour.

A finding would be a disagreement with a claim in `THREAT_MODEL.md` or
`SPEC.md`, a format ambiguity a second implementation could read differently, or a
parse path that is reachable with input the caller is not supposed to control. It
would not be the absence of a defence that `THREAT_MODEL.md` section 5 already
lists as out of scope; those are decisions, not defects, and the document says which
they are.

## What is deliberately not claimed

- **No bit-reproducibility across toolchains.** `SPEC.md` section 16 says a
  different rustc, target-cpu or linker gives a different binary. The CI job
  `reproducible` checks same-machine, same-toolchain, twice, and that is the whole
  of it.
- **No absence of side channels.** `THREAT_MODEL.md` section 5 lists what mili does
  not attempt. There is no constant-time harness in CI and no dudect-style
  measurement, so "no timing side channel" is not a claim mili makes.
- **No formal verification.** Nothing here is machine-checked as a proof. The
  formats are specified in prose and pinned by tests.
- **No third-party attestation.** There are no releases, so there is nothing to
  attest to and no provenance to publish. `SIGNING_KEYS.md` records that.