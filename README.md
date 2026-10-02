# mili

Parameter selection and a misuse-resistant wrapper around third-party Rust
cryptography crates. mili implements no cipher, hash, key encapsulation
mechanism, signature scheme, random number generator or key derivation function.

Post-quantum sealed boxes and signatures, with the parameters fixed in one
specification and the choices a caller could get wrong removed from the API. No
configuration, no algorithm selection, no nonce the caller holds.

**mili has not been audited by anyone.** Every crate it composes has been read by
mili itself and the notes are in `supply-chain/`, which is a weaker thing than an
independent audit. `docs/DISCLAIMER.md` says so in the first section a reader reaches,
and `SECURITY.md` says what to report and what is already a documented position.

Licensed under Apache-2.0 or MIT, at your option. See `LICENSE-APACHE` and
`LICENSE-MIT`.

## Read these first

`docs/README.md` routes you to the one document that matches why you are here.
The short version:

- `docs/SPEC.md` — the wire formats, key hierarchy and key schedules
- `docs/THREAT_MODEL.md` — what is mitigated, what is partial, what is out of scope
- `docs/DISCLAIMER.md` — what mili does not do, and the words mili does not use
- `SECURITY.md` — what to report, and what is already a documented position
- `CONTRIBUTING.md` — the checks, and the four failures that have broken CI

## Suite

| Purpose | Selection | Standard |
|---------|-----------|----------|
| Key encapsulation | X-Wing over X25519 and ML-KEM-768 | internet-draft, not an RFC |
| Signature | ML-DSA-65 and Ed25519, valid only if both verify | internet-draft, not an RFC |
| AEAD | ChaCha20-Poly1305 | RFC 8439 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Password derivation | Argon2id, 64 MiB, 3 passes, 4 lanes | RFC 9106 |
| Randomness | operating system CSPRNG | - |

Symmetric keys are 256 bit. One suite per format version. No algorithm
selection, no runtime option, no environment variable that changes any of the
above.

A `SymmetricKey` can be generated, backed up and restored, and no format in this
library encrypts with one, because every format derives its own key from a seed or
a password. `docs/SPEC.md` section 12.0 records that as a decision and the two
alternatives that were rejected.

## Design rules

1. Nothing is implemented here. Primitives come from crates that other people
   wrote, audited and published.
2. There is no configuration. If it is not in `docs/SPEC.md`, it is not selectable.
3. The API makes misuse hard or impossible at compile time. Signing keys and
   encryption keys are distinct types that do not convert into each other, in
   Rust and in Go. The caller never sees a nonce or a counter.
4. Failure is closed and uniform. Every authentication, key agreement and
   cryptographic parse failure returns `Error::Failed` with a fixed message and
   no detail.
5. No claims beyond what is implemented. See `docs/DISCLAIMER.md`.

## Layout

Source, one directory per deliverable:

```
mili-core/           the library, #![forbid(unsafe_code)]
  src/               error, secret, rng, kdf, kem, aead, seal, signature, stream,
                     format, keyfile, backup
  tests/             property tests against the public API
mili-ffi/            the C ABI, the only crate here with unsafe code
  include/mili.h     the header, hand written and test checked
  tests/             the boundary's own tests
bindings/go/         the Go binding, cgo over that ABI
fuzz/                cargo-fuzz targets, one per parser, outside the workspace
  regressions/       the input that found a real defect, kept so it cannot recur
```

Policy and provenance. The tools are pinned and the notes say what was read:

```
docs/                the format, the threat model, the disclaimer, the signing keys
supply-chain/        cargo-vet configuration, audit notes and what they do not say
tests/vectors/       known answer and NIST ACVP test vectors, read at compile time
.github/workflows/   CI, third-party actions pinned by commit SHA
```

`docs/README.md` is an index rather than a document: it says which of the four
belongs to a reader who wants to use mili, one who is assessing it, one who is
contributing, and one who is verifying a release. `README.md` and `SECURITY.md`
stay at the root because that is where GitHub looks for them.

Build configuration, one file per tool:

```
Cargo.lock           committed
rust-toolchain.toml  pinned toolchain
rustfmt.toml         formatting
deny.toml            cargo-deny: licences, features, duplicates, advisories
audit.toml           cargo-audit: advisory policy
```

`deny.toml` and `audit.toml` are two files because two tools read two different
formats from two different places, and neither would accept the other's file under
the other name. `supply-chain/config.toml` is a third file for the same reason.

`fuzz/` is a separate crate outside the workspace, built by `cargo fuzz` with
sanitizer flags that belong to the fuzz invocation rather than to the library. See
`fuzz/README.md`. `fuzz/corpus/` is generated by running the targets and is not
committed; `fuzz/regressions/` is, because those inputs found real defects and CI
replays them.

## What is implemented

Every format in `docs/SPEC.md` section 3 is implemented, sealed, opened, verified or
streamed as that section says.

| `format_type` | Name | Format | Operations |
|---------------|------|--------|------------|
| `0x01` | sealed box, single shot | `mili-seal-v1` | seal, open |
| `0x02` | streaming file | `mili-stream-v1` | write, read, finish |
| `0x03` | composite signature | `mili-sig-v1` | sign, verify |
| `0x10` | password-wrapped key file | `mili-key-v1` | seal, open, three key kinds |
| `0x11` | backup container | `mili-backup-v1` | create, inspect, restore |

`mili-kdf-v1` is the key derivation the sealed box and the key file both call, not
a file format of its own. `mili-sym-v1` is the name that was rejected;
`docs/SPEC.md` section 12.0 records why a `SymmetricKey` has no format that encrypts
with it.

## Known gaps

Named rather than left for a reader to find.

- `libc` and `curve25519-dalek` are partly read; `supply-chain/README.md` has the
  argument for where each stops and why that boundary is checkable.
- `mili-ffi` exports the formats in this table and no others. There is no PEM,
  no DER and no X.509, so the composite signature's assigned OID is not used.
- A `cargo test` run takes about four minutes, mostly ML-KEM and ML-DSA per
  property case and Argon2 in the key file tests. See the last section.
- No third party has audited mili. `docs/DISCLAIMER.md` section 3 says what exists
  instead.
- Two algorithms are internet-drafts, not RFCs, and may change. mili freezes
  what it implements under a format version byte.
- There is no release yet. Nothing here is on crates.io and no tag exists, so
  `mili-core` is `publish = false` and there is nothing to `cargo install`.
  `docs/SIGNING_KEYS.md` records the state of that.

## Using it

There is no release to install. Clone and build:

```sh
git clone https://github.com/oqullcan/mili.git
cd mili
cargo build --locked --release -p mili-core
```

Then add it as a path or git dependency, the ordinary way:

```toml
[dependencies]
mili-core = { git = "https://github.com/oqullcan/mili.git" }
```

Or write the git URL with `#v1.0.0` once a tag exists. `mili-core` has no build
script, no code generation and no `unsafe`, so a dependency on it brings no build
time surprises beyond compiling the cryptography crates.

The C ABI and the Go binding have their own build steps, below.

The library is not published to a registry, which means there is no version you
can depend on that someone else chose. Pin the git revision if you need a fixed
one, and read `docs/SPEC.md` before depending on a format: two of the primitives are
internet-drafts rather than RFCs, and a format version byte is what freezes what
mili implements.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo +nightly miri test --locked -p mili-core
cargo deny check
cargo audit
cargo vet check

cd fuzz
cargo deny check
cargo +nightly fuzz build --target x86_64-unknown-linux-gnu
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu open_backup regressions/open_backup/*.bin

cd ../..
cargo build --locked --release -p mili-ffi
cd bindings/go
LD_LIBRARY_PATH=../../target/release go test ./...
```

The fuzz targets are a separate job, one target per matrix entry. It replays the
committed corpus, which is what catches a reintroduced defect, and then fuzzes for
one minute as a smoke test that the target still reaches its parser. A campaign
worth the name is run by a person; see `fuzz/README.md`.

The Go tests need `LD_LIBRARY_PATH` pointed at `target/release`, because the binding
links `libmili_ffi.so` from there rather than installing it anywhere. A Go toolchain
is not pinned by this repository; CI uses `actions/setup-go` with a full version.

`cargo vet check` passing does not mean the dependency tree has been independently
audited. It means every crate in `Cargo.lock` is either audited or exempted, and an
exemption records that nobody has looked rather than that a crate is fine.

Every crate on a production edge now has a note in `supply-chain/audits.toml`
written by reading its source: 48 crates across 47 names, since `sha3` appears
twice at 0.11.0 and 0.12.0. The 40 remaining exemptions are all dev or build
dependencies.

Two of those notes are partial: `libc` and `curve25519-dalek`. Both name a
stopping point that is a checkable claim about reachability rather than a matter
of how long the file is, and `supply-chain/README.md` is where that is argued.

`SECURITY.md` is the file behind the repository's security policy setting, so a
report lands in GitHub's private advisory flow rather than in a public issue.
Private vulnerability reporting and secret scanning are both enabled; secret
scanning has push protection, so a push containing a credential is refused rather
than accepted and cleaned up afterwards.

## Why there is no CodeQL

Code scanning is available and was considered. The reason it is not here is
measurable rather than a matter of taste: `mili-core` contains no filesystem
access, no process spawning, no network access and no `unsafe`, which are the
four things CodeQL's highest-yield Rust queries look for. Grepping the crate for
`std::fs`, `Command::new`, `std::net` and `unsafe` returns zero hits in every
case.

That leaves `mili-ffi` as the only place a static analyser has anything to read,
and it is a thin boundary over byte buffers that returns an error code: 64 lines
of `unsafe`, all of it pointer arithmetic into caller-owned buffers, covered by 32
boundary tests including a header that is checked against the exported symbol
list. The finding classes that would apply to unsafe Rust are largely
unsupported by CodeQL today.

The checks that do apply are already present. Hardcoded credentials are covered by
secret scanning, which is enabled with push protection. Panics on malformed input,
which is the failure this library most cares about, are covered by
`clippy::arithmetic_side_effects` being denied, six fuzz targets with committed
regressions, and 284 tests.

So the honest summary is that CodeQL would be a fifth layer over code that has
almost no surface for it. If the library later grows a filesystem, network or
process dependency, that stops being true and this decision should be revisited.

## Releases

There are none. `publish = false` on every crate and no tag exists, which means
the repository is the only distribution channel and there is no version anyone
else chose.

When a release is cut, two things have to be true and are checked by hand rather
than by CI, because CI has `permissions: contents: read` and cannot write a tag:

- The tag is an Ed25519-signed tag. `git tag -v <tag>` prints a fingerprint that
  must appear in `docs/SIGNING_KEYS.md`, which also records a withdrawal if a key is
  ever suspected of exposure. That file is the revocation mechanism, because an
  offline key has nowhere else to be revoked.
- Build provenance is produced keyless with sigstore from the workflow run, which
  needs no key and is why provenance and signing are separate mechanisms.

`docs/SPEC.md` section 17 is the policy and `docs/SIGNING_KEYS.md` is the record.

## The C ABI and the Go binding

`mili-ffi` is the only crate here that contains `unsafe`. `mili-core` is
`#![forbid(unsafe_code)]` and stays that way, which is the reason the crate exists.
Its rules are in `docs/SPEC.md` section 18.1: no pointer arithmetic leaves the crate, output
buffers belong to the caller, every function returns a code, every output takes a
capacity and reports its length, and a panic cannot cross the boundary.

`mili-ffi/include/mili.h` is hand written rather than generated, and checked against
the exported symbols by a test, because a generated header is a build artefact whose
generator, configuration and toolchain all become part of what a caller compiles
against.

`bindings/go` is a cgo layer over that ABI with no dependencies and no policy of its
own. The three key kinds are three distinct Go types, so a symmetric key cannot be
handed to a function expecting a sealing seed by accident: both are 32 bytes and a
length would not tell them apart.

The guarantee is weaker in Go than in `mili-core`, and `keys.go` says so. In
`mili-core` the types are distinct newtypes with no conversions at all, so the
mismatch does not compile. Go permits an explicit conversion between named types
sharing an underlying type, so `mili.SealingKey(aSymmetricKey)` does. Naming stops
it from happening by inference rather than by intent, and each function still states
the kind it expects and checks what it is handed.

## Cost of the checks

`cargo test` takes about four minutes. Three things dominate it. The property
tests run an ML-KEM-768 decapsulation or an ML-DSA-65 signature per case. The
stream tamper sweeps do one decapsulation per tested byte. And the password
based tests do an Argon2id derivation, which at the documented profile touches
64 MiB three times and takes about 120 ms.

That last number is why `argon2` and `blake2` are compiled at `opt-level = 3`
even in the development profile, in `Cargo.toml`. Unoptimised, one derivation
takes about two seconds, the exhaustive tamper sweeps run at about one
derivation per tested byte, and the suite takes over ten minutes instead of four.
The profile override changes how the dependency is compiled, not what it
computes, so the cross implementation vectors in `tests/vectors/` still pin the
output.

The Go tests run in about eight seconds, almost all of it Argon2 in the key file
and backup cases.

For the same reason the exhaustive tamper sweeps do not each run a derivation.
The byte sweep lives in the crate's unit tests at the parse and AEAD layers,
where it costs one ChaCha20-Poly1305 operation per byte, and the property tests
carry the randomised end-to-end version.
`cargo +nightly miri test -p mili-core` takes about six minutes with
`MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance"`, which is what CI
uses, and about twice that without the flags. It is a CI job rather than something
to run in a loop. Tests
that call ML-KEM-768, X25519, ML-DSA-65 or Ed25519 are excluded under miri, as
are the tests that call Argon2id, one exhaustive Wycheproof sweep is ignored
there, and the sealed box byte sweep is reduced to one position per region because
each authenticated operation costs about ten seconds when interpreted.

The exclusions are not loose. Roughly 131 of the 193 library tests are gated, and
an attempt to widen the gate was made and abandoned: the stream module looks like
the obvious candidate because it is ChaCha20-Poly1305 and HKDF with no KEM, but
its tests go through `seal_buffered`, which decapsulates, which is X-Wing, which
is ML-KEM-768 and X25519. `SealingKey::from_bytes` alone is genuinely free, since
it only wraps 32 bytes, but no test in the tree needs a key without also sealing or
opening with it. So the number miri runs is smaller than the number of tests
because the arithmetic is slow to interpret, not because the gating was
over-applied, and the CI job is honest about what it covers rather than quietly
green over a tenth of the suite.

Excluding a test from miri is easy to forget and the symptom is a job that never
finishes rather than a failure that names the test. `keyfile::derive_kek` panics
under miri instead of deriving, so a test that reaches it without
`#[cfg(not(miri))]` fails in seconds with a message saying what to add. Two of the
overflow regression tests added for the bug the fuzzer found were missing the
attribute, which is how that guard came to exist.
