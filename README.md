# mili

Parameter selection and a misuse-resistant wrapper around third-party Rust
cryptography crates. mili implements no cipher, hash, key encapsulation
mechanism, signature scheme, random number generator or key derivation function.

## Read these first

- `SPEC.md` — the wire formats, key hierarchy and key schedules
- `THREAT_MODEL.md` — what is mitigated, what is partial, what is out of scope
- `DISCLAIMER.md` — what mili does not do, and the words mili does not use

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

## Design rules

1. Nothing is implemented here. Primitives come from crates that other people
   wrote, audited and published.
2. There is no configuration. If it is not in `SPEC.md`, it is not selectable.
3. The API makes misuse hard or impossible at compile time. Signing keys and
   encryption keys are distinct types that do not convert into each other, in
   Rust and in Go. The caller never sees a nonce or a counter.
4. Failure is closed and uniform. Every authentication, key agreement and
   cryptographic parse failure returns `Error::Failed` with a fixed message and
   no detail.
5. No claims beyond what is implemented. See `DISCLAIMER.md`.

## Layout

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
tests/vectors/       known answer test vectors, read at compile time
docs/                created when a document does not belong in the root
.github/workflows/   CI, third-party actions pinned by commit SHA
Cargo.lock           committed
deny.toml            dependency policy
audit.toml           advisory policy
rust-toolchain.toml  pinned toolchain
```

`fuzz/` is a separate crate outside the workspace, built by `cargo fuzz` with
sanitizer flags that belong to the fuzz invocation rather than to the library.
See `fuzz/README.md`.

## Implemented so far

| Phase | Status |
|-------|--------|
| 1 skeleton, error type, secret types, RNG, key derivation, CI, dependency policy | done |
| 2 X-Wing sealed box, `mili-seal-v1` | done |
| 3 composite signatures | done |
| 4 streaming file encryption | done |
| 5 password-wrapped key files, backup container | done |
| 6 fuzz targets, miri, hardening | done |
| 7 `mili-ffi` and the Go binding | done |

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo +nightly miri test --locked -p mili-core
cargo deny check
cargo audit

cd fuzz
cargo deny check
cargo +nightly fuzz build
cargo +nightly fuzz run open_backup regressions/open_backup

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

`cargo-vet` is not configured yet. See the phase 1 notes.

## The C ABI and the Go binding

`mili-ffi` is the only crate here that contains `unsafe`. `mili-core` is
`#![forbid(unsafe_code)]` and stays that way, which is the reason the crate exists.
Its rules are in `SPEC.md` section 18.1: no pointer arithmetic leaves the crate, output
buffers belong to the caller, every function returns a code, every output takes a
capacity and reports its length, and a panic cannot cross the boundary.

`mili-ffi/include/mili.h` is hand written rather than generated, and checked against
the exported symbols by a test, because a generated header is a build artefact whose
generator, configuration and toolchain all become part of what a caller compiles
against.

`bindings/go` is a cgo layer over that ABI with no dependencies and no policy of its
own. The three key kinds are three distinct Go types, which is what stops a symmetric
key from being read as a sealing seed: both are 32 bytes, and a length would not tell
them apart.

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
each authenticated operation costs about ten seconds when interpreted. See
`SPEC.md` section 15.1.

Excluding a test from miri is easy to forget and the symptom is a job that never
finishes rather than a failure that names the test. `keyfile::derive_kek` panics
under miri instead of deriving, so a test that reaches it without
`#[cfg(not(miri))]` fails in seconds with a message saying what to add. Two of the
overflow regression tests added for the bug the fuzzer found were missing the
attribute, which is how that guard came to exist.
