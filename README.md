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
   encryption keys are distinct types that do not convert into each other. The
   caller never sees a nonce or a counter.
4. Failure is closed and uniform. Every authentication, key agreement and
   cryptographic parse failure returns `Error::Failed` with a fixed message and
   no detail.
5. No claims beyond what is implemented. See `DISCLAIMER.md`.

## Layout

```
mili-core/           the library
  src/               error, secret, rng, kdf, kem, aead, seal
  tests/             property tests against the public API
tests/vectors/       known answer test vectors, read at compile time
docs/                created when a document does not belong in the root
.github/workflows/   CI, third-party actions pinned by commit SHA
Cargo.lock           committed
deny.toml            dependency policy
audit.toml           advisory policy
rust-toolchain.toml  pinned toolchain
```

`mili-ffi` and `fuzz/` are added in their phases.

## Implemented so far

| Phase | Status |
|-------|--------|
| 1 skeleton, error type, secret types, RNG, key derivation, CI, dependency policy | done |
| 2 X-Wing sealed box, `mili-seal-v1` | done |
| 3 composite signatures | not started |
| 4 streaming file encryption | not started |
| 5 password-wrapped key files | not started |
| 6 fuzz targets, miri, hardening | not started |
| 7 `mili-ffi` and the Go binding | not started |

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo +nightly miri test --locked -p mili-core
cargo deny check
cargo audit
```

`cargo-vet` is not configured yet. See the phase 1 notes.

## Cost of the checks

`cargo test` takes about 50 seconds, dominated by the property tests, which run
one ML-KEM-768 decapsulation per case. `cargo +nightly miri test -p mili-core`
takes about 7 minutes and is a CI job rather than something to run in a loop.
