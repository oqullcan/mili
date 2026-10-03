# Contributing to mili

## Before you write code

`docs/SPEC.md` is the wire format of everything mili reads and writes. A change to
a format is a change to a contract with anyone who already has a file, so a
proposal that does not say which section it changes and why is not ready to
discuss. `docs/SPEC.md` section 14 lists where mili already departs from a
reference implementation and is the most likely place for a change to belong.

`docs/THREAT_MODEL.md` is the other half. A change that weakens a claim in it is
either a fix to the code or a change to the claim, and which one matters.

## The checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
cargo deny check
cargo vet check --locked

cargo +nightly miri test --locked -p mili-core

cd fuzz && cargo +nightly fuzz run --target x86_64-unknown-linux-gnu open_backup regressions/open_backup/*.bin
```

`cargo test` takes about four minutes, dominated by Argon2id in the key file tests
and one ML-KEM operation per property case. The miri job takes about eleven.

A full `cargo test --workspace` run is the gate for anything touching a format.
The six fuzz targets each need a campaign worth the name run by a person; CI runs
one minute per target as a smoke test that the target still reaches its parser.
See `fuzz/README.md`.

## Five things that have broken CI here, so you do not have to rediscover them

Each of these failed a push, and each failed for a reason that is not in the error
message.

**The tools are pinned, and the pin is the point.** `cargo-vet`, `cargo-deny` and
`cargo-fuzz` are installed with an explicit version in `.github/workflows/ci.yml`.
An unpinned `cargo-vet` resolved to 0.10.0 while the local toolchain had 0.10.2, and
the two format `supply-chain/audits.toml` differently, so CI failed on a tree that
passed locally with the same files. This is `docs/SPEC.md` section 16 applied to
the tools that check the dependencies: a version is written down, not fetched.

**`rustup toolchain install --target` for a non-host target changes the default.**
Installing `x86_64-unknown-linux-musl` that way does it with `--force-non-host`,
which makes musl the default for that toolchain, and then `cargo fuzz` builds for
musl, and ASan is incompatible with musl's static linking. The symptom is
`sanitizer is incompatible with statically linked libc` on the first dependency.
The fuzz commands pass `--target x86_64-unknown-linux-gnu` for exactly this reason.
Do not "fix" that by adding a `targets:` entry to the workflow.

**Each CI job gets a clean runner.** The fuzz crate is outside the workspace and
has its own lockfile, so it needs `cargo-deny` installed in its own job. The check
job having it does not carry over.

**Regression replay needs the files, not the directory.**
`cargo fuzz run target regressions/target/` treats the directory as a corpus and
fuzzes forever. `regressions/target/*.bin` executes each input and exits, which is
what a regression check wants. There is one committed regression today,
`open_backup/entries_len_overflow.bin`.

**A test that uses a `#[cfg(not(miri))]` import breaks only the miri job.** The
signing tests skip miri because an ML-DSA-65 plus Ed25519 signature takes minutes
under interpretation, so `SigningKey` and `HEADER_SIZE` are imported under
`#[cfg(not(miri))]` rather than unconditionally. A new test that reaches for one of
them compiles and passes everywhere else, and fails in the miri job at compile time
with `E0425: cannot find value ... in this scope`. Every other job is green and the
failure names a symbol rather than a cause.

Reproduce it locally in about a second instead of waiting for the push:

```sh
RUSTFLAGS="--cfg miri" cargo +nightly test --locked -p mili-core --lib --no-run
```

That builds the test binary with the same `cfg` the miri job sees. It does not
interpret anything, so it is fast, and it catches the whole class. The fix is
either `#[cfg(not(miri))]` on the test if it signs, or moving a constant out of
the gated import if it does not — a length that cannot be asserted under miri is a
length nothing checks there.

## Miri coverage is narrow on purpose

Roughly 142 of the 217 library tests are `#[cfg(not(miri))]`, and that is not an
oversight to be tidied. A test that decapsulates goes through X-Wing, which is
ML-KEM-768 and X25519, and interpreting either of those is not something a six
minute job should do. The stream module looks like the exception because it is
ChaCha20-Poly1305 and HKDF with no KEM, but its tests go through `seal_buffered`,
which decapsulates.

If you add a test, `keyfile::derive_kek` panics under miri rather than deriving, so
a test that reaches it without `#[cfg(not(miri))]` fails in seconds with a message
naming what to add. That guard exists because a test that hung the job was harder
to diagnose than one that failed immediately.

## Adding a dependency

Every version is written as `=x.y.z`. Caret requirements are not used, so adding a
dependency is always an explicit edit and a lockfile change.

**There are two lockfiles.** The fuzz crate is excluded from the workspace and has
its own `fuzz/Cargo.lock`, so a feature change in the root `Cargo.toml` leaves it
stale and every fuzz job fails at its first step with "cannot update the lock file
because `--locked` was passed". The same is true of any dependency change. After
touching `Cargo.toml`, refresh both:

```sh
cargo metadata --format-version 1 > /dev/null
cd fuzz && cargo metadata --format-version 1 > /dev/null
```

Then, for a new dependency:

1. `cargo vet check` will report it as unaudited. Read its source and write a note
   in `supply-chain/audits.toml`, or add an exemption that says why nobody looked.
   An exemption records that nobody has looked; it is not a statement that a crate
   is fine.
2. `cargo deny check` may fail on the licence or on a feature default.
3. If it is a direct dependency of `mili-core`, `cargo deny` will want an entry
   under `[bans.features]` explaining any feature you turned off. That check is
   `exact = true`, so a feature added anywhere fails the build until it is listed,
   which is the intended behaviour rather than an annoyance to work around.

   `hybrid-array` is the one direct dependency without an entry, on purpose: its
   features are chosen by whoever depends on it — `ml-kem`, `ml-dsa` and others
   each turn on a different combination — so an exact entry would be pinning the
   union of every upstream choice, which is not a decision mili makes. `deny.toml`
   says so where `cargo deny` reads it.

## Adding a format

`docs/SPEC.md` section 3 is the format table. A new format needs an entry there, a
section of its own, a `format_type` byte that does not collide, a fuzz target, and
a property test. The three rules a new format must not break are `README.md`'s
design rules: no configuration, no algorithm selection, and a uniform error.
