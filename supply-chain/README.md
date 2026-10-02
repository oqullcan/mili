# mili supply chain

`cargo vet` configuration. Read this before treating `cargo vet check` passing as
a statement about the tree.

## What this does and does not say

A passing `cargo vet check` means every crate in `Cargo.lock` is either audited or
exempted. It does **not** mean every crate has been read, and the difference is the
point of this file.

At the time of writing:

- **Every crate on a production edge has an audit written for it here**, by reading
  its source. 48 third-party crates across 47 names, since `sha3` appears twice at
  0.11.0 and 0.12.0. Plus `rustc_version`, which is a build dependency of
  `curve25519-dalek` and therefore not on a production edge but not disposable
  either.
- **The 40 remaining exemptions are all dev or build dependencies.** They are
  `proptest` and its `rand`, `serde` and `serde_json` for the fuzz targets,
  `zerocopy`, the `syn`/`proc-macro2` pair for a dev-only proc macro,
  `windows-sys`, and similar.

So the honest gap is no longer the production tree. It is reachability inside two
large crates, and it is worth being precise about that rather than quoting line
counts, because line count was misleading in both directions.

`libc` is 129k lines and mili reaches three symbols of it: `dlsym`,
`RTLD_DEFAULT` and `getrandom`, all of them through `getrandom` and none of them
referenced by mili directly. Every one of those three declarations was read.
What the note does not cover is the signature tables for platforms mili does not
build for, which is a different statement from "130k lines are unreviewed" and a
stronger one to lean on.

`curve25519-dalek` is 35k lines, and the first question there is which backend
runs rather than how big the files are. On x86-64 the build selects `simd`, which
is the 2749-line AVX2 backend; the 8874-line serial backend is compiled but not
selected, and the 3247-line `ifma` backend is not compiled at all. The audit is
organised by that, so it covers the field arithmetic that executes and names the
rest as not read.

## The production tree

Grouped by what a defect in it would do to mili.

**KEM and key schedule.** `x-wing`, `ml-kem`, `ml-dsa`, `kem`, `hkdf`, `shake`,
`sponge-cursor`, `universal-hash`, `module-lattice`, `num-traits`. `x-wing` is 383
lines with no unsafe at all, and mili's sealed box is entirely dependent on its
combiner being correct. `ml-kem`'s implicit rejection and constant-time decode are
recorded explicitly, as is the `expand_key`/`decaps_key` split that the shared XOF
cursor makes possible.

**Signatures.** `ed25519-dalek`, `ed25519`, `x25519-dalek`, `curve25519-dalek`,
`curve25519-dalek-derive`, `signature`. No unsafe in the first three, which is the
notable fact rather than a formality: the constant time property is a consequence
of the design rather than an audit finding.

**Hashing and KDF.** `sha2`, `sha3` at both versions, `keccak`, `blake2`, `hmac`,
`digest`, `block-buffer`, `base64ct`, `argon2`. The two SHA-2 and SHA-3 CPU dispatch
chains, and `keccak`'s 664 lines of aarch64 unsafe behind a soft backend fallback,
are the things that needed reading.

**AEAD and cipher.** `chacha20poly1305`, `chacha20`, `poly1305`, `cipher`, `aead`,
`inout`, `cpufeatures`, `sponge-cursor`. The dispatch pattern that all four
accelerated crates share is recorded under `cpufeatures`: one detection per process,
no data in the token, so a union dispatch cannot be re-entered.

**Constant time primitives.** `subtle`, `cmov`, `ctutils`. `cmov` earned the most
scepticism, because a constant time primitive that is not constant time is worse
than an obviously variable one, because it is trusted to be constant time.

**Typed arrays and const machinery.** `hybrid-array`, `typenum`, `cfg-if`,
`zeroize`. `typenum` being 19k lines of compile-time arithmetic is why every length
check in the tree above can compare against a compile-time value.

**Entropy.** `getrandom` and `rand_core`, where the second is a trait crate that
cannot be an entropy source of its own, which is the property `section 9` needs.

**FFI and platform.** `libc`, partial, as described above.

**Proc macro chain.** `syn`, `proc-macro2`, `quote`, `unicode-ident`,
`curve25519-dalek-derive`. All compile-time only; a proc macro is a normal
dependency of the crate using it rather than a build dependency, which is why
`cargo tree --edges normal` lists them, but none of it is in the shipped binary.

## Partial reviews, named as partial

Two notes are partial, and what each one leaves out is stated in reachability terms
rather than in line counts:

- `curve25519-dalek`: the build script, the AVX2 field arithmetic that actually
  executes on x86-64, the constant-time versus variable-time split in the scalar
  multiplication, both paths mili takes, and one constant checked against an
  independent derivation of the field prime. Not read: the `ifma` backend, which
  does not compile on this target; the serial `u64` backend, which is compiled
  but not selected on an AVX2 host; and the multi-scalar kernels mili does not
  reach.
- `libc`: the build script, the shape of the unsafe, and all three symbols mili
  reaches. Not read: the signature tables for platforms mili does not build for.

`curve25519-dalek-derive` and `rustc_version` are complete for what they are: a
proc macro that emits one attribute, and a crate that runs `$RUSTC -vV`.

## Why partial reviews are recorded at all

The temptation in both cases is to close the note by skimming the rest and
writing "looks fine". That is worse than leaving the gap, because it signs the
work as checked when it was not, and a reader of `cargo vet` has no way to tell
the difference between an audit and a skim.

So the stopping point has to be a defensible one rather than a comfortable one.
For `libc` it is that three declarations are reachable and all three were read;
for `curve25519-dalek` it is that the executing backend was read and the rest is
not compiled in. Both are arguments about reachability that can be checked, which
is a better answer than "there were 130k lines".

There is also a test-side argument that belongs here rather than being left
implicit. The AVX2 field arithmetic is not merely compiled, it is executed by
mili's own suite: the 25 NIST ACVP ML-KEM-768 cases and the X-Wing draft vectors
all run through `expand_key` and `decapsulate`, and the shared secrets agree with
vectors generated by NIST's FIPS 204 reference implementation. That is evidence,
not proof, and it is evidence about the paths those vectors reach rather than
about the backend mili does not execute.

## Upstream audits

Two third-party audit collections are imported, and `cargo vet prune` has since
removed most of what they covered, since the manual audits above are stronger:

- **Google**, from the ChromiumOS and Chromium trees.
- **Mozilla**, from mozilla-central and glean.

`cargo vet init` reported that `bytecode-alliance` and `Embark` would cover more
of the tree, but neither is in the registry `cargo-vet` ships with, so they are not
imported.

RustCrypto does not publish `cargo-vet` audits in any of the repositories checked.
That is the single biggest reason the RustCrypto half of this tree needed manual
audits in the first place.

## Running it

```sh
cargo vet check                       # the CI check
cargo vet suggest                     # what is left, cheapest first
cargo vet inspect <crate> <version>   # fetch and read a crate's source
cargo vet certify <crate> <version> --criteria safe-to-deploy --notes ...
```

An exemption is added with `cargo vet add-exemption`. `cargo vet prune` is part of
the CI check's expectation: it removes exemptions that are no longer needed and
reports imports that no longer apply, and this tree is expected to prune clean.