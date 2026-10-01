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

So the honest gap is no longer the production tree. It is volume. `libc` is 130k
lines and `curve25519-dalek` is 35k, and neither has been read end to end. Their
audit notes say so in the notes themselves, in the words "this is an exemption
rather than a full audit" and "what was not read", rather than presenting a partial
review as a finished one.

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

Two notes are partial and say so:

- `curve25519-dalek`: the build script, the `#[unsafe_target_feature]` surface, the
  Montgomery ladder's constant time property, and one constant checked against an
  independent derivation of the field prime. Not read: the field arithmetic, the
  scalar arithmetic, the AVX2 and IFMA backends.
- `libc`: the build script and the shape of the unsafe, which is FFI declarations
  and `unsafe impl Send`/`Sync` for opaque platform handles. Not read: the
  per-platform signature tables.

`curve25519-dalek-derive` and `rustc_version` are complete for what they are: a
proc macro that emits one attribute, and a crate that runs `$RUSTC -vV`.

## Why partial reviews are recorded at all

Auditing `libc` and `curve25519-dalek` properly is a multi-day job that a security
auditor does over weeks. Doing it badly, by skimming and writing "looks fine", is
worse than not doing it, because it puts a signature on the work that says someone
checked. So the compromise here is a note that says exactly which part was read and
which was not, and `cargo vet`'s own notion of criteria kept honest by the notes
themselves.

`curve25519-dalek`'s note also records what was checked rather than skimmed: the
`MINUS_ONE` field element was verified against a derivation of p-1 for p = 2^255-19
in 51-bit limbs, because a file of 7781 lines of limb literals is the wrong thing to
read line by line and the right thing to check one value of.

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