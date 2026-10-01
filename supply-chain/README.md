# mili supply chain

`cargo vet` configuration. Read this before treating `cargo vet check` passing as
a statement about the tree.

## What this does and does not say

A passing `cargo vet check` means every crate in `Cargo.lock` is either audited or
exempted. It does **not** mean the whole tree has been audited, and the difference
is the point of this file.

At the time of writing, of the 52 third-party crates reachable from mili's
shipped code:

- **11 have an audit written for them here**, by reading their source. Nine of
  those are ours; two come from the Google and Mozilla audits `cargo vet import`
  pulled in.
- **The rest are exempted**, which is a record that nobody has looked, not a
  statement that they are fine.

The largest unaudited crates in the shipped path are `libc` (130k lines),
`curve25519-dalek` (35k), `syn` (50k, reached through `curve25519-dalek-derive`),
`typenum` (19k) and `proc-macro2` (6k). Together that is most of the source in
the tree by volume, and none of it has been read.

## Why it is partial rather than complete

Auditing `libc` and `curve25519-dalek` properly is a multi-day job that a security
auditor does over weeks. Doing it badly, by skimming and writing "looks fine", is
worse than not doing it, because it puts a signature on the work that says someone
checked. `cargo vet` is a tool for recording that check happened; it cannot
substitute for the check.

So the honest position is the one recorded here: a partial audit, named.

## Which crates were chosen

The eleven are the ones where reading the source was tractable **and** where a
defect would reach mili's security directly.

- `x-wing`, `hkdf`, `shake`, `sponge-cursor`, `universal-hash`, `kem`: the KEM
  and key schedule. `x-wing` in particular is 383 lines, has no unsafe at all, and
  mili's sealed box is entirely dependent on its combiner being correct.
- `subtle`, `cmov`, `ctutils`: the constant time primitives. `cmov` is the one that
  earned the most scepticism, because a constant time primitive that is not
  constant time is worse than an obviously variable one, because it is trusted to
  be constant time.
- `getrandom`: the only path by which key material enters mili, and the only crate
  in the tree with a build script that had to be read.
- `zeroize`: every secret type in mili depends on it, including the Argon2
  working memory wipe.

`argon2`, `ml-kem`, `ml-dsa`, `sha2`, `sha3`, `chacha20poly1305` and
`ed25519-dalek` are **not** audited here, which is the most significant gap.
Those are the primitives mili's security rests on most directly, and each is
substantial enough that a real review of the unsafe blocks in `sha2`, `chacha20` and
`poly1305` is its own piece of work. They are exempted, and the exemption is the
record.

## Upstream audits

Two third-party audit collections are imported:

- **Google**, from the ChromiumOS and Chromium trees.
- **Mozilla**, from mozilla-central and glean.

`cargo vet init` reported that `bytecode-alliance` and `Embark` would cover more
of the tree, but neither is in the registry `cargo-vet` ships with, so they are
not imported. Between the two that are, they cover 32 of our 52 production crates
by name, but most of that coverage is at older versions and for the weaker
`safe-to-run` criterion, so the number of crates they actually certify is far
smaller.

RustCrypto does not publish `cargo-vet` audits in any of the repositories checked.
That is the single biggest reason the RustCrypto half of this tree is unaudited.

## Running it

```sh
cargo vet check                       # the CI check
cargo vet suggest                     # what is left, cheapest first
cargo vet inspect <crate> <version>   # fetch and read a crate's source
cargo vet certify <crate> <version> --criteria safe-to-deploy --notes ...
```

An exemption is added with `cargo vet add-exemption`. Each one in `config.toml`
should carry a note saying why nobody looked; several of the generated ones do not,
and those are the ones to fix first if this file is ever picked up again.
