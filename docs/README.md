# mili documentation

Five documents, each answering a different question. Read the one that matches
why you are here rather than all five.

## If you want to use mili

**`../README.md`** — the suite, the design rules, how to add it as a dependency,
and the known gaps.

**`SPEC.md`** — the part you cannot skip. This is the wire format of every file
mili reads or writes: header layout, what each field means, which value is
versioned, and the key hierarchy above it. If you are writing or checking a file
format, or you are reasoning about whether two files are compatible, this is the
document and the others assume it.

## If you are assessing whether to trust it

**`THREAT_MODEL.md`** — what mili defends against, what it only partly defends
against, and what it does not attempt. Section 3 is the substantive one; section 5
is the out-of-scope list, which is the part that saves you from asking about
compromised hosts and traffic analysis.

**`DISCLAIMER.md`** — the short version, written to be read before the code rather
than after an incident. Section 3 records that no third party has audited mili and
what exists in place of that, which is the single fact to weigh above everything
else here.

## If you are considering a command line front end

**`CLI.md`** — there is no CLI, and this is what one would have to get right if
there were. It is written after reading Ente's Rust CLI and records both what to
copy from it and what to refuse, the second list being the longer one: a world
readable key file, a password that is only ever accepted as a command line flag,
and a state file created by `--help`. The reason it is a document rather than a
crate is at the end of it, and it is a privacy decision rather than an
engineering one.

## If you are contributing

**`SPEC.md`** first, for the reason above. A change to a wire format is a change
to a contract, and section 14 lists the places where mili deliberately departs
from a reference implementation, which is where a proposal is most likely to
belong.

`../CONTRIBUTING.md` has the mechanical parts: the pinned toolchain, the checks CI
runs, why the fuzz targets need an explicit `--target`, and why `cargo vet` refuses
to let a tool version float.

## If you are verifying a release

**`SIGNING_KEYS.md`** — which public key has signed which tag, how to check a
tag against it, and what to do with a build signed by a key that has since been
withdrawn. There are no releases yet, so the file currently records that.

The dependency tree's provenance is a separate question from mili's own: that is
`../supply-chain/README.md`, which is explicit about what reading the tree did and
did not establish.

## What is not here

There is no `CODE_OF_CONDUCT.md`, because there is no community to have one yet.
It would be added before it were needed rather than after.

`../CHANGELOG.md` records what changed in each release, in the format Keep a
Changelog prescribes. There are no releases yet, so its entries are the ones
being accumulated for `0.1.0`.

The wire format vectors live in `../tests/vectors/` rather than here, with their
own README, because they are read by the test suite at compile time rather than by
a person.
