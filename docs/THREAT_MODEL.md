# mili — Threat Model

This document maps each threat to exactly one of: mitigated, partially
mitigated, out of scope. There is no fourth category and no hedging language.

A threat that is not listed here is not addressed by mili.

## 1. What mili is protecting

mili protects the confidentiality and authenticity of data at rest and in
transit, and the integrity of signatures, against an adversary who can observe,
copy, store, replay, reorder, truncate and modify stored or transmitted files,
and who holds public keys but not secrets.

The adversary may:

- observe a file, indefinitely, and correlate files with each other
- modify any byte of a file and re-present it
- remove bytes from anywhere in a file
- reorder, duplicate or insert chunks
- present a file produced by one recipient to a different recipient
- choose the salt, the counter and every other field of a file it constructs
- construct arbitrarily large or arbitrarily malformed files

The adversary may not:

- read the process memory of a running mili host
- extract an encryption key that has never left that memory
- coerce the key holder

Those are section 6.

## 2. Mitigated

### 2.1 Confidentiality of file contents

ChaCha20-Poly1305 under a key derived from the X-Wing shared secret. An
adversary without the recipient's key or the KEM shared secret cannot read
plaintext. Mitigated by sections 4, 5 and 9 of `SPEC.md`.

### 2.2 Integrity of header, ciphertext and chunks

The header, including the magic, format type, version, salt and KEM ciphertext,
is the AEAD associated data of every ciphertext in the file. Poly1305 covers the
associated data and the ciphertext. Any modification is a decryption failure.
Mitigated by the key schedules in `SPEC.md` sections 4.1 and 5.2.

### 2.3 AEAD nonce reuse

Two files share an AEAD key only if they share the 32 byte `salt`, because the
key is a HKDF-Expand of the salt. Within a stream file the nonce is a strictly
increasing 88 bit counter, which cannot repeat before the file reaches 2^88
chunks, at which point the writer returns `Error::Internal` rather than
wrapping. The writer never transmits a nonce and the caller never sees one.

Mitigated by construction, not by caller discipline.

### 2.4 Chunk reordering

The chunk nonce and the associated data both contain the chunk counter, which
the reader requires to advance by exactly one. A chunk presented at the wrong
index is decrypted with the wrong nonce and the wrong associated data. Mitigated
by `SPEC.md` section 5.3.

### 2.5 Truncation from the end

A stream must end with a chunk carrying the final flag. A stream that stops
without one is `Error::Failed`. Removing the final chunk of a stream leaves the
reader without a final chunk. Removing trailing bytes leaves a short chunk, which
is rejected. Appending after the final chunk leaves trailing data, which is
rejected. Removing a middle chunk makes the following chunks arrive at the wrong
counter, and duplicating the final chunk makes it trailing data. All mitigated by
`SPEC.md` sections 5.3 and 5.4, and covered by tests that perform each of those
operations.

A final chunk whose plaintext is a multiple of the chunk size is the same length
as a non-final one, so length alone does not identify it. The reader tries the
non-final interpretation first and the final one on failure, which is the same
rule age uses. Mitigated, with the ambiguity recorded in `SPEC.md` section 5.3.

### 2.6 Appending to a stream

After the final chunk the reader requires end of input. Trailing bytes are
`Error::Failed`. Mitigated by `SPEC.md` section 5.3.

### 2.7 Key derivation context collision

The `Domain` type is closed. Callers inside the crate cannot supply a free-form
label, so a new derivation purpose cannot be added without a new variant, and a
new variant cannot reuse an existing label without failing the unit test that
asserts the labels are distinct and all carry the `mili-v1:` prefix. No label is
borrowed from age, rage, dark-bio, HPKE, TLS or COSE. Mitigated by `kdf.rs` and
the frozen vectors under `tests/vectors/`.

### 2.8 Password key derivation parameter downgrade

A key file whose stored parameters fall below the documented floor is rejected
before Argon2 runs, so an attacker cannot rewrite a strong key file into a weak
one and have it accepted. Mitigated by `SPEC.md` section 7.2.

### 2.9 Cost exhaustion from a hostile key file

`m_cost` above 1 GiB is rejected before any allocation, and `m_cost` below the
floor is also rejected. `t_cost` above 8 and `p_cost` above 16 are rejected on the
same path, and `m_cost >= 4 * p_cost` is checked so that Argon2 is never asked
for a lane layout it cannot serve.

The `t_cost` ceiling is the part that is easy to leave out. `m_cost` bounds the
allocation; nothing else bounds the number of passes over it, so a file naming a
huge `t_cost` ties up whoever opens it while holding a perfectly ordinary 64 MiB.
Section 5.7 covers the consequence and states what is still not bounded.

Mitigated by `SPEC.md` section 7.2.

### 2.10 Parser panics

`mili-core` is `#![forbid(unsafe_code)]`. Every parse is length checked and
fallible. No library path contains `unwrap`, `expect` or an explicit panic, and
no arithmetic in the library can wrap, because `clippy::arithmetic_side_effects`
is denied over the library and every operation states how it behaves when it
overflows. Panic freedom is checked by `cargo-fuzz` targets on every parser, by
`cargo +nightly miri test`, and by the unit and property suites.

The lint and the fuzzer are not redundant, and the reason is worth recording. The
`open_backup` fuzz target found a wrapping addition in a length check,
`HEADER_SIZE + entries_len + TAG_SIZE`, that the unit tests, the property tests
and the exhaustive byte sweeps all missed. Every one of those generates lengths
near a real file's length; none of them generates a length near `usize::MAX`,
which is the only value that makes the sum wrap. The fix is
`format::exact_length`, the regression is a committed corpus entry that CI
replays, and the lint is what stops the next one from needing a fuzzer.

Fuzzing is not a proof, and a finite campaign is not a campaign. What the targets
establish is narrower: they found one defect in roughly the time it took to write
them, and the corpus makes that one finding permanent rather than leaving it in
someone's terminal. See `../fuzz/README.md` for what each target asserts and for the
throughput cost of fuzzing a format whose cost parameters come from the file.

Mitigated by the code structure, the lint, the fuzz corpus and the test suite.

### 2.11 Secret material left in memory after use

Secret byte arrays implement `Drop` and zeroize. `Debug` and `Display` are
redacted. Comparison of secret values is constant time. Upstream crate secret
types are enabled with their `zeroize` features. Mitigated in part by
`zeroize` semantics.

Residual: the `Hkdf` object returned by `hkdf` 0.13 holds an internal copy of
the pseudorandom key and does not implement `Zeroize`, so that copy is released
to the allocator without being overwritten. The same applies to buffers the
caller allocates. mili does not attempt to control the caller's memory. See
section 4.1.

### 2.12 Error messages as an oracle

Every authentication, agreement and cryptographic parse failure returns
`Error::Failed`, whose `Display` is the fixed string `mili: operation failed` and
whose `Error::source` is `None`. A wrong signature half is not distinguished
from a wrong message. A wrong key is not distinguished from a corrupt file.
There is no public accessor that reveals the failing check. Mitigated by
`error.rs`.

## 3. Partially mitigated

### 3.1 Password guessing

Argon2id at 64 MiB and 3 passes raises the cost of a guess by roughly the cost
of three passes over 64 MiB. This raises cost against parallel hardware. It does
not prevent offline guessing of a weak password against a stolen key file: a
stolen file is all the adversary needs, and no parameter choice makes a weak
password safe. Mitigated against opportunistic and moderately resourced
attackers. Not mitigated against a well-resourced offline attack on a weak
password.

### 3.2 Plaintext exposure during streaming decryption

`stream::StreamReader` releases chunk *i*'s plaintext before chunk *i+1* is
authenticated. If a later chunk fails, earlier plaintext has already been handed
to the caller. `stream::open_buffered` exists for callers who can bound the
message size, and returns plaintext only after the final chunk authenticates, so
it has no partial exposure at all. For messages too large to buffer, the exposure
exists and the caller must discard on error. Same as age and rage. Partially
mitigated by providing a bounded buffered path with no default bound, so the
caller makes the size decision; mitigated by caller discipline otherwise.

A note on the bound: `open_buffered` requires the caller to pass a maximum, and
mili has no default for it. A default would be a library-side policy decision
about acceptable message sizes, and a caller that gets it wrong by omission would
have no way to notice.

### 3.3 Cryptographic implementation correctness

Every primitive is a third-party crate, and mili implements none of them. The risk
in a wrapper is that it composes correct pieces wrongly, which is what a third
party audit of mili itself would look for and what nobody has done.

For the pieces, `chacha20poly1305` 0.11 has one NCC Group audit with no
significant findings. `x-wing` 0.1.0, `ml-kem` 0.3.2, `ml-dsa` 0.1.1,
`ed25519-dalek` 3.0.0, `x25519-dalek` 3.0.0 and `argon2` 0.6.0 carry no
third-party audit that mili found.

What mili has instead is its own reading of each crate, recorded in
`../supply-chain/audits.toml`. That is a weaker statement than an independent audit
and is not offered as one; `DISCLAIMER.md` section 3 says the same. Two notes are
partial, `libc` and `curve25519-dalek`, and both state their stopping point as
something checkable: code mili cannot reach, rather than pages nobody got to.

Known incidents recorded in this repository:

- CVE-2026-24850, `ml-dsa` before 0.1.0-rc.4, accepted signatures with repeated
  hint indices. Fixed at 0.1.0-rc.4; mili pins 0.1.1.
- RUSTSEC-2026-0077, `libcrux-ml-dsa` before 0.0.8, incorrect signer-response
  norm check during verification. Not used.
- ePrint 2026/192 reports thirteen defects in libcrux and hpke-rs that escaped
  their verification, including two FIPS 204 verifier violations in ML-DSA, a
  wrong ML-KEM decompression constant, a missing inverse NTT, a cross-backend
  endianness bug, a missing mandatory X25519 validation and a nonce reuse caused
  by integer overflow.

None of these is in the pinned dependency set, except the first, which is fixed
in the pinned version. The general property, that a cryptographic
implementation can be wrong in a way that tests miss, is partially mitigated by
known answer tests against published vectors and is not eliminated.

### 3.4 Constant time behaviour

mili compares secret values with `subtle` and never branches on secret data in
its own code. The primitives are constant time only where their authors say so.
The `chacha20poly1305` documentation states that its software implementations
are constant time only on processors without variable-time multiplication.
Partially mitigated by upstream claims, not by mili.

### 3.5 Signature forgery

Ed25519 and ML-DSA-65 are both unforgeable under their stated assumptions; a
signature valid only if both verify is at least as strong as either. Both
algorithms are assumed secure; neither has been shown otherwise. Partially
mitigated by construction.

### 3.6 Signature determinism

ML-DSA signing in mili is deterministic, so two signatures by the same key over
the same message are byte identical. An observer who holds a verifying key can
link them. This is not prevented and not claimed to be prevented. The Ed25519
half is also deterministic, as Ed25519 is by construction, so the composite
signature is deterministic throughout.

Making the ML-DSA half randomised requires the `hazmat` feature of `ml-dsa`,
which the pinned version does not expose through its ordinary API. FIPS 204
approves the deterministic algorithm and the composite draft does not require
randomised signing, so the construction is conformant. Partially mitigated: the
linkability is documented rather than removed.

### 3.7 Replay of a whole file

A file decrypted successfully can be presented again and will decrypt again.
mili has no anti-replay state and no freshness field. A timestamp or counter
would require a trusted source that mili does not assume. Not mitigated.

## 4. Known gaps that are recorded but not addressed

### 4.1 Residual in-memory copies

Copies of key material can exist in memory outside mili's control: the
caller's buffers, the `Hkdf` object, upstream crate internals, allocator
retained copies after free, and swap. mili zeroizes what it allocates and
nothing else.

### 4.2 Stack depth and side channels in mili's own control flow

mili's branches depend on public data only: field lengths, magic bytes, version
bytes and chunk indices. No branch in mili depends on secret data. This is
asserted by inspection, not by tool.

### 4.3 Streaming output as a length and timing channel

A stream reveals its plaintext length to within 65536 bytes. mili does not pad.
See section 5.4.

## 5. Out of scope

### 5.1 Compromised host

Memory scraping, keyloggers, rootkits, a debugger attached to the process, a
malicious allocator, core dumps containing key material, or a hypervisor
reading guest memory. A key that has been in the process memory of a compromised
host is read. No design of the key handling within mili changes this.

### 5.2 Coercion

The rubber-hose attack: an adversary who can compel the key holder to disclose
the key. mili contains no plausible deniability and does not attempt any.

### 5.3 Traffic analysis resistance

mili provides no padding, no cover traffic, no fixed-size output and no timing
equalisation. An observer learns file sizes, chunk counts, creation times and
which files share a salt prefix. A stream written twice with the same plaintext
produces different ciphertext, so there is no equality leakage between
encryptions of the same plaintext.

### 5.4 Length hiding

The plaintext length of a sealed box is exact. The plaintext length of a stream
is exact to within 65536 bytes. An empty plaintext is distinguishable from a
short one. mili does not pad and does not claim to.

### 5.5 Hardware side channels beyond upstream handling

Cache timing, power analysis, electromagnetic emission, fault injection and
speculative execution attacks against the host CPU. mili relies on the upstream
crates' constant time implementations and does not add countermeasures.

### 5.6 Formal verification

mili is not formally verified. The primitives are not formally verified either,
except where an upstream project claims so, and section 3.3 records why those
claims need their own scrutiny. The evidence for mili is known answer tests,
property tests, fuzzing and miri.

### 5.7 Availability

mili does not attempt to prevent denial of service by a caller that supplies a
file large enough to exhaust memory. `open_buffered` has an explicit bound. A
streaming reader over a hostile but well formed file will read as far as the
file allows.

A password wrapped key file and a backup container are different, because their
cost parameters are attacker-chosen *before* anything is decrypted. `SPEC.md`
section 7.2 bounds `m_cost` at 1 GiB, `t_cost` at 8 and `p_cost` at 16, and
requires `m_cost >= 4 * p_cost`. All of these are checked before the working
memory is reserved, so opening a hostile file costs a constant amount of work
rather than whatever the file asks for.

The `t_cost` bound is the one that matters most and is the one mili got wrong
first: with only a floor, a file naming two billion passes holds a 64 MiB
allocation and then reads it two billion times, which is a denial of service
against whoever opens the file and which `m_cost`'s ceiling does not catch. The
ceiling is a property of mili, not of Argon2, and it is in the format
specification rather than only in the code so that an implementation that copies
the layout copies the bound.

What mili does not do is rate limit opens. A caller that opens a hundred
hostile files in a loop pays for a hundred bounded derivations. Bounding each
derivation is not bounding the number of them.

### 5.8 The C ABI

`mili-ffi` is the only crate here with `unsafe` code. Its rules are in `SPEC.md`
section 18.1 and its exposure is bounded rather than closed:

- The boundary cannot check that a non-null pointer covers the length the caller
  claims. It refuses null and trusts the rest. A caller who lies about a length gets
  undefined behaviour, as with any C interface.
- The boundary does not stream. A reader or writer crossing it would be a second
  unsafe surface with no format benefit, so a program with a file larger than memory
  writes chunks through the buffer interface instead.
- The boundary does not clear the caller's memory.
- A caught panic becomes `MILI_INTERNAL`. mili-core claims no panic is reachable;
  the boundary assumes that claim could be wrong, and both hold independently.

The Go binding adds no policy of its own and no place where a caller can choose a
weaker option, because it has no options. Its types are named so that the one
mistake a length could cause, using a symmetric key as a sealing seed, is a compile
error rather than a runtime surprise.

What the binding does add is the ordinary risk of a second language: Go's garbage
collector copies key slices, a `String` conversion or a logging library may capture
them, and nothing zeroes them. See `DISCLAIMER.md`.

### 5.9 Key distribution

mili does not authenticate public keys. Key authenticity is the caller's
problem: a binding document, a fingerprint compared over another channel, or a
certificate. An adversary who substitutes the verifying key can substitute
signatures, and mili will verify them.

### 5.10 Multiple recipients

mili-v1 seals to exactly one recipient. There is no recipient list, no
multi-recipient header and no format for it.

## 6. Assets and adversaries

| Asset | Exposure if lost |
|-------|------------------|
| sealing key seed | all files sealed to that key are readable by the holder of the seed |
| signing key seed | the holder can produce signatures that mili accepts as that identity |
| password | all key files wrapped with it are recoverable, at the cost in section 3.1 |
| plaintext | confidentiality is lost for that message only |
| key file | the key is lost unless a backup container exists |

The adversary model is uniform: the same adversary is assumed for every entry in
the table above. mili does not assume different adversaries for different
operations.
