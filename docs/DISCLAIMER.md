# mili — Disclaimer

This file states what mili does not do. It is written to be read before the
code, not after an incident.

## 1. What mili is

mili is parameter selection and a thin wrapper around third-party Rust
cryptography crates. It composes algorithms that other people implemented,
audited and published. mili implements no cipher, hash, key encapsulation
mechanism, signature scheme, random number generator or key derivation function.

## 2. What mili is not

mili does not implement cryptography. mili does not produce new algorithms, new
constructions or new analyses.

## 3. Third-party components

The primitives mili composes come from outside this repository.

**No third party has audited mili, and this repository is not an audit of the
crates below.** What an audit of mili itself would cover is written down in
`AUDIT_SCOPE.md`, which is a scope and not a result. What mili has done for the
crates is read each crate's source itself and record
what was read, in `../supply-chain/audits.toml`. Every crate on a production edge has
one of those notes. That is not the same as an independent audit and it should not
be quoted as one: nobody outside this repository looked, and the two largest notes
say in their own text that they are partial.

| Component | Third-party audit | Read by mili |
|-----------|-------------------|--------------|
| `chacha20poly1305` | one NCC Group audit, no significant findings | yes |
| `x-wing`, `ml-kem`, `ml-dsa` | none found | yes |
| `x25519-dalek`, `ed25519-dalek`, `ed25519` | none found | yes |
| `argon2`, `blake2`, `hkdf`, `sha2`, `hmac` | none found | yes |
| `curve25519-dalek` | none found | **partly** |
| `libc` | none found | **partly** |

The two partial ones are `curve25519-dalek` and `libc`. Both state their
stopping point as unreachability rather than as unread pages, and
`../supply-chain/README.md` is where that argument is made in full, together
with the line counts that do and do not mislead. What belongs here is only the
conclusion: two of the tree's largest crates have been read in the part mili
reaches and not in the part it cannot.

Two algorithms in mili's suite are specified in internet-drafts, not RFCs:
X-Wing (`draft-connolly-cfrg-xwing-kem`) and the composite signature
construction (`draft-ietf-lamps-pq-composite-sigs`). Both may change. mili
freezes the semantics it implements under a format version byte.

See `THREAT_MODEL.md` section 3.3 for the defects that have been published
against the pinned versions and their neighbours.

## 4. Out of scope

### Compromised host

If the machine running mili is under the control of an adversary — malware, a
keylogger, a rootkit, an attached debugger, a hostile allocator, a core dump
containing key material, or a hypervisor reading guest memory — then key
material in that process memory is read. mili zeroizes the buffers it allocates
and cannot protect memory from an adversary who owns the machine.

### Coercion

mili does not provide plausible deniability. If an adversary can compel the key
holder to produce the key, the adversary gets the key. The rubber-hose attack is
not addressed.

### Traffic analysis

mili does not hide traffic patterns. An observer learns file sizes, chunk
counts, timing and which files resemble each other in size. There is no cover
traffic, no padding and no fixed-size output.

### Length hiding

Plaintext lengths are exact for a sealed box and exact to within 65536 bytes for
a stream. mili does not pad and does not claim to.

### Hardware side channels

Cache timing, power analysis, electromagnetic emissions, fault injection and
speculative execution attacks against the host processor are out of scope.
mili relies on the constant time behaviour that upstream crates claim and adds
no countermeasures of its own.

### Formal verification

mili is not formally verified. The primitives are not either, apart from
specific upstream claims whose limits are recorded in `THREAT_MODEL.md`
section 3.3. The evidence offered for mili is known answer tests against
published vectors, property tests, fuzzing and miri.

### Key authenticity

mili does not authenticate public keys. An adversary who substitutes a
verifying key can substitute signatures and mili will accept them. Binding a key
to an identity is the caller's responsibility.

### Availability

mili does not defend against a caller supplying enough input to exhaust memory
or CPU time. Bounded operations have explicit bounds; unbounded ones are named
as unbounded.

### Language bindings

The Go binding in `bindings/go` is a layer over the C ABI and adds no policy of its
own. What it does add is Go's memory model. mili zeroizes the buffers it allocates
inside Rust; a key that has crossed into a Go slice will be copied by the garbage
collector, may be captured by a `String` conversion or a structured logging call, and
will not be zeroed. Zeroing a Go slice is the caller's to arrange, with whatever
means the caller's own threat model implies, and Go's runtime does not promise that
a slice stays put if it does.

The binding also cannot check a caller's own bounds at the C level. It refuses a
null pointer and trusts every other length, as `SPEC.md` section 18.4 records.

## 5. Words mili does not use

mili is not described as secure, unbreakable, military grade, bank grade or
quantum proof. mili does not make claims about the cryptographic strength of
any algorithm beyond the published properties of the standards those algorithms
come from, and it does not predict the cryptanalytic future.

Post-quantum is used only in the sense that ML-KEM-768 and ML-DSA-65 are
algorithms designed to resist analysis by a quantum computer. Whether they will,
and against what, is not something this repository can claim.

## 6. Operational notes

- Losing a key file means losing the key unless a backup container exists.
  mili cannot detect this; every failure returns the same error.
- Password strength dominates the Argon2 parameters. A weak password is
  recoverable from a stolen key file regardless of the cost settings.
- mili's errors are deliberately uniform. A `mili: operation failed` from any
  operation is the expected result of a wrong key, a wrong password, a corrupt
  file and a truncated file alike. Do not treat it as a diagnostic.
- Streaming decryption releases plaintext before the whole message is
  authenticated. Read `THREAT_MODEL.md` section 3.2 before using `StreamReader`
  on anything where a partial result would be acted on.
- A key at rest belongs in a key file or a backup container. A key handed to
  `ToBytes`, `to_bytes` or a Go `SealingKey` is in ordinary memory that nothing
  zeroizes once it has crossed the boundary.
- mili has no public operation that consumes a symmetric key. No format in
  `SPEC.md` takes one. A `SymmetricKey` can be generated, stored in a backup and
  read back, and there is currently nothing in this library to use it with.
  `SPEC.md` section 12.0 records that as a decision, including why it was not
  resolved by adding a symmetric key format or by removing the type.
