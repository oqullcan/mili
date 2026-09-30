# mili — Format Specification

Version 0.1.0. This document describes mili-v1 wire formats, the key hierarchy,
and the key schedules. It is normative: the implementation follows this document,
and changes here require a format version bump.

No section of this document makes a claim about security beyond the specific
properties that are named. See `THREAT_MODEL.md` for the property list and
`DISCLAIMER.md` for what mili does not address.

## 1. Conventions

- All integers are unsigned and big-endian unless stated otherwise.
- All offsets are in bytes.
- All cryptographic primitives are selected. There is no algorithm negotiation,
  no runtime option and no environment variable that changes cryptographic
  behaviour. One suite exists per format version.
- Every length in a format is fixed by the format version. No field is
  variable-length, so no length prefix is required.
- Byte strings written here as `hash` are hexadecimal lowercase.

## 2. Shared header

Every mili file begins with this header. The header is authenticated: it is bound
into the AEAD associated data of every ciphertext that follows it.

```
ofs  len  field
0    4    magic          6D 69 6C 69  ("mili")
4    1    format_type    see section 3
5    1    version        0x01 for mili-v1
6    32   salt           uniform random per file, from the OS CSPRNG
```

Total header size: 38 bytes.

`salt` is 32 uniform random bytes drawn from the operating system CSPRNG for
every file. It is the only field that carries entropy chosen by the writer, and
it is what makes the derived payload key unique per file. See section 9.

A file whose `magic` does not match is rejected. A file whose `format_type` does
not match the operation being attempted is rejected. A file whose `version` is
not `0x01` is rejected with `Error::UnsupportedVersion`. There is no downgrade
path and no fallback parser.

## 3. Format types

| Value | Name | Section |
|-------|------|---------|
| `0x01` | sealed box, single shot | 4 |
| `0x02` | streaming file | 5 |
| `0x03` | composite signature | 6 |
| `0x10` | password-wrapped key file | 7 |
| `0x11` | backup container | 8 |

## 4. Sealed box (`format_type = 0x01`)

Encrypts one in-memory buffer to one recipient public key. Anonymous with respect
to the recipient: the header contains no recipient identifier and no key
identifier. See section 10.

```
ofs  len  field
0    4    magic
4    1    format_type = 0x01
5    1    version = 0x01
6    32   salt
38   1120 kem_ct          X-Wing ciphertext, section 9
1158 n    ciphertext      ChaCha20-Poly1305 output: n plaintext bytes then a
                          16 byte Poly1305 tag
```

Total overhead: 1174 bytes plus the plaintext.

### 4.1 Key schedule

```
ss       = X-Wing-Decapsulate(sealing_key, kem_ct)          32 bytes
seal_key = HKDF-SHA256(ikm = ss, salt = salt,
                       info = "mili-v1:seal")                32 bytes
aad      = header[0..1158]
ciphertext = ChaCha20Poly1305-Encrypt(key = seal_key, nonce = 00 * 12,
                                      aad = aad, plaintext)
```

The AEAD nonce is twelve zero bytes and is never transmitted. Nonce uniqueness
does not depend on the writer keeping state: `seal_key` is a HKDF-Expand of a
32 byte uniform random `salt`, so two files that share an AEAD key must also
share a `salt`.

### 4.2 Seal

```
1. salt                   = random(32)
2. kem_ct, ss             = ek.encapsulate()
3. seal_key               = HKDF-SHA256(ss, salt, "mili-v1:seal")
4. header                 = magic || 0x01 || 0x01 || salt || kem_ct
5. ciphertext             = ChaCha20Poly1305-Encrypt(seal_key, 00*12, header)
```

`ek` is the recipient's [`EncapsulationKey`]. The sender needs no private key of
its own.

### 4.3 Open

```
1. Reject if the buffer is shorter than 1174 bytes.
2. Reject unless magic == "mili" and format_type == 0x01, with Error::Failed.
3. Reject with Error::UnsupportedVersion unless version == 0x01.
4. For each candidate key, in order:
     ss        = X-Wing-Decapsulate(sk, kem_ct)     never fails, section 9
     seal_key  = HKDF-SHA256(ss, salt, "mili-v1:seal")
     plaintext = ChaCha20Poly1305-Decrypt(seal_key, 00*12, header)
     return plaintext on the first success
5. Return Error::Failed.
```

Steps 1, 2, 5 and a wrong key in step 4 all produce `Error::Failed` with no
distinguishing detail. Only step 3 is reported differently, and the version byte
it reads is in cleartext.

## 5. Streaming file (`format_type = 0x02`)

Same header, then a chunk sequence. Chunk size is 65536 bytes of plaintext.

```
ofs  len  field
0    4    magic
4    1    format_type = 0x02
5    1    version = 0x01
6    32   salt
38   1120 kem_ct
1158 n    chunk_0 || chunk_1 || ... || chunk_last
```

### 5.1 Chunk layout

```
len          field
0..65552     ciphertext    ChaCha20-Poly1305 output for the chunk plaintext
65552..65568 tag           16 byte Poly1305 tag
```

Every chunk is exactly 65552 bytes except the last, which is `plaintext_len + 16`
bytes for a `plaintext_len` between 0 and 65536 inclusive.

### 5.2 Key schedule

```
file_key = HKDF-SHA256(ikm = ss, salt = salt, info = "mili-v1:stream")  32 bytes
```

The file key is constant across the chunks of one file. Uniqueness across files
comes from `salt`, as in section 4.1. Each chunk uses a distinct nonce:

```
counter     11 bytes, big endian, starts at all zero, incremented after each chunk
final_flag  1 byte, 0x00 for a non-final chunk, 0x01 for the final chunk
nonce_i     counter || final_flag                    12 bytes
aad_i       header[0..1158] || counter || final_flag
```

The counter is never transmitted and never wraps: reaching `2^88` chunks is an
`Error::Internal`, not a wrap-around. Byte 11 of the nonce is the flag and is
never incremented.

### 5.3 What the reader enforces

- The chunk counter must advance by exactly one per chunk. A chunk presented out
  of order fails to authenticate because its nonce is derived from the index the
  reader expects.
- A chunk that is not the last chunk must be exactly 65552 bytes. A short read is
  `Error::Failed`.
- The final chunk must carry `final_flag = 0x01`. A stream that ends without a
  final chunk is truncated and yields `Error::Failed`.
- After the final chunk, the reader must observe end of input. Trailing bytes
  after the final chunk yield `Error::Failed`.
- A zero-length plaintext produces exactly one chunk of 16 bytes.

### 5.4 Plaintext exposure before full authentication

A streaming reader releases the plaintext of chunk *i* once chunk *i* is
authenticated, before chunk *i+1* is read. If a later chunk fails, the plaintext
of earlier chunks has already been delivered to the caller.

This is inherent to the streaming construction and is the same behaviour as age
and rage. mili exposes two readers:

- `StreamReader`, which implements `Read` and releases plaintext incrementally.
  The caller contract is: on any error, discard everything received so far.
- `open_buffered`, which reads the whole stream into a `Vec` with an explicit
  upper bound and returns plaintext only after the final chunk authenticates.

`open_buffered` is the correct default for correctness-critical callers who can
bound the size. `StreamReader` is for files too large to hold in memory, where
the caller must own the discard contract.

## 6. Composite signature (`format_type = 0x03`)

This is the construction of `draft-ietf-lamps-pq-composite-sigs`, parameter
MLDSA65-Ed25519-SHA512. That document is an IETF internet-draft, not an RFC.

```
ofs  len  field
0    4    magic
4    1    format_type = 0x03
5    1    version = 0x01
6    3309 mldsa65_sig
3370 64   ed25519_sig
3434 total
```

### 6.1 Key sizes

| Object | Size | Content |
|--------|------|---------|
| signing key | 64 | ML-DSA-65 seed (32) \|\| Ed25519 seed (32) |
| verifying key | 1984 | ML-DSA-65 public key (1952) \|\| Ed25519 public key (32) |
| signature | 3373 | ML-DSA-65 signature (3309) \|\| Ed25519 signature (64) |

### 6.2 Transcript

```
prehash = SHA-512(message)
m_prime = "CompositeAlgorithmSignatures2025"        32 bytes
        || "COMPSIG-MLDSA65-Ed25519-SHA512"          30 bytes
        || 0x00                                      len(ctx), ctx is empty
        || prehash
```

`m_prime` is 127 bytes. The draft gives the prefix as the hex string
`436F6D706F73697465416C676F726974686D5369676E61747572657332303235`, which is 32
bytes; the label is 30 bytes. Both are asserted in the unit tests, so a
transcription error cannot survive.

### 6.3 Sign and verify

```
mldsa_sig  = ML-DSA-65.Sign(m_prime, mldsa_ctx = "COMPSIG-MLDSA65-Ed25519-SHA512")
ed_sig     = Ed25519.Sign(m_prime)
signature  = mldsa_sig || ed_sig
```

Verification, as section 3.2 step 4 of the draft states it:

```
valid = ML-DSA-65.Verify(mldsa_pk, m_prime, mldsa_sig, mldsa_ctx = Label)
     && Ed25519.Verify(ed25519_pk, m_prime, ed_sig)
```

A signature is valid only if both halves verify. There is no partial or
alternative acceptance path. If either half fails, the result is `Error::Failed`
with no indication of which half failed.

The draft permits failing early on the first component, on the grounds that no
private key is involved in verification and so there is nothing to learn from
timing. mili returns as soon as a half fails, which is the same choice.

The composite label is passed into ML-DSA as its context string. That is the
draft's own requirement, and it is what binds the ML-DSA half to this composite
algorithm rather than to a bare ML-DSA signature.

Signatures cover a single in-memory buffer. There is no streaming signature in
mili-v1.

### 6.4 ML-DSA signing is deterministic

`ml-dsa` 0.1.1 exposes only the deterministic variant of ML-DSA signing outside
its `hazmat` feature: the randomness parameter is fixed at zero, so signing the
same message with the same key always produces byte-identical output.

Consequences, both of which are real:

- Two signatures by the same key over the same message are identical. An
  observer holding a verifying key can therefore link them. This is the same
  linkability an observer gets from deterministic encryption, and mili does not
  claim to prevent it.
- There is no hedged randomisation, so the extra fault-attack resistance that
  randomised ML-DSA signing provides is not available.

FIPS 204 approves the deterministic algorithm, and the composite draft does not
require randomised signing, so the construction is conformant. It is recorded in
`THREAT_MODEL.md` as a partial mitigation rather than a solved problem. Making
mili's signatures randomised would need the `hazmat` feature of `ml-dsa` and a
signing path that is not exposed without it.

One consequence for testing: the draft's Appendix E vectors pin *verification*,
not signature bytes. The reference implementation that produced them used
randomised ML-DSA signing, so mili's signature over the draft's key and message
verifies under the draft's public key but is not byte identical to the published
one. The test asserts both facts.

## 7. Password-wrapped key file (`format_type = 0x10`)

```
ofs  len  field
0    4    magic
4    1    format_type = 0x10
5    1    version = 0x01
6    1    kdf_id = 0x01               Argon2id
7    1    params_id = 0x01           the fixed profile of section 7.1
8    4    m_cost                     KiB, big endian
12   4    t_cost                     passes, big endian
16   4    p_cost                     lanes, big endian
20   16   argon2_salt
36   1    payload_type               0x01 sealing, 0x02 signing, 0x03 symmetric
37   4    payload_len                big endian
41   n    ciphertext                 ChaCha20-Poly1305 output: payload_len bytes
                                      then a 16 byte tag
```

```
kek       = Argon2id(password, argon2_salt, m_cost, t_cost, p_cost)    32 bytes
wrap_key  = HKDF-SHA256(ikm = kek, salt = argon2_salt,
                        info = "mili-v1:keywrap")                       32 bytes
aad       = header[0..41]
ciphertext = ChaCha20Poly1305-Encrypt(wrap_key, 00*12, aad, payload)
```

The AEAD nonce is twelve zero bytes. `wrap_key` depends on `argon2_salt`, which
is fresh per file.

### 7.1 Argon2id profile

mili writes one profile and no other:

```
algorithm  Argon2id
version    0x13
m_cost     65536      64 MiB
t_cost     3
p_cost     4
salt       128 bit
output     256 bit
```

This is the second recommended option of RFC 9106 section 4, with `m_cost`,
`t_cost` and `p_cost` written into the file so that a future profile increase
does not make existing files unreadable.

`p_cost` is Argon2's lane count. It is not a count of operating system threads
and does not cause thread creation. The derivation is single threaded and
reproducible on any platform.

### 7.2 Parameter checks on open

Applied before Argon2 runs:

- `kdf_id` must be `0x01`, `params_id` must be `0x01`. Any other value is
  rejected. There is no algorithm negotiation.
- `m_cost >= 32768`. A file claiming less memory than the floor is a
  parameter-downgrade attempt.
- `t_cost >= 2`. Same reason.
- `p_cost >= 1`.
- `m_cost <= 1048576` (1 GiB). A larger value is rejected before any allocation,
  so a hostile file cannot force unbounded memory use.

The upper bound is a property of mili, not of Argon2. It is checked before the
derivation so that a file claiming 256 GiB costs nothing to reject.

### 7.3 Loss of a key

Losing a key file is not detectable by mili: every failure mode returns
`Error::Failed`. Recovery is by restoring the file or the backup container of
section 8. The backup container is the only mechanism mili provides for this,
and it is not optional in the sense that it is the designed path: a key whose
only copy is one file has no recovery path.

## 8. Backup container (`format_type = 0x11`)

Wraps several key files under one password.

```
ofs  len  field
0    4    magic
4    1    format_type = 0x11
5    1    version = 0x01
6    1    kdf_id = 0x01
7    1    params_id = 0x01
8    4    m_cost
12   4    t_cost
16   4    p_cost
20   16   argon2_salt
36   4    entry_count
40   8    entries_len                  total length of the entry region
48   n    entries                      entry_count repetitions of:
                                        u16 key_id_len
                                        key_id_len key_id
                                        u32 entry_len
                                        entry_len the bytes of the key file of
                                          section 7 starting at ofs 0
```

The entry region is encrypted with the same key schedule and AEAD as section 7,
with `aad = header[0..48]`.

A backup container is identified by its Argon2 profile and salt, so restoring a
container re-derives the same wrapping key on any platform. `key_id` is the
value of section 11, used only to detect a wrong backup, not to select a key.

## 9. KEM

X-Wing, as specified in `draft-connolly-cfrg-xwing-kem`, built on X25519 and
ML-KEM-768. That document is an IETF CFRG internet-draft, not an RFC.

```
sealing key       32    bytes   seed
encapsulation key 1216  bytes   ML-KEM-768 public key (1184) || X25519 public key (32)
KEM ciphertext    1120  bytes  ML-KEM-768 ciphertext (1088) || X25519 ephemeral (32)
shared secret     32    bytes   SHA3-256 combiner output
```

`ml-kem` 0.3.2 (FIPS 203 final) and `x25519-dalek` 3.0.0 (RFC 7748) supply the
components.

Decapsulation never fails: X-Wing uses implicit rejection, so a malformed
ciphertext produces a shared secret that is not the sender's, and the AEAD step
rejects it. The KEM layer is therefore not an oracle by itself, and there is no
distinct error for it.

X-Wing is not an authenticated KEM. Sender authentication comes from the
signature scheme of section 6, never from the KEM.

## 10. Recipient and key identifiers

mili-v1 writes no recipient identifier and no key identifier into any format.
This is a deliberate deviation from age, which names each recipient in a
cleartext stanza, and from COSE, which carries a `kid`.

`open` takes an iterator of candidate keys and attempts them in order. The
number of attempts is observable, so the *size* of a recipient's key set leaks.
The identity behind a file does not.

An encrypted key identifier does not help: selecting a key requires an attempt,
and a failed attempt gives nothing to read. Putting the identifier in the
plaintext gives an observer exactly the link the rule forbids.

File size and timing correlations are out of scope. See `THREAT_MODEL.md`.

## 11. Key identifiers

```
key_id = HKDF-SHA256(ikm = public_key_bytes, salt = empty,
                     info = "mili-v1:keyid")[0..16]
```

16 bytes. `key_id` is a fingerprint used to detect a wrong key or a wrong backup
after the fact. It is never written into a sealed box or a stream file. It is
only stored inside a backup container, where the container is already
password-protected.

## 12. Key hierarchy

```
sealing_key              32 bytes   X-Wing seed
signing_key              64 bytes   ML-DSA-65 seed (32) || Ed25519 seed (32)
symmetric_key            32 bytes   direct
```

The signing key is the composite private key exactly as
`draft-ietf-lamps-pq-composite-sigs` defines it: the two component seeds
concatenated, ML-DSA-65 first. It is not derived from a shorter master seed.

An earlier draft of this document specified a 32 byte signing master seed
expanded with HKDF into the two component seeds. That is withdrawn. The
composite draft defines its own private key encoding, and adopting the draft for
the signature construction while using a different private key encoding would
break the only interoperability the adoption buys: a key that no other
implementation of the same construction can reconstruct. It would also mean
inventing a key schedule, which the mili rules do not allow. The two
`mili-v1:seed-*` labels are therefore removed from the closed `Domain` set.

### 12.1 Rotation

Rotation produces a new seed and re-wraps. It does not migrate existing files.

- Key file rotation: open with the old password, generate a new `argon2_salt`,
  write the same payload under the same parameters.
- Seed rotation: generate a new seed, write a new key file, keep the old file
  until every file encrypted under the old public key has been re-encrypted.
  Re-encryption of a stream is decrypt-then-encrypt; there is no transform that
  re-seals without the plaintext.

## 13. Comparison with age v1

Both use STREAM with 64 KiB chunks and the same nonce structure.

| Property | age v1 | mili-v1 |
|----------|--------|---------|
| Chunk size | 64 KiB | 64 KiB |
| Chunk nonce | `counter_be(88) \|\| flag` | same |
| Chunk key | fixed payload key | fixed file key |
| Associated data | none | `header \|\| counter \|\| flag` |
| Header integrity | separate MAC key | header is the AEAD AAD of every chunk |
| Payload key derivation | `HKDF(file_key, salt = header_nonce, info = "payload")` from a 16 byte file key | `HKDF(ss, salt = salt, info = "mili-v1:stream")`, file key is the 32 byte KEM output |
| Recipients | named in cleartext stanzas | none |
| Algorithms | X25519 + ChaCha20-Poly1305, scrypt | X-Wing + ChaCha20-Poly1305, Argon2id |

mili uses associated data where age uses none so that a modified counter or a
flipped final flag is an explicit associated-data mismatch rather than a silent
decryption failure. The header is already bound into the file key through `salt`;
including it as associated data is redundant by construction and is done anyway
so that the binding is explicit in the format rather than implicit in the key
schedule.

## 14. Deliberate deviations from reference implementations

| Reference | What it does | What mili does | Reason |
|-----------|--------------|----------------|--------|
| dark-bio `xhpke` | RFC 9180 HPKE over X-Wing | HKDF-SHA256 with mili labels | X-Wing has no registered HPKE KEM codepoint, so the HPKE `suite_id` would be unregistered and the IANA uniqueness guarantee unavailable. HPKE's mode and export surface is unused here. |
| age `x25519` recipient stanzas | recipient named in cleartext | no recipient metadata | section 10 |
| LAMPS composite signatures | Ed25519 half signs `m_prime`, which contains `SHA-512(message)` | adopted unchanged | it is a defined construction with an assigned OID; mili does not implement PEM, DER or X.509, which are the parts that would need the OID |
| rage `age/src/primitives/stream.rs` | stream primitive is a verbatim MIT fork | mili writes its own reader and writer | the STREAM semantics and the truncation and reordering behaviour are reimplemented from the construction and age's documented behaviour. No code is copied. age is BSD-3-Clause, the age stream primitive inside rage is MIT (Jack Grigg). Both are attributed here. |

## 15. Test vector plan

| Source | Used for | Cases | Phase |
|--------|----------|-------|-------|
| RFC 5869 test cases 1 and 3 | HKDF-SHA256 primitive usage | 2 | 1 |
| Frozen mili-v1 domain separation vectors, generated with an independent implementation | `Domain` label binding | 7 | 1 |
| RFC 8439 Section 2.8.2 | ChaCha20-Poly1305 | 1 | 2 |
| C2SP Wycheproof `chacha20_poly1305_test.json` | ChaCha20-Poly1305 edge and negative cases | 316, of which 256 accepted and 60 rejected | 2 |
| `draft-connolly-cfrg-xwing-kem-11` Appendix C | X-Wing keygen, encapsulation and decapsulation | 3 | 2 |
| NIST ACVP vectors for ML-KEM-768 | ML-KEM agreement, if the X-Wing vectors prove insufficient | - | 2 |
| `draft-ietf-lamps-pq-composite-sigs-19` Appendix E | the whole composite signature construction, both components, empty and non empty context | 1 | 3 |
| RFC 9106 test vectors | Argon2id | - | 5 |
| proptest properties and exhaustive byte sweeps | mili formats | - | 2 to 5 |

Where a Wycheproof or ACVP file has no Rust-side runner, the vectors are
converted once into the JSON layout under `tests/vectors/` and the runner is
written against that file. The conversion step is committed and its source URL
and file name are recorded in the JSON.

## 16. Reproducible builds

A build is reproducible from the repository alone when the following hold:

- `rust-toolchain.toml` pins one exact stable channel. The CI workflow fails if
  the toolchain it built with does not match the pin, so the two cannot drift.
- `Cargo.lock` is committed and every cargo invocation uses `--locked`.
- Every dependency version is written as `=x.y.z` in `Cargo.toml`. Caret
  requirements are not used, so adding a dependency is always an explicit edit.
- No build script in the dependency tree reads the network, the clock or the
  environment to produce different output. `cargo deny` and the `Cargo.lock` diff
  in review are how this is checked.

mili does not claim bit-reproducible output across toolchain versions. A
different rustc version, a different `target-cpu` or a different linker will
produce a different binary. Reproducing an exact released binary requires the
same toolchain version and the same linker.

## 17. Release signing

Release signing is not performed by CI.

- The CI workflow has `permissions: contents: read` and references no secrets.
  No job can push a tag, create a release or write to the repository.
- Build provenance for a release is produced keyless with sigstore, which needs
  no stored key.
- A release tag is signed manually with an Ed25519 key that is generated offline,
  stored offline and never placed in a repository, a CI variable or an
  encrypted file in the repository. The public half is recorded in
  `SIGNING_KEYS.md` when one exists.
- If a release key is ever suspected of exposure, the release history is
  re-signed with a new key and the compromise is recorded in writing. There is
  no revocation shortcut, because there is no online key infrastructure to
  revoke against.

