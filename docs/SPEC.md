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

Every mili file begins with these six bytes. They are authenticated: they are
bound into the AEAD associated data of every ciphertext that follows them.

```
ofs  len  field
0    4    magic          6D 69 6C 69  ("mili")
4    1    format_type    see section 3
5    1    version        0x01 for mili-v1
```

Nothing is shared past byte six. The sealed box and the stream put a 32 byte salt
at offset 6, because they derive a payload key from a freshly generated key and
a salt. The password-wrapped key file and the backup container instead put the
identifier of their key derivation function, a parameter set identifier, three
Argon2id cost parameters and a 16 byte Argon2id salt there, because they have to
be readable before anything can be decrypted. The two layouts were originally
written as sharing a 32 byte salt at offset 6, which is not possible: both
layouts need offset 6 and only one of them can have it.

`SALT_SIZE`, `SALT_OFFSET` and `SALT_END` in the implementation refer to the
first of the two layouts and are used only by the sealed box and the stream. The
key file and the backup container define their own offsets, and the constants are
asserted at compile time so that moving a field is a build failure rather than a
file that an earlier build wrote and a later build cannot read.

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
0..65536     ciphertext    ChaCha20-Poly1305 output for the chunk plaintext
65536..65552 tag           16 byte Poly1305 tag
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

The counter is never transmitted and never wraps: the counter is a `u64`, so
reaching `2^64` chunks is an `Error::Failed`, not a wrap-around. Byte 11 of the nonce is the flag and is
never incremented.

### 5.3 Which flag a chunk carries

A non-final chunk is always exactly 65552 bytes. A final chunk is
`plaintext_len + 16` bytes, so a final chunk of a message whose length is an
exact multiple of 65536 is also exactly 65552 bytes and is indistinguishable
from a non-final chunk by length alone. The reader resolves this the way age
does:

- a short chunk is the final chunk, and is tried only with the flag set
- a full length chunk is tried as non-final, and on failure is retried as final

The same decision is made twice: once while selecting a key, since the header
alone does not authenticate and the first chunk is what selects a key, and once
per chunk while reading. The two must agree, and they do because both call the
same rule.

### 5.4 What the reader enforces

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

### 5.5 Plaintext exposure before full authentication

A streaming reader releases the plaintext of chunk *i* once chunk *i* is
authenticated, before chunk *i+1* is read. If a later chunk fails, the plaintext
of earlier chunks has already been delivered to the caller.

This is inherent to the streaming construction and is the same behaviour as age
and rage. mili exposes two readers:

- `stream::StreamReader`, which implements `Read` and releases plaintext
  incrementally. The caller contract is: on any error, discard everything
  received so far.
- `stream::open_buffered`, which reads the whole stream into a buffer with an
  upper bound the caller supplies, and returns plaintext only after the final
  chunk authenticates. It has no partial plaintext exposure at all.

`open_buffered` is the correct default for correctness-critical callers who can
bound the size. `StreamReader` is for files too large to hold in memory, where
the caller must own the discard contract.

`open_buffered`'s bound is mandatory and has no default. Any default would be a
policy decision about message size that the caller has not made, and a library
that guesses it is a library that can be made to allocate without limit.

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
- `t_cost <= 8`.
- `p_cost <= 16`.

Both floors and all three ceilings are properties of mili, not of Argon2. They
are checked before the derivation, so a file naming 256 GiB or two billion passes
costs nothing to reject.

The `t_cost` ceiling exists because `t_cost` multiplies the work of a derivation
and the value comes from the file being opened. Without it, a file naming
`t_cost = 2_000_000_000` is a denial of service delivered by the file itself,
against whoever opens it, and `m_cost`'s ceiling would not catch it: the memory
allocation is bounded while the number of passes over it is not.

The `p_cost` ceiling exists because `p_cost` is a caller-visible multiplier on
the number of Argon2 lanes, and the number of lanes changes how much work the
derivation does at the same `m_cost`. Writing the bound down rather than relying
on a derivation from the memory ceiling keeps the rejection explicit and cheap,
and keeps it a number in the format instead of a consequence of another one.

#### The fourth check, which is not a bound

`check_params` also compares `m_cost` against `4 * p_cost`, because Argon2 needs
at least that many blocks for its block layout. It is not one of the rules above,
and it is not reachable. Once the ranges have been applied `p_cost` is at most 16
and `m_cost` at least 32768, so `4 * p_cost` is at most 64 and the requirement is
already met by a factor of five hundred.

It is listed here rather than in the list above so that a reader implementing
this format does not conclude that a file has to be rejected for `4 * p_cost`.
`mili-core` keeps the comparison as a guard against a future that raises
`P_COST_CEILING` far enough for it to matter, and a test asserts the inequality
above, so raising the lane ceiling far enough to make the comparison live fails
that test rather than leaving the code and this document quietly disagreeing.

#### Why a floor is not enough

The floors alone are the usual choice, and they are not a defence on their own.
A parameter-downgrade attack does not have to go below the floor; it only has to
go to it. A reader that checks `m_cost >= 32768` and nothing else will happily
derive at 32 MiB when the file asks for it, and 32 MiB is a parameter the author
published as the floor precisely because it is the weakest value mili ever
writes. Both halves are needed, and both are needed because the parameters come
from the file being opened rather than from the writer.

Ente's account layer is a worked example of the floors-only version, which is why
this is written down rather than left implicit. Its password-derived
key-encryption key takes `mem_limit` and `ops_limit` from `SrpAttributes`, which
the server serves in the clear, and the only validation is a lower bound —
8 KiB of memory and one pass, the values that crate defines for inputs that are
already high entropy and explicitly never for passwords. A compromised or
malicious server therefore does not have to break Argon2; it sets the two
parameters a client will use for every subsequent login and the offline attack
against the stored encrypted key becomes trivial. Nothing about that is
exploitable through mili, because the ceilings are in the format rather than in
the configuration, but the shape of it is the argument for section 7.2 being
what it is.

### 7.3 Loss of a key

Losing a key file is not detectable by mili: every failure mode returns
`Error::Failed`. Recovery is by restoring the file or the backup container of
section 8. The backup container is the only mechanism mili provides for this,
and it is not optional in the sense that it is the designed path: a key whose
only copy is one file has no recovery path.

## 8. Backup container (`format_type = 0x11`)

Wraps several keys under one password.

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
                                        entry_len one key, as:
                                          u8 payload_type
                                          u32 payload_len
                                          payload_len key bytes
```

The entry region is encrypted with the same key schedule and AEAD as section 7,
with `aad = header[0..48]`. Argon2 runs once for the whole container, whatever
`entry_count` is.

A backup container is identified by its Argon2 profile and salt, so restoring a
container re-derives the same wrapping key on any platform. `key_id` is the
value of section 11, used to tell the entries apart and to detect a wrong backup,
not to select a key. `entry_count` entries with the same `key_id` are refused, so
a container never holds a key twice under one identifier. That rule is enforced on
read as well as on write: `Backup::from_keys` refuses a duplicate while building,
and `parse_entries` refuses one while reading, so a container produced by another
implementation of this format gets the same answer. A write-side-only rule would
mean the reader could hand back two entries under one identifier with no signal.

`Backup::info` reads the unauthenticated header and reports the Argon2 profile and
`entry_count` without a password. It exists so a tool can say "this is a mili
backup, N keys, Argon2id 64 MiB" and ask for a password, rather than paying for a
64 MiB derivation on a file that may not be a mili backup at all.

### 8.1 Why an entry is a key and not a key file

An entry holds key material with a type tag. It does not hold the bytes of a key
file of section 7.

An earlier draft of this section specified an entry as "the bytes of the key file
of section 7 starting at ofs 0". That cannot work, and the reason is worth
recording so that it is not reintroduced. A key file inside the container would
carry its own Argon2 salt and its own cost parameters, and would be wrapped under
its own password. Restoring the backup would then need the container's password
and every key file's password, and the container's password would buy nothing
that N key files did not already provide separately.

An entry is therefore the key itself. Restoring produces a `SealingKey`,
`SigningKey` or `SymmetricKey`, and putting one back into a key file is the
caller's next step, under whatever password the caller chooses. The container's
password protects the container; it is not the password of the key files that come
out of it.

`payload_type` and `payload_len` are the section 7 field names and the section 7
values: `0x01` for a 32 byte X-Wing seed, `0x02` for a 64 byte composite signing
seed, `0x03` for a 32 byte symmetric key. A `payload_len` that does not match its
`payload_type`, or a `payload_type` mili does not implement, is rejected.

### 8.2 Restoring is not the same as wrapping

`Backup::open` returns keys. It does not return key files, and it does not
decide a password for them. Section 12.1 describes seed rotation; recovering a key
from a backup is not rotation, because the key does not change.

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

`Backup::info` reports what a container claims without a password, and
`StoredKey::key_id` computes the other half of this workflow. Both are reachable
through the C ABI as `mili_backup_info` and `mili_key_id`, and through Go as
`Backup.Info` and `KeyID`. The second was added late: `mili_backup_open` returned
the identifiers but a caller had no way to compute the expected one for a key it
held, so the workflow this section describes was not implementable outside
`mili-core` at all.

## 12. Key hierarchy

```
sealing_key              32 bytes   X-Wing seed
signing_key              64 bytes   ML-DSA-65 seed (32) || Ed25519 seed (32)
symmetric_key            32 bytes   direct
```

Two of the three are consumed by a format: the sealing key by the sealed box and
the stream, the signing key by the composite signature. The symmetric key is not,
and that is a decision rather than an omission.

### 12.0 The symmetric key has no consumer

mili-v1 defines no format that takes a symmetric key. Every format derives its own
key from a seed or from a password: the sealed box and the stream from an X-Wing
shared secret, the key file and the backup container from Argon2id. There is
nothing left for a caller's 32 random bytes to be used *with*.

`SymmetricKey` therefore exists as a storage type. It can be generated, wrapped in
a key file, put in a backup container and read back, which is a coherent thing for
a key management library to do for a caller whose symmetric keys it otherwise does
not use. What it cannot do is encrypt anything here.

Three ways this could have gone, and why it went this way:

- **Add a symmetric key format.** A `mili-sym-v1` that takes a 32 byte key would
  make the type useful. It would also be the one format in mili with no
  authentication of its public key, no sender authentication, and a shared secret
  established by a caller-supplied value rather than a KEM. That is a different
  library with a different threat model, and `THREAT_MODEL.md` sections 5.8 and
  5.9 would have to be rewritten around it. If it is wanted, it is wanted as its
  own decision with its own analysis, not as a way to justify an existing type.

- **Remove the type.** Then a caller with a symmetric key has nowhere to put it in
  a mili backup, and would keep it somewhere else and with less care. The backup
  container's whole purpose is to be the answer to "where do I keep this", and a
  key it cannot hold is a key the caller will hold worse.

- **Ship it as a storage type.** This is what happened. The type is honest about
  what it is: its documentation, `DISCLAIMER.md` and this section all say the same
  thing, in those words, so a reader meets the same statement in three places
  rather than discovering the gap by trying to use it.

`SymmetricKey` is not `#[deprecated]`. It is a working storage type with no
consumer in this version, and a future format version may give it one.

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

`counter_be(88)` is age's name for the encoding: the counter occupies an 88 bit
field, of which mili uses 64 and leaves the top 24 bits zero. That matches age's
framing while the counter itself is a `u64`, so the real bound is `2^64` chunks
as section 5.2 says.
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
| NIST ACVP vectors for ML-KEM-768 | ML-KEM encapsulation, against NIST's own vectors | 25 | 6 |
| `draft-ietf-lamps-pq-composite-sigs-19` Appendix E | the whole composite signature construction, both components, empty and non empty context | 1 | 3 |
| RFC 9106 test vectors | Argon2id | - | 5 |
| proptest properties and exhaustive byte sweeps | mili formats | - | 2 to 5 |
| `cargo-fuzz` targets, one per parser | panic freedom and the format invariants each target states | - | 6 |

The Argon2id row is "-" because the RFC's own vectors turned out to be
unreachable through the API mili calls; `../tests/vectors/README.md` records why and
what is pinned in their place.

Where a Wycheproof or ACVP file has no Rust-side runner, the vectors are
converted once into the JSON layout under `tests/vectors/` and the runner is
written against that file. The conversion step is committed and its source URL
and file name are recorded in the JSON.

### 15.1 Why ML-KEM-768 has its own vector file

This file asked for ACVP vectors only "if the X-Wing vectors prove insufficient".
They are insufficient, and the reason is structural rather than a matter of how
many cases each has.

An X-Wing encapsulation key is an ML-KEM-768 encapsulation key followed by an
X25519 public key, and an X-Wing ciphertext is an ML-KEM-768 ciphertext followed
by an X25519 public key. The draft's three vectors therefore do exercise
ML-KEM-768 key generation, encapsulation and decapsulation, but only ever as a
function of an X-Wing seed. No ML-KEM-768 encapsulation key appears anywhere in
the draft file on its own, so nothing in it can be handed to `ml-kem`'s
encapsulation API, and NIST's question cannot be asked of NIST's vectors.

The ACVP file has what the draft file lacks: an encapsulation key as an input,
paired with the ciphertext and shared secret NIST expects from it. The two files
are therefore different tests, and `kem::tests::the_two_vector_sets_are_not_the_same_coverage`
asserts that rather than leaving the duplication to look accidental.

## 16. Reproducible builds

A build is reproducible from the repository alone when the following hold:

- `../rust-toolchain.toml` pins one exact stable channel. The CI workflow fails if
  the toolchain it built with does not match the pin, so the two cannot drift.
- `../Cargo.lock` is committed and every cargo invocation uses `--locked`.
- Every dependency version is written as `=x.y.z` in `../Cargo.toml`. Caret
  requirements are not used, so adding a dependency is always an explicit edit.
- No build script in the dependency tree reads the network or the clock. Three
  crates in the tree have build scripts, and `../supply-chain/audits.toml` records
  what each one does:
  - `getrandom` is eleven lines. It reads `CARGO_CFG_SANITIZE` and sets one cfg so
    MemorySanitizer can unpoison its output.
  - `libc` writes no file. It derives `rustc-cfg` values from
    `CARGO_CFG_TARGET_ENV`, `CARGO_CFG_TARGET_OS`, `CARGO_CFG_TARGET_POINTER_WIDTH`
    and `CARGO_CFG_TARGET_ARCH`.
  - `curve25519-dalek` writes no file either, and reads the same `CARGO_CFG_*`
    variables to pick a 32 or 64 bit backend. A backend the target cannot support
    is a `panic!` in the build script rather than a silent fallback.

  Two of them, `libc` and `curve25519-dalek` through `rustc_version`, also run
  `$RUSTC -vV` and use the reported version in a decision. Cargo sets the compiler,
  so this is the compiler's own trust boundary rather than a new one, but it is the
  reason the claim above is about the network and the clock and not about the
  environment in general.

  `cargo deny` checks that a crate is allowed at all, and `cargo vet` records
  whether anyone has read the code. Every crate on a production edge in
  `../Cargo.lock` now has an audit written here by reading its source, with the two
  partial reviews named as partial in the notes themselves. The remaining
  exemptions are all dev-dependencies or build-dependencies. What
  `cargo vet check` passing does and does not mean is recorded in
  `../supply-chain/README.md`.

mili does not claim bit-reproducible output across toolchain versions. A
different rustc version, a different `target-cpu` or a different linker will
produce a different binary. Reproducing an exact released binary requires the
same toolchain version and the same linker.

## 17. Release signing

Release signing is not performed by CI.

- The CI workflow has `permissions: contents: read`, so no job can push a tag,
  create a release or write to the repository. It references no stored secret.
  The one token it passes is `${{ secrets.GITHUB_TOKEN }}` to `rustsec/audit-check`,
  which GitHub generates per run and which is not a stored credential; it is
  named that way because that is the syntax, not because it is a secret.
- Build provenance for a release is produced keyless with sigstore, which needs
  no stored key.
- A release tag is signed manually with an Ed25519 key that is generated offline,
  stored offline and never placed in a repository, a CI variable or an encrypted
  file in the repository. The public half is recorded in `SIGNING_KEYS.md`, which
  is the revocation mechanism as well as the record, since there is no key server
  to revoke against. That file also states how a user checks a tag and what to do
  if the key that signed it has since been withdrawn.
- If a release key is ever suspected of exposure, the release history is
  re-signed with a new key and the compromise is recorded in writing. There is no
  revocation shortcut, because there is no online key infrastructure to revoke
  against.

There are no releases yet, so none of this has been exercised. The first tag is
the first test of it, and `SIGNING_KEYS.md` says what has to be published before
that tag exists.


## 18. The C ABI

`mili-ffi` exposes mili across a C ABI. It is the only crate in this repository
that contains `unsafe` code; `mili-core` is `#![forbid(unsafe_code)]` and stays
that way, which is the reason the crate exists.

This section is normative for the boundary's shape. The functions are declared in
`../mili-ffi/include/mili.h`, which is hand written and checked against the exported
symbols by a test.

### 18.1 Rules

1. **No pointer arithmetic leaves the crate.** Every function takes a pointer and a
   length, or a pointer to a buffer whose size the caller asked for. A caller's
   packed array is read as slices, never walked with `pointer.add`.
2. **Output buffers belong to the caller.** No function allocates memory the caller
   has to free and none returns a pointer into the library. There is no `free`
   counterpart to mismatch and nothing to use after the library is unloaded.
3. **Every function returns an error code.** Zero is success. Null is never used to
   report failure, so a null out-parameter is a bug in the boundary rather than a
   state a caller handles.
4. **Every output takes a capacity and reports its length.** A capacity that is too
   small fails with `MILI_BUFFER_TOO_SMALL` having written nothing, and no length is
   written on failure. Nothing here trusts the caller to have allocated what the
   documentation says.
5. **A panic cannot cross the boundary.** Every entry point catches an unwind and
   returns `MILI_INTERNAL`.
6. **Nothing is negotiated or configured.** One suite per format version. No function
   selects an algorithm or reads the environment.

Rules 4 and 6 have a stated cost. Rule 4 means a caller asks the library twice, once
for a size and once for the result, where a fixed-size convention would have been one
call. It is there because of what happened without it: the first version had two
conventions, and `mili_sign` was handed a 3373 byte buffer for a 3379 byte signature
and wrote six bytes past the end of it. Rule 6 means the boundary cannot grow a
compatibility shim for anything, which is the same position `mili-core` takes.

### 18.2 Error codes

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `MILI_OK` | success |
| 1 | `MILI_FAILED` | every failure mili does not distinguish |
| 2 | `MILI_UNSUPPORTED_VERSION` | the data names a format version this build does not implement |
| 3 | `MILI_INTERNAL` | a caught panic, or an invariant that did not hold |
| 4 | `MILI_IO` | an I/O error from a caller-supplied stream |
| 5 | `MILI_BUFFER_TOO_SMALL` | the caller's output buffer was too small |

Only 1 is the uniform failure. 2, 3 and 4 are statements about the caller's data,
about the library, or about its own I/O rather than about secrecy. 5 is a statement
about the caller's own allocation.

A caller cannot distinguish a wrong key from a corrupted file from a wrong password,
and the boundary does not add a way to. See `THREAT_MODEL.md` section 2.12.

### 18.3 Sizes

Every size is reported by a `*_size()` function rather than written into the header,
so that a caller compiled against one version of the header and linked against
another asks the linked library rather than trusting a constant it baked in.

The Go binding is the one exception and states it: `SealingKeySize`,
`SigningKeySize` and `SymmetricKeySize` are Go constants rather than calls into
the library, because a Go function call cannot appear where a slice length must be
a compile-time constant, and these three are part of the type definitions rather
than part of a wire format. Every size that appears in a header is still asked of
the library.

Two mili constants are named apart because the boundary got one of them wrong:

- `SIGNATURE_PAYLOAD_SIZE` is 3373, the two component signatures and nothing else.
- `SIGNATURE_SIZE` is 3379, the same plus mili's six byte signature header.

The first version of this boundary reported the payload size where a caller would
allocate a signature buffer, and wrote six bytes past the end. The rename is in
`mili-core` and the note on both constants says why.

### 18.4 What the boundary cannot do

It cannot check that a non-null pointer covers the length a caller claims. That is
inherent to a C boundary: it refuses a null pointer and trusts the rest. Every caller
in this repository is held to the rule that a non-zero length means a buffer that
long.

It does not clear the caller's memory. A key written into a Go slice will be copied
by the garbage collector and will not be zeroed. `DISCLAIMER.md` records this.

It does not stream. `mili_seal_stream` and `mili_open_stream` take a whole message,
because a reader or writer crossing the boundary would be a second unsafe surface
with no format benefit. A Go program with a file larger than memory should write
chunks through these functions, or link the library itself and drive the format.

## 19. The Go binding

`bindings/go` is a cgo layer over the C ABI. It adds no policy: no retry, no
padding, no key derivation of another kind, no option that section 18 or an earlier
section does not define.

The three key kinds are three distinct Go types, `SealingKey`, `SigningKey` and
`SymmetricKey`. That is not decoration. A sealing key and a symmetric key are both
32 bytes, so anything that inferred the kind from the length would read a symmetric
key as a sealing key and hand back bytes the caller would then encrypt with. Naming
the types stops that from happening by accident.

It stops it by accident, which is weaker than in `mili-core`. There the types are
distinct newtypes with no conversions, so the mismatch does not compile. Go permits
an explicit conversion between named types sharing an underlying type, so
`mili.SealingKey(aSymmetricKey)` compiles, and `keys.go` says so and
`keyfile_test.go` does exactly that once to show the library reports the payload
kind rather than guessing. The residual defence is that each function states the
kind it expects to the library and checks what it is handed, so the conversion
produces a file the caller can read back but not one that silently becomes the key
they thought it was.

`KeyFile` and `Backup` are byte strings with methods. A key file opens through
`UnwrapSealing` or `UnwrapSigning`, and each states which kind it expects to the
library, so opening a signing key file as a sealing key is refused rather than
returning 64 bytes into a 32 byte buffer or 32 bytes into a 64 byte one.

A backup is built through `BackupBuilder`, whose `Add` methods are typed. Two keys
with the same identifier are refused, as section 8 requires.

The binding has no dependencies beyond the C library it links. A security library
whose binding pulls in a module graph has a supply chain the user did not choose.
