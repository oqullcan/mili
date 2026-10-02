# mili test vectors

Known answer test vectors used by `mili-core`. Every file here is committed and
is read at compile time with `include_str!`, so a test run needs no network and
no fixture download.

## Layout

```
rfc5869_hkdf_sha256.json            published RFC 5869 vectors, SHA-256 cases
mili_kdf_v1.json                    mili-v1 HKDF-SHA256 domain separation vectors
rfc8439_chacha20poly1305.json       RFC 8439 Section 2.8.2
wycheproof_chacha20_poly1305.json   C2SP Wycheproof, converted
xwing_draft11.json                  draft-connolly-cfrg-xwing-kem-11 Appendix C
lamps19_composite_ed25519.json      draft-ietf-lamps-pq-composite-sigs-19 Appendix E
argon2id_crosscheck.json           Argon2id against the reference implementation
acvp_mlkem768.json                 NIST ACVP, ML-KEM-768 encapsulation
```

## What each file is for

| File | Tests | Runner |
|------|-------|--------|
| `rfc5869_hkdf_sha256.json` | that the pinned `hkdf` and `sha2` behave as RFC 5869 specifies | `kdf::tests::rfc5869_sha256_vectors` |
| `mili_kdf_v1.json` | that `Domain` label bindings have not changed | `kdf::tests::mili_domain_separation_vectors` |
| `rfc8439_chacha20poly1305.json` | ChaCha20-Poly1305 against the RFC | `aead::tests::rfc8439_vector` |
| `wycheproof_chacha20_poly1305.json` | ChaCha20-Poly1305 against 316 converted Wycheproof cases, 256 accepted and 60 rejected | `aead::tests::wycheproof_chacha20_poly1305` |
| `xwing_draft11.json` | X-Wing keygen, encapsulation and decapsulation against the draft, all three | `kem::tests::xwing_*` |
| `lamps19_composite_ed25519.json` | the whole composite signature construction, both components, both transcripts, from the draft's own Appendix E | `signature::tests::lamps_draft_vector` |
| `argon2id_crosscheck.json` | Argon2id against the reference C implementation, at the profile mili writes and at both bounds mili accepts | `keyfile::tests::argon2id_vectors_from_the_reference_implementation` |
| `acvp_mlkem768.json` | ML-KEM-768 encapsulation, against NIST's own test vectors | `kem::tests::acvp_vectors_agree_with_the_key_agreement_they_were_generated_for` |

## Why there is both an X-Wing and an ML-KEM file

`docs/SPEC.md` section 15 made ACVP vectors conditional: add them "if the X-Wing
vectors prove insufficient". They proved insufficient, so they are here, and the
reason is worth recording because it is not obvious from the file list.

An X-Wing encapsulation key is an ML-KEM-768 encapsulation key followed by an
X25519 public key, and an X-Wing ciphertext is an ML-KEM-768 ciphertext followed by
an X25519 public key. The draft's three vectors therefore do exercise ML-KEM-768
key generation, encapsulation and decapsulation, but only ever as a *function of an
X-Wing seed*. There is no point in the draft file where a bare ML-KEM-768
encapsulation key appears, so there is nothing to feed to `ml-kem`'s own
encapsulation API, and no way to ask NIST's question of NIST's vectors.

The ACVP file has exactly what the draft file lacks: an encapsulation key as an
*input*. That makes it a different test, not a longer version of the same one, and
`kem::tests::the_two_vector_sets_are_not_the_same_coverage` asserts the two are
distinct rather than letting the duplication look like redundancy.

## Adding vectors

Each file records its provenance in a `source` or `note` field, and, for
converted upstream data, the URL and file name it was converted from.

A vector file added in a later phase:

- `mlkem768_acvp.json` — from NIST ACVP, if the X-Wing vectors turn out to be
  insufficient to pin the ML-KEM-768 half
- `mldsa65_acvp.json` — from NIST ACVP
- `chacha20poly1305_rfc8439.json` — from RFC 8439
- `argon2id_rfc9106.json` — from RFC 9106, if the crate ever grows an associated
  data input that makes the RFC's own vectors reachable

Conversion from an upstream file to this layout happens once and is committed.
The runner is written against the converted file, not against the upstream
format, so that the test does not change when the upstream file does.

## Regenerating `mili_kdf_v1.json`

Only if the label set in `docs/SPEC.md` changes. The vectors are generated with an
implementation of HKDF-SHA256 written from RFC 5869, not with mili, so that the
test can fail if mili's derivation changes.

## Regenerating `argon2id_crosscheck.json`

These tags are not from RFC 9106, and the file says so. Every Argon2id vector the
RFC publishes folds a secret key and associated data into the initial hash. The
pinned `argon2` 0.6.0 crate takes a secret through `new_with_secret` and has no
associated data input at all, so no RFC vector is reachable through the API mili
calls. Pinning the crate against a vector mili cannot produce would mean pinning
it against a different configuration than the one it is used in.

Instead each tag comes from `argon2-cffi`, which binds the reference C
implementation, and each is compared against the independent pure Rust
implementation. Two independent implementations agreeing is the actual claim being
made, and it is the one that would catch a crate release that changed the
derivation.

Regenerate with:

```python
import base64, json, argon2
from argon2.low_level import Type

def raw(password, salt, t, m, p, taglen=32):
    h = argon2.PasswordHasher(time_cost=t, memory_cost=m, parallelism=p,
                              hash_len=taglen, salt_len=len(salt), type=Type.ID)
    phc = h.hash(password, salt=salt)
    tail = phc.split("$")[-1]
    return base64.b64decode(tail + "=" * (-len(tail) % 4))
```

`argon2.low_level.hash_secret` is the wrong entry point for this: it takes a
secret where the reference implementation's password path takes a password, so it
derives something mili never derives. Using it produces a file that looks
plausible and disagrees with the Rust crate on every case, which is the first
thing that goes wrong if this is regenerated carelessly.

The `in_accepted_range` flag in each case records whether mili would accept that
parameter set on open. `keyfile::tests::argon2id_vector_file_shape_is_pinned`
checks the flag against the implementation, so the file cannot drift away from
what `check_params` does.

The 1 GiB memory ceiling is not in this file. A vector there would need a 1 GiB
allocation in a test suite, and `check_params` bounds are tested directly instead.
