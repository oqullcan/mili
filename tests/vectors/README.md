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
```

## What each file is for

| File | Tests | Runner |
|------|-------|--------|
| `rfc5869_hkdf_sha256.json` | that the pinned `hkdf` and `sha2` behave as RFC 5869 specifies | `kdf::tests::rfc5869_sha256_vectors` |
| `mili_kdf_v1.json` | that `Domain` label bindings have not changed | `kdf::tests::mili_domain_separation_vectors` |
| `rfc8439_chacha20poly1305.json` | ChaCha20-Poly1305 against the RFC | `aead::tests::rfc8439_vector` |
| `wycheproof_chacha20_poly1305.json` | ChaCha20-Poly1305 against 316 converted Wycheproof cases, 256 accepted and 60 rejected | `aead::tests::wycheproof_chacha20_poly1305` |
| `xwing_draft11.json` | X-Wing keygen, encapsulation and decapsulation against the draft, all three | `kem::tests::xwing_*` |

## Adding vectors

Each file records its provenance in a `source` or `note` field, and, for
converted upstream data, the URL and file name it was converted from.

A vector file added in a later phase:

- `mlkem768_acvp.json` — from NIST ACVP, if the X-Wing vectors turn out to be
  insufficient to pin the ML-KEM-768 half
- `ed25519_rfc8032.json` — from RFC 8032
- `mldsa65_acvp.json` — from NIST ACVP
- `chacha20poly1305_rfc8439.json` — from RFC 8439
- `argon2id_rfc9106.json` — from RFC 9106
- `wycheproof_eddsa.json`, `wycheproof_mldsa.json` — from C2SP Wycheproof, in phase 3

Conversion from an upstream file to this layout happens once and is committed.
The runner is written against the converted file, not against the upstream
format, so that the test does not change when the upstream file does.

## Regenerating `mili_kdf_v1.json`

Only if the label set in `SPEC.md` changes. The vectors are generated with an
implementation of HKDF-SHA256 written from RFC 5869, not with mili, so that the
test can fail if mili's derivation changes.
