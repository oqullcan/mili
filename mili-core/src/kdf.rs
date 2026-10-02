//! HKDF-SHA256 key derivation with mandatory domain separation.
//!
//! mili derives keys with HKDF-SHA256 (RFC 5869). Every derived key carries a
//! label from a closed set. Callers inside the crate cannot pass a free-form
//! string, so two purposes cannot be given the same label by accident, and a
//! label cannot collide with a label used by age, rage, dark-bio, HPKE, TLS or
//! COSE because none of those strings are present in this module.
//!
//! [`Domain::label`] is public so that an implementation which needs to
//! interoperate with a mili format can reproduce the derivation. The derivation
//! function itself is crate-private: a caller must not be able to derive a key
//! from a secret of their choosing, because mili has no way to check that the
//! input was high entropy.
//!
//! # Label set
//!
//! The set below is the complete mili-v1 set. Adding a purpose is a change to
//! `docs/SPEC.md` and a new variant; reusing an existing label is prevented by the
//! test that asserts every label is distinct.
//!
//! | Variant | Label | Derived |
//! |---------|-------|---------|
//! | [`Domain::Seal`] | `mili-v1:seal` | sealed box AEAD key |
//! | [`Domain::Stream`] | `mili-v1:stream` | stream file key |
//! | [`Domain::KeyWrap`] | `mili-v1:keywrap` | key file wrapping key |
//! | [`Domain::Signature`] | `mili-v1:signature` | reserved, signature scheme binding |
//! | [`Domain::KeyId`] | `mili-v1:keyid` | key identifier |
//!
//! # Residual
//!
//! `Hkdf` from `hkdf` 0.13 holds an internal copy of the pseudorandom key and
//! does not implement `Zeroize`, so that copy is released without being
//! overwritten. mili uses a single `Hkdf` value per derivation rather than
//! materialising the pseudorandom key separately, which keeps the exposure to
//! one copy. See `docs/THREAT_MODEL.md` section 2.11.

use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::secret::SecretBytes;

/// The prefix shared by every mili key derivation label.
pub const LABEL_PREFIX: &[u8] = b"mili-v1:";

/// A key derivation purpose.
///
/// The set is closed. Every variant maps to exactly one label and no label is
/// reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Domain {
    /// Sealed box payload key.
    Seal,
    /// Stream file key.
    Stream,
    /// Password-wrapped key file wrapping key.
    KeyWrap,
    /// Signature scheme context binding.
    Signature,
    /// Key identifier.
    KeyId,
}

impl Domain {
    /// Every domain, in declaration order.
    pub const ALL: [Domain; 5] = [
        Domain::Seal,
        Domain::Stream,
        Domain::KeyWrap,
        Domain::Signature,
        Domain::KeyId,
    ];

    /// The HKDF `info` label bound to this purpose.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Domain::Seal => b"mili-v1:seal",
            Domain::Stream => b"mili-v1:stream",
            Domain::KeyWrap => b"mili-v1:keywrap",
            Domain::Signature => b"mili-v1:signature",
            Domain::KeyId => b"mili-v1:keyid",
        }
    }
}

/// Derives `N` bytes from `ikm`, bound to `domain` and `salt`.
///
/// `salt` is used as the HKDF extract salt. An empty `salt` selects the
/// all-zero salt that RFC 5869 specifies for the absent case, which is what
/// public-input derivations such as a key identifier use.
///
/// # Errors
///
/// [`Error::Internal`] if `N` exceeds the HKDF output limit for SHA-256,
/// which is 255 times 32 bytes. mili's own uses are 32 bytes, so this is not
/// reachable from a valid caller.
pub(crate) fn derive<const N: usize>(
    domain: Domain,
    ikm: &[u8],
    salt: &[u8],
) -> Result<SecretBytes<N>, Error> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; N]);
    hkdf.expand(domain.label(), okm.as_mut())
        .map_err(|_| Error::Internal)?;
    // `okm` is a Zeroizing buffer, so the value that was written into it is
    // cleared when this function returns. It is moved out by copy, so the
    // caller's value is unaffected.
    let derived = *okm;
    okm.zeroize();
    Ok(SecretBytes::from_bytes(derived))
}

#[cfg(test)]
mod tests {
    use super::{derive, Domain, LABEL_PREFIX};
    use crate::error::Error;
    use serde::Deserialize;

    const RFC5869_JSON: &str = include_str!("../../tests/vectors/rfc5869_hkdf_sha256.json");
    const MILI_KDF_JSON: &str = include_str!("../../tests/vectors/mili_kdf_v1.json");

    #[derive(Deserialize)]
    struct Rfc5869File {
        vectors: Vec<Rfc5869Vector>,
    }

    #[derive(Deserialize)]
    struct Rfc5869Vector {
        name: String,
        ikm: String,
        salt: String,
        info: String,
        length: usize,
        prk: String,
        okm: String,
    }

    #[derive(Deserialize)]
    struct MiliKdfFile {
        ikm: String,
        salt: String,
        length: usize,
        cases: Vec<MiliKdfCase>,
    }

    #[derive(Deserialize)]
    struct MiliKdfCase {
        domain: String,
        label: String,
        okm: String,
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "hex string has odd length");
        (0..text.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&text[i..i + 2], 16).expect("vector file contains valid hex")
            })
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn domain_from(name: &str) -> Domain {
        match name {
            "seal" => Domain::Seal,
            "stream" => Domain::Stream,
            "keywrap" => Domain::KeyWrap,
            "signature" => Domain::Signature,
            "keyid" => Domain::KeyId,
            other => panic!("vector file names an unknown domain: {other}"),
        }
    }

    #[test]
    fn rfc5869_sha256_vectors() {
        let file: Rfc5869File =
            serde_json::from_str(RFC5869_JSON).expect("rfc5869 vector file parses");

        assert!(
            !file.vectors.is_empty(),
            "the RFC 5869 vector file is empty, which would make this test vacuous"
        );

        for vector in &file.vectors {
            let ikm = hex_decode(&vector.ikm);
            let salt = hex_decode(&vector.salt);
            let info = hex_decode(&vector.info);

            // The same construction derive() uses, with the vector's own info
            // in place of a domain label. This establishes that the pinned hkdf
            // and sha2 versions behave as RFC 5869 specifies.
            let salt_ref = if salt.is_empty() {
                None
            } else {
                Some(salt.as_slice())
            };
            let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(salt_ref, &ikm);
            let mut okm = vec![0u8; vector.length];
            hkdf.expand(&info, &mut okm)
                .unwrap_or_else(|e| panic!("{}: HKDF-Expand failed: {e}", vector.name));

            assert_eq!(
                hex_encode(&okm),
                vector.okm,
                "{}: HKDF-Expand output mismatch",
                vector.name
            );

            assert_eq!(
                hex_decode(&vector.prk).len(),
                32,
                "{}: the published PRK must be 32 bytes for SHA-256",
                vector.name
            );
        }
    }

    #[test]
    fn mili_domain_separation_vectors() {
        let file: MiliKdfFile =
            serde_json::from_str(MILI_KDF_JSON).expect("mili kdf vector file parses");

        let ikm = hex_decode(&file.ikm);
        let salt = hex_decode(&file.salt);
        assert_eq!(file.length, 32, "the vector file output length changed");

        assert_eq!(
            file.cases.len(),
            Domain::ALL.len(),
            "the vector file must cover every domain: Domain::ALL has {}, the file has {}",
            Domain::ALL.len(),
            file.cases.len()
        );

        let mut seen: Vec<&str> = Vec::new();

        for case in &file.cases {
            let domain = domain_from(&case.domain);

            assert_eq!(
                String::from_utf8_lossy(domain.label()),
                case.label,
                "the vector file and the Domain enum disagree about the {} label",
                case.domain
            );

            let derived = derive::<32>(domain, &ikm, &salt).expect("32 bytes is a valid length");
            assert_eq!(
                hex_encode(derived.as_bytes()),
                case.okm,
                "{}: derived key mismatch",
                case.domain
            );

            assert!(
                !seen.contains(&case.okm.as_str()),
                "{}: derived a key another domain also derives",
                case.domain
            );
            seen.push(case.okm.as_str());
        }
    }

    #[test]
    fn every_label_carries_the_prefix() {
        for domain in Domain::ALL {
            assert!(
                domain.label().starts_with(LABEL_PREFIX),
                "{domain:?} label does not start with the mili prefix"
            );
        }
    }

    #[test]
    fn labels_are_distinct() {
        for (i, a) in Domain::ALL.iter().enumerate() {
            for b in &Domain::ALL[i + 1..] {
                assert_ne!(a.label(), b.label(), "{a:?} and {b:?} share a label");
            }
        }
    }

    #[test]
    fn labels_are_distinct_as_strings() {
        let mut labels: Vec<&[u8]> = Domain::ALL.iter().map(|d| d.label()).collect();
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), before);
    }

    #[test]
    fn labels_match_the_specification() {
        assert_eq!(Domain::Seal.label(), b"mili-v1:seal");
        assert_eq!(Domain::Stream.label(), b"mili-v1:stream");
        assert_eq!(Domain::KeyWrap.label(), b"mili-v1:keywrap");
        assert_eq!(Domain::Signature.label(), b"mili-v1:signature");
        assert_eq!(Domain::KeyId.label(), b"mili-v1:keyid");
    }

    #[test]
    fn distinct_domains_produce_distinct_keys() {
        let ikm = [0x42u8; 32];
        let salt = [0x24u8; 32];
        let mut seen: Vec<Vec<u8>> = Vec::new();

        for domain in Domain::ALL {
            let key = derive::<32>(domain, &ikm, &salt).expect("32 bytes is a valid length");
            let bytes = key.as_bytes().to_vec();
            assert!(
                !seen.contains(&bytes),
                "{domain:?} derived a key that another domain also derived"
            );
            seen.push(bytes);
        }

        assert_eq!(seen.len(), Domain::ALL.len());
    }

    #[test]
    fn different_ikms_produce_different_keys() {
        let salt = [0x24u8; 32];
        let a = derive::<32>(Domain::Seal, &[0x01u8; 32], &salt).expect("valid length");
        let b = derive::<32>(Domain::Seal, &[0x02u8; 32], &salt).expect("valid length");
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let ikm = [0x42u8; 32];
        let a = derive::<32>(Domain::Seal, &ikm, &[0x01u8; 32]).expect("valid length");
        let b = derive::<32>(Domain::Seal, &ikm, &[0x02u8; 32]).expect("valid length");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_salt_is_accepted() {
        let key = derive::<32>(Domain::KeyId, &[0x42u8; 32], &[]).expect("valid length");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive::<32>(Domain::Stream, &[0x07u8; 32], &[0x08u8; 32]).expect("valid length");
        let b = derive::<32>(Domain::Stream, &[0x07u8; 32], &[0x08u8; 32]).expect("valid length");
        assert_eq!(a, b);
    }

    #[test]
    fn an_output_length_beyond_the_limit_is_an_internal_error() {
        // 255 * 32 is the HKDF-SHA256 output limit. One byte past it must not
        // panic: the crate has no panic path.
        let result = derive::<{ 255 * 32 + 1 }>(Domain::Seal, &[0u8; 32], &[0u8; 32]);
        assert!(matches!(result, Err(Error::Internal)));
    }
}
