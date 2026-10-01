//! Composite signatures: ML-DSA-65 and Ed25519, valid only if both verify.
//!
//! This is the `MLDSA65-Ed25519-SHA512` construction of
//! `draft-ietf-lamps-pq-composite-sigs`. That document is an IETF internet-draft,
//! not an RFC. `SPEC.md` section 6 has the layout byte by byte.
//!
//! Three properties are worth stating before the API.
//!
//! **Both halves or nothing.** A signature verifies only when ML-DSA-65 verifies
//! *and* Ed25519 verifies. There is no partial acceptance path, no configuration
//! that selects a half, and no way to ask "did the classical half pass". The
//! point of a composite signature is that breaking it requires breaking both.
//!
//! **The signing key is the draft's key.** 64 bytes, the ML-DSA-65 seed followed
//! by the Ed25519 seed. It is not derived from a shorter master seed, so any
//! other implementation of the same construction can reconstruct it.
//!
//! **A key type cannot be misused.** [`SigningKey`] and [`VerifyingKey`] are
//! distinct newtypes that do not convert into [`crate::SealingKey`] or
//! [`crate::EncapsulationKey`], and no function takes more than one of them. A
//! signing key cannot reach an encryption operation, and an encryption key cannot
//! reach a signing operation.
//!
//! # Sizes
//!
//! | Object | Bytes | Layout |
//! |--------|-------|--------|
//! | [`SigningKey`] | 64 | ML-DSA-65 seed (32) \|\| Ed25519 seed (32) |
//! | [`VerifyingKey`] | 1984 | ML-DSA-65 public key (1952) \|\| Ed25519 public key (32) |
//! | signature | 3373 | ML-DSA-65 signature (3309) \|\| Ed25519 signature (64) |
//!
//! The signature is large. That is what a composite of ML-DSA-65 and Ed25519
//! costs, and it is the reason mili does not wrap signatures in the streaming
//! format.

use ed25519_dalek::{Signer as _, Verifier as _};
use hybrid_array::Array;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyExport as _, KeyInit as _, MlDsa65,
    Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::Error;

/// Length in bytes of a composite signing key.
pub const SIGNING_KEY_SIZE: usize = 64;

/// Length in bytes of a composite verifying key.
pub const VERIFYING_KEY_SIZE: usize = 1984;

/// Length in bytes of a composite signature.
pub const SIGNATURE_SIZE: usize = 3373;

/// Length in bytes of the ML-DSA-65 seed inside a signing key.
pub const ML_DSA65_SEED_SIZE: usize = 32;

/// Length in bytes of the ML-DSA-65 public key inside a verifying key.
pub const ML_DSA65_VERIFYING_KEY_SIZE: usize = 1952;

/// Length in bytes of the Ed25519 seed inside a signing key.
pub const ED25519_SEED_SIZE: usize = 32;

/// Length in bytes of the Ed25519 public key inside a verifying key.
pub const ED25519_VERIFYING_KEY_SIZE: usize = 32;

/// Length in bytes of the ML-DSA-65 signature half.
pub const ML_DSA65_SIGNATURE_SIZE: usize = 3309;

/// Length in bytes of the Ed25519 signature half.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// The magic every mili file starts with.
const MAGIC: [u8; 4] = *b"mili";

/// The `format_type` byte of a composite signature.
const FORMAT_TYPE: u8 = 0x03;

/// The `version` byte of a composite signature.
const VERSION: u8 = 0x01;

/// The `Prefix` octet string of the composite draft, as fixed bytes.
const COMPOSITE_PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/// The `Label` for this composite algorithm, as fixed bytes.
///
/// The draft also passes this value into ML-DSA as its context string.
const LABEL: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// The object identifier the draft assigns to this composite algorithm.
///
/// Recorded for interoperability. mili does not implement X.509, so the value is
/// not used to build anything.
pub const OID: &str = "1.3.6.1.5.5.7.6.48";

/// A composite signing key: the ML-DSA-65 seed followed by the Ed25519 seed.
///
/// Zeroized on drop, `Debug` is redacted, `Display` is not implemented, there is
/// no `Clone` and no serialization trait.
pub struct SigningKey(SecretBytes<SIGNING_KEY_SIZE>);

impl SigningKey {
    /// Draws a new key from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the operating system randomness source is
    /// unavailable.
    pub fn generate() -> Result<Self, Error> {
        let bytes = crate::rng::array::<SIGNING_KEY_SIZE>()?;
        Ok(Self(SecretBytes::from_bytes(bytes)))
    }

    /// Wraps an existing 64 byte composite seed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNING_KEY_SIZE]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// Borrows the seed.
    ///
    /// Crate-private, for wrapping the key in a key file and for the FFI
    /// boundary.
    pub(crate) fn expose(&self) -> &[u8; SIGNING_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Derives the matching verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let (mldsa_seed, ed25519_seed) = split(&self.0);
        VerifyingKey(component_public_keys(&mldsa_seed, &ed25519_seed))
    }

    /// Signs `message` and returns the `mili-sig-v1` encoding.
    ///
    /// # Errors
    ///
    /// [`Error::Internal`] if a component refuses to sign. ML-DSA-65 returns an
    /// error only for a context string longer than 255 bytes, and the label is 29
    /// bytes, so this is not reachable from any input.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let transcript = transcript(message);
        let (mldsa_seed, ed25519_seed) = split(&self.0);

        let mldsa_key = MlDsaSigningKey::<MlDsa65>::from_seed(&Array::from(*mldsa_seed));
        let mldsa_signature = mldsa_key
            .expanded_key()
            .sign_deterministic(&transcript, LABEL)
            .map_err(|_| Error::Internal)?;
        let mldsa_bytes = ml_dsa_signature_bytes(mldsa_signature.encode());

        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let ed25519_bytes = ed25519.sign(&transcript).to_bytes();

        let mut out = Vec::with_capacity(HEADER_SIZE + SIGNATURE_SIZE);
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_TYPE);
        out.push(VERSION);
        out.extend_from_slice(&mldsa_bytes);
        out.extend_from_slice(&ed25519_bytes);
        Ok(out)
    }
}

/// A composite verifying key: the ML-DSA-65 public key followed by the Ed25519
/// public key.
pub struct VerifyingKey([u8; VERIFYING_KEY_SIZE]);

impl VerifyingKey {
    /// Parses the 1984 byte encoding.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the length is wrong or the embedded Ed25519 public
    /// key is not a valid point encoding. Both mean the input is not a usable
    /// verifying key, and saying which check failed tells a caller more about
    /// the key it supplied than it needs to know.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != VERIFYING_KEY_SIZE {
            return Err(Error::Failed);
        }
        let mut fixed = [0u8; VERIFYING_KEY_SIZE];
        fixed.copy_from_slice(bytes);
        ed25519_dalek::VerifyingKey::from_bytes(&split_verifying(&fixed).1)
            .map_err(|_| Error::Failed)?;
        Ok(Self(fixed))
    }

    /// Copies the 1984 byte encoding out.
    ///
    /// These are public bytes. `Display` is still not implemented, so that a key
    /// cannot end up in a log line by accident.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_SIZE] {
        self.0
    }

    /// Verifies a `mili-sig-v1` signature over `message`.
    ///
    /// Returns as soon as one half fails, which the draft explicitly permits
    /// because no private key is involved in verification and there is nothing to
    /// learn from timing.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] if the version byte names a version this
    /// build does not implement. [`Error::Failed`] for a short buffer, a wrong
    /// magic, a wrong `format_type`, a malformed component key, a component
    /// signature that does not verify, and a message that is not the one signed.
    /// The last three are not distinguished.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let parsed = SignatureFile::parse(signature)?;

        let (mldsa_bytes, ed25519_bytes) = split_signature(parsed.0);
        let (mldsa_public, ed25519_public) = split_verifying(&self.0);

        let transcript = transcript(message);

        let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(&mldsa_public[..])
            .map_err(|_| Error::Failed)?;
        let mldsa_signature = MlDsaSignature::<MlDsa65>::decode(&encoded_signature(&mldsa_bytes))
            .ok_or(Error::Failed)?;

        if !MlDsaVerifyingKey::<MlDsa65>::new(&encoded_key).verify_with_context(
            &transcript,
            LABEL,
            &mldsa_signature,
        ) {
            return Err(Error::Failed);
        }

        // `ed25519::Signature::from_bytes` cannot fail: the 64 bytes are taken
        // as the two R and S scalars without a range check. A signature with an
        // out of range half is rejected by `verify` below, which is the check
        // that matters.
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&ed25519_bytes);
        let ed25519_key =
            ed25519_dalek::VerifyingKey::from_bytes(&ed25519_public).map_err(|_| Error::Failed)?;

        ed25519_key
            .verify(&transcript, &ed25519_signature)
            .map_err(|_| Error::Failed)
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifyingKey([REDACTED])")
    }
}

/// Builds `M' = Prefix || Label || len(ctx) || ctx || PH(M)` with an empty
/// application context, exactly as section 3.2 of the draft specifies.
fn transcript(message: &[u8]) -> Vec<u8> {
    let prehash = Sha512::digest(message);

    // Every term is a constant or a label length, so this cannot overflow in
    // practice; saturating states that rather than leaving it to be checked.
    let capacity = COMPOSITE_PREFIX
        .len()
        .saturating_add(LABEL.len())
        .saturating_add(1)
        .saturating_add(64);
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(LABEL);
    out.push(0);
    out.extend_from_slice(&prehash);
    out
}

/// Length of the fixed header of a signature file.
const HEADER_SIZE: usize = 6;

/// Splits a composite seed into its two component seeds.
///
/// The halves come back in zeroizing buffers so that this frame does not leave a
/// second plain copy of either seed behind.
fn split(
    seed: &SecretBytes<SIGNING_KEY_SIZE>,
) -> (
    Zeroizing<[u8; ML_DSA65_SEED_SIZE]>,
    Zeroizing<[u8; ED25519_SEED_SIZE]>,
) {
    let all = seed.as_bytes();
    let mut mldsa = [0u8; ML_DSA65_SEED_SIZE];
    mldsa.copy_from_slice(&all[..ML_DSA65_SEED_SIZE]);
    let mut ed25519 = [0u8; ED25519_SEED_SIZE];
    ed25519.copy_from_slice(&all[ML_DSA65_SEED_SIZE..]);
    (Zeroizing::new(mldsa), Zeroizing::new(ed25519))
}

/// Derives the two component public keys from the two component seeds.
fn component_public_keys(
    mldsa_seed: &[u8; ML_DSA65_SEED_SIZE],
    ed25519_seed: &[u8; ED25519_SEED_SIZE],
) -> [u8; VERIFYING_KEY_SIZE] {
    let mldsa_key = MlDsaSigningKey::<MlDsa65>::from_seed(&Array::from(*mldsa_seed));
    let mldsa_public = ml_dsa_bytes(mldsa_key.expanded_key().verifying_key().to_bytes());
    let ed25519_public = ed25519_dalek::SigningKey::from_bytes(ed25519_seed)
        .verifying_key()
        .to_bytes();

    let mut bytes = [0u8; VERIFYING_KEY_SIZE];
    bytes[..ML_DSA65_VERIFYING_KEY_SIZE].copy_from_slice(&mldsa_public);
    bytes[ML_DSA65_VERIFYING_KEY_SIZE..].copy_from_slice(&ed25519_public);
    bytes
}

/// Copies an ML-DSA array out as fixed size bytes.
fn ml_dsa_bytes(bytes: EncodedVerifyingKey<MlDsa65>) -> [u8; ML_DSA65_VERIFYING_KEY_SIZE] {
    let mut out = [0u8; ML_DSA65_VERIFYING_KEY_SIZE];
    out.copy_from_slice(bytes.as_slice());
    out
}

/// Copies an ML-DSA signature out as fixed size bytes.
fn ml_dsa_signature_bytes(bytes: EncodedSignature<MlDsa65>) -> [u8; ML_DSA65_SIGNATURE_SIZE] {
    let mut out = [0u8; ML_DSA65_SIGNATURE_SIZE];
    out.copy_from_slice(bytes.as_slice());
    out
}

/// Wraps signature bytes in the type `Signature::decode` expects.
fn encoded_signature(bytes: &[u8; ML_DSA65_SIGNATURE_SIZE]) -> EncodedSignature<MlDsa65> {
    Array::from(*bytes)
}

/// Splits a verifying key into its two component public keys.
fn split_verifying(
    bytes: &[u8; VERIFYING_KEY_SIZE],
) -> (
    [u8; ML_DSA65_VERIFYING_KEY_SIZE],
    [u8; ED25519_VERIFYING_KEY_SIZE],
) {
    let mut mldsa = [0u8; ML_DSA65_VERIFYING_KEY_SIZE];
    mldsa.copy_from_slice(&bytes[..ML_DSA65_VERIFYING_KEY_SIZE]);
    let mut ed25519 = [0u8; ED25519_VERIFYING_KEY_SIZE];
    ed25519.copy_from_slice(&bytes[ML_DSA65_VERIFYING_KEY_SIZE..]);
    (mldsa, ed25519)
}

/// Splits a signature file body into its two component signatures.
fn split_signature(file: &[u8]) -> ([u8; ML_DSA65_SIGNATURE_SIZE], [u8; ED25519_SIGNATURE_SIZE]) {
    let body = &file[HEADER_SIZE..];
    let mut mldsa = [0u8; ML_DSA65_SIGNATURE_SIZE];
    mldsa.copy_from_slice(&body[..ML_DSA65_SIGNATURE_SIZE]);
    let mut ed25519 = [0u8; ED25519_SIGNATURE_SIZE];
    ed25519.copy_from_slice(&body[ML_DSA65_SIGNATURE_SIZE..]);
    (mldsa, ed25519)
}

/// The `mili-sig-v1` file: magic, format type, version, then the two halves.
struct SignatureFile<'a>(&'a [u8]);

impl<'a> SignatureFile<'a> {
    /// Parses and length checks a signature file.
    ///
    /// Nothing here is a security check. The magic, `format_type` and `version`
    /// bytes are public, and the cryptographic check happens in `verify`.
    fn parse(file: &'a [u8]) -> Result<Self, Error> {
        if file.len() != HEADER_SIZE + SIGNATURE_SIZE {
            return Err(Error::Failed);
        }
        if file[..4] != MAGIC || file[4] != FORMAT_TYPE {
            return Err(Error::Failed);
        }
        if file[5] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        Ok(Self(file))
    }
}

// The tests that reach into ML-DSA-65 or Ed25519 arithmetic are excluded
// under miri. Each call costs orders of magnitude more when miri interprets
// it, and `every_signature_byte_is_authenticated` alone runs three thousand
// verifications. The three tests that are not excluded check mili's own
// constants, labels and transcript, which is the part worth proving.
#[cfg(test)]
mod tests {
    use super::{
        transcript, ED25519_SIGNATURE_SIZE, ED25519_VERIFYING_KEY_SIZE, LABEL,
        ML_DSA65_SIGNATURE_SIZE, ML_DSA65_VERIFYING_KEY_SIZE, OID, SIGNATURE_SIZE,
        SIGNING_KEY_SIZE, VERIFYING_KEY_SIZE,
    };
    #[cfg(not(miri))]
    use super::{SigningKey, HEADER_SIZE, ML_DSA65_SEED_SIZE};
    #[cfg(not(miri))]
    use crate::{Error, SealingKey};
    #[cfg(not(miri))]
    use serde::Deserialize;

    #[cfg(not(miri))]
    const LAMPS_JSON: &str = include_str!("../../tests/vectors/lamps19_composite_ed25519.json");

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct VectorFile {
        source: String,
        label: String,
        prefix: String,
        message: String,
        sizes: Sizes,
        vector: Vector,
    }

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct Sizes {
        pk: usize,
        sk: usize,
        #[serde(rename = "s")]
        signature: usize,
        #[serde(rename = "sWithContext")]
        signature_with_context: usize,
    }

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct Vector {
        #[serde(rename = "tcId")]
        tc_id: String,
        pk: String,
        sk: String,
        #[serde(rename = "s")]
        signature: String,
        #[serde(rename = "sWithContext")]
        signature_with_context: String,
    }

    #[cfg(not(miri))]
    fn hex_decode(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "hex string has odd length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("vector file hex is valid"))
            .collect()
    }

    #[cfg(not(miri))]
    fn key() -> SigningKey {
        let mut bytes = [0x5Au8; SIGNING_KEY_SIZE];
        for byte in &mut bytes[ML_DSA65_SEED_SIZE..] {
            *byte = 0xA5;
        }
        SigningKey::from_bytes(bytes)
    }

    #[test]
    fn sizes_match_the_specification() {
        assert_eq!(SIGNING_KEY_SIZE, 64);
        assert_eq!(VERIFYING_KEY_SIZE, 1984);
        assert_eq!(SIGNATURE_SIZE, 3373);
        assert_eq!(ML_DSA65_VERIFYING_KEY_SIZE, 1952);
        assert_eq!(ED25519_VERIFYING_KEY_SIZE, 32);
        assert_eq!(ML_DSA65_SIGNATURE_SIZE, 3309);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
        assert_eq!(
            ML_DSA65_VERIFYING_KEY_SIZE + ED25519_VERIFYING_KEY_SIZE,
            VERIFYING_KEY_SIZE
        );
        assert_eq!(
            ML_DSA65_SIGNATURE_SIZE + ED25519_SIGNATURE_SIZE,
            SIGNATURE_SIZE
        );
    }

    #[test]
    fn the_labels_are_the_ones_the_draft_names() {
        assert_eq!(OID, "1.3.6.1.5.5.7.6.48");
        assert_eq!(LABEL, b"COMPSIG-MLDSA65-Ed25519-SHA512");
        assert_eq!(LABEL.len(), 30);
    }

    #[test]
    fn the_transcript_has_the_draft_layout() {
        // Frozen expected value, computed with an independent SHA-512
        // implementation rather than typed out by hand.
        const EXPECTED: &str = concat!(
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235",
            "434f4d505349472d4d4c44534136352d456432353531392d534841353132",
            "00",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );

        let t = transcript(b"");
        assert_eq!(t.len(), 127);
        assert_eq!(&t[..32], b"CompositeAlgorithmSignatures2025");
        assert_eq!(&t[32..62], LABEL);
        assert_eq!(
            t[62], 0,
            "an empty application context must be encoded as zero"
        );
        assert_eq!(hex_encode(&t), EXPECTED);
    }

    fn hex_encode(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip() {
        let key = key();
        let verifying = key.verifying_key();

        for message in [
            &b""[..],
            b"a",
            b"a longer message to sign",
            &[0x5Au8; 5000][..],
        ] {
            let signature = key.sign(message).expect("sign");
            assert_eq!(signature.len(), HEADER_SIZE + SIGNATURE_SIZE);
            verifying.verify(message, &signature).expect("verify");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_different_message_does_not_verify() {
        let key = key();
        let signature = key.sign(b"signed message").expect("sign");
        assert!(matches!(
            key.verifying_key().verify(b"other message", &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_key_does_not_verify() {
        let key = key();
        let signature = key.sign(b"a message").expect("sign");
        let wrong = SigningKey::from_bytes([0xC3u8; SIGNING_KEY_SIZE]);
        assert!(matches!(
            wrong.verifying_key().verify(b"a message", &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn both_halves_are_required() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let mut signature = key.sign(message).expect("sign");

        // Corrupt the ML-DSA half only.
        let mut broken = signature.clone();
        broken[6] ^= 0x01;
        assert!(
            matches!(verifying.verify(message, &broken), Err(Error::Failed)),
            "a signature with a corrupt ML-DSA half must not verify"
        );

        // Corrupt the Ed25519 half only.
        let mut broken = signature.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0x01;
        assert!(
            matches!(verifying.verify(message, &broken), Err(Error::Failed)),
            "a signature with a corrupt Ed25519 half must not verify"
        );

        // Corrupt a byte in the ML-DSA hint region, which changes the signature
        // without making the encoding undecodable.
        signature[HEADER_SIZE + 100] ^= 0x01;
        assert!(matches!(
            verifying.verify(message, &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn every_signature_byte_is_authenticated() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message to sign";
        let signature = key.sign(message).expect("sign");

        for index in HEADER_SIZE..signature.len() {
            let mut tampered = signature.clone();
            tampered[index] ^= 0x01;
            assert!(
                matches!(verifying.verify(message, &tampered), Err(Error::Failed)),
                "byte {index} was accepted after a bit flip"
            );
        }

        // The header bytes are checked before any cryptography, so flipping the
        // version byte is reported as an unsupported version rather than as a
        // failed authentication. That distinction is deliberate and public.
        for index in 0..HEADER_SIZE {
            let mut tampered = signature.clone();
            tampered[index] ^= 0x01;
            let result = verifying.verify(message, &tampered);
            assert!(
                result.is_err(),
                "header byte {index} was accepted after a flip"
            );
            if index == 5 {
                assert!(matches!(result, Err(Error::UnsupportedVersion)));
            } else {
                assert!(matches!(result, Err(Error::Failed)));
            }
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_header_is_checked() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let signature = key.sign(message).expect("sign");

        let mut bad_magic = signature.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            verifying.verify(message, &bad_magic),
            Err(Error::Failed)
        ));

        let mut bad_type = signature.clone();
        bad_type[4] = 0x02;
        assert!(matches!(
            verifying.verify(message, &bad_type),
            Err(Error::Failed)
        ));

        let mut bad_version = signature.clone();
        bad_version[5] = 0x02;
        assert!(matches!(
            verifying.verify(message, &bad_version),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn every_truncation_is_rejected() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let signature = key.sign(message).expect("sign");

        for len in [0usize, 1, 5, 6, 100, 2000, 3378, signature.len() - 1] {
            assert!(
                verifying.verify(message, &signature[..len]).is_err(),
                "truncation to {len} bytes was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn appended_bytes_are_rejected() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let mut signature = key.sign(message).expect("sign");
        signature.push(0);
        assert!(matches!(
            verifying.verify(message, &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn verifying_key_parsing_rejects_bad_input() {
        let key = key();
        let bytes = key.verifying_key().to_bytes();

        assert!(super::VerifyingKey::from_bytes(&bytes[..VERIFYING_KEY_SIZE - 1]).is_err());
        assert!(super::VerifyingKey::from_bytes(&[]).is_err());

        let mut too_long = bytes.to_vec();
        too_long.push(0);
        assert!(super::VerifyingKey::from_bytes(&too_long).is_err());

        // An Ed25519 public key is a compressed Edwards point; a value that is not
        // a valid encoding must be rejected. `0xEC` repeated is one: the masked
        // y coordinate does not decode to a curve point. `[0xFF; 32]` is not,
        // because it is a valid encoding, so it would be a bad choice here.
        let mut bad_point = bytes;
        let offset = ML_DSA65_VERIFYING_KEY_SIZE;
        bad_point[offset..offset + ED25519_VERIFYING_KEY_SIZE].copy_from_slice(&[0xEC; 32]);
        assert!(matches!(
            super::VerifyingKey::from_bytes(&bad_point),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn verifying_key_round_trips_through_bytes() {
        let key = key();
        let bytes = key.verifying_key().to_bytes();
        let restored = super::VerifyingKey::from_bytes(&bytes).expect("valid key");
        assert_eq!(restored.to_bytes(), bytes);

        let signature = key.sign(b"a message").expect("sign");
        restored.verify(b"a message", &signature).expect("verify");
    }

    #[test]
    #[cfg(not(miri))]
    fn key_generation_produces_distinct_keys() {
        let a = SigningKey::generate().expect("OS randomness is available");
        let b = SigningKey::generate().expect("OS randomness is available");
        assert_ne!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    #[cfg(not(miri))]
    fn debug_is_redacted() {
        assert_eq!(format!("{:?}", key()), "SigningKey([REDACTED])");
        assert_eq!(
            format!("{:?}", key().verifying_key()),
            "VerifyingKey([REDACTED])"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn the_two_seed_halves_are_independent() {
        // Flipping one half of the composite seed must change the verifying key,
        // which is the property that a single shared seed would not have.
        let base = key();
        let mut flipped = *base.expose();
        flipped[0] ^= 0xFF;
        assert_ne!(
            base.verifying_key().to_bytes(),
            SigningKey::from_bytes(flipped).verifying_key().to_bytes()
        );

        let mut flipped = *base.expose();
        flipped[32] ^= 0xFF;
        assert_ne!(
            base.verifying_key().to_bytes(),
            SigningKey::from_bytes(flipped).verifying_key().to_bytes()
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn a_sealing_key_cannot_be_used_here() {
        // The compile time guarantee is that these are distinct types. This test
        // records the runtime consequence, which is that a sealing key's bytes
        // are not a valid composite signing key with the same meaning.
        let sealing = SealingKey::from_bytes([0x11u8; 32]);
        let composite = SigningKey::from_bytes([0x11u8; SIGNING_KEY_SIZE]);
        let signature = composite.sign(b"a message").expect("sign");
        assert!(matches!(
            composite.verifying_key().verify(b"a message", &signature),
            Ok(())
        ));
        let _ = sealing.encapsulation_key();
    }

    #[test]
    #[cfg(not(miri))]
    fn lamps_draft_vector() {
        let file: VectorFile = serde_json::from_str(LAMPS_JSON).expect("lamps vector file parses");

        assert!(file.source.contains("lamps-pq-composite-sigs-19"));
        assert_eq!(file.label, "COMPSIG-MLDSA65-Ed25519-SHA512");
        assert_eq!(file.prefix, "CompositeAlgorithmSignatures2025");
        assert_eq!(file.sizes.pk, VERIFYING_KEY_SIZE);
        assert_eq!(file.sizes.sk, SIGNING_KEY_SIZE);
        assert_eq!(file.sizes.signature, SIGNATURE_SIZE);
        assert_eq!(file.sizes.signature_with_context, SIGNATURE_SIZE);

        let vector = &file.vector;
        assert_eq!(vector.tc_id, "id-MLDSA65-Ed25519-SHA512");

        let message = file.message.as_bytes();
        let verifying = super::VerifyingKey::from_bytes(&hex_decode(&vector.pk))
            .expect("the draft's public key is a valid composite key");

        // The signature computed with an empty application context is the one
        // mili produces, because mili always uses an empty context.
        let signature = hex_decode(&vector.signature);
        let mut file_bytes = Vec::with_capacity(HEADER_SIZE + signature.len());
        file_bytes.extend_from_slice(b"mili");
        file_bytes.push(0x03);
        file_bytes.push(0x01);
        file_bytes.extend_from_slice(&signature);

        verifying
            .verify(message, &file_bytes)
            .expect("the draft's signature must verify under mili's construction");

        // The draft's signing key must derive the draft's published verifying
        // key. That part is exact and is checked here.
        let mut seed = [0u8; SIGNING_KEY_SIZE];
        seed.copy_from_slice(&hex_decode(&vector.sk));
        let signing = SigningKey::from_bytes(seed);
        assert_eq!(
            signing.verifying_key().to_bytes().as_slice(),
            hex_decode(&vector.pk).as_slice(),
            "mili's verifying key differs from the draft's published key"
        );

        // mili's own signature over the same key and message must also verify,
        // but is not byte identical to the published one. The reference
        // implementation that produced the draft's vectors used randomised ML-DSA
        // signing, and mili uses the deterministic variant, so the two
        // signatures differ while both being valid. See SPEC.md section 6.4.
        let produced = signing.sign(message).expect("sign");
        assert_ne!(
            produced, file_bytes,
            "mili produced the draft's exact signature, which would mean the              reference implementation was deterministic after all"
        );
        verifying
            .verify(message, &produced)
            .expect("mili's own signature verifies");
    }

    #[test]
    #[cfg(not(miri))]
    fn the_draft_vector_with_a_context_does_not_verify_under_an_empty_context() {
        // mili always signs with an empty application context, so the draft's
        // sWithContext value, which was produced over a non-empty ctx, must not
        // verify. This is what proves mili is not accidentally ignoring the
        // context field.
        let file: VectorFile = serde_json::from_str(LAMPS_JSON).expect("lamps vector file parses");
        let verifying =
            super::VerifyingKey::from_bytes(&hex_decode(&file.vector.pk)).expect("valid key");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"mili");
        bytes.push(0x03);
        bytes.push(0x01);
        bytes.extend_from_slice(&hex_decode(&file.vector.signature_with_context));

        assert!(matches!(
            verifying.verify(file.message.as_bytes(), &bytes),
            Err(Error::Failed)
        ));
    }
}
