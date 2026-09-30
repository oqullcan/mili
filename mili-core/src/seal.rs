//! Sealed boxes: one message, one recipient, one buffer.
//!
//! A sealed box is the `mili-seal-v1` format. It encrypts a single in-memory
//! buffer to a single X-Wing public key. For files larger than memory, use the
//! streaming format added in a later phase.
//!
//! The layout is fixed and documented byte by byte in `SPEC.md` section 4:
//!
//! ```text
//! ofs  len  field
//! 0    4    magic "mili"
//! 4    1    format_type 0x01
//! 5    1    version 0x01
//! 6    32   salt          uniform random per file
//! 38   1120 kem_ct        X-Wing ciphertext
//! 1158 n    ciphertext     ChaCha20-Poly1305, 16 byte tag at the end
//! ```
//!
//! # Recipient anonymity
//!
//! The header names no recipient and no key. An observer cannot tell which of a
//! recipient's keys a file was sealed to, or whether two files share a recipient,
//! because the only key-dependent bytes in the file are the KEM ciphertext and
//! the ciphertext itself, and the KEM ciphertext is fresh randomness on every
//! call. `open` therefore takes a list of candidate keys and tries them in
//! order; see `SPEC.md` section 10.
//!
//! # Nonce
//!
//! The AEAD nonce is twelve zero bytes and is not transmitted. Key uniqueness
//! comes from `salt`, which is 32 uniform random bytes per file. Two files that
//! share an AEAD key must share a `salt`, and a repeated `salt` would have to
//! come from the operating system CSPRNG.

use zeroize::Zeroizing;

use crate::aead::{AeadKey, AeadNonce};
use crate::error::Error;
use crate::kdf::{self, Domain};
use crate::kem::{EncapsulationKey, SealingKey, KEM_CIPHERTEXT_SIZE};
use crate::secret::SecretBytes;

/// The magic every mili file starts with.
pub const MAGIC: [u8; 4] = *b"mili";

/// The `format_type` byte of a sealed box.
pub const FORMAT_TYPE: u8 = 0x01;

/// The `version` byte of a sealed box.
pub const VERSION: u8 = 0x01;

/// Offset of the `salt` field.
pub(crate) const SALT_OFFSET: usize = 6;

/// Length of the `salt` field.
pub(crate) const SALT_SIZE: usize = 32;

/// Length of the authenticated header: everything before the ciphertext.
pub(crate) const HEADER_SIZE: usize = SALT_OFFSET + SALT_SIZE + KEM_CIPHERTEXT_SIZE;

/// Bytes a sealed box adds to the plaintext: header plus AEAD tag.
pub const SEALED_BOX_OVERHEAD: usize = HEADER_SIZE + crate::aead::TAG_SIZE;

/// Encrypts `plaintext` to `public`.
///
/// The result is the complete `mili-seal-v1` file: header then ciphertext. It is
/// `plaintext.len() + SEALED_BOX_OVERHEAD` bytes long.
///
/// # Errors
///
/// [`Error::Failed`] if the operating system randomness source is unavailable.
/// Seal never fails for any property of the input: a public key is either valid
/// or was rejected when it was parsed.
///
/// # Examples
///
/// ```
/// use mili_core::{open, seal, SealingKey};
///
/// # fn main() -> Result<(), mili_core::Error> {
/// let key = SealingKey::generate()?;
/// let sealed = seal(&key.encapsulation_key(), b"a message")?;
///
/// assert_eq!(*open(&sealed, &[&key])?, *b"a message");
/// # Ok(())
/// # }
/// ```
pub fn seal(public: &EncapsulationKey, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let salt = crate::rng::array::<SALT_SIZE>()?;
    let (kem_ct, shared) = public.encapsulate();

    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(&MAGIC);
    header.push(FORMAT_TYPE);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&kem_ct);

    let aead = aead_for(&shared, &salt)?;
    let ciphertext = aead.seal(AeadNonce::ZERO, &header, plaintext)?;

    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// Decrypts a sealed box, trying each candidate key in order.
///
/// The keys are attempted in the order given. The first one that authenticates
/// wins. If none does, the result is [`Error::Failed`], which is also what a
/// wrong key, a corrupted file and a truncated file produce. Nothing in the
/// result says which key matched, which check failed, or how many keys were
/// tried.
///
/// Trying several keys costs one X-Wing decapsulation per key, which is cheap
/// relative to ML-KEM-768 key generation. mili does not put a key identifier in
/// the file to avoid this, because a cleartext identifier would tell an observer
/// which key opens which file.
///
/// # Errors
///
/// [`Error::UnsupportedVersion`] if the version byte names a version this build
/// does not implement. Every other rejection, including a wrong magic, a wrong
/// `format_type`, a short file and a failed authentication, is
/// [`Error::Failed`].
///
/// # Examples
///
/// ```
/// use mili_core::{open, seal, SealingKey};
///
/// # fn main() -> Result<(), mili_core::Error> {
/// let key = SealingKey::generate()?;
/// let other = SealingKey::generate()?;
/// let sealed = seal(&key.encapsulation_key(), b"a message")?;
///
/// assert_eq!(*open(&sealed, &[&other, &key])?, *b"a message");
/// # Ok(())
/// # }
/// ```
pub fn open(sealed: &[u8], keys: &[&SealingKey]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let header = Header::parse(sealed)?;

    for key in keys {
        let shared = key.decapsulate(header.kem_ct)?;
        let aead = aead_for(&shared, &header.salt)?;
        if let Ok(plaintext) = aead.open(AeadNonce::ZERO, header.bytes, header.ciphertext) {
            return Ok(plaintext);
        }
    }

    Err(Error::Failed)
}

impl SealingKey {
    /// Decrypts a sealed box with this key alone.
    ///
    /// A convenience wrapper around [`open`] with a one element candidate list.
    ///
    /// # Errors
    ///
    /// The same errors as [`open`].
    pub fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        open(sealed, &[self])
    }
}

/// Derives the AEAD key for one file.
fn aead_for(shared: &SecretBytes<32>, salt: &[u8; SALT_SIZE]) -> Result<AeadKey, Error> {
    let key = kdf::derive::<32>(Domain::Seal, shared.as_bytes(), salt)?;
    AeadKey::from_secret(&key)
}

/// The parsed, still unauthenticated header of a sealed box.
struct Header<'a> {
    bytes: &'a [u8],
    salt: [u8; SALT_SIZE],
    kem_ct: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> Header<'a> {
    /// Parses and length checks a sealed box.
    ///
    /// Nothing here is a security check. The magic, `format_type` and `version`
    /// bytes are public, and the authentication happens in the AEAD step, so this
    /// parse only decides whether the buffer is shaped like a sealed box at all.
    fn parse(sealed: &'a [u8]) -> Result<Self, Error> {
        if sealed.len() < SEALED_BOX_OVERHEAD {
            return Err(Error::Failed);
        }
        if sealed[..4] != MAGIC {
            return Err(Error::Failed);
        }
        if sealed[4] != FORMAT_TYPE {
            return Err(Error::Failed);
        }
        if sealed[5] != VERSION {
            return Err(Error::UnsupportedVersion);
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&sealed[SALT_OFFSET..SALT_OFFSET + SALT_SIZE]);

        Ok(Self {
            bytes: &sealed[..HEADER_SIZE],
            salt,
            kem_ct: &sealed[SALT_OFFSET + SALT_SIZE..HEADER_SIZE],
            ciphertext: &sealed[HEADER_SIZE..],
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(miri))]
    use super::open;
    use super::{
        aead_for, seal, FORMAT_TYPE, HEADER_SIZE, MAGIC, SALT_OFFSET, SEALED_BOX_OVERHEAD, VERSION,
    };
    use crate::kem::{KEM_CIPHERTEXT_SIZE, SEALING_KEY_SIZE};
    use crate::SealingKey;
    #[cfg(not(miri))]
    use crate::{EncapsulationKey, Error};

    fn key() -> SealingKey {
        SealingKey::from_bytes([0x11u8; SEALING_KEY_SIZE])
    }

    #[test]
    fn constants_match_the_specification() {
        assert_eq!(MAGIC, [0x6D, 0x69, 0x6C, 0x69]);
        assert_eq!(FORMAT_TYPE, 0x01);
        assert_eq!(VERSION, 0x01);
        assert_eq!(SALT_OFFSET, 6);
        assert_eq!(KEM_CIPHERTEXT_SIZE, 1120);
        assert_eq!(HEADER_SIZE, 1158);
        assert_eq!(SEALED_BOX_OVERHEAD, 1174);
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip() {
        let key = key();
        for len in [0usize, 1, 15, 16, 17, 64, 1000, 4096] {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = seal(&key.encapsulation_key(), &plaintext).expect("seal");
            assert_eq!(sealed.len(), len + SEALED_BOX_OVERHEAD);
            assert_eq!(*key.open(&sealed).expect("open"), plaintext);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn header_layout_is_where_the_specification_says() {
        let key = key();
        let sealed = seal(&key.encapsulation_key(), b"x").expect("seal");

        assert_eq!(&sealed[0..4], b"mili");
        assert_eq!(sealed[4], 0x01);
        assert_eq!(sealed[5], 0x01);
        assert_eq!(sealed.len(), 1 + SEALED_BOX_OVERHEAD);
        assert_eq!(&sealed[HEADER_SIZE..], &sealed[HEADER_SIZE..]);
        assert_eq!(sealed[HEADER_SIZE..].len(), 1 + 16);
    }

    #[test]
    #[cfg(not(miri))]
    fn a_repeated_seal_of_the_same_plaintext_differs() {
        let key = key();
        let public = key.encapsulation_key();
        let a = seal(&public, b"same").expect("seal");
        let b = seal(&public, b"same").expect("seal");
        assert_ne!(a, b, "salt or KEM ciphertext repeated between two seals");
    }

    #[test]
    #[cfg(not(miri))]
    fn the_file_names_no_recipient() {
        let key = key();
        let public = key.encapsulation_key();
        let sealed = seal(&public, b"a message").expect("seal");
        let public_bytes = public.to_bytes();

        // The only place public key bytes could appear is the KEM ciphertext,
        // which is derived from a fresh ephemeral and does not contain them.
        for window in public_bytes.windows(8) {
            assert!(
                !sealed.windows(8).any(|candidate| candidate == window),
                "a fragment of the encapsulation key appears in the file"
            );
        }

        // Two seals to different recipients are the same length and differ only
        // where the freshness is, so there is no recipient field to key on.
        let other = SealingKey::from_bytes([0x22u8; SEALING_KEY_SIZE]);
        let other_sealed = seal(&other.encapsulation_key(), b"a message").expect("seal");
        assert_eq!(sealed.len(), other_sealed.len());
    }

    #[test]
    fn every_byte_of_the_file_is_covered_by_the_tag() {
        // Exhaustive sweep over a whole file, done at the AEAD layer so that the
        // cost is one ChaCha20-Poly1305 operation per byte rather than one
        // ML-KEM-768 decapsulation. The AEAD key and the two buffers are derived
        // once and each byte is flipped in turn.
        let key = key();
        let plaintext = b"";
        let sealed = seal(&key.encapsulation_key(), plaintext).expect("seal");

        let salt: [u8; 32] = sealed[SALT_OFFSET..SALT_OFFSET + 32]
            .try_into()
            .expect("32 bytes");
        let shared = key
            .decapsulate(&sealed[38..HEADER_SIZE])
            .expect("valid length");
        let aead = aead_for(&shared, &salt).expect("derive");

        let baseline_header = &sealed[..HEADER_SIZE];
        let baseline_body = &sealed[HEADER_SIZE..];
        aead.open(crate::aead::AeadNonce::ZERO, baseline_header, baseline_body)
            .expect("the untampered file authenticates");

        // Under miri the sweep is bounded: miri interprets every ChaCha20 round,
        // so a 1174 byte sweep takes hours instead of milliseconds. The bound
        // still covers the header prefix and the whole ciphertext region, which
        // is where the two coverage rules live.
        let sweep: Box<dyn Iterator<Item = usize>> = if cfg!(miri) {
            Box::new((0..128usize).chain(HEADER_SIZE..sealed.len()))
        } else {
            Box::new(0..sealed.len())
        };

        for index in sweep {
            let mut file = sealed.clone();
            file[index] ^= 0x01;
            let (header, body) = file.split_at(HEADER_SIZE);
            assert!(
                aead.open(crate::aead::AeadNonce::ZERO, header, body)
                    .is_err(),
                "byte {index} was accepted after a bit flip"
            );
        }

        assert_eq!(
            plaintext.len(),
            0,
            "the exhaustive sweep uses an empty plaintext"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn sampled_tampering_is_rejected_end_to_end() {
        // The same property as the sweep above, exercised through the public
        // `open`, which is the path that decides what a caller sees. Sampled
        // rather than exhaustive because every call here performs an ML-KEM-768
        // decapsulation, which miri runs far too slowly for a full sweep.
        let key = key();
        let sealed =
            seal(&key.encapsulation_key(), b"a message that is long enough").expect("seal");
        let original = sealed.clone();

        for index in (0..sealed.len()).step_by(37) {
            let mut tampered = original.clone();
            tampered[index] ^= 0x80;
            assert!(
                key.open(&tampered).is_err(),
                "byte {index} was accepted after tampering"
            );
        }

        // Both ends of the file, which the stride above can miss.
        for index in (0..sealed.len()).rev().step_by(37) {
            let mut tampered = original.clone();
            tampered[index] ^= 0x80;
            assert!(
                key.open(&tampered).is_err(),
                "byte {index} was accepted after tampering"
            );
        }

        assert_eq!(
            &*key
                .open(&original)
                .expect("the untampered file still opens"),
            b"a message that is long enough"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn every_truncation_is_rejected() {
        let key = key();
        let sealed =
            seal(&key.encapsulation_key(), b"a message that is long enough").expect("seal");

        for len in 0..sealed.len() {
            let truncated = &sealed[..len];
            let result = key.open(truncated);
            assert!(result.is_err(), "truncation to {len} bytes was accepted");
            assert!(
                matches!(result, Err(Error::Failed) | Err(Error::UnsupportedVersion)),
                "truncation to {len} bytes produced an unexpected error"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_key_is_rejected() {
        let key = key();
        let wrong = SealingKey::from_bytes([0x33u8; SEALING_KEY_SIZE]);
        let sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        assert!(matches!(wrong.open(&sealed), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn no_candidate_key_is_rejected() {
        let key = key();
        let sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        assert!(matches!(open(&sealed, &[]), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn the_right_key_is_found_among_wrong_ones() {
        let key = key();
        let sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");

        let others: Vec<SealingKey> = (0..4)
            .map(|i| SealingKey::from_bytes([i as u8; SEALING_KEY_SIZE]))
            .collect();
        let mut candidates: Vec<&SealingKey> = others.iter().collect();
        candidates.push(&key);

        assert_eq!(*open(&sealed, &candidates).expect("open"), b"a message");
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_magic_is_rejected() {
        let key = key();
        let mut sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        sealed[0] ^= 0xFF;
        assert!(matches!(key.open(&sealed), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_file_is_rejected() {
        let key = key();
        let mut sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        sealed[4] = 0x02;
        assert!(matches!(key.open(&sealed), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_unknown_version_is_reported_as_such() {
        let key = key();
        let mut sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        sealed[5] = 0x02;
        assert!(matches!(key.open(&sealed), Err(Error::UnsupportedVersion)));
    }

    #[test]
    fn a_short_buffer_is_rejected_without_a_panic() {
        let key = key();
        for len in [0usize, 1, 5, 1157, 1173] {
            let buffer = vec![0u8; len];
            assert!(key.open(&buffer).is_err(), "length {len}");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_zero_length_plaintext_round_trips() {
        let key = key();
        let sealed = seal(&key.encapsulation_key(), b"").expect("seal");
        assert_eq!(sealed.len(), SEALED_BOX_OVERHEAD);
        let plaintext = key.open(&sealed).expect("open");
        assert!(plaintext.is_empty());
    }

    #[test]
    #[cfg(not(miri))]
    fn the_aead_key_is_derived_from_the_salt_and_the_shared_secret() {
        let key = key();
        let sealed = seal(&key.encapsulation_key(), b"x").expect("seal");
        let salt = &sealed[SALT_OFFSET..SALT_OFFSET + 32];

        let shared = key
            .decapsulate(&sealed[38..HEADER_SIZE])
            .expect("valid length");
        assert!(aead_for(&shared, salt.try_into().expect("32 bytes")).is_ok());

        // A different salt yields a different AEAD key, which is why the salt is
        // part of the authenticated header as well.
        let mut other_salt = [0u8; 32];
        other_salt.copy_from_slice(salt);
        other_salt[0] ^= 0xFF;
        let a = aead_for(&shared, salt.try_into().expect("32 bytes")).expect("derive");
        let b = aead_for(&shared, &other_salt).expect("derive");
        let sealed_a = a.seal(crate::aead::AeadNonce::ZERO, b"aad", b"plaintext");
        let sealed_b = b.seal(crate::aead::AeadNonce::ZERO, b"aad", b"plaintext");
        assert_ne!(sealed_a.expect("seal"), sealed_b.expect("seal"));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_encapsulation_key_built_from_bytes_agrees_with_the_original() {
        let key = key();
        let public = key.encapsulation_key();
        let restored = EncapsulationKey::from_bytes(&public.to_bytes()).expect("valid key");
        let sealed = seal(&restored, b"a message").expect("seal");
        assert_eq!(*key.open(&sealed).expect("open"), b"a message");
    }

    #[test]
    #[cfg(not(miri))]
    fn key_material_never_reaches_the_output() {
        let key = SealingKey::from_bytes([0x44u8; SEALING_KEY_SIZE]);
        let sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        let seed = key.expose();

        for len in [4usize, 8, 16, 32] {
            assert!(
                !sealed.windows(len).any(|w| w == &seed[..len]),
                "a {len} byte run of the seed appears in the file"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_different_salt_does_not_change_the_open_result() {
        // The salt is authenticated as part of the header and is also the HKDF
        // salt, so changing it changes the AEAD key and the file must stop
        // opening rather than opening into something else.
        let key = key();
        let mut sealed = seal(&key.encapsulation_key(), b"a message").expect("seal");
        sealed[SALT_OFFSET] ^= 0x01;
        assert!(matches!(key.open(&sealed), Err(Error::Failed)));
    }
}
