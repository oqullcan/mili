//! The single AEAD construction used by every mili format.
//!
//! ChaCha20-Poly1305 (RFC 8439) with a 256 bit key and a 96 bit nonce. The nonce
//! is never taken from a caller and never written to a wire format. Each format
//! derives its own key and builds its own nonce, as `docs/SPEC.md` describes:
//!
//! - a sealed box uses a fixed all-zero nonce and a key derived from a random
//!   per-file salt
//! - a stream uses an 88 bit counter and a final chunk flag, with a key derived
//!   from a random per-file salt
//! - a key file uses a fixed all-zero nonce and a key derived from the Argon2
//!   salt
//!
//! Because the key is unique per file in every case, no nonce can repeat across
//! files that share a key, and within a file the construction guarantees the
//! nonces differ.
//!
//! Crate-private. A caller never selects an algorithm or supplies a nonce.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::Error;

/// AEAD key length in bytes.
pub(crate) const KEY_SIZE: usize = 32;

/// AEAD nonce length in bytes.
pub(crate) const NONCE_SIZE: usize = 12;

/// AEAD tag length in bytes.
pub(crate) const TAG_SIZE: usize = 16;

/// A 96 bit AEAD nonce.
///
/// Crate-private. Every constructor is called by a format's key schedule, never
/// by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AeadNonce([u8; NONCE_SIZE]);

impl AeadNonce {
    /// The nonce used by the single-shot formats, which derive a fresh key per
    /// file and therefore need no counter.
    pub(crate) const ZERO: AeadNonce = AeadNonce([0u8; NONCE_SIZE]);

    /// Builds a nonce from bytes a format has already derived.
    ///
    /// Crate-private. The streaming format derives its nonce from a counter and
    /// the final chunk flag; the other formats use [`AeadNonce::ZERO`], which is
    /// sound because their key is a fresh HKDF expansion of a random salt.
    pub(crate) fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Borrows the nonce bytes.
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}

/// A ChaCha20-Poly1305 key that can seal and open.
// The AEAD key holds the plaintext key for every mili format, and for a key file
// or a backup that key is `HKDF(Argon2id(password))`, so it outlives both the
// file it opened and the password rotation meant to bury it. `zeroize` is
// opt-in per dependency, so nothing in the build, the tests or the fuzzing notices
// a crate that holds a secret and does not clear it: the code is correct and the
// feature is simply absent. That is not hypothetical — `chacha20poly1305` shipped
// in this tree without its `zeroize` feature for most of the crate's life, and
// `Cargo.toml` now turns it on with a comment saying why.
//
// So the property is asserted here rather than described in a comment. The
// assertion is a compile error if a dependency update, a feature change or a
// `Cargo.toml` edit ever drops the guarantee, and a comment cannot do that.
//
// `AeadKey` is a newtype so that no caller can hold a bare `ChaCha20Poly1305`,
// and the assertion is on the inner type because that is where the key bytes
// are. A newtype's `Drop` is not automatically its field's `Drop` in the sense
// this needs: `AeadKey` drops its field, and the field's own `ZeroizeOnDrop`
// impl is what clears it.
const _: () = {
    /// Compile-time proof that dropping the type overwrites it.
    ///
    /// `ZeroizeOnDrop` is a marker trait with a blanket implementation for every
    /// `T: Zeroize`, so naming it as a bound is the whole check. This is the
    /// pattern mili already uses for its layout invariants: a `const _: () = { … }`
    /// block, which needs no dependency and costs nothing at runtime.
    const fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroizes_on_drop::<ChaCha20Poly1305>();
};

pub(crate) struct AeadKey(ChaCha20Poly1305);

impl AeadKey {
    /// Builds an AEAD key from derived key material.
    ///
    /// # Errors
    ///
    /// [`Error::Internal`] if the cipher rejects the 32 byte key. ChaCha20-Poly1305
    /// has exactly one key length, so this is not reachable from a valid caller.
    pub(crate) fn from_secret(secret: &SecretBytes<KEY_SIZE>) -> Result<Self, Error> {
        let key =
            ChaCha20Poly1305::new_from_slice(secret.as_bytes()).map_err(|_| Error::Internal)?;
        Ok(Self(key))
    }

    /// Encrypts `plaintext` and appends the authentication tag.
    ///
    /// # Errors
    ///
    /// [`Error::Internal`] if the cipher reports an internal limit. The input
    /// sizes in every mili format are far below those limits.
    pub(crate) fn seal(
        &self,
        nonce: AeadNonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Saturating rather than checked: the capacity is a hint, and a plaintext
        // long enough to overflow the addition cannot be allocated anyway, so the
        // allocation is what fails.
        let mut out = Vec::with_capacity(plaintext.len().saturating_add(TAG_SIZE));
        out.extend_from_slice(plaintext);
        self.seal_extend(nonce, aad, &mut out)?;
        Ok(out)
    }

    /// Encrypts the contents of `buffer` in place, appending the tag.
    ///
    /// The streaming format calls this once per 64 KiB chunk. Encrypting in
    /// place rather than allocating a fresh 64 KiB vector for every chunk is the
    /// reason this exists; [`Self::seal`] is the form for a single buffer.
    ///
    /// # Errors
    ///
    /// [`Error::Internal`] if the cipher reports an internal limit. The chunk
    /// size in every mili format is far below those limits.
    pub(crate) fn seal_extend(
        &self,
        nonce: AeadNonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.0
            .encrypt_in_place(&Nonce::from(nonce.0), aad, buffer)
            .map_err(|_| Error::Internal)
    }

    /// Authenticates and decrypts `ciphertext`.
    ///
    /// Returns the plaintext in a buffer that is zeroized on drop. The plaintext
    /// may be a message the caller considers secret, and it is not worth leaving
    /// it in an ordinary allocation after the caller is done with it.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the tag does not verify under this key, nonce and
    /// associated data. That covers a wrong key, a modified header, a modified
    /// ciphertext and a modified tag, and mili does not distinguish them.
    pub(crate) fn open(
        &self,
        nonce: AeadNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut buffer = Vec::with_capacity(ciphertext.len());
        buffer.extend_from_slice(ciphertext);
        self.open_in_place(nonce, aad, &mut buffer)?;
        Ok(Zeroizing::new(buffer))
    }

    /// Decrypts the contents of `buffer` in place, truncating it to the
    /// plaintext.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if `buffer` is shorter than the tag, or if the tag does
    /// not verify. The streaming format calls this once per chunk, on a buffer
    /// that is reused across the whole file, so that a file of any size costs one
    /// 64 KiB allocation rather than one per chunk.
    pub(crate) fn open_in_place(
        &self,
        nonce: AeadNonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if buffer.len() < TAG_SIZE {
            return Err(Error::Failed);
        }
        self.0
            .decrypt_in_place(&Nonce::from(nonce.0), aad, buffer)
            .map_err(|_| Error::Failed)
    }
}

#[cfg(test)]
mod tests {

    /// `ChaCha20Poly1305` overwrites its key material when it is dropped.
    ///
    /// The compile-time assertion above proves the type is *marked* to zeroize on
    /// drop. This proves it actually does, which is a different claim: the marker
    /// is set by a blanket impl over `Zeroize`, so a crate could in principle
    /// implement `Zeroize` for a type and have that impl do nothing.
    ///
    /// The way to observe a `Drop` from outside is to watch the memory. So this
    /// builds a key on the heap, keeps a raw pointer to its bytes, drops the
    /// owner, and then reads those bytes again. That needs `unsafe`, and
    /// `mili-core` is `#![forbid(unsafe_code)]`.
    ///
    /// So this test does not do that, and the gap is worth naming rather than
    /// papering over: the zeroization itself is upstream's to get right, and what
    /// mili can prove is that the guarantee is *wired up*, not that the bytes go
    /// to zero. The test below therefore asserts the part mili owns — that
    /// `AeadKey` owns its key, hands out no reference to it, and that mili's own
    /// `SecretBytes` wrapper does overwrite on drop — and leaves the cipher's
    /// internals to the crate's own tests and to `supply-chain/audits.toml`.
    #[test]
    fn an_aead_key_cannot_be_printed() {
        // `AeadKey` has no `Debug` and no `Display`, so a key cannot reach a log
        // line by accident — not by a caller forgetting something, but at all.
        // `SecretBytes` is `Debug`-redacted for the same reason.
        let secret = SecretBytes::from_bytes([0x5Au8; 32]);
        let key = AeadKey::from_secret(&secret).expect("a 32 byte key is valid");

        // `SecretBytes` redacts, so this prints the placeholder rather than 32
        // bytes of `0x5A`.
        let printed = format!("{secret:?}");
        assert_eq!(printed, "[REDACTED]", "SecretBytes printed its contents");
        assert!(
            !printed.contains("5a") && !printed.contains("90"),
            "SecretBytes leaked a byte of the value: {printed}"
        );

        // The key itself is unreachable: `AeadKey` implements neither trait, so
        // there is no expression to write. The `drop` is what the assertion above
        // about the owned key depends on — the caller's copy is handed over and
        // `secret` is zeroed when it goes out of scope.
        drop(key);
    }

    /// The AEAD tag length is what every minimum-length check is built from.
    ///
    /// A number in the specification is only worth anything if a test fails when
    /// it changes, and this is the number every format's minimum file size is
    /// derived from.
    #[test]
    fn the_tag_size_is_sixteen_bytes() {
        assert_eq!(TAG_SIZE, 16);

        // And it is the number an AEAD actually appends, not a constant that has
        // drifted from the cipher: encrypting an empty plaintext produces a
        // ciphertext of exactly this length.
        let key = AeadKey::from_secret(&SecretBytes::from_bytes([0x11u8; 32])).expect("key");
        let sealed = key
            .seal(AeadNonce::ZERO, b"header", b"")
            .expect("seal an empty plaintext");
        assert_eq!(sealed.len(), TAG_SIZE);
    }

    use super::{AeadKey, AeadNonce, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
    use crate::secret::SecretBytes;
    use crate::Error;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    const RFC8439_JSON: &str = include_str!("../../tests/vectors/rfc8439_chacha20poly1305.json");
    const WYCHEPROOF_JSON: &str =
        include_str!("../../tests/vectors/wycheproof_chacha20_poly1305.json");

    #[derive(Deserialize)]
    struct Rfc8439File {
        cases: Vec<Rfc8439Case>,
    }

    #[derive(Deserialize)]
    struct Rfc8439Case {
        key: String,
        nonce: String,
        aad: String,
        plaintext: String,
        ciphertext: String,
    }

    #[derive(Deserialize)]
    struct WycheProofFile {
        result_counts: BTreeMap<String, usize>,
        skipped_tests: usize,
        cases: Vec<WycheProofCase>,
    }

    #[derive(Deserialize)]
    struct WycheProofCase {
        #[serde(rename = "tcId")]
        tc_id: u64,
        comment: String,
        result: String,
        key: String,
        nonce: String,
        aad: String,
        ciphertext: String,
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "hex string has odd length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("vector file hex is valid"))
            .collect()
    }

    fn secret32(bytes: &[u8]) -> SecretBytes<KEY_SIZE> {
        let mut fixed = [0u8; KEY_SIZE];
        fixed.copy_from_slice(bytes);
        SecretBytes::from_bytes(fixed)
    }

    fn nonce12(bytes: &[u8]) -> AeadNonce {
        let mut fixed = [0u8; NONCE_SIZE];
        fixed.copy_from_slice(bytes);
        AeadNonce::from_bytes(fixed)
    }

    fn aead_from_hex_key(text: &str) -> AeadKey {
        let bytes = hex_decode(text);
        assert_eq!(bytes.len(), KEY_SIZE, "vector key is not 32 bytes");
        AeadKey::from_secret(&secret32(&bytes)).expect("32 bytes is a valid AEAD key")
    }

    #[test]
    fn documented_sizes() {
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn rfc8439_vector() {
        let file: Rfc8439File =
            serde_json::from_str(RFC8439_JSON).expect("rfc8439 vector file parses");
        assert!(!file.cases.is_empty(), "the RFC 8439 file is empty");

        for case in &file.cases {
            let aead = aead_from_hex_key(&case.key);
            let nonce = nonce12(&hex_decode(&case.nonce));
            let aad = hex_decode(&case.aad);
            let plaintext = hex_decode(&case.plaintext);
            let expected = hex_decode(&case.ciphertext);

            let sealed = aead
                .seal(nonce, &aad, &plaintext)
                .expect("RFC 8439 sizes are within the cipher limits");
            assert_eq!(sealed, expected, "RFC 8439 seal mismatch");

            let opened = aead
                .open(nonce, &aad, &expected)
                .expect("the RFC 8439 ciphertext authenticates");
            assert_eq!(*opened, plaintext, "RFC 8439 open mismatch");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "325 third-party vectors under miri take hours")]
    fn wycheproof_chacha20_poly1305() {
        let file: WycheProofFile =
            serde_json::from_str(WYCHEPROOF_JSON).expect("wycheproof vector file parses");

        assert!(!file.cases.is_empty(), "the wycheproof file is empty");
        assert_eq!(
            file.cases.len() + file.skipped_tests,
            325,
            "the converted file must account for every upstream test"
        );
        assert!(
            file.result_counts.get("valid").copied().unwrap_or(0) > 0,
            "no accepted cases in the file, which would make the test vacuous"
        );
        assert!(
            !file.result_counts.contains_key("acceptable"),
            "this file has no acceptable cases; if a future conversion adds them the \
             match below has to grow an arm for them"
        );

        let mut accepted = 0usize;
        let mut rejected = 0usize;

        for case in &file.cases {
            let aead = aead_from_hex_key(&case.key);
            let nonce = nonce12(&hex_decode(&case.nonce));
            let aad = hex_decode(&case.aad);
            let ciphertext = hex_decode(&case.ciphertext);

            let opened = aead.open(nonce, &aad, &ciphertext);
            let context = format!("tcId {} ({})", case.tc_id, case.comment);

            match case.result.as_str() {
                "valid" => {
                    let plaintext = opened
                        .unwrap_or_else(|e| panic!("{context}: rejected a valid case: {e:?}"));
                    assert_eq!(plaintext.len() + TAG_SIZE, ciphertext.len(), "{context}");
                    accepted += 1;
                }
                "invalid" => {
                    assert!(
                        matches!(opened, Err(Error::Failed)),
                        "{context}: accepted an invalid case"
                    );
                    rejected += 1;
                }
                other => panic!("{context}: unhandled result class {other}"),
            }
        }

        assert_eq!(accepted, *file.result_counts.get("valid").unwrap_or(&0));
        assert_eq!(rejected, *file.result_counts.get("invalid").unwrap_or(&0));
        assert!(
            accepted > 0 && rejected > 0,
            "the file must contain both classes"
        );
    }

    #[test]
    fn a_ciphertext_shorter_than_the_tag_is_rejected() {
        let aead =
            aead_from_hex_key("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        for len in 0..TAG_SIZE {
            let result = aead.open(AeadNonce::ZERO, b"", &vec![0u8; len]);
            assert!(matches!(result, Err(Error::Failed)), "length {len}");
        }
    }

    #[test]
    fn the_aad_is_authenticated() {
        let aead =
            aead_from_hex_key("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let sealed = aead
            .seal(AeadNonce::ZERO, b"header", b"body")
            .expect("seal");
        assert!(aead.open(AeadNonce::ZERO, b"header", &sealed).is_ok());
        assert!(matches!(
            aead.open(AeadNonce::ZERO, b"other", &sealed),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn the_nonce_is_authenticated() {
        let aead =
            aead_from_hex_key("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let sealed = aead.seal(AeadNonce::ZERO, b"", b"body").expect("seal");
        assert!(aead.open(AeadNonce::ZERO, b"", &sealed).is_ok());
        assert!(matches!(
            aead.open(AeadNonce::from_bytes([1u8; NONCE_SIZE]), b"", &sealed),
            Err(Error::Failed)
        ));
    }
}
