//! The bytes every mili file starts with.
//!
//! Magic, format type, version and salt. Two formats share this prefix, the
//! sealed box of `crate::seal` and the stream of `crate::stream`, and both
//! authenticate it. Parsing it in one place is what keeps the two from drifting
//! apart, which would mean a file that one of them accepts and the other
//! misreads.
//!
//! `SPEC.md` section 2 is normative for this layout.

use crate::Error;

/// The magic every mili file starts with.
pub const MAGIC: [u8; 4] = *b"mili";

/// The `version` byte of every mili-v1 file.
pub const VERSION: u8 = 0x01;

/// Offset of the `salt` field.
pub(crate) const SALT_OFFSET: usize = 6;

/// Length of the `salt` field.
pub(crate) const SALT_SIZE: usize = 32;

/// Offset one past the end of the `salt` field.
pub(crate) const SALT_END: usize = SALT_OFFSET + SALT_SIZE;

/// The common prefix, parsed but not yet authenticated.
pub(crate) struct Prefix<'a> {
    /// The 32 byte per-file salt.
    pub(crate) salt: [u8; SALT_SIZE],
    /// Everything after the salt, which is format specific.
    pub(crate) body: &'a [u8],
}

/// Parses and length checks the common prefix.
///
/// `minimum_length` is the smallest total length this format can have, including
/// the prefix. `format_type` selects the format.
///
/// Nothing here is a security check. The magic, `format_type` and `version` bytes
/// are public, and authentication happens in the AEAD step that follows. This
/// function only decides whether the buffer is shaped like this format at all.
pub(crate) fn parse_prefix<'a>(
    file: &'a [u8],
    format_type: u8,
    minimum_length: usize,
) -> Result<Prefix<'a>, Error> {
    if file.len() < minimum_length {
        return Err(Error::Failed);
    }
    if file[..4] != MAGIC {
        return Err(Error::Failed);
    }
    if file[4] != format_type {
        return Err(Error::Failed);
    }
    if file[5] != VERSION {
        return Err(Error::UnsupportedVersion);
    }

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&file[SALT_OFFSET..SALT_END]);
    Ok(Prefix {
        salt,
        body: &file[SALT_END..],
    })
}

/// Appends the common prefix to `out`.
pub(crate) fn write_prefix(out: &mut Vec<u8>, format_type: u8, salt: &[u8; SALT_SIZE]) {
    out.extend_from_slice(&MAGIC);
    out.push(format_type);
    out.push(VERSION);
    out.extend_from_slice(salt);
}

#[cfg(test)]
mod tests {
    use super::{parse_prefix, write_prefix, MAGIC, SALT_END, SALT_OFFSET, SALT_SIZE, VERSION};
    use crate::Error;

    const SEALED_BOX: u8 = 0x01;

    fn file(format_type: u8, version: u8, extra: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(format_type);
        out.push(version);
        out.extend_from_slice(&[7u8; SALT_SIZE]);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn documented_offsets() {
        assert_eq!(MAGIC, [0x6D, 0x69, 0x6C, 0x69]);
        assert_eq!(VERSION, 0x01);
        assert_eq!(SALT_OFFSET, 6);
        assert_eq!(SALT_SIZE, 32);
        assert_eq!(SALT_END, 38);
    }

    #[test]
    fn a_well_formed_prefix_parses() {
        let buffer = file(SEALED_BOX, VERSION, &[1u8, 2, 3]);
        let parsed = parse_prefix(&buffer, SEALED_BOX, SALT_END + 3).expect("parses");
        assert_eq!(parsed.salt, [7u8; SALT_SIZE]);
        assert_eq!(parsed.body, &[1u8, 2, 3]);
    }

    #[test]
    fn a_short_buffer_is_rejected() {
        for len in 0..SALT_END + 3 {
            let buffer = file(SEALED_BOX, VERSION, &[1u8, 2, 3]);
            assert!(
                parse_prefix(&buffer[..len], SEALED_BOX, SALT_END + 3).is_err(),
                "length {len} was accepted"
            );
        }
    }

    #[test]
    fn a_bad_magic_is_rejected() {
        let mut buffer = file(SEALED_BOX, VERSION, &[1u8, 2, 3]);
        buffer[0] ^= 0xFF;
        assert!(matches!(
            parse_prefix(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn a_foreign_format_type_is_rejected() {
        let buffer = file(0x02, VERSION, &[1u8, 2, 3]);
        assert!(matches!(
            parse_prefix(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn an_unknown_version_is_reported_as_such() {
        let buffer = file(SEALED_BOX, 0x02, &[1u8, 2, 3]);
        assert!(matches!(
            parse_prefix(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn the_writer_and_the_parser_agree() {
        let mut out = Vec::new();
        write_prefix(&mut out, SEALED_BOX, &[0xABu8; SALT_SIZE]);
        out.extend_from_slice(b"body");
        assert_eq!(out.len(), SALT_END + 4);

        let parsed = parse_prefix(&out, SEALED_BOX, SALT_END + 4).expect("parses");
        assert_eq!(parsed.salt, [0xABu8; SALT_SIZE]);
        assert_eq!(parsed.body, b"body");
    }
}
