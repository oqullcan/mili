package mili

/*
#include "mili.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// A BackupEntry is one key recovered from a [Backup], with the identifier that names
// it.
type BackupEntry struct {
	// KeyID is the 16 byte identifier, as SPEC.md section 11 computes it. It is
	// public, and it is there so a caller can tell whether the backup it opened is
	// the one it meant without opening anything twice.
	KeyID []byte

	// Key is the key material, typed. Exactly one of the three is non-empty, and
	// [BackupEntry.Kind] says which.
	Key BackupKey
}

// BackupKey holds a recovered key together with its kind.
//
// It is a struct rather than three separate return values so that a caller cannot
// pair a sealing key with a signing key's length, and so that the kind travels with
// the bytes instead of being re-derived from them.
type BackupKey struct {
	// Sealing is non-empty when the entry held a sealing key.
	Sealing SealingKey
	// Signing is non-empty when the entry held a signing key.
	Signing SigningKey
	// Symmetric is non-empty when the entry held a symmetric key.
	Symmetric SymmetricKey
}

// The payload types, which are what a backup entry's type byte means.
const (
	payloadSealing   = PayloadSealing
	payloadSigning   = PayloadSigning
	payloadSymmetric = PayloadSymmetric
)

// Kind names which of a [BackupKey]'s fields is set.
type Kind int

// The kinds of key a [Backup] can hold.
const (
	// KindSealing is an X-Wing sealing key.
	KindSealing Kind = payloadSealing
	// KindSigning is a composite signing key.
	KindSigning Kind = payloadSigning
	// KindSymmetric is a symmetric key.
	KindSymmetric Kind = payloadSymmetric
)

// String names the kind, for a log line.
func (k Kind) String() string {
	switch k {
	case KindSealing:
		return "sealing"
	case KindSigning:
		return "signing"
	case KindSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// Kind reports which field of the key is set.
func (e BackupEntry) Kind() Kind {
	switch {
	case len(e.Key.Sealing) > 0:
		return KindSealing
	case len(e.Key.Signing) > 0:
		return KindSigning
	case len(e.Key.Symmetric) > 0:
		return KindSymmetric
	default:
		return 0
	}
}

// A Backup holds several keys under one password, as SPEC.md section 8 defines.
//
// A backup is the answer to a question mili cannot answer for itself: losing a key.
// Every failure in this library returns the same error, so mili cannot notice that a
// key is gone. A key whose only copy is one key file has no recovery path, and this
// is the path.
//
// Argon2 runs once for the whole container, whatever the number of keys, so a backup
// of a hundred keys costs the same derivation as a backup of one.
type Backup []byte

// A BackupBuilder collects keys and turns them into a [Backup].
//
// The builder is what keeps the type information alive to the boundary: each Add
// method takes a typed key and writes the payload type itself, so a caller cannot
// store a symmetric key without saying so and cannot mislabel one.
type BackupBuilder struct {
	entries [][]byte
}

// NewBackupBuilder returns an empty builder.
func NewBackupBuilder() *BackupBuilder {
	return &BackupBuilder{}
}

// AddSealingKey adds a sealing key.
func (b *BackupBuilder) AddSealingKey(key SealingKey) error {
	if len(key) != SealingKeySize {
		return fmt.Errorf("mili: a sealing key is %d bytes, got %d", SealingKeySize, len(key))
	}
	b.entries = append(b.entries, entry(payloadSealing, key))
	return nil
}

// AddSigningKey adds a signing key.
func (b *BackupBuilder) AddSigningKey(key SigningKey) error {
	if len(key) != SigningKeySize {
		return fmt.Errorf("mili: a signing key is %d bytes, got %d", SigningKeySize, len(key))
	}
	b.entries = append(b.entries, entry(payloadSigning, key))
	return nil
}

// AddSymmetricKey adds a symmetric key.
//
// It is accepted and it round trips, and there is still no mili operation that will
// do anything with one. See [GenerateSymmetricKey].
func (b *BackupBuilder) AddSymmetricKey(key SymmetricKey) error {
	if len(key) != SymmetricKeySize {
		return fmt.Errorf("mili: a symmetric key is %d bytes, got %d", SymmetricKeySize, len(key))
	}
	b.entries = append(b.entries, entry(payloadSymmetric, key))
	return nil
}

func entry(payloadType int, key []byte) []byte {
	out := make([]byte, 0, len(key)+1)
	out = append(out, byte(payloadType))
	return append(out, key...)
}

// Build writes the container. Two keys with the same identifier are refused: a backup
// that holds the same key twice is a backup whose contents a reader cannot describe.
func (b *BackupBuilder) Build(password []byte) (Backup, error) {
	if len(b.entries) == 0 {
		return nil, fmt.Errorf("mili: a backup needs at least one key")
	}

	candidates := pack(b.entries)

	// A generous bound rather than an exact one, so that a caller does not have to
	// compute a size it would get wrong. The length mili actually used comes back
	// through `written`.
	perEntry := 16 + 1 + 4 + 4 + 1 + 4 + SigningKeySize
	out := make([]byte, 48+16+len(b.entries)*perEntry)
	var written C.size_t
	dataPtr, _ := candidates.dataPointer()
	lengthsPtr, count := candidates.lengthsPointer()
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_backup_create(
		dataPtr, lengthsPtr, count,
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	result, err := deliver(code, out, written)
	if err != nil {
		return nil, err
	}
	return Backup(result), nil
}

// Open opens a backup and returns its keys, in the order they were stored.
//
// Every entry carries its identifier and its kind, so a caller can check what it got
// before it uses any of it.
func (b Backup) Open(password []byte) ([]BackupEntry, error) {
	out := make([]byte, len(b))
	var written C.size_t
	backupPtr, backupLen := pointerFor(b)
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_backup_open(
		backupPtr, backupLen,
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	raw, err := deliver(code, out, written)
	if err != nil {
		return nil, err
	}

	var entries []BackupEntry
	for offset := 0; offset < len(raw); {
		// A 16 byte identifier and a one byte type, at minimum.
		if len(raw)-offset < 17 {
			return nil, ErrFailed
		}
		keyID := raw[offset : offset+16]
		payloadType := int(raw[offset+16])
		offset += 17

		var keyLen int
		switch payloadType {
		case payloadSealing:
			keyLen = SealingKeySize
		case payloadSigning:
			keyLen = SigningKeySize
		case payloadSymmetric:
			keyLen = SymmetricKeySize
		default:
			return nil, ErrFailed
		}
		if len(raw)-offset < keyLen {
			return nil, ErrFailed
		}

		entry := BackupEntry{KeyID: append([]byte(nil), keyID...)}
		body := append([]byte(nil), raw[offset:offset+keyLen]...)
		switch payloadType {
		case payloadSealing:
			entry.Key.Sealing = SealingKey(body)
		case payloadSigning:
			entry.Key.Signing = SigningKey(body)
		case payloadSymmetric:
			entry.Key.Symmetric = SymmetricKey(body)
		}
		entries = append(entries, entry)
		offset += keyLen
	}
	return entries, nil
}

// Bytes returns the container's bytes, for writing to storage.
func (b Backup) Bytes() []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// BackupInfo is what a backup container says about itself, read without a
// password.
//
// Every field comes from the unauthenticated header, so it describes what the file
// claims rather than what it is. The point of asking before opening is cost:
// opening runs Argon2id at 64 MiB, and a caller handed an arbitrary file should not
// pay that before knowing whether it is a mili backup at all.
type BackupInfo struct {
	// MCost is the Argon2id memory cost in kibibytes.
	MCost uint32
	// TCost is the Argon2id iteration count.
	TCost uint32
	// PCost is the Argon2id lane count.
	PCost uint32
	// EntryCount is how many keys the header claims.
	EntryCount uint32
}

// Info reports what the container claims, without a password and without running a
// derivation.
//
// It is the operation the README listed for a backup container as "inspect" for
// several releases before it existed.
func (b Backup) Info() (BackupInfo, error) {
	var out [16]C.uint8_t
	bPtr, bLen := pointerFor(b)
	if code := C.mili_backup_info(bPtr, bLen, &out[0], C.size_t(len(out))); code != C.MILI_OK {
		return BackupInfo{}, translate(code)
	}
	read := func(offset int) uint32 {
		return uint32(out[offset]) | uint32(out[offset+1])<<8 |
			uint32(out[offset+2])<<16 | uint32(out[offset+3])<<24
	}
	return BackupInfo{
		MCost:      read(0),
		TCost:      read(4),
		PCost:      read(8),
		EntryCount: read(12),
	}, nil
}

// KeyID computes the 16 byte identifier a backup entry carries, for a key of the
// given kind.
//
// [BackupEntry.KeyID] and this are the two halves of the workflow
// SPEC.md section 11 describes for checking that a backup holds the keys it is
// meant to. Only the first half existed before: a caller could read the
// identifiers out of a backup but had no way to compute the expected one for a key
// it held, so the two could not be compared.
func KeyID(key BackupKey) ([]byte, error) {
	// Exactly one field is set, which is what [BackupKey.Kind] names, so the
	// switch picks the same one the library did rather than re-deriving it from a
	// length.
	var (
		payloadType C.uint8_t
		raw         []byte
	)
	switch {
	case len(key.Sealing) > 0:
		payloadType, raw = C.MILI_PAYLOAD_SEALING, key.Sealing
	case len(key.Signing) > 0:
		payloadType, raw = C.MILI_PAYLOAD_SIGNING, key.Signing
	case len(key.Symmetric) > 0:
		payloadType, raw = C.MILI_PAYLOAD_SYMMETRIC, key.Symmetric
	default:
		return nil, fmt.Errorf("mili: KeyID needs a key, got an empty one")
	}

	var out [16]C.uint8_t
	rawPtr, _ := pointerFor(raw)
	if code := C.mili_key_id(payloadType, rawPtr, &out[0]); code != C.MILI_OK {
		return nil, translate(code)
	}
	return C.GoBytes(unsafe.Pointer(&out[0]), C.int(len(out))), nil
}

// ID returns the identifier of a sealing key, as SPEC.md section 11 defines it.
func (k SealingKey) ID() ([]byte, error) { return KeyID(BackupKey{Sealing: k}) }

// ID returns the identifier of a signing key, as SPEC.md section 11 defines it.
func (k SigningKey) ID() ([]byte, error) { return KeyID(BackupKey{Signing: k}) }

// ID returns the identifier of a symmetric key, as SPEC.md section 11 defines it.
func (k SymmetricKey) ID() ([]byte, error) { return KeyID(BackupKey{Symmetric: k}) }
