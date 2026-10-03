package mili

/*
#include "mili.h"
*/
import "C"

import "fmt"

// The payload types a key file reports, as docs/SPEC.md section 7 writes them.
const (
	// PayloadSealing is a key file holding a [SealingKey].
	PayloadSealing = 1
	// PayloadSigning is a key file holding a [SigningKey].
	PayloadSigning = 2
	// PayloadSymmetric is a key file holding a [SymmetricKey].
	PayloadSymmetric = 3
)

// keyFileOverhead is what a key file adds to the key it holds: a 41 byte header and a
// 16 byte tag.
const keyFileOverhead = 41 + 16

// A KeyFile wraps one key under one password, as docs/SPEC.md section 7 defines.
//
// A key file is a byte string. It authenticates itself, so a caller can keep it in a
// file, in a database row or in a version control system without mili caring, and it
// is the only mili format that turns a passphrased secret into something at rest.
//
// The key's kind is not an argument to [WrapSealingKeyFile] or [WrapSigningKeyFile]
// because it is in the type of the key. A sealing key and a symmetric key are both
// 32 bytes, so anything that inferred the kind from the length would get it wrong for
// one of them, silently and in a way nothing downstream would catch.
type KeyFile []byte

// WrapSealingKeyFile puts a [SealingKey] under a password.
func WrapSealingKeyFile(key SealingKey, password []byte) (KeyFile, error) {
	if len(key) != SealingKeySize {
		return nil, fmt.Errorf("mili: a sealing key is %d bytes, got %d", SealingKeySize, len(key))
	}
	out := make([]byte, SealingKeySize+keyFileOverhead)
	var written C.size_t
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_key_file_wrap_sealing(
		(*C.uint8_t)(unsafePointer(key)),
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return wrapResult(code, out, written)
}

// WrapSigningKeyFile puts a [SigningKey] under a password.
func WrapSigningKeyFile(key SigningKey, password []byte) (KeyFile, error) {
	if len(key) != SigningKeySize {
		return nil, fmt.Errorf("mili: a signing key is %d bytes, got %d", SigningKeySize, len(key))
	}
	out := make([]byte, SigningKeySize+keyFileOverhead)
	var written C.size_t
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_key_file_wrap_signing(
		(*C.uint8_t)(unsafePointer(key)),
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return wrapResult(code, out, written)
}

func wrapResult(code C.int32_t, out []byte, written C.size_t) (KeyFile, error) {
	result, err := deliver(code, out, written)
	if err != nil {
		return nil, err
	}
	return KeyFile(result), nil
}

// PayloadType reports which kind of key this file holds, without a password.
//
// This authenticates nothing. Any bytes have a payload type at a fixed offset, so
// this is a property of the header rather than of the contents, and a caller that
// treats it as proof of anything is wrong. It is here so a program with several keys
// can decide which of [KeyFile.UnwrapSealing] and [KeyFile.UnwrapSigning] to call.
func (f KeyFile) PayloadType() int {
	var out C.size_t
	filePtr, fileLen := pointerFor(f)
	if err := translate(C.mili_key_file_payload_type(filePtr, fileLen, &out)); err != nil {
		return 0
	}
	return int(out)
}

// UnwrapSealing opens a key file that holds a [SealingKey].
//
// A file that holds a signing key is refused, rather than returned as bytes the
// caller would then use as a sealing seed. The error is [ErrFailed], the same as a
// wrong password, because the two are indistinguishable from outside.
func (f KeyFile) UnwrapSealing(password []byte) (SealingKey, error) {
	return f.unwrap(PayloadSealing, password)
}

// unwrap opens a key file that holds the given kind of key.
//
// The kind is passed to the library rather than used here to pick an output buffer,
// because that is the version of this that was wrong once already: a signing key file
// opened into a 32 byte buffer was reported as a buffer problem, and a sealing key
// file opened into a 64 byte buffer was reported as success, handing back a sealing
// seed typed as a signing key. The library checks the file's payload type against
// what the caller asked for.
func (f KeyFile) unwrap(expected int, password []byte) ([]byte, error) {
	var size int
	switch expected {
	case PayloadSealing:
		size = SealingKeySize
	case PayloadSigning:
		size = SigningKeySize
	case PayloadSymmetric:
		size = SymmetricKeySize
	default:
		return nil, fmt.Errorf("mili: %d is not a payload type", expected)
	}

	out := make([]byte, size)
	var written C.size_t
	filePtr, fileLen := pointerFor(f)
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_key_file_unwrap(
		filePtr, fileLen,
		C.uint8_t(expected),
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return deliver(code, out, written)
}

// UnwrapSigning opens a key file that holds a [SigningKey].
func (f KeyFile) UnwrapSigning(password []byte) (SigningKey, error) {
	result, err := f.unwrap(PayloadSigning, password)
	if err != nil {
		return nil, err
	}
	return SigningKey(result), nil
}

// UnwrapSymmetric opens a key file that holds a [SymmetricKey].
//
// This is the other half of [WrapSymmetricKeyFile]. A [SymmetricKey] is not tied to
// a public-key algorithm, so it has no format that encrypts with it — docs/SPEC.md
// section 12.0 records that as a decision — but a key file stores the key itself
// under a password, and mili-core and the C ABI both read one. Without this the Go
// binding could write a symmetric key file and not read it back.
//
// The password is the only thing protecting such a file, which is also true of the
// other two kinds. What is different is that a symmetric key file cannot be
// recovered from anywhere else, so losing the password loses the key rather than
// only the ability to read it with a public key that still exists elsewhere.
func (f KeyFile) UnwrapSymmetric(password []byte) (SymmetricKey, error) {
	result, err := f.unwrap(PayloadSymmetric, password)
	if err != nil {
		return nil, err
	}
	return SymmetricKey(result), nil
}

// Rotate rewrites this key file under the same password with a fresh salt, as docs/SPEC.md
// section 12.1 defines rotation.
//
// It returns a new file and leaves the receiver alone, so a rotation whose copy never
// finished does not destroy the only copy of a key.
//
// Changing a password is not rotation: it is unwrapping and wrapping again.
func (f KeyFile) Rotate(password []byte) (KeyFile, error) {
	out := make([]byte, len(f))
	var written C.size_t
	filePtr, fileLen := pointerFor(f)
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_key_file_rotate(
		filePtr, fileLen,
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return wrapResult(code, out, written)
}

// Bytes returns the file's bytes, for writing to storage.
func (f KeyFile) Bytes() []byte {
	out := make([]byte, len(f))
	copy(out, f)
	return out
}

// WrapSymmetricKeyFile wraps a symmetric key under a password.
//
// This was missing while UnwrapKeyFile already handled PayloadSymmetric, so a
// caller could open a symmetric key file but not create one. A symmetric key could
// also be put in a backup, so before this there was a way to store one and no way
// to wrap one directly.
func WrapSymmetricKeyFile(key SymmetricKey, password []byte) (KeyFile, error) {
	if len(key) != SymmetricKeySize {
		return nil, fmt.Errorf("mili: a symmetric key is %d bytes, got %d", SymmetricKeySize, len(key))
	}
	out := make([]byte, SymmetricKeySize+keyFileOverhead)
	var written C.size_t
	passwordPtr, passwordLen := pointerFor(password)
	code := C.mili_key_file_wrap_symmetric(
		(*C.uint8_t)(unsafePointer(key)),
		passwordPtr, passwordLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return wrapResult(code, out, written)
}
