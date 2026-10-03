// Package mili is the Go binding for mili, a parameter selection and a
// misuse-resistant wrapper around third-party cryptography crates.
//
// # What this package is
//
// A thin layer over the C ABI in mili-ffi. Every operation here is one call across
// that boundary, and none of them adds a policy of its own: there is no algorithm
// selection, no retry, no padding, no key derivation of a different kind, and no
// option that a version of docs/SPEC.md does not define. One suite per format version.
//
// # Errors
//
// mili does not say why something failed. A wrong key, a wrong password, a
// corrupted file, a truncated file, a hostile length and an unknown payload type are
// all [ErrFailed]. This package does not add distinctions mili does not make, and it
// does not wrap them with a message naming a format, because a message that says
// "wrong password" or "wrong recipient" is an oracle for whoever is on the other end
// of it.
//
// Three errors are not [ErrFailed], and each is a statement about the caller's own
// data or allocation rather than about its secrecy:
//
//   - [ErrUnsupportedVersion] means the file names a format version this build does
//     not implement. A caller with a file from a newer mili needs to be able to say
//     so.
//   - [ErrBufferTooSmall] means the output buffer was too small. Nothing was written
//     and nothing about the data was examined.
//   - [ErrInternal] means mili caught a panic at the boundary, which mili's own
//     claims say should not be reachable. It exists so that such a thing is visible
//     rather than looking like a wrong password forever.
//
// # Keys
//
// A [SealingKey], a [SigningKey] and a [SymmetricKey] are byte slices, so they can be
// stored and passed to a key file or a backup. Those bytes are the private key. Go's
// garbage collector will copy them, a [fmt.Stringer] or a logging library may pick
// them up, and nothing will zero them. Use [KeyFile] or [Backup] for a key at rest,
// and treat a copy in memory as the caller's to clear.
//
// # What this package does not do
//
// It does not clear the caller's memory, it does not authenticate a public key, and
// it does not hide file sizes or traffic patterns. See DISCLAIMER.md in the mili
// repository, which is the document that says what mili does not claim, and
// docs/THREAT_MODEL.md, which says what is out of scope.
package mili

/*
#cgo CFLAGS: -I${SRCDIR}/../../mili-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lmili_ffi
#include <stdlib.h>
#include "mili.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// unsafePointer is the one place this package converts a Go slice to a C pointer.
//
// It is a function rather than an inline conversion so that the rule is in one
// place, and it returns nil for an empty slice rather than taking the address of an
// element that is not there. An empty output buffer is not an unusual thing to end
// up with: a caller who sizes from a wrong constant gets one, and `&b[0]` on it is
// an index out of range panic rather than a clean error from the library.
//
// The other half of the rule is that the slice must stay alive for the duration of
// the C call. Every caller here keeps it in a local until the call returns, and a
// slice header is not pinned by cgo, so this is the standard cgo discipline rather
// than something mili adds.
func unsafePointer(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}

// The error codes, as mili.h defines them.
var (
	// ErrFailed is every failure mili does not distinguish. See the package
	// documentation for why it is not broken up.
	ErrFailed = errors.New("mili: operation failed")

	// ErrUnsupportedVersion means the data names a format version this build does
	// not implement.
	ErrUnsupportedVersion = errors.New("mili: unsupported format version")

	// ErrInternal means mili caught a panic at the C boundary, which its own
	// claims say should be unreachable.
	ErrInternal = errors.New("mili: internal error")

	// ErrIO is returned for an I/O failure on a caller-supplied stream. This
	// package does not expose the streams that produce it; it is here so that the
	// mapping is total.
	ErrIO = errors.New("mili: i/o error")

	// ErrBufferTooSmall means the output buffer was too small. Nothing was written
	// and no data was examined, so this is a sizing mistake and not a failure of
	// the operation.
	ErrBufferTooSmall = errors.New("mili: output buffer too small")
)

// The key file and backup payload types are declared in keyfile.go, next to the
// operations that use them.
// translate maps a C error code to a Go error.
//
// A code this build does not recognise becomes [ErrInternal] rather than
// [ErrFailed]: a code from a newer library that this binding does not know about is
// a fact about the binding being out of date, not a fact about the caller's data.
func translate(code C.int32_t) error {
	switch code {
	case C.MILI_OK:
		return nil
	case C.MILI_FAILED:
		return ErrFailed
	case C.MILI_UNSUPPORTED_VERSION:
		return ErrUnsupportedVersion
	case C.MILI_INTERNAL:
		return ErrInternal
	case C.MILI_IO:
		return ErrIO
	case C.MILI_BUFFER_TOO_SMALL:
		return ErrBufferTooSmall
	default:
		return ErrInternal
	}
}

// The sizes mili reports, asked for once.
//
// Each is a call into the library rather than a Go constant, so a binding compiled
// against one library and run against another uses the linked library's numbers. The
// three key sizes are Go constants instead, because they are part of this package's
// type definitions and a caller compares against them at compile time.
var (
	// EncapsulationKeySize is the length of a public sealing key.
	EncapsulationKeySize = sizeOf(miliEncapsulationKeySize)
	// VerifyingKeySize is the length of a composite verifying key.
	VerifyingKeySize = sizeOf(miliVerifyingKeySize)
	// SignatureSize is the length of a whole composite signature, mili's six byte
	// header included.
	SignatureSize = sizeOf(miliSignatureSize)
	// SealedBoxOverhead is what a sealed box adds to a plaintext.
	SealedBoxOverhead = sizeOf(miliSealedBoxOverhead)
)

// Go wrappers for the size functions, so that sizeOf can take them as values.
//
// cgo does not produce a Go func value for a C function, so each one is spelled out.
// They are unexported: a caller reads [SealingKeySize] rather than calling the
// library itself, and the comment above each says what it is for.
func miliEncapsulationKeySize(out *C.size_t) C.int32_t { return C.mili_encapsulation_key_size(out) }
func miliVerifyingKeySize(out *C.size_t) C.int32_t     { return C.mili_verifying_key_size(out) }
func miliSignatureSize(out *C.size_t) C.int32_t        { return C.mili_signature_size(out) }
func miliSealedBoxOverhead(out *C.size_t) C.int32_t    { return C.mili_sealed_box_overhead(out) }

func sizeOf(function func(out *C.size_t) C.int32_t) int {
	var out C.size_t
	if err := translate(function(&out)); err != nil {
		// A size function that fails is a broken library, and there is no useful
		// size to fall back to. Panicking here is the one place this package
		// panics, and it happens during package initialisation, before a caller
		// can hold anything this package returned.
		panic(fmt.Sprintf("mili: a size function failed: %v", err))
	}
	return int(out)
}

// streamOverhead is the number of bytes a stream adds to a plaintext of n bytes.
func streamOverhead(plaintextLen int) int {
	var out C.size_t
	if err := translate(miliStreamOverhead(C.size_t(plaintextLen), &out)); err != nil {
		panic(fmt.Sprintf("mili: mili_stream_overhead failed: %v", err))
	}
	return int(out)
}

// pointerFor returns the pointer and length a C caller would legitimately pass for
// b.
//
// An empty slice becomes a nil pointer and a zero length, which is how "no input" is
// spelled across this boundary. Passing the pointer of an empty slice with a
// separate non-zero length would be a dangling pointer with a length attached, and
// the library would read past it.
func pointerFor(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// packed describes an array of entries laid out back to back, each preceded by its
// length, which is how mili_backup_create takes a list of keys.
type packed struct {
	data    []byte
	lengths []C.size_t
}

// pack lays entries out the way mili_backup_create expects.
func pack(entries [][]byte) packed {
	var out packed
	for _, entry := range entries {
		out.data = append(out.data, entry...)
		out.lengths = append(out.lengths, C.size_t(len(entry)))
	}
	return out
}

// dataPointer returns the pointer and length for the packed entries. An empty one is
// nil and zero, as above.
func (p packed) dataPointer() (*C.uint8_t, C.size_t) {
	if len(p.data) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&p.data[0])), C.size_t(len(p.data))
}

// lengthsPointer returns the pointer and count for the length array. The count is the
// number of entries, not a byte length, because that is what the library wants for
// this argument.
func (p packed) lengthsPointer() (*C.size_t, C.size_t) {
	if len(p.lengths) == 0 {
		return nil, 0
	}
	return &p.lengths[0], C.size_t(len(p.lengths))
}

func miliStreamOverhead(plaintextLen C.size_t, out *C.size_t) C.int32_t {
	return C.mili_stream_overhead(plaintextLen, out)
}

// deliver hands a caller-supplied buffer to a function that fills it, and returns
// the bytes it wrote.
//
// The capacity is checked against the length mili reports, so a sizing mistake is
// an error rather than a silent truncation, and the returned slice is a copy rather
// than a view of the caller's buffer.
func deliver(code C.int32_t, out []byte, written C.size_t) ([]byte, error) {
	if err := translate(code); err != nil {
		return nil, err
	}
	if int(written) > len(out) {
		// The library reported more than it was given, which is a memory safety
		// bug on the other side of the boundary rather than a caller error.
		return nil, fmt.Errorf("mili: the library reported %d bytes into a %d byte buffer", int(written), len(out))
	}
	result := make([]byte, int(written))
	copy(result, out[:written])
	return result, nil
}
