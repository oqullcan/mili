package mili

/*
#include "mili.h"
*/
import "C"

import "fmt"

// Seal encrypts a message to one encapsulation key and returns the sealed box.
//
// A sealed box is anonymous: it names no recipient and carries no key identifier,
// so it is the same length for every recipient and for every message of a given
// length. Nothing here pads and nothing hides the length. See docs/THREAT_MODEL.md
// sections 5.3 and 5.4.
func Seal(recipient, plaintext []byte) ([]byte, error) {
	if len(recipient) != EncapsulationKeySize {
		return nil, fmt.Errorf("mili: an encapsulation key is %d bytes, got %d", EncapsulationKeySize, len(recipient))
	}

	out := make([]byte, len(plaintext)+SealedBoxOverhead)
	var written C.size_t
	recipientPtr, recipientLen := pointerFor(recipient)
	plaintextPtr, plaintextLen := pointerFor(plaintext)
	code := C.mili_seal(
		recipientPtr, recipientLen,
		plaintextPtr, plaintextLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return deliver(code, out, written)
}

// Open decrypts a sealed box with the first candidate sealing key that opens it.
//
// A sealed box names no recipient, so a caller with several keys passes them all and
// mili tries them in order. That is also the cost: every candidate is an ML-KEM-768
// decapsulation, so a program with many keys pays for each one it does not need. A
// caller that knows which key it sealed to should pass only that.
//
// The error for a key that does not open the box is [ErrFailed], the same as for a
// corrupted box, so that neither is an oracle.
func Open(sealed []byte, keys ...SealingKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("mili: open needs at least one candidate key")
	}
	for index, key := range keys {
		if len(key) != SealingKeySize {
			return nil, fmt.Errorf("mili: candidate %d is %d bytes, a sealing key is %d", index, len(key), SealingKeySize)
		}
	}

	entries := make([][]byte, len(keys))
	for index, key := range keys {
		entries[index] = key
	}
	candidates := pack(entries)
	out := make([]byte, len(sealed))
	var written C.size_t
	sealedPtr, sealedLen := pointerFor(sealed)
	dataPtr, _ := candidates.dataPointer()
	lengthsPtr, count := candidates.lengthsPointer()
	code := C.mili_open(
		sealedPtr, sealedLen,
		dataPtr, lengthsPtr, count,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return deliver(code, out, written)
}

// SealStream encrypts a message into a stream.
//
// A stream is for a file too large to hold in memory, and this function takes the
// whole message anyway, because a Go caller with a large file should write chunks
// through mili-ffi's `mili_seal_stream` directly rather than read a file into one
// slice. What this function is for is a message that fits: it is the whole protocol
// in one call, and it produces exactly the bytes `mili_seal_stream` would.
func SealStream(seed SealingKey, plaintext []byte) ([]byte, error) {
	if len(seed) != SealingKeySize {
		return nil, fmt.Errorf("mili: a sealing key is %d bytes, got %d", SealingKeySize, len(seed))
	}

	overhead := streamOverhead(len(plaintext))
	out := make([]byte, len(plaintext)+overhead)
	var written C.size_t
	plaintextPtr, plaintextLen := pointerFor(plaintext)
	code := C.mili_seal_stream(
		(*C.uint8_t)(unsafePointer(seed)),
		plaintextPtr, plaintextLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return deliver(code, out, written)
}

// OpenStream decrypts a stream with the first candidate sealing key that opens it.
//
// maximumPlaintext bounds how much plaintext this call will accept from a file it
// does not trust. It is the only defence a hostile stream has: a stream's length is
// not authenticated until its chunks are read, so a caller that passes a bound it
// believes in is what stops a large file becoming a large allocation. mili does not
// rate limit opens and does not bound a stream itself; see docs/THREAT_MODEL.md
// section 5.7.
func OpenStream(stream []byte, maximumPlaintext int, keys ...SealingKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("mili: open needs at least one candidate key")
	}
	// A negative int converts to a huge C.size_t, which mili-core reads as "no
	// bound at all", so -1 would silently remove the only defence a hostile
	// stream has against exhausting memory. Rust takes a usize and cannot
	// express this mistake; C takes a size_t and cannot either. This is the only
	// layer where it is expressible, so this is the layer that checks it.
	if maximumPlaintext < 0 {
		return nil, fmt.Errorf("mili: maximumPlaintext must not be negative, got %d", maximumPlaintext)
	}
	for index, key := range keys {
		if len(key) != SealingKeySize {
			return nil, fmt.Errorf("mili: candidate %d is %d bytes, a sealing key is %d", index, len(key), SealingKeySize)
		}
	}

	entries := make([][]byte, len(keys))
	for index, key := range keys {
		entries[index] = key
	}
	candidates := pack(entries)
	out := make([]byte, len(stream))
	var written C.size_t
	streamPtr, streamLen := pointerFor(stream)
	dataPtr, _ := candidates.dataPointer()
	lengthsPtr, count := candidates.lengthsPointer()
	code := C.mili_open_stream(
		streamPtr, streamLen,
		dataPtr, lengthsPtr, count,
		C.size_t(maximumPlaintext),
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)),
		&written,
	)
	return deliver(code, out, written)
}

// Sign signs a message with a composite signing key seed.
//
// The signature is valid only if both component signatures verify, as docs/SPEC.md section
// 6 requires: one component alone is not a mili signature and this library will not
// accept one.
//
// Signing is randomised on the ML-DSA half, so the same key and message give
// different bytes every time. The signature is still the same length and verifies the
// same way; see docs/THREAT_MODEL.md section 3.6.
func Sign(seed SigningKey, message []byte) ([]byte, error) {
	if len(seed) != SigningKeySize {
		return nil, fmt.Errorf("mili: a signing key is %d bytes, got %d", SigningKeySize, len(seed))
	}

	out := make([]byte, SignatureSize)
	var written C.size_t
	messagePtr, messageLen := pointerFor(message)
	code := C.mili_sign(
		(*C.uint8_t)(unsafePointer(seed)),
		messagePtr, messageLen,
		(*C.uint8_t)(unsafePointer(out)), C.size_t(len(out)), &written,
	)
	return deliver(code, out, written)
}

// Verify checks a composite signature over a message.
//
// [ErrFailed] covers a signature that does not verify, a truncated one, one for
// another message and one whose other component verifies: mili does not say which,
// because a caller that could tell would have an oracle on the signature scheme.
func Verify(verifying, message, signature []byte) error {
	if len(verifying) != VerifyingKeySize {
		return fmt.Errorf("mili: a verifying key is %d bytes, got %d", VerifyingKeySize, len(verifying))
	}

	messagePtr, messageLen := pointerFor(message)
	signaturePtr, signatureLen := pointerFor(signature)
	return translate(C.mili_verify(
		(*C.uint8_t)(unsafePointer(verifying)),
		messagePtr, messageLen,
		signaturePtr, signatureLen,
	))
}
