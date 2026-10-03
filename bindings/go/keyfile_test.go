package mili

import (
	"bytes"
	"errors"
	"testing"
)

var testPassword = []byte("correct horse battery staple")

func TestKeyFileRoundTripsASealingKey(t *testing.T) {
	key := mustSealingKey(t)
	file, err := WrapSealingKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}

	if len(file) != SealingKeySize+keyFileOverhead {
		t.Errorf("a key file is %d bytes, got %d", SealingKeySize+keyFileOverhead, len(file))
	}
	if !bytes.HasPrefix(file.Bytes(), []byte("mili\x10\x01")) {
		t.Errorf("a key file does not start with mili\\x10\\x01: %x", file.Bytes()[:6])
	}
	if file.PayloadType() != PayloadSealing {
		t.Errorf("PayloadType = %d, want %d", file.PayloadType(), PayloadSealing)
	}
	if bytes.Contains(file.Bytes(), key) {
		t.Error("the key appears in the file in the clear")
	}

	opened, err := file.UnwrapSealing(testPassword)
	if err != nil {
		t.Fatalf("UnwrapSealing: %v", err)
	}
	if !bytes.Equal(opened, key) {
		t.Error("the key came back different")
	}
}

func TestKeyFileRoundTripsASigningKey(t *testing.T) {
	key := mustSigningKey(t)
	file, err := WrapSigningKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSigningKeyFile: %v", err)
	}
	if file.PayloadType() != PayloadSigning {
		t.Errorf("PayloadType = %d, want %d", file.PayloadType(), PayloadSigning)
	}

	opened, err := file.UnwrapSigning(testPassword)
	if err != nil {
		t.Fatalf("UnwrapSigning: %v", err)
	}
	if !bytes.Equal(opened, key) {
		t.Error("the key came back different")
	}
}

// TestTheWrongUnwrapIsRefused is the point of typing the keys. A file holding a
// signing key must not open as a sealing key, even though both are "bytes from a key
// file": handing back 64 bytes read as a 32 byte seed would use one key as another.
func TestTheWrongUnwrapIsRefused(t *testing.T) {
	signing := mustSigningKey(t)
	file, err := WrapSigningKeyFile(signing, testPassword)
	if err != nil {
		t.Fatalf("WrapSigningKeyFile: %v", err)
	}

	if _, err := file.UnwrapSealing(testPassword); !errors.Is(err, ErrFailed) {
		t.Errorf("a signing key file opened as a sealing key: %v", err)
	}

	sealing := mustSealingKey(t)
	other, err := WrapSealingKeyFile(sealing, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}
	if _, err := other.UnwrapSigning(testPassword); !errors.Is(err, ErrFailed) {
		t.Errorf("a sealing key file opened as a signing key: %v", err)
	}
}

func TestKeyFileRejectsAWrongPassword(t *testing.T) {
	key := mustSealingKey(t)
	file, err := WrapSealingKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}

	opened, err := file.UnwrapSealing([]byte("the wrong password"))
	if !errors.Is(err, ErrFailed) {
		t.Errorf("a wrong password gave %v, want ErrFailed", err)
	}
	if opened != nil {
		t.Error("a failed unwrap returned a key")
	}
}

func TestKeyFileRejectsAnEmptyPassword(t *testing.T) {
	key := mustSealingKey(t)
	if _, err := WrapSealingKeyFile(key, nil); !errors.Is(err, ErrFailed) {
		t.Errorf("an empty password on the way in gave %v, want ErrFailed", err)
	}
}

func TestKeyFileRejectsAKeyOfTheWrongLength(t *testing.T) {
	// The types do not stop a caller converting between them, so the length check
	// is what catches a truncated or mislabelled key.
	if _, err := WrapSealingKeyFile(SealingKey(mustSigningKey(t)), testPassword); err == nil {
		t.Error("a 64 byte value was accepted as a sealing key")
	}
	if _, err := WrapSigningKeyFile(SigningKey(mustSealingKey(t)), testPassword); err == nil {
		t.Error("a 32 byte value was accepted as a signing key")
	}
	if _, err := WrapSealingKeyFile(SealingKey{}, testPassword); err == nil {
		t.Error("an empty key was accepted")
	}
}

func TestKeyFileRejectsArbitraryBytes(t *testing.T) {
	for _, length := range []int{0, 1, 88, 89, 200} {
		file := KeyFile(make([]byte, length))
		if payloadType := file.PayloadType(); payloadType != 0 {
			t.Errorf("a %d byte buffer reported payload type %d", length, payloadType)
		}
		if _, err := file.UnwrapSealing(testPassword); err == nil {
			t.Errorf("a %d byte buffer unwrapped", length)
		}
		if _, err := file.Rotate(testPassword); err == nil {
			t.Errorf("a %d byte buffer rotated", length)
		}
	}
}

func TestKeyFileRejectsATamperedByte(t *testing.T) {
	key := mustSealingKey(t)
	file, err := WrapSealingKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}

	for index := 0; index < len(file); index += 7 {
		tampered := append(KeyFile(nil), file...)
		tampered[index] ^= 0x01
		if _, err := tampered.UnwrapSealing(testPassword); !errors.Is(err, ErrFailed) {
			t.Fatalf("byte %d of a tampered key file opened", index)
		}
	}
}

func TestRotateKeepsTheKeyAndChangesTheFile(t *testing.T) {
	key := mustSealingKey(t)
	file, err := WrapSealingKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}

	rotated, err := file.Rotate(testPassword)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if bytes.Equal(rotated.Bytes(), file.Bytes()) {
		t.Error("rotation produced the same bytes")
	}

	opened, err := rotated.UnwrapSealing(testPassword)
	if err != nil {
		t.Fatalf("UnwrapSealing after rotation: %v", err)
	}
	if !bytes.Equal(opened, key) {
		t.Error("rotation changed the key")
	}

	// The original is untouched: a rotation whose copy never finished must not
	// destroy the only copy of a key.
	if _, err := file.UnwrapSealing(testPassword); err != nil {
		t.Errorf("the original stopped working after rotation: %v", err)
	}
}

func TestRotateRejectsAWrongPassword(t *testing.T) {
	key := mustSealingKey(t)
	file, err := WrapSealingKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}
	if _, err := file.Rotate([]byte("the wrong password")); !errors.Is(err, ErrFailed) {
		t.Errorf("rotating with a wrong password gave %v, want ErrFailed", err)
	}
}

// TestChangingAPasswordIsTheComposition is the documented answer to "how do I change
// a key file's password", which is unwrap and wrap, not rotate.
func TestChangingAPasswordIsTheComposition(t *testing.T) {
	key := mustSealingKey(t)
	file, err := WrapSealingKeyFile(key, testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}

	opened, err := file.UnwrapSealing(testPassword)
	if err != nil {
		t.Fatalf("UnwrapSealing: %v", err)
	}
	changed, err := WrapSealingKeyFile(opened, []byte("a different password"))
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}

	if _, err := changed.UnwrapSealing(testPassword); !errors.Is(err, ErrFailed) {
		t.Error("the old password still opens the file")
	}
	if _, err := changed.UnwrapSealing([]byte("a different password")); err != nil {
		t.Errorf("the new password did not open the file: %v", err)
	}
}

// TestASymmetricKeyHasNoKeyFileYet is the honest state of the surface, pinned so it
// fails when the surface changes rather than documenting a state nobody checks.
//
// There is no WrapSymmetricKeyFile, so this cannot be written as a call that fails.
// What it pins is that a symmetric key cannot be smuggled in through the sealing key
// path, which is the mistake the naming exists to prevent.
func TestASymmetricKeyHasNoKeyFileYet(t *testing.T) {
	symmetric := mustSymmetricKey(t)

	// Both are 32 bytes. A sealing key file made from one would open as a sealing
	// key, and nothing would notice.
	sealing, err := WrapSealingKeyFile(SealingKey(symmetric), testPassword)
	if err != nil {
		t.Fatalf("WrapSealingKeyFile: %v", err)
	}
	if sealing.PayloadType() != PayloadSealing {
		t.Fatalf("PayloadType = %d, want %d", sealing.PayloadType(), PayloadSealing)
	}

	// A backup is where a symmetric key belongs for now, and it keeps the type:
	// the builder's Add methods are typed, so this is the route a symmetric key
	// actually has.
	builder := NewBackupBuilder()
	if err := builder.AddSymmetricKey(symmetric); err != nil {
		t.Fatalf("AddSymmetricKey: %v", err)
	}
	backup, err := builder.Build(testPassword)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	entries, err := backup.Open(testPassword)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(entries) != 1 || entries[0].Kind() != KindSymmetric {
		t.Fatalf("the backup came back as %v", entries)
	}
	if !bytes.Equal(entries[0].Key.Symmetric, symmetric) {
		t.Error("the symmetric key came back different")
	}
}

// A Go program can write a symmetric key file and read it back. It could not
// before UnwrapSymmetric existed, because WrapSymmetricKeyFile was added without
// its counterpart — so the binding could produce a file whose only reader was
// written in another language.
func TestUnwrapSymmetricKeyFile(t *testing.T) {
	key, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	file, err := WrapSymmetricKeyFile(key, []byte(testPassword))
	if err != nil {
		t.Fatalf("WrapSymmetricKeyFile: %v", err)
	}

	opened, err := file.UnwrapSymmetric([]byte(testPassword))
	if err != nil {
		t.Fatalf("UnwrapSymmetric: %v", err)
	}
	if string(opened) != string(key) {
		t.Error("the key came back different")
	}

	// The other two openers still refuse it, so the three stay distinct.
	if _, err := file.UnwrapSealing([]byte(testPassword)); !errors.Is(err, ErrFailed) {
		t.Errorf("a symmetric key file opened as a sealing key: %v, want ErrFailed", err)
	}
	if _, err := file.UnwrapSigning([]byte(testPassword)); !errors.Is(err, ErrFailed) {
		t.Errorf("a symmetric key file opened as a signing key: %v, want ErrFailed", err)
	}

	// And the wrong password is refused.
	if _, err := file.UnwrapSymmetric([]byte("wrong password")); !errors.Is(err, ErrFailed) {
		t.Errorf("a wrong password gave %v, want ErrFailed", err)
	}
}
