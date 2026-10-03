package mili

import (
	"bytes"
	"errors"
	"testing"
)

func mustSealingKey(t *testing.T) SealingKey {
	t.Helper()
	key, err := GenerateSealingKey()
	if err != nil {
		t.Fatalf("GenerateSealingKey: %v", err)
	}
	if len(key) != SealingKeySize {
		t.Fatalf("a sealing key is %d bytes, got %d", SealingKeySize, len(key))
	}
	return key
}

func mustSigningKey(t *testing.T) SigningKey {
	t.Helper()
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	if len(key) != SigningKeySize {
		t.Fatalf("a signing key is %d bytes, got %d", SigningKeySize, len(key))
	}
	return key
}

func mustSymmetricKey(t *testing.T) SymmetricKey {
	t.Helper()
	key, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	return key
}

// TestTheSizesAreTheFormatSizes pins every number this package hands a caller,
// against the format rather than against itself.
func TestTheSizesAreTheFormatSizes(t *testing.T) {
	for _, check := range []struct {
		name string
		got  int
		want int
	}{
		{"SealingKeySize", SealingKeySize, 32},
		{"EncapsulationKeySize", EncapsulationKeySize, 1216},
		{"SigningKeySize", SigningKeySize, 64},
		{"VerifyingKeySize", VerifyingKeySize, 1984},
		{"SignatureSize", SignatureSize, 3379},
		{"SymmetricKeySize", SymmetricKeySize, 32},
		{"SealedBoxOverhead", SealedBoxOverhead, 1174},
	} {
		if check.got != check.want {
			t.Errorf("%s = %d, the format says %d", check.name, check.got, check.want)
		}
	}
}

// TestGeneratedKeysDiffer is the CSPRNG's smoke test, and a check that generation is
// not returning a constant.
func TestGeneratedKeysDiffer(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		key := mustSealingKey(t)
		if seen[string(key)] {
			t.Fatal("GenerateSealingKey repeated")
		}
		seen[string(key)] = true

		signing := mustSigningKey(t)
		if seen[string(signing)] {
			t.Fatal("GenerateSigningKey repeated")
		}
		seen[string(signing)] = true
	}
}

func TestKeyDerivationIsDeterministic(t *testing.T) {
	seed := mustSealingKey(t)
	first, err := EncapsulationKey(seed)
	if err != nil {
		t.Fatalf("EncapsulationKey: %v", err)
	}
	second, err := EncapsulationKey(seed)
	if err != nil {
		t.Fatalf("EncapsulationKey: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two derivations of one seed disagreed")
	}

	signing := mustSigningKey(t)
	firstKey, err := VerifyingKey(signing)
	if err != nil {
		t.Fatalf("VerifyingKey: %v", err)
	}
	secondKey, err := VerifyingKey(signing)
	if err != nil {
		t.Fatalf("VerifyingKey: %v", err)
	}
	if !bytes.Equal(firstKey, secondKey) {
		t.Error("two derivations of one signing seed disagreed")
	}
}

func TestKeyDerivationRejectsAWrongLength(t *testing.T) {
	if _, err := EncapsulationKey([]byte{1, 2, 3}); err == nil {
		t.Error("EncapsulationKey accepted a 3 byte seed")
	}
	if _, err := VerifyingKey([]byte{1, 2, 3}); err == nil {
		t.Error("VerifyingKey accepted a 3 byte seed")
	}
}

// TestSealRoundTrips covers the whole sealed box path at several lengths, including
// the empty one, because a zero length plaintext is the case where a size calculation
// is most likely to be off by the tag.
func TestSealRoundTrips(t *testing.T) {
	seed := mustSealingKey(t)
	recipient, err := EncapsulationKey(seed)
	if err != nil {
		t.Fatalf("EncapsulationKey: %v", err)
	}

	for _, length := range []int{0, 1, 17, 1024, 100_000} {
		plaintext := make([]byte, length)
		for i := range plaintext {
			plaintext[i] = byte(i)
		}

		sealed, err := Seal(recipient, plaintext)
		if err != nil {
			t.Fatalf("length %d: Seal: %v", length, err)
		}
		if len(sealed) != length+SealedBoxOverhead {
			t.Errorf("length %d: sealed to %d bytes, expected %d", length, len(sealed), length+SealedBoxOverhead)
		}
		// Only for a plaintext long enough that finding it is not luck. A single
		// byte appears somewhere in 1175 bytes of ciphertext roughly half the
		// time, and calling that a leak would be a test that fails for the wrong
		// reason.
		if length >= 32 && bytes.Contains(sealed, plaintext) {
			t.Errorf("length %d: the plaintext appears in the file", length)
		}

		opened, err := Open(sealed, seed)
		if err != nil {
			t.Fatalf("length %d: Open: %v", length, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("length %d: the plaintext came back different", length)
		}
	}
}

func TestSealRejectsAWrongRecipientLength(t *testing.T) {
	if _, err := Seal([]byte{1, 2, 3}, []byte("hello")); err == nil {
		t.Error("Seal accepted a 3 byte encapsulation key")
	}
}

func TestOpenTriesEveryCandidate(t *testing.T) {
	right := mustSealingKey(t)
	recipient, err := EncapsulationKey(right)
	if err != nil {
		t.Fatalf("EncapsulationKey: %v", err)
	}
	sealed, err := Seal(recipient, []byte("a message"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wrong := []SealingKey{mustSealingKey(t), mustSealingKey(t)}
	opened, err := Open(sealed, append(wrong, right)...)
	if err != nil {
		t.Fatalf("Open with the right key last: %v", err)
	}
	if string(opened) != "a message" {
		t.Errorf("got %q", opened)
	}
}

// TestAWrongKeyAndACorruptFileAreTheSameError is the uniformity claim, checked at the
// level a Go caller actually sees.
func TestAWrongKeyAndACorruptFileAreTheSameError(t *testing.T) {
	seed := mustSealingKey(t)
	recipient, err := EncapsulationKey(seed)
	if err != nil {
		t.Fatalf("EncapsulationKey: %v", err)
	}
	sealed, err := Seal(recipient, []byte("a message"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wrongKey, err := Open(sealed, mustSealingKey(t))
	if !errors.Is(err, ErrFailed) {
		t.Errorf("a wrong key gave %v, want ErrFailed", err)
	}

	corrupted := append([]byte(nil), sealed...)
	corrupted[len(corrupted)-1] ^= 0x01
	corrupt, err := Open(corrupted, seed)
	if !errors.Is(err, ErrFailed) {
		t.Errorf("a corrupted file gave %v, want ErrFailed", err)
	}

	if wrongKey != nil || corrupt != nil {
		t.Error("a failed open returned a plaintext")
	}
}

func TestOpenNeedsACandidate(t *testing.T) {
	if _, err := Open([]byte("mili\x01\x01")); err == nil {
		t.Error("Open with no candidates was accepted")
	}
	if _, err := OpenStream([]byte("mili\x02\x01"), 1024); err == nil {
		t.Error("OpenStream with no candidates was accepted")
	}
}

func TestOpenRejectsAWrongCandidateLength(t *testing.T) {
	if _, err := Open([]byte("mili\x01\x01"), SealingKey{1, 2, 3}); err == nil {
		t.Error("Open accepted a 3 byte candidate")
	}
}

// TestStreamsRoundTrip runs a message across several chunk boundaries, because the
// chunk loop is where a stream differs from a sealed box and where an off-by-one
// would hide.
func TestStreamsRoundTrips(t *testing.T) {
	seed := mustSealingKey(t)

	for _, length := range []int{0, 1, 1024, 65535, 65536, 65537, 200_000} {
		plaintext := make([]byte, length)
		for i := range plaintext {
			plaintext[i] = byte(i * 7)
		}

		stream, err := SealStream(seed, plaintext)
		if err != nil {
			t.Fatalf("length %d: SealStream: %v", length, err)
		}

		opened, err := OpenStream(stream, length+1, seed)
		if err != nil {
			t.Fatalf("length %d: OpenStream: %v", length, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("length %d: the plaintext came back different", length)
		}
	}
}

// TestThePlaintextBoundIsEnforced is the check behind docs/THREAT_MODEL.md section 5.7: a
// stream is not bounded by the format, so the caller's bound is the only defence.
func TestThePlaintextBoundIsEnforced(t *testing.T) {
	seed := mustSealingKey(t)
	plaintext := make([]byte, 40_000)
	stream, err := SealStream(seed, plaintext)
	if err != nil {
		t.Fatalf("SealStream: %v", err)
	}

	if _, err := OpenStream(stream, 1000, seed); !errors.Is(err, ErrFailed) {
		t.Errorf("a bound below the plaintext gave %v, want ErrFailed", err)
	}
	if _, err := OpenStream(stream, len(plaintext), seed); err != nil {
		t.Errorf("a bound equal to the plaintext gave %v, want nil", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	seed := mustSigningKey(t)
	verifying, err := VerifyingKey(seed)
	if err != nil {
		t.Fatalf("VerifyingKey: %v", err)
	}

	signature, err := Sign(seed, []byte("a message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signature) != SignatureSize {
		t.Fatalf("a signature is %d bytes, got %d", SignatureSize, len(signature))
	}

	if err := Verify(verifying, []byte("a message"), signature); err != nil {
		t.Errorf("a good signature did not verify: %v", err)
	}
	if err := Verify(verifying, []byte("another message"), signature); !errors.Is(err, ErrFailed) {
		t.Errorf("a signature for another message gave %v, want ErrFailed", err)
	}
}

// TestSignIsDeterministic is what docs/THREAT_MODEL.md section 3.6 records: ml-dsa 0.1.1
// signs deterministically, so there is no second nonce to leak.
func TestSignIsDeterministic(t *testing.T) {
	seed := mustSigningKey(t)
	first, err := Sign(seed, []byte("a message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := Sign(seed, []byte("a message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two signatures of one message and key differ")
	}
}

// TestTamperedSignaturesAreRefused walks the whole signature, because the composite
// rule means a signature that verifies must have had both halves intact.
func TestTamperedSignaturesAreRefused(t *testing.T) {
	seed := mustSigningKey(t)
	verifying, err := VerifyingKey(seed)
	if err != nil {
		t.Fatalf("VerifyingKey: %v", err)
	}
	original, err := Sign(seed, []byte("a message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for index := 0; index < len(original); index += 211 {
		tampered := append([]byte(nil), original...)
		tampered[index] ^= 0x01
		if err := Verify(verifying, []byte("a message"), tampered); !errors.Is(err, ErrFailed) {
			t.Fatalf("byte %d of a tampered signature verified", index)
		}
	}
}

func TestVerifyRejectsATruncatedSignature(t *testing.T) {
	seed := mustSigningKey(t)
	verifying, err := VerifyingKey(seed)
	if err != nil {
		t.Fatalf("VerifyingKey: %v", err)
	}
	signature, err := Sign(seed, []byte("a message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, length := range []int{0, 1, SignatureSize - 1} {
		if err := Verify(verifying, []byte("a message"), signature[:length]); !errors.Is(err, ErrFailed) {
			t.Errorf("a %d byte signature gave %v, want ErrFailed", length, err)
		}
	}
}

// A negative maximumPlaintext converts to a huge C.size_t, which mili-core
// reads as "no bound", so -1 would silently remove the only defence a hostile
// stream has. Rust and C cannot express the mistake; this layer can, so this
// layer checks it.
func TestOpenStreamRejectsNegativeMaximumPlaintext(t *testing.T) {
	seed, err := GenerateSealingKey()
	if err != nil {
		t.Fatalf("GenerateSealingKey: %v", err)
	}
	stream, err := SealStream(seed, []byte("a message"))
	if err != nil {
		t.Fatalf("SealStream: %v", err)
	}

	for _, bound := range []int{-1, -1024} {
		if _, err := OpenStream(stream, bound, seed); err == nil {
			t.Errorf("OpenStream with maximumPlaintext %d was accepted", bound)
		}
	}

	// Zero is legitimate and means "an empty message only", so it must reach the
	// library and fail there rather than being refused here.
	if _, err := OpenStream(stream, 0, seed); err == nil {
		t.Error("OpenStream with maximumPlaintext 0 opened a non-empty stream")
	}
}
