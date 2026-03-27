package pqctls

import (
	"crypto/rand"
	"testing"
)

func TestNamedGroupCodePoints(t *testing.T) {
	if MLKEM768 != 0x0768 {
		t.Errorf("MLKEM768 code point = %#x, want 0x0768", MLKEM768)
	}
	if MLKEM1024 != 0x1024 {
		t.Errorf("MLKEM1024 code point = %#x, want 0x1024", MLKEM1024)
	}
	if X25519MLKEM768 != 0x6399 {
		t.Errorf("X25519MLKEM768 code point = %#x, want 0x6399", X25519MLKEM768)
	}
	if SecP256r1MLKEM768 != 0x639A {
		t.Errorf("SecP256r1MLKEM768 code point = %#x, want 0x639A", SecP256r1MLKEM768)
	}
}

func TestNamedGroupFromCodePoint(t *testing.T) {
	ng, ok := NamedGroupFromCodePoint(0x6399)
	if !ok || ng != X25519MLKEM768 {
		t.Errorf("NamedGroupFromCodePoint(0x6399) = %v, %v", ng, ok)
	}
	_, ok = NamedGroupFromCodePoint(0xFFFF)
	if ok {
		t.Error("NamedGroupFromCodePoint(0xFFFF) should return false")
	}
}

func TestMLKEM768KeyExchangeRoundtrip(t *testing.T) {
	ks, err := GenerateKeyShare(MLKEM768, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyShare: %v", err)
	}
	if len(ks.PublicKeyShare) != KeyShareSize(MLKEM768) {
		t.Errorf("key share size = %d, want %d", len(ks.PublicKeyShare), KeyShareSize(MLKEM768))
	}

	resp, err := CompleteKeyExchange(MLKEM768, ks.PublicKeyShare, 0, rand.Reader)
	if err != nil {
		t.Fatalf("CompleteKeyExchange: %v", err)
	}

	ss, err := RecoverSharedSecret(MLKEM768, ks.PrivateKey, resp.ResponseKeyShare, 0, 0)
	if err != nil {
		t.Fatalf("RecoverSharedSecret: %v", err)
	}
	if ss != resp.SharedSecret {
		t.Error("shared secrets do not match")
	}
}

func TestX25519MLKEM768KeyExchangeRoundtrip(t *testing.T) {
	ks, err := GenerateKeyShare(X25519MLKEM768, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyShare: %v", err)
	}
	if len(ks.PublicKeyShare) != KeyShareSize(X25519MLKEM768) {
		t.Errorf("key share size = %d, want %d", len(ks.PublicKeyShare), KeyShareSize(X25519MLKEM768))
	}

	resp, err := CompleteKeyExchange(X25519MLKEM768, ks.PublicKeyShare, ks.ClassicalEKSize, rand.Reader)
	if err != nil {
		t.Fatalf("CompleteKeyExchange: %v", err)
	}

	ss, err := RecoverSharedSecret(X25519MLKEM768, ks.PrivateKey, resp.ResponseKeyShare,
		ks.ClassicalDKSize, resp.ClassicalCTSize)
	if err != nil {
		t.Fatalf("RecoverSharedSecret: %v", err)
	}
	if ss != resp.SharedSecret {
		t.Error("shared secrets do not match for X25519MLKEM768")
	}
}

func TestAllGroupsKeyShareSizes(t *testing.T) {
	for _, group := range AllNamedGroups {
		ks, err := GenerateKeyShare(group, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyShare(%v): %v", group, err)
		}
		expected := KeyShareSize(group)
		if len(ks.PublicKeyShare) != expected {
			t.Errorf("group %v: key share size = %d, want %d", group, len(ks.PublicKeyShare), expected)
		}
	}
}

func TestSignatureAlgorithmCodePoints(t *testing.T) {
	if MLDSA44 != 0x0904 {
		t.Errorf("MLDSA44 = %#x, want 0x0904", MLDSA44)
	}
	if MLDSA65 != 0x0905 {
		t.Errorf("MLDSA65 = %#x, want 0x0905", MLDSA65)
	}
	if MLDSA87 != 0x0906 {
		t.Errorf("MLDSA87 = %#x, want 0x0906", MLDSA87)
	}
	if MLDSA65Ed25519 != 0x0907 {
		t.Errorf("MLDSA65Ed25519 = %#x, want 0x0907", MLDSA65Ed25519)
	}
	if MLDSA87Ed25519 != 0x0908 {
		t.Errorf("MLDSA87Ed25519 = %#x, want 0x0908", MLDSA87Ed25519)
	}
}

func TestMLDSA65SignVerify(t *testing.T) {
	kp := GenerateSigningKey(MLDSA65)
	hash := []byte("test handshake transcript hash for CertificateVerify")
	sig := SignHandshake(MLDSA65, kp.SK, hash)
	if !VerifyHandshake(MLDSA65, kp.PK, hash, sig) {
		t.Error("valid signature should verify")
	}
}

func TestCompositeMlDsa65Ed25519SignVerify(t *testing.T) {
	kp := GenerateSigningKey(MLDSA65Ed25519)
	hash := []byte("composite signature handshake hash")
	sig := SignHandshake(MLDSA65Ed25519, kp.SK, hash)
	if !VerifyHandshake(MLDSA65Ed25519, kp.PK, hash, sig) {
		t.Error("valid composite signature should verify")
	}
}

func TestWrongKeyFailsVerification(t *testing.T) {
	kp1 := GenerateSigningKey(MLDSA65)
	kp2 := GenerateSigningKey(MLDSA65)
	hash := []byte("test hash")
	sig := SignHandshake(MLDSA65, kp1.SK, hash)
	if VerifyHandshake(MLDSA65, kp2.PK, hash, sig) {
		t.Error("wrong key should fail verification")
	}
}

func TestCipherSuiteLookupByID(t *testing.T) {
	cs := CipherSuiteByID(0x13010768)
	if cs == nil {
		t.Fatal("cipher suite not found")
	}
	if cs.Name != "TLS_AES_128_GCM_SHA256_MLKEM768" {
		t.Errorf("name = %s, want TLS_AES_128_GCM_SHA256_MLKEM768", cs.Name)
	}

	cs2 := CipherSuiteByID(0x13026399)
	if cs2 == nil {
		t.Fatal("cipher suite not found")
	}
	if cs2.Name != "TLS_AES_256_GCM_SHA384_X25519MLKEM768" {
		t.Errorf("name = %s, want TLS_AES_256_GCM_SHA384_X25519MLKEM768", cs2.Name)
	}

	if CipherSuiteByID(0xDEADBEEF) != nil {
		t.Error("unknown ID should return nil")
	}
}

func TestCipherSuiteDefinitions(t *testing.T) {
	cs := TLS_AES_128_GCM_SHA256_MLKEM768
	if cs.AEAD != AES128GCMSHA256 {
		t.Errorf("AEAD = %v", cs.AEAD)
	}
	if cs.KeyExchange != MLKEM768 {
		t.Errorf("KeyExchange = %v", cs.KeyExchange)
	}
	if cs.Signature != MLDSA65 {
		t.Errorf("Signature = %v", cs.Signature)
	}
}
