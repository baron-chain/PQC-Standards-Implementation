package composite

import (
	"bytes"
	"testing"
)

func testRoundtrip(t *testing.T, scheme Scheme, name string) {
	t.Helper()
	kp := KeyGen(scheme)
	msg := []byte("Composite signature test: " + name)
	sig := Sign(kp, msg)
	if !Verify(scheme, kp.PK, msg, sig) {
		t.Fatalf("%s: valid signature did not verify", name)
	}
}

func testWrongMessage(t *testing.T, scheme Scheme, name string) {
	t.Helper()
	kp := KeyGen(scheme)
	msg := []byte("Original message " + name)
	sig := Sign(kp, msg)
	if Verify(scheme, kp.PK, []byte("Tampered message"), sig) {
		t.Fatalf("%s: wrong message should not verify", name)
	}
}

func testTamperClassical(t *testing.T, scheme Scheme, name string) {
	t.Helper()
	kp := KeyGen(scheme)
	msg := []byte("Tamper classical " + name)
	sig := Sign(kp, msg)
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	if len(tampered) > 4 {
		tampered[4] ^= 0xFF
	}
	if Verify(scheme, kp.PK, msg, tampered) {
		t.Fatalf("%s: tampered classical sig should not verify", name)
	}
}

func testTamperPQ(t *testing.T, scheme Scheme, name string) {
	t.Helper()
	kp := KeyGen(scheme)
	msg := []byte("Tamper PQ " + name)
	sig := Sign(kp, msg)
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)-1] ^= 0xFF
	if Verify(scheme, kp.PK, msg, tampered) {
		t.Fatalf("%s: tampered PQ sig should not verify", name)
	}
}

func testKeyFormat(t *testing.T, scheme Scheme, name string) {
	t.Helper()
	kp := KeyGen(scheme)
	params := pqParams(scheme)
	expectedPKSize := classicalPKSize(scheme) + params.PKSize
	expectedSKSize := classicalSKSize(scheme) + params.SKSize
	if len(kp.PK) != expectedPKSize {
		t.Fatalf("%s: pk size = %d, want %d", name, len(kp.PK), expectedPKSize)
	}
	if len(kp.SK) != expectedSKSize {
		t.Fatalf("%s: sk size = %d, want %d", name, len(kp.SK), expectedSKSize)
	}
}

func testParseSig(t *testing.T, scheme Scheme, name string) {
	t.Helper()
	kp := KeyGen(scheme)
	msg := []byte("Parse sig test " + name)
	sig := Sign(kp, msg)
	classical, pq, err := ParseSig(sig)
	if err != nil {
		t.Fatalf("%s: ParseSig error: %v", name, err)
	}
	if len(classical) == 0 || len(pq) == 0 {
		t.Fatalf("%s: empty component sig", name)
	}
	// Reconstruct and verify
	reconstructed := bytes.Join([][]byte{sig[:4], classical, pq}, nil)
	if !bytes.Equal(reconstructed, sig) {
		t.Fatalf("%s: reconstructed sig does not match", name)
	}
}

// ML-DSA-65 + Ed25519
func TestRoundtripMlDsa65Ed25519(t *testing.T)      { testRoundtrip(t, MlDsa65Ed25519, "ML-DSA-65+Ed25519") }
func TestWrongMsgMlDsa65Ed25519(t *testing.T)        { testWrongMessage(t, MlDsa65Ed25519, "ML-DSA-65+Ed25519") }
func TestTamperClassicalMlDsa65Ed25519(t *testing.T)  { testTamperClassical(t, MlDsa65Ed25519, "ML-DSA-65+Ed25519") }
func TestTamperPQMlDsa65Ed25519(t *testing.T)         { testTamperPQ(t, MlDsa65Ed25519, "ML-DSA-65+Ed25519") }
func TestKeyFormatMlDsa65Ed25519(t *testing.T)        { testKeyFormat(t, MlDsa65Ed25519, "ML-DSA-65+Ed25519") }
func TestParseSigMlDsa65Ed25519(t *testing.T)         { testParseSig(t, MlDsa65Ed25519, "ML-DSA-65+Ed25519") }

// ML-DSA-65 + ECDSA-P256
func TestRoundtripMlDsa65EcdsaP256(t *testing.T)     { testRoundtrip(t, MlDsa65EcdsaP256, "ML-DSA-65+ECDSA-P256") }
func TestWrongMsgMlDsa65EcdsaP256(t *testing.T)      { testWrongMessage(t, MlDsa65EcdsaP256, "ML-DSA-65+ECDSA-P256") }
func TestTamperClassicalMlDsa65EcdsaP256(t *testing.T) { testTamperClassical(t, MlDsa65EcdsaP256, "ML-DSA-65+ECDSA-P256") }
func TestTamperPQMlDsa65EcdsaP256(t *testing.T)       { testTamperPQ(t, MlDsa65EcdsaP256, "ML-DSA-65+ECDSA-P256") }
func TestKeyFormatMlDsa65EcdsaP256(t *testing.T)      { testKeyFormat(t, MlDsa65EcdsaP256, "ML-DSA-65+ECDSA-P256") }

// ML-DSA-87 + Ed25519
func TestRoundtripMlDsa87Ed25519(t *testing.T)       { testRoundtrip(t, MlDsa87Ed25519, "ML-DSA-87+Ed25519") }
func TestWrongMsgMlDsa87Ed25519(t *testing.T)         { testWrongMessage(t, MlDsa87Ed25519, "ML-DSA-87+Ed25519") }
func TestTamperClassicalMlDsa87Ed25519(t *testing.T)   { testTamperClassical(t, MlDsa87Ed25519, "ML-DSA-87+Ed25519") }
func TestTamperPQMlDsa87Ed25519(t *testing.T)          { testTamperPQ(t, MlDsa87Ed25519, "ML-DSA-87+Ed25519") }

// ML-DSA-44 + Ed25519
func TestRoundtripMlDsa44Ed25519(t *testing.T)       { testRoundtrip(t, MlDsa44Ed25519, "ML-DSA-44+Ed25519") }
func TestWrongMsgMlDsa44Ed25519(t *testing.T)         { testWrongMessage(t, MlDsa44Ed25519, "ML-DSA-44+Ed25519") }
func TestTamperClassicalMlDsa44Ed25519(t *testing.T)   { testTamperClassical(t, MlDsa44Ed25519, "ML-DSA-44+Ed25519") }
func TestTamperPQMlDsa44Ed25519(t *testing.T)          { testTamperPQ(t, MlDsa44Ed25519, "ML-DSA-44+Ed25519") }
