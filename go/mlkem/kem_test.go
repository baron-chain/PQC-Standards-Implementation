package mlkem

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/params"
)

func testKemRoundtrip(t *testing.T, p params.ParameterSet, name string) {
	t.Helper()

	ek, dk, err := KeyGen(p, rand.Reader)
	if err != nil {
		t.Fatalf("%s: KeyGen failed: %v", name, err)
	}

	if len(ek) != p.EKSize {
		t.Fatalf("%s: ek length = %d, want %d", name, len(ek), p.EKSize)
	}
	if len(dk) != p.DKSize {
		t.Fatalf("%s: dk length = %d, want %d", name, len(dk), p.DKSize)
	}

	sharedSecret, ct, err := Encapsulate(p, ek, rand.Reader)
	if err != nil {
		t.Fatalf("%s: Encapsulate failed: %v", name, err)
	}

	if len(ct) != p.CTSize {
		t.Fatalf("%s: ct length = %d, want %d", name, len(ct), p.CTSize)
	}

	recoveredSecret := Decapsulate(p, dk, ct)

	if sharedSecret != recoveredSecret {
		t.Fatalf("%s: shared secrets do not match\n  encaps: %x\n  decaps: %x", name, sharedSecret, recoveredSecret)
	}
}

func TestKemRoundtrip512(t *testing.T) {
	testKemRoundtrip(t, params.MlKem512, "ML-KEM-512")
}

func TestKemRoundtrip768(t *testing.T) {
	testKemRoundtrip(t, params.MlKem768, "ML-KEM-768")
}

func TestKemRoundtrip1024(t *testing.T) {
	testKemRoundtrip(t, params.MlKem1024, "ML-KEM-1024")
}

func TestKemImplicitRejection(t *testing.T) {
	p := params.MlKem768

	ek, dk, err := KeyGen(p, rand.Reader)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	sharedSecret, ct, err := Encapsulate(p, ek, rand.Reader)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Tamper with the ciphertext.
	tamperedCT := make([]byte, len(ct))
	copy(tamperedCT, ct)
	tamperedCT[0] ^= 0xFF

	rejectedSecret := Decapsulate(p, dk, tamperedCT)

	if sharedSecret == rejectedSecret {
		t.Fatal("tampered ciphertext produced the same shared secret (implicit rejection failed)")
	}

	// The rejected secret should be deterministic (same z, same tampered ct -> same K_bar).
	rejectedSecret2 := Decapsulate(p, dk, tamperedCT)
	if rejectedSecret != rejectedSecret2 {
		t.Fatal("implicit rejection is not deterministic")
	}
}

func TestKemDeterministic(t *testing.T) {
	p := params.MlKem768

	var d, z [32]byte
	// Use a fixed seed for determinism.
	for i := range d {
		d[i] = byte(i)
	}
	for i := range z {
		z[i] = byte(i + 32)
	}

	ek1, dk1 := KeyGenInternal(p, d, z)
	ek2, dk2 := KeyGenInternal(p, d, z)

	if !bytes.Equal(ek1, ek2) {
		t.Fatal("KeyGenInternal is not deterministic: ek differs")
	}
	if !bytes.Equal(dk1, dk2) {
		t.Fatal("KeyGenInternal is not deterministic: dk differs")
	}

	var m [32]byte
	for i := range m {
		m[i] = byte(i + 64)
	}

	ss1, ct1 := EncapsulateInternal(p, ek1, m)
	ss2, ct2 := EncapsulateInternal(p, ek2, m)

	if ss1 != ss2 {
		t.Fatal("EncapsulateInternal is not deterministic: shared secret differs")
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("EncapsulateInternal is not deterministic: ciphertext differs")
	}
}
