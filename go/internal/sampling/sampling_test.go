package sampling

import (
	"crypto/rand"
	"testing"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

func TestCBDEta2Range(t *testing.T) {
	// eta=2 requires 64*2 = 128 bytes of input
	input := make([]byte, 128)
	rand.Read(input)

	poly := SamplePolyCBD(2, input)
	for i, c := range poly {
		v := c.Value()
		// Coefficient should be in {q-2, q-1, 0, 1, 2} i.e. [-2,2] mod q
		if v > 2 && v < field.Q-2 {
			t.Fatalf("coefficient %d = %d is out of range [-2,2] mod q", i, v)
		}
	}
}

func TestCBDEta3Range(t *testing.T) {
	// eta=3 requires 64*3 = 192 bytes of input
	input := make([]byte, 192)
	rand.Read(input)

	poly := SamplePolyCBD(3, input)
	for i, c := range poly {
		v := c.Value()
		// Coefficient should be in {q-3, q-2, q-1, 0, 1, 2, 3} i.e. [-3,3] mod q
		if v > 3 && v < field.Q-3 {
			t.Fatalf("coefficient %d = %d is out of range [-3,3] mod q", i, v)
		}
	}
}

func TestCBDDeterministic(t *testing.T) {
	input := make([]byte, 128)
	rand.Read(input)

	a := SamplePolyCBD(2, input)
	b := SamplePolyCBD(2, input)
	if a != b {
		t.Fatal("SamplePolyCBD is not deterministic")
	}
}

func TestSampleNTTRange(t *testing.T) {
	var seed [34]byte
	rand.Read(seed[:])

	poly := SampleNTT(seed)
	for i, c := range poly {
		if c.Value() >= field.Q {
			t.Fatalf("coefficient %d = %d is >= q", i, c.Value())
		}
	}
}

func TestSampleNTTDeterministic(t *testing.T) {
	var seed [34]byte
	rand.Read(seed[:])

	a := SampleNTT(seed)
	b := SampleNTT(seed)
	if a != b {
		t.Fatal("SampleNTT is not deterministic")
	}
}

func TestPRFDeterministic(t *testing.T) {
	var seed [32]byte
	rand.Read(seed[:])

	a := PRF(seed, 0x42, 128)
	b := PRF(seed, 0x42, 128)

	if len(a) != len(b) {
		t.Fatal("PRF output lengths differ")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("PRF is not deterministic")
		}
	}
}
