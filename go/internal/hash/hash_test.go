package hash

import (
	"crypto/rand"
	"testing"
)

func TestGDeterministic(t *testing.T) {
	input := make([]byte, 64)
	rand.Read(input)

	a1, a2 := G(input)
	b1, b2 := G(input)
	if a1 != b1 || a2 != b2 {
		t.Fatal("G is not deterministic")
	}
}

func TestGDifferentInputs(t *testing.T) {
	input1 := make([]byte, 32)
	input2 := make([]byte, 32)
	rand.Read(input1)
	rand.Read(input2)

	a1, a2 := G(input1)
	b1, b2 := G(input2)
	if a1 == b1 && a2 == b2 {
		t.Fatal("G produced identical output for different inputs")
	}
}

func TestHDeterministic(t *testing.T) {
	input := make([]byte, 32)
	rand.Read(input)

	a := H(input)
	b := H(input)
	if a != b {
		t.Fatal("H is not deterministic")
	}
}

func TestJDeterministic(t *testing.T) {
	input := make([]byte, 32)
	rand.Read(input)

	a := J(input)
	b := J(input)
	if a != b {
		t.Fatal("J is not deterministic")
	}
}
