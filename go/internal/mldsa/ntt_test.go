package mldsa

import "testing"

func TestBitRev8(t *testing.T) {
	tests := []struct {
		input, expected int
	}{
		{0, 0},
		{1, 128},
		{2, 64},
		{128, 1},
		{255, 255},
		{0b10101010, 0b01010101},
	}
	for _, tc := range tests {
		got := BitRev8(tc.input)
		if got != tc.expected {
			t.Errorf("BitRev8(%d) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

func TestBitRev8Involution(t *testing.T) {
	for i := 0; i < 256; i++ {
		if BitRev8(BitRev8(i)) != i {
			t.Errorf("BitRev8 is not an involution at %d", i)
		}
	}
}

func TestZetas(t *testing.T) {
	// Zeta[0] = 1753^0 mod Q = 1
	// Actually Zetas[0] = 1753^BitRev8(0) = 1753^0 = 1
	if Zetas[0] != 1 {
		t.Errorf("Zetas[0] = %d, want 1", Zetas[0])
	}
	// Zetas[1] = 1753^BitRev8(1) = 1753^128 mod Q
	// 1753 is a primitive 512th root of unity, so 1753^256 = -1 mod Q
	val := FieldPow(1753, 256)
	if val != Q-1 {
		t.Errorf("1753^256 mod Q = %d, want %d (Q-1)", val, Q-1)
	}
}

func TestNTTRoundtrip(t *testing.T) {
	var f [256]int
	for i := 0; i < 256; i++ {
		f[i] = ModQ(int64(i * 1234567 % Q))
	}
	original := f

	NTT(&f)
	NTTInverse(&f)

	for i := 0; i < 256; i++ {
		if f[i] != original[i] {
			t.Errorf("NTT roundtrip failed at index %d: got %d, want %d", i, f[i], original[i])
		}
	}
}

func TestNTTLinearity(t *testing.T) {
	var a, b [256]int
	for i := 0; i < 256; i++ {
		a[i] = ModQ(int64(i * 7))
		b[i] = ModQ(int64(i * 13))
	}

	// sum = a + b
	var sum [256]int
	for i := 0; i < 256; i++ {
		sum[i] = FieldAdd(a[i], b[i])
	}

	NTT(&a)
	NTT(&b)
	NTT(&sum)

	for i := 0; i < 256; i++ {
		expected := FieldAdd(a[i], b[i])
		if sum[i] != expected {
			t.Errorf("NTT linearity failed at %d: %d != %d", i, sum[i], expected)
		}
	}
}

func TestPointwiseMulConvolution(t *testing.T) {
	// Pointwise multiplication in NTT domain = polynomial multiplication mod (x^256+1)
	var a, b [256]int
	a[0] = 1
	a[1] = 2
	b[0] = 3
	b[1] = 4

	NTT(&a)
	NTT(&b)
	c := PointwiseMul(a, b)
	NTTInverse(&c)

	// (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2
	if c[0] != 3 {
		t.Errorf("c[0] = %d, want 3", c[0])
	}
	if c[1] != 10 {
		t.Errorf("c[1] = %d, want 10", c[1])
	}
	if c[2] != 8 {
		t.Errorf("c[2] = %d, want 8", c[2])
	}
}
