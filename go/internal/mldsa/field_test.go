package mldsa

import "testing"

func TestModQ(t *testing.T) {
	tests := []struct {
		input    int64
		expected int
	}{
		{0, 0},
		{1, 1},
		{Q, 0},
		{Q + 1, 1},
		{-1, Q - 1},
		{-Q, 0},
		{int64(Q) * 2, 0},
		{int64(Q)*2 + 5, 5},
	}
	for _, tc := range tests {
		got := ModQ(tc.input)
		if got != tc.expected {
			t.Errorf("ModQ(%d) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

func TestFieldAdd(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{0, 0, 0},
		{1, 2, 3},
		{Q - 1, 1, 0},
		{Q - 1, Q - 1, Q - 2},
	}
	for _, tc := range tests {
		got := FieldAdd(tc.a, tc.b)
		if got != tc.expected {
			t.Errorf("FieldAdd(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.expected)
		}
	}
}

func TestFieldSub(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{0, 0, 0},
		{3, 2, 1},
		{0, 1, Q - 1},
		{1, Q - 1, 2},
	}
	for _, tc := range tests {
		got := FieldSub(tc.a, tc.b)
		if got != tc.expected {
			t.Errorf("FieldSub(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.expected)
		}
	}
}

func TestFieldMul(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{0, 5, 0},
		{1, 5, 5},
		{2, 3, 6},
		{Q - 1, Q - 1, 1}, // (-1)*(-1) = 1
	}
	for _, tc := range tests {
		got := FieldMul(tc.a, tc.b)
		if got != tc.expected {
			t.Errorf("FieldMul(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.expected)
		}
	}
}

func TestFieldPow(t *testing.T) {
	// a^0 = 1
	if got := FieldPow(5, 0); got != 1 {
		t.Errorf("FieldPow(5, 0) = %d, want 1", got)
	}
	// a^1 = a
	if got := FieldPow(5, 1); got != 5 {
		t.Errorf("FieldPow(5, 1) = %d, want 5", got)
	}
	// Fermat: a^(Q-1) = 1
	if got := FieldPow(1753, Q-1); got != 1 {
		t.Errorf("FieldPow(1753, Q-1) = %d, want 1", got)
	}
}

func TestFieldInv(t *testing.T) {
	vals := []int{1, 2, 3, 1753, Q - 1, 42}
	for _, a := range vals {
		inv := FieldInv(a)
		prod := FieldMul(a, inv)
		if prod != 1 {
			t.Errorf("FieldInv(%d) = %d, but %d * %d = %d, want 1", a, inv, a, inv, prod)
		}
	}
}
