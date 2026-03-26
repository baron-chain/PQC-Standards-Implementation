package field

import "testing"

func TestAdd(t *testing.T) {
	a := New(1000)
	b := New(2000)
	if got := a.Add(b).Value(); got != 3000 {
		t.Errorf("1000+2000 = %d, want 3000", got)
	}
}

func TestAddWraps(t *testing.T) {
	a := New(3000)
	b := New(1000)
	if got := a.Add(b).Value(); got != 671 {
		t.Errorf("3000+1000 mod 3329 = %d, want 671", got)
	}
}

func TestSub(t *testing.T) {
	a := New(1000)
	b := New(500)
	if got := a.Sub(b).Value(); got != 500 {
		t.Errorf("1000-500 = %d, want 500", got)
	}
}

func TestSubWraps(t *testing.T) {
	a := New(100)
	b := New(200)
	if got := a.Sub(b).Value(); got != 3229 {
		t.Errorf("100-200 mod 3329 = %d, want 3229", got)
	}
}

func TestMul(t *testing.T) {
	a := New(1000)
	b := New(1000)
	if got := a.Mul(b).Value(); got != 1300 {
		t.Errorf("1000*1000 mod 3329 = %d, want 1300", got)
	}
}

func TestNeg(t *testing.T) {
	a := New(100)
	neg := a.Neg()
	if got := a.Add(neg).Value(); got != 0 {
		t.Errorf("100 + (-100) = %d, want 0", got)
	}
	if got := Element(0).Neg().Value(); got != 0 {
		t.Errorf("-0 = %d, want 0", got)
	}
}

func TestExhaustiveAddSubInverse(t *testing.T) {
	for x := uint16(0); x < Q; x++ {
		a := New(x)
		neg := a.Neg()
		if got := a.Add(neg).Value(); got != 0 {
			t.Fatalf("x=%d: x+(-x) = %d, want 0", x, got)
		}
	}
}

func TestFromI16(t *testing.T) {
	if got := FromI16(-1).Value(); got != 3328 {
		t.Errorf("FromI16(-1) = %d, want 3328", got)
	}
	if got := FromI16(-3).Value(); got != 3326 {
		t.Errorf("FromI16(-3) = %d, want 3326", got)
	}
	if got := FromI16(100).Value(); got != 100 {
		t.Errorf("FromI16(100) = %d, want 100", got)
	}
}
