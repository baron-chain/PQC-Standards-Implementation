package compress

import (
	"testing"

	"github.com/baron-chain/PQC-Standards-Implementation/go/internal/field"
)

func TestCompressRange(t *testing.T) {
	// Compress_d(x) must be in [0, 2^d).
	for _, d := range []int{1, 4, 5, 10, 11} {
		maxOut := uint16(1 << d)
		for x := uint16(0); x < field.Q; x++ {
			c := Compress(d, field.Element(x))
			if c >= maxOut {
				t.Fatalf("Compress(%d, %d) = %d, want < %d", d, x, c, maxOut)
			}
		}
	}
}

func TestDecompressRange(t *testing.T) {
	// Decompress_d(y) must be in [0, q).
	for _, d := range []int{1, 4, 5, 10, 11} {
		maxIn := uint16(1 << d)
		for y := uint16(0); y < maxIn; y++ {
			v := Decompress(d, y)
			if v.Value() >= field.Q {
				t.Fatalf("Decompress(%d, %d) = %d, want < %d", d, y, v.Value(), field.Q)
			}
		}
	}
}

func TestCompressDecompressRoundTrip(t *testing.T) {
	// For d bits, Decompress(Compress(x)) should be close to x.
	// The maximum error is bounded by ceil(q / 2^(d+1)).
	for _, d := range []int{1, 4, 10, 11} {
		maxErr := (field.Q + (1 << (d + 1)) - 1) / (1 << (d + 1))
		for x := uint16(0); x < field.Q; x++ {
			c := Compress(d, field.Element(x))
			y := Decompress(d, c)
			// Compute distance on the circular ring Z_q.
			diff := int(x) - int(y.Value())
			if diff < 0 {
				diff = -diff
			}
			if diff > int(field.Q)/2 {
				diff = int(field.Q) - diff
			}
			if diff > int(maxErr) {
				t.Fatalf("d=%d, x=%d: Compress=%d, Decompress=%d, error=%d > maxErr=%d",
					d, x, c, y.Value(), diff, maxErr)
			}
		}
	}
}

func TestCompressZero(t *testing.T) {
	for _, d := range []int{1, 4, 10, 11} {
		c := Compress(d, field.Element(0))
		if c != 0 {
			t.Errorf("Compress(%d, 0) = %d, want 0", d, c)
		}
	}
}

func TestDecompressZero(t *testing.T) {
	for _, d := range []int{1, 4, 10, 11} {
		v := Decompress(d, 0)
		if v.Value() != 0 {
			t.Errorf("Decompress(%d, 0) = %d, want 0", d, v.Value())
		}
	}
}

func TestCompressD1Midpoint(t *testing.T) {
	// For d=1, values near q/2 should compress to 1, values near 0 or q should compress to 0.
	mid := field.Q / 2 // 1664
	c := Compress(1, field.Element(mid))
	if c != 1 {
		t.Errorf("Compress(1, %d) = %d, want 1", mid, c)
	}
	c = Compress(1, field.Element(0))
	if c != 0 {
		t.Errorf("Compress(1, 0) = %d, want 0", c)
	}
}
