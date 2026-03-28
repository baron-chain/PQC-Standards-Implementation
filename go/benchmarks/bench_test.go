// Package benchmarks provides performance benchmarks for ML-KEM, ML-DSA, and SLH-DSA.
//
// Run with: go test -bench=. -benchmem ./benchmarks/
package benchmarks

import (
	"crypto/rand"
	"testing"

	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
	"github.com/liviuepure/PQC-Standards-Implementation/go/slhdsa"
)

// ---------------------------------------------------------------------------
// ML-KEM benchmarks
// ---------------------------------------------------------------------------

func BenchmarkMlKem768KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := mlkem.KeyGen(params.MlKem768, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlKem768Encaps(b *testing.B) {
	ek, _, err := mlkem.KeyGen(params.MlKem768, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := mlkem.Encapsulate(params.MlKem768, ek, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlKem768Decaps(b *testing.B) {
	ek, dk, err := mlkem.KeyGen(params.MlKem768, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	_, ct, err := mlkem.Encapsulate(params.MlKem768, ek, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mlkem.Decapsulate(params.MlKem768, dk, ct)
	}
}

func BenchmarkMlKem512KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := mlkem.KeyGen(params.MlKem512, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlKem1024KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := mlkem.KeyGen(params.MlKem1024, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// ML-DSA benchmarks
// ---------------------------------------------------------------------------

var benchMsg = []byte("PQC benchmark message for performance testing")

func BenchmarkMlDsa44KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = mldsa.KeyGen(mldsa.MLDSA44)
	}
}

func BenchmarkMlDsa65KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = mldsa.KeyGen(mldsa.MLDSA65)
	}
}

func BenchmarkMlDsa87KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = mldsa.KeyGen(mldsa.MLDSA87)
	}
}

func BenchmarkMlDsa44Sign(b *testing.B) {
	_, sk := mldsa.KeyGen(mldsa.MLDSA44)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mldsa.Sign(sk, benchMsg, mldsa.MLDSA44)
	}
}

func BenchmarkMlDsa65Sign(b *testing.B) {
	_, sk := mldsa.KeyGen(mldsa.MLDSA65)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mldsa.Sign(sk, benchMsg, mldsa.MLDSA65)
	}
}

func BenchmarkMlDsa87Sign(b *testing.B) {
	_, sk := mldsa.KeyGen(mldsa.MLDSA87)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mldsa.Sign(sk, benchMsg, mldsa.MLDSA87)
	}
}

func BenchmarkMlDsa44Verify(b *testing.B) {
	pk, sk := mldsa.KeyGen(mldsa.MLDSA44)
	sig := mldsa.Sign(sk, benchMsg, mldsa.MLDSA44)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mldsa.Verify(pk, benchMsg, sig, mldsa.MLDSA44)
	}
}

func BenchmarkMlDsa65Verify(b *testing.B) {
	pk, sk := mldsa.KeyGen(mldsa.MLDSA65)
	sig := mldsa.Sign(sk, benchMsg, mldsa.MLDSA65)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mldsa.Verify(pk, benchMsg, sig, mldsa.MLDSA65)
	}
}

func BenchmarkMlDsa87Verify(b *testing.B) {
	pk, sk := mldsa.KeyGen(mldsa.MLDSA87)
	sig := mldsa.Sign(sk, benchMsg, mldsa.MLDSA87)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mldsa.Verify(pk, benchMsg, sig, mldsa.MLDSA87)
	}
}

// ---------------------------------------------------------------------------
// SLH-DSA benchmarks (SHAKE-128f — fastest parameter set)
// ---------------------------------------------------------------------------

func BenchmarkSlhDsaShake128fKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = slhdsa.KeyGen(slhdsa.ParamsSHAKE128f)
	}
}

func BenchmarkSlhDsaShake128fSign(b *testing.B) {
	_, sk := slhdsa.KeyGen(slhdsa.ParamsSHAKE128f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = slhdsa.Sign(sk, benchMsg, slhdsa.ParamsSHAKE128f)
	}
}

func BenchmarkSlhDsaShake128fVerify(b *testing.B) {
	pk, sk := slhdsa.KeyGen(slhdsa.ParamsSHAKE128f)
	sig := slhdsa.Sign(sk, benchMsg, slhdsa.ParamsSHAKE128f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = slhdsa.Verify(pk, benchMsg, sig, slhdsa.ParamsSHAKE128f)
	}
}
