// Package mlkem implements ML-KEM (FIPS 203) key encapsulation mechanism.
package mlkem

import (
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/compress"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/encode"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/field"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/hash"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/ntt"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/sampling"
)

// KPKEKeyGen implements K-PKE.KeyGen (FIPS 203 Algorithm 13).
// It generates an encryption key and decryption key from a 32-byte seed d.
func KPKEKeyGen(p params.ParameterSet, d [32]byte) (ekPKE []byte, dkPKE []byte) {
	k := p.K

	// Line 1: (rho, sigma) = G(d)
	rho, sigma := hash.G(d[:])

	// Line 2-6: Generate matrix A_hat in NTT domain.
	// A_hat[i][j] = SampleNTT(rho || j || i)
	aHat := make([][]([256]field.Element), k)
	for i := 0; i < k; i++ {
		aHat[i] = make([][256]field.Element, k)
		for j := 0; j < k; j++ {
			var seed [34]byte
			copy(seed[:32], rho[:])
			seed[32] = byte(j)
			seed[33] = byte(i)
			aHat[i][j] = sampling.SampleNTT(seed)
		}
	}

	// Line 7-10: Sample secret vector s and compute s_hat = NTT(s).
	var n byte
	sHat := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		sHat[i] = sampling.SamplePolyCBD(p.ETA1, sampling.PRF(sigma, n, 64*p.ETA1))
		n++
		ntt.NTT(&sHat[i])
	}

	// Line 11-14: Sample error vector e and compute e_hat = NTT(e).
	eHat := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		eHat[i] = sampling.SamplePolyCBD(p.ETA1, sampling.PRF(sigma, n, 64*p.ETA1))
		n++
		ntt.NTT(&eHat[i])
	}

	// Line 15-16: t_hat = A_hat * s_hat + e_hat
	tHat := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		// t_hat[i] = sum_j(A_hat[i][j] * s_hat[j]) + e_hat[i]
		for j := 0; j < k; j++ {
			product := ntt.MultiplyNTTs(&aHat[i][j], &sHat[j])
			for c := 0; c < 256; c++ {
				tHat[i][c] = tHat[i][c].Add(product[c])
			}
		}
		for c := 0; c < 256; c++ {
			tHat[i][c] = tHat[i][c].Add(eHat[i][c])
		}
	}

	// Line 17: ekPKE = ByteEncode(12, t_hat[0]) || ... || ByteEncode(12, t_hat[k-1]) || rho
	ekPKE = make([]byte, 0, 384*k+32)
	for i := 0; i < k; i++ {
		ekPKE = append(ekPKE, encode.ByteEncode(12, &tHat[i])...)
	}
	ekPKE = append(ekPKE, rho[:]...)

	// Line 18: dkPKE = ByteEncode(12, s_hat[0]) || ... || ByteEncode(12, s_hat[k-1])
	dkPKE = make([]byte, 0, 384*k)
	for i := 0; i < k; i++ {
		dkPKE = append(dkPKE, encode.ByteEncode(12, &sHat[i])...)
	}

	return ekPKE, dkPKE
}

// KPKEEncrypt implements K-PKE.Encrypt (FIPS 203 Algorithm 14).
// It encrypts a 32-byte message m under encryption key ek using randomness r.
func KPKEEncrypt(p params.ParameterSet, ek []byte, m [32]byte, r [32]byte) []byte {
	k := p.K

	// Line 1-3: Decode t_hat from ek and extract rho.
	tHat := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		tHat[i] = encode.ByteDecode(12, ek[384*i:384*(i+1)])
	}
	var rho [32]byte
	copy(rho[:], ek[384*k:])

	// Line 4-8: Reconstruct A_hat from rho.
	aHat := make([][]([256]field.Element), k)
	for i := 0; i < k; i++ {
		aHat[i] = make([][256]field.Element, k)
		for j := 0; j < k; j++ {
			var seed [34]byte
			copy(seed[:32], rho[:])
			seed[32] = byte(j)
			seed[33] = byte(i)
			aHat[i][j] = sampling.SampleNTT(seed)
		}
	}

	// Line 9-12: Sample y vector and compute y_hat = NTT(y).
	var n byte
	yHat := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		yHat[i] = sampling.SamplePolyCBD(p.ETA1, sampling.PRF(r, n, 64*p.ETA1))
		n++
		ntt.NTT(&yHat[i])
	}

	// Line 13-16: Sample e1 (error vector, not NTT'd).
	e1 := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		e1[i] = sampling.SamplePolyCBD(p.ETA2, sampling.PRF(r, n, 64*p.ETA2))
		n++
	}

	// Line 17: Sample e2 (single error polynomial, not NTT'd).
	e2 := sampling.SamplePolyCBD(p.ETA2, sampling.PRF(r, n, 64*p.ETA2))
	// n++ not needed after this

	// Line 18-19: u = NTT^{-1}(A^T * y_hat) + e1
	// A^T[i][j] = A[j][i], so (A^T * y_hat)[i] = sum_j(A_hat[j][i] * y_hat[j])
	u := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		var uHat [256]field.Element
		for j := 0; j < k; j++ {
			product := ntt.MultiplyNTTs(&aHat[j][i], &yHat[j])
			for c := 0; c < 256; c++ {
				uHat[c] = uHat[c].Add(product[c])
			}
		}
		ntt.NTTInverse(&uHat)
		for c := 0; c < 256; c++ {
			u[i][c] = uHat[c].Add(e1[i][c])
		}
	}

	// Line 20: mu = Decompress(1, ByteDecode(1, m))
	mDecoded := encode.ByteDecode(1, m[:])
	var mu [256]field.Element
	for i := 0; i < 256; i++ {
		mu[i] = compress.Decompress(1, mDecoded[i].Value())
	}

	// Line 21: v = NTT^{-1}(t_hat^T * y_hat) + e2 + mu
	var vHat [256]field.Element
	for j := 0; j < k; j++ {
		product := ntt.MultiplyNTTs(&tHat[j], &yHat[j])
		for c := 0; c < 256; c++ {
			vHat[c] = vHat[c].Add(product[c])
		}
	}
	ntt.NTTInverse(&vHat)
	var v [256]field.Element
	for c := 0; c < 256; c++ {
		v[c] = vHat[c].Add(e2[c]).Add(mu[c])
	}

	// Line 22-24: Compress and encode u and v.
	ct := make([]byte, 0, p.CTSize)
	for i := 0; i < k; i++ {
		var compressed [256]field.Element
		for c := 0; c < 256; c++ {
			compressed[c] = field.Element(compress.Compress(p.DU, u[i][c]))
		}
		ct = append(ct, encode.ByteEncode(p.DU, &compressed)...)
	}

	var compressedV [256]field.Element
	for c := 0; c < 256; c++ {
		compressedV[c] = field.Element(compress.Compress(p.DV, v[c]))
	}
	ct = append(ct, encode.ByteEncode(p.DV, &compressedV)...)

	return ct
}

// KPKEDecrypt implements K-PKE.Decrypt (FIPS 203 Algorithm 15).
// It decrypts a ciphertext ct using decryption key dk.
func KPKEDecrypt(p params.ParameterSet, dk []byte, ct []byte) [32]byte {
	k := p.K

	// Line 1-4: Decompress u from ciphertext.
	u := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		uCompressed := encode.ByteDecode(p.DU, ct[32*p.DU*i:32*p.DU*(i+1)])
		for c := 0; c < 256; c++ {
			u[i][c] = compress.Decompress(p.DU, uCompressed[c].Value())
		}
	}

	// Line 5: Decompress v from ciphertext.
	vOffset := 32 * p.DU * k
	vCompressed := encode.ByteDecode(p.DV, ct[vOffset:vOffset+32*p.DV])
	var v [256]field.Element
	for c := 0; c < 256; c++ {
		v[c] = compress.Decompress(p.DV, vCompressed[c].Value())
	}

	// Line 6-7: Decode s_hat from dk.
	sHat := make([][256]field.Element, k)
	for i := 0; i < k; i++ {
		sHat[i] = encode.ByteDecode(12, dk[384*i:384*(i+1)])
	}

	// Line 8: w = v - NTT^{-1}(s_hat^T * NTT(u))
	// Compute s_hat^T * NTT(u) = sum_i(s_hat[i] * NTT(u[i]))
	var inner [256]field.Element
	for i := 0; i < k; i++ {
		uNTT := u[i]
		ntt.NTT(&uNTT)
		product := ntt.MultiplyNTTs(&sHat[i], &uNTT)
		for c := 0; c < 256; c++ {
			inner[c] = inner[c].Add(product[c])
		}
	}
	ntt.NTTInverse(&inner)

	var w [256]field.Element
	for c := 0; c < 256; c++ {
		w[c] = v[c].Sub(inner[c])
	}

	// Line 9: m = ByteEncode(1, Compress(1, w))
	var compressed [256]field.Element
	for c := 0; c < 256; c++ {
		compressed[c] = field.Element(compress.Compress(1, w[c]))
	}
	encoded := encode.ByteEncode(1, &compressed)

	var m [32]byte
	copy(m[:], encoded)
	return m
}
