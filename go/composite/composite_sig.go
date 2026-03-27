// Package composite implements composite signature schemes that combine
// ML-DSA (post-quantum) with classical signatures (Ed25519, ECDSA-P256).
//
// Security holds as long as either the classical or PQ component is secure.
//
// Signature format: len(sig_classical) [4 bytes LE] || sig_classical || sig_pq
package composite

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/baron-chain/PQC-Standards-Implementation/go/mldsa"
)

// Scheme identifies a composite signature variant.
type Scheme int

const (
	MlDsa65Ed25519  Scheme = iota // ML-DSA-65 + Ed25519
	MlDsa65EcdsaP256              // ML-DSA-65 + ECDSA-P256
	MlDsa87Ed25519                // ML-DSA-87 + Ed25519
	MlDsa44Ed25519                // ML-DSA-44 + Ed25519
)

// KeyPair holds a composite key pair.
type KeyPair struct {
	PK     []byte // pk_classical || pk_pq
	SK     []byte // sk_classical || sk_pq
	Scheme Scheme
}

func pqParams(s Scheme) *mldsa.Params {
	switch s {
	case MlDsa44Ed25519:
		return mldsa.MLDSA44
	case MlDsa65Ed25519, MlDsa65EcdsaP256:
		return mldsa.MLDSA65
	case MlDsa87Ed25519:
		return mldsa.MLDSA87
	default:
		panic("composite: unknown scheme")
	}
}

func classicalPKSize(s Scheme) int {
	switch s {
	case MlDsa65Ed25519, MlDsa87Ed25519, MlDsa44Ed25519:
		return ed25519.PublicKeySize // 32
	case MlDsa65EcdsaP256:
		return 65 // uncompressed P-256 point
	default:
		panic("composite: unknown scheme")
	}
}

func classicalSKSize(s Scheme) int {
	switch s {
	case MlDsa65Ed25519, MlDsa87Ed25519, MlDsa44Ed25519:
		return ed25519.SeedSize // 32
	case MlDsa65EcdsaP256:
		return 32 // P-256 scalar
	default:
		panic("composite: unknown scheme")
	}
}

// KeyGen generates a composite key pair.
func KeyGen(scheme Scheme) *KeyPair {
	classicalPK, classicalSK := genClassical(scheme)
	params := pqParams(scheme)
	pqPK, pqSK := mldsa.KeyGen(params)

	pk := make([]byte, 0, len(classicalPK)+len(pqPK))
	pk = append(pk, classicalPK...)
	pk = append(pk, pqPK...)

	sk := make([]byte, 0, len(classicalSK)+len(pqSK))
	sk = append(sk, classicalSK...)
	sk = append(sk, pqSK...)

	return &KeyPair{PK: pk, SK: sk, Scheme: scheme}
}

func genClassical(s Scheme) (pk, sk []byte) {
	switch s {
	case MlDsa65Ed25519, MlDsa87Ed25519, MlDsa44Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic("composite: ed25519 keygen failed: " + err.Error())
		}
		return []byte(pub), priv.Seed()
	case MlDsa65EcdsaP256:
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic("composite: ecdsa keygen failed: " + err.Error())
		}
		pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
		skBytes := privKey.D.Bytes()
		// Pad to 32 bytes
		padded := make([]byte, 32)
		copy(padded[32-len(skBytes):], skBytes)
		return pubBytes, padded
	default:
		panic("composite: unknown scheme")
	}
}

// Sign produces a composite signature on msg.
func Sign(kp *KeyPair, msg []byte) []byte {
	skClassical := kp.SK[:classicalSKSize(kp.Scheme)]
	skPQ := kp.SK[classicalSKSize(kp.Scheme):]

	sigClassical := signClassical(kp.Scheme, skClassical, msg)
	sigPQ := mldsa.Sign(skPQ, msg, pqParams(kp.Scheme))

	out := make([]byte, 4+len(sigClassical)+len(sigPQ))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(sigClassical)))
	copy(out[4:], sigClassical)
	copy(out[4+len(sigClassical):], sigPQ)
	return out
}

func signClassical(s Scheme, sk, msg []byte) []byte {
	switch s {
	case MlDsa65Ed25519, MlDsa87Ed25519, MlDsa44Ed25519:
		privKey := ed25519.NewKeyFromSeed(sk)
		return ed25519.Sign(privKey, msg)
	case MlDsa65EcdsaP256:
		curve := elliptic.P256()
		d := new(big.Int).SetBytes(sk)
		privKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve},
			D:         d,
		}
		privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
		hash := sha256.Sum256(msg)
		sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
		if err != nil {
			panic("composite: ecdsa sign failed: " + err.Error())
		}
		return sig
	default:
		panic("composite: unknown scheme")
	}
}

// Verify verifies a composite signature. Returns true only if BOTH components verify.
func Verify(scheme Scheme, pk, msg, sig []byte) bool {
	if len(sig) < 4 {
		return false
	}
	classicalSigLen := int(binary.LittleEndian.Uint32(sig[0:4]))
	if len(sig) < 4+classicalSigLen {
		return false
	}
	sigClassical := sig[4 : 4+classicalSigLen]
	sigPQ := sig[4+classicalSigLen:]

	pkClassical := pk[:classicalPKSize(scheme)]
	pkPQ := pk[classicalPKSize(scheme):]

	classicalOK := verifyClassical(scheme, pkClassical, msg, sigClassical)
	pqOK := mldsa.Verify(pkPQ, msg, sigPQ, pqParams(scheme))

	return classicalOK && pqOK
}

func verifyClassical(s Scheme, pk, msg, sig []byte) bool {
	switch s {
	case MlDsa65Ed25519, MlDsa87Ed25519, MlDsa44Ed25519:
		return ed25519.Verify(ed25519.PublicKey(pk), msg, sig)
	case MlDsa65EcdsaP256:
		curve := elliptic.P256()
		x, y := elliptic.Unmarshal(curve, pk)
		if x == nil {
			return false
		}
		pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		hash := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pubKey, hash[:], sig)
	default:
		return false
	}
}

// ParseSig is a convenience to extract classical and PQ sig components.
func ParseSig(sig []byte) (classicalSig, pqSig []byte, err error) {
	if len(sig) < 4 {
		return nil, nil, errors.New("composite: signature too short")
	}
	cLen := int(binary.LittleEndian.Uint32(sig[0:4]))
	if len(sig) < 4+cLen {
		return nil, nil, errors.New("composite: truncated signature")
	}
	return sig[4 : 4+cLen], sig[4+cLen:], nil
}
