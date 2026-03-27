package pqctls

import (
	"github.com/baron-chain/PQC-Standards-Implementation/go/composite"
	"github.com/baron-chain/PQC-Standards-Implementation/go/mldsa"
)

// SignatureAlgorithm is a TLS 1.3 signature algorithm identifier for PQC.
type SignatureAlgorithm uint16

const (
	// MLDSA44 is ML-DSA-44 (code point 0x0904).
	MLDSA44 SignatureAlgorithm = 0x0904
	// MLDSA65 is ML-DSA-65 (code point 0x0905).
	MLDSA65 SignatureAlgorithm = 0x0905
	// MLDSA87 is ML-DSA-87 (code point 0x0906).
	MLDSA87 SignatureAlgorithm = 0x0906
	// MLDSA65Ed25519 is ML-DSA-65 + Ed25519 composite (code point 0x0907).
	MLDSA65Ed25519 SignatureAlgorithm = 0x0907
	// MLDSA87Ed25519 is ML-DSA-87 + Ed25519 composite (code point 0x0908).
	MLDSA87Ed25519 SignatureAlgorithm = 0x0908
)

// AllSignatureAlgorithms returns all defined PQC signature algorithms.
var AllSignatureAlgorithms = []SignatureAlgorithm{MLDSA44, MLDSA65, MLDSA87, MLDSA65Ed25519, MLDSA87Ed25519}

// String returns a human-readable name.
func (sa SignatureAlgorithm) String() string {
	switch sa {
	case MLDSA44:
		return "MLDSA44"
	case MLDSA65:
		return "MLDSA65"
	case MLDSA87:
		return "MLDSA87"
	case MLDSA65Ed25519:
		return "MLDSA65_ED25519"
	case MLDSA87Ed25519:
		return "MLDSA87_ED25519"
	default:
		return "Unknown"
	}
}

// IsComposite returns true if the algorithm is a composite (hybrid) signature.
func (sa SignatureAlgorithm) IsComposite() bool {
	return sa == MLDSA65Ed25519 || sa == MLDSA87Ed25519
}

// SignatureAlgorithmFromCodePoint looks up a signature algorithm by code point.
func SignatureAlgorithmFromCodePoint(cp uint16) (SignatureAlgorithm, bool) {
	switch SignatureAlgorithm(cp) {
	case MLDSA44, MLDSA65, MLDSA87, MLDSA65Ed25519, MLDSA87Ed25519:
		return SignatureAlgorithm(cp), true
	default:
		return 0, false
	}
}

func mldsaParams(alg SignatureAlgorithm) *mldsa.Params {
	switch alg {
	case MLDSA44:
		return mldsa.MLDSA44
	case MLDSA65:
		return mldsa.MLDSA65
	case MLDSA87:
		return mldsa.MLDSA87
	default:
		panic("pqctls: not a pure ML-DSA algorithm")
	}
}

func compositeScheme(alg SignatureAlgorithm) composite.Scheme {
	switch alg {
	case MLDSA65Ed25519:
		return composite.MlDsa65Ed25519
	case MLDSA87Ed25519:
		return composite.MlDsa87Ed25519
	default:
		panic("pqctls: not a composite algorithm")
	}
}

// SigningKeyPair holds a signing key pair.
type SigningKeyPair struct {
	PK        []byte
	SK        []byte
	Algorithm SignatureAlgorithm
}

// GenerateSigningKey generates a signing key pair.
func GenerateSigningKey(alg SignatureAlgorithm) *SigningKeyPair {
	switch alg {
	case MLDSA44, MLDSA65, MLDSA87:
		pk, sk := mldsa.KeyGen(mldsaParams(alg))
		return &SigningKeyPair{PK: pk, SK: sk, Algorithm: alg}

	case MLDSA65Ed25519, MLDSA87Ed25519:
		kp := composite.KeyGen(compositeScheme(alg))
		return &SigningKeyPair{PK: kp.PK, SK: kp.SK, Algorithm: alg}

	default:
		panic("pqctls: unsupported signature algorithm")
	}
}

// SignHandshake signs a TLS 1.3 CertificateVerify handshake hash.
func SignHandshake(alg SignatureAlgorithm, sk, handshakeHash []byte) []byte {
	switch alg {
	case MLDSA44, MLDSA65, MLDSA87:
		return mldsa.Sign(sk, handshakeHash, mldsaParams(alg))

	case MLDSA65Ed25519, MLDSA87Ed25519:
		scheme := compositeScheme(alg)
		kp := &composite.KeyPair{PK: nil, SK: sk, Scheme: scheme}
		return composite.Sign(kp, handshakeHash)

	default:
		panic("pqctls: unsupported signature algorithm")
	}
}

// VerifyHandshake verifies a TLS 1.3 CertificateVerify signature.
func VerifyHandshake(alg SignatureAlgorithm, pk, handshakeHash, signature []byte) bool {
	switch alg {
	case MLDSA44, MLDSA65, MLDSA87:
		return mldsa.Verify(pk, handshakeHash, signature, mldsaParams(alg))

	case MLDSA65Ed25519, MLDSA87Ed25519:
		return composite.Verify(compositeScheme(alg), pk, handshakeHash, signature)

	default:
		return false
	}
}
