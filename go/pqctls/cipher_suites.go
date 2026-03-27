package pqctls

// AeadAlgorithm identifies an AEAD algorithm used in TLS 1.3.
type AeadAlgorithm int

const (
	AES128GCMSHA256      AeadAlgorithm = iota
	AES256GCMSHA384
	ChaCha20Poly1305SHA256
)

// String returns a human-readable name.
func (a AeadAlgorithm) String() string {
	switch a {
	case AES128GCMSHA256:
		return "TLS_AES_128_GCM_SHA256"
	case AES256GCMSHA384:
		return "TLS_AES_256_GCM_SHA384"
	case ChaCha20Poly1305SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return "Unknown"
	}
}

// KeyLength returns the AEAD key length in bytes.
func (a AeadAlgorithm) KeyLength() int {
	switch a {
	case AES128GCMSHA256:
		return 16
	case AES256GCMSHA384:
		return 32
	case ChaCha20Poly1305SHA256:
		return 32
	default:
		return 0
	}
}

// HashLength returns the hash output length for HKDF.
func (a AeadAlgorithm) HashLength() int {
	switch a {
	case AES128GCMSHA256:
		return 32
	case AES256GCMSHA384:
		return 48
	case ChaCha20Poly1305SHA256:
		return 32
	default:
		return 0
	}
}

// CipherSuite combines an AEAD algorithm, key exchange named group, and signature algorithm.
type CipherSuite struct {
	ID          uint32
	Name        string
	AEAD        AeadAlgorithm
	KeyExchange NamedGroup
	Signature   SignatureAlgorithm
}

var (
	// TLS_AES_128_GCM_SHA256_MLKEM768 uses ML-KEM-768 key exchange and ML-DSA-65 signatures.
	TLS_AES_128_GCM_SHA256_MLKEM768 = CipherSuite{
		ID:          0x13010768,
		Name:        "TLS_AES_128_GCM_SHA256_MLKEM768",
		AEAD:        AES128GCMSHA256,
		KeyExchange: MLKEM768,
		Signature:   MLDSA65,
	}

	// TLS_AES_256_GCM_SHA384_X25519MLKEM768 uses X25519+ML-KEM-768 hybrid key exchange
	// and ML-DSA-65+Ed25519 composite signatures.
	TLS_AES_256_GCM_SHA384_X25519MLKEM768 = CipherSuite{
		ID:          0x13026399,
		Name:        "TLS_AES_256_GCM_SHA384_X25519MLKEM768",
		AEAD:        AES256GCMSHA384,
		KeyExchange: X25519MLKEM768,
		Signature:   MLDSA65Ed25519,
	}

	// AllCipherSuites lists all defined PQC cipher suites.
	AllCipherSuites = []CipherSuite{
		TLS_AES_128_GCM_SHA256_MLKEM768,
		TLS_AES_256_GCM_SHA384_X25519MLKEM768,
	}
)

// CipherSuiteByID looks up a cipher suite by its ID.
func CipherSuiteByID(id uint32) *CipherSuite {
	for _, cs := range AllCipherSuites {
		if cs.ID == id {
			return &cs
		}
	}
	return nil
}
