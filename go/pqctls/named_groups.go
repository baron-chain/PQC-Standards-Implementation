// Package pqctls provides PQC cipher suite / named group integration
// for TLS 1.3 handshakes.
package pqctls

import (
	"errors"
	"io"

	"github.com/liviuepure/PQC-Standards-Implementation/go/hybrid"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
)

// NamedGroup is a TLS 1.3 named group identifier for PQC key exchange.
type NamedGroup uint16

const (
	// MLKEM768 is the pure ML-KEM-768 named group (0x0768).
	MLKEM768 NamedGroup = 0x0768
	// MLKEM1024 is the pure ML-KEM-1024 named group (0x1024).
	MLKEM1024 NamedGroup = 0x1024
	// X25519MLKEM768 is the X25519 + ML-KEM-768 hybrid (0x6399).
	X25519MLKEM768 NamedGroup = 0x6399
	// SecP256r1MLKEM768 is the P-256 + ML-KEM-768 hybrid (0x639A).
	SecP256r1MLKEM768 NamedGroup = 0x639A
)

// AllNamedGroups returns all defined PQC named groups.
var AllNamedGroups = []NamedGroup{MLKEM768, MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768}

// String returns a human-readable name for the named group.
func (ng NamedGroup) String() string {
	switch ng {
	case MLKEM768:
		return "MLKEM768"
	case MLKEM1024:
		return "MLKEM1024"
	case X25519MLKEM768:
		return "X25519MLKEM768"
	case SecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	default:
		return "Unknown"
	}
}

// NamedGroupFromCodePoint looks up a named group by its TLS code point.
func NamedGroupFromCodePoint(cp uint16) (NamedGroup, bool) {
	switch NamedGroup(cp) {
	case MLKEM768, MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768:
		return NamedGroup(cp), true
	default:
		return 0, false
	}
}

// KeyShareResult holds the result of generating a key share.
type KeyShareResult struct {
	PrivateKey      []byte // Secret key material for completing the exchange.
	PublicKeyShare  []byte // Public key share bytes for ClientHello/ServerHello.
	ClassicalEKSize int    // For hybrid groups: classical EK size boundary.
	ClassicalDKSize int    // For hybrid groups: classical DK size boundary.
}

// KeyExchangeResult holds the result of completing a key exchange.
type KeyExchangeResult struct {
	SharedSecret     [32]byte // Derived shared secret.
	ResponseKeyShare []byte   // Ciphertext / response key share for the peer.
	ClassicalCTSize  int      // For hybrid groups: classical CT size boundary.
}

func mlkemParams(ng NamedGroup) params.ParameterSet {
	switch ng {
	case MLKEM768:
		return params.MlKem768
	case MLKEM1024:
		return params.MlKem1024
	default:
		panic("pqctls: not a pure ML-KEM group")
	}
}

func hybridScheme(ng NamedGroup) hybrid.Scheme {
	switch ng {
	case X25519MLKEM768:
		return hybrid.X25519MlKem768
	case SecP256r1MLKEM768:
		return hybrid.EcdhP256MlKem768
	default:
		panic("pqctls: not a hybrid group")
	}
}

// GenerateKeyShare generates a key share for the given named group.
func GenerateKeyShare(group NamedGroup, rng io.Reader) (*KeyShareResult, error) {
	switch group {
	case MLKEM768, MLKEM1024:
		p := mlkemParams(group)
		ek, dk, err := mlkem.KeyGen(p, rng)
		if err != nil {
			return nil, err
		}
		return &KeyShareResult{
			PrivateKey:     dk,
			PublicKeyShare: ek,
		}, nil

	case X25519MLKEM768, SecP256r1MLKEM768:
		scheme := hybridScheme(group)
		kp, err := hybrid.KeyGen(scheme, rng)
		if err != nil {
			return nil, err
		}
		return &KeyShareResult{
			PrivateKey:      kp.DK,
			PublicKeyShare:  kp.EK,
			ClassicalEKSize: kp.ClassicalEKSize,
			ClassicalDKSize: kp.ClassicalDKSize,
		}, nil

	default:
		return nil, errors.New("pqctls: unsupported named group")
	}
}

// CompleteKeyExchange completes a key exchange as the responder.
func CompleteKeyExchange(group NamedGroup, peerKeyShare []byte, classicalEKSize int, rng io.Reader) (*KeyExchangeResult, error) {
	switch group {
	case MLKEM768, MLKEM1024:
		p := mlkemParams(group)
		ss, ct, err := mlkem.Encapsulate(p, peerKeyShare, rng)
		if err != nil {
			return nil, err
		}
		return &KeyExchangeResult{
			SharedSecret:     ss,
			ResponseKeyShare: ct,
		}, nil

	case X25519MLKEM768, SecP256r1MLKEM768:
		scheme := hybridScheme(group)
		result, err := hybrid.Encaps(scheme, peerKeyShare, classicalEKSize, rng)
		if err != nil {
			return nil, err
		}
		return &KeyExchangeResult{
			SharedSecret:     result.SharedSecret,
			ResponseKeyShare: result.Ciphertext,
			ClassicalCTSize:  result.ClassicalCTSize,
		}, nil

	default:
		return nil, errors.New("pqctls: unsupported named group")
	}
}

// RecoverSharedSecret recovers the shared secret as the initiator.
func RecoverSharedSecret(group NamedGroup, privateKey, peerResponse []byte, classicalDKSize, classicalCTSize int) ([32]byte, error) {
	switch group {
	case MLKEM768, MLKEM1024:
		p := mlkemParams(group)
		ss := mlkem.Decapsulate(p, privateKey, peerResponse)
		return ss, nil

	case X25519MLKEM768, SecP256r1MLKEM768:
		scheme := hybridScheme(group)
		ss, err := hybrid.Decaps(scheme, privateKey, peerResponse, classicalDKSize, classicalCTSize)
		return ss, err

	default:
		return [32]byte{}, errors.New("pqctls: unsupported named group")
	}
}

// KeyShareSize returns the expected public key share size for a named group.
func KeyShareSize(group NamedGroup) int {
	switch group {
	case MLKEM768:
		return params.MlKem768.EKSize
	case MLKEM1024:
		return params.MlKem1024.EKSize
	case X25519MLKEM768:
		return 32 + params.MlKem768.EKSize // X25519 (32) + ML-KEM-768 EK
	case SecP256r1MLKEM768:
		return 65 + params.MlKem768.EKSize // P-256 uncompressed (65) + ML-KEM-768 EK
	default:
		return 0
	}
}
