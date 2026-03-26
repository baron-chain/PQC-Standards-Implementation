// Package params defines ML-KEM parameter sets per FIPS 203.
package params

// ParameterSet holds the parameters for an ML-KEM variant.
type ParameterSet struct {
	K, ETA1, ETA2, DU, DV int
	EKSize, DKSize, CTSize int
}

var (
	// MlKem512 is the ML-KEM-512 parameter set (NIST security level 1).
	MlKem512 = ParameterSet{K: 2, ETA1: 3, ETA2: 2, DU: 10, DV: 4, EKSize: 800, DKSize: 1632, CTSize: 768}
	// MlKem768 is the ML-KEM-768 parameter set (NIST security level 3).
	MlKem768 = ParameterSet{K: 3, ETA1: 2, ETA2: 2, DU: 10, DV: 4, EKSize: 1184, DKSize: 2400, CTSize: 1088}
	// MlKem1024 is the ML-KEM-1024 parameter set (NIST security level 5).
	MlKem1024 = ParameterSet{K: 4, ETA1: 2, ETA2: 2, DU: 11, DV: 5, EKSize: 1568, DKSize: 3168, CTSize: 1568}
)
