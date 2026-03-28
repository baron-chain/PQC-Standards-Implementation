package mldsa

// Params holds the parameter set for an ML-DSA security level.
type Params struct {
	Name   string
	K      int // rows in matrix A
	L      int // columns in matrix A
	Eta    int // secret key coefficient bound
	Tau    int // number of +/-1 coefficients in c
	Beta   int // tau * eta
	Gamma1 int // y coefficient range
	Gamma2 int // low-order rounding range
	Omega  int // max number of 1-bits in hint
	D      int // dropped bits from t
	PKSize int
	SKSize int
	SigSize int
	Lambda int // collision strength in bytes (= security level / 4)
}

// Pre-defined parameter sets per FIPS 204.
var (
	MLDSA44 = &Params{
		Name:    "ML-DSA-44",
		K:       4,
		L:       4,
		Eta:     2,
		Tau:     39,
		Beta:    78,
		Gamma1:  1 << 17, // 131072
		Gamma2:  (Q - 1) / 88, // 95232
		Omega:   80,
		D:       13,
		PKSize:  1312,
		SKSize:  2560,
		SigSize: 2420,
		Lambda:  16,
	}
	MLDSA65 = &Params{
		Name:    "ML-DSA-65",
		K:       6,
		L:       5,
		Eta:     4,
		Tau:     49,
		Beta:    196,
		Gamma1:  1 << 19, // 524288
		Gamma2:  (Q - 1) / 32, // 261888
		Omega:   55,
		D:       13,
		PKSize:  1952,
		SKSize:  4032,
		SigSize: 3309,
		Lambda:  24, // 2λ = 48 bytes c_tilde (FIPS 204)
	}
	MLDSA87 = &Params{
		Name:    "ML-DSA-87",
		K:       8,
		L:       7,
		Eta:     2,
		Tau:     60,
		Beta:    120,
		Gamma1:  1 << 19, // 524288
		Gamma2:  (Q - 1) / 32, // 261888
		Omega:   75,
		D:       13,
		PKSize:  2592,
		SKSize:  4896,
		SigSize: 4627,
		Lambda:  32, // 2λ = 64 bytes c_tilde (FIPS 204)
	}
)
