// generate-all-vectors — Generate test vectors for ALL PQC schemes.
//
// Generates JSON test vectors for:
//   - ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)
//   - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
//   - SLH-DSA-SHAKE-{128,192,256}{f,s} (FIPS 205)
//   - SLH-DSA-SHA2-{128,192,256}{f,s} (FIPS 205)
//   - Hybrid KEM: X25519+ML-KEM-768, ECDH-P256+ML-KEM-768,
//     X25519+ML-KEM-1024, ECDH-P384+ML-KEM-1024
//   - Composite Sig: ML-DSA-65+Ed25519, ML-DSA-65+ECDSA-P256,
//     ML-DSA-87+Ed25519, ML-DSA-44+Ed25519
//   - PQ-TLS named groups, cipher suites, signature algorithms
//
// Usage (from PQC-Standards-Implementation/go):
//   go run ./cmd/generate-all-vectors [output_dir]
//
// Output directory defaults to ../interop/vectors/all
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/liviuepure/PQC-Standards-Implementation/go/composite"
	"github.com/liviuepure/PQC-Standards-Implementation/go/hybrid"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
	"github.com/liviuepure/PQC-Standards-Implementation/go/pqctls"
	"github.com/liviuepure/PQC-Standards-Implementation/go/slhdsa"
)

func toHex(b []byte) string { return hex.EncodeToString(b) }

func writeJSON(dir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), data, 0644)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ---- ML-KEM ----------------------------------------------------------------

type MLKEMVector struct {
	Algorithm   string `json:"algorithm"`
	GeneratedBy string `json:"generated_by"`
	Timestamp   string `json:"timestamp"`
	EK          string `json:"ek"`
	DK          string `json:"dk"`
	CT          string `json:"ct"`
	SS          string `json:"ss"`
}

func genMLKEM(dir, name string, ps params.ParameterSet) error {
	ek, dk, err := mlkem.KeyGen(ps, rand.Reader)
	if err != nil {
		return err
	}
	ss, ct, err := mlkem.Encapsulate(ps, ek, rand.Reader)
	if err != nil {
		return err
	}
	ssGot := mlkem.Decapsulate(ps, dk, ct)
	if ss != ssGot {
		return fmt.Errorf("%s: decaps mismatch", name)
	}
	return writeJSON(dir, name, MLKEMVector{
		Algorithm:   name,
		GeneratedBy: "Go reference (FIPS 203)",
		Timestamp:   now(),
		EK:          toHex(ek),
		DK:          toHex(dk),
		CT:          toHex(ct),
		SS:          toHex(ss[:]),
	})
}

// ---- ML-DSA ----------------------------------------------------------------

type MLDSAVector struct {
	Algorithm   string `json:"algorithm"`
	GeneratedBy string `json:"generated_by"`
	Timestamp   string `json:"timestamp"`
	PK          string `json:"pk"`
	SK          string `json:"sk"`
	Msg         string `json:"msg"`
	Sig         string `json:"sig"`
	Verified    bool   `json:"verified"`
}

func genMLDSA(dir, name string, ps *mldsa.Params) error {
	pk, sk := mldsa.KeyGen(ps)
	msg := []byte("test message for " + name + " cross-language interoperability vector")
	sig := mldsa.Sign(sk, msg, ps)
	ok := mldsa.Verify(pk, msg, sig, ps)
	if !ok {
		return fmt.Errorf("%s: self-verify failed", name)
	}
	return writeJSON(dir, name, MLDSAVector{
		Algorithm:   name,
		GeneratedBy: "Go reference (FIPS 204)",
		Timestamp:   now(),
		PK:          toHex(pk),
		SK:          toHex(sk),
		Msg:         toHex(msg),
		Sig:         toHex(sig),
		Verified:    true,
	})
}

// ---- SLH-DSA ---------------------------------------------------------------

type SLHDSAVector struct {
	Algorithm   string `json:"algorithm"`
	GeneratedBy string `json:"generated_by"`
	Timestamp   string `json:"timestamp"`
	PK          string `json:"pk"`
	SK          string `json:"sk"`
	Msg         string `json:"msg"`
	Sig         string `json:"sig"`
	Verified    bool   `json:"verified"`
}

func genSLHDSA(dir, name string, ps *slhdsa.Params) error {
	pk, sk := slhdsa.KeyGen(ps)
	msg := []byte("test message for " + name + " cross-language interoperability vector")
	sig := slhdsa.Sign(sk, msg, ps)
	ok := slhdsa.Verify(pk, msg, sig, ps)
	if !ok {
		return fmt.Errorf("%s: self-verify failed", name)
	}
	return writeJSON(dir, name, SLHDSAVector{
		Algorithm:   name,
		GeneratedBy: "Go reference (FIPS 205)",
		Timestamp:   now(),
		PK:          toHex(pk),
		SK:          toHex(sk),
		Msg:         toHex(msg),
		Sig:         toHex(sig),
		Verified:    true,
	})
}

// ---- Hybrid KEM ------------------------------------------------------------

type HybridKEMVector struct {
	Algorithm       string `json:"algorithm"`
	GeneratedBy     string `json:"generated_by"`
	Timestamp       string `json:"timestamp"`
	Description     string `json:"description"`
	EK              string `json:"ek"`
	DK              string `json:"dk"`
	CT              string `json:"ct"`
	SS              string `json:"ss"`
	ClassicalEKSize int    `json:"classical_ek_size"`
	ClassicalDKSize int    `json:"classical_dk_size"`
	ClassicalCTSize int    `json:"classical_ct_size"`
}

func genHybridKEM(dir string, scheme hybrid.Scheme) error {
	kp, err := hybrid.KeyGen(scheme, rand.Reader)
	if err != nil {
		return err
	}
	res, err := hybrid.Encaps(scheme, kp.EK, kp.ClassicalEKSize, rand.Reader)
	if err != nil {
		return err
	}
	ss2, err := hybrid.Decaps(scheme, kp.DK, res.Ciphertext, kp.ClassicalDKSize, res.ClassicalCTSize)
	if err != nil {
		return err
	}
	if res.SharedSecret != ss2 {
		return fmt.Errorf("%s: decaps mismatch", scheme.Name)
	}
	return writeJSON(dir, scheme.Name, HybridKEMVector{
		Algorithm:       scheme.Name,
		GeneratedBy:     "Go reference (hybrid: classical ECDH + ML-KEM)",
		Timestamp:       now(),
		Description:     "Hybrid KEM combining classical ECDH with ML-KEM. SS = SHA3-256(ss_classical || ss_pq || label)",
		EK:              toHex(kp.EK),
		DK:              toHex(kp.DK),
		CT:              toHex(res.Ciphertext),
		SS:              toHex(res.SharedSecret[:]),
		ClassicalEKSize: kp.ClassicalEKSize,
		ClassicalDKSize: kp.ClassicalDKSize,
		ClassicalCTSize: res.ClassicalCTSize,
	})
}

// ---- Composite Signature ---------------------------------------------------

type CompositeSigVector struct {
	Algorithm   string `json:"algorithm"`
	GeneratedBy string `json:"generated_by"`
	Timestamp   string `json:"timestamp"`
	Description string `json:"description"`
	PK          string `json:"pk"`
	SK          string `json:"sk"`
	Msg         string `json:"msg"`
	Sig         string `json:"sig"`
	Verified    bool   `json:"verified"`
}

var compositeNames = map[composite.Scheme]string{
	composite.MlDsa65Ed25519:   "ML-DSA-65+Ed25519",
	composite.MlDsa65EcdsaP256: "ML-DSA-65+ECDSA-P256",
	composite.MlDsa87Ed25519:   "ML-DSA-87+Ed25519",
	composite.MlDsa44Ed25519:   "ML-DSA-44+Ed25519",
}

func genCompositeSig(dir string, scheme composite.Scheme) error {
	name := compositeNames[scheme]
	kp := composite.KeyGen(scheme)
	msg := []byte("test message for " + name + " composite signature interoperability vector")
	sig := composite.Sign(kp, msg)
	ok := composite.Verify(scheme, kp.PK, msg, sig)
	if !ok {
		return fmt.Errorf("%s: self-verify failed", name)
	}
	return writeJSON(dir, name, CompositeSigVector{
		Algorithm:   name,
		GeneratedBy: "Go reference (composite: classical + ML-DSA)",
		Timestamp:   now(),
		Description: "Composite signature. Both classical and PQ must verify. Format: len(sig_classical)[4 LE] || sig_classical || sig_pq",
		PK:          toHex(kp.PK),
		SK:          toHex(kp.SK),
		Msg:         toHex(msg),
		Sig:         toHex(sig),
		Verified:    true,
	})
}

// ---- PQ-TLS Metadata -------------------------------------------------------

type TLSVector struct {
	Algorithm           string               `json:"algorithm"`
	GeneratedBy         string               `json:"generated_by"`
	Timestamp           string               `json:"timestamp"`
	Description         string               `json:"description"`
	NamedGroups         []TLSNamedGroupEntry `json:"named_groups"`
	CipherSuites        []TLSCSEntry         `json:"cipher_suites"`
	SignatureAlgorithms []TLSSigAlgEntry     `json:"signature_algorithms"`
	KeyExchangeTest     TLSKeyExchangeTest   `json:"key_exchange_test"`
}

type TLSNamedGroupEntry struct {
	Name         string `json:"name"`
	CodePoint    string `json:"code_point"`
	Type         string `json:"type"`
	KeyShareSize int    `json:"key_share_size_bytes"`
}

type TLSCSEntry struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	AEAD        string `json:"aead"`
	KeyExchange string `json:"key_exchange"`
	Signature   string `json:"signature"`
}

type TLSSigAlgEntry struct {
	Name      string `json:"name"`
	CodePoint string `json:"code_point"`
}

type TLSKeyExchangeTest struct {
	Group            string `json:"group"`
	CodePoint        string `json:"code_point"`
	ClientKeyShare   string `json:"client_public_key_share"`
	ServerKeyShare   string `json:"server_response_key_share"`
	SharedSecret     string `json:"shared_secret"`
	Verified         bool   `json:"verified"`
}

func ngName(ng pqctls.NamedGroup) string   { return ng.String() }
func ngType(ng pqctls.NamedGroup) string {
	switch ng {
	case pqctls.MLKEM768, pqctls.MLKEM1024:
		return "PQ-only"
	default:
		return "Hybrid (classical+PQ)"
	}
}
func aeadName(a pqctls.AeadAlgorithm) string { return a.String() }
func saName(sa pqctls.SignatureAlgorithm) string { return sa.String() }

func genTLS(dir string) error {
	var ngs []TLSNamedGroupEntry
	for _, ng := range pqctls.AllNamedGroups {
		ngs = append(ngs, TLSNamedGroupEntry{
			Name:         ngName(ng),
			CodePoint:    fmt.Sprintf("0x%04X", int(ng)),
			Type:         ngType(ng),
			KeyShareSize: pqctls.KeyShareSize(ng),
		})
	}

	var css []TLSCSEntry
	for _, cs := range pqctls.AllCipherSuites {
		css = append(css, TLSCSEntry{
			Name:        cs.Name,
			ID:          fmt.Sprintf("0x%08X", cs.ID),
			AEAD:        aeadName(cs.AEAD),
			KeyExchange: ngName(cs.KeyExchange),
			Signature:   saName(cs.Signature),
		})
	}

	var sas []TLSSigAlgEntry
	for _, sa := range pqctls.AllSignatureAlgorithms {
		sas = append(sas, TLSSigAlgEntry{
			Name:      saName(sa),
			CodePoint: fmt.Sprintf("0x%04X", int(sa)),
		})
	}

	// Perform an actual X25519MLKEM768 key exchange
	ks, err := pqctls.GenerateKeyShare(pqctls.X25519MLKEM768, rand.Reader)
	if err != nil {
		return err
	}
	resp, err := pqctls.CompleteKeyExchange(pqctls.X25519MLKEM768, ks.PublicKeyShare, ks.ClassicalEKSize, rand.Reader)
	if err != nil {
		return err
	}
	ss, err := pqctls.RecoverSharedSecret(pqctls.X25519MLKEM768, ks.PrivateKey, resp.ResponseKeyShare,
		ks.ClassicalDKSize, resp.ClassicalCTSize)
	if err != nil {
		return err
	}

	return writeJSON(dir, "pq-tls", TLSVector{
		Algorithm:           "PQ-TLS",
		GeneratedBy:         "Go reference (draft-ietf-tls-mlkem, IANA PQC assignments)",
		Timestamp:           now(),
		Description:         "Post-quantum TLS 1.3 named groups, cipher suites, and signature algorithms",
		NamedGroups:         ngs,
		CipherSuites:        css,
		SignatureAlgorithms: sas,
		KeyExchangeTest: TLSKeyExchangeTest{
			Group:          "X25519MLKEM768",
			CodePoint:      "0x6399",
			ClientKeyShare: toHex(ks.PublicKeyShare),
			ServerKeyShare: toHex(resp.ResponseKeyShare),
			SharedSecret:   toHex(ss[:]),
			Verified:       ss == resp.SharedSecret,
		},
	})
}

// ---- Main ------------------------------------------------------------------

func main() {
	outDir := "../interop/vectors/all"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot create output dir: %v\n", err)
		os.Exit(1)
	}

	type task struct {
		name string
		fn   func() error
	}

	tasks := []task{
		// ML-KEM
		{"ML-KEM-512",  func() error { return genMLKEM(outDir, "ML-KEM-512", params.MlKem512) }},
		{"ML-KEM-768",  func() error { return genMLKEM(outDir, "ML-KEM-768", params.MlKem768) }},
		{"ML-KEM-1024", func() error { return genMLKEM(outDir, "ML-KEM-1024", params.MlKem1024) }},
		// ML-DSA
		{"ML-DSA-44", func() error { return genMLDSA(outDir, "ML-DSA-44", mldsa.MLDSA44) }},
		{"ML-DSA-65", func() error { return genMLDSA(outDir, "ML-DSA-65", mldsa.MLDSA65) }},
		{"ML-DSA-87", func() error { return genMLDSA(outDir, "ML-DSA-87", mldsa.MLDSA87) }},
		// SLH-DSA SHAKE
		{"SLH-DSA-SHAKE-128f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-128f", slhdsa.ParamsSHAKE128f) }},
		{"SLH-DSA-SHAKE-128s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-128s", slhdsa.ParamsSHAKE128s) }},
		{"SLH-DSA-SHAKE-192f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-192f", slhdsa.ParamsSHAKE192f) }},
		{"SLH-DSA-SHAKE-192s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-192s", slhdsa.ParamsSHAKE192s) }},
		{"SLH-DSA-SHAKE-256f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-256f", slhdsa.ParamsSHAKE256f) }},
		{"SLH-DSA-SHAKE-256s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-256s", slhdsa.ParamsSHAKE256s) }},
		// SLH-DSA SHA2
		{"SLH-DSA-SHA2-128f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-128f", slhdsa.ParamsSHA2128f) }},
		{"SLH-DSA-SHA2-128s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-128s", slhdsa.ParamsSHA2128s) }},
		{"SLH-DSA-SHA2-192f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-192f", slhdsa.ParamsSHA2192f) }},
		{"SLH-DSA-SHA2-192s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-192s", slhdsa.ParamsSHA2192s) }},
		{"SLH-DSA-SHA2-256f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-256f", slhdsa.ParamsSHA2256f) }},
		{"SLH-DSA-SHA2-256s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-256s", slhdsa.ParamsSHA2256s) }},
		// Hybrid KEM
		{"Hybrid-X25519-MLKEM768",    func() error { return genHybridKEM(outDir, hybrid.X25519MlKem768) }},
		{"Hybrid-ECDHP256-MLKEM768",  func() error { return genHybridKEM(outDir, hybrid.EcdhP256MlKem768) }},
		{"Hybrid-X25519-MLKEM1024",   func() error { return genHybridKEM(outDir, hybrid.X25519MlKem1024) }},
		{"Hybrid-ECDHP384-MLKEM1024", func() error { return genHybridKEM(outDir, hybrid.EcdhP384MlKem1024) }},
		// Composite Signatures
		{"Composite-ML-DSA-65+Ed25519",    func() error { return genCompositeSig(outDir, composite.MlDsa65Ed25519) }},
		{"Composite-ML-DSA-65+ECDSA-P256", func() error { return genCompositeSig(outDir, composite.MlDsa65EcdsaP256) }},
		{"Composite-ML-DSA-87+Ed25519",    func() error { return genCompositeSig(outDir, composite.MlDsa87Ed25519) }},
		{"Composite-ML-DSA-44+Ed25519",    func() error { return genCompositeSig(outDir, composite.MlDsa44Ed25519) }},
		// PQ-TLS
		{"PQ-TLS", func() error { return genTLS(outDir) }},
	}

	pass, fail := 0, 0
	for _, t := range tasks {
		if err := t.fn(); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", t.name, err)
			fail++
		} else {
			fmt.Printf("PASS: %-40s -> %s/%s.json\n", t.name, outDir, t.name)
			pass++
		}
	}

	total := pass + fail
	fmt.Printf("\n%d/%d PASS", pass, total)
	if fail > 0 {
		fmt.Printf(", %d FAIL\n", fail)
		os.Exit(1)
	}
	fmt.Println()
}
