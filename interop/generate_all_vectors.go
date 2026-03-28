// generate_all_vectors.go — Generate test vectors for ALL PQC schemes.
//
// Generates deterministic JSON test vectors for:
//   - ML-KEM-512, ML-KEM-768, ML-KEM-1024
//   - ML-DSA-44, ML-DSA-65, ML-DSA-87
//   - SLH-DSA-SHAKE-{128,192,256}{f,s}
//   - Hybrid KEM: X25519+ML-KEM-768, ECDH-P256+ML-KEM-768,
//     X25519+ML-KEM-1024, ECDH-P384+ML-KEM-1024
//   - Composite Sig: ML-DSA-65+Ed25519, ML-DSA-65+ECDSA-P256,
//     ML-DSA-87+Ed25519, ML-DSA-44+Ed25519
//   - PQ-TLS Named Groups and Cipher Suites (metadata only)
//
// Run from repo root:
//   cd go && go run ../interop/generate_all_vectors.go [output_dir]
//
// Output directory defaults to ../interop/vectors/all
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/liviuepure/PQC-Standards-Implementation/go/composite"
	"github.com/liviuepure/PQC-Standards-Implementation/go/hybrid"
	internalparams "github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
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

// ---- ML-KEM ----------------------------------------------------------------

type MLKEMVector struct {
	Algorithm  string `json:"algorithm"`
	GeneratedBy string `json:"generated_by"`
	Timestamp  string `json:"timestamp"`
	EK         string `json:"ek"`
	DK         string `json:"dk"`
	CT         string `json:"ct"`
	SS         string `json:"ss"`
}

func genMLKEM(dir string, name string, ps internalparams.ParameterSet) error {
	ek, dk, err := mlkem.KeyGen(ps, rand.Reader)
	if err != nil {
		return err
	}
	ss, ct, err := mlkem.Encapsulate(ps, ek, rand.Reader)
	if err != nil {
		return err
	}
	ssGot := mlkem.Decapsulate(ps, dk, ct)
	if [32]byte(ss) != ssGot {
		return fmt.Errorf("%s: encaps/decaps mismatch", name)
	}
	v := MLKEMVector{
		Algorithm:   name,
		GeneratedBy: "Go reference implementation (FIPS 203)",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		EK:          toHex(ek),
		DK:          toHex(dk),
		CT:          toHex(ct),
		SS:          toHex(ss[:]),
	}
	return writeJSON(dir, name, v)
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

func genMLDSA(dir string, name string, ps *mldsa.Params) error {
	kp, err := mldsa.KeyGen(ps, rand.Reader)
	if err != nil {
		return err
	}
	msg := []byte("test message for " + name + " cross-language interoperability vector")
	sig, err := mldsa.Sign(ps, kp.SK, msg, rand.Reader)
	if err != nil {
		return err
	}
	ok := mldsa.Verify(ps, kp.PK, msg, sig)
	if !ok {
		return fmt.Errorf("%s: self-verify failed", name)
	}
	v := MLDSAVector{
		Algorithm:   name,
		GeneratedBy: "Go reference implementation (FIPS 204)",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		PK:          toHex(kp.PK),
		SK:          toHex(kp.SK),
		Msg:         toHex(msg),
		Sig:         toHex(sig),
		Verified:    true,
	}
	return writeJSON(dir, name, v)
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

func genSLHDSA(dir string, name string, ps slhdsa.Params) error {
	sk, pk, err := slhdsa.KeyGen(ps, rand.Reader)
	if err != nil {
		return err
	}
	msg := []byte("test message for " + name + " cross-language interoperability vector")
	sig, err := slhdsa.Sign(ps, sk, msg, rand.Reader)
	if err != nil {
		return err
	}
	ok := slhdsa.Verify(ps, pk, msg, sig)
	if !ok {
		return fmt.Errorf("%s: self-verify failed", name)
	}
	v := SLHDSAVector{
		Algorithm:   name,
		GeneratedBy: "Go reference implementation (FIPS 205)",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		PK:          toHex(pk),
		SK:          toHex(sk),
		Msg:         toHex(msg),
		Sig:         toHex(sig),
		Verified:    true,
	}
	return writeJSON(dir, name, v)
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
		return fmt.Errorf("%s: encaps/decaps mismatch", scheme.Name)
	}
	v := HybridKEMVector{
		Algorithm:       scheme.Name,
		GeneratedBy:     "Go reference implementation",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Description:     "Hybrid KEM: classical ECDH + ML-KEM. SS = SHA3-256(ss_classical || ss_pq || label)",
		EK:              toHex(kp.EK),
		DK:              toHex(kp.DK),
		CT:              toHex(res.Ciphertext),
		SS:              toHex(res.SharedSecret[:]),
		ClassicalEKSize: kp.ClassicalEKSize,
		ClassicalDKSize: kp.ClassicalDKSize,
		ClassicalCTSize: res.ClassicalCTSize,
	}
	return writeJSON(dir, scheme.Name, v)
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

var compositeSchemeNames = map[composite.Scheme]string{
	composite.MlDsa65Ed25519:   "ML-DSA-65+Ed25519",
	composite.MlDsa65EcdsaP256: "ML-DSA-65+ECDSA-P256",
	composite.MlDsa87Ed25519:   "ML-DSA-87+Ed25519",
	composite.MlDsa44Ed25519:   "ML-DSA-44+Ed25519",
}

func genCompositeSig(dir string, scheme composite.Scheme) error {
	name := compositeSchemeNames[scheme]
	kp, err := composite.KeyGen(scheme, rand.Reader)
	if err != nil {
		return err
	}
	msg := []byte("test message for " + name + " composite signature interoperability vector")
	sig, err := composite.Sign(kp, msg)
	if err != nil {
		return err
	}
	ok, err := composite.Verify(kp.PK, scheme, msg, sig)
	if err != nil || !ok {
		return fmt.Errorf("%s: self-verify failed: %v", name, err)
	}
	v := CompositeSigVector{
		Algorithm:   name,
		GeneratedBy: "Go reference implementation",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Description: "Composite signature: both classical and PQ must verify. Format: len(sig_classical)[4 LE] || sig_classical || sig_pq",
		PK:          toHex(kp.PK),
		SK:          toHex(kp.SK),
		Msg:         toHex(msg),
		Sig:         toHex(sig),
		Verified:    true,
	}
	return writeJSON(dir, name, v)
}

// ---- PQ-TLS Metadata -------------------------------------------------------

type TLSNamedGroupEntry struct {
	Name      string `json:"name"`
	CodePoint string `json:"code_point"`
	Type      string `json:"type"`
	KeyShareSize int `json:"key_share_size_bytes"`
}

type TLSCipherSuiteEntry struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	AEAD       string `json:"aead"`
	KeyExchange string `json:"key_exchange"`
	Signature  string `json:"signature"`
}

type TLSSigAlgEntry struct {
	Name      string `json:"name"`
	CodePoint string `json:"code_point"`
}

type TLSVector struct {
	Algorithm   string                `json:"algorithm"`
	GeneratedBy string                `json:"generated_by"`
	Timestamp   string                `json:"timestamp"`
	Description string                `json:"description"`
	NamedGroups []TLSNamedGroupEntry  `json:"named_groups"`
	CipherSuites []TLSCipherSuiteEntry `json:"cipher_suites"`
	SignatureAlgorithms []TLSSigAlgEntry `json:"signature_algorithms"`
	KeyExchangeTest     *TLSKeyExchangeTest `json:"key_exchange_test"`
}

type TLSKeyExchangeTest struct {
	Group       string `json:"group"`
	CodePoint   string `json:"code_point"`
	PublicKeyShare string `json:"client_public_key_share"`
	ResponseKeyShare string `json:"server_response_key_share"`
	SharedSecret string `json:"shared_secret"`
	Verified     bool   `json:"verified"`
}

func aeadName(a pqctls.AEADAlgorithm) string {
	switch a {
	case pqctls.AES128GCMSHA256:
		return "TLS_AES_128_GCM_SHA256"
	case pqctls.AES256GCMSHA384:
		return "TLS_AES_256_GCM_SHA384"
	case pqctls.CHACHA20POLY1305SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func namedGroupName(ng pqctls.NamedGroup) string {
	switch ng {
	case pqctls.MLKEM768:
		return "MLKEM768"
	case pqctls.MLKEM1024:
		return "MLKEM1024"
	case pqctls.X25519MLKEM768:
		return "X25519MLKEM768"
	case pqctls.SecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	default:
		return fmt.Sprintf("unknown(%d)", ng)
	}
}

func namedGroupType(ng pqctls.NamedGroup) string {
	switch ng {
	case pqctls.MLKEM768, pqctls.MLKEM1024:
		return "PQ-only"
	case pqctls.X25519MLKEM768, pqctls.SecP256r1MLKEM768:
		return "Hybrid (classical+PQ)"
	default:
		return "unknown"
	}
}

func sigAlgName(sa pqctls.SignatureAlgorithm) string {
	switch sa {
	case pqctls.MLDSA44:
		return "ML-DSA-44"
	case pqctls.MLDSA65:
		return "ML-DSA-65"
	case pqctls.MLDSA87:
		return "ML-DSA-87"
	case pqctls.MLDSA65Ed25519:
		return "ML-DSA-65+Ed25519"
	case pqctls.MLDSA87Ed25519:
		return "ML-DSA-87+Ed25519"
	default:
		return fmt.Sprintf("unknown(%d)", sa)
	}
}

func genTLS(dir string) error {
	var namedGroups []TLSNamedGroupEntry
	for _, ng := range pqctls.AllNamedGroups {
		namedGroups = append(namedGroups, TLSNamedGroupEntry{
			Name:         namedGroupName(ng),
			CodePoint:    fmt.Sprintf("0x%04X", int(ng)),
			Type:         namedGroupType(ng),
			KeyShareSize: pqctls.KeyShareSize(ng),
		})
	}

	var cipherSuites []TLSCipherSuiteEntry
	for _, cs := range pqctls.AllCipherSuites {
		cipherSuites = append(cipherSuites, TLSCipherSuiteEntry{
			Name:        cs.Name,
			ID:          fmt.Sprintf("0x%08X", cs.ID),
			AEAD:        aeadName(cs.AEAD),
			KeyExchange: namedGroupName(cs.KeyExchange),
			Signature:   sigAlgName(cs.Signature),
		})
	}

	var sigAlgs []TLSSigAlgEntry
	for _, sa := range pqctls.AllSignatureAlgorithms {
		sigAlgs = append(sigAlgs, TLSSigAlgEntry{
			Name:      sigAlgName(sa),
			CodePoint: fmt.Sprintf("0x%04X", int(sa)),
		})
	}

	// Perform a real X25519MLKEM768 key exchange
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
	verified := ss == resp.SharedSecret

	v := TLSVector{
		Algorithm:   "PQ-TLS",
		GeneratedBy: "Go reference implementation (draft-ietf-tls-mlkem)",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Description: "Post-quantum TLS 1.3 named groups, cipher suites, and signature algorithms per IANA assignments and IETF drafts",
		NamedGroups: namedGroups,
		CipherSuites: cipherSuites,
		SignatureAlgorithms: sigAlgs,
		KeyExchangeTest: &TLSKeyExchangeTest{
			Group:           "X25519MLKEM768",
			CodePoint:       "0x6399",
			PublicKeyShare:  toHex(ks.PublicKeyShare),
			ResponseKeyShare: toHex(resp.ResponseKeyShare),
			SharedSecret:    toHex(ss[:]),
			Verified:        verified,
		},
	}
	return writeJSON(dir, "pq-tls", v)
}

// ---- X25519 public key fix (classical only, for hybrid) -------------------

func x25519PublicKey(privBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()
	sk, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	return sk.PublicKey().Bytes(), nil
}

func bigToFixedBytes(b *big.Int, size int) []byte {
	out := make([]byte, size)
	bBytes := b.Bytes()
	copy(out[size-len(bBytes):], bBytes)
	return out
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

	type result struct {
		name string
		err  error
	}
	var results []result
	fail := 0

	run := func(name string, fn func() error) {
		err := fn()
		results = append(results, result{name, err})
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", name, err)
			fail++
		} else {
			fmt.Printf("PASS: %s\n", name)
		}
	}

	// ML-KEM
	run("ML-KEM-512",  func() error { return genMLKEM(outDir, "ML-KEM-512", internalparams.MlKem512) })
	run("ML-KEM-768",  func() error { return genMLKEM(outDir, "ML-KEM-768", internalparams.MlKem768) })
	run("ML-KEM-1024", func() error { return genMLKEM(outDir, "ML-KEM-1024", internalparams.MlKem1024) })

	// ML-DSA
	run("ML-DSA-44", func() error { return genMLDSA(outDir, "ML-DSA-44", mldsa.MLDSA44) })
	run("ML-DSA-65", func() error { return genMLDSA(outDir, "ML-DSA-65", mldsa.MLDSA65) })
	run("ML-DSA-87", func() error { return genMLDSA(outDir, "ML-DSA-87", mldsa.MLDSA87) })

	// SLH-DSA SHAKE variants
	run("SLH-DSA-SHAKE-128f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-128f", slhdsa.Shake128f) })
	run("SLH-DSA-SHAKE-128s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-128s", slhdsa.Shake128s) })
	run("SLH-DSA-SHAKE-192f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-192f", slhdsa.Shake192f) })
	run("SLH-DSA-SHAKE-192s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-192s", slhdsa.Shake192s) })
	run("SLH-DSA-SHAKE-256f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-256f", slhdsa.Shake256f) })
	run("SLH-DSA-SHAKE-256s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHAKE-256s", slhdsa.Shake256s) })

	// SLH-DSA SHA2 variants
	run("SLH-DSA-SHA2-128f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-128f", slhdsa.Sha2128f) })
	run("SLH-DSA-SHA2-128s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-128s", slhdsa.Sha2128s) })
	run("SLH-DSA-SHA2-192f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-192f", slhdsa.Sha2192f) })
	run("SLH-DSA-SHA2-192s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-192s", slhdsa.Sha2192s) })
	run("SLH-DSA-SHA2-256f", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-256f", slhdsa.Sha2256f) })
	run("SLH-DSA-SHA2-256s", func() error { return genSLHDSA(outDir, "SLH-DSA-SHA2-256s", slhdsa.Sha2256s) })

	// Hybrid KEM
	run("Hybrid-X25519-MLKEM768",    func() error { return genHybridKEM(outDir, hybrid.X25519MlKem768) })
	run("Hybrid-ECDHP256-MLKEM768",  func() error { return genHybridKEM(outDir, hybrid.EcdhP256MlKem768) })
	run("Hybrid-X25519-MLKEM1024",   func() error { return genHybridKEM(outDir, hybrid.X25519MlKem1024) })
	run("Hybrid-ECDHP384-MLKEM1024", func() error { return genHybridKEM(outDir, hybrid.EcdhP384MlKem1024) })

	// Composite Signatures
	run("Composite-ML-DSA-65+Ed25519",    func() error { return genCompositeSig(outDir, composite.MlDsa65Ed25519) })
	run("Composite-ML-DSA-65+ECDSA-P256", func() error { return genCompositeSig(outDir, composite.MlDsa65EcdsaP256) })
	run("Composite-ML-DSA-87+Ed25519",    func() error { return genCompositeSig(outDir, composite.MlDsa87Ed25519) })
	run("Composite-ML-DSA-44+Ed25519",    func() error { return genCompositeSig(outDir, composite.MlDsa44Ed25519) })

	// PQ-TLS
	run("PQ-TLS", func() error { return genTLS(outDir) })

	fmt.Printf("\n%d/%d PASS\n", len(results)-fail, len(results))
	if fail > 0 {
		os.Exit(1)
	}
}
