// Package main — Comprehensive Go cross-language PQC interoperability verifier.
//
// Reads all JSON vector files from VECTORS_DIR and verifies:
//   ML-KEM:  Decapsulate(dk, ct) == ss
//   ML-DSA:  Verify(pk, msg, sig) == true
//   SLH-DSA: Verify(pk, msg, sig) == true
//
// Output lines (parseable by orchestrator):
//   RESULT:ML-KEM-512:PASS
//   RESULT:ML-DSA-44:FAIL:verification returned false
//
// Usage (from PQC-Standards-Implementation/go):
//   go run ./cmd/interop-verify [VECTORS_DIR]
// VECTORS_DIR defaults to ../interop/vectors

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
	"github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"
	"github.com/liviuepure/PQC-Standards-Implementation/go/slhdsa"
)

// ---------------------------------------------------------------------------
// JSON vector schemas
// ---------------------------------------------------------------------------

type mlkemVector struct {
	Algorithm string `json:"algorithm"`
	DK        string `json:"dk"`
	CT        string `json:"ct"`
	SS        string `json:"ss"`
}

type mldsaVector struct {
	Algorithm string `json:"algorithm"`
	PK        string `json:"pk"`
	Msg       string `json:"msg"`
	Sig       string `json:"sig"`
}

type slhdsaVector struct {
	Algorithm string `json:"algorithm"`
	PK        string `json:"pk"`
	Msg       string `json:"msg"`
	Sig       string `json:"sig"`
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex: %v", err))
	}
	return b
}

// ---------------------------------------------------------------------------
// Algorithm dispatch
// ---------------------------------------------------------------------------

func verifyMLKEM(alg string, data []byte) (bool, string) {
	var v mlkemVector
	if err := json.Unmarshal(data, &v); err != nil {
		return false, fmt.Sprintf("JSON parse error: %v", err)
	}

	dk := mustHex(v.DK)
	ct := mustHex(v.CT)
	ssExpected := mustHex(v.SS)

	var p params.ParameterSet
	switch alg {
	case "ML-KEM-512":
		p = params.MlKem512
	case "ML-KEM-768":
		p = params.MlKem768
	case "ML-KEM-1024":
		p = params.MlKem1024
	default:
		return false, fmt.Sprintf("unknown parameter set: %s", alg)
	}

	ssGot := mlkem.Decapsulate(p, dk, ct)
	if !bytes.Equal(ssGot[:], ssExpected) {
		return false, "decapsulated shared secret does not match expected"
	}
	return true, ""
}

func verifyMLDSA(alg string, data []byte) (bool, string) {
	var v mldsaVector
	if err := json.Unmarshal(data, &v); err != nil {
		return false, fmt.Sprintf("JSON parse error: %v", err)
	}

	pk  := mustHex(v.PK)
	msg := mustHex(v.Msg)
	sig := mustHex(v.Sig)

	var p *mldsa.Params
	switch alg {
	case "ML-DSA-44":
		p = mldsa.MLDSA44
	case "ML-DSA-65":
		p = mldsa.MLDSA65
	case "ML-DSA-87":
		p = mldsa.MLDSA87
	default:
		return false, fmt.Sprintf("unknown parameter set: %s", alg)
	}

	if !mldsa.Verify(pk, msg, sig, p) {
		return false, "signature verification returned false"
	}
	return true, ""
}

func verifySLHDSA(alg string, data []byte) (bool, string) {
	var v slhdsaVector
	if err := json.Unmarshal(data, &v); err != nil {
		return false, fmt.Sprintf("JSON parse error: %v", err)
	}

	pk  := mustHex(v.PK)
	msg := mustHex(v.Msg)
	sig := mustHex(v.Sig)

	var p *slhdsa.Params
	switch alg {
	case "SLH-DSA-SHAKE-128f":
		p = slhdsa.ParamsSHAKE128f
	case "SLH-DSA-SHAKE-128s":
		p = slhdsa.ParamsSHAKE128s
	case "SLH-DSA-SHAKE-192f":
		p = slhdsa.ParamsSHAKE192f
	case "SLH-DSA-SHAKE-192s":
		p = slhdsa.ParamsSHAKE192s
	case "SLH-DSA-SHAKE-256f":
		p = slhdsa.ParamsSHAKE256f
	case "SLH-DSA-SHAKE-256s":
		p = slhdsa.ParamsSHAKE256s
	default:
		return false, fmt.Sprintf("unknown parameter set: %s", alg)
	}

	if !slhdsa.Verify(pk, msg, sig, p) {
		return false, "signature verification returned false"
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	vectorsDir := filepath.Join("..", "interop", "vectors")
	if len(os.Args) > 1 {
		vectorsDir = os.Args[1]
	}

	entries, err := os.ReadDir(vectorsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot read vectors dir %q: %v\n", vectorsDir, err)
		os.Exit(1)
	}

	var failed int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(vectorsDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cannot read %s: %v\n", entry.Name(), err)
			failed++
			continue
		}

		var header struct {
			Algorithm string `json:"algorithm"`
		}
		if err := json.Unmarshal(data, &header); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad JSON in %s: %v\n", entry.Name(), err)
			failed++
			continue
		}
		alg := header.Algorithm

		var pass bool
		var errMsg string

		switch {
		case strings.HasPrefix(alg, "ML-KEM"):
			pass, errMsg = verifyMLKEM(alg, data)
		case strings.HasPrefix(alg, "ML-DSA"):
			pass, errMsg = verifyMLDSA(alg, data)
		case strings.HasPrefix(alg, "SLH-DSA"):
			pass, errMsg = verifySLHDSA(alg, data)
		default:
			pass, errMsg = false, fmt.Sprintf("unknown algorithm family: %s", alg)
		}

		if pass {
			fmt.Printf("RESULT:%s:PASS\n", alg)
		} else {
			fmt.Printf("RESULT:%s:FAIL:%s\n", alg, errMsg)
			failed++
		}
	}

	if failed > 0 {
		os.Exit(1)
	}
}
