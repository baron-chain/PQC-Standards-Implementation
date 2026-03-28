// verify_go.go -- Verify ML-DSA-65 interop test vectors using the Go implementation.
//
// Usage:
//     cd PQC-Standards-Implementation/go
//     go run ../interop/verify_go.go
//
// The program reads ../interop/mldsa65_vectors.json (relative to the go/ dir)
// and verifies the signature with the Go ML-DSA-65 implementation.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"
)

type vectors struct {
	Algorithm   string `json:"algorithm"`
	Description string `json:"description"`
	PK          string `json:"pk"`
	Msg         string `json:"msg"`
	Sig         string `json:"sig"`
}

func main() {
	fmt.Println("=== ML-DSA-65 verification (Go) ===")

	// Locate vectors file relative to this source file or working directory.
	// When run from go/ directory: ../interop/mldsa65_vectors.json
	candidates := []string{
		filepath.Join("..", "interop", "mldsa65_vectors.json"),
		filepath.Join("interop", "mldsa65_vectors.json"),
	}

	var data []byte
	var err error
	for _, path := range candidates {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot read vectors file: %v\n", err)
		os.Exit(1)
	}

	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot parse JSON: %v\n", err)
		os.Exit(1)
	}

	pk, err := hex.DecodeString(v.PK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: bad pk hex: %v\n", err)
		os.Exit(1)
	}
	msg, err := hex.DecodeString(v.Msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: bad msg hex: %v\n", err)
		os.Exit(1)
	}
	sig, err := hex.DecodeString(v.Sig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: bad sig hex: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  algorithm : %s\n", v.Algorithm)
	fmt.Printf("  pk size   : %d bytes\n", len(pk))
	fmt.Printf("  msg size  : %d bytes\n", len(msg))
	fmt.Printf("  sig size  : %d bytes\n", len(sig))

	ok := mldsa.Verify(pk, msg, sig, mldsa.MLDSA65)

	if ok {
		fmt.Println("  result    : PASS")
	} else {
		fmt.Println("  result    : FAIL")
		os.Exit(1)
	}
}
