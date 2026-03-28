package mlkem

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
)

// parseKATVector reads a C2SP/CCTV intermediate test vector file and extracts
// the hex-encoded values for d, z, ek, dk, m, K, and c fields.
func parseKATVector(t *testing.T, path string) map[string][]byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read KAT file %s: %v", path, err)
	}

	fields := map[string][]byte{}
	// We only need the top-level scalar fields, not the array/matrix fields.
	wantKeys := map[string]bool{"d": true, "z": true, "ek": true, "dk": true, "m": true, "K": true, "c": true}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " = ", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if !wantKeys[key] {
			continue
		}
		// Only take the first occurrence of each key.
		if _, exists := fields[key]; exists {
			continue
		}
		val, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("failed to hex-decode field %q: %v", key, err)
		}
		fields[key] = val
	}

	return fields
}

func testKAT(t *testing.T, p params.ParameterSet, vectorPath string, name string) {
	t.Helper()

	kv := parseKATVector(t, vectorPath)

	// Extract seeds.
	var d, z [32]byte
	copy(d[:], kv["d"])
	copy(z[:], kv["z"])

	// Test KeyGenInternal.
	ek, dk := KeyGenInternal(p, d, z)

	if !bytes.Equal(ek, kv["ek"]) {
		t.Fatalf("%s: ek mismatch\n  got:  %x\n  want: %x", name, ek[:min(len(ek), 64)], kv["ek"][:min(len(kv["ek"]), 64)])
	}
	if !bytes.Equal(dk, kv["dk"]) {
		t.Fatalf("%s: dk mismatch\n  got:  %x\n  want: %x", name, dk[:min(len(dk), 64)], kv["dk"][:min(len(kv["dk"]), 64)])
	}

	// Test EncapsulateInternal.
	var m [32]byte
	copy(m[:], kv["m"])

	sharedSecret, ct := EncapsulateInternal(p, ek, m)

	if !bytes.Equal(ct, kv["c"]) {
		t.Fatalf("%s: ciphertext mismatch\n  got:  %x\n  want: %x", name, ct[:min(len(ct), 64)], kv["c"][:min(len(kv["c"]), 64)])
	}

	expectedK := kv["K"]
	if !bytes.Equal(sharedSecret[:], expectedK) {
		t.Fatalf("%s: shared secret (encaps) mismatch\n  got:  %x\n  want: %x", name, sharedSecret, expectedK)
	}

	// Test Decapsulate.
	recoveredK := Decapsulate(p, dk, ct)
	if !bytes.Equal(recoveredK[:], expectedK) {
		t.Fatalf("%s: shared secret (decaps) mismatch\n  got:  %x\n  want: %x", name, recoveredK, expectedK)
	}
}

func TestKAT512(t *testing.T) {
	testKAT(t, params.MlKem512,
		"../../test-vectors/ml-kem/ML-KEM-512-intermediate.txt",
		"ML-KEM-512")
}

func TestKAT768(t *testing.T) {
	testKAT(t, params.MlKem768,
		"../../test-vectors/ml-kem/ML-KEM-768-intermediate.txt",
		"ML-KEM-768")
}

func TestKAT1024(t *testing.T) {
	testKAT(t, params.MlKem1024,
		"../../test-vectors/ml-kem/ML-KEM-1024-intermediate.txt",
		"ML-KEM-1024")
}
