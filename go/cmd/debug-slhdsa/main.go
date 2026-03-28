package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	slhpub "github.com/liviuepure/PQC-Standards-Implementation/go/slhdsa"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/slhdsa"
)

func main() {
	data, _ := os.ReadFile("/tmp/pqc-vectors/slh-dsa-shake-128f.json")
	var v struct {
		PK  string `json:"pk"`
		Sig string `json:"sig"`
		Msg string `json:"msg"`
	}
	json.Unmarshal(data, &v)

	pk, _ := hex.DecodeString(v.PK)
	sig, _ := hex.DecodeString(v.Sig)
	msg, _ := hex.DecodeString(v.Msg)

	// Test with public Verify function
	params := slhpub.ParamsSHAKE128f
	ok := slhpub.Verify(pk, msg, sig, params)
	fmt.Printf("Verify result: %v\n", ok)

	// Show ADRS layout check
	var adrs slhdsa.Address
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(uint64(0x1234567890abcdef))
	adrs.SetType(3) // FORS_TREE
	adrs.SetKeyPairAddress(2)

	fmt.Printf("ADRS bytes: %s\n", hex.EncodeToString(adrs[:]))
	fmt.Printf("Layer (0-3): %s\n", hex.EncodeToString(adrs[0:4]))
	fmt.Printf("Tree (4-15): %s\n", hex.EncodeToString(adrs[4:16]))
	fmt.Printf("Type (16-19): %s\n", hex.EncodeToString(adrs[16:20]))
	fmt.Printf("KP (20-23): %s\n", hex.EncodeToString(adrs[20:24]))
}
