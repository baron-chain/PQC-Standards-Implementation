package slhdsa

import "encoding/binary"

// Address type constants per FIPS 205.
const (
	AddrWotsHash  = 0
	AddrWotsPK    = 1
	AddrTree      = 2
	AddrForsTree  = 3
	AddrForsRoots = 4
	AddrWotsPRF   = 5
	AddrForsPRF   = 6
)

// Address is a 32-byte structure used throughout SLH-DSA.
// FIPS 205 Figure 2 layout:
//
//	Bytes  0– 3: layer address       (4 bytes)
//	Bytes  4–15: tree address        (12 bytes, uint64 right-aligned, big-endian)
//	Bytes 16–19: type                (4 bytes)
//	Bytes 20–23: keypair address     (4 bytes)
//	Bytes 24–27: chain/tree height   (4 bytes)
//	Bytes 28–31: hash/tree index     (4 bytes)
type Address [32]byte

// SetLayerAddress sets bytes 0–3.
func (a *Address) SetLayerAddress(v uint32) {
	binary.BigEndian.PutUint32(a[0:4], v)
}

// GetLayerAddress returns the layer address.
func (a *Address) GetLayerAddress() uint32 {
	return binary.BigEndian.Uint32(a[0:4])
}

// SetTreeAddress sets the 64-bit tree address in bytes 4–15 (right-aligned, big-endian).
// Bytes 4–7 are zero; bytes 8–15 hold the uint64 value.
func (a *Address) SetTreeAddress(v uint64) {
	binary.BigEndian.PutUint32(a[4:8], 0)
	binary.BigEndian.PutUint64(a[8:16], v)
}

// GetTreeAddress returns the 64-bit tree address from bytes 8–15.
func (a *Address) GetTreeAddress() uint64 {
	return binary.BigEndian.Uint64(a[8:16])
}

// SetType sets bytes 16–19 and zeroes bytes 20–31.
func (a *Address) SetType(v uint32) {
	binary.BigEndian.PutUint32(a[16:20], v)
	// Zero the type-specific fields
	binary.BigEndian.PutUint32(a[20:24], 0)
	binary.BigEndian.PutUint32(a[24:28], 0)
	binary.BigEndian.PutUint32(a[28:32], 0)
}

// GetType returns bytes 16–19.
func (a *Address) GetType() uint32 {
	return binary.BigEndian.Uint32(a[16:20])
}

// SetKeyPairAddress sets bytes 20–23.
func (a *Address) SetKeyPairAddress(v uint32) {
	binary.BigEndian.PutUint32(a[20:24], v)
}

// GetKeyPairAddress returns bytes 20–23.
func (a *Address) GetKeyPairAddress() uint32 {
	return binary.BigEndian.Uint32(a[20:24])
}

// SetChainAddress sets bytes 24–27.
func (a *Address) SetChainAddress(v uint32) {
	binary.BigEndian.PutUint32(a[24:28], v)
}

// GetChainAddress returns bytes 24–27.
func (a *Address) GetChainAddress() uint32 {
	return binary.BigEndian.Uint32(a[24:28])
}

// SetHashAddress sets bytes 28–31.
func (a *Address) SetHashAddress(v uint32) {
	binary.BigEndian.PutUint32(a[28:32], v)
}

// GetHashAddress returns bytes 28–31.
func (a *Address) GetHashAddress() uint32 {
	return binary.BigEndian.Uint32(a[28:32])
}

// SetTreeHeight sets bytes 24–27 (alias for tree contexts).
func (a *Address) SetTreeHeight(v uint32) {
	binary.BigEndian.PutUint32(a[24:28], v)
}

// GetTreeHeight returns bytes 24–27.
func (a *Address) GetTreeHeight() uint32 {
	return binary.BigEndian.Uint32(a[24:28])
}

// SetTreeIndex sets bytes 28–31 (alias for tree contexts).
func (a *Address) SetTreeIndex(v uint32) {
	binary.BigEndian.PutUint32(a[28:32], v)
}

// GetTreeIndex returns bytes 28–31.
func (a *Address) GetTreeIndex() uint32 {
	return binary.BigEndian.Uint32(a[28:32])
}

// Copy returns a copy of the address.
func (a *Address) Copy() Address {
	var c Address
	copy(c[:], a[:])
	return c
}

// CompressedAddress returns the 22-byte compressed address (ADRSc) used
// in SHA2 variants per FIPS 205.
// ADRSc drops the high 3 bytes from layer and type, keeps full tree (8 bytes)
// and full 4-byte words for keypair, chain/height, hash/index.
func (a *Address) CompressedAddress() []byte {
	// ADRSc layout (22 bytes):
	// byte  0: layer (last byte of bytes 0–3)
	// bytes 1–8: tree address (bytes 8–15, the uint64 part)
	// byte  9: type (last byte of bytes 16–19)
	// bytes 10–13: keypair (bytes 20–23)
	// bytes 14–17: chain/height (bytes 24–27)
	// bytes 18–21: hash/index (bytes 28–31)
	c := make([]byte, 22)
	c[0] = a[3]               // layer: last byte of 4-byte field
	copy(c[1:9], a[8:16])     // tree address: 8-byte uint64 portion
	c[9] = a[19]              // type: last byte of 4-byte field
	copy(c[10:14], a[20:24])  // keypair: 4 bytes
	copy(c[14:18], a[24:28])  // chain/height: 4 bytes
	copy(c[18:22], a[28:32])  // hash/index: 4 bytes
	return c
}
