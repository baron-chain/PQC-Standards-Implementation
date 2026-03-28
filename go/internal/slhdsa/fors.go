package slhdsa

// FORS (Forest of Random Subsets) implementation per FIPS 205.

// FORSSKGen generates a FORS secret key value.
// FIPS 205 Algorithm 12.
func FORSSKGen(hs HashSuite, skSeed, pkSeed []byte, adrs *Address, idx int, n int) []byte {
	skAdrs := adrs.Copy()
	skAdrs.SetType(AddrForsPRF)
	skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	skAdrs.SetTreeIndex(uint32(idx))
	return hs.PRF(pkSeed, skSeed, &skAdrs, n)
}

// FORSNode computes a node in a FORS tree.
// FIPS 205 Algorithm 13: fors_node(SK.seed, i, z, PK.seed, ADRS).
// adrs is never modified; local copies are used for all hash calls.
func FORSNode(hs HashSuite, skSeed, pkSeed []byte, i, z int, adrs *Address, p *Params) []byte {
	n := p.N
	kp := adrs.GetKeyPairAddress()

	if z == 0 {
		sk := FORSSKGen(hs, skSeed, pkSeed, adrs, i, n)
		nodeAdrs := adrs.Copy()
		nodeAdrs.SetType(AddrForsTree)
		nodeAdrs.SetKeyPairAddress(kp)
		nodeAdrs.SetTreeHeight(0)
		nodeAdrs.SetTreeIndex(uint32(i))
		return hs.F(pkSeed, &nodeAdrs, sk, n)
	}

	left := FORSNode(hs, skSeed, pkSeed, 2*i, z-1, adrs, p)
	right := FORSNode(hs, skSeed, pkSeed, 2*i+1, z-1, adrs, p)

	nodeAdrs := adrs.Copy()
	nodeAdrs.SetType(AddrForsTree)
	nodeAdrs.SetKeyPairAddress(kp)
	nodeAdrs.SetTreeHeight(uint32(z))
	nodeAdrs.SetTreeIndex(uint32(i))

	concat := make([]byte, 0, 2*n)
	concat = append(concat, left...)
	concat = append(concat, right...)
	return hs.H(pkSeed, &nodeAdrs, concat, n)
}

// FORSSign generates a FORS signature.
// FIPS 205 Algorithm 14: fors_sign(md, SK.seed, PK.seed, ADRS).
func FORSSign(hs HashSuite, md, skSeed, pkSeed []byte, adrs *Address, p *Params) []byte {
	n := p.N
	k := p.K
	a := p.A

	indices := base2b(md, a, k)

	sig := make([]byte, 0, k*(1+a)*n)

	for i := 0; i < k; i++ {
		idx := indices[i]
		absIdx := i*(1<<uint(a)) + idx // global leaf index in FORS forest

		// Secret key value
		sk := FORSSKGen(hs, skSeed, pkSeed, adrs, absIdx, n)
		sig = append(sig, sk...)

		// Authentication path: sibling at each height j
		// Global sibling index at height j = i*2^(a-j) + ((idx>>j)^1)
		for j := 0; j < a; j++ {
			globalSibling := i*(1<<uint(a-j)) + ((idx >> uint(j)) ^ 1)
			authNode := FORSNode(hs, skSeed, pkSeed, globalSibling, j, adrs, p)
			sig = append(sig, authNode...)
		}
	}

	return sig
}

// FORSPKFromSig computes the FORS public key from a signature.
// FIPS 205 Algorithm 15: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS).
func FORSPKFromSig(hs HashSuite, sigFORS, md, pkSeed []byte, adrs *Address, p *Params) []byte {
	n := p.N
	k := p.K
	a := p.A

	indices := base2b(md, a, k)

	roots := make([]byte, 0, k*n)
	offset := 0

	kp := adrs.GetKeyPairAddress()

	for i := 0; i < k; i++ {
		idx := indices[i]
		absIdx := i*(1<<uint(a)) + idx // global leaf index in FORS forest

		// Leaf from secret key
		sk := sigFORS[offset : offset+n]
		offset += n

		nodeAdrs := adrs.Copy()
		nodeAdrs.SetType(AddrForsTree)
		nodeAdrs.SetKeyPairAddress(kp)
		nodeAdrs.SetTreeHeight(0)
		nodeAdrs.SetTreeIndex(uint32(absIdx))
		node := hs.F(pkSeed, &nodeAdrs, sk, n)

		// Walk up authentication path
		for j := 0; j < a; j++ {
			authNode := sigFORS[offset : offset+n]
			offset += n

			nodeAdrs.SetTreeHeight(uint32(j + 1))
			nodeAdrs.SetTreeIndex(uint32(absIdx >> uint(j+1)))

			if (idx>>uint(j))%2 == 0 {
				concat := make([]byte, 0, 2*n)
				concat = append(concat, node...)
				concat = append(concat, authNode...)
				node = hs.H(pkSeed, &nodeAdrs, concat, n)
			} else {
				concat := make([]byte, 0, 2*n)
				concat = append(concat, authNode...)
				concat = append(concat, node...)
				node = hs.H(pkSeed, &nodeAdrs, concat, n)
			}
		}

		roots = append(roots, node...)
	}

	// Hash all roots together
	forsRootsAdrs := adrs.Copy()
	forsRootsAdrs.SetType(AddrForsRoots)
	forsRootsAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	return hs.Tl(pkSeed, &forsRootsAdrs, roots, n)
}
