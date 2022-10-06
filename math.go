package keysplitting

import (
	"math/big"
)

// check that n divides (a - b)
func congruentModN(a *big.Int, b *big.Int, N *big.Int) bool {
	aModN := new(big.Int).Mod(a, N)
	bModN := new(big.Int).Mod(b, N)

	return aModN.Cmp(bModN) == 0
}

// calculate the Euler totient of n using its prime factors, however many there are
func eulerTotient(primes []*big.Int) *big.Int {
	// multiply the first two primes (guaranteed to be at least 2)
	// phi <- (p[0] - 1) * (p[1] - 1)
	p0m1 := new(big.Int).Sub(primes[0], bigOne)
	p1m1 := new(big.Int).Sub(primes[1], bigOne)
	phi := new(big.Int).Mul(p0m1, p1m1)

	// iteratively multiply any additional primes to phi
	for i := 2; i < len(primes); i++ {
		// phi[i] <- phi[i-1] * (p[i] - 1)
		pim1 := new(big.Int).Sub(primes[i], bigOne)
		phi.Mul(phi, pim1)
	}

	return phi
}
