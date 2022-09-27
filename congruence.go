package mpcrsa

import (
	"math/big"
)

// check that n divides (a - b)
func congruentModN(a *big.Int, b *big.Int, N *big.Int) bool {
	aModN := new(big.Int).Mod(a, N)
	bModN := new(big.Int).Mod(b, N)

	return aModN.Cmp(bModN) == 0
}
