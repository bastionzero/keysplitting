package math

import (
	"math/big"
)

// FIXME: debatable whether this needs to be separate at this point -- still want the test though!

// check that n divides (a - b)
func CongruentModN(a *big.Int, b *big.Int, N *big.Int) bool {
	aModN := new(big.Int).Mod(a, N)
	bModN := new(big.Int).Mod(b, N)

	return aModN.Cmp(bModN) == 0
}
