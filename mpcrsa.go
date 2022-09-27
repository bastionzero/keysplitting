/*
Package mpcrsa implements primitives for multi-party computation (MPC) using Go's crypto/rsa library
*/
package mpcrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

// FIXME: probably a better way to initialize big ints
// e.g. new(big.Int).SetBytes(em)

type SplitBy int

const (
	Addition SplitBy = iota
	Multiplication

	maxShards = 16
)

var (
	one = big.NewInt(1)
)

// SplitD returns k shards that together compose priv.D
func SplitD(priv *rsa.PrivateKey, k int, splitBy SplitBy) ([]*big.Int, error) {
	if k > maxShards {
		return nil, fmt.Errorf("cannot split key into %d shards. Maximum is %d", k, maxShards)
	}

	phi := phi(priv.Primes)

	switch splitBy {
	case Multiplication:
		return splitMultiplicative(priv, k, phi)
	case Addition:
		return splitAdditive(priv, k, phi)
	default:
		return nil, fmt.Errorf("unrecognized splitBy argument: %v", splitBy)
	}
}

// FirstSign uses the given key shard to perform the initial signature on a message
func SignFirst(random io.Reader, shard *big.Int, hash crypto.Hash, hashed []byte, pub *rsa.PublicKey) ([]byte, error) {
	priv := &rsa.PrivateKey{
		PublicKey: *pub,
		D:         shard,
	}
	return rsa.SignPKCS1v15(random, priv, hash, hashed)
}

// NextSign uses the given key shard to sign a partially-signed message
func SignNext(random io.Reader, shard *big.Int, hash crypto.Hash, hashed []byte, pub *rsa.PublicKey, splitBy SplitBy, partialSig []byte) ([]byte, error) {
	switch splitBy {
	case Multiplication:
		return nil, fmt.Errorf("not yet implemented")
	case Addition:
		if nextSig, err := SignFirst(random, shard, hash, hashed, pub); err != nil {
			return nil, err
		} else {
			nextInt := new(big.Int).SetBytes(nextSig)
			partialInt := new(big.Int).SetBytes(partialSig)
			sigNext := new(big.Int).Mul(nextInt, partialInt)
			return sigNext.Bytes(), nil
		}
	default:
		return nil, fmt.Errorf("unrecognized splitBy argument: %v", splitBy)
	}
}

// calculate the Euler totient of priv.N
// TODO: consider renaming // test it
func phi(primes []*big.Int) *big.Int {
	// z1 and z2 are placeholders so that intermediate operations don't modify the original primes
	// FIXME: necessary?
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)

	z1.Sub(primes[0], one)

	// primes is guaranteed to have size >= 2
	// phi <- (p_0 - 1) * (p_1 - 1)
	phi := new(big.Int).Mul(z1.Sub(primes[0], one), z2.Sub(primes[1], one))

	// multiply any additional primes
	for i := 2; i < len(primes); i++ {
		// phi_i <- phi_(i-1) * (p_i - 1)
		phi.Mul(phi, z1.Sub(primes[i], one))
	}

	return phi
}

// TODO: shard name might be problematic
// FIXME: revisit this logic; pretty sure there's a better way to generate an n-byte number
// generate a shard of x by taking a random number of length len(x) - fewerBits
func randomShard(x *big.Int, fewerBytes int) (*big.Int, error) {
	lx := x.BitLen() / 8

	ly := lx - fewerBytes
	if ly < 0 {
		return nil, fmt.Errorf("TODO:")
	}

	b := make([]byte, ly)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to produce random number: %s", err)
	}

	return new(big.Int).SetBytes(b), nil
}

// FIXME: this has problems
func splitMultiplicative(priv *rsa.PrivateKey, k int, phi *big.Int) ([]*big.Int, error) {

	return nil, fmt.Errorf("not yet implemented")
	/*
		// generate initial shard slightly shorter than d
		// FIXME: s1 **HAS** to be coprime to phi for this to always work
		s1, err := randomShard(priv.D, 2)
		if err != nil {
			return nil, err
		}

		s2 := big.NewInt(0)
		// z1 and z2 are placeholders so that intermediate operations don't modify the original primes
		// FIXME: necessary?
		z1 := big.NewInt(0)
		// s_2 <- d/s_1 mod phi
		fmt.Printf("The things are:\nN: %v\ns2: %v\nD: %v\ns1: %v\none: %v\nphi: %v\n", priv.N, s2, priv.D, s1, one, phi)
		z1.Exp(s1, one.Neg(one), phi)
		fmt.Printf("z1: %v\n", z1)

		s2.Mul(priv.D, z1)

		return []*big.Int{s1, s2}, nil
	*/
}

func splitAdditive(priv *rsa.PrivateKey, k int, phi *big.Int) ([]*big.Int, error) {
	remainingD, err := copyBigInt(priv.D)
	if err != nil {
		return nil, err
	}

	shards := make([]*big.Int, k)
	var newShard *big.Int

	for i := 0; i < k; i++ {
		if i == k-1 {
			// if this is the lat shard, give it everything that's left
			shards[i] = remainingD
		} else {
			// TODO: D or remainingD?
			foundNewShard := false
			for !foundNewShard {
				// generate new shard slightly shorter than D
				// if D is a 2048-bit number, this will be 5 digits shorter in base 10
				newShard, err = randomShard(priv.D, 2)
				if err != nil {
					return nil, err
				} else if !shardIn(shards, newShard) {
					// make sure it's not a duplicate of an existing shard
					foundNewShard = true
				}
			}
			shards[i] = newShard
			// cumulatively subtract each shard value from D
			remainingD.Sub(remainingD, shards[i])
		}
	}
	return shards, nil
}

func shardIn(shards []*big.Int, shard *big.Int) bool {
	for _, s := range shards {
		if s != nil && s.Cmp(shard) == 0 {
			return true
		}
	}
	return false
}

func copyBigInt(x *big.Int) (*big.Int, error) {
	if result, ok := new(big.Int).SetString(x.String(), 10); !ok {
		return nil, fmt.Errorf("failed to copy invalid big.Int %v", x)
	} else {
		return result, nil
	}
}
