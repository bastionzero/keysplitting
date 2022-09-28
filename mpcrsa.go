/*
Package mpcrsa implements primitives for multi-party computation (MPC) using Go's crypto/rsa library

informed by: https://eprint.iacr.org/2001/060.pdf
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

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

// FIXME: probably a better way to initialize big ints
// FIXME: cCopy := new(big.Int).Set(c)
// e.g. new(big.Int).SetBytes(em)
// and is there a better way to chain operations?
// seems like best practice is to split to multiple lines

type SplitBy int

const (
	Addition SplitBy = iota
	Multiplication

	maxShards = 16
)

// SplitD returns k shards that together compose priv.D
func SplitD(priv *rsa.PrivateKey, k int, splitBy SplitBy) ([]*big.Int, error) {
	if k > maxShards || k < 2 {
		return nil, fmt.Errorf("cannot split key into %d shards. 2 <= k <= %d", k, maxShards)
	} else if priv == nil {
		return nil, fmt.Errorf("cannot split a nil key")
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

// calculate the Euler totient of priv.N
// TODO: consider renaming // test it
func phi(primes []*big.Int) *big.Int {
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

// note: each shard is longer than the last, at a linear rate of growth. If the first shard is length 1, the second shard is length 2, the third length 3, and so on
func splitMultiplicative(priv *rsa.PrivateKey, k int, phi *big.Int) ([]*big.Int, error) {

	shards := make([]*big.Int, 0)
	seed := priv.D

	// each call to randomShardsMultiplicative produces a pair of shards such that s1 * s2 ≡ seed (mod phi), where D is the original seed.
	// If we require more than two shards, we sacrifice one of them to become the new seed.
	// For a *purely visual* but not mathematically correct analogy, think of it this way: https://i.stack.imgur.com/k4h0y.png,
	// where in the 3-shard case, we would use one 1/2 block and two 1/4 blocks
	for len(shards) < k {
		s1, s2, err := randomShardsMultiplicative(seed, phi)
		if err != nil {
			return nil, err
		}
		shards = append(shards, s1)

		// if we only need one more shard, add the "last" s2 and exit from the loop
		// (the break is not strictly necessary since len(shards) should now equal k)
		if len(shards) == k-1 {
			shards = append(shards, s2)
			break
		} else {
			// otherwise, use s2 as our new seed to be split
			seed = s2
		}
	}
	return shards, nil
}

// TODO: shard name might be problematic
// generate two shards of seed such that s1 * s2 ≡ seed (mod phi)
func randomShardsMultiplicative(seed *big.Int, phi *big.Int) (s1 *big.Int, s2 *big.Int, err error) {
	success := false
	for !success {
		// from section 2 of the paper, pick a random integer between 1 and phi (exclusive)
		s1, err = rand.Int(rand.Reader, phi)
		if err != nil {
			return
		} else if s1.Cmp(bigZero) == 0 || s1.Cmp(bigOne) == 0 {
			continue
		}

		// this will only succeed if s1 is coprime to phi
		s1i := new(big.Int).Exp(s1, big.NewInt(-1), phi)
		if s1i == nil {
			continue
		}

		// s2 <- d/s1 mod phi
		s2 = new(big.Int).Mul(seed, s1i)
		success = true
	}

	return s1, s2, err
}

func splitAdditive(priv *rsa.PrivateKey, k int, phi *big.Int) ([]*big.Int, error) {
	remainingD := new(big.Int).Set(priv.D)

	shards := make([]*big.Int, k)
	var newShard *big.Int
	var err error

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
				newShard, err = randomShardAdditive(priv.D, 2)
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

// TODO: shard name / xmight be problematic
// generate a shard of seed by taking a random number of length len(x) - fewerBits
func randomShardAdditive(seed *big.Int, fewerBytes int) (*big.Int, error) {
	lenSeed := seed.BitLen() / 8

	lenShard := lenSeed - fewerBytes
	// TODO: we should have a higher floor on this
	if lenShard <= 0 {
		return nil, fmt.Errorf("cannot create shard of length %d: minimum length is 1", lenShard)
	}

	b := make([]byte, lenShard)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to produce random number: %s", err)
	}

	return new(big.Int).SetBytes(b), nil
}

func shardIn(shards []*big.Int, shard *big.Int) bool {
	for _, s := range shards {
		if s != nil && s.Cmp(shard) == 0 {
			return true
		}
	}
	return false
}

// FirstSign uses the given key shard to perform the initial signature on a message
func SignFirst(random io.Reader, shard *big.Int, hash crypto.Hash, hashed []byte, pub *rsa.PublicKey) ([]byte, error) {
	priv := &rsa.PrivateKey{
		PublicKey: *pub,
		D:         shard,
	}
	// TODO: revisit name
	return signPKCS1v15(random, priv, hash, hashed)
}

// NextSign uses the given key shard to sign a partially-signed message
//
// If SplitBy.Multiplication, nextSig(H) <- partialSig(H)^shard (mod N), i.e. a chain of exponentiation
// If SplitBy.Addition, nextSig(H) <- partialSig(H) * H^shard (mod N), i.e. a chain of multiplication
//
// TODO: extra notes vis a vis signing the hash?
func SignNext(random io.Reader, shard *big.Int, hash crypto.Hash, hashed []byte, pub *rsa.PublicKey, splitBy SplitBy, partialSig []byte) ([]byte, error) {

	partialInt := new(big.Int).SetBytes(partialSig)

	switch splitBy {
	case Multiplication:
		if nextSig := new(big.Int).Exp(partialInt, shard, pub.N); nextSig == nil {
			return nil, fmt.Errorf("failed to add next signature with the given shard, public key, and partial signature")
		} else {
			return nextSig.Bytes(), nil
		}
	case Addition:
		if nextBaseSig, err := SignFirst(random, shard, hash, hashed, pub); err != nil {
			return nil, err
		} else {
			nextBaseInt := new(big.Int).SetBytes(nextBaseSig)
			nextSig := new(big.Int).Mul(nextBaseInt, partialInt)
			nextSig.Mod(nextSig, pub.N)
			return nextSig.Bytes(), nil
		}
	default:
		return nil, fmt.Errorf("unrecognized splitBy argument: %v", splitBy)
	}
}
