package keysplitting

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

// TODO: considering modifying the additive split to d + (r * phi)

// SplitBy determines the algorithm used to split the private key and combine partial signatures.
// Either algorithm is suitable from a performance and security standpoint
type SplitBy int

const (
	Multiplication SplitBy = iota
	Addition
)

// SplitD returns k private key shards that together compose priv.D
//
// If [SplitBy].Multiplication is used, the shards will be such that s1 * s2 * ... * sk ≡ D (mod phi(N))
//
// If [SplitBy].Addition is used, the shards will be such that s1 + s2 + ... + sk ≡ D (mod phi(N))
//
// "Either type of split lends itself equally well to two-party based signing," [1] but they are not interoperable.
// Whichever SplitBy method you use with SplitD, you must use the same method when running [SignNext]
func SplitD(priv *rsa.PrivateKey, k int, splitBy SplitBy) ([]*SplitPrivateKey, error) {
	if k < 2 {
		return nil, fmt.Errorf("cannot split key into fewer than 2 shards")
	}

	// because rsa.GenerateMultiPrimeKey supports an arbitrary number of primes, so do we.
	// priv.Primes are the factors of the modulus N
	phi := eulerTotient(priv.Primes)

	switch splitBy {
	case Multiplication:
		return splitMultiplicative(priv, k, phi)
	case Addition:
		return splitAdditive(priv, k, phi)
	default:
		return nil, fmt.Errorf("unrecognized splitBy argument: %v", splitBy)
	}
}

// finds shards for priv.D by finding random pairs of factors whose cumulative product is congruent to priv.D (mod phi)
//
// note: each shard is longer than the last, at a linear rate of growth.
// If the first shard is length 1, the second shard is length 2, the third length 3, and so on
func splitMultiplicative(priv *rsa.PrivateKey, k int, phi *big.Int) ([]*SplitPrivateKey, error) {

	shards := make([]*SplitPrivateKey, 0)
	seed := priv.D

	// each call to splitSeed produces a pair of shards such that shardA * shardB ≡ seed (mod phi), where D is the original seed.
	// If we require more than two shards, we sacrifice one of them to become the new seed. If a shard is being used as the next seed, it is not added to shards
	// For a *purely visual* but not mathematically correct analogy, think of it this way: https://i.stack.imgur.com/k4h0y.png,
	// where in the 3-shard case, we would use one 1/2 block and two 1/4 blocks
	for len(shards) < k {
		shardA, shardB, err := splitSeed(seed, phi)
		if err != nil {
			return nil, err
		}
		shards = append(shards, &SplitPrivateKey{
			PublicKey: &priv.PublicKey,
			D:         shardA,
		})

		// if we only need one more shard, add the "last" s2 and exit from the loop
		// (the break is not strictly necessary since len(shards) should now equal k)
		if len(shards) == k-1 {
			shards = append(shards, &SplitPrivateKey{
				PublicKey: &priv.PublicKey,
				D:         shardB,
			})
			break
		}

		// otherwise, use s2 as our new seed to be split
		seed = shardB
	}
	return shards, nil
}

// generate two shards of seed such that shardA * shardB ≡ seed (mod phi)
func splitSeed(seed *big.Int, phi *big.Int) (shardA *big.Int, shardB *big.Int, err error) {
	success := false
	for !success {
		shardA, err = validRandomNumber(phi, seed)
		if err != nil {
			return
		}

		// this will only succeed if shardA is coprime to phi, because otherwise,
		// shardA has no multiplicative inverse in the ring ℤ/phiℤ
		// however, validRandomNumber checks for coprimality with phi, so this
		// should always succeed
		shardAInverse := new(big.Int).ModInverse(shardA, phi)
		if shardAInverse == nil {
			continue
		}

		// shardB <- seed/shardA mod phi
		shardB = new(big.Int).Mul(seed, shardAInverse)
		success = true
	}

	return
}

// finds shards for priv.D by picking k random numbers whose sum is congruent to D (mod phi)
func splitAdditive(priv *rsa.PrivateKey, k int, phi *big.Int) ([]*SplitPrivateKey, error) {
	// we use this outer loop as a restart mechanism in case of an undesirable combination of shards
ShardSearchLoop:
	for {
		shards := make([]*SplitPrivateKey, k)
		var err error

		for i := 0; i < k; i++ {
			newShard := &SplitPrivateKey{PublicKey: &priv.PublicKey}
			foundNewShard := false

			if i == k-1 {
				// if this is the final shard, it's time to make sure all of this adds up to D (mod phi)
				sum := shardSum(shards)
				switch sum.Cmp(priv.D) {
				case -1:
					// [sum of shards] is less than D (less likely case)
					// set the remaining shard to D - [sum of shards]
					newShard.D = new(big.Int).Sub(priv.D, sum)
				case 1:
					// [sum of shards] is greater than D (more likely case)
					// set the remaining shard to phi - [sum of shards] + D
					phiMinusSum := new(big.Int).Sub(phi, sum)
					newShard.D = new(big.Int).Add(phiMinusSum, priv.D)
				default:
					// [sum of shards] is equal to D (astronomically unlikely)
					// not allowed, so restart the search
					continue ShardSearchLoop
				}

				if shardIn(shards, newShard) {
					// our new shard is equal to an existing one (astronomically unlikely)
					// not allowed, so restart the search
					continue ShardSearchLoop
				}

				foundNewShard = true
			}

			// if this is a shard other than the last one, just pick a new random number
			for !foundNewShard {
				newShard.D, err = validRandomNumber(phi, priv.D)
				if err != nil {
					return nil, err
				}

				if !shardIn(shards, newShard) {
					// make sure it's not a duplicate of an existing shard
					foundNewShard = true
				}
			}

			shards[i] = newShard
		}

		return shards, nil
	}
}

// returns a random number between 1 and phi that is
//   - coprime to phi
//   - not equal to seed
//
// TODO: revisit name
func validRandomNumber(phi *big.Int, seed *big.Int) (r *big.Int, err error) {
	for {
		// from section 2 of [1], pick a random integer between 1 and phi (exclusive)
		r, err = rand.Int(rand.Reader, phi)
		if err != nil {
			return
		}

		// from section 3.1 of [2], check that r is coprime to phi
		gcd := new(big.Int).GCD(nil, nil, r, phi)
		if gcd.Cmp(bigOne) != 0 {
			continue
		}

		// check that r is not equal to 0, 1, or seed
		if r.Cmp(bigZero) == 0 || r.Cmp(bigOne) == 0 || r.Cmp(seed) == 0 {
			continue
		}

		return
	}
}

// returns the sum of a slice of shards (nil shards count as 0)
func shardSum(shards []*SplitPrivateKey) *big.Int {
	result := big.NewInt(0)
	for _, s := range shards {
		if s != nil {
			result.Add(result, s.D)
		}
	}
	return result
}

func shardIn(shards []*SplitPrivateKey, shard *SplitPrivateKey) bool {
	for _, s := range shards {
		if s != nil && s.D != nil && s.D.Cmp(shard.D) == 0 {
			return true
		}
	}
	return false
}

// SignFirst uses the given key shard to perform the initial signature on a hashed message.
// Note that hashed must be the result of hashing the input message using the given hash function
func SignFirst(random io.Reader, shard *SplitPrivateKey, hashFn crypto.Hash, hashed []byte) ([]byte, error) {
	priv := &rsa.PrivateKey{
		PublicKey: *shard.PublicKey,
		D:         shard.D,
	}
	// TODO: revisit name
	return signPKCS1v15(random, priv, hashFn, hashed)
}

// SignNext uses the given key shard to sign a partially-signed message
//
// If [SplitBy].Multiplication is used, nextSig(H) <- partialSig(H)^shard (mod N), i.e. a chain of exponentiation
//
// If [SplitBy].Addition is used, nextSig(H) <- partialSig(H) * H^shard (mod N), i.e. a chain of multiplication
//
// Note that hashed must be the result of hashing the input message using the given hash function.
func SignNext(random io.Reader, shard *SplitPrivateKey, hashFn crypto.Hash, hashed []byte, splitBy SplitBy, partialSig []byte) ([]byte, error) {
	partialInt := new(big.Int).SetBytes(partialSig)

	switch splitBy {
	case Multiplication:
		nextSig := new(big.Int).Exp(partialInt, shard.D, shard.PublicKey.N)
		if nextSig == nil {
			return nil, fmt.Errorf("failed to add next signature with the given shard, public key, and partial signature")
		}

		return nextSig.Bytes(), nil
	case Addition:
		nextBaseSig, err := SignFirst(random, shard, hashFn, hashed)
		if err != nil {
			return nil, err
		}

		nextBaseInt := new(big.Int).SetBytes(nextBaseSig)
		nextSig := new(big.Int).Mul(nextBaseInt, partialInt)
		nextSig.Mod(nextSig, shard.PublicKey.N)
		return nextSig.Bytes(), nil
	default:
		return nil, fmt.Errorf("unrecognized splitBy argument: %v", splitBy)
	}
}
