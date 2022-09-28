package mpcrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// randomize order of shards
func shuffleShards(shards []*big.Int) {
	mrand.Seed(int64(time.Now().UnixMicro()))
	for i := range shards {
		j := mrand.Intn(i + 1)
		shards[i], shards[j] = shards[j], shards[i]
	}
}

func shardSum(shards []*big.Int) *big.Int {
	result := big.NewInt(0)
	for _, s := range shards {
		result.Add(result, s)
	}
	return result
}

func shardProduct(shards []*big.Int) *big.Int {
	result := big.NewInt(1)
	for _, s := range shards {
		result.Mul(result, s)
	}
	return result
}

func runTest(priv *rsa.PrivateKey, i int, hashed []byte, splitBy SplitBy) {
	var shards []*big.Int
	var err error
	var label string
	switch splitBy {
	case Multiplication:
		label = "product"
	case Addition:
		label = "sum"
	}

	It("Successfully splits the key", func() {
		shards, err = SplitD(priv, i, splitBy)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to split RSA key into %d shards: %s", i, err))
	})

	It(fmt.Sprintf("Produces keys whose %s is congruent to the original key mod phi(N)", label), func() {
		phi := eulerTotient(priv.Primes)

		switch splitBy {
		case Multiplication:
			product := shardProduct(shards)
			Expect(congruentModN(product, priv.D, phi)).To(BeTrue(), fmt.Sprintf("%v ≢ %v (mod %v)", product, priv.D, phi))
		case Addition:
			sum := shardSum(shards)
			Expect(congruentModN(sum, priv.D, phi)).To(BeTrue(), fmt.Sprintf("%v ≢ %v (mod %v)", sum, priv.D, phi))
		}
	})

	It("Produces a valid split signature", func() {
		// this randomization demonstrates that the order of signing doesn't matter
		shuffleShards(shards)

		sig1, err := SignFirst(rand.Reader, shards[0], crypto.SHA512, hashed, &priv.PublicKey)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to generate first signature: %s", err))

		// simulate each party iteratively adding their signature
		sigNext := sig1
		for k := 1; k < len(shards); k++ {
			sigNext, err = SignNext(rand.Reader, shards[k], crypto.SHA512, hashed, &priv.PublicKey, splitBy, sigNext)
			Expect(err).To(BeNil(), fmt.Sprintf("failed to generate signature #%d: %s", k, err))
		}

		// verify once all parties have signed
		err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hashed, sigNext)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to verify signature: %s", err))
	})
}

// TODO: I mean obviously this should say TestKeySplitting
func TestMpcRsa(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MpcRsa Suite")
}

var _ = Describe("MpcRsa", func() {

	keyLength := 2048
	message := "TEST MESSAGE"

	hashFn := sha512.New()
	hashFn.Write([]byte(message))
	hashed := hashFn.Sum(nil)

	Context("Basic interfacing", func() {
		priv, _ := rsa.GenerateKey(rand.Reader, keyLength)

		When("Attempting to split a key into 1 shard", func() {
			It("Should fail", func() {
				_, err := SplitD(priv, 1, Addition)
				Expect(err).NotTo(BeNil(), "Shouldn't be able to split a key into 1 shard")
			})
		})

		When("Attempting to split a key into too many shards", func() {
			It("Should fail", func() {
				_, err := SplitD(priv, maxShards+1, Addition)
				Expect(err).NotTo(BeNil(), fmt.Sprintf("Shouldn't be able to split a key %d ways", maxShards+1))
			})
		})
	})

	Context("Splitting keys multiplicatively", func() {
		priv, _ := rsa.GenerateKey(rand.Reader, keyLength)

		for i := 2; i <= maxShards; i++ {
			When(fmt.Sprintf("Splitting a key %d ways", i), Ordered, func() {
				runTest(priv, i, hashed, Multiplication)
			})
		}
	})

	Context("Splitting keys additively", func() {
		priv, _ := rsa.GenerateKey(rand.Reader, keyLength)
		for i := 2; i <= maxShards; i++ {
			When(fmt.Sprintf("Splitting a key %d ways", i), func() {
				runTest(priv, i, hashed, Addition)
			})
		}
	})

	// we don't expect multi-prime keys to be heavily used but we should make sure they can be split just like everybody else
	Context("Multi-prime keys", func() {
		When("Using a 4096-bit / 3-prime key split 5 ways additively", func() {
			priv, _ := rsa.GenerateMultiPrimeKey(rand.Reader, 3, keyLength*2)
			runTest(priv, 5, hashed, Addition)
		})

		When("Using a 8192-bit / 5-prime key split 3 ways multiplicatively", func() {
			priv, _ := rsa.GenerateMultiPrimeKey(rand.Reader, 5, keyLength*4)
			runTest(priv, 5, hashed, Addition)
		})
	})
})
