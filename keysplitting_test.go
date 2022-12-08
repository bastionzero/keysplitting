package keysplitting

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

const maxTestShards = 16

// randomize order of shards
func shuffleShards(shards []*SplitPrivateKey) {
	mrand.Seed(int64(time.Now().UnixMicro()))
	for i := range shards {
		j := mrand.Intn(i + 1)
		shards[i], shards[j] = shards[j], shards[i]
	}
}

func shardProduct(shards []*SplitPrivateKey) *big.Int {
	result := big.NewInt(1)
	for _, s := range shards {
		result.Mul(result, s.D)
	}
	return result
}

// run a full workflow of splitting a key and using the shards to sign a message
func runTest(priv *rsa.PrivateKey, i int, hashed []byte, splitBy SplitBy) {
	var shards []*SplitPrivateKey
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
		By("Shuffling the shards to demonstrate that the order of signatures doesn't matter")
		shuffleShards(shards)

		// although the overall order doesn't matter, someone has to make the first signature
		sig1, err := SignFirst(rand.Reader, shards[0], crypto.SHA512, hashed)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to generate first signature: %s", err))

		// simulate each party iteratively adding their signature
		sigNext := sig1
		for k := 1; k < len(shards); k++ {
			// no partial signatures should verify
			Expect(rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hashed, sigNext)).NotTo(Succeed(), "partial signature must not verify")

			sigNext, err = SignNext(rand.Reader, shards[k], crypto.SHA512, hashed, splitBy, sigNext)
			Expect(err).To(BeNil(), fmt.Sprintf("failed to generate signature #%d: %s", k, err))
		}

		// verify once all parties have signed
		err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hashed, sigNext)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to verify signature: %s", err))
	})
}

func TestKeysplitting(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Keysplitting Suite")
}

var _ = Describe("Keysplitting", func() {

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
	})

	Context("Splitting keys multiplicatively", func() {
		priv, _ := rsa.GenerateKey(rand.Reader, keyLength)

		for i := 2; i <= maxTestShards; i++ {
			When(fmt.Sprintf("Splitting a key %d ways", i), Ordered, func() {
				runTest(priv, i, hashed, Multiplication)
			})
		}
	})

	Context("Splitting keys additively", func() {
		priv, _ := rsa.GenerateKey(rand.Reader, keyLength)
		for i := 2; i <= maxTestShards; i++ {
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
