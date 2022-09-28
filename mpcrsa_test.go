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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// randomize order of shards
func shuffleShards(shards []*big.Int) {
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

	Context("Splitting keys additively", func() {
		priv, err := rsa.GenerateKey(rand.Reader, keyLength)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to generate %d-bit RSA key: %s", keyLength, err))

		for i := 2; i <= maxShards; i++ {
			When(fmt.Sprintf("Splitting a key %d ways", i), func() {

				shards, err := SplitD(priv, i, Addition)
				Expect(err).To(BeNil(), fmt.Sprintf("failed to split RSA key into %d shards: %s", i, err))

				It("Produces keys whose sum is congruent to the original key mod phi(N)", func() {
					sum := shardSum(shards)
					phi := phi(priv.Primes)
					Expect(congruentModN(sum, priv.D, phi)).To(BeTrue(), fmt.Sprintf("%v ≢ %v (mod %v)", sum, priv.D, phi))
				})

				It("Produces a valid split signature", func() {
					sig1, err := SignFirst(rand.Reader, shards[0], crypto.SHA512, hashed, &priv.PublicKey)
					Expect(err).To(BeNil(), fmt.Sprintf("failed to generate first signature: %s", err))

					// this randomization demonstrates that the order of signing doesn't matter
					shuffleShards(shards)

					// simulate each party iteratively adding their signature
					sigNext := sig1
					for i := 1; i < len(shards); i++ {
						sigNext, err = SignNext(rand.Reader, shards[i], crypto.SHA512, hashed, &priv.PublicKey, Addition, sigNext)
						Expect(err).To(BeNil(), fmt.Sprintf("failed to generate signature #%d: %s", i, err))
					}

					// verify once all parties have signed
					err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hashed, sigNext)
					Expect(err).To(BeNil(), fmt.Sprintf("failed to verify signature: %s", err))
				})
			})
		}
	})

	Context("Splitting keys multiplicatively", func() {
		priv, err := rsa.GenerateKey(rand.Reader, keyLength)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to generate %d-bit RSA key: %s", keyLength, err))

		for i := 2; i <= maxShards; i++ {
			When(fmt.Sprintf("Splitting a key %d ways", i), func() {

				shards, err := SplitD(priv, i, Multiplication)
				Expect(err).To(BeNil(), fmt.Sprintf("failed to split RSA key into %d shards: %s", i, err))

				It("Produces keys whose product is congruent to the original key mod phi(N)", func() {
					product := shardProduct(shards)
					phi := phi(priv.Primes)
					Expect(congruentModN(product, priv.D, phi)).To(BeTrue(), fmt.Sprintf("%v ≢ %v (mod %v)", product, priv.D, phi))
				})

				It("Produces a valid split signature", func() {
					sig1, err := SignFirst(rand.Reader, shards[0], crypto.SHA512, hashed, &priv.PublicKey)
					Expect(err).To(BeNil(), fmt.Sprintf("failed to generate first signature: %s", err))

					// this randomization demonstrates that the order of signing doesn't matter
					shuffleShards(shards)

					// simulate each party iteratively adding their signature
					sigNext := sig1
					for i := 1; i < len(shards); i++ {
						sigNext, err = SignNext(rand.Reader, shards[i], crypto.SHA512, hashed, &priv.PublicKey, Multiplication, sigNext)
						Expect(err).To(BeNil(), fmt.Sprintf("failed to generate signature #%d: %s", i, err))
					}

					// verify once all parties have signed
					err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hashed, sigNext)
					Expect(err).To(BeNil(), fmt.Sprintf("failed to verify signature: %s", err))
				})
			})
		}
	})
})
