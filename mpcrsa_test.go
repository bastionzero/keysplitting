package mpcrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"bastionzero.com/mpcrsa/v1/mpcrsa/math"
)

func sumShards(shards []*big.Int) *big.Int {
	result := big.NewInt(0)
	for _, s := range shards {
		result.Add(result, s)
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

	BeforeEach(func() {
	})

	Context("Splitting keys additively", func() {

		priv, err := rsa.GenerateKey(rand.Reader, keyLength)
		Expect(err).To(BeNil(), fmt.Sprintf("failed to generate %d-bit RSA key: %s", keyLength, err))

		When("Splitting a key 2 ways", func() {

			shards, err := SplitD(priv, 2, Addition)
			Expect(err).To(BeNil(), fmt.Sprintf("failed to split RSA key into 2 shards: %s", err))

			It("Produces keys whose sum is congruent to the original key mod phi(N)", func() {
				shardSum := sumShards(shards)
				phi := phi(priv.Primes)
				Expect(math.CongruentModN(shardSum, priv.D, phi)).To(BeTrue(), fmt.Sprintf("%v ≢ %v (mod %v)", shardSum, priv.D, phi))
			})

			It("Produces a valid signature", func() {
				hasher := sha512.New()

				hasher.Write([]byte(message))

				hash := hasher.Sum(nil)
				sig1, err := SignFirst(rand.Reader, shards[0], crypto.SHA512, hash, &priv.PublicKey)
				Expect(err).To(BeNil(), fmt.Sprintf("failed to generate first signature: %s", err))

				sigFinal, err := SignNext(rand.Reader, shards[1], crypto.SHA512, hash, &priv.PublicKey, Addition, sig1)
				Expect(err).To(BeNil(), fmt.Sprintf("failed to generate final signature: %s", err))

				err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hash, sigFinal)
				Expect(err).To(BeNil(), fmt.Sprintf("failed to verify signature %s with public key: %s", sigFinal, err))
			})
		})

		When("Splitting a key 16 ways", func() {

			shards, err := SplitD(priv, 16, Addition)
			Expect(err).To(BeNil(), fmt.Sprintf("failed to split RSA key into 16 shards: %s", err))

			It("Produces keys whose sum is congruent to the original key mod phi(N)", func() {
				shardSum := sumShards(shards)
				phi := phi(priv.Primes)
				Expect(math.CongruentModN(shardSum, priv.D, phi)).To(BeTrue(), fmt.Sprintf("%v ≢ %v (mod %v)", shardSum, priv.D, phi))
			})
		})
	})
})
