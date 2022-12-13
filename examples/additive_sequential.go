package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"

	"github.com/bastionzero/keysplitting"
)

func runAdditiveSequential() {
	fmt.Println("Running sequential additive script -- a basic split/sign workflow")
	msg := "test message"
	hasher := sha512.New()
	hasher.Write([]byte(msg))
	hashed := hasher.Sum(nil)

	/*
	 * This operation is performed on a trusted server. It securely distributes the shards, then destroys them.
	 * Optionally, the server may be one of the signing parties and keep a shard for itself/.
	 */
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	shards, err := keysplitting.SplitD(key, 3, keysplitting.Addition)
	if err != nil {
		panic(err)
	}
	shard0 := shards[0]
	shard1 := shards[1]
	shard2 := shards[2]

	shards = nil

	/*
	 * Although the overall order doesn't matter, someone has to make the first signature.
	 * The first signing party signs the message and sends the partially-signed message to the next party in the clear.
	 * The original message must be sent as well.
	 */
	sig1, err := keysplitting.SignFirst(rand.Reader, shard0, crypto.SHA512, hashed)
	if err != nil {
		panic(err)
	}

	/*
	 * Upon receiving sig1 and the message, the second party adds their signature and sends it to the third party
	 */
	sig2, err := keysplitting.SignNext(rand.Reader, shard1, crypto.SHA512, hashed, sig1)
	if err != nil {
		panic(err)
	}

	/*
	 * Upon receiving sig2 and the message, the third party adds their signature. Only this signature will verify
	 */
	sig3, err := keysplitting.SignNext(rand.Reader, shard2, crypto.SHA512, hashed, sig2)
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sig3)
	if err != nil {
		panic(err)
	}

	// neither of the partial signatures will verify
	sig1Err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sig1)
	if sig1Err == nil {
		panic(err)
	}

	sig2Err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sig2)
	if sig2Err == nil {
		panic(err)
	}

	fmt.Println("Success!")
}
