package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/bastionzero/keysplitting"
)

func runAdditiveBrokered() {
	fmt.Println("Running sequential additive script -- a split/sign workflow with a central broker to verify")
	msg := "test message"
	hasher := sha512.New()
	hasher.Write([]byte(msg))
	hashed := hasher.Sum(nil)

	/*
	 * This operation is performed on a trusted server. It securely distributes the shards, then destroys them.
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
	 * In this model, all parties sign in parallel, then send their partial signatures to a central broker for verification.
	 */
	sig1, err := keysplitting.SignFirst(rand.Reader, shard0, crypto.SHA512, hashed)
	if err != nil {
		panic(err)
	}

	sig2, err := keysplitting.SignFirst(rand.Reader, shard1, crypto.SHA512, hashed)
	if err != nil {
		panic(err)
	}

	sig3, err := keysplitting.SignFirst(rand.Reader, shard2, crypto.SHA512, hashed)
	if err != nil {
		panic(err)
	}

	/*
	 * The broker rolls up all the partial signatures into the complete one, which verifies.
	 * To do this, simply convert the signatures to integers, multiply them, and mod by the public modulus
	 */
	sig1int := new(big.Int).SetBytes(sig1)
	sig2int := new(big.Int).SetBytes(sig2)
	sig3int := new(big.Int).SetBytes(sig3)

	sig1and2 := new(big.Int).Mul(sig1int, sig2int)
	sigFinal := new(big.Int).Mul(sig1and2, sig3int)
	sigFinal.Mod(sigFinal, key.N)

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sigFinal.Bytes())
	if err != nil {
		panic(err)
	}

	// none of the 3 partial signatures will verify
	sig1Err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sig1)
	if sig1Err == nil {
		panic(err)
	}

	sig2Err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sig2)
	if sig2Err == nil {
		panic(err)
	}

	sig3Err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hashed, sig3)
	if sig3Err == nil {
		panic(err)
	}

	fmt.Println("Success!")
}
