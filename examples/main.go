package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"

	"bastionzero.com/mpcrsa/v1/mpcrsa"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	msg := "a message"
	fmt.Println("runnin...")
	hasher := sha512.New()

	hasher.Write([]byte(msg))

	hash := hasher.Sum(nil)
	/*
		hashInt := big.NewInt(int64(binary.BigEndian.Uint64(hash)))

		var sig, ver big.Int
		sig.Exp(hashInt, key.D, key.N)
	*/
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, hash)
	if err == nil {
		err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hash, sig)
		if err == nil {
			fmt.Println("you done it!")
		}
	}

	shards, err := mpcrsa.SplitD(key, 2, mpcrsa.Addition)
	if err == nil {
		fmt.Printf("Good job: %+v\n", shards)
	}
}
