/*
Package keysplitting implements primitives for multi-party RSA signatures using Go's crypto/rsa library

# Overview

Keysplitting supports a simple and secure flow for producing multi-party signatures. First, a broker generates an ordinary RSA keypair and splits the private key into shards:

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	shards, err := keysplitting.SplitD(key, 2, keysplitting.Addition)
	if err != nil {
	    return err
	}

The broker then distributes the private shards (as well as the public key) over a secure channel,
destroying each shards as it is sent. If the broker will be one of the parties to the signature,
it keeps one of the shards.

When it comes time to sign a message, the key shards do not need to be reassembled.
Instead, each party uses its shard to generate a partial signature. It is these partial signatures,
not the shards, that are combined to create the final valid signature.
This can be verified against the public key in the usual way:

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hash, fullSig)

# The additive vs. multiplicative split schemes

Keysplitting offers two algorithms for splitting the private key, Addition and Multiplication, specified by the [SplitBy] type.
Both methods are equally secure and applicable to most use cases. However, the following differences may lead you to choose one over the other:
  - The Multiplication algorithm supports blinding during signature (TODO: not yet implemented)
  - The Multiplication algorithm can only be used sequentially (i.e. partial signatures / decryptions are generated one at a time by parties who each have their own shard)
  - The Addition algorithm can be used sequentially. Alternatively, all parties can partially sign at once and send the results to a broker, who can combine them without using a key shard

To learn how to use each algorithm, see the [examples]. To learn more about how they work, see this TODO: detailed explanation published somewhere!!

# Sources

	[1] https://eprint.iacr.org/2001/060.pdf
	[2] https://crypto.stanford.edu/semmail/mrsa.pdf

[examples]: https://github.com/bastionzero/keysplitting/tree/master/examples
*/
package keysplitting
