/*
Package keysplitting implements primitives for multi-party RSA signatures using Go's crypto/rsa library

# Overview

TODO: what is this for, fundamentally?

# Keysplitting supports a simple and secure flow for producing multi-party signatures

First, a broker generates an ordinary RSA keypair and splits the private key into shards:

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	shards, err := keysplitting.SplitD(key, 2, keysplitting.Addition)

TODO: look into how other libraries handle this awkwardness about errors in examples

The broker then distributes the private shards (as well as the public key) over a secure channel,
destroying each shards as it is sent. If the broker will be one of the parties to the signature,
it keeps one of the shards

When it comes time to sign a message, the key shards do not need to be reassembled.
Instead, each party uses its shard to generate a partial signature. It is these partial signatures,
not the shards, that are combined to create the final valid signature.
This can be verified against the public key as usual:

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, hash, fullSig)

# The additive vs. multiplicative split schemes

Keysplitting offers two algorithms for splitting the private key, Addition and Multiplication, specified by the [SplitBy] type.
Both methods are equally secure, but they differ slightly in their models for combining partial signatures,
either "sequential" or "parallel."  TODO: really what would be more useful here would be a discussion of architectures

In the sequential model, the partial signatures are combined iteratively,
with one party signing at a time and then passing on the result until the signature is complete. In the parallel model,
all parties sign individually and then send their partial signatures to a broker, who combines them.
The Multiplication algorithm supports only the sequential model, whereas the Addition algorithm supports either.

The Multiplication algorithm splits the private key into k "multiplicative" shards, such that d1 * d2 * ... * dk ≡ d (mod Φ).
To perform a joint signature with multiplicative shards:
  - Only one party signs the message directly, and sends its partial signature to the next party
  - Each subsequent party receives a partial signature and uses its shard to sign it -- not the message.
  - The complete signature is the result of this chain of modular exponentiaation: H(m)^(d1 * d2 * ... * dk) (mod Φ)
  - TODO: link to example or reframe this as code

We see that only parties in possession of a key shard can build the complete signature. Therefore, the parallel
model is not supported. TODO: is it even worth saying that you don't need to pass the message? Is that a remotely useful thing?
TODO: parallel isn't a great name; you could technically do it in parallel. You just can't do it with a central broker

The Addition algorithm splits the private key into k "additive" shards, such that d1 + d2 + ... + dk ≡ d (mod Φ).
To perform a joint signature with additive shards:

  - Each party i uses its shard di to sign a copy of the message, generating a partial signature si
  - To combine the partial signatures, multiply their integer representations together (mod Φ)
  - The complete signature is the product s1 * s2 * ... * sk (mod Φ)
  - TODO: link to example or reframe this as code

We see that the parallel model is supported, because a central broker can multiply the partial signatures together without
possessing a shard. However, if no such broker exists, the signing parties can still build the signature sequentially.

# Sources

	[1] https://eprint.iacr.org/2001/060.pdf
*/
package keysplitting

// FIXME: examples for additive and multiplicative
// TODO: correct how d1, d2 are used in combination with shard1, shard2
