package keysplitting

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

const pemType = "RSA SPLIT PRIVATE KEY"

// A SplitPrivateKey represents an RSA key shard. The public key matches that of the original key
type SplitPrivateKey struct {
	PublicKey *rsa.PublicKey // public part
	D         *big.Int       // split private exponent
	// someday could have "E minor," the split public exponent
}

// used exclusively as a placeholder for encoding-decoding
type publicKey struct {
	N []byte
	E int
}

// used exclusively as a placeholder for encoding-decoding
type splitPrivateKey struct {
	PublicKey publicKey
	D         []byte
}

func (spk *SplitPrivateKey) EncodePEM() (string, error) {
	// we perform this conversion because asn1.Marshal cannot handle pointer values or unexported fields
	spkToMarshal := splitPrivateKey{
		PublicKey: publicKey{
			N: spk.PublicKey.N.Bytes(),
			E: spk.PublicKey.E,
		},
		D: spk.D.Bytes(),
	}
	b, err := asn1.Marshal(spkToMarshal)
	if err != nil {
		return "", fmt.Errorf("failed to DER-encode: %s", err)
	}

	keyPEM := new(bytes.Buffer)
	err = pem.Encode(keyPEM, &pem.Block{
		Type:  pemType,
		Bytes: b,
	})
	if err != nil {
		return "", fmt.Errorf("failed to PEM-encode: %s", err)
	}

	return keyPEM.String(), nil
}

func DecodePEM(encoded string) (*SplitPrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil || block.Type != pemType {
		return nil, fmt.Errorf("failed to decode PEM block containing split private key")
	}

	var spkToUnmarshal splitPrivateKey

	// do I need to do anything with rst?
	_, err := asn1.Unmarshal(block.Bytes, &spkToUnmarshal)

	return &SplitPrivateKey{
		PublicKey: &rsa.PublicKey{
			N: new(big.Int).SetBytes(spkToUnmarshal.PublicKey.N),
			E: spkToUnmarshal.PublicKey.E,
		},
		D: new(big.Int).SetBytes(spkToUnmarshal.D),
	}, err
}
