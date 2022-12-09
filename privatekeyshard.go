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

// A PrivateKeyShard represents one shard of a split RSA key. The public key matches that of the whole original key
type PrivateKeyShard struct {
	PublicKey *rsa.PublicKey // public part
	D         *big.Int       // split private exponent
	SplitBy   SplitBy        // the algorithm used to split the original key
	// someday could have "E minor," the split public exponent

}

// used exclusively as a placeholder for encoding-decoding
type publicKey struct {
	N []byte
	E int
}

// used exclusively as a placeholder for encoding-decoding
type privateKeyShard struct {
	PublicKey publicKey
	D         []byte
	SplitBy   SplitBy
}

// returns a PEM encoding of the key data
func (pks *PrivateKeyShard) EncodePEM() (string, error) {
	// we perform this conversion because asn1.Marshal cannot handle pointer values or unexported fields
	b, err := asn1.Marshal(privateKeyShard{
		PublicKey: publicKey{
			N: pks.PublicKey.N.Bytes(),
			E: pks.PublicKey.E,
		},
		D:       pks.D.Bytes(),
		SplitBy: pks.SplitBy,
	})

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

// returns key data from a PEM encoding
func DecodePEM(encodedPks string) (*PrivateKeyShard, error) {
	block, rest := pem.Decode([]byte(encodedPks))
	if block == nil || block.Type != pemType || len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM block containing private key shard")
	}

	var pks privateKeyShard
	rest, err := asn1.Unmarshal(block.Bytes, &pks)
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to unmarshal DER-encoded private key shard")
	}

	return &PrivateKeyShard{
		PublicKey: &rsa.PublicKey{
			N: new(big.Int).SetBytes(pks.PublicKey.N),
			E: pks.PublicKey.E,
		},
		D:       new(big.Int).SetBytes(pks.D),
		SplitBy: pks.SplitBy,
	}, err
}
