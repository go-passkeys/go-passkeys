package cbor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// https://datatracker.ietf.org/doc/html/rfc8152
// https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// https://www.iana.org/assignments/cose/cose.xhtml#key-type
// https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves

type PublicKey struct {
	ID        string
	Algorithm int64
	Public    crypto.PublicKey
}

const (
	RS512 = -259
	RS384 = -258
	RS256 = -257
	ES256 = -7
)

const (
	keyTypeOKP = 1
	keyTypeEC2 = 2
	keyTypeRSA = 3

	ecP256    = 1
	ecP384    = 2
	ecP521    = 3
	ecEd25519 = 6

	keyTypeOKPCRV = -1
	keyTypeOKPPub = -2
)

func (d *Decoder) PublicKey() (*PublicKey, error) {
	var (
		ecID       int64
		n1, n2, n3 []byte
		kty        int64
		keyID      []byte
		alg        int64
	)
	if !d.Map(func(kv *Decoder) bool {
		var key int64
		if !kv.Int(&key) {
			return false
		}
		switch key {
		case 1:
			return kv.Int(&kty)
		case 2:
			return kv.Bytes(&keyID)
		case 3:
			return kv.Int(&alg)
		case -1:
			if kv.Peek() == TypeByteString {
				return kv.Bytes(&n1)
			}
			return kv.Int(&ecID)
		case -2:
			return kv.Bytes(&n2)
		case -3:
			return kv.Bytes(&n3)
		default:
			return kv.Skip()
		}
	}) {
		return nil, fmt.Errorf("invalid cbor data")
	}

	var pub crypto.PublicKey
	switch kty {
	case keyTypeEC2:
		if ecID == 0 {
			return nil, fmt.Errorf("no curve for ec key specified")
		}
		if len(n2) == 0 {
			return nil, fmt.Errorf("no x coordinate specified for ec key")
		}
		if len(n3) == 0 {
			return nil, fmt.Errorf("no xy coordinate specified for ec key")
		}

		var curve elliptic.Curve
		switch ecID {
		case ecP256:
			curve = elliptic.P256()
		case ecP384:
			curve = elliptic.P384()
		case ecP521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve id: %d", ecID)
		}

		x := big.NewInt(0).SetBytes(n2)
		y := big.NewInt(0).SetBytes(n3)
		pub = &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	case keyTypeRSA:
		if len(n1) == 0 {
			return nil, fmt.Errorf("no modulus n for RSA key")
		}
		if len(n2) == 0 {
			return nil, fmt.Errorf("no public exponent e for RSA key")
		}
		n := big.NewInt(0).SetBytes(n1)
		e := big.NewInt(0).SetBytes(n2)
		pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case keyTypeOKP:
		if ecID != ecEd25519 {
			return nil, fmt.Errorf("unsupported elliptic curve type %d for octet key pair", ecID)
		}
		if len(n2) == 0 {
			return nil, fmt.Errorf("no public key value for Ed25519 key")
		}
		pub = ed25519.PublicKey(n2)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", kty)
	}
	return &PublicKey{
		ID:        string(keyID),
		Public:    pub,
		Algorithm: alg,
	}, nil
}
