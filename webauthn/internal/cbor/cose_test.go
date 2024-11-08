package cbor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples

var ecTestKeyHex, _ = hex.DecodeString(strings.Join(strings.Fields(`A5
   01  02

   03  26

   20  01

   21  58 20   65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d

   22  58 20   1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c`), ""))

func TestParseECKey(t *testing.T) {
	d := NewDecoder(ecTestKeyHex)
	got, err := d.PublicKey()
	if err != nil {
		t.Fatalf("Parsing public key")
	}

	wantX, _ := hex.DecodeString("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
	wantY, _ := hex.DecodeString("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")

	want := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(wantX),
		Y:     big.NewInt(0).SetBytes(wantY),
	}
	if !want.Equal(got.Public) {
		t.Errorf("Public keys didn't match, got=%#v, want=%#v", got.Public, want)
	}
	if got.Algorithm != ES256 {
		t.Errorf("Unexpected algorithm, got=%v, want=%v", got.Algorithm, ES256)
	}
}
