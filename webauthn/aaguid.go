package webauthn

import (
	"encoding/hex"
	"fmt"
)

// AAGUID identifies an authenticator or specific authenticator model.
//
// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#authenticator-attestation-guid-aaguid-typedef
type AAGUID [16]byte

// Name attemps to determine the human presentable name of the AAGUID, such as
// "YubiKey 5 Series", "iCloud Keychain", or "Google Password Manager".
//
// Names are gathered from a number of sources including:
//   - https://github.com/passkeydeveloper/passkey-authenticator-aaguids
//   - https://fidoalliance.org/metadata/
func (a AAGUID) Name() (string, bool) {
	// The "passkey-authenticator-aaguids" repo is hand maintained and assumed to
	// have slightly more human-readable names. Prefer this.
	if name, ok := passkeyAuthenticatorAAGUIDs[a]; ok {
		return name, true
	}

	// Query the FIDO metadata service as a second option.
	if name, ok := metadataAAGUIDs[a]; ok {
		return name, true
	}
	return "", false
}

func mustParseAAGUID(s string) AAGUID {
	aaguid, err := ParseAAGUID(s)
	if err != nil {
		panic(err)
	}
	return aaguid
}

// ParseAAGUID parses a formatted AAGUID (e.g. "7a98c250-6808-11cf-b73b-00aa00b677a7").
func ParseAAGUID(s string) (AAGUID, error) {
	var a AAGUID
	err := a.UnmarshalText([]byte(s))
	return a, err
}

// https://datatracker.ietf.org/doc/html/rfc4122#section-3
func (a AAGUID) marshalText() []byte {
	b := make([]byte, 36)
	hex.Encode(b[0:8], a[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], a[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], a[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], a[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], a[10:16])
	return b
}

// String returns a formatted AAGUID.
func (a AAGUID) String() string {
	return string(a.marshalText())
}

// MarshalText encodes the AAGUID in its string representation, and can be used
// with JSON encoding.
func (a AAGUID) MarshalText() ([]byte, error) {
	return a.marshalText(), nil
}

// UnmarshalText parses an AAGUID from its string representation, and can be
// used for parsing JSON document, such as the FIDO Metadata Service.
func (a *AAGUID) UnmarshalText(s []byte) error {
	if len(s) != 36 {
		return fmt.Errorf("expected aaguid string of length 36, got %d", len(s))
	}

	var raw [32]byte
	n := 0
	for _, r := range s {
		if n >= 32 {
			return fmt.Errorf("expected 4 '-' characters in aaguid")
		}
		if r == '-' {
			continue
		}
		raw[n] = byte(r)
		n++
	}

	if _, err := hex.Decode((*a)[:], raw[:]); err != nil {
		return fmt.Errorf("decoding aaguid: %v", err)
	}
	return nil
}
