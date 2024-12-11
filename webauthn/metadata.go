package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#authenticator-attestation-guid-aaguid-typedef
type AAGUID [16]byte

func AAGUIDName(a AAGUID) (string, bool) {
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

func (a AAGUID) String() string {
	return string(a.marshalText())
}

func (a AAGUID) MarshalText() ([]byte, error) {
	return a.marshalText(), nil
}

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

type Metadata struct {
	Entries []*MetadataEntry `json:"entries"`
}

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
type MetadataEntry struct {
	AAID     string            `json:"aaid"`
	AAGUID   AAGUID            `json:"aaguid"`
	KeyIDs   []string          `json:"attestationCertificateKeyIdentifiers"`
	Metadata MetadataStatement `json:"metadataStatement"`
}

// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys
type MetadataStatement struct {
	AAGUID                      AAGUID   `json:"aaguid"`
	Description                 string   `json:"description"`
	AttestationRootCertificates []string `json:"attestationRootCertificates"`
}

func ParseMetadata(b []byte) (*Metadata, error) {
	parts := bytes.Split(b, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt")
	}
	data := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	if _, err := base64.RawURLEncoding.Decode(data, parts[1]); err != nil {
		return nil, fmt.Errorf("decoding jwt payload: %v", err)
	}
	var md Metadata
	if err := json.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("decoding blob: %v", err)
	}
	return &md, nil
}
