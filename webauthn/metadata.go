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

func (m *AAGUID) UnmarshalText(s []byte) error {
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

	if _, err := hex.Decode((*m)[:], raw[:]); err != nil {
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
