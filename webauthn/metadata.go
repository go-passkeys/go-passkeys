package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type mdsBlob struct {
	Entries []*mdsBlobPayloadEntry `json:"entries"`
}

type mdsAAGUID []byte

func (m *mdsAAGUID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("aaguid was not a valid string: %v", err)
	}

	s = strings.ReplaceAll(s, "-", "")
	data, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("parsing aaguid hex data: %v", err)
	}
	if len(data) != 16 {
		return fmt.Errorf("expected aaguid to be 16 bytes, got %d", len(data))
	}
	*m = data
	return nil
}

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
type mdsBlobPayloadEntry struct {
	AAID     string          `json:"aaid"`
	AAGUID   mdsAAGUID       `json:"aaguid"`
	KeyIDs   []string        `json:"attestationCertificateKeyIdentifiers"`
	Metadata mdsBlobMetadata `json:"metadataStatement"`
}

// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys
type mdsBlobMetadata struct {
	AAGUID                      mdsAAGUID `json:"aaguid"`
	Description                 string    `json:"description"`
	AttestationRootCertificates []string  `json:"attestationRootCertificates"`
}

type Metadata struct {
	blob mdsBlob
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
	var blob mdsBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("decoding blob: %v", err)
	}
	return &Metadata{blob: blob}, nil
}
