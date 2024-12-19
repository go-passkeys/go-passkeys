package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
//   * https://github.com/passkeydeveloper/passkey-authenticator-aaguids
//   * https://fidoalliance.org/metadata/
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

// Metadata is a parsed FIDO Metadata Service BLOB, and can be used to validate
// the certificate chain of "packed" attestations.
//
// https://fidoalliance.org/metadata/
type Metadata struct {
	entries []*metadataEntry `json:"entries"`
}

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
type metadataEntry struct {
	AAID     string            `json:"aaid"`
	AAGUID   AAGUID            `json:"aaguid"`
	KeyIDs   []string          `json:"attestationCertificateKeyIdentifiers"`
	Metadata metadataStatement `json:"metadataStatement"`
}

// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys
type metadataStatement struct {
	AAGUID                      AAGUID   `json:"aaguid"`
	Description                 string   `json:"description"`
	AttestationRootCertificates []string `json:"attestationRootCertificates"`
}

// ParseMetadata parses the FIDO Metadata Service BLOB containing centrally
// registered attestation certificates for authenticators. This can be used to
// verify "packed" attestation statements, such as those from physical security
// keys.
//
// The BLOB can be downloaded from: https://mds3.fidoalliance.org/
//
// ParseMetadata parses the raw JWT file provided by the service, but does not
// perform signature validation.
//
// "We suggest downloading the BLOB once a month and then caching its content
// because the MDS data does not change often."
//
// - https://fidoalliance.org/metadata/
func ParseMetadata(b []byte) (*Metadata, error) {
	parts := bytes.Split(b, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt")
	}
	data := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	if _, err := base64.RawURLEncoding.Decode(data, parts[1]); err != nil {
		return nil, fmt.Errorf("decoding jwt payload: %v", err)
	}
	var md struct {
		Entries []*metadataEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("decoding blob: %v", err)
	}
	return &Metadata{entries: md.Entries}, nil
}
