package webauthn

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestVerifyAttestation(t *testing.T) {
	testCases := []struct {
		name              string
		rp                *RelyingParty
		challenge         string
		clientData        string
		attestationObject string
		format            string
	}{
		{
			name: "YubiKey 5 Series",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "-ium4NdjLD6Acqy9p66NtA",
			clientData:        `{"type":"webauthn.create","challenge":"-ium4NdjLD6Acqy9p66NtA","origin":"http://localhost:8080","crossOrigin":false}`,
			format:            "packed",
			attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAL7ex0WTU1ZpLSRhoTxNxaYbwYcaNEA/h9eJEp0weJEqAiEA1vMTwi4bkvkE/gzQDO1seRyw0SupYth902MWOpZ0TDpjeDVjgVkC3TCCAtkwggHBoAMCAQICCQCkQGRCP4Vr/DANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTExMzg2NjQwNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPkOtta+hbyNLleVf1puWkTqbHzBJz+y42wVbN881zPGfYHty7riyxT4c3fcoXK+bl1/XE7f/2D3I3WT9ILQVYOjgYEwfzATBgorBgEEAYLECg0BBAUEAwUHATAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBAZCDw9g4NLGLwDjxyasv0bMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHzCOWZTA+e+ni1+kmfydBAZgdLyWGbYLQxlJtjd00qbh6M41UaYuRm12eKm3uYDgPT1BnVqqGN69k/1+P91O+knuRBfb48El12Up1hfzyON1UKGgBA6IdmghqYbK+X5baMMLGdsZ1nLKEWjVRecjLg79GwHy9HJ25j+Gb7+yNZMJdfgMJvfrecD35Tgmw+3fTCbzpnlW9Sp/LNdkHjdECaicue3MdhtrwaVmNfyVNvU5mqHzQAH2zf4/TsTZKdx2aIDFmqZZAartwD7RskFfQpnN0CWU6uCaBS0ECgDPLLW3q39mfvJ/y2rHPhaSWue85+2lNK+NJPP43ZsNrA7Rw5oYXV0aERhdGFYwkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjxQAAAAMZCDw9g4NLGLwDjxyasv0bADDC4gNtuVFFZvyU4A2YDTFDSAOHTXQfTVUeXPpK2xTdoFx6LnSx3o2dcheLtBrEj0ylAQIDJiABIVggwuIDbblRRWb8lOANmAK3w9dppoKQXC2rw7yY6c9W/C4iWCBp5XU3NpH55RWYheccEtji/4Yc+zscmwMQN+KrQ/o7/qFrY3JlZFByb3RlY3QD",
		},
		{
			name: "iCloud Keychain",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "Z_napzbTBbiJZpDJy2_x2g",
			clientData:        `{"type":"webauthn.create","challenge":"Z_napzbTBbiJZpDJy2_x2g","origin":"http://localhost:8080","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`,
			format:            "none",
			attestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMC0tFpykeOylx0hbDMMaBciaCL5pQECAyYgASFYIKsaYc3GYw62BgN5xbZzvqFN79cLPWo4SU2aJQIFNZXBIlggkfCM3E0nCG0SSc3pu1bCcfYVHWwXzYeh8WCUBDDN3v4=",
		},
		{
			name: "Google Password Manager",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "ZnTNLi5zseMQowTP5bnrhQ",
			clientData:        `{"type":"webauthn.create","challenge":"ZnTNLi5zseMQowTP5bnrhQ","origin":"http://localhost:8080","crossOrigin":false}`,
			format:            "none",
			attestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEJdiX6sHQ7x/IRv7PJqmJCqlAQIDJiABIVgghc/4hoXkAaBsUc5vrE56q/v9S5xa8rA3q5rVZFI2rIAiWCAy2H59mtPD+fMeCHUJQ3DOJwxkjESVjEGovXqCMcOtLA==",
		},
		{
			name: "Chrome local",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "8XJI5cQqW-VqtSPO7JIpUg",
			clientData:        `{"type":"webauthn.create","challenge":"8XJI5cQqW-VqtSPO7JIpUg","origin":"http://localhost:8080","crossOrigin":false}`,
			format:            "packed",
			attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAJdhPjKXQAoWBgBDw+tu8q2WpTrXLULwFBgpJGu0SLI7AiA493f+tIVJkf9oeSX24FsSHJqkNKYmph2IAD7wSzTMAGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGfNA5n4RSq0gsGzIB6kmazzLLe0goRP+1QG4uixw+zTpQECAyYgASFYIJtUv3C9FxTn1i7xALbGQJjzDkyFECHaHQ5+KYom9eh9IlggCfXDLnVZU9KEKuhqdPInGHcfAlZSCTOeRWSUzrSkkHo=",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := base64.RawURLEncoding.DecodeString(tc.challenge)
			if err != nil {
				t.Fatalf("Parsing challenge: %v", err)
			}
			attestationObject, err := base64.StdEncoding.DecodeString(tc.attestationObject)
			if err != nil {
				t.Fatalf("Parsing attestation object: %v", err)
			}
			format, err := AttestationFormat(attestationObject)
			if err != nil {
				t.Errorf("Failed to parse attestation format: %v", err)
			} else if format != tc.format {
				t.Errorf("Attestation using unexpected format, got=%v, want=%v", tc.format, format)
			}

			clientDataJSON := []byte(tc.clientData)
			if _, err := tc.rp.VerifyAttestation(challenge, clientDataJSON, attestationObject); err != nil {
				t.Errorf("Verifying attestation: %v", err)
			}
		})
	}
}

func TestVerifyAttestationPacked(t *testing.T) {
	testCases := []struct {
		name              string
		rp                *RelyingParty
		challenge         string
		clientData        string
		attestationObject string
	}{
		{
			name: "YubiKey 5 Series",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "-ium4NdjLD6Acqy9p66NtA",
			clientData:        `{"type":"webauthn.create","challenge":"-ium4NdjLD6Acqy9p66NtA","origin":"http://localhost:8080","crossOrigin":false}`,
			attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAL7ex0WTU1ZpLSRhoTxNxaYbwYcaNEA/h9eJEp0weJEqAiEA1vMTwi4bkvkE/gzQDO1seRyw0SupYth902MWOpZ0TDpjeDVjgVkC3TCCAtkwggHBoAMCAQICCQCkQGRCP4Vr/DANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTExMzg2NjQwNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPkOtta+hbyNLleVf1puWkTqbHzBJz+y42wVbN881zPGfYHty7riyxT4c3fcoXK+bl1/XE7f/2D3I3WT9ILQVYOjgYEwfzATBgorBgEEAYLECg0BBAUEAwUHATAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBAZCDw9g4NLGLwDjxyasv0bMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHzCOWZTA+e+ni1+kmfydBAZgdLyWGbYLQxlJtjd00qbh6M41UaYuRm12eKm3uYDgPT1BnVqqGN69k/1+P91O+knuRBfb48El12Up1hfzyON1UKGgBA6IdmghqYbK+X5baMMLGdsZ1nLKEWjVRecjLg79GwHy9HJ25j+Gb7+yNZMJdfgMJvfrecD35Tgmw+3fTCbzpnlW9Sp/LNdkHjdECaicue3MdhtrwaVmNfyVNvU5mqHzQAH2zf4/TsTZKdx2aIDFmqZZAartwD7RskFfQpnN0CWU6uCaBS0ECgDPLLW3q39mfvJ/y2rHPhaSWue85+2lNK+NJPP43ZsNrA7Rw5oYXV0aERhdGFYwkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjxQAAAAMZCDw9g4NLGLwDjxyasv0bADDC4gNtuVFFZvyU4A2YDTFDSAOHTXQfTVUeXPpK2xTdoFx6LnSx3o2dcheLtBrEj0ylAQIDJiABIVggwuIDbblRRWb8lOANmAK3w9dppoKQXC2rw7yY6c9W/C4iWCBp5XU3NpH55RWYheccEtji/4Yc+zscmwMQN+KrQ/o7/qFrY3JlZFByb3RlY3QD",
		},
		{
			name: "Chrome local",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "8XJI5cQqW-VqtSPO7JIpUg",
			clientData:        `{"type":"webauthn.create","challenge":"8XJI5cQqW-VqtSPO7JIpUg","origin":"http://localhost:8080","crossOrigin":false}`,
			attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAJdhPjKXQAoWBgBDw+tu8q2WpTrXLULwFBgpJGu0SLI7AiA493f+tIVJkf9oeSX24FsSHJqkNKYmph2IAD7wSzTMAGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGfNA5n4RSq0gsGzIB6kmazzLLe0goRP+1QG4uixw+zTpQECAyYgASFYIJtUv3C9FxTn1i7xALbGQJjzDkyFECHaHQ5+KYom9eh9IlggCfXDLnVZU9KEKuhqdPInGHcfAlZSCTOeRWSUzrSkkHo=",
		},
	}

	blobData, err := os.ReadFile("testdata/blob.jwt")
	if err != nil {
		t.Fatalf("loading metadata blob: %v", err)
	}
	parts := strings.Split(string(blobData), ".")
	if len(parts) != 3 {
		t.Fatalf("Failed to parse blob JWT, expected 3 parts got %d", len(parts))
	}
	mdRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWT: %v", err)
	}

	md := &metadata{}
	if err := json.Unmarshal(mdRaw, md); err != nil {
		t.Fatalf("parsing metadata blob: %v", err)
	}
	opts := &PackedOptions{
		GetRoots:          md.getRoots,
		AllowSelfAttested: true,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := base64.RawURLEncoding.DecodeString(tc.challenge)
			if err != nil {
				t.Fatalf("Parsing challenge: %v", err)
			}
			attestationObject, err := base64.StdEncoding.DecodeString(tc.attestationObject)
			if err != nil {
				t.Fatalf("Parsing attestation object: %v", err)
			}
			clientDataJSON := []byte(tc.clientData)
			if _, err := tc.rp.VerifyAttestationPacked(challenge, clientDataJSON, attestationObject, opts); err != nil {
				t.Errorf("Verifying attestation: %v", err)
			}
		})
	}
}

func TestVerifyAuthentication(t *testing.T) {
	const (
		UP   = 1
		RFU1 = 1 << 1
		UV   = 1 << 2
		BE   = 1 << 3
		BS   = 1 << 4
		RFU2 = 1 << 5
		AT   = 1 << 6
		ED   = 1 << 7
	)

	testCases := []struct {
		name           string
		rp             *RelyingParty
		publicKey      string
		alg            Algorithm
		challenge      string
		clientDataJSON string
		authData       string
		signature      string

		wantFlags   Flags
		wantCounter uint32
	}{
		{
			name: "iCloud Keychain",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			publicKey:      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENyvB2asAdRnjlORh0i+qRWaGrywFAGDEpI+2AesrBGyh5KR6VMc7XjfELnqpqGVAVuuow+hi7yDH9XR3a97KYQ==",
			alg:            ES256,
			challenge:      "Dq/hvK3bJiDKSuOSSrHFKg==",
			clientDataJSON: `{"type":"webauthn.get","challenge":"Dq_hvK3bJiDKSuOSSrHFKg","origin":"http://localhost:8080","crossOrigin":false}`,
			authData:       "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==",
			signature:      "MEUCIQDMI/66BWmFKXyP4jia1s01Bzm5XuaNeH+/NmvX8KaLtwIgeOCSpBTsgxKIBNQpwmgLTGX1tlaEA+npDkyUkTvUceI=",
			wantFlags:      UP | UV | BE | BS,
			wantCounter:    0,
		},
		{
			name: "Google Password Manager",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			publicKey:      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhc/4hoXkAaBsUc5vrE56q/v9S5xa8rA3q5rVZFI2rIAy2H59mtPD+fMeCHUJQ3DOJwxkjESVjEGovXqCMcOtLA==",
			alg:            ES256,
			challenge:      "lqIA7pwRP4IreUpXp8k5yw==",
			clientDataJSON: `{"type":"webauthn.get","challenge":"lqIA7pwRP4IreUpXp8k5yw","origin":"http://localhost:8080","crossOrigin":false}`,
			authData:       "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==",
			signature:      "MEYCIQDdD7fAAkQB6Jyut40lLFUhLP1U+Ts44VxZrzsCdmbJ3QIhAMDAlBmjRFm/B/7DR1ODoNGrHthXQVqUKnf9SSSaK7lR",
			wantFlags:      UP | UV | BE | BS,
		},
		{
			name: "YubiKey 5 Series",
			rp: &RelyingParty{
				ID:     "localhost",
				Origin: "http://localhost:8080",
			},
			publicKey:      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwuIDbblRRWb8lOANmAK3w9dppoKQXC2rw7yY6c9W/C5p5XU3NpH55RWYheccEtji/4Yc+zscmwMQN+KrQ/o7/g==",
			alg:            ES256,
			challenge:      "jXTEukbfgfYPd0KUi9AEHA==",
			clientDataJSON: `{"type":"webauthn.get","challenge":"jXTEukbfgfYPd0KUi9AEHA","origin":"http://localhost:8080","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`,
			authData:       "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAACw==",
			signature:      "MEUCIQD+CCL//FsMb88xAbqNHRLFtYAwBhG5Z79EUpA+ykG9AgIgHpDIi7BvdEBxU3uVAbbtrcgxZp9xKx/isqBsVW8p3mU=",
			wantFlags:      UP | UV,
			wantCounter:    11,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pubDer, err := base64.StdEncoding.DecodeString(tc.publicKey)
			if err != nil {
				t.Fatalf("Decoding public key: %v", err)
			}
			pub, err := x509.ParsePKIXPublicKey(pubDer)
			if err != nil {
				t.Fatalf("Parsing public key: %v", err)
			}

			challenge, err := base64.StdEncoding.DecodeString(tc.challenge)
			if err != nil {
				t.Fatalf("Decoding challenge: %v", err)
			}
			authData, err := base64.StdEncoding.DecodeString(tc.authData)
			if err != nil {
				t.Fatalf("Decoding auth data: %v", err)
			}
			sig, err := base64.StdEncoding.DecodeString(tc.signature)
			if err != nil {
				t.Fatalf("Decoding signature: %v", err)
			}

			clientDataJSON := []byte(tc.clientDataJSON)

			got, err := tc.rp.VerifyAssertion(pub, tc.alg, challenge, clientDataJSON, authData, sig)
			if err != nil {
				t.Fatalf("Verifying authentication: %v", err)
			}

			if got.Flags != tc.wantFlags {
				t.Errorf("Authentication returned unexpected flags, got=%v, want=%v", got.Flags, tc.wantFlags)
			}
			if got.Counter != tc.wantCounter {
				t.Errorf("Authentication returned unexpected counter, got=%v, want=%v", got.Counter, tc.wantCounter)
			}
		})
	}
}

// metadata is a parsed FIDO metadata Service BLOB, and can be used to validate
// the certificate chain of "packed" attestations.
//
// https://fidoalliance.org/metadata/
type metadata struct {
	Entries []*metadataEntry `json:"entries"`
}

func (m *metadata) getRoots(aaguid AAGUID) (*x509.CertPool, error) {
	for _, ent := range m.Entries {
		if ent.Metadata.AAGUID != aaguid {
			continue
		}

		pool := x509.NewCertPool()
		for _, cert := range ent.Metadata.AttestationRootCertificates {
			data, err := base64.StdEncoding.DecodeString(cert)
			if err != nil {
				return nil, fmt.Errorf("decoding certificate base64 for aaguid %s: %v", aaguid, err)
			}
			cert, err := x509.ParseCertificate(data)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate for aaguid %s: %v", aaguid, err)
			}
			pool.AddCert(cert)
		}
		return pool, nil
	}
	return nil, fmt.Errorf("no certificates found for aaguid: %s", aaguid)
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
