package webauthn

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	}{
		{
			name: "YubiKey 5 Series",
			rp: &RelyingParty{
				RPID:   "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "-ium4NdjLD6Acqy9p66NtA",
			clientData:        `{"type":"webauthn.create","challenge":"-ium4NdjLD6Acqy9p66NtA","origin":"http://localhost:8080","crossOrigin":false}`,
			attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAL7ex0WTU1ZpLSRhoTxNxaYbwYcaNEA/h9eJEp0weJEqAiEA1vMTwi4bkvkE/gzQDO1seRyw0SupYth902MWOpZ0TDpjeDVjgVkC3TCCAtkwggHBoAMCAQICCQCkQGRCP4Vr/DANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTExMzg2NjQwNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPkOtta+hbyNLleVf1puWkTqbHzBJz+y42wVbN881zPGfYHty7riyxT4c3fcoXK+bl1/XE7f/2D3I3WT9ILQVYOjgYEwfzATBgorBgEEAYLECg0BBAUEAwUHATAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBAZCDw9g4NLGLwDjxyasv0bMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHzCOWZTA+e+ni1+kmfydBAZgdLyWGbYLQxlJtjd00qbh6M41UaYuRm12eKm3uYDgPT1BnVqqGN69k/1+P91O+knuRBfb48El12Up1hfzyON1UKGgBA6IdmghqYbK+X5baMMLGdsZ1nLKEWjVRecjLg79GwHy9HJ25j+Gb7+yNZMJdfgMJvfrecD35Tgmw+3fTCbzpnlW9Sp/LNdkHjdECaicue3MdhtrwaVmNfyVNvU5mqHzQAH2zf4/TsTZKdx2aIDFmqZZAartwD7RskFfQpnN0CWU6uCaBS0ECgDPLLW3q39mfvJ/y2rHPhaSWue85+2lNK+NJPP43ZsNrA7Rw5oYXV0aERhdGFYwkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjxQAAAAMZCDw9g4NLGLwDjxyasv0bADDC4gNtuVFFZvyU4A2YDTFDSAOHTXQfTVUeXPpK2xTdoFx6LnSx3o2dcheLtBrEj0ylAQIDJiABIVggwuIDbblRRWb8lOANmAK3w9dppoKQXC2rw7yY6c9W/C4iWCBp5XU3NpH55RWYheccEtji/4Yc+zscmwMQN+KrQ/o7/qFrY3JlZFByb3RlY3QD",
		},
		{
			name: "iCloud Keychain",
			rp: &RelyingParty{
				RPID:   "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "Z_napzbTBbiJZpDJy2_x2g",
			clientData:        `{"type":"webauthn.create","challenge":"Z_napzbTBbiJZpDJy2_x2g","origin":"http://localhost:8080","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`,
			attestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMC0tFpykeOylx0hbDMMaBciaCL5pQECAyYgASFYIKsaYc3GYw62BgN5xbZzvqFN79cLPWo4SU2aJQIFNZXBIlggkfCM3E0nCG0SSc3pu1bCcfYVHWwXzYeh8WCUBDDN3v4=",
		},
		{
			name: "Google Password Manager",
			rp: &RelyingParty{
				RPID:   "localhost",
				Origin: "http://localhost:8080",
			},
			challenge:         "ZnTNLi5zseMQowTP5bnrhQ",
			clientData:        `{"type":"webauthn.create","challenge":"ZnTNLi5zseMQowTP5bnrhQ","origin":"http://localhost:8080","crossOrigin":false}`,
			attestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEJdiX6sHQ7x/IRv7PJqmJCqlAQIDJiABIVgghc/4hoXkAaBsUc5vrE56q/v9S5xa8rA3q5rVZFI2rIAiWCAy2H59mtPD+fMeCHUJQ3DOJwxkjESVjEGovXqCMcOtLA==",
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
			clientDataJSON := []byte(tc.clientData)
			if _, err := tc.rp.VerifyAttestation(challenge, clientDataJSON, attestationObject); err != nil {
				t.Errorf("Verifying attestation: %v", err)
			}
		})
	}
}

var chromeLocalTestData = `
o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoM
dl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAECd+IVW0KqKvYjZ4ETlBR1KlAQIDJiABIVggCkgUPXo1Qp
RF8Wz7Nny5cgwQaVW711TjRob9EvB/w9AiWCAwDkFxvcXP2l31FCqetOkl894TFLKN/i0Ga+duc3KPd
w==`

func TestParseAttestationObjectChrome(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(strings.Replace(chromeLocalTestData, "\n", "", -1))
	if err != nil {
		t.Fatalf("Parsing test data: %v", err)
	}
	if _, err := parseAttestationObject(data); err != nil {
		t.Errorf("Parsing attestation object: %v", err)
	}
}

var chromeDirectAttestationObject = `
o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAJdhPjKXQAoWBgBDw+tu8q2WpTrXLUL
wFBgpJGu0SLI7AiA493f+tIVJkf9oeSX24FsSHJqkNKYmph2IAD7wSzTMAGhhdXRoRGF0YVikSZYN5Y
gOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGfNA5n4RSq0g
sGzIB6kmazzLLe0goRP+1QG4uixw+zTpQECAyYgASFYIJtUv3C9FxTn1i7xALbGQJjzDkyFECHaHQ5+
KYom9eh9IlggCfXDLnVZU9KEKuhqdPInGHcfAlZSCTOeRWSUzrSkkHo=`

var chromeDirectClientDataJSON = `
eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOFhKSTVjUXFXLVZxdFNQTzdKSXB
VZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=`

func TestParseAttestationObjectChromeDirect(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(chromeDirectAttestationObject)
	if err != nil {
		t.Fatalf("Parsing test data: %v", err)
	}
	clientDataJSON, err := base64.StdEncoding.DecodeString(chromeDirectClientDataJSON)
	if err != nil {
		t.Fatalf("Parsing client data json: %v", err)
	}

	blobData, err := os.ReadFile("testdata/blob.jwt")
	if err != nil {
		t.Fatalf("loading metadata blob: %v", err)
	}
	blob, err := ParseMetadata(blobData)
	if err != nil {
		t.Fatalf("parsing metadata blob: %v", err)
	}

	attest, err := parseAttestationObject(data)
	if err != nil {
		t.Fatalf("Parsing attestation object: %v", err)
	}
	if attest.format != "packed" {
		t.Errorf("Unexpected attestation format: %s", attest.format)
	}
	if _, err := attest.VerifyPacked(clientDataJSON, &PackedOptions{Metadata: blob}); err != nil {
		t.Fatalf("Verifying packed data: %v", err)
	}
	var clientData clientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		t.Fatalf("Parsing client data: %v", err)
	}
}

// Generated via a Yubico 5C resident key.
var yubikeyNoneAttestationObject = `
o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjCSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoM
dl2PFAAAAAQAAAAAAAAAAAAAAAAAAAAAAMBZIIH8BS0I3PJeOcDdHuV7XwtWUU70NkJ9G6GD8ofgAst
Ep1iQ3dSTvKNIGzernlKUBAgMmIAEhWCAWSCB/AUtCNzyXjnA3G5zD702NEvFYkpyip/BjUDT+pCJYI
PFiSZLeRIunVLBtBQ3LIzvIa0PWiPkmX9AhxQPtQy+GoWtjcmVkUHJvdGVjdAM=`

var yubikeyNoneClientDataJSON = `
eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibEVGLWd5NzVLOHZIY1R0MUdCbHZ
QZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=`

func TestParseAttestationObjectNoneYubikey5C(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(yubikeyNoneAttestationObject)
	if err != nil {
		t.Fatalf("Parsing test data: %v", err)
	}
	attest, err := parseAttestationObject(data)
	if err != nil {
		t.Fatalf("Parsing attestation object: %v", err)
	}
	if attest.format != "none" {
		t.Errorf("Unexpected attestation format: %s", attest.format)
	}
}

var yubikeyDirectAttestationObject = `
o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgL0WM03U24brZ8ApENdtiuSgm7nzsHDD
xZZIoWA9S+vMCIEL/aEJ3qGc70J9f+NXujqHib0TBZfoio1tlS0rDrdpaY3g1Y4FZAt0wggLZMIIBwa
ADAgECAgkApEBkQj+Fa/wwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290I
ENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJ
BgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN
0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDExMTM4NjY0MDQwWTATBgcqhkjOPQ
IBBggqhkjOPQMBBwNCAAT5DrbWvoW8jS5XlX9ablpE6mx8wSc/suNsFWzfPNczxn2B7cu64ssU+HN33
KFyvm5df1xO3/9g9yN1k/SC0FWDo4GBMH8wEwYKKwYBBAGCxAoNAQQFBAMFBwEwIgYJKwYBBAGCxAoC
BBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQ
EEgQQGQg8PYODSxi8A48cmrL9GzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQB8wjlmUw
Pnvp4tfpJn8nQQGYHS8lhm2C0MZSbY3dNKm4ejONVGmLkZtdnipt7mA4D09QZ1aqhjevZP9fj/dTvpJ
7kQX2+PBJddlKdYX88jjdVChoAQOiHZoIamGyvl+W2jDCxnbGdZyyhFo1UXnIy4O/RsB8vRyduY/hm+
/sjWTCXX4DCb363nA9+U4JsPt30wm86Z5VvUqfyzXZB43RAmonLntzHYba8GlZjX8lTb1OZqh80AB9s
3+P07E2SncdmiAxZqmWQGq7cA+0bJBX0KZzdAllOrgmgUtBAoAzyy1t6t/Zn7yf8tqxz4WklrnvOftp
TSvjSTz+N2bDawO0cOaGF1dGhEYXRhWMJJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY8UAA
AADGQg8PYODSxi8A48cmrL9GwAwhHXoPh9w0LmLY8eifxLeZ7Mb/7ZLXbNEY53cU+Mdi4jehzrFS8XM
wbocAj4JXT0QpQECAyYgASFYIIR16D4fcNC5i2PHon8nIvhPmebJR11t0F5T7d8jmOTyIlggJhKyMS1
kOu6SPPw0TVFuVVGCnC+WMJJXOUZ8/l2mlKKha2NyZWRQcm90ZWN0Aw==`

var yubikeyDirectClientDataJSON = `
eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMGwtd0dDbGFkajB6MkZ2dGhQTFZ
BZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3
RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OI
GFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9`

func TestParseAttestationObjectDirectYubikey5C(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(yubikeyDirectAttestationObject)
	if err != nil {
		t.Fatalf("Parsing test data: %v", err)
	}
	clientDataJSON, err := base64.StdEncoding.DecodeString(yubikeyDirectClientDataJSON)
	if err != nil {
		t.Fatalf("Parsing client data json: %v", err)
	}

	blobData, err := os.ReadFile("testdata/blob.jwt")
	if err != nil {
		t.Fatalf("loading metadata blob: %v", err)
	}
	blob, err := ParseMetadata(blobData)
	if err != nil {
		t.Fatalf("parsing metadata blob: %v", err)
	}

	attest, err := parseAttestationObject(data)
	if err != nil {
		t.Fatalf("Parsing attestation object: %v", err)
	}
	if attest.format != "packed" {
		t.Errorf("Unexpected attestation format: %s", attest.format)
	}
	if _, err := attest.VerifyPacked(clientDataJSON, &PackedOptions{Metadata: blob}); err != nil {
		t.Fatalf("Verifying packed data: %v", err)
	}
}

var (
	chromeLoginPublicKey         = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7TuX1/aYvHTE3nfQjsypRWv5f/EdBPga4lQSxcupuzWE/4kNnBBLjR9ONy5MXdl9ZCxBta7Q4BbbaUiVqQPNGQ=="
	chromeLoginAuthenticatorData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA=="
	chromeLoginClientJSON        = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoic2xfMkhTV3RGekpBYWF1RjNUOXpCUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0="
	chromeLoginSignature         = "MEQCICeg3UzPEZ+wDyJjDYDfZ8ErqQ6Ol8OOfM36TdxSqCItAiAMhxF1kC1BQX6vjTEwhECmnn8louKMHBxrFDqaKHOC+g=="
)

func TestVerify(t *testing.T) {
	pubBytes, _ := base64.StdEncoding.DecodeString(chromeLoginPublicKey)
	authData, _ := base64.StdEncoding.DecodeString(chromeLoginAuthenticatorData)
	clientDataJSON, _ := base64.StdEncoding.DecodeString(chromeLoginClientJSON)
	sig, _ := base64.StdEncoding.DecodeString(chromeLoginSignature)
	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("Parsing test key: %v", err)
	}
	challenge, _ := base64.RawURLEncoding.DecodeString("sl_2HSWtFzJAaauF3T9zBQ")

	if err := Verify(pub, ES256, challenge, authData, clientDataJSON, sig); err != nil {
		t.Errorf("Verifying signature: %v", err)
	}
}
