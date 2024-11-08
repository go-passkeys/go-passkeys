package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ericchiang/go-webauthn/webauthn"
)

func newTestServer(t *testing.T) (*http.Client, *httptest.Server, *server) {
	t.Helper()

	s := &server{
		staticFS: staticFSEmbed,
		storage:  newTestStorage(t),
	}

	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Creating cookie jar: %v", err)
	}

	client := srv.Client()
	client.Jar = jar
	return client, srv, s
}

func TestRegistrationStart(t *testing.T) {
	client, srv, _ := newTestServer(t)

	reqBody := strings.NewReader(`{"username":"testuser"}`)
	req, err := http.NewRequest("POST", srv.URL+"/registration-start", reqBody)
	if err != nil {
		t.Fatalf("Creating test request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Reading response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Response returned unexpected status code: %s: %s", resp.Status, body)
	}
}

var yubikeyDirectAttestationObject = strings.ReplaceAll(`
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
kOu6SPPw0TVFuVVGCnC+WMJJXOUZ8/l2mlKKha2NyZWRQcm90ZWN0Aw==`, "\n", "")

var yubikeyDirectClientDataJSON = strings.ReplaceAll(`
eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMGwtd0dDbGFkajB6MkZ2dGhQTFZ
BZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3
RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OI
GFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9`, "\n", "")

func TestRegistrationFinish(t *testing.T) {
	ctx := context.Background()
	client, srv, s := newTestServer(t)

	// Parsed from client data JSON above.
	challenge, err := base64.RawURLEncoding.DecodeString("0l-wGCladj0z2FvthPLVAg")
	if err != nil {
		t.Fatalf("Decoding challenge: %v", err)
	}

	reg := &passkeyRegistration{
		id:        "testregistrationid",
		username:  "testuser",
		userID:    []byte("testuserid"),
		challenge: challenge,
		createdAt: time.Now(),
	}
	if err := s.storage.insertPasskeyRegistration(ctx, reg); err != nil {
		t.Fatalf("Inserting passkey failed: %v", err)
	}

	reqBody := strings.NewReader(`{
		"attestationObject": "` + yubikeyDirectAttestationObject + `",
		"clientDataJSON": "` + yubikeyDirectClientDataJSON + `"
	}`)
	req, err := http.NewRequest("POST", srv.URL+"/registration-finish", reqBody)
	if err != nil {
		t.Fatalf("Creating test request: %v", err)
	}
	u, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(u, []*http.Cookie{
		{
			Name:  cookieRegistrationID,
			Value: "testregistrationid",
		},
	})

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Reading response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Response returned unexpected status code: %s: %s", resp.Status, body)
	}
}

func TestLoginStart(t *testing.T) {
	ctx := context.Background()
	client, srv, s := newTestServer(t)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Generating test key: %v", err)
	}

	u := &user{
		username: "testuser",
		passkeys: []*passkey{
			{
				username:          "testuser",
				name:              "testkey",
				passkeyID:         []byte("testkeyid"),
				publicKey:         priv.Public(),
				algorithm:         webauthn.ES256,
				attestationObject: []byte("attestation"),
				clientDataJSON:    []byte("{}"),
			},
		},
	}
	if err := s.storage.insertUser(ctx, u); err != nil {
		t.Fatalf("Inserting test user: %v", err)
	}

	reqBody := strings.NewReader(`{"username":"testuser"}`)
	req, err := http.NewRequest("POST", srv.URL+"/login-start", reqBody)
	if err != nil {
		t.Fatalf("Creating test request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Reading response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Response returned unexpected status code: %s: %s", resp.Status, body)
	}
}
