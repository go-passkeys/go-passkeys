package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-passkeys/go-passkeys/webauthn"
)

func newTestServer(t *testing.T) (*http.Client, *httptest.Server, *server) {
	t.Helper()

	s := &server{
		staticFS: staticFSEmbed,
		storage:  newTestStorage(t),
		rp: &webauthn.RelyingParty{
			ID:     "localhost",
			Origin: "http://localhost:8080",
		},
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

	reqBody := strings.NewReader(`{"username":"testuser","passkeyName":"testkey"}`)
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

	reg := &registration{
		id:         "testregistrationid",
		username:   "testuser",
		userHandle: []byte("testuserid"),
		challenge:  challenge,
		expiresAt:  time.Now(),
	}
	if err := s.storage.insertRegistration(ctx, reg); err != nil {
		t.Fatalf("Inserting passkey failed: %v", err)
	}

	reqBody := strings.NewReader(`{
		"transports": ["hybrid", "internal"],
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
			Name:  "registration.id",
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
				userHandle:        []byte("testuserhandle"),
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

	reqBody := strings.NewReader(`{}`)
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

func base64Decode(t *testing.T, s string) []byte {
	t.Helper()

	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("Decoding base64 string: %v", err)
	}
	return data
}

func base64URLDecode(t *testing.T, s string) []byte {
	t.Helper()

	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("Decoding base64 string: %v", err)
	}
	return data
}

func TestLoginFinish(t *testing.T) {
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
				userHandle:        []byte("testuserhandle"),
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

	// Values taken from Google Password Manager.
	challenge := base64URLDecode(t, "sl_2HSWtFzJAaauF3T9zBQ")
	authenticatorData := base64Decode(t, "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==")
	clientDataJSON := base64Decode(t, "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoic2xfMkhTV3RGekpBYWF1RjNUOXpCUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=")

	l := &login{
		id:        "loginid",
		username:  "testuser",
		challenge: challenge,
	}
	if err := s.storage.insertLogin(ctx, l); err != nil {
		t.Fatalf("Inserting login attempt: %v", err)
	}

	su, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(su, []*http.Cookie{
		{
			Name:  "login.id",
			Value: "loginid",
		},
	})

	clientDataHash := sha256.Sum256(clientDataJSON)

	data := append([]byte{}, authenticatorData...)
	data = append(data, clientDataHash[:]...)

	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("Generating signature: %v", err)
	}

	reqBody := struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
		Signature         []byte `json:"signature"`
		UserHandle        []byte `json:"userHandle"`
	}{authenticatorData, clientDataJSON, sig, []byte("testuserhandle")}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Encoding request body: %v", err)
	}

	req, err := http.NewRequest("POST", srv.URL+"/login-finish", bytes.NewReader(reqBodyBytes))
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

func TestReauth(t *testing.T) {
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
				userHandle:        []byte("testuserhandle"),
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

	ses := &session{
		id:        "sessionid",
		username:  "testuser",
		expiresAt: time.Now(),
	}
	if err := s.storage.insertSession(ctx, ses); err != nil {
		t.Fatalf("Inserting login attempt: %v", err)
	}

	su, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(su, []*http.Cookie{
		{
			Name:  "session.id",
			Value: "sessionid",
		},
	})

	req, err := http.NewRequest("POST", srv.URL+"/reauth-start", strings.NewReader("{}"))
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

	var respBody struct {
		CredentialIDs [][]byte `json:"credentialIDs"`
		Challenge     []byte   `json:"challenge"`
	}
	if err := json.Unmarshal(body, &respBody); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	authenticatorData := base64Decode(t, "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==")

	clientData := struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(respBody.Challenge),
		Origin:    "http://localhost:8080",
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatalf("Encoding client data: %v", err)
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	data := append([]byte{}, authenticatorData...)
	data = append(data, clientDataHash[:]...)
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("Generating signature: %v", err)
	}

	finishReqBody := struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
		Signature         []byte `json:"signature"`
		UserHandle        []byte `json:"userHandle"`
	}{authenticatorData, clientDataJSON, sig, []byte("testuserhandle")}
	finishReqBodyBytes, err := json.Marshal(finishReqBody)
	if err != nil {
		t.Fatalf("Encoding request body: %v", err)
	}

	finishReq, err := http.NewRequest("POST", srv.URL+"/reauth-finish", bytes.NewReader(finishReqBodyBytes))
	if err != nil {
		t.Fatalf("Creating test request: %v", err)
	}
	finishResp, err := client.Do(finishReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer finishResp.Body.Close()

	finishBody, err := io.ReadAll(finishResp.Body)
	if err != nil {
		t.Fatalf("Reading response body: %v", err)
	}
	if finishResp.StatusCode != http.StatusOK {
		t.Fatalf("Response returned unexpected status code: %s: %s", resp.Status, finishBody)
	}
}

func TestRegisterKey(t *testing.T) {
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
				userHandle:        []byte("testuserhandle"),
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

	ses := &session{
		id:        "sessionid",
		username:  "testuser",
		expiresAt: time.Now(),
	}
	if err := s.storage.insertSession(ctx, ses); err != nil {
		t.Fatalf("Inserting login attempt: %v", err)
	}

	su, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(su, []*http.Cookie{
		{
			Name:  "session.id",
			Value: "sessionid",
		},
	})

	req, err := http.NewRequest("POST", srv.URL+"/register-key-start", strings.NewReader("{}"))
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

	var respData struct {
		Challenge []byte `json:"challenge"`
	}
	if err := json.Unmarshal(body, &respData); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}
	ch := base64.RawURLEncoding.EncodeToString(respData.Challenge)

	clientDataJSON := `{"type":"webauthn.create","challenge":"` + ch + `","origin":"http://localhost:8080","crossOrigin":false}`

	finishReqBodyBytes := strings.NewReader(`{
		"attestationObject": "` + yubikeyDirectAttestationObject + `",
		"clientDataJSON": "` + base64.StdEncoding.EncodeToString([]byte(clientDataJSON)) + `"
	}`)

	finishReq, err := http.NewRequest("POST", srv.URL+"/register-key-finish", finishReqBodyBytes)
	if err != nil {
		t.Fatalf("Creating test request: %v", err)
	}
	finishResp, err := client.Do(finishReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer finishResp.Body.Close()

	finishBody, err := io.ReadAll(finishResp.Body)
	if err != nil {
		t.Fatalf("Reading response body: %v", err)
	}
	if finishResp.StatusCode != http.StatusOK {
		t.Fatalf("Response returned unexpected status code: %s: %s", resp.Status, finishBody)
	}
}
