package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"text/template"
	"time"

	"github.com/go-passkeys/go-passkeys/webauthn"
)

func main() {
	var (
		addr   string
		dbPath string
		watch  bool
	)

	flag.StringVar(&addr, "addr", "localhost:8080",
		"Address to listen on.")
	flag.BoolVar(&watch, "watch", false,
		"When provided, live reload web assests rather than serving them statically.")
	flag.StringVar(&dbPath, "db", filepath.Join(os.TempDir(), "passkey.db"),
		"Path to sql database.")
	flag.Parse()

	var staticFS fs.FS = staticFSEmbed
	if watch {
		staticFS = os.DirFS(".")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("Splitting host and port: %v", err)
	}

	ctx := context.Background()
	st, err := newStorage(ctx, dbPath)
	if err != nil {
		log.Fatalf("Initializing database: %v", err)
	}

	s := &server{
		storage:  st,
		staticFS: staticFS,
		rp: &webauthn.RelyingParty{
			ID:     host,
			Origin: "http://" + addr,
		},
	}
	log.Printf("Using database: %s", dbPath)
	log.Printf("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(":8080", s))
}

// randBytes returns some number of cryptographically secure random bytes. This
// is used for challenges and session IDs.
func randBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Go 1.24 will start crashing the program on bad reads, so
		// panic'ing here isn't problematic.
		//
		// https://github.com/golang/go/issues/66821
		panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// Cookies used by the server. The values are purely random values that match
// a database row.
const (
	cookieKeyRegistrationID = "keyregistration.id"
	cookieLoginID           = "login.id"
	cookieReauthID          = "reauth.id"
	cookieRegistrationID    = "registration.id"
	cookieSessionID         = "session.id"
)

// Frontend assets that are statically compiled into the binary. Can optionally,
// use the on-disk assets with the --watch flag.
//
//go:embed static
var staticFSEmbed embed.FS

// server is a WebAuthn example server, allowing users to register passkeys to
// an account, and perform various actions, such as registering additional keys,
// challenging existing keys, etc. All state is stored in an sqlite3 database to
// persist across restarts.
type server struct {
	staticFS fs.FS
	storage  *storage
	rp       *webauthn.RelyingParty

	once    sync.Once // Guards handler.
	handler http.Handler
}

// ServerHTTP handles all HTTP requests by the server.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Instead of a constructor, initialize the routing on first request.
	s.once.Do(func() {
		mux := http.NewServeMux()

		// Handle basic HTTP requests by the browser.
		mux.HandleFunc("GET /", s.handleIndex)
		mux.HandleFunc("GET /logout", s.handleLogout)

		// APIs for Javascript to query to drive the page.
		mux.HandleFunc("POST /registration-start", s.handleRegistrationStart)
		mux.HandleFunc("POST /registration-finish", s.handleRegistrationFinish)
		mux.HandleFunc("POST /login-start", s.handleLoginStart)
		mux.HandleFunc("POST /login-finish", s.handleLoginFinish)
		mux.HandleFunc("POST /reauth-start", s.handleReauthStart)
		mux.HandleFunc("POST /reauth-finish", s.handleReauthFinish)
		mux.HandleFunc("POST /register-key-start", s.handleNewKeyStart)
		mux.HandleFunc("POST /register-key-finish", s.handleNewKeyFinish)

		// Static Javascript and CSS assets.
		mux.HandleFunc("GET /js/main.js", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, s.staticFS, "static/main.js")
		})
		mux.HandleFunc("GET /css/main.css", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, s.staticFS, "static/main.css")
		})
		s.handler = mux
	})

	s.handler.ServeHTTP(w, r)
}

// user returns the authenticated user for the request, or false if one can't be
// found. Errors generally represent internal issues, and should be surfaced to
// the end user, not just assumed that a user isn't logged in.
func (s *server) user(r *http.Request) (*user, bool, error) {
	c, err := r.Cookie(cookieSessionID)
	if err != nil {
		return nil, false, nil
	}

	ses, ok, err := s.storage.getSession(r.Context(), c.Value)
	if err != nil {
		return nil, false, fmt.Errorf("getting session: %v", err)
	}
	if !ok {
		return nil, false, nil
	}

	u, ok, err := s.storage.getUser(r.Context(), ses.username)
	if err != nil {
		return nil, false, fmt.Errorf("getting user: %v", err)
	}
	return u, ok, nil
}

// setCookie is a helper that sets a cookie to a provided value.
func (s *server) setCookie(w http.ResponseWriter, r *http.Request, key, val string, exp time.Time) {
	c := &http.Cookie{
		Name:     key,
		Value:    val,
		Secure:   r.TLS != nil, // Attempt to detect if the request uses HTTPS.
		HttpOnly: true,
		Expires:  exp,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, c)
}

// clearCookie instructs the client to delete a cookie.
func (s *server) clearCookie(w http.ResponseWriter, r *http.Request, key string) {
	c := &http.Cookie{
		Name:     key,
		MaxAge:   -1,
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

// handleIndex drives the two main HTML pages a user sees, either a request to
// login or register an account, or their logged in account and associated
// passkeys.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Recompile every time to allow the --watch flag to work. In the future, only
	// do this once if the embedded FS is used.
	tmpl, err := template.ParseFS(s.staticFS, "static/*.tmpl")
	if err != nil {
		http.Error(w, "Parsing templates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u, ok, err := s.user(r)
	if err != nil {
		http.Error(w, "Fetching user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	buff := &bytes.Buffer{}
	if ok {
		// User is logged in. Display their keys back to them.
		type userPasskeys struct {
			ID                string
			Name              string
			Algorithm         string
			Public            string
			AttestationObject string
			AttestationFormat string
			ClientData        string
			CreatedAt         int64
			BackedUp          bool
			Transports        []string
		}
		var passkeys []userPasskeys
		for _, pk := range u.passkeys {
			pub, err := x509.MarshalPKIXPublicKey(pk.publicKey)
			if err != nil {
				http.Error(w, "Encoding key: "+err.Error(), http.StatusInternalServerError)
				return
			}
			format, err := webauthn.AttestationFormat(pk.attestationObject)
			if err != nil {
				http.Error(w, "Parsing attestation format: "+err.Error(), http.StatusInternalServerError)
				return
			}

			p := userPasskeys{
				ID:                base64.StdEncoding.EncodeToString(pk.passkeyID),
				Name:              pk.name,
				Algorithm:         pk.algorithm.String(),
				Public:            base64.StdEncoding.EncodeToString(pub),
				CreatedAt:         pk.createdAt.UnixMilli(),
				ClientData:        string(pk.clientDataJSON),
				AttestationFormat: format,
				AttestationObject: base64.StdEncoding.EncodeToString(pk.attestationObject),
				Transports:        pk.transports,
			}
			passkeys = append(passkeys, p)
		}

		slices.SortFunc(passkeys, func(p1, p2 userPasskeys) int {
			return cmp.Compare(p2.CreatedAt, p1.CreatedAt)
		})

		data := struct {
			Username string
			Passkeys []userPasskeys
		}{
			Username: u.username,
			Passkeys: passkeys,
		}
		if err := tmpl.ExecuteTemplate(buff, "user.html.tmpl", data); err != nil {
			http.Error(w, "Rendering template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// User isn't logged in. Display a page for them to login or register.
		if err := tmpl.ExecuteTemplate(buff, "login.html.tmpl", nil); err != nil {
			http.Error(w, "Rendering template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	io.Copy(w, buff)
}

// handleLogout clears the user's current session.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, r, cookieSessionID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLoginStart attempts to initiate a challenge against a user's security
// keys. Because the user isn't logged in yet, the challenge requires a resident
// key, and therefore doesn't present the set of key IDs back to the user.
func (s *server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	// "Challenges SHOULD therefore be at least 16 bytes long."
	//
	// https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
	challenge := randBytes(16)
	loginID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	exp := time.Now().Add(time.Hour)

	l := &login{
		id:        loginID,
		challenge: challenge,
		expiresAt: exp,
	}
	if err := s.storage.insertLogin(r.Context(), l); err != nil {
		http.Error(w, "Creating login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Set the login cookie.
	s.setCookie(w, r, cookieLoginID, loginID, exp)

	resp := struct {
		Challenge []byte `json:"challenge"`
	}{
		Challenge: challenge,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleLoginFinish processes a channel response from a passkey, attempting to
// authenticate as the user specified in the login attempt.
func (s *server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieLoginID)
	if err != nil {
		http.Error(w, "No login ID provided: "+err.Error(), http.StatusBadRequest)
		return
	}
	l, err := s.storage.getLogin(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "Get passkey login: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
		Signature         []byte `json:"signature"`
		UserHandle        []byte `json:"userHandle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}

	p, err := s.storage.getPasskey(r.Context(), req.UserHandle)
	if err != nil {
		http.Error(w, "Looking up passkey: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := s.rp.VerifyAssertion(p.publicKey, p.algorithm, l.challenge, req.ClientDataJSON, req.AuthenticatorData, req.Signature); err != nil {
		http.Error(w, "Verifying passkey: "+err.Error(), http.StatusUnauthorized)
		return
	}

	exp := time.Now().Add(time.Hour * 24)
	// User is authenticate, create a session and set a cookie.
	sessionID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	ses := &session{
		id:        sessionID,
		username:  p.username,
		expiresAt: exp,
	}
	if err := s.storage.insertSession(r.Context(), ses); err != nil {
		http.Error(w, "Creating session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.setCookie(w, r, cookieSessionID, sessionID, exp)
}

// handleRegistrationStart begins the process of registering an account. This
// verifies the username doesn't already exist, generates a registration
// challenge, and returns the challenge and a cookie to the user.
func (s *server) handleRegistrationStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}

	_, ok, err := s.storage.getUser(r.Context(), req.Username)
	if err != nil {
		http.Error(w, "Looking up user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if ok {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	// "Challenges SHOULD therefore be at least 16 bytes long."
	//
	// https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
	challenge := randBytes(16)
	registrationID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	userHandle := randBytes(16)

	exp := time.Now().Add(time.Hour)
	reg := &registration{
		id:         registrationID,
		username:   req.Username,
		userHandle: userHandle,
		challenge:  challenge,
		expiresAt:  exp,
	}
	if err := s.storage.insertRegistration(r.Context(), reg); err != nil {
		http.Error(w, "Creating registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		Challenge []byte `json:"challenge"`
		UserID    []byte `json:"userID"`
	}{
		Challenge: challenge,
		UserID:    userHandle,
	}

	s.setCookie(w, r, cookieRegistrationID, registrationID, exp)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRegistrationFinish verifies the attestation data of the passkey
// creation and creates an account if the data is valid.
func (s *server) handleRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieRegistrationID)
	if err != nil {
		http.Error(w, "No registration ID provided: "+err.Error(), http.StatusBadRequest)
		return
	}
	reg, err := s.storage.getRegistration(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "Get passkey registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		Transports        []string `json:"transports"`
		AttestationObject []byte   `json:"attestationObject"`
		ClientDataJSON    []byte   `json:"clientDataJSON"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}

	authData, err := s.rp.VerifyAttestation(reg.challenge, req.ClientDataJSON, req.AttestationObject)
	if err != nil {
		http.Error(w, "Failed to verify attestation: "+err.Error(), http.StatusBadRequest)
		return
	}

	passkeyName := "Passkey"
	if name, ok := authData.AAGUID.Name(); ok {
		passkeyName = name
	}

	p := &passkey{
		username:          reg.username,
		name:              passkeyName,
		userHandle:        reg.userHandle,
		passkeyID:         authData.CredentialID,
		publicKey:         authData.PublicKey,
		algorithm:         authData.Algorithm,
		createdAt:         time.Now(),
		transports:        req.Transports,
		attestationObject: req.AttestationObject,
		clientDataJSON:    req.ClientDataJSON,
	}
	u := &user{
		username: reg.username,
		passkeys: []*passkey{p},
	}
	if err := s.storage.insertUser(r.Context(), u); err != nil {
		http.Error(w, "Creating user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	exp := time.Now().Add(time.Hour * 24)
	sessionID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	ses := &session{
		id:        sessionID,
		username:  reg.username,
		expiresAt: exp,
	}
	if err := s.storage.insertSession(r.Context(), ses); err != nil {
		http.Error(w, "Creating session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.setCookie(w, r, cookieSessionID, sessionID, exp)
}

// handleReauthStart is a second factor challenge against the set of passkeys
// registered for a logged in account.
func (s *server) handleReauthStart(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.user(r)
	if err != nil {
		http.Error(w, "Fetching user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}

	challenge := randBytes(16)
	reauthID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	exp := time.Now().Add(time.Hour)

	re := &reauth{
		id:        reauthID,
		username:  u.username,
		challenge: challenge,
		expiresAt: exp,
	}
	if err := s.storage.insertReauth(r.Context(), re); err != nil {
		http.Error(w, "Creating login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.setCookie(w, r, cookieReauthID, reauthID, exp)

	type reauthCredential struct {
		ID         []byte   `json:"id"`
		Transports []string `json:"transports"`
	}

	var creds []reauthCredential
	for _, pk := range u.passkeys {
		creds = append(creds, reauthCredential{pk.passkeyID, pk.transports})
	}

	resp := struct {
		Credentials []reauthCredential `json:"credentials"`
		Challenge   []byte             `json:"challenge"`
	}{
		Credentials: creds,
		Challenge:   challenge,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleReauthFinish verifies an second factor challenge against the currently
// logged in account.
func (s *server) handleReauthFinish(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.user(r)
	if err != nil {
		http.Error(w, "Fetching user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}

	c, err := r.Cookie(cookieReauthID)
	if err != nil {
		http.Error(w, "No reauth ID provided: "+err.Error(), http.StatusBadRequest)
		return
	}
	re, err := s.storage.getReauth(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "Get reauth challenge: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
		Signature         []byte `json:"signature"`
		UserHandle        []byte `json:"userHandle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}

	p, err := s.storage.getPasskey(r.Context(), req.UserHandle)
	if err != nil {
		http.Error(w, "Looking up passkey: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if p.username != u.username {
		http.Error(w, "Passkey not registered for user", http.StatusBadRequest)
		return
	}

	if _, err := s.rp.VerifyAssertion(p.publicKey, p.algorithm, re.challenge, req.ClientDataJSON, req.AuthenticatorData, req.Signature); err != nil {
		http.Error(w, "Verifying passkey: "+err.Error(), http.StatusUnauthorized)
		return
	}

	s.clearCookie(w, r, cookieReauthID)
}

// handleNewKeyStart begins the processes to register a passkey with an account.
func (s *server) handleNewKeyStart(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.user(r)
	if err != nil {
		http.Error(w, "Fetching user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}

	id := base64.RawURLEncoding.EncodeToString(randBytes(16))
	challenge := randBytes(16)
	credentialID := randBytes(16)
	userHandle := randBytes(16)

	exp := time.Now().Add(time.Hour)
	reg := &passkeyRegistration{
		id:         id,
		challenge:  challenge,
		userHandle: userHandle,
		expiresAt:  exp,
	}

	if err := s.storage.insertPasskeyRegistration(r.Context(), reg); err != nil {
		http.Error(w, "Creating registration record: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var credIDs [][]byte
	for _, pk := range u.passkeys {
		credIDs = append(credIDs, pk.passkeyID)
	}

	resp := struct {
		ID        []byte   `json:"credentialID"`
		IDs       [][]byte `json:"credentialIDs"`
		Username  string   `json:"username"`
		UserID    []byte   `json:"userID"`
		Challenge []byte   `json:"challenge"`
	}{
		ID:        credentialID,
		IDs:       credIDs,
		Username:  u.username,
		UserID:    userHandle,
		Challenge: challenge,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Encoding response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.setCookie(w, r, cookieKeyRegistrationID, id, exp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// handleNewKeyFinish processes a key challenge and attempts to register the
// key with the active account.
func (s *server) handleNewKeyFinish(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.user(r)
	if err != nil {
		http.Error(w, "Fetching user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}

	c, err := r.Cookie(cookieKeyRegistrationID)
	if err != nil {
		http.Error(w, "No key registration ID provided: "+err.Error(), http.StatusBadRequest)
		return
	}
	reg, err := s.storage.getPasskeyRegistration(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "Get passkey registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		Transports        []string `json:"transports"`
		AttestationObject []byte   `json:"attestationObject"`
		ClientDataJSON    []byte   `json:"clientDataJSON"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}

	authData, err := s.rp.VerifyAttestation(reg.challenge, req.ClientDataJSON, req.AttestationObject)
	if err != nil {
		http.Error(w, "Failed to verify attestation: "+err.Error(), http.StatusBadRequest)
		return
	}
	passkeyName := "Passkey"
	if name, ok := authData.AAGUID.Name(); ok {
		passkeyName = name
	}

	p := &passkey{
		username:          u.username,
		name:              passkeyName,
		userHandle:        reg.userHandle,
		passkeyID:         authData.CredentialID,
		publicKey:         authData.PublicKey,
		algorithm:         authData.Algorithm,
		createdAt:         time.Now(),
		transports:        req.Transports,
		attestationObject: req.AttestationObject,
		clientDataJSON:    req.ClientDataJSON,
	}
	if err := s.storage.insertPasskey(r.Context(), p); err != nil {
		http.Error(w, "Saving passkey to database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.clearCookie(w, r, cookieKeyRegistrationID)
}
