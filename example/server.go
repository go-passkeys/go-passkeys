package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"text/template"
	"time"

	"github.com/ericchiang/go-webauthn/webauthn"
)

const (
	cookieSessionID      = "session.id"
	cookieRegistrationID = "registration.id"
	cookieLoginID        = "login.id"
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

	md, err := getMetadataBLOB()
	if err != nil {
		log.Fatalf("getting FIDO metadata: %v", err)
	}

	var staticFS fs.FS = staticFSEmbed
	if watch {
		staticFS = os.DirFS(".")
	}

	ctx := context.Background()
	st, err := newStorage(ctx, dbPath)
	if err != nil {
		log.Fatalf("Initializing database: %v", err)
	}

	s := &server{
		storage:  st,
		staticFS: staticFS,
		metadata: md,
	}
	log.Printf("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(":8080", s))
}

func getMetadataBLOB() (*webauthn.Metadata, error) {
	resp, err := http.Get("https://mds3.fidoalliance.org/")
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request returned unexpected status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %v", err)
	}
	md, err := webauthn.ParseMetadata(body)
	if err != nil {
		return nil, fmt.Errorf("parsing blob: %v", err)
	}
	return md, nil
}

func randBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

//go:embed static
var staticFSEmbed embed.FS

type server struct {
	staticFS fs.FS
	storage  *storage
	metadata *webauthn.Metadata

	once    sync.Once
	handler http.Handler
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.once.Do(func() {
		mux := http.NewServeMux()

		mux.HandleFunc("GET /", s.handleIndex)
		mux.HandleFunc("GET /login", s.handleLogin)
		mux.HandleFunc("GET /logout", s.handleLogout)

		mux.HandleFunc("POST /registration-start", s.handleRegistrationStart)
		mux.HandleFunc("POST /registration-finish", s.handleRegistrationFinish)
		mux.HandleFunc("POST /login-start", s.handleLoginStart)
		mux.HandleFunc("POST /login-finish", s.handleLoginFinish)

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

func (s *server) setCookie(w http.ResponseWriter, r *http.Request, key, val string, exp time.Duration) {
	c := &http.Cookie{
		Name:     key,
		Value:    val,
		Secure:   r.TLS != nil,
		HttpOnly: true,
		Expires:  time.Now().Add(exp),
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, c)
}

func (s *server) clearCookie(w http.ResponseWriter, r *http.Request, key string) {
	c := &http.Cookie{
		Name:     key,
		MaxAge:   -1,
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
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
		type userPasskeys struct {
			Name      string
			Algorithm string
			Public    string
		}
		var passkeys []userPasskeys
		for _, pk := range u.passkeys {
			pub, err := x509.MarshalPKIXPublicKey(pk.publicKey)
			if err != nil {
				http.Error(w, "Encoding key: "+err.Error(), http.StatusInternalServerError)
				return
			}
			p := userPasskeys{
				Name:      pk.name,
				Algorithm: pk.algorithm.String(),
				Public:    base64.StdEncoding.EncodeToString(pub),
			}
			passkeys = append(passkeys, p)
		}

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
		if err := tmpl.ExecuteTemplate(buff, "login.html.tmpl", nil); err != nil {
			http.Error(w, "Rendering template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	io.Copy(w, buff)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, r, cookieSessionID)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, s.staticFS, "static/login.html")
}

func (s *server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
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
	if !ok {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// "Challenges SHOULD therefore be at least 16 bytes long."
	//
	// https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
	challenge := randBytes(16)
	loginID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	now := time.Now()

	l := &passkeyLogin{
		id:        loginID,
		username:  req.Username,
		challenge: challenge,
		createdAt: now,
	}
	if err := s.storage.insertPasskeyLogin(r.Context(), l); err != nil {
		http.Error(w, "Creating login: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		Challenge []byte `json:"challenge"`
	}{
		Challenge: challenge,
	}

	s.setCookie(w, r, cookieLoginID, loginID, time.Hour)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

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
	userID := randBytes(16)

	now := time.Now()
	reg := &passkeyRegistration{
		id:        registrationID,
		username:  req.Username,
		userID:    userID,
		challenge: challenge,
		createdAt: now,
	}
	if err := s.storage.insertPasskeyRegistration(r.Context(), reg); err != nil {
		http.Error(w, "Creating registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		Challenge []byte `json:"challenge"`
		UserID    []byte `json:"userID"`
	}{
		Challenge: challenge,
		UserID:    userID,
	}

	s.setCookie(w, r, cookieRegistrationID, registrationID, time.Hour)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieLoginID)
	if err != nil {
		http.Error(w, "No login ID provided: "+err.Error(), http.StatusBadRequest)
		return
	}
	l, err := s.storage.getPasskeyLogin(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "Get passkey login: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
		Signature         []byte `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}

	u, ok, err := s.storage.getUser(r.Context(), l.username)
	if err != nil {
		http.Error(w, "Looking up user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "User does not exist: "+l.username, http.StatusBadRequest)
		return
	}

	var found bool
	for _, pk := range u.passkeys {
		if err := webauthn.Verify(pk.publicKey, pk.algorithm, req.AuthenticatorData, req.ClientDataJSON, req.Signature); err == nil {
			found = true
		}
	}
	if !found {
		http.Error(w, "Passkey not registered to account", http.StatusUnauthorized)
		return
	}

	sessionID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	ses := &session{
		id:        sessionID,
		username:  l.username,
		createdAt: time.Now(),
	}
	if err := s.storage.insertSession(r.Context(), ses); err != nil {
		http.Error(w, "Creating session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.setCookie(w, r, cookieSessionID, sessionID, time.Hour*24)
}

func (s *server) handleRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieRegistrationID)
	if err != nil {
		http.Error(w, "No registration ID provided: "+err.Error(), http.StatusBadRequest)
		return
	}
	reg, err := s.storage.getPasskeyRegistration(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "Get passkey registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		AttestationObject []byte `json:"attestationObject"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Decoding request: "+err.Error(), http.StatusBadRequest)
		return
	}

	att, err := webauthn.ParseAttestationObject(req.AttestationObject)
	if err != nil {
		http.Error(w, "Failed to parse attestation object: "+err.Error(), http.StatusBadRequest)
		return
	}
	authData, err := att.AuthenticatorData()
	if err != nil {
		http.Error(w, "Parsing authenticator data: "+err.Error(), http.StatusBadRequest)
		return
	}

	var clientData webauthn.ClientData
	if err := json.Unmarshal(req.ClientDataJSON, &clientData); err != nil {
		http.Error(w, "Parsing client data: "+err.Error(), http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(clientData.Challenge), reg.challenge) != 1 {
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	p := &passkey{
		username:          reg.username,
		name:              "My passkey",
		passkeyID:         authData.CredID,
		publicKey:         authData.PublicKey,
		algorithm:         authData.Alg,
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

	sessionID := base64.RawURLEncoding.EncodeToString(randBytes(16))
	ses := &session{
		id:        sessionID,
		username:  reg.username,
		createdAt: time.Now(),
	}
	if err := s.storage.insertSession(r.Context(), ses); err != nil {
		http.Error(w, "Creating session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.setCookie(w, r, cookieSessionID, sessionID, time.Hour*24)
}
