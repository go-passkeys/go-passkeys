package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ericchiang/go-webauthn/webauthn"
	"github.com/google/go-cmp/cmp"
)

func newTestStorage(t *testing.T) *storage {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := newStorage(ctx, dbPath)
	if err != nil {
		t.Fatalf("Creating new storage: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Closing storage: %v", err)
		}
	})
	return s
}

func TestNewStorage(t *testing.T) {
	newTestStorage(t)
}

func TestStorageGC(t *testing.T) {
	now := time.Now()
	s := newTestStorage(t)
	s.now = func() time.Time { return now }

	if err := s.gc(); err != nil {
		t.Errorf("Running storage garbage collection: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if err := s.gc(); err != nil {
		t.Errorf("Running storage garbage collection after advancing clock: %v", err)
	}
}

// go-cmp option for allowing comparison of unexported fields.
//
// https://github.com/google/go-cmp/issues/40
var cmpOptAllowUnexported = cmp.Exporter(func(reflect.Type) bool {
	return true
})

func TestStorageUser(t *testing.T) {
	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Generating test key: %v", err)
	}

	s := newTestStorage(t)
	want := &user{
		username: "testuser",
		passkeys: []*passkey{
			{
				username:          "testuser",
				name:              "my security key",
				userHandle:        []byte("testuserhandle"),
				passkeyID:         []byte("passkeyid"),
				publicKey:         priv.Public(),
				algorithm:         webauthn.ES256,
				attestationObject: []byte("attestation"),
				clientDataJSON:    []byte("client data json"),
			},
		},
	}
	if err := s.insertUser(ctx, want); err != nil {
		t.Fatalf("Inserting user: %v", err)
	}
	if err := s.insertUser(ctx, want); err == nil {
		t.Errorf("Inserting duplicate user expected failure")
	}

	got, ok, err := s.getUser(ctx, "testuser")
	if err != nil || !ok {
		t.Fatalf("Getting user returned unexpected result, err=%v, ok=%v", err, ok)
	}
	if diff := cmp.Diff(want, got, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting user returned unexpected diff (-want, +got): %s", diff)
	}

	_, ok, err = s.getUser(ctx, "idontexist")
	if err != nil {
		t.Fatalf("Getting unknown user returned unexpected result: %v", err)
	}
	if ok {
		t.Fatalf("Getting unknown user returned user unexpectedly")
	}

	gotP, err := s.getPasskey(ctx, []byte("testuserhandle"))
	if err != nil {
		t.Fatalf("Getting passkey: %v", err)
	}
	wantP := got.passkeys[0]
	if diff := cmp.Diff(wantP, gotP, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting passkey returned unexpected diff (-want, +got): %s", diff)
	}
}

func TestStorageSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)
	u := &user{username: "testuser"}
	if err := s.insertUser(ctx, u); err != nil {
		t.Fatalf("Inserting user: %v", err)
	}

	now := time.Now().Round(time.Microsecond)
	want := &session{
		id:        "abcd",
		username:  "testuser",
		createdAt: now,
	}
	if err := s.insertSession(ctx, want); err != nil {
		t.Fatalf("Inserting session: %v", err)
	}

	got, _, err := s.getSession(ctx, "abcd")
	if err != nil {
		t.Fatalf("Getting session: %v", err)
	}
	if diff := cmp.Diff(got, want, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting session returned unexpected result (-want, +got): %s", diff)
	}

	if _, ok, err := s.getSession(ctx, "idontexist"); err != nil || ok {
		t.Errorf("Getting session that doesn't exist, got (ok=%v, err=%v), want(ok=false, err=nil)", ok, err)
	}
}

func TestStorageRegistration(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	now := time.Now().Round(time.Microsecond)
	want := &registration{
		id:          "testid",
		username:    "testuser",
		passkeyName: "testkey",
		userHandle:  []byte("testuserid"),
		challenge:   []byte("testchallenge"),
		createdAt:   now,
	}
	if err := s.insertRegistration(ctx, want); err != nil {
		t.Fatalf("Inserting passkey registration: %v", err)
	}
	got, err := s.getRegistration(ctx, "testid")
	if err != nil {
		t.Fatalf("Getting passkey registration: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting passkey registration returned unexpected result (-want, +got): %s", diff)
	}

	if _, err := s.getRegistration(ctx, "testid"); err == nil {
		t.Errorf("Expected getting registration to delete row")
	}
}

func TestStorageLogin(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	now := time.Now().Round(time.Microsecond)
	want := &login{
		id:        "testid",
		username:  "testuser",
		challenge: []byte("testchallenge"),
		createdAt: now,
	}
	if err := s.insertLogin(ctx, want); err != nil {
		t.Fatalf("Inserting passkey login: %v", err)
	}
	got, err := s.getLogin(ctx, "testid")
	if err != nil {
		t.Fatalf("Getting passkey login: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting passkey login returned unexpected result (-want, +got): %s", diff)
	}

	if _, err := s.getLogin(ctx, "testid"); err == nil {
		t.Errorf("Expected getting login to delete row")
	}
}

func TestStorageReauth(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	now := time.Now().Round(time.Microsecond)
	want := &reauth{
		id:        "testid",
		username:  "testuser",
		challenge: []byte("testchallenge"),
		createdAt: now,
	}
	if err := s.insertReauth(ctx, want); err != nil {
		t.Fatalf("Inserting passkey reauth: %v", err)
	}
	got, err := s.getReauth(ctx, "testid")
	if err != nil {
		t.Fatalf("Getting passkey reauth: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting passkey reauth returned unexpected result (-want, +got): %s", diff)
	}

	if _, err := s.getReauth(ctx, "testid"); err == nil {
		t.Errorf("Expected getting reauth to delete row")
	}
}
