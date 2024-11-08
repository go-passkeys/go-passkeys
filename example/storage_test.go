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

func TestStoragePasskeyRegistration(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	now := time.Now().Round(time.Microsecond)
	want := &passkeyRegistration{
		id:        "testid",
		username:  "testuser",
		userID:    []byte("testuserid"),
		challenge: []byte("testchallenge"),
		createdAt: now,
	}
	if err := s.insertPasskeyRegistration(ctx, want); err != nil {
		t.Fatalf("Inserting passkey registration: %v", err)
	}
	got, err := s.getPasskeyRegistration(ctx, "testid")
	if err != nil {
		t.Fatalf("Getting passkey registration: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting passkey registration returned unexpected result (-want, +got): %s", diff)
	}

	if _, err := s.getPasskeyRegistration(ctx, "testid"); err == nil {
		t.Errorf("Expected getting registration to delete row")
	}
}

func TestStoragePasskeyLogin(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	now := time.Now().Round(time.Microsecond)
	want := &passkeyLogin{
		id:        "testid",
		username:  "testuser",
		challenge: []byte("testchallenge"),
		createdAt: now,
	}
	if err := s.insertPasskeyLogin(ctx, want); err != nil {
		t.Fatalf("Inserting passkey login: %v", err)
	}
	got, err := s.getPasskeyLogin(ctx, "testid")
	if err != nil {
		t.Fatalf("Getting passkey login: %v", err)
	}
	if diff := cmp.Diff(want, got, cmpOptAllowUnexported); diff != "" {
		t.Errorf("Getting passkey login returned unexpected result (-want, +got): %s", diff)
	}

	if _, err := s.getPasskeyLogin(ctx, "testid"); err == nil {
		t.Errorf("Expected getting login to delete row")
	}
}
