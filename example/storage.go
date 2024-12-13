package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ericchiang/go-webauthn/webauthn"

	_ "github.com/mattn/go-sqlite3" // Register driver.
)

var schema = `
-- Users tracked by the application.
CREATE TABLE IF NOT EXISTS users (
	username STRING NOT NULL,

	PRIMARY KEY(username),
	UNIQUE(username)
);

-- A child table holding user passkeys.
CREATE TABLE IF NOT EXISTS passkeys (
	-- Name of the user this passkey is associated with.
	username STRING NOT NULL,
	-- User handle stored on the passkey and presented during authentication.
	--
	-- https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle
	user_handle BLOB NOT NULL,

	name        STRING NOT NULL,
	passkey_id  BLOB NOT NULL,
	public_key  BLOB NOT NULL,
	algorithm   INTEGER NOT NULL,
	created_at  INTEGER NOT NULL,
	-- JSON array of transport that have been registered.
	transports BLOB NOT NULL,

	-- Fields used during registration and stored for debugging.
	attestation_object BLOB NOT NULL,
    client_data_json   BLOB NOT NULL,

	PRIMARY KEY(user_handle),
	FOREIGN KEY(username) REFERENCES users(username),
	UNIQUE(user_handle)
);

CREATE INDEX IF NOT EXISTS passkeys_by_username ON passkeys (username);

-- Inflight attempts to register a new account with the server.
CREATE TABLE IF NOT EXISTS registrations (
	registration_id STRING NOT NULL,
	username        STRING NOT NULL,
	user_handle     BLOB NOT NULL,
	challenge       BLOB NOT NULL,

	-- Unix microseconds. Used to clean up old registration attempts.
	expires_at INTEGER NOT NULL,

	PRIMARY KEY(registration_id)
);

-- Inflight attempts to login to the server.
CREATE TABLE IF NOT EXISTS logins (
	login_id   STRING NOT NULL,
	username   STRING NOT NULL,
	challenge  BLOB NOT NULL,

	-- Unix microseconds. Used to clean up old login attempts.
	expires_at INTEGER NOT NULL,

	PRIMARY KEY(login_id)
);

-- Inflight attempts to reauthenticate to the server.
CREATE TABLE IF NOT EXISTS reauths (
	reauth_id   STRING NOT NULL,
	username   STRING NOT NULL,
	challenge  BLOB NOT NULL,

	-- Unix microseconds. Used to clean up old login attempts.
	expires_at INTEGER NOT NULL,

	PRIMARY KEY(reauth_id)
);

-- Active sessions where a user is authenticated.
CREATE TABLE IF NOT EXISTS sessions (
	session_id STRING NOT NULL,
	username   STRING NOT NULL,

	-- Unix microseconds. Session expire after 24 hours.
	expires_at INTEGER NOT NULL,

	UNIQUE (session_id),
	PRIMARY KEY(session_id),
	FOREIGN KEY(username) REFERENCES users(username)
);

-- Attempts to register a new key for an account.
CREATE TABLE IF NOT EXISTS passkey_registrations (
	id          STRING NOT NULL,
	challenge   BLOB NOT NULL,
	user_handle BLOB NOT NULL,

	-- Unix microseconds. Expires after 1 hour.
	expires_at INTEGER NOT NULL,

	PRIMARY KEY(id)
);
`

// storage implements an SQLite3 database client.
type storage struct {
	db *sql.DB

	close func()
	// An optional user provided time function.
	now func() time.Time
}

// newStorage initializes a connection to the provied database and attempts to
// apply any schema changes, initializes a background routine for cleaning up
// expired rows, and returns a connection.
//
// Callers are expected to call Close() on the returned storage object.
func newStorage(ctx context.Context, path string) (*storage, error) {
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("opening db: %v", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, fmt.Errorf("creating schema: %v", err)
	}
	s := &storage{db: db}

	doneCh := make(chan struct{})
	go func() {
		select {
		case <-time.After(time.Minute):
			if err := s.gc(); err != nil {
				log.Printf("Running garbage collection: %v", err)
			}
		case <-doneCh:
			return
		}
	}()
	s.close = func() {
		close(doneCh)
	}
	return s, nil
}

// Close cleans up all resources associated with the client.
func (s *storage) Close() error {
	s.close()
	return s.db.Close()
}

// gc deletes any rows that have expired.
func (s *storage) gc() error {
	now := s.now
	if now == nil {
		now = time.Now
	}

	t := now().UnixMicro()
	if _, err := s.db.Exec(`
		DELETE FROM registrations
		WHERE expires_at < ?`, t); err != nil {
		return fmt.Errorf("deleting old registrations: %v", err)
	}
	if _, err := s.db.Exec(`
		DELETE FROM logins
		WHERE expires_at < ?`, t); err != nil {
		return fmt.Errorf("deleting old logins: %v", err)
	}
	if _, err := s.db.Exec(`
		DELETE FROM sessions
		WHERE expires_at < ?`, t); err != nil {
		return fmt.Errorf("deleting old sessions: %v", err)
	}
	if _, err := s.db.Exec(`
		DELETE FROM passkey_registrations
		WHERE expires_at < ?`, t); err != nil {
		return fmt.Errorf("deleting old passkey registrations")
	}
	return nil
}

// user represents a user account. A username and a set of passkeys that can
// be used to authenticate as that user.
type user struct {
	username string

	passkeys []*passkey
}

// passkey holds various data associated with the key, including registration
// blobs, such as the attestation object and clientDataJSON that were returned
// by the browser.
type passkey struct {
	username   string
	name       string
	userHandle []byte
	passkeyID  []byte
	createdAt  time.Time
	publicKey  crypto.PublicKey
	algorithm  webauthn.Algorithm
	transports []string

	attestationObject []byte
	clientDataJSON    []byte
}

// insertUser creates database records for the provided user and associated
// passkeys.
func (s *storage) insertUser(ctx context.Context, u *user) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (username)
		VALUES (?)`, u.username); err != nil {
		return fmt.Errorf("inserting user: %v", err)
	}

	for _, p := range u.passkeys {
		pub, err := x509.MarshalPKIXPublicKey(p.publicKey)
		if err != nil {
			return fmt.Errorf("encoding public key: %v", err)
		}
		transports, err := json.Marshal(p.transports)
		if err != nil {
			return fmt.Errorf("encoding transports: %v", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO passkeys
			(username, name, passkey_id, user_handle, created_at,
			public_key, algorithm, transports,
			attestation_object, client_data_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, p.username, p.name, p.passkeyID, p.userHandle, p.createdAt.UnixMicro(),
			pub, int64(p.algorithm), transports,
			p.attestationObject, p.clientDataJSON); err != nil {
			return fmt.Errorf("inserting passkey: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commiting transaction: %v", err)
	}
	return nil
}

// insertPasskey stores a passkey associated with a user
func (s *storage) insertPasskey(ctx context.Context, p *passkey) error {
	pub, err := x509.MarshalPKIXPublicKey(p.publicKey)
	if err != nil {
		return fmt.Errorf("encoding public key: %v", err)
	}
	transports, err := json.Marshal(p.transports)
	if err != nil {
		return fmt.Errorf("encoding transports: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
			INSERT INTO passkeys
			(username, name, passkey_id, user_handle, created_at,
			public_key, algorithm, transports,
			attestation_object, client_data_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, p.username, p.name, p.passkeyID, p.userHandle, p.createdAt.UnixMicro(),
		pub, int64(p.algorithm), transports,
		p.attestationObject, p.clientDataJSON); err != nil {
		return fmt.Errorf("inserting passkey: %v", err)
	}
	return nil
}

// getUser returns the requested user by name and the set of passkeys that can
// be used to login to their account.
func (s *storage) getUser(ctx context.Context, username string) (*user, bool, error) {
	u := &user{}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, fmt.Errorf("getting user: %v", err)
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `
		SELECT username
		FROM users
		WHERE username = ?`, username).Scan(&u.username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("querying row: %v", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT
		name, passkey_id, user_handle, created_at,
		public_key, algorithm, transports,
		attestation_object, client_data_json
		FROM passkeys
		WHERE username = ?`, username)
	if err != nil {
		return nil, false, fmt.Errorf("querying passkeys: %v", err)
	}
	for rows.Next() {
		p := &passkey{username: username}
		var (
			pubDER     []byte
			transports []byte
			alg        int64
			createdAt  int64
		)
		if err := rows.Scan(&p.name, &p.passkeyID, &p.userHandle, &createdAt, &pubDER, &alg, &transports, &p.attestationObject, &p.clientDataJSON); err != nil {
			return nil, false, fmt.Errorf("scanning passkey row: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			return nil, false, fmt.Errorf("parsing public key: %v", err)
		}
		if err := json.Unmarshal(transports, &p.transports); err != nil {
			return nil, false, fmt.Errorf("parsing transports: %v", err)
		}
		p.publicKey = pub
		p.algorithm = webauthn.Algorithm(alg)
		p.createdAt = time.UnixMicro(createdAt)

		u.passkeys = append(u.passkeys, p)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("scanning passkey rows: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commiting transaction: %v", err)
	}
	return u, true, nil
}

// getPasskey returns an individual passkey by user handle.
func (s *storage) getPasskey(ctx context.Context, userHandle []byte) (*passkey, error) {
	p := &passkey{
		userHandle: userHandle,
	}
	var (
		pubDER     []byte
		transports []byte
		alg        int64
		createdAt  int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT
		username, name, passkey_id, created_at,
		public_key, algorithm, transports,
		attestation_object, client_data_json
		FROM passkeys
		WHERE user_handle = ?`, userHandle).
		Scan(&p.username, &p.name, &p.passkeyID, &createdAt, &pubDER, &alg, &transports, &p.attestationObject, &p.clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("scanning passkey row: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	if err := json.Unmarshal(transports, &p.transports); err != nil {
		return nil, fmt.Errorf("parsing transports: %v", err)
	}
	p.publicKey = pub
	p.algorithm = webauthn.Algorithm(alg)
	p.createdAt = time.UnixMicro(createdAt)
	return p, nil
}

// session represents an active, authenticated session by a particular user.
type session struct {
	id        string
	username  string
	expiresAt time.Time
}

// insertSession stores a session record in the database.
func (s *storage) insertSession(ctx context.Context, ses *session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions
		(session_id, username, expires_at)
		VALUES (?, ?, ?)`, ses.id, ses.username, ses.expiresAt.UnixMicro())
	if err != nil {
		return fmt.Errorf("inserting session: %v", err)
	}
	return nil
}

// getSession returns the session by ID. Or false if the ID was not found, for
// example, because it expired.
func (s *storage) getSession(ctx context.Context, id string) (*session, bool, error) {
	ses := &session{id: id}
	var expiresAt int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT username, expires_at
		FROM sessions
		WHERE session_id = ?`, id).Scan(&ses.username, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("querying session table: %v", err)
	}
	ses.expiresAt = time.UnixMicro(expiresAt)
	return ses, true, nil
}

// login is an attempt to login.
type login struct {
	id        string
	username  string
	challenge []byte
	expiresAt time.Time
}

// insertLogin creates a database record for the login attempt.
func (s *storage) insertLogin(ctx context.Context, l *login) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO logins
		(login_id, username, challenge, expires_at)
		VALUES
		(?, ?, ?, ?)`,
		l.id, l.username, l.challenge, l.expiresAt.UnixMicro()); err != nil {
		return fmt.Errorf("inserting login row: %v", err)
	}
	return nil
}

// getLogin retreives a login attempt by ID, then immediately deletes
// the record. The read-once logic is to avoid any issues with duplicate logins
// or having to reasoning about similar shenanigans.
func (s *storage) getLogin(ctx context.Context, id string) (*login, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()

	l := &login{id: id}
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `
		SELECT username, challenge, expires_at
		FROM logins
		WHERE login_id = ?`, id).
		Scan(&l.username, &l.challenge, &expiresAt); err != nil {
		return nil, fmt.Errorf("reading row: %v", err)
	}
	l.expiresAt = time.UnixMicro(expiresAt)

	result, err := tx.ExecContext(ctx, `DELETE FROM logins WHERE login_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("deleting login record: %v", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("determining rows affected: %v", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("failed to delete row")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %v", err)
	}
	return l, nil
}

// reauth is an attempt to reauth.
type reauth struct {
	id        string
	username  string
	challenge []byte
	expiresAt time.Time
}

// insertReauth creates a database record for the reauth attempt.
func (s *storage) insertReauth(ctx context.Context, l *reauth) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO reauths
		(reauth_id, username, challenge, expires_at)
		VALUES
		(?, ?, ?, ?)`,
		l.id, l.username, l.challenge, l.expiresAt.UnixMicro()); err != nil {
		return fmt.Errorf("inserting reauth row: %v", err)
	}
	return nil
}

// getReauth retreives a reauth attempt by ID, then immediately deletes
// the record. The read-once logic is to avoid any issues with duplicate reauths
// or having to reasoning about similar shenanigans.
func (s *storage) getReauth(ctx context.Context, id string) (*reauth, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()

	l := &reauth{id: id}
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `
		SELECT username, challenge, expires_at
		FROM reauths
		WHERE reauth_id = ?`, id).
		Scan(&l.username, &l.challenge, &expiresAt); err != nil {
		return nil, fmt.Errorf("reading row: %v", err)
	}
	l.expiresAt = time.UnixMicro(expiresAt)

	result, err := tx.ExecContext(ctx, `DELETE FROM reauths WHERE reauth_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("deleting reauth record: %v", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("determining rows affected: %v", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("failed to delete row")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %v", err)
	}
	return l, nil
}

// registration is an attempt to register an account, with associated
// passkey attestation challenge.
type registration struct {
	id         string
	username   string
	userHandle []byte
	challenge  []byte
	expiresAt  time.Time
}

// insertRegistration persists the registration attempt to the database.
func (s *storage) insertRegistration(ctx context.Context, p *registration) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO registrations
		(registration_id, username, user_handle, challenge, expires_at)
		VALUES
		(?, ?, ?, ?, ?)`,
		p.id, p.username, p.userHandle, p.challenge, p.expiresAt.UnixMicro()); err != nil {
		return fmt.Errorf("insert record: %v", err)
	}
	return nil
}

// getPasskeyLogin retreives a registration attempt by ID, then immediately
// deletes the record. The read-once logic is to avoid any issues with duplicate
// registrations or having to reasoning about similar shenanigans.
func (s *storage) getRegistration(ctx context.Context, id string) (*registration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()

	p := &registration{id: id}
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `
		SELECT username,  user_handle, challenge, expires_at
		FROM registrations
		WHERE registration_id = ?`, id).
		Scan(&p.username, &p.userHandle, &p.challenge, &expiresAt); err != nil {
		return nil, fmt.Errorf("reading row: %v", err)
	}
	p.expiresAt = time.UnixMicro(expiresAt)

	result, err := tx.ExecContext(ctx, `DELETE FROM registrations WHERE registration_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("deleting registration: %v", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("determining rows affected: %v", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("failed to delete row")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %v", err)
	}
	return p, nil
}

// passkeyRegistration is a challenge for associating a key with a profile.
type passkeyRegistration struct {
	id         string
	challenge  []byte
	userHandle []byte
	expiresAt  time.Time
}

// insertPasskeyRegistration persists the registration attempt to the database.
func (s *storage) insertPasskeyRegistration(ctx context.Context, p *passkeyRegistration) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO passkey_registrations
		(id, challenge, user_handle, expires_at)
		VALUES
		(?, ?, ?, ?)`,
		p.id, p.challenge, p.userHandle, p.expiresAt.UnixMicro()); err != nil {
		return fmt.Errorf("insert record: %v", err)
	}
	return nil
}

// getPasskeyRegistration returns the registration data for a given ID.
func (s *storage) getPasskeyRegistration(ctx context.Context, id string) (*passkeyRegistration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()

	p := &passkeyRegistration{id: id}
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `
		SELECT challenge, user_handle, expires_at
		FROM passkey_registrations
		WHERE id = ?`, id).
		Scan(&p.challenge, &p.userHandle, &expiresAt); err != nil {
		return nil, fmt.Errorf("reading row: %v", err)
	}
	p.expiresAt = time.UnixMicro(expiresAt)

	result, err := tx.ExecContext(ctx, `DELETE FROM passkey_registrations WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("deleting registration: %v", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("determining rows affected: %v", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("failed to delete row")
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %v", err)
	}
	return p, nil
}
