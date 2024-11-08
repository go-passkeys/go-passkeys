package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ericchiang/go-webauthn/webauthn"

	_ "github.com/mattn/go-sqlite3" // Register driver.
)

var schema = `
CREATE TABLE IF NOT EXISTS users (
	username STRING NOT NULL,

	PRIMARY KEY(username),
	UNIQUE(username)
);

CREATE TABLE IF NOT EXISTS passkey_registrations (
	registration_id STRING NOT NULL,
	username        STRING NOT NULL,
	user_id         BLOB NOT NULL,
	challenge       BLOB NOT NULL,
	created_at      INTEGER NOT NULL,

	PRIMARY KEY(registration_id)
);

CREATE TABLE IF NOT EXISTS passkey_logins (
	login_id   STRING NOT NULL,
	username   STRING NOT NULL,
	challenge  BLOB NOT NULL,
	created_at INTEGER NOT NULL,

	PRIMARY KEY(login_id)
);

CREATE TABLE IF NOT EXISTS passkeys (
	username    STRING NOT NULL,
	name        STRING NOT NULL,
	passkey_id  BLOB NOT NULL,
	public_key  BLOB NOT NULL,
	algorithm   INTEGER NOT NULL,

	-- Fields used during registration and stored for debugging.
	attestation_object BLOB NOT NULL,
    client_data_json   BLOB NOT NULL,

	PRIMARY KEY(username),
	FOREIGN KEY(username) REFERENCES users(username)
);

CREATE TABLE IF NOT EXISTS sessions (
	session_id STRING NOT NULL,
	username   STRING NOT NULL,
	created_at INTEGER NOT NULL,

	UNIQUE (session_id),
	PRIMARY KEY(session_id),
	FOREIGN KEY(username) REFERENCES users(username)
);
`

type storage struct {
	db *sql.DB

	close func()
	// An optional user provided time function.
	now func() time.Time
}

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

func (s *storage) Close() error {
	s.close()
	return s.db.Close()
}

func (s *storage) gc() error {
	now := s.now
	if now == nil {
		now = time.Now
	}

	t := now().Add(-time.Hour).UnixMicro()
	if _, err := s.db.Exec(`
		DELETE FROM passkey_registrations
		WHERE created_at < ?`, t); err != nil {
		return fmt.Errorf("deleting old registrations: %v", err)
	}
	if _, err := s.db.Exec(`
		DELETE FROM passkey_logins
		WHERE created_at < ?`, t); err != nil {
		return fmt.Errorf("deleting old logins: %v", err)
	}

	st := now().Add(-time.Hour * 24).UnixMicro()
	if _, err := s.db.Exec(`
		DELETE FROM sessions
		WHERE created_at < ?`, st); err != nil {
		return fmt.Errorf("deleting old logins: %v", err)
	}
	return nil
}

type user struct {
	username string

	passkeys []*passkey
}

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
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO passkeys
			(username, name, passkey_id, public_key, algorithm,
			attestation_object, client_data_json)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, p.username, p.name, p.passkeyID, pub, int64(p.algorithm),
			p.attestationObject, p.clientDataJSON); err != nil {
			return fmt.Errorf("inserting passkey: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commiting transaction: %v", err)
	}
	return nil
}

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
		name, passkey_id, public_key, algorithm,
		attestation_object, client_data_json
		FROM passkeys
		WHERE username = ?`, username)
	if err != nil {
		return nil, false, fmt.Errorf("querying passkeys: %v", err)
	}
	for rows.Next() {
		p := &passkey{username: username}
		var (
			pubDER []byte
			alg    int64
		)
		if err := rows.Scan(&p.name, &p.passkeyID, &pubDER, &alg, &p.attestationObject, &p.clientDataJSON); err != nil {
			return nil, false, fmt.Errorf("scanning passkey row: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			return nil, false, fmt.Errorf("parsing public key: %v", err)
		}
		p.publicKey = pub
		p.algorithm = webauthn.Algorithm(alg)

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

type passkey struct {
	username  string
	name      string
	passkeyID []byte
	publicKey crypto.PublicKey
	algorithm webauthn.Algorithm

	attestationObject []byte
	clientDataJSON    []byte
}

type session struct {
	id        string
	username  string
	createdAt time.Time
}

func (s *storage) insertSession(ctx context.Context, ses *session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions
		(session_id, username, created_at)
		VALUES (?, ?, ?)`, ses.id, ses.username, ses.createdAt.UnixMicro())
	if err != nil {
		return fmt.Errorf("inserting session: %v", err)
	}
	return nil
}

func (s *storage) getSession(ctx context.Context, id string) (*session, bool, error) {
	ses := &session{id: id}
	var createdAt int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT username, created_at
		FROM sessions
		WHERE session_id = ?`, id).Scan(&ses.username, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("querying session table: %v", err)
	}
	ses.createdAt = time.UnixMicro(createdAt)
	return ses, true, nil
}

type passkeyLogin struct {
	id        string
	username  string
	challenge []byte
	createdAt time.Time
}

func (s *storage) insertPasskeyLogin(ctx context.Context, l *passkeyLogin) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO passkey_logins
		(login_id, username, challenge, created_at)
		VALUES
		(?, ?, ?, ?)`,
		l.id, l.username, l.challenge, l.createdAt.UnixMicro()); err != nil {
		return fmt.Errorf("inserting login row: %v", err)
	}
	return nil
}

func (s *storage) getPasskeyLogin(ctx context.Context, id string) (*passkeyLogin, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()

	l := &passkeyLogin{id: id}
	var createdAt int64
	if err := tx.QueryRowContext(ctx, `
		SELECT username, challenge, created_at
		FROM passkey_logins
		WHERE login_id = ?`, id).
		Scan(&l.username, &l.challenge, &createdAt); err != nil {
		return nil, fmt.Errorf("reading row: %v", err)
	}
	l.createdAt = time.UnixMicro(createdAt)

	result, err := tx.ExecContext(ctx, `DELETE FROM passkey_logins WHERE login_id = ?`, id)
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

type passkeyRegistration struct {
	id        string
	username  string
	userID    []byte
	challenge []byte
	createdAt time.Time
}

func (s *storage) insertPasskeyRegistration(ctx context.Context, p *passkeyRegistration) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO passkey_registrations
		(registration_id, username, user_id, challenge, created_at)
		VALUES
		(?, ?, ?, ?, ?)`,
		p.id, p.username, p.userID, p.challenge, p.createdAt.UnixMicro()); err != nil {
		return fmt.Errorf("insert record: %v", err)
	}
	return nil
}

func (s *storage) getPasskeyRegistration(ctx context.Context, id string) (*passkeyRegistration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %v", err)
	}
	defer tx.Rollback()

	p := &passkeyRegistration{id: id}
	var createdAt int64
	if err := tx.QueryRowContext(ctx, `
		SELECT username, user_id, challenge, created_at
		FROM passkey_registrations
		WHERE registration_id = ?`, id).
		Scan(&p.username, &p.userID, &p.challenge, &createdAt); err != nil {
		return nil, fmt.Errorf("reading row: %v", err)
	}
	p.createdAt = time.UnixMicro(createdAt)

	result, err := tx.ExecContext(ctx, `DELETE FROM passkey_registrations WHERE registration_id = ?`, id)
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
