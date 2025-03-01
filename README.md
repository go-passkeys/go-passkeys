# Passkey support for Go

This repo implements passkey support for Go. Providing both an importable
package, as well as a full demo app as an end-to-end example of how to integrate
backend Go code with frontend Javascript.

The Go package is similar to other Go WebAuthn projects, but has no dependencies
and is scoped to server-side credential verification. It is not opinionated
about frontend options, storage layers, or serialization formats.

## Example app

This repo ships a full example app as a starting place for users. This app
implements key creation, login, and second factor challenges. It also displays
objects used in the protocol for debugging and generation of test cases.

Use `go run` to run the app locally:

```
go run github.com/go-passkeys/go-passkeys/example
```

Then browser to http://localhost:8080 to view an interact with the service.

## webauthn package

[![Go Reference](https://pkg.go.dev/badge/github.com/go-passkeys/go-passkeys/webauthn.svg)](https://pkg.go.dev/github.com/go-passkeys/go-passkeys/webauthn)

The webauthn package provides relying party validation of WebAuthn credentials.
Server's initialize a relying party value with a given ID and target origin that
the user will register credentials with.

```go
import (
    // ...

    "github.com/go-passkeys/go-passkeys/webauthn"
)

var relyingParty = &webauthn.RelyingParty{
    ID:     "localhost",
    Origin: "http://localhost:8080",
}
```

### Attestation

Servers register keys by issuing a challenge (a random array of bytes), and has
the browser prompt the user to register a passkey. The response object has a
number fields that are then sent back to the server.

https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#creating_a_key_pair_and_registering_a_user

```javascript
const cred = await navigator.credentials.create({
	publicKey: {
		challenge: challenge, // Provided by the server.
		// ...
	},
});

// Convert to base64 strings.
const attestationObject = btoa(String.fromCharCode(
    ...new Uint8Array(cred.response.attestationObject)));
const clientDataJSON = btoa(String.fromCharCode(
    ...new Uint8Array(cred.response.clientDataJSON)));

// POST values to the server.
const resp = await fetch("/registration-finish", {
	method: "POST",
	body: JSON.stringify({
		attestationObject: attestationObject,
		clientDataJSON: clientDataJSON,
		transports: cred.response.getTransports(), // Used later for hints.
    }),
});
```

The server receives those values, then uses its relying party config to
validate the credential used the correct challenge, and targets the correct
origin.

```go
func handleRegistration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AttestationObject []byte   `json:"attestationObject"`
		ClientDataJSON    []byte   `json:"clientDataJSON"`
		Transports        []string `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// ...
	}

	// Configure the relying party and validate the credential creation. The
	// "challenge" value should be fetched separately, not provided by the
	// client.
	att, err := relyingParty.VerifyAttestation(
        challenge, req.ClientDataJSON, req.AuthenticatorData)
	if err != nil {
		// ...
	}

	// Pull out public key and algorithm for future authentication.
	alg := att.Algorithm
	pub, err := x509.MarshalPKIXPublicKey(a.PublicKey)
	if err != nil {
		// ...
	}

	// Stored later to fill in "allowedCredentials" for second-factor
	// authentication.
	credentialID := att.CredentialID
	transports := req.Transports

	// Determine authenticator name to display to user. For example: "iCloud
    // Keychain".
	name, ok := att.AAGUID.Name()
	if !ok {
		// ...
	}

	// ...
}
```

The server then stores the public key for future authentication attempts.

### Assertion

When authenticating with a passkey, the server one again issues a challenge,
then waits for the browser to prompt a user to sign the value with a passkey.

https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#authenticating_a_user

```javascript
// Trigger the user to authenticate with a passkey.
const cred = await navigator.credentials.get({
	publicKey: {
		challenge: challenge, // Challenge for the credential to sign.
		// Other fields...
	},
});

// Convert result values to base64 to send over the wire.
const authenticatorData = btoa(String.fromCharCode(
    ...new Uint8Array(cred.response.authenticatorData)));
const clientDataJSON = btoa(String.fromCharCode(
    ...new Uint8Array(cred.response.clientDataJSON)));
const signature = btoa(String.fromCharCode(
    ...new Uint8Array(cred.response.signature)));
const userHandle = btoa(String.fromCharCode(
    ...new Uint8Array(cred.response.userHandle)));

// POST data back to server.
const resp = await fetch("/login-finish", {
    method: "POST",
    body: JSON.stringify({
		authenticatorData: authenticatorData,
		clientDataJSON: clientDataJSON,
		signature: signature,
		userHandle: userHandle,
    }),
});
```

The relying party can then validate the authentication attempt.

```go
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		ClientDataJSON    []byte `json:"clientDataJSON"`
		Signature         []byte `json:"signature"`
		UserHandle        []byte `json:"userHandle"` // Used to identify the public key.
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// ...
	}

	// Public key, algorithm, and challenge are looked up separately...

	a, err := relyingParty.VerifyAssertion(
        pub, alg, challenge,
        req.ClientDataJSON, req.AuthenticatorData, req.Signature)
    if err != nil {
        // ...
    }

	// ...
}
```
