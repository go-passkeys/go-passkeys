// The webauthn package implements relying party logic for WebAuthn.
//
// # Attestation
//
// Attestation allows the creation of new keys through the browser. To register
// a key, the server generates a challenge and user handle and passes those
// values to the browser. In turn, the browser calls
// [navigator.credentials.create()] with [PublicKeyCredentialCreationOptions]
// to initiate a credential.
//
// [navigator.credentials.create()]: https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
// [PublicKeyCredentialCreationOptions]: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
//
//	const cred = await navigator.credentials.create({
//		publicKey: {
//			challenge: challenge, // Provided by the server.
//			user: {
//				id: userHandle, // Can later be used during authentication to identify key.
//				// ...
//			},
//			// Other fields...
//		},
//	});
//
//	// Convert to base64 strings.
//	const attestationObject = btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject)));
//	const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)));
//
//	// POST values to the server.
//	const resp = await fetch("/registration-finish", {
//		method: "POST",
//		body: JSON.stringify({
//			attestationObject: attestationObject,
//			clientDataJSON: clientDataJSON,
//			transports: cred.response.getTransports(), // Used later for hints.
//	    }),
//	});
//
// The browser then passes parts of the response back to the server, which
// configures a [RelyingParty] and calls [RelyingParty.VerifyAttestation] to
// validate the credential was created for the correct origin.
//
//	func handleRegistration(w http.ResponseWriter, r *http.Request) {
//		var req struct {
//			AttestationObject []byte   `json:"attestationObject"`
//			ClientDataJSON    []byte   `json:"clientDataJSON"`
//			Transports        []string `json:"transports"`
//		}
//		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//			// ...
//		}
//
//		// Configure the relying party and validate the credential creation. The
//		// "challenge" value should be fetched separately, not provided by the
//		// client.
//		rp := &webauthn.RelyingParty{
//			ID:     "login.example.com",
//			Origin: "https://login.example.com",
//		}
//		a, err := rp.VerifyAttestation(challenge, req.ClientDataJSON, req.AuthenticatorData)
//		if err != nil {
//			// ...
//		}
//
//		// Pull out public key and algorithm for future authentication.
//		pub, err := x509.MarshalPKIXPublicKey(a.PublicKey)
//		if err != nil {
//			// ...
//		}
//		alg := a.Algorithm
//
//		// Stored later to fill in "allowedCredentials" for second-factor
//		// authentication.
//		credentialID := a.CredentialID
//		transports := req.Transports
//
//		// Determine authenticator name to display to user. For example: "iCloud Keychain".
//		authenticatorName, ok := a.AAGUID.Name()
//		if !ok {
//			// ...
//		}
//
//		// ...
//	}
//
// The parsed response contains information such as the public key, signing
// algorithm, credential ID, and authenticator that generated the credential.
//
// # Assertion
//
// Servers can request a credential sign a challenge to authenticate a user.
// The server generates random bytes, passes the values to the frontend, which
// in turn calls [navigator.credentials.get()] with
// [PublicKeyCredentialRequestOptions].
//
// [navigator.credentials.get()]: https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
// [PublicKeyCredentialRequestOptions]: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
//
//	// Trigger the user to authenticate with a passkey.
//	const cred = await navigator.credentials.get({
//		publicKey: {
//			// Challenge for the credential to sign.
//			challenge: challenge,
//			// Other fields...
//		},
//	});
//
//	// Convert result values to base64 to send over the wire.
//	const authenticatorData = btoa(String.fromCharCode(...new Uint8Array(cred.response.authenticatorData)));
//	const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)));
//	const signature = btoa(String.fromCharCode(...new Uint8Array(cred.response.signature)));
//	const userHandle = btoa(String.fromCharCode(...new Uint8Array(cred.response.userHandle)));
//
//	// POST data back to server.
//	const resp = await fetch("/login-finish", {
//	    method: "POST",
//	    body: JSON.stringify({
//			authenticatorData: authenticatorData,
//			clientDataJSON: clientDataJSON,
//			signature: signature,
//			userHandle: userHandle,
//	    }),
//	});
//
// The server then validates the values against its relying party configuration.
//
//	func handleLogin(w http.ResponseWriter, r *http.Request) {
//		var req struct {
//			AuthenticatorData []byte `json:"authenticatorData"`
//			ClientDataJSON    []byte `json:"clientDataJSON"`
//			Signature         []byte `json:"signature"`
//			UserHandle        []byte `json:"userHandle"` // Unique to each credential.
//		}
//		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//			// ...
//		}
//
//		// Public key, algorithm, and challenge are looked up separately.
//
//		rp := &webauthn.RelyingParty{
//			ID:     "login.example.com",
//			Origin: "https://login.example.com",
//		}
//		a, err := rp.VerifyAssertion(pub, alg, challenge, req.ClientDataJSON, req.AuthenticatorData, req.Signature)
//
//		// ...
//	}
package webauthn
