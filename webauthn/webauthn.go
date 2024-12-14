package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ericchiang/go-webauthn/webauthn/internal/cbor"
)

var idFIDOGenCEAAGUIDOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
type Algorithm int

const (
	ES256 Algorithm = -7
	ES384 Algorithm = -35
	ES512 Algorithm = -36
	EdDSA Algorithm = -8
	RS256 Algorithm = -257
	RS384 Algorithm = -258
	RS512 Algorithm = -259
)

var algStrings = map[Algorithm]string{
	ES256: "ES256",
	ES384: "ES384",
	ES512: "ES512",
	EdDSA: "EdDSA",
	RS256: "RS256",
	RS384: "RS384",
	RS512: "RS512",
}

// Algorithm returns a human readable representation of the algorithm.
func (a Algorithm) String() string {
	if s, ok := algStrings[a]; ok {
		return s
	}
	return fmt.Sprintf("Algorithm(0x%x)", int(a))
}

const (
	FormatNone   = "none"
	FormatPacked = "packed"
)

type attestationObject struct {
	format string

	attestationStatement []byte
	authData             []byte
}

// AttestationFormat returns the format purported to be used by the attestation.
// This can be values such as "packed", "apple", "none", etc.
func AttestationFormat(attestationObject []byte) (string, error) {
	d := cbor.NewDecoder(attestationObject)
	var format string
	if !d.Map(func(kv *cbor.Decoder) bool {
		var key string
		if !kv.String(&key) {
			return false
		}
		switch key {
		case "fmt":
			return kv.String(&format)
		default:
			return kv.Skip()
		}
	}) || !d.Done() {
		return "", fmt.Errorf("invalid cbor data")
	}
	return format, nil
}

type RelyingParty struct {
	RPID string

	Origin string
}

func (rp *RelyingParty) VerifyAttestation(challenge, clientDataJSON, attestationObject []byte) (*AttestationData, error) {
	var clientData clientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return nil, fmt.Errorf("parsing client data: %v", err)
	}
	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("invalid client data type, expected 'webauthn.create', got '%s'", clientData.Type)
	}
	if clientData.Origin != rp.Origin {
		return nil, fmt.Errorf("invalid client data origin, expected '%s', got '%s'", rp.Origin, clientData.Origin)
	}
	if !clientData.Challenge.Equal(challenge) {
		return nil, fmt.Errorf("invalid client data challenge")
	}

	attObj, err := parseAttestationObject(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("parsing attestation object: %v", err)
	}

	data, err := attObj.AuthenticatorData()
	if err != nil {
		return nil, fmt.Errorf("parsing authenticator data: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte(rp.RPID))
	if data.RPIDHash != rpIDHash {
		return nil, fmt.Errorf("attestation was generated for a different relying party ID")
	}
	return data, nil
}

func (rp *RelyingParty) VerifyAuthentication(pub crypto.PublicKey, alg Algorithm, challenge, clientDataJSON, authData, sig []byte) (*AuthenticationData, error) {
	clientDataHash := sha256.Sum256(clientDataJSON)

	var clientData clientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return nil, fmt.Errorf("parsing client data: %v", err)
	}
	if clientData.Type != "webauthn.get" {
		return nil, fmt.Errorf("invalid client data type, expected 'webauthn.get', got '%s'", clientData.Type)
	}
	if clientData.Origin != rp.Origin {
		return nil, fmt.Errorf("invalid client data origin, expected '%s', got '%s'", rp.Origin, clientData.Origin)
	}
	if !clientData.Challenge.Equal(challenge) {
		return nil, fmt.Errorf("invalid client data challenge")
	}

	data := append([]byte{}, authData...)
	data = append(data, clientDataHash[:]...)
	if err := verifySignature(pub, alg, data, sig); err != nil {
		return nil, fmt.Errorf("invalid signature: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte(rp.RPID))
	if len(authData) < 32 {
		return nil, fmt.Errorf("not enough bytes for rpid hash")
	}
	if !bytes.Equal(rpIDHash[:], authData[:32]) {
		return nil, fmt.Errorf("assertion issued for different relying party")
	}
	if len(authData) < 32+1 {
		return nil, fmt.Errorf("not enough bytes for flag")
	}
	flags := Flags(authData[32])
	if len(authData) < 32+1+4 {
		return nil, fmt.Errorf("not enough bytes for counter")
	}

	counter := binary.BigEndian.Uint32(authData[32+1 : 32+1+4])
	return &AuthenticationData{
		Flags:   flags,
		Counter: counter,
	}, nil
}

// Format returns the sets of attestation formats.
//
// https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats
func (o *attestationObject) Format() string {
	return o.format
}

// AuthenticatorData performs no validation of the provided data, immediately
// returning the authenticator data. This is appropriate for relying parties
// that aren't attempting to perform attestation, as well as [FormatNone]
// attestation statements.
//
// https://www.w3.org/TR/webauthn-3/#sctn-none-attestation
func (o *attestationObject) AuthenticatorData() (*AttestationData, error) {
	return parseAuthData(o.authData)
}

// PackedOptions allows configuration for validating packed attestation
// statement.
//
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type PackedOptions struct {
	// Metadata allows use the FIDO Alliance Metadata Service for
	// verifying packed attestations using registered root certificates.
	//
	// https://fidoalliance.org/metadata/
	Metadata *Metadata
}

// Packed holds a parsed packed attestation format.
//
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type Packed struct {
	// Parsed and validated authenticator data.
	AuthenticatorData *AttestationData

	// If true, the data was self attested and signed with the key returned in
	// authenticator data, rather than an attestation certificate.
	//
	// https://www.w3.org/TR/webauthn-3/#self-attestation
	SelfAttested bool

	// AttestationCertificate is the per-device certificate that was used to
	// sign the attestation and chains up to a root certificate within the
	// configuration.
	//
	// https://www.w3.org/TR/webauthn-3/#attca
	AttestationCertificate *x509.Certificate
}

// VerifyPacked validates an attestation object and client JSON data against
// a packed signature.
//
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
func (o *attestationObject) VerifyPacked(clientDataJSON []byte, opts *PackedOptions) (*Packed, error) {
	if opts == nil {
		return nil, fmt.Errorf("options must be provided")
	}
	if opts.Metadata == nil {
		return nil, fmt.Errorf("metadata blob must be provided in options")
	}

	p, err := parsePacked(o.attestationStatement)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation statement: %v", err)
	}
	ad, err := parseAuthData(o.authData)
	if err != nil {
		return nil, fmt.Errorf("invalid auth data: %v", err)
	}

	// https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data
	clientDataHash := sha256.Sum256(clientDataJSON)
	data := append([]byte{}, o.authData...)
	data = append(data, clientDataHash[:]...)

	if len(p.x5c) == 0 {
		// "If self attestation is in use, the authenticator produces sig by
		// concatenating authenticatorData and clientDataHash, and signing the
		// result using the credential private key. It sets alg to the
		// algorithm of the credential private key and omits the other fields.""
		//
		// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
		if err := verifySignature(ad.PublicKey, ad.Algorithm, data, p.sig); err != nil {
			return nil, fmt.Errorf("verifying self-attested data: %v", err)
		}
		return &Packed{
			AuthenticatorData: ad,
			SelfAttested:      true,
		}, nil
	}

	var x5c []*x509.Certificate
	for _, rawCert := range p.x5c {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate: %v", err)
		}
		x5c = append(x5c, cert)
	}

	// "Verify that sig is a valid signature over the concatenation of
	// authenticatorData and clientDataHash using the attestation public key in
	// attestnCert with the algorithm specified in alg."

	attCert := x5c[0]

	pub := attCert.PublicKey
	if err := verifySignature(pub, Algorithm(p.alg), data, p.sig); err != nil {
		return nil, fmt.Errorf("verifying with attestation certificate: %v", err)
	}

	// "Verify that attestnCert meets the requirements in § 8.2.1 Packed
	// Attestation Statement Certificate Requirements."
	//
	// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements

	if attCert.Version != 3 {
		// Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
		return nil, fmt.Errorf("attestation certificate uses version %d, must be version 3", attCert.Version)
	}

	ou := attCert.Subject.OrganizationalUnit
	if len(ou) != 1 || ou[0] != "Authenticator Attestation" {
		return nil, fmt.Errorf("attestation certificate Subject-OU must be set to the string 'Authenticator Attestation': %s", ou)
	}
	if attCert.IsCA {
		return nil, fmt.Errorf("attestation certificate basic constraints CA value must be set to false")
	}

	var aaguidExt []byte
	for _, ext := range attCert.Extensions {
		if ext.Id.Equal(idFIDOGenCEAAGUIDOID) {
			aaguidExt = ext.Value
			break
		}
	}
	if len(aaguidExt) == 0 {
		return nil, fmt.Errorf("no id-fido-gen-ce-aaguid extension in attestation certifiate")
	}
	var aaguid []byte
	if _, err := asn1.Unmarshal(aaguidExt, &aaguid); err != nil {
		return nil, fmt.Errorf("failed to parse id-fido-gen-ce-aaguid extension in attestation certifiate: %v", err)
	}
	if len(aaguid) != 16 {
		return nil, fmt.Errorf("expected id-fido-gen-ce-aaguid extension to be a 16 byte value, got %d", len(aaguid))
	}

	var ent *MetadataEntry
	for _, entry := range opts.Metadata.Entries {
		if bytes.Equal(entry.AAGUID[:], aaguid) {
			ent = entry
			break
		}
	}
	if ent == nil {
		return nil, fmt.Errorf("no entry in metadata found with aaguid %x", aaguid)
	}

	v := x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}
	for _, certRaw := range ent.Metadata.AttestationRootCertificates {
		certBytes, err := base64.StdEncoding.DecodeString(certRaw)
		if err != nil {
			return nil, fmt.Errorf("decoding certificate for provider %s (%x): %v", ent.Metadata.Description, aaguid, err)
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate for provider %s (%x): %v", ent.Metadata.Description, aaguid, err)
		}
		v.Roots.AddCert(cert)
	}
	if len(x5c) > 1 {
		v.Intermediates = x509.NewCertPool()
		for _, cert := range x5c[1:] {
			v.Intermediates.AddCert(cert)
		}
	}
	if _, err := attCert.Verify(v); err != nil {
		return nil, fmt.Errorf("failed to verify attestation certificate for provider %s (%x): %v", ent.Metadata.Description, aaguid, err)
	}
	return &Packed{
		AuthenticatorData:      ad,
		AttestationCertificate: attCert,
	}, nil
}

func verifySignature(pub crypto.PublicKey, alg Algorithm, data, sig []byte) error {
	switch alg {
	case ES256:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for ES256 algorithm: %T", pub)
		}
		h := sha256.New()
		h.Write(data)
		if !ecdsa.VerifyASN1(ecdsaPub, h.Sum(nil), sig) {
			return fmt.Errorf("invalid ES256 signature")
		}
	case ES384:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for ES384 algorithm: %T", pub)
		}
		h := sha512.New384()
		h.Write(data)
		if !ecdsa.VerifyASN1(ecdsaPub, h.Sum(nil), sig) {
			return fmt.Errorf("invalid ES384 signature")
		}
	case ES512:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for ES512 algorithm: %T", pub)
		}
		h := sha512.New()
		h.Write(data)
		if !ecdsa.VerifyASN1(ecdsaPub, h.Sum(nil), sig) {
			return fmt.Errorf("invalid ES512 signature")
		}
	case EdDSA:
		ed25519Pub, ok := pub.(*ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for EdDSA algorithm: %T", pub)
		}
		if !ed25519.Verify(*ed25519Pub, data, sig) {
			return fmt.Errorf("invalid EdDSA signature")
		}
	case RS256:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for RSA256 algorithm: %T", pub)
		}
		h := sha256.New()
		h.Write(data)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h.Sum(nil), sig); err != nil {
			return fmt.Errorf("invalid RS256 signature: %v", err)
		}
	case RS384:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for RSA384 algorithm: %T", pub)
		}
		h := sha512.New384()
		h.Write(data)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, h.Sum(nil), sig); err != nil {
			return fmt.Errorf("invalid RS384 signature: %v", err)
		}
	case RS512:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for RSA512 algorithm: %T", pub)
		}
		h := sha512.New()
		h.Write(data)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, h.Sum(nil), sig); err != nil {
			return fmt.Errorf("invalid RS512 signature: %v", err)
		}
	default:
		return fmt.Errorf("unsupported signing algorithm: %d", alg)
	}
	return nil
}

// https://www.w3.org/TR/webauthn-3/#authdata-flags
type Flags byte

// String returns a binary representation of the flags.
func (f Flags) String() string {
	var vals []string
	if f.UserPresent() {
		vals = append(vals, "UP")
	}
	if (byte(f) & (1 << 1)) != 0 {
		vals = append(vals, "RFU1")
	}
	if f.UserVerified() {
		vals = append(vals, "UV")
	}
	if f.BackupEligible() {
		vals = append(vals, "BE")
	}
	if f.BackedUp() {
		vals = append(vals, "BS")
	}
	if (byte(f) & (1 << 5)) != 0 {
		vals = append(vals, "RFU2")
	}
	if f.AttestedCredentialData() {
		vals = append(vals, "AT")
	}
	if f.Extensions() {
		vals = append(vals, "ED")
	}
	if len(vals) == 0 {
		return "Flags()"
	}
	return fmt.Sprintf("Flags(%s)", strings.Join(vals, "|"))
}

// https://www.w3.org/TR/webauthn-3/#concept-user-present
func (f Flags) UserPresent() bool {
	return (byte(f) & 1) != 0
}

// https://www.w3.org/TR/webauthn-3/#concept-user-verified
func (f Flags) UserVerified() bool {
	return (byte(f) & (1 << 2)) != 0
}

// https://www.w3.org/TR/webauthn-3/#backup-eligible
func (f Flags) BackupEligible() bool {
	return (byte(f) & (1 << 3)) != 0
}

// https://www.w3.org/TR/webauthn-3/#backed-up
func (f Flags) BackedUp() bool {
	return (byte(f) & (1 << 4)) != 0
}

// https://www.w3.org/TR/webauthn-3/#attested-credential-data
func (f Flags) AttestedCredentialData() bool {
	return (byte(f) & (1 << 6)) != 0
}

// https://www.w3.org/TR/webauthn-3/#authdata-extensions
func (f Flags) Extensions() bool {
	return (byte(f) & (1 << 7)) != 0
}

type AuthenticationData struct {
	// Various bits of information about this key, such as if it is synced to a
	// Cloud service.
	//
	// https://www.w3.org/TR/webauthn-3/#authdata-flags
	Flags Flags
	// Counter is incremented value that is increased every time the key signs a
	// challenge. This may be zero for authenticators that don't support signing
	// counters.
	//
	// Signature counters are intended to be used to detect cloned credentials.
	//
	// https://www.w3.org/TR/webauthn-3/#sctn-sign-counter
	Counter uint32
}

// AttestationData holds information about an individual credential. This
// data can be verified through attestation statements during registration, but
// is generally assumed to have been correctly provided by the browser.
//
// https://www.w3.org/TR/webauthn-3/#authenticator-data
type AttestationData struct {
	// SHA-256 hash of the relying party ID. Whereas the "origin" is always the
	// full base URL seen by the browser during registration, with scheme and
	// optional port, the RP ID can be a domain or URL with some restrictions.
	//
	// The spec provides the following example:
	//
	// 	"...given a Relying Party whose origin is https://login.example.com:1337,
	//	then the following RP IDs are valid: login.example.com (default) and
	//	example.com, but not m.login.example.com and not com."
	//
	// https://www.w3.org/TR/webauthn-3/#rp-id
	RPIDHash [32]byte
	// Various bits of information about this key, such as if it is synced to a
	// Cloud service.
	//
	// https://www.w3.org/TR/webauthn-3/#authdata-flags
	Flags Flags
	// Counter is incremented value that is increased every time the key signs a
	// challenge. This may be zero for authenticators that don't support signing
	// counters.
	//
	// Signature counters are intended to be used to detect cloned credentials.
	//
	// https://www.w3.org/TR/webauthn-3/#sctn-sign-counter
	Counter uint32
	// The identifier for authenticator or credential service used to validate the
	// key.
	//
	// [AAGUIDName] can be used to translate this to a human readable string, such
	// as "iCloud Keychain" or "Google Password Manager".
	AAGUID AAGUID
	// Raw ID of the credential. This value can be used as hints to the browser
	// when authenticating a user, or during registration to avoid re-registering
	// the same key twice.
	//
	// https://www.w3.org/TR/webauthn-3/#credential-id
	CredentialID []byte
	// Algorithm used by the key to sign challenges.
	Algorithm Algorithm
	// Public key parse from the attestation statement.
	//
	// Callers can use [x509.MarshalPKIXPublicKey] and [x509.ParsePKIXPublicKey] to
	// serialize these keys.
	PublicKey crypto.PublicKey

	// Raw extension data.
	Extensions []byte
}

// https://developers.yubico.com/FIDO/yubico-metadata.json

// parseAttestationObject parses the result of a key creation event. This
// includes information such as the public key, key ID, RP ID hash, etc.
//
//	const cred = await navigator.credentials.create({
//		publicKey: {
//			// ...
//		},
//	});
//	console.log(cred.response.attestationObject);
//
// https://www.w3.org/TR/webauthn-3/#attestation-object
func parseAttestationObject(b []byte) (*attestationObject, error) {
	// TODO: compare hash of ID to relying party.

	d := cbor.NewDecoder(b)
	var (
		format   string
		authData []byte
		attest   []byte
	)
	if !d.Map(func(kv *cbor.Decoder) bool {
		var key string
		if !kv.String(&key) {
			return false
		}
		switch key {
		case "fmt":
			return kv.String(&format)
		case "attStmt":
			return kv.Raw(&attest)
		case "authData":
			return kv.Bytes(&authData)
		default:
			return kv.Skip()
		}
	}) || !d.Done() {
		return nil, fmt.Errorf("invalid cbor data")
	}
	if len(authData) == 0 {
		return nil, fmt.Errorf("no auth data")
	}
	return &attestationObject{
		format:               format,
		attestationStatement: attest,
		authData:             authData,
	}, nil
}

type packed struct {
	alg int64
	sig []byte
	x5c [][]byte
}

// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
func parsePacked(b []byte) (*packed, error) {
	d := cbor.NewDecoder(b)
	p := &packed{}
	ok := d.Map(func(kv *cbor.Decoder) bool {
		var key string
		if !kv.String(&key) {
			return false
		}
		switch key {
		case "alg":
			return kv.Int(&p.alg)
		case "sig":
			return kv.Bytes(&p.sig)
		case "x5c":
			return kv.Array(func(d *cbor.Decoder) bool {
				var cert []byte
				if !d.Bytes(&cert) {
					return false
				}
				p.x5c = append(p.x5c, cert)
				return true
			})
		default:
			return kv.Skip()
		}
	}) && d.Done()
	if !ok {
		return nil, fmt.Errorf("attestation statement was not valid cbor")
	}
	if p.alg == 0 {
		return nil, fmt.Errorf("attestation statement didn't specify an algorithm")
	}
	if len(p.sig) == 0 {
		return nil, fmt.Errorf("attestation statement didn't contain a signature")
	}
	return p, nil
}

func parseAuthData(b []byte) (*AttestationData, error) {
	var ad AttestationData
	if len(b) < 32 {
		return nil, fmt.Errorf("not enough bytes for rpid hash")
	}
	copy(ad.RPIDHash[:], b[:32])
	b = b[32:]
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes for flag")
	}
	ad.Flags = Flags(b[0])
	b = b[1:]
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes for counter")
	}

	ad.Counter = binary.BigEndian.Uint32(b[:4])
	b = b[4:]

	if len(b) < 16 {
		return nil, fmt.Errorf("not enough bytes for aaguid")
	}
	copy(ad.AAGUID[:], b[:16])
	b = b[16:]

	if len(b) < 2 {
		return nil, fmt.Errorf("not enough bytes for cred ID length")
	}
	credIDSize := binary.BigEndian.Uint16(b[:2])
	b = b[2:]

	size := int(credIDSize)
	if len(b) < size {
		return nil, fmt.Errorf("not enough bytes for cred ID")
	}
	ad.CredentialID = b[:size]
	b = b[size:]

	d := cbor.NewDecoder(b)
	pub, err := d.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	ad.Algorithm = Algorithm(pub.Algorithm)
	ad.PublicKey = pub.Public
	if !d.Done() {
		ad.Extensions = d.Rest()
	}
	return &ad, nil
}

// clientDataChallenge is a wrapper on top of a WebAuthn challenge.
//
// Note that the specification recommends that "Challenges SHOULD therefore be
// at least 16 bytes long."
//
// https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
type clientDataChallenge []byte

// Equal compares the challenge value against a set of bytes.
func (c clientDataChallenge) Equal(b []byte) bool {
	return subtle.ConstantTimeCompare([]byte(c), b) == 1
}

// UnmarshalJSON implements the challenge encoding used by clientDataJSON.
//
// https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson
func (c *clientDataChallenge) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("challenge value doesn't parse into string: %v", err)
	}
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*c = clientDataChallenge(data)
	return nil
}

// clientData holds information passed to the authenticator for both registration
// and authentication.
//
// https://www.w3.org/TR/webauthn-3/#dictionary-client-data
//
// JSON tags are added to provide unmarshalling from the clientDataJSON format.
//
// https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson
type clientData struct {
	Type        string              `json:"type"`
	Challenge   clientDataChallenge `json:"challenge"`
	Origin      string              `json:"origin"`
	TopOrigin   string              `json:"topOrigin"`
	CrossOrigin bool                `json:"crossOrigin"`
}
