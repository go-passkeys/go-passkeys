// Package packed provides mechanisms for validating "packed" attestation statements.
package packed

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/go-passkeys/go-passkeys/webauthn"
	"github.com/go-passkeys/go-passkeys/webauthn/internal/cbor"
)

// VerifyOptions allows configuration for validating packed attestation
// statement.
//
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type VerifyOptions struct {
	// When set, allow packed verifications that are self-attested.
	//
	// https://www.w3.org/TR/webauthn-3/#self-attestation
	AllowSelfAttested bool

	// GetRoots returns the root certificates for a given AAGUID. For example, by
	// parsing the FIDO Alliance Metadata Service.
	//
	// https://fidoalliance.org/metadata/
	GetRoots func(aaguid webauthn.AAGUID) (*x509.CertPool, error)
}

// Attestation holds a parsed packed attestation format.
//
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type Attestation struct {
	// Parsed and validated authenticator data.
	AuthenticatorData *webauthn.AuthenticatorData

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

var idFIDOGenCEAAGUIDOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// VerifyPacked validates an attestation object and client JSON data against
// a packed signature.
//
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
func Verify(o *webauthn.AttestationObject, rpid string, clientDataJSON []byte, opts *VerifyOptions) (*Attestation, error) {
	if opts == nil {
		return nil, fmt.Errorf("options must be provided")
	}
	if !opts.AllowSelfAttested && opts.GetRoots == nil {
		return nil, fmt.Errorf("self attested not allowed and no root certificates provided")
	}

	p, err := parsePacked(o.AttestationStatement)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation statement: %v", err)
	}
	ad, err := webauthn.ParseAuthenticatorData(rpid, o.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("invalid auth data: %v", err)
	}

	// https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data
	clientDataHash := sha256.Sum256(clientDataJSON)
	data := append([]byte{}, o.AuthenticatorData...)
	data = append(data, clientDataHash[:]...)

	if len(p.x5c) == 0 {
		if !opts.AllowSelfAttested {
			return nil, fmt.Errorf("attestation statement is self attested, which is not permitted by packed validation config")
		}

		// "If self attestation is in use, the authenticator produces sig by
		// concatenating authenticatorData and clientDataHash, and signing the
		// result using the credential private key. It sets alg to the
		// algorithm of the credential private key and omits the other fields.""
		//
		// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
		if err := webauthn.VerifySignature(ad.PublicKey, ad.Algorithm, data, p.sig); err != nil {
			return nil, fmt.Errorf("verifying self-attested data: %v", err)
		}
		return &Attestation{
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
	if err := webauthn.VerifySignature(pub, webauthn.Algorithm(p.alg), data, p.sig); err != nil {
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
	var aaguidRaw []byte
	if _, err := asn1.Unmarshal(aaguidExt, &aaguidRaw); err != nil {
		return nil, fmt.Errorf("failed to parse id-fido-gen-ce-aaguid extension in attestation certifiate: %v", err)
	}
	if len(aaguidRaw) != 16 {
		return nil, fmt.Errorf("expected id-fido-gen-ce-aaguid extension to be a 16 byte value, got %d", len(aaguidRaw))
	}
	var aaguid webauthn.AAGUID
	copy(aaguid[:], aaguidRaw[:])

	if aaguid != ad.AAGUID {
		return nil, fmt.Errorf("authenticator data aaguid (%s) doesn't match packed certificate aaguid (%s)", ad.AAGUID, aaguid)
	}

	roots, err := opts.GetRoots(aaguid)
	if err != nil {
		return nil, err
	}

	v := x509.VerifyOptions{
		Roots: roots,
	}
	if len(x5c) > 1 {
		v.Intermediates = x509.NewCertPool()
		for _, cert := range x5c[1:] {
			v.Intermediates.AddCert(cert)
		}
	}
	if _, err := attCert.Verify(v); err != nil {
		return nil, fmt.Errorf("failed to verify attestation certificate for provider %s: %v", aaguid, err)
	}
	return &Attestation{
		AuthenticatorData:      ad,
		AttestationCertificate: attCert,
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
