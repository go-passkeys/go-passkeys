package webauthn

import (
	"os"
	"testing"
)

func TestParseFIDOMetadata(t *testing.T) {
	data, err := os.ReadFile("testdata/blob.jwt")
	if err != nil {
		t.Fatalf("Reading blob: %v", err)
	}
	if _, err := ParseMetadata(data); err != nil {
		t.Fatalf("Parsing FIDO metadata: %v", err)
	}
}
