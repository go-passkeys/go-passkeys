package webauthn

import (
	"encoding/json"
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

func TestParseAAGUID(t *testing.T) {
	testCases := []struct {
		aaguid  string
		want    [16]byte
		wantErr bool
	}{
		{
			"7a98c250-6808-11cf-b73b-00aa00b677a7",
			[16]byte{
				122, 152, 194, 80, 104, 8, 17, 207, 183, 59, 0, 170, 0, 182, 119, 167,
			},
			false,
		},
	}
	for _, tc := range testCases {
		var got struct {
			AAGUID mdsAAGUID `json:"aaguid"`
		}
		if err := json.Unmarshal([]byte(`{"aaguid":"`+tc.aaguid+`"}`), &got); err != nil {
			if !tc.wantErr {
				t.Errorf("Parsing %s: %v", tc.aaguid, err)
			}
			continue
		}
		if tc.wantErr {
			t.Errorf("Expected error parsing: %s", tc.aaguid)
			continue
		}
		if got.AAGUID != tc.want {
			t.Errorf("Parsing %s returned unexpected result, got=%v, want=%v", tc.aaguid, got.AAGUID, tc.want)
		}
	}
}
