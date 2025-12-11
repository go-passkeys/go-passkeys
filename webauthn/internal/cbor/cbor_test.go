package cbor

import (
	"encoding/hex"
	"reflect"
	"slices"
	"testing"
)

// https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da

func TestUint(t *testing.T) {
	testCases := []struct {
		enc  string
		want uint64
	}{
		{"00", 0},
		{"01", 1},
		{"0a", 10},
		{"17", 23},
		{"1818", 24},
		{"1819", 25},
		{"1864", 100},
		{"1903e8", 1000},
		{"1a000f4240", 1000000},
		{"1b000000e8d4a51000", 1000000000000},
		{"1bffffffffffffffff", 18446744073709551615},
		// {"c249010000000000000000", 18446744073709551616},
	}

	for _, tc := range testCases {
		data, err := hex.DecodeString(tc.enc)
		if err != nil {
			t.Errorf("Failed to decode value 0x%s: %v", tc.enc, err)
			continue
		}
		var got uint64
		dec := NewDecoder(data)
		if !dec.PositiveInteger(&got) {
			t.Errorf("Failed to decode uint from: 0x%s", tc.enc)
			continue
		}
		if got != tc.want {
			t.Errorf("Decoding 0x%s as uint returned unexpected value, got=%v, want=%v", tc.enc, got, tc.want)
		}
		if !dec.Done() {
			t.Errorf("Decoding 0x%s contained trailing data", tc.enc)
		}
	}
}

func TestNegativeInteger(t *testing.T) {
	testCases := []struct {
		enc  string
		want int64
	}{
		{"20", -1},
		{"29", -10},
		{"3863", -100},
		{"3903e7", -1000},
	}

	for _, tc := range testCases {
		data, err := hex.DecodeString(tc.enc)
		if err != nil {
			t.Errorf("Failed to decode value 0x%s: %v", tc.enc, err)
			continue
		}
		var got int64
		dec := NewDecoder(data)
		if !dec.NegativeInteger(&got) {
			t.Errorf("Failed to decode int from: 0x%s", tc.enc)
			continue
		}
		if got != tc.want {
			t.Errorf("Decoding 0x%s as int returned unexpected value, got=%v, want=%v", tc.enc, got, tc.want)
		}
		if !dec.Done() {
			t.Errorf("Decoding 0x%s contained trailing data", tc.enc)
		}
	}
}

func TestInt(t *testing.T) {
	testCases := []struct {
		enc  string
		want int64
	}{
		{"00", 0},
		{"01", 1},
		{"0a", 10},
		{"17", 23},
		{"1818", 24},
		{"1819", 25},
		{"1864", 100},
		{"1903e8", 1000},
		{"1a000f4240", 1000000},
		{"1b000000e8d4a51000", 1000000000000},
		{"20", -1},
		{"29", -10},
		{"3863", -100},
		{"3903e7", -1000},
	}

	for _, tc := range testCases {
		data, err := hex.DecodeString(tc.enc)
		if err != nil {
			t.Errorf("Failed to decode value 0x%s: %v", tc.enc, err)
			continue
		}
		var got int64
		dec := NewDecoder(data)
		if !dec.Int(&got) {
			t.Errorf("Failed to decode int from: 0x%s", tc.enc)
			continue
		}
		if got != tc.want {
			t.Errorf("Decoding 0x%s as int returned unexpected value, got=%v, want=%v", tc.enc, got, tc.want)
		}
		if !dec.Done() {
			t.Errorf("Decoding 0x%s contained trailing data", tc.enc)
		}
	}
}

func TestEmptyArray(t *testing.T) {
	d := NewDecoder([]byte{0x80})
	if !d.Array(func(val *Decoder) bool {
		// Array is empty, this should never be called.
		return false
	}) || !d.Done() {
		t.Errorf("Failed to parse empty array")
	}
}

func TestIntegerArray(t *testing.T) {
	d := NewDecoder([]byte{0x83, 0x01, 0x02, 0x03})
	var got []uint64
	if !d.Array(func(val *Decoder) bool {
		var n uint64
		ok := val.PositiveInteger(&n)
		got = append(got, n)
		return ok
	}) || !d.Done() {
		t.Errorf("Failed to parse integer array")
	}

	want := []uint64{1, 2, 3}
	if !slices.Equal(want, got) {
		t.Errorf("Parsing integer array failed, got=%v, want=%v", got, want)
	}
}

func TestParseNestedArray(t *testing.T) {
	// [1, [2, 3], [4, 5]]
	d := NewDecoder([]byte{0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05})
	var got []any
	i := 0
	if !d.Array(func(val *Decoder) bool {
		var ok bool
		if i == 0 {
			var n uint64
			ok = val.PositiveInteger(&n)
			got = append(got, n)
		} else {
			var subArray []any
			ok = val.Array(func(val *Decoder) bool {
				var n uint64
				ok := val.PositiveInteger(&n)
				subArray = append(subArray, n)
				return ok
			})
			got = append(got, subArray)
		}
		i++
		return ok
	}) || !d.Done() {
		t.Errorf("Failed to parse nested array")
	}

	want := []any{
		uint64(1),
		[]any{uint64(2), uint64(3)},
		[]any{uint64(4), uint64(5)},
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Parsing integer array failed, got=%v, want=%v", got, want)
	}
}

func TestBool(t *testing.T) {
	var gotTrue, gotFalse bool
	dataFalse := []byte{0xf4}
	dataTrue := []byte{0xf5}

	dt := NewDecoder(dataTrue)
	if !dt.Bool(&gotTrue) || !dt.Done() {
		t.Errorf("Failed to parse 'true' value")
	}
	if gotTrue != true {
		t.Errorf("Parsing 'true' value returned 'false'")
	}

	df := NewDecoder(dataFalse)
	if !df.Bool(&gotFalse) || !df.Done() {
		t.Errorf("Failed to parse 'false' value")
	}
	if gotFalse != false {
		t.Errorf("Parsing 'false' value returned 'true'")
	}
}

func TestMap(t *testing.T) {
	type val struct {
		a uint64
		b []uint64
	}
	var got val
	// {"a": 1, "b": [2, 3]}
	d := NewDecoder([]byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03})
	if !d.Map(func(kv *Decoder) bool {
		var key string
		if !kv.String(&key) {
			return false
		}

		switch key {
		case "a":
			return kv.PositiveInteger(&got.a)
		case "b":
			return kv.Array(func(val *Decoder) bool {
				var n uint64
				ok := val.PositiveInteger(&n)
				got.b = append(got.b, n)
				return ok
			})
		default:
			return kv.Skip()
		}
	}) || !d.Done() {
		t.Errorf("Failed to parse map")
	}

	want := val{
		a: 1,
		b: []uint64{2, 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parsing map returned unexpected value, got=%#v, want=%#v", got, want)
	}
}

func TestSkip(t *testing.T) {
	testCase := []struct {
		enc string
	}{
		{"a26161016162820203"}, // {"a": 1, "b": [2, 3]}
		{"826161a161626163"},   // ["a", {"b": "c"}]
	}
	for _, tc := range testCase {
		val, err := hex.DecodeString(tc.enc)
		if err != nil {
			t.Errorf("Parsing test case %s: %v", tc.enc, err)
			continue
		}
		d := NewDecoder(val)
		if !d.Skip() || !d.Done() {
			t.Errorf("Failed to skip test case: %s", tc.enc)
		}
	}
}

func TestSkipTruncatedByteString(t *testing.T) {
	d := NewDecoder([]byte{0x42, 0x00})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Skip panicked on truncated byte string: %v", r)
		}
	}()
	if d.Skip() {
		t.Fatalf("Skip succeeded on truncated byte string")
	}
}

func TestBytesLengthOverflow(t *testing.T) {
	d := NewDecoder([]byte{0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0, 0})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Bytes panicked on oversized length: %v", r)
		}
	}()
	var b []byte
	if d.Bytes(&b) {
		t.Fatalf("Bytes unexpectedly succeeded on oversized length")
	}
}

func TestStringLengthOverflow(t *testing.T) {
	d := NewDecoder([]byte{0x7b, 0x80, 0, 0, 0, 0, 0, 0, 0, 0})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("String panicked on oversized length: %v", r)
		}
	}()
	var s string
	if d.String(&s) {
		t.Fatalf("String unexpectedly succeeded on oversized length")
	}
}
