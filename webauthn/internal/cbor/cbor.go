// The cbor package implements CTAP2 CBOR parsing.
//
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
package cbor

import (
	"encoding/binary"
)

type Decoder struct {
	pos  int
	buff []byte
}

func (d *Decoder) Rest() []byte {
	return d.buff[d.pos:]
}

func (d *Decoder) len() int {
	return len(d.buff) - d.pos
}

func (d *Decoder) byte() byte {
	b := d.buff[d.pos]
	d.pos++
	return b
}

func (d *Decoder) bytes(n int) []byte {
	b := d.buff[d.pos : d.pos+n]
	d.pos += n
	return b
}

const (
	TypeUnsignedInteger = 0
	TypeNegativeInteger = 1
	TypeByteString      = 2
	TypeTextString      = 3
	TypeArray           = 4
	TypeMap             = 5
	TypeTag             = 6
	TypeFloatOrSimple   = 7
)

// NewDecoder creates a reader for the provided CBOR object.
func NewDecoder(b []byte) *Decoder {
	return &Decoder{buff: b}
}

func (d *Decoder) Done() bool {
	return d.len() == 0
}

func (d *Decoder) Bytes(b *[]byte) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeByteString {
		return false
	}
	if d.len() < int(arg) {
		return false
	}
	*b = append([]byte{}, d.bytes(int(arg))...)
	return true
}

func (d *Decoder) String(s *string) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeTextString {
		return false
	}
	if d.len() < int(arg) {
		return false
	}
	*s = string(d.bytes(int(arg)))
	return true
}

func (d *Decoder) Int(n *int64) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	switch typ {
	case TypeUnsignedInteger:
		*n = int64(arg)
	case TypeNegativeInteger:
		*n = -1 - int64(arg)
	default:
		return false
	}
	return true
}

func (d *Decoder) PositiveInteger(n *uint64) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeUnsignedInteger {
		return false
	}
	*n = arg
	return true
}

func (d *Decoder) Bool(b *bool) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeFloatOrSimple {
		return false
	}
	switch arg {
	case 20:
		*b = false
	case 21:
		*b = true
	default:
		return false
	}
	return true
}

func (d *Decoder) NegativeInteger(n *int64) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeNegativeInteger {
		return false
	}
	*n = -1 - int64(arg)
	return true
}

// Raw returns the next value, unencoded.
func (d *Decoder) Raw(raw *[]byte) bool {
	start := d.pos
	if !d.Skip() {
		return false
	}
	end := d.pos
	*raw = append([]byte{}, d.buff[start:end]...)
	return true
}

// Skip consumes the next object.
func (d *Decoder) Skip() bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	switch typ {
	case TypeNegativeInteger, TypeUnsignedInteger:
		// Numbers have no content, they're expressed through their
		// argument.
	case TypeByteString, TypeTextString:
		// For strings, consume the length of the value.
		if arg > uint64(d.len()) {
			return false
		}
		d.bytes(int(arg))
	case TypeArray:
		var i uint64
		for ; i < arg; i++ {
			if !d.Skip() {
				return false
			}
		}
	case TypeMap:
		var i uint64
		for ; i < arg; i++ {
			if !d.Skip() || !d.Skip() {
				return false
			}
		}
	case TypeFloatOrSimple:
		if arg == 20 || arg == 21 {
			// Support bool values.
			return true
		}
		return false
	default:
		return false
	}
	return true
}

// Map iterates over a map, providing the value. It's the callers responsibility
// to either parse the value or skip it.
//
//	d := cbor.NewDecoder(buff)
//	var format string
//	ok := d.Map(func(kv *cbor.Decoder) bool {
//		var key string
//		if !kv.String(&key) {
//			return false
//		}
//		switch key {
//		case "fmt":
//			return kv.String(&format)
//		default:
//			return kv.Skip()
//		}
//	})
func (d *Decoder) Map(fn func(keyval *Decoder) bool) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeMap {
		return false
	}
	var i uint64
	for ; i < arg; i++ {
		if !fn(d) {
			return false
		}
	}
	return true
}

func (d *Decoder) Peek() byte {
	if d.len() == 0 {
		return 0xff
	}
	return d.buff[d.pos] >> 5
}

func (d *Decoder) Array(fn func(val *Decoder) bool) bool {
	typ, arg, ok := d.typAndArg()
	if !ok {
		return false
	}
	if typ != TypeArray {
		return false
	}
	var i uint64
	for ; i < arg; i++ {
		if !fn(d) {
			return false
		}
	}
	return true
}

func (d *Decoder) typAndArg() (byte, uint64, bool) {
	if d.len() < 1 {
		return 0, 0, false
	}

	// Decode type and initial argument value.
	b := d.byte()
	typ := b >> 5
	val := b & 0x1f

	// https://www.rfc-editor.org/rfc/rfc8949.html#section-3-2
	if val < 24 {
		return typ, uint64(val), true
	}

	// Value indicates that
	switch val {
	case 24:
		if d.len() < 1 {
			return 0, 0, false
		}
		n := uint64(d.byte())
		return typ, n, true
	case 25:
		if d.len() < 2 {
			return 0, 0, false
		}
		n := uint64(binary.BigEndian.Uint16(d.bytes(2)))
		return typ, n, true
	case 26:
		if d.len() < 4 {
			return 0, 0, false
		}
		n := uint64(binary.BigEndian.Uint32(d.bytes(4)))
		return typ, n, true
	case 27:
		if d.len() < 8 {
			return 0, 0, false
		}
		n := binary.BigEndian.Uint64(d.bytes(8))
		return typ, n, true
	default:
		// We explicitly ignore indefinite length types (value 31), since
		// these aren't supported by WebAuthn.
		return 0, 0, false
	}
}
