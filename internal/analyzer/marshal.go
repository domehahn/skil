package analyzer

import "encoding/binary"

// This file implements a bounded, read-only decoder for CPython's `marshal`
// serialization format, used only to reach into a .pyc file's compiled code
// object and extract co_names (identifiers referenced by LOAD_GLOBAL/
// LOAD_METHOD/LOAD_ATTR/IMPORT_NAME) and any nested code objects reachable
// through co_consts, without ever executing, importing, or constructing a
// live Python value. It mirrors pickle.go's own stance: this disassembles a
// serialization format, it does not run it.
//
// marshal's wire format has stayed structurally stable and self-describing
// since Python 3.4 (each object's type byte, optionally OR'd with
// FLAG_REF/0x80 to mark it for a later back-reference, is immediately
// followed by exactly the bytes that type needs — nothing here depends on
// guessing a length). What *does* change across CPython releases is the
// fixed positional field sequence of a code object's own marshalled form
// (Python/marshal.c's w_object/r_object for TYPE_CODE), so decoding a code
// object requires knowing which field-layout family the .pyc's declared
// Python version belongs to. Any version whose layout isn't in
// pycFieldLayoutFor below (including every version with an "unknown (magic
// 0x...)" label) fails closed rather than guessing at a field count that
// could desync the whole read partway through.

const (
	marshalFlagRef = 0x80

	marshalTypeNull             = 0x30 // '0'
	marshalTypeNone             = 'N'
	marshalTypeFalse            = 'F'
	marshalTypeTrue             = 'T'
	marshalTypeStopIter         = 'S'
	marshalTypeEllipsis         = '.'
	marshalTypeInt              = 'i'
	marshalTypeInt64            = 'I'
	marshalTypeFloat            = 'f'
	marshalTypeBinaryFloat      = 'g'
	marshalTypeComplex          = 'x'
	marshalTypeBinaryComplex    = 'y'
	marshalTypeLong             = 'l'
	marshalTypeString           = 's'
	marshalTypeInterned         = 't'
	marshalTypeASCII            = 'a'
	marshalTypeASCIIInterned    = 'A'
	marshalTypeShortASCII       = 'z'
	marshalTypeShortASCIIIntern = 'Z'
	marshalTypeUnicode          = 'u'
	marshalTypeSmallTuple       = ')'
	marshalTypeTuple            = '('
	marshalTypeList             = '['
	marshalTypeDict             = '{'
	marshalTypeSet              = '<'
	marshalTypeFrozenSet        = '>'
	marshalTypeCode             = 'c'
	marshalTypeRef              = 'r'
)

// marshalNull is the decoded value of a TYPE_NULL object, distinct from Go
// nil (which represents Python None) so a TYPE_DICT's NULL-terminated
// key/value loop can be told apart from a legitimate {None: ...} entry.
var marshalNull = &struct{}{}

const (
	maxMarshalObjects = 500_000 // bound: never walk unboundedly on adversarial input
	maxMarshalDepth   = 200
)

// pycFieldLayout identifies which positional field sequence a TYPE_CODE
// object uses, keyed off the .pyc's declared Python version family.
type pycFieldLayout int

const (
	pycLayoutUnknown pycFieldLayout = iota
	pycLayout37                     // 3.7: no posonlyargcount
	pycLayout38to310                // 3.8-3.10: adds posonlyargcount, still has nlocals/lnotab
	pycLayout311plus                // 3.11+: no nlocals, adds qualname/exceptiontable, linetable
)

func pycFieldLayoutFor(pythonVersion string) pycFieldLayout {
	switch pythonVersion {
	case "3.7":
		return pycLayout37
	case "3.8", "3.9", "3.10":
		return pycLayout38to310
	case "3.11", "3.12", "3.13":
		return pycLayout311plus
	default:
		return pycLayoutUnknown
	}
}

// pycCodeObject holds only the two fields this scanner needs from a
// marshalled code object: its own referenced identifiers, and its
// constants (which may recursively contain nested code objects for
// closures/comprehensions/nested functions).
type pycCodeObject struct {
	names  []string
	consts []interface{}
}

type marshalReader struct {
	data         []byte
	pos          int
	refs         []interface{}
	layout       pycFieldLayout
	objectBudget int
}

func (r *marshalReader) readByte() (byte, bool) {
	if r.pos >= len(r.data) {
		return 0, false
	}
	b := r.data[r.pos]
	r.pos++
	return b, true
}

func (r *marshalReader) readN(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, false
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, true
}

func (r *marshalReader) readInt32() (int32, bool) {
	b, ok := r.readN(4)
	if !ok {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(b)), true
}

// readObject decodes exactly one marshalled object, consuming exactly the
// bytes that object's type requires. depth bounds recursion (nested
// tuples/code objects); the reader's shared objectBudget bounds the total
// number of objects decoded across the whole call, so a deeply-nested or
// very wide adversarial stream cannot force unbounded work.
func (r *marshalReader) readObject(depth int) (interface{}, bool) {
	if depth > maxMarshalDepth {
		return nil, false
	}
	r.objectBudget--
	if r.objectBudget < 0 {
		return nil, false
	}
	typeByte, ok := r.readByte()
	if !ok {
		return nil, false
	}
	flagged := typeByte&marshalFlagRef != 0
	base := typeByte &^ marshalFlagRef

	var refSlot int = -1
	if flagged {
		refSlot = len(r.refs)
		r.refs = append(r.refs, nil) // reserved; filled in once decoded below
	}

	value, ok := r.readObjectBody(base, depth)
	if !ok {
		return nil, false
	}
	if flagged {
		r.refs[refSlot] = value
	}
	return value, true
}

func (r *marshalReader) readObjectBody(base byte, depth int) (interface{}, bool) {
	switch base {
	case marshalTypeNull:
		return marshalNull, true
	case marshalTypeNone, marshalTypeFalse, marshalTypeTrue, marshalTypeStopIter, marshalTypeEllipsis:
		return nil, true
	case marshalTypeInt:
		_, ok := r.readN(4)
		return nil, ok
	case marshalTypeInt64:
		_, ok := r.readN(8)
		return nil, ok
	case marshalTypeFloat:
		n, ok := r.readByte()
		if !ok {
			return nil, false
		}
		_, ok = r.readN(int(n))
		return nil, ok
	case marshalTypeBinaryFloat:
		_, ok := r.readN(8)
		return nil, ok
	case marshalTypeComplex:
		n1, ok := r.readByte()
		if !ok {
			return nil, false
		}
		if _, ok := r.readN(int(n1)); !ok {
			return nil, false
		}
		n2, ok := r.readByte()
		if !ok {
			return nil, false
		}
		_, ok = r.readN(int(n2))
		return nil, ok
	case marshalTypeBinaryComplex:
		_, ok := r.readN(16)
		return nil, ok
	case marshalTypeLong:
		n, ok := r.readInt32()
		if !ok {
			return nil, false
		}
		count := int(n)
		if count < 0 {
			count = -count
		}
		_, ok = r.readN(count * 2)
		return nil, ok
	case marshalTypeString:
		// TYPE_STRING carries a raw bytes payload (co_code's compiled
		// bytecode is the common, often large, case) rather than an
		// identifier — this scanner never needs its content, only to stay
		// correctly positioned past it, so it's read and discarded without
		// the allocation+copy string(b) would cost on a large payload.
		n, ok := r.readInt32()
		if !ok || n < 0 {
			return nil, false
		}
		if _, ok := r.readN(int(n)); !ok {
			return nil, false
		}
		return nil, true
	case marshalTypeInterned, marshalTypeUnicode, marshalTypeASCII, marshalTypeASCIIInterned:
		n, ok := r.readInt32()
		if !ok || n < 0 {
			return nil, false
		}
		b, ok := r.readN(int(n))
		if !ok {
			return nil, false
		}
		return string(b), true
	case marshalTypeShortASCII, marshalTypeShortASCIIIntern:
		n, ok := r.readByte()
		if !ok {
			return nil, false
		}
		b, ok := r.readN(int(n))
		if !ok {
			return nil, false
		}
		return string(b), true
	case marshalTypeSmallTuple:
		n, ok := r.readByte()
		if !ok {
			return nil, false
		}
		return r.readItems(int(n), depth)
	case marshalTypeTuple, marshalTypeList:
		n, ok := r.readInt32()
		if !ok || n < 0 {
			return nil, false
		}
		return r.readItems(int(n), depth)
	case marshalTypeSet, marshalTypeFrozenSet:
		n, ok := r.readInt32()
		if !ok || n < 0 {
			return nil, false
		}
		if _, ok := r.readItems(int(n), depth); !ok {
			return nil, false
		}
		return nil, true
	case marshalTypeDict:
		for {
			key, ok := r.readObject(depth + 1)
			if !ok {
				return nil, false
			}
			if key == marshalNull {
				break
			}
			if _, ok := r.readObject(depth + 1); !ok {
				return nil, false
			}
		}
		return nil, true
	case marshalTypeCode:
		return r.readCodeObject(depth)
	case marshalTypeRef:
		idx, ok := r.readInt32()
		if !ok || idx < 0 || int(idx) >= len(r.refs) {
			return nil, false
		}
		return r.refs[idx], true
	default:
		// Unrecognized type byte: stop rather than guess at how many bytes
		// it consumes, which could desync every subsequent read.
		return nil, false
	}
}

func (r *marshalReader) readItems(n, depth int) ([]interface{}, bool) {
	items := make([]interface{}, 0, minInt(n, 1024))
	for i := 0; i < n; i++ {
		v, ok := r.readObject(depth + 1)
		if !ok {
			return nil, false
		}
		items = append(items, v)
	}
	return items, true
}

// readCodeObject decodes a TYPE_CODE object's fixed field sequence for the
// reader's configured layout, keeping only the consts and names fields;
// every other field is decoded (to stay correctly positioned in the
// stream) and discarded.
//
// CPython's marshal.c writes a code object's scalar integer fields
// (argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags,
// firstlineno) as bare 4-byte little-endian longs via w_long — with no
// marshal type byte at all — while every other field goes through the
// ordinary typed w_object path. Reading the scalar fields as full objects
// (as if they had a type byte like everything else) desyncs the entire
// rest of the stream after the first field; skipRawLong below matches
// w_long/r_long exactly.
func (r *marshalReader) readCodeObject(depth int) (*pycCodeObject, bool) {
	if r.layout == pycLayoutUnknown {
		return nil, false
	}
	skip := func() bool {
		_, ok := r.readObject(depth + 1)
		return ok
	}
	skipRawLong := func() bool {
		_, ok := r.readInt32()
		return ok
	}
	if !skipRawLong() { // argcount
		return nil, false
	}
	if r.layout != pycLayout37 {
		if !skipRawLong() { // posonlyargcount
			return nil, false
		}
	}
	if !skipRawLong() { // kwonlyargcount
		return nil, false
	}
	if r.layout != pycLayout311plus {
		if !skipRawLong() { // nlocals
			return nil, false
		}
	}
	if !skipRawLong() { // stacksize
		return nil, false
	}
	if !skipRawLong() { // flags
		return nil, false
	}
	if !skip() { // code (raw bytecode bytes)
		return nil, false
	}
	constsObj, ok := r.readObject(depth + 1)
	if !ok {
		return nil, false
	}
	namesObj, ok := r.readObject(depth + 1)
	if !ok {
		return nil, false
	}
	if r.layout == pycLayout311plus {
		if !skip() { // co_localsplusnames
			return nil, false
		}
		if !skip() { // co_localspluskinds
			return nil, false
		}
	} else {
		if !skip() { // varnames
			return nil, false
		}
		if !skip() { // freevars
			return nil, false
		}
		if !skip() { // cellvars
			return nil, false
		}
	}
	if !skip() { // filename
		return nil, false
	}
	if !skip() { // name
		return nil, false
	}
	if r.layout == pycLayout311plus {
		if !skip() { // qualname
			return nil, false
		}
	}
	if !skipRawLong() { // firstlineno
		return nil, false
	}
	if !skip() { // lnotab / linetable
		return nil, false
	}
	if r.layout == pycLayout311plus {
		if !skip() { // exceptiontable
			return nil, false
		}
	}
	items, ok := constsObj.([]interface{})
	if !ok {
		return nil, false
	}
	nameItems, ok := namesObj.([]interface{})
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(nameItems))
	for _, n := range nameItems {
		if s, ok := n.(string); ok {
			names = append(names, s)
		}
	}
	return &pycCodeObject{names: names, consts: items}, true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractPycNames decodes body (a .pyc file's bytes with the 16-byte PEP
// 552 header already stripped) as a marshalled code object for the given
// declared Python version, and returns the union of every identifier in
// co_names across it and every code object nested in its co_consts
// (closures, comprehensions, nested/decorated functions). ok is false for
// any Python version this decoder doesn't have a known field layout for,
// or for any marshal stream that doesn't parse as a well-formed code
// object under that layout — never a partial or best-guess result.
func extractPycNames(body []byte, pythonVersion string) (map[string]bool, bool) {
	layout := pycFieldLayoutFor(pythonVersion)
	if layout == pycLayoutUnknown {
		return nil, false
	}
	r := &marshalReader{data: body, layout: layout, objectBudget: maxMarshalObjects}
	obj, ok := r.readObject(0)
	if !ok {
		return nil, false
	}
	root, ok := obj.(*pycCodeObject)
	if !ok {
		return nil, false
	}
	names := map[string]bool{}
	seen := map[*pycCodeObject]bool{}
	var walk func(c *pycCodeObject, depth int)
	walk = func(c *pycCodeObject, depth int) {
		if c == nil || seen[c] || depth > maxMarshalDepth {
			return
		}
		seen[c] = true
		for _, n := range c.names {
			names[n] = true
		}
		for _, cst := range c.consts {
			if nested, ok := cst.(*pycCodeObject); ok {
				walk(nested, depth+1)
			}
		}
	}
	walk(root, 0)
	return names, true
}
