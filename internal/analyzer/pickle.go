package analyzer

import (
	"encoding/binary"
)

// pickleGlobal records a module.name reference extracted from a pickle
// opcode stream via GLOBAL (protocol 0-2) or STACK_GLOBAL (protocol 4+).
type pickleGlobal struct {
	Module, Name string
	Reduced      bool // true when followed by REDUCE opcode within the same stream
}

// scanPickleOpcodes performs a bounded, linear, read-only walk of a pickle
// byte stream and extracts every GLOBAL/STACK_GLOBAL-referenced
// (module, name) pair. It never constructs, imports, or invokes anything —
// it only reads opcode bytes and their length-prefixed or newline-
// terminated arguments, mirroring how static pickle scanners (e.g. Hugging
// Face's) work: it disassembles the bytecode, it does not run it. If the
// stream is truncated, malformed, or uses an opcode this scanner doesn't
// recognize, it stops and returns whatever was found so far rather than
// erroring — a best-effort static heuristic, not a full pickle VM.
func scanPickleOpcodesOnce(data []byte) ([]pickleGlobal, int) {
	var globals []pickleGlobal
	type peeker struct {
		value  string
		global bool
		gi     int
	}
	var stack []peeker
	pop2 := func() (peeker, peeker, bool) {
		if len(stack) < 2 {
			return peeker{}, peeker{}, false
		}
		a, b := stack[len(stack)-2], stack[len(stack)-1]
		stack = stack[:len(stack)-2]
		return a, b, true
	}
	push := func(s string) { stack = append(stack, peeker{value: s, gi: -1}) }
	pushGlobal := func(s string, gi int) { stack = append(stack, peeker{value: s, global: true, gi: gi}) }

	i := 0
	n := len(data)
	readLine := func() (string, bool) {
		start := i
		for i < n && data[i] != '\n' {
			i++
		}
		if i >= n {
			return "", false
		}
		s := string(data[start:i])
		i++ // consume newline
		return s, true
	}
	readN := func(count int) ([]byte, bool) {
		if count < 0 || i+count > n {
			return nil, false
		}
		b := data[i : i+count]
		i += count
		return b, true
	}
	readUint := func(width int) (int, bool) {
		b, ok := readN(width)
		if !ok {
			return 0, false
		}
		switch width {
		case 1:
			return int(b[0]), true
		case 2:
			return int(binary.LittleEndian.Uint16(b)), true
		case 4:
			return int(binary.LittleEndian.Uint32(b)), true
		case 8:
			return int(binary.LittleEndian.Uint64(b)), true
		}
		return 0, false
	}
	// skipLenPrefixed consumes a `width`-byte little-endian length prefix
	// followed by that many bytes, and returns the payload as a string if
	// isString is set (for opcodes that push a value onto the stack).
	skipLenPrefixed := func(width int, isString bool) bool {
		length, ok := readUint(width)
		if !ok {
			return false
		}
		payload, ok := readN(length)
		if !ok {
			return false
		}
		if isString {
			push(string(payload))
		} else {
			push("")
		}
		return true
	}

	const maxOpcodes = 200000 // bound: never loop unboundedly on adversarial input
	for opIndex := 0; opIndex < maxOpcodes && i < n; opIndex++ {
		op := data[i]
		i++
		switch op {
		case '.': // STOP
			return globals, i
		case '(': // MARK
			push("\x00mark")
		case '\x94': // MEMOIZE — true no-op for stack-tracking purposes:
			// it stores a reference to the current stack top in the memo
			// table without popping or pushing. Handling this correctly is
			// essential: PyTorch/protocol-4 pickles emit
			// SHORT_BINUNICODE MEMOIZE SHORT_BINUNICODE MEMOIZE
			// STACK_GLOBAL, and treating MEMOIZE as pushing a value would
			// desync the stack so STACK_GLOBAL's "pop the last two" no
			// longer lines up with the two strings just pushed.
		case '\x93': // STACK_GLOBAL
			a, b, ok := pop2()
			if ok && !isMarkOrEmpty(a.value) && !isMarkOrEmpty(b.value) {
				globals = append(globals, pickleGlobal{Module: a.value, Name: b.value})
				pushGlobal("\x00global", len(globals)-1)
			} else {
				push("\x00global")
			}
		case '1': // POP_MARK
			for len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if top.value == "\x00mark" {
					break
				}
			}
		case 'a', 'b', 's', 'u', '2': // APPEND/BUILD/SETITEM/SETITEMS/DUP: consume, don't push a new tracked value
		case '0': // POP
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case 'N', 'd', 'e', 'l', 'o', 't',
			'}', ']', ')', '\x81', '\x85', '\x86', '\x87', '\x88', '\x89',
			'\x8f', '\x90', '\x91', '\x92', '\x97', '\x98',
			'Q':
			// Other zero-argument opcodes: push a placeholder result.
			// Imprecise for opcodes with non-trivial stack effects (e.g.
			// NEWOBJ pops 2 pushes 1), but harmless for GLOBAL/
			// STACK_GLOBAL tracking since malicious payloads keep the
			// class-reconstruction call immediately adjacent to its
			// GLOBAL/STACK_GLOBAL reference.
			push("")
		case 'F', 'I', 'J', 'K', 'L', 'M', 'G': // numeric literals: newline or fixed-width, not strings
			switch op {
			case 'F', 'I', 'L':
				if _, ok := readLine(); !ok {
					return globals, i
				}
			case 'J':
				if _, ok := readN(4); !ok {
					return globals, i
				}
			case 'K':
				if _, ok := readN(1); !ok {
					return globals, i
				}
			case 'M':
				if _, ok := readN(2); !ok {
					return globals, i
				}
			case 'G':
				if _, ok := readN(8); !ok {
					return globals, i
				}
			}
			push("")
		case 'P': // PERSID
			if _, ok := readLine(); !ok {
				return globals, i
			}
			push("")
		case 'S': // STRING (quoted, newline-terminated)
			line, ok := readLine()
			if !ok {
				return globals, i
			}
			push(unquotePickleString(line))
		case 'V': // UNICODE (newline-terminated, raw-unicode-escape)
			line, ok := readLine()
			if !ok {
				return globals, i
			}
			push(line)
		case 'T': // BINSTRING
			if !skipLenPrefixed(4, true) {
				return globals, i
			}
		case 'U': // SHORT_BINSTRING
			if !skipLenPrefixed(1, true) {
				return globals, i
			}
		case 'X': // BINUNICODE
			if !skipLenPrefixed(4, true) {
				return globals, i
			}
		case '\x8c': // SHORT_BINUNICODE
			if !skipLenPrefixed(1, true) {
				return globals, i
			}
		case '\x8d': // BINUNICODE8
			if !skipLenPrefixed(8, true) {
				return globals, i
			}
		case 'B': // BINBYTES
			if !skipLenPrefixed(4, false) {
				return globals, i
			}
		case 'C': // SHORT_BINBYTES
			if !skipLenPrefixed(1, false) {
				return globals, i
			}
		case '\x8e': // BINBYTES8
			if !skipLenPrefixed(8, false) {
				return globals, i
			}
		case '\x96': // BYTEARRAY8
			if !skipLenPrefixed(8, false) {
				return globals, i
			}
		case '\x8a': // LONG1
			if !skipLenPrefixed(1, false) {
				return globals, i
			}
		case '\x8b': // LONG4
			if !skipLenPrefixed(4, false) {
				return globals, i
			}
		case 'g': // GET
			if _, ok := readLine(); !ok {
				return globals, i
			}
			push("")
		case 'h': // BINGET
			if _, ok := readN(1); !ok {
				return globals, i
			}
			push("")
		case 'j': // LONG_BINGET
			if _, ok := readN(4); !ok {
				return globals, i
			}
			push("")
		case 'p': // PUT
			if _, ok := readLine(); !ok {
				return globals, i
			}
		case 'q': // BINPUT
			if _, ok := readN(1); !ok {
				return globals, i
			}
		case 'r': // LONG_BINPUT
			if _, ok := readN(4); !ok {
				return globals, i
			}
		case '\x80': // PROTO
			if _, ok := readN(1); !ok {
				return globals, i
			}
		case '\x82': // EXT1
			if _, ok := readN(1); !ok {
				return globals, i
			}
			push("")
		case '\x83': // EXT2
			if _, ok := readN(2); !ok {
				return globals, i
			}
			push("")
		case '\x84': // EXT4
			if _, ok := readN(4); !ok {
				return globals, i
			}
			push("")
		case '\x95': // FRAME
			if _, ok := readN(8); !ok {
				return globals, i
			}
		case 'c': // GLOBAL (module\n name\n)
			module, ok1 := readLine()
			name, ok2 := readLine()
			if !ok1 || !ok2 {
				return globals, i
			}
			globals = append(globals, pickleGlobal{Module: module, Name: name})
			pushGlobal("\x00global", len(globals)-1)
		case 'i': // INST (module\n name\n) — like GLOBAL but also instantiates
			module, ok1 := readLine()
			name, ok2 := readLine()
			if !ok1 || !ok2 {
				return globals, i
			}
			globals = append(globals, pickleGlobal{Module: module, Name: name, Reduced: true})
			push("\x00inst")
		case 'R': // REDUCE — pops (callable, args) and invokes
			if len(stack) >= 2 {
				callable := stack[len(stack)-2]
				if callable.global && callable.gi >= 0 && callable.gi < len(globals) {
					globals[callable.gi].Reduced = true
				}
			}
			if len(stack) >= 2 {
				stack = stack[:len(stack)-2]
			}
			push("")
		default:
			// Unrecognized opcode: stop rather than mis-parse the rest of
			// the stream (a wrong guess here could silently hide real
			// evidence later in the stream, which is worse than an honest
			// early stop).
			return globals, i
		}
	}
	return globals, i
}

// scanPickleOpcodes walks data as one or more concatenated pickle streams
// and returns every GLOBAL/STACK_GLOBAL reference found across all of them.
// Legacy-format PyTorch checkpoints (saved without the newer zip container)
// concatenate several independent pickle streams back to back, so a single
// STOP-terminated parse alone would silently miss evidence in later
// streams; this loops until the input is exhausted or no further progress
// is made, bounded to avoid any possibility of looping on adversarial
// input.
func scanPickleOpcodes(data []byte) []pickleGlobal {
	var all []pickleGlobal
	offset := 0
	for stream := 0; stream < 64 && offset < len(data); stream++ {
		globals, consumed := scanPickleOpcodesOnce(data[offset:])
		all = append(all, globals...)
		if consumed <= 0 {
			break
		}
		offset += consumed
	}
	return all
}

func isMarkOrEmpty(s string) bool {
	return s == "" || s == "\x00mark" || s == "\x00global" || s == "\x00inst"
}

// unquotePickleString performs the minimal unescaping pickletools applies
// to protocol-0 STRING opcode arguments (surrounding quotes only; pickle's
// STRING opcode uses Python repr()-style quoting for its argument).
func unquotePickleString(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
