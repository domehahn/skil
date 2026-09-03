package analyzer

import (
	"encoding/base64"
	"testing"
)

// realPyc312Danger and realPyc312Benign are byte-for-byte real Python 3.12
// py_compile output (not hand-constructed), used to verify extractPycNames
// against CPython's actual marshal encoding rather than only against a
// from-scratch reimplementation of the same assumptions. danger.py:
//
//	import os
//	def run():
//	    os.system("id")
//
// benign.py:
//
//	def add(a, b):
//	    return a + b
const (
	realPyc312Danger = "yw0NCgAAAAD+h5lqKgAAAOMAAAAAAAAAAAAAAAACAAAAAAAAAPMSAAAAlwBkAGQBbABaAGQChABaAXkBKQPpAAAAAE5jAAAAAAAAAAAAAAAAAwAAAAMAAADzLgAAAJcAdAEAAAAAAAAAAGoCAAAAAAAAAAAAAAAAAAAAAAAAZAGrAQAAAAAAAAEAeQApAk7aAmlkKQLaAm9z2gZzeXN0ZW2pAPMAAAAA+glkYW5nZXIucHnaA3J1bnIKAAAAAwAAAHMNAAAAgADcBAaHSYFJiGSFT3IIAAAAKQJyBQAAAHIKAAAAcgcAAAByCAAAAHIJAAAA2gg8bW9kdWxlPnILAAAAAQAAAHMNAAAA8AMBAQHbAAnzBAEBFHIIAAAA"
	realPyc312Benign = "yw0NCgAAAAD+h5lqIAAAAOMAAAAAAAAAAAAAAAABAAAAAAAAAPMKAAAAlwBkAIQAWgB5ASkCYwIAAAAAAAAAAAAAAAIAAAADAAAA8wwAAACXAHwAfAF6AAAAUwApAU6pACkC2gFh2gFicwIAAAAgIPoJYmVuaWduLnB52gNhZGRyBwAAAAEAAABzCwAAAIAA2AsMiHGJNYBM8wAAAABOKQFyBwAAAHIDAAAAcggAAAByBgAAANoIPG1vZHVsZT5yCQAAAAEAAABzCgAAAPADAQEB8wIBARFyCAAAAA=="
)

func decodePyc(t *testing.T, encoded string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestExtractPycNamesRealCompiledDangerousModule(t *testing.T) {
	data := decodePyc(t, realPyc312Danger)
	header, ok := parsePycHeader(data)
	if !ok {
		t.Fatal("expected a valid header")
	}
	if header.PythonVersion != "3.12" {
		t.Fatalf("PythonVersion = %q, want 3.12", header.PythonVersion)
	}
	// os.system is referenced inside the nested run() code object, not the
	// module-level code object, proving co_consts recursion into nested
	// code objects works.
	names, ok := extractPycNames(data[16:], header.PythonVersion)
	if !ok {
		t.Fatal("extractPycNames failed on real compiled output")
	}
	if !names["os"] || !names["system"] {
		t.Fatalf("expected os and system in names: %v", names)
	}
}

func TestExtractPycNamesRealCompiledBenignModule(t *testing.T) {
	data := decodePyc(t, realPyc312Benign)
	header, ok := parsePycHeader(data)
	if !ok {
		t.Fatal("expected a valid header")
	}
	names, ok := extractPycNames(data[16:], header.PythonVersion)
	if !ok {
		t.Fatal("extractPycNames failed on real compiled output")
	}
	if names["os"] || names["system"] {
		t.Fatalf("did not expect os/system in a benign add() module: %v", names)
	}
	if !names["add"] {
		t.Fatalf("expected the module-level name 'add': %v", names)
	}
}

// legacyLayoutBody38to310 is a hand-assembled marshal stream for a single
// code object under the pre-3.11 field layout (posonlyargcount present,
// nlocals present, varnames/freevars/cellvars instead of
// localsplusnames/localspluskinds, no qualname/exceptiontable), referencing
// os.system in its co_names. Real 3.8-3.10 interpreters were not available
// in the development environment, so this body was assembled by hand
// against the documented field order and cross-checked field-by-field
// against a byte-level trace of real Python 3.12 output (which shares the
// same scalar-field encoding, differing only in which object fields are
// present) — see the PR description for the trace used to verify this.
const legacyLayoutBody38to310 = "YwAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAHMEAAAAAAAAACkBTikCWgJvc1oGc3lzdGVtKQApACkAeglsZWdhY3kucHlaA3J1bgEAAABzAAAAAA=="

func TestExtractPycNamesLegacy38to310Layout(t *testing.T) {
	body := decodePyc(t, legacyLayoutBody38to310)
	for _, version := range []string{"3.8", "3.9", "3.10"} {
		names, ok := extractPycNames(body, version)
		if !ok {
			t.Fatalf("extractPycNames failed for %s layout", version)
		}
		if !names["os"] || !names["system"] {
			t.Fatalf("%s: expected os/system: %v", version, names)
		}
	}
}

func TestExtractPycNamesUnsupportedVersionDeclinesRatherThanGuesses(t *testing.T) {
	data := decodePyc(t, realPyc312Danger)
	if _, ok := extractPycNames(data[16:], "3.14"); ok {
		t.Fatal("expected a version with no known field layout to be declined")
	}
	if _, ok := extractPycNames(data[16:], "unknown (magic 0x9999)"); ok {
		t.Fatal("expected an unrecognized-magic label to be declined")
	}
}

func TestExtractPycNamesTruncatedStreamFailsClosed(t *testing.T) {
	data := decodePyc(t, realPyc312Danger)
	body := data[16:]
	for _, cut := range []int{0, 1, 5, len(body) / 2, len(body) - 1} {
		if _, ok := extractPycNames(body[:cut], "3.12"); ok {
			t.Fatalf("truncated body (%d/%d bytes) unexpectedly parsed as well-formed", cut, len(body))
		}
	}
}

func TestExtractPycNamesRejectsNonCodeTopLevelObject(t *testing.T) {
	// A bare TYPE_NONE object is well-formed marshal but not a code object.
	if _, ok := extractPycNames([]byte{'N'}, "3.12"); ok {
		t.Fatal("expected a non-code top-level object to be rejected")
	}
}

func TestMarshalReaderNeverPanicsOnAdversarialBytes(t *testing.T) {
	// A bounded scan over short adversarial byte sequences, checking only
	// that the reader returns rather than panics or hangs — a lightweight
	// standalone version of the derived-views fuzz discipline for a parser
	// this session has no live fuzz target wired up for yet.
	seeds := [][]byte{
		{},
		{'c'},
		{0xe3},
		{'(', 0xff, 0xff, 0xff, 0x7f},
		{')', 0xff},
		{'{'},
		{'r', 0, 0, 0, 0},
		{'l', 0xff, 0xff, 0xff, 0x7f},
	}
	for _, seed := range seeds {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("panic on %x: %v", seed, rec)
				}
			}()
			extractPycNames(seed, "3.12")
		}()
	}
}
