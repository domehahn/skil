//go:build windows

package eval

import (
	"reflect"
	"testing"
)

func TestWindowsEnvironmentBuildsDoubleNULTerminatedBlock(t *testing.T) {
	environment, err := windowsEnvironment([]string{"A=one", "B=two"})
	if err != nil {
		t.Fatal(err)
	}
	expected := []uint16{'A', '=', 'o', 'n', 'e', 0, 'B', '=', 't', 'w', 'o', 0, 0}
	if !reflect.DeepEqual(environment, expected) {
		t.Fatalf("unexpected environment block: %#v", environment)
	}
}

func TestWindowsEnvironmentRejectsNUL(t *testing.T) {
	if _, err := windowsEnvironment([]string{"A=one\x00B=two"}); err == nil {
		t.Fatal("expected embedded NUL to be rejected")
	}
}
