//go:build !windows

package eval

import (
	"context"
	"errors"
	"io"
)

func windowsIsolationAvailable() error {
	return errors.New("windows AppContainer isolation is unavailable on this platform")
}

func runWindowsIsolation(context.Context, string, IsolationRequest, IsolationLimits, string, io.Writer, io.Writer) error {
	return errors.New("windows AppContainer isolation is unavailable on this platform")
}
