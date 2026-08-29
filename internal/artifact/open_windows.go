//go:build windows

package artifact

import (
	"fmt"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkEscape, path)
	}
	return os.Open(path)
}
