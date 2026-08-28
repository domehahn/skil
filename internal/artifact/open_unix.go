//go:build !windows

package artifact

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, fmt.Errorf("%w: %s", ErrSymlinkEscape, path)
		}
		return nil, err
	}
	return f, nil
}
