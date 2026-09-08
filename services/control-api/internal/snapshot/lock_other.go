//go:build !linux

package snapshot

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("durable local stores currently require Linux")
}
