//go:build !darwin && !linux && !windows

// No daemon unit on a system ur is not released for.

package main

import (
	"errors"
)

func hostUnitEnv() (*unitEnv, error) {
	return nil, errors.New("no daemon unit on this system")
}
