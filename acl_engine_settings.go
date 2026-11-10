//go:build !ios_extension

// AclEngine's tunables (connect/CODESTYLE.md's settings rule).

package sidecar

import (
	"time"
)

// What an AclEngine is tuned by.
type AclEngineSettings struct {
	// How far a client's clock may stand from the gates' server time (§8.6: ±60 s): a check honors a rule until this
	// long past its expiry by the local clock, so a flow a gate admitted on its own time is not refused for skew.
	// Non-positive honors none.
	ClockSkew time.Duration
}

// §8.6's 60 s.
func DefaultAclEngineSettings() *AclEngineSettings {
	return &AclEngineSettings{
		ClockSkew: 60 * time.Second,
	}
}
