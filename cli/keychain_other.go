//go:build (!darwin || ios || sdk_mobile_bind) && !windows && (!linux || android)

// Where §5.9 names no store: the pass alone wraps U.

package main

import (
	"github.com/urnetwork/sidecar"
)

// No store on this system.
func newOsKeyStore(args *osKeyStoreArgs) (sidecar.SidecarKeyStore, osKeyStoreKind, error) {
	return nil, osKeyStorePass, nil
}
