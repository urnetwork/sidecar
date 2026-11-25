//go:build sidecar_http && !ios_extension

// The connect identity's credentials on the page Worker's leg (§18.10), record_secret_match_connect.go's twin. This leg
// runs no connect client, so it keeps no connect identity of its own and derives nothing from one
// (sidecarHttpLeg.keepsConnectIdentity), and it links no connect package, whose provide modes the derivation names:
// of a record a keychain holds here, its seed is what a matcher holds.

package sidecar

import "bytes"

// The seed alone, a copy the caller clears.
func sidecarConnectIdentityCredentials(seed []byte) ([][]byte, error) {
	return [][]byte{bytes.Clone(seed)}, nil
}
