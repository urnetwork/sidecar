//go:build sidecar_http && !ios_extension

// The compute credentials Sidecar.SecretMatcher holds on the page Worker's leg (§18.10), record_secret_match_custody.go's
// twin: none. The page Worker gets no compute (DESIGN-COMPUTE §15.4, §1.2) and links no compute family's file, so no
// source registers on this leg and there is nothing to read.

package sidecar

// None.
func (self *Sidecar) secretMatchComputeCredentials() ([][]byte, error) {
	return nil, nil
}
