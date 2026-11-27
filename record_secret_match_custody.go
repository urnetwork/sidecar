//go:build !ios_extension && !sidecar_http

// The compute credentials Sidecar.SecretMatcher holds on the legs that run compute (DESIGN-COMPUTE §2.5): what each
// registered source holds, read as compute_custody.go reads it. record_secret_match_custody_http.go is the page
// Worker's twin, which links no compute family's file (§15.4, §1.2).

package sidecar

// What this Sidecar's registered compute sources hold now, each a copy the caller clears: computeCustodyCredentials.
func (self *Sidecar) secretMatchComputeCredentials() ([][]byte, error) {
	return self.computeCustodyCredentials()
}
