//go:build js || ios || android || sdk_mobile_bind

// D-TRUST-3's host check on a host with no ur: a phone or a page, whose app is the host and holds its own state, so
// there is no other store to refuse beside (identity_host_stores.go is the desktop's).

package sidecar

// None: this host runs no ur.
func HostCredentialStores() []SidecarHostCredentialStore {
	return nil
}
