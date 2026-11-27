//go:build sidecar_http && !ios_extension

// The components' keys Sidecar.SecretMatcher holds on the page Worker's leg (§18.10),
// record_secret_match_components.go's twin: none. The page Worker runs no tls component and sends no mail, and links
// neither's file, so its keychain keeps no device key, front session root or DKIM key.

package sidecar

// None.
func loadSidecarComponentKeyCredentials(secrets SidecarSecrets) ([][]byte, error) {
	return nil, nil
}
