// The host's presence authenticator for ur daemon (MCP-M3-09; §16.6's profiles, D-MCP-19, FS-124): each platform's
// file gives urPlatformPresenceProvider, the root's PresenceProvider over what the host has, or nil where it has none,
// which every prompt then refuses:
//
//	darwin   the ur bundle's Secure Enclave key, ecdsa-p256-sha256, created with kSecAccessControlUserPresence and used
//	         through a fresh LAContext each time (presence_darwin.go)
//	windows  Windows Hello through webauthn.dll, webauthn-es256 (presence_windows.go)
//	linux    a FIDO2 key on hidraw over CTAP2, webauthn-es256 (presence_linux.go, presence_fido.go)
//
// Every provider asks the person itself, for biometry, a passcode or a touch, at each assertion; none caches one. The
// keys never leave the authenticator, so nothing here holds a private key. A webauthn-es256 assertion's client data is
// a webauthn.get with challenge base64url(SHA-256(message)) and origin https://ur.io, what the root's origin table
// holds for every host but Android (QD-073), and rp id ur.io. Registration asks for no attestation, since no release
// ships roots yet (QD-137), so every key labels asserted: a webauthn-es256 registration carries a fmt none attestation
// object and the create ceremony's client data, KeyRegister.attestation's map (QD-730), and a Secure Enclave key none.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// §16.6's webauthn-es256 identifiers, as the root's protocol/bridge/signed_presence.go holds them: the rp id whose
// SHA-256 an assertion's authenticator data starts with, and the one origin its table holds for these hosts.
const (
	urPresenceRpId   = "ur.io"
	urPresenceOrigin = "https://ur.io"
	// WebAuthn's client data types for a credential's creation and an assertion.
	urPresenceCreateType = "webauthn.create"
	urPresenceGetType    = "webauthn.get"
)

// A webauthn-es256 ceremony's client data JSON, as §16.6's per-use and countersign rows check it: its type, the
// challenge base64url(SHA-256(message)), and the origin, never cross-origin.
func urPresenceClientData(clientType string, message []byte) []byte {
	challenge := sha256.Sum256(message)
	clientData, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:        clientType,
		Challenge:   base64.RawURLEncoding.EncodeToString(challenge[:]),
		Origin:      urPresenceOrigin,
		CrossOrigin: false,
	})
	if err != nil {
		// a struct of strings and a bool always encodes
		panic(fmt.Sprintf("client data: %s", err))
	}
	return clientData
}
