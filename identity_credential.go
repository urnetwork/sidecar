// SidecarEnrollCredential, which §5.4's Enroll takes and §5.4 leaves unspecified, fixed here (CORE-M1-09): one of
// §5.6's credentials, used once and then erased. An auth key's bearer is the only part a request carries (§7.8); a
// pre-approved key's #<bundle> is client-only and is never sent, logged, persisted raw or passed to MCP, and prints
// only through RedactAuthKey. Nothing here names a connect type, so it builds on every leg.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

var (
	// A pre-approved key's bundle, which signs this sidecar's own SidecarAdmit (§5.6), refused whole until the verified
	// log can give its Delegation's row (TEAM-M2-10), rather than half-applied: FAILED_PRECONDITION.
	ErrSidecarEnrollBundle = errors.New("a pre-approved auth key's bundle cannot be applied until admission lands")
	// A child token minted elsewhere, which carries no admin_refused this sidecar saw (D-CORE-7): an sdk host enrolls
	// through MintChild (CORE-M8-01), and a pairing's token waits for CORE-M8-02.
	ErrSidecarEnrollChild = errors.New("a child token alone cannot be enrolled: its mint must be this sidecar's")
	// api did not confirm admin_refused, so nothing was kept and the client was removed, best effort (D-CORE-7): the
	// daemon must not start on a client that could administer the network.
	ErrSidecarEnrollNotAdminRefused = errors.New("api did not confirm the client refuses administration")
	// The sidecar is enrolled with a working client: `ur logout` first, or wait for a refusal to end it.
	ErrSidecarEnrolled = errors.New("already enrolled")
	// The state directory was restored or copied from another machine (§5.9): only `--replace` enrolls here.
	ErrSidecarRestored = errors.New("restored or copied state: enroll with --replace")
	// An ephemeral enrollment on an instance whose keychain would reach a disk.
	ErrSidecarEnrollEphemeral = errors.New("an ephemeral enrollment needs a memory-only keychain")
	// A store on this host holds a readable network by_jwt, so ur refuses to enroll here (D-TRUST-3).
	ErrSidecarHostCredentialStore = errors.New("a URnetwork app or extension on this host holds a network credential")
)

// A store on this host holding a readable network by_jwt (D-TRUST-3): its kind, never its path or value.
type SidecarHostCredentialStore struct {
	// app: a URnetwork app's .by/.auth_state or legacy .by/.by_jwt; extension: the URnetwork browser extension.
	Kind string
}

// What §5.6's paths enroll with. Enroll erases it, whatever the outcome. Printing one shows none of it.
type SidecarEnrollCredential struct {
	// The auth key as a person holds it, ur-authkey-<id>-<secret>[#<bundle>] (§7.8). Enroll splits the client-only
	// bundle off before anything else reads it, and sends only the bearer. A urn_ API key, or any network
	// credential, is refused (D-CORE-7).
	AuthKey string
	// A pre-approved key's decoded #<bundle>, client-only, which a caller that parsed the key itself may set
	// (TEAM-M1-05's ParseAuthKey). Refused until CORE-M2-01, as one in AuthKey is.
	Bundle *AuthKeyBundle
	// A child token minted elsewhere, as a pairing's would be (§5.8). It carries no mint answer this sidecar saw
	// confirm admin_refused (D-CORE-7), so Enroll refuses it alone; an sdk host enrolls through MintChild.
	ChildJwt string
	// An sdk host's mint of this sidecar's client as a child of its device client (§5.6's sdk host row, CORE-M8-01):
	// POST /network/auth-client on the device's token, admin_refused and strict_exp, naming clientPublicKey, this
	// generation's ClientKey. The device's token stays the host's; only the child's answer comes back, and Enroll keeps
	// nothing unless it confirms both marks.
	MintChild func(ctx context.Context, clientPublicKey []byte) (*SidecarAuthClientResult, error)
	// The keychain stays in memory and is never written: the instance must be on a memory backend (§5.6). Reaping
	// the client revokes it (§7.10).
	Ephemeral bool
	// `ur proxy` or a public exit is set, so the client declares provider egress (§20.8). False declares none.
	DeclaresEgress bool
	// The client's device description. Empty takes "ur".
	DeviceSpec string
	// `--replace` (plan-CORE-cli-ui-missing #4): on state restored or copied from another machine, keep the
	// sidecar_id and identity key, bind the next generation on a new client, and take this machine as the
	// instance's own.
	Replace bool
	// The genesis anchor an invite carries, which Enroll checks whole before anything is sent and records as the
	// sidecar's SidecarAnchor (identity_anchor.go), the log its ConfigClient follows having to chain to it.
	Anchor *SidecarEnrollAnchor
}

// The genesis anchor an enrollment checks the network against (§5.6's genesis row, §7.9).
type SidecarEnrollAnchor struct {
	// A_0 = SHA-256(Signed Genesis) (plan-TEAM-genesis-custody).
	GenesisSha256 []byte
	// The log position the anchor's creator stood at: its version and chain digest.
	HeadVersion uint64
	HeadChain   []byte
}

// Drops the key and the child token, and zeroes the bundle's seeds: §5.6's "used once, then erased". A Go string
// cannot be zeroed in place, so a string's bytes stay until collected.
func (self *SidecarEnrollCredential) Erase() {
	self.AuthKey = ""
	self.ChildJwt = ""
	self.MintChild = nil
	if self.Bundle != nil {
		self.Bundle.Erase()
	}
}

// Says what kind of credential it is, never any of it.
func (self *SidecarEnrollCredential) String() string {
	switch {
	case self.ChildJwt != "" || self.MintChild != nil:
		return "SidecarEnrollCredential{child}"
	case self.Bundle != nil:
		return "SidecarEnrollCredential{auth key, pre-approved}"
	}
	return "SidecarEnrollCredential{auth key}"
}

// As String, for %#v.
func (self *SidecarEnrollCredential) GoString() string {
	return self.String()
}

// Why api refused an enrollment, for `ur` to print: SidecarEnrollPreview when the network is not one of
// preview_networks before stage 2 (D-TRUST-3), SidecarEnrollNoGenesis before the owner's first untagged device
// signs Genesis (§7.9's genesis), else SidecarEnrollRefused. Nothing was kept.
type SidecarEnrollError struct {
	Reason string
	// api's answer: route, status and code, never a body or a token.
	Api *SidecarApiError
}

// The reasons a SidecarEnrollError gives.
const (
	SidecarEnrollPreview   = "preview"
	SidecarEnrollNoGenesis = "no_genesis"
	SidecarEnrollRefused   = "refused"
)

// api's codes for the two refusals ur names. no_genesis is §7.9's; not_preview is the reading
// core-m1-08-enroll-preview-code.md asks the owner to confirm, since TEAM-M1-02's refusal on auth-client carries
// only text today.
const (
	sidecarEnrollCodeNoGenesis  = "no_genesis"
	sidecarEnrollCodeNotPreview = "not_preview"
)

// The reason and api's status and code, none of the server's text.
func (self *SidecarEnrollError) Error() string {
	return fmt.Sprintf("enrollment %s: %s", self.Reason, self.Api.Error())
}

// The api error beneath.
func (self *SidecarEnrollError) Unwrap() error {
	return self.Api
}

// An enroll refusal as ur prints it.
func newSidecarEnrollError(apiErr *SidecarApiError) *SidecarEnrollError {
	reason := SidecarEnrollRefused
	switch apiErr.Code {
	case sidecarEnrollCodeNoGenesis:
		reason = SidecarEnrollNoGenesis
	case sidecarEnrollCodeNotPreview:
		reason = SidecarEnrollPreview
	}
	return &SidecarEnrollError{Reason: reason, Api: apiErr}
}
