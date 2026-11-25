//go:build !ios_extension && !sidecar_http

// A support message as it leaves the device (DESIGN-COMPUTE §28.10): its SupportBody, as JSON, over TLS to the feedback
// service's host the newest verified policy names. Nothing in it is sealed: the support conversation is meant to be fully
// read by the platform (CO-46), so what keeps secrets and the person's private data out is on the device, before a body
// is built (support_form.go, support_client.go).
//
// client_ref is FB section 3's retry key, 128 bits (§28.6): for a Harness run's message the first 16 bytes of
// SHA-256("urnetwork-sidecar-v1/support" || 0x00 || run id || tool call id), which a resumed run repeats; otherwise 16
// random bytes. A kind-27 message keeps the client_ref it was built with, which field 80 and the body field 3 hashes
// name, its use's effect key mapping to it in the outbox (QD-1398, which reads §28.6's derivation from the effect key as
// the message's own). The outbox posts each body under its one client_ref as Idempotency-Key, with its tier and its
// approver beside it (supportHeaderTier), so a crash at any step posts the message once.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
)

// A SupportBody's format version.
const supportBodyVersion = 1

// What a run's client_ref is derived under (§28.6).
const supportClientRefDomain = "urnetwork-sidecar-v1/support"

// A message's tier (§28.5): who wrote it and who let it go.
type SupportTier string

const (
	// The person typed it: in the app, or ur support send confirmed on /dev/tty with no harness process among its
	// ancestors.
	SupportTierHuman SupportTier = "human"
	// An agent's message a person approved, kind 27's decision on a human channel.
	SupportTierReleased SupportTier = "released"
	// An agent's message sent without a person: from a clean run, or approved by the device's classifier.
	SupportTierAgent SupportTier = "agent"
	// FB section 10.3's enumerated report.
	SupportTierAuto SupportTier = "auto"
)

// FB section 4's kind hints, which triage may change, in field 80's order from 1.
var supportKindNames = []string{"bug", "feature", "question", "praise", "security", "other"}

// A kind hint's field 80 number, 0 for none, and false for a word FB does not name.
func supportKindNumber(kind string) (uint32, bool) {
	if kind == "" {
		return supportKindNone, true
	}
	index := slices.Index(supportKindNames, kind)
	if index < 0 {
		return 0, false
	}
	return uint32(index + 1), true
}

// Who wrote a message, as the platform reads it with the message (§28.10, FB section 3's agent_ref).
type SupportBodySender struct {
	// The person, typing in an app or confirming on /dev/tty.
	Person bool `json:"person,omitempty"`
	// The agent's registered name (§20.5), and where it runs: this device, an enclave of the member's, or a tagged
	// sidecar of the sponsor's.
	Agent string `json:"agent,omitempty"`
	Where string `json:"where,omitempty"`
	// Whether the agent's run had read anything untrusted, and who approved the message: none, where that is known as
	// the body is built; a kind-27 message's body names no approver, since none has decided when field 3 hashes it
	// (QD-1398), and its post names the decider beside it.
	Tainted  bool   `json:"tainted,omitempty"`
	Approved string `json:"approved,omitempty"`
}

// Who let a message go (§28.5, §28.8): none for the person's own and a clean run's, else kind 27's decider.
const (
	SupportApprovedNone       = "none"
	SupportApprovedClassifier = "classifier"
	SupportApprovedPerson     = "person"
)

// The headers a post carries beside the body (QD-1398): the message's tier and who let it go, which a kind-27
// message's body cannot hold, since field 3 hashes the body before anyone decides. Every post carries both, so the
// service reads them in one place; where the body names them too, they agree.
const (
	supportHeaderTier     = "Support-Tier"
	supportHeaderApproved = "Support-Approved"
)

// The tier a decision gives a kind-27 message: a person's approval sends it released, the classifier's agent (§28.8).
func supportTierOfDecider(approved string) SupportTier {
	if approved == SupportApprovedClassifier {
		return SupportTierAgent
	}
	return SupportTierReleased
}

// An attachment as the body names it: its hash and size, never its bytes, which post apart.
type SupportBodyAttachment struct {
	// text, png or jpeg; empty for the support log's bundle.
	Type   string `json:"type,omitempty"`
	Name   string `json:"name,omitempty"`
	Sha256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// One message as JSON (§28.10): its version, product, client_ref, the entry it continues, its tier and kind hint, its
// text, its sender, its bundle's and files' hashes and sizes, and the support:urnetwork version it went under. A
// kind-27 message's body names no tier, which its decision gives it, posted beside the body (QD-1398).
type SupportBody struct {
	V          int                      `json:"v"`
	Product    string                   `json:"product"`
	ClientRef  string                   `json:"client_ref"`
	Entry      string                   `json:"entry,omitempty"`
	Tier       SupportTier              `json:"tier,omitempty"`
	Kind       string                   `json:"kind,omitempty"`
	Text       string                   `json:"text"`
	Sender     *SupportBodySender       `json:"sender"`
	Bundle     *SupportBodyAttachment   `json:"bundle,omitempty"`
	Files      []*SupportBodyAttachment `json:"files,omitempty"`
	Disclosure uint32                   `json:"disclosure"`
}

// The body's bytes as stored and posted: one encoding, so field 3's hash and the post agree.
func (self *SupportBody) encode() ([]byte, error) {
	encoded, err := json.Marshal(self)
	if err != nil {
		return nil, fmt.Errorf("support body: %w", err)
	}
	return encoded, nil
}

// A Harness run's client_ref for one tool call, which the run repeats when it resumes (§24.7).
func SupportClientRefOfRun(runId Id, toolCallId string) []byte {
	hash := sha256.New()
	hash.Write([]byte(supportClientRefDomain))
	hash.Write([]byte{0})
	hash.Write(runId.Bytes())
	hash.Write([]byte(toolCallId))
	return hash.Sum(nil)[:supportClientRefByteCount]
}

// Any other message's client_ref, the person's and a kind-27 one with no run's tool call: 16 random bytes.
func newSupportClientRef() ([]byte, error) {
	clientRef := make([]byte, supportClientRefByteCount)
	if _, err := rand.Read(clientRef); err != nil {
		return nil, fmt.Errorf("support: %w", err)
	}
	return clientRef, nil
}

// A client_ref as the wire and Idempotency-Key spell it: lowercase hex.
func supportClientRefText(clientRef []byte) string {
	return hex.EncodeToString(clientRef)
}
