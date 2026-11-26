//go:build !ios_extension && !sidecar_http

// The support push topic (DESIGN-COMPUTE §28.9, D-SUP-6; §6.8's registry, owner decision 783), end to end:
//
//	publisher  the feedback service, FB's and not built here, hints PushTopicSupport through Push.HintSidecars for
//	           each sidecar of a member whose conversation gained an event, and for a tagged sender's own: the hint
//	           NewSupportClientHint builds, a SupportHint {product, entry, seq} under kind SUPPORT_HINT, its version the
//	           service's clock in ms, which the hint script raises past the stored value (§2.8's support-2)
//	resident   tells the topic to a sidecar's client alone: a forwarding device client is told team only (owner decision
//	           197), and with no live resident the hint's wake goes to the app as mail's does, a topic class and a
//	           version and nothing else (§18.7, WK4)
//	device     each client generation's push holds the topic for the Sidecar's support client (supportHintComponent):
//	           a hint, or a resync notice that the topic moved, wakes the client's loop, which reads the member's events
//	           from its cursor over its own session and tells its listeners each new one's enumerated fields; a hint
//	           naming another product's conversation, recURd's dock, asks nothing of this client
//	listeners  a running agent's watch (ur support watch, MCP's resources/updated on ur://support/urnetwork) and the
//	           apps' notification hook, for which SupportNotificationOf keeps support's replies and status moves, so the
//	           app composes its own words with no reply's text (FB section 7)
//
// A hint is a prompt and never content (R-PROTO-8): the device acts on none of its fields but the product, and what
// it reads it reads from the service, so a forged or lost hint costs a read or the loop's interval, nothing more.
// With the release's switch off (SupportSettings.ServiceEnabled) a hint asks nothing and Wake answers
// ErrSupportUnavailable, so the topic stays dark with the rest of the skill (§28.21).

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A support hint a publisher cannot send: a product FB does not name, an entry its ids do not take, a seq of 0 or a
// version of 0.
var errSupportHintInvalid = errors.New("support hint invalid")

// The support topic's hint for the event seq of entry in product's conversation, at version, the publisher's clock in
// ms: what the feedback service passes to Push.HintSidecars for each of the member's sidecars (§28.9). It carries the
// event's name alone, a few dozen bytes, far inside the format's 256.
func NewSupportClientHint(product string, entry string, seq uint32, version uint64) (*ClientHint, error) {
	switch {
	case product != SupportProductUrnetwork && product != supportProductRecurd:
		return nil, fmt.Errorf("%w: product %q", errSupportHintInvalid, product)
	case !supportEntryPattern.MatchString(entry):
		return nil, fmt.Errorf("%w: an entry FB's ids do not take", errSupportHintInvalid)
	case seq == 0 || version == 0:
		return nil, fmt.Errorf("%w: seq %d at version %d", errSupportHintInvalid, seq, version)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SupportHint{Product: product, Entry: entry, Seq: seq})
	if err != nil {
		return nil, err
	}
	return &ClientHint{
		Topic:   PushTopicSupport,
		Version: version,
		Kind:    uint32(protocol.MessageType_SUPPORT_HINT),
		Body:    body,
	}, nil
}

// The event a support notice names, or false for one that names none: a resync notice, a hint whose bytes a resident
// dropped (§6.8's bound), one of another kind or that does not decode, and one naming an entry FB's ids do not take.
func supportHintOf(notice PushNotice) (*protocol.SupportHint, bool) {
	if notice.Topic != PushTopicSupport || notice.Resync || notice.Kind != uint32(protocol.MessageType_SUPPORT_HINT) || len(notice.Hint) == 0 {
		return nil, false
	}
	hint := &protocol.SupportHint{}
	if err := proto.Unmarshal(notice.Hint, hint); err != nil || !supportEntryPattern.MatchString(hint.Entry) {
		return nil, false
	}
	return hint, true
}

// A notice of the support topic, on the push's goroutine, which it never blocks: anything but a hint naming another
// product's conversation wakes the loop, whose pass reads the member's events. Nothing with the release's switch off.
func (self *SupportClient) takeHint(notice PushNotice) {
	if !self.settings.ServiceEnabled || notice.Topic != PushTopicSupport {
		return
	}
	if hint, named := supportHintOf(notice); named && hint.Product != SupportProductUrnetwork {
		// recURd's dock keeps its own thread, which this client neither writes nor reads (§28.5)
		return
	}
	self.poke()
}

// The client's part of each client generation (§5.4's components): it holds the support topic on the generation's
// push for the client's hints while the generation runs, and keeps nothing in its store. A generation without push
// holds nothing, and the loop's interval reads meanwhile.
type supportHintComponent struct {
	client *SupportClient
}

// The component's name, a seal class of its own beside the client's support store.
const supportHintComponentName = "support-hint"

func (self *supportHintComponent) Name() string {
	return supportHintComponentName
}

// Subscribes the client to the support topic for the generation's life.
func (self *supportHintComponent) Attach(env *SidecarEnv) error {
	if env.Subprotocol == nil {
		return nil
	}
	remove, err := env.Subprotocol.Subscribe(PushTopicSupport, self.client.takeHint)
	if err != nil {
		return nil
	}
	context.AfterFunc(env.Ctx, remove)
	return nil
}

// Nothing: the client closes itself.
func (self *supportHintComponent) Close() {}

// What the apps tell their person of an event while the conversation is out of view (§28.9; FB section 7): support
// replied on an item, or moved it. Enumerated fields alone, never a reply's text, from which the app composes its own
// words, "URnetwork support replied on #100171", so Apple and Google, who carry the app's notification, see no reply.
type SupportNotification struct {
	Product string `json:"product"`
	Entry   string `json:"entry"`
	Seq     uint32 `json:"seq"`
	// SupportNotificationReply or SupportNotificationStatus.
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	FixedIn string `json:"fixed_in,omitempty"`
	Final   bool   `json:"final"`
}

// SupportNotification.Kind's values.
const (
	// Support wrote a note on the item: FB section 4's note event.
	SupportNotificationReply = "reply"
	// Support moved the item: its status, its fixed_in, a link to a board item or a merge (FB sections 6 and 8).
	SupportNotificationStatus = "status"
)

// The notification an update raises, or false for one that raises none: the person's own messages and their agents',
// from this device or another, their acknowledgments, attachments, deletions, a message given up, and any event FB
// does not name. Only support moves an item and only support writes a note (FB section 6), so each of those is
// support's act and the person's to hear of.
func SupportNotificationOf(update *SupportUpdate) (*SupportNotification, bool) {
	if update == nil || !supportEntryPattern.MatchString(update.Entry) {
		return nil, false
	}
	kind := ""
	switch update.Type {
	case "note":
		kind = SupportNotificationReply
	case "status", "fixed_in", "linked", "merged":
		kind = SupportNotificationStatus
	default:
		return nil, false
	}
	return &SupportNotification{
		Product: update.Product,
		Entry:   update.Entry,
		Seq:     update.Seq,
		Kind:    kind,
		Status:  update.Status,
		FixedIn: update.FixedIn,
		Final:   update.Final,
	}, true
}

// The person's replies not yet read across the conversation, as each item's stub counts them for the person: the
// apps' badge beside a notification.
func (self *SupportClient) UnreadReplies() (int, error) {
	stubs, err := self.List(&SupportListArgs{Scope: "member"})
	if err != nil {
		return 0, err
	}
	unread := 0
	for _, stub := range stubs {
		unread += stub.UnreadReplies
	}
	return unread, nil
}
