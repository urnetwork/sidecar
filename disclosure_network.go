//go:build !ios_extension && !sidecar_http

// The network's acknowledgment of a disclosure, for its tagged and cloud sidecars, which read no vault (DESIGN-COMPUTE
// §2.8's network row; CO-41, Q-CTRUST-3's (c); R-CCTX-25, D-CTRUST-3, IC-21; Appendix D's §6.9, §6.11 and §7.9 rows;
// CTRUST-M12-02):
//
//	statement  protocol.DisclosureAck, the body of a §6.9 Signed of purpose disclosure-ack and type SIGNED_DISCLOSURE_ACK
//	           (0x1809), by the identity key of an Owner's or Admin's approval-capable device: the network, the id, the
//	           version, the locale and revision shown and the member, then the signing device and the AuthPin of the
//	           verified state it signed at, by which a reader judges "when it signed" (the plan's proposal, as an
//	           ApprovalDecision's auth_pin is judged)
//	act        AckNetworkDisclosure: the person's confirmed act, no harness process among the caller's ancestors, on an
//	           Owner's or Admin's approval-capable device that runs the network's config writer (any other is refused,
//	           naming who can), after the whole text was shown at the current version (else disclosure_changed). It
//	           signs the statement and saves it as the compute block's disclosures entry {"<id>": <the Signed,
//	           deterministic protobuf in standard base64>} through SetComputeBlockDisclosure: into the document by the
//	           policy save path, planned as every save is and refused where the edit would change the document's rows,
//	           or, with no document, into the block-alone record, a config record that sets no reach (§16.4).
//	           RemoveNetworkDisclosure takes an entry out, any Owner's or Admin's on such a device, which only narrows
//	covers     search:, inference:, listeners:publish and support:urnetwork, the uses a tagged or cloud sidecar may have
//	           (§2.8, §26.6, §28.13); an entry of any other family is listed and never taken, and none is made
//	judge      ComputeNetworkDisclosures takes an entry only if its Signed verifies under the identity key the verified
//	           state admits for its signer, that signer is the device the statement names and was an approval-capable
//	           device of an Owner or Admin of the network's AdminSet at the pin it names, that pin is on this device's
//	           verified chain, the network is this one and the id is the entry's key. A pin past the state this device
//	           still holds, before the previous base, is judged as an ApprovalDecision's: the retained rows show the
//	           signer admitted at the pin and not revoked by it, and its standing and role are those of the verified
//	           state, which only narrows. A taken entry covers a use at the current version, or at the previous one while
//	           the new version's grace runs (computeDisclosureCovered, CTRUST-M12-01's rule)
//	readers    ComputeDisclosureCheck takes the network's on a tagged or cloud sidecar alone, never on a member's device
//	           or an enclave (disclosure_check.go); Stands is what LSTN's publisher and host hook read for
//	           listeners:publish; every device lists the entries, who gave each and when, in Disclosures(), ur
//	           disclosures and ur status, which an Owner's or Admin's settings and each tagged sidecar's card show
//	notice     at a new version of an id the block holds, disclosure_changed on each Owner's and Admin's approval-capable
//	           device, once a version while the Sidecar runs: the apps' notice to acknowledge again
//
// The statements are device-side policy text, never compiled into rows or the projection, and the broker checks none
// (Q-CTRUST-2): a rows input that depended on the policy a reader holds would split readers. Another writer's save
// carries an entry byte for byte (CACL-M12-03's editing keeps every byte it does not change). Nothing here creates,
// derives or unwraps a key: the identity key signs through Sidecar.Sign. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose the identity key signs a DisclosureAck under (§6.9, Appendix D), which identity_sign.go writes out.
const ComputeDisclosureAckPurpose = "disclosure-ack"

// On each Owner's and Admin's approval-capable device, at a new version of an id the network's compute block holds an
// acknowledgment of: DisclosureId names the id and Version its current version, which the network's entry no longer
// names. The apps show it as the notice to acknowledge again (§2.8's new version row).
const SidecarEventDisclosureChanged SidecarEventKind = "disclosure_changed"

// The families the network's acknowledgment covers (the file header's covers row): their uses are the ones a tagged or
// cloud sidecar may have.
var computeNetworkDisclosureFamilies = []ComputeDisclosureFamily{
	ComputeDisclosureFamilySearch,
	ComputeDisclosureFamilyInference,
	ComputeDisclosureFamilyListeners,
	ComputeDisclosureFamilySupport,
}

// Why an entry of the network's block is not taken (ComputeNetworkDisclosure.Refusal).
const (
	// The statement is no Signed DisclosureAck: not standard base64, not a Signed, a Signed of another type, a key_id or
	// evidence beside the identity key's signature, or a body that does not read whole.
	ComputeNetworkDisclosureRefusalStatement = "statement"
	// The signature does not verify under the identity key the verified state admits for its signer, or the state
	// admits no key for it.
	ComputeNetworkDisclosureRefusalSignature = "signature"
	// The statement names another network.
	ComputeNetworkDisclosureRefusalNetwork = "network"
	// The statement names another id than the block's key, or the id is of a family the network's acknowledgment does
	// not cover.
	ComputeNetworkDisclosureRefusalId = "id"
	// The pin it names is ahead of this device's verified state, off its chain, or one at which no retained row admits
	// the signer.
	ComputeNetworkDisclosureRefusalPin = "pin"
	// The signer is not the device the statement names, or was no approval-capable device of an Owner or Admin at
	// its pin: a Network admin's, a Member's, a tagged device's, an enclave's or a read_only device's signature counts
	// for nothing.
	ComputeNetworkDisclosureRefusalSigner = "signer"
)

var (
	// The network's acknowledgment is made only by an Owner's or Admin's own act, on an approval-capable device that runs
	// the network's config writer. Nothing was signed or saved.
	ErrNetworkDisclosureRefused = errors.New("the network's acknowledgment of a disclosure is made only by an Owner's or Admin's own act on an approval-capable device that runs the network's config writer, never through MCP, a hook, a harness, a run or a server")
	// The id is of a family the network's acknowledgment does not cover (the file header's covers row). Nothing was
	// signed or saved.
	ErrNetworkDisclosureUncovered = errors.New("the network's acknowledgment covers web search, inference, listeners:publish and support:urnetwork alone")
	// The edit would change what the network's document compiles to, which an acknowledgment never does. Nothing was
	// saved.
	ErrNetworkDisclosureRowsChanged = errors.New("the acknowledgment would change the network's rows, so it was not saved")
)

// A statement of id's acknowledgment for the network, as a reader takes it from the block. Answers the Signed and its
// body, the body read only once the Signed's shape is a DisclosureAck's: what signs it is the caller's to check
// (computeNetworkDisclosureJudge).
func parseComputeDisclosureAckStatement(statement string) (*bridge.Signed, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(statement)
	if err != nil {
		return nil, err
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(data, signed); err != nil {
		return nil, err
	}
	switch {
	case len(signed.ProtoReflect().GetUnknown()) != 0:
		return nil, errors.New("a Signed with fields this build does not read")
	case signed.GetType() != uint32(bridge.SignedType_SIGNED_DISCLOSURE_ACK):
		return nil, fmt.Errorf("a Signed of type %#x", signed.GetType())
	case len(signed.GetKeyId()) != 0 || signed.GetWebauthn() != nil:
		// the identity key signs it alone: no presence key, no countersignature
		return nil, errors.New("a Signed with a key_id or evidence")
	}
	return signed, nil
}

// The DisclosureAck a verified Signed carries, read whole.
func parseComputeDisclosureAckBody(signed *bridge.Signed) (*protocol.DisclosureAck, error) {
	body := &protocol.DisclosureAck{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, err
	}
	if len(body.ProtoReflect().GetUnknown()) != 0 || len(body.GetAuthPin().ProtoReflect().GetUnknown()) != 0 {
		return nil, errors.New("a body with fields this build does not read")
	}
	return body, nil
}

// statement as the block holds it: the Signed in deterministic protobuf, in standard base64.
func encodeComputeDisclosureAckStatement(signed *bridge.Signed) (string, error) {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// What a judgment reads of a signer at one position.
type computeNetworkDisclosureSigner struct {
	// An approval-capable device of the member (§16.6), and no enclave.
	approvalCapable bool
	// The member's role.
	role bridge.MemberRole
	// The position's time, unix milliseconds; 0 where the signer was judged at the verified state, its pin being past
	// what this device holds.
	atMs int64
}

// Whether the signer could give the network's acknowledgment: an approval-capable device of an Owner or Admin.
func (self *computeNetworkDisclosureSigner) admin() bool {
	return self.approvalCapable && configAdminSignerRole(self.role)
}

// What the network's acknowledgments are judged against: this device's verified network state.
type computeNetworkDisclosureState interface {
	// The network the state is of.
	networkId() Id
	// The verified pin.
	pin() *bridge.AuthPin
	// The identity key the state's rows admit for the sidecar, a revoked one's included, nil for none.
	identityKey(sidecarId Id) []byte
	// The signer, a device of member, as the state judges it at pin (the file header's judge row), or why it cannot:
	// an error wrapping ErrConfigPinAhead, ErrConfigPinOffChain or ErrConfigSignerNotAdmitted.
	signerAt(pin *bridge.AuthPin, sidecarId Id, memberId Id) (*computeNetworkDisclosureSigner, error)
	// This device as the verified state judges it: its member, false for a tagged or no member device, and the member's
	// standing at the verified state.
	device(sidecarId Id) (Id, *computeNetworkDisclosureSigner, bool)
}

// computeNetworkDisclosureState over §7.9's S(n), the device's verified state.
type computeNetworkDisclosureConfig struct {
	state *ConfigState
}

// See computeNetworkDisclosureState.
func (self *computeNetworkDisclosureConfig) networkId() Id {
	return self.state.NetworkId()
}

// See computeNetworkDisclosureState.
func (self *computeNetworkDisclosureConfig) pin() *bridge.AuthPin {
	return self.state.Pin()
}

// See computeNetworkDisclosureState.
func (self *computeNetworkDisclosureConfig) identityKey(sidecarId Id) []byte {
	return self.state.IdentityKey(sidecarId)
}

// The signer at state, its time atMs.
func computeNetworkDisclosureSignerOf(state *ConfigState, sidecarId Id, memberId Id, atMs int64) *computeNetworkDisclosureSigner {
	signer := &computeNetworkDisclosureSigner{atMs: atMs}
	if member := state.Member(memberId); member != nil {
		signer.role = member.GetRole()
	}
	row := state.SidecarRow(sidecarId)
	acl, err := state.Acl()
	signer.approvalCapable = row != nil && !configRowEnclave(row) && err == nil && acl != nil &&
		acl.ApprovalCapable(sidecarId) && acl.ConsentedFor(sidecarId, memberId)
	return signer
}

// See computeNetworkDisclosureState: S(k) at the pin where the state still holds it; a pin before what it holds as
// the file header's judge row says.
func (self *computeNetworkDisclosureConfig) signerAt(pin *bridge.AuthPin, sidecarId Id, memberId Id) (*computeNetworkDisclosureSigner, error) {
	judged, err := self.state.StateAt(pin)
	switch {
	case err == nil:
		return computeNetworkDisclosureSignerOf(judged, sidecarId, memberId, judged.TimeMs()), nil
	case errors.Is(err, ErrConfigPinNotRetained):
		if _, err := self.state.retainedIdentityKey(sidecarId, pin); err != nil {
			return nil, err
		}
		return computeNetworkDisclosureSignerOf(self.state, sidecarId, memberId, 0), nil
	}
	return nil, err
}

// See computeNetworkDisclosureState.
func (self *computeNetworkDisclosureConfig) device(sidecarId Id) (Id, *computeNetworkDisclosureSigner, bool) {
	memberId, untagged := configRowMember(self.state.SidecarRow(sidecarId))
	if !untagged {
		return Id{}, nil, false
	}
	return memberId, computeNetworkDisclosureSignerOf(self.state, sidecarId, memberId, self.state.TimeMs()), true
}

// Whether the network's acknowledgment covers id's family (the file header's covers row).
func computeNetworkDisclosureCovers(id ComputeDisclosureId) bool {
	return slices.Contains(computeNetworkDisclosureFamilies, id.Family)
}

// The network's acknowledgment of one id as this device judges it: what its statement names, who gave it and when,
// whether it is taken, and whether it covers a use now. JSON in the daemon's and the sdk's answers.
type ComputeNetworkDisclosure struct {
	// The block's key.
	Id string `json:"id"`
	// What the statement names, where it reads: the version, and the locale and revision of the text shown.
	Version  uint32 `json:"version,omitempty"`
	Locale   string `json:"locale,omitempty"`
	Revision uint32 `json:"revision,omitempty"`
	// The Owner or Admin who gave it, and the device that signed it; zero where the statement does not read.
	MemberId  Id `json:"member_id"`
	SidecarId Id `json:"sidecar_id"`
	// When it signed: the verified position it names, and that position's time, unix milliseconds, where this device
	// still holds the state there; 0 for none.
	PinVersion uint64 `json:"pin_version,omitempty"`
	SignedAtMs int64  `json:"signed_at_ms,omitempty"`
	// Whether the statement verifies and its signer could give it; else why not, one of the ComputeNetworkDisclosure
	// refusals.
	Taken   bool   `json:"taken"`
	Refusal string `json:"refusal,omitempty"`
	// Whether it covers a use now: taken, at the current version, or at the previous one while the new version's grace
	// runs, until GraceEndMs, unix milliseconds.
	Stands     bool  `json:"stands"`
	InGrace    bool  `json:"in_grace,omitempty"`
	GraceEndMs int64 `json:"grace_end_ms,omitempty"`
}

// One entry of the block judged at state (the file header's judge row), its coverage not yet read.
func computeNetworkDisclosureJudge(state computeNetworkDisclosureState, entry AclComputeDisclosure, settings *ComputeDisclosureSettings) *ComputeNetworkDisclosure {
	judged := &ComputeNetworkDisclosure{Id: entry.Id}
	refuse := func(refusal string) *ComputeNetworkDisclosure {
		judged.Refusal = refusal
		return judged
	}
	id, err := ParseComputeDisclosureId(entry.Id, settings)
	if err != nil || !computeNetworkDisclosureCovers(id) {
		return refuse(ComputeNetworkDisclosureRefusalId)
	}
	signed, err := parseComputeDisclosureAckStatement(entry.Statement)
	if err != nil {
		return refuse(ComputeNetworkDisclosureRefusalStatement)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return refuse(ComputeNetworkDisclosureRefusalSigner)
	}
	identityKey := state.identityKey(signerId)
	if len(identityKey) == 0 {
		return refuse(ComputeNetworkDisclosureRefusalSignature)
	}
	// the body is read only once its signature verifies (§6.9): the signer's key is the same at every position, a
	// sidecar's row keeping it for life
	err = bridge.VerifySigned(signed, ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, bridge.SignedKeyAlgEd25519, identityKey)
	if err != nil {
		return refuse(ComputeNetworkDisclosureRefusalSignature)
	}
	body, err := parseComputeDisclosureAckBody(signed)
	if err != nil {
		return refuse(ComputeNetworkDisclosureRefusalStatement)
	}
	memberId, memberErr := IdFromBytes(body.GetMemberId())
	sidecarId, sidecarErr := IdFromBytes(body.GetSidecarId())
	pin := body.GetAuthPin()
	if memberErr != nil || sidecarErr != nil || body.GetVersion() == 0 || pin == nil || len(pin.GetChain()) != sha256.Size {
		return refuse(ComputeNetworkDisclosureRefusalStatement)
	}
	judged.Version, judged.Locale, judged.Revision = body.GetVersion(), ApprovalPrintable(body.GetLocale()), body.GetRevision()
	judged.MemberId, judged.SidecarId, judged.PinVersion = memberId, sidecarId, pin.GetVersion()
	switch {
	case !bytes.Equal(body.GetNetworkId(), state.networkId().Bytes()):
		return refuse(ComputeNetworkDisclosureRefusalNetwork)
	case body.GetDisclosureId() != entry.Id:
		return refuse(ComputeNetworkDisclosureRefusalId)
	case sidecarId != signerId:
		return refuse(ComputeNetworkDisclosureRefusalSigner)
	}
	signer, err := state.signerAt(pin, sidecarId, memberId)
	if err != nil {
		return refuse(ComputeNetworkDisclosureRefusalPin)
	}
	judged.SignedAtMs = signer.atMs
	if !signer.admin() {
		return refuse(ComputeNetworkDisclosureRefusalSigner)
	}
	judged.Taken = true
	return judged
}

// A copy of judged with its coverage at now under the newest verified policy: none where the policy holds nothing for
// its id.
func (self *ComputeNetworkDisclosure) coveredAt(registry *ComputeDisclosureRegistry, now time.Time) *ComputeNetworkDisclosure {
	covered := *self
	if !covered.Taken || registry == nil {
		return &covered
	}
	disclosure, err := registry.Disclosure(covered.Id)
	if err != nil {
		return &covered
	}
	stands, graceEnd := computeDisclosureCovered(covered.Version, disclosure, now)
	covered.Stands = stands
	covered.InGrace = stands && covered.Version < disclosure.Version()
	if covered.InGrace {
		covered.GraceEndMs = graceEnd.UnixMilli()
	}
	return &covered
}

// What the network's acknowledgments read at each call.
type computeNetworkDisclosuresArgs struct {
	// The texts; an error reads every entry as covering nothing.
	registry func() (*ComputeDisclosureRegistry, error)
	// The device's verified state and the compute block its head compiled; an error reads nothing.
	read func() (computeNetworkDisclosureState, []AclComputeDisclosure, error)
	// The check's time.
	now      func() time.Time
	settings *ComputeDisclosureSettings
}

// The network's acknowledgments as this device judges them (the file header's judge row): what a tagged or cloud
// sidecar's check takes, what LSTN reads for listeners:publish, and what every device lists.
type ComputeNetworkDisclosures struct {
	args *computeNetworkDisclosuresArgs

	stateLock sync.Mutex
	// the judgments made at judgedPin, by statement, so a check judges each entry once a verified position
	judgedPin *bridge.AuthPin
	judged    map[string]*ComputeNetworkDisclosure
}

// The acknowledgments over args.
func newComputeNetworkDisclosures(args *computeNetworkDisclosuresArgs) *ComputeNetworkDisclosures {
	return &ComputeNetworkDisclosures{args: args, judged: map[string]*ComputeNetworkDisclosure{}}
}

// entry's judgment at state, judged once a verified position.
func (self *ComputeNetworkDisclosures) judgment(state computeNetworkDisclosureState, entry AclComputeDisclosure) *ComputeNetworkDisclosure {
	pin := state.pin()
	key := entry.Id + "\x00" + entry.Statement
	held := func() *ComputeNetworkDisclosure {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !proto.Equal(self.judgedPin, pin) {
			self.judgedPin, self.judged = pin, map[string]*ComputeNetworkDisclosure{}
			return nil
		}
		return self.judged[key]
	}()
	if held != nil {
		return held
	}
	judged := computeNetworkDisclosureJudge(state, entry, self.args.settings)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if proto.Equal(self.judgedPin, pin) {
			self.judged[key] = judged
		}
	}()
	return judged
}

// Every entry the network's compute block holds, judged at this device's verified state and covered at now, in the
// block's order; an error where the state or the block cannot be read, which a caller refuses on.
func (self *ComputeNetworkDisclosures) Entries(ctx context.Context) ([]*ComputeNetworkDisclosure, error) {
	state, statements, err := self.args.read()
	if err != nil {
		return nil, err
	}
	registry, err := self.args.registry()
	if err != nil {
		registry = nil
	}
	now := self.args.now()
	entries := []*ComputeNetworkDisclosure{}
	for _, statement := range statements {
		entries = append(entries, self.judgment(state, statement).coveredAt(registry, now))
	}
	return entries, nil
}

// One id's entry, nil where the block holds none.
func (self *ComputeNetworkDisclosures) Entry(ctx context.Context, id string) (*ComputeNetworkDisclosure, error) {
	entries, err := self.Entries(ctx)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Id == id {
			return entry, nil
		}
	}
	return nil, nil
}

// By id, the version each taken entry names: what the check on a tagged or cloud sidecar holds to the current version
// or the previous one within its grace (ComputeNetworkDisclosureAcks).
func (self *ComputeNetworkDisclosures) Versions(ctx context.Context) (map[string]uint32, error) {
	entries, err := self.Entries(ctx)
	if err != nil {
		return nil, err
	}
	versions := map[string]uint32{}
	for _, entry := range entries {
		if entry.Taken {
			versions[entry.Id] = entry.Version
		}
	}
	return versions, nil
}

// Whether the network's acknowledgment of id stands now: taken, at the current version or the previous one within its
// grace. What LSTN's publisher and host hook read for listeners:publish, on the device alone (§26.6, C-33); false with
// an error where the state cannot be read, which a caller treats as not standing.
func (self *ComputeNetworkDisclosures) Stands(ctx context.Context, id string) (bool, error) {
	entry, err := self.Entry(ctx, id)
	if err != nil {
		return false, err
	}
	return entry != nil && entry.Stands, nil
}

// What the network's acknowledgment, as an Owner or Admin makes it, records (Sidecar.AckNetworkDisclosure).
type ComputeNetworkDisclosureAckArgs struct {
	// The disclosure, family:slug.
	Id string
	// The version shown, which must be the newest verified policy's current one; and the locale and revision of the
	// text shown, which need not be English: the locale one of the version's texts.
	Version  uint32
	Locale   string
	Revision uint32
	// The act's origin: only SidecarActConfirmed records.
	Origin SidecarActOrigin
	// A harness process is among the caller's ancestors (Sidecar.HarnessAncestor), which refuses the act.
	HarnessAncestor bool
}

// What a removal of the network's acknowledgment names (Sidecar.RemoveNetworkDisclosure).
type ComputeNetworkDisclosureRemoveArgs struct {
	Id              string
	Origin          SidecarActOrigin
	HarnessAncestor bool
}

// What one act on the network's acknowledgments acts through: this device, how it signs, the writer, state and head
// it saves on, and the texts.
type computeNetworkDisclosureActor struct {
	sidecarId Id
	// Signs a DisclosureAck's body as this device's identity key (Sidecar.Sign).
	sign   func(body []byte) (*bridge.Signed, error)
	writer *ConfigWriter
	// The writer's verified state, and the same state as the acts' checks read it.
	state    *ConfigState
	view     computeNetworkDisclosureState
	tip      *ConfigHeadTip
	registry *ComputeDisclosureRegistry
	// The time a document's save judges at.
	now time.Time
	// The config repo's keys, which open activated grants' sealed details for a save's tests; nil opens none.
	repoKeyAt func(generation uint64) *EvsRepoKey
}

// The member of this device, if it is an Owner's or Admin's approval-capable device at the actor's state; else the
// refusal, naming who can.
func (self *computeNetworkDisclosureActor) admin() (Id, error) {
	if self.view == nil {
		return Id{}, fmt.Errorf("%w: no verified network state", ErrNetworkDisclosureRefused)
	}
	memberId, signer, untagged := self.view.device(self.sidecarId)
	switch {
	case !untagged:
		return Id{}, fmt.Errorf("%w: a tagged or cloud sidecar acknowledges for no one; an Owner or Admin does, on their own device", ErrNetworkDisclosureRefused)
	case !configAdminSignerRole(signer.role):
		return Id{}, fmt.Errorf("%w: this device's member is no Owner or Admin; one of the network's Owners or Admins acknowledges for it", ErrNetworkDisclosureRefused)
	case !signer.approvalCapable:
		return Id{}, fmt.Errorf("%w: this device is not approval-capable; acknowledge on an Owner's or Admin's approval-capable device", ErrNetworkDisclosureRefused)
	}
	return memberId, nil
}

// Refuses an act that is not the person's own, before anything is read.
func computeNetworkDisclosureActRefusal(origin SidecarActOrigin, harnessAncestor bool) error {
	if origin != SidecarActConfirmed {
		return fmt.Errorf("%w: the act's origin is no person's confirmation", ErrNetworkDisclosureRefused)
	}
	if harnessAncestor {
		return fmt.Errorf("%w: a harness process is among the caller's ancestors", ErrNetworkDisclosureRefused)
	}
	return nil
}

// The locale of the text shown, if it is one of disclosure's taken texts, as the registry spells it.
func computeDisclosureShownLocale(disclosure *ComputeDisclosure, locale string) (string, bool) {
	for _, text := range disclosure.texts {
		if strings.EqualFold(text.Locale, locale) {
			return text.Locale, true
		}
	}
	return "", false
}

// Signs and saves the network's acknowledgment of args.Id (the file header's act row). Answers the base's pin.
func (self *computeNetworkDisclosureActor) ack(ctx context.Context, args *ComputeNetworkDisclosureAckArgs) (*bridge.AuthPin, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no act", ErrNetworkDisclosureRefused)
	}
	if err := computeNetworkDisclosureActRefusal(args.Origin, args.HarnessAncestor); err != nil {
		return nil, err
	}
	// who may act, before what the text says
	memberId, err := self.admin()
	if err != nil {
		return nil, err
	}
	disclosure, err := self.registry.Disclosure(args.Id)
	if err != nil {
		return nil, err
	}
	if !computeNetworkDisclosureCovers(disclosure.Id) {
		return nil, fmt.Errorf("%w: not %s", ErrNetworkDisclosureUncovered, args.Id)
	}
	locale, shown := computeDisclosureShownLocale(disclosure, args.Locale)
	if args.Version != disclosure.Version() || !shown || disclosure.Revision() < args.Revision {
		// not this version's text: show the current text again
		return nil, ErrDisclosureChanged
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.DisclosureAck{
		NetworkId:    self.view.networkId().Bytes(),
		DisclosureId: disclosure.Id.String(),
		Version:      args.Version,
		Locale:       locale,
		Revision:     args.Revision,
		MemberId:     memberId.Bytes(),
		SidecarId:    self.sidecarId.Bytes(),
		AuthPin:      self.view.pin(),
	})
	if err != nil {
		return nil, err
	}
	signed, err := self.sign(body)
	if err != nil {
		return nil, err
	}
	statement, err := encodeComputeDisclosureAckStatement(signed)
	if err != nil {
		return nil, err
	}
	testHookBarrier("disclosure.network.save.before", args.Id)
	pin, err := self.save(ctx, func(source []byte) ([]byte, error) {
		return SetComputeBlockDisclosure(source, disclosure.Id.String(), statement)
	})
	testHookBarrier("disclosure.network.save.after", args.Id)
	return pin, err
}

// Takes the network's acknowledgment of args.Id out of the block, which only narrows; nothing is saved where the block
// holds none. Answers the base's pin, nil where nothing was saved.
func (self *computeNetworkDisclosureActor) remove(ctx context.Context, args *ComputeNetworkDisclosureRemoveArgs) (*bridge.AuthPin, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no act", ErrNetworkDisclosureRefused)
	}
	if err := computeNetworkDisclosureActRefusal(args.Origin, args.HarnessAncestor); err != nil {
		return nil, err
	}
	if _, err := ParseComputeDisclosureId(args.Id, self.registry.Settings()); err != nil {
		return nil, err
	}
	if _, err := self.admin(); err != nil {
		return nil, err
	}
	if self.tip == nil || self.tip.Head == nil {
		return nil, fmt.Errorf("%w: this device runs no config writer for the network", ErrNetworkDisclosureRefused)
	}
	source := self.tip.Head.File(ConfigHeadPolicyPath)
	if source == nil {
		source = self.tip.Head.File(ConfigHeadComputePath)
	}
	if source == nil {
		// neither a document nor a record: no entry to take out
		return nil, nil
	}
	removed, err := RemoveComputeBlockDisclosure(source, args.Id)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(removed, source) {
		return nil, nil
	}
	return self.save(ctx, func(source []byte) ([]byte, error) {
		return RemoveComputeBlockDisclosure(source, args.Id)
	})
}

// Saves edit's change to the block on the actor's writer at its tip: into the document, through the policy save path,
// or with no document into the block-alone record (the file header's act row).
func (self *computeNetworkDisclosureActor) save(ctx context.Context, edit func(source []byte) ([]byte, error)) (*bridge.AuthPin, error) {
	if self.writer == nil || self.tip == nil || self.tip.Head == nil {
		return nil, fmt.Errorf("%w: this device runs no config writer for the network", ErrNetworkDisclosureRefused)
	}
	head := self.tip.Head
	document := head.File(ConfigHeadPolicyPath)
	if document == nil {
		edited, err := edit(head.File(ConfigHeadComputePath))
		if err != nil {
			return nil, err
		}
		return AclComputeRecordSave(ctx, self.writer, head, self.state, edited, self.tip)
	}
	edited, err := edit(document)
	if err != nil {
		return nil, err
	}
	// planned as a config writer plans every save, its selectors from the head's own rows, and held to the rows the
	// document compiles to as it stands, so the edit changes no one's reach
	plan := func(source []byte) (*AclSavePlan, error) {
		resolve := &protocol.ConfigResolution{}
		if err := aclSaveDecode(head, ConfigHeadResolvePath, resolve); err != nil {
			return nil, err
		}
		networks := map[string]Id{}
		for _, row := range resolve.GetNetworks() {
			if id, err := IdFromBytes(row.GetNetworkId()); err == nil {
				networks[row.GetText()] = id
			}
		}
		return PlanAclSave(ctx, &AclSaveInput{
			Policy: source, Head: head, State: self.state, Now: self.now, ResolveScope: self.state.TeamScope,
			ResolveNetworkLabel: func(text string) (Id, bool) {
				id, ok := networks[text]
				return id, ok
			},
			RepoKeyAt: self.repoKeyAt,
		})
	}
	before, err := plan(document)
	if err != nil {
		return nil, err
	}
	after, err := plan(edited)
	if err != nil {
		return nil, err
	}
	if !computeNetworkDisclosureRowsEqual(before.Rows, after.Rows) {
		return nil, ErrNetworkDisclosureRowsChanged
	}
	after.ref = self.tip
	return AclSave(ctx, self.writer, after)
}

// Whether two compiles' rows are the same reach: equal, compute_rows read as unset where it holds only the defaults a
// block that names nothing compiles to, which the broker applies to an unset one (§16.5).
func computeNetworkDisclosureRowsEqual(a *protocol.AclRows, b *protocol.AclRows) bool {
	normal := func(rows *protocol.AclRows) *protocol.AclRows {
		if rows == nil {
			return &protocol.AclRows{}
		}
		normalized := proto.Clone(rows).(*protocol.AclRows)
		if proto.Equal(normalized.GetComputeRows(), &protocol.AclComputeRows{SearchEnabled: true}) {
			normalized.ComputeRows = nil
		}
		return normalized
	}
	return proto.Equal(normal(a), normal(b))
}

// The network's acknowledgment of a disclosure, an Owner's or Admin's act after its whole text was shown at its
// current version (the file header's act row): signed by this device's identity key and saved into the compute block.
// Answers the base's pin. Refused, with nothing signed or saved, for an act that is not the person's own, on any device
// but an Owner's or Admin's approval-capable one that runs the network's config writer, for a family the network's
// acknowledgment does not cover, and with ErrDisclosureChanged for a text that is not the current version's.
func (self *Sidecar) AckNetworkDisclosure(ctx context.Context, args *ComputeNetworkDisclosureAckArgs) (*bridge.AuthPin, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no act", ErrNetworkDisclosureRefused)
	}
	if err := computeNetworkDisclosureActRefusal(args.Origin, args.HarnessAncestor); err != nil {
		return nil, err
	}
	actor, err := self.computeNetworkDisclosureActor(ctx)
	if err != nil {
		return nil, err
	}
	return actor.ack(ctx, args)
}

// Takes the network's acknowledgment of a disclosure out of the compute block, any Owner's or Admin's act on such a
// device, which only narrows. Answers the base's pin, nil where the block held none.
func (self *Sidecar) RemoveNetworkDisclosure(ctx context.Context, args *ComputeNetworkDisclosureRemoveArgs) (*bridge.AuthPin, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no act", ErrNetworkDisclosureRefused)
	}
	if err := computeNetworkDisclosureActRefusal(args.Origin, args.HarnessAncestor); err != nil {
		return nil, err
	}
	actor, err := self.computeNetworkDisclosureActor(ctx)
	if err != nil {
		return nil, err
	}
	return actor.remove(ctx, args)
}

// The actor of this device's act: an Owner's or Admin's approval-capable device, checked at the verified state before
// the writer is read, so a refusal names who can; then the writer, its state and head.
func (self *Sidecar) computeNetworkDisclosureActor(ctx context.Context) (*computeNetworkDisclosureActor, error) {
	registry, err := self.ComputeDisclosureRegistry()
	if err != nil {
		return nil, err
	}
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	state, err := self.configState()
	if err != nil {
		return nil, err
	}
	actor := &computeNetworkDisclosureActor{sidecarId: identity.SidecarId, view: &computeNetworkDisclosureConfig{state: state}, registry: registry}
	if _, err := actor.admin(); err != nil {
		return nil, err
	}
	writer, writerState, tip, err := self.aclSaveContext(ctx, false)
	if errors.Is(err, ErrConfigWriterNotWriter) {
		return nil, fmt.Errorf("%w: %w; acknowledge on an Owner's or Admin's device that runs it", ErrNetworkDisclosureRefused, err)
	}
	if err != nil {
		return nil, err
	}
	actor.writer, actor.state, actor.view, actor.tip = writer, writerState, &computeNetworkDisclosureConfig{state: writerState}, tip
	actor.sign = func(body []byte) (*bridge.Signed, error) {
		return self.Sign(ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body, nil)
	}
	actor.now, actor.repoKeyAt = self.clock.Now(), self.aclRepoKeyAt()
	return actor, nil
}

// The new-version notice (the file header's notice row): what the component's loop runs once an interval.
type computeNetworkDisclosureNotices struct {
	disclosures *ComputeNetworkDisclosures
	// This device's sidecar id, false before it has one.
	self func() (Id, bool)
	emit func(event SidecarEvent)

	stateLock sync.Mutex
	// by id, the newest version a notice was raised for
	noticed map[string]uint32
}

// Raises disclosure_changed for each id whose taken entry names a version older than the current one, once a
// version, where this device is an Owner's or Admin's approval-capable device. Answers the ids it raised it for.
func (self *computeNetworkDisclosureNotices) notice(ctx context.Context) []string {
	sidecarId, ok := self.self()
	if !ok {
		return nil
	}
	state, _, err := self.disclosures.args.read()
	if err != nil {
		return nil
	}
	if _, signer, untagged := state.device(sidecarId); !untagged || !signer.admin() {
		return nil
	}
	registry, err := self.disclosures.args.registry()
	if err != nil {
		return nil
	}
	entries, err := self.disclosures.Entries(ctx)
	if err != nil {
		return nil
	}
	raised := []string{}
	for _, entry := range entries {
		if !entry.Taken {
			continue
		}
		disclosure, err := registry.Disclosure(entry.Id)
		if err != nil || disclosure.Version() <= entry.Version {
			continue
		}
		version := disclosure.Version()
		first := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if version <= self.noticed[entry.Id] {
				return false
			}
			self.noticed[entry.Id] = version
			return true
		}()
		if first {
			self.emit(SidecarEvent{Kind: SidecarEventDisclosureChanged, DisclosureId: entry.Id, Version: uint64(version)})
			raised = append(raised, entry.Id)
		}
	}
	return raised
}

// The component's name.
const computeNetworkDisclosureComponentName = "disclosures-network"

// Registers the network's acknowledgments as a compute component, beside the disclosures' own (disclosure_registry.go),
// whose registry it reads at use.
func init() {
	registerComputeComponent(computeNetworkDisclosureComponentName, newComputeNetworkDisclosureComponent,
		func(component *computeNetworkDisclosureComponent) { component.close() })
}

// The network's acknowledgments on one Sidecar, and the notice's loop, which ends with the Sidecar.
type computeNetworkDisclosureComponent struct {
	disclosures *ComputeNetworkDisclosures
	notices     *computeNetworkDisclosureNotices
	settings    *ComputeDisclosureSettings
	clock       Clock
	cancel      context.CancelFunc
	done        chan struct{}
}

// The component over sidecar, reading its state, block and registry at use; its loop starts here.
func newComputeNetworkDisclosureComponent(sidecar *Sidecar) (*computeNetworkDisclosureComponent, error) {
	settings := sidecar.settings.Disclosure
	if settings == nil {
		settings = DefaultComputeDisclosureSettings()
	}
	disclosures := newComputeNetworkDisclosures(&computeNetworkDisclosuresArgs{
		registry: sidecar.ComputeDisclosureRegistry,
		read:     sidecar.computeNetworkDisclosureRead,
		now: func() time.Time {
			gate, err := sidecar.ComputePolicyGate()
			if err != nil {
				return sidecar.clock.Now()
			}
			return gate.Now()
		},
		settings: settings,
	})
	ctx, cancel := context.WithCancel(context.Background())
	component := &computeNetworkDisclosureComponent{
		disclosures: disclosures,
		notices: &computeNetworkDisclosureNotices{
			disclosures: disclosures,
			self: func() (Id, bool) {
				identity := sidecar.Identity()
				if identity == nil {
					return Id{}, false
				}
				return identity.SidecarId, true
			},
			emit:    sidecar.emitEvent,
			noticed: map[string]uint32{},
		},
		settings: settings,
		clock:    sidecar.clock,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go component.run(ctx)
	return component, nil
}

// The notice's loop: once at start, then each NetworkNoticeInterval, until the Sidecar ends; a non-positive interval
// checks once.
func (self *computeNetworkDisclosureComponent) run(ctx context.Context) {
	defer close(self.done)
	for {
		self.notices.notice(ctx)
		if self.settings.NetworkNoticeInterval <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.NetworkNoticeInterval):
		}
	}
}

// Ends the loop and waits for it.
func (self *computeNetworkDisclosureComponent) close() {
	self.cancel()
	<-self.done
}

// The device's verified state and the compute block its head compiled: ErrComputePolicyUnread before it has read them.
func (self *Sidecar) computeNetworkDisclosureRead() (computeNetworkDisclosureState, []AclComputeDisclosure, error) {
	follower := self.ConfigFollower()
	if follower == nil {
		return nil, nil, ErrComputePolicyUnread
	}
	state := follower.VerifiedState()
	view, err := self.ComputePolicy()
	if state == nil || err != nil {
		return nil, nil, ErrComputePolicyUnread
	}
	return &computeNetworkDisclosureConfig{state: state}, view.Disclosures(), nil
}

// This Sidecar's network acknowledgments (the file header's judge row), or an error wrapping
// ErrComputeComponentUnavailable that says why there are none: with none, a tagged or cloud sidecar is refused.
func (self *Sidecar) ComputeNetworkDisclosures() (*ComputeNetworkDisclosures, error) {
	component, err := sidecarComputeComponent[computeNetworkDisclosureComponent](self, computeNetworkDisclosureComponentName)
	if err != nil {
		return nil, err
	}
	return component.disclosures, nil
}

// ComputeNetworkDisclosureAcks over a Sidecar's network acknowledgments, read at use: the check's network seam
// (disclosure_check.go).
type computeNetworkDisclosureSidecarAcks struct {
	sidecar *Sidecar
}

// See ComputeNetworkDisclosureAcks.
func (self *computeNetworkDisclosureSidecarAcks) Versions(ctx context.Context) (map[string]uint32, error) {
	disclosures, err := self.sidecar.ComputeNetworkDisclosures()
	if err != nil {
		return nil, err
	}
	return disclosures.Versions(ctx)
}

// Every entry, for the lists (disclosure_check.go's withAcks).
func (self *computeNetworkDisclosureSidecarAcks) Entries(ctx context.Context) ([]*ComputeNetworkDisclosure, error) {
	disclosures, err := self.sidecar.ComputeNetworkDisclosures()
	if err != nil {
		return nil, err
	}
	return disclosures.Entries(ctx)
}
