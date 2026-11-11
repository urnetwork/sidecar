//go:build !ios_extension

// §16.6's spend check, spendable(d, a, s, P), run before any effect (D-MCP-12, R-MCP-9, I-8, I-16, AD1-AD4, FI-3,
// FI-7): by the executing daemon at spend step 1, by every server gate after its stored-result lookup, and by every
// reader's and api's GrantActivate and bridge-approval check as ACL-M2-07's AclSpendCheck. It is one pure function of
// the decision as received, the action as stored, the spender, the verifier's time and what SpendState says of P, so
// all three reach one verdict from one position, and it reads no local state and no clock of its own.
//
// In §16.6's order, each refusal a SpendRefusal with its code:
//
//	forked     P is a projection the spender knows forked (AD3), checked first
//	signer     d's signer resolves to a key P holds for d.channel: device, the identity key of signer_id, a sidecar
//	           and not s; presence, the presence key key_id names, registered to d.approver_member_id; harness,
//	           s's own identity key
//	signature  d verifies over its bytes as received, never a re-marshal (§6.9, SIGNED_APPROVAL_DECISION, purpose
//	           approval), a presence key by its §16.6 profile with no counter
//	verdict    d.decision is approve
//	signer     the signer fits d.channel: device, an approval-capable device of d.approver_member_id other than s;
//	           harness, s itself, an approval-capable device of that member, since harness_ok's requester is the
//	           approver's own untagged consented sidecar and a read_only one signs no decision; presence, the key
//	           above. A harness decision's other conditions, taint included, are the signing daemon's, which no
//	           gate sees, so nothing here re-derives them
//	requester  d.requester_sidecar_id = s (AD1)
//	payload    d.payload_sha256 = SHA-256(a as stored)
//	template   d.uses > 1 exactly when a is a template, scope = true (record.proto's uses comment)
//	expired    now <= d.not_after_millis plus the settings' skew, skipped for a use already reserved (spend step 1)
//	pin        d.auth_pin is 40 bytes' worth, its version <= P's, and its digest equals A_k wherever P retains k
//	rule       a rule governs a: a grant's requests rule still takes it at P, its subject s (SpendState.Govern)
//	approver   the approver is still eligible under P
//	evidence   d.channel is in the governing evidence list, which the verifier must know
//
// SpendableSet adds §16.6's k approvers: decisions of one approval and one request_sha256 from distinct eligible
// approvers, at least the rule's k and meeting §8.6's admin clause, the budget the smallest uses and the expiry the
// earliest not_after. A gate adds the field comparison (SpendableAtGate): a carries only fields its kind's server column
// lets a server path see (QD-064), and those equal the gate's own request.
//
// A presence decision's signCount is never compared here, as a gate's and a reader's never are: a decision is spent
// many times over (its uses, its retries, each reader's check), so the spending daemon compares the count once, when
// the decision arrives (MCP-M3-05), with its PresenceCounter.
//
// Nothing here creates, derives or unwraps a key, and nothing linearizes, so nothing calls testHookSecret or
// testHookBarrier. Package-level functions are safe for concurrent use, and so is a SpendCheck. On every leg but the
// ios_extension legs, whose forwarding role spends no decision, the sidecar_http page Worker's included: root Id, no
// connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A decision does not spend: SpendRefusal says why.
var ErrSpendRefused = errors.New("approval decision does not spend")

// Why a decision does not spend, one value a step of §16.6's spendable. Stable text: vectors and records name these.
type SpendRefusalCode string

const (
	// P is a projection the spender knows forked (AD3).
	SpendRefusalForked SpendRefusalCode = "forked"
	// The signer resolves to no key P holds for the channel, or does not fit the channel.
	SpendRefusalSigner SpendRefusalCode = "signer"
	// The signature does not verify.
	SpendRefusalSignature SpendRefusalCode = "signature"
	// The decision denies.
	SpendRefusalVerdict SpendRefusalCode = "verdict"
	// The decision names another requester (AD1).
	SpendRefusalRequester SpendRefusalCode = "requester"
	// The decision hashes another action.
	SpendRefusalPayload SpendRefusalCode = "payload"
	// uses and scope disagree: a template under a single-use decision, or a multi-use decision of one action.
	SpendRefusalTemplate SpendRefusalCode = "template"
	// Past not_after.
	SpendRefusalExpired SpendRefusalCode = "expired"
	// auth_pin is malformed, ahead of P, or off P's chain where P retains its position.
	SpendRefusalPin SpendRefusalCode = "pin"
	// No rule governs the action at P that should: the rule is gone or no longer takes it.
	SpendRefusalRule SpendRefusalCode = "rule"
	// The approver is not eligible under P.
	SpendRefusalApprover SpendRefusalCode = "approver"
	// The channel is not in the governing evidence list.
	SpendRefusalEvidence SpendRefusalCode = "evidence"
	// This verifier does not know the governing evidence list, so no channel is in it.
	SpendRefusalEvidenceUnknown SpendRefusalCode = "evidence_unknown"
	// Decisions of more than one approval or request, or one approver twice.
	SpendRefusalSet SpendRefusalCode = "set"
	// Fewer distinct eligible approvers than the rule's k, or §8.6's admin clause unmet.
	SpendRefusalQuorum SpendRefusalCode = "quorum"
	// The action carries a field no server path may see, or its fields differ from the gate's request.
	SpendRefusalGateField SpendRefusalCode = "gate_field"
	// The inputs or the state cannot be judged: none given, or a state that holds no keys.
	SpendRefusalState SpendRefusalCode = "state"
)

// One refusal: its code and what did not hold, ids and positions only (I-13).
type SpendRefusal struct {
	Code SpendRefusalCode
	// nil for none
	Cause error
}

// ErrSpendRefused, the code and the cause.
func (self *SpendRefusal) Error() string {
	if self.Cause == nil {
		return fmt.Sprintf("%s: %s", ErrSpendRefused, self.Code)
	}
	return fmt.Sprintf("%s: %s: %s", ErrSpendRefused, self.Code, self.Cause)
}

// ErrSpendRefused and the cause.
func (self *SpendRefusal) Unwrap() []error {
	if self.Cause == nil {
		return []error{ErrSpendRefused}
	}
	return []error{ErrSpendRefused, self.Cause}
}

// A refusal with a cause, nil for none.
func spendRefuse(code SpendRefusalCode, cause error) *SpendRefusal {
	return &SpendRefusal{Code: code, Cause: cause}
}

// The code an error from this file carries, empty for nil or any other error.
func SpendRefusalCodeOf(err error) SpendRefusalCode {
	refusal := &SpendRefusal{}
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// The spend check's settings.
type SpendSettings struct {
	// How far past a decision's not_after_millis a client still spends it, for the clock skew between approver,
	// spender and server: §8.6's ±60 s, which every reader's GrantActivate check applies alike. A gate judges on its
	// own server time with none (SpendableAtGate). Non-positive allows none.
	DecisionSkew time.Duration
}

// §8.6's values.
func DefaultSpendSettings() *SpendSettings {
	return &SpendSettings{
		DecisionSkew: 60 * time.Second,
	}
}

// What a spend is judged on besides the decision and P. AD4: a gate's inputs hold no run id, agent id, recipient or
// preview, so this holds none either.
type SpendInput struct {
	// a, as stored: the action every decision hashes, a multi-use decision's template.
	Action *StoredCanonicalAction
	// s: the sidecar spending, at a gate the bearer token's ur_sidecar_id.
	Spender Id
	// The verifier's time: the daemon's clock, the gate's server time, or a log entry's time at a reader.
	Now time.Time
	// A use of the decision is reserved already, so spend step 3's expiry bounds the retry and this check skips its
	// own (§16.6's spend step 1).
	Reserved bool
}

// §16.6's spendable(d, a, s, P) on one decision: nil when d spends, else a *SpendRefusal. See the file header.
func Spendable(decision *StoredApprovalDecision, input *SpendInput, state SpendState, settings *SpendSettings) error {
	if settings == nil {
		settings = DefaultSpendSettings()
	}
	if refusal := spendCheckInputs(decision, input, state); refusal != nil {
		return refusal
	}
	if state.Forked() {
		return spendRefuse(SpendRefusalForked, nil)
	}
	if refusal := spendDecision(decision, input, state, settings.DecisionSkew); refusal != nil {
		return refusal
	}
	rule, err := state.Govern(input.Action, input.Spender, input.Now)
	if err != nil {
		return spendRefuse(SpendRefusalRule, err)
	}
	if refusal := spendUnderRule(decision, rule); refusal != nil {
		return refusal
	}
	return nil
}

// What k decisions spend for: the approval, the request, and the budget and expiry the set has.
type SpendBudget struct {
	ApprovalId    Id
	RequestSha256 [sha256.Size]byte
	// The smallest uses.
	Uses uint32
	// The earliest not_after_millis.
	NotAfterMillis int64
	// The distinct approvers, sorted.
	ApproverMemberIds []Id
}

// §16.6's k approvers: every decision spendable, all of one approval_id and request_sha256, each approver once, at
// least the governing rule's k of them and §8.6's admin clause met. The budget is the smallest uses and the expiry the
// earliest not_after. nil and a *SpendRefusal when the set does not spend.
func SpendableSet(decisions []*StoredApprovalDecision, input *SpendInput, state SpendState, settings *SpendSettings) (*SpendBudget, error) {
	return spendableSet(decisions, input, state, settings.decisionSkew())
}

// SpendableSet under a skew the caller fixes.
func spendableSet(decisions []*StoredApprovalDecision, input *SpendInput, state SpendState, skew time.Duration) (*SpendBudget, error) {
	if len(decisions) == 0 {
		return nil, spendRefuse(SpendRefusalSet, errors.New("no decision"))
	}
	for _, decision := range decisions {
		if refusal := spendCheckInputs(decision, input, state); refusal != nil {
			return nil, refusal
		}
	}
	if state.Forked() {
		return nil, spendRefuse(SpendRefusalForked, nil)
	}
	first := decisions[0].Decision
	if len(first.GetApprovalId()) != recordIdByteCount || len(first.GetRequestSha256()) != sha256.Size {
		return nil, spendRefuse(SpendRefusalSet, errors.New("a decision its parser did not check"))
	}
	budget := &SpendBudget{
		ApprovalId:     recordIdOf(first.GetApprovalId()),
		RequestSha256:  [sha256.Size]byte(first.GetRequestSha256()),
		Uses:           first.GetUses(),
		NotAfterMillis: first.GetNotAfterMillis(),
	}
	for _, decision := range decisions {
		body := decision.Decision
		if !bytes.Equal(body.GetApprovalId(), first.GetApprovalId()) || !bytes.Equal(body.GetRequestSha256(), first.GetRequestSha256()) {
			return nil, spendRefuse(SpendRefusalSet, errors.New("decisions of more than one request"))
		}
		approver := recordIdOf(body.GetApproverMemberId())
		if slices.Contains(budget.ApproverMemberIds, approver) {
			return nil, spendRefuse(SpendRefusalSet, fmt.Errorf("two decisions of approver %s", approver))
		}
		if refusal := spendDecision(decision, input, state, skew); refusal != nil {
			return nil, refusal
		}
		budget.ApproverMemberIds = append(budget.ApproverMemberIds, approver)
		budget.Uses = min(budget.Uses, body.GetUses())
		budget.NotAfterMillis = min(budget.NotAfterMillis, body.GetNotAfterMillis())
	}
	rule, err := state.Govern(input.Action, input.Spender, input.Now)
	if err != nil {
		return nil, spendRefuse(SpendRefusalRule, err)
	}
	for _, decision := range decisions {
		if refusal := spendUnderRule(decision, rule); refusal != nil {
			return nil, refusal
		}
	}
	if len(budget.ApproverMemberIds) < rule.ApproverCount() {
		return nil, spendRefuse(SpendRefusalQuorum, fmt.Errorf("%d of %d approvers", len(budget.ApproverMemberIds), rule.ApproverCount()))
	}
	if !rule.AdminClauseMet(budget.ApproverMemberIds) {
		return nil, spendRefuse(SpendRefusalQuorum, errors.New("a grant touching others needs an admin's approval"))
	}
	slices.SortFunc(budget.ApproverMemberIds, Id.Cmp)
	return budget, nil
}

// The skew, none for nil settings' defaults.
func (self *SpendSettings) decisionSkew() time.Duration {
	if self == nil {
		return DefaultSpendSettings().DecisionSkew
	}
	return self.DecisionSkew
}

// Refuses a call with nothing to judge.
func spendCheckInputs(decision *StoredApprovalDecision, input *SpendInput, state SpendState) *SpendRefusal {
	switch {
	case decision == nil || decision.Decision == nil || decision.Signed == nil:
		return spendRefuse(SpendRefusalState, errors.New("no decision"))
	case input == nil || input.Action == nil || input.Action.Action == nil:
		return spendRefuse(SpendRefusalState, errors.New("no action"))
	case state == nil:
		return spendRefuse(SpendRefusalState, errors.New("no state"))
	}
	return nil
}

// spendable's steps before "under P": signer, signature, verdict, requester, payload, template, expiry and pin.
func spendDecision(decision *StoredApprovalDecision, input *SpendInput, state SpendState, skew time.Duration) *SpendRefusal {
	body := decision.Decision
	signed := decision.Signed
	approver := recordIdOf(body.GetApproverMemberId())
	channel := protocol.ApprovalChannel(body.GetChannel())

	// the signer's key, by channel, then the signature over the bytes as received
	var signerId Id
	switch channel {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
		id, err := IdFromBytes(signed.GetSignerId())
		if err != nil || len(signed.GetKeyId()) != 0 {
			return spendRefuse(SpendRefusalSigner, errors.New("no sidecar's identity key signs it"))
		}
		signerId = id
		identityKey := state.IdentityKey(signerId)
		if identityKey == nil {
			return spendRefuse(SpendRefusalSigner, fmt.Errorf("sidecar %s has no identity key at P", signerId))
		}
		if err := decision.Verify(bridge.SignedKeyAlgEd25519, identityKey); err != nil {
			return spendRefuse(SpendRefusalSignature, err)
		}
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		key := state.PresenceKey(signed.GetKeyId(), approver)
		if key == nil {
			return spendRefuse(SpendRefusalSigner, fmt.Errorf("no live presence key of member %s under its key_id", approver))
		}
		if err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key, nil); err != nil {
			return spendRefuse(SpendRefusalSignature, err)
		}
	default:
		return spendRefuse(SpendRefusalSigner, fmt.Errorf("channel %d", body.GetChannel()))
	}
	if protocol.ApprovalVerdict(body.GetDecision()) != protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE {
		return spendRefuse(SpendRefusalVerdict, nil)
	}

	// the signer fits the channel
	switch channel {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE:
		if signerId == input.Spender {
			return spendRefuse(SpendRefusalSigner, errors.New("a device decision the spender signed itself"))
		}
		if !state.ApprovalCapable(signerId, approver) {
			return spendRefuse(SpendRefusalSigner, fmt.Errorf("sidecar %s is no approval-capable device of member %s", signerId, approver))
		}
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
		if signerId != input.Spender {
			return spendRefuse(SpendRefusalSigner, errors.New("a harness decision another sidecar signed"))
		}
		if !state.ApprovalCapable(signerId, approver) {
			return spendRefuse(SpendRefusalSigner, fmt.Errorf("sidecar %s is no approval-capable device of member %s", signerId, approver))
		}
	}

	if recordIdOf(body.GetRequesterSidecarId()) != input.Spender {
		return spendRefuse(SpendRefusalRequester, nil)
	}
	payloadSha256 := input.Action.PayloadSha256()
	if !bytes.Equal(body.GetPayloadSha256(), payloadSha256[:]) {
		return spendRefuse(SpendRefusalPayload, nil)
	}
	if (1 < body.GetUses()) != input.Action.Action.GetScope() {
		return spendRefuse(SpendRefusalTemplate, fmt.Errorf("uses %d, scope %t", body.GetUses(), input.Action.Action.GetScope()))
	}
	if !input.Reserved && body.GetNotAfterMillis()+max(0, skew.Milliseconds()) < input.Now.UnixMilli() {
		return spendRefuse(SpendRefusalExpired, nil)
	}

	pin := body.GetAuthPin()
	current := state.Pin()
	switch {
	case pin == nil || len(pin.GetChain()) != sha256.Size:
		return spendRefuse(SpendRefusalPin, errors.New("a malformed auth_pin"))
	case current == nil || current.GetVersion() < pin.GetVersion():
		return spendRefuse(SpendRefusalPin, fmt.Errorf("auth_pin %d is ahead of P", pin.GetVersion()))
	}
	if chain, retained := state.ChainAt(pin.GetVersion()); retained && !bytes.Equal(chain[:], pin.GetChain()) {
		return spendRefuse(SpendRefusalPin, fmt.Errorf("auth_pin %d is off P's chain", pin.GetVersion()))
	}
	return nil
}

// spendable's "under P": the approver still eligible and the channel in the governing evidence list.
func spendUnderRule(decision *StoredApprovalDecision, rule SpendRule) *SpendRefusal {
	body := decision.Decision
	if !rule.Eligible(recordIdOf(body.GetApproverMemberId())) {
		return spendRefuse(SpendRefusalApprover, nil)
	}
	evidence, known := rule.Evidence()
	if !known {
		return spendRefuse(SpendRefusalEvidenceUnknown, nil)
	}
	if !slices.Contains(evidence, protocol.ApprovalChannel(body.GetChannel())) {
		return spendRefuse(SpendRefusalEvidence, nil)
	}
	return nil
}

// What a server gate's own request shows of the action it acts on, which the action's fields must equal (§16.6's gate
// clause: host, port, audience, expiry, name and rdata). Kind picks which fields compare.
type SpendGateFields struct {
	Kind SidecarActionKind
	// A publish's host, port, audience and expiry. A request's audience of 0 compares as members, 1, since a publish's
	// action always writes the resolved value (plan-MCP-wire-enum-numbers).
	Host          string
	Port          uint32
	Audience      uint32
	ExpiresMillis int64
	// A DNS write's name, type, value (its rdata) and ttl (§12.8).
	DnsName  string
	DnsType  string
	DnsValue string
	DnsTtl   uint32
}

// The gate clause: the action is of the request's kind, carries no field its kind's server column does not let a
// server path see (QD-064, CheckCanonicalActionForServer), and every field the gate sees equals the request's. A dns
// action's optional value, ttl and expiry compare only where the action sets them, so a delete naming only its name
// and type matches a request that names the same.
func CheckSpendGateFields(action *StoredCanonicalAction, fields *SpendGateFields) error {
	if action == nil || action.Action == nil || fields == nil {
		return spendRefuse(SpendRefusalGateField, errors.New("nothing to compare"))
	}
	if err := CheckCanonicalActionForServer(action); err != nil {
		return spendRefuse(SpendRefusalGateField, err)
	}
	canonical := action.Action
	kind := SidecarActionKind(canonical.GetKind())
	if kind != fields.Kind {
		return spendRefuse(SpendRefusalGateField, fmt.Errorf("kind %d for a request of kind %d", kind, fields.Kind))
	}
	differ := func(name string) error {
		return spendRefuse(SpendRefusalGateField, fmt.Errorf("%s differs from the request's", name))
	}
	switch kind {
	case SidecarActionPublish:
		audience := fields.Audience
		if audience == uint32(protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED) {
			audience = uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS)
		}
		switch {
		case canonical.GetHost() != fields.Host:
			return differ("host")
		case canonical.GetPort() != fields.Port:
			return differ("port")
		case canonical.GetAudience() != audience:
			return differ("audience")
		case canonical.GetExpiresMillis() != fields.ExpiresMillis:
			return differ("expiry")
		}
	case SidecarActionDnsSet, SidecarActionDnsDelete:
		switch {
		case canonical.GetDnsName() != fields.DnsName:
			return differ("dns name")
		case canonical.GetDnsType() != fields.DnsType:
			return differ("dns type")
		case (canonical.GetDnsValue() != "" || kind == SidecarActionDnsSet) && canonical.GetDnsValue() != fields.DnsValue:
			return differ("dns value")
		case canonical.GetDnsTtl() != 0 && canonical.GetDnsTtl() != fields.DnsTtl:
			return differ("dns ttl")
		case canonical.GetExpiresMillis() != 0 && canonical.GetExpiresMillis() != fields.ExpiresMillis:
			return differ("expiry")
		}
	default:
		return spendRefuse(SpendRefusalGateField, fmt.Errorf("kind %d has no gate comparison", kind))
	}
	return nil
}

// A server gate's whole check at server time (§16.6's gate step 1, after its stored-result lookup): the gate clause,
// then SpendableSet with no skew, since the gate's own clock is the one decisions are judged by and a first
// presentation past not_after is refused there (§16.6's expiry row; §8.6's "gates use server time").
func SpendableAtGate(decisions []*StoredApprovalDecision, input *SpendInput, fields *SpendGateFields, state SpendState) (*SpendBudget, error) {
	if input == nil {
		return nil, spendRefuse(SpendRefusalState, errors.New("no action"))
	}
	if err := CheckSpendGateFields(input.Action, fields); err != nil {
		return nil, err
	}
	return spendableSet(decisions, input, state, 0)
}

// §16.6's spend check as ACL-M2-07's AclSpendCheck, which api and every reader install in ConfigLogSettings: the
// state is S(n-1), the state the entry lands on, its view TEAM's ConfigState, never forked, since a fork stops a log
// before any entry applies, and holding no evidenceDefault, which rows do not carry. Immutable once made.
type SpendCheck struct {
	settings *SpendSettings
}

// A spend check on settings, nil for the defaults.
func NewSpendCheck(settings *SpendSettings) *SpendCheck {
	if settings == nil {
		settings = DefaultSpendSettings()
	}
	return &SpendCheck{settings: settings}
}

// §16.6's check on S(n-1) at the entry's time. A state over any view but a ConfigState holds no keys, so it refuses.
func (self *SpendCheck) Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error {
	if state == nil {
		return spendRefuse(SpendRefusalState, errors.New("no state"))
	}
	config, ok := state.View().(*ConfigState)
	if !ok || config == nil {
		return spendRefuse(SpendRefusalState, errors.New("a state that holds no keys"))
	}
	if pin == nil || config.n != pin.GetVersion() || !bytes.Equal(config.chain[:], pin.GetChain()) {
		return spendRefuse(SpendRefusalState, errors.New("a pin other than the state's"))
	}
	spendState, err := NewConfigSpendState(config, false, nil)
	if err != nil {
		return spendRefuse(SpendRefusalState, err)
	}
	return Spendable(decision, &SpendInput{Action: action, Spender: spender, Now: now}, spendState, self.settings)
}
