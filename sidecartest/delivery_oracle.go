// FS-104's oracle (KEYS-M2-29; §10.9's delivery checks, §10.5's key holders, FI-28): one more verifier of a
// ReaderWrap or a DelegationWrap, which judges each delivery from the authorization log alone and shares no code
// with the members' checks. It is written from §10.5's and §10.9's text and imports only the protocol's types and
// bridge.VerifySigned, so a member check and this file never fail the same way for the same reason: a schedule holds
// every member's verdict to this one, and a mutant of the members' CheckDelivery shows as a difference.
//
// The log is what a schedule appends: each position's pin and the facts §7.9's state and §8.6's evaluation hold
// there, the rows of sidecars, members and Delegations, each repo's kind and readers with the time each stops
// reading, and the repos a tag's grants read. Nothing here reads a tip: a delivery is judged at its own pin, a
// STAGED one at gen/<g>'s, so a later revocation, key replacement or replay changes no verdict (§10.9's history
// row). What a judge brings is only where its log ends and where its previous base lies, which decide whether it
// judges at all: above its tip a delivery waits, before its previous base it is not judged.
//
//	body      the Signed verifies under the signer's admitted identity key at the judged state, as a ReaderWrap or
//	          a DelegationWrap by its path's recipient; group, generation and commitment are gen/<g>'s; the
//	          recipient and the first 8 bytes of recipient_key_sha256 are the path's
//	staged    no auth, no time; the signer is gen/<g>'s; the recipient is a key holder at gen/<g>'s auth and time
//	late      auth on the chain at or past gen/<g>'s version; gen/<g>'s time <= time <= the judge's clock + 60 s;
//	          the recipient a key holder at (auth, time); the signer one, or covered by a Delegation that is one,
//	          standing and not read_only
//	holders   leaf, agent, delegation, recovery and forwarding identities as §10.5 lists them, with their hash
//
// Not judged here: wrap_count against the staged objects, and whether the sealed key opens, which only the recipient
// can tell. A tree is judged from the roster a schedule reads off the epoch (JudgeRoster), since the oracle decodes
// no MLS.
//
// Not safe for concurrent use: one schedule appends and judges.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purposes §6.11 signs gkm's objects under, and the identity bytes' kinds (§10.5): identifiers of the format.
const (
	deliveryOraclePurposeWrap      = "reader-wrap"
	deliveryOraclePurposeGenRotate = "gen-rotate"

	deliveryOracleKindLeaf       byte = 1
	deliveryOracleKindAgent      byte = 2
	deliveryOracleKindDelegation byte = 3
	deliveryOracleKindRecovery   byte = 4
	deliveryOracleKindForwarding byte = 5

	deliveryOracleStaged uint32 = 1
	deliveryOracleLate   uint32 = 2
)

// What the oracle holds a judge's clock to. The defaults are the protocol's (§10.9's time rows).
type DeliveryOracleSettings struct {
	// How far past the judge's clock a LATE delivery's time may lie before it waits: 60 s.
	ClockSkew time.Duration
}

func DefaultDeliveryOracleSettings() *DeliveryOracleSettings {
	return &DeliveryOracleSettings{
		ClockSkew: 60 * time.Second,
	}
}

// A 16-byte id as the log's rows carry it: a sidecar's, a member's, a repo's or a tag atom's.
type DeliveryOracleId [16]byte

// The id in bytes, false for another size.
func DeliveryOracleIdOf(idBytes []byte) (DeliveryOracleId, bool) {
	id := DeliveryOracleId{}
	if len(idBytes) != len(id) {
		return id, false
	}
	copy(id[:], idBytes)
	return id, true
}

// One repo at one position.
type DeliveryOracleRepo struct {
	Kind protocol.RepoKind
	// Every sidecar §8.6 lets read the repo there, with the time it stops reading; the zero time for one that reads
	// at every time.
	Readers map[DeliveryOracleId]time.Time
}

// A signer whose records a compromise cascade voids from a position on (§7.9's cascade).
type DeliveryOracleVoid struct {
	Signer []byte
	From   uint64
}

// One position of the log, as facts.
type DeliveryOracleState struct {
	// (n, A_n).
	Pin         *bridge.AuthPin
	Sidecars    []*bridge.SidecarRow
	Members     []*bridge.MemberRow
	Delegations []*bridge.DelegationRow
	Repos       map[DeliveryOracleId]*DeliveryOracleRepo
	// By tag atom, the repos a read or write grant naming it reads there.
	AtomRepos map[DeliveryOracleId][]DeliveryOracleId
	Voids     []*DeliveryOracleVoid
}

// The row of a sidecar, nil for one the position never admitted.
func (self *DeliveryOracleState) sidecar(sidecarId []byte) *bridge.SidecarRow {
	for _, row := range self.Sidecars {
		if bytes.Equal(row.GetSidecarId(), sidecarId) {
			return row
		}
	}
	return nil
}

// Whether a cascade voids a record by signer carried at position at.
func (self *DeliveryOracleState) voids(signer []byte, at uint64) bool {
	for _, void := range self.Voids {
		if bytes.Equal(void.Signer, signer) && void.From <= at {
			return true
		}
	}
	return false
}

// Whether a sidecar reads the repo at the time given.
func (self *DeliveryOracleState) reads(repo *DeliveryOracleRepo, sidecarId []byte, at time.Time) bool {
	id, ok := DeliveryOracleIdOf(sidecarId)
	if !ok {
		return false
	}
	until, reads := repo.Readers[id]
	return reads && (until.IsZero() || at.Before(until))
}

// What the oracle answers of one delivery.
type DeliveryOracleVerdictKind int

const (
	// Every row holds at the delivery's own state.
	DeliveryOracleValid DeliveryOracleVerdictKind = iota
	// A row fails: the delivery poisons its generation for whoever reads it.
	DeliveryOracleInvalid
	// Its pin is above the judge's tip, or its time past the judge's clock: judged once the log or the clock reaches
	// it.
	DeliveryOracleWaits
	// Its pin is before the judge's previous base: not judged, and held against no one.
	DeliveryOracleNotJudged
)

func (self DeliveryOracleVerdictKind) String() string {
	switch self {
	case DeliveryOracleValid:
		return "valid"
	case DeliveryOracleInvalid:
		return "invalid"
	case DeliveryOracleWaits:
		return "waits"
	case DeliveryOracleNotJudged:
		return "not judged"
	}
	return fmt.Sprintf("verdict %d", int(self))
}

// One verdict.
type DeliveryOracleVerdict struct {
	Kind DeliveryOracleVerdictKind
	// With Invalid: the pin lies off the log's chain, which is a fork as well.
	Fork bool
	// The signer the delivery names, which a poisoned generation's alarm names; empty where the body names none.
	SignerId []byte
	// Which row failed, or what is waited for.
	Reason string
}

func (self DeliveryOracleVerdict) String() string {
	if self.Reason == "" {
		return self.Kind.String()
	}
	return self.Kind.String() + ": " + self.Reason
}

// One delivery and the judge it is judged for.
type DeliveryOracleCase struct {
	RepoId DeliveryOracleId
	// The stored wrap object: a Signed ReaderWrap or DelegationWrap.
	Delivery []byte
	// The stored gen/<g>: a Signed GenRotate.
	Generation []byte
	// The last two segments of the wrap/ path the delivery lies at: its recipient, s:<sidecar_id> or
	// d:<delegation_id> in hex, and k8.
	PathRecipient string
	PathKey8      string
	// Where the judge's log ends. 0: the oracle's whole log.
	Tip uint64
	// The judge's previous base: a pin below it is not judged. 0: it judges from the first position.
	PreviousBase uint64
	// The judge's clock.
	Now time.Time
}

// The oracle. See the file header.
type DeliveryOracle struct {
	settings *DeliveryOracleSettings
	// by version - 1
	states []*DeliveryOracleState
}

// nil settings take the defaults.
func NewDeliveryOracle(settings *DeliveryOracleSettings) *DeliveryOracle {
	if settings == nil {
		settings = DefaultDeliveryOracleSettings()
	}
	return &DeliveryOracle{settings: settings}
}

// Appends the log's next position. Its pin's version must be the next one.
func (self *DeliveryOracle) Append(state *DeliveryOracleState) error {
	if state == nil {
		return fmt.Errorf("delivery oracle: no position appended where %d belongs", len(self.states)+1)
	}
	if state.Pin.GetVersion() != uint64(len(self.states))+1 {
		return fmt.Errorf("delivery oracle: position %d appended where %d belongs", state.Pin.GetVersion(), len(self.states)+1)
	}
	self.states = append(self.states, state)
	return nil
}

// How many positions the oracle holds.
func (self *DeliveryOracle) Tip() uint64 {
	return uint64(len(self.states))
}

// The state a pin names for a judge whose log ends at tip and whose previous base is previousBase, or the verdict
// that takes its place: waits above the tip, not judged before the base, invalid and a fork off the chain.
func (self *DeliveryOracle) stateAt(pin *bridge.AuthPin, tip uint64, previousBase uint64) (*DeliveryOracleState, *DeliveryOracleVerdict) {
	if tip == 0 || self.Tip() < tip {
		tip = self.Tip()
	}
	version := pin.GetVersion()
	if version == 0 || len(pin.GetChain()) != sha256.Size {
		return nil, &DeliveryOracleVerdict{Kind: DeliveryOracleInvalid, Reason: "no auth pin"}
	}
	if tip < version {
		return nil, &DeliveryOracleVerdict{Kind: DeliveryOracleWaits, Reason: fmt.Sprintf("pin %d above the judge's tip %d", version, tip)}
	}
	if version < previousBase {
		return nil, &DeliveryOracleVerdict{Kind: DeliveryOracleNotJudged, Reason: fmt.Sprintf("pin %d before the judge's previous base %d", version, previousBase)}
	}
	state := self.states[version-1]
	if !bytes.Equal(state.Pin.GetChain(), pin.GetChain()) {
		return nil, &DeliveryOracleVerdict{Kind: DeliveryOracleInvalid, Fork: true, Reason: fmt.Sprintf("pin %d off the chain", version)}
	}
	return state, nil
}

// One key holder's identity bytes: the kind byte, then its id (§10.5).
func deliveryOracleIdentity(kind byte, id []byte) string {
	return string(append([]byte{kind}, id...))
}

// live(d) at a state and time (§10.5): not ended, its key not dropped, before its not_after, and no cascade voiding
// it. A forwarding Delegation is no delegation(d).
func (self *DeliveryOracleState) delegationLive(row *bridge.DelegationRow, at time.Time) bool {
	if len(row.GetDelegationId()) != sha256.Size || len(row.GetForwardSidecarId()) != 0 {
		return false
	}
	if row.GetEndedAt() != 0 || row.GetKeyDroppedAt() != 0 {
		return false
	}
	if row.GetNotAfter() == 0 || row.GetNotAfter() <= at.UnixMilli() {
		return false
	}
	return !self.voids(row.GetSigner(), row.GetAt())
}

// Whether reach(d) holds the repo (§10.5): the config and a directory always, any other where a grant naming one of
// d's tags reads it.
func (self *DeliveryOracleState) delegationReaches(row *bridge.DelegationRow, repoId DeliveryOracleId, repo *DeliveryOracleRepo) bool {
	if repo.Kind == protocol.RepoKind_REPO_KIND_CONFIG || repo.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		return true
	}
	for _, atomBytes := range row.GetTagAtoms() {
		atom, ok := DeliveryOracleIdOf(atomBytes)
		if !ok {
			continue
		}
		if slices.Contains(self.AtomRepos[atom], repoId) {
			return true
		}
	}
	return false
}

// KeyHolders(R, S, t) as a set of identity bytes (§10.5), false for a repo the state does not hold.
func (self *DeliveryOracleState) holders(repoId DeliveryOracleId, at time.Time) (map[string]bool, bool) {
	repo := self.Repos[repoId]
	if repo == nil {
		return nil, false
	}
	holders := map[string]bool{}
	// delegation(d)
	holdingDelegationIds := map[string]bool{}
	for _, row := range self.Delegations {
		if self.delegationLive(row, at) && self.delegationReaches(row, repoId, repo) {
			holdingDelegationIds[string(row.GetDelegationId())] = true
			holders[deliveryOracleIdentity(deliveryOracleKindDelegation, row.GetDelegationId())] = true
		}
	}
	// forward(s), in the config alone: each sidecar's newest forwarding Delegation that neither ended nor was
	// superseded, while the sidecar reads the config and its key stands
	if repo.Kind == protocol.RepoKind_REPO_KIND_CONFIG {
		newest := map[string]*bridge.DelegationRow{}
		for _, row := range self.Delegations {
			if len(row.GetForwardSidecarId()) == 0 || row.GetEndedAt() != 0 || row.GetSupersededAt() != 0 {
				continue
			}
			sidecarKey := string(row.GetForwardSidecarId())
			held := newest[sidecarKey]
			if held == nil || held.GetAt() < row.GetAt() || (held.GetAt() == row.GetAt() && bytes.Compare(held.GetDelegationId(), row.GetDelegationId()) < 0) {
				newest[sidecarKey] = row
			}
		}
		for sidecarKey, row := range newest {
			standing := row.GetKeyDroppedAt() == 0 && len(row.GetDelegationId()) == sha256.Size && len(row.GetReaderKeySha256()) == sha256.Size &&
				!self.voids(row.GetSigner(), row.GetAt())
			if standing && self.reads(repo, []byte(sidecarKey), at) {
				holders[deliveryOracleIdentity(deliveryOracleKindForwarding, []byte(sidecarKey))] = true
			}
		}
	}
	// leaf(s), agent(s) and the members they read for
	readingMembers := map[string]bool{}
	for readerId := range repo.Readers {
		if !self.reads(repo, readerId[:], at) {
			continue
		}
		row := self.sidecar(readerId[:])
		if row == nil {
			continue
		}
		if len(row.GetTagIds()) == 0 && len(row.GetMemberId()) == len(readerId) && !row.GetEphemeral() {
			holders[deliveryOracleIdentity(deliveryOracleKindLeaf, readerId[:])] = true
			readingMembers[string(row.GetMemberId())] = true
			continue
		}
		if admitting := row.GetDelegationId(); 0 < len(admitting) && holdingDelegationIds[string(admitting)] {
			// covered: it reads through its Delegation's wrap
			continue
		}
		holders[deliveryOracleIdentity(deliveryOracleKindAgent, readerId[:])] = true
	}
	// recovery(m): the binding in effect is the member's newest, and no cascade voids it
	for _, member := range self.Members {
		if !readingMembers[string(member.GetMemberId())] {
			continue
		}
		bindings := member.GetBindings()
		if len(member.GetRecoveryKeySha256()) == 0 || len(bindings) == 0 {
			continue
		}
		if bytes.Equal(bindings[0].GetKeySha256(), member.GetRecoveryKeySha256()) && !self.voids(bindings[0].GetSigner(), bindings[0].GetAt()) {
			holders[deliveryOracleIdentity(deliveryOracleKindRecovery, member.GetMemberId())] = true
		}
	}
	return holders, true
}

// holders_sha256 of the repo at a pin and time as the oracle computes it (QD-465): the identities sorted as bytes
// and joined. False where the oracle's log does not hold the pin or the repo. A schedule compares it with each
// gen/<g>'s, which holds the oracle's key holders to the rotators'.
func (self *DeliveryOracle) HoldersSha256(repoId DeliveryOracleId, pin *bridge.AuthPin, at time.Time) ([]byte, bool) {
	state, verdict := self.stateAt(pin, 0, 0)
	if verdict != nil {
		return nil, false
	}
	holders, ok := state.holders(repoId, at)
	if !ok {
		return nil, false
	}
	identities := make([]string, 0, len(holders))
	for identity := range holders {
		identities = append(identities, identity)
	}
	slices.Sort(identities)
	hasher := sha256.New()
	for _, identity := range identities {
		hasher.Write([]byte(identity))
	}
	return hasher.Sum(nil), true
}

// A Signed and its body, verified under the signer's identity key as state admits it.
func deliveryOracleVerify(state *DeliveryOracleState, signedBytes []byte, purpose string, signedType bridge.SignedType) (*bridge.Signed, string) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, "the object is no Signed"
	}
	row := state.sidecar(signed.GetSignerId())
	if row == nil || len(row.GetIdentityPublicKey()) == 0 {
		return signed, "the signer has no admitted identity key at the judged state"
	}
	if err := bridge.VerifySigned(signed, purpose, signedType, bridge.SignedKeyAlgEd25519, row.GetIdentityPublicKey()); err != nil {
		return signed, "the signature does not verify under the signer's admitted identity key"
	}
	return signed, ""
}

// Judges one delivery at its own state: see the file header.
func (self *DeliveryOracle) Judge(c *DeliveryOracleCase) DeliveryOracleVerdict {
	invalid := func(signerId []byte, format string, args ...any) DeliveryOracleVerdict {
		return DeliveryOracleVerdict{Kind: DeliveryOracleInvalid, SignerId: bytes.Clone(signerId), Reason: fmt.Sprintf(format, args...)}
	}
	// the path says which delivery this is
	prefix, recipientHex, found := strings.Cut(c.PathRecipient, ":")
	pathRecipient, err := hex.DecodeString(recipientHex)
	if !found || err != nil {
		return invalid(nil, "a path that names no recipient")
	}
	var signedType bridge.SignedType
	switch {
	case prefix == "s" && len(pathRecipient) == len(DeliveryOracleId{}):
		signedType = bridge.SignedType_SIGNED_READER_WRAP
	case prefix == "d" && len(pathRecipient) == sha256.Size:
		signedType = bridge.SignedType_SIGNED_DELEGATION_WRAP
	default:
		return invalid(nil, "a path that names no recipient")
	}

	// the bodies, before any signature: they name the pins the signatures are judged at
	deliverySigned := &bridge.Signed{}
	if err := proto.Unmarshal(c.Delivery, deliverySigned); err != nil {
		return invalid(nil, "the delivery is no Signed")
	}
	signerId := deliverySigned.GetSignerId()
	body := &protocol.KeyDelivery{}
	switch signedType {
	case bridge.SignedType_SIGNED_READER_WRAP:
		wrap := &protocol.ReaderWrap{}
		if err := proto.Unmarshal(deliverySigned.GetBody(), wrap); err != nil || wrap.GetWrap() == nil {
			return invalid(signerId, "the delivery's body is no ReaderWrap")
		}
		body = wrap.GetWrap()
	case bridge.SignedType_SIGNED_DELEGATION_WRAP:
		wrap := &protocol.DelegationWrap{}
		if err := proto.Unmarshal(deliverySigned.GetBody(), wrap); err != nil || wrap.GetWrap() == nil {
			return invalid(signerId, "the delivery's body is no DelegationWrap")
		}
		body = wrap.GetWrap()
	}
	generationSigned := &bridge.Signed{}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(c.Generation, generationSigned); err != nil {
		return invalid(signerId, "gen/<g> is no Signed")
	}
	if err := proto.Unmarshal(generationSigned.GetBody(), rotate); err != nil {
		return invalid(signerId, "gen/<g>'s body is no GenRotate")
	}

	// body: the delivery is of gen/<g>, of this repo, and its path's
	if !bytes.Equal(body.GetGroupId(), rotate.GetGroupId()) || body.GetGeneration() != rotate.GetGeneration() ||
		!bytes.Equal(body.GetCommitment(), rotate.GetCommitment()) {
		return invalid(signerId, "the delivery names another group, generation or commitment than gen/<g>")
	}
	if !bytes.Equal(rotate.GetRepoId(), c.RepoId[:]) {
		return invalid(signerId, "gen/<g> is another repo's")
	}
	if !bytes.Equal(body.GetRecipient(), pathRecipient) {
		return invalid(signerId, "the delivery's recipient is not its path's")
	}
	keySha256 := body.GetRecipientKeySha256()
	if len(keySha256) != sha256.Size || hex.EncodeToString(keySha256[:8]) != c.PathKey8 {
		return invalid(signerId, "the delivery's key digest is not its path's k8")
	}

	// judged: gen/<g> at its own pin first, since a STAGED delivery is its claim's
	generationState, verdict := self.stateAt(rotate.GetAuth(), c.Tip, c.PreviousBase)
	if verdict != nil && verdict.Kind == DeliveryOracleInvalid {
		verdict.SignerId = bytes.Clone(signerId)
		return *verdict
	}
	pin := rotate.GetAuth()
	at := time.UnixMilli(rotate.GetTimeMs())
	late := false
	switch body.GetDeliveryKind() {
	case deliveryOracleStaged:
		if body.GetAuth() != nil || body.GetTimeMs() != 0 {
			return invalid(signerId, "a STAGED delivery with an auth pin or a time")
		}
		if !bytes.Equal(signerId, generationSigned.GetSignerId()) {
			return invalid(signerId, "a STAGED delivery by another than gen/<g>'s signer")
		}
	case deliveryOracleLate:
		late = true
		pin = body.GetAuth()
		if pin.GetVersion() < rotate.GetAuth().GetVersion() {
			return invalid(signerId, "a LATE delivery's pin %d below gen/<g>'s %d", pin.GetVersion(), rotate.GetAuth().GetVersion())
		}
		if body.GetTimeMs() < rotate.GetTimeMs() {
			return invalid(signerId, "a LATE delivery before gen/<g>'s time")
		}
		at = time.UnixMilli(body.GetTimeMs())
	default:
		return invalid(signerId, "delivery kind %d", body.GetDeliveryKind())
	}
	state, verdict := self.stateAt(pin, c.Tip, c.PreviousBase)
	if verdict != nil {
		verdict.SignerId = bytes.Clone(signerId)
		return *verdict
	}
	if generationState == nil {
		// gen/<g>'s pin lies before the judge's previous base while the delivery's does not: its signature is read
		// at the delivery's state, where an admitted sidecar keeps its identity key
		generationState = state
	}
	if late && c.Now.Add(self.settings.ClockSkew).UnixMilli() < body.GetTimeMs() {
		return DeliveryOracleVerdict{Kind: DeliveryOracleWaits, SignerId: bytes.Clone(signerId), Reason: "a LATE delivery's time past the judge's clock"}
	}

	// the signatures, under the identity keys the judged states admit
	if _, reason := deliveryOracleVerify(generationState, c.Generation, deliveryOraclePurposeGenRotate, bridge.SignedType_SIGNED_GEN_ROTATE); reason != "" {
		return invalid(signerId, "gen/<g>: %s", reason)
	}
	if _, reason := deliveryOracleVerify(state, c.Delivery, deliveryOraclePurposeWrap, signedType); reason != "" {
		return invalid(signerId, "the delivery: %s", reason)
	}

	// the recipient, a key holder by its wrap's type at the delivery's state and time
	holders, ok := state.holders(c.RepoId, at)
	if !ok {
		return invalid(signerId, "the state at the pin holds no such repo")
	}
	switch signedType {
	case bridge.SignedType_SIGNED_READER_WRAP:
		if !holders[deliveryOracleIdentity(deliveryOracleKindLeaf, pathRecipient)] && !holders[deliveryOracleIdentity(deliveryOracleKindAgent, pathRecipient)] {
			return invalid(signerId, "a ReaderWrap to no key holder at its state")
		}
	case bridge.SignedType_SIGNED_DELEGATION_WRAP:
		held := holders[deliveryOracleIdentity(deliveryOracleKindDelegation, pathRecipient)]
		if !held {
			// a sidecar's live forwarding Delegation, whose holder is the sidecar's forwarding identity
			for _, row := range state.Delegations {
				if bytes.Equal(row.GetDelegationId(), pathRecipient) && len(row.GetForwardSidecarId()) != 0 &&
					row.GetEndedAt() == 0 && row.GetSupersededAt() == 0 &&
					holders[deliveryOracleIdentity(deliveryOracleKindForwarding, row.GetForwardSidecarId())] {
					held = true
				}
			}
		}
		if !held {
			return invalid(signerId, "a DelegationWrap to no live Delegation at its state")
		}
	}

	// a LATE delivery's signer: a holder, or covered by a Delegation that is one, standing and not read_only
	if late {
		row := state.sidecar(signerId)
		if row == nil || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
			return invalid(signerId, "a LATE delivery by a signer that is unadmitted, revoked or parked at its state")
		}
		if row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0 {
			return invalid(signerId, "a LATE delivery by a read_only signer")
		}
		holds := holders[deliveryOracleIdentity(deliveryOracleKindLeaf, signerId)] || holders[deliveryOracleIdentity(deliveryOracleKindAgent, signerId)]
		if !holds {
			repo := state.Repos[c.RepoId]
			admitting := row.GetDelegationId()
			holds = 0 < len(admitting) && holders[deliveryOracleIdentity(deliveryOracleKindDelegation, admitting)] && state.reads(repo, signerId, at)
		}
		if !holds {
			return invalid(signerId, "a LATE delivery by a signer that holds no key at its state")
		}
	}
	return DeliveryOracleVerdict{Kind: DeliveryOracleValid, SignerId: bytes.Clone(signerId)}
}

// Judges the tree a generation's leaf wrap, or a commit's GenWrap, lies under (§10.9's roster row): every leaf of the
// roster, by sidecar id, is a leaf identity among the key holders at the pin and time given, a rotation's or a
// commit header's. The roster is what a schedule reads off the epoch, since the oracle decodes no MLS. Invalid names
// the first leaf outside the holders.
func (self *DeliveryOracle) JudgeRoster(repoId DeliveryOracleId, pin *bridge.AuthPin, at time.Time, rosterSidecarIds [][]byte, tip uint64, previousBase uint64) DeliveryOracleVerdict {
	state, verdict := self.stateAt(pin, tip, previousBase)
	if verdict != nil {
		return *verdict
	}
	holders, ok := state.holders(repoId, at)
	if !ok {
		return DeliveryOracleVerdict{Kind: DeliveryOracleInvalid, Reason: "the state at the pin holds no such repo"}
	}
	for _, leafId := range rosterSidecarIds {
		if !holders[deliveryOracleIdentity(deliveryOracleKindLeaf, leafId)] {
			return DeliveryOracleVerdict{
				Kind:   DeliveryOracleInvalid,
				Reason: fmt.Sprintf("the tree holds leaf %s, no key holder at the state", hex.EncodeToString(leafId)),
			}
		}
	}
	return DeliveryOracleVerdict{Kind: DeliveryOracleValid}
}

// The newest generation among deliveries, by generation, that holds a delivery the recipient named in its path could
// be handed: the part of the model's Reach the store's wrap paths decide (DESIGN-DETAILS 6.3), which a schedule
// joins with what the removed device's own MLS state opens. wrapPaths are gkm's wrap/ keys under one group.
func DeliveryOracleWrapReach(wrapPaths []string, pathRecipient string) uint64 {
	reach := uint64(0)
	for _, path := range wrapPaths {
		// gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8>
		parts := strings.Split(path, "/")
		if len(parts) != 7 || parts[2] != "wrap" || parts[5] != pathRecipient {
			continue
		}
		generation, err := strconv.ParseUint(parts[3], 10, 64)
		if err != nil {
			continue
		}
		reach = max(reach, generation)
	}
	return reach
}
