// §10.4's admission and §10.9's verdicts, the part of the member checks every other part rests on (KEYS-M2-19,
// DESIGN-DETAILS 6.2.3 and 6.7): a credential is admitted only through the log, its identity key is pinned to its
// sidecar_id and a second key is refused, and each check of a commit, a rotation or a delivery answers one
// GkmVerdict, judged at the object's own pin, never at this device's tip (R1).
//
//	admitted   the credential's sidecar has a row in the state, its identity key is the one the log admits for it,
//	           and its admission_sha256 is the row's: what the engine asks of every leaf it takes in, a KeyPackage's,
//	           a path's, a tree's and an external joiner's, since a tree may still hold a leaf whose Remove is due
//	standing   admitted, and neither revoked nor parked at that state: what an Add and an external join need
//	pin        the identity key the log admits for a sidecar is its pin, which a revoked sidecar keeps for what it
//	           signed before; §6's Hello reads the same pin (CheckMlsIdentityPin)
//	judged     a pin above the state waits (ErrGkmAuthAhead, an error and never a refusal); one before what this
//	           reader retains is not judged and counts against no one, so its verdict passes with NotJudged set;
//	           one off the chain is invalid and a fork
//
// A reading: §7.9 keeps A_k only for a day or two of entries while a generation lives up to 30 days and an epoch
// as long, so a device meets objects whose pins it no longer retains as a matter of course, a late joiner's first
// generation among them. Such an object passes, as gkm_gate.go reads the same pin for coverage: the members that
// held the log then judged it when it was new, and this device's own commits, rotations and deliveries are still
// fenced at its own pin (R3 to R6), where nothing unjudged can carry a non-holder forward.
//
// gkm sees no proposal (owner decision 59), so these checks are the only authority check of a commit: a bug here adds
// a reader. They are pure functions over GkmAuthView, on every leg. Nothing here creates, derives or unwraps a key
// but CheckCommit's GenWrap and GkmUseDelivery's delivery, which the ladder's own functions hook.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The skew a member allows a statement's time past its own clock (§10.9's time rows): 60 s, a value every member
// holds alike, since a looser member would adopt what a stricter one still waits for.
const GkmMemberClockSkew = 60 * time.Second

// A KeyPackage's life, which a credential's not_after is its signing time plus (QD-057): the stale rule reads the
// leaf's last change back out of it.
const gkmCredentialLifetime = 90 * 24 * time.Hour

var (
	// A statement's time is past this device's clock and skew: it waits and is judged again, and never poisons,
	// since a skewed rotator can pass gkm's 10 minutes (§10.9's time row).
	ErrGkmTimeAhead = errors.New("gkm: a statement's time is ahead of this clock")
	// A credential the log does not admit, or admits under another key or admission.
	ErrGkmNotAdmitted = errors.New("gkm: credential not admitted")
)

// Why a check refused, as an alarm names it. Opaque words only (I-13).
type GkmRefusalReason string

const (
	GkmRefusalNone GkmRefusalReason = ""
	// The pin lies off this device's chain: invalid, and a fork alarm.
	GkmRefusalFork GkmRefusalReason = "auth_off_chain"
	// A pin below a floor: the previous epoch's, the carried generation's or the parent's (R2).
	GkmRefusalPinFloor GkmRefusalReason = "pin_below_floor"
	// The header, statement or body is not what its object says.
	GkmRefusalMalformed GkmRefusalReason = "malformed"
	// The committer may not make this commit (§10.9's committer rows).
	GkmRefusalCommitter GkmRefusalReason = "committer"
	// An Add of a device the state does not let in: unadmitted, revoked, parked, no reader, unconsented, not
	// leaf-entitled, or past the seats.
	GkmRefusalAdd GkmRefusalReason = "add"
	// A Remove with no input the state shows.
	GkmRefusalRemove GkmRefusalReason = "remove"
	// The new tree holds a leaf outside the key holders at the commit's pin (R3).
	GkmRefusalRoster GkmRefusalReason = "roster"
	// The carried generation or its GenWrap is not gen/<g>'s (R4).
	GkmRefusalGenWrap GkmRefusalReason = "gen_wrap"
	// A credential the log does not admit, or a second identity key.
	GkmRefusalCredential GkmRefusalReason = "credential"
	// The rotation's signer may not rotate.
	GkmRefusalSigner GkmRefusalReason = "signer"
	// parent_commitment, the generation number or the ids do not chain.
	GkmRefusalChain GkmRefusalReason = "chain"
	// holders_sha256 differs from this device's recomputation, or a leaf_wrap's tree holds a non-holder.
	GkmRefusalHolders GkmRefusalReason = "holders"
	// The cause is not the one the state requires.
	GkmRefusalCause GkmRefusalReason = "cause"
	// A time below the parent's or the generation's, or a drop key's life out of bounds.
	GkmRefusalTime GkmRefusalReason = "time"
	// A delivery to a recipient outside the holders it is judged against, or by a signer that may not deliver.
	GkmRefusalDelivery GkmRefusalReason = "delivery"
)

// What a member check answers of one commit, rotation or delivery. The zero value passes.
type GkmVerdict struct {
	// A check failed: never adopt the object, never encrypt to its epoch or generation, and alarm refused.
	Refused bool
	// The generation a refusal poisons (§10.9's poisoned row): never seal to it again, rotate at once with cause
	// REMOVE, and the next leaf commit removes its maker. 0 for none.
	Poisoned uint64
	// The object's pin lies before what this reader retains: not judged and held against no one. It passes.
	NotJudged bool
	// The pin is off this device's chain: head_alarm (fork), with Refused.
	Fork   bool
	Reason GkmRefusalReason
	// What failed, for the alarm's text: ids and positions only.
	Detail string
}

// Whether the object may be adopted or used: not refused. One this reader could not judge passes.
func (self GkmVerdict) Passed() bool {
	return !self.Refused
}

// A refusal for reason.
func gkmRefuse(reason GkmRefusalReason, format string, args ...any) GkmVerdict {
	return GkmVerdict{Refused: true, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// §10.9's judged row for one pin: the state at it, or why nothing is judged there. A pin above the tip is an error
// to wait on; one off the chain a refusal and a fork; one not retained a verdict that judges nothing.
func gkmJudgedView(view GkmAuthView, pin *bridge.AuthPin) (GkmAuthView, GkmVerdict, error) {
	if view == nil {
		return nil, GkmVerdict{}, fmt.Errorf("%w: no verified state", ErrGkmUnavailable)
	}
	if pin == nil || pin.GetVersion() == 0 || len(pin.GetChain()) != gkmAuthChainByteCount {
		return nil, gkmRefuse(GkmRefusalMalformed, "no auth pin"), nil
	}
	at, err := view.At(pin)
	switch {
	case err == nil:
		return at, GkmVerdict{}, nil
	case errors.Is(err, ErrGkmAuthAhead):
		return nil, GkmVerdict{}, fmt.Errorf("%w: pin %d above the state's %d", ErrGkmAuthAhead, pin.GetVersion(), view.Pin().GetVersion())
	case errors.Is(err, ErrGkmAuthNotRetained):
		return nil, GkmVerdict{NotJudged: true, Detail: fmt.Sprintf("pin %d before what is retained", pin.GetVersion())}, nil
	}
	verdict := gkmRefuse(GkmRefusalFork, "pin %d off the chain", pin.GetVersion())
	verdict.Fork = true
	return nil, verdict, nil
}

// §10.9's time rows: a statement's time against this clock. Ahead of it by more than the skew waits.
func gkmCheckNotAhead(timeMs int64, now time.Time) error {
	if now.Add(GkmMemberClockSkew).UnixMilli() < timeMs {
		return fmt.Errorf("%w: %d ms", ErrGkmTimeAhead, timeMs-now.UnixMilli())
	}
	return nil
}

// Whether a row is a member device (§7.9's leaves row): untagged, naming a member, and not ephemeral.
func gkmRowMemberDevice(row *bridge.SidecarRow) bool {
	return row != nil && len(row.GetTagIds()) == 0 && len(row.GetMemberId()) == len(Id{}) && !row.GetEphemeral()
}

// Whether a row is a read_only device's (D-TEAM-24): it signs no rotation, delivery, Add or Remove.
func gkmRowReadOnly(row *bridge.SidecarRow) bool {
	return row != nil && row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0
}

// Whether a row stands at its state: admitted, and neither revoked nor parked.
func gkmRowStanding(row *bridge.SidecarRow) bool {
	return row != nil && row.GetRevokedAt() == 0 && row.GetParkedAt() == 0
}

// §10.4's admission of one credential at a state: its sidecar has a row there, the identity key it names is the
// one the log admits for that sidecar, so a second key is refused (ErrMlsIdentityPin), and its admission_sha256 is
// the row's. A revoked or parked sidecar's credential is still admitted, for the leaves a tree holds until their
// Remove; GkmCredentialStanding is what an Add needs.
func GkmCredentialAdmitted(view GkmAuthView, credential *protocol.UrMlsCredential) error {
	if view == nil || credential == nil {
		return fmt.Errorf("%w: no state or credential", ErrGkmNotAdmitted)
	}
	sidecarId, err := IdFromBytes(credential.GetSidecarId())
	if err != nil {
		return fmt.Errorf("%w: sidecar_id", ErrGkmNotAdmitted)
	}
	row := view.SidecarRow(sidecarId)
	if row == nil {
		return fmt.Errorf("%w: sidecar %s has no admission", ErrGkmNotAdmitted, sidecarId)
	}
	admittedKey := view.IdentityKey(sidecarId)
	if len(admittedKey) == 0 {
		return fmt.Errorf("%w: sidecar %s has no admitted identity key", ErrGkmNotAdmitted, sidecarId)
	}
	if !bytes.Equal(admittedKey, credential.GetIdentityPublicKey()) {
		return fmt.Errorf("%w: sidecar %s: %w", ErrGkmNotAdmitted, sidecarId, ErrMlsIdentityPin)
	}
	if !bytes.Equal(row.GetAdmissionSha256(), credential.GetAdmissionSha256()) {
		return fmt.Errorf("%w: sidecar %s names another admission", ErrGkmNotAdmitted, sidecarId)
	}
	return nil
}

// GkmCredentialAdmitted, and the sidecar neither revoked nor parked at the state: §10.9's Add row for the
// credential itself.
func GkmCredentialStanding(view GkmAuthView, credential *protocol.UrMlsCredential) error {
	if err := GkmCredentialAdmitted(view, credential); err != nil {
		return err
	}
	sidecarId, _ := IdFromBytes(credential.GetSidecarId())
	if !gkmRowStanding(view.SidecarRow(sidecarId)) {
		return fmt.Errorf("%w: sidecar %s is revoked or parked", ErrGkmNotAdmitted, sidecarId)
	}
	return nil
}

// The admission check an MLS engine runs on every leaf it takes in (MlsCredentialCheck), against the newest
// verified state state answers: nil, before the first state, refuses every credential, so an engine adds no one and
// joins nothing until the log is read.
func NewGkmCredentialCheck(state func() GkmAuthView) MlsCredentialCheck {
	return func(credential *protocol.UrMlsCredential) error {
		view := state()
		if view == nil {
			return fmt.Errorf("%w: no verified state yet", ErrGkmNotAdmitted)
		}
		return GkmCredentialAdmitted(view, credential)
	}
}

// The pin source §6's Hello and every MLS leaf share from M2 on: the identity key the log admits for a sidecar, nil
// for one it never admitted (CheckMlsIdentityPin's pinnedIdentityKey).
func GkmPinnedIdentityKey(view GkmAuthView) func(sidecarId Id) []byte {
	return func(sidecarId Id) []byte {
		if view == nil {
			return nil
		}
		return view.IdentityKey(sidecarId)
	}
}

// The identity keys a state admits, as ParseGenRotate and ParseGkmDelivery ask for them: a signer the state never
// admitted fails authentication.
func GkmIdentityKeys(view GkmAuthView) GkmIdentityKeyFunction {
	return func(signerId Id) ([]byte, error) {
		if view != nil {
			if key := view.IdentityKey(signerId); 0 < len(key) {
				return key, nil
			}
		}
		return nil, fmt.Errorf("%w: signer %s is not admitted", ErrGkmAuthentication, signerId)
	}
}

// A ReaderKey gkm serves for sidecarId, held to the identity key the state admits for it and to §10.5's readerkey
// row at timeMs, so a key a server or another sidecar forged seals nothing (S3).
func GkmAdmittedReaderKey(view GkmAuthView, signed *bridge.Signed, sidecarId Id, timeMs int64) (*GkmReaderKey, error) {
	identityKey, err := GkmIdentityKeys(view)(sidecarId)
	if err != nil {
		return nil, err
	}
	return CheckGkmReaderKey(signed, sidecarId, identityKey, timeMs)
}

// Whether the sidecar holds the repo's key at the state and time as a leaf or an uncovered agent, or reads it
// through a Delegation among the holders that covers it (§10.9's signer rows: "in it or covered by a Delegation in
// it").
func gkmHolderOrCovered(view GkmAuthView, holders GkmHolders, repoId Id, sidecarId Id, at time.Time) bool {
	if holders.Contains(GkmHolderLeaf, sidecarId.Bytes()) || holders.Contains(GkmHolderAgent, sidecarId.Bytes()) {
		return true
	}
	row := view.SidecarRow(sidecarId)
	if row == nil || len(row.GetDelegationId()) == 0 || !holders.Contains(GkmHolderDelegation, row.GetDelegationId()) {
		return false
	}
	// the Delegation is a holder, and the sidecar still reads the repo under it
	_, reads := gkmFindId(view.RepoReadersAt(repoId, at), sidecarId)
	return reads
}

// Whether ids, in any order, holds id.
func gkmFindId(ids []Id, id Id) (int, bool) {
	for index, candidate := range ids {
		if candidate == id {
			return index, true
		}
	}
	return -1, false
}

// Whether the sidecar writes the repo at the state.
func gkmWrites(view GkmAuthView, repoId Id, sidecarId Id) bool {
	_, writes := gkmFindId(view.RepoWriters(repoId), sidecarId)
	return writes
}

// Whether a repo's group follows §7.9's leaves rule rather than data seats: the config's and a team directory's.
func gkmGroupLeafRanked(repo *protocol.AclRepo) bool {
	return repo != nil && aclRepoKindLeafRanked(repo.GetKind())
}
