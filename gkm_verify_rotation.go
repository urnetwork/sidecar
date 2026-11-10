// §10.9's rotation checks for one GenRotate, with R2 of DESIGN-DETAILS 6.2.3: what every member runs on gen/<g>
// before it holds, opens or seals to generation g, and what a rotator runs on a 412's winner before it adopts it.
//
//	judged    at the statement's auth pin (R1): above the tip waits, off the chain is a fork, before what is retained
//	          is not judged
//	signer    a key holder at (auth, time), or covered by a Delegation among them; standing and not read_only; and a
//	          writer at auth or, in the config and directory groups, any such holder (below)
//	chain     generation g names its repo, and parent_commitment is gen/<g-1>'s C; generation 1 has no parent
//	floors    auth and time at or past the parent's (R2), so holders only shrink along the chain
//	holders   holders_sha256 equals this device's recomputation of KeyHolders at (auth, time); every STAGED delivery
//	          this device read passes the delivery checks; a leaf_wrap's epoch, where this device knows its tree,
//	          holds key holders alone (R5)
//	cause     REMOVE where the state requires it (a shrink, an expiry or a compromise retirement since the parent,
//	          or a poisoned parent); gen/1 is REQUEST and a REMOVE there is refused
//	time      time_ms at most this clock plus 60 s, else it waits (ErrGkmTimeAhead) and is judged again, and never
//	          poisons; a drop key lives time_ms < drop_not_after_ms <= time_ms + DropKeyLifetime + 10 min
//	          (plan-KEYS-drop-key-lifetime)
//
// A GenRotate that fails any row poisons its generation (§10.9's poisoned row): members never seal to it and rotate
// at once with cause REMOVE.
//
// Readings: the rows keep no revocation's signer, so "in the config group the signer of the statement it answers"
// (owner decision 128) is taken as any standing holder there that is not read_only; and a REMOVE the state does not
// require is accepted, since its rotator may have seen a poisoned parent this device did not, and costs only
// §11.7's checkpoint.
//
// Pure, on every leg. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"bytes"
	"fmt"
	"time"
)

// What a rotation's check reads beside the state.
type GkmRotationCheckArgs struct {
	RepoId Id
	// gen/<g>, parsed under the identity key the state admits for its signer (ParseGenRotate with GkmIdentityKeys).
	Generation *GkmGeneration
	// gen/<g-1>, as this device parsed and judged it; nil for generation 1.
	Parent *GkmGeneration
	// Whether this device holds the parent as poisoned.
	ParentPoisoned bool
	// The STAGED deliveries of g this device read, each parsed (ParseGkmDelivery): its own, and others' when it
	// answers wrap-pending.
	StagedDeliveries []*GkmDelivery
	// The leaves of the leaf_wrap's epoch, when this device adopted that epoch and so knows its tree; nil
	// otherwise, and for a GenRotate with no leaf_wrap.
	LeafWrapRoster []MlsMember
	// GkmSettings.DropKeyLifetime.
	DropKeyLifetime time.Duration
	// This device's clock.
	Now time.Time
}

// §10.9's rotation checks of gen/<g> at its own auth pin. The error is a wait or a state that cannot answer, never
// a refusal: ErrGkmAuthAhead while the pin is above view, ErrGkmTimeAhead while time_ms is past this clock. A
// refused verdict poisons g.
func CheckRotation(view GkmAuthView, args *GkmRotationCheckArgs) (GkmVerdict, error) {
	if args == nil || args.Generation == nil || args.Generation.Rotate == nil || args.Now.IsZero() {
		return GkmVerdict{}, fmt.Errorf("%w: a rotation check needs gen/<g> and a clock", ErrGkmMalformed)
	}
	rotate := args.Generation.Rotate
	generation := rotate.GetGeneration()
	poison := func(reason GkmRefusalReason, format string, formatArgs ...any) (GkmVerdict, error) {
		verdict := gkmRefuse(reason, format, formatArgs...)
		verdict.Poisoned = generation
		return verdict, nil
	}
	if !bytes.Equal(rotate.GetRepoId(), args.RepoId.Bytes()) {
		return poison(GkmRefusalChain, "gen/%d names another repo", generation)
	}
	at, verdict, err := gkmJudgedView(view, rotate.GetAuth())
	if err != nil {
		return GkmVerdict{}, err
	}
	if verdict.NotJudged {
		return verdict, nil
	}
	if verdict.Refused {
		verdict.Poisoned = generation
		return verdict, nil
	}
	// a future time waits rather than poisons
	if err := gkmCheckNotAhead(rotate.GetTimeMs(), args.Now); err != nil {
		return GkmVerdict{}, err
	}
	repo := at.Repo(args.RepoId)
	if repo == nil {
		return poison(GkmRefusalHolders, "the state at the pin holds no such repo")
	}
	rotateTime := time.UnixMilli(rotate.GetTimeMs())

	// chain and floors
	switch {
	case generation == 1:
		if args.Parent != nil || len(rotate.GetParentCommitment()) != 0 {
			return poison(GkmRefusalChain, "gen/1 with a parent")
		}
		if GkmCause(rotate.GetCause()) != GkmCauseRequest {
			return poison(GkmRefusalCause, "gen/1 with cause %d", rotate.GetCause())
		}
	default:
		if args.Parent == nil || args.Parent.Rotate == nil {
			return GkmVerdict{}, fmt.Errorf("%w: gen/%d to chain gen/%d on", ErrGkmKeyMissing, generation-1, generation)
		}
		parent := args.Parent.Rotate
		if parent.GetGeneration()+1 != generation || !bytes.Equal(parent.GetRepoId(), rotate.GetRepoId()) ||
			!bytes.Equal(parent.GetCommitment(), rotate.GetParentCommitment()) {
			return poison(GkmRefusalChain, "gen/%d does not chain on gen/%d", generation, parent.GetGeneration())
		}
		if rotate.GetAuth().GetVersion() < parent.GetAuth().GetVersion() {
			return poison(GkmRefusalPinFloor, "pin %d below the parent's %d", rotate.GetAuth().GetVersion(), parent.GetAuth().GetVersion())
		}
		if rotate.GetTimeMs() < parent.GetTimeMs() {
			return poison(GkmRefusalTime, "a time before the parent's")
		}
	}

	// holders
	holders, err := KeyHolders(at, args.RepoId, rotateTime)
	if err != nil {
		return GkmVerdict{}, err
	}
	if !bytes.Equal(holders.Sha256(), rotate.GetHoldersSha256()) {
		return poison(GkmRefusalHolders, "holders_sha256 differs from this state's key holders")
	}

	// signer
	signerId := args.Generation.SignerId
	signerRow := at.SidecarRow(signerId)
	if !gkmRowStanding(signerRow) || gkmRowReadOnly(signerRow) {
		return poison(GkmRefusalSigner, "a signer that is revoked, parked, read_only or unadmitted")
	}
	if !gkmHolderOrCovered(at, holders, args.RepoId, signerId, rotateTime) {
		return poison(GkmRefusalSigner, "a signer that holds no key at its pin")
	}
	if !gkmWrites(at, args.RepoId, signerId) && !gkmGroupLeafRanked(repo) {
		return poison(GkmRefusalSigner, "a signer that does not write the repo")
	}

	// cause
	if 1 < generation {
		required, err := GkmRotationRemoveRequired(at, args.RepoId, args.Parent.Rotate, rotate, args.ParentPoisoned)
		if err != nil {
			return GkmVerdict{}, err
		}
		if required && GkmCause(rotate.GetCause()) != GkmCauseRemove {
			return poison(GkmRefusalCause, "cause %d where the state requires REMOVE", rotate.GetCause())
		}
	}

	// the drop key's life
	if 0 < len(rotate.GetDropPublicKey()) || rotate.GetDropNotAfterMs() != 0 {
		latest := rotate.GetTimeMs() + (args.DropKeyLifetime + GkmClockSkew).Milliseconds()
		if len(rotate.GetDropPublicKey()) == 0 || rotate.GetDropNotAfterMs() <= rotate.GetTimeMs() || latest < rotate.GetDropNotAfterMs() {
			return poison(GkmRefusalTime, "a drop key's life out of bounds")
		}
	}

	// R5: a leaf_wrap's epoch holds key holders alone
	if rotate.GetLeafWrap() != nil {
		for _, member := range args.LeafWrapRoster {
			if !holders.Contains(GkmHolderLeaf, member.SidecarId.Bytes()) {
				return poison(GkmRefusalHolders, "a leaf_wrap under an epoch whose tree holds a non-holder")
			}
		}
	}

	// each staged delivery this device read
	for _, delivery := range args.StagedDeliveries {
		deliveryVerdict, err := CheckDelivery(view, &GkmDeliveryCheckArgs{
			RepoId:     args.RepoId,
			Delivery:   delivery,
			Generation: args.Generation,
			Now:        args.Now,
		})
		if err != nil {
			return GkmVerdict{}, err
		}
		if deliveryVerdict.Refused {
			deliveryVerdict.Poisoned = generation
			return deliveryVerdict, nil
		}
	}
	return GkmVerdict{}, nil
}
