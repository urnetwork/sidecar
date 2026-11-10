// §10.9's delivery checks for one ReaderWrap or DelegationWrap, with R6 of DESIGN-DETAILS 6.2.3: what every member
// runs on a delivery it reads, its own when it fetches it and another's when it answers wrap-pending, judged at the
// delivery's own state and never at the member's later one.
//
//	body      group_id, generation and commitment are gen/<g>'s; the recipient and recipient_key_sha256 are its
//	          path's, when the caller gives the path it came by
//	staged    no auth and no time; the signer is gen/<g>'s; the recipient is in KeyHolders at gen/<g>'s auth and time
//	late      auth on this chain, at or past gen/<g>'s (R2); gen/<g>'s time_ms <= time_ms <= this clock + 60 s, a
//	          later one waiting (ErrGkmTimeAhead); the recipient in KeyHolders(R, auth, time_ms); the signer in it or
//	          covered by a Delegation in it, standing and not read_only
//	judged    at the delivery's auth, a STAGED one's being gen/<g>'s: above the tip waits, off the chain is invalid
//	          and a fork, before what is retained is not judged and counts against no one
//	history   a delivery valid at its own state stays valid after its recipient's or signer's revocation, a key
//	          replacement or a replay (FI-28): nothing here reads the tip
//	use       GkmUseDelivery: the recipient opens only a delivery to itself and to a key it holds whose RK_g matches
//	          C_g, then judges it as any member does
//
// A recipient is a key holder by its wrap's type: a ReaderWrap's a leaf or an uncovered agent, a DelegationWrap's a
// live Delegation among the holders. A ReaderWrap to an agent its Delegation covers is refused: it reads through
// the Delegation's wrap (§10.5's covered row).
//
// Pure, on every leg. GkmUseDelivery unwraps RK_g through OpenGkmDelivery, which hooks it.

package sidecar

import (
	"bytes"
	"crypto/hpke"
	"fmt"
	"time"
)

// What a delivery's check reads beside the state.
type GkmDeliveryCheckArgs struct {
	RepoId Id
	// The delivery, parsed under the identity key the state admits for its signer (ParseGkmDelivery).
	Delivery *GkmDelivery
	// gen/<g> of the delivery's generation, as this device parsed and judged it.
	Generation *GkmGeneration
	// The wrap/ path the delivery came by, in the group of its route; empty when the caller built the path from the
	// body itself.
	Path string
	// This device's clock.
	Now time.Time
}

// §10.9's delivery checks of one delivery at its own state. The error is a wait or a state that cannot answer, never
// a refusal: ErrGkmAuthAhead while its pin is above view, ErrGkmTimeAhead while a LATE delivery's time is past this
// clock. A refused STAGED delivery poisons its generation, which the rotation check reports; a refused LATE one
// poisons nothing but itself.
func CheckDelivery(view GkmAuthView, args *GkmDeliveryCheckArgs) (GkmVerdict, error) {
	if args == nil || args.Delivery == nil || args.Delivery.Body == nil || args.Generation == nil || args.Generation.Rotate == nil || args.Now.IsZero() {
		return GkmVerdict{}, fmt.Errorf("%w: a delivery check needs the delivery, gen/<g> and a clock", ErrGkmMalformed)
	}
	delivery := args.Delivery
	body := delivery.Body
	rotate := args.Generation.Rotate

	// body
	if !bytes.Equal(body.GetGroupId(), rotate.GetGroupId()) || body.GetGeneration() != rotate.GetGeneration() ||
		!bytes.Equal(body.GetCommitment(), rotate.GetCommitment()) {
		return gkmRefuse(GkmRefusalDelivery, "a delivery of another generation"), nil
	}
	if !bytes.Equal(rotate.GetRepoId(), args.RepoId.Bytes()) {
		return gkmRefuse(GkmRefusalDelivery, "a delivery of another repo's generation"), nil
	}
	if args.Path != "" {
		groupId, err := IdFromBytes(body.GetGroupId())
		if err != nil {
			return gkmRefuse(GkmRefusalMalformed, "a delivery's group id"), nil
		}
		path, err := GkmDeliveryPath(groupId, delivery)
		if err != nil || path != args.Path {
			return gkmRefuse(GkmRefusalDelivery, "a delivery that is not its path's"), nil
		}
	}

	// judged, and the kind's own row
	pin := rotate.GetAuth()
	at := time.UnixMilli(rotate.GetTimeMs())
	switch GkmDeliveryKind(body.GetDeliveryKind()) {
	case GkmDeliveryStaged:
		if body.GetAuth() != nil || body.GetTimeMs() != 0 {
			return gkmRefuse(GkmRefusalMalformed, "a STAGED delivery with an auth pin or a time"), nil
		}
		if delivery.SignerId != args.Generation.SignerId {
			return gkmRefuse(GkmRefusalDelivery, "a STAGED delivery by another than gen/<g>'s signer"), nil
		}
	case GkmDeliveryLate:
		pin = body.GetAuth()
		if pin.GetVersion() < rotate.GetAuth().GetVersion() {
			return gkmRefuse(GkmRefusalPinFloor, "a LATE delivery's pin %d below gen/<g>'s %d", pin.GetVersion(), rotate.GetAuth().GetVersion()), nil
		}
		if body.GetTimeMs() < rotate.GetTimeMs() {
			return gkmRefuse(GkmRefusalTime, "a LATE delivery before gen/<g>'s time"), nil
		}
		at = time.UnixMilli(body.GetTimeMs())
	default:
		return gkmRefuse(GkmRefusalMalformed, "delivery kind %d", body.GetDeliveryKind()), nil
	}
	stateAt, verdict, err := gkmJudgedView(view, pin)
	if err != nil {
		return GkmVerdict{}, err
	}
	if !verdict.Passed() {
		return verdict, nil
	}
	late := GkmDeliveryKind(body.GetDeliveryKind()) == GkmDeliveryLate
	if late {
		if err := gkmCheckNotAhead(body.GetTimeMs(), args.Now); err != nil {
			return GkmVerdict{}, err
		}
	}
	if stateAt.Repo(args.RepoId) == nil {
		return gkmRefuse(GkmRefusalDelivery, "the state at the pin holds no such repo"), nil
	}
	holders, err := KeyHolders(stateAt, args.RepoId, at)
	if err != nil {
		return GkmVerdict{}, err
	}

	// the recipient, a key holder by its wrap's type
	recipient := body.GetRecipient()
	switch delivery.Type {
	case GkmWrapTypeReader:
		if !holders.Contains(GkmHolderLeaf, recipient) && !holders.Contains(GkmHolderAgent, recipient) {
			return gkmRefuse(GkmRefusalDelivery, "a ReaderWrap to no key holder at its state"), nil
		}
	case GkmWrapTypeDelegation:
		if !holders.Contains(GkmHolderDelegation, recipient) {
			return gkmRefuse(GkmRefusalDelivery, "a DelegationWrap to no live Delegation at its state"), nil
		}
	default:
		return gkmRefuse(GkmRefusalMalformed, "wrap type %d", delivery.Type), nil
	}

	// a LATE delivery's signer: any holder, or one a Delegation among them covers, but a read_only one
	if late {
		signerRow := stateAt.SidecarRow(delivery.SignerId)
		if !gkmRowStanding(signerRow) || gkmRowReadOnly(signerRow) {
			return gkmRefuse(GkmRefusalDelivery, "a LATE delivery by a signer that is revoked, parked, read_only or unadmitted"), nil
		}
		if !gkmHolderOrCovered(stateAt, holders, args.RepoId, delivery.SignerId, at) {
			return gkmRefuse(GkmRefusalDelivery, "a LATE delivery by a signer that holds no key at its state"), nil
		}
	}
	return GkmVerdict{}, nil
}

// §10.9's use row: RK_g from a delivery to this recipient at a key it holds, accepted against gen/<g>'s C_g, and
// then judged as any member judges it. The key is returned only when the verdict passes; a refused or unjudged
// delivery gives none, and one that waits gives the error to wait on.
func GkmUseDelivery(view GkmAuthView, args *GkmDeliveryCheckArgs, recipient []byte, privateKey hpke.PrivateKey) (*EvsRepoKey, GkmVerdict, error) {
	verdict, err := CheckDelivery(view, args)
	if err != nil || !verdict.Passed() {
		return nil, verdict, err
	}
	key, err := OpenGkmDelivery(args.Delivery, args.Generation, recipient, privateKey)
	if err != nil {
		return nil, GkmVerdict{}, err
	}
	return key, verdict, nil
}
