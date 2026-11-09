// 5d, §11.8's gate (D-EVS-18): a push commits only if (1) its pins pass §10.6's gate predicate against the newest
// authorization state evs holds, and (2) neither pin is below the head's, equal versions needing equal chains and
// commitments. The head's If-Match makes (2) atomic with the commit, so once any commit carries a newer state, no
// commit under an older one follows on that ref, retries included.
//
//	fence      the push's auth pin and generation pin against the head's: below, or equal under another chain or
//	           commitment, is final (412 GATE_CLOSED)
//	record     gen/<g> of the push's group, from evs's caches: the push's C_g must be its commitment and the record
//	           this repo's, else final; a record evs does not hold yet answers 503
//	own pin    the push's auth pin on evs's chain: above evs's state answers 503 (api's notification brings the state
//	           within 5 s, §8.9), off the chain is a fork and final, before what evs retains is not judged
//	predicate  sidecar.GkmGateCheck with the generation's GenRotate's pin and time at evs's clock: a shrink or expiry
//	           the generation does not cover is recorded (412 GATE_CLOSED); a generation pin above evs's state, a
//	           state lacking the repo, or one whose holders cannot be computed answers 503, since each may pass a
//	           moment later
//
// D-TEST-6's revocation suite runs with this gate off, to show that readers' own checks hold (I-5): only a
// sidecar_testhooks build can turn it off (check_gate_off_testhooks.go), and a release build has no switch at all.
// With it off the head store still refuses a pin that would fall (head.go).

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// 5d: see the file header.
func CheckGate(view *PushView) *EvsCheckRefusal {
	if evsGateSwitchedOff() {
		return nil
	}
	push := view.Statement.Push
	if view.headExists() {
		head := view.Head
		pinBelow := func(detail string) *EvsCheckRefusal {
			return newEvsCheckRefusal(EvsCheckReasonPinBelowHead, detail)
		}
		if headAuth := head.GetAuth(); headAuth != nil {
			switch {
			case push.GetAuth().GetVersion() < headAuth.GetVersion():
				return pinBelow(fmt.Sprintf("auth pin %d below the head's %d", push.GetAuth().GetVersion(), headAuth.GetVersion()))
			case push.GetAuth().GetVersion() == headAuth.GetVersion() && !bytes.Equal(push.GetAuth().GetChain(), headAuth.GetChain()):
				return pinBelow("the head's auth pin under another chain")
			}
		}
		if 0 < head.GetGeneration() {
			switch {
			case push.GetGeneration() < head.GetGeneration():
				return pinBelow(fmt.Sprintf("generation %d below the head's %d", push.GetGeneration(), head.GetGeneration()))
			case push.GetGeneration() == head.GetGeneration() &&
				(!bytes.Equal(push.GetGroupId(), head.GetGroupId()) || !bytes.Equal(push.GetGenerationCommitment(), head.GetGenerationCommitment())):
				return pinBelow("the head's generation under another group or commitment")
			}
		}
	}

	record := view.Generation
	if record == nil {
		return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no record of the push's generation")
	}
	if !bytes.Equal(record.GetGroupId(), push.GetGroupId()) || record.GetGeneration() != push.GetGeneration() ||
		!bytes.Equal(record.GetRepoId(), view.RepoId.Bytes()) {
		return newEvsCheckRefusal(EvsCheckReasonPinForked, "a generation pin of another group or repo")
	}
	if !bytes.Equal(record.GetCommitment(), push.GetGenerationCommitment()) {
		return newEvsCheckRefusal(EvsCheckReasonPinForked, "a generation commitment that is not gen/<g>'s")
	}

	if view.Auth == nil {
		return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no authorization state")
	}
	if !view.Auth.OnChain(push.GetAuth()) {
		_, err := view.Auth.At(push.GetAuth())
		switch {
		case err == nil, errors.Is(err, sidecar.ErrGkmAuthNotRetained):
		case errors.Is(err, sidecar.ErrGkmAuthAhead):
			return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "an auth pin above evs's state")
		default:
			return newEvsCheckRefusal(EvsCheckReasonPinForked, "an auth pin off evs's chain")
		}
	}

	err := sidecar.GkmGateCheck(view.Auth, view.RepoId, record.GetAuth(), time.UnixMilli(record.GetTimeMs()), view.Now)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sidecar.ErrGkmAuthAhead), errors.Is(err, sidecar.ErrGkmNoRepo), errors.Is(err, sidecar.ErrGkmMalformed):
		return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "the gate cannot be judged at evs's state yet")
	}
	return newEvsCheckRefusal(EvsCheckReasonGateClosed, "the generation does not cover the state's shrinks and expiries")
}
