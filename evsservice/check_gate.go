// 5d, §11.8's gate (D-EVS-18): a push commits only if (1) its pins pass §10.6's gate predicate against the newest
// authorization state evs holds, (2) neither pin is below the head's, equal versions needing equal chains and
// commitments, and (3) a push that creates or re-creates a shared ref is pinned at or above the repo's newest prefix
// rule set in that state (DESIGN-DETAILS 16.2.9; QD-803). The head's If-Match makes (2) atomic with the commit, so
// once any commit carries a newer state, no commit under an older one follows on that ref, retries included. (3)
// holds the pin where no head can: a ref with no head gives (2) nothing to compare, and a deleted one only its
// DELETE's pin, so readers, who judge a push under the set in force at its pin, judge a new name under that set or a
// later one.
//
//	fence      the push's auth pin and generation pin against the head's: below, or equal under another chain or
//	           commitment, is final (412 GATE_CLOSED)
//	record     gen/<g> of the push's group, from evs's caches: the push's C_g must be its commitment and the record
//	           this repo's, else final; a record evs does not hold yet answers 503
//	own pin    the push's auth pin on evs's chain: above evs's state answers 503 (api's notification brings the state
//	           within 5 s, §8.9), off the chain is a fork and final, before what evs retains is not judged. The
//	           genesis pin {0, A_0} is taken on the config repo's first push alone, which base 1 names and so precedes
//	           (QD-081 #4): on any other push it is final
//	rules      a push on no head, a placeholder or a deleted head (the creating test 5c's sections make), of ref kind
//	           shared, against the greatest position in the state's AclRepo.prefix_rules for the repo
//	           (sidecar.AclPrefixRulesNewestAt): an auth pin below it is recorded (412 GATE_CLOSED), a pin at the
//	           set's own position passing; a state lacking the repo's row answers 503; a row with no set compares
//	           nothing. evs reads the newest row's position and never a rule, whatever a reader makes of its body.
//	           No flag exempts a push, FORCE included. Owned, deposit and erasure refs are outside the rules and the
//	           clause, and every push on a head that has a version and is not deleted is held to the head's pin by
//	           the fence. Below the own-pin row, so versions are compared only once the pin is judged against evs's
//	           chain; on a deleted head below the fence, whose refusal of a pin under the DELETE's is final and comes
//	           first. Recorded, not final: one process's state settles it, and a sibling that has not loaded the set
//	           would take a held attempt of the same push id if no record answered it
//	predicate  sidecar.GkmGateCheck with the generation's GenRotate's pin and time at evs's clock: a shrink or expiry
//	           the generation does not cover is recorded (412 GATE_CLOSED); a generation pin above evs's state, a
//	           state lacking the repo, or one whose holders cannot be computed answers 503, since each may pass a
//	           moment later
//
// D-TEST-6's revocation suite runs with this gate off, the rules clause with it, to show that readers' own checks hold
// (I-5): only a sidecar_testhooks build can turn it off (check_gate_off_testhooks.go), and a release build has no
// switch at all. With it off the head store still refuses a pin that would fall (head.go).

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
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
	if push.GetAuth().GetVersion() == 0 && (view.Repo.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || view.headExists()) {
		// the genesis pin is the config repo's first push's alone, the push base 1 names (QD-081 #4)
		return newEvsCheckRefusal(EvsCheckReasonPinForked, "a genesis pin outside the config repo's first push")
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

	// the rules clause: a creating push of a shared ref, against the newest set's position
	creating := !view.headExists() || view.Head.GetDeleted()
	if creating && protocol.EvsRefKind(push.GetRefKind()) == protocol.EvsRefKind_EVS_REF_SHARED {
		repo := view.Auth.Repo(view.RepoId)
		if repo == nil {
			return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "a state lacking the repo's row, whose rule sets a creating push is held to")
		}
		if at, ok := sidecar.AclPrefixRulesNewestAt(repo); ok && push.GetAuth().GetVersion() < at {
			return newEvsCheckRefusal(EvsCheckReasonPinBelowRules,
				fmt.Sprintf("auth pin %d below the repo's newest rule set at %d", push.GetAuth().GetVersion(), at))
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
