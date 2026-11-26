//go:build !ios_extension

// A grant's action asked again (§16.6's retry row and its grant component, §8.6's requests; I-8, AU4, AD2): what a
// caller that builds a grant-backed action keeps between its calls, so the call made again after a person's decision
// presents the bytes the decision names. Sidecar.Listen's tls/ and smtp/ listen (socket_listen.go), MCP's
// socket_listen (socket_listen_grant.go) and §13.10's publish (tls_publish.go) keep theirs in a GrantActionKeeper, and
// a share's activation keeps its action in its invite's record (bridge_share_invite.go), which asks priorGrant as
// these do.
//
//	kept      the expiry a requests rule gives moves with the clock, so an action built afresh asks another action,
//	          and a decision on the first is never spent: GrantActionKeeper keeps each action as its request was filed,
//	          by its caller's key, until that expiry, and hands it back while a fresh build differs from it in that
//	          expiry alone and asks no shorter grant
//	ended     a kept action whose decision already activated its grant, and whose grant has since been revoked or
//	          ended, is asked afresh: its spent decision answers its recorded outcome to every retry (AU4) and
//	          activates nothing again (AD2), so presenting it would answer done for a grant that no longer stands
//	          (AclGrantFiler.priorGrant)
//	standing  an action no requests rule takes names no rule and no expiry, so no decision could activate a grant for
//	          it: a standing grant alone covers it (AclEngine.ActiveGrant), under aclStandingGrantEffect, and with none
//	          it is refused before the gate, filing nothing
//	landed    a use that activates a grant is done only once this device's engine holds the grant in force, waited on
//	          in the network's config up to its GrantActivate's receipt within its caller's bound (landedEffect and
//	          awaitGrant, the one wait §13.10's publish, MCP's socket_listen and Sidecar.Listen's tls/ and smtp/
//	          listens take, as a forward's confirmForwardGrant waits), so the caller acts on a grant the log holds
//	          where the network's gates read it; one the engine does not hold by then leaves the use uncertain, never
//	          not_done, since the grant may still land, its error naming the grant (AclGrantUnconfirmedError), and the
//	          same call made again completes it
//	named     that call made again once the engine holds the grant passes the gate as standing under it (§16.6's step
//	          2), whose empty key the grant component answers with nothing; the kept action's effect answers there the
//	          grant its own decision activated (priorGrant), so its caller names that grant as it names one its use
//	          activated, as a publish names its own
//
// The keeper is in memory alone: a request filed before a restart is filed again after it. Safe for concurrent use.
// Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The grant a use activated is not in force in this device's engine yet (the file header's landed row): the use is
// uncertain, never not_done, and the same call made again completes it.
var ErrAclGrantUnconfirmed = errors.New("acl grant not confirmed in this device's engine")

// The grant a use activated, which this device's engine does not hold in force yet (the file header's landed row), and
// why its wait ended: awaitGrant's answer, so its caller can name the grant the same call made again completes on.
// The grant_id is an opaque id (I-13). errors.Is matches ErrAclGrantUnconfirmed and the cause.
type AclGrantUnconfirmedError struct {
	GrantId []byte
	Err     error
}

// See error.
func (self *AclGrantUnconfirmedError) Error() string {
	return fmt.Sprintf("%v: grant %x: %v", ErrAclGrantUnconfirmed, self.GrantId, self.Err)
}

// ErrAclGrantUnconfirmed and the cause.
func (self *AclGrantUnconfirmedError) Unwrap() []error {
	return []error{ErrAclGrantUnconfirmed, self.Err}
}

// What a use waits on for the grant it activated to reach this device's engine (the file header's landed row):
// TEAM-M2-10's ConfigClient is one, whose follower installs each state in the engine before WaitFor answers.
type AclGrantConfig interface {
	// The state at or past n, once the follow reaches it.
	WaitFor(ctx context.Context, n uint64) (*ConfigState, error)
}

var _ AclGrantConfig = (*ConfigClient)(nil)

// Actions kept as their requests were filed, by a caller's key, each until its expiry (the file header's kept row).
// Safe for concurrent use.
type GrantActionKeeper[K comparable] struct {
	stateLock  sync.Mutex
	keyActions map[K]*StoredCanonicalAction
}

// A keeper holding nothing.
func NewGrantActionKeeper[K comparable]() *GrantActionKeeper[K] {
	return &GrantActionKeeper[K]{keyActions: map[K]*StoredCanonicalAction{}}
}

// The action to present for key at now: the one kept, while its expiry is ahead, fresh differs from it in its expiry
// alone, and fresh asks no shorter grant than it; else fresh, which is kept in its place. A kept action that ended
// answers true for, its grant spent and gone, gives way to fresh too; ended nil ends none, and runs with no lock held.
// Expired actions are dropped as each key is asked for, so the keeper holds one a key asked within a rule's lifetime,
// and an action with no expiry is kept until the next call alone.
func (self *GrantActionKeeper[K]) Keep(key K, fresh *StoredCanonicalAction, now time.Time, ended func(kept *StoredCanonicalAction) bool) *StoredCanonicalAction {
	kept := func() *StoredCanonicalAction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		nowMs := now.UnixMilli()
		for keptKey, kept := range self.keyActions {
			if kept.Action.GetExpiresMillis() <= nowMs {
				delete(self.keyActions, keptKey)
			}
		}
		if kept := self.keyActions[key]; kept != nil && grantActionKeptFor(kept, fresh) {
			return kept
		}
		self.keyActions[key] = fresh
		return nil
	}()
	if kept == nil {
		return fresh
	}
	if ended == nil || !ended(kept) {
		return kept
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.keyActions[key] == kept {
			self.keyActions[key] = fresh
		}
	}()
	return fresh
}

// Drops what key keeps, so its next action is built afresh: a caller's own end of the grant, an unpublish's say.
func (self *GrantActionKeeper[K]) Forget(key K) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.keyActions, key)
}

// Whether kept still stands for fresh: fresh, built now, differs from it in expires_millis alone, and asks no shorter
// grant, a rule that now gives less than kept asks having to be asked again.
func grantActionKeptFor(kept *StoredCanonicalAction, fresh *StoredCanonicalAction) bool {
	if kept == nil || fresh == nil || kept.Action == nil || fresh.Action == nil {
		return false
	}
	if fresh.Action.GetExpiresMillis() < kept.Action.GetExpiresMillis() {
		return false
	}
	freshAtKeptExpiry := proto.Clone(fresh.Action).(*protocol.CanonicalAction)
	freshAtKeptExpiry.ExpiresMillis = kept.Action.GetExpiresMillis()
	return proto.Equal(kept.Action, freshAtKeptExpiry)
}

// The effect of a grant's action no requests rule takes (the file header's standing row): a standing grant passes it
// under an empty key, with nothing to do, and no decision's use can activate a grant for it, since a GrantActivate
// names the requests rule its grant is asked under (§8.8), so a use proves that nothing happened.
type aclStandingGrantEffect struct{}

// See SidecarEffect.
func (self aclStandingGrantEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if len(effectKey) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("%w: no requests rule takes this action, so no grant activates for it", ErrSidecarEffectNotDone)
}

// base with the grant's fields of request filled and no rule and no expiry named, as stored: the action a grant no
// requests rule takes is asked as, which only a standing grant covers (the file header's standing row).
func aclStandingGrantAction(base *protocol.CanonicalAction, request *AclGrantRequest) (*StoredCanonicalAction, error) {
	if base == nil || request == nil {
		return nil, fmt.Errorf("%w: no action", ErrAclGrantFile)
	}
	action := proto.Clone(base).(*protocol.CanonicalAction)
	action.Subject = request.Subject.Bytes()
	action.GrantDst = append([]string(nil), request.GrantDst...)
	action.GrantAllow = append([]string(nil), request.GrantAllow...)
	action.RuleId = nil
	action.ExpiresMillis = 0
	return NewCanonicalAction(action)
}

// The grant a decision on action already activated, for the run, agent and detail its request binds: its grant_id,
// and whether the installed state still holds it in force at now. nil where no decision on it activated one this
// state knows of, or where this sidecar runs no gate to ask (the file header's ended row). A use the gate passed under
// the grant its own decision activated, which the gate takes as standing (§16.6's step 2) and so answers with an empty
// reference, names that grant again by it.
func (self *AclGrantFiler) priorGrant(action *StoredCanonicalAction, detail *SidecarActionDetail, runId *Id, agentId *Id, now time.Time) ([]byte, bool) {
	if self == nil || self.sidecar == nil || self.engine == nil || action == nil {
		return nil, false
	}
	gate, err := self.sidecar.ApprovalGate()
	if err != nil || gate.inbox.ensureLoaded() != nil {
		return nil, false
	}
	state := self.engine.State()
	if state == nil {
		return nil, false
	}
	var ended []byte
	for _, candidate := range gate.inbox.candidates(action, detail, runId, agentId) {
		// the grant component fixes the grant_id from the request's action as stored, the spend's (aclGrantEffect)
		grantId := AclGrantId(candidate.request.ApprovalId(), candidate.request.Action.PayloadSha256())
		rule := state.grantRule(grantId[:])
		if rule != nil && rule.activeAt(now.UnixMilli()) {
			return bytes.Clone(grantId[:]), true
		}
		if ended == nil && (rule != nil || state.spentGrant(grantId[:]) != nil) {
			ended = bytes.Clone(grantId[:])
		}
	}
	return ended, false
}

// Whether a decision on action activated a grant that no longer stands at now (priorGrant): the kept action asked
// afresh.
func (self *AclGrantFiler) grantEnded(action *StoredCanonicalAction, detail *SidecarActionDetail, runId *Id, agentId *Id, now time.Time) bool {
	grantId, stands := self.priorGrant(action, detail, runId, agentId, now)
	return grantId != nil && !stands
}

// The grant component's effect for action (Effect's) whose use is done only once this device's engine holds the grant
// it activated in force (the file header's landed row): once its GrantActivate's post answers, the receipt is waited on
// within timeout in the config that config answers then (awaitGrant). The one wait §13.10's publish (tls_publish.go),
// MCP's socket_listen (keptEffect) and Sidecar.Listen's tls/ and smtp/ listens (socket_listen.go) take. config nil, or
// answering nil, waits on nothing, so a grant the engine does not hold as its post answers leaves the use uncertain.
// Under a standing pass's empty key it does nothing, as Effect's.
func (self *AclGrantFiler) landedEffect(action *StoredCanonicalAction, config func() AclGrantConfig, timeout time.Duration) *aclGrantEffect {
	return &aclGrantEffect{filer: self, action: action, confirm: func(ctx context.Context, pin *bridge.AuthPin, signed []byte, grantId []byte) error {
		var waitOn AclGrantConfig
		if config != nil {
			waitOn = config()
		}
		return self.awaitGrant(ctx, waitOn, timeout, pin, grantId)
	}}
}

// The grant component's effect for a kept grant action (the file header's landed and named rows): under a use's key
// the GrantActivate its spend fixes, done only once this device's engine holds the grant in force, waited on in config
// within timeout (landedEffect); under a standing pass's empty key the grant the action's own decision activated, where
// it stands. detail, runId and agentId are what the action's request binds beside it. config nil waits on nothing, so
// a grant the engine does not hold as its post answers leaves the use uncertain.
func (self *AclGrantFiler) keptEffect(action *StoredCanonicalAction, detail *SidecarActionDetail, runId *Id, agentId *Id,
	config AclGrantConfig, timeout time.Duration) SidecarEffect {
	return &aclKeptGrantEffect{
		filer: self,
		grant: self.landedEffect(action, func() AclGrantConfig {
			return config
		}, timeout),
		action:  action,
		detail:  detail,
		runId:   runId,
		agentId: agentId,
	}
}

// See AclGrantFiler.keptEffect.
type aclKeptGrantEffect struct {
	filer   *AclGrantFiler
	grant   *aclGrantEffect
	action  *StoredCanonicalAction
	detail  *SidecarActionDetail
	runId   *Id
	agentId *Id
}

// See SidecarEffect: the grant component's Run under a use's key; under a standing pass's empty key the grant the
// action's own decision activated while the installed state holds it in force (the file header's named row), and
// nothing for one a standing grant of the config's covers, nothing having been activated for it.
func (self *aclKeptGrantEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if 0 < len(effectKey) {
		return self.grant.Run(ctx, effectKey)
	}
	if self.filer.sidecar == nil {
		return nil, nil
	}
	grantId, stands := self.filer.priorGrant(self.action, self.detail, self.runId, self.agentId, self.filer.sidecar.clock.Now())
	if !stands {
		return nil, nil
	}
	return grantId, nil
}

// Whether this device's engine holds grantId in force at now.
func (self *AclGrantFiler) grantStands(grantId []byte, now time.Time) bool {
	state := self.engine.State()
	if state == nil {
		return false
	}
	rule := state.grantRule(grantId)
	return rule != nil && rule.activeAt(now.UnixMilli())
}

// The landed row (the file header), the one wait every grant-backed caller takes: nil once this device's engine holds
// grantId in force, at once or once config, waited on within timeout, reaches the position of pin, its GrantActivate's
// receipt, as the follower installs each state in the engine before its position shows (acl_follow.go). A non-positive
// timeout waits not at all. An *AclGrantUnconfirmedError naming grantId otherwise: no receipt, no config to wait on, a
// wait that ended first, its timeout's included, or a state there that does not hold the grant in force.
func (self *AclGrantFiler) awaitGrant(ctx context.Context, config AclGrantConfig, timeout time.Duration, pin *bridge.AuthPin, grantId []byte) error {
	unconfirmed := func(err error) error {
		return &AclGrantUnconfirmedError{GrantId: bytes.Clone(grantId), Err: err}
	}
	if self.sidecar == nil || self.engine == nil {
		return unconfirmed(errors.New("no engine to hold the grant"))
	}
	clock := self.sidecar.clock
	if self.grantStands(grantId, clock.Now()) {
		return nil
	}
	if pin == nil || pin.GetVersion() == 0 {
		return unconfirmed(errors.New("no receipt for the grant"))
	}
	if config == nil {
		return unconfirmed(errors.New("no verified config to wait on for the grant"))
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := config.WaitFor(waitCtx, pin.GetVersion()); err != nil {
		return unconfirmed(fmt.Errorf("waiting for the grant: %w", err))
	}
	if !self.grantStands(grantId, clock.Now()) {
		return unconfirmed(errors.New("the grant is not in force in this device's engine"))
	}
	return nil
}
