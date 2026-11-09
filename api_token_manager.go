// sidecarTokenManager, D-CORE-8's refresher (§5.6): one per client generation, it runs sdk's schedule
// (api_token_schedule.go) on GET /auth/refresh through SidecarApi, whose DPoP proof crypto/ed25519 signs by the
// ClientKey, and refreshes again whenever connect reports a refused credential. A refreshed token is checked to name
// the same client and device, persisted to the keychain first, and only then installed: in SidecarApi, and through
// the owner's install callback in connect's three holders, api.SetByJwt, transport.SetAuth and
// ApiOutOfBandControl.SetByJwt (connect/transfer_oob_control.go:101 keeps its own jwt), SetAuth with the new token
// ending connect's refusal hold.
//
// A confirmed rejection, a 401 or a 200 whose error object holds a code other than restore_required, ends the
// generation, never the sidecar: the owner moves to Unenrolled with identity, keys and admission kept, as §18.5 maps
// it, session_revoked to session_ended, a child's to parent_lost (plan-CORE-parent-lost-signal), else refused, and a
// token whose exp passed with no refresh to expired. Only a verified SidecarRevoke means Revoked, which is not this
// file's to decide. restore_required, after a Postgres restore, is no rejection: the owner re-posts the newest
// binding and each component's registrations, and the manager refreshes again (§19.10). Network errors and anything
// else retry after the schedule's jitter.
//
// A refresh request is level-triggered, a counter in a MonitorValue, so one made while a refresh is in flight is
// honored when it returns rather than dropped with an edge nobody was waiting on. Every wait is on the sidecar's
// Clock. With a host TokenSource the owner starts no manager (CORE-M8-01). This file is in both legs and names no
// connect type: connect's AuthorizationClosed reaches authorizationClosed through the owner's adapter.
//
// A manager is safe for concurrent use. Its callbacks run on its own goroutine and must not block for long or call
// back into it.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

// The keychain record of the core's namespace holding the client's current jwt (§5.9's keychain.ur).
const sidecarByJwtRecordName = "by_jwt"

// What a manager takes from its owner, CORE-M1-08's Sidecar, or a test.
type sidecarTokenManagerArgs struct {
	// Holds the token the schedule reads and is the one that refreshes it.
	Api      *SidecarApi
	Settings *SidecarTokenRefreshSettings
	Clock    Clock
	Log      Logger
	// The client generation this manager serves, which every report names, so a stale generation's is dropped
	// (D-SDK-14).
	Generation int64
	// The client is a child of a device client (paired or an sdk host), whose confirmed rejection reads as
	// parent_lost (plan-CORE-parent-lost-signal).
	Child bool
	// Keeps a refreshed token in the keychain. Called before anything installs it; an error installs nothing.
	Persist func(byJwt string) error
	// Installs a persisted token in connect's holders. Nil on the sidecar_http leg, which has none.
	Install func(byJwt string)
	// The generation was refused: the owner moves to Unenrolled for reason.
	Refused func(generation int64, reason SidecarStateReason)
	// restore_required: re-post the newest binding and each component's registrations (§19.10).
	Restore func(ctx context.Context) error
	// The retry wait after a failed refresh, a uniform draw below RefreshRetryTimeout. Nil draws one; a test fixes it.
	RetryTimeout func() time.Duration
}

// What one refresh came to.
type sidecarRefreshOutcome int

const (
	// A new token is persisted and installed.
	sidecarRefreshInstalled sidecarRefreshOutcome = iota + 1
	// A confirmed rejection, or exp passed unrefreshed: the generation is over.
	sidecarRefreshEnded
	// restore_required was answered and the restore ran: refresh again at once.
	sidecarRefreshRestored
	// Anything else: retry after the jitter.
	sidecarRefreshFailed
)

// D-CORE-8's refresher for one client generation. Construct with newSidecarTokenManager, which starts it.
type sidecarTokenManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	args   *sidecarTokenManagerArgs
	done   chan struct{}
	// refresh requests so far, each a bump, read with the channel armed at the same instant
	requests *MonitorValue[uint64]

	// owned by run: the token the schedule was made for and its refresh time, the requests run has consumed, and
	// when the last attempt began
	scheduledByJwt         string
	scheduledRefreshTime   time.Time
	handledRequests        uint64
	lastRefreshAttemptTime time.Time

	stateLock sync.Mutex
	// the reason the generation ended, empty while it runs
	endedReason SidecarStateReason
}

// A running manager for args, which must name an Api, settings, a clock and the callbacks a refresh needs.
func newSidecarTokenManager(ctx context.Context, args *sidecarTokenManagerArgs) *sidecarTokenManager {
	cancelCtx, cancel := context.WithCancel(ctx)
	if args.Log == nil {
		args.Log = NewNoopLogger()
	}
	if args.Clock == nil {
		args.Clock = RealClock{}
	}
	if args.RetryTimeout == nil {
		retryTimeout := args.Settings.RefreshRetryTimeout
		args.RetryTimeout = func() time.Duration {
			if retryTimeout <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(retryTimeout)))
		}
	}
	self := &sidecarTokenManager{
		ctx:      cancelCtx,
		cancel:   cancel,
		args:     args,
		done:     make(chan struct{}),
		requests: NewMonitorValue[uint64](0),
	}
	go self.run()
	return self
}

// Asks for a refresh now, on top of the schedule. Level-triggered: a request made during a refresh is honored when
// it returns. Never blocks.
func (self *sidecarTokenManager) requestRefresh() {
	self.requests.Update(func(count uint64) uint64 {
		return count + 1
	})
}

// connect's AuthorizationClosed, which is a nonblocking notification: a close for unavailability is ignored, and any
// other cause requests a refresh and nothing more, since connect says only a later confirmed API rejection signs out
// (connect/transport.go:528).
func (self *sidecarTokenManager) authorizationClosed(unavailable bool) {
	if unavailable {
		return
	}
	self.requestRefresh()
}

// Why the generation ended, or "" while it runs.
func (self *sidecarTokenManager) ended() SidecarStateReason {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.endedReason
}

// Stops the manager. Safe to call again.
func (self *sidecarTokenManager) close() {
	self.cancel()
}

// Stops the manager and waits for its goroutine.
func (self *sidecarTokenManager) closeAndWait() {
	self.cancel()
	<-self.done
}

// How long until byJwt's scheduled refresh, keeping a token's schedule while it stays the same token.
func (self *sidecarTokenManager) scheduledRefreshTimeout(byJwt string) time.Duration {
	now := self.args.Clock.Now()
	if byJwt != self.scheduledByJwt {
		self.scheduledByJwt = byJwt
		self.scheduledRefreshTime = sidecarJwtRefreshTime(byJwt, now, sidecarJwtRefreshDraw(byJwt), self.args.Settings)
	}
	return sidecarJwtRefreshTimeout(self.scheduledRefreshTime, self.lastRefreshAttemptTime, now, self.args.Settings)
}

// The schedule's loop: waits for the token's point or a request, refreshes, and on a failure retries after the
// jitter, until the generation ends or the manager closes.
func (self *sidecarTokenManager) run() {
	defer close(self.done)
	for {
		// subscribe and read in one step, then read the token, so a request between them is never lost
		requestCount, notify := self.requests.Get()
		byJwt := self.args.Api.currentByJwt()
		if !sidecarJwtCanRefresh(byJwt) {
			// keep no copy of a token that is no longer scheduled
			self.scheduledByJwt = ""
			select {
			case <-self.ctx.Done():
				return
			case <-notify:
				continue
			}
		}
		timeout := time.Duration(0)
		if requestCount == self.handledRequests {
			timeout = self.scheduledRefreshTimeout(byJwt)
		}
		if 0 < timeout {
			if self.args.Log.V(1).Enabled() {
				self.args.Log.Infof("[token]refresh in %s", timeout)
			}
			select {
			case <-self.ctx.Done():
				return
			case <-notify:
				continue
			case <-self.args.Clock.After(timeout):
			}
		} else {
			select {
			case <-self.ctx.Done():
				return
			default:
			}
		}
		self.handledRequests = requestCount

		for {
			self.lastRefreshAttemptTime = self.args.Clock.Now()
			outcome := self.refresh(byJwt)
			switch outcome {
			case sidecarRefreshInstalled:
			case sidecarRefreshEnded:
				return
			case sidecarRefreshRestored:
				if self.ctx.Err() != nil {
					return
				}
				continue
			case sidecarRefreshFailed:
				if self.ctx.Err() != nil {
					return
				}
				retryCount, retryNotify := self.requests.Get()
				if retryCount != self.handledRequests {
					// a request arrived during the failed call: it does not wait out the jitter
					break
				}
				retryTimeout := self.args.RetryTimeout()
				select {
				case <-self.ctx.Done():
					return
				case <-retryNotify:
				case <-self.args.Clock.After(retryTimeout):
					// the same token again, unless it changed meanwhile
					if current := self.args.Api.currentByJwt(); current == byJwt {
						continue
					}
				}
			}
			break
		}
	}
}

// One refresh of byJwt, the token this attempt presents.
func (self *sidecarTokenManager) refresh(byJwt string) sidecarRefreshOutcome {
	if expiration := sidecarJwtExpiration(byJwt); !expiration.IsZero() && !self.args.Clock.Now().Before(expiration) {
		self.end(SidecarReasonExpired)
		return sidecarRefreshEnded
	}
	testHookBarrier("token.refresh.before", "")
	refreshed, err := self.args.Api.Refresh(self.ctx)
	testHookBarrier("token.refresh.after", "")
	if err != nil {
		apiErr := &SidecarApiError{}
		if errors.As(err, &apiErr) {
			switch {
			case apiErr.Code == SidecarApiCodeRestoreRequired:
				return self.restore()
			case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusOK:
				self.end(self.refusedReason(apiErr))
				return sidecarRefreshEnded
			}
		}
		if self.ctx.Err() == nil {
			self.args.Log.Infof("[token]refresh failed, retrying: %s", err)
		}
		return sidecarRefreshFailed
	}
	if err := self.install(byJwt, refreshed); err != nil {
		self.args.Log.Warningf("[token]a refreshed token was not installed: %s", err)
		return sidecarRefreshFailed
	}
	return sidecarRefreshInstalled
}

// §18.5's reason for a confirmed rejection.
func (self *sidecarTokenManager) refusedReason(apiErr *SidecarApiError) SidecarStateReason {
	switch {
	case apiErr.Code == SidecarApiCodeSessionRevoked:
		return SidecarReasonSessionEnded
	case self.args.Child:
		return SidecarReasonParentLost
	}
	return SidecarReasonRefused
}

// Ends the generation for reason, once.
func (self *sidecarTokenManager) end(reason SidecarStateReason) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.endedReason != "" {
			return false
		}
		self.endedReason = reason
		return true
	}()
	if !first {
		return
	}
	self.args.Log.Infof("[token]generation %d ended: %s", self.args.Generation, reason)
	if self.args.Refused != nil {
		self.args.Refused(self.args.Generation, reason)
	}
}

// Runs the owner's restore after restore_required.
func (self *sidecarTokenManager) restore() sidecarRefreshOutcome {
	if self.args.Restore == nil {
		self.args.Log.Warningf("[token]restore_required, and nothing restores")
		return sidecarRefreshFailed
	}
	if err := self.args.Restore(self.ctx); err != nil {
		if self.ctx.Err() == nil {
			self.args.Log.Infof("[token]restore failed, retrying: %s", err)
		}
		return sidecarRefreshFailed
	}
	return sidecarRefreshRestored
}

// Checks refreshed names byJwt's client and device, persists it, then installs it in SidecarApi and connect's
// holders, in that order, so no holder carries a token the keychain would lose.
func (self *sidecarTokenManager) install(byJwt string, refreshed string) error {
	previous, previousOk := sidecarJwtIdentityOf(byJwt)
	next, nextOk := sidecarJwtIdentityOf(refreshed)
	if !previousOk || !nextOk || previous != next {
		return errors.New("the refreshed token names another client or device")
	}
	// a token installed meanwhile, by a re-enrollment or another refresh, is newer than this answer
	if current := self.args.Api.currentByJwt(); current != byJwt {
		return errors.New("the token changed during the refresh")
	}
	if self.args.Persist != nil {
		if err := self.args.Persist(refreshed); err != nil {
			return fmt.Errorf("persist: %w", err)
		}
	}
	self.args.Api.SetByJwt(refreshed)
	if self.args.Install != nil {
		self.args.Install(refreshed)
	}
	return nil
}

// Keeps byJwt in secrets, the core's namespace of the network's keychain: enrollment's first token and each
// refreshed one.
func persistSidecarByJwt(secrets SidecarSecrets, byJwt string) error {
	if byJwt == "" {
		return fmt.Errorf("%w: an empty token", ErrSidecarStoreName)
	}
	return secrets.Put(sidecarByJwtRecordName, []byte(byJwt))
}

// The token secrets holds, reported to the privacy harness as it is read.
func loadSidecarByJwt(secrets SidecarSecrets) (string, error) {
	value, err := secrets.Get(sidecarByJwtRecordName)
	if err != nil {
		return "", err
	}
	testHookSecret("by_client_jwt", value)
	return string(value), nil
}

// A component's registrations at api that a Postgres restore can lose: mail host keys, TLS endpoints, the push
// token (§5.6, §19.10). A component that has any implements this beside SidecarComponent, and when refresh answers
// restore_required, the core re-posts its newest binding and then calls each, before it refreshes again.
type SidecarRestorer interface {
	// Posts this component's registrations again. Idempotent: api takes a repeat of what it holds.
	Reregister(ctx context.Context) error
}

// restore_required's steps (§5.6): POST /sidecar/bind with the newest binding, taken once the re-published
// projection admits the identity key, then each restorer's registrations. The first error stops it, and the
// manager retries the whole after its jitter.
func (self *Sidecar) restoreRegistrations(ctx context.Context, restorers []SidecarRestorer) error {
	var secrets SidecarSecrets
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		secrets = self.coreSecrets
	}()
	if secrets == nil {
		return ErrSidecarNoIdentity
	}
	record, err := loadSidecarIdentity(secrets)
	if err != nil {
		return err
	}
	record.keys.erase()
	if _, err := self.sidecarApi.Bind(ctx, record.binding); err != nil {
		if isSidecarRevokedRefusal(err) {
			// a claim, checked against the config and never taken on api's word (CORE-M2-07)
			if _, verifyErr := self.VerifyRevocationClaim(ctx); verifyErr != nil {
				self.log.Infof("[identity]a refused bind's revocation claim was not checked: %s", verifyErr)
			}
		}
		return err
	}
	for _, restorer := range restorers {
		if err := restorer.Reregister(ctx); err != nil {
			return err
		}
	}
	return nil
}

// A refused generation's move: Online drops to Offline as its connection does, then Unenrolled with the reason, each
// naming the generation, so an older generation's refusal is dropped (D-SDK-14).
func (self *Sidecar) tokenRefused(generation int64, reason SidecarStateReason) {
	online := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.lifecycle.state == SidecarStateOnline
	}()
	if online {
		self.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: generation})
	}
	self.applyTransition(sidecarTransition{to: SidecarStateUnenrolled, reason: reason, generation: generation})
}
