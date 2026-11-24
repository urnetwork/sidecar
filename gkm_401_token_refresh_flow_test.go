//go:build !sidecar_http

// A write whose kept token gkm no longer authenticates goes on after one renewal (gkm_api.go's file comment), on the
// grant-lag world (gkm_grant_lag_test.go): the device's client on GkmApi itself, over a keeper in front of the world's
// exchange that keeps each token for its scope set and drops one at ForgetServiceToken, as Sidecar's keeper does, and
// a gkm that answers 401 to the tokens a test marks before its guard on the log's tip judges the rest.

package sidecar_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A token keeper in front of an exchange: it keeps the token of an exchange that granted every scope asked, for the
// scope set in any order, as Sidecar.GrantedServiceToken does, and drops one at forget, as Sidecar.ForgetServiceToken
// does. Safe for concurrent use.
type gkmTokenRenewFlowKeeper struct {
	exchange sidecar.GkmGrantedServiceTokenFunction

	stateLock sync.Mutex
	keyTokens map[string]string
}

// The key a token for resource with scopes is kept under.
func gkmTokenRenewFlowKey(resource string, scopes []string) string {
	return resource + " " + strings.Join(slices.Sorted(slices.Values(scopes)), " ")
}

// Sidecar.GrantedServiceToken's shape: the kept token, else the exchange's.
func (self *gkmTokenRenewFlowKeeper) token(ctx context.Context, resource string, scopes []string) (string, []string, error) {
	key := gkmTokenRenewFlowKey(resource, scopes)
	token, kept := func() (string, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		token, kept := self.keyTokens[key]
		return token, kept
	}()
	if kept {
		return token, slices.Clone(scopes), nil
	}
	token, granted, err := self.exchange(ctx, resource, scopes)
	if err != nil {
		return "", nil, err
	}
	if gkmTokenRenewFlowKey(resource, granted) == key {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.keyTokens[key] = token
	}
	return token, granted, nil
}

// Sidecar.ForgetServiceToken's shape.
func (self *gkmTokenRenewFlowKeeper) forget(resource string, scopes []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.keyTokens, gkmTokenRenewFlowKey(resource, scopes))
}

// gkm answering 401 to a token a test marked as no longer authenticating there, and passing every other request to
// the world's gkm, its guard on the log's tip. Safe for concurrent use.
type gkmTokenRenewFlowGkm struct {
	gkm *gkmGrantLagGkm

	stateLock     sync.Mutex
	expiredTokens map[string]bool
	// every bearer presented, in order
	bearers      []string
	refusedCount int
}

// gkm's 401 to a marked token, else the world's gkm's answer.
func (self *gkmTokenRenewFlowGkm) RoundTrip(request *http.Request) (*http.Response, error) {
	bearer := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	expired := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.bearers = append(self.bearers, bearer)
		if self.expiredTokens[bearer] {
			self.refusedCount += 1
			return true
		}
		return false
	}()
	if expired {
		if request.Body != nil {
			request.Body.Close()
		}
		return gkmGrantLagResponse(gkmGrantLagAnswer{status: http.StatusUnauthorized}), nil
	}
	return self.gkm.RoundTrip(request)
}

// Every token presented so far no longer authenticates at gkm: gkm's clock passed its life, or its key retired.
func (self *gkmTokenRenewFlowGkm) expirePresented() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, bearer := range self.bearers {
		self.expiredTokens[bearer] = true
	}
}

// How many requests it refused 401, and how many bearers were presented.
func (self *gkmTokenRenewFlowGkm) counts() (refused int, presented int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refusedCount, len(self.bearers)
}

// A writer holding generation 1, whose kept token gkm no longer authenticates, past its life by gkm's clock, which
// runs ahead of the device's, or signed under a key gkm retired: its write's read of the generations meets gkm's 401,
// drops the token, asks the exchange once more and goes again at once under the new token, and EnsureWritable answers
// generation 1 with the clock unmoved and nothing claimed. The next write presents the new token, which the keeper
// kept, and asks the exchange nothing. Since gkm-ladder-token-refusal the code before ended the write at the first 401
// with ErrGkmTokenRefused, a refusal for good, where KF7's keychain path had covered it until then.
func TestAWriteWhoseKeptTokenGkmNoLongerAuthenticatesGoesOnAfterOneRenewal(t *testing.T) {
	lag := newGkmGrantLagReader(t, true)
	agent := lag.device
	keeper := &gkmTokenRenewFlowKeeper{exchange: lag.exchange.token(agent.id), keyTokens: map[string]string{}}
	gkm := &gkmTokenRenewFlowGkm{gkm: lag.gkm, expiredTokens: map[string]bool{}}
	api, err := sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:              "https://gkm.example",
		Transport:           gkm,
		GrantedServiceToken: keeper.token,
		ForgetServiceToken:  keeper.forget,
		Settings:            lag.apiSettings,
		Clock:               lag.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	lag.api = api
	lag.setScopes(sidecar.GkmScopeRoleWrite)
	lag.groupApi = &gkmGrantLagApi{api: api, fake: agent.api, hooks: map[string]func(){}}
	lag.restart(lag.groupApi)

	key, err, _ := lag.ensureWritable()
	if err != nil || key.Generation() != 1 {
		t.Fatalf("the writer's first write: %v", err)
	}
	// what a write takes with its token standing: its reads of the generations, each under the batch's kept token
	firstReads := lag.gkm.taken("Generations")
	_, firstPresented := gkm.counts()
	if len(firstReads) == 0 || firstPresented != len(firstReads) {
		t.Fatalf("the first write presented %d tokens for %d reads of the generations", firstPresented, len(firstReads))
	}
	gkm.expirePresented()
	asksBefore := lag.exchange.count(agent.id)

	key, err, took := lag.ensureWritable()
	if err != nil || key.Generation() != 1 || took != 0 {
		t.Fatalf("a write under a kept token gkm no longer authenticates: %v after %s", err, took)
	}
	refused, presented := gkm.counts()
	if refused != 1 || presented-firstPresented != len(firstReads)+1 {
		t.Errorf("gkm refused %d of the write's %d requests, a write with its token standing making %d", refused, presented-firstPresented, len(firstReads))
	}
	if asks := lag.exchange.count(agent.id) - asksBefore; asks != 1 {
		t.Errorf("the write asked the exchange %d times", asks)
	}
	reads := lag.gkm.taken("Generations")[len(firstReads):]
	if len(reads) != len(firstReads) || slices.ContainsFunc(reads, func(read *gkmGrantLagRequest) bool { return read.status != http.StatusOK }) {
		t.Errorf("gkm's guard took %d reads of the generations, a write with its token standing %d", len(reads), len(firstReads))
	}

	asksBefore = lag.exchange.count(agent.id)
	key, err, _ = lag.ensureWritable()
	if err != nil || key.Generation() != 1 {
		t.Fatalf("the write after the renewal: %v", err)
	}
	if asks := lag.exchange.count(agent.id) - asksBefore; asks != 0 {
		t.Errorf("the keeper did not keep the renewed token: %d asks", asks)
	}
	if refusedAfter, _ := gkm.counts(); refusedAfter != refused {
		t.Errorf("gkm refused the renewed token")
	}
	if lag.store.callCount("ClaimGeneration") != 0 || lag.store.newestGeneration(lag.groupId) != 1 {
		t.Errorf("gkm's store took %d claims and holds generation %d", lag.store.callCount("ClaimGeneration"), lag.store.newestGeneration(lag.groupId))
	}
}
