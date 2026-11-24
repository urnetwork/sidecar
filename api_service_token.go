// Sidecar.ServiceToken (§5.4, §7.8, R-CORE-10): a service token for one audience, evs, gkm, dns, certs or mail, from
// the token exchange, which the sidecar's components present to that service. sockets' token, the sixth audience
// (QD-1029), is SidecarApi's own, which the /socket/* routes keep (api_routes_socket.go). A token lives 15 minutes (owner
// decision 2), and is kept per audience and scope set for SidecarTokenRefreshSettings.ServiceTokenCacheTimeout,
// under that life, and never across a client generation, since a new client's exchange names a new subject. A token
// the service refuses goes at once (ForgetServiceToken), so the caller's one retry exchanges again.
//
// A service token goes only to in-process callers: never into a reply, an environment or a log (I-7, §5.7). It is
// held here and in the caller's request, and nothing here prints one. This file is in both legs, the page Worker's
// included.
//
// ServiceToken's own refusals are typed, so a caller's retry owner tells what can change from what cannot: a keychain
// still locked or no api yet goes again within the owner's bound, and no enrolled client ends the call, as the
// exchange's refusals for good do (sidecarServiceTokenRefusalOf, which evs's retry owners read).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// The exchange's 400 code for a request no scope of which is granted in the newest state api's gate holds (§7.8;
// server/oauth's ErrInvalidScope).
const sidecarExchangeCodeInvalidScope = "invalid_scope"

var (
	// ServiceToken's refusal while Locked: no key is open, so no client's token can be presented. An unlock lifts it,
	// so a caller asks again within its bound. It is ErrSidecarStoreLocked too.
	ErrSidecarServiceTokenLocked = fmt.Errorf("service token: %w", ErrSidecarStoreLocked)
	// ServiceToken's refusal while this sidecar runs no client generation: Unenrolled, before an enrollment, after a
	// credential refused or expired, and for the moment an unlock takes to start the client again, and Revoked, which
	// nothing leaves. No exchange is asked. A call ends with it rather than ask again within its bound, since a token
	// comes only once a generation starts; a retry owner above the call, an owned ref's queue say, tries again at its
	// own pace.
	ErrSidecarServiceTokenNoClient = errors.New("service token: no enrolled client")
	// ServiceToken's refusal of a Sidecar holding no api client to run the exchange on. Nothing is sent, and a caller
	// asks again within its bound.
	ErrSidecarServiceTokenNoApi = errors.New("service token: no api")
)

// How a call whose service token could not be had goes on, by why it could not (§7.8's exchange answers): what a
// service client's retry owner reads, evs's retryRefusingNothing, leases and deliveries among them. The zero value goes
// again at the owner's own wait: no answer from api, a keychain still locked, no api yet, an error of any other kind.
type sidecarServiceTokenRefusal struct {
	// The call ends with its error, since the same request meets the same answer however long it waits.
	final bool
	// The answer is the exchange's request's own, api's answer or SidecarApi's refusal to send it as given, and not the
	// token keeper's state: what an owned ref's queue holds on, as on evs's 403 SCOPE.
	exchange bool
	// The exchange answered invalid_scope, no scope asked granted in the newest state api's gate holds (final too). A
	// grant reaches server gates within §8.9's 5 s of its entry, and may reach this device's own state first, so a retry
	// owner asks again within EvsSettings.ExchangeScopeWaitTimeout of the first such answer before it takes it as final.
	scopeRefused bool
	// The wait the exchange's 429 or 5xx asked for, its retry_after_ms or Retry-After: zero where it named none.
	retryAfter time.Duration
}

// How a call goes on whose service token could not be had for err: the error a ServiceToken of Sidecar's shape answered,
// or one wrapping it. Final where api answered anything but a 429 or a 5xx, which refuse nothing, where SidecarApi would
// not send the request as given (ErrSidecarApiArgs), where api's 2xx was not the exchange's (ErrSidecarApiReply), and
// where no enrolled client holds a token to present (ErrSidecarServiceTokenNoClient): invalid_scope where the newest
// state api's gate holds grants none of the scopes asked, invalid_grant where that state no longer admits the client,
// restore_required in re-seed mode, invalid_request, invalid_target, and invalid_dpop_proof once SidecarApi's own retry
// on api's clock is spent (QD-757). Nothing else is final: no answer from api, a keychain still locked, no api yet.
func sidecarServiceTokenRefusalOf(err error) sidecarServiceTokenRefusal {
	var apiErr *SidecarApiError
	switch {
	case errors.As(err, &apiErr):
		if apiErr.Status == http.StatusTooManyRequests || apiErr.Status/100 == 5 {
			return sidecarServiceTokenRefusal{retryAfter: time.Duration(apiErr.RetryAfterMs) * time.Millisecond}
		}
		return sidecarServiceTokenRefusal{
			final:        true,
			exchange:     true,
			scopeRefused: apiErr.Status == http.StatusBadRequest && apiErr.Code == sidecarExchangeCodeInvalidScope,
		}
	case errors.Is(err, ErrSidecarApiArgs), errors.Is(err, ErrSidecarApiReply):
		return sidecarServiceTokenRefusal{final: true, exchange: true}
	case errors.Is(err, ErrSidecarServiceTokenNoClient):
		return sidecarServiceTokenRefusal{final: true}
	}
	return sidecarServiceTokenRefusal{}
}

// The audience and scope set a cached token was issued for.
type sidecarServiceTokenKey struct {
	resource string
	// the scopes, sorted and joined by spaces, so one set has one key whatever its order
	scopes string
}

// One cached service token.
type sidecarServiceTokenEntry struct {
	accessToken string
	// the client generation whose token the exchange presented
	generation int64
	keepUntil  time.Time
}

// The cache behind ServiceToken. Safe for concurrent use.
type sidecarServiceTokens struct {
	stateLock sync.Mutex
	entries   map[sidecarServiceTokenKey]*sidecarServiceTokenEntry
}

// The token cached for key, current for generation at now.
func (self *sidecarServiceTokens) get(key sidecarServiceTokenKey, generation int64, now time.Time) (string, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.entries[key]
	if !ok {
		return "", false
	}
	if entry.generation != generation || !now.Before(entry.keepUntil) {
		delete(self.entries, key)
		return "", false
	}
	return entry.accessToken, true
}

// Keeps a token, dropping every entry of an older generation.
func (self *sidecarServiceTokens) put(key sidecarServiceTokenKey, entry *sidecarServiceTokenEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.entries == nil {
		self.entries = map[sidecarServiceTokenKey]*sidecarServiceTokenEntry{}
	}
	for otherKey, other := range self.entries {
		if other.generation < entry.generation {
			delete(self.entries, otherKey)
		}
	}
	self.entries[key] = entry
}

// Drops every token, as a generation's end does.
func (self *sidecarServiceTokens) clear() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = nil
}

// Drops the token kept for key, if any.
func (self *sidecarServiceTokens) forget(key sidecarServiceTokenKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.entries, key)
}

// The key a token for resource with scopes is kept under: the scopes sorted, so one set has one key whatever its
// order.
func newSidecarServiceTokenKey(resource string, scopes []string) sidecarServiceTokenKey {
	sortedScopes := slices.Clone(scopes)
	slices.Sort(sortedScopes)
	return sidecarServiceTokenKey{resource: resource, scopes: strings.Join(slices.Compact(sortedScopes), " ")}
}

// Drops the token kept for resource with scopes, so the next ServiceToken for them exchanges again: what a service's
// 401 asks of its caller (evs's UNAUTHENTICATED, §11.20), the token no longer authenticating there. The tokens of
// other audiences and scope sets stay.
func (self *Sidecar) ForgetServiceToken(resource string, scopes []string) {
	self.serviceTokens.forget(newSidecarServiceTokenKey(resource, scopes))
}

// A service token for resource, a service's url, with scopes, for an in-process caller only: never a reply, an
// environment or a log (I-7). A token cached for the same audience and scope set in this client generation, and kept
// under ServiceTokenCacheTimeout and its own expires_in, is answered again; otherwise one exchange runs. Refuses
// ErrSidecarServiceTokenLocked while Locked and ErrSidecarServiceTokenNoClient with no enrolled client, as the exchange
// has no token to present then, and ErrSidecarServiceTokenNoApi with no api to ask.
func (self *Sidecar) ServiceToken(ctx context.Context, resource string, scopes []string) (string, error) {
	var state SidecarState
	var generation int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state = self.lifecycle.state
		generation = self.lifecycle.generation
	}()
	switch state {
	case SidecarStateLocked:
		return "", ErrSidecarServiceTokenLocked
	case SidecarStateUnenrolled, SidecarStateRevoked:
		return "", ErrSidecarServiceTokenNoClient
	}
	if self.sidecarApi == nil {
		return "", ErrSidecarServiceTokenNoApi
	}
	sortedScopes := slices.Clone(scopes)
	slices.Sort(sortedScopes)
	key := newSidecarServiceTokenKey(resource, sortedScopes)
	clock := self.settings.ClockOrReal()
	if accessToken, ok := self.serviceTokens.get(key, generation, clock.Now()); ok {
		return accessToken, nil
	}
	issueTime := clock.Now()
	token, err := self.sidecarApi.ExchangeToken(ctx, resource, sortedScopes)
	if err != nil {
		return "", err
	}
	// The exchange can grant a subset, including no scopes before admission. An
	// attempt made after a grant must exchange again for that original request.
	if key != newSidecarServiceTokenKey(resource, token.Scopes) {
		return token.AccessToken, nil
	}
	keepFor := self.settings.TokenRefreshSettings.ServiceTokenCacheTimeout
	if 0 < token.ExpiresIn && token.ExpiresIn < keepFor {
		keepFor = token.ExpiresIn
	}
	self.serviceTokens.put(key, &sidecarServiceTokenEntry{
		accessToken: token.AccessToken,
		generation:  generation,
		keepUntil:   issueTime.Add(keepFor),
	})
	return token.AccessToken, nil
}
