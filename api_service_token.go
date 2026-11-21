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

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

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
// while Locked or with no enrolled client, as the exchange has no token to present then.
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
		return "", errors.New("service token: the keychain is locked")
	case SidecarStateUnenrolled, SidecarStateRevoked:
		return "", errors.New("service token: no enrolled client")
	}
	if self.sidecarApi == nil {
		return "", errors.New("service token: no api")
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
