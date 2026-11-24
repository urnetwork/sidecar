// The client's transport to gkm (§10.14's routes), on every leg: net/http over SidecarApi's transport, which dials by
// the client strategy on a connect leg and is fetch in the page Worker, with no connect import, so the sidecar_http
// leg links it too (§18.10 keeps mls_ and the key ladder in a leg with no components). It is not a SidecarComponent:
// it lives for the network, and each call carries its own deadline.
//
// Each call presents a service token for gkm (aud gkm, 15 minutes, §7.8) from the caller's ServiceToken, which keeps
// a token for its scope set at most 10 of its 15 minutes and never across a client generation. A token carries at
// most 64 repo: scopes, keeping the bearer under the lb's 8 KiB header line (§7.8), so the client batches the scopes
// its state gives it: sorted by repo, 64 a token, so 300 repos cost 5 exchanges per 15 minutes and every call on a
// repo presents the one token whose batch holds it. A call needing a stronger role than its repo's batch carries, as
// a group's creation needs admin, asks for a token of that one scope. A route on no one repo (a sidecar's own
// ReaderKey and KeyPackages, the Welcomes, a public ReaderKey) takes the first batch, since gkm needs an r, rw or
// admin scope on some repo there (QD-177); GET /gkm/welcomes answers per token, so it asks with each.
//
// The token goes only into the request's Authorization header: never into a url, a reply, an error or a log (I-7).
// URLs carry opaque ids only, 32 lowercase hex characters (QD-442), and an error never repeats a url or a body
// (I-13).
//
// Answers map to typed errors: 401 is ErrGkmTokenRefused, any other answer of gkm's but a success is a *GkmError
// carrying its status, its Retry-After and, for a 409 or 412, the winner gkm stored. A 502 or 504 is the lb's
// answer, no answer from gkm at all, and is ErrGkmNoAnswer, never a *GkmError (QD-876, as QD-758 has evs's client
// read one): its callers take it as they take a transport error, so gkm is unreachable for KF7, and a write's
// outcome is unknown and read back, never judged refused. A read retries a 429 or 503 after its Retry-After; a
// write never retries those here, since each flow resolves its own unknown outcome by rereading (§10.5's Rotate,
// §10.6's late wraps).
//
// A 403 to a batch carrying a stronger role on the call's repo than the call needs goes once more, read or write,
// under that repo's one scope at the role the call needs (QD-1179). gkm's guard asks its newest state for the
// strongest right the token holds of those the route takes, with each weaker right of its role that the route takes,
// and honors them only whole (§10.6's checks row; owner decision 563). So while this client's state and gkm's
// disagree on the role, as in the moments after an ACL save narrows or widens it, gkm refuses the batch's stronger
// scope though the client holds the right the call needs; the call's own role alone, which evs's client always
// presents (evsCallScopes), is honored. Every 403 of a route that goes again is answered before gkm writes anything,
// so a write goes again with its same bytes. A call refused for a right the client lacks is refused twice. A call
// whose batch carries its own role there, or that presented its repo's one scope already, goes once, and so does an
// admin route, whose role nothing outranks, unless the exchange left the repo's scope out, below.
//
// The exchange grants only the scopes the newest state api's gate holds gives the client (§7.8), and a grant reaches
// that gate up to §8.9's 5 s after this client's own state may show it. So api's gate lags a new grant in two ways:
// it leaves the new scope out of a batch's token, a partial grant, and it refuses a token of that scope alone
// invalid_scope. gkm's client rides both out within the call (QD-1230, as QD-1226 has evs's client ride the second
// out). A call refused 403 under a batch whose token's granted scopes left out the batch's scope on the call's repo,
// which the client's verified state gives at the role the call needs or a stronger one, and a call whose batch the
// exchange refused invalid_scope, granting it nothing, go again under the call's repo scope alone at the role it
// needs: QD-1179's single-scope form. The exchange's invalid_scope to the call's own scope, which the client's state
// gives, is asked again ReadRetryWait apart until ExchangeScopeWaitTimeout has passed since the call's first such
// answer, the last try at the window's end, and then ends the call. So a new writer's first write after a shrink of the
// repo's holders rotates and lands once api's gate holds its grant (§10.5's Rotate inside EnsureWritable), as its late
// deliveries do, while a scope never granted, or taken away, costs api an exchange and gkm a call about once a second
// for the window. The granted scopes come from GrantedServiceToken; a client built on ServiceToken alone reads every
// token as granting each scope asked, so none of its calls takes this retry.
//
// Every other failure to get a token is read by why it failed (sidecarServiceTokenRefusalOf), and sent nothing to
// gkm, so a write goes on as a read does: a refusal for good, invalid_grant or no enrolled client say, ends the call at
// once, and one that may change, no answer from api, its 429 or 5xx, a keychain still locked or no api yet, goes again
// at most ExchangeRetryCount times. Such a failure carries errGkmNoServiceToken, so a flow that reads an unknown
// outcome back after a lost answer knows nothing was sent.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The body type of every gkm request and answer: a protocol/gkm.proto message, a bare Signed, or MLS bytes.
const gkmHttpContentType = "application/octet-stream"

// The roles of a gkm repo scope (§7.8).
const (
	GkmScopeRoleRead    = "r"
	GkmScopeRoleWrite   = "rw"
	GkmScopeRoleAdmin   = "admin"
	GkmScopeRoleDeposit = "deposit"
)

// The prefix of a member's recovery scope, which an unadmitted client of that member holds alone (§7.8).
const gkmRecoveryScopePrefix = "recovery:"

var (
	// gkm refused the call's token (401): its subject is revoked or voided by rev/, or the token is past its life.
	ErrGkmTokenRefused = errors.New("gkm: token refused")
	// An answer that does not hold §10.14's form: a body that does not parse, or one past its bound. Never read as a
	// refusal.
	ErrGkmReplyInvalid = errors.New("gkm: reply invalid")
	// The client holds no repo scope a call could present: its state gives it none yet.
	ErrGkmNoScope = errors.New("gkm: no repo scope to present")
	// The lb answered in gkm's place, a 502 or a 504, and gkm gave no answer at all (QD-876). gkm answers neither
	// itself, and its routes buffer at the lb, so nginx answers one only after its tries at gkm's blocks failed or
	// timed out, and a block may have applied a write before it died. Never read as a refusal: a caller takes it as
	// it takes a transport error, gkm unreachable and a write's outcome unknown.
	ErrGkmNoAnswer = errors.New("gkm: no answer")
)

// A call's service token could not be had, so nothing reached gkm: carried with the token keeper's error, which
// sidecarServiceTokenRefusalOf reads, once the call has ridden out or retried what it may. A write's outcome is known
// on it, nothing sent.
var errGkmNoServiceToken = errors.New("no service token")

// A service token for an audience url with scopes, Sidecar.ServiceToken's shape: for an in-process caller only.
type GkmServiceTokenFunction func(ctx context.Context, resource string, scopes []string) (string, error)

// A service token for an audience url with scopes, and the scopes the exchange granted it, which may be fewer than
// those asked (§7.8): Sidecar.GrantedServiceToken's shape, for an in-process caller only.
type GkmGrantedServiceTokenFunction func(ctx context.Context, resource string, scopes []string) (token string, grantedScopes []string, err error)

// Every answer of gkm's but a success (§10.14). Its text names the status and never a path, an id or a token. The
// lb's 502 or 504 is no answer of gkm's and never one of these (ErrGkmNoAnswer).
type GkmError struct {
	Status int
	// A 429's or 503's Retry-After.
	RetryAfter time.Duration
	// A 409's or 412's body: what gkm holds where this call's write would have gone, the winner, which the caller
	// judges (§10.9).
	Winner []byte
}

// The status alone.
func (self *GkmError) Error() string {
	return fmt.Sprintf("gkm refused: %d", self.Status)
}

// Whether the answer refuses nothing, so the same request may go again after RetryAfter: a 429 or a 503.
func (self *GkmError) RefusesNothing() bool {
	return self.Status == http.StatusTooManyRequests || self.Status == http.StatusServiceUnavailable
}

// The *GkmError err holds, and false for any other error.
func GkmErrorOf(err error) (*GkmError, bool) {
	var gkmError *GkmError
	if errors.As(err, &gkmError) {
		return gkmError, true
	}
	return nil, false
}

// Whether err is gkm's answer with status.
func IsGkmStatus(err error, status int) bool {
	gkmError, ok := GkmErrorOf(err)
	return ok && gkmError.Status == status
}

// One repo scope the client's newest verified state gives it: the strongest role it holds on the repo for the gkm
// audience, as AclState.EvsAccess answers it (§7.8's exchange computes the same).
type GkmRepoScope struct {
	RepoId Id
	// r, rw, admin, or deposit for a repo the sidecar only deposits to.
	Role string
}

// The scope string, as §7.8's exchange takes it.
func (self GkmRepoScope) scope() string {
	return sidecarExchangeRepoScopePrefix + self.RepoId.String() + ":" + self.Role
}

// Whether a scope of role held reaches a call that needs needed: admin covers rw, rw covers r, and r, rw and admin
// cover deposit's one route (QD-177).
func gkmRoleCovers(held string, needed string) bool {
	rank := func(role string) int {
		switch role {
		case GkmScopeRoleDeposit:
			return 0
		case GkmScopeRoleRead:
			return 1
		case GkmScopeRoleWrite:
			return 2
		case GkmScopeRoleAdmin:
			return 3
		}
		return -1
	}
	if rank(held) < 0 || rank(needed) < 0 {
		return false
	}
	if held == GkmScopeRoleDeposit {
		return needed == GkmScopeRoleDeposit
	}
	return rank(needed) <= rank(held)
}

// What NewGkmApi takes.
type GkmApiArgs struct {
	// SidecarSettings.GkmUrl: absolute, no trailing slash.
	GkmUrl string
	// SidecarApi's transport, which holds every request to an absolute url.
	Transport http.RoundTripper
	// Sidecar.ServiceToken, unused where GrantedServiceToken is set.
	ServiceToken GkmServiceTokenFunction
	// Sidecar.GrantedServiceToken: the token with the scopes the exchange granted it, which tells a call gkm refused
	// because the exchange left the call's repo scope out of a batch's token (QD-1230). nil takes ServiceToken, each of
	// whose tokens is read as granting every scope asked, so no call takes that retry. One of the two is required.
	GrantedServiceToken GkmGrantedServiceTokenFunction
	// nil takes the defaults.
	Settings *GkmSettings
	// nil is real time.
	Clock Clock
}

// The client's half of gkm's HTTP surface. See the file header.
type GkmApi struct {
	baseUrl      string
	transport    http.RoundTripper
	serviceToken GkmGrantedServiceTokenFunction
	settings     *GkmSettings
	clock        Clock

	stateLock sync.Mutex
	// each token's scopes, sorted by repo, at most 64 a batch
	batchScopes [][]string
	// each repo's batch, and the role its scope there carries
	repoIdBatches map[Id]int
	repoIdRoles   map[Id]string
	// whether batchScopes hold an r, rw or admin scope, which a call on no repo presents: what the ReaderKey upkeep
	// waits on after an upload that found none (accessScopes); set under stateLock with batchScopes
	accessScopesHeld *MonitorValue[bool]
}

// A client of the gkm at args.GkmUrl.
func NewGkmApi(args *GkmApiArgs) (*GkmApi, error) {
	switch {
	case args == nil:
		return nil, fmt.Errorf("%w: no gkm api args", errInvalidSettings)
	case args.Transport == nil || args.ServiceToken == nil && args.GrantedServiceToken == nil:
		return nil, fmt.Errorf("%w: a gkm api needs its transport and service token", errInvalidSettings)
	}
	if err := checkServiceUrl("GkmUrl", args.GkmUrl, "http", "https"); err != nil {
		return nil, err
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultGkmSettings()
	}
	serviceToken := args.GrantedServiceToken
	if serviceToken == nil {
		plainServiceToken := args.ServiceToken
		serviceToken = func(ctx context.Context, resource string, scopes []string) (string, []string, error) {
			// a keeper that names no grant: each scope asked is read as granted
			token, err := plainServiceToken(ctx, resource, scopes)
			return token, scopes, err
		}
	}
	return &GkmApi{
		baseUrl:          args.GkmUrl,
		transport:        args.Transport,
		serviceToken:     serviceToken,
		settings:         settings,
		clock:            clockOrReal(args.Clock),
		repoIdBatches:    map[Id]int{},
		repoIdRoles:      map[Id]string{},
		accessScopesHeld: NewMonitorValue(false),
	}, nil
}

// Replaces the scopes the client's state gives it, which its calls present in batches of at most 64: what the state
// applier calls at each new state. A scope of no known role is left out.
func (self *GkmApi) SetRepoScopes(scopes []GkmRepoScope) {
	sorted := []GkmRepoScope{}
	seenRepoIds := map[Id]bool{}
	for _, scope := range scopes {
		if !gkmRoleCovers(scope.Role, scope.Role) || seenRepoIds[scope.RepoId] {
			continue
		}
		seenRepoIds[scope.RepoId] = true
		sorted = append(sorted, scope)
	}
	slices.SortFunc(sorted, func(a GkmRepoScope, b GkmRepoScope) int { return a.RepoId.Cmp(b.RepoId) })
	batchScopes := [][]string{}
	repoIdBatches := map[Id]int{}
	repoIdRoles := map[Id]string{}
	for i, scope := range sorted {
		if i%sidecarExchangeMaxRepoScopeCount == 0 {
			batchScopes = append(batchScopes, []string{})
		}
		batch := len(batchScopes) - 1
		batchScopes[batch] = append(batchScopes[batch], scope.scope())
		repoIdBatches[scope.RepoId] = batch
		repoIdRoles[scope.RepoId] = scope.Role
	}
	accessScopesHeld := slices.ContainsFunc(sorted, func(scope GkmRepoScope) bool { return scope.Role != GkmScopeRoleDeposit })
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.batchScopes = batchScopes
	self.repoIdBatches = repoIdBatches
	self.repoIdRoles = repoIdRoles
	// a leaf lock, taken under stateLock so two calls leave it as their batches stand
	self.accessScopesHeld.Set(accessScopesHeld)
}

// Whether the scopes the client's state gives it hold one a call on no repo can present, an r, rw or admin scope, as
// a ReaderKey's upload needs (scopesFor), and a channel closed once that changes, armed at the same instant: what the
// ReaderKey upkeep waits on after an upload that found none to present (ErrGkmNoScope), so it publishes the key as
// soon as a state gives it one.
func (self *GkmApi) accessScopes() (held bool, changed <-chan struct{}) {
	return self.accessScopesHeld.Get()
}

// What one call presents: its token's scopes, and those of the one retry a refusal of them takes.
type gkmCallScopes struct {
	scopes []string
	// The call's repo scope alone at the role the call needs, where scopes is a batch holding a scope on that repo
	// whose role covers the call's: what a 403 to the batch goes again under where the batch carries a stronger role
	// there (QD-1179) or the exchange left the batch's scope there out of its token, and what the batch's
	// invalid_scope does (QD-1230). nil where scopes is that one scope already, and for a call on no repo.
	narrowedScopes []string
	// The batch's scope on the call's repo, which the token's granted scopes are read for: "" with no narrowed retry.
	batchScope string
	// Whether the batch's role on the repo outranks the call's, so a 403 to it goes again whatever the exchange granted.
	stronger bool
	// Whether the client's verified state gives the call's repo at its role or a stronger one: the exchange's
	// invalid_scope to the call's own scope is ridden out only then (QD-1230).
	stateGives bool
}

// The scopes a call on repoId needing role presents: the batch holding the repo when its role covers role, else that
// one scope alone, and that one scope as the narrowed retry's where the batch is more than it. A call on no repo,
// repoId nil, presents the first batch holding an r, rw or admin scope, and has no narrowed retry.
func (self *GkmApi) scopesFor(repoId *Id, role string) (gkmCallScopes, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if repoId == nil {
		for _, scopes := range self.batchScopes {
			for _, scope := range scopes {
				if !strings.HasSuffix(scope, ":"+GkmScopeRoleDeposit) {
					return gkmCallScopes{scopes: scopes}, nil
				}
			}
		}
		return gkmCallScopes{}, ErrGkmNoScope
	}
	repoScopes := []string{GkmRepoScope{RepoId: *repoId, Role: role}.scope()}
	batch, ok := self.repoIdBatches[*repoId]
	batchRole := self.repoIdRoles[*repoId]
	if !ok || !gkmRoleCovers(batchRole, role) {
		// a role the client's state does not give: that one scope, refused as gkm or the exchange refuses it
		return gkmCallScopes{scopes: repoScopes}, nil
	}
	callScopes := gkmCallScopes{scopes: self.batchScopes[batch], stateGives: true}
	if !slices.Equal(callScopes.scopes, repoScopes) {
		callScopes.narrowedScopes = repoScopes
		callScopes.batchScope = GkmRepoScope{RepoId: *repoId, Role: batchRole}.scope()
		// covers and is not role: a stronger role, which gkm refuses whole while its state does not give it
		callScopes.stronger = batchRole != role
	}
	return callScopes, nil
}

// Every batch holding an r, rw or admin scope, for a route gkm answers per token.
func (self *GkmApi) accessBatches() [][]string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	batches := [][]string{}
	for _, scopes := range self.batchScopes {
		if slices.ContainsFunc(scopes, func(scope string) bool { return !strings.HasSuffix(scope, ":"+GkmScopeRoleDeposit) }) {
			batches = append(batches, scopes)
		}
	}
	return batches
}

// An id as a path or query names it: 32 lowercase hex characters (QD-442).
func gkmUrlId(id Id) string {
	return hex.EncodeToString(id[:])
}

// One call to gkm.
type gkmCall struct {
	// The route's template for errors: method and pattern, which hold no id.
	route  string
	method string
	// After the service url, opaque ids only (I-13), with its query.
	path string
	// The token's scopes, and the narrowed retry's.
	scopes gkmCallScopes
	// The body: a message's bytes, a Signed's, or none.
	body []byte
	// Whether a 429 or 503 goes again (reads only).
	retry bool
}

// A message's bytes for a body.
func gkmBody(message proto.Message) ([]byte, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("%w: a body that does not marshal: %w", ErrGkmMalformed, err)
	}
	return body, nil
}

// Sends call and answers a success's status and body, at most ReplyMaxByteCount, or an error for any other answer.
// gkm's own 429 or 503 goes again as call.retry allows. Its 403 to a batch with narrowed scopes goes again once, at
// once, under those scopes, which the rest of the call presents, where the batch carries a stronger role on the
// call's repo (QD-1179) or the token's granted scopes left the batch's scope there out (QD-1230); ReadRetryCount does
// not count that retry, and the batch's invalid_scope takes it too. A token that could not be had is read by why
// (sidecarServiceTokenRefusalOf): the exchange's invalid_scope to the call's own scope, which the client's state
// gives, goes again ReadRetryWait apart until ExchangeScopeWaitTimeout has passed since the call's first, the last try
// at the window's end; another refusal for good ends the call at once; and a failure that may change goes again at
// most ExchangeRetryCount times. No answer, the lb's 502 or 504 among them, comes back at once, as a transport error
// does.
func (self *GkmApi) do(ctx context.Context, call *gkmCall) (int, []byte, error) {
	scopes := call.scopes.scopes
	// whether scopes is the call's own repo scope alone or holds no other to narrow to, so nothing narrows it again
	narrowed := call.scopes.narrowedScopes == nil
	retryCount := 0
	exchangeRetryCount := 0
	// the first of the exchange's invalid_scope answers to the call's own scope, zero while none came
	var scopeRefusedAt time.Time
	for {
		status, body, grantedScopes, err := self.doOnce(ctx, call, scopes)
		if err == nil {
			return status, body, nil
		}
		if ctx.Err() != nil {
			return 0, nil, err
		}
		var wait time.Duration
		if errors.Is(err, errGkmNoServiceToken) {
			refusal := sidecarServiceTokenRefusalOf(err)
			switch {
			case refusal.scopeRefused && !narrowed:
				// QD-1230: the batch was granted nothing, its scope on the call's repo left out with the rest, and the
				// call's own scope alone may be
				scopes, narrowed = call.scopes.narrowedScopes, true
				continue
			case refusal.scopeRefused && call.scopes.stateGives && 0 < self.settings.ExchangeScopeWaitTimeout:
				// QD-1230: the call's own scope, which this client's verified state gives, is refused while api's gate
				// lags the grant, §8.9's 5 s at most
				now := self.clock.Now()
				if scopeRefusedAt.IsZero() {
					scopeRefusedAt = now
				}
				left := scopeRefusedAt.Add(self.settings.ExchangeScopeWaitTimeout).Sub(now)
				if left <= 0 {
					return 0, nil, err
				}
				wait = left
				if 0 < self.settings.ReadRetryWait {
					wait = min(self.settings.ReadRetryWait, left)
				}
			case refusal.final:
				return 0, nil, err
			default:
				// no answer from api, its 429 or 5xx, a keychain still locked, no api yet: nothing reached gkm, so a
				// write goes again as a read does
				if self.settings.ExchangeRetryCount <= exchangeRetryCount {
					return 0, nil, err
				}
				exchangeRetryCount += 1
				wait = self.settings.ReadRetryWait
				if 0 < refusal.retryAfter {
					if self.settings.ReadRetryMaxWait < refusal.retryAfter {
						return 0, nil, err
					}
					wait = refusal.retryAfter
				}
			}
		} else {
			gkmError, ok := GkmErrorOf(err)
			if !ok {
				return 0, nil, err
			}
			if gkmError.Status == http.StatusForbidden && !narrowed && (call.scopes.stronger || !slices.Contains(grantedScopes, call.scopes.batchScope)) {
				// QD-1179: the batch's stronger role on the call's repo, which gkm's state does not give yet or any
				// longer; QD-1230: a batch whose token the exchange granted without its scope on the call's repo. The
				// role the call needs alone may be honored
				scopes, narrowed = call.scopes.narrowedScopes, true
				continue
			}
			if !call.retry || !gkmError.RefusesNothing() || self.settings.ReadRetryCount <= retryCount {
				return 0, nil, err
			}
			retryCount += 1
			wait = gkmError.RetryAfter
			if wait <= 0 {
				wait = self.settings.ReadRetryWait
			}
			if self.settings.ReadRetryMaxWait < wait {
				return 0, nil, err
			}
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-self.clock.After(wait):
		}
	}
}

// One attempt, presenting a token of scopes. Answers the scopes the exchange granted the token beside gkm's answer,
// nil where no token could be had, which comes back carrying errGkmNoServiceToken.
func (self *GkmApi) doOnce(ctx context.Context, call *gkmCall, scopes []string) (int, []byte, []string, error) {
	token, grantedScopes, err := self.serviceToken(ctx, self.baseUrl, scopes)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("gkm %s: %w: %w", call.route, errGkmNoServiceToken, err)
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.RequestTimeout, cancel)
	defer stop()
	var bodyReader io.Reader
	if call.body != nil {
		bodyReader = bytes.NewReader(call.body)
	}
	request, err := http.NewRequestWithContext(callCtx, call.method, self.baseUrl+call.path, bodyReader)
	if err != nil {
		return 0, nil, grantedScopes, fmt.Errorf("gkm %s: a request that does not build", call.route)
	}
	if call.body != nil {
		request.Header.Set("Content-Type", gkmHttpContentType)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, grantedScopes, ctx.Err()
		}
		// a transport error may hold the url, which holds only ids, but never the token
		return 0, nil, grantedScopes, fmt.Errorf("gkm %s: %w", call.route, err)
	}
	defer response.Body.Close()
	if gkmStatusIsNoAnswer(response.StatusCode) {
		// the lb's answer: nothing of its body is read, so an error page past the bound or cut short changes nothing
		return 0, nil, grantedScopes, gkmErrorOfAnswer(call.route, response.StatusCode, response.Header, nil)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ReplyMaxByteCount+1))
	if err != nil {
		return 0, nil, grantedScopes, fmt.Errorf("%w: %s: the answer was cut short", ErrGkmReplyInvalid, call.route)
	}
	if self.settings.ReplyMaxByteCount < int64(len(body)) {
		return 0, nil, grantedScopes, fmt.Errorf("%w: %s: an answer past %d bytes", ErrGkmReplyInvalid, call.route, self.settings.ReplyMaxByteCount)
	}
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusCreated {
		return response.StatusCode, body, grantedScopes, nil
	}
	return 0, nil, grantedScopes, gkmErrorOfAnswer(call.route, response.StatusCode, response.Header, body)
}

// Whether an answer of status is the lb's and none of gkm's: a 502 or a 504 (QD-876). gkm answers neither on any
// route (§10.14), and no refusal of gkm's has a body form a 502 or 504 could carry (a 409's or 412's body is the
// winner, and every other refusal has none), so no body is read to tell: every one is nginx's, when both of its
// tries at gkm's blocks failed, or each passed its read timeout.
func gkmStatusIsNoAnswer(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusGatewayTimeout
}

// The error an answer of route that is no success gives, from its status, header and body. A 401 is
// ErrGkmTokenRefused. A 502 or 504 is ErrGkmNoAnswer, with nothing of its header or body read: the lb's answer says
// nothing of what gkm did, so it carries no Retry-After and no winner, and it is no *GkmError, which every caller
// reads as gkm's refusal. Any other status is gkm's refusal, a *GkmError with its Retry-After and, for a 409 or
// 412, its body as the winner.
func gkmErrorOfAnswer(route string, status int, header http.Header, body []byte) error {
	switch {
	case status == http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrGkmTokenRefused, route)
	case gkmStatusIsNoAnswer(status):
		return fmt.Errorf("%w: %s: the lb answered %d", ErrGkmNoAnswer, route, status)
	}
	gkmError := &GkmError{Status: status}
	if seconds, err := strconv.Atoi(header.Get("Retry-After")); err == nil && 0 < seconds {
		gkmError.RetryAfter = time.Duration(seconds) * time.Second
	}
	if status == http.StatusConflict || status == http.StatusPreconditionFailed {
		gkmError.Winner = body
	}
	return gkmError
}

// Sends call and unmarshals a success's body into reply, which may be nil for none.
func (self *GkmApi) callMessage(ctx context.Context, call *gkmCall, reply proto.Message) error {
	_, body, err := self.do(ctx, call)
	if err != nil {
		return err
	}
	if reply == nil {
		return nil
	}
	if err := proto.Unmarshal(body, reply); err != nil {
		return fmt.Errorf("%w: %s: a body that does not parse", ErrGkmReplyInvalid, call.route)
	}
	return nil
}

// A group route's path: /gkm/groups/<group_id> and rest.
func gkmGroupPath(groupId Id, rest string) string {
	return "/gkm/groups/" + gkmUrlId(groupId) + rest
}

// POST /gkm/key-packages: this sidecar's KeyPackages, each its MLSMessage (§10.6's KeyPackages row).
func (self *GkmApi) UploadKeyPackages(ctx context.Context, keyPackages [][]byte) error {
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	body, err := gkmBody(&protocol.GkmKeyPackagesRequest{KeyPackages: keyPackages})
	if err != nil {
		return err
	}
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/key-packages", method: http.MethodPost, path: "/gkm/key-packages", scopes: scopes, body: body}, nil)
}

// POST /gkm/key-packages/claim: a KeyPackage of target's for an Add to groupId, a group of repoId.
func (self *GkmApi) ClaimKeyPackage(ctx context.Context, repoId Id, groupId Id, target Id) (*protocol.GkmKeyPackageClaimReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleWrite)
	if err != nil {
		return nil, err
	}
	body, err := gkmBody(&protocol.GkmKeyPackageClaimRequest{GroupId: groupId.Bytes(), Target: target.Bytes()})
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmKeyPackageClaimReply{}
	call := &gkmCall{route: "POST /gkm/key-packages/claim", method: http.MethodPost, path: "/gkm/key-packages/claim", scopes: scopes, body: body}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// POST /gkm/reader-key: this sidecar's new ReaderKey.
func (self *GkmApi) UploadReaderKey(ctx context.Context, readerKey *bridge.Signed) error {
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	body, err := gkmBody(readerKey)
	if err != nil {
		return err
	}
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/reader-key", method: http.MethodPost, path: "/gkm/reader-key", scopes: scopes, body: body}, nil)
}

// GET /gkm/reader-key/<sidecar_id>: the ReaderKey gkm serves for a sidecar, unchecked, or nil for none. A sealer
// checks it before it seals (§10.5's readerkey row).
func (self *GkmApi) ReaderKey(ctx context.Context, sidecarId Id) (*bridge.Signed, error) {
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	readerKey := &bridge.Signed{}
	call := &gkmCall{route: "GET /gkm/reader-key/{sidecar_id}", method: http.MethodGet, path: "/gkm/reader-key/" + gkmUrlId(sidecarId), scopes: scopes, retry: true}
	err = self.callMessage(ctx, call, readerKey)
	if IsGkmStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return readerKey, nil
}

// POST /gkm/reader-keys, in batches of 256: each sidecar's ReaderKey in order, nil for one with none.
func (self *GkmApi) ReaderKeys(ctx context.Context, sidecarIds []Id) ([]*bridge.Signed, error) {
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	readerKeys := []*bridge.Signed{}
	batchCount := max(1, self.settings.ReaderKeysBatchCount)
	for start := 0; start < len(sidecarIds); start += batchCount {
		request := &protocol.GkmReaderKeysRequest{}
		for _, sidecarId := range sidecarIds[start:min(len(sidecarIds), start+batchCount)] {
			request.SidecarIds = append(request.SidecarIds, sidecarId.Bytes())
		}
		body, err := gkmBody(request)
		if err != nil {
			return nil, err
		}
		reply := &protocol.GkmReaderKeysReply{}
		call := &gkmCall{route: "POST /gkm/reader-keys", method: http.MethodPost, path: "/gkm/reader-keys", scopes: scopes, body: body, retry: true}
		if err := self.callMessage(ctx, call, reply); err != nil {
			return nil, err
		}
		if len(reply.GetReaderKeys()) != len(request.SidecarIds) {
			return nil, fmt.Errorf("%w: POST /gkm/reader-keys: %d answers for %d sidecars", ErrGkmReplyInvalid, len(reply.GetReaderKeys()), len(request.SidecarIds))
		}
		for _, readerKey := range reply.GetReaderKeys() {
			if len(readerKey.GetBody()) == 0 {
				readerKey = nil
			}
			readerKeys = append(readerKeys, readerKey)
		}
	}
	return readerKeys, nil
}

// The path of a forwarding Delegation's reader key at gkm, or an error for an id of another size than 32 bytes.
func gkmDelegationKeyRoutePath(delegationId []byte) (string, error) {
	pathId, err := GkmDelegationPathId(delegationId)
	if err != nil {
		return "", err
	}
	return "/gkm/delegation-keys/" + pathId, nil
}

// PUT /gkm/delegation-keys/<delegation_id>: a forwarding Delegation's reader key, its 1,216 B X-Wing public key, by
// the sidecar that signed the Delegation (DESIGN-DETAILS 4.2.6's S3), under a token holding r, rw or admin on some
// repo. gkm creates the object once, holding the key to the Delegation's row in its newest state: a 409 while that
// state does not hold the row yet, which the same call answers once it does, and the same bytes again answer
// success, so a retry after a lost answer is safe.
func (self *GkmApi) UploadDelegationKey(ctx context.Context, delegationId []byte, readerKey []byte) error {
	path, err := gkmDelegationKeyRoutePath(delegationId)
	if err != nil {
		return err
	}
	if len(readerKey) != gkmXWingPublicKeyByteCount {
		return fmt.Errorf("%w: a reader key of %d bytes", ErrGkmMalformed, len(readerKey))
	}
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	call := &gkmCall{route: "PUT /gkm/delegation-keys/{delegation_id}", method: http.MethodPut, path: path, scopes: scopes, body: bytes.Clone(readerKey)}
	_, _, err = self.do(ctx, call)
	return err
}

// GET /gkm/delegation-keys/<delegation_id>: the reader key gkm holds for a forwarding Delegation, unchecked, or nil
// for none, under the scopes of configRepoId, the network's config repo, whose readers alone may read it. A sealer
// holds it to the Delegation's row before it seals to it (GkmForwardingReaderKey).
func (self *GkmApi) DelegationKey(ctx context.Context, configRepoId Id, delegationId []byte) ([]byte, error) {
	path, err := gkmDelegationKeyRoutePath(delegationId)
	if err != nil {
		return nil, err
	}
	scopes, err := self.scopesFor(&configRepoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	call := &gkmCall{route: "GET /gkm/delegation-keys/{delegation_id}", method: http.MethodGet, path: path, scopes: scopes, retry: true}
	_, body, err := self.do(ctx, call)
	if IsGkmStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(body) != gkmXWingPublicKeyByteCount {
		return nil, fmt.Errorf("%w: GET /gkm/delegation-keys: a key of %d bytes", ErrGkmReplyInvalid, len(body))
	}
	return body, nil
}

// POST /gkm/delegation-keys (QD-637): the reader keys gkm holds for forwarding Delegations, unchecked, in the order
// asked, nil for one with none stored, in requests of at most 256 under the scopes of configRepoId, the network's
// config repo, whose readers alone may read them. A request gkm answers 404 names no forwarding Delegation its state
// holds, so each of its entries is nil. An entry is passed on as gkm sent it, whatever its size: a sealer holds each
// key to its Delegation's row before it seals to it (GkmForwardingReaderKey), so one bad entry costs one holder its
// wrap and fails nothing else.
func (self *GkmApi) DelegationKeys(ctx context.Context, configRepoId Id, delegationIds [][]byte) ([][]byte, error) {
	for _, delegationId := range delegationIds {
		if len(delegationId) != gkmDelegationIdByteCount {
			return nil, fmt.Errorf("%w: a delegation id of %d bytes", ErrGkmMalformed, len(delegationId))
		}
	}
	scopes, err := self.scopesFor(&configRepoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	readerKeys := make([][]byte, 0, len(delegationIds))
	batchCount := max(1, self.settings.DelegationKeysBatchCount)
	for start := 0; start < len(delegationIds); start += batchCount {
		request := &protocol.GkmDelegationKeysRequest{}
		for _, delegationId := range delegationIds[start:min(len(delegationIds), start+batchCount)] {
			request.DelegationIds = append(request.DelegationIds, bytes.Clone(delegationId))
		}
		body, err := gkmBody(request)
		if err != nil {
			return nil, err
		}
		reply := &protocol.GkmDelegationKeysReply{}
		call := &gkmCall{route: "POST /gkm/delegation-keys", method: http.MethodPost, path: "/gkm/delegation-keys", scopes: scopes, body: body, retry: true}
		err = self.callMessage(ctx, call, reply)
		if IsGkmStatus(err, http.StatusNotFound) {
			for range request.DelegationIds {
				readerKeys = append(readerKeys, nil)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(reply.GetReaderKeys()) != len(request.DelegationIds) {
			return nil, fmt.Errorf("%w: POST /gkm/delegation-keys: %d answers for %d Delegations", ErrGkmReplyInvalid, len(reply.GetReaderKeys()), len(request.DelegationIds))
		}
		for _, readerKey := range reply.GetReaderKeys() {
			if len(readerKey) == 0 {
				readerKey = nil
			}
			readerKeys = append(readerKeys, readerKey)
		}
	}
	return readerKeys, nil
}

// POST /gkm/groups (KF1): the GroupForm, epoch 0 and generation 1 of repoId's group.
func (self *GkmApi) CreateGroup(ctx context.Context, repoId Id, request *protocol.GkmGroupCreateRequest) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleAdmin)
	if err != nil {
		return err
	}
	body, err := gkmBody(request)
	if err != nil {
		return err
	}
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups", method: http.MethodPost, path: "/gkm/groups", scopes: scopes, body: body}, nil)
}

// GET /gkm/groups/<id>: the GroupForm naming a group of repoId.
func (self *GkmApi) Group(ctx context.Context, repoId Id, groupId Id) (*protocol.GkmGroupReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmGroupReply{}
	call := &gkmCall{route: "GET /gkm/groups/{group_id}", method: http.MethodGet, path: gkmGroupPath(groupId, ""), scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// GET /gkm/repos/<id>/forms: a repo's Signed GroupForms, oldest first (QD-156).
func (self *GkmApi) Forms(ctx context.Context, repoId Id) (*protocol.GkmFormsReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmFormsReply{}
	call := &gkmCall{route: "GET /gkm/repos/{repo_id}/forms", method: http.MethodGet, path: "/gkm/repos/" + gkmUrlId(repoId) + "/forms", scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// POST /gkm/repos/<id>/forms: a re-form's GroupForm and the new group's epoch 0 (§10.8).
func (self *GkmApi) Reform(ctx context.Context, repoId Id, request *protocol.GkmGroupReformRequest) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleAdmin)
	if err != nil {
		return err
	}
	body, err := gkmBody(request)
	if err != nil {
		return err
	}
	call := &gkmCall{route: "POST /gkm/repos/{repo_id}/forms", method: http.MethodPost, path: "/gkm/repos/" + gkmUrlId(repoId) + "/forms", scopes: scopes, body: body}
	return self.callMessage(ctx, call, nil)
}

// GET /gkm/groups/<id>/epochs?after=: the epoch objects after an epoch, in order, up to gkm's bound; ask again after
// the last until none comes.
func (self *GkmApi) Epochs(ctx context.Context, repoId Id, groupId Id, after uint64) (*protocol.GkmEpochsReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmEpochsReply{}
	path := gkmGroupPath(groupId, "/epochs?after="+strconv.FormatUint(after, 10))
	call := &gkmCall{route: "GET /gkm/groups/{group_id}/epochs", method: http.MethodGet, path: path, scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// GET /gkm/groups/<id>/epochs with no after: the epoch objects from epoch 0, which a group no commit has moved holds
// alone, and which a recovery self-join reads its GroupInfo from (§10.8).
func (self *GkmApi) EpochsFromStart(ctx context.Context, repoId Id, groupId Id) (*protocol.GkmEpochsReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmEpochsReply{}
	call := &gkmCall{route: "GET /gkm/groups/{group_id}/epochs", method: http.MethodGet, path: gkmGroupPath(groupId, "/epochs"), scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// POST /gkm/groups/<id>/epochs/<n>: a commit that makes epoch n. A 409 is a *GkmError whose Winner is the
// GkmEpochObject that won the epoch (KF6).
func (self *GkmApi) CommitEpoch(ctx context.Context, repoId Id, groupId Id, epoch uint64, request *protocol.GkmEpochRequest) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	body, err := gkmBody(request)
	if err != nil {
		return err
	}
	path := gkmGroupPath(groupId, "/epochs/"+strconv.FormatUint(epoch, 10))
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups/{group_id}/epochs/{n}", method: http.MethodPost, path: path, scopes: scopes, body: body}, nil)
}

// GET /gkm/groups/<id>/gen?since=: the Signed GenRotates after a generation, in order, up to gkm's bound.
func (self *GkmApi) Generations(ctx context.Context, repoId Id, groupId Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmGenerationsReply{}
	path := gkmGroupPath(groupId, "/gen?since="+strconv.FormatUint(since, 10))
	call := &gkmCall{route: "GET /gkm/groups/{group_id}/gen", method: http.MethodGet, path: path, scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// POST /gkm/groups/<id>/gen/<g>: the claim of generation g, a Signed GenRotate, where alone a generation exists
// (D-KEYS-15). A 412 is a *GkmError whose Winner is the GenRotate that holds g, which the rotator judges (§10.5's
// Rotate, step 4).
func (self *GkmApi) ClaimGeneration(ctx context.Context, repoId Id, groupId Id, generation uint64, rotate *bridge.Signed) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleWrite)
	if err != nil {
		return err
	}
	body, err := gkmBody(rotate)
	if err != nil {
		return err
	}
	path := gkmGroupPath(groupId, "/gen/"+strconv.FormatUint(generation, 10))
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups/{group_id}/gen/{g}", method: http.MethodPost, path: path, scopes: scopes, body: body}, nil)
}

// What a deliveries read asks for: the recipient whose deliveries it wants, and on a late delivery's ask the key it
// wants one to and when it first asked (§10.6's late wraps).
type GkmWrapsQuery struct {
	// s:<sidecar_id> or d:<delegation_id>, as the wrap path writes it.
	Recipient string
	// The first 8 bytes of the wanted key's SHA-256: k8. Nil asks for no late delivery.
	Want []byte
	// The recipient's first ask, which GkmLateAsks keeps.
	Since time.Time
}

// GET /gkm/groups/<id>/wraps/<g>: the caller's deliveries of generation g, the wanted key's first. A query with Want
// is a late delivery's ask, which hints wrap-pending at gkm; GkmLateAsks keeps a recipient to one a minute.
func (self *GkmApi) Wraps(ctx context.Context, repoId Id, groupId Id, generation uint64, query *GkmWrapsQuery) (*protocol.GkmWrapsReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	if query != nil {
		if query.Recipient != "" {
			values.Set("recipient", query.Recipient)
		}
		if query.Want != nil {
			values.Set("want", hex.EncodeToString(query.Want))
			values.Set("since", strconv.FormatInt(query.Since.UnixMilli(), 10))
		}
	}
	path := gkmGroupPath(groupId, "/wraps/"+strconv.FormatUint(generation, 10))
	if 0 < len(values) {
		path += "?" + values.Encode()
	}
	reply := &protocol.GkmWrapsReply{}
	call := &gkmCall{route: "GET /gkm/groups/{group_id}/wraps/{g}", method: http.MethodGet, path: path, scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// The path segment of a generation's commitment prefix: c8, hex of C_g's first 8 bytes.
func gkmUrlCommitmentPrefix(commitment []byte) (string, error) {
	return gkmPathPrefix(commitment)
}

// POST /gkm/groups/<id>/wraps/<g>/<c8>: 1 to 256 Signed deliveries of generation g, staged or late, answered one
// result each, in order (QD-066).
func (self *GkmApi) UploadWraps(ctx context.Context, repoId Id, groupId Id, generation uint64, commitment []byte, batch *protocol.GkmWrapBatch) (*protocol.GkmWrapBatchReply, error) {
	return self.uploadBatch(ctx, repoId, "POST /gkm/groups/{group_id}/wraps/{g}/{c8}", "/wraps/", groupId, generation, commitment, batch, len(batch.GetDeliveries()))
}

// POST /gkm/groups/<id>/recovery-wraps/<g>/<c8>: a rotator's RecoveryWraps of generation g, answered as UploadWraps
// is, a 412's winner being the stored ciphertext.
func (self *GkmApi) UploadRecoveryWraps(ctx context.Context, repoId Id, groupId Id, generation uint64, commitment []byte, batch *protocol.GkmRecoveryWrapBatch) (*protocol.GkmWrapBatchReply, error) {
	return self.uploadBatch(ctx, repoId, "POST /gkm/groups/{group_id}/recovery-wraps/{g}/{c8}", "/recovery-wraps/", groupId, generation, commitment, batch, len(batch.GetItems()))
}

// One batch upload, its reply held to one result per item.
func (self *GkmApi) uploadBatch(ctx context.Context, repoId Id, route string, segment string, groupId Id, generation uint64, commitment []byte, batch proto.Message, itemCount int) (*protocol.GkmWrapBatchReply, error) {
	c8, err := gkmUrlCommitmentPrefix(commitment)
	if err != nil {
		return nil, err
	}
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	body, err := gkmBody(batch)
	if err != nil {
		return nil, err
	}
	path := gkmGroupPath(groupId, segment+strconv.FormatUint(generation, 10)+"/"+c8)
	reply := &protocol.GkmWrapBatchReply{}
	if err := self.callMessage(ctx, &gkmCall{route: route, method: http.MethodPost, path: path, scopes: scopes, body: body}, reply); err != nil {
		return nil, err
	}
	if len(reply.GetResults()) != itemCount {
		return nil, fmt.Errorf("%w: %s: %d results for %d items", ErrGkmReplyInvalid, route, len(reply.GetResults()), itemCount)
	}
	return reply, nil
}

// POST /gkm/groups/<id>/ladder: a re-formed group's old generations, at most 64 a call, ascending (QD-074).
func (self *GkmApi) UploadLadder(ctx context.Context, repoId Id, groupId Id, request *protocol.GkmLadderRequest) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleAdmin)
	if err != nil {
		return err
	}
	body, err := gkmBody(request)
	if err != nil {
		return err
	}
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups/{group_id}/ladder", method: http.MethodPost, path: gkmGroupPath(groupId, "/ladder"), scopes: scopes, body: body}, nil)
}

// POST /gkm/groups/<id>/welcome/<n>: epoch n's Welcome and its recipients, after the epoch, by its uploader.
func (self *GkmApi) UploadWelcome(ctx context.Context, repoId Id, groupId Id, epoch uint64, request *protocol.GkmWelcomeRequest) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleWrite)
	if err != nil {
		return err
	}
	body, err := gkmBody(request)
	if err != nil {
		return err
	}
	path := gkmGroupPath(groupId, "/welcome/"+strconv.FormatUint(epoch, 10))
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups/{group_id}/welcome/{n}", method: http.MethodPost, path: path, scopes: scopes, body: body}, nil)
}

// HEAD /gkm/groups/<id>/welcome/<n> (QD-747): whether epoch n's Welcome stands at gkm, its 200 or its 404, which
// carry no body. Any other answer is an error and says nothing of the Welcome: a caller removes no joiner on one.
func (self *GkmApi) WelcomeStands(ctx context.Context, repoId Id, groupId Id, epoch uint64) (bool, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleWrite)
	if err != nil {
		return false, err
	}
	path := gkmGroupPath(groupId, "/welcome/"+strconv.FormatUint(epoch, 10))
	call := &gkmCall{route: "HEAD /gkm/groups/{group_id}/welcome/{n}", method: http.MethodHead, path: path, scopes: scopes, retry: true}
	status, _, err := self.do(ctx, call)
	switch {
	case err == nil && status == http.StatusOK:
		return true, nil
	case err == nil:
		return false, fmt.Errorf("%w: %s: a success that is not a 200", ErrGkmReplyInvalid, call.route)
	case IsGkmStatus(err, http.StatusNotFound):
		return false, nil
	}
	return false, err
}

// GET /gkm/groups/<id>/group-info?want=: the pointer at 16 leaves or fewer, else the sealed GroupInfo; nil want asks
// for no newer one, and one older than want hints wrap-pending at gkm (KF5).
func (self *GkmApi) GroupInfo(ctx context.Context, repoId Id, groupId Id, want *uint64) (*protocol.GkmGroupInfoObject, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return nil, err
	}
	path := gkmGroupPath(groupId, "/group-info")
	if want != nil {
		path += "?want=" + strconv.FormatUint(*want, 10)
	}
	reply := &protocol.GkmGroupInfoObject{}
	call := &gkmCall{route: "GET /gkm/groups/{group_id}/group-info", method: http.MethodGet, path: path, scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// POST /gkm/groups/<id>/group-info: the pointer, or above 16 leaves the sealed GroupInfo.
func (self *GkmApi) UploadGroupInfo(ctx context.Context, repoId Id, groupId Id, object *protocol.GkmGroupInfoObject) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	body, err := gkmBody(object)
	if err != nil {
		return err
	}
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups/{group_id}/group-info", method: http.MethodPost, path: gkmGroupPath(groupId, "/group-info"), scopes: scopes, body: body}, nil)
}

// POST /gkm/groups/<id>/ack: this sidecar's leaf's newest applied epoch, which retention reads.
func (self *GkmApi) Ack(ctx context.Context, repoId Id, groupId Id, epoch uint64) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	body, err := gkmBody(&protocol.GkmAckRequest{Epoch: epoch})
	if err != nil {
		return err
	}
	return self.callMessage(ctx, &gkmCall{route: "POST /gkm/groups/{group_id}/ack", method: http.MethodPost, path: gkmGroupPath(groupId, "/ack"), scopes: scopes, body: body}, nil)
}

// GET /gkm/welcomes, with each token: this sidecar's Welcomes, each once, by its pointer's group and epoch, which is
// what names a Welcome: one last-resort KeyPackage serves Adds in several groups, and every one of them is joined
// (DESIGN-DETAILS 6.2.2's pointer row).
func (self *GkmApi) Welcomes(ctx context.Context) ([]*protocol.GkmWelcomeEntry, error) {
	batches := self.accessBatches()
	if len(batches) == 0 {
		return nil, ErrGkmNoScope
	}
	welcomes := []*protocol.GkmWelcomeEntry{}
	seenPointers := map[string]bool{}
	for _, scopes := range batches {
		reply := &protocol.GkmWelcomesReply{}
		// no narrowed retry: gkm leaves out a group whose repo's scope its state does not honor, refusing nothing
		call := &gkmCall{route: "GET /gkm/welcomes", method: http.MethodGet, path: "/gkm/welcomes", scopes: gkmCallScopes{scopes: scopes}, retry: true}
		if err := self.callMessage(ctx, call, reply); err != nil {
			return nil, err
		}
		for _, welcome := range reply.GetWelcomes() {
			pointer := welcome.GetPointer()
			pointerKey := string(pointer.GetGroupId()) + "/" + strconv.FormatUint(pointer.GetEpoch(), 10)
			if seenPointers[pointerKey] {
				continue
			}
			seenPointers[pointerKey] = true
			welcomes = append(welcomes, welcome)
		}
	}
	return welcomes, nil
}

// GET /gkm/repos/<id>/drop-key?since=: the newest GenRotate of the repo's newest group, up to 64 after since
// (QD-156), under deposit or any stronger scope.
func (self *GkmApi) DropKeys(ctx context.Context, repoId Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleDeposit)
	if err != nil {
		return nil, err
	}
	reply := &protocol.GkmGenerationsReply{}
	path := "/gkm/repos/" + gkmUrlId(repoId) + "/drop-key?since=" + strconv.FormatUint(since, 10)
	call := &gkmCall{route: "GET /gkm/repos/{repo_id}/drop-key", method: http.MethodGet, path: path, scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// GET /gkm/recovery/<member_id>/wraps, as a device of that member, or with recoveryScope as its unadmitted client
// under recovery:<member_id>, which reaches nothing else (§7.8, §7.9).
func (self *GkmApi) RecoveryWraps(ctx context.Context, memberId Id, recoveryScope bool) (*protocol.GkmRecoveryWrapsReply, error) {
	scopes := gkmCallScopes{scopes: []string{gkmRecoveryScopePrefix + memberId.String()}}
	if !recoveryScope {
		var err error
		scopes, err = self.scopesFor(nil, GkmScopeRoleRead)
		if err != nil {
			return nil, err
		}
	}
	reply := &protocol.GkmRecoveryWrapsReply{}
	call := &gkmCall{route: "GET /gkm/recovery/{member_id}/wraps", method: http.MethodGet, path: "/gkm/recovery/" + gkmUrlId(memberId) + "/wraps", scopes: scopes, retry: true}
	if err := self.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// Checks the member's complete coverage under the current binding, including groups read by its other devices.
func (self *GkmApi) CheckRecoveryCoverage(ctx context.Context, memberId Id, binding []byte) error {
	if len(binding) != gkmDigestByteCount {
		return ErrGkmMalformed
	}
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	path := "/gkm/recovery/" + gkmUrlId(memberId) + "/wraps?complete=" + hex.EncodeToString(binding[:gkmDigestPrefixByteCount])
	return self.callMessage(ctx, &gkmCall{route: "GET /gkm/recovery/{member_id}/wraps", method: http.MethodGet, path: path, scopes: scopes, retry: true}, nil)
}

// POST /gkm/recovery/<member_id>/wraps: one re-wrap after a rebind, by that member's device, of a group of repoId.
func (self *GkmApi) UploadRecoveryWrap(ctx context.Context, repoId Id, memberId Id, wrap *protocol.GkmRecoveryWrap) error {
	scopes, err := self.scopesFor(&repoId, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	body, err := gkmBody(wrap)
	if err != nil {
		return err
	}
	call := &gkmCall{route: "POST /gkm/recovery/{member_id}/wraps", method: http.MethodPost, path: "/gkm/recovery/" + gkmUrlId(memberId) + "/wraps", scopes: scopes, body: body}
	return self.callMessage(ctx, call, nil)
}

// DELETE /gkm/recovery/<member_id>/wraps?binding=<b8>: a retired binding's wraps, once every new one exists.
func (self *GkmApi) DeleteRecoveryWraps(ctx context.Context, memberId Id, bindingPrefix []byte) error {
	if len(bindingPrefix) != gkmDigestPrefixByteCount {
		return fmt.Errorf("%w: a binding prefix of %d bytes", ErrGkmMalformed, len(bindingPrefix))
	}
	scopes, err := self.scopesFor(nil, GkmScopeRoleRead)
	if err != nil {
		return err
	}
	path := "/gkm/recovery/" + gkmUrlId(memberId) + "/wraps?binding=" + hex.EncodeToString(bindingPrefix)
	return self.callMessage(ctx, &gkmCall{route: "DELETE /gkm/recovery/{member_id}/wraps", method: http.MethodDelete, path: path, scopes: scopes}, nil)
}

// One recipient's late-delivery ask of one generation: when it first asked and when last.
type gkmLateAsk struct {
	since time.Time
	last  time.Time
}

// The late-delivery asks of one sidecar (§10.6's late wraps): a recipient asks with ?want=&since= at most once per
// LateAskInterval for a generation, since its first ask, which gkm reads to widen its hints after 15 minutes. Safe for
// concurrent use.
type GkmLateAsks struct {
	settings *GkmSettings

	stateLock sync.Mutex
	keyAsks   map[string]*gkmLateAsk
}

// No asks yet.
func NewGkmLateAsks(settings *GkmSettings) *GkmLateAsks {
	if settings == nil {
		settings = DefaultGkmSettings()
	}
	return &GkmLateAsks{settings: settings, keyAsks: map[string]*gkmLateAsk{}}
}

// The key of a recipient's ask of one generation of a group.
func gkmLateAskKey(groupId Id, generation uint64, recipient string) string {
	return gkmUrlId(groupId) + ":" + strconv.FormatUint(generation, 10) + ":" + recipient
}

// Whether the recipient may ask now, and its first ask's time, which the query's since carries. An ask within
// LateAskInterval of the last is not made: the read goes without want.
func (self *GkmLateAsks) Ask(groupId Id, generation uint64, recipient string, now time.Time) (since time.Time, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := gkmLateAskKey(groupId, generation, recipient)
	ask, found := self.keyAsks[key]
	if !found {
		self.keyAsks[key] = &gkmLateAsk{since: now, last: now}
		return now, true
	}
	if now.Sub(ask.last) < self.settings.LateAskInterval {
		return ask.since, false
	}
	ask.last = now
	return ask.since, true
}

// The delivery came, or the generation is no longer newest: the next ask of it starts afresh.
func (self *GkmLateAsks) Done(groupId Id, generation uint64, recipient string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.keyAsks, gkmLateAskKey(groupId, generation, recipient))
}
