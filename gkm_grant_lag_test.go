//go:build !sidecar_http

// gkm's key client riding out api's gate lag on a new grant inside its flows (QD-1230): a device's GkmGroupClient
// over GkmApi itself, whose token exchange answers from a state of api's gate a test holds behind the log, and whose
// gkm guards its routes on the log's tip, as gkm's gate holds an entry at once while api's takes up to §8.9's 5 s. The
// guard passes each call it honors to the flows' fake gkm (gkm_fake_service_test.go), so the store, the flows and the
// client's scopes are those every other flow test runs on. KeyDelivery devices, as the e2e case's are, so a writer's
// rotation runs inside EnsureWritable (runPendingInFlow, rotateInFlow).

package sidecar_test

import (
	"context"
	"crypto/hpke"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The roles a route's row takes, strongest first, as gkmservice's scope rows: an access route's, a write route's, a
// creation's and the drop-key route's.
var (
	gkmGrantLagAccessRoles  = []string{sidecar.GkmScopeRoleAdmin, sidecar.GkmScopeRoleWrite, sidecar.GkmScopeRoleRead}
	gkmGrantLagWriteRoles   = []string{sidecar.GkmScopeRoleAdmin, sidecar.GkmScopeRoleWrite}
	gkmGrantLagAdminRoles   = []string{sidecar.GkmScopeRoleAdmin}
	gkmGrantLagDepositRoles = []string{sidecar.GkmScopeRoleAdmin, sidecar.GkmScopeRoleWrite, sidecar.GkmScopeRoleRead, sidecar.GkmScopeRoleDeposit}
)

// What the fake gkm answers one request it honored: the fake store's answer, or its planted fault as no answer at all.
type gkmGrantLagAnswer struct {
	status int
	header http.Header
	body   []byte
	err    error
}

// The fake store's answer to a call: a message's bytes for a success, nil for one with no body, and its refusal as
// gkm sends it, a 409's or 412's winner its body.
func gkmGrantLagAnswerOf(reply proto.Message, err error) gkmGrantLagAnswer {
	if err != nil {
		if gkmError, refused := sidecar.GkmErrorOf(err); refused {
			header := http.Header{}
			if 0 < gkmError.RetryAfter {
				header.Set("Retry-After", strconv.Itoa(int(gkmError.RetryAfter/time.Second)))
			}
			return gkmGrantLagAnswer{status: gkmError.Status, header: header, body: gkmError.Winner}
		}
		if errors.Is(err, sidecar.ErrGkmNoAnswer) {
			return gkmGrantLagAnswer{status: http.StatusBadGateway}
		}
		if errors.Is(err, sidecar.ErrGkmTokenRefused) {
			return gkmGrantLagAnswer{status: http.StatusUnauthorized}
		}
		return gkmGrantLagAnswer{err: err}
	}
	if reply == nil {
		return gkmGrantLagAnswer{status: http.StatusOK}
	}
	body, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(reply)
	if marshalErr != nil {
		return gkmGrantLagAnswer{status: http.StatusInternalServerError}
	}
	return gkmGrantLagAnswer{status: http.StatusOK, body: body}
}

// One call's route as the fake gkm guards it: its repo, nil for a route on no repo, the roles its row takes, and the
// fake store's act, given the request's body.
type gkmGrantLagRoute struct {
	name   string
	repoId *sidecar.Id
	roles  []string
	act    func(body []byte) gkmGrantLagAnswer
}

// A repo scope as §7.8's exchange takes it: repo:<repo_id>:<role>.
func gkmGrantLagScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// The context key a call's route rides to the fake gkm under.
type gkmGrantLagRouteKey struct{}

// One token the exchange minted: its client and the scopes it granted.
type gkmGrantLagToken struct {
	sidecarId sidecar.Id
	scopes    []string
}

// One exchange the fake took.
type gkmGrantLagAsk struct {
	sidecarId sidecar.Id
	at        time.Time
	scopes    []string
	granted   []string
	err       error
}

// A token exchange behind the log, as api's lagging gate is: it grants a client each repo scope the state it has
// applied gives at that role, a writer rw and a reader r, and every scope of another repo, which stands for the
// config's scope every device holds; a request it grants nothing of is refused invalid_scope, and a revoked client
// invalid_grant, as server/oauth answers. A state waiting is applied once the clock reaches its due time, or never
// while held. Safe for concurrent use.
type gkmGrantLagExchange struct {
	clock   *sidecartest.FakeClock
	repoId  sidecar.Id
	otherId sidecar.Id

	stateLock sync.Mutex
	applied   sidecar.GkmAuthView
	waiting   sidecar.GkmAuthView
	// when the waiting state applies, zero while it is held
	dueAt time.Time
	// what every exchange answers from now on in place of a token, nil for none
	refusal error
	// the repo's admins, which the fixture's states do not hold, so api's gate and gkm's both give them admin from the
	// start, as a re-former's
	admins map[sidecar.Id]bool
	tokens map[string]*gkmGrantLagToken
	asks   []*gkmGrantLagAsk
}

// Every exchange from now on answers err in place of a token.
func (self *gkmGrantLagExchange) refuse(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusal = err
}

// api's gate applies view now.
func (self *gkmGrantLagExchange) apply(view sidecar.GkmAuthView) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.applied, self.waiting, self.dueAt = view, nil, time.Time{}
}

// api's gate applies view lag from now.
func (self *gkmGrantLagExchange) applyAfter(view sidecar.GkmAuthView, lag time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waiting, self.dueAt = view, self.clock.Now().Add(lag)
}

// api's gate holds view until a test applies it.
func (self *gkmGrantLagExchange) hold(view sidecar.GkmAuthView) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waiting, self.dueAt = view, time.Time{}
}

// Sidecar.GrantedServiceToken's shape for the client sidecarId, over the state api's gate holds at the clock's now.
func (self *gkmGrantLagExchange) token(sidecarId sidecar.Id) sidecar.GkmGrantedServiceTokenFunction {
	return func(ctx context.Context, resource string, scopes []string) (string, []string, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		now := self.clock.Now()
		if self.waiting != nil && !self.dueAt.IsZero() && !now.Before(self.dueAt) {
			self.applied, self.waiting, self.dueAt = self.waiting, nil, time.Time{}
		}
		ask := &gkmGrantLagAsk{sidecarId: sidecarId, at: now, scopes: slices.Sorted(slices.Values(scopes))}
		self.asks = append(self.asks, ask)
		if self.refusal != nil {
			ask.err = self.refusal
			return "", nil, ask.err
		}
		if row := self.applied.SidecarRow(sidecarId); row == nil || row.GetRevokedAt() != 0 {
			ask.err = &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"}
			return "", nil, ask.err
		}
		repoPrefix := "repo:" + self.repoId.String() + ":"
		granted := []string{}
		for _, scope := range ask.scopes {
			switch {
			case strings.HasPrefix(scope, "repo:"+self.otherId.String()+":"):
				granted = append(granted, scope)
			case scope == repoPrefix+sidecar.GkmScopeRoleWrite && slices.Contains(self.applied.RepoWriters(self.repoId), sidecarId):
				granted = append(granted, scope)
			case scope == repoPrefix+sidecar.GkmScopeRoleRead && slices.Contains(self.applied.RepoReaders(self.repoId), sidecarId):
				granted = append(granted, scope)
			case scope == repoPrefix+sidecar.GkmScopeRoleAdmin && self.admins[sidecarId]:
				granted = append(granted, scope)
			}
		}
		if len(granted) == 0 {
			ask.err = &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_scope"}
			return "", nil, ask.err
		}
		ask.granted = granted
		token := fmt.Sprintf("synthetic-grant-lag-flow-token-%d", len(self.asks))
		self.tokens[token] = &gkmGrantLagToken{sidecarId: sidecarId, scopes: granted}
		return token, slices.Clone(granted), nil
	}
}

// The token a bearer names, nil for one never minted.
func (self *gkmGrantLagExchange) tokenOf(bearer string) *gkmGrantLagToken {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tokens[bearer]
}

// Whether api's gate and gkm's give sidecarId admin of the repo.
func (self *gkmGrantLagExchange) admin(sidecarId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.admins[sidecarId]
}

// Every exchange sidecarId asked of scopes exactly, in order.
func (self *gkmGrantLagExchange) asked(sidecarId sidecar.Id, scopes ...string) []*gkmGrantLagAsk {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := []*gkmGrantLagAsk{}
	for _, ask := range self.asks {
		if ask.sidecarId == sidecarId && slices.Equal(ask.scopes, slices.Sorted(slices.Values(scopes))) {
			asked = append(asked, ask)
		}
	}
	return asked
}

// How many exchanges sidecarId asked.
func (self *gkmGrantLagExchange) count(sidecarId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, ask := range self.asks {
		if ask.sidecarId == sidecarId {
			count += 1
		}
	}
	return count
}

// One request the fake gkm took: its route, the scopes its token carried and the status it answered.
type gkmGrantLagRequest struct {
	route  string
	scopes []string
	status int
}

// gkm behind the lb, its gate on the log's tip: a call's token must carry, of the roles its route's row takes, the
// strongest it holds on the route's repo, which the tip gives the client whole (rw a writer's, r a reader's; owner
// decision 563), else 403; a token never minted, or a client the tip revoked, 401; a route on no repo any r, rw or
// admin scope. An honored call is the fake store's to answer. Safe for concurrent use.
type gkmGrantLagGkm struct {
	t        *testing.T
	log      *sidecartest.FakeGkmAuthLog
	exchange *gkmGrantLagExchange

	stateLock sync.Mutex
	requests  []*gkmGrantLagRequest
}

func (self *gkmGrantLagGkm) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		var err error
		if body, err = io.ReadAll(request.Body); err != nil {
			return nil, err
		}
	}
	route, ok := request.Context().Value(gkmGrantLagRouteKey{}).(*gkmGrantLagRoute)
	if !ok {
		self.t.Errorf("a gkm request of no known route: %s %s", request.Method, request.URL.Path)
		return gkmGrantLagResponse(gkmGrantLagAnswer{status: http.StatusInternalServerError}), nil
	}
	token := self.exchange.tokenOf(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
	status := self.judge(token, route)
	recorded := &gkmGrantLagRequest{route: route.name, status: status}
	if token != nil {
		recorded.scopes = slices.Clone(token.scopes)
	}
	answer := gkmGrantLagAnswer{status: status}
	if status == 0 {
		answer = route.act(body)
		recorded.status = answer.status
	}
	self.stateLock.Lock()
	self.requests = append(self.requests, recorded)
	self.stateLock.Unlock()
	if answer.err != nil {
		return nil, answer.err
	}
	return gkmGrantLagResponse(answer), nil
}

// gkm's guard on the tip: 0 for a call it honors, else its refusal.
func (self *gkmGrantLagGkm) judge(token *gkmGrantLagToken, route *gkmGrantLagRoute) int {
	tip := self.log.Tip()
	if token == nil {
		return http.StatusUnauthorized
	}
	if row := tip.SidecarRow(token.sidecarId); row == nil || row.GetRevokedAt() != 0 {
		return http.StatusUnauthorized
	}
	if route.repoId == nil {
		for _, scope := range token.scopes {
			if !strings.HasSuffix(scope, ":"+sidecar.GkmScopeRoleDeposit) {
				return 0
			}
		}
		return http.StatusForbidden
	}
	for _, role := range route.roles {
		if !slices.Contains(token.scopes, gkmGrantLagScope(*route.repoId, role)) {
			continue
		}
		switch {
		case role == sidecar.GkmScopeRoleAdmin && self.exchange.admin(token.sidecarId):
			return 0
		case role == sidecar.GkmScopeRoleWrite && slices.Contains(tip.RepoWriters(*route.repoId), token.sidecarId) && slices.Contains(tip.RepoReaders(*route.repoId), token.sidecarId):
			return 0
		case role == sidecar.GkmScopeRoleRead && slices.Contains(tip.RepoReaders(*route.repoId), token.sidecarId):
			return 0
		}
		// the strongest held, honored only whole
		return http.StatusForbidden
	}
	return http.StatusForbidden
}

// The requests of a route, in order.
func (self *gkmGrantLagGkm) taken(route string) []*gkmGrantLagRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	taken := []*gkmGrantLagRequest{}
	for _, request := range self.requests {
		if request.route == route {
			taken = append(taken, request)
		}
	}
	return taken
}

// An answer as the transport hands it to GkmApi.
func gkmGrantLagResponse(answer gkmGrantLagAnswer) *http.Response {
	recorder := httptest.NewRecorder()
	for name, values := range answer.header {
		for _, value := range values {
			recorder.Header().Add(name, value)
		}
	}
	recorder.WriteHeader(answer.status)
	recorder.Write(answer.body)
	return recorder.Result()
}

// A device's GkmGroupApi through GkmApi: each method passes its route to the fake gkm in its context and calls
// GkmApi's own, whose scopes, exchange and retries are what this file tests; the fake gkm hands an honored request to
// the device's fake store api with the call's own arguments. Safe for concurrent use, as a rotation's staging calls it.
type gkmGrantLagApi struct {
	api  *sidecar.GkmApi
	fake *gkmFakeApi

	stateLock sync.Mutex
	// what a test runs once just before the next call of a route goes to GkmApi
	hooks map[string]func()
}

// Has hook run once just before the next call of route.
func (self *gkmGrantLagApi) hook(route string, hook func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hooks[route] = hook
}

var (
	_ sidecar.GkmGroupApi  = (*gkmGrantLagApi)(nil)
	_ sidecar.GkmReformApi = (*gkmGrantLagApi)(nil)
)

// ctx carrying a route of repoId, nil for none, with the roles its row takes and act, once the route's hook has run.
func (self *gkmGrantLagApi) context(ctx context.Context, name string, repoId *sidecar.Id, roles []string, act func(body []byte) gkmGrantLagAnswer) context.Context {
	hook := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hook := self.hooks[name]
		delete(self.hooks, name)
		return hook
	}()
	if hook != nil {
		hook()
	}
	return context.WithValue(ctx, gkmGrantLagRouteKey{}, &gkmGrantLagRoute{name: name, repoId: repoId, roles: roles, act: act})
}

func (self *gkmGrantLagApi) CreateGroup(ctx context.Context, repoId sidecar.Id, request *protocol.GkmGroupCreateRequest) error {
	return self.api.CreateGroup(self.context(ctx, "CreateGroup", &repoId, gkmGrantLagAdminRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.CreateGroup(ctx, repoId, request))
	}), repoId, request)
}

func (self *gkmGrantLagApi) Forms(ctx context.Context, repoId sidecar.Id) (*protocol.GkmFormsReply, error) {
	return self.api.Forms(self.context(ctx, "Forms", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.Forms(ctx, repoId))
	}), repoId)
}

func (self *gkmGrantLagApi) Epochs(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, after uint64) (*protocol.GkmEpochsReply, error) {
	return self.api.Epochs(self.context(ctx, "Epochs", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.Epochs(ctx, repoId, groupId, after))
	}), repoId, groupId, after)
}

func (self *gkmGrantLagApi) CommitEpoch(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, epoch uint64, request *protocol.GkmEpochRequest) error {
	return self.api.CommitEpoch(self.context(ctx, "CommitEpoch", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.CommitEpoch(ctx, repoId, groupId, epoch, request))
	}), repoId, groupId, epoch, request)
}

func (self *gkmGrantLagApi) Generations(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	return self.api.Generations(self.context(ctx, "Generations", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.Generations(ctx, repoId, groupId, since))
	}), repoId, groupId, since)
}

func (self *gkmGrantLagApi) ClaimGeneration(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, rotate *bridge.Signed) error {
	return self.api.ClaimGeneration(self.context(ctx, "ClaimGeneration", &repoId, gkmGrantLagWriteRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.ClaimGeneration(ctx, repoId, groupId, generation, rotate))
	}), repoId, groupId, generation, rotate)
}

func (self *gkmGrantLagApi) Wraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, query *sidecar.GkmWrapsQuery) (*protocol.GkmWrapsReply, error) {
	return self.api.Wraps(self.context(ctx, "Wraps", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.Wraps(ctx, repoId, groupId, generation, query))
	}), repoId, groupId, generation, query)
}

func (self *gkmGrantLagApi) UploadWraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, commitment []byte, batch *protocol.GkmWrapBatch) (*protocol.GkmWrapBatchReply, error) {
	return self.api.UploadWraps(self.context(ctx, "UploadWraps", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.UploadWraps(ctx, repoId, groupId, generation, commitment, batch))
	}), repoId, groupId, generation, commitment, batch)
}

func (self *gkmGrantLagApi) UploadRecoveryWraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, commitment []byte, batch *protocol.GkmRecoveryWrapBatch) (*protocol.GkmWrapBatchReply, error) {
	return self.api.UploadRecoveryWraps(self.context(ctx, "UploadRecoveryWraps", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.UploadRecoveryWraps(ctx, repoId, groupId, generation, commitment, batch))
	}), repoId, groupId, generation, commitment, batch)
}

func (self *gkmGrantLagApi) ReaderKey(ctx context.Context, sidecarId sidecar.Id) (*bridge.Signed, error) {
	return self.api.ReaderKey(self.context(ctx, "ReaderKey", nil, nil, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.ReaderKey(ctx, sidecarId))
	}), sidecarId)
}

func (self *gkmGrantLagApi) ReaderKeys(ctx context.Context, sidecarIds []sidecar.Id) ([]*bridge.Signed, error) {
	return self.api.ReaderKeys(self.context(ctx, "ReaderKeys", nil, nil, func(body []byte) gkmGrantLagAnswer {
		// the request's own ids: GkmApi asks 256 a request
		request := &protocol.GkmReaderKeysRequest{}
		if err := proto.Unmarshal(body, request); err != nil {
			return gkmGrantLagAnswer{status: http.StatusBadRequest}
		}
		ids := []sidecar.Id{}
		for _, idBytes := range request.GetSidecarIds() {
			id, err := sidecar.IdFromBytes(idBytes)
			if err != nil {
				return gkmGrantLagAnswer{status: http.StatusBadRequest}
			}
			ids = append(ids, id)
		}
		readerKeys, err := self.fake.ReaderKeys(ctx, ids)
		return gkmGrantLagAnswerOf(&protocol.GkmReaderKeysReply{ReaderKeys: readerKeys}, err)
	}), sidecarIds)
}

func (self *gkmGrantLagApi) DelegationKey(ctx context.Context, configRepoId sidecar.Id, delegationId []byte) ([]byte, error) {
	return self.api.DelegationKey(self.context(ctx, "DelegationKey", &configRepoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		key, err := self.fake.DelegationKey(ctx, configRepoId, delegationId)
		if err == nil && key == nil {
			return gkmGrantLagAnswer{status: http.StatusNotFound}
		}
		answer := gkmGrantLagAnswerOf(nil, err)
		answer.body = key
		return answer
	}), configRepoId, delegationId)
}

func (self *gkmGrantLagApi) DelegationKeys(ctx context.Context, configRepoId sidecar.Id, delegationIds [][]byte) ([][]byte, error) {
	return self.api.DelegationKeys(self.context(ctx, "DelegationKeys", &configRepoId, gkmGrantLagAccessRoles, func(body []byte) gkmGrantLagAnswer {
		request := &protocol.GkmDelegationKeysRequest{}
		if err := proto.Unmarshal(body, request); err != nil {
			return gkmGrantLagAnswer{status: http.StatusBadRequest}
		}
		keys, err := self.fake.DelegationKeys(ctx, configRepoId, request.GetDelegationIds())
		return gkmGrantLagAnswerOf(&protocol.GkmDelegationKeysReply{ReaderKeys: keys}, err)
	}), configRepoId, delegationIds)
}

func (self *gkmGrantLagApi) ClaimKeyPackage(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, target sidecar.Id) (*protocol.GkmKeyPackageClaimReply, error) {
	return self.api.ClaimKeyPackage(self.context(ctx, "ClaimKeyPackage", &repoId, gkmGrantLagWriteRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.ClaimKeyPackage(ctx, repoId, groupId, target))
	}), repoId, groupId, target)
}

func (self *gkmGrantLagApi) GroupInfo(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, want *uint64) (*protocol.GkmGroupInfoObject, error) {
	return self.api.GroupInfo(self.context(ctx, "GroupInfo", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.GroupInfo(ctx, repoId, groupId, want))
	}), repoId, groupId, want)
}

func (self *gkmGrantLagApi) UploadGroupInfo(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, object *protocol.GkmGroupInfoObject) error {
	return self.api.UploadGroupInfo(self.context(ctx, "UploadGroupInfo", &repoId, gkmGrantLagAccessRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.UploadGroupInfo(ctx, repoId, groupId, object))
	}), repoId, groupId, object)
}

func (self *gkmGrantLagApi) UploadWelcome(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, epoch uint64, request *protocol.GkmWelcomeRequest) error {
	return self.api.UploadWelcome(self.context(ctx, "UploadWelcome", &repoId, gkmGrantLagWriteRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.UploadWelcome(ctx, repoId, groupId, epoch, request))
	}), repoId, groupId, epoch, request)
}

func (self *gkmGrantLagApi) WelcomeStands(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, epoch uint64) (bool, error) {
	return self.api.WelcomeStands(self.context(ctx, "WelcomeStands", &repoId, gkmGrantLagWriteRoles, func([]byte) gkmGrantLagAnswer {
		stands, err := self.fake.WelcomeStands(ctx, repoId, groupId, epoch)
		if err == nil && !stands {
			return gkmGrantLagAnswer{status: http.StatusNotFound}
		}
		return gkmGrantLagAnswerOf(nil, err)
	}), repoId, groupId, epoch)
}

func (self *gkmGrantLagApi) Welcomes(ctx context.Context) ([]*protocol.GkmWelcomeEntry, error) {
	return self.api.Welcomes(self.context(ctx, "Welcomes", nil, nil, func([]byte) gkmGrantLagAnswer {
		welcomes, err := self.fake.Welcomes(ctx)
		return gkmGrantLagAnswerOf(&protocol.GkmWelcomesReply{Welcomes: welcomes}, err)
	}))
}

func (self *gkmGrantLagApi) Reform(ctx context.Context, repoId sidecar.Id, request *protocol.GkmGroupReformRequest) error {
	return self.api.Reform(self.context(ctx, "Reform", &repoId, gkmGrantLagAdminRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.Reform(ctx, repoId, request))
	}), repoId, request)
}

func (self *gkmGrantLagApi) UploadLadder(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, request *protocol.GkmLadderRequest) error {
	return self.api.UploadLadder(self.context(ctx, "UploadLadder", &repoId, gkmGrantLagAdminRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(nil, self.fake.UploadLadder(ctx, repoId, groupId, request))
	}), repoId, groupId, request)
}

func (self *gkmGrantLagApi) DropKeys(ctx context.Context, repoId sidecar.Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	return self.api.DropKeys(self.context(ctx, "DropKeys", &repoId, gkmGrantLagDepositRoles, func([]byte) gkmGrantLagAnswer {
		return gkmGrantLagAnswerOf(self.fake.DropKeys(ctx, repoId, since))
	}), repoId, since)
}

// The flows' world with one device on GkmApi, api's gate behind the log.
type gkmGrantLagWorld struct {
	*gkmFlowWorld
	exchange *gkmGrantLagExchange
	gkm      *gkmGrantLagGkm
	device   *gkmFlowDevice
	api      *sidecar.GkmApi
	// the device's GkmGroupApi over api
	groupApi *gkmGrantLagApi
	// what GkmApi runs under: the defaults
	apiSettings *sidecar.GkmSettings
}

// Puts device on GkmApi over the lagging exchange and the guarded gkm, api's gate holding the log's tip, the device's
// scopes as its state gives them, and restarts its client on it over the same keychain.
func newGkmGrantLagWorld(world *gkmFlowWorld, device *gkmFlowDevice) *gkmGrantLagWorld {
	world.t.Helper()
	exchange := &gkmGrantLagExchange{
		clock:   world.clock,
		repoId:  world.repoId,
		otherId: sidecar.NewId(),
		admins:  map[sidecar.Id]bool{},
		tokens:  map[string]*gkmGrantLagToken{},
	}
	exchange.apply(world.log.Tip())
	lag := &gkmGrantLagWorld{
		gkmFlowWorld: world,
		exchange:     exchange,
		gkm:          &gkmGrantLagGkm{t: world.t, log: world.log, exchange: exchange},
		device:       device,
		apiSettings:  sidecar.DefaultGkmSettings(),
	}
	api, err := sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:              "https://gkm.example",
		Transport:           lag.gkm,
		GrantedServiceToken: exchange.token(device.id),
		Settings:            lag.apiSettings,
		Clock:               world.clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	lag.api = api
	lag.groupApi = &gkmGrantLagApi{api: api, fake: device.api, hooks: map[string]func(){}}
	lag.restart(lag.groupApi)
	return lag
}

// The device's client over api, as gkmFlowDevice.restart builds one: the same keychain, nothing else kept.
func (self *gkmGrantLagWorld) restart(api sidecar.GkmGroupApi) {
	self.t.Helper()
	device := self.device
	args := &sidecar.GkmGroupClientArgs{
		SidecarId: device.id,
		Api:       api,
		Sign:      device.signer.Sign,
		Secrets:   device.secrets,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			privateKey, ok := device.readerPrivateKeys[string(keySha256)]
			if !ok {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return privateKey, nil
		},
		ReaderKeySha256: func() []byte { return device.readerKeySha256 },
		RecoveryKey: func(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
			return self.recoveryKeys[memberId], nil
		},
		ReaderRepoIds: func() []sidecar.Id { return []sidecar.Id{self.repoId} },
		Alarm:         func(alarm *sidecar.GkmAlarm) { device.alarms = append(device.alarms, alarm) },
		HoldsState:    func() bool { return true },
		Jitter:        func(max time.Duration) time.Duration { return 0 },
		Settings:      self.gkmFlowWorld.settings,
		Clock:         self.clock,
	}
	if len(device.row.GetTagIds()) == 0 {
		args.Mls = device.mls
	}
	client, err := sidecar.NewGkmGroupClient(args)
	if err != nil {
		self.t.Fatal(err)
	}
	device.client = client
	if tip := self.log.Tip(); tip != nil {
		client.AuthAdvanced(tip)
	}
}

// The device's scopes as a state applier sets them: the repo at role, "" for none, and the other repo at r.
func (self *gkmGrantLagWorld) setScopes(role string) {
	scopes := []sidecar.GkmRepoScope{{RepoId: self.exchange.otherId, Role: sidecar.GkmScopeRoleRead}}
	if role != "" {
		scopes = append(scopes, sidecar.GkmRepoScope{RepoId: self.repoId, Role: role})
	}
	self.api.SetRepoScopes(scopes)
}

// The repo's scope at role.
func (self *gkmGrantLagWorld) scope(role string) string {
	return gkmGrantLagScope(self.repoId, role)
}

// Runs act on its own goroutine, moving the clock to each wait it arms no further than ReadRetryWait ahead, the
// ride-out's, never to a request's own deadline, and answers its error and how far the clock moved.
func (self *gkmGrantLagWorld) drive(act func() error) (error, time.Duration) {
	start := self.clock.Now()
	done := make(chan error, 1)
	go func() {
		done <- act()
	}()
	ended := func(err error) (error, time.Duration) {
		self.now = self.clock.Now()
		return err, self.now.Sub(start)
	}
	for {
		pending, added := self.clock.WatchTimers()
		select {
		case err := <-done:
			return ended(err)
		default:
		}
		if 0 < len(pending) && !pending[0].After(self.clock.Now().Add(self.apiSettings.ReadRetryWait)) {
			self.clock.AdvanceTo(pending[0])
			continue
		}
		select {
		case err := <-done:
			return ended(err)
		case <-added:
		}
	}
}

// The device's EnsureWritable, driven: its key, its error and how far the clock moved.
func (self *gkmGrantLagWorld) ensureWritable() (*sidecar.EvsRepoKey, error, time.Duration) {
	var key *sidecar.EvsRepoKey
	err, took := self.drive(func() error {
		var err error
		key, err = self.device.client.EnsureWritable(self.ctx, self.repoId)
		return err
	})
	return key, err, took
}

// The offsets of asks from start.
func gkmGrantLagAskOffsets(asks []*gkmGrantLagAsk, start time.Time) []time.Duration {
	offsets := []time.Duration{}
	for _, ask := range asks {
		offsets = append(offsets, ask.at.Sub(start))
	}
	return offsets
}

// A reader that writes nothing yet, a tagged KeyDelivery device holding generation 1, with its client on GkmApi.
func newGkmGrantLagReader(t *testing.T, write bool) *gkmGrantLagWorld {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	agent := world.admitAgent("agent", write)
	world.stateFor()
	world.hold(agent.gkmWorldDevice, world.gen1)
	lag := newGkmGrantLagWorld(world, agent)
	role := sidecar.GkmScopeRoleRead
	if write {
		role = sidecar.GkmScopeRoleWrite
	}
	lag.setScopes(role)
	return lag
}

// QD-1230's e2e case at the flows: a shrink of the repo's holders, and at once a reader granted writer, whose first
// write must rotate before it seals (§10.5); gkm's gate holds both at once, api's 2.5 s later. The writer's
// EnsureWritable reads gkm's generations under the repo's r scope, which api's gate gives it, and rotates; its claim's
// batch token comes back without the repo's rw, gkm refuses the claim, and the claim goes again under rw alone, riding
// the exchange's invalid_scope out at 0, 1 and 2 s until api's gate holds the grant at 2.5 s. The claim lands at 3 s:
// generation 2, cause REMOVE, the writer's, which members accept, and gkm took one claim. The code before ended the
// write with ErrGkmWait at the claim's first 403, as the e2e case's runs 3 and 4 showed.
func TestANewWritersFirstWriteAfterAShrinkRotatesOnceApisGateHoldsItsGrant(t *testing.T) {
	lag := newGkmGrantLagReader(t, false)
	agent := lag.device
	lag.revoke(lag.x)
	lag.grant(true, agent.gkmWorldDevice)
	shrunk := lag.stateFor()
	lag.exchange.applyAfter(shrunk, 2500*time.Millisecond)
	lag.setScopes(sidecar.GkmScopeRoleWrite)
	start := lag.clock.Now()

	key, err, took := lag.ensureWritable()
	if err != nil {
		t.Fatalf("the new writer's first write after the shrink: %v", err)
	}
	if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("its key: generation %d, cause %d", key.Generation(), key.Cause())
	}
	if generation := lag.storedGeneration(shrunk, 2); generation.SignerId != agent.id {
		t.Errorf("gen/2 is %s's", generation.SignerId)
	}
	if verdict := lag.memberAccepts(shrunk, 2, lag.a); !verdict.Passed() {
		t.Errorf("a member's check of the new writer's rotation: %+v", verdict)
	}
	alone := lag.exchange.asked(agent.id, lag.scope(sidecar.GkmScopeRoleWrite))
	if offsets := gkmGrantLagAskOffsets(alone, start); !slices.Equal(offsets, []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second}) {
		t.Errorf("the rw scope alone was asked at %v", offsets)
	}
	for index, ask := range alone {
		if last := index == len(alone)-1; last && ask.granted == nil || !last && ask.err == nil {
			t.Errorf("the ask at +%s: %v, granting %v", ask.at.Sub(start), ask.err, ask.granted)
		}
	}
	claims := lag.gkm.taken("ClaimGeneration")
	if len(claims) != 2 || claims[0].status != http.StatusForbidden || slices.Contains(claims[0].scopes, lag.scope(sidecar.GkmScopeRoleWrite)) ||
		!slices.Equal(claims[1].scopes, []string{lag.scope(sidecar.GkmScopeRoleWrite)}) {
		t.Errorf("gkm's claims: %d", len(claims))
		for _, claim := range claims {
			t.Logf("a claim under %v answered %d", claim.scopes, claim.status)
		}
	}
	if lag.store.callCount("ClaimGeneration") != 1 || lag.store.newestGeneration(lag.groupId) != 2 {
		t.Errorf("gkm's store took %d claims and holds generation %d", lag.store.callCount("ClaimGeneration"), lag.store.newestGeneration(lag.groupId))
	}
	if took != 3*time.Second {
		t.Errorf("the write took %s of the clock", took)
	}
}

// A writer's grant that never reaches api's gate: the same first write after a shrink rides the claim's rw scope out
// for ExchangeScopeWaitTimeout, asking at 0 to 5 s, and then ends with the exchange's invalid_scope, no generation 2
// standing and gkm's store taking no claim, rather than read as a lost answer and sent again. Once api's gate holds
// the grant, the next write resumes the rotation's draft and lands generation 2.
func TestANewWritersGrantApisGateNeverHoldsEndsItsWriteAfterTheWindow(t *testing.T) {
	lag := newGkmGrantLagReader(t, false)
	agent := lag.device
	lag.revoke(lag.x)
	lag.grant(true, agent.gkmWorldDevice)
	shrunk := lag.stateFor()
	lag.exchange.hold(shrunk)
	lag.setScopes(sidecar.GkmScopeRoleWrite)
	start := lag.clock.Now()

	_, err, took := lag.ensureWritable()
	var apiError *sidecar.SidecarApiError
	if !errors.As(err, &apiError) || apiError.Code != "invalid_scope" {
		t.Fatalf("a write whose grant never reached api's gate ended with %v, not the exchange's invalid_scope", err)
	}
	alone := lag.exchange.asked(agent.id, lag.scope(sidecar.GkmScopeRoleWrite))
	wantOffsets := []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second}
	if offsets := gkmGrantLagAskOffsets(alone, start); !slices.Equal(offsets, wantOffsets) {
		t.Errorf("the rw scope alone was asked at %v, want %v", offsets, wantOffsets)
	}
	if took != lag.apiSettings.ExchangeScopeWaitTimeout {
		t.Errorf("the write took %s of the clock, not the window", took)
	}
	if lag.store.callCount("ClaimGeneration") != 0 || lag.store.newestGeneration(lag.groupId) != 1 {
		t.Errorf("gkm's store took %d claims and holds generation %d", lag.store.callCount("ClaimGeneration"), lag.store.newestGeneration(lag.groupId))
	}
	if claims := lag.gkm.taken("ClaimGeneration"); len(claims) != 1 || claims[0].status != http.StatusForbidden {
		t.Errorf("gkm took %d claims", len(claims))
	}

	lag.exchange.apply(shrunk)
	key, err, _ := lag.ensureWritable()
	if err != nil || key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the write once api's gate holds the grant: %v", err)
	}
	if lag.store.callCount("ClaimGeneration") != 1 {
		t.Errorf("gkm's store took %d claims", lag.store.callCount("ClaimGeneration"))
	}
}

// A revoked writer is refused, its own state still showing the grant gkm's gate has taken away (the shrink before it
// due a rotation): with api's gate behind the revocation, the token carries the repo's scopes, gkm refuses its read
// of the generations at the batch's rw and at r alone, and the write ends with gkm's 403 at once, the clock unmoved;
// with api's gate holding the revocation too, the r scope alone is refused invalid_scope through the window, QD-1230's
// cost, and the write is refused ErrGkmWait, the shrink uncovered. No claim reaches gkm either way. Once its own state
// holds the revocation, it is no writer, and asks the exchange nothing.
func TestARevokedWriterIsRefused(t *testing.T) {
	lag := newGkmGrantLagReader(t, true)
	agent := lag.device
	lag.revoke(lag.x)
	shrunk := lag.stateFor()
	lag.drop(agent.gkmWorldDevice)
	revoked := lag.stateFor(agent.gkmWorldDevice)
	lag.exchange.apply(shrunk)

	_, err, took := lag.ensureWritable()
	if !sidecar.IsGkmStatus(err, http.StatusForbidden) || took != 0 {
		t.Errorf("a revoked writer, api's gate behind: %v after %s", err, took)
	}
	if generations := lag.gkm.taken("Generations"); len(generations) != 2 || generations[1].status != http.StatusForbidden {
		t.Errorf("gkm took %d reads of the generations", len(generations))
	}

	lag.exchange.apply(revoked)
	start := lag.clock.Now()
	readsBefore := len(lag.exchange.asked(agent.id, lag.scope(sidecar.GkmScopeRoleRead)))
	_, err, took = lag.ensureWritable()
	if !errors.Is(err, sidecar.ErrGkmWait) || took != lag.apiSettings.ExchangeScopeWaitTimeout {
		t.Errorf("a revoked writer, api's gate holding it: %v after %s", err, took)
	}
	reads := lag.exchange.asked(agent.id, lag.scope(sidecar.GkmScopeRoleRead))[readsBefore:]
	if offsets := gkmGrantLagAskOffsets(reads, start); len(offsets) != 6 || offsets[5] != 5*time.Second {
		t.Errorf("the r scope alone was asked at %v", offsets)
	}
	if lag.store.callCount("ClaimGeneration") != 0 || len(lag.gkm.taken("ClaimGeneration")) != 0 || lag.store.newestGeneration(lag.groupId) != 1 {
		t.Errorf("a revoked writer's claim reached gkm")
	}

	agent.client.AuthAdvanced(revoked)
	before := lag.exchange.count(agent.id)
	if _, err, _ := lag.ensureWritable(); !errors.Is(err, sidecar.ErrGkmNotWriter) || lag.exchange.count(agent.id) != before {
		t.Errorf("a writer whose own state holds its revocation: %v after %d asks", err, lag.exchange.count(agent.id)-before)
	}
}

// QD-1230's late deliveries a new holder is owed: a device admitted with no grant, then granted writer beside a joiner
// granted reader, holding generation 1 by its first wrap, answers the joiner's wrap-pending with a LATE delivery,
// which it writes under the repo's r scope. api's gate gives the writer nothing on the repo for 2.5 s, so the batch's
// token leaves the repo out, gkm refuses the delivery, and r alone is refused invalid_scope at 0, 1 and 2 s; the
// delivery lands at 3 s, once the gate holds the grant. The code before ended it at the exchange's first refusal,
// leaving the joiner to its next ask a minute on.
func TestANewWritersLateDeliveryRidesOutItsGrantsLagAtApi(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	writer := world.flow(world.admit("writer", sidecar.NewId()))
	joiner := world.flow(world.admit("joiner", sidecar.NewId()))
	world.stateFor()
	lag := newGkmGrantLagWorld(world, writer)
	world.grant(true, writer.gkmWorldDevice)
	world.grant(false, joiner.gkmWorldDevice)
	granted := world.stateFor()
	world.hold(writer.gkmWorldDevice, world.gen1)
	lag.exchange.applyAfter(granted, 2500*time.Millisecond)
	lag.setScopes(sidecar.GkmScopeRoleWrite)
	start := lag.clock.Now()

	recipient := "s:" + hex.EncodeToString(joiner.id.Bytes())
	err, took := lag.drive(func() error {
		return writer.client.DeliverLate(lag.ctx, lag.repoId, recipient)
	})
	if err != nil {
		t.Fatalf("the late delivery: %v", err)
	}
	if kind, ok := lag.deliveryRecipients(1)["s:joiner"]; !ok || kind != sidecar.GkmDeliveryLate {
		t.Errorf("gkm holds no LATE delivery of generation 1 to the joiner: %v", lag.deliveryRecipients(1))
	}
	alone := lag.exchange.asked(writer.id, lag.scope(sidecar.GkmScopeRoleRead))
	if offsets := gkmGrantLagAskOffsets(alone, start); !slices.Equal(offsets, []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second}) {
		t.Errorf("the r scope alone was asked at %v", offsets)
	}
	if took != 3*time.Second {
		t.Errorf("the delivery took %s of the clock", took)
	}
}

// A token that cannot be had sent nothing to gkm, so a write that would read a lost answer back ends with the
// exchange's refusal instead: a group's creation (KF1) whose POST meets invalid_grant ends after that one ask, where the
// code before read it as a lost answer and sent the same bytes CommitSendCount times, each exchanging again, then
// answered that the creation got no answer.
func TestAGroupsCreationEndsAtATokenRefusalForGood(t *testing.T) {
	world, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	lag := newGkmGrantLagWorld(world, world.flows[world.a])
	lag.setScopes(sidecar.GkmScopeRoleAdmin)
	refusal := &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"}
	asksBefore := 0
	lag.groupApi.hook("CreateGroup", func() {
		asksBefore = lag.exchange.count(lag.device.id)
		lag.exchange.refuse(refusal)
	})

	_, err := lag.device.client.CreateGroup(lag.ctx, lag.createArgs())
	if !errors.Is(err, refusal) {
		t.Fatalf("a creation the exchange refuses for good ended with %v", err)
	}
	if asks := lag.exchange.count(lag.device.id) - asksBefore; asks != 1 {
		t.Errorf("the creation asked the exchange %d times after its refusal", asks)
	}
	if lag.store.callCount("CreateGroup") != 0 || len(lag.gkm.taken("CreateGroup")) != 0 {
		t.Error("a creation with no token reached gkm")
	}
}

// The same for a leaf's commit of a pending Remove: its epoch's PUT meets the exchange's invalid_grant and the commit
// ends with it after that one ask, where the code before read it as a lost answer and asked the exchange again for
// the epochs read that would have said what happened.
func TestACommitEndsAtATokenRefusalForGood(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	lag := newGkmGrantLagWorld(world, world.flows[world.a])
	lag.setScopes(sidecar.GkmScopeRoleWrite)
	world.revoke(world.x)
	lag.exchange.apply(world.stateFor())
	refusal := &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"}
	asksBefore := 0
	lag.groupApi.hook("CommitEpoch", func() {
		asksBefore = lag.exchange.count(lag.device.id)
		lag.exchange.refuse(refusal)
	})

	if err := lag.device.client.RunPending(lag.ctx, lag.repoId); !errors.Is(err, refusal) {
		t.Fatalf("a commit the exchange refuses for good ended with %v", err)
	}
	if asks := lag.exchange.count(lag.device.id) - asksBefore; asks != 1 {
		t.Errorf("the commit asked the exchange %d times after its refusal", asks)
	}
	if lag.store.callCount("CommitEpoch") != 0 || len(lag.gkm.taken("CommitEpoch")) != 0 {
		t.Error("a commit with no token reached gkm")
	}
}

// The same for a re-form after a site loss: its form's POST meeting the exchange's invalid_grant ends the re-form after
// that one ask, and so does its ladder's once the form stands, where the code before sent the same bytes again
// CommitSendCount times, each exchanging again, then answered that the re-form, or the ladder, got no answer.
func TestAReformEndsAtATokenRefusalForGood(t *testing.T) {
	world := newGkmReformWorld(t)
	lag := newGkmGrantLagWorld(world.gkmFlowWorld, world.flows[world.a])
	lag.exchange.admins[lag.device.id] = true
	lag.setScopes(sidecar.GkmScopeRoleAdmin)
	world.loseSite()
	refusal := &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"}
	for _, route := range []string{"Reform", "UploadLadder"} {
		asksBefore := 0
		lag.groupApi.hook(route, func() {
			asksBefore = lag.exchange.count(lag.device.id)
			lag.exchange.refuse(refusal)
		})
		if _, err := lag.device.client.ReformGroup(lag.ctx, &sidecar.GkmReformArgs{RepoId: lag.repoId}); !errors.Is(err, refusal) {
			t.Fatalf("%s: a re-form the exchange refuses for good ended with %v", route, err)
		}
		if asks := lag.exchange.count(lag.device.id) - asksBefore; asks != 1 {
			t.Errorf("%s: the re-form asked the exchange %d times after its refusal", route, asks)
		}
		if lag.store.callCount(route) != 0 || len(lag.gkm.taken(route)) != 0 {
			t.Errorf("%s: a call with no token reached gkm", route)
		}
		lag.exchange.refuse(nil)
	}
	if lag.store.callCount("Reform") != 1 {
		t.Errorf("gkm's store took %d forms", lag.store.callCount("Reform"))
	}
}
