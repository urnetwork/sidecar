// An HTTPS-only page on the Net (§18.8, D-SDK-17; SDK-M4-08): TestHttpPage is a client of the Net's api that polls,
// refreshes and reads, and never connects. It stands for the page Worker of the sidecar_http leg, which T2 cannot
// build, since sidecartest links connect, and speaks the routes that Worker does: GET /sidecar/sync/poll with its
// cursor, GET /auth/refresh with its ClientKey's DPoP proof, GET /sidecar/sync/versions, and the key-origin
// document's close beacon, POST /sidecar/close with the close capability as a text/plain body and no Authorization
// header, since navigator.sendBeacon sets none.
//
// A page is FS-37's (ephemeral: a quick burner's shape, an ephemeral client with a lease and a close capability) or
// the read_only fixture device FS-97 and FS-106 name (a member device's page Worker, which no lease reaps), for
// TEAM-M4-01 and KEYS-M4-01. Either way it is enrolled strict_exp and admin_refused, as the key origin mints a
// Worker's client (§18.8's identity row), and bound under an identity key of its own, so a test can admit it
// read_only in the network's log by its sidecar_id and identity key. It holds no config, MLS or record state: a test
// that needs a Worker's keys builds them on this page's identity.
//
// The api's side of the lease, beside fake_api_core.go's mint, as server's model/network_client_lease_model.go does
// it (TEAM-M1-10; §7.7, §18.8):
//
//	lease    one per ephemeral client: seen_time, and the SHA-256 of the 128-bit close capability its mint returned
//	         once; gone with its client
//	poll     the Net's long-poll writes seen_time when its marker {scp_<C>}hb sets or errs (push_net.go), after the
//	         route authenticated the poll, so a reaped or revoked client's poll is 401 and writes nothing
//	reap     ReapEphemeralClients, one pass of taskworker's job at the clock's now: an ephemeral client with no open
//	         connection whose seen_time and newest disconnect are both over LeaseReapAfter old is removed, every token
//	         of it refused after
//	close    POST /sidecar/close reaps at once the client whose capability's hash matches, and answers 204 whether
//	         or not one did
//	connect  OpenConnection records a connection of a client, as network_client_connection does, until its close
//
// Every reap is recorded with what it read, so a schedule can check FI-2's destructive clause from outside: nothing
// is reaped that was not reapable when it was. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
)

// A close capability's length, 128 bits (§7.7), as base64url without padding: a format value of the route.
const (
	fakeApiCloseCapabilityByteCount  = 16
	fakeApiCloseCapabilityTextLength = 22
)

// The page has been killed: the tab is gone, and it sends nothing more.
var ErrTestHttpPageKilled = errors.New("the page was killed")

// One ephemeral client's lease.
type fakeApiLease struct {
	seenTime    time.Time
	closeSha256 [sha256.Size]byte
}

// One connection of a client, open while its disconnect time is zero.
type fakeApiConnection struct {
	connectTime    time.Time
	disconnectTime time.Time
}

// One reap, with what the reap read when it took the client.
type FakeApiReap struct {
	ClientId sidecar.Id
	Time     time.Time
	// The close beacon reaped it, whatever its lease said; else the reaper's pass did.
	Close bool
	// The lease's seen_time at the reap.
	SeenTime time.Time
	// The client's newest disconnect at the reap, zero for none, and whether a connection was open.
	NewestDisconnectTime time.Time
	Connected            bool
}

// The leases' state on FakeApi, under its stateLock.
type fakeApiLeaseState struct {
	leases      map[sidecar.Id]*fakeApiLease
	connections map[sidecar.Id][]*fakeApiConnection
	reaps       []*FakeApiReap
	// lease writes that moved a seen_time, the poll's narrow-row write
	touchCount int
}

func newFakeApiLeaseState() fakeApiLeaseState {
	return fakeApiLeaseState{
		leases:      map[sidecar.Id]*fakeApiLease{},
		connections: map[sidecar.Id][]*fakeApiConnection{},
	}
}

// The route, on the api's mux.
func (self *FakeApi) addLeaseRoutes() {
	self.mux.HandleFunc("POST /sidecar/close", self.counted("POST /sidecar/close", self.handleClose))
}

// A capability's bytes from its text, strictly: exactly the base64url of exactly 16 bytes.
func parseFakeApiCloseCapability(capability string) ([]byte, bool) {
	if len(capability) != fakeApiCloseCapabilityTextLength {
		return nil, false
	}
	capabilityBytes, err := base64.RawURLEncoding.DecodeString(capability)
	if err != nil || len(capabilityBytes) != fakeApiCloseCapabilityByteCount ||
		base64.RawURLEncoding.EncodeToString(capabilityBytes) != capability {
		return nil, false
	}
	return capabilityBytes, true
}

// Mints a strict_exp, admin_refused, top-level client of networkId that proves clientPublicKey on refresh, as the key
// origin mints a page Worker's (§18.8), and for an ephemeral one its lease, seen at the mint, with the close
// capability the mint returns once; api keeps only its SHA-256. The token and capability are secrets the Net's
// capture scans for.
func (self *FakeApi) mintHttpPageClient(networkId sidecar.Id, clientPublicKey ed25519.PublicKey, ephemeral bool) (clientId sidecar.Id, token string, capability string, err error) {
	now := self.clock.Now()
	clientId = sidecar.NewId()
	if ephemeral {
		capabilityBytes := make([]byte, fakeApiCloseCapabilityByteCount)
		if _, err := rand.Read(capabilityBytes); err != nil {
			return sidecar.Id{}, "", "", err
		}
		capability = base64.RawURLEncoding.EncodeToString(capabilityBytes)
		lease := &fakeApiLease{seenTime: now, closeSha256: sha256.Sum256(capabilityBytes)}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.lease.leases[clientId] = lease
		}()
		if self.secretSink != nil {
			self.secretSink("close_capability", []byte(capability))
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.core.enrollClientKeys[clientId] = append(ed25519.PublicKey{}, clientPublicKey...)
	}()
	token = self.mintClientToken(&fakeApiClient{
		networkId:    networkId,
		clientId:     clientId,
		deviceId:     sidecar.NewId(),
		sessionId:    sidecar.NewId(),
		strictExp:    true,
		adminRefused: true,
		createTime:   now,
	})
	return clientId, token, capability, nil
}

// A poll's lease write, which the Net's long-poll calls when the client's marker sets or errs: seen_time moves to now,
// and never back. A client with no lease, every client that is not ephemeral and every removed one, writes nothing.
func (self *FakeApi) touchLease(clientId sidecar.Id) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lease := self.lease.leases[clientId]
	if lease == nil || self.removedClientIds[clientId] || !lease.seenTime.Before(now) {
		return
	}
	lease.seenTime = now
	self.lease.touchCount += 1
}

// The Net's long-poll's LeaseTouch (pushservice.LeaseTouchFunction): the lease lives on the Net's api, the one
// AddHttpPage mints on, so before that api exists there is none to touch.
func (self *Net) touchLease(ctx context.Context, clientId connect.Id) error {
	self.stateLock.Lock()
	api := self.api
	self.stateLock.Unlock()
	if api != nil {
		api.touchLease(sidecar.Id(clientId))
	}
	return nil
}

// Records a connection of the client opening now, as a connect resident's network_client_connection row; close
// records its disconnect at the clock's now then, once.
func (self *FakeApi) OpenConnection(clientId sidecar.Id) (close func()) {
	connection := &fakeApiConnection{connectTime: self.clock.Now()}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.lease.connections[clientId] = append(self.lease.connections[clientId], connection)
	}()
	var closeOnce sync.Once
	return func() {
		closeOnce.Do(func() {
			now := self.clock.Now()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			connection.disconnectTime = now
		})
	}
}

// Whether the client has a connection open now, and its newest disconnect, zero for none. Runs under stateLock.
func (self *FakeApi) connectionsWithLock(clientId sidecar.Id) (connected bool, newestDisconnectTime time.Time) {
	for _, connection := range self.lease.connections[clientId] {
		if connection.disconnectTime.IsZero() {
			connected = true
		} else if newestDisconnectTime.Before(connection.disconnectTime) {
			newestDisconnectTime = connection.disconnectTime
		}
	}
	return
}

// Removes an ephemeral client as a reap does: its tokens are refused after and its lease goes, by the removal
// chain's lease effect. Runs under stateLock.
func (self *FakeApi) reapWithLock(clientId sidecar.Id, now time.Time, close bool) *FakeApiReap {
	lease := self.lease.leases[clientId]
	connected, newestDisconnectTime := self.connectionsWithLock(clientId)
	reap := &FakeApiReap{
		ClientId:             clientId,
		Time:                 now,
		Close:                close,
		SeenTime:             lease.seenTime,
		NewestDisconnectTime: newestDisconnectTime,
		Connected:            connected,
	}
	self.removedClientIds[clientId] = true
	delete(self.lease.leases, clientId)
	self.lease.reaps = append(self.lease.reaps, reap)
	return reap
}

// One pass of taskworker's ephemeral job at the clock's now (§18.8's reap row): each ephemeral client with no open
// connection whose lease seen_time and newest disconnect, if any, are both over LeaseReapAfter old is reaped. The
// reaps this pass made.
func (self *FakeApi) ReapEphemeralClients() []*FakeApiReap {
	now := self.clock.Now()
	cutoff := now.Add(-self.settings.LeaseReapAfter)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reaps := []*FakeApiReap{}
	for clientId, lease := range self.lease.leases {
		if !lease.seenTime.Before(cutoff) || self.removedClientIds[clientId] {
			continue
		}
		connected, newestDisconnectTime := self.connectionsWithLock(clientId)
		if connected || !newestDisconnectTime.Before(cutoff) {
			continue
		}
		reaps = append(reaps, self.reapWithLock(clientId, now, false))
	}
	return reaps
}

// POST /sidecar/close (§18.8's close row): Public, its body the close capability as text/plain, no Authorization
// header read. A capability that matches a lease reaps its client at once; any other body does nothing. 204 either
// way, since a beacon reads no answer, and the body is never echoed.
func (self *FakeApi) handleClose(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(io.LimitReader(request.Body, self.settings.MaxCloseByteCount+1))
	if err != nil || self.settings.MaxCloseByteCount < int64(len(body)) {
		http.Error(writer, "Bad request", http.StatusBadRequest)
		return
	}
	if capabilityBytes, ok := parseFakeApiCloseCapability(strings.TrimSpace(string(body))); ok {
		closeSha256 := sha256.Sum256(capabilityBytes)
		now := self.clock.Now()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for clientId, lease := range self.lease.leases {
				if lease.closeSha256 == closeSha256 && !self.removedClientIds[clientId] {
					self.reapWithLock(clientId, now, true)
					return
				}
			}
		}()
	}
	writer.WriteHeader(http.StatusNoContent)
}

// Every reap so far, in order.
func (self *FakeApi) Reaps() []*FakeApiReap {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reaps := make([]*FakeApiReap, 0, len(self.lease.reaps))
	for _, reap := range self.lease.reaps {
		copied := *reap
		reaps = append(reaps, &copied)
	}
	return reaps
}

// The client's lease seen_time, false for no lease: none minted, or reaped or removed since.
func (self *FakeApi) LeaseSeenTime(clientId sidecar.Id) (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lease := self.lease.leases[clientId]
	if lease == nil {
		return time.Time{}, false
	}
	return lease.seenTime, true
}

// How many lease writes moved a seen_time so far.
func (self *FakeApi) LeaseTouchCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lease.touchCount
}

// What a page is.
type TestHttpPageSettings struct {
	// The page's network: zero is the Net's default network.
	NetworkId sidecar.Id
	// An ephemeral client with a lease and a close capability, a quick burner's shape and FS-37's page; false is a
	// member device's page Worker, which no lease reaps.
	Ephemeral bool
}

// One HTTPS-only page: its client, ClientKey and identity, and its cursor. Safe for concurrent use; its requests
// may run at once, as a page's polls and refreshes do.
type TestHttpPage struct {
	Name      string
	net       *Net
	api       *FakeApi
	networkId sidecar.Id
	sidecarId sidecar.Id
	clientId  sidecar.Id
	// signs the page's DPoP proofs; its public half is the client's enrolled key
	clientKey ed25519.PrivateKey
	// signs the page's identity binding; the sidecar_id is its own
	identityKey ed25519.PrivateKey
	// empty for a member page
	closeCapability string

	stateLock sync.Mutex
	token     string
	cursor    []byte
	killed    bool
}

// Adds an HTTPS-only page to the Net: its client minted on the Net's api (§18.8's identity row), and bound under an
// identity key of its own, so it refreshes as a bound sidecar's client does. settings nil is an ephemeral page in
// the Net's default network. Nothing is admitted in the log, and the page never connects.
func (self *Net) AddHttpPage(name string, settings *TestHttpPageSettings) (*TestHttpPage, error) {
	if settings == nil {
		settings = &TestHttpPageSettings{Ephemeral: true}
	}
	api, err := self.Api()
	if err != nil {
		return nil, err
	}
	networkId := settings.NetworkId
	if networkId == (sidecar.Id{}) {
		networkId = self.DefaultNetworkId()
	}
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, identityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	clientId, token, capability, err := api.mintHttpPageClient(networkId, clientKey.Public().(ed25519.PublicKey), settings.Ephemeral)
	if err != nil {
		return nil, err
	}
	page := &TestHttpPage{
		Name:            name,
		net:             self,
		api:             api,
		networkId:       networkId,
		sidecarId:       sidecar.NewId(),
		clientId:        clientId,
		clientKey:       clientKey,
		identityKey:     identityKey,
		closeCapability: capability,
		token:           token,
	}
	if HooksLinked {
		self.capture.AddSecret("page_client_key", clientKey.Seed())
		self.capture.AddSecret("page_identity_key", identityKey.Seed())
	}
	if err := page.bind(self.ctx); err != nil {
		return nil, fmt.Errorf("page %s did not bind: %w", name, err)
	}
	return page, nil
}

func (self *TestHttpPage) NetworkId() sidecar.Id {
	return self.networkId
}

func (self *TestHttpPage) ClientId() sidecar.Id {
	return self.clientId
}

// The page's sidecar_id, the subject a test admits read_only.
func (self *TestHttpPage) SidecarId() sidecar.Id {
	return self.sidecarId
}

// The public half of the page's identity key, which its admission names.
func (self *TestHttpPage) IdentityPublicKey() ed25519.PublicKey {
	return self.identityKey.Public().(ed25519.PublicKey)
}

// The page's current token.
func (self *TestHttpPage) Token() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.token
}

// The close capability its mint returned, which the key-origin document holds; empty for a member page.
func (self *TestHttpPage) CloseCapability() string {
	return self.closeCapability
}

// Kills the tab with no unload: every later request of the page fails with ErrTestHttpPageKilled, and no beacon goes.
func (self *TestHttpPage) Kill() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.killed = true
}

// The token to send, or ErrTestHttpPageKilled.
func (self *TestHttpPage) liveToken() (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.killed {
		return "", ErrTestHttpPageKilled
	}
	return self.token, nil
}

// Sends one request of the page to the api through its in-process transport, with the bearer when it is not empty:
// the answer's status and body. A transport error is the request's unknown outcome, as a page sees a dropped
// connection.
func (self *TestHttpPage) send(ctx context.Context, method string, path string, bearer string, dpop string, contentType string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, self.api.Origin()+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if dpop != "" {
		request.Header.Set("DPoP", dpop)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := self.api.Transport().RoundTrip(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, responseBody, nil
}

// POST /sidecar/bind of the page's first binding, by its identity key and ClientKey.
func (self *TestHttpPage) bind(ctx context.Context) error {
	binding, err := sidecar.NewSidecarIdentityBinding(&sidecar.SidecarIdentityBinding{
		NetworkId:  self.networkId,
		SidecarId:  self.sidecarId,
		ClientId:   self.clientId,
		Generation: 1,
		IssuedAt:   self.net.clock.Now(),
	}, self.identityKey.Seed(), self.clientKey.Seed())
	if err != nil {
		return err
	}
	body, err := json.Marshal(&fakeApiBindArgs{Binding: binding})
	if err != nil {
		return err
	}
	status, _, err := self.send(ctx, http.MethodPost, "/sidecar/bind", self.Token(), "", "application/json", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("bind answered %d", status)
	}
	return nil
}

// A DPoP proof of the page's ClientKey for method on path over token (§7.4, RFC 9449): a fresh 128-bit jti, iat the
// clock's whole second, htu the api's origin and path.
func (self *TestHttpPage) proof(method string, path string, token string) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]any{
		"alg": "EdDSA",
		"jwk": map[string]string{"crv": "Ed25519", "kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(self.clientKey.Public().(ed25519.PublicKey))},
		"typ": "dpop+jwt",
	})
	if err != nil {
		return "", err
	}
	ath := sha256.Sum256([]byte(token))
	claims, err := json.Marshal(map[string]any{
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
		"htm": method,
		"htu": self.api.Origin() + path,
		"iat": self.net.clock.Now().Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(self.clientKey, []byte(signingInput))), nil
}

// The answer of a sync route: a 200's PollResponse, nil for any other status.
func testHttpPagePollResponse(status int, body []byte) (*protocol.PollResponse, error) {
	if status != http.StatusOK {
		return nil, nil
	}
	response := &protocol.PollResponse{}
	if err := proto.Unmarshal(body, response); err != nil {
		return nil, err
	}
	return response, nil
}

// One GET /sidecar/sync/poll with the page's cursor, which holds on the Net's clock until a hint or the long-poll's
// hold: its status and a 200's answer, whose cursor the page keeps for its next poll. A lost answer keeps the old one,
// as a Worker does with an outcome it never saw.
func (self *TestHttpPage) Poll(ctx context.Context) (*protocol.PollResponse, int, error) {
	token, err := self.liveToken()
	if err != nil {
		return nil, 0, err
	}
	self.stateLock.Lock()
	path := "/sidecar/sync/poll"
	if 0 < len(self.cursor) {
		path += "?cursor=" + base64.RawURLEncoding.EncodeToString(self.cursor)
	}
	self.stateLock.Unlock()
	status, body, err := self.send(ctx, http.MethodGet, path, token, "", "", nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := testHttpPagePollResponse(status, body)
	if err != nil {
		return nil, status, err
	}
	if response != nil {
		self.stateLock.Lock()
		self.cursor = response.Cursor
		self.stateLock.Unlock()
	}
	return response, status, nil
}

// A poll the page started, which a schedule waits on once it has moved the clock past its hold.
type TestHttpPagePoll struct {
	done     chan struct{}
	response *protocol.PollResponse
	status   int
	err      error
}

// Starts one Poll on a goroutine of its own, as a page keeps one held.
func (self *TestHttpPage) StartPoll(ctx context.Context) *TestHttpPagePoll {
	poll := &TestHttpPagePoll{done: make(chan struct{})}
	go func() {
		defer close(poll.done)
		poll.response, poll.status, poll.err = self.Poll(ctx)
	}()
	return poll
}

// Closed once the poll has its answer.
func (self *TestHttpPagePoll) Done() <-chan struct{} {
	return self.done
}

// The poll's answer, once it has one, or ctx's error.
func (self *TestHttpPagePoll) Wait(ctx context.Context) (*protocol.PollResponse, int, error) {
	select {
	case <-self.done:
		return self.response, self.status, self.err
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

// One GET /auth/refresh with the page's ClientKey's proof: its status. A new token replaces the page's.
func (self *TestHttpPage) Refresh(ctx context.Context) (int, error) {
	token, err := self.liveToken()
	if err != nil {
		return 0, err
	}
	proof, err := self.proof(http.MethodGet, "/auth/refresh", token)
	if err != nil {
		return 0, err
	}
	status, body, err := self.send(ctx, http.MethodGet, "/auth/refresh", token, proof, "", nil)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return status, nil
	}
	result := &fakeApiRefreshResult{}
	if err := json.Unmarshal(body, result); err != nil {
		return status, err
	}
	if result.Error != nil || result.ByJwt == "" {
		return status, fmt.Errorf("refresh refused: %s", result.Error.Code)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.token = result.ByJwt
	return status, nil
}

// One GET /sidecar/sync/versions, the page's read of every topic's version: its status and a 200's answer.
func (self *TestHttpPage) ReadVersions(ctx context.Context) (*protocol.PollResponse, int, error) {
	token, err := self.liveToken()
	if err != nil {
		return nil, 0, err
	}
	status, body, err := self.send(ctx, http.MethodGet, "/sidecar/sync/versions", token, "", "", nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := testHttpPagePollResponse(status, body)
	return response, status, err
}

// The key-origin document's pagehide beacon: POST /sidecar/close with the close capability as a text/plain body and
// no Authorization header. Its status, which a beacon never reads.
func (self *TestHttpPage) Unload(ctx context.Context) (int, error) {
	if _, err := self.liveToken(); err != nil {
		return 0, err
	}
	status, _, err := self.send(ctx, http.MethodPost, "/sidecar/close", "", "", "text/plain;charset=UTF-8", []byte(self.closeCapability))
	return status, err
}

// Where a long-poll hold that starts now ends, and how many timers are set for then already: what a schedule reads
// before it starts its pages' polls, and waits from with AwaitPollHolds. Another timer can fall at the same instant,
// such as a poll marker's expiry, so only the timers past this count are the holds.
type PollHoldMark struct {
	HoldEnd time.Time
	Count   int
}

// The mark of holds that start now (PollHoldMark).
func (self *Net) PollHoldMark() PollHoldMark {
	holdEnd := self.clock.Now().Add(pushservice.DefaultLongPollSettings().HoldTimeout)
	return PollHoldMark{HoldEnd: holdEnd, Count: self.timersAt(holdEnd)}
}

// How many pending timers of the Net's clock are set for at.
func (self *Net) timersAt(at time.Time) int {
	pending := self.clock.PendingTimers()
	count := 0
	for _, timer := range pending {
		if timer.Equal(at) {
			count += 1
		}
	}
	return count
}

// Returns once count long-poll holds started since mark wait on the Net's clock: count more timers set for the
// mark's hold end. How a schedule knows its pages' polls hold before it moves the clock past them, with no sleep.
func (self *Net) AwaitPollHolds(ctx context.Context, mark PollHoldMark, count int) error {
	for {
		pending, added := self.clock.WatchTimers()
		held := -mark.Count
		for _, at := range pending {
			if at.Equal(mark.HoldEnd) {
				held += 1
			}
		}
		if count <= held {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
