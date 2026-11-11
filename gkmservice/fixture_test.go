package gkmservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A synthetic id from a label, so tests read the same every run.
func testId(label string) sidecar.Id {
	var id sidecar.Id
	copy(id[:], fmt.Sprintf("%-16s", label))
	return id
}

// One sidecar's honored rights on one repo in the fake state.
type fakeGkmAuthKey struct {
	sidecarId sidecar.Id
	repoId    sidecar.Id
}

// T2's GkmAuthState: what a test says gkm's newest verified state holds. Safe for concurrent use.
type fakeGkmAuthState struct {
	stateLock sync.Mutex
	// every answer unknown, as a network whose state is not loaded
	unloaded bool
	// sidecars a rev/ object voids
	revokedSidecarIds map[sidecar.Id]bool
	// what CheckRevocation answers when it cannot tell
	revocationErr   error
	revocationCount int
	sidecarFacts    map[sidecar.Id]*GkmSidecarFacts
	honoredRights   map[fakeGkmAuthKey]sidecar.AclEvsRights
	repoReaderIds   map[sidecar.Id]map[sidecar.Id]bool
	pendingTargets  map[sidecar.Id][]*GkmPendingTarget
	honorCount      int
	// the log as gkm's state judges pins: the chain at each position, its newest position and its previous base's
	logChains       map[uint64][]byte
	newestVersion   uint64
	baseVersion     uint64
	delegationReads map[string]bool
	// what DelegationKey answers, by delegation_id: Denied for one not here
	delegationKeys  map[string]*GkmDelegationKeyFacts
	lateHolderIds   map[sidecar.Id][]sidecar.Id
	writerOverrides map[sidecar.Id][]sidecar.Id
	// what HoldersDropped answers for a repo, Denied when unset, and what it was last asked
	holdersDroppedAnswers map[sidecar.Id]GkmAuthAnswer
	holdersDroppedAsks    []*fakeGkmHoldersDroppedAsk
}

// One HoldersDropped question as the fake state was asked it.
type fakeGkmHoldersDroppedAsk struct {
	repoId     sidecar.Id
	pinVersion uint64
	since      time.Time
}

func newFakeGkmAuthState() *fakeGkmAuthState {
	return &fakeGkmAuthState{
		revokedSidecarIds: map[sidecar.Id]bool{},
		sidecarFacts:      map[sidecar.Id]*GkmSidecarFacts{},
		honoredRights:     map[fakeGkmAuthKey]sidecar.AclEvsRights{},
		repoReaderIds:     map[sidecar.Id]map[sidecar.Id]bool{},
		pendingTargets:    map[sidecar.Id][]*GkmPendingTarget{},
		logChains:         map[uint64][]byte{},
		delegationReads:   map[string]bool{},
		delegationKeys:    map[string]*GkmDelegationKeyFacts{},
		lateHolderIds:     map[sidecar.Id][]sidecar.Id{},
		writerOverrides:   map[sidecar.Id][]sidecar.Id{},

		holdersDroppedAnswers: map[sidecar.Id]GkmAuthAnswer{},
	}
}

// What HoldersDropped answers for repoId from now on: Allowed as a shrink, an expiry or a compromise retirement since
// any pin would show.
func (self *fakeGkmAuthState) setHoldersDropped(repoId sidecar.Id, answer GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holdersDroppedAnswers[repoId] = answer
}

// The HoldersDropped questions asked so far.
func (self *fakeGkmAuthState) holdersDroppedAsked() []*fakeGkmHoldersDroppedAsk {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.holdersDroppedAsks)
}

func (self *fakeGkmAuthState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holdersDroppedAsks = append(self.holdersDroppedAsks, &fakeGkmHoldersDroppedAsk{repoId: repoId, pinVersion: pin.GetVersion(), since: since})
	if self.unloaded {
		return GkmAuthUnknown
	}
	answer, ok := self.holdersDroppedAnswers[repoId]
	if !ok {
		return GkmAuthDenied
	}
	return answer
}

// A synthetic chain value A_n for position n.
func fakeGkmChain(version uint64) []byte {
	chain := sha256.Sum256([]byte(fmt.Sprintf("chain-%d", version)))
	return chain[:]
}

// Moves the log to version, every position up to it on one chain, with its previous base at baseVersion.
func (self *fakeGkmAuthState) advanceLog(version uint64, baseVersion uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for n := self.newestVersion + 1; n <= version; n += 1 {
		self.logChains[n] = fakeGkmChain(n)
	}
	self.newestVersion = max(self.newestVersion, version)
	self.baseVersion = baseVersion
}

// The pin of position version on the fake log's chain.
func fakeGkmPin(version uint64) *bridge.AuthPin {
	return &bridge.AuthPin{Version: version, Chain: fakeGkmChain(version)}
}

func (self *fakeGkmAuthState) setDelegationReads(repoId sidecar.Id, delegationId []byte, reads bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.delegationReads[sidecar.EvsKeyId(repoId)+":"+fmt.Sprintf("%x", delegationId)] = reads
}

// What the state holds of a Delegation's reader key from now on, nil forgetting it.
func (self *fakeGkmAuthState) setDelegationKey(delegationId []byte, facts *GkmDelegationKeyFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if facts == nil {
		delete(self.delegationKeys, string(delegationId))
		return
	}
	factsCopy := *facts
	self.delegationKeys[string(delegationId)] = &factsCopy
}

func (self *fakeGkmAuthState) setLateHolders(repoId sidecar.Id, sidecarIds []sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lateHolderIds[repoId] = slices.Clone(sidecarIds)
}

// Who a repo's pending and wrap-pending hints go to, in place of its writers, as the directory group's rule would.
func (self *fakeGkmAuthState) setWriters(repoId sidecar.Id, sidecarIds []sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writerOverrides[repoId] = slices.Clone(sidecarIds)
}

func (self *fakeGkmAuthState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, GkmAuthUnknown
	}
	readerIds := []sidecar.Id{}
	for sidecarId, reads := range self.repoReaderIds[repoId] {
		if reads {
			readerIds = append(readerIds, sidecarId)
		}
	}
	slices.SortFunc(readerIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	return readerIds, GkmAuthAllowed
}

func (self *fakeGkmAuthState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, GkmAuthUnknown
	}
	if overrides, ok := self.writerOverrides[repoId]; ok {
		return slices.Clone(overrides), GkmAuthAllowed
	}
	writerIds := []sidecar.Id{}
	for key, rights := range self.honoredRights {
		if key.repoId == repoId && rights.Has(sidecar.AclEvsWrite) {
			writerIds = append(writerIds, key.sidecarId)
		}
	}
	slices.SortFunc(writerIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	return writerIds, GkmAuthAllowed
}

func (self *fakeGkmAuthState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case self.unloaded, self.newestVersion < pin.GetVersion():
		return GkmAuthUnknown
	case pin.GetVersion() < self.baseVersion, !bytes.Equal(self.logChains[pin.GetVersion()], pin.GetChain()):
		return GkmAuthDenied
	}
	return GkmAuthAllowed
}

func (self *fakeGkmAuthState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return GkmAuthUnknown
	}
	if self.delegationReads[sidecar.EvsKeyId(repoId)+":"+fmt.Sprintf("%x", delegationId)] {
		return GkmAuthAllowed
	}
	return GkmAuthDenied
}

func (self *fakeGkmAuthState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*GkmDelegationKeyFacts, GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, GkmAuthUnknown
	}
	facts, ok := self.delegationKeys[string(delegationId)]
	if !ok {
		return nil, GkmAuthDenied
	}
	factsCopy := *facts
	return &factsCopy, GkmAuthAllowed
}

func (self *fakeGkmAuthState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, GkmAuthUnknown
	}
	return slices.Clone(self.lateHolderIds[repoId]), GkmAuthAllowed
}

// Admits a sidecar with facts, replacing what the state held of it.
func (self *fakeGkmAuthState) admit(sidecarId sidecar.Id, facts *GkmSidecarFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	factsCopy := *facts
	self.sidecarFacts[sidecarId] = &factsCopy
}

// Changes what the state holds of an admitted sidecar.
func (self *fakeGkmAuthState) update(sidecarId sidecar.Id, edit func(facts *GkmSidecarFacts)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	edit(self.sidecarFacts[sidecarId])
}

// Gives a sidecar rights on a repo, with what they imply, replacing what it held; a reader once it reads.
func (self *fakeGkmAuthState) grant(sidecarId sidecar.Id, repoId sidecar.Id, rights sidecar.AclEvsRights) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	implied := gkmImpliedRights(gkmStrongestRight(rights)) | rights
	self.honoredRights[fakeGkmAuthKey{sidecarId: sidecarId, repoId: repoId}] = implied
	if self.repoReaderIds[repoId] == nil {
		self.repoReaderIds[repoId] = map[sidecar.Id]bool{}
	}
	self.repoReaderIds[repoId][sidecarId] = implied.Has(sidecar.AclEvsRead)
}

// Drops every right a sidecar holds on a repo, as a group edit or a Suspend would.
func (self *fakeGkmAuthState) drop(sidecarId sidecar.Id, repoId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.honoredRights, fakeGkmAuthKey{sidecarId: sidecarId, repoId: repoId})
	delete(self.repoReaderIds[repoId], sidecarId)
}

func (self *fakeGkmAuthState) setPendingTargets(sidecarId sidecar.Id, targets []*GkmPendingTarget) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pendingTargets[sidecarId] = targets
}

func (self *fakeGkmAuthState) revoke(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revokedSidecarIds[sidecarId] = true
}

func (self *fakeGkmAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revocationCount += 1
	if self.revocationErr != nil {
		return self.revocationErr
	}
	if principal.SidecarId != nil && self.revokedSidecarIds[sidecar.Id(*principal.SidecarId)] {
		return ErrGkmTokenRevoked
	}
	return nil
}

func (self *fakeGkmAuthState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*GkmSidecarFacts, GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, GkmAuthUnknown
	}
	facts, ok := self.sidecarFacts[sidecarId]
	if !ok {
		return nil, GkmAuthDenied
	}
	factsCopy := *facts
	return &factsCopy, GkmAuthAllowed
}

func (self *fakeGkmAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.honorCount += 1
	if self.unloaded {
		return GkmAuthUnknown
	}
	held := self.honoredRights[fakeGkmAuthKey{sidecarId: sidecar.Id(*principal.SidecarId), repoId: repoId}]
	if right != 0 && held.Has(right) {
		return GkmAuthAllowed
	}
	return GkmAuthDenied
}

func (self *fakeGkmAuthState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return GkmAuthUnknown
	}
	if self.repoReaderIds[repoId][sidecarId] {
		return GkmAuthAllowed
	}
	return GkmAuthDenied
}

func (self *fakeGkmAuthState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*GkmPendingTarget, GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, GkmAuthUnknown
	}
	return slices.Clone(self.pendingTargets[sidecarId]), GkmAuthAllowed
}

// gkm-9's lines as a test reads them.
type recordingGkmServiceLog struct {
	stateLock sync.Mutex
	entries   []*GkmServiceLogEntry
}

func (self *recordingGkmServiceLog) Write(entry *GkmServiceLogEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entryCopy := *entry
	self.entries = append(self.entries, &entryCopy)
}

func (self *recordingGkmServiceLog) last() *GkmServiceLogEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.entries[len(self.entries)-1]
}

// One engine on one fake host with two metadata clusters, its network admitted by the gkm gate.
type gkmFixture struct {
	t          *testing.T
	ctx        context.Context
	clock      *sidecartest.FakeClock
	host       *sidecartest.FakeHost
	auth       *fakeGkmAuthState
	serviceLog *recordingGkmServiceLog
	settings   *GkmServiceSettings
	deps       *GkmEngineDeps
	engine     *GkmEngine
	networkId  connect.Id
}

func newGkmFixture(t *testing.T) *gkmFixture {
	return newGkmFixtureWith(t, nil)
}

func newGkmFixtureWith(t *testing.T, adjust func(settings *GkmServiceSettings, deps *GkmEngineDeps)) *gkmFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1", "meta-2"}
	// every report fails the test: §10.6's <ref>.claim beside its <ref> is a byte prefix and no path prefix
	// (owner decision 234), so the fake reports none
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	networkId := connect.Id(testId("network-a"))
	host.Gates.OpenService(sidecar.ServiceGateGkm, networkId)
	fixture := &gkmFixture{
		t:          t,
		ctx:        ctx,
		clock:      clock,
		host:       host,
		auth:       newFakeGkmAuthState(),
		serviceLog: &recordingGkmServiceLog{},
		settings:   DefaultGkmServiceSettings(),
		networkId:  networkId,
	}
	fixture.deps = &GkmEngineDeps{AuthState: fixture.auth, ServiceLog: fixture.serviceLog}
	if adjust != nil {
		adjust(fixture.settings, fixture.deps)
	}
	fixture.start()
	return fixture
}

// Starts an engine on the fixture's host, as a restart would: nothing of the last one's caches carries over.
func (self *gkmFixture) start() {
	if self.engine != nil {
		self.engine.Close()
	}
	engine, err := NewGkmEngine(self.ctx, self.host.ServiceHost(), self.settings, self.deps)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	self.engine = engine
}

// The fixture's ctx as a write budget passes it, for a test writing as a handler would once it has spent: the budget
// is not what such a test is about (budget_test.go is).
func (self *gkmFixture) spentCtx() context.Context {
	return sidecar.WithWriteClass(self.ctx, sidecar.WriteClassP1)
}

// A token for sidecarId with scopes, each repo:<id>:<role> or recovery:<member_id>. A zero sidecarId gives a token
// with no ur_sidecar_id.
func (self *gkmFixture) token(sidecarId sidecar.Id, scopes ...string) string {
	principal := &sidecar.Principal{
		NetworkId: self.networkId,
		ClientId:  connect.Id(testId("client-" + string(sidecarId[:6]))),
		Audience:  GkmAudience,
		Scopes:    scopes,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	}
	if sidecarId != (sidecar.Id{}) {
		connectSidecarId := connect.Id(sidecarId)
		principal.SidecarId = &connectSidecarId
	}
	return self.host.Authenticator.Issue(principal)
}

// The scope string for a repo and role.
func repoScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// One request through the engine's handler.
func (self *gkmFixture) serve(method string, path string, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(self.ctx, method, path, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// A message's bytes.
func (self *gkmFixture) marshal(message proto.Message) []byte {
	self.t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		self.t.Fatal(err)
	}
	return body
}

// A cluster of the fake store.
func (self *gkmFixture) cluster(clusterId string) sidecar.BlobCluster {
	self.t.Helper()
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

// Creates key on a cluster, as another writer would.
func (self *gkmFixture) put(clusterId string, key string, body []byte) {
	self.t.Helper()
	if _, err := self.cluster(clusterId).PutIfNoneMatch(self.ctx, key, body, nil); err != nil {
		self.t.Fatalf("put %s: %v", key, err)
	}
}

// What a key holds on a cluster, nil for nothing.
func (self *gkmFixture) object(clusterId string, key string) []byte {
	self.t.Helper()
	objectBytes, _, err := readGkmObject(self.ctx, self.cluster(clusterId), key, 16*1024*1024)
	if err != nil {
		return nil
	}
	return objectBytes
}

// Places a repo on clusterId with repo/ in state, as evs's creation would.
func (self *gkmFixture) placeRepo(repoId sidecar.Id, clusterId string, state protocol.EvsRepoState) {
	self.t.Helper()
	place := &sidecar.EvsRepoPlace{ClusterId: clusterId, CreatorSidecarId: testId("creator")}
	placeBytes, err := place.Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	self.put("meta-1", sidecar.EvsPlaceKey(repoId), placeBytes)
	self.put(clusterId, GkmEvsRepoKey(repoId), self.marshal(&protocol.EvsRepoObject{
		RepoId:    repoId.Bytes(),
		Kind:      protocol.RepoKind_REPO_KIND_GENERAL,
		State:     state,
		Format:    1,
		NetworkId: testId("network-a").Bytes(),
	}))
}

// Files a GroupForm at seq tying groupId to repoId on clusterId, as KEYS-M2-14's POST /gkm/groups would.
func (self *gkmFixture) fileForm(repoId sidecar.Id, clusterId string, seq uint64, groupId sidecar.Id) {
	self.t.Helper()
	body := self.marshal(&protocol.GroupForm{RepoId: repoId.Bytes(), GroupId: groupId.Bytes(), Generation: 1})
	signed := &bridge.Signed{Body: body, SignerId: testId("creator").Bytes(), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM)}
	self.put(clusterId, GkmFormKey(repoId, seq), self.marshal(signed))
	// the group's owner marker, as a creation writes it first, in the fixture's one network
	self.put(clusterId, GkmGroupOwnerKey(groupId), self.marshal(&protocol.GkmGroupOwner{RepoId: repoId.Bytes(), NetworkId: sidecar.Id(self.networkId).Bytes()}))
}

// One admitted sidecar with its own identity key, which signs as it would.
type gkmTestSidecar struct {
	sidecarId  sidecar.Id
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// A new sidecar the fake state admits with facts, its identity key filled in.
func (self *gkmFixture) newSidecar(label string, facts *GkmSidecarFacts) *gkmTestSidecar {
	self.t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		self.t.Fatal(err)
	}
	testSidecar := &gkmTestSidecar{sidecarId: testId(label), publicKey: publicKey, privateKey: privateKey}
	factsCopy := *facts
	factsCopy.IdentityPublicKey = publicKey
	self.auth.admit(testSidecar.sidecarId, &factsCopy)
	return testSidecar
}

// What a member device's facts start as.
func memberDeviceFacts(memberId sidecar.Id) *GkmSidecarFacts {
	return &GkmSidecarFacts{MemberDevice: true, MemberId: &memberId}
}

// Signs as the sidecar's identity key, sidecar.GkmSignFunction's shape.
func (self *gkmTestSidecar) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// The real MLS engine of this sidecar, which makes its KeyPackages.
func (self *gkmTestSidecar) mlsEngine(t *testing.T, clock sidecar.Clock) sidecar.MlsEngine {
	t.Helper()
	admission := sha256.Sum256(append([]byte("admission of "), self.sidecarId.Bytes()...))
	engine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         self.sidecarId,
		IdentityPublicKey: self.publicKey,
		AdmissionSha256:   admission[:],
		Sign:              self.sign,
		Store:             sidecartest.NewFakeStore().Root(),
		Clock:             clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// The hints a sidecar's current client was told, once every queued hint has gone out.
func (self *gkmFixture) hints(sidecarId sidecar.Id) []*protocol.GkmHint {
	self.t.Helper()
	if err := self.engine.AwaitHints(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	hints := []*protocol.GkmHint{}
	for _, clientHint := range self.host.Push.Hints(connect.Id(self.clientOf(sidecarId))) {
		hint := &protocol.GkmHint{}
		if err := proto.Unmarshal(clientHint.Body, hint); err != nil {
			self.t.Fatalf("a hint that does not parse: %v", err)
		}
		hints = append(hints, hint)
	}
	return hints
}

// The client a sidecar is bound to in the fake push, bound on first use.
func (self *gkmFixture) clientOf(sidecarId sidecar.Id) sidecar.Id {
	clientId := testId("push-" + string(sidecarId[:10]))
	self.host.Push.BindSidecar(connect.Id(sidecarId), connect.Id(clientId))
	return clientId
}
