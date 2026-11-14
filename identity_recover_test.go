package sidecar

// CORE-M2-06: code-only recovery in §5.6's and §7.9's order, on a test network's real verified log, real sealed
// bindings and real config heads, with fakes of KEYS-M2-24's recovery client and of the head reader. §22.7's admission
// rows: until admitted the device reads only the log and its member's wraps and signs nothing but its admission; §7.9's
// table picks a plain admission or a proposal by the log's own judge; FS-16's forged genesis whose log admits the real
// rotators raises head_alarm (fork) and stops, and so does a forged RecoveryWrap; a restored binding uploads its
// ReaderKey and no KeyPackage before the anchor; a restart resumes the one admission it filed, with the same bytes.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A recovery code's words, from entropy counting up from fill.
func recoverTestWords(t *testing.T, fill byte) string {
	t.Helper()
	code, err := NewRecoveryCode(bytes.NewReader(countingBytes(fill, recoveryCodeByteCount)))
	if err != nil {
		t.Fatal(err)
	}
	words, err := code.Words()
	code.Erase()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(words, " ")
}

// A fresh code of the words, as a person types them.
func recoverTestCode(t *testing.T, words string) *RecoveryCode {
	t.Helper()
	code, err := ParseRecoveryCode(words)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// The keys the words derive.
func recoverTestKeys(t *testing.T, words string) *RecoveryKeys {
	t.Helper()
	keys, err := recoverTestCode(t, words).Keys()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// A test network like newTestConfigNet's, its owner's first device another, so another genesis for the same network
// id, as a forged log carries.
func newRecoverTestNetOwnedBy(t *testing.T, ownerLabel string) *testConfigNet {
	t.Helper()
	self := &testConfigNet{
		t:             t,
		networkId:     testConfigId("network"),
		ownerMemberId: testConfigId("owner member"),
		source:        newTestConfigRowsSource(),
		timeMs:        testConfigStartMs,
		statesAt:      map[uint64]*ConfigState{},
		verdicts:      map[uint64]ConfigVerdict{},
	}
	self.owner = testConfigDevice{sidecarId: testConfigId(ownerLabel), memberId: self.ownerMemberId, key: testConfigDeviceKey(ownerLabel)}
	self.signedGenesis = self.sign(self.owner, bridge.SignedType_SIGNED_GENESIS, &bridge.Genesis{
		NetworkId:              self.networkId.Bytes(),
		ConfigRepoId:           testConfigId("config repo").Bytes(),
		OwnerMemberId:          self.ownerMemberId.Bytes(),
		OwnerSidecarId:         self.owner.sidecarId.Bytes(),
		OwnerIdentityPublicKey: self.owner.publicKey(),
		TimeMs:                 testConfigStartMs,
	})
	self.chain = bridge.GenesisChain(self.signedGenesis)
	log, err := NewConfigLog(testConfigLogSettings(), self.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	self.log = log
	self.statesAt[0] = log.State()
	rows := &bridge.ProjectionRows{
		Members: []*bridge.MemberRow{{MemberId: self.ownerMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         self.owner.sidecarId.Bytes(),
			AdmissionSigners:  [][]byte{self.owner.sidecarId.Bytes()},
			IdentityPublicKey: self.owner.publicKey(),
			IdentityAlg:       configIdentityAlgEd25519,
			MemberId:          self.ownerMemberId.Bytes(),
		}},
	}
	if verdict := self.pushBase(self.owner, rows, 0, 1, 0); !verdict.Accepted() {
		t.Fatalf("base 1: %v", verdict.Refusal)
	}
	return self
}

// §7.9's verified state as the recovering device reads it, over the net's own log: ConfigAuthority's answers, from
// the same ConfigState, and the judge and anchor view this task adds.
type recoverTestAuthority struct {
	world *recoverTestWorld
}

var (
	_ SidecarAuthority          = (*recoverTestAuthority)(nil)
	_ SidecarStatementJudge     = (*recoverTestAuthority)(nil)
	_ SidecarRecoveryLogView    = (*recoverTestAuthority)(nil)
	_ SidecarRecoveryAuthority  = (*recoverTestAuthority)(nil)
	_ SidecarAuthorityProposals = (*recoverTestAuthority)(nil)
)

func (self *recoverTestAuthority) state() *ConfigState {
	return self.world.net.log.State()
}

func (self *recoverTestAuthority) Pin() *bridge.AuthPin {
	return self.state().Pin()
}

func (self *recoverTestAuthority) Admission(sidecarId Id) *AclSidecar {
	return configCloneAclSidecar(self.state().Sidecar(sidecarId))
}

func (self *recoverTestAuthority) MemberDevices(memberId Id) []*AclSidecar {
	state := self.state()
	devices := []*AclSidecar{}
	for _, sidecarId := range state.SidecarIds() {
		if rowMemberId, untagged := configRowMember(state.SidecarRow(sidecarId)); untagged && rowMemberId == memberId {
			devices = append(devices, configCloneAclSidecar(state.Sidecar(sidecarId)))
		}
	}
	return devices
}

func (self *recoverTestAuthority) Consented(sidecarId Id, memberId Id) bool {
	acl, err := self.state().Acl()
	return err == nil && acl.ConsentedFor(sidecarId, memberId)
}

func (self *recoverTestAuthority) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	binding := self.state().CurrentBinding(memberId)
	if binding == nil {
		return nil
	}
	return proto.Clone(binding).(*bridge.RecoveryBindingRow)
}

func (self *recoverTestAuthority) PresenceRequired(statement *SidecarStatement) bool {
	return self.state().PresenceRequired(statement)
}

func (self *recoverTestAuthority) LiveKeys(sidecarId Id) []*bridge.KeyRow {
	return self.state().LiveKeys(sidecarId)
}

func (self *recoverTestAuthority) Cascade(targetId Id, sinceN uint64) ([]DeviceRevokeItem, error) {
	return nil, nil
}

func (self *recoverTestAuthority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	return 0, time.Time{}, false
}

func (self *recoverTestAuthority) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	return func() {}
}

func (self *recoverTestAuthority) BindingRestored(memberId Id) bool {
	return self.state().BindingRestored(memberId)
}

func (self *recoverTestAuthority) PendingProposal(proposalId []byte) *bridge.ProposalRow {
	state := self.state()
	if len(proposalId) != sha256.Size {
		return nil
	}
	proposal := state.proposals[[sha256.Size]byte(proposalId)]
	if proposal == nil || !proposal.open(state.timeMs) {
		return nil
	}
	return proto.Clone(proposal.row).(*bridge.ProposalRow)
}

func (self *recoverTestAuthority) Settings() *bridge.ProjectionSettings {
	return self.state().Settings()
}

func (self *recoverTestAuthority) JudgeStatement(signedBytes []byte) error {
	return configJudgeStatement(self.world.net.log, signedBytes, self.world.clock.Now())
}

func (self *recoverTestAuthority) RecoveryLog() (*SidecarRecoveryLog, error) {
	return configRecoveryLog(self.world.net.log)
}

// api's delta route over the world's net, judging and appending as its sequencer does: a statement the log refuses
// answers 403 and appends nothing, and a retry of one it holds answers that entry. answers scripts each post: ok,
// lost (appended, the answer lost) or down (nothing appended, 503). Every route asked is kept.
type recoverTestApi struct {
	world *recoverTestWorld

	stateLock sync.Mutex
	routes    []string
	posts     [][]byte
	answers   []string
	landed    map[[sha256.Size]byte]*bridge.AuthPin
}

func (self *recoverTestApi) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	if err != nil {
		return nil, err
	}
	respond := func(status int, value any) *http.Response {
		encoded, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(encoded)), Header: http.Header{"Content-Type": {"application/json"}}, Request: request}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = append(self.routes, request.Method+" "+request.URL.Path)
	if request.URL.Path != "/network/config/delta" {
		return respond(http.StatusNotFound, map[string]any{"error": "No such route.", "code": "not_found"}), nil
	}
	answer := "ok"
	if 0 < len(self.answers) {
		answer, self.answers = self.answers[0], self.answers[1:]
	}
	wire := &sidecarConfigDeltaWire{}
	if err := json.Unmarshal(body, wire); err != nil {
		return nil, err
	}
	self.posts = append(self.posts, wire.Signed)
	if answer == "down" {
		return respond(http.StatusServiceUnavailable, map[string]any{"error": "The log is unavailable.", "code": "unavailable"}), nil
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(wire.Signed, signed); err != nil {
		return nil, err
	}
	signedType := bridge.SignedType(signed.GetType())
	purpose, _ := ConfigStatementPurpose(signedType)
	statementId := bridge.SignedBytesSha256(purpose, signedType, signed.GetBody())
	pin := self.landed[statementId]
	if pin == nil {
		net := self.world.net
		if verdict := net.log.Check(wire.Signed, net.timeMs+1000); verdict.Refusal != nil {
			return respond(http.StatusForbidden, map[string]any{"error": "The statement fails at the tip.", "code": "config_refused"}), nil
		}
		pin = net.push(net.makeEntry(bridge.AuthEntryKindStatement, wire.Signed)).Pin
		self.landed[statementId] = pin
	}
	if answer == "lost" {
		return nil, errors.New("the answer was lost")
	}
	return respond(http.StatusOK, &sidecarConfigPinReply{N: pin.GetVersion(), Chain: pin.GetChain()}), nil
}

// The routes asked so far, and every post's statement, decoded.
func (self *recoverTestApi) routesSoFar() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.routes)
}

func (self *recoverTestApi) postsSoFar(t *testing.T) []*bridge.Signed {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	signeds := []*bridge.Signed{}
	for _, post := range self.posts {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(post, signed); err != nil {
			t.Fatal(err)
		}
		signeds = append(signeds, signed)
	}
	return signeds
}

// KEYS-M2-24's recovery client as its contract reads (gkm_recovery.go): the fetch keeps nothing of note; the anchor
// waits while this device is not admitted by its member's recovery key, or no wrap has given it the config group's
// key, runs the check once on that key, stops for good on a check that failed and changes nothing on one that could
// not run; the pass runs only once anchored. Every call is kept, in order.
type recoverTestGroups struct {
	world *recoverTestWorld
	calls []string
	// the config group's key a RecoveryWrap or a ReaderWrap gives the device, nil for none yet
	key   *EvsRepoKey
	phase SidecarRecoveryPhase
	// what each run of the check answered
	anchorErrs []error
	repos      []*GkmRecoveryRepo
}

func (self *recoverTestGroups) FetchRecoveryWraps(ctx context.Context, binding *GkmRecoveryBinding, admitted bool) (int, error) {
	self.calls = append(self.calls, fmt.Sprintf("fetch admitted=%v", admitted))
	if err := checkGkmRecoveryBinding(binding); err != nil {
		return 0, err
	}
	return 1, nil
}

func (self *recoverTestGroups) AnchorRecovery(ctx context.Context, args *GkmRecoverArgs) error {
	self.calls = append(self.calls, "anchor")
	switch self.phase {
	case SidecarRecoveryAnchored:
		return nil
	case SidecarRecoveryStopped:
		return ErrGkmRecoveryStopped
	}
	if err := checkGkmRecoveryBinding(args.Binding); err != nil {
		return err
	}
	if args.Anchor == nil {
		return ErrGkmUnavailable
	}
	if args.ConfigRepoId != testConfigId("config repo") {
		return fmt.Errorf("%w: repo %s", ErrGkmNoRepo, args.ConfigRepoId)
	}
	state := self.world.net.log.State()
	row := state.SidecarRow(self.world.selfId)
	if row == nil || row.GetRevokedAt() != 0 || !gkmRecoveryAdmitted(state, row) {
		return fmt.Errorf("%w: not admitted by a recovery key", ErrGkmWait)
	}
	if self.key == nil {
		return fmt.Errorf("%w: no wrap of the config group yet", ErrGkmWait)
	}
	err := args.Anchor(ctx, self.key)
	self.anchorErrs = append(self.anchorErrs, err)
	if errors.Is(err, ErrGkmRecoveryAnchor) {
		self.phase = SidecarRecoveryStopped
		return fmt.Errorf("%w: %w", ErrGkmRecoveryStopped, err)
	}
	if err != nil {
		return err
	}
	self.phase = SidecarRecoveryAnchored
	return nil
}

func (self *recoverTestGroups) RunRecovery(ctx context.Context, args *GkmRecoverArgs) ([]*GkmRecoveryRepo, error) {
	self.calls = append(self.calls, "run")
	switch self.phase {
	case SidecarRecoveryAnchored:
		return self.repos, nil
	case SidecarRecoveryStopped:
		return nil, ErrGkmRecoveryStopped
	}
	return nil, ErrGkmRecoveryNotAnchored
}

// The config head reader: the heads the test built by config version, opened under the world's config key alone,
// its keyAt answering that key's generation; or, set, a forged head answered under any key, as a server that forged
// the wrap gives one of its own; ladderKey, set, is what keyAt answers for every generation.
type recoverTestHeads struct {
	world     *recoverTestWorld
	heads     map[uint64]*ConfigHead
	forged    *ConfigHead
	ladderKey *EvsRepoKey
	reads     []uint64
}

func (self *recoverTestHeads) ReadRecoveryHead(ctx context.Context, key *EvsRepoKey, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, func(generation uint64) *EvsRepoKey, error) {
	self.reads = append(self.reads, configVersion)
	if !bytes.Equal(configHeadSha256, testConfigHeadSha256(configVersion)) {
		return nil, nil, fmt.Errorf("%w: the ref's chain at %d is another", ErrConfigHeadMismatch, configVersion)
	}
	keyAt := func(generation uint64) *EvsRepoKey {
		if self.ladderKey != nil {
			return self.ladderKey
		}
		if generation == key.Generation() {
			return key
		}
		return nil
	}
	if self.forged != nil {
		return self.forged, keyAt, nil
	}
	head := self.heads[configVersion]
	if head == nil {
		return nil, nil, fmt.Errorf("%w: version %d not pushed", ErrConfigHeadUnavailable, configVersion)
	}
	configKey := self.world.configKey
	if key == nil || key.Generation() != configKey.Generation() || !bytes.Equal(key.repoKey, configKey.repoKey) {
		return nil, nil, fmt.Errorf("%w: the head does not open under this key", ErrGkmAuthentication)
	}
	return head, keyAt, nil
}

// The recovering device's world: a test network whose log the test drives, member M with a consented laptop and a
// recovery code that laptop bound with a real sealed body, and the device recovering by that code, enrolled as M's
// client and unadmitted, with the world's authority, api, recovery client and head reader.
type recoverTestWorld struct {
	t         *testing.T
	ctx       context.Context
	net       *testConfigNet
	memberId  Id
	laptop    testConfigDevice
	words     string
	configKey *EvsRepoKey
	byJwt     string
	// at k = 2, the admin's device that cosigns M's binding, nil for none
	cosigner *testConfigDevice

	instance  *SidecarInstance
	clock     *identityTestClock
	sidecar   *Sidecar
	selfId    Id
	events    *alarmTestEvents
	authority *recoverTestAuthority
	api       *recoverTestApi
	groups    *recoverTestGroups
	heads     *recoverTestHeads
}

// The world on net: M is net's owner when owner is set, a personal network's member or, with a cosigner, an AdminSet
// member at k = 2 whose binding that admin's device cosigns; else a member outside the AdminSet. Its code is bound
// over net's own genesis, and the device enrolled.
func newRecoverTestWorldOn(t *testing.T, net *testConfigNet, owner bool, cosigner *testConfigDevice) *recoverTestWorld {
	t.Helper()
	world := &recoverTestWorld{t: t, ctx: context.Background(), net: net, configKey: testConfigSealKey(1), cosigner: cosigner}
	if owner {
		world.memberId, world.laptop = net.ownerMemberId, net.owner
	} else {
		world.memberId, world.laptop = net.consentedMember("m")
	}
	world.words = recoverTestWords(t, 0x40)
	genesisSha256 := sha256.Sum256(net.signedGenesis)
	world.bind(world.words, genesisSha256[:])
	world.authority = &recoverTestAuthority{world: world}
	world.api = &recoverTestApi{world: world, landed: map[[sha256.Size]byte]*bridge.AuthPin{}}
	world.groups = &recoverTestGroups{world: world, key: world.configKey}
	world.heads = &recoverTestHeads{world: world, heads: map[uint64]*ConfigHead{}}
	head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	world.heads.heads[1] = head
	world.startDevice()
	return world
}

func newRecoverTestWorld(t *testing.T, owner bool) *recoverTestWorld {
	return newRecoverTestWorldOn(t, newTestConfigNet(t), owner, nil)
}

// Binds the words' code to M by M's laptop: a RecoveryBind where M has no binding, else a RecoveryRebind of the
// binding in effect, its body sealed under the config key with a genesis_sig over genesisSha256.
func (self *recoverTestWorld) bind(words string, genesisSha256 []byte) {
	self.bindBy(self.laptop, words, genesisSha256)
}

func (self *recoverTestWorld) bindBy(signer testConfigDevice, words string, genesisSha256 []byte) {
	t := self.t
	t.Helper()
	keys := recoverTestKeys(t, words)
	defer keys.Erase()
	genesisSig, err := keys.SignGenesis(self.net.networkId, genesisSha256)
	if err != nil {
		t.Fatal(err)
	}
	body := &protocol.RecoveryBindBody{XwingPublicKey: keys.XwingPublicKey(), Ed25519PublicKey: keys.Ed25519PublicKey(), GenesisSig: genesisSig}
	header := self.net.header()
	current := self.net.log.State().Member(self.memberId).GetRecoveryKeySha256()
	if len(current) == 0 {
		sealed, err := SealConfigBody(self.configKey, NewConfigSealContext(bridge.SignedType_SIGNED_RECOVERY_BIND, header), body, nil)
		if err != nil {
			t.Fatal(err)
		}
		self.post(signer, bridge.SignedType_SIGNED_RECOVERY_BIND, &protocol.RecoveryBind{
			Header: header, MemberId: self.memberId.Bytes(), Ed25519PublicKeySha256: keys.KeySha256(), SealedBody: sealed,
		})
		return
	}
	sealed, err := SealConfigBody(self.configKey, NewConfigSealContext(bridge.SignedType_SIGNED_RECOVERY_REBIND, header), body, nil)
	if err != nil {
		t.Fatal(err)
	}
	self.post(signer, bridge.SignedType_SIGNED_RECOVERY_REBIND, &protocol.RecoveryRebind{
		Header: header, MemberId: self.memberId.Bytes(), PrevSha256: bytes.Clone(current), Ed25519PublicKeySha256: keys.KeySha256(),
		Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE, SealedBody: sealed,
	})
}

// Posts a binding by signer, failing the test unless it takes effect: on its own, or with a cosigner as an
// AuthorityProposal that cosigner's device completes.
func (self *recoverTestWorld) post(signer testConfigDevice, signedType bridge.SignedType, body proto.Message) {
	self.t.Helper()
	if self.cosigner == nil || signer.sidecarId != self.laptop.sidecarId {
		self.net.mustPost(signer, signedType, body)
		return
	}
	proposed, proposalId := self.net.propose(signer, signedType, body)
	if !proposed.Accepted() {
		self.t.Fatalf("the binding's proposal: %v", proposed.Refusal)
	}
	if completed := self.net.cosign(*self.cosigner, proposalId); !completed.Accepted() || len(completed.CompletedProposalId) == 0 {
		self.t.Fatalf("the binding's cosign: %v", completed.Refusal)
	}
}

// Enrolls the recovering device as a client of M: an identity in the network and a token naming M, unadmitted.
func (self *recoverTestWorld) startDevice() {
	t := self.t
	t.Helper()
	instance, secrets := newIdentityTestSecrets(t, self.net.networkId)
	self.instance = instance
	identityKeys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer identityKeys.erase()
	binding := &SidecarIdentityBinding{
		NetworkId:  self.net.networkId,
		SidecarId:  testConfigId("recovering device"),
		ClientId:   testConfigId("recovering client"),
		Generation: 1,
		IssuedAt:   time.UnixMilli(self.net.timeMs),
	}
	signedBinding, err := NewSidecarIdentityBinding(binding, identityKeys.identitySeed, identityKeys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, identityKeys, signedBinding); err != nil {
		t.Fatal(err)
	}
	self.byJwt = testClientJwt(fmt.Sprintf(`{"network_id":%q,"client_id":%q,"user_id":%q}`, self.net.networkId, binding.ClientId, self.memberId))
	if err := persistSidecarByJwt(secrets, self.byJwt); err != nil {
		t.Fatal(err)
	}
	self.clock = &identityTestClock{current: time.UnixMilli(self.net.timeMs)}
	self.restart()
}

// A Sidecar over the device's keychain, as a restart builds one: nothing but the keychain kept, the world's seams
// installed again.
func (self *recoverTestWorld) restart() {
	t := self.t
	t.Helper()
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	sidecar.instance = self.instance
	sidecar.clock = self.clock
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled}) {
		t.Fatal("no move to unenrolled")
	}
	if err := sidecar.adoptIdentity(self.instance.secrets(self.net.networkId, sidecarCoreSecretsNamespace)); err != nil {
		t.Fatal(err)
	}
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1}) {
		t.Fatal("no move to offline")
	}
	networkId := self.net.networkId
	sidecar.networkId = &networkId
	api, err := newSidecarApi(sidecar.settings, self.api, self.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(self.byJwt)
	sidecar.sidecarApi = api
	self.sidecar = sidecar
	self.selfId = sidecar.currentIdentity().SidecarId
	self.events = &alarmTestEvents{}
	t.Cleanup(sidecar.AddEventCallback(self.events.add))
	t.Cleanup(sidecar.InstallAuthority(self.authority))
	t.Cleanup(sidecar.InstallRecovery(&SidecarRecoveryArgs{Groups: self.groups, Heads: self.heads}))
}

// RecoverWithCode with the world's words, as the person types them again.
func (self *recoverTestWorld) recover() (*SidecarRecovery, error) {
	return self.sidecar.RecoverWithCode(self.ctx, recoverTestCode(self.t, self.words), SidecarActConfirmed)
}

// recover, failing the test on an error or another phase.
func (self *recoverTestWorld) mustRecover(phase SidecarRecoveryPhase) *SidecarRecovery {
	self.t.Helper()
	result, err := self.recover()
	if err != nil {
		self.t.Fatalf("a recovery: %v", err)
	}
	if result.Phase != phase {
		self.t.Fatalf("a recovery at %s, not %s: %+v", result.Phase, phase, result)
	}
	return result
}

// Moves the net's entry clock and the device's clock on together.
func (self *recoverTestWorld) wait(ms int64) {
	self.net.wait(ms)
	self.clock.advance(time.Duration(ms) * time.Millisecond)
}

// Turns self_admit off in a base folding the log to its tip.
func (self *recoverTestWorld) selfAdmitOff() {
	self.t.Helper()
	self.net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF}
	self.foldTo(2)
}

// A base at configVersion folding the log through its tip, and the head it names, which holds the genesis and a
// record of every entry through the fold, as a config writer saves it.
func (self *recoverTestWorld) foldTo(configVersion uint64) {
	t := self.t
	t.Helper()
	through := self.net.n
	records, ok := self.net.log.foldedRecords(1, through)
	if !ok {
		t.Fatal("the net does not keep every entry")
	}
	head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: self.net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	if head, err = head.WithFold(records, through); err != nil {
		t.Fatal(err)
	}
	if settings := self.net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))]; settings != nil {
		signedSettings := self.net.sign(self.net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
		if head, err = head.WithFile(ConfigHeadServiceSettingsPath, signedSettings); err != nil {
			t.Fatal(err)
		}
	}
	self.heads.heads[configVersion] = head
	if verdict := self.net.fold(self.net.owner, through, configVersion); !verdict.Accepted() {
		t.Fatalf("the fold at %d: %v", configVersion, verdict.Refusal)
	}
}

// The device's admission row, nil while none.
func (self *recoverTestWorld) row() *bridge.SidecarRow {
	return self.net.log.State().SidecarRow(self.selfId)
}

// What Sign answers for each type while the gate is up: a statement, an MLS credential, a rotation, a push, a ReaderKey,
// this device's sign-out and another's revocation. nil for a type it signed.
func (self *recoverTestWorld) signs() map[string]error {
	sidecar := self.sidecar
	identity := sidecar.currentIdentity()
	ownSignOut := testConfigMarshal(self.t, &bridge.SidecarRevoke{SidecarId: identity.SidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED})
	otherRevoke := testConfigMarshal(self.t, &bridge.SidecarRevoke{SidecarId: self.laptop.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST})
	answers := map[string]error{}
	sign := func(name string, signedType bridge.SignedType, body []byte) {
		purpose, _ := sidecarIdentitySignedPurpose(signedType)
		_, err := sidecar.Sign(purpose, signedType, body, nil)
		answers[name] = err
	}
	sign("owner confirm", bridge.SignedType_SIGNED_OWNER_CONFIRM, []byte("a statement"))
	sign("mls credential", bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, []byte("a credential"))
	sign("gen rotate", bridge.SignedType_SIGNED_GEN_ROTATE, []byte("a rotation"))
	sign("evs push", bridge.SignedType_SIGNED_EVS_PUSH, []byte("a push"))
	sign("reader wrap", bridge.SignedType_SIGNED_READER_WRAP, []byte("a wrap"))
	sign("reader key", bridge.SignedType_SIGNED_READER_KEY, []byte("a reader key"))
	sign("own sign-out", bridge.SignedType_SIGNED_SIDECAR_REVOKE, ownSignOut)
	sign("another's revocation", bridge.SignedType_SIGNED_SIDECAR_REVOKE, otherRevoke)
	return answers
}

// Fails the test unless Sign signed exactly the types named.
func (self *recoverTestWorld) expectSigns(context string, signed ...string) {
	self.t.Helper()
	for name, err := range self.signs() {
		switch {
		case slices.Contains(signed, name) && err != nil:
			self.t.Errorf("%s: %s refused: %v", context, name, err)
		case !slices.Contains(signed, name) && !errors.Is(err, ErrSidecarRecoveryUnanchored):
			self.t.Errorf("%s: %s: %v", context, name, err)
		}
	}
}

// §22.7's admission row: until it is admitted a code-only device reads only the log and its member's recovery wraps,
// and signs one statement, its admission by the code's key; it asks api for nothing but that post and gkm for nothing
// but the wraps under recovery:<member_id>, and its identity key signs only its ReaderKey and its own sign-out. Once
// an admin's cosign admits it, the next call anchors and only then runs KEYS-M2-24's pass.
func TestUntilAdmittedACodeOnlyDeviceReadsOnlyTheLogAndItsWraps(t *testing.T) {
	world := newRecoverTestWorld(t, false)
	world.selfAdmitOff()
	result := world.mustRecover(SidecarRecoveryPending)
	if !result.Proposal || result.ProposalKind != bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED || result.Entry == nil ||
		!strings.Contains(result.Waiting, "cosign") || result.MemberId != world.memberId {
		t.Fatalf("the filing: %+v", result)
	}
	if routes := world.api.routesSoFar(); !slices.Equal(routes, []string{"POST /network/config/delta"}) {
		t.Errorf("an unadmitted device asked api for %v", routes)
	}
	if !slices.Equal(world.groups.calls, []string{"fetch admitted=false"}) {
		t.Errorf("an unadmitted device asked gkm for %v", world.groups.calls)
	}
	if len(world.heads.reads) != 0 {
		t.Errorf("an unadmitted device read a config head")
	}
	// the one statement: the code's key proposing this device, as M
	posts := world.api.postsSoFar(t)
	keys := recoverTestKeys(t, world.words)
	defer keys.Erase()
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL ||
		!bytes.Equal(posts[0].GetSignerId(), world.memberId.Bytes()) || !bytes.Equal(posts[0].GetKeyId(), keys.Ed25519PublicKey()) {
		t.Fatalf("the posts: %+v", posts)
	}
	statementId := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, posts[0].GetBody())
	if !bytes.Equal(result.StatementId, statementId[:]) {
		t.Errorf("the result names another statement")
	}
	world.expectSigns("before admission", "reader key", "own sign-out")
	if !world.sidecar.RecoveryAwaitingAnchor() {
		t.Error("an unadmitted recovery awaits no anchor")
	}
	if kept, err := world.sidecar.Recovery(); err != nil || kept.Phase != SidecarRecoveryPending || !bytes.Equal(kept.StatementId, statementId[:]) {
		t.Errorf("the kept recovery: %+v %v", kept, err)
	}

	// an admin's cosign admits it; the next call anchors on the config group's key, then runs the pass
	if completed := world.net.cosign(world.net.owner, result.StatementId); !completed.Accepted() || world.row() == nil {
		t.Fatalf("the admin's cosign: %v", completed.Refusal)
	}
	world.expectSigns("admitted, before the anchor", "reader key", "own sign-out")
	world.groups.repos = []*GkmRecoveryRepo{{RepoId: testConfigId("config repo"), Generation: 1, SelfJoined: true, Leaf: true}}
	recovered := world.mustRecover(SidecarRecoveryAnchored)
	if !recovered.OfferRotate || len(recovered.Repos) != 1 || !slices.Equal(world.groups.calls, []string{"fetch admitted=false", "anchor", "run"}) {
		t.Fatalf("the recovery once admitted: %+v, calls %v", recovered, world.groups.calls)
	}
	if len(world.groups.anchorErrs) != 1 || world.groups.anchorErrs[0] != nil || !slices.Equal(world.heads.reads, []uint64{2}) {
		t.Fatalf("the anchor: %v, heads read %v", world.groups.anchorErrs, world.heads.reads)
	}
	world.expectSigns("anchored", "owner confirm", "mls credential", "gen rotate", "evs push", "reader wrap", "reader key", "own sign-out", "another's revocation")
	if world.sidecar.RecoveryAwaitingAnchor() {
		t.Error("an anchored recovery still awaits its anchor")
	}
	if posts := world.api.postsSoFar(t); len(posts) != 1 {
		t.Errorf("%d posts", len(posts))
	}
}

// §7.9's table, outside the AdminSet with self_admit on: the code's key admits the device plainly, at its position,
// which the same call sees, anchors on and recovers from: the fetch before the admission, the anchor before the pass,
// one post and one head read.
func TestARecoveryAdmitsPlainlyOutsideTheAdminSetWithSelfAdmitOn(t *testing.T) {
	world := newRecoverTestWorld(t, false)
	result := world.mustRecover(SidecarRecoveryAnchored)
	if result.Proposal || result.Entry == nil || !result.OfferRotate {
		t.Fatalf("the recovery: %+v", result)
	}
	keys := recoverTestKeys(t, world.words)
	defer keys.Erase()
	row := world.row()
	if row == nil || row.GetAdmittedAt() != result.Entry.GetVersion() || len(row.GetAdmissionSigners()) != 1 ||
		!bytes.Equal(row.GetAdmissionSigners()[0], keys.KeySha256()) || !bytes.Equal(row.GetMemberId(), world.memberId.Bytes()) {
		t.Fatalf("the admission: %v", row)
	}
	posts := world.api.postsSoFar(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_ADMIT || !bytes.Equal(posts[0].GetKeyId(), keys.Ed25519PublicKey()) {
		t.Fatalf("the posts: %+v", posts)
	}
	if !slices.Equal(world.groups.calls, []string{"fetch admitted=false", "anchor", "run"}) || !slices.Equal(world.heads.reads, []uint64{1}) {
		t.Fatalf("calls %v, heads read %v", world.groups.calls, world.heads.reads)
	}
	// a second call files nothing and anchors no more: the pass runs again as the log moves
	again := world.mustRecover(SidecarRecoveryAnchored)
	if len(world.api.postsSoFar(t)) != 1 || !slices.Equal(world.groups.calls, []string{"fetch admitted=false", "anchor", "run", "run"}) || again.Entry != nil {
		t.Errorf("a second call: %+v, calls %v", again, world.groups.calls)
	}
}

// §7.9's table, the rows that propose: a personal network's owner (k = 1) and an AdminSet member at k = 2 propose and
// wait out the window, the second also for a counted cosign; the device is admitted only at the activating tick, which
// the call after it anchors on.
func TestARecoveryProposesInTheAdminSetAndWaitsOutTheWindow(t *testing.T) {
	for _, team := range []bool{false, true} {
		var net *testConfigNet
		var cosigner *testConfigDevice
		if team {
			configTeam := newTestConfigTeam(t)
			net, cosigner = configTeam.testConfigNet, &configTeam.adminB
		} else {
			net = newTestConfigNet(t)
		}
		world := newRecoverTestWorldOn(t, net, true, cosigner)
		result := world.mustRecover(SidecarRecoveryPending)
		if !result.Proposal || result.ProposalKind != bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY {
			t.Fatalf("team %v: the filing: %+v", team, result)
		}
		proposalRow := world.authority.PendingProposal(result.StatementId)
		if proposalRow == nil || !result.ActivatesAfter.Equal(time.UnixMilli(proposalRow.GetWindowTimeMs()+DefaultConfigRecoverySettings().Window.Milliseconds())) {
			t.Fatalf("team %v: the window: %v, activates after %v", team, proposalRow, result.ActivatesAfter)
		}
		if team {
			if cosigned := net.cosign(*cosigner, result.StatementId); !cosigned.Accepted() {
				t.Fatalf("the counted cosign: %v", cosigned.Refusal)
			}
		}
		world.wait(71 * testConfigHourMs)
		if early := net.activate(result.StatementId); early.Accepted() {
			t.Fatalf("team %v: an activation before the window ran", team)
		}
		world.mustRecover(SidecarRecoveryPending)
		world.wait(testConfigHourMs)
		if activated := net.activate(result.StatementId); !activated.Accepted() || world.row() == nil {
			t.Fatalf("team %v: the activation: %v", team, activated.Refusal)
		}
		world.mustRecover(SidecarRecoveryAnchored)
		if !slices.Equal(world.groups.calls, []string{"fetch admitted=false", "anchor", "run"}) {
			t.Errorf("team %v: calls %v", team, world.groups.calls)
		}
		if posts := world.api.postsSoFar(t); len(posts) != 1 {
			t.Errorf("team %v: %d posts", team, len(posts))
		}
	}
}

// FS-16's forged genesis: a server serves the device a log of its own, on another genesis for the same network id,
// that binds M to the code's real key and admits the device, and a RecoveryWrap of its own that opens that log's head,
// even carrying the real network's genesis_sig. The anchor fails: head_alarm (fork) with that base's AuthPin, the
// record kept stopped, no pass run, nothing more signed, now or after a restart. A forged head claiming the real
// genesis over the forged log fails too.
func TestForgedGenesisRaisesForkAndStops(t *testing.T) {
	for _, claimsRealGenesis := range []bool{false, true} {
		real := newTestConfigNet(t)
		forgedNet := newRecoverTestNetOwnedBy(t, "forger's device")
		if bytes.Equal(real.signedGenesis, forgedNet.signedGenesis) {
			t.Fatal("the forged genesis is the real one")
		}
		world := newRecoverTestWorldOn(t, forgedNet, false, nil)
		// the binding in the forged log carries the real network's genesis_sig
		realGenesisSha256 := sha256.Sum256(real.signedGenesis)
		world.words = recoverTestWords(t, 0x60)
		world.bind(world.words, realGenesisSha256[:])
		if claimsRealGenesis {
			forgedHead, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: real.signedGenesis})
			if err != nil {
				t.Fatal(err)
			}
			world.heads.forged = forgedHead
		}

		result, err := world.recover()
		if !errors.Is(err, ErrSidecarRecoveryStopped) || !errors.Is(err, ErrGkmRecoveryAnchor) || result == nil || result.Phase != SidecarRecoveryStopped {
			t.Fatalf("real genesis claimed %v: a forged genesis: %+v %v", claimsRealGenesis, result, err)
		}
		if world.row() == nil {
			t.Fatal("the forged log did not admit the device")
		}
		alarms := world.events.of(SidecarEventHeadAlarm)
		basePin := world.net.log.State().Base()
		wantPin := configPinBytes(&bridge.AuthPin{Version: basePin.GetVersion(), Chain: bytes.Clone(world.net.log.State().base.chain[:])})
		if len(alarms) != 1 || alarms[0].HeadAlarm != SidecarHeadAlarmFork || !bytes.Equal(alarms[0].Evidence[0], wantPin) {
			t.Fatalf("real genesis claimed %v: the alarms: %+v", claimsRealGenesis, alarms)
		}
		if !slices.Equal(world.groups.calls, []string{"fetch admitted=false", "anchor"}) {
			t.Errorf("real genesis claimed %v: calls %v", claimsRealGenesis, world.groups.calls)
		}
		world.expectSigns("stopped", "own sign-out")
		// it acts no further, now or after a restart, and alarms no more
		if _, err := world.recover(); !errors.Is(err, ErrSidecarRecoveryStopped) || len(world.groups.calls) != 2 {
			t.Errorf("a call after the stop: %v, calls %v", err, world.groups.calls)
		}
		world.restart()
		if _, err := world.recover(); !errors.Is(err, ErrSidecarRecoveryStopped) || len(world.groups.calls) != 2 {
			t.Errorf("a call after a restart: %v, calls %v", err, world.groups.calls)
		}
		world.expectSigns("stopped, restarted", "own sign-out")
		if len(world.events.of(SidecarEventHeadAlarm)) != 0 {
			t.Error("a restarted stop alarmed again")
		}
		if kept, err := world.sidecar.Recovery(); err != nil || kept.Phase != SidecarRecoveryStopped {
			t.Errorf("the kept recovery: %+v %v", kept, err)
		}
	}
}

// §22.7's forged RecoveryWrap: one a server sealed to M's public recovery key, under a generation whose C_g it chose,
// gives the anchor a key that is not the config group's. Whether the real head does not open under it, a forged head
// opens that does not chain to the verified log, or the real head's records are served with the forged key behind
// them, so the binding's body opens to nothing, the anchor fails with head_alarm and the device stops.
func TestForgedRecoveryWrapStops(t *testing.T) {
	forgedKey := &EvsRepoKey{repoId: testConfigId("config repo"), generation: 1, repoKey: bytes.Repeat([]byte{0xee}, gkmRepoKeyByteCount)}
	for _, served := range []string{"the real head, which does not open", "a forged head", "the real head over the forged key"} {
		world := newRecoverTestWorld(t, false)
		world.groups.key = forgedKey
		switch served {
		case "a forged head":
			forged, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: world.net.signedGenesis})
			if err != nil {
				t.Fatal(err)
			}
			// a record the verified log does not hold
			if forged, err = forged.WithFold([]ConfigFoldRecord{{Id: bytes.Repeat([]byte{1}, 32), N: 1, TimeMs: testConfigStartMs, Kind: bridge.AuthEntryKindStatement, Body: []byte("a forged record")}}, 1); err != nil {
				t.Fatal(err)
			}
			world.heads.forged = forged
		case "the real head over the forged key":
			world.heads.forged = world.heads.heads[1]
			world.heads.ladderKey = forgedKey
		}
		result, err := world.recover()
		if !errors.Is(err, ErrSidecarRecoveryStopped) || result.Phase != SidecarRecoveryStopped {
			t.Fatalf("%s: %+v %v", served, result, err)
		}
		if alarms := world.events.of(SidecarEventHeadAlarm); len(alarms) != 1 || alarms[0].HeadAlarm != SidecarHeadAlarmFork {
			t.Errorf("%s: the alarms: %+v", served, alarms)
		}
		if slices.Contains(world.groups.calls, "run") {
			t.Errorf("%s: the pass ran", served)
		}
		world.expectSigns(served, "own sign-out")
	}
}

// §7.9's restored order: under a binding a void restored, the code's key files only an AuthorityProposal, fetches no
// wrap and activates through the window. Admitted, the device uploads its ReaderKey and no KeyPackage, both by the
// upkeep's role and by Sign's gate, and waits for a config writer's ReaderWrap; on it the anchor passes, and only then
// do KeyPackages go up.
func TestRestoredBindingUploadsNoKeyPackageBeforeAnchor(t *testing.T) {
	world := newRecoverTestWorld(t, false)
	net := world.net
	// a stolen device rebinds M to another code, and a compromise revocation of it voids that binding, restoring the
	// world's code's
	stolen := net.device("m stolen", world.memberId)
	net.admitDevice(world.laptop, stolen, 0)
	sinceN := net.n + 1
	genesisSha256 := sha256.Sum256(net.signedGenesis)
	world.bindBy(stolen, recoverTestWords(t, 0x70), genesisSha256[:])
	net.mustPost(world.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(stolen, sinceN))
	keys := recoverTestKeys(t, world.words)
	if !net.log.State().BindingRestored(world.memberId) || !bytes.Equal(net.log.State().Member(world.memberId).GetRecoveryKeySha256(), keys.KeySha256()) {
		t.Fatal("the void did not restore the world's code")
	}
	keys.Erase()
	world.groups.key = nil

	result := world.mustRecover(SidecarRecoveryPending)
	if !result.Proposal || !result.Restored || result.ProposalKind != bridge.ProposalKind_PROPOSAL_KIND_RESTORED || result.ActivatesAfter.IsZero() {
		t.Fatalf("the filing: %+v", result)
	}
	if len(world.groups.calls) != 0 {
		t.Errorf("a restored binding asked gkm for %v", world.groups.calls)
	}
	world.wait(72 * testConfigHourMs)
	if activated := net.activate(result.StatementId); !activated.Accepted() || world.row() == nil {
		t.Fatalf("the activation: %v", activated.Refusal)
	}
	waiting := world.mustRecover(SidecarRecoveryAdmitted)
	if !strings.Contains(waiting.Waiting, "ReaderWrap") || !slices.Equal(world.groups.calls, []string{"anchor"}) {
		t.Fatalf("admitted with no ReaderWrap: %+v, calls %v", waiting, world.groups.calls)
	}

	// upkeep, admitted and not anchored: its ReaderKey goes up, its KeyPackages wait; a host that read the role wrong
	// still makes none, since no MLS credential is signed
	upkeepApi := &gkmTestUpkeepApi{}
	upkeepArgs, err := world.sidecar.GkmUpkeepArgs(upkeepApi, nil)
	if err != nil {
		t.Fatal(err)
	}
	upkeepArgs.Role = func() GkmUpkeepRole {
		return GkmUpkeepRole{MemberDevice: true, AwaitingAnchor: world.sidecar.RecoveryAwaitingAnchor()}
	}
	created := 0
	upkeepArgs.CreateKeyPackage = func(lastResort bool) (*MlsKeyPackage, error) {
		if _, err := world.sidecar.Sign("mls-credential", bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, []byte("a credential"), nil); err != nil {
			return nil, err
		}
		created += 1
		return &MlsKeyPackage{Encoded: []byte{byte(created)}, LastResort: lastResort}, nil
	}
	upkeep, err := newGkmUpkeep(world.ctx, upkeepArgs)
	if err != nil {
		t.Fatal(err)
	}
	upkeep.pass(world.ctx)
	if len(upkeepApi.readerKeys) != 1 || len(upkeepApi.keyPackageUploads) != 0 || created != 0 {
		t.Fatalf("before the anchor: %d ReaderKeys, %d KeyPackage uploads", len(upkeepApi.readerKeys), len(upkeepApi.keyPackageUploads))
	}
	lying := *upkeepArgs
	lying.Role = func() GkmUpkeepRole { return GkmUpkeepRole{MemberDevice: true} }
	lyingUpkeep, err := newGkmUpkeep(world.ctx, &lying)
	if err != nil {
		t.Fatal(err)
	}
	lyingUpkeep.pass(world.ctx)
	if len(upkeepApi.keyPackageUploads) != 0 || created != 0 {
		t.Fatalf("a role that ignores the anchor uploaded %d KeyPackage sets", len(upkeepApi.keyPackageUploads))
	}

	// a config writer's late ReaderWrap gives the device the config group's key: the anchor passes, then KeyPackages
	world.groups.key = world.configKey
	world.mustRecover(SidecarRecoveryAnchored)
	if !slices.Equal(world.groups.calls, []string{"anchor", "anchor", "run"}) {
		t.Errorf("calls %v", world.groups.calls)
	}
	upkeep.pass(world.ctx)
	if len(upkeepApi.keyPackageUploads) == 0 || created == 0 {
		t.Error("no KeyPackage went up once anchored")
	}
}

// §7.9's restart row: the device keeps its identity, sidecar_id and the statement's id, and a restart resumes the
// admission it filed. A post whose answer was lost goes again with the same bytes, which api answers with the entry it
// holds, so the log carries it once; a call after the restart files nothing new, refuses another code, and anchors
// once the window activates the proposal.
func TestRestartResumesProposal(t *testing.T) {
	world := newRecoverTestWorld(t, true)
	world.api.answers = []string{"lost"}
	result := world.mustRecover(SidecarRecoveryPending)
	if result.Entry != nil || !result.Proposal {
		t.Fatalf("a lost answer: %+v", result)
	}
	tip := world.net.n
	posts := world.api.postsSoFar(t)
	if len(posts) != 1 {
		t.Fatalf("%d posts", len(posts))
	}
	statementId := result.StatementId

	world.restart()
	resumed := world.mustRecover(SidecarRecoveryPending)
	if !bytes.Equal(resumed.StatementId, statementId) || world.net.n != tip {
		t.Fatalf("the resumed recovery: %+v, the log at %d from %d", resumed, world.net.n, tip)
	}
	reposted := world.api.postsSoFar(t)
	if len(reposted) != 2 || !proto.Equal(reposted[0], reposted[1]) {
		t.Fatalf("the repost is not the same bytes: %d posts", len(reposted))
	}
	// nothing more goes once it has landed, and another code is refused
	world.restart()
	world.mustRecover(SidecarRecoveryPending)
	if len(world.api.postsSoFar(t)) != 2 {
		t.Errorf("a landed statement went again")
	}
	if _, err := world.sidecar.RecoverWithCode(world.ctx, recoverTestCode(t, recoverTestWords(t, 0x11)), SidecarActConfirmed); !errors.Is(err, ErrSidecarRecoveryOtherCode) {
		t.Errorf("another code: %v", err)
	}

	world.wait(72 * testConfigHourMs)
	if activated := world.net.activate(statementId); !activated.Accepted() {
		t.Fatalf("the activation: %v", activated.Refusal)
	}
	world.restart()
	world.mustRecover(SidecarRecoveryAnchored)
	if !slices.Equal(world.groups.calls, []string{"fetch admitted=false", "anchor", "run"}) {
		t.Errorf("calls %v", world.groups.calls)
	}
}

// What a recovery refuses keeps nothing: no statement, no record, no gate. Origins other than the person's
// confirmation; a code that is not M's binding in effect, another member's or one a rebind retired; a device admitted
// already by its member's laptop; no authority, no recovery seams, no judge; and api's refusal at the tip.
func TestRecoveryRefusalsKeepNothing(t *testing.T) {
	keepsNothing := func(world *recoverTestWorld, context string) {
		t.Helper()
		if kept, err := world.sidecar.Recovery(); err != nil || kept != nil {
			t.Errorf("%s: a record: %+v %v", context, kept, err)
		}
		if pending, err := world.sidecar.pendingStatements(); err != nil || len(pending) != 0 {
			t.Errorf("%s: %d statements pending: %v", context, len(pending), err)
		}
		if world.sidecar.RecoveryAwaitingAnchor() {
			t.Errorf("%s: the gate is up", context)
		}
	}

	world := newRecoverTestWorld(t, false)
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := world.sidecar.RecoverWithCode(world.ctx, recoverTestCode(t, world.words), origin); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	keepsNothing(world, "a mode")
	if _, err := world.sidecar.RecoverWithCode(world.ctx, recoverTestCode(t, recoverTestWords(t, 0x11)), SidecarActConfirmed); !errors.Is(err, ErrSidecarRecoveryUnbound) {
		t.Errorf("an unbound code: %v", err)
	}
	keepsNothing(world, "an unbound code")
	genesisSha256 := sha256.Sum256(world.net.signedGenesis)
	retired := world.words
	world.words = recoverTestWords(t, 0x22)
	world.bind(world.words, genesisSha256[:])
	if _, err := world.sidecar.RecoverWithCode(world.ctx, recoverTestCode(t, retired), SidecarActConfirmed); !errors.Is(err, ErrSidecarRecoveryUnbound) {
		t.Errorf("a retired code: %v", err)
	}
	keepsNothing(world, "a retired code")
	world.api.answers = []string{"ok"}
	func() {
		removeRecovery := world.sidecar.InstallRecovery(nil)
		defer world.sidecar.InstallRecovery(&SidecarRecoveryArgs{Groups: world.groups, Heads: world.heads})
		removeRecovery()
		if _, err := world.recover(); !errors.Is(err, ErrSidecarRecoveryUnavailable) {
			t.Errorf("no recovery seams: %v", err)
		}
	}()
	keepsNothing(world, "no seams")
	if len(world.api.postsSoFar(t)) != 0 {
		t.Errorf("a refused recovery posted")
	}

	// api refuses the statement at the tip: nothing is kept
	refused := newRecoverTestWorld(t, false)
	refused.net.mustPost(refused.net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: refused.net.header(), MemberId: refused.memberId.Bytes()})
	if _, err := refused.recover(); err == nil {
		t.Errorf("a removed member's code recovered")
	}
	keepsNothing(refused, "a removed member")

	// a device its member's laptop admitted needs no code
	admitted := newRecoverTestWorld(t, false)
	identity := admitted.sidecar.currentIdentity()
	admitted.net.mustPost(admitted.laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header: admitted.net.header(), NetworkId: admitted.net.networkId.Bytes(), SidecarId: identity.SidecarId.Bytes(),
		IdentityPublicKey: identity.IdentityPublicKey, IdentityAlg: configIdentityAlgEd25519, MemberId: admitted.memberId.Bytes(),
	})
	if _, err := admitted.recover(); !errors.Is(err, ErrSidecarRecoveryAdmitted) {
		t.Errorf("an admitted device: %v", err)
	}
	keepsNothing(admitted, "an admitted device")
}

// The anchor's own rows on a log with a fold, the binding a record of the head's: a head that chains passes; one
// missing a record, on another genesis or of another network fails; a sealed body under a generation the ladder does
// not reach, or a log that holds nothing the head's records reach, could not run, which stops nothing.
func TestTheAnchorChecksTheHeadAndTheBindingOnItsChain(t *testing.T) {
	world := newRecoverTestWorld(t, false)
	world.foldTo(2)
	keys := recoverTestKeys(t, world.words)
	defer keys.Erase()
	log, err := configRecoveryLog(world.net.log)
	if err != nil {
		t.Fatal(err)
	}
	keyAt := func(generation uint64) *EvsRepoKey {
		if generation == world.configKey.Generation() {
			return world.configKey
		}
		return nil
	}
	args := func(head *ConfigHead) *recoveryCodeAnchorArgs {
		return &recoveryCodeAnchorArgs{log: log, head: head, keyAt: keyAt, networkId: world.net.networkId, memberId: world.memberId, ed25519PublicKey: keys.Ed25519PublicKey()}
	}
	head := world.heads.heads[2]
	if err := checkRecoveryCodeAnchor(args(head)); err != nil {
		t.Fatalf("a head that chains: %v", err)
	}

	records, err := head.RecordsIn(0, head.FoldedThrough())
	if err != nil {
		t.Fatal(err)
	}
	short, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: world.net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	shortRecords := []ConfigFoldRecord{}
	for _, record := range records[:len(records)-1] {
		shortRecords = append(shortRecords, ConfigFoldRecord{Id: record.GetId(), N: record.GetN(), TimeMs: record.GetTimeMs(), Kind: record.GetKind(), Body: record.GetBody()})
	}
	if short, err = short.WithFold(shortRecords, head.FoldedThrough()); err != nil {
		t.Fatal(err)
	}
	otherGenesis, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: newRecoverTestNetOwnedBy(t, "another owner").signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	edited := func(head *ConfigHead, edit func(edited *recoveryCodeAnchorArgs)) *recoveryCodeAnchorArgs {
		anchorArgs := args(head)
		edit(anchorArgs)
		return anchorArgs
	}
	for name, failing := range map[string]*recoveryCodeAnchorArgs{
		"a head missing a record": args(short),
		"another genesis":         args(otherGenesis),
		"another network":         edited(head, func(edited *recoveryCodeAnchorArgs) { edited.networkId = testConfigId("another network") }),
		"another member":          edited(head, func(edited *recoveryCodeAnchorArgs) { edited.memberId = testConfigId("another member") }),
	} {
		if err := checkRecoveryCodeAnchor(failing); !errors.Is(err, ErrGkmRecoveryAnchor) {
			t.Errorf("%s: %v", name, err)
		}
	}
	trimmed := *log
	trimmed.HeldFrom = head.FoldedThrough() + 2
	for name, unrun := range map[string]*recoveryCodeAnchorArgs{
		"no ladder to the body's generation":     edited(head, func(edited *recoveryCodeAnchorArgs) { edited.keyAt = nil }),
		"no head":                                args(nil),
		"a log holding nothing the head reaches": edited(head, func(edited *recoveryCodeAnchorArgs) { edited.log = &trimmed }),
	} {
		if err := checkRecoveryCodeAnchor(unrun); err == nil || errors.Is(err, ErrGkmRecoveryAnchor) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ConfigAuthority answers the judge and the anchor's view from the client's verified log, as the helpers do: the
// device's own SidecarAdmit by M's laptop takes effect, a garbled one does not, and the view names the log's genesis,
// base and every entry it keeps.
func TestConfigAuthorityJudgesAndShowsTheAnchorItsLog(t *testing.T) {
	world := newRecoverTestWorld(t, false)
	client := &ConfigClient{clock: world.clock}
	client.configLog.Store(world.net.log)
	authority := client.Authority()
	identity := world.sidecar.currentIdentity()
	admit := world.net.sign(world.laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header: world.net.header(), NetworkId: world.net.networkId.Bytes(), SidecarId: identity.SidecarId.Bytes(),
		IdentityPublicKey: identity.IdentityPublicKey, IdentityAlg: configIdentityAlgEd25519, MemberId: world.memberId.Bytes(),
	})
	if err := authority.JudgeStatement(admit); err != nil {
		t.Errorf("the laptop's admission: %v", err)
	}
	if err := authority.JudgeStatement([]byte("not a statement")); err == nil {
		t.Error("a garbled statement takes effect")
	}
	log, err := authority.RecoveryLog()
	if err != nil {
		t.Fatal(err)
	}
	if log.GenesisChain != bridge.GenesisChain(world.net.signedGenesis) || log.ConfigRepoId != testConfigId("config repo") ||
		log.Base.GetVersion() != 1 || log.BasePin.GetVersion() != 1 || log.HeldFrom != 1 || uint64(len(log.Held)) != world.net.n ||
		log.HeldPrevChain != bridge.GenesisChain(world.net.signedGenesis) {
		t.Errorf("the view: %+v", log)
	}
	if (&ConfigAuthority{client: &ConfigClient{}}).JudgeStatement(admit) == nil {
		t.Error("a client with no log judged")
	}
}

// No device keeps the code: after a recovery anchored, neither the state directory's bytes nor any record of the core
// or gkm namespaces as it decrypts holds the code's entropy, its Ed25519 seed or its words, and the record holds the
// key's hash alone.
func TestRecoveryKeepsNoCode(t *testing.T) {
	world := newRecoverTestWorld(t, false)
	world.mustRecover(SidecarRecoveryAnchored)
	code := recoverTestCode(t, world.words)
	entropy := bytes.Clone(code.entropy[:])
	code.Erase()
	keys, err := deriveRecoveryKeys(entropy)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(world.words)
	needles := map[string][]byte{
		"the entropy":             entropy,
		"the Ed25519 seed":        keys.ed25519Key.Seed(),
		"the words":               []byte(world.words),
		"the first words":         []byte(strings.Join(words[:4], " ")),
		"the entropy in hex":      []byte(hex.EncodeToString(entropy)),
		"the Ed25519 seed in hex": []byte(hex.EncodeToString(keys.ed25519Key.Seed())),
	}
	scan := func(where string, content []byte) {
		for name, needle := range needles {
			if bytes.Contains(content, needle) {
				t.Errorf("%s holds %s", where, name)
			}
		}
	}
	for path, content := range backendSnapshot(t, world.instance.backend) {
		scan(path, content)
	}
	for _, namespace := range []string{sidecarCoreSecretsNamespace, gkmUpkeepSecretsNamespace} {
		secrets := world.instance.secrets(world.net.networkId, namespace)
		names, err := secrets.List("")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			content, err := secrets.Get(name)
			if err != nil {
				t.Fatal(err)
			}
			scan(namespace+"/"+name, content)
		}
	}
	record, err := loadSidecarRecoveryRecord(world.sidecar.currentCoreSecrets())
	if err != nil || record == nil || !bytes.Equal(record.KeySha256, keys.KeySha256()) || record.Phase != SidecarRecoveryAnchored {
		t.Errorf("the record: %+v %v", record, err)
	}
}
