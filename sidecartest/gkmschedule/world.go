package gkmschedule

// The world KEYS-M2-27's and KEYS-M2-28's schedules run in (§22.8's rules; C-18: one builder, a T2 and a T3 test):
// gkm's group client on the real MLS subset, never FakeMls, every device its own engine, identity key, keychain and
// store, against gkmservice's engine on a host whose stores the caller gives, the fake host's on T2, both reading one
// log of fixture states at its tip as a gate's state reads §8.9's cache. The repo, its group formed by KF1, and once
// ConfigWriters names some, the network's config repo, whose group CreateConfig forms the same way.
//
// What it models of §7.9 and §8.6: member devices of one member and tagged agents; each device's reading, writing and
// repo admin right, as the next position's rows hold them; a revocation as a tombstone that reads and writes nothing,
// with each repo it read shrinking there; read_only leaves; the member's recovery bindings, a RecoveryBind and each
// RecoveryRebind, newest first, a compromise one shrinking every repo the member reads, and a device the member's
// recovery key admits, unadmitted until AdmitRecovered; Delegations, with the agents they admit and cover, a Suspend
// dropping the Delegation's key, an Unsuspend, a DelegationRevoke ending it and a reap. What it leaves out:
// owner-bound kinds, cascades (CascadeVoids answers false) and the config and directory groups' leaves rule past
// their first 1,000 member devices.
//
// Interleavings are made at each device's transport, which holds a request while another device runs, loses an
// answer gkm gave, or fails a request before gkm takes it, and at gkm's store, whose writes BlobWrite may fail or lose
// the answer of, as a kill between two of gkm's writes does; nothing sleeps or depends on the scheduler. A device
// that is Offline takes no state, as one whose app is closed. Not safe for concurrent use: one schedule drives it, or
// fault's driver, whose actors run one at a time (sidecartest/fault's fs_keys.go).

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
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

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a schedule fails and ends through: the part of testing.TB the world calls, so a T2 or T3 test passes its own
// testing.TB, and fault's driver a failer that ends the step it runs in.
type FsKeysT interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
	Context() context.Context
	Cleanup(cleanup func())
}

var _ FsKeysT = (testing.TB)(nil)

// What a device's transport does with one request, and what BlobWrite does with one of gkm's store writes.
type FsKeysFault int

const (
	// Serves it.
	FsKeysFaultNone FsKeysFault = iota
	// Serves it and loses the answer, which the caller sees as a transport error: §22.8's unknown rule.
	FsKeysFaultDropAnswer
	// Fails it before it is taken, as a kill as it leaves does.
	FsKeysFaultFailBefore
)

// The error a lost or failed request answers its caller.
var errFsKeysTransport = errors.New("fs keys: the request's answer was lost")

// The error a lost or failed store write answers gkm.
var errFsKeysStore = errors.New("fs keys: the store write's answer was lost")

// One device's transport to the world's gkm engine, the one standing now, so a restarted engine takes the next
// request. Before, when set, sees each request first and says what becomes of it; it may run another device's flow
// before this request is served.
type FsKeysTransport struct {
	world  *FsKeysWorld
	Before func(request *http.Request) FsKeysFault
	// When set, answers in gkm's place where it returns an answer, as a lying or replaying server does; nil passes
	// the request on.
	Respond func(request *http.Request) *http.Response
}

func (self *FsKeysTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	fault := FsKeysFaultNone
	if self.Before != nil {
		fault = self.Before(request)
	}
	if self.Respond != nil {
		if response := self.Respond(request); response != nil {
			return response, nil
		}
	}
	if fault == FsKeysFaultFailBefore {
		return nil, errFsKeysTransport
	}
	recorder := httptest.NewRecorder()
	self.world.Engine.Handler().ServeHTTP(recorder, request)
	if fault == FsKeysFaultDropAnswer {
		return nil, errFsKeysTransport
	}
	return recorder.Result(), nil
}

// Whether path is gkm's claim of generation, POST /gkm/groups/<id>/gen/<generation>.
func FsKeysGenerationClaim(path string, generation uint64) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 6 && parts[1] == "gkm" && parts[2] == "groups" && parts[4] == "gen" && parts[5] == strconv.FormatUint(generation, 10)
}

// Whether a request commits an epoch, POST /gkm/groups/<id>/epochs/<n>.
func FsKeysEpochCommit(request *http.Request) bool {
	parts := strings.Split(request.URL.Path, "/")
	return request.Method == http.MethodPost && len(parts) == 6 && parts[2] == "groups" && parts[4] == "epochs"
}

// One device of the world.
type FsKeysDevice struct {
	Label  string
	world  *FsKeysWorld
	signer *sidecartest.FakeGkmSigner
	// its row as the next position holds it
	row             *bridge.SidecarRow
	admissionSha256 []byte
	// the ReaderKeys it signed, by the SHA-256 of their public key, and its current one's digest and Signed
	readerPrivateKeys map[string]hpke.PrivateKey
	readerKeySha256   []byte
	ReaderKey         *bridge.Signed
	// its keychain and its MLS engine's store, which survive a restart
	secrets *fsKeysKeychain
	store   *sidecartest.FakeStore
	// nil for an agent, which holds no leaf
	Mls       sidecar.MlsEngine
	Api       *sidecar.GkmApi
	Client    *sidecar.GkmGroupClient
	Transport *FsKeysTransport
	// takes no state while set
	Offline bool
	// the client its sidecar is now, which hints reach
	ClientId connect.Id
	// whether Publish has uploaded its first keys
	published bool
	// a device the member's recovery key admits stands in no state until AdmitRecovered
	unadmitted bool
	// the newest state it took, which its engine's credential check reads
	state  sidecar.GkmAuthView
	Alarms []*sidecar.GkmAlarm
}

// The device's sidecar.
func (self *FsKeysDevice) SidecarId() sidecar.Id {
	return self.signer.SidecarId
}

// Whether the device holds a leaf: a member device.
func (self *FsKeysDevice) member() bool {
	return len(self.row.GetTagIds()) == 0
}

// The world.
type FsKeysWorld struct {
	t         FsKeysT
	Ctx       context.Context
	Clock     *sidecartest.FakeClock
	Host      *sidecartest.FakeHost
	Engine    *gkmservice.GkmEngine
	Log       *sidecartest.FakeGkmAuthLog
	NetworkId connect.Id
	MemberId  sidecar.Id
	RepoId    sidecar.Id
	Kind      protocol.RepoKind
	// the repo's group, once KF1 formed it
	GroupId sidecar.Id
	Devices []*FsKeysDevice
	// processes that hold another device's identity key and keychain, which take states but stand in no row
	clones []*FsKeysDevice
	// what the next position holds
	readers        []sidecar.Id
	writers        []sidecar.Id
	admins         []sidecar.Id
	depositors     []sidecar.Id
	readerExpiries map[sidecar.Id]time.Time
	suspended      map[sidecar.Id]bool
	// the sidecars a rev/ object voids every token of (§7.8), which gkm reads before each request
	voided map[sidecar.Id]bool
	// the RepoCreate's signer, the repo's first admin, and the config's writers, whose config repo the world has only
	// once ConfigWriters names some
	creator       *sidecar.Id
	configWriters []sidecar.Id
	ConfigRepoId  sidecar.Id
	// the config repo's group, once CreateConfig formed it
	ConfigGroupId sidecar.Id
	// each repo's holders_shrunk_at, by repo
	shrunkAt map[sidecar.Id]uint64
	// the member's recovery bindings, newest first
	bindings []*FsKeysRecoveryBinding
	// every Delegation, in the order added
	delegations    []*FsKeysDelegation
	engineSettings *gkmservice.GkmServiceSettings
	// how many hint calls the host's push has taken, which a schedule waits on
	hintCount *sidecar.MonitorValue[int]
	// the reconciler's watch, once StartReconciler started one
	reconcilerChanged func(change *gkmservice.GkmStateChange)
	// how many positions gkm's state trails the log's tip: a gate cache that has not read the newest yet
	GkmBehind int
	// When set, sees each write gkm's engine sends its store, a PUT or a DELETE, and says what becomes of it, as a
	// kill between two of gkm's writes does. The world's own writes pass it too, so a schedule sets it only around
	// the engine's work it faults.
	BlobWrite func(op string, key string) FsKeysFault
	// every position Advance appended, by version - 1
	views []*sidecartest.FakeGkmAuthView
	// what the services' host takes in place of the fake host's own stores
	adjust func(host *sidecar.ServiceHost)
	// the barrier driver's Blocking, where the world runs on a fault schedule's Net
	blocking func(wait func())
}

// How a schedule makes each world it runs in: T2's on the fake host, T3's on the local stack's stores.
type FsKeysNewWorld func(kind protocol.RepoKind) *FsKeysWorld

// T2's worlds for t: each NewFsKeysWorld's.
func FsKeysT2(t FsKeysT) FsKeysNewWorld {
	return func(kind protocol.RepoKind) *FsKeysWorld {
		return NewFsKeysWorld(t, kind)
	}
}

// A world with one repo of kind and no device, its engine on a fresh fake host. Its engine reads place/, repo/, the
// forms and group-info from the store each time, with no cache, so a schedule sees each write at once.
func NewFsKeysWorld(t FsKeysT, kind protocol.RepoKind) *FsKeysWorld {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	return NewFsKeysWorldOn(t, kind, clock, host, nil)
}

// A world with one repo of kind on host, the services' host adjusted by adjust, which a T3 test gives its real
// clusters and Redis, and fault's driver its Net's; nil keeps the fake host's own. The world reads and writes its
// objects through the adjusted host's stores too. Its engine reads place/, repo/, the forms and group-info from the
// store each time.
func NewFsKeysWorldOn(t FsKeysT, kind protocol.RepoKind, clock *sidecartest.FakeClock, host *sidecartest.FakeHost, adjust func(host *sidecar.ServiceHost)) *FsKeysWorld {
	world := &FsKeysWorld{
		t:         t,
		Ctx:       t.Context(),
		Clock:     clock,
		Host:      host,
		Log:       sidecartest.NewFakeGkmAuthLog(),
		NetworkId: connect.NewId(),
		MemberId:  sidecar.NewId(),
		RepoId:    sidecar.NewId(),
		Kind:      kind,
		suspended: map[sidecar.Id]bool{},
		voided:    map[sidecar.Id]bool{},
		shrunkAt:  map[sidecar.Id]uint64{},
		hintCount: sidecar.NewMonitorValue(0),
		adjust:    adjust,
	}
	host.Gates.OpenService(sidecar.ServiceGateGkm, world.NetworkId)
	engineSettings := gkmservice.DefaultGkmServiceSettings()
	engineSettings.RepoCacheTtl = 0
	engineSettings.FormCacheTtl = 0
	engineSettings.GroupInfoCacheTtl = 0
	// a placement is read again each time, its 404 kept for nothing, so a repo placed after a read is found
	place := *engineSettings.Place
	place.NotFoundTtl = 0
	engineSettings.Place = &place
	world.engineSettings = engineSettings
	world.RestartEngine()
	return world
}

// A gkm instance over the world's stores, in place of the one standing: what a restart on another instance is. The
// old instance closes.
func (self *FsKeysWorld) RestartEngine() {
	self.t.Helper()
	if self.Engine != nil {
		self.Engine.Close()
	}
	engine, err := gkmservice.NewGkmEngine(self.Ctx, self.serviceHost(), self.engineSettings, &gkmservice.GkmEngineDeps{AuthState: &fsKeysWorldState{world: self}})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	self.Engine = engine
}

// gkm's settings changed by change, on a new instance over the same stores: a schedule that pages epochs at a smaller
// bound, say.
func (self *FsKeysWorld) Reconfigure(change func(settings *gkmservice.GkmServiceSettings)) {
	change(self.engineSettings)
	self.RestartEngine()
}

// The host the world's services run on: the fake host's, or what adjust gives, its push counting each hint it takes
// and its store's writes passing BlobWrite.
func (self *FsKeysWorld) serviceHost() *sidecar.ServiceHost {
	serviceHost := self.Host.ServiceHost()
	if self.adjust != nil {
		self.adjust(serviceHost)
	}
	serviceHost.Push = &fsKeysPush{inner: self.Host.Push, count: self.hintCount}
	serviceHost.Blobs = &fsKeysBlobs{inner: serviceHost.Blobs, world: self}
	return serviceHost
}

// gkm's soft state of the world's groups in Redis is lost (owner decisions 2, 136): the fake host's whole Redis, or on
// real stores each group's {gka_} family, the one family gkm keeps there.
func (self *FsKeysWorld) LoseRedis() {
	self.t.Helper()
	if self.adjust == nil {
		self.Host.Redis.LoseEverything()
		return
	}
	keys := []string{gkmservice.GkmAckRedisKey(self.GroupId)}
	if self.ConfigGroupId != (sidecar.Id{}) {
		keys = append(keys, gkmservice.GkmAckRedisKey(self.ConfigGroupId))
	}
	if err := self.serviceHost().Redis.Delete(self.Ctx, keys); err != nil {
		self.t.Fatalf("the loss of {gka_}: %v", err)
	}
}

// The fake host's push, which also counts each call, so a schedule can wait on a hint gkm queues to its workers.
type fsKeysPush struct {
	inner *sidecartest.FakePush
	count *sidecar.MonitorValue[int]
}

func (self *fsKeysPush) Hint(ctx context.Context, clientIds []connect.Id, hint *sidecar.ClientHint) error {
	defer self.count.Update(func(count int) int { return count + 1 })
	return self.inner.Hint(ctx, clientIds, hint)
}

func (self *fsKeysPush) HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *sidecar.ClientHint) error {
	defer self.count.Update(func(count int) int { return count + 1 })
	return self.inner.HintSidecars(ctx, sidecarIds, hint)
}

// The services' store, each cluster's writes passing the world's BlobWrite.
type fsKeysBlobs struct {
	inner sidecar.BlobStore
	world *FsKeysWorld
}

func (self *fsKeysBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	cluster, err := self.inner.Cluster(clusterId)
	if err != nil {
		return nil, err
	}
	return &fsKeysCluster{BlobCluster: cluster, world: self.world}, nil
}

func (self *fsKeysBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.inner.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &fsKeysCluster{BlobCluster: cluster, world: self.world}, nil
}

func (self *fsKeysBlobs) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.inner.SegmentCluster()
}

func (self *fsKeysBlobs) MetadataClusterIds() []string {
	return self.inner.MetadataClusterIds()
}

func (self *fsKeysBlobs) NewRepoClusterId() string {
	return self.inner.NewRepoClusterId()
}

// One cluster whose PUTs and DELETEs pass the world's BlobWrite; its reads are the cluster's own.
type fsKeysCluster struct {
	sidecar.BlobCluster
	world *FsKeysWorld
}

// Runs one write under the world's BlobWrite.
func (self *fsKeysCluster) write(op string, key string, apply func() error) error {
	fault := FsKeysFaultNone
	if self.world.BlobWrite != nil {
		fault = self.world.BlobWrite(op, key)
	}
	if fault == FsKeysFaultFailBefore {
		return errFsKeysStore
	}
	if err := apply(); err != nil {
		return err
	}
	if fault == FsKeysFaultDropAnswer {
		return errFsKeysStore
	}
	return nil
}

func (self *fsKeysCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (newEtag string, err error) {
	err = self.write(http.MethodPut, key, func() error {
		newEtag, err = self.BlobCluster.PutIfNoneMatch(ctx, key, body, options)
		return err
	})
	return newEtag, err
}

func (self *fsKeysCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (newEtag string, err error) {
	err = self.write(http.MethodPut, key, func() error {
		newEtag, err = self.BlobCluster.PutIfMatch(ctx, key, etag, body, options)
		return err
	})
	return newEtag, err
}

func (self *fsKeysCluster) Delete(ctx context.Context, key string) error {
	return self.write(http.MethodDelete, key, func() error {
		return self.BlobCluster.Delete(ctx, key)
	})
}

// The gkm hints the device's client was told, each with its topic, in order.
func (self *FsKeysWorld) Hints(device *FsKeysDevice) []*FsKeysHint {
	self.t.Helper()
	hints := []*FsKeysHint{}
	for _, hint := range self.Host.Push.Hints(device.ClientId) {
		if hint.Topic != sidecar.PushTopicGkm && !strings.HasPrefix(hint.Topic, sidecar.PushTopicGkmGroupPrefix) {
			continue
		}
		body := &protocol.GkmHint{}
		if err := proto.Unmarshal(hint.Body, body); err != nil {
			self.t.Fatalf("a gkm hint that does not parse: %v", err)
		}
		hints = append(hints, &FsKeysHint{Topic: hint.Topic, Version: hint.Version, Hint: body})
	}
	return hints
}

// One gkm hint a client was told.
type FsKeysHint struct {
	Topic   string
	Version uint64
	Hint    *protocol.GkmHint
}

// Waits until the device was told a hint match takes, the hints counted so far rechecked at each new one; fails
// the schedule when its ctx ends first.
func (self *FsKeysWorld) AwaitHint(device *FsKeysDevice, match func(hint *FsKeysHint) bool) *FsKeysHint {
	self.t.Helper()
	for {
		_, changed := self.hintCount.Get()
		for _, hint := range self.Hints(device) {
			if match(hint) {
				return hint
			}
		}
		done := false
		self.block(func() {
			select {
			case <-changed:
			case <-self.Ctx.Done():
				done = true
			}
		})
		if done {
			self.t.Fatalf("%s was never told the hint", device.Label)
			return nil
		}
	}
}

// gkm's reconciler on the world's host, its state the world's log, told of each position Advance appends. nil
// settings take the defaults with the engine's own service settings, which cache no place/, repo/, form or
// group-info read, so a repo placed after a pass is found at the next.
func (self *FsKeysWorld) StartReconciler(settings *gkmservice.GkmReconcilerSettings) *gkmservice.GkmReconciler {
	self.t.Helper()
	if settings == nil {
		settings = gkmservice.DefaultGkmReconcilerSettings()
		settings.Service = self.engineSettings
	}
	reconciler, err := gkmservice.NewGkmReconciler(self.Ctx, self.serviceHost(), settings, &gkmservice.GkmReconcilerDeps{State: &fsKeysReconcilerState{world: self}})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(reconciler.Close)
	return reconciler
}

// Waits for the reconciler's next pass past the one counted now, which run calls after an Advance.
func (self *FsKeysWorld) AwaitPass(reconciler *gkmservice.GkmReconciler, run func()) {
	self.t.Helper()
	before, _ := reconciler.Passes()
	run()
	for {
		count, changed := reconciler.Passes()
		if before < count {
			return
		}
		done := false
		self.block(func() {
			select {
			case <-changed:
			case <-self.Ctx.Done():
				done = true
			}
		})
		if done {
			self.t.Fatal("the reconciler made no pass")
			return
		}
	}
}

// The reconciler's view of the world's log: one network, its repo and its config repo.
type fsKeysReconcilerState struct {
	world *FsKeysWorld
}

func (self *fsKeysReconcilerState) Watch(changed func(change *gkmservice.GkmStateChange)) (func(), error) {
	self.world.reconcilerChanged = changed
	return func() {}, nil
}

func (self *fsKeysReconcilerState) Networks() []sidecar.Id {
	return []sidecar.Id{sidecar.Id(self.world.NetworkId)}
}

func (self *fsKeysReconcilerState) State(ctx context.Context, networkId sidecar.Id) (*gkmservice.GkmNetworkState, error) {
	tip := self.world.Log.Tip()
	if tip == nil || networkId != sidecar.Id(self.world.NetworkId) {
		return nil, errors.New("fs keys: no state of the network")
	}
	return &gkmservice.GkmNetworkState{View: tip, RepoIds: self.world.repoIds()}, nil
}

func (self *fsKeysReconcilerState) SidecarStanding(ctx context.Context, sidecarId sidecar.Id) (sidecar.Id, bool, bool, error) {
	tip := self.world.Log.Tip()
	if tip == nil {
		return sidecar.Id{}, false, false, nil
	}
	row := tip.SidecarRow(sidecarId)
	if row == nil {
		return sidecar.Id{}, false, false, nil
	}
	return sidecar.Id(self.world.NetworkId), row.GetRevokedAt() != 0, true, nil
}

// The world's repo, and its config repo once ConfigWriters named one.
func (self *FsKeysWorld) repoIds() []sidecar.Id {
	repoIds := []sidecar.Id{self.RepoId}
	if self.ConfigRepoId != (sidecar.Id{}) {
		repoIds = append(repoIds, self.ConfigRepoId)
	}
	return repoIds
}

// Admits a member device of the world's member, read_only with readOnly, with its real MLS engine. It reads and
// writes nothing until Grant says so.
func (self *FsKeysWorld) AddMember(label string, readOnly bool) *FsKeysDevice {
	self.t.Helper()
	device := self.admit(label)
	device.row.MemberId = self.MemberId.Bytes()
	if readOnly {
		device.row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	}
	device.Restart()
	return device
}

// Admits a tagged agent, which holds no leaf: it reads by its ReaderWraps and rotates by wraps.
func (self *FsKeysWorld) AddAgent(label string) *FsKeysDevice {
	self.t.Helper()
	device := self.admit(label)
	device.row.TagIds = [][]byte{sidecar.NewId().Bytes()}
	device.Restart()
	return device
}

// A device's identity, row and stores.
func (self *FsKeysWorld) admit(label string) *FsKeysDevice {
	signer := sidecartest.NewFakeGkmSigner()
	admission := sha256.Sum256([]byte("fs keys admission of " + label))
	position := self.nextPosition()
	device := &FsKeysDevice{
		Label:  label,
		world:  self,
		signer: signer,
		row: &bridge.SidecarRow{
			SidecarId:         signer.SidecarId.Bytes(),
			AdmissionSha256:   admission[:],
			AdmittedAt:        position,
			LiveSince:         position,
			IdentityPublicKey: signer.PublicKey(),
			IdentityAlg:       "ed25519",
		},
		admissionSha256:   admission[:],
		readerPrivateKeys: map[string]hpke.PrivateKey{},
		secrets:           &fsKeysKeychain{nameValues: map[string][]byte{}},
		store:             sidecartest.NewFakeStore(),
	}
	device.Transport = &FsKeysTransport{world: self}
	// the client the host's push resolves the sidecar to (§5.8)
	device.ClientId = connect.NewId()
	self.Host.Push.BindSidecar(connect.Id(signer.SidecarId), device.ClientId)
	self.Devices = append(self.Devices, device)
	return device
}

// A new process of the device over the keychain and store it had: its MLS engine and group client built again, and
// given the newest state it took. Its transport and its hooks are kept.
func (self *FsKeysDevice) Restart() {
	world := self.world
	world.t.Helper()
	connectSidecarId := connect.Id(self.signer.SidecarId)
	api, err := sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:    "https://gkm.example",
		Transport: self.Transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return world.Host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: world.NetworkId,
				ClientId:  connect.NewId(),
				SidecarId: &connectSidecarId,
				Audience:  gkmservice.GkmAudience,
				Scopes:    scopes,
				IssuedAt:  world.Clock.Now(),
				ExpiresAt: world.Clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Clock: world.Clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	self.Api = api
	self.rescope()
	self.Mls = nil
	if self.member() {
		self.Mls, err = sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
			SidecarId:         self.signer.SidecarId,
			IdentityPublicKey: self.signer.PublicKey(),
			AdmissionSha256:   self.admissionSha256,
			Sign:              self.signer.Sign,
			Store:             self.store.Root(),
			CheckCredential:   sidecar.NewGkmCredentialCheck(func() sidecar.GkmAuthView { return self.state }),
			Clock:             world.Clock,
		})
		if err != nil {
			world.t.Fatal(err)
		}
	}
	settings := sidecar.DefaultGkmSettings()
	client, err := sidecar.NewGkmGroupClient(&sidecar.GkmGroupClientArgs{
		SidecarId: self.signer.SidecarId,
		NetworkId: sidecar.Id(world.NetworkId),
		Api:       api,
		Sign:      self.signer.Sign,
		Secrets:   self.secrets,
		Mls:       self.Mls,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			privateKey, ok := self.readerPrivateKeys[string(keySha256)]
			if !ok {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return privateKey, nil
		},
		ReaderKeySha256: func() []byte { return bytes.Clone(self.readerKeySha256) },
		RecoveryKey:     world.recoveryKey,
		ReaderRepoIds:   world.repoIds,
		Alarm:           func(alarm *sidecar.GkmAlarm) { self.Alarms = append(self.Alarms, alarm) },
		Jitter:          func(max time.Duration) time.Duration { return 0 },
		Settings:        settings,
		Clock:           world.Clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	self.Client = client
	if self.state != nil {
		client.AuthAdvanced(self.state)
	}
}

// An active clone of device (§2.10's copied keychain row): another process holding its identity key, and copies of
// its keychain and its ReaderKeys' private halves as they stand now, under its sidecar's row, as one who copied the
// device runs it. Its MLS store starts empty. It takes the states device takes and stands in no row of its own.
func (self *FsKeysWorld) Clone(device *FsKeysDevice, label string) *FsKeysDevice {
	self.t.Helper()
	clone := &FsKeysDevice{
		Label:             label,
		world:             self,
		signer:            device.signer,
		row:               device.row,
		admissionSha256:   device.admissionSha256,
		readerPrivateKeys: map[string]hpke.PrivateKey{},
		readerKeySha256:   bytes.Clone(device.readerKeySha256),
		ReaderKey:         device.ReaderKey,
		secrets:           &fsKeysKeychain{nameValues: map[string][]byte{}},
		store:             sidecartest.NewFakeStore(),
		ClientId:          connect.NewId(),
		published:         true,
		state:             device.state,
	}
	for keySha256, privateKey := range device.readerPrivateKeys {
		clone.readerPrivateKeys[keySha256] = privateKey
	}
	names, err := device.secrets.List("")
	if err != nil {
		self.t.Fatal(err)
	}
	for _, name := range names {
		value, err := device.secrets.Get(name)
		if err != nil {
			self.t.Fatal(err)
		}
		clone.secrets.Put(name, value)
	}
	clone.Transport = &FsKeysTransport{world: self}
	clone.Restart()
	self.clones = append(self.clones, clone)
	return clone
}

// The device's MLS state is lost, its keychain kept: a new process over a new, empty store, as a device whose
// group state did not survive is.
func (self *FsKeysDevice) LoseMlsState() {
	self.store = sidecartest.NewFakeStore()
	self.Restart()
}

// Lets devices read the repo, and write it too with write. Their tokens' scopes follow at their next restart, and at
// once for a device not yet started.
func (self *FsKeysWorld) Grant(write bool, devices ...*FsKeysDevice) {
	for _, device := range devices {
		if !slices.Contains(self.readers, device.SidecarId()) {
			self.readers = append(self.readers, device.SidecarId())
		}
		if write && !slices.Contains(self.writers, device.SidecarId()) {
			self.writers = append(self.writers, device.SidecarId())
		}
		device.rescope()
	}
}

// Lets devices deposit into the repo and nothing else, as §8.5's deposit column gives a kind that takes deposits.
func (self *FsKeysWorld) Depositor(devices ...*FsKeysDevice) {
	for _, device := range devices {
		if !slices.Contains(self.depositors, device.SidecarId()) {
			self.depositors = append(self.depositors, device.SidecarId())
		}
		device.rescope()
	}
}

// Ends a device's reading of the repo at at, a grant's expiry, which shows as the clock passes it with no entry
// (§7.9's expiry row).
func (self *FsKeysWorld) ExpireAt(device *FsKeysDevice, at time.Time) {
	if self.readerExpiries == nil {
		self.readerExpiries = map[sidecar.Id]time.Time{}
	}
	self.readerExpiries[device.SidecarId()] = at
}

// Ends a device's reading and writing of the repo at the next position with no change to its row, as a grant's
// revocation does: a shrink there.
func (self *FsKeysWorld) Drop(device *FsKeysDevice) {
	drop := func(ids []sidecar.Id) []sidecar.Id {
		return slices.DeleteFunc(ids, func(id sidecar.Id) bool { return id == device.SidecarId() })
	}
	self.readers = drop(self.readers)
	self.writers = drop(self.writers)
	self.admins = drop(self.admins)
	self.shrink(self.nextPosition(), self.RepoId)
}

// Moves holders_shrunk_at of repoIds to at, the config repo's once ConfigWriters named one, whose row then joins the
// rows (Advance).
func (self *FsKeysWorld) shrink(at uint64, repoIds ...sidecar.Id) {
	for _, repoId := range repoIds {
		if repoId != (sidecar.Id{}) {
			self.shrunkAt[repoId] = at
		}
	}
}

// A raw request of method to path through gkm, under a fresh token of device's holding scopes: gkm's status, for a
// route the client would not send under the scopes its api holds.
func (self *FsKeysWorld) RawStatus(device *FsKeysDevice, method string, path string, body []byte, scopes ...string) int {
	self.t.Helper()
	connectSidecarId := connect.Id(device.SidecarId())
	token := self.Host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: self.NetworkId,
		ClientId:  connect.NewId(),
		SidecarId: &connectSidecarId,
		Audience:  gkmservice.GkmAudience,
		Scopes:    scopes,
		IssuedAt:  self.Clock.Now(),
		ExpiresAt: self.Clock.Now().Add(15 * time.Minute),
	})
	request := httptest.NewRequest(method, "https://gkm.example"+path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/octet-stream")
	recorder := httptest.NewRecorder()
	self.Engine.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}

// A message as gkm would answer it, 200 with its bytes, for a Respond hook.
func FsKeysAnswer(message proto.Message) *http.Response {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		panic(err)
	}
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Content-Type", "application/octet-stream")
	recorder.WriteHeader(http.StatusOK)
	recorder.Write(body)
	return recorder.Result()
}

// Makes a device the repo's creator: the RepoCreate's signer, its first admin, whose own row signs it in (owner
// decision 8), every other admin's row then signed by it.
func (self *FsKeysWorld) Creator(device *FsKeysDevice) {
	creatorId := device.SidecarId()
	self.creator = &creatorId
	self.Admin(device)
}

// Makes devices the network's config writers and its config repo's admins: the network has a config repo, which every
// standing device reads and these write, and gkm's pending hint about a repo with no group goes to them (QD-638). Its
// row is the view's, as ACL's state adds it, until its first shrink puts it in the rows (QD-719, QD-762). Member devices
// also hold gkm's rw in the config group (§7.8), so they claim KeyPackages and write its Welcomes.
func (self *FsKeysWorld) ConfigWriters(devices ...*FsKeysDevice) {
	if self.ConfigRepoId == (sidecar.Id{}) {
		self.ConfigRepoId = sidecar.NewId()
	}
	for _, device := range devices {
		if !slices.Contains(self.configWriters, device.SidecarId()) {
			self.configWriters = append(self.configWriters, device.SidecarId())
		}
	}
	for _, device := range self.Devices {
		device.rescope()
	}
}

// The repo's form at seq as gkm holds it.
func (self *FsKeysWorld) Form(seq uint64) *protocol.GroupForm {
	self.t.Helper()
	cluster := self.cluster()
	object, err := cluster.Get(self.Ctx, gkmservice.GkmFormKey(self.RepoId, seq))
	if err != nil {
		self.t.Fatalf("form %d: %v", seq, err)
	}
	body, err := io.ReadAll(object.Body)
	object.Body.Close()
	if err != nil {
		self.t.Fatal(err)
	}
	signed := &bridge.Signed{}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(body, signed); err != nil {
		self.t.Fatal(err)
	}
	if err := proto.Unmarshal(signed.GetBody(), form); err != nil {
		self.t.Fatal(err)
	}
	return form
}

// Makes a device the repo's admin, its creator's right (owner decision 8).
func (self *FsKeysWorld) Admin(device *FsKeysDevice) {
	if !slices.Contains(self.admins, device.SidecarId()) {
		self.admins = append(self.admins, device.SidecarId())
	}
	device.rescope()
}

// The device's token scopes, as its reading, writing and admin right stand: on the repo, and on the config repo
// once the world has one, admin for a config writer, rw for any other member device and r for an agent.
func (self *FsKeysDevice) rescope() {
	world := self.world
	role := sidecar.GkmScopeRoleRead
	switch {
	case slices.Contains(world.admins, self.SidecarId()):
		role = sidecar.GkmScopeRoleAdmin
	case slices.Contains(world.writers, self.SidecarId()):
		role = sidecar.GkmScopeRoleWrite
	case slices.Contains(world.depositors, self.SidecarId()) && !slices.Contains(world.readers, self.SidecarId()):
		role = sidecar.GkmScopeRoleDeposit
	}
	scopes := []sidecar.GkmRepoScope{{RepoId: world.RepoId, Role: role}}
	if world.ConfigRepoId != (sidecar.Id{}) {
		configRole := sidecar.GkmScopeRoleRead
		switch {
		case slices.Contains(world.configWriters, self.SidecarId()):
			configRole = sidecar.GkmScopeRoleAdmin
		case self.member():
			configRole = sidecar.GkmScopeRoleWrite
		}
		scopes = append(scopes, sidecar.GkmRepoScope{RepoId: world.ConfigRepoId, Role: configRole})
	}
	if self.Api != nil {
		self.Api.SetRepoScopes(scopes)
	}
}

// Revokes a device at the next position: its row a tombstone that reads and writes nothing, and a shrink there of
// the repo and the config repo, which it read (§7.9). The repo's admin rows keep it, as access logs keep their
// history; a tombstone stands for nothing.
func (self *FsKeysWorld) Revoke(device *FsKeysDevice) {
	at := self.nextPosition()
	device.row.RevokedAt = at
	drop := func(ids []sidecar.Id) []sidecar.Id {
		return slices.DeleteFunc(ids, func(id sidecar.Id) bool { return id == device.SidecarId() })
	}
	self.readers = drop(self.readers)
	self.writers = drop(self.writers)
	self.configWriters = drop(self.configWriters)
	self.shrink(at, self.RepoId, self.ConfigRepoId)
}

// api's rev/ object for device's revocation (§7.8): gkm refuses every token of its sidecar from now, whatever its
// state shows yet. A schedule whose revoked device must still reach gkm while gkm's state trails leaves this out.
func (self *FsKeysWorld) VoidTokens(device *FsKeysDevice) {
	self.voided[device.SidecarId()] = true
}

// The position the next state takes.
func (self *FsKeysWorld) nextPosition() uint64 {
	if tip := self.Log.Tip(); tip != nil {
		return tip.Pin().GetVersion() + 1
	}
	return 1
}

// Whether a device reads at the next position: admitted, and not revoked, parked or suspended.
func (self *FsKeysWorld) standing(device *FsKeysDevice) bool {
	return !device.unadmitted && device.row.GetRevokedAt() == 0 && device.row.GetParkedAt() == 0 && !self.suspended[device.SidecarId()]
}

// Appends the world as it stands as the log's next position, which every device that is not Offline takes.
func (self *FsKeysWorld) Advance() *sidecartest.FakeGkmAuthView {
	self.t.Helper()
	admins := []*protocol.AclRepoAdminRow{}
	for _, adminId := range self.admins {
		switch {
		case self.creator == nil:
			admins = append(admins, &protocol.AclRepoAdminRow{SidecarId: adminId.Bytes(), Signer: adminId.Bytes(), At: 1})
		case *self.creator == adminId:
			// the RepoCreate's own row
			admins = append(admins, &protocol.AclRepoAdminRow{SidecarId: adminId.Bytes(), Signer: adminId.Bytes(), At: 1})
		default:
			admins = append(admins, &protocol.AclRepoAdminRow{SidecarId: adminId.Bytes(), Signer: self.creator.Bytes(), At: 2})
		}
	}
	repos := []*protocol.AclRepo{{RepoId: self.RepoId.Bytes(), Kind: self.Kind, Admins: admins, HoldersShrunkAt: self.shrunkAt[self.RepoId]}}
	if configShrunkAt := self.shrunkAt[self.ConfigRepoId]; self.ConfigRepoId != (sidecar.Id{}) && configShrunkAt != 0 {
		// the config's row joins the rows at its first shrink, with no admins, sorted in, as TEAM's rows take it
		// (QD-762); until then the view adds it from the fixture's ConfigRepoId
		repos = append(repos, &protocol.AclRepo{
			RepoId: self.ConfigRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG, HoldersShrunkAt: configShrunkAt,
		})
		slices.SortFunc(repos, func(a *protocol.AclRepo, b *protocol.AclRepo) int { return bytes.Compare(a.GetRepoId(), b.GetRepoId()) })
	}
	acl, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.AclRows{Repos: repos})
	if err != nil {
		self.t.Fatal(err)
	}
	member := &bridge.MemberRow{MemberId: self.MemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}
	if 0 < len(self.bindings) {
		member.RecoveryKeySha256 = bytes.Clone(self.bindings[0].KeySha256)
		for _, binding := range self.bindings {
			member.Bindings = append(member.Bindings, binding.row())
		}
	}
	rows := &bridge.ProjectionRows{
		Acl:     acl,
		Members: []*bridge.MemberRow{member},
	}
	for _, delegation := range self.delegations {
		rows.Delegations = append(rows.Delegations, proto.Clone(delegation.row).(*bridge.DelegationRow))
	}
	identityKeys := map[sidecar.Id][]byte{}
	for _, device := range self.Devices {
		if device.unadmitted {
			continue
		}
		rows.Sidecars = append(rows.Sidecars, proto.Clone(device.row).(*bridge.SidecarRow))
		identityKeys[device.SidecarId()] = device.signer.PublicKey()
	}
	expiries := map[sidecar.Id]time.Time{}
	for sidecarId, at := range self.readerExpiries {
		expiries[sidecarId] = at
	}
	// a suspended or unadmitted device reads and writes nothing, its grants kept for its Unsuspend
	reading := func(ids []sidecar.Id) []sidecar.Id {
		reading := []sidecar.Id{}
		for _, id := range ids {
			if device := self.device(id); device == nil || self.standing(device) {
				reading = append(reading, id)
			}
		}
		return reading
	}
	repoReaders := map[sidecar.Id][]sidecar.Id{self.RepoId: reading(self.readers)}
	repoWriters := map[sidecar.Id][]sidecar.Id{self.RepoId: reading(self.writers)}
	atomRepos := map[sidecar.Id][]sidecar.Id{}
	for _, delegation := range self.delegations {
		atomRepos[delegation.atom] = []sidecar.Id{self.RepoId}
	}
	if self.ConfigRepoId != (sidecar.Id{}) {
		configReaders := []sidecar.Id{}
		for _, device := range self.Devices {
			if self.standing(device) {
				configReaders = append(configReaders, device.SidecarId())
			}
		}
		repoReaders[self.ConfigRepoId] = configReaders
		repoWriters[self.ConfigRepoId] = reading(self.configWriters)
	}
	view := self.Log.Append(&sidecartest.FakeGkmAuthFixture{
		Rows:               rows,
		IdentityKeys:       identityKeys,
		RepoReaders:        repoReaders,
		RepoWriters:        repoWriters,
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{self.RepoId: expiries},
		AtomRepos:          atomRepos,
		ConfigRepoId:       self.ConfigRepoId,
	})
	self.views = append(self.views, view)
	for _, device := range append(slices.Clone(self.Devices), self.clones...) {
		if !device.Offline {
			device.Take(view)
		}
	}
	if self.reconcilerChanged != nil {
		self.reconcilerChanged(&gkmservice.GkmStateChange{NetworkId: sidecar.Id(self.NetworkId)})
	}
	return view
}

// The world's device with this sidecar, nil for none.
func (self *FsKeysWorld) device(sidecarId sidecar.Id) *FsKeysDevice {
	for _, device := range self.Devices {
		if device.SidecarId() == sidecarId {
			return device
		}
	}
	return nil
}

// The device takes a state, as its log applier hands it one.
func (self *FsKeysDevice) Take(view sidecar.GkmAuthView) {
	self.state = view
	self.Client.AuthAdvanced(view)
}

// Each device's first ReaderKey, valid 6 days, and each member device's first KeyPackages, three one-time ones and
// its last-resort one, as upkeep uploads them, for every standing device that has published none yet.
func (self *FsKeysWorld) Publish() {
	self.t.Helper()
	for _, device := range self.Devices {
		if !self.standing(device) || device.published {
			continue
		}
		device.published = true
		if !slices.Contains(self.readers, device.SidecarId()) && self.ConfigRepoId == (sidecar.Id{}) {
			// a deposit-only principal reads nothing, and its scope reaches the drop-key route alone (QD-177)
			continue
		}
		device.PublishReaderKey()
		if device.Mls == nil {
			continue
		}
		device.PublishKeyPackages()
	}
}

// Three one-time KeyPackages and a last-resort one, uploaded, as upkeep refills them.
func (self *FsKeysDevice) PublishKeyPackages() {
	world := self.world
	world.t.Helper()
	keyPackages := [][]byte{}
	for i := range 4 {
		keyPackage, err := self.Mls.CreateKeyPackage(i == 3)
		if err != nil {
			world.t.Fatal(err)
		}
		keyPackages = append(keyPackages, keyPackage.Encoded)
	}
	world.Again(self.Label+"'s KeyPackages", func() error { return self.Api.UploadKeyPackages(world.Ctx, keyPackages) })
}

// A fresh ReaderKey of the device, valid 6 days, uploaded and its private key kept.
func (self *FsKeysDevice) PublishReaderKey() {
	world := self.world
	world.t.Helper()
	now := world.Clock.Now()
	readerKey, privateKey, err := sidecar.NewGkmReaderKey(self.SidecarId(), now, now.Add(6*24*time.Hour), self.signer.Sign)
	if err != nil {
		world.t.Fatal(err)
	}
	digest := sha256.Sum256(privateKey.PublicKey().Bytes())
	self.readerPrivateKeys[string(digest[:])] = privateKey
	self.readerKeySha256 = digest[:]
	self.ReaderKey = readerKey
	world.Again(self.Label+"'s ReaderKey", func() error { return self.Api.UploadReaderKey(world.Ctx, readerKey) })
}

// The first cluster, where the world's repos are placed.
func (self *FsKeysWorld) cluster() sidecar.BlobCluster {
	self.t.Helper()
	cluster, err := self.serviceHost().Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

// A message's bytes.
func (self *FsKeysWorld) marshal(message proto.Message) []byte {
	self.t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		self.t.Fatal(err)
	}
	return body
}

// Places the repo as evs's PUT does, keying, on the first cluster, by creator.
func (self *FsKeysWorld) Place(creator *FsKeysDevice) {
	self.placeRepo(self.RepoId, self.Kind, creator)
}

// Places a repo of kind, keying, on the first cluster, by creator.
func (self *FsKeysWorld) placeRepo(repoId sidecar.Id, kind protocol.RepoKind, creator *FsKeysDevice) {
	self.t.Helper()
	cluster := self.cluster()
	place, err := (&sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: creator.SidecarId()}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.putOnce(cluster, sidecar.EvsPlaceKey(repoId), place); err != nil {
		self.t.Fatal(err)
	}
	self.putRepoStateOf(repoId, kind, protocol.EvsRepoState_EVS_REPO_KEYING)
}

// Writes the repo's repo/ in state, over what stands, as evs's routes move it.
func (self *FsKeysWorld) putRepoState(state protocol.EvsRepoState) {
	self.putRepoStateOf(self.RepoId, self.Kind, state)
}

// Writes a repo's repo/ in state, over what stands.
func (self *FsKeysWorld) putRepoStateOf(repoId sidecar.Id, kind protocol.RepoKind, state protocol.EvsRepoState) {
	self.t.Helper()
	cluster := self.cluster()
	body := self.marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: kind, State: state, Format: 1, NetworkId: sidecar.Id(self.NetworkId).Bytes(),
	})
	if err := self.putOver(cluster, gkmservice.GkmEvsRepoKey(repoId), body); err != nil {
		self.t.Fatalf("repo/ %s: %v", state, err)
	}
}

// evs's activation, keying to active, which follows KF1's deliveries.
func (self *FsKeysWorld) Activate() {
	self.putRepoState(protocol.EvsRepoState_EVS_REPO_ACTIVE)
}

// KF1 by creator: the repo placed keying, its group, epoch 0 and generation 1 with their deliveries, then the repo
// active.
func (self *FsKeysWorld) Create(creator *FsKeysDevice) *sidecar.EvsRepoKey {
	self.t.Helper()
	self.Place(creator)
	var key *sidecar.EvsRepoKey
	self.Again("KF1", func() (err error) {
		key, err = creator.Client.CreateGroup(self.Ctx, &sidecar.GkmCreateGroupArgs{NetworkId: sidecar.Id(self.NetworkId), RepoId: self.RepoId, Kind: self.Kind})
		return err
	})
	self.GroupId = key.GroupId()
	self.Activate()
	return key
}

// KF1 of the config repo by creator, a config writer, as §7.9's genesis forms it: created keying, its group,
// epoch 0 and generation 1 with every holder's delivery, then active (KEYS plan reading 6).
func (self *FsKeysWorld) CreateConfig(creator *FsKeysDevice) *sidecar.EvsRepoKey {
	self.t.Helper()
	if self.ConfigRepoId == (sidecar.Id{}) {
		self.t.Fatal("no config repo: ConfigWriters names its writers first")
	}
	self.placeRepo(self.ConfigRepoId, protocol.RepoKind_REPO_KIND_CONFIG, creator)
	var key *sidecar.EvsRepoKey
	self.Again("the config repo's KF1", func() (err error) {
		key, err = creator.Client.CreateGroup(self.Ctx, &sidecar.GkmCreateGroupArgs{
			NetworkId: sidecar.Id(self.NetworkId), RepoId: self.ConfigRepoId, Kind: protocol.RepoKind_REPO_KIND_CONFIG,
		})
		return err
	})
	self.ConfigGroupId = key.GroupId()
	self.putRepoStateOf(self.ConfigRepoId, protocol.RepoKind_REPO_KIND_CONFIG, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	return key
}

// KF2 for every member device with a KeyPackage: committer's pending run commits the Adds, and every other member
// device that is not Offline joins by its Welcome.
func (self *FsKeysWorld) AddPending(committer *FsKeysDevice) {
	self.AddPendingIn(committer, self.RepoId)
}

// AddPending in the repo repoId names, the world's repo or its config repo.
func (self *FsKeysWorld) AddPendingIn(committer *FsKeysDevice, repoId sidecar.Id) {
	self.t.Helper()
	self.Again(committer.Label+"'s pending run", func() error { return committer.Client.RunPending(self.Ctx, repoId) })
	for _, device := range self.Devices {
		if device == committer || device.Mls == nil || device.Offline || !self.standing(device) {
			continue
		}
		self.Again(device.Label+"'s join", func() error {
			_, err := device.Client.JoinWelcomes(self.Ctx)
			return err
		})
	}
}

// The objects under prefix on the first cluster, by key.
func (self *FsKeysWorld) objects(prefix string) map[string][]byte {
	self.t.Helper()
	cluster := self.cluster()
	objects := map[string][]byte{}
	startAfter := ""
	for {
		infos, more, err := cluster.List(self.Ctx, prefix, startAfter, 1000)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, info := range infos {
			object, err := cluster.Get(self.Ctx, info.Key)
			if errors.Is(err, sidecar.ErrBlobNotFound) {
				startAfter = info.Key
				continue
			}
			if err != nil {
				self.t.Fatal(err)
			}
			body, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				self.t.Fatal(err)
			}
			objects[info.Key] = body
			startAfter = info.Key
		}
		if !more || len(infos) == 0 {
			return objects
		}
	}
}

// How many generations gkm holds of the group.
func (self *FsKeysWorld) GenerationCount() int {
	return self.GenerationCountIn(self.GroupId)
}

// How many generations gkm holds of groupId.
func (self *FsKeysWorld) GenerationCountIn(groupId sidecar.Id) int {
	return len(self.objects(gkmservice.GkmGenerationPrefix(groupId)))
}

// gen/<generation> as gkm holds it, parsed under the log's identity keys.
func (self *FsKeysWorld) Generation(generation uint64) *sidecar.GkmGeneration {
	return self.GenerationIn(self.GroupId, generation)
}

// gen/<generation> of groupId as gkm holds it, parsed under the log's identity keys.
func (self *FsKeysWorld) GenerationIn(groupId sidecar.Id, generation uint64) *sidecar.GkmGeneration {
	self.t.Helper()
	cluster := self.cluster()
	object, err := cluster.Get(self.Ctx, gkmservice.GkmGenerationKey(groupId, generation))
	if err != nil {
		self.t.Fatalf("gen/%d: %v", generation, err)
	}
	body, err := io.ReadAll(object.Body)
	object.Body.Close()
	if err != nil {
		self.t.Fatal(err)
	}
	parsed, err := sidecar.ParseGenRotate(body, groupId, generation, sidecar.GkmIdentityKeys(self.Log.Tip()))
	if err != nil {
		self.t.Fatalf("gen/%d: %v", generation, err)
	}
	return parsed
}

// The private halves of every ReaderKey the device signed so far, as a copy of its keychain holds them.
func (self *FsKeysDevice) CopyReaderKeys() []hpke.PrivateKey {
	keys := []hpke.PrivateKey{}
	for _, privateKey := range self.readerPrivateKeys {
		keys = append(keys, privateKey)
	}
	return keys
}

// Whether any of keys opens a ReaderWrap gkm holds of generation to device.
func (self *FsKeysWorld) OpensWrapOf(device *FsKeysDevice, generation uint64, keys []hpke.PrivateKey) bool {
	self.t.Helper()
	return self.opensDelivery(self.GroupId, generation, sidecar.GkmWrapTypeReader, device.SidecarId().Bytes(), keys)
}

// Whether any of keys opens a delivery gkm holds of groupId's generation to recipient, a sidecar's ReaderWrap or a
// Delegation's DelegationWrap.
func (self *FsKeysWorld) opensDelivery(groupId sidecar.Id, generation uint64, wrapType sidecar.GkmWrapType, recipient []byte, keys []hpke.PrivateKey) bool {
	self.t.Helper()
	if uint64(self.GenerationCountIn(groupId)) < generation {
		return false
	}
	parsed := self.GenerationIn(groupId, generation)
	recipientPath := "/" + fsKeysRecipientPath(wrapType, recipient) + "/"
	for key, body := range self.objects(gkmservice.GkmWrapGenerationPrefix(groupId, generation)) {
		if !strings.Contains(key, recipientPath) {
			continue
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body, signed); err != nil {
			continue
		}
		delivery, err := sidecar.ParseGkmDelivery(signed, wrapType, sidecar.GkmIdentityKeys(self.Log.Tip()))
		if err != nil {
			continue
		}
		for _, privateKey := range keys {
			if _, err := sidecar.OpenGkmDelivery(delivery, parsed, recipient, privateKey); err == nil {
				return true
			}
		}
	}
	return false
}

// The time a generation's holders were counted at.
func (self *FsKeysWorld) GenerationTime(generation *sidecar.GkmGeneration) time.Time {
	return time.UnixMilli(generation.Rotate.GetTimeMs())
}

// The sidecars gkm holds a ReaderWrap of generation to, staged or late.
func (self *FsKeysWorld) WrapRecipients(generation uint64) map[sidecar.Id]bool {
	return self.WrapRecipientsIn(self.GroupId, generation)
}

// The sidecars gkm holds a ReaderWrap of groupId's generation to, staged or late.
func (self *FsKeysWorld) WrapRecipientsIn(groupId sidecar.Id, generation uint64) map[sidecar.Id]bool {
	self.t.Helper()
	prefix := gkmservice.GkmWrapGenerationPrefix(groupId, generation)
	recipients := map[sidecar.Id]bool{}
	for key := range self.objects(prefix) {
		parts := strings.Split(strings.TrimPrefix(key, prefix), "/")
		if len(parts) != 3 || !strings.HasPrefix(parts[1], "s:") {
			continue
		}
		idBytes, err := hex.DecodeString(strings.TrimPrefix(parts[1], "s:"))
		if err != nil {
			self.t.Fatalf("a wrap path %s: %v", key, err)
		}
		sidecarId, err := sidecar.IdFromBytes(idBytes)
		if err != nil {
			self.t.Fatalf("a wrap path %s: %v", key, err)
		}
		recipients[sidecarId] = true
	}
	return recipients
}

// The Delegations, by delegation_id in hex, gkm holds a DelegationWrap of the group's generation to.
func (self *FsKeysWorld) DelegationRecipients(generation uint64) map[string]bool {
	self.t.Helper()
	prefix := gkmservice.GkmWrapGenerationPrefix(self.GroupId, generation)
	recipients := map[string]bool{}
	for key := range self.objects(prefix) {
		parts := strings.Split(strings.TrimPrefix(key, prefix), "/")
		if len(parts) == 3 && strings.HasPrefix(parts[1], "d:") {
			recipients[strings.TrimPrefix(parts[1], "d:")] = true
		}
	}
	return recipients
}

// The newest epoch gkm holds of the group.
func (self *FsKeysWorld) NewestEpoch() uint64 {
	return self.NewestEpochIn(self.GroupId)
}

// The newest epoch gkm holds of groupId.
func (self *FsKeysWorld) NewestEpochIn(groupId sidecar.Id) uint64 {
	self.t.Helper()
	newest := uint64(0)
	for key := range self.objects(gkmservice.GkmEpochPrefix(groupId)) {
		epoch, err := strconv.ParseUint(key[strings.LastIndex(key, "/")+1:], 10, 64)
		if err != nil {
			self.t.Fatalf("an epoch key %s: %v", key, err)
		}
		newest = max(newest, epoch)
	}
	return newest
}

// epoch/<epoch> as gkm holds it, nil for none.
func (self *FsKeysWorld) EpochObject(epoch uint64) *protocol.GkmEpochObject {
	return self.EpochObjectIn(self.GroupId, epoch)
}

// epoch/<epoch> of groupId as gkm holds it, nil for none.
func (self *FsKeysWorld) EpochObjectIn(groupId sidecar.Id, epoch uint64) *protocol.GkmEpochObject {
	self.t.Helper()
	cluster := self.cluster()
	object, err := cluster.Get(self.Ctx, gkmservice.GkmEpochKey(groupId, epoch))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		self.t.Fatal(err)
	}
	body, err := io.ReadAll(object.Body)
	object.Body.Close()
	if err != nil {
		self.t.Fatal(err)
	}
	epochObject := &protocol.GkmEpochObject{}
	if err := proto.Unmarshal(body, epochObject); err != nil {
		self.t.Fatal(err)
	}
	return epochObject
}

// The labels of the leaves of the epoch device holds, sorted and joined.
func (self *FsKeysWorld) Roster(device *FsKeysDevice) string {
	return self.RosterIn(device, self.GroupId)
}

// The labels of the leaves of groupId's epoch device holds, sorted and joined.
func (self *FsKeysWorld) RosterIn(device *FsKeysDevice, groupId sidecar.Id) string {
	self.t.Helper()
	group, err := device.Mls.LoadGroup(groupId)
	if err != nil {
		self.t.Fatalf("%s's group: %v", device.Label, err)
	}
	labels := []string{}
	for _, member := range group.Roster() {
		for _, other := range self.Devices {
			if other.SidecarId() == member.SidecarId {
				labels = append(labels, other.Label)
			}
		}
	}
	slices.Sort(labels)
	return strings.Join(labels, "")
}

// The devices hold one epoch and one epoch_authenticator.
func (self *FsKeysWorld) AgreeOnEpoch(devices ...*FsKeysDevice) {
	self.t.Helper()
	self.AgreeOnEpochIn(self.GroupId, devices...)
}

// The devices hold one epoch of groupId and one epoch_authenticator.
func (self *FsKeysWorld) AgreeOnEpochIn(groupId sidecar.Id, devices ...*FsKeysDevice) {
	self.t.Helper()
	var first sidecar.MlsGroup
	for _, device := range devices {
		group, err := device.Mls.LoadGroup(groupId)
		if err != nil {
			self.t.Fatalf("%s's group: %v", device.Label, err)
		}
		if first == nil {
			first = group
			continue
		}
		if group.Epoch() != first.Epoch() || !bytes.Equal(group.EpochAuthenticator(), first.EpochAuthenticator()) {
			self.t.Errorf("%s holds epoch %d, another epoch %d", device.Label, group.Epoch(), first.Epoch())
		}
	}
}

// The newest generation a removed device opens from everything gkm stores, as the model's Reach computes it (6.3):
// every epoch its own MLS state can follow from the one it last held, each GenWrap and each generation's leaf_wrap
// under that epoch's KEK, and every delivery gkm holds to it under each key it kept. The ladder opens only downward,
// so this bounds what it reads.
func (self *FsKeysWorld) RemovedReach(device *FsKeysDevice) uint64 {
	return self.RemovedReachIn(device, self.RepoId, self.GroupId)
}

// RemovedReach in repoId's group, groupId.
func (self *FsKeysWorld) RemovedReachIn(device *FsKeysDevice, repoId sidecar.Id, groupId sidecar.Id) uint64 {
	self.t.Helper()
	reach := uint64(0)
	// the KEK of each epoch the device's MLS state reaches, which a GenWrap or a leaf_wrap of that epoch opens under
	epochKeks := map[uint64][]byte{}
	open := func(epoch uint64, exporter sidecar.MlsExporter, object *protocol.GkmEpochObject) {
		kek, err := sidecar.MlsKek(exporter, repoId)
		if err != nil {
			return
		}
		epochKeks[epoch] = kek
		generation := object.GetHeader().GetGeneration()
		if generation == 0 || len(object.GetGenWrap()) == 0 {
			return
		}
		if _, err := sidecar.OpenGkmGenWrap(self.GenerationIn(groupId, generation), groupId, epoch, kek, object.GetGenWrap()); err == nil && reach < generation {
			reach = generation
		}
	}
	if device.Mls != nil {
		if group, err := device.Mls.LoadGroup(groupId); err == nil {
			epoch := group.Epoch()
			if object := self.EpochObjectIn(groupId, epoch); object != nil {
				open(epoch, group, object)
			}
			for next := epoch + 1; ; next += 1 {
				object := self.EpochObjectIn(groupId, next)
				if object == nil {
					break
				}
				staged, err := group.Process(object.GetCommit())
				if err != nil {
					break
				}
				open(next, staged, object)
				adopted, err := staged.Adopt()
				if err != nil {
					break
				}
				group = adopted
			}
		}
	}
	keys := device.CopyReaderKeys()
	for generation := uint64(1); generation <= uint64(self.GenerationCountIn(groupId)); generation += 1 {
		if reach < generation && self.opensDelivery(groupId, generation, sidecar.GkmWrapTypeReader, device.SidecarId().Bytes(), keys) {
			reach = generation
		}
		parsed := self.GenerationIn(groupId, generation)
		if leafWrap := parsed.Rotate.GetLeafWrap(); leafWrap != nil && reach < generation {
			if kek, ok := epochKeks[leafWrap.GetEpoch()]; ok {
				if _, err := sidecar.OpenGkmLeafWrap(parsed, kek); err == nil {
					reach = generation
				}
			}
		}
	}
	return reach
}

// Stages a path-only commit on the epoch device holds whose header names generation at the device's state, seals
// that generation's GenWrap under the new epoch's KEK where the device holds the key, and posts it past every check
// the client makes: gkm's answer.
func (self *FsKeysWorld) InjectPathCommit(device *FsKeysDevice, generation uint64) int {
	self.t.Helper()
	return self.InjectCommit(device, generation, nil)
}

// InjectPathCommit with adds, KeyPackages the commit adds, as a hostile leaf would make it: no Welcome is written.
func (self *FsKeysWorld) InjectCommit(device *FsKeysDevice, generation uint64, adds [][]byte) int {
	self.t.Helper()
	group, err := device.Mls.LoadGroup(self.GroupId)
	if err != nil {
		self.t.Fatal(err)
	}
	header := self.marshal(&protocol.GkmCommitHeader{Generation: generation, Auth: device.state.Pin()})
	staged, err := group.Commit(&sidecar.MlsCommitArgs{Adds: adds, Path: true, AuthenticatedData: header})
	if err != nil {
		self.t.Fatal(err)
	}
	defer staged.Discard()
	key, err := device.Client.RepoKey(self.Ctx, self.RepoId, generation)
	if err != nil {
		self.t.Fatalf("%s's generation %d: %v", device.Label, generation, err)
	}
	kek, err := sidecar.MlsKek(staged, self.RepoId)
	if err != nil {
		self.t.Fatal(err)
	}
	genWrap, err := sidecar.SealGkmGenWrap(key, self.GroupId, staged.Epoch(), kek)
	if err != nil {
		self.t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		self.t.Fatal(err)
	}
	sealedGroupInfo, err := sidecar.SealGkmGroupInfo(key, self.GroupId, staged.Epoch(), groupInfo)
	if err != nil {
		self.t.Fatal(err)
	}
	err = device.Api.CommitEpoch(self.Ctx, self.RepoId, self.GroupId, staged.Epoch(), &protocol.GkmEpochRequest{
		Commit: staged.Message(), GenWrap: genWrap, SealedGroupInfo: sealedGroupInfo, GroupInfoGeneration: generation,
	})
	if err == nil {
		return http.StatusOK
	}
	if gkmError, ok := sidecar.GkmErrorOf(err); ok {
		return gkmError.Status
	}
	self.t.Fatalf("the injected commit: %v", err)
	return 0
}

// gkm's newest verified state as the world's log holds it at its tip, read through the root's own rules, as a gate's
// GkmAuthState reads §8.9's cache.
type fsKeysWorldState struct {
	world *FsKeysWorld
}

// gkm's newest verified state: the log's tip, or the position GkmBehind trails it by.
func (self *fsKeysWorldState) tip() *sidecartest.FakeGkmAuthView {
	views := self.world.views
	if len(views) == 0 {
		return self.world.Log.Tip()
	}
	return views[max(0, len(views)-1-self.world.GkmBehind)]
}

func (self *fsKeysWorldState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if principal.SidecarId != nil && self.world.voided[sidecar.Id(*principal.SidecarId)] {
		return gkmservice.ErrGkmTokenRevoked
	}
	return nil
}

func (self *fsKeysWorldState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*gkmservice.GkmSidecarFacts, gkmservice.GkmAuthAnswer) {
	view := self.tip()
	if view == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	row := view.SidecarRow(sidecarId)
	if row == nil {
		return nil, gkmservice.GkmAuthDenied
	}
	facts := &gkmservice.GkmSidecarFacts{
		IdentityPublicKey: view.IdentityKey(sidecarId),
		Revoked:           row.GetRevokedAt() != 0,
		Parked:            row.GetParkedAt() != 0,
		Suspended:         self.world.suspended[sidecarId],
		ReadOnly:          row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0,
		MemberDevice:      len(row.GetTagIds()) == 0 && len(row.GetMemberId()) != 0 && !row.GetEphemeral(),
		RecoveryAdmitted:  fsKeysRecoveryAdmitted(view, row),
	}
	if memberId, err := sidecar.IdFromBytes(row.GetMemberId()); err == nil && len(row.GetMemberId()) != 0 {
		facts.MemberId = &memberId
	}
	if delegationId := row.GetDelegationId(); 0 < len(delegationId) {
		for _, delegation := range view.Delegations() {
			if bytes.Equal(delegation.GetDelegationId(), delegationId) && sidecar.GkmDelegationLive(view, delegation, self.world.Clock.Now()) {
				facts.CoveringDelegationId = bytes.Clone(delegationId)
			}
		}
	}
	return facts, gkmservice.GkmAuthAllowed
}

// Whether a member device's admission was signed by one of its member's recovery bindings (§10.8).
func fsKeysRecoveryAdmitted(view sidecar.GkmAuthView, row *bridge.SidecarRow) bool {
	memberId, err := sidecar.IdFromBytes(row.GetMemberId())
	if err != nil || len(row.GetTagIds()) != 0 || row.GetEphemeral() {
		return false
	}
	member := view.Member(memberId)
	for _, signer := range row.GetAdmissionSigners() {
		for _, binding := range member.GetBindings() {
			if bytes.Equal(signer, binding.GetKeySha256()) {
				return true
			}
		}
	}
	return false
}

// The answer of a test of membership.
func fsKeysAnswer(allowed bool) gkmservice.GkmAuthAnswer {
	if allowed {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

func (self *fsKeysWorldState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) gkmservice.GkmAuthAnswer {
	view := self.tip()
	sidecarId := sidecar.Id(*principal.SidecarId)
	world := self.world
	if repoId == world.ConfigRepoId && repoId != (sidecar.Id{}) && right == sidecar.AclEvsWrite {
		// §7.8: the config gives its member devices gkm's rw, read_only ones aside
		row := view.SidecarRow(sidecarId)
		memberDevice := row != nil && len(row.GetTagIds()) == 0 && len(row.GetMemberId()) != 0 && !row.GetEphemeral() &&
			row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) == 0
		return fsKeysAnswer(memberDevice && slices.Contains(view.RepoReadersAt(repoId, now), sidecarId))
	}
	switch right {
	case sidecar.AclEvsRead:
		return fsKeysAnswer(slices.Contains(view.RepoReadersAt(repoId, now), sidecarId))
	case sidecar.AclEvsWrite:
		return fsKeysAnswer(slices.Contains(view.RepoWriters(repoId), sidecarId))
	case sidecar.AclEvsAdmin:
		repo := view.Repo(repoId)
		if repoId == world.ConfigRepoId && repoId != (sidecar.Id{}) {
			// no row lists the config's admins (QD-719, QD-762): the world's config writers at the tip hold it, which
			// question acl-config-repo-row-config-admin's second option reads; ACL as built gives it to the Genesis's
			// owner sidecar alone
			return fsKeysAnswer(repo != nil && slices.Contains(view.RepoWriters(repoId), sidecarId))
		}
		return fsKeysAnswer(repo != nil && slices.ContainsFunc(repo.GetAdmins(), func(admin *protocol.AclRepoAdminRow) bool {
			return sidecar.AclRepoAdminStands(admin) && bytes.Equal(admin.GetSidecarId(), sidecarId.Bytes())
		}))
	case sidecar.AclEvsDeposit:
		return fsKeysAnswer(slices.Contains(world.depositors, sidecarId) || slices.Contains(view.RepoReadersAt(repoId, now), sidecarId))
	}
	return gkmservice.GkmAuthDenied
}

func (self *fsKeysWorldState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) gkmservice.GkmAuthAnswer {
	return fsKeysAnswer(slices.Contains(self.tip().RepoReadersAt(repoId, now), sidecarId))
}

func (self *fsKeysWorldState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*gkmservice.GkmPendingTarget, gkmservice.GkmAuthAnswer) {
	view := self.tip()
	targets := []*gkmservice.GkmPendingTarget{}
	for _, repoId := range self.world.repoIds() {
		if slices.Contains(view.RepoReadersAt(repoId, now), sidecarId) {
			targets = append(targets, &gkmservice.GkmPendingTarget{RepoId: repoId, SidecarIds: view.RepoWriters(repoId)})
		}
	}
	return targets, gkmservice.GkmAuthAllowed
}

func (self *fsKeysWorldState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return self.tip().RepoReadersAt(repoId, now), gkmservice.GkmAuthAllowed
}

func (self *fsKeysWorldState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return self.tip().RepoWriters(repoId), gkmservice.GkmAuthAllowed
}

func (self *fsKeysWorldState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) gkmservice.GkmAuthAnswer {
	view := self.tip()
	if view.Pin().GetVersion() < pin.GetVersion() {
		return gkmservice.GkmAuthUnknown
	}
	return fsKeysAnswer(view.OnChain(pin))
}

func (self *fsKeysWorldState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) gkmservice.GkmAuthAnswer {
	holds, err := sidecar.GkmDelegationHolds(self.tip(), repoId, delegationId, now)
	if err != nil {
		return gkmservice.GkmAuthUnknown
	}
	return fsKeysAnswer(holds)
}

// A Delegation's reader key digest, from its row: no Delegation of this world forwards.
func (self *fsKeysWorldState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*gkmservice.GkmDelegationKeyFacts, gkmservice.GkmAuthAnswer) {
	for _, row := range self.tip().Delegations() {
		if !bytes.Equal(row.GetDelegationId(), delegationId) {
			continue
		}
		keySha256, ok := sidecar.GkmDelegationKeySha256(row)
		if !ok {
			return nil, gkmservice.GkmAuthDenied
		}
		return &gkmservice.GkmDelegationKeyFacts{ReaderKeySha256: keySha256, ConfigRepoId: self.world.ConfigRepoId}, gkmservice.GkmAuthAllowed
	}
	return nil, gkmservice.GkmAuthDenied
}

// The holders that may answer a late ask, standing and not read_only, the recipient left out.
func (self *fsKeysWorldState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	view := self.tip()
	holders := []sidecar.Id{}
	for _, readerId := range view.RepoReadersAt(repoId, now) {
		row := view.SidecarRow(readerId)
		if row == nil || row.GetRevokedAt() != 0 || row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0 {
			continue
		}
		if recipient == fsKeysRecipient(readerId) {
			continue
		}
		holders = append(holders, readerId)
	}
	return holders, gkmservice.GkmAuthAllowed
}

func (self *fsKeysWorldState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) gkmservice.GkmAuthAnswer {
	dropped, err := sidecar.GkmRemoveDue(self.tip(), repoId, pin, since, now)
	if err != nil {
		return gkmservice.GkmAuthUnknown
	}
	return fsKeysAnswer(dropped)
}

// Whether the device's keychain holds a rotation's draft for the repo, <repo_id>/draft, its RK' and GenRotate kept
// before its first delivery is staged (DESIGN-DETAILS 6.2.2's keychain items).
func (self *FsKeysDevice) HoldsRotateDraft() bool {
	_, err := self.secrets.Get(hex.EncodeToString(self.world.RepoId.Bytes()) + "/draft")
	return err == nil
}

// A sidecar as a wrap path and a late ask name it: s:<sidecar_id in hex>.
func fsKeysRecipient(sidecarId sidecar.Id) string {
	return "s:" + hex.EncodeToString(sidecarId.Bytes())
}

// A delivery's recipient as its wrap path names it: s:<sidecar_id> for a ReaderWrap, d:<delegation_id> for a
// DelegationWrap, in hex.
func fsKeysRecipientPath(wrapType sidecar.GkmWrapType, recipient []byte) string {
	if wrapType == sidecar.GkmWrapTypeDelegation {
		return "d:" + hex.EncodeToString(recipient)
	}
	return "s:" + hex.EncodeToString(recipient)
}

// keychain.ur's namespace for gkm in memory, a device's keychain, which survives its restarts.
type fsKeysKeychain struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

func (self *fsKeysKeychain) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *fsKeysKeychain) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return nil
}

func (self *fsKeysKeychain) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return nil
}

func (self *fsKeysKeychain) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.nameValues {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// What a schedule's failure prints of a device.
func (self *FsKeysDevice) String() string {
	return fmt.Sprintf("%s (%s)", self.Label, self.SidecarId())
}
