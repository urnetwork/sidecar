//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// The git world (EVS1-M2-43; §22.9's git row, §22.8's twenty agents, DESIGN-DETAILS 8.6): one general repo on an evs,
// whose refs git mode takes at their first push, and devices that serve it to stock git through the local tier as a
// daemon does, so a test drives stock git end to end against the real receive path, publish, sync engine and evs:
//
//	evs      evsservice's engine hosted on a sidecartest.FakeHost in this process, as server/cli/evs would host it (T2), with
//	         every write of an evs request finishing its step 8 before the answer goes back; a T3 caller builds its
//	         own block on the world's authorization state, gate views and receipt keys, and mints its tokens
//	         (WorldSettings.Evs; server/evshost's TestFs5OnT3)
//	devices  each a sidecar of the network with its own identity key, client id, sealed store and EvsClient, a mount
//	         registry on its own state with the repo's bare repository, and a daemon whose git-hook mode serves that
//	         bare repository's hooks and whose git mode hands git-remote-ur's sessions to the client's git service;
//	         each mount runs as ur daemon runs it (EvsLocalRepo.Run), so an owned ref's queue publishes on its own
//	remotes  git's http and ssh fronts and git-remote-ur, each a transport a clone can take besides git's local one
//	         (transport.go)
//	hooks    a test binary that builds a world names a test of its own in HookCommand which calls HookHelper:
//	         git's hooks exec it, and it relays the hook to the daemon whose socket HookSocketVariable names
//	git      stock git as each device's client, at the path the settings name, in plain clones whose committer is
//	         the device's agent label at <client_id>@ur.invalid (owner decision 81)
//	clock    real time for everything: the queue's delays and the receive path's waits run on it, and Commit stamps
//	         commits by it; or a fake clock that follows real time plus what Jump moved it (FollowRealTime), which
//	         every device, T2's engine and each commit read, so a schedule ages stored state by days (FS-73)
//	format2  WorldSettings.Format2 puts the network in §19.11's format2 gate and has every device read format 2
//	lfs      WorldSettings.Lfs gives every clone stock git-lfs, its transfer agent a test binary that relays each
//	         object to the device's daemon, which serves it from the repo's ur/lfs store (lfs.go)
//
// Not safe to share between tests. Its methods are safe for concurrent use as the devices are.

package evsgit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The environment variable naming the daemon socket a hook relays to.
const HookSocketVariable = "UR_TEST_EVS_GIT_HOOK_SOCKET"

// The daemon version every device's daemon and hook name.
const daemonVersion = "synthetic-evs-git-world"

// What a world is built with (DefaultWorldSettings).
type WorldSettings struct {
	// What each hook file execs, the hook's name appended: the test binary and a -test.run naming the test that calls
	// HookHelper, then "--". Required.
	HookCommand []string
	// The git each device's client runs, an absolute path; empty finds git on PATH.
	ClientGit string
	// The evs the devices reach: a T3 caller's block. Nil hosts T2's engine in this process.
	Evs *WorldEvs
	// The engine's settings on T2; nil takes evsservice's defaults with the batch flushed at once.
	EngineSettings *evsservice.EvsSettings
	// Each device's evs settings; nil takes the client's defaults.
	ClientSettings *sidecar.EvsSettings
	// The life of each service token a device's client is given: 15 min, §7.4's.
	TokenLifetime time.Duration
	// How long before the world's start its receipt key took effect, so every receipt it signs is current: 48 h.
	ReceiptKeyAge time.Duration
	// The clock every device, T2's engine and every commit's dates read, kept at real time plus what Jump moved it
	// (FollowRealTime); nil runs on real time, which nothing moves.
	Clock *FollowingClock
	// The world's network in §19.11's format2 gate: T2's gates list it, and each device's client reads the gate as
	// admitting it and reads format 2. A T3 caller's block lists it in the gates it writes.
	Format2 bool
	// git-lfs in each device's clones, its objects moving through the device's daemon (lfs.go); nil for none.
	Lfs *WorldLfs
	// What git execs as git-remote-ur for a ur:// remote, git's <remote> and <url> appended: the test binary, a
	// -test.run naming the test that calls RemoteHelper, then "--" (transport.go). Nil serves no ur:// remote.
	RemoteHelperCommand []string
}

// A world's defaults: the caller names its HookCommand.
func DefaultWorldSettings() *WorldSettings {
	return &WorldSettings{TokenLifetime: 15 * time.Minute, ReceiptKeyAge: 48 * time.Hour}
}

// An evs a T3 caller hosts over the world's own seams: NewHost builds its block once the world knows its network, and
// IssueToken mints a token that block's Authenticator verifies.
type WorldEvs struct {
	NewHost    func(ctx context.Context, deps *WorldEvsDeps) (*WorldEvsHost, error)
	IssueToken func(principal *sidecar.Principal) (string, error)
}

// What the world gives a T3 caller's block: the network its gates and quota answer for, and the seams evs honors the
// world's devices by.
type WorldEvsDeps struct {
	NetworkId   sidecar.Id
	AuthState   evsservice.EvsAuthState
	GateViews   evsservice.EvsGateViews
	ReceiptKeys *evsservice.ReceiptKeys
}

// A T3 caller's block as the world reaches it.
type WorldEvsHost struct {
	Handler http.Handler
	// The engine behind the handler, whose step 8s the world waits out before an answer goes back.
	Engine *evsservice.EvsEngine
	// The block's stores: gkm's fake keeps its objects in Blobs, and the world places its repo on Cluster, one of
	// its metadata clusters.
	Blobs   sidecar.BlobStore
	Cluster sidecar.BlobCluster
}

// The world: one network, its member, one repo, and its devices; a device may be another member's or a tagged
// sidecar's, whose pushes a reader takes as untrusted (DESIGN-COMPUTE IC-12; the bundled git's taint tests).
type World struct {
	t        testing.TB
	ctx      context.Context
	settings *WorldSettings
	clock    sidecar.Clock
	host     *sidecartest.FakeHost
	// a T3 caller's block's stores, nil on T2, where host holds them
	evsBlobs  sidecar.BlobStore
	cluster   sidecar.BlobCluster
	engine    *evsservice.EvsEngine
	handler   http.Handler
	issue     func(principal *sidecar.Principal) (string, error)
	networkId sidecar.Id
	memberId  sidecar.Id
	repoId    sidecar.Id
	gkm       *sidecartest.FakeGkm
	authLog   *sidecartest.FakeGkmAuthLog
	gitPath   string

	stateLock  sync.Mutex
	view       *sidecartest.FakeGkmAuthView
	signers    map[sidecar.Id]*sidecartest.FakeGkmSigner
	gkmClients map[sidecar.Id]sidecar.GkmClient
	writers    []sidecar.Id
	admins     []sidecar.Id
	devices    []*Device
	// each device of another member, by its sidecar; each tagged device
	otherMembers map[sidecar.Id]sidecar.Id
	tagged       map[sidecar.Id]bool
	// called with each request before the engine serves it, and after, nil for none: an error loses the request, or
	// its answer, as a crash or a dropped connection would, and a response before answers in the engine's place
	before func(request *http.Request) (*http.Response, error)
	after  func(request *http.Request) error
}

// evs's view of the world: every writer is honored, admins too.
type worldAuthState struct {
	world *World
}

func (self *worldAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *worldAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *worldAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	world := self.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	if repoId != world.repoId || principal.SidecarId == nil {
		return evsservice.EvsAuthDenied
	}
	sidecarId := sidecar.Id(*principal.SidecarId)
	granted := sidecar.AclEvsRights(0)
	if slices.Contains(world.writers, sidecarId) {
		granted |= sidecar.AclEvsRead | sidecar.AclEvsWrite
	}
	if slices.Contains(world.admins, sidecarId) {
		granted |= sidecar.AclEvsRead | sidecar.AclEvsWrite | sidecar.AclEvsAdmin
	}
	if rights&^granted != 0 {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *worldAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	world := self.world
	if repoId != world.repoId {
		return nil, evsservice.EvsAuthDenied
	}
	return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: world.networkId}, evsservice.EvsAuthAllowed
}

func (self *worldAuthState) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	world := self.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	if networkId != world.networkId || world.view == nil {
		return nil, evsservice.EvsAuthUnknown
	}
	return world.view, evsservice.EvsAuthAllowed
}

// The git a world's clients run: settings', else PATH's; "" when the host has none, which a caller skips on.
func ClientGit(settings *WorldSettings) string {
	if settings != nil && settings.ClientGit != "" {
		return settings.ClientGit
	}
	path, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	return path
}

// The gates a world's evs reads: evs open to the network, and §19.11's format2 gate too when format2 is set, with its
// purge and drops in observe, as §23.9's rollout opens it. A T3 caller's block writes these.
func WorldGates(networkId sidecar.Id, format2 bool) string {
	network := connect.Id(networkId).String()
	gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)
	if format2 {
		gates += fmt.Sprintf("  format2: {enabled: true, networks: [%q], percent: 0, purge: \"observe\", drop: \"observe\"}\n", network)
	}
	return gates
}

// A world with no device yet: its repo placed on the cluster, its group held by no one until the first device.
func NewWorld(t testing.TB, settings *WorldSettings) *World {
	t.Helper()
	if settings == nil || len(settings.HookCommand) == 0 {
		t.Fatal("an evs git world needs the hook command its test binary serves")
	}
	gitPath := ClientGit(settings)
	if gitPath == "" {
		t.Skip("no git on this host")
	}
	ctx := t.Context()
	var clock sidecar.Clock = sidecar.RealClock{}
	if settings.Clock != nil {
		clock = settings.Clock.Fake()
	}
	world := &World{
		t: t, ctx: ctx, settings: settings, clock: clock, networkId: sidecar.NewId(), memberId: sidecar.NewId(),
		repoId: sidecar.NewId(), authLog: sidecartest.NewFakeGkmAuthLog(), gitPath: gitPath,
		signers: map[sidecar.Id]*sidecartest.FakeGkmSigner{}, gkmClients: map[sidecar.Id]sidecar.GkmClient{},
		otherMembers: map[sidecar.Id]sidecar.Id{}, tagged: map[sidecar.Id]bool{},
	}
	if settings.Evs != nil {
		world.hostEvs(settings.Evs)
	} else {
		world.hostEngine()
	}
	world.gkm = sidecartest.NewFakeGkm(clock, world.blobs(), nil)
	world.stateLock.Lock()
	world.publishWithLock()
	world.stateLock.Unlock()
	return world
}

// T2's engine, as recordEvsWorld and the evs worlds host it.
func (self *World) hostEngine() {
	t := self.t
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(self.ctx, self.clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	self.host = host
	if err := host.Gates.Set(WorldGates(self.networkId, self.settings.Format2)); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(self.networkId), 1024*1024*1024*1024)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	self.cluster = cluster
	usage, err := evsservice.NewUsageBatcher(self.ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(self.ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKeys := self.receiptKeys()
	settings := self.settings.EngineSettings
	if settings == nil {
		settings = evsservice.DefaultEvsSettings()
		settings.BatchFlushDelay = 0
		settings.PushUnknownRereadInterval = 0
		settings.RepoCacheTtl = 0
	}
	authState := &worldAuthState{world: self}
	engine, err := evsservice.NewEvsEngine(self.ctx, host.ServiceHost(), settings, &evsservice.EvsEngineDeps{
		AuthState: authState,
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: authState,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	self.engine = engine
	self.handler = engine.Handler()
	self.issue = func(principal *sidecar.Principal) (string, error) {
		return host.Authenticator.Issue(principal), nil
	}
}

// A T3 caller's block, built on the world's seams for its network.
func (self *World) hostEvs(evs *WorldEvs) {
	t := self.t
	if evs.NewHost == nil || evs.IssueToken == nil {
		t.Fatal("a T3 world's evs names its block and its tokens")
	}
	authState := &worldAuthState{world: self}
	host, err := evs.NewHost(self.ctx, &WorldEvsDeps{
		NetworkId: self.networkId, AuthState: authState, GateViews: authState, ReceiptKeys: self.receiptKeys(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if host == nil || host.Handler == nil || host.Blobs == nil || host.Cluster == nil {
		t.Fatal("a T3 block with no handler or stores")
	}
	self.handler, self.engine, self.evsBlobs, self.cluster, self.issue = host.Handler, host.Engine, host.Blobs, host.Cluster, evs.IssueToken
}

// The upload receipts' keys, one in effect since ReceiptKeyAge before the world's start.
func (self *World) receiptKeys() *evsservice.ReceiptKeys {
	receiptKey := sha256.Sum256([]byte("evs git world receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: self.clock.Now().Add(-self.settings.ReceiptKeyAge)}}, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return receiptKeys
}

// The blobs gkm keeps its objects in: the host's on T2, the T3 block's on T3.
func (self *World) blobs() sidecar.BlobStore {
	if self.host != nil {
		return self.host.Blobs
	}
	return self.evsBlobs
}

// The repo's id.
func (self *World) RepoId() sidecar.Id {
	return self.repoId
}

// The engine the devices reach: T2's, or the T3 block's.
func (self *World) Engine() *evsservice.EvsEngine {
	return self.engine
}

// The network's id.
func (self *World) NetworkId() sidecar.Id {
	return self.networkId
}

// The clock every device reads.
func (self *World) Clock() sidecar.Clock {
	return self.clock
}

// Moves the world's clock forward by d, as days pass: every device's, evs's and the next commit's. A world on real
// time cannot, and fails.
func (self *World) Jump(d time.Duration) {
	self.t.Helper()
	if self.settings.Clock == nil {
		self.t.Fatal("a world on real time cannot move its clock")
	}
	self.settings.Clock.Jump(d)
}

// The world's state as the log's next position: the repo's row, its readers, writers and admins.
func (self *World) publishWithLock() {
	row := &protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, OwnerMemberId: self.memberId.Bytes()}
	for _, adminId := range self.admins {
		row.Admins = append(row.Admins, &protocol.AclRepoAdminRow{SidecarId: adminId.Bytes()})
	}
	rows := sidecartest.FakeGkmAuthRows(row)
	devices := []sidecar.Id{}
	identityKeys := map[sidecar.Id][]byte{}
	for sidecarId, signer := range self.signers {
		identityKeys[sidecarId] = signer.PublicKey()
		devices = append(devices, sidecarId)
	}
	slices.SortFunc(devices, sidecar.Id.Cmp)
	// the world's member's devices, then each other member's, then the tagged sidecars, which no member's row names
	own := []sidecar.Id{}
	others := map[sidecar.Id][]sidecar.Id{}
	otherMemberIds := []sidecar.Id{}
	tagged := []sidecar.Id{}
	for _, sidecarId := range devices {
		switch otherMemberId, other := self.otherMembers[sidecarId]; {
		case self.tagged[sidecarId]:
			tagged = append(tagged, sidecarId)
		case other:
			if _, seen := others[otherMemberId]; !seen {
				otherMemberIds = append(otherMemberIds, otherMemberId)
			}
			others[otherMemberId] = append(others[otherMemberId], sidecarId)
		default:
			own = append(own, sidecarId)
		}
	}
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(self.memberId, own...)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	for _, otherMemberId := range otherMemberIds {
		otherRows, otherMember := sidecartest.FakeGkmAuthMemberDevices(otherMemberId, others[otherMemberId]...)
		otherMember.Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
		rows.Sidecars = append(rows.Sidecars, otherRows...)
		rows.Members = append(rows.Members, otherMember)
	}
	for _, sidecarId := range tagged {
		rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), TagIds: [][]byte{sidecarId.Bytes()}, AdmittedAt: 1})
	}
	writers := slices.Clone(self.writers)
	slices.SortFunc(writers, sidecar.Id.Cmp)
	view := self.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows, IdentityKeys: identityKeys,
		RepoReaders: map[sidecar.Id][]sidecar.Id{self.repoId: writers}, RepoWriters: map[sidecar.Id][]sidecar.Id{self.repoId: writers},
	})
	self.view = view
	for _, gkmClient := range self.gkmClients {
		gkmClient.AuthAdvanced(view)
	}
}

// The devices' verified state.
func (self *World) View() sidecar.GkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.view
}

// Sets what runs around each request the engine serves: before may lose the request or answer it instead, after may
// lose its answer.
func (self *World) SetIntercept(before func(request *http.Request) (*http.Response, error), after func(request *http.Request) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.before, self.after = before, after
}

// The devices' transport: the handler, every push's step 8 waited out on T2 before the answer goes back.
func (self *World) RoundTrip(request *http.Request) (*http.Response, error) {
	before, after := func() (func(*http.Request) (*http.Response, error), func(*http.Request) error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.before, self.after
	}()
	if before != nil {
		response, err := before(request)
		if err != nil || response != nil {
			return response, err
		}
	}
	recorder := httptest.NewRecorder()
	self.handler.ServeHTTP(recorder, request)
	if self.engine != nil && strings.Contains(request.URL.Path, "/push") {
		for {
			started, finished, changed := self.engine.StepEights()
			if started == finished {
				break
			}
			<-changed
		}
	}
	if after != nil {
		if err := after(request); err != nil {
			return nil, err
		}
	}
	return recorder.Result(), nil
}

// One device: a sidecar's evs client, its mount and daemon, and the clones its git works in.
type Device struct {
	world     *World
	Label     string
	SidecarId sidecar.Id
	ClientId  sidecar.Id
	Client    *sidecar.EvsClient
	Mounts    *sidecar.EvsMounts
	Mount     *sidecar.EvsLocalRepo
	// The repo's git-lfs store as the device's daemon serves it to its clones' agents, nil without WorldSettings.Lfs.
	Lfs    *sidecar.EvsLfsStore
	socket string
	// the device's own directory beside its state, short enough for a socket's path
	directory string
	// what the device's daemon did for its agents, nil without WorldSettings.Lfs
	lfsCalls *lfsCalls
	// the client's evs settings
	clientSettings *sidecar.EvsSettings
	// the remotes git's http and ssh fronts serve, by transport, each started at its first use (transport.go)
	remotesLock sync.Mutex
	remotes     map[string]*deviceRemote
	cancel      context.CancelFunc
	ran         chan error
}

// What a device is made as.
type DeviceSettings struct {
	// A repo admin, who may FORCE and DELETE a shared ref and sign an import.
	Admin bool
	// The client's evs settings beside the world's, nil for those.
	Client *sidecar.EvsSettings
	// A device of another member of the network, which the world makes for it, not of the world's own member.
	OtherMember bool
	// A tagged sidecar, a cloud agent's or an enclave's, which no member's row names.
	Tagged bool
}

// A new device of the world's member that writes the repo, its mount made and running.
func (self *World) Device(label string, settings *DeviceSettings) *Device {
	t := self.t
	t.Helper()
	if settings == nil {
		settings = &DeviceSettings{}
	}
	sidecarId := sidecar.NewId()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &sidecartest.FakeGkmSigner{SidecarId: sidecarId, PrivateKey: privateKey}
	first := false
	gkmClient := func() sidecar.GkmClient {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		first = len(self.signers) == 0
		self.signers[sidecarId] = signer
		if settings.OtherMember {
			self.otherMembers[sidecarId] = sidecar.NewId()
		}
		if settings.Tagged {
			self.tagged[sidecarId] = true
		}
		self.writers = append(self.writers, sidecarId)
		if settings.Admin || first {
			self.admins = append(self.admins, sidecarId)
		}
		gkmClient := self.gkm.Client(sidecarId, signer.Sign)
		self.gkmClients[sidecarId] = gkmClient
		self.publishWithLock()
		return gkmClient
	}()
	device := &Device{world: self, Label: label, SidecarId: sidecarId, ClientId: sidecar.NewId()}
	identity := &sidecar.SidecarIdentity{NetworkId: self.networkId, SidecarId: sidecarId, ClientId: device.ClientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	clientSettings := settings.Client
	if clientSettings == nil {
		clientSettings = self.settings.ClientSettings
	}
	if clientSettings == nil {
		clientSettings = sidecar.DefaultEvsSettings()
	}
	device.clientSettings = clientSettings
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    "https://evs.example",
		Transport: self,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(sidecarId)
			return self.issue(&sidecar.Principal{
				NetworkId: connect.Id(self.networkId), ClientId: connect.Id(device.ClientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(self.settings.TokenLifetime),
			})
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkmClient,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   self.View,
		Clock:    self.clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: clientSettings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	device.Client = client
	if self.settings.Format2 {
		// core's gates, as the composition reads them, admit the network
		client.SetFormat2Source(func() bool { return true })
		client.EnableFormat2Reader()
	}
	if first {
		self.placeRepo(gkmClient, sidecarId)
	}
	directory := shortDirectory(t)
	device.directory = directory
	home := filepath.Join(directory, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	runner, err := sidecar.NewEvsGitRunner(self.ctx, self.gitPath, home, clientSettings, self.clock)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := sidecar.NewEvsMounts(client, filepath.Join(directory, "state"), runner)
	if err != nil {
		t.Fatal(err)
	}
	device.Mounts = mounts
	mounts.SetOwnClients(func() ([]sidecar.Id, error) { return []sidecar.Id{device.ClientId}, nil })
	mount, err := mounts.Add(self.ctx, self.repoId, &sidecar.EvsMountArgs{AgentLabel: label})
	if err != nil {
		t.Fatal(err)
	}
	device.Mount = mount
	device.socket = filepath.Join(directory, "run", "d.sock")
	daemon, err := sidecar.NewDaemon(self.ctx, &sidecar.DaemonSettings{
		Instance: "default", StateDirectory: filepath.Join(directory, "daemon"), SocketPath: device.socket,
		Local: sidecar.DefaultSidecarSettings().LocalSettings, Version: daemonVersion, Log: sidecar.NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.RegisterMode(sidecar.DaemonModeGitHook, func(ctx context.Context, hello *sidecar.DaemonHello, stream io.ReadWriter) error {
		return mounts.ServeGitHook(ctx, hello.Service, stream)
	}); err != nil {
		t.Fatal(err)
	}
	// git-remote-ur's sessions go to the client's git service as ur daemon's composition hands them; this daemon
	// hosts no Sidecar, so <net> is not resolved among hosted networks (transport.go)
	if err := daemon.RegisterMode(sidecar.DaemonModeGit, func(ctx context.Context, hello *sidecar.DaemonHello, stream io.ReadWriter) error {
		_, repo, _ := strings.Cut(hello.Repo, "/")
		return client.ServeGit(ctx, &sidecar.DaemonGitSession{Hello: hello, Repo: repo, Service: hello.Service, Stream: stream})
	}); err != nil {
		t.Fatal(err)
	}
	if self.settings.Lfs != nil {
		device.serveLfs(daemon)
	}
	if len(self.settings.RemoteHelperCommand) != 0 {
		device.installRemoteHelper()
	}
	daemonRan := make(chan error, 1)
	go func() { daemonRan <- daemon.Run() }()
	t.Cleanup(func() {
		daemon.Close()
		<-daemonRan
	})
	if err := mounts.SetHookCommand(self.settings.HookCommand, []string{HookSocketVariable + "=" + device.socket}); err != nil {
		t.Fatal(err)
	}
	mountCtx, cancel := context.WithCancel(self.ctx)
	device.cancel = cancel
	device.ran = make(chan error, 1)
	go func() { device.ran <- mount.Run(mountCtx) }()
	t.Cleanup(device.Stop)
	self.stateLock.Lock()
	self.devices = append(self.devices, device)
	self.stateLock.Unlock()
	return device
}

// Stops the device's mount, as its daemon's exit would; a second call does nothing. The daemon still serves git's
// hooks, so an owned ref's push is taken and queued while nothing publishes it.
func (self *Device) Stop() {
	if self.cancel == nil {
		return
	}
	self.cancel()
	<-self.ran
	self.cancel = nil
}

// Starts the device's stopped mount again, as its daemon's restart would: the restart's steps, then the sync engine
// and the queue, which take up what was journaled; a running mount is left as it is.
func (self *Device) Start() {
	if self.cancel != nil {
		return
	}
	mountCtx, cancel := context.WithCancel(self.world.ctx)
	self.cancel = cancel
	self.ran = make(chan error, 1)
	go func() { self.ran <- self.Mount.Run(mountCtx) }()
}

// Places the repo as its creator would, its group the first device's: place/, repo/ active, and gkm's group form.
func (self *World) placeRepo(gkmClient sidecar.GkmClient, creatorId sidecar.Id) {
	t := self.t
	t.Helper()
	ctx := self.ctx
	if _, err := gkmClient.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: self.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL}); err != nil {
		t.Fatal(err)
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: self.cluster.ClusterId(), CreatorSidecarId: creatorId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(self.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: self.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsservice.RepoKey(self.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
}

// A directory short enough for a Unix socket's path, removed when the test ends.
func shortDirectory(t testing.TB) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "urg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return directory
}

// The device's committer email: <client_id>@ur.invalid.
func (self *Device) Email() string {
	return self.ClientId.String() + "@ur.invalid"
}

// Runs the world's git in dir, answering its combined output and whether it succeeded. In a world with git-lfs, git
// finds the world's git-lfs first on its PATH and the agent it starts finds the device's daemon (lfs.go); in one with
// git-remote-ur, git finds the world's helper, which finds the device's daemon (transport.go).
func (self *Device) GitIn(dir string, env []string, args ...string) (string, bool) {
	command := exec.Command(self.world.gitPath, append([]string{"-C", dir}, args...)...)
	command.Env = append([]string{"HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "PATH=" + self.gitSearchPath(), "LC_ALL=C"}, self.lfsEnvironment()...)
	command.Env = append(command.Env, self.remoteEnvironment()...)
	command.Env = append(command.Env, env...)
	out, err := command.CombinedOutput()
	return string(out), err == nil
}

// The PATH a device's git runs with: the world's git-lfs and git-remote-ur first, where the world has them.
func (self *Device) gitSearchPath() string {
	directories := []string{}
	if self.world.settings.Lfs != nil {
		directories = append(directories, self.lfsBin())
	}
	if len(self.world.settings.RemoteHelperCommand) != 0 {
		directories = append(directories, self.urBin())
	}
	return strings.Join(append(directories, os.Getenv("PATH")), string(os.PathListSeparator))
}

// git in dir that must succeed, its output.
func (self *Device) MustGit(dir string, args ...string) string {
	self.world.t.Helper()
	out, ok := self.GitIn(dir, nil, args...)
	if !ok {
		self.world.t.Fatalf("git %s: %s", strings.Join(args, " "), out)
	}
	return out
}

// A clone of the mount's bare repository, its committer this device's client under its label. In a world with git-lfs
// its agent is configured before the checkout, as ur mount add and git-remote-ur write it, so the checkout's smudge
// already reads through the daemon.
func (self *Device) Clone() string {
	t := self.world.t
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "clone")
	cloneArgs := []string{"clone", "-q", self.Mount.BareDir, dir}
	if self.world.settings.Lfs != nil {
		cloneArgs = []string{"clone", "-q", "--no-checkout", self.Mount.BareDir, dir}
	}
	if out, ok := self.GitIn(parent, nil, cloneArgs...); !ok {
		t.Fatalf("clone: %s", out)
	}
	for _, setting := range [][]string{
		{"user.name", self.Label}, {"user.email", self.Email()}, {"committer.name", self.Label}, {"committer.email", self.Email()},
	} {
		self.MustGit(dir, "config", setting[0], setting[1])
	}
	if self.world.settings.Lfs != nil {
		self.configureLfs(dir)
		if _, born := self.GitIn(dir, nil, "rev-parse", "--verify", "-q", "HEAD"); born {
			self.MustGit(dir, "checkout", "-q")
		}
	}
	return dir
}

// Commits files in a clone, a nil content removing its path, answering the commit's oid.
func (self *Device) Commit(dir string, message string, files map[string]*string) string {
	t := self.world.t
	t.Helper()
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if content == nil {
			if err := os.Remove(full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(*content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	self.MustGit(dir, "add", "-A")
	// stamped by the world's clock, which a world's Jump moves past real time
	date := fmt.Sprintf("@%d +0000", self.world.clock.Now().Unix())
	if out, ok := self.GitIn(dir, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}, "commit", "-q", "--allow-empty", "-m", message); !ok {
		t.Fatalf("git commit: %s", out)
	}
	return strings.TrimSpace(self.MustGit(dir, "rev-parse", "HEAD"))
}

// Pushes from a clone through a receive session of the device's daemon, answering git's porcelain output and whether
// every ref took.
func (self *Device) Push(dir string, args ...string) (string, bool) {
	session, closeSession := self.Mounts.OpenReceiveSession(self.Mount, self.Label)
	defer closeSession()
	return self.GitIn(dir, self.Mounts.ReceiveEnvironment(session), append([]string{"push", "--porcelain"}, args...)...)
}

// Replays the ref of name to evs's head into the bare repository.
func (self *Device) Replay(name string) error {
	refId, err := self.RefId(name)
	if err != nil {
		return err
	}
	return self.Mount.Sync().Replay(self.world.ctx, refId)
}

// The ref id of a ref's name bytes, under the repo's K_ref.
func (self *Device) RefId(name string) (sidecar.Id, error) {
	return self.Client.Repo(self.world.repoId).RefIdOf(self.world.ctx, []byte(name))
}

// The bare repository's gitRef, "" when it has none.
func (self *Device) LocalRef(gitRef string) string {
	out, ok := self.GitIn(self.Mount.BareDir, nil, "rev-parse", "--verify", "-q", gitRef)
	if !ok {
		return ""
	}
	return strings.TrimSpace(out)
}

// git fsck --strict over the bare repository: nil when it finds nothing.
func (self *Device) Fsck() error {
	out, ok := self.GitIn(self.Mount.BareDir, nil, "fsck", "--strict", "--no-dangling")
	if !ok || strings.Contains(out, "error") || strings.Contains(out, "missing") {
		return fmt.Errorf("git fsck --strict: %s", out)
	}
	return nil
}

// The commit, tree and parents of rev in dir, as git prints them, for comparing two devices' copies.
func (self *Device) Shape(dir string, rev string) string {
	return strings.TrimSpace(self.MustGit(dir, "log", "-1", "--format=%H %T %P", rev))
}

// The refs the device's bare repository advertises to a client: what ls-remote shows.
func (self *Device) Advertised() []string {
	out := self.MustGit(self.world.t.TempDir(), "ls-remote", self.Mount.BareDir)
	refs := []string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 {
			refs = append(refs, fields[1])
		}
	}
	return refs
}

// Exports every ref the device holds into a new bare repository, answering its directory and each ref's tip.
func (self *Device) Export(refNames ...string) (string, map[string]string) {
	t := self.world.t
	t.Helper()
	dir := filepath.Join(t.TempDir(), "export.git")
	names := [][]byte{}
	for _, name := range refNames {
		names = append(names, []byte(name))
	}
	result, err := self.Client.Repo(self.world.repoId).Export(self.world.ctx, &sidecar.EvsExportArgs{Dir: dir, RefNames: names})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	tips := map[string]string{}
	for _, ref := range result.Refs {
		tips[ref.GitRef] = ref.Tip.String()
	}
	return dir, tips
}

// The test a hook command names: it relays the hook to the daemon whose socket HookSocketVariable names, then
// exits with the daemon's code. It returns at once when the variable is unset, so the test passes as itself.
func HookHelper() {
	socket := os.Getenv(HookSocketVariable)
	if socket == "" {
		return
	}
	hook := os.Args[len(os.Args)-1]
	code := sidecar.EvsGitHookRelay(context.Background(), &sidecar.EvsGitHookRelayArgs{
		Hook: hook,
		Dial: func(ctx context.Context) (io.ReadWriteCloser, error) {
			client, err := sidecar.DialDaemon(ctx, socket, &sidecar.DaemonHello{Mode: sidecar.DaemonModeGitHook, Version: daemonVersion, Service: hook})
			if err != nil {
				return nil, err
			}
			return &daemonStream{ReadWriter: client.Stream(), client: client}, nil
		},
		Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	os.Exit(code)
}

// A daemon session's stream, a hook's or git-remote-ur's, closed with its client.
type daemonStream struct {
	io.ReadWriter
	client *sidecar.DaemonClient
}

func (self *daemonStream) Close() error {
	return self.client.Close()
}

// A content pointer, for Commit's files.
func Text(text string) *string {
	return &text
}

// Every device's bare repository's main, which they agree on once each replayed it.
func (self *World) Devices() []*Device {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.devices)
}

// evs's refusal of code at status, as an intercept answers in the engine's place.
func Refusal(status int, code protocol.EvsRefusalCode) *http.Response {
	body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: code, Recorded: true})
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Content-Type", "application/x-protobuf")
	recorder.WriteHeader(status)
	recorder.Write(body)
	return recorder.Result()
}
