// Path epochs end to end on T2 (DESIGN-DETAILS 9.6's reads, writes and mapper rows against evsservice; FS-4;
// EVS1-M2-28 and EVS1-M2-47): sidecar.EvsClient devices against an evsservice.EvsEngine over FakeHost's stores,
// FakeGkm's ladder rotating at a removal, a device's mapper building, uploading and committing the PATH_EPOCH through
// evs's 5e, and evs's copy job run as taskworker would run it.
//
//	cut-over  files written in epoch 1, one push of them rooted, read, listed and walked by History by a reader pinned
//	          before the removal and by one first reading after the cut-over, before the copy and after it (9.1 B);
//	          a creation on the blocking ref while the removal is due sends no token of its name and waits (F), and
//	          lands in epoch 2 once the mapper committed
//	409       9.1 C: a creation planned in epoch 1 and in flight across a cut-over, after another writer created the
//	          same name, answers 409 on its retoken, the other's file standing under one row
//	mapper    a map in several parts whose upload fails after the first resumes on a client restarted over the same
//	          store, uploading the rest from disk, and commits
//
// The devices' clock reads the world's and answers every wait at once, so a creation waiting out a due spins through
// its retries without sleeping; the engine's clock is the world's. Every request goes through the world's transport,
// which may hold one device's request while the test acts.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
)

// A general repo on one engine, its devices, and the authorization log they all follow.
type epochWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *FakeClock
	host      *FakeHost
	cluster   sidecar.BlobCluster
	networkId sidecar.Id
	repoId    sidecar.Id
	clientId  sidecar.Id
	memberId  sidecar.Id
	kind      protocol.RepoKind
	log       *FakeGkmAuthLog
	gkm       *FakeGkm
	engine    *evsservice.EvsEngine
	gate      *epochGateViews
	signers   map[string]*FakeGkmSigner

	stateLock sync.Mutex
	view      *FakeGkmAuthView
	devices   []*epochDevice
	// called before a device's request is served, nil for none; an error fails the request as a transport would
	intercept func(device *epochDevice, request *http.Request) error
}

// evs's view of the authorization state, the world's newest.
type epochGateViews struct {
	networkId sidecar.Id

	stateLock sync.Mutex
	view      sidecar.GkmAuthView
}

func (self *epochGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if networkId != self.networkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.view, evsservice.EvsAuthAllowed
}

// One device: a signer's sidecar with its own gkm client, store and evs client.
type epochDevice struct {
	world  *epochWorld
	label  string
	signer *FakeGkmSigner
	gkm    sidecar.GkmClient
	store  sidecar.SidecarStore
	client *sidecar.EvsClient
	repo   *sidecar.EvsRepo
}

// A device's clock: the world's time, every wait answered at once, and AfterFunc on the world's clock.
type epochDeviceClock struct {
	clock *FakeClock
}

func (self *epochDeviceClock) Now() time.Time {
	return self.clock.Now()
}

func (self *epochDeviceClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *epochDeviceClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.clock.AfterFunc(timeout, function)
}

// The labels of every sidecar the world knows: three writers, a reader, and a reader the test removes.
var epochWorldLabels = []string{"w", "v", "m", "r", "d"}

// A general repo created by w, read by every label and written by w, v and m.
func newEpochWorld(t *testing.T) *epochWorld {
	t.Helper()
	return newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_GENERAL)
}

// newEpochWorld's repo of kind.
func newEpochWorldOf(t *testing.T, kind protocol.RepoKind) *epochWorld {
	t.Helper()
	ctx := t.Context()
	clock := NewFakeClock(DefaultClockStart())
	hostSettings := DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := NewFakeHost(ctx, clock, nil, nil, hostSettings)
	RegisterEvsTwins(host.Redis)
	world := &epochWorld{
		t: t, ctx: ctx, clock: clock, host: host,
		networkId: sidecar.NewId(), repoId: sidecar.NewId(), clientId: sidecar.NewId(), memberId: sidecar.NewId(),
		kind: kind, log: NewFakeGkmAuthLog(), signers: map[string]*FakeGkmSigner{},
	}
	for _, label := range epochWorldLabels {
		world.signers[label] = NewFakeGkmSigner()
	}
	world.gate = &epochGateViews{networkId: world.networkId}
	network := connect.Id(world.networkId).String()
	if err := host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(world.networkId), 1<<40)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	world.cluster = cluster
	world.advance([]string{"w", "v", "m", "r", "d"}, 0, nil)
	world.gkm = NewFakeGkm(clock, host.Blobs, nil)
	creator := world.gkm.Client(world.signers["w"].SidecarId, world.signers["w"].Sign)
	creator.AuthAdvanced(world.currentView())
	if _, err := creator.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: kind}); err != nil {
		t.Fatal(err)
	}
	usage, err := evsservice.NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKey := sha256.Sum256([]byte("epoch world receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-48 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	settings.RepoCacheTtl = 0
	world.engine, err = evsservice.NewEvsEngine(ctx, host.ServiceHost(), settings, &evsservice.EvsEngineDeps{
		AuthState: &depositAuthState{networkId: world.networkId, kind: kind},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: world.gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: world.signers["w"].SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: kind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, evsservice.RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	return world
}

// Appends a position at which readers read the repo and w, v and m write it, holders_shrunk_at at shrunkAt, with the
// reader expiries given, and gives it to evs and every device.
func (self *epochWorld) advance(readers []string, shrunkAt uint64, expiries map[string]time.Time) *FakeGkmAuthView {
	fixture := &FakeGkmAuthFixture{
		Rows:               FakeGkmAuthRows(&protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: self.kind, HoldersShrunkAt: shrunkAt}),
		IdentityKeys:       map[sidecar.Id][]byte{},
		RepoReaders:        map[sidecar.Id][]sidecar.Id{},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{},
	}
	sidecarIds := []sidecar.Id{}
	for _, label := range epochWorldLabels {
		signer := self.signers[label]
		fixture.IdentityKeys[signer.SidecarId] = signer.PublicKey()
		sidecarIds = append(sidecarIds, signer.SidecarId)
	}
	sidecarRows, memberRow := FakeGkmAuthMemberDevices(self.memberId, sidecarIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	for _, label := range readers {
		fixture.RepoReaders[self.repoId] = append(fixture.RepoReaders[self.repoId], self.signers[label].SidecarId)
	}
	for _, label := range []string{"w", "v", "m"} {
		fixture.RepoWriters[self.repoId] = append(fixture.RepoWriters[self.repoId], self.signers[label].SidecarId)
	}
	if 0 < len(expiries) {
		fixture.RepoReaderExpiries[self.repoId] = map[sidecar.Id]time.Time{}
		for label, at := range expiries {
			fixture.RepoReaderExpiries[self.repoId][self.signers[label].SidecarId] = at
		}
	}
	view := self.log.Append(fixture)
	self.stateLock.Lock()
	self.view = view
	devices := slices.Clone(self.devices)
	self.stateLock.Unlock()
	self.gate.stateLock.Lock()
	self.gate.view = view
	self.gate.stateLock.Unlock()
	for _, device := range devices {
		device.gkm.AuthAdvanced(view)
	}
	return view
}

// The newest position.
func (self *epochWorld) currentView() *FakeGkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.view
}

// A device of label with a store of its own.
func (self *epochWorld) device(label string, mutate func(settings *sidecar.EvsSettings)) *epochDevice {
	return self.deviceOn(label, NewFakeStore().Root(), mutate)
}

// A device of label over store: a restarted device when another had it.
func (self *epochWorld) deviceOn(label string, store sidecar.SidecarStore, mutate func(settings *sidecar.EvsSettings)) *epochDevice {
	self.t.Helper()
	signer := self.signers[label]
	device := &epochDevice{world: self, label: label, signer: signer, store: store, gkm: self.gkm.Client(signer.SidecarId, signer.Sign)}
	device.gkm.AuthAdvanced(self.currentView())
	identity := &sidecar.SidecarIdentity{NetworkId: self.networkId, SidecarId: signer.SidecarId, ClientId: self.clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	settings := sidecar.DefaultEvsSettings()
	if mutate != nil {
		mutate(settings)
	}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    "https://evs.example",
		Transport: &epochTransport{world: self, device: device},
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(signer.SidecarId)
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      device.gkm,
		Store:    store,
		Config:   func() sidecar.GkmAuthView { return self.currentView() },
		Clock:    &epochDeviceClock{clock: self.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	device.client = client
	device.repo = client.Repo(self.repoId)
	self.stateLock.Lock()
	self.devices = append(self.devices, device)
	self.stateLock.Unlock()
	return device
}

// A device's transport: the engine's handler, its step 8s waited out after each push.
type epochTransport struct {
	world  *epochWorld
	device *epochDevice
}

func (self *epochTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	self.world.stateLock.Lock()
	intercept := self.world.intercept
	self.world.stateLock.Unlock()
	if intercept != nil {
		if err := intercept(self.device, request); err != nil {
			return nil, err
		}
	}
	recorder := httptest.NewRecorder()
	self.world.engine.Handler().ServeHTTP(recorder, request)
	if strings.HasSuffix(request.URL.Path, "/push") {
		for {
			started, finished, changed := self.world.engine.StepEights()
			if started == finished {
				break
			}
			<-changed
		}
	}
	return recorder.Result(), nil
}

// Sets the request hook, nil to clear it.
func (self *epochWorld) setIntercept(intercept func(device *epochDevice, request *http.Request) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.intercept = intercept
}

// The main ref's id.
func (self *epochWorld) mainRefId(device *epochDevice) sidecar.Id {
	self.t.Helper()
	repoKey, err := device.gkm.CurrentRepoKey(self.ctx, self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	refKey, err := sidecar.NewEvsRefKey(repoKey)
	if err != nil {
		self.t.Fatal(err)
	}
	refId, err := sidecar.EvsRefId(refKey, sidecar.EvsMainRefName)
	if err != nil {
		self.t.Fatal(err)
	}
	return refId
}

// The main ref's head as the cluster holds it.
func (self *epochWorld) head(refId sidecar.Id) *protocol.EvsHead {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, evsservice.HeadKey(self.repoId, refId))
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	headBytes, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	head := &protocol.EvsHead{}
	if err := proto.Unmarshal(headBytes, head); err != nil {
		self.t.Fatal(err)
	}
	return head
}

// Runs evs's copy into epoch until it ends, as taskworker runs the job and its successors, at a rate the world's
// frozen clock never holds.
func (self *epochWorld) copyInto(refId sidecar.Id, epoch uint64) *evsservice.EvsEpochCopyResult {
	self.t.Helper()
	settings := evsservice.DefaultEvsSettings()
	settings.CopyRepoOpsPerSecond = 1 << 20
	settings.CopyRepoSourcesOpsPerSecond = 1 << 20
	self.host.Budget.SetCopyOpsPerSecond("meta-1", 1<<20)
	var last *evsservice.EvsEpochCopyResult
	for range 16 {
		result, err := evsservice.RunPathEpochCopy(self.ctx, self.host.ServiceHost(), &evsservice.EvsEpochCopyDeps{Settings: settings}, evsservice.EvsEpochCopyArgs(self.repoId, refId, epoch))
		if err != nil {
			self.t.Fatalf("the copy into epoch %d: %v", epoch, err)
		}
		last = result
		if result.SourcesDropped || result.Superseded || result.MovesLeft == 0 {
			return result
		}
	}
	return last
}

// Writes each path's content in one push, removing a path whose content is nil.
func (self *epochDevice) writePaths(files map[string][]byte) (*sidecar.EvsWritePathsResult, error) {
	writes := []*sidecar.EvsPathWrite{}
	paths := []string{}
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		write := &sidecar.EvsPathWrite{Path: path, Remove: files[path] == nil}
		if files[path] != nil {
			write.Content = bytes.NewReader(files[path])
		}
		writes = append(writes, write)
	}
	return self.repo.WritePaths(self.world.ctx, &sidecar.EvsWritePathsArgs{Writes: writes})
}

// Writes one path.
func (self *epochDevice) write(path string, content []byte) (*sidecar.EvsWritePathsResult, error) {
	return self.writePaths(map[string][]byte{path: content})
}

// A path's newest content, verified.
func (self *epochDevice) read(path string) ([]byte, *sidecar.EvsFileInfo, error) {
	out := &bytes.Buffer{}
	info, err := self.repo.ReadHead(self.world.ctx, &sidecar.EvsReadArgs{Path: path}, out)
	return out.Bytes(), info, err
}

// A directory's names, verified, sorted.
func (self *epochDevice) list(path string) ([]string, error) {
	listing, err := self.repo.List(self.world.ctx, &sidecar.EvsReadArgs{Path: path})
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, entry := range listing.Entries {
		names = append(names, string(entry.Name))
	}
	slices.Sort(names)
	return names, nil
}

// The token path of path in epoch, as a holder of that epoch derives it.
func (self *epochDevice) tokenPath(path string, epoch uint64) sidecar.EvsTokenPath {
	self.world.t.Helper()
	repoKey, err := self.gkm.RepoKey(self.world.ctx, self.world.repoId, epoch)
	if err != nil {
		self.world.t.Fatal(err)
	}
	pathKey, err := sidecar.NewEvsPathKey(repoKey)
	if err != nil {
		self.world.t.Fatal(err)
	}
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	tokenPath, err := sidecar.EvsPathTokens(pathKey, names)
	if err != nil {
		self.world.t.Fatal(err)
	}
	return tokenPath
}

// Every request body the world's transport served, for the token checks below. Off until record is called.
type epochRequestLog struct {
	stateLock sync.Mutex
	bodies    [][]byte
}

// Records every request body from now on, leaving the hook the test sets after it in place of this one.
func (self *epochWorld) record() *epochRequestLog {
	requests := &epochRequestLog{}
	self.setIntercept(func(device *epochDevice, request *http.Request) error {
		if request.Body == nil {
			return nil
		}
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		requests.stateLock.Lock()
		defer requests.stateLock.Unlock()
		requests.bodies = append(requests.bodies, body)
		return nil
	})
	return requests
}

// Whether any recorded body holds the last token of tokenPath, which names a path whatever its framing.
func (self *epochRequestLog) named(tokenPath sidecar.EvsTokenPath) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	token := tokenPath.Last().Bytes()
	for _, body := range self.bodies {
		if bytes.Contains(body, token) {
			return true
		}
	}
	return false
}

// How many bodies it holds.
func (self *epochRequestLog) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.bodies)
}

// Content of path in its writing's round, so every version differs.
func epochContent(path string, round int) []byte {
	return []byte(fmt.Sprintf("%s, round %d", path, round))
}

// 9.1 B, F and the copy end to end: twelve files written in one rooted push and docs/old.md written twice in epoch 1;
// d removed (a shrink, so the crossing is immediate on this blocking ref); w's creation of docs/new.md sends no token of
// the name and answers EVS_PATH_EPOCH_DUE; w maps, being the device whose EnsureWritable rotated, and its PATH_EPOCH
// commits epoch 2 over source 1; a reader pinned before the removal and one first reading now read every file, list
// the directories and walk docs/old.md's History, before the copy and after it; the copy drains and drops the source;
// and the creation then lands in epoch 2.
func TestEvsPathEpochCutOverEndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	w := world.device("w", nil)
	pinned := world.device("r", nil)
	bulk := map[string][]byte{}
	for i := range 12 {
		path := fmt.Sprintf("bulk/f%02d", i)
		bulk[path] = epochContent(path, 1)
	}
	if _, err := w.writePaths(bulk); err != nil {
		t.Fatalf("the rooted push: %v", err)
	}
	for round := 1; round <= 2; round += 1 {
		if _, err := w.write("docs/old.md", epochContent("docs/old.md", round)); err != nil {
			t.Fatalf("docs/old.md round %d: %v", round, err)
		}
	}
	refId := world.mainRefId(w)
	if content, _, err := pinned.read("docs/old.md"); err != nil || !bytes.Equal(content, epochContent("docs/old.md", 2)) {
		t.Fatalf("the pinned reader before the removal: %q %v", content, err)
	}
	if content, _, err := pinned.read("bulk/f03"); err != nil || !bytes.Equal(content, bulk["bulk/f03"]) {
		t.Fatalf("the pinned reader's bulk/f03 before the removal: %q %v", content, err)
	}

	// d leaves: a shrink at the next position, so w's next EnsureWritable rotates REMOVE and the crossing is immediate
	world.advance([]string{"w", "v", "m", "r"}, 2, nil)
	requests := world.record()
	if _, err := w.write("docs/new.md", epochContent("docs/new.md", 1)); !errors.Is(err, sidecar.ErrEvsPathEpochDue) {
		t.Fatalf("a creation while the removal is due: %v", err)
	}
	if requests.named(w.tokenPath("docs/new.md", 1)) || requests.named(w.tokenPath("docs/new.md", 2)) {
		t.Fatal("a token of docs/new.md reached evs while the removal was due")
	}
	if 0 == requests.count() {
		t.Fatal("the creation read nothing")
	}
	world.setIntercept(nil)
	// a modification still writes, crossing the removal and recording the due
	if _, err := w.write("docs/old.md", epochContent("docs/old.md", 3)); err != nil {
		t.Fatalf("a modification while the removal is due: %v", err)
	}
	head := world.head(refId)
	if head.GetPathEpoch().GetDueGeneration() != 2 || !head.GetPathEpoch().GetDueBlocksCreation() {
		t.Fatalf("the due evs recorded: %v", head.GetPathEpoch())
	}
	status, err := w.repo.PathEpochStatus(world.ctx, nil)
	if err != nil || status.Current != 1 || status.DueGeneration != 2 || status.Class != "immediate" {
		t.Fatalf("w's status while due: %+v %v", status, err)
	}

	// w rotated to the removal, so its mapper starts at once
	if err := w.repo.TickMapper(world.ctx, refId); err != nil {
		t.Fatalf("w's mapper: %v", err)
	}
	head = world.head(refId)
	if current := head.GetPathEpoch().GetCurrent(); current != 2 {
		t.Fatalf("the epoch after the mapper: %v", head.GetPathEpoch())
	}
	if sources := head.GetPathEpoch().GetSources(); len(sources) != 1 || sources[0].GetEpoch() != 1 {
		t.Fatalf("the sources after the cut-over: %v", sources)
	}

	fresh := world.device("r", nil)
	readAll := func(when string) {
		t.Helper()
		for _, reader := range []*epochDevice{pinned, fresh} {
			if content, _, err := reader.read("docs/old.md"); err != nil || !bytes.Equal(content, epochContent("docs/old.md", 3)) {
				t.Fatalf("%s: docs/old.md: %q %v", when, content, err)
			}
			for path, want := range bulk {
				if content, _, err := reader.read(path); err != nil || !bytes.Equal(content, want) {
					t.Fatalf("%s: %s: %q %v", when, path, content, err)
				}
			}
			if names, err := reader.list("bulk"); err != nil || len(names) != 12 {
				t.Fatalf("%s: the bulk listing: %v %v", when, names, err)
			}
			if names, err := reader.list("docs"); err != nil || !slices.Equal(names, []string{"old.md"}) {
				t.Fatalf("%s: the docs listing: %v %v", when, names, err)
			}
			if names, err := reader.list(""); err != nil || !slices.Equal(names, []string{"bulk", "docs"}) {
				t.Fatalf("%s: the root listing: %v %v", when, names, err)
			}
			history, err := reader.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: "docs/old.md"})
			if err != nil || len(history.Versions) != 3 {
				t.Fatalf("%s: docs/old.md's history: %v %v", when, history, err)
			}
		}
	}
	readAll("before the copy")
	result := world.copyInto(refId, 2)
	if !result.SourcesDropped || 0 < result.MissedCount {
		t.Fatalf("the copy: %+v", result)
	}
	if sources := world.head(refId).GetPathEpoch().GetSources(); len(sources) != 0 {
		t.Fatalf("sources after the copy: %v", sources)
	}
	readAll("after the copy")

	// the creation lands in epoch 2
	if _, err := w.write("docs/new.md", epochContent("docs/new.md", 1)); err != nil {
		t.Fatalf("the creation after the cut-over: %v", err)
	}
	if content, _, err := fresh.read("docs/new.md"); err != nil || !bytes.Equal(content, epochContent("docs/new.md", 1)) {
		t.Fatalf("docs/new.md: %q %v", content, err)
	}
	if names, err := fresh.list("docs"); err != nil || !slices.Equal(names, []string{"new.md", "old.md"}) {
		t.Fatalf("the docs listing at the end: %v %v", names, err)
	}
}

// QD-681 end to end (question evs1-m2-28-rooted-delta-proofs): a writer's second 12-file push into one directory
// plans, each new name's read walking the first push, whose list is under changes_root and changed the directory by a
// delta; a device pinned below both pushes reads a file that was there before them and one each push created, and
// lists the directory while both deltas stand unfolded, each verified by its own proof; and a third push by another
// writer, pinned below them, lands the same way.
func TestEvsSecondRootedPushIntoADirectoryPlansAndReadsEndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	w := world.device("w", nil)
	pinned := world.device("r", nil)
	other := world.device("v", nil)
	if _, err := w.write("bulk/keep", epochContent("bulk/keep", 1)); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*epochDevice{pinned, other} {
		if content, _, err := device.read("bulk/keep"); err != nil || !bytes.Equal(content, epochContent("bulk/keep", 1)) {
			t.Fatalf("bulk/keep before the pushes: %q %v", content, err)
		}
		if names, err := device.list("bulk"); err != nil || !slices.Equal(names, []string{"keep"}) {
			t.Fatalf("the listing before the pushes: %v %v", names, err)
		}
	}
	batch := func(label string) map[string][]byte {
		files := map[string][]byte{}
		for i := range 12 {
			path := fmt.Sprintf("bulk/%s%02d", label, i)
			files[path] = epochContent(path, 1)
		}
		return files
	}
	first, second, third := batch("a"), batch("b"), batch("c")
	if _, err := w.writePaths(first); err != nil {
		t.Fatalf("the first 12-file push: %v", err)
	}
	if _, err := w.writePaths(second); err != nil {
		t.Fatalf("the second 12-file push into the directory: %v", err)
	}
	refId := world.mainRefId(w)
	if head := world.head(refId); head.GetFoldedThrough() != 0 && head.GetVersion() <= head.GetFoldedThrough() {
		t.Fatalf("the pushes are folded at %d of %d: nothing unfolded is read", head.GetFoldedThrough(), head.GetVersion())
	}
	want := []string{"keep"}
	for _, files := range []map[string][]byte{first, second} {
		for path := range files {
			want = append(want, strings.TrimPrefix(path, "bulk/"))
		}
	}
	slices.Sort(want)
	if content, _, err := pinned.read("bulk/keep"); err != nil || !bytes.Equal(content, epochContent("bulk/keep", 1)) {
		t.Fatalf("bulk/keep across both pushes: %q %v", content, err)
	}
	for _, path := range []string{"bulk/a03", "bulk/b07"} {
		if content, _, err := pinned.read(path); err != nil || !bytes.Equal(content, epochContent(path, 1)) {
			t.Fatalf("%s: %q %v", path, content, err)
		}
	}
	if names, err := pinned.list("bulk"); err != nil || !slices.Equal(names, want) {
		t.Fatalf("the listing with both deltas unfolded: %v %v", names, err)
	}
	// another writer, pinned below both pushes, plans its own 12 files into the directory
	if _, err := other.writePaths(third); err != nil {
		t.Fatalf("a third 12-file push by a writer pinned below the first two: %v", err)
	}
	for path := range third {
		want = append(want, strings.TrimPrefix(path, "bulk/"))
	}
	slices.Sort(want)
	for _, device := range []*epochDevice{pinned, w, other} {
		if names, err := device.list("bulk"); err != nil || !slices.Equal(names, want) {
			t.Fatalf("%s's listing after the third push: %v %v", device.label, names, err)
		}
	}
}

// Whether request is a one-part push, POST .../push.
func epochIsPush(request *http.Request) bool {
	return request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push")
}

// Whether request uploads a map part, POST .../path-epoch.
func epochIsMapPart(request *http.Request) bool {
	return request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/path-epoch")
}

// 9.1 C end to end: d's access expires, so the next generation is a batched REMOVE and creation goes on in epoch 1. w
// plans docs/report.md in epoch 1, where no row names it; before w's push reaches evs, v creates the same name in
// epoch 1 and maps, and its PATH_EPOCH commits epoch 2 over source 1. w's push is refused 412 PATH_EPOCH; its retoken
// lowers the name's floor to epoch 1 and names it there as a source, where evs finds v's file: 409, and v's file
// stands under one row, before the copy and after it.
func TestEvsPathEpochCreationAcrossACutOverAnswers409EndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	world.advance([]string{"w", "v", "m", "r", "d"}, 0, map[string]time.Time{"d": world.clock.Now().Add(time.Hour)})
	w := world.device("w", nil)
	// v maps a batched due at once: its lead covers the whole day, and its spread is nothing
	v := world.device("v", func(settings *sidecar.EvsSettings) {
		settings.MapperBatchedLead = 48 * time.Hour
		settings.MapperSpread = time.Nanosecond
	})
	if _, err := w.write("docs/keep.md", epochContent("docs/keep.md", 1)); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(w)
	world.clock.Advance(2 * time.Hour)

	var once sync.Once
	var interceptErr error
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if device != w || !epochIsPush(request) {
			return nil
		}
		once.Do(func() {
			world.setIntercept(nil)
			if _, err := v.write("docs/report.md", epochContent("docs/report.md", 1)); err != nil {
				interceptErr = fmt.Errorf("v's creation: %w", err)
				return
			}
			if err := v.repo.TickMapper(world.ctx, refId); err != nil {
				interceptErr = fmt.Errorf("v's mapper: %w", err)
			}
		})
		return nil
	})
	_, err := w.write("docs/report.md", epochContent("docs/report.md", 2))
	if interceptErr != nil {
		t.Fatal(interceptErr)
	}
	if head := world.head(refId); head.GetPathEpoch().GetCurrent() != 2 || head.GetPathEpoch().GetDueBlocksCreation() {
		t.Fatalf("the cut-over: %v", head.GetPathEpoch())
	}
	if !sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT) {
		t.Fatalf("w's creation across the cut-over: %v, want 409 PATH_CONFLICT", err)
	}
	check := func(when string) {
		t.Helper()
		reader := world.device("r", nil)
		if content, _, err := reader.read("docs/report.md"); err != nil || !bytes.Equal(content, epochContent("docs/report.md", 1)) {
			t.Fatalf("%s: docs/report.md: %q %v", when, content, err)
		}
		if names, err := reader.list("docs"); err != nil || !slices.Equal(names, []string{"keep.md", "report.md"}) {
			t.Fatalf("%s: the docs listing: %v %v", when, names, err)
		}
	}
	check("before the copy")
	if result := world.copyInto(refId, 2); !result.SourcesDropped || 0 < result.MissedCount {
		t.Fatalf("the copy: %+v", result)
	}
	check("after the copy")
	// w writes it now as a modification of v's version
	if _, err := w.write("docs/report.md", epochContent("docs/report.md", 3)); err != nil {
		t.Fatalf("w's modification: %v", err)
	}
}

// FS-4's mapper half, a kill mid-upload, end to end: a map of several parts whose second part's upload fails; the
// device restarted over the same store resumes from its job record, uploads the parts not yet marked from disk, and
// commits, evs taking the parts the first run left.
func TestEvsPathEpochMapperResumesEndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	small := func(settings *sidecar.EvsSettings) {
		settings.MapPartFillByteCount = 2 * 1024
		settings.MapUploadCount = 1
	}
	w := world.device("w", small)
	files := map[string][]byte{}
	for i := range 40 {
		path := fmt.Sprintf("tree/d%d/f%02d", i%4, i)
		files[path] = epochContent(path, 1)
	}
	if _, err := w.writePaths(files); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(w)
	world.advance([]string{"w", "v", "m", "r"}, 2, nil)
	// a modification rotates w to the removal and records the due
	if _, err := w.write("tree/d0/f00", epochContent("tree/d0/f00", 2)); err != nil {
		t.Fatal(err)
	}
	parts := 0
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if !epochIsMapPart(request) {
			return nil
		}
		parts += 1
		if 1 < parts {
			return errors.New("the link went down")
		}
		return nil
	})
	if err := w.repo.TickMapper(world.ctx, refId); err == nil {
		t.Fatal("a mapper whose upload failed committed")
	}
	if head := world.head(refId); head.GetPathEpoch().GetCurrent() != 1 {
		t.Fatalf("the epoch after the failed upload: %v", head.GetPathEpoch())
	}
	status, err := w.repo.PathEpochStatus(world.ctx, nil)
	if err != nil || status.State != sidecar.EvsPathEpochStateUploading || status.PartsUploaded != 1 || status.PartCount < 3 {
		t.Fatalf("the status after the failed upload: %+v %v", status, err)
	}
	partCount := status.PartCount
	resumed := 0
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if epochIsMapPart(request) {
			resumed += 1
		}
		return nil
	})
	restarted := world.deviceOn("w", w.store, small)
	if err := restarted.repo.TickMapper(world.ctx, refId); err != nil {
		t.Fatalf("the restarted mapper: %v", err)
	}
	world.setIntercept(nil)
	if resumed != partCount-1 {
		t.Fatalf("the restart uploaded %d parts of %d, one already up", resumed, partCount)
	}
	head := world.head(refId)
	if head.GetPathEpoch().GetCurrent() != 2 {
		t.Fatalf("the epoch after the resume: %v", head.GetPathEpoch())
	}
	if result := world.copyInto(refId, 2); !result.SourcesDropped || 0 < result.MissedCount {
		t.Fatalf("the copy: %+v", result)
	}
	reader := world.device("r", nil)
	for path, want := range files {
		if path == "tree/d0/f00" {
			want = epochContent(path, 2)
		}
		if content, _, err := reader.read(path); err != nil || !bytes.Equal(content, want) {
			t.Fatalf("%s after the copy: %q %v", path, content, err)
		}
	}
}

// The slot/ objects the cluster holds for the repo, by key.
func (self *epochWorld) slotKeys() []string {
	keys := []string{}
	prefix := strings.TrimSuffix(evsservice.SlotKey(self.repoId, sidecar.Id{}), sidecar.EvsKeyId(sidecar.Id{}))
	for key := range self.host.Blobs.Dump() {
		_, objectKey, _ := strings.Cut(key, "/")
		if strings.HasPrefix(objectKey, prefix) {
			keys = append(keys, objectKey)
		}
	}
	slices.Sort(keys)
	return keys
}

// The slot ids among after that before does not hold.
func epochNewSlots(before []string, after []string) []sidecar.Id {
	slotIds := []sidecar.Id{}
	for _, key := range after {
		if slices.Contains(before, key) {
			continue
		}
		slotId, err := sidecar.ParseId(key[strings.LastIndex(key, "/")+1:])
		if err == nil {
			slotIds = append(slotIds, slotId)
		}
	}
	return slotIds
}

// Record-class writes end to end (§11.6's object key row; EVS1-M2-30's slot-keyed chains): in a record repo every
// chain's key goes in a slot of its own. A small file, which a general repo would inline, and a larger one each
// introduce one slot and read back; a diff on the small one seals under its chain's slot key, introducing none; a
// CLOSURE re-checkpoints it under a new slot, and an ERASE of the old slot's key leaves the closure's version
// reading and the versions before it opening no more.
func TestEvsRecordClassWritesSlotKeyedEndToEnd(t *testing.T) {
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.device("w", nil)
	reader := world.device("r", nil)
	small := bytes.Repeat([]byte("an entry of the ledger; "), 300)
	if _, err := w.write("ledger/a", small); err != nil {
		t.Fatalf("the small entry: %v", err)
	}
	afterSmall := world.slotKeys()
	if len(afterSmall) != 1 {
		t.Fatalf("%d slots after the small entry", len(afterSmall))
	}
	large := bytes.Repeat([]byte("a larger entry; "), 20000)
	if _, err := w.write("ledger/b", large); err != nil {
		t.Fatalf("the large entry: %v", err)
	}
	afterLarge := world.slotKeys()
	if len(afterLarge) != 2 {
		t.Fatalf("%d slots after the large entry", len(afterLarge))
	}
	for path, want := range map[string][]byte{"ledger/a": small, "ledger/b": large} {
		if content, _, err := reader.read(path); err != nil || !bytes.Equal(content, want) {
			t.Fatalf("%s: %d bytes %v", path, len(content), err)
		}
	}
	// a small change: a diff under the chain's own slot key, no new slot
	changed := append(bytes.Clone(small[:len(small)-10]), []byte("a new tail")...)
	if _, err := w.write("ledger/a", changed); err != nil {
		t.Fatalf("the change: %v", err)
	}
	if slots := world.slotKeys(); len(slots) != 2 {
		t.Fatalf("%d slots after a diff", len(slots))
	}
	if content, _, err := reader.read("ledger/a"); err != nil || !bytes.Equal(content, changed) {
		t.Fatalf("ledger/a after the diff: %v", err)
	}
	// the CLOSURE: ledger/a again under a fresh key in a new slot, its erased list naming the old chain's key
	oldSlot := epochNewSlots(nil, afterSmall)[0]
	erased := []*sidecar.EvsErasedKey{{SlotId: oldSlot, KeyIndex: 0}}
	closed := []byte("the ledger with the entry gone")
	if _, err := w.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		Writes: []*sidecar.EvsPathWrite{{Path: "ledger/a", Content: bytes.NewReader(closed)}}, Erased: erased,
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	afterClosure := world.slotKeys()
	if len(epochNewSlots(afterLarge, afterClosure)) != 1 {
		t.Fatalf("%d slots after the CLOSURE", len(afterClosure))
	}
	if _, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: erased, Complete: true}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	fresh := world.device("r", nil)
	if content, _, err := fresh.read("ledger/a"); err != nil || !bytes.Equal(content, closed) {
		t.Fatalf("ledger/a after the ERASE: %q %v", content, err)
	}
	if content, _, err := fresh.read("ledger/b"); err != nil || !bytes.Equal(content, large) {
		t.Fatalf("ledger/b after the ERASE: %v", err)
	}
	history, err := fresh.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: "ledger/a"})
	if err != nil || len(history.Versions) != 3 {
		t.Fatalf("ledger/a's history: %v %v", history, err)
	}
	for _, version := range history.Versions[1:] {
		out := &bytes.Buffer{}
		if _, err := fresh.repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: "ledger/a", Version: version.Version}, out); err == nil {
			t.Fatalf("version %d of ledger/a opened after its key was erased", version.Version)
		}
	}
}

// The new slots and flags of a push request's statement and payload, nil for a request that is not a one-part push.
func epochPushSlots(t *testing.T, request *http.Request) (flags uint32, slotIds []sidecar.Id, ok bool) {
	t.Helper()
	if !epochIsPush(request) || request.Body == nil {
		return 0, nil, false
	}
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	pushRequest := &protocol.EvsPushRequest{}
	if err := proto.Unmarshal(body, pushRequest); err != nil {
		t.Fatal(err)
	}
	statement, err := sidecar.ParseEvsStatement(pushRequest.GetStatement())
	if err != nil {
		t.Fatal(err)
	}
	checked, err := sidecar.EvsCheckPayload(statement, pushRequest.GetPayload())
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range checked.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			slotIds = append(slotIds, sidecar.Id(object.Id))
		}
	}
	return statement.Push.GetFlags(), slotIds, true
}

// DESIGN-DETAILS 9.6's K end to end in a record-class repo: a CLOSURE in flight across a cut-over is refused 412
// PATH_EPOCH and retokened with what it sealed kept, so the slot it introduces is the one its first attempt named and
// its segment goes up once.
func TestEvsRecordClassClosureAcrossACutOverKeepsItsSlotEndToEnd(t *testing.T) {
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.device("w", nil)
	m := world.device("m", func(settings *sidecar.EvsSettings) { settings.MapperSpread = time.Nanosecond })
	entry := bytes.Repeat([]byte("an entry to close over; "), 400)
	if _, err := w.write("ledger/a", entry); err != nil {
		t.Fatal(err)
	}
	oldSlot := epochNewSlots(nil, world.slotKeys())[0]
	refId := world.mainRefId(w)
	before := world.slotKeys()
	// d leaves: w's next EnsureWritable rotates to the REMOVE generation, which m maps to
	world.advance([]string{"w", "v", "m", "r"}, 2, nil)
	var firstSlots []sidecar.Id
	closurePosts, segmentPuts := 0, 0
	var interceptErr error
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if device != w {
			return nil
		}
		if request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/segments/") {
			segmentPuts += 1
			return nil
		}
		flags, slotIds, ok := epochPushSlots(t, request)
		if !ok || flags&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) == 0 {
			return nil
		}
		closurePosts += 1
		if closurePosts == 1 {
			firstSlots = slotIds
			if err := m.repo.TickMapper(world.ctx, refId); err != nil {
				interceptErr = fmt.Errorf("m's mapper: %w", err)
			}
		} else if !slices.Equal(slotIds, firstSlots) {
			interceptErr = fmt.Errorf("the retoken introduces slots %v, its first attempt %v", slotIds, firstSlots)
		}
		return nil
	})
	closed := []byte("the ledger, the entry gone")
	_, err := w.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		Writes: []*sidecar.EvsPathWrite{{Path: "ledger/a", Content: bytes.NewReader(closed)}},
		Erased: []*sidecar.EvsErasedKey{{SlotId: oldSlot, KeyIndex: 0}},
	})
	world.setIntercept(nil)
	if interceptErr != nil {
		t.Fatal(interceptErr)
	}
	if err != nil {
		t.Fatalf("the CLOSURE across the cut-over: %v", err)
	}
	if world.head(refId).GetPathEpoch().GetCurrent() != 2 || closurePosts != 2 || segmentPuts != 1 || len(firstSlots) != 1 {
		t.Fatalf("epoch %d, %d CLOSURE posts, %d segment uploads, %d slots", world.head(refId).GetPathEpoch().GetCurrent(), closurePosts, segmentPuts, len(firstSlots))
	}
	if added := epochNewSlots(before, world.slotKeys()); len(added) != 1 || added[0] != firstSlots[0] {
		t.Fatalf("slots added %v, the first attempt's %v", added, firstSlots)
	}
	if content, _, err := world.device("r", nil).read("ledger/a"); err != nil || !bytes.Equal(content, closed) {
		t.Fatalf("ledger/a after the CLOSURE: %q %v", content, err)
	}
}
