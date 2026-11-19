package evsservice

// The client's half of QD-1078 against this engine (§11.14's drop row; EVS2-M10-21's EvsDropIndexHook): a repo
// admin's sidecar.EvsClient, at format 2 over FakeGkm, writes a path three times and an index shard whose postings name
// each version, files the dry run, which runs as taskworker runs it with resolve and mark faked as drop_routes_test.go
// fakes them, and drops the path's history with a hook that writes the shard again without the dropped versions'
// postings, padded to its length. The rewrite rides the DROP: the shard reads back without them at the DROP's own
// version and push, with no backfill. Its twin's hook pads nothing and grows the shard past Padmé of its length: evs
// answers 409 DROP_BOUNDARY, the client sends the DROP again without the rewrite, as it would to an older evs, and the
// shard keeps its postings for the backfill.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// The shard the tests' index holds, a bucket shard under the file-mode ref's index root, and the length its
// plaintext pads to.
const (
	dropIndexClientShardPath      = ".ur-index/i1/b/20400/s/0"
	dropIndexClientShardByteCount = 512
)

// A general repo on one engine and its admin's device, in the format2 gate.
type dropIndexClientWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	engine    *EvsEngine
	previews  *DropPreviews
	networkId sidecar.Id
	repoId    sidecar.Id
	client    *sidecar.EvsClient
	repo      *sidecar.EvsRepo
	// the dry run's answer for each path
	resolver *fakeDropResolver

	stateLock sync.Mutex
	// evs's status to each DROP push posted, in order
	dropStatuses []int
}

// evs's gate view of the world's network.
type dropIndexClientGateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *dropIndexClientGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, EvsAuthUnknown
	}
	return self.view, EvsAuthAllowed
}

func newDropIndexClientWorld(t *testing.T) *dropIndexClientWorld {
	t.Helper()
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	world := &dropIndexClientWorld{
		t: t, ctx: ctx, clock: clock, host: host,
		networkId: testId("index network"), repoId: testId("index repo"),
		resolver: &fakeDropResolver{events: &dropJobEvents{}},
	}
	network := connect.Id(world.networkId).String()
	gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q]}\n", network, network)
	if err := host.Gates.Set(gates); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(world.networkId), 1<<40)
	host.Quota.SetLimits(connect.Id(world.networkId), &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"evs_drops_per_day": 10, "evs_drop_previews_per_day": 10}})

	// the admin, the repo's one reader and writer, and the authorization state every party reads
	signer := sidecartest.NewFakeGkmSigner()
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins: []*protocol.AclRepoAdminRow{{SidecarId: signer.SidecarId.Bytes()}},
	})
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(testId("index member"), signer.SidecarId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{memberRow}
	view := sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows:               rows,
		IdentityKeys:       map[sidecar.Id][]byte{signer.SidecarId: signer.PublicKey()},
		RepoReaders:        map[sidecar.Id][]sidecar.Id{world.repoId: {signer.SidecarId}},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{world.repoId: {signer.SidecarId}},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{},
	})
	gkm := sidecartest.NewFakeGkm(clock, host.Blobs, nil).Client(signer.SidecarId, signer.Sign)
	gkm.AuthAdvanced(view)
	if _, err := gkm.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL}); err != nil {
		t.Fatal(err)
	}

	auth := newFakeAuthState()
	auth.grant(signer.SidecarId, world.repoId, sidecar.AclEvsAdmin)
	auth.setRepo(world.repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: world.networkId})
	usage, err := NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := NewQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKeys, err := NewReceiptKeys([]*ReceiptKey{testReceiptKey(1, clock.Now().Add(-48*time.Hour))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	settings.RepoCacheTtl = 0
	world.engine, err = NewEvsEngine(ctx, host.ServiceHost(), settings, &EvsEngineDeps{
		AuthState: auth,
		Uploads:   &EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &dropIndexClientGateViews{networkId: world.networkId, view: view},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	world.previews, err = NewDropPreviews(host.ServiceHost(), &DropPreviewDeps{
		Resolver: world.resolver,
		Marker:   &fakeDropMarker{events: world.resolver.events},
		Horizon:  &fakeDropHorizon{events: world.resolver.events, horizon: clock.Now().Add(-time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}

	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: signer.SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}

	clientId := testId("index client")
	identity := &sidecar.SidecarIdentity{NetworkId: world.networkId, SidecarId: signer.SidecarId, ClientId: clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	world.client, err = sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: world.networkId,
		EvsUrl:    "https://evs.example",
		Transport: world,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(signer.SidecarId)
			return host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(world.networkId), ClientId: connect.Id(clientId), SidecarId: &connectSidecarId,
				Audience: EvsAudience, Scopes: scopes, IssuedAt: clock.Now(), ExpiresAt: clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkm,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return view },
		Clock:    &reseedDeviceClock{clock: clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.client.Close)
	world.client.SetFormat2Source(func() bool { return true })
	world.client.EnableFormat2Reader()
	world.repo = world.client.Repo(world.repoId)
	return world
}

// The engine serves the device in process: a dry run's read first runs the queued dry run as taskworker would, and a
// push's answer waits out its step 8; each DROP posted is counted with evs's status.
func (self *dropIndexClientWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/drops/preview/") {
		if _, err := self.previews.Run(self.ctx, "meta-1", self.repoId); err != nil {
			return nil, err
		}
	}
	drop := false
	if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		pushRequest := &protocol.EvsPushRequest{}
		if proto.Unmarshal(body, pushRequest) == nil {
			if statement, err := sidecar.ParseEvsStatementFormat2(pushRequest.GetStatement()); err == nil {
				drop = statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0
			}
		}
	}
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if strings.HasSuffix(request.URL.Path, "/push") {
		for {
			started, finished, changed := self.engine.StepEights()
			if started == finished {
				break
			}
			<-changed
		}
	}
	if drop {
		self.stateLock.Lock()
		self.dropStatuses = append(self.dropStatuses, recorder.Code)
		self.stateLock.Unlock()
	}
	return recorder.Result(), nil
}

// evs's statuses to the DROP pushes posted, in order.
func (self *dropIndexClientWorld) dropStatusesPosted() []int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]int(nil), self.dropStatuses...)
}

// A shard's plaintext naming each posting on its own line, padded with zero bytes to length.
func dropIndexClientShard(t *testing.T, length int, postings ...string) []byte {
	t.Helper()
	shard := []byte(strings.Join(postings, "\n") + "\n")
	if length < len(shard) {
		t.Fatalf("postings of %d bytes past a shard of %d", len(shard), length)
	}
	return append(shard, make([]byte, length-len(shard))...)
}

// Writes a.txt three times and the shard naming each version's posting, then files the drop's dry run of a.txt.
func (self *dropIndexClientWorld) historyAndPreview() *sidecar.EvsDropPreview {
	t := self.t
	t.Helper()
	for _, content := range []string{"alpha", "beta", "gamma"} {
		if _, err := self.repo.WritePaths(self.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{Path: "a.txt", Content: strings.NewReader(content)}}}); err != nil {
			t.Fatal(err)
		}
	}
	shard := dropIndexClientShard(t, dropIndexClientShardByteCount, "a.txt 1 alpha", "a.txt 2 beta", "a.txt 3 gamma")
	_, err := self.repo.WritePaths(self.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{
		Path: dropIndexClientShardPath, Content: bytes.NewReader(shard), Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if read, info := self.read(dropIndexClientShardPath); !bytes.Equal(read, shard) || info.Version == 0 {
		t.Fatal("the shard does not read back as written")
	}
	self.resolver.preview = &DropPreviewResolveResult{
		Paths:           []*protocol.EvsDropPreviewPath{{ListMatch: true, Count: 3, Linked: true}},
		SnapshotVersion: 4,
	}
	preview, err := self.repo.DropHistoryPreview(self.ctx, &sidecar.EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

// path's newest content and its info, verified by the device's reader.
func (self *dropIndexClientWorld) read(path string) ([]byte, *sidecar.EvsFileInfo) {
	self.t.Helper()
	out := &bytes.Buffer{}
	info, err := self.repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: path}, out)
	if err != nil {
		self.t.Fatalf("a read of a path: %v", err)
	}
	return out.Bytes(), info
}

// The hook's rewrites ride the DROP to this engine: the shard reads back without the dropped versions' postings at
// the DROP's own version and push, with no backfill between, and a.txt reads its kept head there too.
func TestDropIndexHookRewritesLandWithTheDrop(t *testing.T) {
	world := newDropIndexClientWorld(t)
	preview := world.historyAndPreview()
	kept := dropIndexClientShard(t, dropIndexClientShardByteCount, "a.txt 3 gamma")
	calls := 0
	world.client.SetDropIndexHook(func(ctx context.Context, repo *sidecar.EvsRepo, args *sidecar.EvsDropIndexArgs) (*sidecar.EvsDropIndexRewrites, error) {
		calls += 1
		return &sidecar.EvsDropIndexRewrites{Writes: []*sidecar.EvsPathWrite{{
			Path: dropIndexClientShardPath, Content: bytes.NewReader(kept), Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
		}}}, nil
	})
	result, err := world.repo.DropHistory(world.ctx, &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(result.Pushes) != 1 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("hook calls %d, pushes %d, the rewrites riding none of them: %v", calls, len(result.Pushes), world.dropStatusesPosted())
	}
	if statuses := world.dropStatusesPosted(); len(statuses) != 1 || statuses[0] != http.StatusOK {
		t.Fatalf("evs answered the DROPs %v", statuses)
	}
	dropped := result.Pushes[0]
	shard, info := world.read(dropIndexClientShardPath)
	if !bytes.Equal(shard, kept) || bytes.Contains(shard, []byte("alpha")) || bytes.Contains(shard, []byte("beta")) {
		t.Fatalf("the shard after the DROP: %q", bytes.TrimRight(shard, "\x00"))
	}
	if info.CommitVersion != dropped.Version || info.PushId != dropped.PushId {
		t.Fatalf("the shard's rewrite committed at %d by another push than the DROP's at %d", info.CommitVersion, dropped.Version)
	}
	head, headInfo := world.read("a.txt")
	if string(head) != "gamma" || headInfo.CommitVersion != dropped.Version || headInfo.Version != 4 {
		t.Fatalf("a.txt after the DROP: %q at version %d, committed at %d", head, headInfo.Version, headInfo.CommitVersion)
	}
}

// A hook whose rewrite is not padded and grows the shard past Padmé of its length: evs answers 409 DROP_BOUNDARY, and
// the client sends the DROP again without its rewrites, which commits; the shard keeps every posting, left to the
// backfill.
func TestDropIndexHookUnpaddedRewriteGoesWithoutIt(t *testing.T) {
	world := newDropIndexClientWorld(t)
	preview := world.historyAndPreview()
	before, beforeInfo := world.read(dropIndexClientShardPath)
	grown := dropIndexClientShard(t, 4*dropIndexClientShardByteCount, "a.txt 3 gamma")
	world.client.SetDropIndexHook(func(ctx context.Context, repo *sidecar.EvsRepo, args *sidecar.EvsDropIndexArgs) (*sidecar.EvsDropIndexRewrites, error) {
		return &sidecar.EvsDropIndexRewrites{Writes: []*sidecar.EvsPathWrite{{
			Path: dropIndexClientShardPath, Content: bytes.NewReader(grown), Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
		}}}, nil
	})
	result, err := world.repo.DropHistory(world.ctx, &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pushes) != 1 || result.Pushes[0].IndexRewritten {
		t.Fatalf("%d pushes, the last rewritten %v", len(result.Pushes), len(result.Pushes) != 0 && result.Pushes[0].IndexRewritten)
	}
	if statuses := world.dropStatusesPosted(); len(statuses) != 2 || statuses[0] != http.StatusConflict || statuses[1] != http.StatusOK {
		t.Fatalf("evs answered the DROPs %v", statuses)
	}
	after, afterInfo := world.read(dropIndexClientShardPath)
	if !bytes.Equal(after, before) || afterInfo.CommitVersion != beforeInfo.CommitVersion {
		t.Fatal("the shard moved with a DROP evs sent back without its rewrite")
	}
	digest := sha256.Sum256(after)
	if digest != sha256.Sum256(dropIndexClientShard(t, dropIndexClientShardByteCount, "a.txt 1 alpha", "a.txt 2 beta", "a.txt 3 gamma")) {
		t.Fatal("the shard lost its postings")
	}
}
