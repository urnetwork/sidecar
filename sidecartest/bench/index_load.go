//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !windows

// The index writers' load driver (SEARCH-M10-40; D-TEST-13, R-EVS-24, FS-81; §22.8's index row): what
// server/cli/filecluster-bench's index mode runs as its IndexLoad (EVSB-M10-08's index.go), in this process over the
// store it is handed, so every write a leg's load causes reaches that store and the mode's count.
//
// A leg is a world of its own over the store: evsservice's engine at format 2, as server/cli/evs builds it, with the
// network in §19.11's format2 gate; a notes vault, every writer a device of its own committing through sidecar.EvsClient
// as built to a file-mode ref of its own; and, with the indexed class on, each writer's in-ref index writer
// (SEARCH-M10-13's IndexWriter on the push builder, through the root's sidecar_testhooks seam), so one head CAS commits
// a push's content and its writer's index head. The writers' pushes are paced open loop at PushRate for the leg's
// duration (sidecartest/load's Driver, on real time: a load run is), each writing FilesPerPush files of generated text
// over PathsPerWriter paths a writer rewrites in turn. At its end the leg drains: the engine's background folds finish
// and evacuation runs once on every metadata cluster, as taskworker's hourly run would, so the leg's writes are all in
// the count; then the world closes.
//
// It counts, by filecluster-bench's names: content_in_ref, each content push committed, and indexed_push, each that
// carried its writer's index writes (a push the writer left unindexed, to be backfilled, is not one).
//
// What is not driven yet, each failing its leg closed with the reason, so a run never reads a class as costing nothing:
//
//	companion  git-mode refs and record streams index through ur/index's companion pushes (SEARCH-M10-14), which no
//	           composition builds over EvsRepo yet; the twenty-agent test's git pushes and the mailbox stream's
//	           deposits, the row's other content, ride them, so only the notes vault's in-ref pushes run here
//	rollup     a bucket expires a window after it opens, which a leg on real time does not reach
//	cut        an erasure's CUT and the INDEX_EPOCH rebuilds it causes, and
//	rewrite    its CLOSURE and ERASE rewrites: SEARCH-M10-16 and -17's eraser runs over EvsRepo (FS-111's T3 case),
//	           but no load here drives erasures beside the writers yet
//	migration  a format-1 repo's migration (EVS2-M10-18), not composed here
//
// Purges are not driven either: the format2 gate's purge observes in these legs, so a replaced version's segment stays
// for the sweep, which the leg does not run; the mode's file says what drained.
//
// Safe for one leg at a time, as IndexLoad is.

package bench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/load"
)

// What a leg names as content and events: filecluster-bench's names (index.go), which its file reads.
const (
	IndexLoadContentInRef   = "content_in_ref"
	IndexLoadEventIndexed   = "indexed_push"
	IndexLoadClassIndexed   = "indexed"
	IndexLoadClassCompanion = "companion"
	IndexLoadClassRollup    = "rollup"
	IndexLoadClassCut       = "cut"
	IndexLoadClassRewrite   = "rewrite"
	IndexLoadClassMigration = "migration"
)

// A class this driver cannot run yet: its leg fails closed with the reason.
var ErrIndexLoadUnbuilt = errors.New("index load: a class this driver does not run yet")

// What a leg runs. DefaultIndexLoadSettings is the row's.
type IndexLoadSettings struct {
	// Writers, each a device and a ref of its own: 8.
	WriterCount int
	// Content pushes a second over every writer: 4, the twenty-agent test's pace beside its merges (§22.8).
	PushRate float64
	// The most pushes in flight; past it an arrival is refused, as the driver counts it. 64.
	MaxInFlight int
	// Files a push writes, the words each holds, and the paths a writer rewrites in turn: 3, 80 and 64, so entries are
	// overwritten and folded as a working ref's are and every file is a document the index takes.
	FilesPerPush   int
	WordsPerFile   int
	PathsPerWriter int
	// How long the end waits for the engine's background folds: 2 min, and how often it looks: 100 ms.
	DrainTimeout      time.Duration
	DrainPollInterval time.Duration
	// A device's token's life: 15 min, the exchange's.
	TokenLife time.Duration
	// The network's credit, so quota never refuses: 1 TiB.
	NetworkBalance int64
	// How long before the leg the upload receipts' key was issued: 48 h, its previous key's keep.
	ReceiptKeyAge time.Duration
	Seed          int64
}

func DefaultIndexLoadSettings() *IndexLoadSettings {
	return &IndexLoadSettings{
		WriterCount:       8,
		PushRate:          4,
		MaxInFlight:       64,
		FilesPerPush:      3,
		WordsPerFile:      80,
		PathsPerWriter:    64,
		DrainTimeout:      2 * time.Minute,
		DrainPollInterval: 100 * time.Millisecond,
		TokenLife:         15 * time.Minute,
		NetworkBalance:    1024 * 1024 * 1024 * 1024,
		ReceiptKeyAge:     48 * time.Hour,
		Seed:              1,
	}
}

// See the file header.
type IndexLoad struct {
	settings *IndexLoadSettings
}

// A driver at settings, nil for the row's.
func NewIndexLoad(settings *IndexLoadSettings) (*IndexLoad, error) {
	if settings == nil {
		settings = DefaultIndexLoadSettings()
	}
	if settings.WriterCount <= 0 || settings.PushRate <= 0 || settings.FilesPerPush <= 0 || settings.WordsPerFile <= 0 || settings.PathsPerWriter <= 0 {
		return nil, fmt.Errorf("index load: %d writers at %v pushes a second, %d files of %d words over %d paths", settings.WriterCount,
			settings.PushRate, settings.FilesPerPush, settings.WordsPerFile, settings.PathsPerWriter)
	}
	copied := *settings
	return &IndexLoad{settings: &copied}, nil
}

// Nothing outlives a leg.
func (self *IndexLoad) Close() {}

// Runs the leg's load over store for duration with classes on: see the file header. The content pushes it committed
// by kind, each class's events, and whether every deferred write ran before it returned. A class it cannot run fails
// the leg before anything is written, ErrIndexLoadUnbuilt naming it.
func (self *IndexLoad) RunLeg(ctx context.Context, store sidecar.BlobStore, name string, classes []string, duration time.Duration) (map[string]int64, map[string]int64, bool, error) {
	contentPushes := map[string]int64{}
	events := map[string]int64{}
	indexed := false
	for _, class := range classes {
		switch class {
		case IndexLoadClassIndexed:
			indexed = true
		case IndexLoadClassCompanion:
			return contentPushes, events, false, fmt.Errorf("%w: %s: ur/index's companion pushes for git-mode refs and record streams are composed over no EvsRepo yet", ErrIndexLoadUnbuilt, class)
		case IndexLoadClassRollup:
			return contentPushes, events, false, fmt.Errorf("%w: %s: a bucket expires a window after it opens, past any leg on real time", ErrIndexLoadUnbuilt, class)
		case IndexLoadClassCut, IndexLoadClassRewrite:
			return contentPushes, events, false, fmt.Errorf("%w: %s: no erasure runs beside the writers yet", ErrIndexLoadUnbuilt, class)
		case IndexLoadClassMigration:
			return contentPushes, events, false, fmt.Errorf("%w: %s: no format-1 repo's migration is composed here", ErrIndexLoadUnbuilt, class)
		default:
			return contentPushes, events, false, fmt.Errorf("index load: no class %q", class)
		}
	}
	if duration <= 0 {
		return contentPushes, events, false, fmt.Errorf("index load: a leg of %v", duration)
	}
	world, err := newIndexLoadWorld(ctx, self.settings, store, indexed)
	if err != nil {
		return contentPushes, events, false, fmt.Errorf("leg %s: %w", name, err)
	}
	defer world.close()
	driverSettings := load.DefaultDriverSettings()
	driverSettings.Name = "index-" + name
	driverSettings.Rate = self.settings.PushRate
	driverSettings.Warmup = 0
	driverSettings.Steady = duration
	driverSettings.MaxInFlight = self.settings.MaxInFlight
	report := load.NewDriver(driverSettings, world.push).Run(ctx)
	contentPushes[IndexLoadContentInRef] = world.committed.Load()
	if indexed {
		events[IndexLoadEventIndexed] = world.indexedPushes.Load()
	}
	if report.Failed != 0 {
		return contentPushes, events, false, fmt.Errorf("leg %s: %d of %d pushes failed: %v", name, report.Failed, report.Arrivals, report.FailureKinds)
	}
	drained, err := world.drain(ctx)
	return contentPushes, events, drained, err
}

// One leg's world: see the file header.
type indexLoadWorld struct {
	ctx       context.Context
	cancel    context.CancelFunc
	settings  *IndexLoadSettings
	fakes     *sidecartest.FakeHost
	host      *sidecar.ServiceHost
	store     sidecar.BlobStore
	engine    *evsservice.EvsEngine
	networkId sidecar.Id
	repoId    sidecar.Id
	writers   []*indexLoadWriter
	closers   []func()

	committed     atomic.Int64
	indexedPushes atomic.Int64
}

// One writer: a device committing to its own ref, one push at a time.
type indexLoadWriter struct {
	pushLock sync.Mutex
	device   *sidecar.EvsClient
	refName  []byte
	pushes   int64
	random   *rand.Rand
	// whether the push being made carried index writes, as its last plan did
	planIndexed bool
}

func newIndexLoadWorld(ctx context.Context, settings *IndexLoadSettings, store sidecar.BlobStore, indexed bool) (world *indexLoadWorld, returnErr error) {
	worldCtx, cancel := context.WithCancel(ctx)
	clock := sidecar.RealClock{}
	fakes := sidecartest.NewFakeHost(worldCtx, clock, nil, nil, nil)
	world = &indexLoadWorld{ctx: worldCtx, cancel: cancel, settings: settings, fakes: fakes, store: store, networkId: sidecar.NewId(), repoId: sidecar.NewId()}
	defer func() {
		if returnErr != nil {
			world.close()
		}
	}()
	sidecartest.RegisterEvsTwins(fakes.Redis)
	host := fakes.ServiceHost()
	host.Blobs = store
	world.host = host
	network := connect.Id(world.networkId).String()
	if err := fakes.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q], percent: 0, purge: %q, drop: %q}\n",
		network, network, "observe", "observe")); err != nil {
		return nil, err
	}
	fakes.Quota.SetBalance(connect.Id(world.networkId), settings.NetworkBalance)

	signers := []*sidecartest.FakeGkmSigner{}
	sidecarIds := []sidecar.Id{}
	identityKeys := map[sidecar.Id][]byte{}
	for range settings.WriterCount {
		signer := sidecartest.NewFakeGkmSigner()
		signers = append(signers, signer)
		sidecarIds = append(sidecarIds, signer.SidecarId)
		identityKeys[signer.SidecarId] = signer.PublicKey()
	}
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(sidecar.NewId(), sidecarIds...)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	view := sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: identityKeys,
		RepoReaders:  map[sidecar.Id][]sidecar.Id{world.repoId: sidecarIds},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{world.repoId: sidecarIds},
	})

	usage, err := evsservice.NewUsageBatcher(worldCtx, host, nil)
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, usage.Close)
	quota, err := evsservice.NewQuotaGate(worldCtx, host, nil)
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, quota.Close)
	receiptKey := sha256.Sum256([]byte("index load receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{
		{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-settings.ReceiptKeyAge)},
	}, nil)
	if err != nil {
		return nil, err
	}
	engineSettings := evsservice.DefaultEvsSettings()
	engineSettings.InstanceFormat = sidecar.EvsRepoFormat2
	world.engine, err = evsservice.NewEvsEngine(worldCtx, host, engineSettings, &evsservice.EvsEngineDeps{
		AuthState: &indexLoadAuthState{networkId: world.networkId, repoId: world.repoId},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &indexLoadGateViews{networkId: world.networkId, view: view},
	})
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, world.engine.Close)

	first, err := store.FirstCluster()
	if err != nil {
		return nil, err
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: first.ClusterId(), CreatorSidecarId: signers[0].SidecarId}).Marshal()
	if err != nil {
		return nil, err
	}
	if _, err := first.PutIfNoneMatch(worldCtx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		return nil, fmt.Errorf("place/: %w", err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	if _, err := first.PutIfNoneMatch(worldCtx, sidecar.EvsRepoObjectKey(world.repoId), repoBytes, nil); err != nil {
		return nil, fmt.Errorf("repo/: %w", err)
	}
	gkm := sidecartest.NewFakeGkm(clock, store, nil)
	groupClient := gkm.Client(signers[0].SidecarId, signers[0].Sign)
	groupClient.AuthAdvanced(view)
	if _, err := groupClient.CreateGroup(worldCtx, &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL}); err != nil {
		return nil, fmt.Errorf("the repo's group: %w", err)
	}

	for index, signer := range signers {
		deviceGkm := gkm.Client(signer.SidecarId, signer.Sign)
		deviceGkm.AuthAdvanced(view)
		clientId := sidecar.NewId()
		identity := &sidecar.SidecarIdentity{
			NetworkId: world.networkId, SidecarId: signer.SidecarId, ClientId: clientId, Generation: 1, IdentityPublicKey: signer.PublicKey(),
		}
		sidecarId := signer.SidecarId
		device, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
			NetworkId: world.networkId,
			EvsUrl:    "https://evs.example",
			Transport: world,
			ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				connectSidecarId := connect.Id(sidecarId)
				return fakes.Authenticator.Issue(&sidecar.Principal{
					NetworkId: connect.Id(world.networkId),
					ClientId:  connect.Id(clientId),
					SidecarId: &connectSidecarId,
					Audience:  evsservice.EvsAudience,
					Scopes:    scopes,
					IssuedAt:  clock.Now(),
					ExpiresAt: clock.Now().Add(settings.TokenLife),
				}), nil
			},
			Sign:     sidecar.EvsSignFunction(signer.Sign),
			Identity: func() *sidecar.SidecarIdentity { return identity },
			Gkm:      deviceGkm,
			Store:    sidecartest.NewFakeStore().Root(),
			Config:   func() sidecar.GkmAuthView { return view },
			Clock:    clock,
			Log:      sidecar.NewNoopLogger(),
			Settings: sidecar.DefaultEvsSettings(),
		})
		if err != nil {
			return nil, err
		}
		world.closers = append(world.closers, device.Close)
		// format 2 as the gate admits the network, its reader installed, as a composition sets a device up
		device.SetFormat2Source(func() bool { return true })
		device.EnableFormat2Reader()
		writer := &indexLoadWriter{
			device: device, refName: []byte(fmt.Sprintf("notes/%d", index)),
			random: rand.New(rand.NewPCG(uint64(settings.Seed), uint64(index))),
		}
		if indexed {
			remove, err := sidecar.InstallSearchTestIndexWriterCounting(device, &sidecar.SearchTestIndexWriterArgs{
				IsAdmin: func(signer sidecar.Id) bool { return false },
			}, func(planIndexed bool) { writer.planIndexed = planIndexed })
			if err != nil {
				return nil, err
			}
			world.closers = append(world.closers, remove)
		}
		world.writers = append(world.writers, writer)
	}
	return world, nil
}

func (self *indexLoadWorld) close() {
	for index := len(self.closers) - 1; 0 <= index; index -= 1 {
		self.closers[index]()
	}
	self.closers = nil
	self.cancel()
}

// The devices' transport: the engine's handler.
func (self *indexLoadWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

// The words a generated file holds: lower-case pseudo-words, so each file is text the index takes.
var indexLoadSyllables = []string{"ka", "lo", "mi", "ne", "ru", "sa", "te", "vo", "zi", "ba", "do", "fe", "gu", "ha", "ji"}

// One content push of arrival's writer: FilesPerPush files over the writer's paths in turn.
func (self *indexLoadWorld) push(ctx context.Context, arrival int64) error {
	writer := self.writers[arrival%int64(len(self.writers))]
	writer.pushLock.Lock()
	defer writer.pushLock.Unlock()
	writes := []*sidecar.EvsPathWrite{}
	for file := range self.settings.FilesPerPush {
		path := (writer.pushes*int64(self.settings.FilesPerPush) + int64(file)) % int64(self.settings.PathsPerWriter)
		words := make([]string, self.settings.WordsPerFile)
		for index := range words {
			words[index] = indexLoadSyllables[writer.random.IntN(len(indexLoadSyllables))] + indexLoadSyllables[writer.random.IntN(len(indexLoadSyllables))]
		}
		content := []byte(fmt.Sprintf("# note %d\n\n%s\n", path, strings.Join(words, " ")))
		writes = append(writes, &sidecar.EvsPathWrite{Path: fmt.Sprintf("notes/%03d.md", path), Content: bytes.NewReader(content)})
	}
	writer.pushes += 1
	writer.planIndexed = false
	repo := writer.device.Repo(self.repoId)
	if _, err := repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{RefName: writer.refName, Writes: writes}); err != nil {
		return err
	}
	self.committed.Add(1)
	if writer.planIndexed {
		self.indexedPushes.Add(1)
	}
	return nil
}

// Waits for the engine's background folds, then runs evacuation once on every metadata cluster: whether every
// deferred write ran.
func (self *indexLoadWorld) drain(ctx context.Context) (bool, error) {
	deadline := time.Now().Add(self.settings.DrainTimeout)
	for {
		count, changed := self.engine.Folder().BackgroundFolds()
		if count == 0 {
			break
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-changed:
		case <-time.After(self.settings.DrainPollInterval):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	evacuator, err := evsservice.NewEvacuator(self.host, &evsservice.EvacuatorDeps{Log: sidecar.NewNoopLogger(), Format2: evsservice.NewFormat2Gate(self.host)})
	if err != nil {
		return false, err
	}
	clusterIds := slices.Clone(self.store.MetadataClusterIds())
	for _, clusterId := range clusterIds {
		if _, err := evacuator.Run(ctx, clusterId); err != nil {
			return false, fmt.Errorf("evacuation on %s: %w", clusterId, err)
		}
	}
	return true, nil
}

// An authorization state that admits the world's writers to its one repo.
type indexLoadAuthState struct {
	networkId sidecar.Id
	repoId    sidecar.Id
}

func (self *indexLoadAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *indexLoadAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *indexLoadAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	if repoId != self.repoId || connect.Id(self.networkId) != principal.NetworkId {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *indexLoadAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	if repoId != self.repoId {
		return nil, evsservice.EvsAuthDenied
	}
	return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: self.networkId}, evsservice.EvsAuthAllowed
}

// The world's network's view, for evs's gate.
type indexLoadGateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *indexLoadGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.view, evsservice.EvsAuthAllowed
}
