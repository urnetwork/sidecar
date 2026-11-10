package fault

// FI-1's oracle (fi1.go) on T2, through two worlds that share the Net's stores with the oracle:
//
//   - fiWorld: evsservice's engine as built on the Net's host, the fake gkm on the Net's blobs, and a writer device
//     that pushes through sidecar.EvsClient as built, so the oracle reads what real pushes, folds, page-outs and
//     evacuation leave. The healthy run and most mutants run here, each mutant a step that changes the store the
//     way the bug it stands for would;
//   - fiHandWorld: pushes built with the format's own builders and committed through evsservice.HeadStore, for what
//     the client does not write yet (slot-keyed records, an ERASE, a push left pending), as fs60_test.go's world
//     builds its history. Its keys are made outside any actor's step, so no named actor holds them and the decrypt
//     clause does not run there.
//
// A mutant asserts the run fails at its step, on the invariant and text it names, and its schedule's healthy prefix
// passes every check before it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// See the file header.
type fiWorld struct {
	t         *testing.T
	ctx       context.Context
	net       *Net
	host      *sidecartest.FakeHost
	networkId sidecar.Id
	repoId    sidecar.Id
	clientId  sidecar.Id
	writer    *sidecartest.FakeGkmSigner
	view      *sidecartest.FakeGkmAuthView
	gkm       *sidecartest.FakeGkm
	engine    *evsservice.EvsEngine
	device    *sidecar.EvsClient
	// main's, known once the group exists
	refId      sidecar.Id
	writeCount int

	stateLock sync.Mutex
	// the device call in flight, and the 429 or 503 that ended it: the clock stands still, so a wait would never end
	callCancel context.CancelFunc
	callWait   error
}

func newFiWorld(t *testing.T) *fiWorld {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	host := net.Fakes()
	sidecartest.RegisterEvsTwins(host.Redis)
	world := &fiWorld{
		t: t, ctx: t.Context(), net: net, host: host,
		networkId: sidecar.NewId(), repoId: sidecar.NewId(), clientId: sidecar.NewId(),
		writer: sidecartest.NewFakeGkmSigner(),
	}
	network := connect.Id(world.networkId).String()
	if err := host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(world.networkId), 1<<40)

	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins: []*protocol.AclRepoAdminRow{{SidecarId: world.writer.SidecarId.Bytes()}},
	})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(sidecar.NewId(), world.writer.SidecarId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	world.view = sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: map[sidecar.Id][]byte{world.writer.SidecarId: world.writer.PublicKey()},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{world.repoId: {world.writer.SidecarId}},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{world.repoId: {world.writer.SidecarId}},
	})
	SetAuthorizationView(net, world.networkId, world.view)
	world.gkm = sidecartest.NewFakeGkm(net.Clock(), net.Host().Blobs, nil)

	usage, err := evsservice.NewUsageBatcher(world.ctx, net.Host(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(world.ctx, net.Host(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKey := sha256.Sum256([]byte("fi1 receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{
		{KeyId: 1, Key: receiptKey[:], IssueFrom: net.Clock().Now().Add(-48 * time.Hour)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := evsservice.DefaultEvsSettings()
	settings.InstanceFormat = sidecar.EvsRepoFormat1
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	// the clock stands still between steps, so a cached repo/ would never lapse
	settings.RepoCacheTtl = 0
	// no fold off the reply path, so a check meets a store at rest: a step folds explicitly (fold), and step 6's
	// page-out folds as it pages
	settings.FoldUnfoldedTriggerCount = 0
	settings.FoldIdleDelay = 0
	world.engine, err = evsservice.NewEvsEngine(world.ctx, net.Host(), settings, &evsservice.EvsEngineDeps{
		AuthState: &fiAuthState{networkId: world.networkId},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &fiGateViews{networkId: world.networkId, view: world.view},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)

	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: first.ClusterId(), CreatorSidecarId: world.writer.SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.PutIfNoneMatch(world.ctx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.PutIfNoneMatch(world.ctx, sidecar.EvsRepoObjectKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}

	gkmClient := world.gkm.Client(world.writer.SidecarId, world.writer.Sign)
	gkmClient.AuthAdvanced(world.view)
	identity := &sidecar.SidecarIdentity{
		NetworkId: world.networkId, SidecarId: world.writer.SidecarId, ClientId: world.clientId, Generation: 1,
		IdentityPublicKey: world.writer.PublicKey(),
	}
	world.device, err = sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: world.networkId,
		EvsUrl:    "https://evs.example",
		Transport: world,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return world.token(scopes), nil
		},
		Sign:     sidecar.EvsSignFunction(world.writer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkmClient,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return world.view },
		Clock:    net.Clock(),
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.device.Close)
	return world
}

type fiAuthState struct {
	networkId sidecar.Id
}

func (self *fiAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *fiAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *fiAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *fiAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: self.networkId}, evsservice.EvsAuthAllowed
}

type fiGateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *fiGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.view, evsservice.EvsAuthAllowed
}

// The writer's token for scopes.
func (self *fiWorld) token(scopes []string) string {
	sidecarId := connect.Id(self.writer.SidecarId)
	return self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.networkId),
		ClientId:  connect.Id(self.clientId),
		SidecarId: &sidecarId,
		Audience:  evsservice.EvsAudience,
		Scopes:    scopes,
		IssuedAt:  self.net.Clock().Now(),
		ExpiresAt: self.net.Clock().Now().Add(15 * time.Minute),
	})
}

// The device's transport: the engine's handler, a 429 or 503 ending the call it answered.
func (self *fiWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	response := recorder.Result()
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		reply := &protocol.EvsRefusalReply{}
		proto.Unmarshal(recorder.Body.Bytes(), reply)
		self.stateLock.Lock()
		if self.callCancel != nil && self.callWait == nil {
			self.callWait = fmt.Errorf("evs answered %d %s", response.StatusCode, reply.GetCode())
			self.callCancel()
		}
		self.stateLock.Unlock()
	}
	return response, nil
}

// One device call, then every step 8 the engine started, so a check meets a store at rest.
func (self *fiWorld) call(ctx context.Context, run func(ctx context.Context) error) error {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	self.stateLock.Lock()
	self.callCancel = cancel
	self.callWait = nil
	self.stateLock.Unlock()
	err := run(callCtx)
	self.stateLock.Lock()
	wait := self.callWait
	self.callCancel = nil
	self.stateLock.Unlock()
	if wait != nil {
		return wait
	}
	if err != nil {
		return err
	}
	return self.settle()
}

// Waits out the engine's step 8s, in real time only as a failure's bound.
func (self *fiWorld) settle() error {
	deadline := time.After(10 * time.Second)
	for {
		started, finished, changed := self.engine.StepEights()
		if started == finished {
			return nil
		}
		select {
		case <-changed:
		case <-deadline:
			return errors.New("the engine's step 8s never finished")
		}
	}
}

// The writer makes the repo's group, so its RK_g is the writer actor's, and learns main's ref id.
func (self *fiWorld) createGroup(ctx context.Context, net *Net) error {
	gkmClient := self.gkm.Client(self.writer.SidecarId, self.writer.Sign)
	gkmClient.AuthAdvanced(self.view)
	repoKey, err := gkmClient.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: self.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		return err
	}
	refKey, err := sidecar.NewEvsRefKey(repoKey)
	if err != nil {
		return err
	}
	self.refId, err = sidecar.EvsRefId(refKey, []byte("main"))
	return err
}

// A step's action writing path with size bytes, different on every write.
func (self *fiWorld) write(path string, size int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.writeCount += 1
		content := bytes.Repeat([]byte(fmt.Sprintf("write %d of %s;", self.writeCount, path)), size/16+1)[:size]
		return self.call(ctx, func(ctx context.Context) error {
			_, err := self.device.Repo(self.repoId).Write(ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(content), Size: int64(len(content))})
			return err
		})
	}
}

func (self *fiWorld) remove(path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.call(ctx, func(ctx context.Context) error {
			_, err := self.device.Repo(self.repoId).Write(ctx, &sidecar.EvsWriteArgs{Path: path, Remove: true})
			return err
		})
	}
}

func (self *fiWorld) cluster() sidecar.BlobCluster {
	cluster, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

func (self *fiWorld) segmentCluster() sidecar.BlobCluster {
	cluster, err := self.net.Host().Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

// main's head from the cluster.
func (self *fiWorld) head(ctx context.Context) (*evsservice.EvsStoredHead, error) {
	return self.engine.Heads().ReadCluster(ctx, self.cluster(), self.repoId, self.refId)
}

// The engine folds every unfolded version of main; its next commit raises folded_through over them.
func (self *fiWorld) fold(ctx context.Context, net *Net) error {
	head, err := self.head(ctx)
	if err != nil {
		return err
	}
	now := net.Clock().Now()
	if _, err := self.engine.Folder().FoldAll(ctx, self.cluster(), self.repoId, self.refId, head, now, now.Add(15*time.Second)); err != nil {
		return err
	}
	return self.settle()
}

// One hourly evacuation run on the repo's cluster.
func (self *fiWorld) evacuate(ctx context.Context, net *Net) error {
	settings := evsservice.DefaultEvacuatorSettings()
	settings.SpoolDirectory = self.t.TempDir()
	evacuator, err := evsservice.NewEvacuator(net.Host(), &evsservice.EvacuatorDeps{Settings: settings})
	if err != nil {
		return err
	}
	_, err = evacuator.Run(ctx, self.cluster().ClusterId())
	return err
}

// The keys under prefix on a cluster, every page.
func fiKeys(ctx context.Context, cluster sidecar.BlobCluster, prefix string) ([]*sidecar.BlobInfo, error) {
	infos := []*sidecar.BlobInfo{}
	startAfter := ""
	for {
		page, more, err := cluster.List(ctx, prefix, startAfter, 1000)
		if err != nil {
			return nil, err
		}
		infos = append(infos, page...)
		if !more || len(page) == 0 {
			return infos, nil
		}
		startAfter = page[len(page)-1].Key
	}
}

// The checks every test here runs after every step.
func fiChecks() []Invariant {
	return []Invariant{FI(1), FI(6)}
}

// A run that must pass.
func fiRequirePass(t *testing.T, result *Result) {
	t.Helper()
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

// A run that must fail at step, with a violation of invariant whose error says each of texts.
func fiRequireViolation(t *testing.T, result *Result, step int, invariant string, texts ...string) {
	t.Helper()
	if result.Err == nil {
		t.Fatalf("the mutant passed: %s", result)
	}
	if result.FailedStep != step {
		t.Fatalf("failed at step %d, not %d: %s", result.FailedStep, step, result)
	}
	for _, violation := range result.Violations {
		if violation.Invariant != invariant {
			continue
		}
		message := violation.Err.Error()
		found := true
		for _, text := range texts {
			found = found && strings.Contains(message, text)
		}
		if found {
			return
		}
	}
	t.Fatalf("no %s violation says %q: %s", invariant, texts, result)
}

// A healthy run reads clean at every step: real pushes of inline and segment files, directories, an overwrite and a
// removal, a fold and the commit that raises the horizon over it, enough pushes for a page-out with its folds, and an
// hourly evacuation 26 h on that packs or parcels every record, read back through pidx/.
func TestFi1AndFi6ReadAHealthyMultiPushRunClean(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "writerA", Action: world.write("docs/b.txt", 200)},
		{Actor: "writerA", Action: world.write("docs/c.txt", 300)},
		{Actor: "writerA", Action: world.write("big.bin", 96*1024)},
		{Actor: "writerA", Action: world.write("a.txt", 150)},
		{Actor: "writerA", Action: world.remove("docs/c.txt")},
		{Actor: "evs", Action: world.fold},
		{Actor: "writerA", Action: world.write("d.txt", 50)},
	}
	// past 127 versions, so a push pages out the oldest 63 and folds them first: ten writes a step, each step well
	// inside the driver's stall timeout
	for batch := 0; batch < 13; batch += 1 {
		steps = append(steps, &Step{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			for i := batch * 10; i < batch*10+10; i += 1 {
				if err := world.write(fmt.Sprintf("n/%03d.txt", i), 40)(ctx, net); err != nil {
					return fmt.Errorf("write %d: %w", i, err)
				}
			}
			return nil
		}})
	}
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.write("docs/b.txt", 250)},
		{Actor: "clock", Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.evacuate},
		{Actor: "writerA", Action: world.write("e.txt", 60)},
	}...)
	result := Run(t.Context(), &Schedule{Id: "fi-healthy", Steps: steps, Check: fiChecks()}, world.net)
	fiRequirePass(t, result)
	// what the run must have reached for its clean reads to mean anything
	head, err := world.head(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if head.Version() < 130 || head.Head.GetFoldedThrough() == 0 || evsservice.EvsHeadWindowFirstVersion(head.Head) <= 1 {
		t.Fatalf("the run never paged out or folded: version %d, folded_through %d, window from %d", head.Version(), head.Head.GetFoldedThrough(), evsservice.EvsHeadWindowFirstVersion(head.Head))
	}
	entries, err := fiKeys(t.Context(), world.cluster(), "pidx/")
	if err != nil || len(entries) == 0 {
		t.Fatalf("evacuation wrote no pidx/ entry: %v, %v", entries, err)
	}
	segments, err := fiKeys(t.Context(), world.segmentCluster(), "seg/")
	if err != nil || len(segments) == 0 {
		t.Fatalf("no segment was uploaded: %v, %v", segments, err)
	}
	if sidecartest.HooksLinked && !fiDecryptRan(world) {
		t.Fatal("with the hooks linked, no named actor held the repo's keys, so the decrypt clause never ran")
	}
}

// Whether a named actor of the world holds a key FI-1's decrypt clause opens with.
func fiDecryptRan(world *fiWorld) bool {
	for _, actor := range world.net.HeldSecrets().Actors() {
		if actor != "" && 0 < len(world.net.HeldSecrets().Secrets(actor, "RK_g")) {
			return true
		}
	}
	return false
}

// A head naming a deleted segment: FI-1 finds the version's segment gone, and FI-6 the committed object reclaimed.
func TestFi1CatchesAHeadNamingADeletedSegment(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("big.bin", 96*1024)},
		{Actor: "gc", Action: func(ctx context.Context, net *Net) error {
			segments, err := fiKeys(ctx, world.segmentCluster(), "seg/")
			if err != nil {
				return err
			}
			if len(segments) != 1 {
				return fmt.Errorf("segments %v", segments)
			}
			return world.segmentCluster().Delete(ctx, segments[0].Key)
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-deleted-segment", Steps: steps, Check: fiChecks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-1", "names seg/", "does not hold")
	fiRequireViolation(t, result, 2, "FI-6", "a committed object reclaimed")
}

// Where the Net holds a current reader's keys, a committed segment whose bytes were swapped under its key no longer
// decrypts for that reader: FI-1's decrypt clause says so, beside a closure that is otherwise whole.
func TestFi1CatchesASegmentThatNoLongerDecrypts(t *testing.T) {
	if !sidecartest.HooksLinked {
		t.Skip("the decrypt clause opens a reader's keys, which only the sidecar_testhooks leg holds")
	}
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("big.bin", 96*1024)},
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			segments, err := fiKeys(ctx, world.segmentCluster(), "seg/")
			if err != nil || len(segments) != 1 {
				return fmt.Errorf("segments %v, %v", segments, err)
			}
			object, err := world.segmentCluster().Get(ctx, segments[0].Key)
			if err != nil {
				return err
			}
			body := new(bytes.Buffer)
			_, err = body.ReadFrom(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			swapped := body.Bytes()
			// inside the first record's frames, past the header and its key block
			swapped[2000] ^= 0xff
			if err := world.segmentCluster().Delete(ctx, segments[0].Key); err != nil {
				return err
			}
			_, err = world.segmentCluster().PutIfNoneMatch(ctx, segments[0].Key, swapped, nil)
			return err
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-undecryptable", Steps: steps, Check: []Invariant{FI(1)}}, world.net)
	fiRequireViolation(t, result, 2, "FI-1", "does not decrypt for writerA")
}

// A committed record's batch deleted before evacuation moved it: no container holds it, so FI-1 finds the version's
// record gone.
func TestFi1CatchesACommittedRecordReclaimed(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			batches, err := fiKeys(ctx, world.cluster(), "pb/")
			if err != nil {
				return err
			}
			for _, batch := range batches {
				if err := world.cluster().Delete(ctx, batch.Key); err != nil {
					return err
				}
			}
			return nil
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-deleted-record", Steps: steps, Check: []Invariant{FI(1)}}, world.net)
	fiRequireViolation(t, result, 2, "FI-1", "version 1", "in no batch and in no container")
}

// A packed record read through pidx/ as a reader does: once evacuation moved version 1's record and its batch went,
// a pack's or parcel's entry serves it; the container deleted under its entry leaves FI-1 finding the record gone.
func TestFi1ResolvesAnEvacuatedRecordThroughPidx(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "clock", Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.evacuate},
		{Actor: "nightly", Action: func(ctx context.Context, net *Net) error {
			if batches, err := fiKeys(ctx, world.cluster(), "pb/"); err != nil || len(batches) != 0 {
				return fmt.Errorf("evacuation left batches %v, %v", batches, err)
			}
			for _, cluster := range []sidecar.BlobCluster{world.cluster(), world.segmentCluster()} {
				for _, prefix := range []string{"hp/", "pack/"} {
					containers, err := fiKeys(ctx, cluster, prefix)
					if err != nil {
						return err
					}
					for _, container := range containers {
						if err := cluster.Delete(ctx, container.Key); err != nil {
							return err
						}
					}
				}
			}
			return nil
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-pidx", Steps: steps, Check: []Invariant{FI(1)}}, world.net)
	fiRequireViolation(t, result, 4, "FI-1", "in no batch and in no container")
}

// See the file header.
type fiHandWorld struct {
	t         *testing.T
	ctx       context.Context
	net       *Net
	cluster   sidecar.BlobCluster
	heads     *evsservice.HeadStore
	networkId sidecar.Id
	repoId    sidecar.Id
	groupId   sidecar.Id
	repoKey   *sidecar.EvsRepoKey
	admin     *sidecartest.FakeGkmSigner
	stranger  *sidecartest.FakeGkmSigner
	view      *sidecartest.FakeGkmAuthView
	// each ref's chain, C_0 first
	chains   map[sidecar.Id][][sha256.Size]byte
	batchSeq uint32
	// what the next commit writes as the head's horizon and path epoch, nil the first epoch alone
	foldedThrough uint64
	pathEpoch     *protocol.EvsPathEpoch
}

func newFiHandWorld(t *testing.T) *fiHandWorld {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	world := &fiHandWorld{
		t: t, ctx: t.Context(), net: net, cluster: cluster,
		heads:     evsservice.NewHeadStore(net.Clock(), net.Host().ClockCheck, nil, evsservice.DefaultEvsSettings(), nil),
		networkId: sidecar.NewId(), repoId: sidecar.NewId(), groupId: sidecar.NewId(),
		admin: sidecartest.NewFakeGkmSigner(), stranger: sidecartest.NewFakeGkmSigner(),
		chains: map[sidecar.Id][][sha256.Size]byte{},
	}
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins: []*protocol.AclRepoAdminRow{{SidecarId: world.admin.SidecarId.Bytes()}},
	})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(sidecar.NewId(), world.admin.SidecarId, world.stranger.SidecarId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	world.view = sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			world.admin.SidecarId: world.admin.PublicKey(), world.stranger.SidecarId: world.stranger.PublicKey(),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{world.repoId: {world.admin.SidecarId, world.stranger.SidecarId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{world.repoId: {world.admin.SidecarId, world.stranger.SidecarId}},
	})
	SetAuthorizationView(net, world.networkId, world.view)

	put := func(key string, body []byte) {
		if _, err := cluster.PutIfNoneMatch(world.ctx, key, body, nil); err != nil {
			t.Fatal(err)
		}
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: world.admin.SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	put(sidecar.EvsPlaceKey(world.repoId), placeBytes)
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	put(sidecar.EvsRepoObjectKey(world.repoId), repoBytes)
	holders := sha256.Sum256([]byte("fi hand world holders"))
	repoKey, rotate, err := sidecar.NewGkmFirstGeneration(world.repoId, world.groupId, &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: world.view.Pin(), Time: net.Clock().Now(), HoldersSha256: holders[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	world.repoKey = repoKey
	generationBytes, err := StoreViewFixtureGeneration(rotate)
	if err != nil {
		t.Fatal(err)
	}
	put(sidecar.GkmGenerationPath(world.groupId, 1), generationBytes)
	return world
}

// One push as built and signed, and its record's place once written.
type fiHandPush struct {
	refId     sidecar.Id
	statement *sidecar.EvsStatement
	payload   []byte
	place     *protocol.EvsPlace
	signerId  sidecar.Id
}

// Builds push pushId on refId at its head, signed by signer: changes, new slots with their bodies, and erased keys.
func (self *fiHandWorld) build(refId sidecar.Id, refKind protocol.EvsRefKind, flags uint32, signer *sidecartest.FakeGkmSigner, pushId sidecar.Id, changes []*sidecar.EvsPlannedChange, newObjects []*sidecar.EvsNewObject, slotBodies [][]byte, erased []*sidecar.EvsErasedKey) (*fiHandPush, error) {
	chains := self.chains[refId]
	if chains == nil {
		chains = [][sha256.Size]byte{sidecar.EvsChainStart(self.repoId, refId)}
		self.chains[refId] = chains
	}
	baseVersion := uint64(len(chains) - 1)
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: refKind, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: chains[baseVersion],
		Generation: 1, GroupId: self.groupId, GenerationCommitment: self.repoKey.Commitment(), PathEpoch: 1,
		Auth: self.view.Pin(), SignerSidecarId: signer.SidecarId, ClientId: sidecar.NewId(),
		TimeMs: self.net.Clock().Now().UnixMilli(), Flags: flags, SealedMetadata: []byte("sealed metadata"),
		Changes: changes, NewObjects: newObjects, SlotBodies: slotBodies, Erased: erased,
	}
	built, err := sidecar.NewEvsStatementBuilder(signer.Sign).Build(plan)
	if err != nil {
		return nil, err
	}
	return &fiHandPush{refId: refId, statement: built.Statement, payload: built.Payload, signerId: signer.SidecarId}, nil
}

// Step 6: the push's record alone in a batch of the clock's minute.
func (self *fiHandWorld) writeRecord(ctx context.Context, push *fiHandPush) error {
	now := self.net.Clock().Now()
	minute := evsservice.BatchMinute(now)
	self.batchSeq += 1
	writer := sidecar.NewEvsBatchWriter(0xf1f6, minute, self.batchSeq, now.UnixMilli())
	place, err := writer.Add(&sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: push.refId,
		PushId: sidecar.Id(push.statement.Push.GetPushId()), SignerSidecarId: push.signerId, TimeMs: now.UnixMilli(),
		Body: sidecar.EvsPushRecordBody(push.statement.Bytes, push.payload),
	})
	if err != nil {
		return err
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		return err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsservice.BatchKey(minute, 0xf1f6, self.batchSeq), batchBytes, nil); err != nil {
		return err
	}
	push.place = place
	return nil
}

// Step 7: the ref's head at its next version, naming the push's statement at its record's place.
func (self *fiHandWorld) commit(ctx context.Context, push *fiHandPush) error {
	prior, err := self.heads.ReadCluster(ctx, self.cluster, self.repoId, push.refId)
	if err != nil {
		return err
	}
	chains := self.chains[push.refId]
	version := uint64(len(chains))
	chain := sidecar.EvsChainNext(chains[version-1], sidecar.Id(push.statement.Push.GetPushId()), push.statement.Sha256)
	next := evsservice.CloneEvsHead(prior.Head)
	statementPush := push.statement.Push
	next.Version = version
	next.Chain = chain[:]
	next.PushId = statementPush.GetPushId()
	next.RefKind = statementPush.GetRefKind()
	next.RefMode = statementPush.GetRefMode()
	next.GroupId = statementPush.GetGroupId()
	next.Generation = statementPush.GetGeneration()
	next.GenerationCommitment = statementPush.GetGenerationCommitment()
	next.Auth = statementPush.GetAuth()
	next.PathEpoch = &protocol.EvsPathEpoch{Current: 1}
	if self.pathEpoch != nil {
		next.PathEpoch = proto.Clone(self.pathEpoch).(*protocol.EvsPathEpoch)
	}
	next.FoldedThrough = max(prior.Head.GetFoldedThrough(), self.foldedThrough)
	if len(next.GetWindow()) == 0 {
		next.WindowBaseChain = chains[version-1][:]
	}
	changedPaths := []sidecar.EvsTokenPath{}
	for _, change := range push.statement.Changes {
		changedPaths = append(changedPaths, change.TokenPath)
	}
	entry := sidecar.NewEvsWindowEntry(push.statement.Sha256, statementPush, changedPaths, nil, 0 < len(changedPaths), push.place)
	next.Window = append(bytes.Clone(next.GetWindow()), entry.Encode()...)
	if _, err := self.heads.Commit(ctx, self.cluster, self.repoId, push.refId, prior, next); err != nil {
		return err
	}
	self.chains[push.refId] = append(chains, chain)
	return nil
}

// A committed file at a fresh token path of epoch 1, folded into its entry as a fold writes one, with the horizon
// the next commit raises over it. Returns its token path.
func (self *fiHandWorld) foldedFile(ctx context.Context, refId sidecar.Id) (sidecar.EvsTokenPath, error) {
	pushId := sidecar.NewId()
	change, err := self.fileChange(pushId)
	if err != nil {
		return nil, err
	}
	push, err := self.build(refId, protocol.EvsRefKind_EVS_REF_SHARED, 0, self.admin, pushId, []*sidecar.EvsPlannedChange{change}, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := self.writeRecord(ctx, push); err != nil {
		return nil, err
	}
	if err := self.commit(ctx, push); err != nil {
		return nil, err
	}
	version := uint64(len(self.chains[refId]) - 1)
	entryBytes, err := proto.Marshal(&protocol.EvsIndexEntry{Versions: []*protocol.EvsIndexVersion{
		{PushId: pushId.Bytes(), CommitVersion: version, EntryVersion: change.EntryVersion},
	}})
	if err != nil {
		return nil, err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsOracleIndexKey(self.repoId, refId, 1, change.TokenPath), entryBytes, nil); err != nil {
		return nil, err
	}
	self.foldedThrough = version
	return change.TokenPath, nil
}

// A cut-over of refId to epoch 2: one map part moving each of moves, uploaded under pmap/, then the PATH_EPOCH push
// committed with epoch 1 listed as its source. Returns the map's hash.
func (self *fiHandWorld) cutOver(ctx context.Context, refId sidecar.Id, moves []*protocol.EvsPathMove) ([]byte, error) {
	chains := self.chains[refId]
	sourceVersion := uint64(len(chains) - 1)
	partBody, err := proto.Marshal(&protocol.EvsPathMap{
		RepoId: self.repoId.Bytes(), RefId: refId.Bytes(), PathEpoch: 2, Part: 1, Parts: 1, Moves: moves,
		SourceVersion: sourceVersion, SourceChain: chains[sourceVersion][:],
	})
	if err != nil {
		return nil, err
	}
	signed, err := self.admin.Sign("evs-path-epoch", bridge.SignedType_SIGNED_EVS_PATH_MAP, partBody, nil)
	if err != nil {
		return nil, err
	}
	partBytes, err := proto.Marshal(signed)
	if err != nil {
		return nil, err
	}
	mapSha256 := sidecar.EvsPathMapSha256([][]byte{partBytes})
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsOracleMapPrefix(self.repoId, refId, 2, mapSha256)+evsOracleNumber(1)+"/_", partBytes, nil); err != nil {
		return nil, err
	}
	pushId := sidecar.NewId()
	baseVersion := uint64(len(chains) - 1)
	built, err := sidecar.NewEvsStatementBuilder(self.admin.Sign).Build(&sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: chains[baseVersion],
		Generation: 1, GroupId: self.groupId, GenerationCommitment: self.repoKey.Commitment(), PathEpoch: 2,
		Auth: self.view.Pin(), SignerSidecarId: self.admin.SidecarId, ClientId: sidecar.NewId(),
		TimeMs: self.net.Clock().Now().UnixMilli(), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH),
		PathMapSha256: mapSha256, MapSourceVersion: sourceVersion, MapSourceChain: chains[sourceVersion][:],
		SealedMetadata: []byte("sealed metadata"),
	})
	if err != nil {
		return nil, err
	}
	push := &fiHandPush{refId: refId, statement: built.Statement, payload: built.Payload, signerId: self.admin.SidecarId}
	if err := self.writeRecord(ctx, push); err != nil {
		return nil, err
	}
	self.pathEpoch = &protocol.EvsPathEpoch{Current: 2, Sources: []*protocol.EvsEpochSource{{Epoch: 1, MapSha256: mapSha256}}}
	return mapSha256, self.commit(ctx, push)
}

// A move of one path from its epoch-1 token path to a fresh epoch-2 one.
func fiMove(source sidecar.EvsTokenPath) (*protocol.EvsPathMove, sidecar.EvsTokenPath) {
	target := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	return &protocol.EvsPathMove{
		NewTokenPath: target.Components(),
		Sources:      []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: source.Components()}},
		SealedName:   []byte("a name sealed in epoch 2"),
	}, target
}

// A file creation's change at a fresh token path, naming slots.
func (self *fiHandWorld) fileChange(pushId sidecar.Id, slotIds ...sidecar.Id) (*sidecar.EvsPlannedChange, error) {
	slotIdBytes := [][]byte{}
	for _, slotId := range slotIds {
		slotIdBytes = append(slotIdBytes, slotId.Bytes())
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: 1, PushId: pushId.Bytes(), TimeMs: self.net.Clock().Now().UnixMilli(),
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Chain:   []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
		SlotIds: slotIdBytes,
	})
	if err != nil {
		return nil, err
	}
	return &sidecar.EvsPlannedChange{TokenPath: sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, EntryVersion: entryBytes}, nil
}

// A slot body of keyCount keys, each a key wrapped under fek_1.
func (self *fiHandWorld) slotBody(keyCount int) ([]byte, error) {
	fek, err := sidecar.NewEvsFekKey(self.repoKey)
	if err != nil {
		return nil, err
	}
	slot := &protocol.EvsSlotObject{}
	for i := range keyCount {
		wrapped, err := sidecar.EvsWrapObjectKey(fek, sidecar.NewEvsObjectKey())
		if err != nil {
			return nil, err
		}
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: uint32(i), Generation: 1, Wrapped: wrapped})
	}
	return sidecar.EvsEncodeSlotObject(slot)
}

// A push on main creating one file whose version names a new slot of two keys, its slot written after its record,
// as step 6 writes it, and committed unless pending. Returns the slot id and the push.
func (self *fiHandWorld) slotPush(ctx context.Context, refId sidecar.Id, pending bool) (sidecar.Id, *fiHandPush, error) {
	slotId := sidecar.NewEvsSlotId()
	body, err := self.slotBody(2)
	if err != nil {
		return slotId, nil, err
	}
	pushId := sidecar.NewId()
	change, err := self.fileChange(pushId, slotId)
	if err != nil {
		return slotId, nil, err
	}
	push, err := self.build(refId, protocol.EvsRefKind_EVS_REF_SHARED, 0, self.admin, pushId, []*sidecar.EvsPlannedChange{change},
		[]*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()}}, [][]byte{body}, nil)
	if err != nil {
		return slotId, nil, err
	}
	if err := self.writeRecord(ctx, push); err != nil {
		return slotId, nil, err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsOracleSlotKey(self.repoId, slotId.Bytes()), body, nil); err != nil {
		return slotId, nil, err
	}
	if pending {
		return slotId, push, nil
	}
	return slotId, push, self.commit(ctx, push)
}

// An ERASE of slotId's key on the repo's erasure ref, signed by signer and committed, then the slot rewritten without
// the key, as §11.12's slots/delete does.
func (self *fiHandWorld) erase(ctx context.Context, signer *sidecartest.FakeGkmSigner, slotId sidecar.Id, keyIndex uint16) error {
	push, err := self.build(sidecar.EvsErasureRefId(self.repoId), protocol.EvsRefKind_EVS_REF_ERASURE, uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE), signer,
		sidecar.NewId(), nil, nil, nil, []*sidecar.EvsErasedKey{{SlotId: slotId, KeyIndex: keyIndex}})
	if err != nil {
		return err
	}
	if err := self.writeRecord(ctx, push); err != nil {
		return err
	}
	if err := self.commit(ctx, push); err != nil {
		return err
	}
	key := evsOracleSlotKey(self.repoId, slotId.Bytes())
	object, err := self.cluster.Get(ctx, key)
	if err != nil {
		return err
	}
	defer object.Body.Close()
	slotBytes := new(bytes.Buffer)
	if _, err := slotBytes.ReadFrom(object.Body); err != nil {
		return err
	}
	rewritten, _, err := sidecar.EvsSlotWithoutKeys(slotBytes.Bytes(), []uint32{uint32(keyIndex)})
	if err != nil {
		return err
	}
	_, err = self.cluster.PutIfMatch(ctx, key, object.Etag, rewritten, nil)
	return err
}

// A slot's key destroyed by an ERASE whose signer is no repo admin: FI-1 reads the ERASE's authority, finds it
// wanting, and the key lost, rather than reading a missing key as erased.
func TestFi1CatchesASlotKeyAnUnauthorizedEraseTook(t *testing.T) {
	world := newFiHandWorld(t)
	var slotId sidecar.Id
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "eraserS", Action: func(ctx context.Context, net *Net) error {
			return world.erase(ctx, world.stranger, slotId, 1)
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-unauthorized-erase", Steps: steps, Check: []Invariant{FI(1)}}, world.net)
	fiRequireViolation(t, result, 1, "FI-1", "lost key 1, which no authorized, committed ERASE names")
	fiRequireViolation(t, result, 1, "FI-1", "is not authorized", "no repo admin")
}

// The twin: the same ERASE by a repo admin excuses the key it destroyed, and the closure reads clean.
func TestFi1TakesASlotKeyAnAuthorizedEraseTook(t *testing.T) {
	world := newFiHandWorld(t)
	var slotId sidecar.Id
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "eraserA", Action: func(ctx context.Context, net *Net) error {
			return world.erase(ctx, world.admin, slotId, 1)
		}},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi1-authorized-erase", Steps: steps, Check: fiChecks()}, world.net))
}

// A key no ERASE names at all goes missing: FI-1 reads it lost.
func TestFi1CatchesASlotKeyLostWithNoErase(t *testing.T) {
	world := newFiHandWorld(t)
	var slotId sidecar.Id
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			key := evsOracleSlotKey(world.repoId, slotId.Bytes())
			info, err := world.cluster.Head(ctx, key)
			if err != nil {
				return err
			}
			body, err := world.slotBody(1)
			if err != nil {
				return err
			}
			_, err = world.cluster.PutIfMatch(ctx, key, info.Etag, body, nil)
			return err
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-lost-key", Steps: steps, Check: []Invariant{FI(1)}}, world.net)
	fiRequireViolation(t, result, 1, "FI-1", "lost key 1")
}

// A slot a committed version names deleted outright: FI-1 finds it gone.
func TestFi1CatchesACommittedSlotDeleted(t *testing.T) {
	world := newFiHandWorld(t)
	var slotId sidecar.Id
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			return world.cluster.Delete(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()))
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-deleted-slot", Steps: steps, Check: fiChecks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-1", "which a committed version names, is gone")
	fiRequireViolation(t, result, 1, "FI-6", "a committed object reclaimed")
}

// A committed PATH_EPOCH's map part deleted: FI-1 finds the map, which the ref's history needs, gone.
func TestFi1CatchesACommittedMapPartDeleted(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var mapSha256 []byte
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			tokenPath, err := world.foldedFile(ctx, main)
			if err != nil {
				return err
			}
			move, _ := fiMove(tokenPath)
			mapSha256, err = world.cutOver(ctx, main, []*protocol.EvsPathMove{move})
			return err
		}},
		{Actor: "taskworker", Action: func(ctx context.Context, net *Net) error {
			return world.cluster.Delete(ctx, evsOracleMapPrefix(world.repoId, main, 2, mapSha256)+evsOracleNumber(1)+"/_")
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi1-map-part", Steps: steps, Check: []Invariant{FI(1)}}, world.net)
	fiRequireViolation(t, result, 1, "FI-1", "the PATH_EPOCH at 2", "its map has no part under pmap/")
}

// A shred's run: a committed slot, then repo/ moved to shredding under a deletion id and the repo's slots deleted, as
// §11.12's phases do; authorized names the deletion in the access log's RepoDelete.
func fiShredRun(t *testing.T, authorized bool) *Result {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	main := sidecar.NewId()
	if authorized {
		rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
			RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Admins:   []*protocol.AclRepoAdminRow{{SidecarId: world.admin.SidecarId.Bytes()}},
			Deletion: &protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), Now: true, DeletedAt: 2},
		})
		SetAuthorizationView(world.net, world.networkId, sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{Rows: rows}))
	}
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "shred", Action: func(ctx context.Context, net *Net) error {
			key := sidecar.EvsRepoObjectKey(world.repoId)
			info, err := world.cluster.Head(ctx, key)
			if err != nil {
				return err
			}
			repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
				RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_SHREDDING,
				Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(), DeletionId: deletionId.Bytes(),
			})
			if err != nil {
				return err
			}
			if _, err := world.cluster.PutIfMatch(ctx, key, info.Etag, repoBytes, nil); err != nil {
				return err
			}
			slots, err := fiKeys(ctx, world.cluster, evsOracleRepoPrefix("slot/", world.repoId))
			if err != nil {
				return err
			}
			for _, slot := range slots {
				if err := world.cluster.Delete(ctx, slot.Key); err != nil {
					return err
				}
			}
			return nil
		}},
	}
	return Run(t.Context(), &Schedule{Id: "fi1-shred", Steps: steps, Check: fiChecks()}, world.net)
}

// A shred authorized by the access log's RepoDelete excuses the repo's closure.
func TestFi1TakesAnAuthorizedShred(t *testing.T) {
	fiRequirePass(t, fiShredRun(t, true))
}

// The same shred with no RepoDelete in the access log excuses nothing: what it took reads as missing.
func TestFi1CatchesAnUnauthorizedShred(t *testing.T) {
	result := fiShredRun(t, false)
	fiRequireViolation(t, result, 1, "FI-1", "repo/ shows a shred the access log holds no RepoDelete for")
	fiRequireViolation(t, result, 1, "FI-1", "which a committed version names, is gone")
}

// The store's ids, held to their key forms: what the oracle builds from the format's text names what the engine
// writes.
func TestEvsOracleKeysAreTheFormats(t *testing.T) {
	repoId := sidecar.NewId()
	refId := sidecar.NewId()
	place := &protocol.EvsPlace{Minute: evsservice.BatchMinute(time.Date(2026, 11, 10, 12, 34, 0, 0, time.UTC)), Instance: 7, Seq: 9}
	tokenPath := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken(), sidecar.NewEvsRandomToken()}
	segmentId := sha256.Sum256([]byte("segment"))
	mapSha256 := sha256.Sum256([]byte("map"))
	pairs := [][2]string{
		{evsOracleBatchKey(place), evsservice.BatchKey(place.GetMinute(), 7, 9)},
		{evsOracleLogPageKey(repoId, refId, 3), evsservice.LogPageKey(repoId, refId, 3)},
		{evsOracleIndexKey(repoId, refId, 2, tokenPath), evsservice.IndexEntryKey(repoId, refId, 2, tokenPath)},
		{evsOracleIndexKey(repoId, refId, 2, nil), evsservice.IndexEntryKey(repoId, refId, 2, nil)},
		{evsOracleSegmentKey(repoId, segmentId[:]), evsservice.SegmentKey(repoId, segmentId)},
		{evsOracleSlotKey(repoId, refId.Bytes()), evsservice.SlotKey(repoId, refId)},
		{evsOracleMapPrefix(repoId, refId, 4, mapSha256[:]), evsservice.PathMapPrefix(repoId, refId, 4, mapSha256[:])},
		{evsOracleRefPrefix("pidx/", repoId, refId), evsservice.PidxRefPrefix(repoId, refId)},
		{evsOracleIndexPrefix(repoId, refId, 2), evsservice.IndexEpochPrefix(repoId, refId, 2)},
	}
	for _, pair := range pairs {
		if pair[0] != pair[1] {
			t.Errorf("the oracle builds %s where the engine writes %s", pair[0], pair[1])
		}
	}
	if minute, ok := evsOracleBatchKeyMinute(evsOracleBatchKey(place)); !ok || minute.Unix() != int64(place.GetMinute())*60 {
		t.Errorf("the batch key's minute: %v, %t", minute, ok)
	}
	if repo, ok := evsOracleKeyRepo(evsOracleSlotKey(repoId, refId.Bytes())); !ok || repo != repoId {
		t.Errorf("a slot key's repo: %s, %t", repo, ok)
	}
	epoch, parsed, err := fi6ParseIndexKey(evsOracleRefPrefix("idx/", repoId, refId), evsOracleIndexKey(repoId, refId, 2, tokenPath))
	if err != nil || epoch != 2 || !parsed.Equal(tokenPath) {
		t.Errorf("an index key parsed: %d, %v, %v", epoch, parsed, err)
	}
}
