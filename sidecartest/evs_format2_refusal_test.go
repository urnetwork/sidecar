// Format 1's refusal of format 2, swept end to end (EVS1-M2-39; §11.6's kinds and format rows, D-EVS-39, D-PHASE-9,
// FI-17, FS-72's and FS-95's format-1 cases): every row of testdata/evs/format2_refusals.json driven on T2 through
// the code that meets it. The rows are the reservation as M10's planners must keep it: each names a format-2
// construct, the numbers of testdata/evs/reserved_numbers.yml it uses, the side that meets it, what format-1 code
// answers, and a twin that is malformed or unsigned and must not answer as needing format 2.
//
// The world is one FakeHost with two engines on its stores and two kinds of device:
//
//   - format1, an evsservice.EvsEngine of InstanceFormat 1: the code under test, as M2's binary and a rolled-back
//     one are;
//   - format2, the same engine as format 2 with the network in §19.11's format2 gate and rules that pass every
//     format-2 push: the format-2 evs whose stored bytes a format-1 evs serves and a format-1 reader meets. Its rules
//     are EVS2-M10-06's, not built here, so what it commits is held only to format 2's shapes;
//   - a format-2 device, which builds each construct with the root's format-2 builders, sealed under the repo's real
//     keys and signed by an admitted writer, and holds it to format 2's parsers before it is sent;
//   - format-1 devices, sidecar.EvsClient as built, writing and reading through an engine's handler.
//
// Sides, each a test below:
//
//   - evs rows post the construct to format1 and hold the answer, the head's refusal record, every stored object and
//     the engine's alarms;
//   - reader rows commit the construct through format2, put it in the stores as a format-2 evs would, or lay it into
//     a read reply, and read it with a format-1 device through format1;
//   - the repo row holds a format-1 evs to a repo that format 2 raised, and the evacuator row a format-1 evacuation
//     to a format-2 batch;
//   - writer rows hold the paths, refs and setting a format-1 device refuses before any request;
//   - config rows, §7.9's VersioningRules and §8.8's RepoVersioning, are driven by the root's own tests, which each
//     row names and the coverage test finds;
//   - the slot rule's two refusals (FS-95), which format 1 checks from M2.
//
// The coverage test holds the rows to testdata/evs/reserved_numbers.yml: every number format 1 reserves for format 2
// is driven by a row, held by a named test, or listed unswept with its reason. T3, the same rows through server's
// handlers on real stores, is not here: this task's files are this package's.
//
// Nothing sleeps: the clock is fake and every wait is on a channel the engine closes.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const format2RefusalVectorsPath = "../testdata/evs/format2_refusals.json"

// testdata/evs/format2_refusals.json.
type format2RefusalVectors struct {
	Description string `json:"description"`
	// FORMAT_UNSUPPORTED's needs_format on every refusing row.
	NeedsFormat uint32               `json:"needs_format"`
	Rows        []*format2RefusalRow `json:"rows"`
	// §11.8's slot rule as format 1 checks it from M2 (FS-95).
	SlotRule []*format2SlotRuleRow `json:"slot_rule"`
	// Reserved numbers no row drives, each with the test that holds format 1 to it.
	Elsewhere []*format2RefusalElsewhere `json:"elsewhere"`
	Unswept   []*format2RefusalUnswept   `json:"unswept"`
}

type format2RefusalRow struct {
	Name      string `json:"name"`
	Construct string `json:"construct"`
	// reserved_numbers.yml's keys this construct uses.
	Numbers []string `json:"numbers"`
	// evs, reader, writer, repo, evacuator or config.
	Side string `json:"side"`
	// format_unsupported, ignored, unavailable, reserved, left or folded.
	Outcome string `json:"outcome"`
	// An evs row: the answer's status, and whether the head records the refusal.
	Status   int                 `json:"status,omitempty"`
	Recorded bool                `json:"recorded,omitempty"`
	Twin     *format2RefusalTwin `json:"twin,omitempty"`
	// A config row, which another package's test drives: that test.
	HeldBy *format2RefusalTest `json:"held_by,omitempty"`
}

// A test by its file, from the module root, and its name.
type format2RefusalTest struct {
	File string `json:"file"`
	Test string `json:"test"`
}

// One of the slot rule's refusals.
type format2SlotRuleRow struct {
	Name      string `json:"name"`
	Construct string `json:"construct"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Recorded  bool   `json:"recorded"`
	Twin      string `json:"twin"`
}

// Reserved numbers nothing here drives or names a test for, with why.
type format2RefusalUnswept struct {
	Numbers []string `json:"numbers"`
	Why     string   `json:"why"`
}

type format2RefusalTwin struct {
	Construct string `json:"construct"`
	// refused: evs answers Code at Status, recording nothing. alarm: the reader raises evs_alarm Alarm. evs_alarm:
	// evs raises its alarm Alarm. unavailable: evs answers 503. committed: the write commits.
	Outcome string `json:"outcome"`
	Status  int    `json:"status,omitempty"`
	Code    string `json:"code,omitempty"`
	Alarm   string `json:"alarm,omitempty"`
}

type format2RefusalElsewhere struct {
	Numbers []string `json:"numbers"`
	// The file, from the module root, and the test in it.
	File string `json:"file"`
	Test string `json:"test"`
	Why  string `json:"why"`
}

func loadFormat2RefusalVectors(t *testing.T) *format2RefusalVectors {
	t.Helper()
	vectorBytes, err := os.ReadFile(format2RefusalVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(vectorBytes))
	decoder.DisallowUnknownFields()
	vectors := &format2RefusalVectors{}
	if err := decoder.Decode(vectors); err != nil {
		t.Fatalf("%s: %v", format2RefusalVectorsPath, err)
	}
	return vectors
}

// The rows of side, each with a driver in drivers and no driver without a row.
func format2RefusalRowsOf[D any](t *testing.T, side string, drivers map[string]D) []*format2RefusalRow {
	t.Helper()
	vectors := loadFormat2RefusalVectors(t)
	if vectors.NeedsFormat != sidecar.EvsRepoFormat2 {
		t.Fatalf("needs_format %d", vectors.NeedsFormat)
	}
	rows := []*format2RefusalRow{}
	named := map[string]bool{}
	for _, row := range vectors.Rows {
		if row.Side != side {
			continue
		}
		if _, ok := drivers[row.Name]; !ok {
			t.Errorf("%s: a %s row no driver builds", row.Name, side)
			continue
		}
		named[row.Name] = true
		rows = append(rows, row)
	}
	for name := range drivers {
		if !named[name] {
			t.Errorf("%s: a %s driver with no row", name, side)
		}
	}
	return rows
}

// The engine's log, kept for its alarms.
type format2Log struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *format2Log) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *format2Log) Info(args ...any)                    { self.add(fmt.Sprint(args...)) }
func (self *format2Log) Infof(format string, args ...any)    { self.add(fmt.Sprintf(format, args...)) }
func (self *format2Log) Warningf(format string, args ...any) { self.add(fmt.Sprintf(format, args...)) }
func (self *format2Log) Errorf(format string, args ...any)   { self.add(fmt.Sprintf(format, args...)) }
func (self *format2Log) V(level int32) sidecar.Verbose       { return sidecar.NewNoopLogger().V(level) }

// The lines that raise an alarm.
func (self *format2Log) alarms() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := []string{}
	for _, line := range self.lines {
		if strings.Contains(line, "alarm") {
			alarms = append(alarms, line)
		}
	}
	return alarms
}

// The newest verified state as the world's one view gives it: every scope honored, the repo general.
type format2AuthState struct {
	networkId sidecar.Id
}

func (self *format2AuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *format2AuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *format2AuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *format2AuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: self.networkId}, evsservice.EvsAuthAllowed
}

type format2GateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *format2GateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.view, evsservice.EvsAuthAllowed
}

// A format-1 device of the world: the client as built, and the events it raised.
type format2Device struct {
	world  *format2World
	signer *FakeGkmSigner
	client *sidecar.EvsClient

	stateLock sync.Mutex
	events    []sidecar.SidecarEvent
}

// The alarms the device raised: evs_alarm's reasons, and head_alarm as fork.
func (self *format2Device) alarms() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := []string{}
	for _, event := range self.events {
		switch event.Kind {
		case sidecar.SidecarEventEvsAlarm:
			alarms = append(alarms, string(event.EvsAlarm))
		case sidecar.SidecarEventHeadAlarm:
			alarms = append(alarms, "fork")
		}
	}
	return alarms
}

// The newest file at path.
func (self *format2Device) read(path string) ([]byte, error) {
	out := &bytes.Buffer{}
	err := self.world.call(func(ctx context.Context) error {
		_, err := self.client.Repo(self.world.repoId).ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, out)
		return err
	})
	return out.Bytes(), err
}

func (self *format2Device) write(path string, content []byte) error {
	return self.writeRef(nil, path, content, "")
}

func (self *format2Device) writeRef(refName []byte, path string, content []byte, versioning string) error {
	defer self.world.settle()
	return self.world.call(func(ctx context.Context) error {
		_, err := self.client.Repo(self.world.repoId).Write(ctx, &sidecar.EvsWriteArgs{
			RefName: refName, Path: path, Content: bytes.NewReader(content), Size: int64(len(content)), Versioning: versioning,
		})
		return err
	})
}

func (self *format2Device) remove(path string) error {
	defer self.world.settle()
	return self.world.call(func(ctx context.Context) error {
		_, err := self.client.Repo(self.world.repoId).Write(ctx, &sidecar.EvsWriteArgs{Path: path, Remove: true})
		return err
	})
}

// Waits out the serving engine's step 8s, so the next read meets the head a commit left and not the cache before it.
func (self *format2World) settle() {
	self.stateLock.Lock()
	engine := self.serving
	self.stateLock.Unlock()
	self.awaitStepEights(engine)
}

// An answer evs gave a device that the device waits out and sends again: a 429 or a 503.
type format2Wait struct {
	status     int
	code       protocol.EvsRefusalCode
	retryAfter string
}

func (self *format2Wait) Error() string {
	return fmt.Sprintf("evs answered %d %s, Retry-After %q", self.status, format2CodeName(self.code), self.retryAfter)
}

// One call of a device. The clock stands still, so an answer the client would wait out and send again ends the
// call instead, as that answer.
func (self *format2World) call(run func(ctx context.Context) error) error {
	ctx, cancel := context.WithCancel(self.ctx)
	defer cancel()
	self.stateLock.Lock()
	self.callCancel = cancel
	self.callWait = nil
	self.stateLock.Unlock()
	err := run(ctx)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.callCancel = nil
	if self.callWait != nil {
		return self.callWait
	}
	return err
}

// See the file header.
type format2World struct {
	t         *testing.T
	ctx       context.Context
	clock     *FakeClock
	host      *FakeHost
	cluster   sidecar.BlobCluster
	networkId sidecar.Id
	repoId    sidecar.Id
	// main's
	refId    sidecar.Id
	clientId sidecar.Id
	writer   *FakeGkmSigner
	reader   *FakeGkmSigner
	// a key no state admits, which signs the unsigned twins
	stranger *FakeGkmSigner
	view     *FakeGkmAuthView
	gkm      *FakeGkm
	repoKey  *sidecar.EvsRepoKey
	manifest *sidecar.EvsManifestKey
	fek      *sidecar.EvsFekKey
	pathKey  *sidecar.EvsPathKey

	receiptKeys *evsservice.ReceiptKeys
	quota       *evsservice.QuotaGate
	usage       *evsservice.UsageBatcher
	format1     *evsservice.EvsEngine
	format2     *evsservice.EvsEngine
	format1Log  *format2Log

	stateLock sync.Mutex
	// the engine the devices' requests reach
	serving *evsservice.EvsEngine
	// what a format-2 evs, or a hostile one, makes of each frame of a read reply; nil leaves the reply as served
	rewrite      func(frame *protocol.EvsReadFrame)
	requestCount int
	// the device call in flight, and the answer that ended it (call)
	callCancel context.CancelFunc
	callWait   *format2Wait
}

func newFormat2World(t *testing.T) *format2World {
	t.Helper()
	ctx := t.Context()
	clock := NewFakeClock(DefaultClockStart())
	hostSettings := DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := NewFakeHost(ctx, clock, nil, nil, hostSettings)
	RegisterEvsTwins(host.Redis)
	world := &format2World{
		t: t, ctx: ctx, clock: clock, host: host,
		networkId: sidecar.NewId(), repoId: sidecar.NewId(), clientId: sidecar.NewId(),
		writer: NewFakeGkmSigner(), reader: NewFakeGkmSigner(), stranger: NewFakeGkmSigner(),
		format1Log: &format2Log{},
	}
	network := connect.Id(world.networkId).String()
	gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q]}\n", network, network)
	if err := host.Gates.Set(gates); err != nil {
		t.Fatal(err)
	}
	// a network with transfer to spend, so no read marks it spent and no push meets §20's gate
	host.Quota.SetBalance(connect.Id(world.networkId), 1<<40)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	world.cluster = cluster

	rows := FakeGkmAuthRows(&protocol.AclRepo{RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	sidecarRows, member := FakeGkmAuthMemberDevices(sidecar.NewId(), world.writer.SidecarId, world.reader.SidecarId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	world.view = NewFakeGkmAuthLog().Append(&FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			world.writer.SidecarId: world.writer.PublicKey(),
			world.reader.SidecarId: world.reader.PublicKey(),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{world.repoId: {world.writer.SidecarId, world.reader.SidecarId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{world.repoId: {world.writer.SidecarId}},
	})
	world.gkm = NewFakeGkm(clock, host.Blobs, nil)
	writerGkm := world.gkm.Client(world.writer.SidecarId, world.writer.Sign)
	writerGkm.AuthAdvanced(world.view)
	if world.repoKey, err = writerGkm.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL}); err != nil {
		t.Fatal(err)
	}
	if world.manifest, err = sidecar.NewEvsManifestKey(world.repoKey); err != nil {
		t.Fatal(err)
	}
	if world.fek, err = sidecar.NewEvsFekKey(world.repoKey); err != nil {
		t.Fatal(err)
	}
	if world.pathKey, err = sidecar.NewEvsPathKey(world.repoKey); err != nil {
		t.Fatal(err)
	}
	refKey, err := sidecar.NewEvsRefKey(world.repoKey)
	if err != nil {
		t.Fatal(err)
	}
	if world.refId, err = sidecar.EvsRefId(refKey, []byte("main")); err != nil {
		t.Fatal(err)
	}

	if world.usage, err = evsservice.NewUsageBatcher(ctx, host.ServiceHost(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.usage.Close)
	if world.quota, err = evsservice.NewQuotaGate(ctx, host.ServiceHost(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.quota.Close)
	receiptKey := sha256.Sum256([]byte("format 2 refusals receipt key"))
	world.receiptKeys, err = evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{
		{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-48 * time.Hour)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.format1 = world.newEngine(sidecar.EvsRepoFormat1, world.format1Log)
	world.format2 = world.newEngine(sidecar.EvsRepoFormat2, nil)
	world.serving = world.format1

	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: world.writer.SidecarId}).Marshal()
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
	if _, err := cluster.PutIfNoneMatch(ctx, evsservice.RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	return world
}

// An engine of the instance format on the world's stores. A format-2 one takes every format-2 push the gate admits.
func (self *format2World) newEngine(instanceFormat uint32, log sidecar.Logger) *evsservice.EvsEngine {
	self.t.Helper()
	settings := evsservice.DefaultEvsSettings()
	settings.InstanceFormat = instanceFormat
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	// the clock stands still, so a cached repo/ would never lapse
	settings.RepoCacheTtl = 0
	deps := &evsservice.EvsEngineDeps{
		AuthState: &format2AuthState{networkId: self.networkId},
		Log:       log,
		Uploads:   &evsservice.EvsUploadDeps{Keys: self.receiptKeys, Quota: self.quota, Usage: self.usage},
		GateViews: &format2GateViews{networkId: self.networkId, view: self.view},
	}
	if instanceFormat == sidecar.EvsRepoFormat2 {
		deps.Format2Rules = func(view *evsservice.PushView) *evsservice.EvsCheckRefusal { return nil }
	}
	engine, err := evsservice.NewEvsEngine(self.ctx, self.host.ServiceHost(), settings, deps)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// The engine the devices reach from now on.
func (self *format2World) serve(engine *evsservice.EvsEngine) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.serving = engine
}

func (self *format2World) setRewrite(rewrite func(frame *protocol.EvsReadFrame)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rewrite = rewrite
}

func (self *format2World) requests() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.requestCount
}

// The devices' transport: the serving engine's handler, a read reply's frames passing through rewrite.
func (self *format2World) RoundTrip(request *http.Request) (*http.Response, error) {
	self.stateLock.Lock()
	engine := self.serving
	rewrite := self.rewrite
	self.requestCount += 1
	self.stateLock.Unlock()
	recorder := httptest.NewRecorder()
	engine.Handler().ServeHTTP(recorder, request)
	response := recorder.Result()
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		reply := &protocol.EvsRefusalReply{}
		proto.Unmarshal(recorder.Body.Bytes(), reply)
		self.stateLock.Lock()
		if self.callCancel != nil && self.callWait == nil {
			self.callWait = &format2Wait{status: response.StatusCode, code: reply.GetCode(), retryAfter: response.Header.Get("Retry-After")}
			self.callCancel()
		}
		self.stateLock.Unlock()
	}
	if rewrite == nil || response.StatusCode != http.StatusOK || !strings.HasSuffix(request.URL.Path, "/read") {
		return response, nil
	}
	rewritten := &bytes.Buffer{}
	frames := sidecar.NewEvsReadFrames(response.Body)
	for {
		frame, err := frames.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		rewrite(frame)
		frameBytes, err := sidecar.EncodeEvsReadFrame(frame)
		if err != nil {
			return nil, err
		}
		rewritten.Write(frameBytes)
	}
	response.Body.Close()
	response.Body = io.NopCloser(rewritten)
	response.ContentLength = int64(rewritten.Len())
	return response, nil
}

// A token of sidecarId for scopes.
func (self *format2World) token(sidecarId sidecar.Id, scopes []string) string {
	connectSidecarId := connect.Id(sidecarId)
	return self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.networkId),
		ClientId:  connect.Id(self.clientId),
		SidecarId: &connectSidecarId,
		Audience:  evsservice.EvsAudience,
		Scopes:    scopes,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
}

// The writer's rw token on the repo.
func (self *format2World) writerToken() string {
	return self.token(self.writer.SidecarId, []string{"repo:" + self.repoId.String() + ":rw"})
}

// A format-1 device of signer.
func (self *format2World) device(signer *FakeGkmSigner) *format2Device {
	self.t.Helper()
	device := &format2Device{world: self, signer: signer}
	gkmClient := self.gkm.Client(signer.SidecarId, signer.Sign)
	gkmClient.AuthAdvanced(self.view)
	identity := &sidecar.SidecarIdentity{
		NetworkId: self.networkId, SidecarId: signer.SidecarId, ClientId: self.clientId, Generation: 1,
		IdentityPublicKey: signer.PublicKey(),
	}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    "https://evs.example",
		Transport: self,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return self.token(signer.SidecarId, scopes), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkmClient,
		Store:    NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return self.view },
		Emit: func(event sidecar.SidecarEvent) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.events = append(device.events, event)
		},
		Clock:    self.clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	device.client = client
	return device
}

// main's head from the cluster.
func (self *format2World) head() *evsservice.EvsStoredHead {
	self.t.Helper()
	head, err := self.format1.Heads().ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		self.t.Fatal(err)
	}
	return head
}

// repo/ as the cluster holds it.
func (self *format2World) repo() *protocol.EvsRepoObject {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, evsservice.RepoKey(self.repoId))
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	repoBytes, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	repo := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(repoBytes, repo); err != nil {
		self.t.Fatal(err)
	}
	return repo
}

// Every stored object but main's head: what a refusal, which only the head records, must leave as it was.
func (self *format2World) objects() map[string][]byte {
	headKey := evsservice.HeadKey(self.repoId, self.refId)
	objects := map[string][]byte{}
	for key, object := range self.host.Blobs.Dump() {
		if !strings.HasSuffix(key, headKey) {
			objects[key] = bytes.Clone(object)
		}
	}
	return objects
}

func (self *format2World) requireSameObjects(what string, before map[string][]byte) {
	self.t.Helper()
	after := self.objects()
	for key, object := range after {
		if held, ok := before[key]; !ok || !bytes.Equal(held, object) {
			self.t.Errorf("%s: wrote %s", what, key)
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			self.t.Errorf("%s: deleted %s", what, key)
		}
	}
}

// Waits for every step 8 an engine started.
func (self *format2World) awaitStepEights(engine *evsservice.EvsEngine) {
	self.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		started, finished, changed := engine.StepEights()
		if started == finished {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			self.t.Fatal("step 8 never finished")
		}
	}
}

// A request body sent to an engine's route under the writer's token.
func (self *format2World) send(engine *evsservice.EvsEngine, method string, route string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(self.ctx, method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+route, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+self.writerToken())
	recorder := httptest.NewRecorder()
	engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

func (self *format2World) postPush(engine *evsservice.EvsEngine, body *protocol.EvsPushRequest) *httptest.ResponseRecorder {
	self.t.Helper()
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	recorder := self.send(engine, http.MethodPost, "/push", bodyBytes)
	self.awaitStepEights(engine)
	return recorder
}

// The refusal an answer carries; an empty one for a 200.
func format2Refusal(t *testing.T, recorder *httptest.ResponseRecorder) *protocol.EvsRefusalReply {
	t.Helper()
	reply := &protocol.EvsRefusalReply{}
	if recorder.Code == http.StatusOK {
		return reply
	}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatalf("a refusal that does not parse: %v", err)
	}
	return reply
}

// The code's name as the vectors spell it.
func format2CodeName(code protocol.EvsRefusalCode) string {
	return strings.TrimPrefix(code.String(), "EVS_REFUSAL_")
}

// A plan of the format-2 device on main at its head, signed as the writer.
func (self *format2World) plan() *sidecar.EvsPushPlan {
	self.t.Helper()
	return self.planWith(&protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}})
}

func (self *format2World) planWith(metadata *protocol.EvsSealedMetadata) *sidecar.EvsPushPlan {
	self.t.Helper()
	sealedMetadata, err := sidecar.EvsSealMetadata(self.manifest, metadata)
	if err != nil {
		self.t.Fatal(err)
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: sidecar.NewEvsPushId(), BaseChain: sidecar.EvsChainStart(self.repoId, self.refId),
		Generation: self.repoKey.Generation(), GroupId: self.repoKey.GroupId(), GenerationCommitment: self.repoKey.Commitment(),
		PathEpoch: 1, Auth: self.view.Pin(), SignerSidecarId: self.writer.SidecarId, ClientId: self.clientId,
		TimeMs: self.clock.Now().UnixMilli(), SealedMetadata: sealedMetadata,
	}
	if head := self.head(); !head.Absent() && 0 < head.Version() {
		plan.BaseVersion = head.Version()
		plan.BaseChain = [sha256.Size]byte(head.Head.GetChain())
	}
	return plan
}

// path's tokens in epoch 1.
func (self *format2World) tokens(path string) sidecar.EvsTokenPath {
	self.t.Helper()
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	tokenPath, err := sidecar.EvsPathTokens(self.pathKey, names)
	if err != nil {
		self.t.Fatal(err)
	}
	return tokenPath
}

// git's blob oid of content.
func format2BlobOid(content []byte) sidecar.EvsGitOid {
	digest := sha1.New()
	fmt.Fprintf(digest, "blob %d\x00", len(content))
	digest.Write(content)
	return sidecar.EvsGitOid(digest.Sum(nil))
}

// One checkpoint record's header for content.
func format2RecordHeader(content []byte) *sidecar.EvsRecordHeader {
	oid := format2BlobOid(content)
	header := &sidecar.EvsRecordHeader{
		RecordId: sidecar.NewEvsSlotId(), BodyLength: uint64(len(content)),
		Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
	}
	copy(header.Oid[:], oid[:])
	return header
}

// A file's creation on plan at a root path: its entry version sealed under the repo's keys as a device of the
// versioning's format seals one, an inline checkpoint of content unless mutate gives it another chain.
func (self *format2World) create(plan *sidecar.EvsPushPlan, path string, content []byte, versioning protocol.EvsVersioning, mutate func(entry *protocol.EvsEntryVersion)) {
	self.t.Helper()
	fileId := sidecar.NewId()
	oid := format2BlobOid(content)
	fields := &protocol.EvsSealedFields{
		FileId: fileId.Bytes(), Mode: 0o100644, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: uint64(len(content)),
	}
	if versioning != protocol.EvsVersioning_EVS_VERSIONING_KEPT {
		contentSha256 := sha256.Sum256(content)
		fields.ContentSha256 = contentSha256[:]
	}
	sealedFields, err := sidecar.EvsSealFieldsFormat2(self.manifest, fields, uint32(versioning))
	if err != nil {
		self.t.Fatal(err)
	}
	inline, _, err := sidecar.EvsSealInlineRecord(self.manifest, self.fek, nil, fileId, format2RecordHeader(content), content)
	if err != nil {
		self.t.Fatal(err)
	}
	entry := &protocol.EvsEntryVersion{
		Version: plan.BaseVersion + 1, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: sidecar.EvsPadme(uint64(len(content))),
		SealedFields: sealedFields, Versioning: uint32(versioning),
		Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inline}},
	}
	if mutate != nil {
		mutate(entry)
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: self.tokens(path), EntryVersion: entryBytes})
}

// A kind-5 segment of pushId holding content as its one record: its bytes, its summary and the locator that cites
// it.
func (self *format2World) kind5Segment(pushId sidecar.Id, content []byte) ([]byte, *sidecar.EvsSegmentSummary, *protocol.EvsLocator) {
	self.t.Helper()
	segment := &bytes.Buffer{}
	builder, err := sidecar.NewEvsKind5SegmentBuilder(segment, self.manifest, self.fek, pushId)
	if err != nil {
		self.t.Fatal(err)
	}
	record, err := builder.BeginRecord(sidecar.NewId(), format2RecordHeader(content))
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := record.Write(content); err != nil {
		self.t.Fatal(err)
	}
	if err := record.Close(); err != nil {
		self.t.Fatal(err)
	}
	summary, err := builder.Finish()
	if err != nil {
		self.t.Fatal(err)
	}
	locator := &protocol.EvsLocator{
		Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: summary.Id[:],
		Offset: summary.Places[0].Offset, Length: summary.Places[0].Length,
	}
	return segment.Bytes(), summary, locator
}

// How the format-2 device signs a push: as the writer, the statement's push passing through mutate first, or with
// the stranger's key under the writer's id.
type format2Signing struct {
	mutate   func(push *protocol.EvsPush)
	stranger bool
	// the statement as signed, which a builder that then refuses its shape does not give back
	statementBytes []byte
}

func (self *format2World) sign(signing *format2Signing) sidecar.EvsSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		if signing.mutate != nil {
			push := &protocol.EvsPush{}
			if err := proto.Unmarshal(body, push); err != nil {
				return nil, err
			}
			signing.mutate(push)
			mutated, err := proto.MarshalOptions{Deterministic: true}.Marshal(push)
			if err != nil {
				return nil, err
			}
			body = mutated
		}
		signed, err := self.writer.Sign(purpose, signedType, body, agentId)
		if err != nil {
			return nil, err
		}
		if signing.stranger {
			forged, err := self.stranger.Sign(purpose, signedType, body, agentId)
			if err != nil {
				return nil, err
			}
			signed.Signature = forged.Signature
		}
		signing.statementBytes, err = proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			return nil, err
		}
		return signed, nil
	}
}

// plan's request body: built as format 2, signed by the writer, and held to format 2's parsers and the writer's key,
// so what format 1 refuses is a signed, well-formed construct.
func (self *format2World) body(plan *sidecar.EvsPushPlan, mutate func(push *protocol.EvsPush), staged []byte) *protocol.EvsPushRequest {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(self.sign(&format2Signing{mutate: mutate})).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	statement, err := sidecar.ParseEvsStatementFormat2(built.Statement.Bytes)
	if err != nil {
		self.t.Fatalf("format 2 does not parse the statement: %v", err)
	}
	if err := statement.Verify(self.writer.PublicKey()); err != nil {
		self.t.Fatalf("the statement is not the writer's: %v", err)
	}
	if _, err := sidecar.EvsCheckPayloadFormat2(statement, built.Payload, staged); err != nil {
		self.t.Fatalf("format 2 does not take the payload: %v", err)
	}
	return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload, Staged: staged}
}

// plan's request body under a signature that is not its signer's, the statement's push passing through mutate.
func (self *format2World) unsignedBody(plan *sidecar.EvsPushPlan, mutate func(push *protocol.EvsPush), staged []byte) *protocol.EvsPushRequest {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(self.sign(&format2Signing{mutate: mutate, stranger: true})).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := built.Statement.Verify(self.writer.PublicKey()); err == nil {
		self.t.Fatal("the unsigned twin verifies")
	}
	return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload, Staged: staged}
}

// plan's request body signed by the writer with an entry out of every format's shape: the builder hashes entries
// and does not parse them, so the statement stands and the payload does not.
func (self *format2World) malformedEntryBody(plan *sidecar.EvsPushPlan) *protocol.EvsPushRequest {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(self.sign(&format2Signing{})).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := sidecar.EvsCheckPayloadFormat2(built.Statement, built.Payload, nil); err == nil {
		self.t.Fatal("format 2 takes the malformed twin")
	}
	return &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
}

// plan's request body signed by the writer over a push mutate put out of every format's shape. The builder refuses
// what it signed, so the statement is the bytes its signer saw, over the payload the plan builds unmutated.
func (self *format2World) malformedStatementBody(plan *sidecar.EvsPushPlan, mutate func(push *protocol.EvsPush)) *protocol.EvsPushRequest {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(self.sign(&format2Signing{})).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	signing := &format2Signing{mutate: mutate}
	if _, err := sidecar.NewEvsStatementBuilder(self.sign(signing)).BuildFormat2(plan); err == nil {
		self.t.Fatal("format 2 parses the malformed twin")
	}
	return &protocol.EvsPushRequest{Statement: signing.statementBytes, Payload: built.Payload}
}

// The versionless receipt a format-2 evs issues the writer for a kind-5 segment it stored.
func (self *format2World) versionlessReceipt(summary *sidecar.EvsSegmentSummary) *protocol.EvsUploadReceipt {
	self.t.Helper()
	receipt, err := evsservice.IssueUploadReceipt(self.receiptKeys, self.repoId, summary.Id, summary.PaddedSize, self.clock.Now(), self.writer.SidecarId, true, self.clock.Now())
	if err != nil {
		self.t.Fatal(err)
	}
	return receipt
}

// A kind-5 segment as a format-2 evs stored it for pushId: its locator, and the item and receipt a push adopts it
// by.
func (self *format2World) storeKind5Segment(pushId sidecar.Id, content []byte) (*protocol.EvsLocator, *sidecar.EvsNewObject, *protocol.EvsUploadReceipt) {
	self.t.Helper()
	segmentBytes, summary, locator := self.kind5Segment(pushId, content)
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := segmentCluster.PutStream(self.ctx, evsservice.SegmentKey(self.repoId, summary.Id), bytes.NewReader(segmentBytes), int64(len(segmentBytes)), summary.Id[:]); err != nil {
		self.t.Fatal(err)
	}
	receipt := self.versionlessReceipt(summary)
	object := &sidecar.EvsNewObject{
		Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: summary.Id[:], PaddedSize: summary.PaddedSize,
		UploadDay: uint32(receipt.GetUploadMs() / (24 * 60 * 60 * 1000)),
	}
	return locator, object, receipt
}

// A DROP's body and lists for one path of two listed versions, as a format-2 device signs them.
func (self *format2World) drop(plan *sidecar.EvsPushPlan) ([]byte, []byte) {
	self.t.Helper()
	paths := []*protocol.EvsDropPath{{
		Lineage:        []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: self.tokens("dropped.txt").Components()}},
		ThroughVersion: 3,
		Boundary:       1,
	}}
	first := sha256.Sum256([]byte("a listed entry version"))
	second := sha256.Sum256([]byte("another listed entry version"))
	listed := [][]byte{first[:], second[:]}
	slices.SortFunc(listed, bytes.Compare)
	lists, err := sidecar.EvsBuildDropLists(paths, [][][]byte{listed})
	if err != nil {
		self.t.Fatal(err)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsDropHistory{
		DropId: sidecar.NewId().Bytes(), Action: 1, NotBeforeMs: plan.TimeMs + sidecar.EvsDropWindowMs, Paths: paths,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return body, lists
}

// What an evs row sends format1: a push, or a segment upload, and its twin, which is malformed or unsigned.
type format2EvsCase struct {
	push *protocol.EvsPushRequest
	twin *protocol.EvsPushRequest
	// PUT .../segments/<id>?push=<segmentPushId>
	segment       []byte
	twinSegment   []byte
	segmentPushId sidecar.Id
	// POST .../push/<partPushId>/<number>
	part       *format2Part
	twinPart   *format2Part
	partPushId sidecar.Id
}

// One part of a push in parts, as its route takes it.
type format2Part struct {
	number int
	body   *protocol.EvsPartRequest
}

func (self *format2World) sendCase(push *protocol.EvsPushRequest, part *format2Part, partPushId sidecar.Id, segment []byte, segmentPushId sidecar.Id) *httptest.ResponseRecorder {
	self.t.Helper()
	if push != nil {
		return self.postPush(self.format1, push)
	}
	if part != nil {
		bodyBytes, err := proto.Marshal(part.body)
		if err != nil {
			self.t.Fatal(err)
		}
		return self.send(self.format1, http.MethodPost, fmt.Sprintf("/push/%s/%d", sidecar.EvsKeyId(partPushId), part.number), bodyBytes)
	}
	route := fmt.Sprintf("/segments/%x?push=%s", sha256.Sum256(segment), sidecar.EvsKeyId(segmentPushId))
	return self.send(self.format1, http.MethodPut, route, segment)
}

// An erasure's CUT: flag 512.
func setCut(push *protocol.EvsPush) {
	push.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
}

// An index push's field 34.
func setIndexEpoch(push *protocol.EvsPush) {
	push.IndexEpoch = 7
}

// The evs rows' constructs, by name.
var format2EvsDrivers = map[string]func(world *format2World) *format2EvsCase{
	"entry-versioning-1": func(world *format2World) *format2EvsCase {
		plan := world.plan()
		world.create(plan, "versionless.bin", []byte("versionless"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, nil)
		twin := world.plan()
		world.create(twin, "versionless.bin", []byte("versionless"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, nil)
		return &format2EvsCase{push: world.body(plan, nil, nil), twin: world.unsignedBody(twin, nil, nil)}
	},
	"entry-versioning-2": func(world *format2World) *format2EvsCase {
		plan := world.plan()
		world.create(plan, "index.bin", []byte("an index file"), protocol.EvsVersioning_EVS_VERSIONING_INDEX, nil)
		twin := world.plan()
		world.create(twin, "index.bin", []byte("an index file"), protocol.EvsVersioning_EVS_VERSIONING_INDEX, nil)
		return &format2EvsCase{push: world.body(plan, nil, nil), twin: world.unsignedBody(twin, nil, nil)}
	},
	"locator-kind-5": func(world *format2World) *format2EvsCase {
		plan := world.plan()
		_, _, locator := world.kind5Segment(plan.PushId, []byte("a versionless segment"))
		world.create(plan, "cited.bin", []byte("a versionless segment"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, func(entry *protocol.EvsEntryVersion) {
			entry.Chain = []*protocol.EvsLocator{locator}
		})
		twin := world.plan()
		world.create(twin, "cited.bin", []byte("a versionless segment"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, func(entry *protocol.EvsEntryVersion) {
			entry.Chain = []*protocol.EvsLocator{{Kind: 6, Id: locator.GetId(), Offset: locator.GetOffset(), Length: locator.GetLength()}}
		})
		return &format2EvsCase{push: world.body(plan, nil, nil), twin: world.malformedEntryBody(twin)}
	},
	"locator-staged": func(world *format2World) *format2EvsCase {
		stage := func(plan *sidecar.EvsPushPlan) []byte {
			segmentBytes, _, locator := world.kind5Segment(plan.PushId, []byte("staged"))
			segment, err := sidecar.EvsStagedSegmentOf(segmentBytes, world.repoId, plan.PushId)
			if err != nil {
				world.t.Fatal(err)
			}
			locator.Staged = true
			plan.NewObjects = append(plan.NewObjects, segment.NewObject())
			world.create(plan, "staged.bin", []byte("staged"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, func(entry *protocol.EvsEntryVersion) {
				entry.Chain = []*protocol.EvsLocator{locator}
			})
			return sidecar.EvsEncodeStaged([][]byte{segmentBytes})
		}
		plan := world.plan()
		staged := stage(plan)
		twin := world.plan()
		twinStaged := stage(twin)
		return &format2EvsCase{push: world.body(plan, nil, staged), twin: world.unsignedBody(twin, nil, twinStaged)}
	},
	"receipt-versionless": func(world *format2World) *format2EvsCase {
		adopt := func(plan *sidecar.EvsPushPlan) *protocol.EvsUploadReceipt {
			locator, object, receipt := world.storeKind5Segment(plan.PushId, []byte("adopted"))
			locator.Kind = uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT)
			plan.NewObjects = append(plan.NewObjects, object)
			world.create(plan, "adopted.bin", []byte("adopted"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, func(entry *protocol.EvsEntryVersion) {
				entry.Chain = []*protocol.EvsLocator{locator}
			})
			return receipt
		}
		plan := world.plan()
		receipt := adopt(plan)
		body := world.body(plan, nil, nil)
		body.Receipts = []*protocol.EvsUploadReceipt{receipt}
		twin := world.plan()
		forged := adopt(twin)
		forged.Mac = bytes.Repeat([]byte{0x5a}, len(forged.GetMac()))
		twinBody := world.body(twin, nil, nil)
		twinBody.Receipts = []*protocol.EvsUploadReceipt{forged}
		return &format2EvsCase{push: body, twin: twinBody}
	},
	"push-flag-256-field-33": func(world *format2World) *format2EvsCase {
		plan := world.plan()
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
		plan.DropBody, plan.DropLists = world.drop(plan)
		twin := world.plan()
		world.create(twin, "kept.txt", []byte("kept"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
		return &format2EvsCase{push: world.body(plan, nil, nil), twin: world.malformedStatementBody(twin, func(push *protocol.EvsPush) {
			push.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
		})}
	},
	"push-flag-512": func(world *format2World) *format2EvsCase {
		plan := world.plan()
		world.create(plan, "cut.txt", []byte("cut"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
		twin := world.plan()
		world.create(twin, "cut.txt", []byte("cut"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
		return &format2EvsCase{push: world.body(plan, setCut, nil), twin: world.malformedStatementBody(twin, func(push *protocol.EvsPush) {
			push.Flags |= 1024
		})}
	},
	"push-field-34": func(world *format2World) *format2EvsCase {
		plan := world.plan()
		world.create(plan, "indexed.txt", []byte("indexed"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
		twin := world.plan()
		world.create(twin, "indexed.txt", []byte("indexed"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
		return &format2EvsCase{push: world.body(plan, setIndexEpoch, nil), twin: world.unsignedBody(twin, setIndexEpoch, nil)}
	},
	"part-staged": func(world *format2World) *format2EvsCase {
		// 96 inline files of 12 KiB pass a one-part payload's 1 MiB, so the push goes in parts; one more file is
		// versionless, its record staged
		plan := world.plan()
		content := bytes.Repeat([]byte{'p'}, 12*1024)
		for i := range 96 {
			world.create(plan, fmt.Sprintf("part-%03d.bin", i), content, protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
		}
		segmentBytes, _, locator := world.kind5Segment(plan.PushId, []byte("staged"))
		segment, err := sidecar.EvsStagedSegmentOf(segmentBytes, world.repoId, plan.PushId)
		if err != nil {
			world.t.Fatal(err)
		}
		locator.Staged = true
		plan.NewObjects = append(plan.NewObjects, segment.NewObject())
		world.create(plan, "staged.bin", []byte("staged"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, func(entry *protocol.EvsEntryVersion) {
			entry.Chain = []*protocol.EvsLocator{locator}
		})
		staged := sidecar.EvsEncodeStaged([][]byte{segmentBytes})
		built, err := sidecar.NewEvsStatementBuilder(world.sign(&format2Signing{})).BuildFormat2(plan)
		if err != nil {
			world.t.Fatal(err)
		}
		// the plan's bytes are fixed, so a second build differs only in its signature
		unsigned, err := sidecar.NewEvsStatementBuilder(world.sign(&format2Signing{stranger: true})).BuildFormat2(plan)
		if err != nil {
			world.t.Fatal(err)
		}
		if len(built.Parts) < 2 || len(unsigned.Parts) != len(built.Parts) {
			world.t.Fatalf("the push built in %d parts", len(built.Parts))
		}
		c := &format2EvsCase{partPushId: plan.PushId}
		for i, partBytes := range built.Parts {
			if !bytes.Equal(partBytes, unsigned.Parts[i]) {
				world.t.Fatal("the two builds' parts differ")
			}
			if _, err := sidecar.EvsCheckPartFormat2(built.Statement, partBytes, staged); err != nil {
				world.t.Fatalf("format 2 does not take part %d: %v", i+1, err)
			}
			if c.part == nil {
				c.part = &format2Part{number: i + 1, body: &protocol.EvsPartRequest{Statement: built.Statement.Bytes, Part: partBytes, Staged: staged}}
			}
			// the twin's part holds no format-2 entry, so only its signature refuses it
			if _, err := sidecar.EvsCheckPart(built.Statement, partBytes); err == nil && c.twinPart == nil {
				c.twinPart = &format2Part{number: i + 1, body: &protocol.EvsPartRequest{Statement: unsigned.Statement.Bytes, Part: partBytes}}
			}
		}
		if c.twinPart == nil {
			world.t.Fatal("every part holds a format-2 entry")
		}
		return c
	},
	"segment-header-kind-5": func(world *format2World) *format2EvsCase {
		pushId := sidecar.NewEvsPushId()
		segmentBytes, _, _ := world.kind5Segment(pushId, []byte("an upload"))
		twinBytes := bytes.Clone(segmentBytes)
		twinBytes[4] = 3
		return &format2EvsCase{segment: segmentBytes, twinSegment: twinBytes, segmentPushId: pushId}
	},
}

// FS-72's format-1 case at evs: each signed, well-formed format-2 construct a push or an upload carries is refused
// 409 FORMAT_UNSUPPORTED {needs_format: 2}; a push's refusal is recorded in the head and answered again, recorded,
// to the retry, at this instance and at a format-2 one in the gate (plan-EVS1-format-unsupported#5); nothing else is
// written, the repo keeps format 1, and no alarm rises. Each twin, malformed or unsigned, is refused by its own
// code and recorded nowhere.
func TestEvsFormat2ConstructsRefusedAtAFormat1Evs(t *testing.T) {
	for _, row := range format2RefusalRowsOf(t, "evs", format2EvsDrivers) {
		world := newFormat2World(t)
		// a ref with a history, so a refusal is recorded in a head some push committed
		writer := world.device(world.writer)
		if err := writer.write("first.txt", []byte("first")); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		world.awaitStepEights(world.format1)
		c := format2EvsDrivers[row.Name](world)
		if row.Outcome != "format_unsupported" || row.Status != http.StatusConflict || row.Twin == nil || row.Twin.Outcome != "refused" {
			t.Fatalf("%s: an evs row answers format_unsupported at 409 with a refused twin", row.Name)
		}

		headBefore := world.head()
		objectsBefore := world.objects()
		recorder := world.sendCase(c.twin, c.twinPart, c.partPushId, c.twinSegment, c.segmentPushId)
		reply := format2Refusal(t, recorder)
		if recorder.Code != row.Twin.Status || format2CodeName(reply.GetCode()) != row.Twin.Code || reply.GetNeedsFormat() != 0 || reply.GetRecorded() {
			t.Errorf("%s: the twin answered %d %s %v, want %d %s", row.Name, recorder.Code, format2CodeName(reply.GetCode()), reply, row.Twin.Status, row.Twin.Code)
		}
		if head := world.head(); !bytes.Equal(head.Bytes, headBefore.Bytes) {
			t.Errorf("%s: the twin moved the head", row.Name)
		}
		world.requireSameObjects(row.Name+"'s twin", objectsBefore)

		recorder = world.sendCase(c.push, c.part, c.partPushId, c.segment, c.segmentPushId)
		reply = format2Refusal(t, recorder)
		if recorder.Code != row.Status || reply.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED || reply.GetNeedsFormat() != sidecar.EvsRepoFormat2 || reply.GetRecorded() {
			t.Errorf("%s: answered %d %s %v", row.Name, recorder.Code, format2CodeName(reply.GetCode()), reply)
		}
		head := world.head()
		if head.Version() != headBefore.Version() || !bytes.Equal(head.Head.GetChain(), headBefore.Head.GetChain()) {
			t.Errorf("%s: the head moved to version %d", row.Name, head.Version())
		}
		recorded := len(head.Head.GetRefused()) - len(headBefore.Head.GetRefused())
		if row.Recorded && recorded != sidecar.EvsRefusalByteCount || !row.Recorded && !bytes.Equal(head.Bytes, headBefore.Bytes) {
			t.Errorf("%s: the head's refusal records grew %d B, recorded %t", row.Name, recorded, row.Recorded)
		}
		world.requireSameObjects(row.Name, objectsBefore)
		if repo := world.repo(); repo.GetFormat() != sidecar.EvsRepoFormat1 {
			t.Errorf("%s: a format-1 instance raised the repo to format %d", row.Name, repo.GetFormat())
		}
		if alarms := world.format1Log.alarms(); len(alarms) != 0 {
			t.Errorf("%s: evs alarmed: %v", row.Name, alarms)
		}
		if _, err := writer.read("first.txt"); err != nil {
			t.Errorf("%s: the ref no longer reads: %v", row.Name, err)
		}
		if alarms := writer.alarms(); len(alarms) != 0 {
			t.Errorf("%s: a reader alarmed: %v", row.Name, alarms)
		}
		if !row.Recorded {
			continue
		}
		again := world.postPush(world.format1, c.push)
		reply = format2Refusal(t, again)
		if again.Code != row.Status || reply.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED || !reply.GetRecorded() {
			t.Errorf("%s: answered the retry %d %s %v", row.Name, again.Code, format2CodeName(reply.GetCode()), reply)
		}
		world.requireSameObjects(row.Name+"'s retry", objectsBefore)
		// the rolling case: the format-2 instance meets the retry and answers the record, committing nothing. Its
		// own writes on the way to the head's CAS, a batch record and the repo's raise, are format 2's to judge.
		again = world.postPush(world.format2, c.push)
		reply = format2Refusal(t, again)
		if again.Code != row.Status || reply.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED || !reply.GetRecorded() {
			t.Errorf("%s: a format-2 instance answered the retry %d %s %v", row.Name, again.Code, format2CodeName(reply.GetCode()), reply)
		}
		if after := world.head(); !bytes.Equal(after.Bytes, head.Bytes) {
			t.Errorf("%s: a retry moved the head", row.Name)
		}
	}
}

// What a reader row lays before a format-1 device: a construct the driver committed through format2 or put in the
// stores, or one a read reply alone carries.
type format2ReaderCase struct {
	// the path whose read meets the construct
	path string
	// an ignored row: what the read gives
	content []byte
	// a path of the same ref that format 1 still reads, and what it holds when that is not the kept file's; empty
	// where the construct stops the ref's walk
	sibling        string
	siblingContent []byte
	// what a format-2 evs lays into each frame of a read reply
	rewrite func(frame *protocol.EvsReadFrame)
	// the twin: what a hostile evs makes of the reply, and what it does to the stores first
	twinRewrite func(frame *protocol.EvsReadFrame)
	twin        func()
}

// body committed through engine at version.
func (self *format2World) commit(engine *evsservice.EvsEngine, body *protocol.EvsPushRequest) {
	self.t.Helper()
	recorder := self.postPush(engine, body)
	if recorder.Code != http.StatusOK {
		reply := format2Refusal(self.t, recorder)
		self.t.Fatalf("a push the engine should take answered %d %s %v", recorder.Code, format2CodeName(reply.GetCode()), reply)
	}
}

// Whether frame is the path reply for path.
func (self *format2World) repliesFor(frame *protocol.EvsReadFrame, path string) bool {
	if frame.GetPath() == nil {
		return false
	}
	tokenPath, err := sidecar.ParseEvsTokenPath(frame.GetPath().GetTokenPath())
	return err == nil && tokenPath.Equal(self.tokens(path))
}

// A hostile evs's reply for path: the entry it serves is not the one its statement hashes.
func (self *format2World) tamperEntry(path string) func(frame *protocol.EvsReadFrame) {
	return func(frame *protocol.EvsReadFrame) {
		if !self.repliesFor(frame, path) || frame.GetPath().GetVersion() == nil {
			return
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(frame.GetPath().GetVersion().GetEntryVersion(), entry); err != nil {
			return
		}
		entry.PaddedSize += 1
		frame.Path.Version.EntryVersion, _ = proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	}
}

// A hostile evs's log: the statement of pushId under a signature its signer's key did not make.
func unsignStatement(pushId sidecar.Id) func(frame *protocol.EvsReadFrame) {
	return func(frame *protocol.EvsReadFrame) {
		if frame.GetStatement() == nil {
			return
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(frame.GetStatement().GetStatement(), signed); err != nil {
			return
		}
		push := &protocol.EvsPush{}
		if err := proto.Unmarshal(signed.GetBody(), push); err != nil || !bytes.Equal(push.GetPushId(), pushId.Bytes()) {
			return
		}
		signed.Signature[0] ^= 1
		frame.Statement.Statement, _ = proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	}
}

// A format-2 evs's read state on path's reply.
func (self *format2World) readState(path string, mutate func(reply *protocol.EvsReadPathReply)) func(frame *protocol.EvsReadFrame) {
	return func(frame *protocol.EvsReadFrame) {
		if self.repliesFor(frame, path) {
			mutate(frame.GetPath())
		}
	}
}

// A file the format-2 device creates through format2 with versioning, a format-1 file beside it. mutate gives the
// entry another chain, and the receipts of what it uploaded.
func format2ReaderEntry(versioning protocol.EvsVersioning, mutate func(world *format2World, plan *sidecar.EvsPushPlan, entry *protocol.EvsEntryVersion) []*protocol.EvsUploadReceipt) func(world *format2World) *format2ReaderCase {
	return func(world *format2World) *format2ReaderCase {
		plan := world.plan()
		var receipts []*protocol.EvsUploadReceipt
		world.create(plan, "construct.bin", []byte("a format-2 file"), versioning, func(entry *protocol.EvsEntryVersion) {
			if mutate != nil {
				receipts = mutate(world, plan, entry)
			}
		})
		body := world.body(plan, nil, nil)
		body.Receipts = receipts
		world.commit(world.format2, body)
		return &format2ReaderCase{path: "construct.bin", sibling: "kept.txt", twinRewrite: world.tamperEntry("construct.bin")}
	}
}

// A statement of format 2 the format-2 device commits through format2, which a format-1 reader's walk then meets.
func format2ReaderStatement(mutate func(world *format2World, plan *sidecar.EvsPushPlan) func(push *protocol.EvsPush)) func(world *format2World) *format2ReaderCase {
	return func(world *format2World) *format2ReaderCase {
		plan := world.plan()
		world.commit(world.format2, world.body(plan, mutate(world, plan), nil))
		return &format2ReaderCase{path: "kept.txt", twinRewrite: unsignStatement(plan.PushId)}
	}
}

// A read state or field only a format-2 evs's reply carries, on a path format 1 otherwise reads.
func format2ReaderState(mutate func(reply *protocol.EvsReadPathReply)) func(world *format2World) *format2ReaderCase {
	return func(world *format2World) *format2ReaderCase {
		return &format2ReaderCase{path: "kept.txt", rewrite: world.readState("kept.txt", mutate), twinRewrite: world.tamperEntry("kept.txt")}
	}
}

// The reader rows' constructs, by name.
var format2ReaderDrivers = map[string]func(world *format2World) *format2ReaderCase{
	"read-entry-versioning-1": format2ReaderEntry(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, nil),
	"read-entry-versioning-2": format2ReaderEntry(protocol.EvsVersioning_EVS_VERSIONING_INDEX, nil),
	"read-locator-kind-5": format2ReaderEntry(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, func(world *format2World, plan *sidecar.EvsPushPlan, entry *protocol.EvsEntryVersion) []*protocol.EvsUploadReceipt {
		locator, object, receipt := world.storeKind5Segment(plan.PushId, []byte("a format-2 file"))
		plan.NewObjects = append(plan.NewObjects, object)
		entry.Chain = []*protocol.EvsLocator{locator}
		return []*protocol.EvsUploadReceipt{receipt}
	}),
	"read-statement-flag-512": format2ReaderStatement(func(world *format2World, plan *sidecar.EvsPushPlan) func(push *protocol.EvsPush) { return setCut }),
	"read-statement-field-34": format2ReaderStatement(func(world *format2World, plan *sidecar.EvsPushPlan) func(push *protocol.EvsPush) {
		return setIndexEpoch
	}),
	"read-statement-flag-256": format2ReaderStatement(func(world *format2World, plan *sidecar.EvsPushPlan) func(push *protocol.EvsPush) {
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
		plan.DropBody, plan.DropLists = world.drop(plan)
		return nil
	}),
	"read-segment-header-kind-5": format2ReadSegmentHeaderKind5,
	"read-removal-marker-ids":    format2ReadRemovalMarkerIds,
	"read-provenance-tainted":    format2ReadProvenanceTainted,
	"read-window-bits-4-5":       format2ReadWindowBits,
	"read-head-index-epoch":      format2ReadHeadIndexEpoch,
	"read-batch-record-format-2": format2ReadBatchRecordFormat2,
	"read-state-collected": format2ReaderState(func(reply *protocol.EvsReadPathReply) {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
	}),
	"read-state-drop-pending": format2ReaderState(func(reply *protocol.EvsReadPathReply) {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING
		reply.DropId = sidecar.NewId().Bytes()
		reply.NotBeforeMs = 1
	}),
	"read-state-dropped": format2ReaderState(func(reply *protocol.EvsReadPathReply) {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_DROPPED
		reply.DropId = sidecar.NewId().Bytes()
		reply.DropVersion = 1
		reply.DropStatement = []byte("the DROP's statement")
		reply.DropBody = []byte("its body")
	}),
}

// FS-72's format-1 case at a reader: a format-1 device reading, through a format-1 evs, a ref that holds each
// format-2 construct answers that path, or the ref whose walk meets a format-2 statement, as needing format 2, raises
// no fork, tamper or missing-segment alarm, and still reads the format-1 paths beside it; an ignored construct
// changes nothing it reads. Each twin, tampered with or unsigned, alarms.
func TestEvsFormat2ConstructsAtAFormat1Reader(t *testing.T) {
	for _, row := range format2RefusalRowsOf(t, "reader", format2ReaderDrivers) {
		world := newFormat2World(t)
		writer := world.device(world.writer)
		kept := format2KeptContent
		world.serve(world.format2)
		if err := writer.write("kept.txt", kept); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		world.awaitStepEights(world.format2)
		c := format2ReaderDrivers[row.Name](world)
		if row.Twin == nil {
			t.Fatalf("%s: a reader row has a twin", row.Name)
		}
		// the binary rolls back: a format-1 evs serves what the format-2 one stored
		world.serve(world.format1)
		reader := world.device(world.reader)
		world.setRewrite(c.rewrite)
		content, err := reader.read(c.path)
		switch row.Outcome {
		case "format_unsupported":
			// the reader's own refusal, or evs's for a record it cannot serve, which names the format
			evsError, refused := sidecar.EvsErrorOf(err)
			refused = refused && evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED && evsError.NeedsFormat == sidecar.EvsRepoFormat2
			if !refused && !(errors.Is(err, sidecar.ErrEvsFormatUnsupported) && sidecar.EvsRefusalCodeOf(err) == protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED) {
				t.Errorf("%s: read %q, %v", row.Name, content, err)
			}
		case "ignored":
			if err != nil || !bytes.Equal(content, c.content) {
				t.Errorf("%s: read %q, %v", row.Name, content, err)
			}
		default:
			t.Fatalf("%s: outcome %q", row.Name, row.Outcome)
		}
		world.setRewrite(nil)
		if c.sibling != "" {
			want := kept
			if c.siblingContent != nil {
				want = c.siblingContent
			}
			if content, err := reader.read(c.sibling); err != nil || !bytes.Equal(content, want) {
				t.Errorf("%s: the format-1 path beside it read %q, %v", row.Name, content, err)
			}
		}
		if alarms := reader.alarms(); len(alarms) != 0 {
			t.Errorf("%s: the reader alarmed: %v", row.Name, alarms)
		}
		if alarms := world.format1Log.alarms(); len(alarms) != 0 {
			t.Errorf("%s: evs alarmed: %v", row.Name, alarms)
		}

		twinReader := world.device(world.reader)
		if c.twin != nil {
			c.twin()
		}
		world.setRewrite(c.twinRewrite)
		content, err = twinReader.read(c.path)
		if err == nil || errors.Is(err, sidecar.ErrEvsFormatUnsupported) || sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED) {
			t.Errorf("%s: the twin read %q, %v", row.Name, content, err)
		}
		var wait *format2Wait
		switch row.Twin.Outcome {
		case "alarm":
			if alarms := twinReader.alarms(); !slices.Contains(alarms, row.Twin.Alarm) {
				t.Errorf("%s: the twin raised %v, want %s (%v)", row.Name, alarms, row.Twin.Alarm, err)
			}
		case "evs_alarm":
			if alarms := world.format1Log.alarms(); !format2AlarmsName(alarms, row.Twin.Alarm) {
				t.Errorf("%s: the twin raised %v at evs, want %s (%v)", row.Name, alarms, row.Twin.Alarm, err)
			}
		case "unavailable":
			if !errors.As(err, &wait) || wait.status != http.StatusServiceUnavailable {
				t.Errorf("%s: the twin read: %v", row.Name, err)
			}
		default:
			t.Fatalf("%s: twin outcome %q", row.Name, row.Twin.Outcome)
		}
	}
}

// The file every reader row finds beside its construct, written by a format-1 device.
var format2KeptContent = []byte("kept on format 1")

// main's head put as a format-2 evs, or a broken one, leaves it: mutate's change, under a raised fence. The engines'
// own head writes hold a head to format 1's shape, so this one goes to the cluster as bytes.
func (self *format2World) rewriteHead(mutate func(head *protocol.EvsHead)) {
	self.t.Helper()
	prior := self.head()
	next := evsservice.CloneEvsHead(prior.Head)
	mutate(next)
	next.Fence += 1
	headBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(next)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfMatch(self.ctx, evsservice.HeadKey(self.repoId, self.refId), prior.Etag, headBytes, nil); err != nil {
		self.t.Fatal(err)
	}
}

// Sets flags on every entry of the head's window.
func setWindowFlags(head *protocol.EvsHead, flags uint32) {
	window := head.GetWindow()
	for at := 0; at+sidecar.EvsWindowEntryByteCount <= len(window); at += sidecar.EvsWindowEntryByteCount {
		flagBytes := window[at+sidecar.EvsWindowEntryByteCount-4 : at+sidecar.EvsWindowEntryByteCount]
		binary.BigEndian.PutUint32(flagBytes, binary.BigEndian.Uint32(flagBytes)|flags)
	}
}

// The newest push's batch record moved to a batch of its own, as format 2 lays one out when change gives it a tail,
// and the head's window pointed there: where a format-2 evs would have stored that push. corrupt, when it is not
// nil, then spoils the record's bytes in place.
func (self *format2World) restoreNewestRecord(seq uint32, tail *sidecar.EvsBatchRecordTail, corrupt func(recordBytes []byte)) {
	self.t.Helper()
	head := self.head()
	window, err := evsservice.EvsHeadWindow(head.Head)
	if err != nil || len(window) == 0 {
		self.t.Fatalf("the head's window: %v", err)
	}
	entry := window[len(window)-1]
	stored, ok := self.stored(evsservice.PlaceBatchKey(entry.Place))
	if !ok {
		self.t.Fatal("the newest push's batch is gone")
	}
	record, _, err := sidecar.NewEvsBatchReader(bytes.NewReader(stored)).RecordFormat2(entry.Place)
	if err != nil {
		self.t.Fatal(err)
	}
	writer := sidecar.NewEvsBatchWriter(entry.Place.GetInstance(), entry.Place.GetMinute(), seq, self.clock.Now().UnixMilli())
	place, err := writer.AddFormat2(record, tail)
	if err != nil {
		self.t.Fatal(err)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := sidecar.ParseEvsBatchFormat2(batchBytes); err != nil {
		self.t.Fatalf("format 2 does not parse the batch: %v", err)
	}
	if _, err := sidecar.ParseEvsBatch(batchBytes); !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		self.t.Fatalf("format 1 parsed a format-2 batch: %v", err)
	}
	if corrupt != nil {
		corrupt(batchBytes[place.GetOffset() : place.GetOffset()+place.GetLength()])
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, evsservice.PlaceBatchKey(place), batchBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	entry.Place = place
	self.rewriteHead(func(head *protocol.EvsHead) {
		head.Window = append(bytes.Clone(head.GetWindow()[:len(head.GetWindow())-sidecar.EvsWindowEntryByteCount]), entry.Encode()...)
	})
}

// A kept version whose segment locator names a segment under a kind-5 header; its twin, the segment gone.
func format2ReadSegmentHeaderKind5(world *format2World) *format2ReaderCase {
	// versioning turned on over a versionless version adopts its upload (D-EVS-38): a kept version whose
	// segment locator names a segment under a kind-5 header
	plan := world.plan()
	locator, object, receipt := world.storeKind5Segment(plan.PushId, []byte("a format-2 file"))
	locator.Kind = uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT)
	plan.NewObjects = append(plan.NewObjects, object)
	world.create(plan, "construct.bin", []byte("a format-2 file"), protocol.EvsVersioning_EVS_VERSIONING_KEPT, func(entry *protocol.EvsEntryVersion) {
		entry.Chain = []*protocol.EvsLocator{locator}
	})
	body := world.body(plan, nil, nil)
	body.Receipts = []*protocol.EvsUploadReceipt{receipt}
	world.commit(world.format2, body)
	return &format2ReaderCase{path: "construct.bin", sibling: "kept.txt", twin: func() {
		segmentCluster, err := world.host.Blobs.SegmentCluster()
		if err != nil {
			world.t.Fatal(err)
		}
		if err := segmentCluster.Delete(world.ctx, evsservice.SegmentKey(world.repoId, [sha256.Size]byte(locator.GetId()))); err != nil {
			world.t.Fatal(err)
		}
	}}

}

// A removed path whose marker carries a versionless file's ids; its twin, a removal off the versions rule.
func format2ReadRemovalMarkerIds(world *format2World) *format2ReaderCase {
	writer := world.device(world.writer)
	if err := writer.write("gone.txt", []byte("gone")); err != nil {
		world.t.Fatal(err)
	}
	if err := writer.remove("gone.txt"); err != nil {
		world.t.Fatal(err)
	}
	world.awaitStepEights(world.format2)
	segmentId := sha256.Sum256([]byte("a versionless file's segment"))
	return &format2ReaderCase{
		path: "gone.txt",
		rewrite: world.readState("gone.txt", func(reply *protocol.EvsReadPathReply) {
			if reply.GetRemoval() != nil {
				reply.Removal.SegmentIds = [][]byte{segmentId[:]}
				reply.Removal.SlotIds = [][]byte{sidecar.NewEvsSlotId().Bytes()}
			}
		}),
		twinRewrite: world.readState("gone.txt", func(reply *protocol.EvsReadPathReply) {
			if reply.GetRemoval() != nil {
				reply.Removal.PathVersion += 1
			}
		}),
	}

}

// A format-1 file whose push was written in a tainted run.
func format2ReadProvenanceTainted(world *format2World) *format2ReaderCase {
	content := []byte("written in a tainted run")
	plan := world.planWith(&protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{Tainted: true}})
	world.create(plan, "tainted.txt", content, protocol.EvsVersioning_EVS_VERSIONING_KEPT, nil)
	// the bit is sealed, so a format-1 evs commits the push as any other
	world.commit(world.format1, world.body(plan, nil, nil))
	if repo := world.repo(); repo.GetFormat() != sidecar.EvsRepoFormat1 {
		world.t.Fatal("a tainted push raised the repo")
	}
	return &format2ReaderCase{path: "tainted.txt", content: content, sibling: "kept.txt", twinRewrite: world.tamperEntry("tainted.txt")}

}

// A head whose window entries carry bits 4 and 5; its twin, a bit no format holds.
func format2ReadWindowBits(world *format2World) *format2ReaderCase {
	bits := uint32(protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED) | uint32(protocol.EvsWindowFlag_EVS_WINDOW_DROP)
	world.rewriteHead(func(head *protocol.EvsHead) { setWindowFlags(head, bits) })
	// a format-1 evs commits on that head, carrying its window's entries as they are
	world.serve(world.format1)
	writer := world.device(world.writer)
	if err := writer.write("after.txt", []byte("after")); err != nil {
		world.t.Fatalf("a push on a head whose window carries bits 4 and 5: %v", err)
	}
	world.awaitStepEights(world.format1)
	window, err := evsservice.EvsHeadWindow(world.head().Head)
	if err != nil || len(window) != 2 || window[0].Flags&bits != bits || window[1].Flags&bits != 0 {
		world.t.Fatalf("the window after a format-1 commit: %v, %v", window, err)
	}
	return &format2ReaderCase{path: "kept.txt", content: format2KeptContent, sibling: "after.txt", siblingContent: []byte("after"), twin: func() {
		world.rewriteHead(func(head *protocol.EvsHead) { setWindowFlags(head, 64) })
	}}

}

// A head whose index_epoch a CUT set (QD-640): a format-1 evs commits on it, carrying it, and serves it in the head's
// summary, which a format-1 reader reads past; its twin, an entry that does not hash to its statement's.
func format2ReadHeadIndexEpoch(world *format2World) *format2ReaderCase {
	world.rewriteHead(func(head *protocol.EvsHead) { head.IndexEpoch = 2 })
	world.serve(world.format1)
	writer := world.device(world.writer)
	if err := writer.write("after.txt", []byte("after")); err != nil {
		world.t.Fatalf("a push on a head carrying index_epoch: %v", err)
	}
	world.awaitStepEights(world.format1)
	if indexEpoch := world.head().Head.GetIndexEpoch(); indexEpoch != 2 {
		world.t.Fatalf("a format-1 commit left index_epoch %d", indexEpoch)
	}
	return &format2ReaderCase{path: "kept.txt", content: format2KeptContent, sibling: "after.txt", siblingContent: []byte("after"),
		twinRewrite: world.tamperEntry("kept.txt")}
}

// A push a format-2 evs stored as a format-2 record; its twin, a record of no format.
func format2ReadBatchRecordFormat2(world *format2World) *format2ReaderCase {
	purgeList, err := sidecar.EncodeEvsPurgeList(&protocol.EvsPurgeList{Marked: true})
	if err != nil {
		world.t.Fatal(err)
	}
	tail := &sidecar.EvsBatchRecordTail{PurgeList: purgeList}
	world.restoreNewestRecord(1000, tail, nil)
	return &format2ReaderCase{path: "kept.txt", twin: func() {
		// record format 3, which no format holds
		world.restoreNewestRecord(2000, tail, func(recordBytes []byte) { recordBytes[1] = 3 })
	}}

}

// FS-72's format-1 case on repo/'s format 2: once a format-2 push raised the repo, a format-1 evs answers every push
// 503 with Retry-After before step 4, a format-1 push included, refusing nothing and recording nothing
// (plan-EVS1-format-unsupported#4), writes nothing, and serves the stored bytes, each path as a format-1 reader
// takes it. The twin, a repo/ of format 3, takes no push either, and alarms.
func TestEvsFormat1EvsServesAFormat2RepoAndTakesNoPush(t *testing.T) {
	rows := format2RefusalRowsOf(t, "repo", map[string]bool{"repo-format-2": true})
	if len(rows) != 1 || rows[0].Outcome != "unavailable" || rows[0].Status != http.StatusServiceUnavailable || rows[0].Twin == nil {
		t.Fatal("the repo row answers unavailable at 503, with a twin")
	}
	row := rows[0]
	world := newFormat2World(t)
	writer := world.device(world.writer)
	world.serve(world.format2)
	if err := writer.write("kept.txt", format2KeptContent); err != nil {
		t.Fatal(err)
	}
	plan := world.plan()
	world.create(plan, "versionless.bin", []byte("versionless"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, nil)
	world.commit(world.format2, world.body(plan, nil, nil))
	if repo := world.repo(); repo.GetFormat() != sidecar.EvsRepoFormat2 {
		t.Fatalf("the first format-2 push left repo/ at format %d", repo.GetFormat())
	}

	// the binary rolls back
	world.serve(world.format1)
	before := world.host.Blobs.Dump()
	requireNothingWritten := func(what string) {
		t.Helper()
		after := world.host.Blobs.Dump()
		for key, object := range after {
			if held, ok := before[key]; !ok || !bytes.Equal(held, object) {
				t.Errorf("%s: wrote %s", what, key)
			}
		}
		for key := range before {
			if _, ok := after[key]; !ok {
				t.Errorf("%s: deleted %s", what, key)
			}
		}
	}
	var wait *format2Wait
	if err := writer.write("more.txt", []byte("more")); !errors.As(err, &wait) || wait.status != row.Status || wait.retryAfter == "" {
		t.Errorf("a format-1 push to a format-2 repo: %v", err)
	}
	requireNothingWritten("a format-1 push")
	next := world.plan()
	world.create(next, "next.bin", []byte("next"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, nil)
	recorder := world.postPush(world.format1, world.body(next, nil, nil))
	if reply := format2Refusal(t, recorder); recorder.Code != row.Status || recorder.Header().Get("Retry-After") == "" || reply.GetRecorded() ||
		reply.GetCode() == protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED {
		t.Errorf("a format-2 push to a format-2 repo answered %d %v", recorder.Code, reply)
	}
	requireNothingWritten("a format-2 push")

	reader := world.device(world.reader)
	if content, err := reader.read("kept.txt"); err != nil || !bytes.Equal(content, format2KeptContent) {
		t.Errorf("the format-1 path read %q, %v", content, err)
	}
	if _, err := reader.read("versionless.bin"); !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		t.Errorf("the format-2 path read: %v", err)
	}
	requireNothingWritten("the reads")
	if alarms := append(reader.alarms(), world.format1Log.alarms()...); len(alarms) != 0 {
		t.Errorf("alarms: %v", alarms)
	}

	// the twin: a repo/ whose format no code holds
	repo := world.repo()
	repo.Format = 3
	repoBytes, err := proto.Marshal(repo)
	if err != nil {
		t.Fatal(err)
	}
	info, err := world.cluster.Head(world.ctx, evsservice.RepoKey(world.repoId))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfMatch(world.ctx, evsservice.RepoKey(world.repoId), info.Etag, repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	err = writer.write("more.txt", []byte("more"))
	if !errors.As(err, &wait) || wait.status != http.StatusServiceUnavailable {
		t.Errorf("the twin's push: %v", err)
	}
	if alarms := world.format1Log.alarms(); row.Twin.Outcome != "evs_alarm" || !format2AlarmsName(alarms, row.Twin.Alarm) {
		t.Errorf("the twin raised %v, want %s (%v)", alarms, row.Twin.Alarm, err)
	}
}

// Whether a log's alarm lines name an alarm.
func format2AlarmsName(alarms []string, name string) bool {
	return slices.ContainsFunc(alarms, func(line string) bool { return strings.Contains(line, name) })
}

// The writer rows: what a format-1 device is asked to write, and the near miss beside it that it does write.
var format2WriterDrivers = map[string]struct {
	write func(device *format2Device) error
	twin  func(device *format2Device) error
}{
	"write-ur-index-directory": {
		write: func(device *format2Device) error { return device.write(".ur-index/i1/a/0", []byte("a shard")) },
		twin:  func(device *format2Device) error { return device.write(".ur-indexes/notes.md", []byte("notes")) },
	},
	"write-ref-ur-index": {
		write: func(device *format2Device) error {
			return device.writeRef([]byte("ur/index"), "i1/a/0", []byte("a shard"), "")
		},
		twin: func(device *format2Device) error {
			return device.writeRef([]byte("ur/indexes"), "i1/a/0", []byte("a file"), "")
		},
	},
	"write-ref-ur-lfs": {
		write: func(device *format2Device) error {
			return device.writeRef([]byte("ur/lfs"), "ab/cd/abcd", []byte("an object"), "")
		},
		twin: func(device *format2Device) error {
			return device.writeRef([]byte("ur/lfs-notes"), "ab/cd/abcd", []byte("a file"), "")
		},
	},
	"write-versioning-off": {
		write: func(device *format2Device) error { return device.writeRef(nil, "big.bin", []byte("big"), "off") },
		twin:  func(device *format2Device) error { return device.writeRef(nil, "big.bin", []byte("big"), "on") },
	},
}

// §11.6's kinds row at a format-1 writer: it writes nothing under .ur-index/ on a file-mode ref, nothing on ur/index
// or ur/lfs, and no versionless file, each refused before any request reaches evs; the name or setting beside each
// commits.
func TestEvsFormat2WritesRefusedAtAFormat1Writer(t *testing.T) {
	for _, row := range format2RefusalRowsOf(t, "writer", format2WriterDrivers) {
		world := newFormat2World(t)
		device := world.device(world.writer)
		driver := format2WriterDrivers[row.Name]
		requestsBefore := world.requests()
		err := driver.write(device)
		switch row.Outcome {
		case "reserved":
			if !errors.Is(err, sidecar.ErrEvsReservedPath) {
				t.Errorf("%s: %v", row.Name, err)
			}
		case "format_unsupported":
			if !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
				t.Errorf("%s: %v", row.Name, err)
			}
		default:
			t.Fatalf("%s: outcome %q", row.Name, row.Outcome)
		}
		if sent := world.requests() - requestsBefore; sent != 0 {
			t.Errorf("%s: %d requests reached evs", row.Name, sent)
		}
		if head := world.head(); !head.Absent() {
			t.Errorf("%s: the ref has a head", row.Name)
		}
		if row.Twin == nil || row.Twin.Outcome != "committed" {
			t.Fatalf("%s: a writer row's twin commits", row.Name)
		}
		if err := driver.twin(device); err != nil {
			t.Errorf("%s: the twin: %v", row.Name, err)
		}
	}
}

// One object's bytes as the cluster holds them, and whether it holds any.
func (self *format2World) stored(key string) ([]byte, bool) {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, false
	}
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	stored, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored, true
}

// FS-72's format-2 batch at a format-1 evacuator: a batch of format 2, here one holding a staged push's record with
// its staged bytes, is no batch format 1 parses, so the run leaves it for a format-2 evacuator, deleting nothing of
// it and saying so under its own alarm, never as a batch that fails its checks. The twin, a format-1 batch with a
// byte flipped, is left as failing them.
func TestEvsFormat2BatchLeftByAFormat1Evacuator(t *testing.T) {
	rows := format2RefusalRowsOf(t, "evacuator", map[string]bool{"batch-format-2": true})
	if len(rows) != 1 || rows[0].Outcome != "left" || rows[0].Twin == nil || rows[0].Twin.Outcome != "evs_alarm" {
		t.Fatal("the evacuator row is left, its twin alarming")
	}
	row := rows[0]
	world := newFormat2World(t)
	plan := world.plan()
	segmentBytes, _, locator := world.kind5Segment(plan.PushId, []byte("staged"))
	segment, err := sidecar.EvsStagedSegmentOf(segmentBytes, world.repoId, plan.PushId)
	if err != nil {
		t.Fatal(err)
	}
	locator.Staged = true
	plan.NewObjects = append(plan.NewObjects, segment.NewObject())
	world.create(plan, "staged.bin", []byte("staged"), protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, func(entry *protocol.EvsEntryVersion) {
		entry.Chain = []*protocol.EvsLocator{locator}
	})
	staged := sidecar.EvsEncodeStaged([][]byte{segmentBytes})
	body := world.body(plan, nil, staged)
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: world.repoId, RefId: world.refId, PushId: plan.PushId,
		SignerSidecarId: world.writer.SidecarId, TimeMs: plan.TimeMs, Body: sidecar.EvsPushRecordBody(body.GetStatement(), body.GetPayload()),
	}
	minute := evsservice.BatchMinute(world.clock.Now())
	batches := map[string][]byte{}
	for seq, name := range []string{"format 2", "twin"} {
		writer := sidecar.NewEvsBatchWriter(7, minute, uint32(seq), world.clock.Now().UnixMilli())
		tail := &sidecar.EvsBatchRecordTail{Staged: staged}
		if name == "twin" {
			// format 1's layout, which a tail would turn to format 2's
			tail = nil
		}
		place, err := writer.AddFormat2(record, tail)
		if err != nil {
			t.Fatal(err)
		}
		batchBytes, err := writer.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sidecar.ParseEvsBatchFormat2(batchBytes); err != nil {
			t.Fatalf("format 2 does not parse the batch: %v", err)
		}
		if name == "twin" {
			batchBytes[len(batchBytes)-1] ^= 1
		}
		_, err = sidecar.ParseEvsBatch(batchBytes)
		if unsupported := errors.Is(err, sidecar.ErrEvsFormatUnsupported); err == nil || unsupported != (name == "format 2") {
			t.Fatalf("format 1 parsed the %s batch as: %v", name, err)
		}
		key := evsservice.PlaceBatchKey(place)
		if _, err := world.cluster.PutIfNoneMatch(world.ctx, key, batchBytes, nil); err != nil {
			t.Fatal(err)
		}
		batches[key] = batchBytes
	}

	log := &format2Log{}
	settings := evsservice.DefaultEvacuatorSettings()
	settings.SpoolDirectory = t.TempDir()
	evsSettings := evsservice.DefaultEvsSettings()
	evsSettings.InstanceFormat = sidecar.EvsRepoFormat1
	evacuator, err := evsservice.NewEvacuator(world.host.ServiceHost(), &evsservice.EvacuatorDeps{Settings: settings, EvsSettings: evsSettings, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(settings.MinuteAge + time.Hour)
	result, err := evacuator.Run(world.ctx, "meta-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.BatchCount != len(batches) || result.BatchDeletedCount != 0 || result.MinuteDeletedCount != 0 {
		t.Errorf("the run read %d batches and deleted %d, in %d minutes", result.BatchCount, result.BatchDeletedCount, result.MinuteDeletedCount)
	}
	for key, batchBytes := range batches {
		if stored, ok := world.stored(key); !ok || !bytes.Equal(stored, batchBytes) {
			t.Errorf("batch %s did not stay as it was", key)
		}
	}
	alarms := log.alarms()
	if !format2AlarmsName(alarms, "evacuate_batch_format") || !format2AlarmsName(alarms, row.Twin.Alarm) || len(alarms) != len(batches) {
		t.Errorf("the run's alarms: %v", alarms)
	}
}

// One of §11.8's slot rule's refusals (5h and step 6), which format 1 checks from M2 so that format 2's one key per
// versionless path can rest on it (§11.22, FS-95): the push refused, and its twin that commits.
type format2SlotCase struct {
	push *protocol.EvsPushRequest
	twin *protocol.EvsPushRequest
}

// A slot's id, its new-objects item and its body.
func format2Slot() (sidecar.Id, *sidecar.EvsNewObject, []byte, error) {
	slotId := sidecar.NewEvsSlotId()
	slotBody, err := sidecar.EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{
		{KeyIndex: 0, Generation: 1, Wrapped: make([]byte, sidecar.EvsWrappedKeyByteCount)},
	}})
	return slotId, &sidecar.EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()}, slotBody, err
}

// A file's creation on plan naming slotId, which the plan introduces when object is given.
func (self *format2World) createSlotted(plan *sidecar.EvsPushPlan, path string, slotId sidecar.Id, object *sidecar.EvsNewObject, slotBody []byte) {
	self.t.Helper()
	self.create(plan, path, []byte(path), protocol.EvsVersioning_EVS_VERSIONING_KEPT, func(entry *protocol.EvsEntryVersion) {
		entry.SlotIds = [][]byte{slotId.Bytes()}
	})
	if object != nil {
		plan.NewObjects = append(plan.NewObjects, object)
		plan.SlotBodies = append(plan.SlotBodies, slotBody)
	}
}

var format2SlotDrivers = map[string]func(world *format2World) *format2SlotCase{
	// 5h: a version naming a slot that neither its push introduces nor a version step 4 read names
	"slot-unknown": func(world *format2World) *format2SlotCase {
		slotId, object, slotBody, err := format2Slot()
		if err != nil {
			world.t.Fatal(err)
		}
		plan := world.plan()
		world.createSlotted(plan, "unknown.txt", slotId, nil, nil)
		twin := world.plan()
		world.createSlotted(twin, "unknown.txt", slotId, object, slotBody)
		return &format2SlotCase{push: world.body(plan, nil, nil), twin: world.body(twin, nil, nil)}
	},
	// step 6: a new slot's PUT meeting an equal object over 23 h old
	"slot-stale": func(world *format2World) *format2SlotCase {
		slotId, object, slotBody, err := format2Slot()
		if err != nil {
			world.t.Fatal(err)
		}
		first := world.plan()
		world.createSlotted(first, "first.txt", slotId, object, slotBody)
		firstBody := world.body(first, nil, nil)
		world.commit(world.format1, firstBody)
		// the twin: the first push sent again, which meets its own commit. Half an hour past the rule's 23 h, and
		// inside the day the host's quota reservations last
		world.clock.Advance(23*time.Hour + 30*time.Minute)
		again := world.plan()
		world.createSlotted(again, "again.txt", slotId, object, slotBody)
		return &format2SlotCase{push: world.body(again, nil, nil), twin: firstBody}
	},
}

// FS-95's format-1 cases from M2: a format-1 evs refuses a version naming a slot that neither its push introduced
// nor a version step 4 read names (§11.8's 5h), and a new-slot PUT meeting an equal object over 23 h old (step 6),
// each recorded and writing no version; each twin commits.
func TestEvsSlotRuleRefusedAtAFormat1Evs(t *testing.T) {
	vectors := loadFormat2RefusalVectors(t)
	named := map[string]bool{}
	for _, row := range vectors.SlotRule {
		driver, ok := format2SlotDrivers[row.Name]
		if !ok {
			t.Errorf("%s: a slot rule row no driver builds", row.Name)
			continue
		}
		named[row.Name] = true
		world := newFormat2World(t)
		c := driver(world)
		headBefore := world.head()
		recorder := world.postPush(world.format1, c.push)
		reply := format2Refusal(t, recorder)
		if recorder.Code != row.Status || format2CodeName(reply.GetCode()) != row.Code {
			t.Errorf("%s: answered %d %s %v, want %d %s", row.Name, recorder.Code, format2CodeName(reply.GetCode()), reply, row.Status, row.Code)
		}
		head := world.head()
		if head.Version() != headBefore.Version() {
			t.Errorf("%s: the head moved to version %d", row.Name, head.Version())
		}
		if recorded := len(head.Head.GetRefused()) - len(headBefore.Head.GetRefused()); row.Recorded != (recorded == sidecar.EvsRefusalByteCount) {
			t.Errorf("%s: the head's refusal records grew %d B, recorded %t", row.Name, recorded, row.Recorded)
		}
		if alarms := world.format1Log.alarms(); len(alarms) != 0 {
			t.Errorf("%s: evs alarmed: %v", row.Name, alarms)
		}
		if twin := world.postPush(world.format1, c.twin); twin.Code != http.StatusOK {
			t.Errorf("%s: the twin answered %d %v", row.Name, twin.Code, format2Refusal(t, twin))
		}
	}
	for name := range format2SlotDrivers {
		if !named[name] {
			t.Errorf("%s: a slot rule driver with no row", name)
		}
	}
}

// testdata/evs/reserved_numbers.yml's lists of what format 1 holds for format 2.
type format2ReservedNumbers struct {
	Fields  map[string]int `yaml:"fields"`
	Values  map[string]int `yaml:"values"`
	Layouts map[string]int `yaml:"layouts"`
}

// The vectors name every number format 1 reserves for format 2: each field, value and layout of
// reserved_numbers.yml is driven by a row here, held by a test the vectors name, or listed as unswept with its
// reason, and no row names a number the list lacks. Each config row names the test that holds it, which exists.
func TestEvsFormat2RefusalVectorsCoverTheReservations(t *testing.T) {
	vectors := loadFormat2RefusalVectors(t)
	reservedBytes, err := os.ReadFile("../testdata/evs/reserved_numbers.yml")
	if err != nil {
		t.Fatal(err)
	}
	reserved := &format2ReservedNumbers{}
	if err := yaml.Unmarshal(reservedBytes, reserved); err != nil {
		t.Fatal(err)
	}
	numbers := map[string]bool{}
	for _, list := range []map[string]int{reserved.Fields, reserved.Values, reserved.Layouts} {
		for number := range list {
			numbers[number] = false
		}
	}
	if len(numbers) == 0 {
		t.Fatal("no reserved numbers read")
	}
	cover := func(who string, cited []string) {
		for _, number := range cited {
			if _, ok := numbers[number]; !ok {
				t.Errorf("%s: %q is no reserved number", who, number)
				continue
			}
			numbers[number] = true
		}
	}
	testExists := func(who string, file string, test string) {
		source, err := os.ReadFile("../" + file)
		if err != nil || !bytes.Contains(source, []byte("func "+test+"(")) {
			t.Errorf("%s: no %s in %s (%v)", who, test, file, err)
		}
	}
	names := map[string]bool{}
	for _, row := range vectors.Rows {
		if names[row.Name] || row.Construct == "" {
			t.Errorf("%s: a row named twice, or with no construct", row.Name)
		}
		names[row.Name] = true
		switch row.Side {
		case "evs", "reader", "writer", "repo", "evacuator":
			if row.HeldBy != nil {
				t.Errorf("%s: a row this sweep drives names another test", row.Name)
			}
		case "config":
			if row.HeldBy == nil {
				t.Errorf("%s: a config row names the test that holds it", row.Name)
				continue
			}
			testExists(row.Name, row.HeldBy.File, row.HeldBy.Test)
		default:
			t.Errorf("%s: side %q", row.Name, row.Side)
		}
		cover(row.Name, row.Numbers)
	}
	for _, elsewhere := range vectors.Elsewhere {
		testExists(elsewhere.Test, elsewhere.File, elsewhere.Test)
		cover(elsewhere.Test, elsewhere.Numbers)
	}
	for _, unswept := range vectors.Unswept {
		if unswept.Why == "" {
			t.Errorf("%v: unswept with no reason", unswept.Numbers)
		}
		cover("unswept", unswept.Numbers)
	}
	for number, covered := range numbers {
		if !covered {
			t.Errorf("%s: a reserved number no row, test or reason names", number)
		}
	}
}
