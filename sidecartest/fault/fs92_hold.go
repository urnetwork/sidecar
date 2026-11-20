// FS-92 (§22.8; §11.13's holds and delete rows, §21.9's preservation holds, owner decisions 93, 184 and 629,
// D-ABUSE-8, FI-5, FI-13c, FI-27; ABUSE-M10-01) on the evs world with its drop wiring (evs_world_drop.go), each hold
// placed through its Net's api (EvsWorldHolds: server's api on T3, model.PlaceLegalHold behind its staff path; the
// fixture on T2, sidecartest.FixtureHoldApi), beside a twin that places none.
//
// x.txt is written three times, each version its own uploaded segment, and its history dropped now: the drop lists the
// three versions and keeps the head by writing it again, as FS-91's history does, so the job's candidates are the three
// versions' segments.
//
//	(a)  Fs92HoldBeforeTheDrop, the registered case: a network hold placed before the DROP. The DROP is accepted, the
//	     listed versions read dropped and the admin's listing reads the drop done, as the twin's; the job moves every
//	     candidate to held and deletes nothing, the stored count falling once, by their stored sizes, as the twin's
//	     falls when it deletes them. At the hold's deadline api's hold pass ends it, evs's hold-end sweep queued before
//	     the object goes, and the job's next round deletes every held candidate after an incremental mark and verify,
//	     the stored count not moving again. Its twin, Fs92NoHold, places no hold: the job deletes the three at once. The
//	     hold is a §2258A hold whose year ends 10 days on. Fs92HoldOutlastsTheDropTable runs the same with a 90-day
//	     §2703(f) order, past the 30 days an ended drop's entry is kept: the table keeps the held entry while the
//	     listing lets the drop go as its twin's would, and at the order's end the job deletes every held candidate,
//	     the drop leaving the table at once (owner decision 643; fs92_hold_outlasts.go)
//	(b)  Fs92HoldBetweenVerifyAndDelete: the job held after its verify, a hold placed, the clock moved past §11.13's 5 s
//	     cache (owner decision 629), the job released: nothing is deleted. Fs92HoldBetweenDeletes: held after its first
//	     DELETE, the hold placed and the clock moved past the cache: that DELETE stands, none issues after the reread,
//	     and the rest move to held. Fs92DeleteInFlight: held at its first DELETE about to issue, its read of hold/ at its
//	     bound, the hold placed as the DELETE issues, before the hold binds that deleter: the DELETE completes, and the
//	     reread before the next finds the hold. Each one's twin is Fs92NoHold
//	(c)  Fs92SealedHold, a sealed hold placed before the DROP in a record repo, run held and not
//	     (Fs92SealedHoldTwins): every answer the network's devices took from evs, the admin's listing, the listed
//	     versions' states and reads, and the bill equal the twin's (HoldAnswers). An ERASE of y.txt's keys under the
//	     hold destroys them at once, its slots rewritten without them when the ERASE answers and its ciphertext stored;
//	     the reader reads y.txt's version as erased, nothing shown and no alarm, right after the ERASE and again at the
//	     run's end, as the twin's reader does (EvsWorldReadsErased; evs_read_erased.go's keyless-slot rule)
//
// FI-5, FI-16, FI-17 and FI-27 are checked after every step with the world's own checks. FI-13's oracle is not bound
// (QUOTA-M2-13), so FI(13) fails closed and is not named: its (c) clause here is the schedules' own steps on the fake
// Quota (EvsWorld.MarkStored, EvsWorld.StoredFell), the drop job's batches taking the listed bytes off the count once,
// at move-to-held or the DELETE, and nothing more after the hold ends. On a Net whose clusters have not passed settle
// (fsDropSettled), as T3's local stack has not, every schedule holds the job to its wait on settle, deleting nothing,
// before any barrier past the job's start; server's hold tests run T3 on clusters they declare settled
// (server/model/abuse_fs92_t3_test.go).

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs92Case = Register("FS-92", "", []Tier{TierT2, TierT3}, Fs92HoldBeforeTheDrop)

// ----- holds on the evs world -----

// Bounds of EvsWorldHolds.
type EvsWorldHoldsSettings struct {
	// How many evs.sweep runs one pass's queue may take before it fails as never ending: a hold's end queues a start,
	// a scan of each metadata cluster and a pass of each repo.
	SweepRunCount int
	// How long after api acknowledged a placement a deleter is bound: §11.13's cache of hold/, 5 s (owner decision
	// 629). A schedule moves the clock this far before it releases a deleter it means to see the hold.
	BindTimeout time.Duration
}

func DefaultEvsWorldHoldsSettings() *EvsWorldHoldsSettings {
	return &EvsWorldHoldsSettings{
		SweepRunCount: 64,
		BindTimeout:   sidecar.DefaultHoldSetSettings().RereadInterval,
	}
}

// The holds a schedule places on an evs world's network through its Net's api (sidecartest.NetHoldApi, or a fixture
// on the Net's own stores where the tier gave none), each kept by a label, and the evs.sweep runs api's hold pass
// queues, which Pass runs as taskworker runs the job. Safe for concurrent use.
type EvsWorldHolds struct {
	world    *EvsWorld
	settings *EvsWorldHoldsSettings

	stateLock sync.Mutex
	fixture   *sidecartest.FixtureHoldApi
	records   map[string]*sidecar.HoldRecord
	// what api's passes queued and no run has taken, in order
	queued []*sidecar.TaskRequest
	// each repo pass the runs made, in order
	swept []*evsservice.SweepResult
}

// settings nil takes the defaults.
func NewEvsWorldHolds(world *EvsWorld, settings *EvsWorldHoldsSettings) *EvsWorldHolds {
	if settings == nil {
		settings = DefaultEvsWorldHoldsSettings()
	}
	return &EvsWorldHolds{world: world, settings: settings, records: map[string]*sidecar.HoldRecord{}}
}

// net's api for holds: its tier's, else a fixture on the Net's own stores, made once.
func (self *EvsWorldHolds) Api(net *Net) sidecartest.HoldApi {
	if api := sidecartest.NetHoldApi(net); api != nil {
		return api
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.fixture == nil {
		self.fixture = sidecartest.NewFixtureHoldApi(net.Host().Blobs, net.Clock(), evsservice.EvsSweepHoldEndTaskRequest, nil)
	}
	return self.fixture
}

// The terms of the hold placed as label, nil before its placement.
func (self *EvsWorldHolds) Record(label string) *sidecar.HoldRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.records[label]
}

// What a placement asks: the kind, whether its scope is the world's repo alone rather than the network, and whether
// it is sealed.
type EvsWorldHold struct {
	Kind       sidecar.HoldKind
	RepoScoped bool
	Sealed     bool
	// report_2258a: how long before the placement the report reached NCMEC, which its year runs from.
	ReportAge time.Duration
}

// A step action: api places hold on the world's network, kept as label. A placement api refuses fails the step, and
// so does one whose terms are not what was asked.
func (self *EvsWorldHolds) Place(label string, hold *EvsWorldHold) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		placement := &sidecartest.HoldPlacement{NetworkId: self.world.NetworkId, Kind: hold.Kind, Sealed: hold.Sealed}
		if hold.RepoScoped {
			placement.Scope = sidecar.HoldScopeRepos(self.world.RepoId)
		}
		if hold.Kind == sidecar.HoldKindReport2258a {
			placement.ReportTime = net.Clock().Now().Add(-hold.ReportAge)
		}
		record, err := self.Api(net).PlaceHold(ctx, placement)
		if err != nil {
			return fmt.Errorf("api's placement of hold %q: %w", label, err)
		}
		if record.NetworkId != self.world.NetworkId || record.Kind != hold.Kind || record.Scope.Network() == hold.RepoScoped {
			return fmt.Errorf("api placed hold %q with other terms than asked: %+v", label, record)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.records[label] = record
		return nil
	}
}

// A step action: the clock moves to the expiry api gave the hold placed as label, where its kind's deadline ends it.
func (self *EvsWorldHolds) ToExpiry(label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		record := self.Record(label)
		if record == nil {
			return fmt.Errorf("no hold %q was placed", label)
		}
		if record.ExpireTime.Before(net.Clock().Now()) {
			return fmt.Errorf("hold %q expired before the schedule moved to it", label)
		}
		net.Clock().AdvanceTo(record.ExpireTime)
		return nil
	}
}

// A step action: api's hold pass at the clock's now, which must end exactly the world's holds labels name, then
// every evs.sweep run it queued, run as taskworker runs the job, the runs those queue in turn included. A hold the
// pass ends whose sweep queued nothing, or a run that fails, fails the step.
func (self *EvsWorldHolds) Pass(labels ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		ended, err := self.Api(net).RunHoldPass(ctx, &evsWorldHoldTasks{holds: self})
		if err != nil {
			return fmt.Errorf("api's hold pass: %w", err)
		}
		endedCaseIds := []sidecar.Id{}
		for _, record := range ended {
			// a tier whose api holds other networks' holds ends theirs too: this world judges its own
			if record.NetworkId == self.world.NetworkId {
				endedCaseIds = append(endedCaseIds, record.CaseId)
			}
		}
		want := []sidecar.Id{}
		for _, label := range labels {
			record := self.Record(label)
			if record == nil {
				return fmt.Errorf("no hold %q was placed", label)
			}
			want = append(want, record.CaseId)
		}
		slices.SortFunc(endedCaseIds, func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) })
		slices.SortFunc(want, func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) })
		if !slices.Equal(endedCaseIds, want) {
			return fmt.Errorf("api's hold pass ended %d of the world's holds, not the %d named", len(endedCaseIds), len(want))
		}
		self.stateLock.Lock()
		queuedCount := len(self.queued)
		self.stateLock.Unlock()
		if 0 < len(want) && queuedCount == 0 {
			return errors.New("api's hold pass ended a hold and queued no hold-end sweep for it")
		}
		return self.runSweeps(ctx, net)
	}
}

// The next queued run, nil when none is.
func (self *EvsWorldHolds) take() *sidecar.TaskRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.queued) == 0 {
		return nil
	}
	request := self.queued[0]
	self.queued = self.queued[1:]
	return request
}

// Runs every queued evs.sweep run until none is left, as taskworker's evs host runs the job.
func (self *EvsWorldHolds) runSweeps(ctx context.Context, net *Net) error {
	evsSettings, err := self.world.dropEvsSettings(net)
	if err != nil {
		return err
	}
	host := *net.Host()
	host.Tasks = &evsWorldHoldTasks{holds: self}
	deps := &evsservice.SweepDeps{Format2: evsservice.NewFormat2Gate(net.Host()), EvsSettings: evsSettings}
	for count := 0; ; count += 1 {
		request := self.take()
		if request == nil {
			return nil
		}
		if self.settings.SweepRunCount <= count {
			return fmt.Errorf("the hold-end sweep queued more than %d runs", self.settings.SweepRunCount)
		}
		if request.Name != evsservice.EvsSweepTaskName {
			return fmt.Errorf("api's hold pass queued %q, not evs's hold-end sweep", request.Name)
		}
		result, err := evsservice.RunSweepTask(ctx, &host, deps, request.Args)
		if err != nil {
			return fmt.Errorf("evs.sweep: %w", err)
		}
		if result.Swept != nil {
			self.stateLock.Lock()
			self.swept = append(self.swept, result.Swept)
			self.stateLock.Unlock()
		}
	}
}

// How many repo passes the hold-end sweeps made so far.
func (self *EvsWorldHolds) SweptCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.swept)
}

// A step action: the hold-end sweeps made at least one repo pass, over the world's repo: api's end reached evs.
func (self *EvsWorldHolds) Swept() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if self.SweptCount() == 0 {
			return errors.New("no hold-end sweep passed over the world's repo")
		}
		return nil
	}
}

// The queue api's hold pass and evs.sweep's runs schedule into, which EvsWorldHolds runs: once-keyed as taskworker's
// queue is, a request coalescing with a pending one of its key.
type evsWorldHoldTasks struct {
	holds *EvsWorldHolds
}

// Jobs bind where they run, and this queue runs only evs.sweep, by name.
func (self *evsWorldHoldTasks) Register(name string, function sidecar.TaskFunction) {
}

func (self *evsWorldHoldTasks) Schedule(ctx context.Context, request *sidecar.TaskRequest) error {
	if request == nil || request.Name == "" || request.OnceKey == "" {
		return errors.New("a task request with no name or once key")
	}
	self.holds.stateLock.Lock()
	defer self.holds.stateLock.Unlock()
	for _, queued := range self.holds.queued {
		if queued.OnceKey == request.OnceKey {
			return nil
		}
	}
	self.holds.queued = append(self.holds.queued, request)
	return nil
}

// ----- the stored count -----

// What the drop jobs moved the world's network's stored count by at a mark, as the fake Quota applied their batches,
// and the stored sizes of the objects the mark named: what FI-13(c)'s held clause compares later counts with. Only
// taskworker's batches count, which in the world are the drop job's alone (its evacuation reports to a sink of its
// own), so a push's usage an evs instance reports late moves nothing here.
type EvsWorldStoredMark struct {
	stateLock       sync.Mutex
	marked          bool
	delta           int64
	listedByteCount int64
}

// The stored-byte deltas taskworker's batches applied for networkId so far, each batch once.
func evsWorldJobStoredDelta(net *Net, networkId sidecar.Id) int64 {
	delta := int64(0)
	for _, batch := range net.Fakes().Quota.Batches() {
		if batch.Producer != sidecar.QuotaProducerTaskworker {
			continue
		}
		for _, event := range batch.Events {
			if event.NetworkId == connect.Id(networkId) {
				delta += event.StoredByteDelta
			}
		}
	}
	return delta
}

// A step action: mark notes the jobs' stored delta, and the stored size of each segment segments names, read by HEAD.
func (self *EvsWorld) MarkStored(mark *EvsWorldStoredMark, segments func() ([][]byte, error)) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		ids, err := segments()
		if err != nil {
			return err
		}
		cluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		listedByteCount := int64(0)
		for _, id := range ids {
			info, err := cluster.Head(sidecartest.InspectContext(ctx), evsservice.SegmentKey(self.RepoId, [32]byte(id)))
			if err != nil {
				return fmt.Errorf("a listed segment at the mark: %w", err)
			}
			listedByteCount += info.ByteCount
		}
		mark.stateLock.Lock()
		defer mark.stateLock.Unlock()
		mark.marked = true
		mark.delta = evsWorldJobStoredDelta(net, self.NetworkId)
		mark.listedByteCount = listedByteCount
		return nil
	}
}

// A step action: the stored count stands fallen since mark by exactly what fell says of mark's listed bytes: all of
// them once, whatever ran since, or none.
func (self *EvsWorld) StoredFell(mark *EvsWorldStoredMark, fell bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		marked, delta, listedByteCount := mark.marked, mark.delta, mark.listedByteCount
		mark.stateLock.Unlock()
		if !marked {
			return errors.New("no stored mark was taken")
		}
		want := int64(0)
		if fell {
			want = listedByteCount
		}
		if got := delta - evsWorldJobStoredDelta(net, self.NetworkId); got != want {
			return fmt.Errorf("the stored count fell %d bytes since the mark, not %d (FI-13c: once, at move-to-held or the DELETE)", got, want)
		}
		return nil
	}
}

// ----- answers a network sees -----

// What a network's devices took from evs, as FS-92 (c) compares a held network's with its twin's: each answer's
// device, method, target, status, length and header names, and what a schedule adds (the admin's listing, the bill),
// every id of 16 bytes or more in hex by its first appearance, so two worlds of one history read alike. Header values
// are not kept: a Date or an ETag differs between any two runs. Safe for concurrent use.
type HoldAnswers struct {
	stateLock sync.Mutex
	ids       map[string]string
	lines     []string
}

func NewHoldAnswers() *HoldAnswers {
	return &HoldAnswers{ids: map[string]string{}}
}

// An id in a target or an added line: 16 bytes or more in lowercase hex.
var holdAnswersIdPattern = regexp.MustCompile(`[0-9a-f]{32,}`)

// text with every id replaced by its first appearance's ordinal.
func (self *HoldAnswers) normalizeWithLock(text string) string {
	return holdAnswersIdPattern.ReplaceAllStringFunc(text, func(id string) string {
		if named, ok := self.ids[id]; ok {
			return named
		}
		named := fmt.Sprintf("<id %d>", len(self.ids)+1)
		self.ids[id] = named
		return named
	})
}

// Keeps one line, its ids normalized.
func (self *HoldAnswers) Add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, self.normalizeWithLock(line))
}

// Every line kept, in order.
func (self *HoldAnswers) Lines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

// An EvsWorldSettings.DeviceTransport: each answer device takes through lb is kept, its body passed on whole.
func (self *HoldAnswers) Transport(device string, lb http.RoundTripper) http.RoundTripper {
	return &holdAnswersTransport{answers: self, device: device, lb: lb}
}

type holdAnswersTransport struct {
	answers *HoldAnswers
	device  string
	lb      http.RoundTripper
}

func (self *holdAnswersTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.lb.RoundTrip(request)
	target := request.Method + " " + request.URL.RequestURI()
	if err != nil {
		self.answers.Add(fmt.Sprintf("%s %s: no answer", self.device, target))
		return nil, err
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	names := []string{}
	for name := range response.Header {
		names = append(names, name)
	}
	slices.Sort(names)
	line := fmt.Sprintf("%s %s: %d, %d bytes, headers %s", self.device, target, response.StatusCode, len(body), strings.Join(names, " "))
	if readErr != nil {
		line += ", its body cut"
	}
	self.answers.Add(line)
	return response, nil
}

// nil when the two kept the same lines, else the first difference.
func HoldAnswersEqual(held *HoldAnswers, twin *HoldAnswers) error {
	heldLines, twinLines := held.Lines(), twin.Lines()
	if len(heldLines) == 0 {
		return errors.New("the held network took no answer to compare")
	}
	for i := range max(len(heldLines), len(twinLines)) {
		heldLine, twinLine := "(none)", "(none)"
		if i < len(heldLines) {
			heldLine = heldLines[i]
		}
		if i < len(twinLines) {
			twinLine = twinLines[i]
		}
		if heldLine != twinLine {
			return fmt.Errorf("answer %d differs between the held network and its twin: %q and %q", i, heldLine, twinLine)
		}
	}
	return nil
}

// A step action: device lists the repo's drops, path's among them in state, each kept in answers when answers is not
// nil, its freed bytes and not_before with its ids normalized.
func (self *EvsWorld) ListingReads(device string, path string, state protocol.EvsDropState, answers *HoldAnswers) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		drop := self.DropOf(path)
		if drop == nil {
			return fmt.Errorf("the world holds no drop of %q", path)
		}
		drops, err := self.Device(device).Repo.Drops(ctx, &sidecar.EvsDropsArgs{KnownPaths: []string{path}})
		if err != nil {
			return fmt.Errorf("%s's listing of the drops: %w", device, err)
		}
		found := false
		for _, listed := range drops {
			status := listed.Status
			if answers != nil {
				answers.Add(fmt.Sprintf("listing: drop %x ref %x version %d not_before %d state %s reason %s freed %d phase %d paths %d",
					status.GetDropId(), status.GetRefId(), status.GetVersion(), status.GetNotBeforeMs(), status.GetState(), status.GetReason(),
					status.GetFreedBytes(), status.GetPhase(), len(listed.Paths)))
			}
			if bytes.Equal(status.GetDropId(), drop.Push.DropId.Bytes()) {
				found = true
				if status.GetState() != state {
					return fmt.Errorf("%s's listing reads %q's drop %s, not %s", device, path, status.GetState(), state)
				}
			}
		}
		if !found {
			return fmt.Errorf("%s's listing names no drop of %q", device, path)
		}
		return nil
	}
}

// A step action: what the drop jobs took off the network's stored count since mark, kept in answers as the bill reads
// it. Usage batches themselves reach api alone, never the network, so their number is not compared.
func (self *EvsWorld) BillAnswers(mark *EvsWorldStoredMark, answers *HoldAnswers) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		delta := mark.delta
		mark.stateLock.Unlock()
		answers.Add(fmt.Sprintf("bill: the drop took %d bytes off the stored count", delta-evsWorldJobStoredDelta(net, self.NetworkId)))
		return nil
	}
}

// ----- the ERASE under a hold -----

// A ReadVersionEnds check: the version reads as erased, its key destroyed by a committed ERASE, nothing of it shown
// (sidecar.ErrEvsErased). The world's checks hold that the read raised no alarm.
func EvsWorldReadsErased() func(read []byte, err error) error {
	return func(read []byte, err error) error {
		if !errors.Is(err, sidecar.ErrEvsErased) {
			return errors.New("not erased")
		}
		if len(read) != 0 {
			return fmt.Errorf("%d bytes of an erased version shown", len(read))
		}
		return nil
	}
}

// A step action: device erases every key path's versions name (EvsRepo.SlotKeysOf, then Erase), which must commit;
// when it answers, each slot holds none of the erased keys, and every segment of the repo stored before stays.
func (self *EvsWorld) EraseAtOnce(device string, path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		repo := self.Device(device).Repo
		keys, err := repo.SlotKeysOf(ctx, nil, []string{path})
		if err != nil {
			return fmt.Errorf("%s's slot keys of %q: %w", device, path, err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("%q names no slot key", path)
		}
		segmentsBefore, err := self.segmentKeys(ctx, net)
		if err != nil {
			return err
		}
		erased, err := repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true})
		if err != nil {
			return fmt.Errorf("%s's ERASE of %q: %w", device, path, err)
		}
		if erased.Version == 0 {
			return fmt.Errorf("%s's ERASE of %q found nothing to erase", device, path)
		}
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		for _, key := range keys {
			object, err := first.Get(sidecartest.InspectContext(ctx), evsservice.SlotKey(self.RepoId, key.SlotId))
			if errors.Is(err, sidecar.ErrBlobNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			body, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			slot, err := sidecar.EvsDecodeSlotObject(body)
			if err != nil {
				return err
			}
			for _, held := range slot.GetKeys() {
				if held.GetKeyIndex() == uint32(key.KeyIndex) {
					return fmt.Errorf("a slot still holds key %d when the ERASE of %q answered", key.KeyIndex, path)
				}
			}
		}
		segmentsAfter, err := self.segmentKeys(ctx, net)
		if err != nil {
			return err
		}
		for _, segmentKey := range segmentsBefore {
			if !slices.Contains(segmentsAfter, segmentKey) {
				return fmt.Errorf("the ERASE of %q deleted ciphertext: a key's destruction is all it does", path)
			}
		}
		return nil
	}
}

// The repo's seg/ keys, as an inspecting LIST reads them.
func (self *EvsWorld) segmentKeys(ctx context.Context, net *Net) ([]string, error) {
	cluster, err := net.Host().Blobs.SegmentCluster()
	if err != nil {
		return nil, err
	}
	prefix := evsservice.SegmentKey(self.RepoId, [32]byte{})
	prefix = prefix[:strings.LastIndex(prefix, "/")+1]
	keys := []string{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(sidecartest.InspectContext(ctx), prefix, startAfter, 1000)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			keys = append(keys, object.Key)
		}
		if !more || len(objects) == 0 {
			return keys, nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}

// ----- FS-92 -----

// Which FS-92 schedule a run builds.
type fs92Variant int

const (
	fs92NoHold fs92Variant = iota
	fs92BeforeTheDrop
	fs92BetweenVerifyAndDelete
	fs92BetweenDeletes
	fs92DeleteInFlight
	fs92OutlastsTheDropTable
)

// One FS-92 history: its world, its holds and x.txt's three versions as their writes committed them.
type fs92History struct {
	world *EvsWorld
	holds *EvsWorldHolds

	stateLock sync.Mutex
	versions  []*EvsWorldCommittedEntry
}

func newFs92History(net *Net, settings *EvsWorldSettings) *fs92History {
	world := NewEvsWorld(net, settings)
	return &fs92History{world: world, holds: NewEvsWorldHolds(world, nil)}
}

// Steps: the world set up, path written count times, each version an uploaded segment of its own, kept.
func (self *fs92History) writes(path string, count int) []*Step {
	steps := []*Step{}
	for ordinal := 1; ordinal <= count; ordinal += 1 {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: self.world.Write("admin", path, fsDropWritten(path, ordinal, fsDropUploadContent))},
			{Actor: "check", Action: func(ctx context.Context, net *Net) error {
				entry, err := self.world.CommittedEntry("admin", path)
				if err != nil {
					return err
				}
				if path == "x.txt" {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.versions = append(self.versions, entry)
				}
				return nil
			}},
		}...)
	}
	return steps
}

// The segments x.txt's three versions name: the drop's candidates.
func (self *fs92History) listed() ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.versions) != 3 {
		return nil, fmt.Errorf("x.txt's writes committed %d versions, not 3", len(self.versions))
	}
	ids := [][]byte{}
	for _, version := range self.versions {
		ids = append(ids, version.SegmentIds()...)
	}
	return ids, nil
}

// A step action: of x.txt's listed segments, exactly deletedCount are gone and the rest stored.
func (self *fs92History) expectDeleted(deletedCount int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		ids, err := self.listed()
		if err != nil {
			return err
		}
		cluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		goneCount := 0
		for _, id := range ids {
			_, err := cluster.Head(sidecartest.InspectContext(ctx), evsservice.SegmentKey(self.world.RepoId, [32]byte(id)))
			switch {
			case errors.Is(err, sidecar.ErrBlobNotFound):
				goneCount += 1
			case err != nil:
				return err
			}
		}
		if goneCount != deletedCount {
			return fmt.Errorf("%d of the drop's %d candidates are deleted, not %d", goneCount, len(ids), deletedCount)
		}
		return nil
	}
}

// The checks FS-92 names, after every step: the world's, format 2's, FI-5, FI-16 and FI-27.
func fs92Checks(world *EvsWorld) []Invariant {
	return world.Checks(world.FormatHolds(), FI(5), FI(16), FI(17), FI(27))
}

// See the file header.
func Fs92HoldBeforeTheDrop(net *Net) *Schedule {
	schedule := fs92Schedule(net, fs92BeforeTheDrop)
	schedule.Twin = Fs92NoHold
	return schedule
}

// See the file header.
func Fs92NoHold(net *Net) *Schedule {
	return fs92Schedule(net, fs92NoHold)
}

// See the file header.
func Fs92HoldBetweenVerifyAndDelete(net *Net) *Schedule {
	schedule := fs92Schedule(net, fs92BetweenVerifyAndDelete)
	schedule.Twin = Fs92NoHold
	return schedule
}

// See the file header.
func Fs92HoldBetweenDeletes(net *Net) *Schedule {
	schedule := fs92Schedule(net, fs92BetweenDeletes)
	schedule.Twin = Fs92NoHold
	return schedule
}

// See the file header.
func Fs92DeleteInFlight(net *Net) *Schedule {
	schedule := fs92Schedule(net, fs92DeleteInFlight)
	schedule.Twin = Fs92NoHold
	return schedule
}

// See the file header: (a) with a 90-day §2703(f) hold, which outlasts the drop table's 30 days for an ended drop
// (fs92OutlastingSteps).
func Fs92HoldOutlastsTheDropTable(net *Net) *Schedule {
	schedule := fs92Schedule(net, fs92OutlastsTheDropTable)
	schedule.Twin = Fs92NoHold
	return schedule
}

// The network hold the barrier schedules place: a §2703(f) order, 90 days.
var fs92Order = &EvsWorldHold{Kind: sidecar.HoldKindPreserve2703f}

// The network hold (a) places and api's expiry ends: a §2258A hold whose report reached NCMEC 355 days before, so its
// year ends 10 days after its placement, inside the 30 days the drop table keeps an ended drop (see
// Fs92HoldOutlastsTheDropTable for the 90-day order).
var fs92Report = &EvsWorldHold{Kind: sidecar.HoldKindReport2258a, ReportAge: 355 * 24 * time.Hour}

func fs92Schedule(net *Net, variant fs92Variant) *Schedule {
	history := newFs92History(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	world, holds := history.world, history.holds
	bind := holds.settings.BindTimeout
	hold := fs92Order
	if variant == fs92BeforeTheDrop {
		hold = fs92Report
	}
	place := &Step{Actor: "abuse", Action: holds.Place("order", hold)}
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	steps = append(steps, history.writes("x.txt", 3)...)
	if variant == fs92BeforeTheDrop || variant == fs92OutlastsTheDropTable {
		steps = append(steps, place, &Step{Advance: bind})
	}
	stored := &EvsWorldStoredMark{}
	steps = append(steps, []*Step{
		// a hold never refuses a DROP, and the listed versions read as an unheld drop's do
		{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped, 2: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Advance: 50 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "check", Action: world.MarkStored(stored, history.listed)},
	}...)
	if !fsDropSettled(net) {
		// the job waits on settle, deleting nothing (fsDropExecute's reading of such a Net)
		steps = append(steps, fsDropExecute(net, world)[2:]...)
		return &Schedule{Id: "FS-92", Steps: steps, Check: fs92Checks(world), Tiers: []Tier{TierT2, TierT3}}
	}
	job := func(background bool) *Step {
		return &Step{Actor: "taskworker", Action: world.RunDropJob("taskworker", nil), Background: background}
	}
	held := []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateHeld)},
		{Actor: "admin", Action: world.ListingReads("admin", "x.txt", protocol.EvsDropState_EVS_DROP_DONE, nil)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "check", Action: world.StoredFell(stored, true)},
	}
	switch variant {
	case fs92NoHold:
		steps = append(steps, []*Step{
			job(false),
			{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
			{Actor: "admin", Action: world.ListingReads("admin", "x.txt", protocol.EvsDropState_EVS_DROP_DONE, nil)},
			{Actor: "check", Action: history.expectDeleted(3)},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
			{Actor: "check", Action: world.StoredFell(stored, true)},
		}...)
	case fs92OutlastsTheDropTable:
		steps = append(steps, job(false))
		steps = append(steps, held...)
		steps = append(steps, fs92OutlastingSteps(history, stored, job)...)
	case fs92BeforeTheDrop:
		steps = append(steps, job(false))
		steps = append(steps, held...)
		steps = append(steps, []*Step{
			{Actor: "check", Action: history.expectDeleted(0)},
			// api's expiry ends the hold, at its kind's deadline
			{Actor: "abuse", Action: holds.ToExpiry("order")},
			{Actor: "abuse", Action: holds.Pass("order")},
			{Actor: "check", Action: holds.Swept()},
			{Advance: time.Hour},
			job(false),
			{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
			{Actor: "admin", Action: world.ListingReads("admin", "x.txt", protocol.EvsDropState_EVS_DROP_DONE, nil)},
			{Actor: "check", Action: history.expectDeleted(3)},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
			// once, at move-to-held: the later DELETEs report nothing
			{Actor: "check", Action: world.StoredFell(stored, true)},
		}...)
	case fs92BetweenVerifyAndDelete:
		steps = append(steps, []*Step{
			job(true),
			{Actor: "taskworker", Await: evsservice.BarrierDropVerifyAfter},
			place,
			{Advance: bind},
			{Release: []string{sidecartest.ActorBarrierSite("taskworker", evsservice.BarrierDropVerifyAfter)}},
			{Actor: "taskworker", Join: true},
			{Actor: "check", Action: history.expectDeleted(0)},
		}...)
		steps = append(steps, held...)
	case fs92BetweenDeletes:
		steps = append(steps, []*Step{
			job(true),
			{Actor: "taskworker", Await: evsservice.BarrierDropDeleteAfter},
			place,
			{Advance: bind},
			{Release: []string{sidecartest.ActorBarrierSite("taskworker", evsservice.BarrierDropDeleteAfter)}},
			{Actor: "taskworker", Join: true},
			// the DELETE before the hold stands; none issues after the reread
			{Actor: "check", Action: history.expectDeleted(1)},
		}...)
		steps = append(steps, held...)
	case fs92DeleteInFlight:
		steps = append(steps, []*Step{
			job(true),
			{Actor: "taskworker", Await: evsservice.BarrierDropDeleteBefore},
			// the deletes' read of hold/ ages to its bound, and the hold is placed as the DELETE issues: before the
			// hold binds that deleter (owner decision 629), so it completes, and the reread before the next finds it
			{Advance: bind},
			place,
			{Release: []string{sidecartest.ActorBarrierSite("taskworker", evsservice.BarrierDropDeleteBefore)}},
			{Actor: "taskworker", Join: true},
			{Actor: "check", Action: history.expectDeleted(1)},
		}...)
		steps = append(steps, held...)
	}
	return &Schedule{Id: "FS-92", Steps: steps, Check: fs92Checks(world), Tiers: []Tier{TierT2, TierT3}}
}

// What a tier adds to FS-92 (c)'s answers at the end of a run, while its hold stands: on T3, api's own answers to the
// network (GET /abuse/status and GET /abuse/cases), which T2 has no api to give. nil adds nothing.
type Fs92TierAnswers func(ctx context.Context, net *Net, networkId sidecar.Id, answers *HoldAnswers) error

// FS-92 (c): see the file header. held places a sealed hold before the DROP; answers takes every answer the
// network's devices take, its listing and its bill, and what tier adds.
func Fs92SealedHold(held bool, answers *HoldAnswers, tier Fs92TierAnswers) Builder {
	return func(net *Net) *Schedule {
		settings := fsDropWorldSettings(protocol.RepoKind_REPO_KIND_RECORD, false)
		settings.DeviceTransport = answers.Transport
		history := newFs92History(net, settings)
		world, holds := history.world, history.holds
		steps := []*Step{{Actor: "admin", Action: world.Setup}}
		steps = append(steps, history.writes("x.txt", 3)...)
		steps = append(steps, history.writes("y.txt", 1)...)
		if held {
			steps = append(steps, &Step{Actor: "abuse", Action: holds.Place("sealed order", &EvsWorldHold{Kind: sidecar.HoldKindPreserve2703f, Sealed: true})})
		}
		stored := &EvsWorldStoredMark{}
		steps = append(steps, []*Step{
			{Advance: holds.settings.BindTimeout},
			{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
			{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped, 2: sidecar.EvsVersionStateDropped})},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
			// the ERASE goes at once under the hold, and the ciphertext stays; the reader reads the version erased,
			// its key gone by a committed ERASE, with no tamper alarm
			{Actor: "admin", Action: world.EraseAtOnce("admin", "y.txt")},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsErased())},
			{Advance: 50 * time.Hour},
			{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
			{Actor: "check", Action: world.MarkStored(stored, history.listed)},
		}...)
		if !fsDropSettled(net) {
			steps = append(steps, fsDropExecute(net, world)[2:]...)
		} else {
			state, deletedCount := evsservice.DropStateDone, 3
			if held {
				state, deletedCount = evsservice.DropStateHeld, 0
			}
			steps = append(steps, []*Step{
				{Actor: "taskworker", Action: world.RunDropJob("taskworker", nil)},
				{Actor: "check", Action: world.ExpectDropState("x.txt", state)},
				{Actor: "check", Action: history.expectDeleted(deletedCount)},
				{Actor: "check", Action: world.StoredFell(stored, true)},
			}...)
		}
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.ListingReads("admin", "x.txt", protocol.EvsDropState_EVS_DROP_DONE, answers)},
			{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped, 2: sidecar.EvsVersionStateDropped})},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 2, EvsWorldReadsDropped())},
			{Actor: "reader", Action: world.Verify("reader", "x.txt")},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsErased())},
			{Actor: "check", Action: world.BillAnswers(stored, answers)},
		}...)
		if tier != nil {
			steps = append(steps, &Step{Actor: "api", Action: func(ctx context.Context, net *Net) error {
				return tier(ctx, net, world.NetworkId, answers)
			}})
		}
		return &Schedule{Id: "FS-92 (c)", Steps: steps, Check: fs92Checks(world), Tiers: []Tier{TierT2, TierT3}}
	}
}

// What Fs92SealedHoldTwins ran: each world's result and answers.
type Fs92Twins struct {
	Held        *Result
	Twin        *Result
	HeldAnswers *HoldAnswers
	TwinAnswers *HoldAnswers
}

// FS-92 (c) whole: Fs92SealedHold with its hold and without, each on a Net newNet builds, closed before the next
// opens, tier adding its answers to each, and their answers compared. An error names a run that failed or the first
// answer that differs.
func Fs92SealedHoldTwins(ctx context.Context, newNet func() *Net, tier Fs92TierAnswers) (*Fs92Twins, error) {
	twins := &Fs92Twins{HeldAnswers: NewHoldAnswers(), TwinAnswers: NewHoldAnswers()}
	run := func(held bool, answers *HoldAnswers) *Result {
		net := newNet()
		defer net.Close()
		return Run(ctx, Fs92SealedHold(held, answers, tier)(net), net)
	}
	twins.Held = run(true, twins.HeldAnswers)
	if twins.Held.Err != nil {
		return twins, fmt.Errorf("the held network's run: %s", twins.Held)
	}
	twins.Twin = run(false, twins.TwinAnswers)
	if twins.Twin.Err != nil {
		return twins, fmt.Errorf("the twin's run: %s", twins.Twin)
	}
	return twins, HoldAnswersEqual(twins.HeldAnswers, twins.TwinAnswers)
}
