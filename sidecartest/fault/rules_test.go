package fault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const toyCounterKey = "counter/toy/_"

// Two writers each add their name to a list: read, then swap If-Match, and after a refused or lost
// write read again, finding their own name if it landed. The planted lost update is a writer that takes
// the ETag fresh before it writes instead of the one it read, so its condition always holds and a name
// that landed between its read and its write is overwritten.
type toyCounter struct {
	blind bool
}

func toyCounterNames(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	return strings.Split(string(body), ",")
}

func (self *toyCounter) increment(writerId string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		cluster, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		for {
			object, err := cluster.Get(ctx, toyCounterKey)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(object.Body)
			if err != nil {
				return err
			}
			names := toyCounterNames(body)
			if slices.Contains(names, writerId) {
				// a write whose answer was lost, found landed
				return nil
			}
			net.Barriers().Hit("toy.counter.read", "")
			etag := object.Etag
			if self.blind {
				info, err := cluster.Head(ctx, toyCounterKey)
				if err != nil {
					return err
				}
				etag = info.Etag
			}
			_, err = cluster.PutIfMatch(ctx, toyCounterKey, etag, []byte(strings.Join(append(names, writerId), ",")), nil)
			var unknown *sidecar.BlobUnknownError
			switch {
			case err == nil:
				return nil
			case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
				// another write landed after the read, or this one's answer was lost: read again
				continue
			default:
				return err
			}
		}
	}
}

// The toy's promise: each writer's name once, and at the end every writer's.
func toyCounterCounts(writerIds ...string) Invariant {
	return NewInvariant("toy-counter-counts", func(ctx context.Context, oracle *Oracle) error {
		cluster, err := oracle.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		object, err := cluster.Get(ctx, toyCounterKey)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		body, err := io.ReadAll(object.Body)
		if err != nil {
			return err
		}
		names := toyCounterNames(body)
		for _, writerId := range writerIds {
			count := 0
			for _, name := range names {
				if name == writerId {
					count += 1
				}
			}
			if 1 < count {
				return fmt.Errorf("%s counted %d times: %v", writerId, count, names)
			}
			if oracle.Final && count == 0 {
				return fmt.Errorf("an increment was lost: %s is missing from %v", writerId, names)
			}
		}
		return nil
	})
}

func toyCounterBuilder(writer *toyCounter) Builder {
	return func(net *Net) *Schedule {
		return &Schedule{
			Id: "toy-counter",
			Steps: []*Step{
				{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
					cluster, err := net.Host().Blobs.FirstCluster()
					if err != nil {
						return err
					}
					_, err = cluster.PutIfNoneMatch(ctx, toyCounterKey, nil, nil)
					var unknown *sidecar.BlobUnknownError
					if errors.As(err, &unknown) {
						// never retry past one on faith: read again (host_blobs.go)
						_, err = cluster.Head(ctx, toyCounterKey)
					}
					return err
				}},
				{Actor: "writerA", Background: true, Action: writer.increment("writerA")},
				{Actor: "writerB", Background: true, Action: writer.increment("writerB")},
				{Actor: "writerA", Join: true},
				{Actor: "writerB", Join: true},
			},
			Check: []Invariant{toyCounterCounts("writerA", "writerB")},
		}
	}
}

// The fixed order runs the writers one after the other and never sees the planted lost update; the
// explorer's merge seeds find it, and the failing seed leaves its trace.
func TestExplorerFindsAPlantedLostUpdateWithinTenSeeds(t *testing.T) {
	blind := toyCounterBuilder(&toyCounter{blind: true})
	if result := runBuilt(t.Context(), blind, nil, nil); result.Err != nil {
		t.Fatalf("the fixed order found it, so the explorer is not what is tested: %s", result)
	}
	settings := toyRuleSettings(t)
	report := Explore(t.Context(), blind, settings)
	if len(report.Seeds) != 10 || len(report.Failures) == 0 {
		t.Fatalf("%s", report)
	}
	if !strings.Contains(report.Failures[0].Err.Error(), "an increment was lost") {
		t.Errorf("failed on something else: %s", report.Failures[0])
	}
	if len(report.TracePaths) != len(report.Failures) || report.TracePaths[0] == "" || 0 < len(report.TraceErrors) {
		t.Fatalf("traces %v %v", report.TracePaths, report.TraceErrors)
	}
	wantName := fmt.Sprintf("toy-counter-%d.trace", report.Failures[0].Seed)
	if filepath.Base(report.TracePaths[0]) != wantName {
		t.Errorf("trace %s, want %s", report.TracePaths[0], wantName)
	}
	if text := report.String(); !strings.Contains(text, "10 seeds run (1 to 10)") || strings.Contains(text, "no race") {
		t.Errorf("report %q", text)
	}
	// the correct writer passes the same seeds, which shows only what they reached
	if report := Explore(t.Context(), toyCounterBuilder(&toyCounter{}), toyRuleSettings(t)); 0 < len(report.Failures) {
		t.Errorf("%s", report)
	}
}

// A failing seed's trace is a fixed schedule: its replay fails the same way every time, keeping to the
// trace, and the fixed code passes it.
func TestAReplayOfAFailingTraceFailsEveryTimeAndTheFixPassesIt(t *testing.T) {
	blind := toyCounterBuilder(&toyCounter{blind: true})
	report := Explore(t.Context(), blind, toyRuleSettings(t))
	if len(report.Failures) == 0 {
		t.Fatalf("%s", report)
	}
	trace, err := ReadTrace(report.TracePaths[0])
	if err != nil {
		t.Fatal(err)
	}
	if trace.Seed != report.Failures[0].Seed || trace.Id != "toy-counter" || !strings.Contains(trace.Failure, "an increment was lost") {
		t.Fatalf("trace %+v", trace)
	}
	for range 5 {
		result := runBuilt(t.Context(), Replay(blind, trace), nil, nil)
		if result.Err == nil || !strings.Contains(result.Err.Error(), "an increment was lost") {
			t.Fatalf("the replay did not fail as the seed did: %s", result)
		}
		if result.LeftTrace != "" {
			t.Errorf("the same code left the trace: %s", result.LeftTrace)
		}
		if !slices.Equal(result.Trace, report.Failures[0].Trace) {
			t.Errorf("the replay ran another order:\n%s\n%s", strings.Join(result.Trace, "\n"), strings.Join(report.Failures[0].Trace, "\n"))
		}
	}
	fixed := runBuilt(t.Context(), Replay(toyCounterBuilder(&toyCounter{}), trace), nil, nil)
	if fixed.Err != nil {
		t.Fatalf("the fix failed the replay: %s", fixed)
	}
	if fixed.LeftTrace == "" {
		t.Error("the fix reread and wrote again, and the replay says it kept to the trace")
	}
}

// A replay makes a seed's choices without the seed: who ran, where each yielded, and the order a step
// released its sites in, which a seed shuffles.
func TestAReplayRepeatsEachSeedsOrder(t *testing.T) {
	releaseFirst := map[string]int{}
	builder := func(net *Net) *Schedule {
		hold := func(site string) func(ctx context.Context, net *Net) error {
			return func(ctx context.Context, net *Net) error {
				net.Barriers().Hit(site, "")
				net.Barriers().Hit("toy.after.release", "")
				return nil
			}
		}
		return &Schedule{
			Id: "toy-release",
			Steps: []*Step{
				{Actor: "writerA", Action: hold("toy.release.a"), Await: "toy.release.a"},
				{Actor: "writerB", Action: hold("toy.release.b"), Await: "toy.release.b"},
				{Actor: "writerC", Action: hold("toy.release.c"), Await: "toy.release.c"},
				{Release: []string{"toy.release.a", "toy.release.b", "toy.release.c"}},
				{Actor: "writerA", Join: true},
				{Actor: "writerB", Join: true},
				{Actor: "writerC", Join: true},
			},
		}
	}
	for _, seed := range seedRange(12) {
		seeded := runBuilt(t.Context(), builder, nil, func(schedule *Schedule) { schedule.Seed = seed })
		if seeded.Err != nil {
			t.Fatalf("seed %d: %s", seed, seeded)
		}
		// a seed repeats its order, every released actor queued for the baton as it is released
		if again := runBuilt(t.Context(), builder, nil, func(schedule *Schedule) { schedule.Seed = seed }); !slices.Equal(again.Trace, seeded.Trace) {
			t.Errorf("seed %d ran two orders:\n%s\n%s", seed, again, seeded)
		}
		replayed := runBuilt(t.Context(), Replay(builder, TraceOf(seeded)), nil, nil)
		if replayed.Err != nil || replayed.LeftTrace != "" || !slices.Equal(replayed.Trace, seeded.Trace) {
			t.Errorf("seed %d's replay:\n%s\nthe seed's:\n%s", seed, replayed, seeded)
		}
		for _, event := range seeded.Events {
			if event.Kind == sidecartest.BarrierReleased {
				releaseFirst[event.Name] += 1
				break
			}
		}
	}
	// the seeds shuffled the release, so the replays above repeated more than the written order
	if len(releaseFirst) < 2 {
		t.Errorf("every seed released one site first: %v", releaseFirst)
	}
}

// A replay takes its order from the trace alone.
func TestAReplayNamingASeedFails(t *testing.T) {
	builder := toyCounterBuilder(&toyCounter{})
	result := runBuilt(t.Context(), Replay(builder, &Trace{Id: "toy-counter", Seed: 3}), nil, func(schedule *Schedule) {
		schedule.Seed = 3
	})
	if result.Err == nil || !strings.Contains(result.Err.Error(), "a replay takes its order from the trace alone") {
		t.Errorf("%s", result)
	}
}

// A toy feature behind a switch: one object per writer under quota/, a second refused; switched off,
// it refuses every write, as a disabled feature does.
type toyQuota struct {
	enabled bool
}

var errToyQuota = errors.New("toy quota: refused")

func (self *toyQuota) write(ctx context.Context, net *Net, key string) error {
	if !self.enabled {
		return errToyQuota
	}
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	objects, _, err := cluster.List(ctx, "quota/", "", 2)
	if err != nil {
		return err
	}
	if 0 < len(objects) {
		return errToyQuota
	}
	_, err = cluster.PutIfNoneMatch(ctx, key, []byte("v"), nil)
	return err
}

// The refusal: a writer holding one object is refused a second. Its fixture puts the first object
// straight into the store, so the refusal alone passes whether the feature is on or off.
func toyQuotaRefusal(quota *toyQuota) Builder {
	return func(net *Net) *Schedule {
		return &Schedule{
			Id:      "toy-quota",
			Refuses: "a second object past the quota",
			Steps: []*Step{
				{Actor: "fixture", Action: func(ctx context.Context, net *Net) error {
					cluster, err := net.Host().Blobs.FirstCluster()
					if err != nil {
						return err
					}
					_, err = cluster.PutIfNoneMatch(ctx, "quota/a", []byte("v"), nil)
					return err
				}},
				{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
					if err := quota.write(ctx, net, "quota/b"); !errors.Is(err, errToyQuota) {
						return fmt.Errorf("a second object: %v", err)
					}
					return nil
				}},
			},
		}
	}
}

// The twin: the same writer's first object is let in.
func toyQuotaSuccess(quota *toyQuota) Builder {
	return func(net *Net) *Schedule {
		return &Schedule{
			Id: "toy-quota",
			Steps: []*Step{
				{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
					return quota.write(ctx, net, "quota/a")
				}},
			},
		}
	}
}

// A refusal registers only with its twin, and runs only beside one.
func TestARefusalWithNoTwinFailsToRegister(t *testing.T) {
	quota := &toyQuota{enabled: true}
	// FS-2's own registration (fs2.go) stands before and after: the refused one adds nothing beside it
	before := Lookup("FS-2", "", TierT2)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Twin with no twin passed")
			}
		}()
		Register("FS-2", "", []Tier{TierT2}, Twin(toyQuotaRefusal(quota), nil))
	}()
	if registration := Lookup("FS-2", "", TierT2); registration != before {
		t.Errorf("a refusal with no twin registered: %v", registration)
	}
	// a refusal schedule built outside Twin fails where it runs
	result := runBuilt(t.Context(), toyQuotaRefusal(quota), nil, nil)
	if result.Err == nil || !strings.Contains(result.Err.Error(), "names no twin that must succeed") {
		t.Errorf("%s", result)
	}
	report := CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: toyQuotaRefusal(quota)}, toyRuleSettings(t))
	if !report.Failed() {
		t.Errorf("a row with a refusal and no twin passed: %s", report)
	}
	// with its twin, it passes
	report = CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: Twin(toyQuotaRefusal(quota), toyQuotaSuccess(quota))}, toyRuleSettings(t))
	if report.Failed() || report.Twin == nil || report.Twin.Err != nil {
		t.Errorf("%s", report)
	}
}

// Switched off, the feature refuses everything, so the refusal passes alone; its twin fails, and so
// the row does.
func TestATwinAgainstADisabledFeatureFails(t *testing.T) {
	quota := &toyQuota{enabled: false}
	if result := runBuilt(t.Context(), Twin(toyQuotaRefusal(quota), toyQuotaSuccess(quota)), nil, nil); result.Err != nil {
		t.Fatalf("the refusal failed alone, so the twin is not what is tested: %s", result)
	}
	report := CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: Twin(toyQuotaRefusal(quota), toyQuotaSuccess(quota))}, toyRuleSettings(t))
	if !report.Failed() || report.Twin == nil || report.Twin.Err == nil || !errors.Is(report.Twin.Err, errToyQuota) {
		t.Errorf("a disabled feature passed its row: %s", report)
	}
	// a twin that expects a refusal itself is no twin
	twinRefuses := func(net *Net) *Schedule {
		schedule := toyQuotaSuccess(quota)(net)
		schedule.Refuses = "everything"
		return schedule
	}
	if result := RunTwin(t.Context(), Twin(toyQuotaRefusal(quota), twinRefuses)(nil), nil); result.Err == nil || !strings.Contains(result.Err.Error(), "a twin must succeed") {
		t.Errorf("%s", result)
	}
}

// A forged schedule runs on T2 alone, so its twin carries T3, and one with no twin fails.
func TestAForgedCasesTwinCarriesT3(t *testing.T) {
	honest := func(net *Net) *Schedule {
		return &Schedule{Id: "toy-forged", Tiers: []Tier{TierT2}}
	}
	report := CheckRow(t.Context(), &Registration{Row: "FS-17", Tiers: []Tier{TierT2}, Build: honest}, toyRuleSettings(t))
	if !report.Failed() || !strings.Contains(fmt.Sprint(report.Errors), "its twin, which runs on T3, is missing") {
		t.Errorf("%s", report)
	}
	forged := Twin(func(net *Net) *Schedule {
		return &Schedule{Id: "toy-forged", Refuses: "a forged head", Tiers: []Tier{TierT2}}
	}, honest)
	report = CheckRow(t.Context(), &Registration{Row: "FS-17", Tiers: []Tier{TierT2}, Build: forged}, toyRuleSettings(t))
	if report.Failed() {
		t.Fatalf("%s", report)
	}
	schedule := forged(nil)
	schedule.Forged = true
	if twin := twinBuilder(schedule)(nil); !slices.Contains(twin.Tiers, TierT3) || twin.Id != "toy-forged twin" {
		t.Errorf("the twin runs on %v as %q", twin.Tiers, twin.Id)
	}
}

// The writes of one schedule: two PUTs, a DELETE and two Redis writes, with a Redis read between that
// the rule must not count. Each call's error is recorded, and the schedule goes on past it.
type toyWrites struct {
	builds int
	// by build, each call's name and whether it failed
	calls [][]string
}

func (self *toyWrites) builder() Builder {
	return func(net *Net) *Schedule {
		self.builds += 1
		build := self.builds - 1
		self.calls = append(self.calls, nil)
		record := func(name string, err error) {
			if err != nil {
				name += " failed"
			}
			self.calls[build] = append(self.calls[build], name)
		}
		return &Schedule{
			Id: "toy-writes",
			Steps: []*Step{
				{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
					cluster, err := net.Host().Blobs.FirstCluster()
					if err != nil {
						return err
					}
					redis := net.Host().Redis
					_, err = cluster.PutIfNoneMatch(ctx, "toy/a", []byte("v"), nil)
					record("put a", err)
					record("redis set", redis.Set(ctx, "{toy}k", []byte("v"), 0))
					_, _, err = redis.Get(ctx, "{toy}k")
					record("redis get", err)
					_, err = cluster.PutIfNoneMatch(ctx, "toy/b", []byte("v"), nil)
					record("put b", err)
					record("delete a", cluster.Delete(ctx, "toy/a"))
					_, err = redis.Increment(ctx, "{toy}c", 0)
					record("redis incr", err)
					return nil
				}},
			},
		}
	}
}

// EveryWrite loses each write's response once, a Redis write by its place among writes alone, and the
// read between them never.
func TestEveryWriteVisitsEachWriteOnce(t *testing.T) {
	writes := &toyWrites{}
	failures, lostWrites := EveryWrite(t.Context(), writes.builder(), nil)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
	want := []LostWrite{
		{Op: sidecartest.FaultOpPut, Nth: 1}, {Op: sidecartest.FaultOpPut, Nth: 2},
		{Op: sidecartest.FaultOpDelete, Nth: 1},
		{Op: sidecartest.FaultOpRedis, Nth: 1}, {Op: sidecartest.FaultOpRedis, Nth: 2},
	}
	if !slices.Equal(lostWrites, want) || writes.builds != 1+len(want) {
		t.Fatalf("%d builds, lost %v", writes.builds, lostWrites)
	}
	failed := func(calls []string) []string {
		names := []string{}
		for _, call := range calls {
			if name, ok := strings.CutSuffix(call, " failed"); ok {
				names = append(names, name)
			}
		}
		return names
	}
	if dry := failed(writes.calls[0]); len(dry) != 0 {
		t.Errorf("the dry run lost %v", dry)
	}
	for index, wantLost := range []string{"put a", "put b", "delete a", "redis set", "redis incr"} {
		if lost := failed(writes.calls[index+1]); !slices.Equal(lost, []string{wantLost}) {
			t.Errorf("rerun %d lost %v, want %s", index+1, lost, wantLost)
		}
	}
}

// A cleanup that trusts a lost response deletes what may have landed: the rule's rerun catches it, and
// a writer that reads again passes.
func TestEveryWriteCatchesACleanupOnAnUnknownOutcome(t *testing.T) {
	cleanup := func(rereads bool) Builder {
		return func(net *Net) *Schedule {
			return &Schedule{
				Id: "toy-cleanup",
				Steps: []*Step{
					{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
						cluster, err := net.Host().Blobs.FirstCluster()
						if err != nil {
							return err
						}
						if _, err := cluster.PutIfNoneMatch(ctx, "slot/a/_", []byte("v"), nil); err == nil {
							return nil
						}
						if rereads {
							_, err := cluster.Head(ctx, "slot/a/_")
							return err
						}
						return cluster.Delete(ctx, "slot/a/_")
					}},
				},
				Check: []Invariant{UnknownDeletesNothing},
			}
		}
	}
	failures, _ := EveryWrite(t.Context(), cleanup(false), nil)
	if len(failures) == 0 || !strings.Contains(failures[0].Err.Error(), "on an unknown outcome") {
		t.Errorf("failures %v", failures)
	}
	if failures, _ := EveryWrite(t.Context(), cleanup(true), nil); 0 < len(failures) {
		t.Errorf("%v", failures)
	}
}

// A barrier nothing releases fails inside §22.8's bound, here shortened, with the trace that shows
// where the actor is held, and the explorer writes that trace.
func TestAHungBarrierFailsInsideTheBoundWithItsTrace(t *testing.T) {
	settings := toyRuleSettings(t)
	settings.Net.Barriers.AwaitTimeout = 100 * time.Millisecond
	settings.Seeds = []int64{1}
	builder := func(net *Net) *Schedule {
		return &Schedule{
			Id: "toy-hung",
			Steps: []*Step{
				{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
					net.Barriers().Hit("toy.hung.site", "")
					return nil
				}, Await: "toy.hung.site"},
				{Actor: "writerA", Join: true},
			},
		}
	}
	start := time.Now()
	report := Explore(t.Context(), builder, settings)
	if elapsed := time.Since(start); 5*time.Second < elapsed {
		t.Errorf("the hung barrier took %s", elapsed)
	}
	if len(report.Failures) != 1 || !strings.Contains(report.Failures[0].Err.Error(), "waited 100ms") {
		t.Fatalf("%s", report)
	}
	data, err := os.ReadFile(report.TracePaths[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "held writerA toy.hung.site") || !strings.Contains(string(data), "# failed") {
		t.Errorf("trace:\n%s", data)
	}
}

// A slow row is fixed, never given longer than §22.8's 10 s.
func TestCheckRowRefusesARaisedBarrierWait(t *testing.T) {
	settings := toyRuleSettings(t)
	settings.Net.Barriers.AwaitTimeout = 20 * time.Second
	report := CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: toyCounterBuilder(&toyCounter{})}, settings)
	if !report.Failed() || !strings.Contains(fmt.Sprint(report.Errors), "never raised for a slow row") {
		t.Errorf("%s", report)
	}
}

// A run that failed is a failure: nothing runs it again to see it pass (R-TEST-9). This builder's
// first schedule fails and every later one passes, as a flaky row would.
func TestNothingRetriesAFailedAttempt(t *testing.T) {
	builds := 0
	flaky := func(net *Net) *Schedule {
		builds += 1
		attempt := builds
		return &Schedule{
			Id: "toy-flaky",
			Steps: []*Step{
				{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
					if attempt == 1 {
						return errors.New("the first attempt failed")
					}
					return nil
				}},
			},
		}
	}
	report := CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: flaky}, toyRuleSettings(t))
	if !report.Failed() || report.Fixed.Err == nil || len(report.Failures) != 1 {
		t.Errorf("%s", report)
	}
	if report.Explore == nil || len(report.Explore.Seeds) != 10 {
		t.Errorf("the explorer did not run after the failure: %v", report.Explore)
	}
}

// Every rule a row on the unknown list takes runs in CheckRow, with its committed traces replayed.
func TestCheckRowRunsEveryRuleAndReplaysCommittedTraces(t *testing.T) {
	settings := toyRuleSettings(t)
	report := Explore(t.Context(), toyCounterBuilder(&toyCounter{blind: true}), settings)
	if len(report.Failures) == 0 {
		t.Fatal("no seed failed")
	}
	// the trace of a failing toy, committed under FS-1's name, which the row's run then replays
	trace, err := ReadTrace(report.TracePaths[0])
	if err != nil {
		t.Fatal(err)
	}
	trace.Id = "FS-1"
	settings.SeedsDirectory = t.TempDir()
	if _, err := WriteTrace(settings.SeedsDirectory, trace); err != nil {
		t.Fatal(err)
	}
	fixed := CheckRow(t.Context(), &Registration{Row: "FS-1", Tiers: []Tier{TierT2}, Build: toyCounterBuilder(&toyCounter{})}, settings)
	if fixed.Failed() || len(fixed.Replays) != 1 || len(fixed.LostWrites) == 0 || fixed.Explore == nil {
		t.Fatalf("%s", fixed)
	}
	blind := CheckRow(t.Context(), &Registration{Row: "FS-1", Tiers: []Tier{TierT2}, Build: toyCounterBuilder(&toyCounter{blind: true})}, settings)
	if !blind.Failed() || len(blind.Replays) != 1 || blind.Replays[0].Err == nil {
		t.Fatalf("%s", blind)
	}
}

// A trace survives its file, a stall included, and a row finds its own traces and no other's.
func TestATraceRoundTripsAndARowFindsItsOwn(t *testing.T) {
	trace := &Trace{
		Id:      "FS-19's config-read",
		Seed:    7,
		Failure: "FI-3 after step 2:\nthe head moved",
		Events: []*sidecartest.BarrierEvent{
			{Kind: sidecartest.BarrierRan, Actor: "writerA"},
			{Kind: sidecartest.BarrierPassed, Actor: "writerA", Name: "evs.head_cas.before", Key: "01JTESTREPO"},
			{Kind: sidecartest.BarrierPassed, Name: "evs.fold.after"},
			{Kind: sidecartest.BarrierStalled, Actor: "writerB"},
		},
	}
	data, err := trace.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# a stall") {
		t.Errorf("the stall is not called out:\n%s", data)
	}
	parsed, err := ParseTrace(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Id != trace.Id || parsed.Seed != trace.Seed || parsed.Failure != trace.Failure || len(parsed.Events) != len(trace.Events) {
		t.Fatalf("%+v", parsed)
	}
	for index, event := range trace.Events {
		if *parsed.Events[index] != *event {
			t.Errorf("event %d: %v, want %v", index, parsed.Events[index], event)
		}
	}
	if trace.FileName() != "FS-19-config-read-7.trace" {
		t.Errorf("file name %s", trace.FileName())
	}

	directory := t.TempDir()
	for _, other := range []*Trace{
		trace,
		{Id: "FS-19's config-read", Seed: 3},
		{Id: "FS-19", Seed: 1},
		{Id: "FS-1", Seed: 1},
		{Id: "FS-191", Seed: 1},
	} {
		if _, err := WriteTrace(directory, other); err != nil {
			t.Fatal(err)
		}
	}
	found, err := Traces(directory, "FS-19's config-read")
	if err != nil || len(found) != 2 || found[0].Seed != 3 || found[1].Seed != 7 {
		t.Errorf("found %v, %v", found, err)
	}
	found, err = Traces(directory, "FS-19")
	if err != nil || len(found) != 1 || found[0].Id != "FS-19" {
		t.Errorf("found %v, %v", found, err)
	}
	for _, planted := range []string{"# id x\n", "# seed 1\n", "# id x\n# seed 1\nran\n", "# id x\n# seed 1\nflew a b\n"} {
		if _, err := ParseTrace([]byte(planted)); err == nil {
			t.Errorf("%q parsed", planted)
		}
	}
	if _, err := (&Trace{Id: "x", Events: []*sidecartest.BarrierEvent{{Kind: sidecartest.BarrierRan, Actor: "writer A"}}}).Bytes(); err == nil {
		t.Error("an actor with a space was written")
	}
}

// The repository keeps its seeds where every row finds them.
func TestTheRepositoryHasASeedsDirectory(t *testing.T) {
	directory, err := SeedsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "README")); err != nil {
		t.Errorf("%s has no README: %v", directory, err)
	}
}

// A twin's seeds leave their traces under the twin's name, and the row's run replays them too.
func TestCheckRowReplaysATwinsCommittedTraces(t *testing.T) {
	quota := &toyQuota{enabled: true}
	settings := toyRuleSettings(t)
	twinRun := runBuilt(t.Context(), toyQuotaSuccess(quota), nil, func(schedule *Schedule) { schedule.Seed = 3 })
	if twinRun.Err != nil {
		t.Fatalf("%s", twinRun)
	}
	trace := TraceOf(twinRun)
	trace.Id = "FS-2 twin"
	if _, err := WriteTrace(settings.SeedsDirectory, trace); err != nil {
		t.Fatal(err)
	}
	report := CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: Twin(toyQuotaRefusal(quota), toyQuotaSuccess(quota))}, settings)
	if report.Failed() || len(report.Replays) != 1 || report.Replays[0].Id != "FS-2 twin" {
		t.Errorf("%s; replays %v", report, report.Replays)
	}
}
