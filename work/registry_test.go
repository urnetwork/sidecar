package work

// The registry and §14.5's compute jobs (CSRV-M12-05): every design job registered or listed unbuilt, each cadence
// from its settings, §14.8's settlement rate covered by the defaults, a job's name registered once, and
// compute_model_mirror once a file.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// §14.5's eighteen jobs, the seventeen of its table that taskworker runs and compute_model_mirror (CO-49): each
// registered or listed unbuilt, never both and never neither, with a known area, a group of §14.4's or none, and a
// cadence its settings give.
func TestComputeJobDesignIsRegisteredOrUnbuilt(t *testing.T) {
	design := ComputeJobDesign(nil)
	if len(design) != 18 {
		t.Fatalf("the table holds %d jobs, §14.5 eighteen", len(design))
	}
	names := map[string]bool{}
	taskNames := map[string]bool{}
	for _, job := range design {
		if names[job.Name] {
			t.Errorf("%s twice", job.Name)
		}
		names[job.Name] = true
		taskName := ComputeJobTaskName(job.Name)
		if taskNames[taskName] || !strings.HasPrefix(taskName, "compute.") {
			t.Errorf("%s's task name %s", job.Name, taskName)
		}
		taskNames[taskName] = true
		if !slices.Contains([]string{"BAL", "ENC", "INFER", "PROV", "GAMMA", "SRCH", "CSRV"}, job.Owner) {
			t.Errorf("%s has no area", job.Name)
		}
		if !slices.Contains([]string{ComputeJobGroupLedger, ComputeJobGroupProviders, ComputeJobGroupEnclaves, ""}, job.Group) {
			t.Errorf("%s reads group %q", job.Name, job.Group)
		}
		switch job.Cadence {
		case ComputeJobCadenceEvery:
			// a chain through pending_task only for a minute or more
			if job.Interval < time.Minute {
				t.Errorf("%s chains every %v", job.Name, job.Interval)
			}
		case ComputeJobCadenceDaily:
			if job.TimeOfDay < 0 || 24*time.Hour <= job.TimeOfDay {
				t.Errorf("%s runs at %v past midnight", job.Name, job.TimeOfDay)
			}
		case ComputeJobCadenceShardLoop:
			if job.Interval <= 0 || job.ShardCount <= 0 {
				t.Errorf("%s loops every %v over %d shards", job.Name, job.Interval, job.ShardCount)
			}
		case ComputeJobCadenceLoop:
			if job.Interval <= 0 {
				t.Errorf("%s loops every %v", job.Name, job.Interval)
			}
		case ComputeJobCadenceQueued:
		default:
			t.Errorf("%s has cadence %d", job.Name, job.Cadence)
		}
		registered := RegisteredJob(job.Name) != nil
		unbuilt := slices.Contains(computeJobUnbuilt, job.Name)
		switch {
		case registered && unbuilt:
			t.Errorf("%s is registered and still listed unbuilt", job.Name)
		case !registered && !unbuilt:
			t.Errorf("%s (%s) is neither registered nor listed unbuilt", job.Name, job.Owner)
		}
	}
	for _, name := range computeJobUnbuilt {
		if !names[name] {
			t.Errorf("%s is listed unbuilt and is no job of §14.5", name)
		}
	}
	for _, name := range RegisteredJobNames() {
		if strings.HasPrefix(name, "compute_") && !names[name] {
			t.Errorf("%s is registered and is no job of §14.5", name)
		}
	}
}

// The table's figures are §14.5's, from the settings: settlement every 2 s over 16 shards, the minute jobs every
// minute, the daily ones at 02:00 and 04:00 UTC, and the mirror's run bounded by its copy's timeout.
func TestComputeJobDesignTakesItsSettings(t *testing.T) {
	jobs := map[string]*ComputeJob{}
	for _, job := range ComputeJobDesign(nil) {
		jobs[job.Name] = job
	}
	for name, interval := range map[string]time.Duration{
		ComputeJobOpRecover: time.Minute, ComputeJobAutoRenew: time.Minute, ComputeJobSuspend: time.Minute,
		ComputeJobSearchTickets: time.Minute, ComputeJobDirectSettle: time.Minute, ComputeJobEnclaveMeter: 10 * time.Minute,
		ComputeJobGammaMint: 5 * time.Minute, ComputeJobGammaSpend: 5 * time.Minute, ComputeJobSearchPurge: 5 * time.Minute,
		ComputeJobProviderPrices: time.Hour, ComputeJobCanary: time.Hour, ComputeJobSearchOutcomes: time.Hour,
		ComputeJobPromoLapse: time.Hour,
	} {
		if jobs[name].Cadence != ComputeJobCadenceEvery || jobs[name].Interval != interval {
			t.Errorf("%s: cadence %d every %v, want every %v", name, jobs[name].Cadence, jobs[name].Interval, interval)
		}
	}
	if job := jobs[ComputeJobSettle]; job.Cadence != ComputeJobCadenceShardLoop || job.Interval != 2*time.Second || job.ShardCount != 16 {
		t.Errorf("compute_settle: %+v", job)
	}
	if job := jobs[ComputeJobRollupDay]; job.Cadence != ComputeJobCadenceDaily || job.TimeOfDay != 2*time.Hour {
		t.Errorf("compute_rollup_day: %+v", job)
	}
	if job := jobs[ComputeJobReconcile]; job.Cadence != ComputeJobCadenceDaily || job.TimeOfDay != 4*time.Hour {
		t.Errorf("compute_reconcile: %+v", job)
	}
	if job := jobs[ComputeJobGammaWatch]; job.Cadence != ComputeJobCadenceLoop || job.Interval <= 0 {
		t.Errorf("compute_gamma_watch: %+v", job)
	}
	if job := jobs[ComputeJobModelMirror]; job.Cadence != ComputeJobCadenceQueued || job.Group != "" || job.MaxTime != model.DefaultComputeModelMirrorSettings().CopyTimeout {
		t.Errorf("compute_model_mirror: %+v", job)
	}
	settings := DefaultComputeJobSettings()
	settings.Ledger.SettleShardCount = 4
	settings.SearchTicketsInterval = 2 * time.Minute
	for _, job := range ComputeJobDesign(settings) {
		if job.Name == ComputeJobSettle && job.ShardCount != 4 || job.Name == ComputeJobSearchTickets && job.Interval != 2*time.Minute {
			t.Errorf("%s does not take its settings: %+v", job.Name, job)
		}
	}
}

// §14.8's check: the defaults' shards × rows a batch ÷ the interval cover 1,000 calls a second with headroom, at a few
// booking transactions a second. Each call writes its operation row four times, inserted at its hold, updated at its
// settlement and its booking, and deleted after its drop: about 4,000 row writes a second at the design rate, which
// CTEST-M12-05 counts on real stores.
func TestComputeSettleCoversTheDesignRate(t *testing.T) {
	// §14.8's figures
	designCallsPerSecond := 1000.0
	headroom := 2.0
	fewTransactionsPerSecond := 10.0
	ledger := DefaultComputeJobSettings().Ledger
	seconds := ledger.SettleInterval.Seconds()
	if seconds <= 0 {
		t.Fatalf("compute_settle runs every %v", ledger.SettleInterval)
	}
	rowsPerSecond := float64(ledger.SettleShardCount*ledger.SettleBatchRowCount) / seconds
	if rowsPerSecond < designCallsPerSecond*headroom {
		t.Errorf("the defaults book %.0f rows a second, under %.0f calls a second with %.0f× headroom", rowsPerSecond, designCallsPerSecond, headroom)
	}
	transactionsPerSecond := float64(ledger.SettleShardCount) / seconds
	if fewTransactionsPerSecond < transactionsPerSecond {
		t.Errorf("the defaults book in %.1f transactions a second, past a few", transactionsPerSecond)
	}
	// at the design rate, each shard's batch is a fraction of its bound, so a burst drains within a run or two
	if batchFill := designCallsPerSecond * seconds / float64(ledger.SettleShardCount); float64(ledger.SettleBatchRowCount) < batchFill {
		t.Errorf("a shard's batch of %d rows is under the %.0f the design rate settles a run", ledger.SettleBatchRowCount, batchFill)
	}
}

// A name is registered once, and a job needs a name and a run.
func TestComputeJobRegistryRefusesWhatItCannotRun(t *testing.T) {
	for label, register := range map[string]func(){
		"twice":   func() { RegisterJob(&Job{Name: ComputeJobSettle, Run: RegisteredJob(ComputeJobSettle).Run}) },
		"nil":     func() { RegisterJob(nil) },
		"no name": func() { RegisterJob(&Job{Run: RegisteredJob(ComputeJobSettle).Run}) },
		"no run":  func() { RegisterJob(&Job{Name: "compute_test_no_run"}) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
	if RegisteredJob("compute_test_no_run") != nil {
		t.Fatal("a job with no run was kept")
	}
}

// compute_settle's args name one shard, which its run reads back; anything else is refused before any store is read.
func TestComputeSettleJobArgsNameItsShard(t *testing.T) {
	for _, shard := range []int16{0, 7, 15} {
		got, err := computeSettleJobShard(ComputeSettleJobArgs(shard))
		if err != nil || got != shard {
			t.Errorf("shard %d reads back %d %v", shard, got, err)
		}
	}
	for _, args := range []string{"", "7", "shard:", "shard:-1", "shard:70000", "shard:x"} {
		if _, err := computeSettleJobShard([]byte(args)); !errors.Is(err, ErrComputeJobArgs) {
			t.Errorf("%q: %v", args, err)
		}
		if _, err := RegisteredJob(ComputeJobSettle).Run(context.Background(), []byte(args)); !errors.Is(err, ErrComputeJobArgs) {
			t.Errorf("a run of %q: %v", args, err)
		}
	}
}

// A store of the mirror's objects in memory, as server's rules have it for what these runs touch.
type testComputeJobMirrorStore struct {
	stateLock     sync.Mutex
	records       map[string]*model.ComputeModelFileRecord
	chunks        map[string][]byte
	chunkPutCount int
}

func (self *testComputeJobMirrorStore) FileRecord(ctx context.Context, sha256Text string) (*model.ComputeModelFileRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, ok := self.records[sha256Text]
	if !ok {
		return nil, model.ErrComputeModelObjectAbsent
	}
	copied := *record
	return &copied, nil
}

func (self *testComputeJobMirrorStore) OpenIndex(ctx context.Context, sha256Text string) (io.ReadCloser, error) {
	return nil, model.ErrComputeModelObjectAbsent
}

func (self *testComputeJobMirrorStore) OpenChunk(ctx context.Context, sha256Text string, n int) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	data, ok := self.chunks[fmt.Sprintf("%s/%d", sha256Text, n)]
	if !ok {
		return nil, model.ErrComputeModelObjectAbsent
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (self *testComputeJobMirrorStore) PutIndex(ctx context.Context, sha256Text string, localPath string) error {
	return errors.New("no index is put by a copy")
}

func (self *testComputeJobMirrorStore) PutChunk(ctx context.Context, sha256Text string, n int, localPath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.chunks[fmt.Sprintf("%s/%d", sha256Text, n)] = data
	self.chunkPutCount += 1
	return nil
}

func (self *testComputeJobMirrorStore) PutFileRecord(ctx context.Context, sha256Text string, record *model.ComputeModelFileRecord) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *record
	self.records[sha256Text] = &copied
	return nil
}

// A hub serving one file's bytes at its url, counting requests.
type testComputeJobHub struct {
	stateLock    sync.Mutex
	url          string
	data         []byte
	requestCount int
}

func (self *testComputeJobHub) Open(ctx context.Context, fileUrl string, offset int64) (io.ReadCloser, int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requestCount += 1
	if fileUrl != self.url {
		return nil, 0, fmt.Errorf("%w: the hub answered 404", model.ErrComputeModelFetchRefused)
	}
	return io.NopCloser(bytes.NewReader(self.data[min(offset, int64(len(self.data))):])), int64(len(self.data)), nil
}

// compute_model_mirror's run copies a manifest's file once: its args name the file and coalesce under its SHA-256,
// the same file's run again leaves the copy as it is and asks the hub nothing, another file has its own key, and a
// process that installed no store runs nothing.
func TestComputeModelMirrorJobRunsOnceAFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "compute", "models", "draft.json"))
	if err != nil {
		t.Fatal(err)
	}
	inferSettings := sidecar.DefaultInferSettings()
	manifest, err := model.ParseComputeModelDraftManifest(data, inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	files := model.ComputeModelManifestFiles(manifest)
	if len(files) < 2 {
		t.Fatalf("the draft names %d files", len(files))
	}
	file := files[0]
	// the vectors' files' bytes, by the testdata README's rule: byte i is (i + seed) mod 251
	fileBytes := []byte(nil)
	for _, seedByteCount := range []struct{ byteCount, seed int }{{byteCount: 2621440, seed: 0}, {byteCount: 1048577, seed: 7}} {
		candidate := make([]byte, seedByteCount.byteCount)
		for i := range candidate {
			candidate[i] = byte((i + seedByteCount.seed) % 251)
		}
		digest := sha256.Sum256(candidate)
		if hex.EncodeToString(digest[:]) == file.Sha256 {
			fileBytes = candidate
		}
	}
	if fileBytes == nil {
		t.Fatalf("the README's rule makes no file of %s", file.Sha256)
	}

	args, onceKey, err := ComputeModelMirrorJobArgs(file)
	if err != nil || onceKey != ComputeJobModelMirror+"."+file.Sha256 {
		t.Fatalf("args %q key %q %v", args, onceKey, err)
	}
	if _, otherKey, err := ComputeModelMirrorJobArgs(files[1]); err != nil || otherKey == onceKey {
		t.Fatalf("another file's key %q %v", otherKey, err)
	}
	if again, againKey, _ := ComputeModelMirrorJobArgs(file); !bytes.Equal(again, args) || againKey != onceKey {
		t.Fatal("one file's args are not one")
	}

	job := RegisteredJob(ComputeJobModelMirror)
	// no store installed: nothing runs
	if _, err := job.Run(context.Background(), args); !errors.Is(err, ErrComputeJobDepsNotInstalled) {
		t.Fatalf("a run with no store: %v", err)
	}

	settings := DefaultComputeJobSettings()
	settings.ModelMirror.HubHost = "hub.example"
	settings.ModelMirror.HubRedirectHostSuffixes = []string{"cdn.example"}
	settings.ModelMirror.HubRetryInterval = 0
	settings.ModelMirror.StagingDirectory = t.TempDir()
	store := &testComputeJobMirrorStore{records: map[string]*model.ComputeModelFileRecord{}, chunks: map[string][]byte{}}
	hub := &testComputeJobHub{url: file.Url, data: fileBytes}
	t.Cleanup(InstallComputeJobDeps(&ComputeJobDeps{Settings: settings, ModelMirrorStore: store, ModelMirrorFetcher: hub}))

	if _, err := job.Run(context.Background(), args); err != nil {
		t.Fatalf("the copy: %v", err)
	}
	record, err := store.FileRecord(context.Background(), file.Sha256)
	if err != nil || record.State != model.ComputeModelFileStateCopied || store.chunkPutCount == 0 {
		t.Fatalf("after the copy: %+v %v, %d chunks put", record, err, store.chunkPutCount)
	}
	requestCount, chunkPutCount := hub.requestCount, store.chunkPutCount
	if _, err := job.Run(context.Background(), args); err != nil {
		t.Fatalf("the copy again: %v", err)
	}
	if hub.requestCount != requestCount || store.chunkPutCount != chunkPutCount {
		t.Errorf("a second run asked the hub %d more times and put %d more chunks", hub.requestCount-requestCount, store.chunkPutCount-chunkPutCount)
	}
	if _, err := job.Run(context.Background(), []byte(`{"name":"no sha"}`)); !errors.Is(err, ErrComputeJobArgs) {
		t.Errorf("args naming no file: %v", err)
	}
}
