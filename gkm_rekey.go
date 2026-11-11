//go:build !ios_extension

// ur evs rekey's job (§10.16's v0, R-KEYS-3, D-KEYS-6, owner decision 64; KEYS-M2-26): a client job that
// re-checkpoints the files of a repo under its current generation, so that no file's chain still reaches back to a
// key an older generation held. A removed reader keeps what it could already open; rewriting is lazy by §11.7's rule
// (4), a file's first write after a REMOVE generation, and this job does at once what that rule does file by file.
// §11 consumes rekey and does not own it: the job has no format of its own and writes only through EvsRepo.WritePaths,
// each path's ForceCheckpoint set, so every push is an ordinary push a reader verifies as any other.
//
//	generation  the one EvsRepo's writes seal to when the job begins, from GkmClient.EnsureWritable, which rotates
//	            first when a shrink is not covered; the job is done when every file it walked has a chain whose every
//	            record is of that generation or a newer one
//	walk        each ref named, each path named on it, depth first with a directory's children in name order; a file
//	            whose chain is already wholly of the generation is left as it stands, so a second run writes nothing
//	pushes      a push carries at most PushEntryWriteCount entry writes, 1,024, and at most PushByteCount of content,
//	            and goes in parts past §11.8's part bounds as any push does
//	rate        at most FileRate files a second per repo, 50, each file taking its turn before its content is read
//	progress    one sealed record per repo in the evs component's directory, rewritten only after a push commits, or
//	            after a run of files that needed no write, and naming the last path settled; a restart walks again
//	            from it, so a kill between a commit and its record rewrites nothing twice (the files are found
//	            current) and never skips a file
//	moved       a file written or removed by someone else between the job's read and its push refuses the push
//	            (EvsPathWrite.IfVersion, and evs's own 5g); the batch is read and built again, at most MovedRetryCount
//	            times, so the job never puts an older content back
//
// What it cannot name it does not claim. A repo's refs are named by the caller, main when none is, since a head
// stores no sealed ref name yet (questions/evs1-m2-01-ref-creation-fields.md), and a ref's root has no entry in
// format 1 (questions/evs1-m2-24-root-directory-names.md), so a request naming no path asks List for the root,
// which refuses, and the job ends having written nothing. A git-mode ref is rekeyed as any other, its pushes sealed
// as the REKEY shape (DESIGN-DETAILS 8.2.10, question keys-m2-26-rekey-git-mode-refs): its own entries, an overlay's
// held files and nothing it inherits, nothing on a tag ref. Another sidecar's owned ref takes writes only from its
// owner: it is skipped and named in the progress, never counted as done. Record-class repos refuse as their writes do (EVS1-M2-29, EVS1-M2-30). The scope a finished job covered is
// the refs and paths its progress names, nothing more.
//
// One job per repo at a time. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The job's steps a fault schedule holds (§22.8): around each push, and after the progress record that follows it.
const (
	gkmBarrierRekeyPushBefore    = "gkm.rekey.push.before"
	gkmBarrierRekeyPushAfter     = "gkm.rekey.push.after"
	gkmBarrierRekeyProgressAfter = "gkm.rekey.progress.after"
)

// The directory of the progress records, one file per repo, under the store the job is given.
const gkmRekeyDirectory = "rekey/"

// The progress record's layout version.
const gkmRekeyRecordVersion = 1

var (
	// A second job for a repo whose job is running.
	ErrGkmRekeyRunning = errors.New("gkm rekey: a job for the repo is running")
	// A batch whose paths kept moving under it past MovedRetryCount: the job stops and resumes from its record.
	ErrGkmRekeyMoved = errors.New("gkm rekey: the paths kept changing under the job")
)

// The job's tunables (§10.16: both limits are settings).
type GkmRekeySettings struct {
	// The most entry writes one push carries: 1,024 (§10.16), §11.8's bound on one part's entry writes too, so a
	// push past it is never built here. Each file rewritten is one entry write.
	PushEntryWriteCount int
	// The files a second the job takes, per repo: 50, one at a time (§10.16), so a large repo's rekey stays a
	// small share of its metadata cluster's write budget (§11.13).
	FileRate SidecarRate
	// The most content one push holds before it is sent: 64 MiB, which bounds what the job keeps open at once
	// whatever the files' sizes. A file past it goes in a push of its own.
	PushByteCount int64
	// How many times a push refused because its paths moved is read and built again before the job stops with
	// ErrGkmRekeyMoved: 3. A stopped job resumes from its record.
	MovedRetryCount int
}

// The defaults, a fresh value each call.
func DefaultGkmRekeySettings() *GkmRekeySettings {
	return &GkmRekeySettings{
		PushEntryWriteCount: EvsPartMaxEntryWriteCount,
		FileRate:            SidecarRate{Count: 50, Burst: 1, Interval: 1 * time.Second},
		PushByteCount:       64 * 1024 * 1024,
		MovedRetryCount:     3,
	}
}

// Every number positive, and a push within §10.16's bound.
func (self *GkmRekeySettings) validate() error {
	if err := checkSettingsNumbers("GkmRekeySettings", reflect.ValueOf(self).Elem(), false); err != nil {
		return err
	}
	if EvsPartMaxEntryWriteCount < self.PushEntryWriteCount {
		return fmt.Errorf("%w: GkmRekeySettings.PushEntryWriteCount past §10.16's 1,024", errInvalidSettings)
	}
	return nil
}

// Where a job stands.
type GkmRekeyState string

const (
	// A job is walking the repo in this process.
	GkmRekeyStateRunning GkmRekeyState = "running"
	// A job began and did not finish, and none runs now: a kill, a refusal or a lost connection. It resumes.
	GkmRekeyStateStopped GkmRekeyState = "stopped"
	// Every file under the refs and paths the progress names is of the generation or newer. A ref it lists as
	// skipped is not among them.
	GkmRekeyStateDone GkmRekeyState = "done"
)

// What a job is asked to cover.
type GkmRekeyRequest struct {
	RepoId Id
	// The refs' name bytes. Nil is main, or, with no path either, the refs of the repo's unfinished job.
	RefNames [][]byte
	// The paths to walk on each ref, raw names joined by /: a file, or a directory with everything below it. Nil
	// walks each ref from its root, which format 1 cannot list yet (see the file header), or, with no ref either,
	// resumes the repo's unfinished job.
	Paths []string
}

// A ref a job could not write, and why.
type GkmRekeySkippedRef struct {
	RefName []byte
	// "not_owner": another sidecar's owned ref, or a ref kind that takes its own pushes. "git_mode" is no longer
	// given: a git-mode ref is rekeyed through the REKEY shape.
	Reason string
}

// A job's progress, as its stored record holds it, so nothing here is ahead of what a restart would find: counts and
// positions, and this device's own paths, which stay in the sealed store and are never logged (I-13).
type GkmRekeyProgress struct {
	RepoId Id
	State  GkmRekeyState
	// The generation every walked file is brought to.
	Generation uint64
	// The scope: the refs and paths walked. Files outside it keep the keys they had.
	RefNames [][]byte
	Paths    []string
	// Files re-checkpointed by pushes that committed.
	RewrittenCount uint64
	// Files found already wholly of the generation, and left.
	CurrentCount uint64
	// Files a listing named that were gone by the time they were read.
	AbsentCount uint64
	// Pushes committed.
	PushCount   uint64
	SkippedRefs []*GkmRekeySkippedRef
	StartedAt   time.Time
	UpdatedAt   time.Time
	// Why the last run in this process stopped, empty when it did not or none ran. An error's text, which names no
	// path.
	StopReason string
}

// The stored form of a job's progress.
type gkmRekeyRecord struct {
	Version    int      `json:"version"`
	Generation uint64   `json:"generation"`
	RefNames   [][]byte `json:"ref_names"`
	Paths      []string `json:"paths"`
	// refs before this index are settled, and on this one every path at or before AfterPath in walk order
	RefIndex       int                   `json:"ref_index"`
	AfterPath      string                `json:"after_path,omitempty"`
	RewrittenCount uint64                `json:"rewritten_count"`
	CurrentCount   uint64                `json:"current_count"`
	AbsentCount    uint64                `json:"absent_count"`
	PushCount      uint64                `json:"push_count"`
	Skipped        []*gkmRekeySkipRecord `json:"skipped,omitempty"`
	Done           bool                  `json:"done"`
	StartedAtMs    int64                 `json:"started_at_ms"`
	UpdatedAtMs    int64                 `json:"updated_at_ms"`
}

// A skipped ref's stored form.
type gkmRekeySkipRecord struct {
	RefName []byte `json:"ref_name"`
	Reason  string `json:"reason"`
}

// What a GkmRekey takes.
type GkmRekeyArgs struct {
	// The network's evs client: the job reads and writes through it, and its gkm client answers the generation.
	Evs *EvsClient
	// A sealed directory for the progress records: the evs component's.
	Store SidecarStore
	// nil takes the defaults.
	Settings *GkmRekeySettings
	// nil is real time.
	Clock Clock
	Log   Logger
}

// One network's rekey jobs. See the file header.
type GkmRekey struct {
	args     *GkmRekeyArgs
	settings *GkmRekeySettings
	clock    Clock
	log      Logger
	ctx      context.Context
	cancel   context.CancelFunc
	started  sync.WaitGroup

	stateLock sync.Mutex
	// the repos a job runs for now
	runningRepoIds map[Id]bool
	// why each repo's last run here stopped
	repoIdStopReasons map[Id]string
	closed            bool
}

// The jobs of a network, none running. Start's jobs end with Close.
func NewGkmRekey(args *GkmRekeyArgs) (*GkmRekey, error) {
	if args == nil || args.Evs == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: a rekey job needs an evs client and a store", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultGkmRekeySettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &GkmRekey{
		args:              args,
		settings:          settings,
		clock:             clockOrReal(args.Clock),
		log:               loggerOrDefault(args.Log),
		ctx:               ctx,
		cancel:            cancel,
		runningRepoIds:    map[Id]bool{},
		repoIdStopReasons: map[Id]string{},
	}, nil
}

// Ends every job Start began and waits for each to stop. A stopped job keeps its record and resumes.
func (self *GkmRekey) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	self.cancel()
	self.started.Wait()
}

// Begins request's job, or resumes the repo's unfinished one, on a goroutine of its own, and answers the progress
// it starts from. ErrGkmRekeyRunning when one runs already.
func (self *GkmRekey) Start(request *GkmRekeyRequest) (*GkmRekeyProgress, error) {
	// counted before Close can begin its wait, so Close waits for every job that got this far
	open := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.started.Add(1)
		return true
	}()
	if !open {
		return nil, context.Canceled
	}
	run, err := self.begin(self.ctx, request)
	if err != nil {
		self.started.Done()
		return nil, err
	}
	progress := run.progress(GkmRekeyStateRunning)
	go func() {
		defer self.started.Done()
		self.finish(run, run.walk(self.ctx))
	}()
	return progress, nil
}

// Runs request's job to its end, or resumes the repo's unfinished one, and answers its progress. An error leaves
// the record at the last push that committed.
func (self *GkmRekey) Run(ctx context.Context, request *GkmRekeyRequest) (*GkmRekeyProgress, error) {
	run, err := self.begin(ctx, request)
	if err != nil {
		return nil, err
	}
	err = run.walk(ctx)
	self.finish(run, err)
	if err != nil {
		progress := run.progress(GkmRekeyStateStopped)
		progress.StopReason = err.Error()
		return progress, err
	}
	return run.progress(GkmRekeyStateDone), nil
}

// The repo's job as its record stands, false when it has none.
func (self *GkmRekey) Progress(repoId Id) (*GkmRekeyProgress, bool, error) {
	record, err := self.loadRecord(repoId)
	if err != nil || record == nil {
		return nil, false, err
	}
	run := &gkmRekeyRun{rekey: self, repoId: repoId, record: record}
	running, stopReason := func() (bool, string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.runningRepoIds[repoId], self.repoIdStopReasons[repoId]
	}()
	state := GkmRekeyStateStopped
	switch {
	case record.Done:
		state = GkmRekeyStateDone
	case running:
		state = GkmRekeyStateRunning
	}
	progress := run.progress(state)
	if state == GkmRekeyStateStopped {
		progress.StopReason = stopReason
	}
	return progress, true, nil
}

// Takes the repo's slot and readies its run: the unfinished record when request names its scope or none, else a
// new record at the generation writes seal to now.
func (self *GkmRekey) begin(ctx context.Context, request *GkmRekeyRequest) (*gkmRekeyRun, error) {
	if request == nil || request.RepoId == (Id{}) {
		return nil, fmt.Errorf("%w: a rekey names its repo", ErrEvsWriteInvalid)
	}
	repoId := request.RepoId
	paths, err := gkmRekeyTopPaths(request.Paths)
	if err != nil {
		return nil, err
	}
	taken, err := func() (bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false, context.Canceled
		}
		if self.runningRepoIds[repoId] {
			return false, ErrGkmRekeyRunning
		}
		self.runningRepoIds[repoId] = true
		delete(self.repoIdStopReasons, repoId)
		return true, nil
	}()
	if !taken {
		return nil, err
	}
	run := &gkmRekeyRun{rekey: self, repoId: repoId, repo: self.args.Evs.Repo(repoId), pacer: newGkmRekeyPacer(self.clock, self.settings.FileRate)}
	err = func() error {
		record, err := self.loadRecord(repoId)
		if err != nil {
			return err
		}
		unscoped := request.RefNames == nil && request.Paths == nil
		refNames := request.RefNames
		if refNames == nil {
			refNames = [][]byte{EvsMainRefName}
		}
		if record != nil && !record.Done && (unscoped || gkmRekeySameScope(record, refNames, paths)) {
			run.record = record
			return nil
		}
		// a new job: the generation its writes seal to, which EnsureWritable rotates to first when a shrink or
		// an expiry is not covered (§10.6)
		repoKey, err := self.args.Evs.args.Gkm.EnsureWritable(ctx, repoId)
		if err != nil {
			return err
		}
		now := self.clock.Now().UnixMilli()
		run.record = &gkmRekeyRecord{
			Version: gkmRekeyRecordVersion, Generation: repoKey.Generation(), RefNames: refNames, Paths: paths,
			StartedAtMs: now, UpdatedAtMs: now,
		}
		return run.persist(run.record)
	}()
	if err != nil {
		self.finish(run, err)
		return nil, err
	}
	return run, nil
}

// Frees the repo's slot and keeps why its run stopped.
func (self *GkmRekey) finish(run *gkmRekeyRun, err error) {
	run.closeBatch()
	if err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm]rekey stopped: %v", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.runningRepoIds, run.repoId)
	if err != nil {
		self.repoIdStopReasons[run.repoId] = err.Error()
	}
}

// The repo's record, nil when it has none. A record that does not open or parse is an error, never read as none,
// since a job begun again from nothing would report files it did not walk as walked (D-CORE-15).
func (self *GkmRekey) loadRecord(repoId Id) (*gkmRekeyRecord, error) {
	reader, err := self.args.Store.Open(gkmRekeyDirectory + repoId.String())
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	record := &gkmRekeyRecord{}
	if err := json.Unmarshal(data, record); err != nil || record.Version != gkmRekeyRecordVersion || record.Generation == 0 ||
		len(record.RefNames) == 0 || record.RefIndex < 0 || len(record.RefNames) < record.RefIndex {
		return nil, fmt.Errorf("%w: a rekey record does not parse", ErrSidecarStoreFailed)
	}
	return record, nil
}

// Whether record's scope is these refs and paths.
func gkmRekeySameScope(record *gkmRekeyRecord, refNames [][]byte, paths []string) bool {
	return slices.EqualFunc(record.RefNames, refNames, bytes.Equal) && slices.Equal(record.Paths, paths)
}

// Paths in walk order, each a valid path, none inside another: a path under a directory also named is walked with
// that directory.
func gkmRekeyTopPaths(paths []string) ([]string, error) {
	sorted := []string{}
	for _, path := range paths {
		if _, err := evsPathNames(path); err != nil {
			return nil, err
		}
		sorted = append(sorted, path)
	}
	slices.SortFunc(sorted, gkmRekeyComparePaths)
	tops := []string{}
	for _, path := range sorted {
		if 0 < len(tops) && (tops[len(tops)-1] == path || strings.HasPrefix(path, tops[len(tops)-1]+"/")) {
			continue
		}
		tops = append(tops, path)
	}
	if len(tops) == 0 {
		return nil, nil
	}
	return tops, nil
}

// The walk's order: name by name as bytes, a directory before what it holds. A depth-first walk that takes each
// directory's children in name order visits files in this order.
func gkmRekeyComparePaths(a string, b string) int {
	aNames, bNames := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < min(len(aNames), len(bNames)); i += 1 {
		if order := strings.Compare(aNames[i], bNames[i]); order != 0 {
			return order
		}
	}
	return len(aNames) - len(bNames)
}

// One file read and waiting for its push.
type gkmRekeyFile struct {
	path    string
	content *evsSpill
	// the entry version its content was read at, which the push is held to
	version uint64
}

// One run of a repo's job: the walk from its record's position. Not safe for concurrent use: one goroutine walks.
type gkmRekeyRun struct {
	rekey  *GkmRekey
	repoId Id
	repo   *EvsRepo
	pacer  *gkmRekeyPacer
	// guards record, which Progress reads while the walk writes
	recordLock sync.Mutex
	record     *gkmRekeyRecord

	// the ref being walked
	refName []byte
	refId   Id
	// files that needed no write, counted since the record was last written: the record takes them at its next
	// write, which names a position at or past each of them, so the record in memory is always the record as stored
	currentCount uint64
	absentCount  uint64
	// listed files waiting for their read, in walk order
	listedPaths []string
	// read files waiting for their push, in walk order
	batch          []*gkmRekeyFile
	batchByteCount int64
}

// The run's progress in state.
func (self *gkmRekeyRun) progress(state GkmRekeyState) *GkmRekeyProgress {
	self.recordLock.Lock()
	defer self.recordLock.Unlock()
	record := self.record
	progress := &GkmRekeyProgress{
		RepoId: self.repoId, State: state, Generation: record.Generation,
		RefNames: slices.Clone(record.RefNames), Paths: slices.Clone(record.Paths),
		RewrittenCount: record.RewrittenCount, CurrentCount: record.CurrentCount, AbsentCount: record.AbsentCount,
		PushCount: record.PushCount,
		StartedAt: time.UnixMilli(record.StartedAtMs), UpdatedAt: time.UnixMilli(record.UpdatedAtMs),
	}
	for _, skipped := range record.Skipped {
		progress.SkippedRefs = append(progress.SkippedRefs, &GkmRekeySkippedRef{RefName: skipped.RefName, Reason: skipped.Reason})
	}
	return progress
}

// Changes the record, with the counts waiting beside it, and writes it whole, so a kill leaves the old record or the
// new one (SidecarStore's rule). The record in memory changes only once the write committed.
func (self *gkmRekeyRun) update(change func(record *gkmRekeyRecord)) error {
	next := func() *gkmRekeyRecord {
		self.recordLock.Lock()
		defer self.recordLock.Unlock()
		next := *self.record
		next.Skipped = slices.Clone(self.record.Skipped)
		return &next
	}()
	change(next)
	next.CurrentCount += self.currentCount
	next.AbsentCount += self.absentCount
	next.UpdatedAtMs = self.rekey.clock.Now().UnixMilli()
	if err := self.persist(next); err != nil {
		return err
	}
	self.currentCount, self.absentCount = 0, 0
	self.recordLock.Lock()
	defer self.recordLock.Unlock()
	self.record = next
	return nil
}

// Writes record as the repo's.
func (self *gkmRekeyRun) persist(record *gkmRekeyRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	writer, err := self.rekey.args.Store.Create(gkmRekeyDirectory + self.repoId.String())
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Drops what the open batch holds.
func (self *gkmRekeyRun) closeBatch() {
	for _, file := range self.batch {
		file.content.close()
	}
	self.batch = nil
	self.batchByteCount = 0
	self.listedPaths = nil
}

// Walks every ref from the record's position, and marks the record done.
func (self *gkmRekeyRun) walk(ctx context.Context) error {
	for {
		refIndex, refNames := func() (int, [][]byte) {
			self.recordLock.Lock()
			defer self.recordLock.Unlock()
			return self.record.RefIndex, self.record.RefNames
		}()
		if len(refNames) <= refIndex {
			break
		}
		skipReason, err := self.walkRef(ctx, refNames[refIndex])
		if err != nil {
			return err
		}
		// the ref is settled: the next begins at its first path
		err = self.update(func(record *gkmRekeyRecord) {
			if skipReason != "" {
				record.Skipped = append(record.Skipped, &gkmRekeySkipRecord{RefName: refNames[refIndex], Reason: skipReason})
			}
			record.RefIndex = refIndex + 1
			record.AfterPath = ""
		})
		if err != nil {
			return err
		}
	}
	return self.update(func(record *gkmRekeyRecord) { record.Done = true })
}

// Walks one ref's named paths past the record's position. A ref this sidecar cannot write is not walked, and the
// reason answers.
func (self *gkmRekeyRun) walkRef(ctx context.Context, refName []byte) (skipReason string, err error) {
	defer self.closeBatch()
	self.refName = refName
	self.refId, err = self.repo.resolveRefId(ctx, refName, nil)
	if err != nil {
		return "", err
	}
	paths := func() []string {
		self.recordLock.Lock()
		defer self.recordLock.Unlock()
		return self.record.Paths
	}()
	if paths == nil {
		// the ref's root: its children, which format 1 cannot list yet, so this refuses with List's error
		listing, err := self.repo.List(ctx, &EvsReadArgs{RefId: &self.refId, Path: ""})
		if err != nil {
			return "", err
		}
		for _, entry := range listing.Entries {
			if err := self.walkEntry(ctx, string(entry.Name), entry.Kind); err != nil {
				return "", err
			}
		}
	} else {
		for start := 0; start < len(paths); start += EvsReadMaxPathCount {
			named := paths[start:min(len(paths), start+EvsReadMaxPathCount)]
			kinds, reason, err := self.namedKinds(ctx, refName, named)
			if err != nil || reason != "" {
				return reason, err
			}
			for i, path := range named {
				if err := self.walkEntry(ctx, path, kinds[i]); err != nil {
					return "", err
				}
			}
		}
	}
	if err := self.readListed(ctx); err != nil {
		return "", err
	}
	return "", self.pushBatch(ctx)
}

// What stands at each named path, unspecified for one that is gone, and why the ref takes no write from this
// sidecar, when it does not.
func (self *gkmRekeyRun) namedKinds(ctx context.Context, refName []byte, paths []string) ([]protocol.EvsEntryKind, string, error) {
	result, err := self.repo.read(ctx, self.refId, paths, 0, false)
	if err != nil {
		return nil, "", err
	}
	defer result.objects.close()
	writable := &EvsWritePlan{}
	// a rekey's writes are all rekey writes, which a git-mode ref takes (DESIGN-DETAILS 8.2.10)
	switch err := writable.setRef(result.head.Head, refName, self.rekey.args.Evs.args.Identity().SidecarId, true); {
	case errors.Is(err, ErrEvsWriteInvalid):
		return nil, "not_owner", nil
	case err != nil:
		return nil, "", err
	}
	kinds := make([]protocol.EvsEntryKind, len(paths))
	for i, verified := range result.replies {
		if verified.Base != nil {
			// an overlay's path it holds no version of: its base ref's to rekey, so nothing here
			continue
		}
		if verified.Entry != nil && verified.Removal == nil && !verified.Absent {
			kinds[i] = protocol.EvsEntryKind(verified.Entry.GetKind())
		}
	}
	return kinds, "", nil
}

// Walks one path: a file is listed for its read, a directory walked, its children in name order. Anything wholly
// at or before the record's position was settled by an earlier run and is passed.
func (self *gkmRekeyRun) walkEntry(ctx context.Context, path string, kind protocol.EvsEntryKind) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	after := func() string {
		self.recordLock.Lock()
		defer self.recordLock.Unlock()
		return self.record.AfterPath
	}()
	switch kind {
	case protocol.EvsEntryKind_EVS_ENTRY_FILE:
		if after != "" && gkmRekeyComparePaths(path, after) <= 0 {
			return nil
		}
		self.listedPaths = append(self.listedPaths, path)
		if EvsReadMaxPathCount <= len(self.listedPaths) {
			return self.readListed(ctx)
		}
		return nil
	case protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY:
		if after != "" && gkmRekeyComparePaths(path, after) < 0 && !strings.HasPrefix(after, path+"/") {
			return nil
		}
		listing, err := self.repo.List(ctx, &EvsReadArgs{RefId: &self.refId, Path: path})
		if errors.Is(err, ErrEvsPathAbsent) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range listing.Entries {
			if err := self.walkEntry(ctx, path+"/"+string(entry.Name), entry.Kind); err != nil {
				return err
			}
		}
		return nil
	default:
		// a path named that does not stand: counted as gone, once
		if after == "" || 0 < gkmRekeyComparePaths(path, after) {
			self.absentCount += 1
		}
		return nil
	}
}

// Reads the listed files, each in its turn under the rate: one already of the generation is left, any other joins
// the batch, which is pushed as it fills. With nothing left waiting for a push, the position moves past them.
func (self *gkmRekeyRun) readListed(ctx context.Context) error {
	paths := self.listedPaths
	self.listedPaths = nil
	if len(paths) == 0 {
		return nil
	}
	if err := self.readFiles(ctx, paths, true); err != nil {
		return err
	}
	if 0 < len(self.batch) {
		return nil
	}
	last := paths[len(paths)-1]
	return self.update(func(record *gkmRekeyRecord) { record.AfterPath = last })
}

// Reads paths, in walk order, into the batch. pushFull pushes the batch each time it fills, as the walk does; a
// batch being read again after its paths moved is pushed by its caller instead.
func (self *gkmRekeyRun) readFiles(ctx context.Context, paths []string, pushFull bool) error {
	generation := func() uint64 {
		self.recordLock.Lock()
		defer self.recordLock.Unlock()
		return self.record.Generation
	}()
	result, err := self.repo.read(ctx, self.refId, paths, 0, false)
	if err != nil {
		return err
	}
	defer result.objects.close()
	for i, verified := range result.replies {
		switch {
		case verified.Base != nil:
			return ErrEvsOverlayBase
		case verified.Entry == nil || verified.Removal != nil || verified.Absent:
			self.absentCount += 1
			continue
		case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE):
			// a directory took the name since the listing: its files are new, sealed to a current generation
			self.absentCount += 1
			continue
		}
		if err := self.pacer.take(ctx); err != nil {
			return err
		}
		content, chain, _, err := self.repo.readBase(ctx, result, verified)
		if err != nil {
			return err
		}
		if generation <= chain.KeyGeneration {
			content.close()
			self.currentCount += 1
			continue
		}
		self.batch = append(self.batch, &gkmRekeyFile{path: paths[i], content: content, version: verified.Entry.GetVersion()})
		self.batchByteCount += content.Size()
		if pushFull && (self.rekey.settings.PushEntryWriteCount <= len(self.batch) || self.rekey.settings.PushByteCount <= self.batchByteCount) {
			// every file counted so far is at or before this push's last path, which the record then names
			if err := self.pushBatch(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// Pushes the batch, every file a forced checkpoint held to the version it was read at, and only then moves the
// record's position to its last path. A push refused because a path moved reads the batch again and pushes what
// still needs it.
func (self *gkmRekeyRun) pushBatch(ctx context.Context) error {
	if len(self.batch) == 0 {
		return nil
	}
	barrierKey := self.repoId.String()
	last := self.batch[len(self.batch)-1].path
	for moved := 0; 0 < len(self.batch); moved += 1 {
		writes := make([]*EvsPathWrite, len(self.batch))
		for i, file := range self.batch {
			writes[i] = &EvsPathWrite{Path: file.path, Content: file.content, ForceCheckpoint: true, IfVersion: file.version}
		}
		testHookBarrier(gkmBarrierRekeyPushBefore, barrierKey)
		_, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: self.refName, Writes: writes})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrEvsPathMoved) && !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT) {
			return err
		}
		if self.rekey.settings.MovedRetryCount <= moved {
			return fmt.Errorf("%w: %w", ErrGkmRekeyMoved, err)
		}
		paths := make([]string, len(self.batch))
		for i, file := range self.batch {
			paths[i] = file.path
			file.content.close()
		}
		self.batch = nil
		self.batchByteCount = 0
		for start := 0; start < len(paths); start += EvsReadMaxPathCount {
			if err := self.readFiles(ctx, paths[start:min(len(paths), start+EvsReadMaxPathCount)], false); err != nil {
				return err
			}
		}
	}
	testHookBarrier(gkmBarrierRekeyPushAfter, barrierKey)
	pushed := uint64(len(self.batch))
	for _, file := range self.batch {
		file.content.close()
	}
	self.batch = nil
	self.batchByteCount = 0
	err := self.update(func(record *gkmRekeyRecord) {
		record.AfterPath = last
		record.RewrittenCount += pushed
		if 0 < pushed {
			record.PushCount += 1
		}
	})
	if err != nil {
		return err
	}
	testHookBarrier(gkmBarrierRekeyProgressAfter, barrierKey)
	return nil
}

// The job's rate: each file takes one turn, turns Interval / Count apart, at most Burst taken at once after an idle
// stretch. Waits run on the job's clock. Not safe for concurrent use: one walk takes turns.
type gkmRekeyPacer struct {
	clock Clock
	// the spacing between turns, and how far behind the clock the next turn may fall and still be taken at once
	step      time.Duration
	tolerance time.Duration
	// when the next turn is due
	nextAt time.Time
}

// A pacer at rate, its first turn free.
func newGkmRekeyPacer(clock Clock, rate SidecarRate) *gkmRekeyPacer {
	step := rate.Interval / time.Duration(rate.Count)
	return &gkmRekeyPacer{clock: clock, step: step, tolerance: step * time.Duration(rate.Burst-1)}
}

// Waits for the next turn, or for ctx.
func (self *gkmRekeyPacer) take(ctx context.Context) error {
	now := self.clock.Now()
	if self.nextAt.Before(now.Add(-self.tolerance)) {
		self.nextAt = now.Add(-self.tolerance)
	}
	if wait := self.nextAt.Sub(now); 0 < wait {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.clock.After(wait):
		}
	}
	self.nextAt = self.nextAt.Add(self.step)
	return ctx.Err()
}
