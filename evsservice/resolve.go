// Where a push id stands in its ref's history (§11.8's 5a and Resolve rows), one rule for the push route's retries and
// for evacuation:
//
//	committed  the head window, then at most two log pages of (b, b+64], name P at a version with P's statement
//	           prefix; the window entry or page entry gives its place
//	reused     they name P under another statement prefix, or a refusal record names P under another: 409
//	           PUSH_ID_REUSED
//	recorded   a refusal record names P and its statement: its refusal, again
//	dead       for Resolve: not committed, and the head at or past b+64 (git mode b+1), or the statement past its time
//	           checks (time_ms + 35 min) with the head's fence_ms later than that
//	pending    for Resolve: none of the above
//
// Log pages never change, so each is read once a process (LogPageCache); one packed after 24 h is found through
// pidx/ (RecordLocator). Safe for concurrent use.

package evsservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Resolve's dead rule: a statement can no longer pass 5b's time checks once its time_ms is 35 min past, the seal's
// 30 min bound with margin (§11.8's Resolve row).
const evsResolveStatementLife = 35 * time.Minute

// A push id's standing in one head and the log pages under it.
type EvsPushStanding struct {
	// Committed at Version, its record at Place.
	Committed bool
	Version   uint64
	Place     *protocol.EvsPlace
	// The id names another statement: committed or recorded under another prefix.
	Reused bool
	// A refusal record of this statement.
	Recorded *sidecar.EvsRefusal
}

// Where pushId, whose statement hashes to statementSha256 and was built on baseVersion in git or file mode, stands
// in head and the log pages of (b, b+64] below its window. readPage reads one log page; nil reads none.
func EvsPushStandingIn(ctx context.Context, head *protocol.EvsHead, pushId sidecar.Id, statementSha256 [32]byte, baseVersion uint64, gitMode bool, readPage func(ctx context.Context, page uint64) (*LogPage, error)) (*EvsPushStanding, error) {
	standing := &EvsPushStanding{}
	if head == nil {
		return standing, nil
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, err
	}
	first := EvsHeadWindowFirstVersion(head)
	for i, entry := range window {
		if entry.PushId != pushId {
			continue
		}
		if entry.StatementPrefix != [16]byte(statementSha256[:16]) {
			standing.Reused = true
			return standing, nil
		}
		standing.Committed = true
		standing.Version = first + uint64(i)
		standing.Place = entry.Place
		return standing, nil
	}

	// the versions of (b, b+64] the window no longer holds, git mode only b+1
	last := baseVersion + evsFileModeBaseWindow + 1
	if gitMode {
		last = baseVersion + 1
	}
	last = min(last, first-1, head.GetVersion())
	if readPage != nil && baseVersion+1 <= last {
		for page := EvsLogPageOf(baseVersion + 1); page <= EvsLogPageOf(last); page += 1 {
			logPage, err := readPage(ctx, page)
			if err != nil {
				return nil, err
			}
			version, ok := logPage.VersionOf(pushId)
			if !ok {
				continue
			}
			entry, _, _ := logPage.At(version)
			if entry.StatementPrefix != [16]byte(statementSha256[:16]) {
				standing.Reused = true
				return standing, nil
			}
			standing.Committed = true
			standing.Version = version
			standing.Place = entry.Place
			return standing, nil
		}
	}

	refusals, err := sidecar.DecodeEvsRefusals(head.GetRefused())
	if err != nil {
		return nil, err
	}
	for _, refusal := range refusals {
		if !refusal.RecordsPush(pushId) {
			continue
		}
		if !refusal.RecordsStatement(statementSha256) {
			standing.Reused = true
			return standing, nil
		}
		standing.Recorded = refusal
		return standing, nil
	}
	return standing, nil
}

// A log page of a ref: this process's cache, its object, or, once packed, its container through pidx/.
func (self *EvsEngine) readLogPage(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	logPage, err := ReadLogPage(ctx, self.folder.LogPages(), cluster, repoId, refId, page)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return logPage, err
	}
	pageBytes, err := self.locator.ReadLogPage(ctx, cluster, repoId, refId, page)
	if err != nil {
		return nil, err
	}
	logPage, err = ParseLogPage(repoId, refId, page, pageBytes)
	if err != nil {
		return nil, err
	}
	self.folder.LogPages().Put(cluster.ClusterId(), repoId, refId, logPage)
	return logPage, nil
}

// What Resolve finds of one batch record's push.
type EvsResolveState int

const (
	// Committed at the place its version's entry names.
	EvsResolveCommitted EvsResolveState = iota + 1
	// Not committed and never will be: evacuation drops the record and deletes the new slots it lists (§11.13).
	EvsResolveDead
	// Neither yet: evacuation raises the ref's fence and resolves again.
	EvsResolvePending
)

// What Resolve found.
type EvsResolution struct {
	State EvsResolveState
	// Committed: the version and the place its entry names, which may be another copy's.
	Version uint64
	Place   *protocol.EvsPlace
}

// §11.8's Resolve rule for a batch record, which evacuation runs over every record of a batch past 25 h (§11.13): a
// push's or seal's by its own statement against its ref's cluster head and log pages; a part follows its seal, so
// it resolves as its statement's push; a reseed counts as committed. head is the ref's head as the caller read it
// from the cluster, nil when the ref has none.
func (self *EvsEngine) ResolvePush(ctx context.Context, cluster sidecar.BlobCluster, record *sidecar.EvsBatchRecord, head *protocol.EvsHead) (*EvsResolution, error) {
	return ResolveBatchRecord(ctx, record, head, func(ctx context.Context, page uint64) (*LogPage, error) {
		return self.readLogPage(ctx, cluster, record.RepoId, record.RefId, page)
	})
}

// A batch record's statement: a push's, part's, seal's or reseed's first item, parsed in either format.
func EvsBatchRecordStatement(record *sidecar.EvsBatchRecord) (*sidecar.EvsStatement, error) {
	var statementBytes []byte
	var err error
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, _, err = sidecar.ParseEvsPushRecordBody(record.Body)
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		statementBytes, _, _, _, err = sidecar.ParseEvsPartRecordBody(record.Body)
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, _, err = sidecar.ParseEvsSealRecordBody(record.Body)
	default:
		return nil, sidecar.ErrEvsPushInvalid
	}
	if err != nil {
		return nil, err
	}
	return sidecar.ParseEvsStatementFormat2(statementBytes)
}

// ResolvePush's rule for a caller that holds no engine, taskworker's evacuation: readPage reads one log page of the
// record's ref, from log/ or, once packed, from its pack.
func ResolveBatchRecord(ctx context.Context, record *sidecar.EvsBatchRecord, head *protocol.EvsHead, readPage func(ctx context.Context, page uint64) (*LogPage, error)) (*EvsResolution, error) {
	if record.Type == protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		return &EvsResolution{State: EvsResolveCommitted}, nil
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	push := statement.Push
	gitMode := protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
	standing, err := EvsPushStandingIn(ctx, head, record.PushId, statement.Sha256, push.GetBaseVersion(), gitMode, readPage)
	if err != nil {
		return nil, err
	}
	if standing.Committed {
		return &EvsResolution{State: EvsResolveCommitted, Version: standing.Version, Place: standing.Place}, nil
	}
	bound := push.GetBaseVersion() + evsFileModeBaseWindow + 1
	if gitMode {
		bound = push.GetBaseVersion() + 1
	}
	if head != nil && bound <= head.GetVersion() {
		return &EvsResolution{State: EvsResolveDead}, nil
	}
	if expiresMs := time.UnixMilli(push.GetTimeMs()).Add(evsResolveStatementLife).UnixMilli(); head != nil && expiresMs < head.GetFenceMs() {
		return &EvsResolution{State: EvsResolveDead}, nil
	}
	return &EvsResolution{State: EvsResolvePending}, nil
}
