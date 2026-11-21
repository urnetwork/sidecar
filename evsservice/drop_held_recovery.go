package evsservice

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Restore a lost held-job record only when its immutable snap-0 and deletion
// history identify it uniquely. A previous observed job can cover the same
// DROP, so a matching snap-0 alone is insufficient. Leave incomplete evidence
// in place for storage recovery and keep the read route closed in that case.
func (self *DropJob) restoreHeldOwners(ctx context.Context, cluster sidecar.BlobCluster, segments sidecar.BlobCluster, repoId sidecar.Id, table *DropTableState, missing missingHeldOwners) (*DropTableRead, error) {
	var jobs []*DropJobRecord
	owners := map[sidecar.Id]sidecar.Id{}
	prefix := dropscanKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	startAfter := ""
	for {
		objects, more, err := segments.List(ctx, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			idText, _, ok := strings.Cut(strings.TrimPrefix(object.Key, prefix), "/")
			jobId, err := parseEvsHexId(idText)
			if !ok || err != nil || object.Key != DropFileKey(repoId, jobId, DropFileSnap, 0) {
				continue
			}
			files := NewDropFiles(segments, repoId, jobId, self.settings)
			snap, err := files.Read(ctx, DropFileSnap, 0)
			if err != nil {
				return nil, err
			}
			if snap == nil {
				return nil, fmt.Errorf("%w: listed snap-0 is missing", ErrDropJobState)
			}
			job := &DropJobRecord{
				JobId: jobId, Held: true, Resumed: true, Phase: protocol.EvsDropPhase_EVS_DROP_HORIZON,
				StartedMs: object.LastModified.UnixMilli(), CoveredCount: uint16(len(snap.Covered)),
			}
			var matched []sidecar.Id
			for _, drop := range snap.Covered {
				job.FenceMs = max(job.FenceMs, drop.SeenMs)
				if !missing[drop.DropId] {
					continue
				}
				entry := table.Drop(drop.DropId)
				if entry.RefId != drop.RefId || entry.Version != drop.Version || entry.PushId != drop.PushId || entry.SeenMs != drop.SeenMs {
					return nil, fmt.Errorf("%w: held drop does not match its snap-0", ErrDropJobState)
				}
				if len(matched) != 0 && (entry.FreedByteCount != job.FreedByteCount || entry.HeldByteCount != job.HeldByteCount) {
					return nil, fmt.Errorf("%w: held drops disagree on job byte counts", ErrDropJobState)
				}
				job.FreedByteCount, job.HeldByteCount = entry.FreedByteCount, entry.HeldByteCount
				matched = append(matched, drop.DropId)
			}
			if len(matched) == 0 {
				continue
			}
			round, err := heldRecoveryRound(ctx, files)
			if err != nil {
				return nil, err
			}
			if round == 0 {
				// No record of this job ever moving a candidate to held.
				continue
			}
			job.Round = round
			jobs = append(jobs, job)
			for _, id := range matched {
				if _, exists := owners[id]; exists {
					return nil, fmt.Errorf("%w: multiple jobs claim a held drop", ErrDropJobState)
				}
				owners[id] = jobId
			}
		}
		if !more || len(objects) == 0 {
			break
		}
		startAfter = objects[len(objects)-1].Key
	}
	if len(owners) != len(missing) {
		return nil, missing
	}
	slices.SortFunc(jobs, func(a, b *DropJobRecord) int {
		if a.StartedMs != b.StartedMs {
			return cmp.Compare(a.StartedMs, b.StartedMs)
		}
		return bytes.Compare(a.JobId[:], b.JobId[:])
	})
	return self.update(ctx, cluster, repoId, func(state *DropTableState, now time.Time) (bool, error) {
		var remaining missingHeldOwners
		err := checkHeldCoverage(ctx, segments, repoId, state, self.settings, nil)
		if !errors.As(err, &remaining) {
			return false, err
		}
		needed := map[sidecar.Id]bool{}
		for id := range remaining {
			jobId, ok := owners[id]
			if !ok {
				return false, remaining
			}
			needed[jobId] = true
		}
		for _, job := range jobs {
			if needed[job.JobId] && state.HeldJob(job.JobId) == nil {
				state.HeldJobs = append(state.HeldJobs, job)
			}
		}
		return true, nil
	})
}

// snap-0 and list files outlive all other files. The old tidy pass deletes an
// ended job's files in key order, cand-0 first. Require its candidates and its
// completed round to remain before reusing any held deletion history.
func heldRecoveryRound(ctx context.Context, files *DropFiles) (uint32, error) {
	dels, err := files.ReadAll(ctx, DropFileDel)
	if err != nil {
		return 0, err
	}
	held := map[DropScanId]bool{}
	for sequence, file := range dels {
		if file.Sequence != uint32(sequence) {
			return 0, fmt.Errorf("%w: held job lost a deletion file", ErrDropJobState)
		}
		for _, answer := range file.Answers {
			if answer.Outcome == DropOutcomeHeld {
				held[answer.DropScanId] = true
			}
		}
	}
	if len(held) == 0 {
		return 0, nil
	}
	heldFiles, err := files.ReadAll(ctx, DropFileHeld)
	if err != nil {
		return 0, err
	}
	recorded := map[DropScanId]bool{}
	for sequence, file := range heldFiles {
		if file.Sequence != uint32(sequence) {
			return 0, fmt.Errorf("%w: held job lost a held file", ErrDropJobState)
		}
		for _, id := range file.Ids {
			if !held[id] {
				return 0, fmt.Errorf("%w: held ID has no corresponding deletion outcome", ErrDropJobState)
			}
			recorded[id] = true
		}
	}
	for id := range held {
		if !recorded[id] {
			return 0, fmt.Errorf("%w: held job lost its held file", ErrDropJobState)
		}
	}
	candidates, err := files.ReadAll(ctx, DropFileCand)
	if err != nil {
		return 0, err
	}
	for sequence, file := range candidates {
		if file.Sequence != uint32(sequence) {
			return 0, fmt.Errorf("%w: held job lost a candidate file", ErrDropJobState)
		}
		for _, id := range file.Ids {
			delete(held, id)
		}
	}
	rounds, err := files.Sequences(ctx, DropFileSnap)
	if err != nil {
		return 0, err
	}
	if len(held) != 0 || len(rounds) < 2 {
		return 0, fmt.Errorf("%w: held job files are incomplete", ErrDropJobState)
	}
	for i, sequence := range rounds {
		if sequence != uint32(i) {
			return 0, fmt.Errorf("%w: held job lost a round snapshot", ErrDropJobState)
		}
	}
	return rounds[len(rounds)-1], nil
}
