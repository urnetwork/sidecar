// The sweep's one-off passes as taskworker runs them (§11.13's sweep row; EVSB-M10-02): evs.sweep, a sidecar job on
// taskworker's evs host. Its args name one of three runs:
//
//	start  a hold's end, with its network, its scope and the window from 26 h before its placement to its end; or
//	       the purge's turn-on from observe. A hold scoped to repos queues each repo's run on the cluster place/
//	       names; a network's hold and the turn-on queue a scan of each metadata cluster
//	scan   one page of a cluster's repo/ objects: each repo of the hold's network, or each at format 2 for the
//	       turn-on, gets its run, and the next page its own scan
//	repo   one repo's pass on its cluster: HoldEndPass or TurnOnPass
//
// Every run is once-keyed by what it covers, so a start asked twice, or a scan rerun after a crash, queues each repo's
// pass once while it is pending. A pass that cannot finish (ErrSweepRetry, a store that did not answer) returns its
// error and reruns on server/task's backoff, and a rerun deletes nothing twice: what an earlier run deleted is absent,
// and every DELETE names the LastModified its HEAD read. A hold that still covers the repo, or another hold, keeps what
// it keeps, since each DELETE rereads hold/.
//
// What queues a start is not yet settled (questions/evsb-m3-02-sweep-pass-triggers.md): a hold ends in api's
// AbuseHoldPass (ABUSE-M5-14), and the purge turns on by an operator's act. Until one does, nothing queues a start, and
// what a hold or observe mode kept stays, alarming nowhere: content is kept, never lost.
//
// Safe for concurrent use.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The registered job, which taskworker binds.
const EvsSweepTaskName = "evs.sweep"

// The passes, as the args name them.
const (
	evsSweepKindHoldEnd = "hold_end"
	evsSweepKindTurnOn  = "turn_on"
)

// The runs, as the args name them.
const (
	evsSweepRunStart = "start"
	evsSweepRunScan  = "scan"
	evsSweepRunRepo  = "repo"
)

// Args that name no run of evs.sweep.
var ErrEvsSweepArgs = errors.New("evs.sweep args invalid")

// One run of evs.sweep, as its args carry it: ids and times only (host_tasks.go).
type evsSweepArgs struct {
	run  string
	kind string
	// scan and repo: the metadata cluster
	clusterId string
	// hold_end: the hold's network
	networkId sidecar.Id
	// start of a repo-scoped hold: its repos; repo: the one repo
	repoIds []sidecar.Id
	// hold_end: the hold's placement and end, in ms
	placeMs int64
	endMs   int64
	// scan: the last repo/ key a page ended at
	startAfter string
}

// The args' bytes: the run's fields one a line, absent ones empty.
func (self *evsSweepArgs) encode() []byte {
	networkText := ""
	if self.networkId != (sidecar.Id{}) {
		networkText = sidecar.EvsKeyId(self.networkId)
	}
	repoTexts := []string{}
	for _, repoId := range self.repoIds {
		repoTexts = append(repoTexts, sidecar.EvsKeyId(repoId))
	}
	return []byte(strings.Join([]string{
		self.run, self.kind, self.clusterId, networkText, strings.Join(repoTexts, ","),
		strconv.FormatInt(self.placeMs, 10), strconv.FormatInt(self.endMs, 10), self.startAfter,
	}, "\n"))
}

// The args parsed and held to their run's shape.
func parseEvsSweepArgs(args []byte) (*evsSweepArgs, error) {
	fields := strings.Split(string(args), "\n")
	if len(fields) != 8 {
		return nil, fmt.Errorf("%w: %d fields", ErrEvsSweepArgs, len(fields))
	}
	parsed := &evsSweepArgs{run: fields[0], kind: fields[1], clusterId: fields[2], startAfter: fields[7]}
	if parsed.kind != evsSweepKindHoldEnd && parsed.kind != evsSweepKindTurnOn {
		return nil, fmt.Errorf("%w: a pass %q", ErrEvsSweepArgs, parsed.kind)
	}
	if fields[3] != "" {
		networkId, err := parseEvsHexId(fields[3])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsSweepArgs, err)
		}
		parsed.networkId = networkId
	}
	if fields[4] != "" {
		for _, repoText := range strings.Split(fields[4], ",") {
			repoId, err := parseEvsHexId(repoText)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrEvsSweepArgs, err)
			}
			parsed.repoIds = append(parsed.repoIds, repoId)
		}
	}
	var err error
	if parsed.placeMs, err = strconv.ParseInt(fields[5], 10, 64); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsSweepArgs, err)
	}
	if parsed.endMs, err = strconv.ParseInt(fields[6], 10, 64); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsSweepArgs, err)
	}
	holdEnd := parsed.kind == evsSweepKindHoldEnd
	switch parsed.run {
	case evsSweepRunStart:
		if holdEnd && (parsed.networkId == (sidecar.Id{}) || parsed.endMs <= parsed.placeMs) {
			return nil, fmt.Errorf("%w: a hold's end with no network or no window", ErrEvsSweepArgs)
		}
		if !holdEnd && (parsed.networkId != (sidecar.Id{}) || len(parsed.repoIds) != 0) {
			return nil, fmt.Errorf("%w: a turn-on with a scope", ErrEvsSweepArgs)
		}
	case evsSweepRunScan:
		if parsed.clusterId == "" || (holdEnd && parsed.networkId == (sidecar.Id{})) {
			return nil, fmt.Errorf("%w: a scan with no cluster or no network", ErrEvsSweepArgs)
		}
	case evsSweepRunRepo:
		if parsed.clusterId == "" || len(parsed.repoIds) != 1 {
			return nil, fmt.Errorf("%w: a repo's pass with no cluster or not one repo", ErrEvsSweepArgs)
		}
	default:
		return nil, fmt.Errorf("%w: a run %q", ErrEvsSweepArgs, parsed.run)
	}
	return parsed, nil
}

// The request for args' run, once-keyed by what it covers.
func (self *evsSweepArgs) request() *sidecar.TaskRequest {
	window := fmt.Sprintf("%d.%d", self.placeMs, self.endMs)
	key := EvsSweepTaskName + "." + self.run + "." + self.kind
	switch self.run {
	case evsSweepRunStart:
		if self.networkId != (sidecar.Id{}) {
			key += "." + sidecar.EvsKeyId(self.networkId)
		}
		key += "." + window
		for _, repoId := range self.repoIds {
			key += "." + sidecar.EvsKeyId(repoId)
		}
	case evsSweepRunScan:
		// the cursor in the key, so each page is a request of its own
		key += "." + self.clusterId + "." + window + "." + strings.TrimPrefix(self.startAfter, repoKeyPrefix)
		if self.networkId != (sidecar.Id{}) {
			key += "." + sidecar.EvsKeyId(self.networkId)
		}
	case evsSweepRunRepo:
		key += "." + self.clusterId + "." + sidecar.EvsKeyId(self.repoIds[0]) + "." + window
	}
	return &sidecar.TaskRequest{Name: EvsSweepTaskName, OnceKey: key, Args: self.encode()}
}

// The start of a hold's end pass (§11.13's sweep row), for the caller that ends the hold: the repos its scope lists,
// or every repo of its network, reread from 26 h before its placement to its end, deleting what it kept.
func EvsSweepHoldEndTaskRequest(record *sidecar.HoldRecord, endTime time.Time) (*sidecar.TaskRequest, error) {
	if record == nil || record.NetworkId == (sidecar.Id{}) || !record.PlaceTime.Before(endTime) {
		return nil, fmt.Errorf("%w: a hold with no network, or ending before its placement", ErrEvsSweepArgs)
	}
	args := &evsSweepArgs{
		run: evsSweepRunStart, kind: evsSweepKindHoldEnd, networkId: record.NetworkId,
		repoIds: slices.Clone(record.Scope.RepoIds), placeMs: record.PlaceTime.UnixMilli(), endMs: endTime.UnixMilli(),
	}
	request := args.request()
	// never before the end: a pass that ran while the hold still stood would keep everything and be done
	request.RunAt = endTime
	return request, nil
}

// The start of the turn-on pass (§11.13's sweep row), for whatever turns §19.11's purge on from observe: every repo at
// format 2 on every metadata cluster, reread whole, deleting what observe mode kept.
func EvsSweepTurnOnTaskRequest() *sidecar.TaskRequest {
	return (&evsSweepArgs{run: evsSweepRunStart, kind: evsSweepKindTurnOn}).request()
}

// What one run of evs.sweep did: the runs it queued, and for a repo's pass what the pass did.
type EvsSweepRunResult struct {
	QueuedCount int
	Swept       *SweepResult
}

// One run of evs.sweep on host, its sweep built from deps: see the file header.
func RunSweepTask(ctx context.Context, host *sidecar.ServiceHost, deps *SweepDeps, args []byte) (*EvsSweepRunResult, error) {
	parsed, err := parseEvsSweepArgs(args)
	if err != nil {
		return nil, err
	}
	if host == nil || host.Tasks == nil || host.Blobs == nil {
		return nil, errors.New("evs.sweep needs a host with Blobs and a task queue")
	}
	sweep, err := NewSweep(host, deps)
	if err != nil {
		return nil, err
	}
	result := &EvsSweepRunResult{}
	queue := func(run *evsSweepArgs) error {
		if err := host.Tasks.Schedule(ctx, run.request()); err != nil {
			return err
		}
		result.QueuedCount += 1
		return nil
	}
	switch parsed.run {
	case evsSweepRunStart:
		if parsed.kind == evsSweepKindHoldEnd && 0 < len(parsed.repoIds) {
			places := sidecar.NewEvsRepoPlaceResolver(host.Blobs, sweep.clock, nil)
			for _, repoId := range parsed.repoIds {
				place, err := places.Resolve(ctx, repoId)
				if errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
					// never placed: nothing of it to reread
					continue
				}
				if err != nil {
					return result, err
				}
				if err := queue(&evsSweepArgs{run: evsSweepRunRepo, kind: parsed.kind, clusterId: place.ClusterId, repoIds: []sidecar.Id{repoId},
					placeMs: parsed.placeMs, endMs: parsed.endMs}); err != nil {
					return result, err
				}
			}
			return result, nil
		}
		for _, clusterId := range host.Blobs.MetadataClusterIds() {
			if err := queue(&evsSweepArgs{run: evsSweepRunScan, kind: parsed.kind, clusterId: clusterId, networkId: parsed.networkId,
				placeMs: parsed.placeMs, endMs: parsed.endMs}); err != nil {
				return result, err
			}
		}
		return result, nil
	case evsSweepRunScan:
		return result, sweep.scan(ctx, parsed, queue)
	}
	repoId := parsed.repoIds[0]
	if !slices.Contains(host.Blobs.MetadataClusterIds(), parsed.clusterId) {
		return result, fmt.Errorf("%w: evs.sweep for a cluster this process does not hold", sidecar.ErrBlobClusterUnknown)
	}
	if parsed.kind == evsSweepKindHoldEnd {
		endTime := time.UnixMilli(parsed.endMs)
		if sweep.clock.Now().Before(endTime) {
			return result, fmt.Errorf("%w: the hold has not ended", ErrSweepRetry)
		}
		result.Swept, err = sweep.HoldEndPass(ctx, parsed.clusterId, repoId, time.UnixMilli(parsed.placeMs), endTime)
	} else {
		result.Swept, err = sweep.TurnOnPass(ctx, parsed.clusterId, repoId, time.Time{})
	}
	return result, err
}

// One page of the cluster's repo/ objects: each repo the pass covers gets its run, and a next page its scan.
func (self *Sweep) scan(ctx context.Context, parsed *evsSweepArgs, queue func(run *evsSweepArgs) error) error {
	cluster, err := self.blobs.Cluster(parsed.clusterId)
	if err != nil {
		return err
	}
	objects, more, err := cluster.List(ctx, repoKeyPrefix, parsed.startAfter, self.settings.ListLimit)
	if err != nil {
		return err
	}
	for _, object := range objects {
		repoId, err := parseEvsHexId(strings.TrimPrefix(object.Key, repoKeyPrefix))
		if err != nil {
			continue
		}
		read, err := self.repos.Read(ctx, cluster, repoId)
		if errors.Is(err, sidecar.ErrEvsRepoNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if parsed.kind == evsSweepKindHoldEnd {
			networkId, err := sidecar.IdFromBytes(read.Object.GetNetworkId())
			if err != nil || networkId != parsed.networkId {
				// a repo/ naming no network is kept by every reader (plan-EVSB-repo-network): nothing to reread
				continue
			}
		} else if read.Object.GetFormat() < sidecar.EvsRepoFormat2 {
			continue
		}
		if read.Object.GetState() == protocol.EvsRepoState_EVS_REPO_SHREDDED {
			continue
		}
		if err := queue(&evsSweepArgs{run: evsSweepRunRepo, kind: parsed.kind, clusterId: parsed.clusterId, repoIds: []sidecar.Id{repoId},
			placeMs: parsed.placeMs, endMs: parsed.endMs}); err != nil {
			return err
		}
	}
	if more && 0 < len(objects) {
		next := *parsed
		next.startAfter = objects[len(objects)-1].Key
		return queue(&next)
	}
	return nil
}
