// The drop routes (§11.20; §11.13's who and preview rows; DESIGN-DETAILS 10.2.4, 10.2.8; EVSB-M10-03) and the dry runs
// they queue:
//
//	GET  .../drops                   (r) the drop table as EvsDropsReply: each void record whose entry has left as its
//	                                 drop_id and state alone, then each entry oldest first; a held drop reads done with
//	                                 its held bytes counted as freed, so no field, value or count shows a hold (owner
//	                                 decision 184)
//	POST .../drops/preview           (admin) EvsDropPreviewRequest: its paths held to an EvsDropPath's shape, map_parts
//	                                 empty or one per older lineage entry, and the counts within 1,048,576 in all (409
//	                                 DROP_LIST); counted against evs_drop_previews_per_day (§20.4), 429 past it; the
//	                                 request written to dropscan/<repo>/<preview_id>/ask-0000000000, then the dry run
//	                                 queued in the table by If-Match, P1 for the token's network; 202 {preview_id}
//	GET  .../drops/preview/<id>      (admin) the dry run's state, and once done the results it stored, res-0000000000;
//	                                 404 NOT_FOUND for one the table holds no record of
//
// A dry run is P2 work, one at a time a repo, which taskworker's evs.drop runs (DropPreviews): resolve's link and set
// checks at a snapshot of the request ref (DropResolver.Preview, EVSB-M10-04's), which answer each path's list_match,
// resolved count, map_parts and linked, and write its candidates; mark at that snapshot (DropMarker); then the byte
// figures from one HEAD a candidate: shared for one a live version names, young for one whose LastModified +
// AdoptionBound the snapshot's horizon has not passed, freed for the rest, and packed for none, since spidx/ stays
// empty while segment packing is off. A dry run whose resolve or mark is not built, or that a deleted repo stops,
// ends failed: file another.
//
// Safe for concurrent use.

package evsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route templates.
const (
	evsDropsTemplate          = "GET /evs/v1/repos/{repo_id}/drops"
	evsDropPreviewTemplate    = "POST /evs/v1/repos/{repo_id}/drops/preview"
	evsDropPreviewGetTemplate = "GET /evs/v1/repos/{repo_id}/drops/preview/{preview_id}"
	// the path value a dry run's GET names it by
	evsDropPreviewIdPathValue = "preview_id"
)

// The drop routes.
func (self *EvsEngine) dropRoutes() []*EvsRoute {
	pattern := evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/drops"
	return []*EvsRoute{
		{Method: http.MethodGet, Pattern: pattern, Name: evsDropsTemplate, Rights: sidecar.AclEvsRead, Placed: true, RefuseDeleted: true, Serve: self.serveDrops},
		{Method: http.MethodPost, Pattern: pattern + "/preview", Name: evsDropPreviewTemplate, Rights: sidecar.AclEvsAdmin, Write: true, Placed: true, RefuseDeleted: true, Serve: self.serveDropPreviewRequest},
		{Method: http.MethodGet, Pattern: pattern + "/preview/{" + evsDropPreviewIdPathValue + "}", Name: evsDropPreviewGetTemplate, Rights: sidecar.AclEvsAdmin, Placed: true, RefuseDeleted: true, Serve: self.serveDropPreview},
	}
}

// The process's drop table, which the drop routes write.
func (self *EvsEngine) Drops() *DropTable {
	return self.drops
}

// GET .../drops: see the file header.
func (self *EvsEngine) serveDrops(request *EvsRequest) {
	read, err := self.drops.Read(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	request.Reply(DropStatuses(read.State))
}

// The listing of a table (§11.20's GET .../drops): void records whose entries have left, as their drop_id and state
// alone, then each entry oldest first, a held one as done with its held bytes counted as freed.
func DropStatuses(state *DropTableState) *protocol.EvsDropsReply {
	reply := &protocol.EvsDropsReply{}
	for _, void := range state.Voids {
		if state.Drop(void.DropId) != nil {
			continue
		}
		status, _ := void.State.Status()
		reply.Drops = append(reply.Drops, &protocol.EvsDropStatus{DropId: void.DropId.Bytes(), State: status})
	}
	for _, entry := range state.Drops {
		status, reason := entry.State.Status()
		dropStatus := &protocol.EvsDropStatus{
			DropId: entry.DropId.Bytes(), RefId: entry.RefId.Bytes(), PushId: entry.PushId.Bytes(), Version: entry.Version,
			NotBeforeMs: entry.NotBeforeMs, State: status, Reason: reason,
			FreedBytes: entry.FreedByteCount + entry.HeldByteCount,
		}
		if entry.State == DropStateExecuting {
			dropStatus.Phase = entry.Phase
		}
		if entry.PreviewId != (sidecar.Id{}) {
			dropStatus.PreviewId = entry.PreviewId.Bytes()
		}
		reply.Drops = append(reply.Drops, dropStatus)
	}
	return reply
}

// A dry run's request held to an EvsDropPath's shape (EVS-FORMAT.md's DROP chapter, map_parts empty or whole): 0, or
// the code it is refused with.
func checkDropPreviewRequest(previewRequest *protocol.EvsDropPreviewRequest, settings *DropSettings) protocol.EvsRefusalCode {
	invalid := protocol.EvsRefusalCode_EVS_REFUSAL_INVALID
	if _, err := sidecar.IdFromBytes(previewRequest.GetRefId()); err != nil {
		return invalid
	}
	paths := previewRequest.GetPaths()
	if len(paths) == 0 || settings.PreviewPathCount < len(paths) {
		return invalid
	}
	listedCount := uint64(0)
	for _, path := range paths {
		lineage := path.GetLineage()
		if len(lineage) == 0 || (len(path.GetMapParts()) != 0 && len(path.GetMapParts()) != len(lineage)-1) {
			return invalid
		}
		for i, entry := range lineage {
			if entry.GetEpoch() == 0 || (0 < i && lineage[i-1].GetEpoch() <= entry.GetEpoch()) {
				return invalid
			}
			tokens := entry.GetTokenPath()
			if len(tokens) == 0 || sidecar.EvsTokenPathMaxLength < len(tokens) {
				return invalid
			}
			for _, token := range tokens {
				if len(token) != sidecar.EvsTokenByteCount {
					return invalid
				}
			}
		}
		if path.GetThroughVersion() < 2 || (path.GetBoundary() != 1 && path.GetBoundary() != 2) || len(path.GetListedSha256()) != sha256.Size ||
			path.GetCount() == 0 || uint64(path.GetCount()) >= path.GetThroughVersion() {
			return invalid
		}
		listedCount += uint64(path.GetCount())
	}
	if settings.PreviewListedCount < listedCount {
		return protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST
	}
	return 0
}

// 202 with message's bytes: a dry run's queuing.
func (self *EvsRequest) replyAccepted(message proto.Message) {
	if self.answered {
		return
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		self.Unavailable(nil)
		return
	}
	self.write(http.StatusAccepted, body)
}

// POST .../drops/preview: see the file header.
func (self *EvsEngine) serveDropPreviewRequest(request *EvsRequest) {
	settings := self.settings.Drop
	previewRequest := &protocol.EvsDropPreviewRequest{}
	if !request.ReadMessage(previewRequest, settings.PreviewRequestByteCount) {
		return
	}
	if code := checkDropPreviewRequest(previewRequest, settings); code != 0 {
		request.RefuseCode(code)
		return
	}
	refId, _ := sidecar.IdFromBytes(previewRequest.GetRefId())
	previewId, err := newDropId()
	if err != nil {
		request.Unavailable(nil)
		return
	}
	networkId := networkIdOf(request.Principal)
	if self.host.Quota == nil {
		request.Unavailable(nil)
		return
	}
	refusal, err := self.host.Quota.CountRate(request.Ctx, connect.Id(networkId),
		map[string]int64{sidecar.QuotaRateKeyDropPreview(connect.Id(request.RepoId)): 1}, connect.Id(previewId))
	switch {
	case err != nil:
		request.Unavailable(nil)
		return
	case refusal != nil:
		request.Refuse(evsQuotaRefusalReply(refusal))
		return
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		request.Unavailable(nil)
		return
	}
	requestBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(previewRequest)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	ask, err := EncodeDropMessageFile(DropFileAsk, request.RepoId, previewId, requestBytes)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	if err := NewDropFiles(segmentCluster, request.RepoId, previewId, settings).Put(request.Ctx, DropFileAsk, 0, ask); err != nil {
		request.Unavailable(nil)
		return
	}
	cost, err := PricePush(self.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: WriteOperationOverwrite, ObjectByteCount: int64(settings.TableByteCount), Count: 1}},
	})
	if err != nil {
		request.Unavailable(nil)
		return
	}
	grant, err := self.budget.AdmitP1(request.Ctx, request.Cluster.ClusterId(), connect.Id(networkId), cost)
	var writeRefusal *sidecar.WriteRefusal
	switch {
	case errors.As(err, &writeRefusal):
		request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, RetryAfterMs: writeRefusal.RetryAfterMs()})
		return
	case err != nil:
		request.Unavailable(nil)
		return
	}
	defer grant.Close()
	_, err = self.drops.Update(grant.Context(), request.Cluster, request.RepoId, func(state *DropTableState, now time.Time) (bool, error) {
		if state.Preview(previewId) != nil {
			return false, nil
		}
		state.Previews = append(state.Previews, &DropPreviewRecord{
			PreviewId: previewId, RefId: refId, State: protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED, CreatedMs: now.UnixMilli(),
		})
		return true, nil
	})
	switch {
	case errors.Is(err, ErrDropTableFull):
		request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, RetryAfterMs: uint32(settings.HorizonRetryInterval.Milliseconds())})
		return
	case err != nil:
		request.Unavailable(nil)
		return
	}
	self.drops.Hint(request.Ctx, request.RepoId, request.Cluster.ClusterId())
	request.Note("preview " + sidecar.EvsKeyId(previewId))
	request.replyAccepted(&protocol.EvsDropPreviewReply{PreviewId: previewId.Bytes()})
}

// GET .../drops/preview/<preview_id>: see the file header.
func (self *EvsEngine) serveDropPreview(request *EvsRequest) {
	previewId, err := parseEvsHexId(request.Http.PathValue(evsDropPreviewIdPathValue))
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	read, err := self.drops.Read(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	preview := read.State.Preview(previewId)
	if preview == nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		return
	}
	if preview.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE {
		request.Reply(&protocol.EvsDropPreviewReply{PreviewId: previewId.Bytes(), State: preview.State})
		return
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		request.Unavailable(nil)
		return
	}
	file, err := NewDropFiles(segmentCluster, request.RepoId, previewId, self.settings.Drop).Read(request.Ctx, DropFileRes, 0)
	if err != nil || file == nil {
		request.Unavailable(nil)
		return
	}
	reply := &protocol.EvsDropPreviewReply{}
	if err := proto.Unmarshal(file.Message, reply); err != nil {
		request.Unavailable(nil)
		return
	}
	request.Reply(reply)
}

// What a repo's dry runs run on beyond their host.
type DropPreviewDeps struct {
	Resolver DropResolver
	Marker   DropMarker
	// The snapshot's horizon, for young bytes. nil reads it through a NightlyPass of its own.
	Horizon DropHorizonSource
	// nil: the defaults.
	Settings    *DropSettings
	EvsSettings *EvsSettings
	Log         sidecar.Logger
}

// What one run of a repo's dry runs did.
type DropPreviewResult struct {
	// The dry run it took, zero for none.
	PreviewId sidecar.Id
	State     protocol.EvsDropPreviewState
	// When the repo asks again: another dry run queued, or one running elsewhere whose lease may lapse.
	Next time.Time
}

// A repo's dry runs, one at a time. See the file header.
type DropPreviews struct {
	host     *sidecar.ServiceHost
	deps     *DropPreviewDeps
	settings *DropSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	blobs    sidecar.BlobStore
	table    *DropTable
	horizon  DropHorizonSource

	scanBytes sidecar.MetricsCounter
}

// Dry runs on host, which needs Blobs and a write budget.
func NewDropPreviews(host *sidecar.ServiceHost, deps *DropPreviewDeps) (*DropPreviews, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's dry runs need a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &DropPreviewDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultDropSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	blobs := NewBudgetedBlobs(host.Blobs)
	table, err := NewDropTable(host, blobs, settings, log)
	if err != nil {
		return nil, err
	}
	horizon := deps.Horizon
	if horizon == nil {
		pass, err := NewNightlyPass(host, &NightlyPassDeps{Log: log, EvsSettings: deps.EvsSettings})
		if err != nil {
			return nil, err
		}
		horizon = pass
	}
	self := &DropPreviews{host: host, deps: deps, settings: settings, clock: host.ClockOrReal(), log: log, blobs: blobs, table: table, horizon: horizon}
	if host.Metrics != nil {
		self.scanBytes = host.Metrics.Counter(dropScanBytesMetricName, "Bytes the drop jobs and dry runs read, by pass.", "pass")
	}
	return self, nil
}

// A table write of a dry run's state, unfunded P2 of rank drop: a dry run is P2 (§11.13's preview row).
func (self *DropPreviews) update(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, decide func(state *DropTableState, now time.Time) (bool, error)) (*DropTableRead, error) {
	priceTable, err := DefaultPriceTable(DefaultEvsSettings().PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	byteCount, err := priceTable.Price(WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(self.settings.TableByteCount), Count: 1})
	if err != nil {
		return nil, err
	}
	grant, err := self.host.Budget.AcquireP2(ctx, cluster.ClusterId(), &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankDrop, Due: self.clock.Now(), ByteCount: byteCount})
	if err != nil {
		return nil, err
	}
	defer grant.Close()
	return self.table.Update(grant.Context(), cluster, repoId, decide)
}

// One run: takes the repo's oldest queued dry run, unless one runs under a live lease, and runs it to done or failed.
func (self *DropPreviews) Run(ctx context.Context, clusterId string, repoId sidecar.Id) (*DropPreviewResult, error) {
	result := &DropPreviewResult{}
	cluster, err := self.blobs.Cluster(clusterId)
	if err != nil {
		return result, err
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		return result, err
	}
	var taken *DropPreviewRecord
	read, err := self.update(ctx, cluster, repoId, func(state *DropTableState, now time.Time) (bool, error) {
		taken = nil
		for _, preview := range state.Previews {
			if preview.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_RUNNING && now.Before(time.UnixMilli(preview.UntilMs).Add(self.settings.LeaseLapse)) {
				// one at a time a repo
				return false, nil
			}
		}
		for _, preview := range state.Previews {
			if preview.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED || preview.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_RUNNING {
				preview.State = protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_RUNNING
				preview.UntilMs = now.Add(self.settings.LeaseTime).UnixMilli()
				copied := *preview
				taken = &copied
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return result, err
	}
	if taken == nil {
		for _, preview := range read.State.Previews {
			if preview.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_RUNNING {
				result.Next = time.UnixMilli(preview.UntilMs).Add(self.settings.LeaseLapse)
			}
		}
		return result, nil
	}
	result.PreviewId = taken.PreviewId
	reply, err := self.preview(ctx, cluster, segmentCluster, repoId, taken)
	state := protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE
	if err != nil || reply == nil {
		if err != nil {
			self.log.Errorf("[evs] dry run %s of repo %s failed: %v", sidecar.EvsKeyId(taken.PreviewId), sidecar.EvsKeyId(repoId), err)
		}
		state = protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED
	} else {
		reply.PreviewId = taken.PreviewId.Bytes()
		reply.State = state
		replyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(reply)
		if err != nil {
			return result, err
		}
		res, err := EncodeDropMessageFile(DropFileRes, repoId, taken.PreviewId, replyBytes)
		if err != nil {
			return result, err
		}
		if err := NewDropFiles(segmentCluster, repoId, taken.PreviewId, self.settings).Put(ctx, DropFileRes, 0, res); err != nil {
			return result, err
		}
	}
	read, err = self.update(ctx, cluster, repoId, func(table *DropTableState, now time.Time) (bool, error) {
		preview := table.Preview(taken.PreviewId)
		if preview == nil || preview.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_RUNNING {
			return false, nil
		}
		preview.State = state
		preview.UntilMs = now.UnixMilli()
		if reply != nil {
			preview.SnapshotVersion = reply.GetSnapshotVersion()
		}
		return true, nil
	})
	if err != nil {
		return result, err
	}
	result.State = state
	for _, preview := range read.State.Previews {
		if preview.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED {
			result.Next = self.clock.Now()
		}
	}
	return result, nil
}

// One dry run's results, nil with no error for one that cannot run: its resolve or mark not built, a clock unsure
// for the horizon, or its repo not active.
func (self *DropPreviews) preview(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, repoId sidecar.Id, taken *DropPreviewRecord) (*protocol.EvsDropPreviewReply, error) {
	if self.deps.Resolver == nil || self.deps.Marker == nil {
		return nil, nil
	}
	files := NewDropFiles(segmentCluster, repoId, taken.PreviewId, self.settings)
	ask, err := files.Read(ctx, DropFileAsk, 0)
	if err != nil {
		return nil, err
	}
	if ask == nil {
		return nil, fmt.Errorf("%w: a dry run with no ask file", ErrDropJobState)
	}
	previewRequest := &protocol.EvsDropPreviewRequest{}
	if err := proto.Unmarshal(ask.Message, previewRequest); err != nil {
		return nil, err
	}
	horizon, err := self.horizon.OrphanHorizon(ctx, cluster)
	if err != nil {
		return nil, err
	}
	pace := func(ctx context.Context, byteCount int64) error {
		return dropPace(ctx, self.clock, self.settings, byteCount)
	}
	resolved, err := self.deps.Resolver.Preview(ctx, &DropPreviewResolveRequest{
		Cluster: cluster, SegmentCluster: segmentCluster, RepoId: repoId, PreviewId: taken.PreviewId, Request: previewRequest, Pace: pace,
	})
	if err != nil {
		return nil, err
	}
	read, err := self.table.Read(ctx, cluster, repoId)
	if err != nil {
		return nil, err
	}
	marked, err := self.deps.Marker.Mark(ctx, &DropMarkRequest{
		Cluster: cluster, SegmentCluster: segmentCluster, RepoId: repoId, JobId: taken.PreviewId, Round: 1, Horizon: horizon,
		Since: map[sidecar.Id]uint64{}, Liveness: dropLiveness(read.State, nil), Pace: pace,
		Renew: func(ctx context.Context) error { return nil },
	})
	if err != nil {
		return nil, err
	}
	if self.scanBytes != nil {
		self.scanBytes.Add(float64(resolved.ScanByteCount+marked.ScanByteCount), "preview")
	}
	candidates, err := files.Candidates(ctx)
	if err != nil {
		return nil, err
	}
	marks, _, _, err := files.Marks(ctx)
	if err != nil {
		return nil, err
	}
	reply := &protocol.EvsDropPreviewReply{
		Paths: resolved.Paths, InlineBytes: resolved.InlineByteCount, SnapshotVersion: resolved.SnapshotVersion,
		SnapshotMs: self.clock.Now().UnixMilli(), Progress: resolved.VersionCount, ProgressTotal: resolved.VersionCount,
	}
	for _, candidate := range candidates {
		var info *sidecar.BlobInfo
		if candidate.Kind == DropIdSlot {
			info, err = cluster.Head(ctx, SlotKey(repoId, candidate.SlotId()))
		} else {
			info, err = segmentCluster.Head(ctx, SegmentKey(repoId, candidate.Id))
		}
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			continue
		case err != nil:
			return nil, err
		}
		byteCount := uint64(max(0, info.ByteCount))
		switch {
		case marks[candidate.DropScanId]:
			reply.SharedBytes += byteCount
		case horizon.Before(info.LastModified.Add(self.settings.AdoptionBound)):
			reply.YoungBytes += byteCount
		default:
			reply.FreedBytes += byteCount
		}
	}
	return reply, nil
}
