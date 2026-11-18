//go:build !ios_extension

// The drop's dry run and listing (§11.7's cli row, §11.13's preview row, §11.20's drop routes; D-MCP-32, FS-93;
// DESIGN-DETAILS 10.2.4's dry run row; EVS2-M10-20): what `ur history drop` shows before it signs, what MCP's
// evs_drop_preview and §18.5's SidecarEvs call, and `ur history drops`.
//
//	paths      each named path a lineage (evs_drop_lineage.go); --recursive adds every file below a directory, each a
//	           lineage, from verified listings; --follow, rename ancestors through file_id, is not built and is
//	           refused, failing closed; one command's lineages ride one DROP while they fit its bounds, and past them
//	           the command cuts them into batches at lineage boundaries, each its own dry run and DROP push
//	           (evsDropBatches; EVS2-M10-21), confirmed once as one command
//	keep       a completed dry run is kept on the client for DropHistory to name by its first batch's preview id
//	           (evs_drop_push.go); --resume reads evs's results for dry runs it filed before, walking the lineages
//	           again and filing nothing
//	dry run    POST .../drops/preview {ref_id, paths} with each lineage, through_version, count and listed_sha256, its
//	           map_parts left empty; then GET .../drops/preview/<preview_id> every DropPreviewPollInterval, at most
//	           DropPreviewPollCount times, until done. A path whose list_match is false stops the command with
//	           ErrEvsDropListMismatch and the resolved count; one whose linked is false with ErrEvsDropUnlinked. Its
//	           map_parts are copied into the lineage, the one field taken from evs, on which only the job's own read
//	           cost rests. It reports versions, freed, shared, inline, packed and young bytes
//	quota      a preview is an admin's act but no drop, so MCP may call it (D-MCP-32), within the network's
//	           evs_drop_previews_per_day, which evs counts
//	Drops      GET .../drops: each drop's status, with the names of the paths this device knows that its lineages
//	           cover, at most DropNamesCount (I-13: names stay on the device). A DROP's body is read from its push's
//	           record, else from the bodies this device checked and keeps (evs_drop_state.go); a drop whose body this
//	           device cannot read is listed with no names. Each state evs reports raises history_drop once
//	           (EVS2-M10-22): pending, cancelled, executing, done (a held or observed drop reads done) and refused
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// What a dry run is asked.
type EvsDropPreviewArgs struct {
	// The ref's name bytes: nil is main.
	RefName []byte
	// Raw names joined by /.
	Paths []string
	// Every file below each directory named, each a lineage.
	Recursive bool
	// Rename ancestors through file_id: not built, refused.
	Follow bool
	// Dry runs evs already holds, each batch's preview id in order: the lineages are walked again and evs read for
	// the results, nothing filed (`ur history drop --resume`). Their count must be the batches' the walk makes.
	ResumePreviewIds [][]byte
}

// One DROP push's worth of a dry run: lineages within one DROP's bounds, cut at lineage boundaries in body order, and
// evs's dry run of them (EVS2-M10-21).
type EvsDropPreviewBatch struct {
	PreviewId []byte
	Lineages  []*EvsDropLineage
	// versions listed, and the bytes evs's resolve reported
	VersionCount uint64
	FreedBytes   uint64
	SharedBytes  uint64
	InlineBytes  uint64
	PackedBytes  uint64
	YoungBytes   uint64
	// the push that dropped it, once one committed (evs_drop_push.go)
	committed *EvsDropPushResult
}

// A dry run's lineages and evs's figures.
type EvsDropPreview struct {
	// The first batch's preview id: what DropHistory names.
	PreviewId []byte
	// The ref, and the paths the dry run was asked for as the person named them (EvsDropConfirmText).
	RefName    []byte
	NamedPaths []string
	// Every batch's lineages in order, and the batches, one DROP push each.
	Lineages []*EvsDropLineage
	Batches  []*EvsDropPreviewBatch
	// versions listed in all, and the bytes evs's resolve reported, summed over the batches
	VersionCount uint64
	FreedBytes   uint64
	SharedBytes  uint64
	InlineBytes  uint64
	PackedBytes  uint64
	YoungBytes   uint64
	repoId       Id
}

// lineages, in body order, cut into DROP pushes at lineage boundaries, each within one DROP's bounds: at most
// DropMaxPathCount lineages, lists of at most DropMaxListedCount values, and a body within DropMaxBodyByteCount once
// the dry run's map_parts are in it, which is reckoned at their largest (§11.7's action row; DESIGN-DETAILS 10.2.4's
// bounds row). A lineage alone past a bound was refused when it was walked (ErrEvsDropTooLarge).
func evsDropBatches(format *EvsFormatSettings, lineages []*EvsDropLineage) [][]*EvsDropLineage {
	fixed := proto.Size(&protocol.EvsDropHistory{
		DropId: make([]byte, 16), Action: evsDropActionDrop, NotBeforeMs: math.MaxInt64, PreviewId: make([]byte, 16),
	})
	pathSize := func(lineage *EvsDropLineage) int {
		largest := proto.Clone(lineage.DropPath).(*protocol.EvsDropPath)
		for i := range largest.MapParts {
			largest.MapParts[i] = uint32(format.PathMapMaxPartCount)
		}
		return protowire.SizeTag(6) + protowire.SizeBytes(proto.Size(largest))
	}
	batches := [][]*EvsDropLineage{}
	batch := []*EvsDropLineage{}
	bodySize, listedCount := fixed, 0
	for _, lineage := range lineages {
		size, count := pathSize(lineage), int(lineage.DropPath.GetCount())
		if 0 < len(batch) && (format.DropMaxPathCount <= len(batch) || format.DropMaxBodyByteCount < bodySize+size ||
			format.DropMaxListedCount < listedCount+count) {
			batches = append(batches, batch)
			batch, bodySize, listedCount = []*EvsDropLineage{}, fixed, 0
		}
		batch = append(batch, lineage)
		bodySize += size
		listedCount += count
	}
	if 0 < len(batch) {
		batches = append(batches, batch)
	}
	return batches
}

// The dry run of a drop of args' paths: see the file header.
func (self *EvsRepo) DropHistoryPreview(ctx context.Context, args *EvsDropPreviewArgs) (*EvsDropPreview, error) {
	if args.Follow {
		return nil, fmt.Errorf("%w: --follow is not built", ErrEvsDropPath)
	}
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	paths, err := self.dropPaths(ctx, refName, args.Paths, args.Recursive)
	if err != nil {
		return nil, err
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	preview := &EvsDropPreview{RefName: refName, NamedPaths: slices.Clone(args.Paths), repoId: self.repoId}
	for _, path := range paths {
		lineage, err := self.DropLineage(ctx, refName, path)
		if err != nil {
			return nil, err
		}
		preview.Lineages = append(preview.Lineages, lineage)
		preview.VersionCount += uint64(lineage.DropPath.GetCount())
	}
	// the lineages sorted as a DROP's body holds them: by their newest token path's bytes
	slices.SortStableFunc(preview.Lineages, func(a *EvsDropLineage, b *EvsDropLineage) int {
		return evsDropNewestTokenPathCompare(a.DropPath, b.DropPath)
	})
	cut := evsDropBatches(DefaultEvsFormatSettings(), preview.Lineages)
	if 0 < len(args.ResumePreviewIds) && len(args.ResumePreviewIds) != len(cut) {
		return nil, fmt.Errorf("%w: %d dry runs to resume for %d batches", ErrEvsDropListMismatch, len(args.ResumePreviewIds), len(cut))
	}
	for i, lineages := range cut {
		batch := &EvsDropPreviewBatch{Lineages: lineages}
		var resume []byte
		if 0 < len(args.ResumePreviewIds) {
			resume = args.ResumePreviewIds[i]
		}
		if err := self.previewBatch(ctx, refId, batch, resume); err != nil {
			return nil, err
		}
		preview.Batches = append(preview.Batches, batch)
		preview.FreedBytes += batch.FreedBytes
		preview.SharedBytes += batch.SharedBytes
		preview.InlineBytes += batch.InlineBytes
		preview.PackedBytes += batch.PackedBytes
		preview.YoungBytes += batch.YoungBytes
	}
	preview.PreviewId = preview.Batches[0].PreviewId
	self.client.keepDropPreview(preview)
	return preview, nil
}

// One batch's dry run: filed, or resumed by its preview id, then read until done, every path's list matching and
// linked, and its map_parts copied into the lineages.
func (self *EvsRepo) previewBatch(ctx context.Context, refId Id, batch *EvsDropPreviewBatch, resume []byte) error {
	previewId := resume
	if previewId == nil {
		request := &protocol.EvsDropPreviewRequest{RefId: refId.Bytes()}
		for _, lineage := range batch.Lineages {
			request.Paths = append(request.Paths, lineage.DropPath)
		}
		started := &protocol.EvsDropPreviewReply{}
		call := &evsCall{
			route:  "POST /evs/v1/repos/{repo_id}/drops/preview",
			method: http.MethodPost,
			path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/drops/preview",
			repoId: self.repoId,
			role:   evsScopeAdmin,
			body:   request,
			// the dry run's queuing answers 202 {preview_id}
			accepted: true,
		}
		if err := self.client.http.callMessage(ctx, call, started); err != nil {
			return err
		}
		previewId = started.GetPreviewId()
	}
	if len(previewId) != 16 {
		return fmt.Errorf("%w: a dry run with no preview id", ErrEvsReplyInvalid)
	}
	batch.PreviewId = bytes.Clone(previewId)
	reply, err := self.waitDropPreview(ctx, batch.PreviewId)
	if err != nil {
		return err
	}
	if len(reply.GetPaths()) != len(batch.Lineages) {
		return fmt.Errorf("%w: a dry run answering %d of %d paths", ErrEvsReplyInvalid, len(reply.GetPaths()), len(batch.Lineages))
	}
	for i, result := range reply.GetPaths() {
		lineage := batch.Lineages[i]
		switch {
		case !result.GetListMatch():
			return fmt.Errorf("%w: lineage %d lists %d versions where evs resolved %d", ErrEvsDropListMismatch, i, lineage.DropPath.GetCount(), result.GetCount())
		case !result.GetLinked():
			return fmt.Errorf("%w: lineage %d", ErrEvsDropUnlinked, i)
		case len(result.GetMapParts()) != len(lineage.DropPath.GetMapParts()):
			return fmt.Errorf("%w: a dry run's map parts for %d of %d older entries", ErrEvsReplyInvalid, len(result.GetMapParts()), len(lineage.DropPath.GetMapParts()))
		}
		lineage.DropPath.MapParts = slices.Clone(result.GetMapParts())
		batch.VersionCount += uint64(lineage.DropPath.GetCount())
	}
	batch.FreedBytes, batch.SharedBytes, batch.InlineBytes = reply.GetFreedBytes(), reply.GetSharedBytes(), reply.GetInlineBytes()
	batch.PackedBytes, batch.YoungBytes = reply.GetPackedBytes(), reply.GetYoungBytes()
	return nil
}

// Orders two lineages by their newest token path's bytes, then their newest epoch.
func evsDropNewestTokenPathCompare(a *protocol.EvsDropPath, b *protocol.EvsDropPath) int {
	newestOf := func(path *protocol.EvsDropPath) ([]byte, uint64) {
		if len(path.GetLineage()) == 0 {
			return nil, 0
		}
		return bytes.Join(path.GetLineage()[0].GetTokenPath(), nil), path.GetLineage()[0].GetEpoch()
	}
	aPath, aEpoch := newestOf(a)
	bPath, bEpoch := newestOf(b)
	if order := bytes.Compare(aPath, bPath); order != 0 {
		return order
	}
	switch {
	case aEpoch < bEpoch:
		return -1
	case bEpoch < aEpoch:
		return 1
	}
	return 0
}

// GET .../drops/preview/<preview_id> until done, every DropPreviewPollInterval, at most DropPreviewPollCount times.
func (self *EvsRepo) waitDropPreview(ctx context.Context, previewId []byte) (*protocol.EvsDropPreviewReply, error) {
	call := &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/drops/preview/{preview_id}",
		method: http.MethodGet,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/drops/preview/" + evsUrlId(Id(previewId)),
		repoId: self.repoId,
		role:   evsScopeAdmin,
		retry:  true,
	}
	for poll := 0; poll < max(1, self.client.settings.DropPreviewPollCount); poll += 1 {
		reply := &protocol.EvsDropPreviewReply{}
		if err := self.client.http.callMessage(ctx, call, reply); err != nil {
			return nil, err
		}
		switch reply.GetState() {
		case protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE:
			return reply, nil
		case protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED:
			return nil, fmt.Errorf("%w: the dry run stopped short; file another", ErrEvsDropListMismatch)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.client.clock.After(self.client.settings.DropPreviewPollInterval):
		}
	}
	return nil, fmt.Errorf("%w: the dry run did not finish in %d reads", ErrEvsReplyInvalid, self.client.settings.DropPreviewPollCount)
}

// The paths a drop of named paths covers: each one, and with recursive every file below a directory, from verified
// listings, at most the most lineages a DROP takes.
func (self *EvsRepo) dropPaths(ctx context.Context, refName []byte, named []string, recursive bool) ([]string, error) {
	paths := []string{}
	seen := map[string]bool{}
	add := func(path string) error {
		if seen[path] {
			return nil
		}
		if DefaultEvsFormatSettings().DropMaxPathCount <= len(paths) {
			return fmt.Errorf("%w: more than %d paths", ErrEvsDropTooLarge, DefaultEvsFormatSettings().DropMaxPathCount)
		}
		seen[path] = true
		paths = append(paths, path)
		return nil
	}
	for _, path := range named {
		if !recursive {
			if err := add(path); err != nil {
				return nil, err
			}
			continue
		}
		listing, err := self.List(ctx, &EvsReadArgs{RefName: refName, Path: path, Fresh: true})
		if err != nil && !errors.Is(err, ErrEvsPathKind) {
			return nil, err
		}
		if err != nil {
			// a file, not a directory
			if err := add(path); err != nil {
				return nil, err
			}
			continue
		}
		level := []*EvsListing{listing}
		for depth := 0; 0 < len(level); depth += 1 {
			if EvsTokenPathMaxLength < depth {
				return nil, fmt.Errorf("%w: %d levels", ErrEvsPlanRemoveDepth, depth)
			}
			next := []*EvsListing{}
			for _, directory := range level {
				for _, entry := range directory.Entries {
					child := string(entry.Name)
					if directory.Path != "" {
						child = directory.Path + "/" + child
					}
					if entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
						below, err := self.List(ctx, &EvsReadArgs{RefName: refName, Path: child})
						if err != nil {
							return nil, err
						}
						next = append(next, below)
						continue
					}
					if err := add(child); err != nil {
						return nil, err
					}
				}
			}
			level = next
		}
	}
	return paths, nil
}

// One drop as `ur history drops` lists it: its status, and the paths this device knows that its lineages cover.
type EvsDrop struct {
	Status *protocol.EvsDropStatus
	Paths  []string
}

// What Drops is asked.
type EvsDropsArgs struct {
	// The ref whose drops are named; nil is main.
	RefName []byte
	// The paths this device knows on the ref, which a drop's lineages are matched against.
	KnownPaths []string
}

// The repo's drops: see the file header.
func (self *EvsRepo) Drops(ctx context.Context, args *EvsDropsArgs) ([]*EvsDrop, error) {
	call := &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/drops",
		method: http.MethodGet,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/drops",
		repoId: self.repoId,
		role:   evsScopeRead,
		retry:  true,
	}
	reply := &protocol.EvsDropsReply{}
	if err := self.client.http.callMessage(ctx, call, reply); err != nil {
		return nil, err
	}
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	drops := []*EvsDrop{}
	for _, status := range reply.GetDrops() {
		drop := &EvsDrop{Status: status}
		drops = append(drops, drop)
		if bytes.Equal(status.GetRefId(), refId.Bytes()) && 0 < len(args.KnownPaths) {
			body, err := self.dropBody(ctx, refId, status)
			if err != nil {
				body = self.keptDropBody(refId, status)
			}
			if body != nil {
				if drop.Paths, err = self.dropNames(ctx, body, args.KnownPaths); err != nil {
					return nil, err
				}
			}
		}
		// history_drop at each state evs reports, once a state (EVS2-M10-22): a held drop reads done
		if state, ok := SidecarDropStateOf(status.GetState()); ok {
			dropId, dropErr := IdFromBytes(status.GetDropId())
			statusRefId, refErr := IdFromBytes(status.GetRefId())
			if dropErr == nil && refErr == nil {
				event := &SidecarHistoryDrop{RepoId: self.repoId, RefId: statusRefId, DropId: dropId, State: state, NotBefore: evsTime(status.GetNotBeforeMs())}
				if 0 < len(drop.Paths) {
					event.Path = drop.Paths[0]
				}
				self.client.raiseHistoryDropOnce(event)
			}
		}
	}
	return drops, nil
}

// A drop's body this device checked and keeps (evs_drop_state.go), nil for none: what names a drop whose push record
// this device does not read.
func (self *EvsRepo) keptDropBody(refId Id, status *protocol.EvsDropStatus) *protocol.EvsDropHistory {
	dropId, err := IdFromBytes(status.GetDropId())
	if err != nil {
		return nil
	}
	body, _, statementBytes, ok, err := self.client.dropBodies().get(self.repoId, refId, dropId)
	if err != nil || !ok {
		return nil
	}
	statement, err := ParseEvsStatementFormat2(statementBytes)
	if err != nil {
		return nil
	}
	lists, err := NewEvsDropLists(statement.Push, body)
	if err != nil {
		return nil
	}
	return lists.History()
}

// The DROP body a status names, read from its push's record through the ref's verified head.
func (self *EvsRepo) dropBody(ctx context.Context, refId Id, status *protocol.EvsDropStatus) (*protocol.EvsDropHistory, error) {
	head, err := self.pinnedHead(ctx, refId)
	if err != nil {
		return nil, err
	}
	statement, ok := head.StatementAt(status.GetVersion())
	if !ok || !bytes.Equal(statement.Statement.Push.GetPushId(), status.GetPushId()) {
		return nil, fmt.Errorf("%w: a drop's statement the head does not hold", ErrEvsObjectMissing)
	}
	payload, err := self.pushPayload(ctx, head, statement)
	if err != nil {
		return nil, err
	}
	if payload.Drop == nil || payload.Drop.History == nil {
		return nil, fmt.Errorf("%w: a drop's push with no body", ErrEvsReplyInvalid)
	}
	return payload.Drop.History, nil
}

// The known paths a DROP's lineages cover, at most DropNamesCount: a path whose token path in a lineage entry's epoch
// is that entry's.
func (self *EvsRepo) dropNames(ctx context.Context, body *protocol.EvsDropHistory, known []string) ([]string, error) {
	keys := newEvsReadKeys(self)
	covered := map[string]bool{}
	for _, path := range body.GetPaths() {
		for _, entry := range path.GetLineage() {
			covered[fmt.Sprint(entry.GetEpoch(), "/", string(bytes.Join(entry.GetTokenPath(), []byte{0})))] = true
		}
	}
	names := []string{}
	for _, path := range known {
		if self.client.settings.DropNamesCount <= len(names) {
			break
		}
		pathNames, err := evsPathNames(path)
		if err != nil {
			continue
		}
		for _, path2 := range body.GetPaths() {
			found := false
			for _, entry := range path2.GetLineage() {
				tokenPath, err := keys.tokenPathIn(ctx, pathNames, entry.GetEpoch())
				if err != nil {
					return nil, err
				}
				if covered[fmt.Sprint(entry.GetEpoch(), "/", string(bytes.Join(tokenPath.Components(), []byte{0})))] {
					found = true
					break
				}
			}
			if found {
				names = append(names, path)
				break
			}
		}
	}
	return names, nil
}
