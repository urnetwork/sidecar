//go:build !ios_extension

// The drop's dry run and listing (§11.7's cli row, §11.13's preview row, §11.20's drop routes; D-MCP-32, FS-93;
// DESIGN-DETAILS 10.2.4's dry run row; EVS2-M10-20): what `ur history drop` shows before it signs, what MCP's
// evs_drop_preview and §18.5's SidecarEvs call, and `ur history drops`.
//
//	paths      each named path a lineage (evs_drop_lineage.go); --recursive adds every file below a directory, each a
//	           lineage, from verified listings; --follow, rename ancestors through file_id, is not built and is
//	           refused, failing closed; one command's lineages ride one DROP while they fit its bounds, and past them
//	           the command cuts them into several pushes at lineage boundaries, each previewed (EVS2-M10-21's)
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
//	           record; a drop whose body this device cannot read is listed with no names
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

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
}

// A dry run's lineages and evs's figures.
type EvsDropPreview struct {
	PreviewId []byte
	Lineages  []*EvsDropLineage
	// versions listed in all, and the bytes evs's resolve reported
	VersionCount uint64
	FreedBytes   uint64
	SharedBytes  uint64
	InlineBytes  uint64
	PackedBytes  uint64
	YoungBytes   uint64
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
	preview := &EvsDropPreview{}
	request := &protocol.EvsDropPreviewRequest{RefId: refId.Bytes()}
	for _, path := range paths {
		lineage, err := self.DropLineage(ctx, refName, path)
		if err != nil {
			return nil, err
		}
		preview.Lineages = append(preview.Lineages, lineage)
		request.Paths = append(request.Paths, lineage.DropPath)
		preview.VersionCount += uint64(lineage.DropPath.GetCount())
	}
	// the lineages sorted as a DROP's body holds them: by their newest token path's bytes
	slices.SortStableFunc(preview.Lineages, func(a *EvsDropLineage, b *EvsDropLineage) int {
		return evsDropNewestTokenPathCompare(a.DropPath, b.DropPath)
	})
	request.Paths = request.Paths[:0]
	for _, lineage := range preview.Lineages {
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
		return nil, err
	}
	if len(started.GetPreviewId()) != 16 {
		return nil, fmt.Errorf("%w: a dry run with no preview id", ErrEvsReplyInvalid)
	}
	preview.PreviewId = started.GetPreviewId()
	reply, err := self.waitDropPreview(ctx, preview.PreviewId)
	if err != nil {
		return nil, err
	}
	if len(reply.GetPaths()) != len(preview.Lineages) {
		return nil, fmt.Errorf("%w: a dry run answering %d of %d paths", ErrEvsReplyInvalid, len(reply.GetPaths()), len(preview.Lineages))
	}
	for i, result := range reply.GetPaths() {
		lineage := preview.Lineages[i]
		switch {
		case !result.GetListMatch():
			return nil, fmt.Errorf("%w: lineage %d lists %d versions where evs resolved %d", ErrEvsDropListMismatch, i, lineage.DropPath.GetCount(), result.GetCount())
		case !result.GetLinked():
			return nil, fmt.Errorf("%w: lineage %d", ErrEvsDropUnlinked, i)
		case len(result.GetMapParts()) != len(lineage.DropPath.GetMapParts()):
			return nil, fmt.Errorf("%w: a dry run's map parts for %d of %d older entries", ErrEvsReplyInvalid, len(result.GetMapParts()), len(lineage.DropPath.GetMapParts()))
		}
		lineage.DropPath.MapParts = slices.Clone(result.GetMapParts())
	}
	preview.FreedBytes, preview.SharedBytes, preview.InlineBytes = reply.GetFreedBytes(), reply.GetSharedBytes(), reply.GetInlineBytes()
	preview.PackedBytes, preview.YoungBytes = reply.GetPackedBytes(), reply.GetYoungBytes()
	return preview, nil
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
		if !bytes.Equal(status.GetRefId(), refId.Bytes()) || len(args.KnownPaths) == 0 {
			continue
		}
		body, err := self.dropBody(ctx, refId, status)
		if err != nil {
			// a drop this device cannot read the body of is listed with no names
			continue
		}
		if drop.Paths, err = self.dropNames(ctx, body, args.KnownPaths); err != nil {
			return nil, err
		}
	}
	return drops, nil
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
