// GET /evs/v1/repos/<id>/refs (§11.9; EVS1-M2-14): the repo's refs as their heads stand, with repo/'s format and the
// repo's push sequence. One LIST of head/<repo>/ pages the keys, each head read from the cluster together, at most
// EvsSettings.EntryReadConcurrency of them in flight (read_fanout.go), a placeholder head (version 0, no kind or
// mode) left out as absent, and each ref's push sequence from {evsh_}
// where it holds one. The ?moved_after= form reads and keeps only the refs past the value, or every ref with all set
// where the sequence cannot place it (refs_moved.go; EVS1-M6-01).

package evsservice

import (
	"context"
	"maps"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// See the file header.
func (self *EvsEngine) serveRefs(request *EvsRequest) {
	ctx := request.Ctx
	cluster := self.attemptCluster(request)
	repoId := request.RepoId
	query := request.Http.URL.Query()
	moved := query.Has(evsMovedAfterParameter)
	movedAfter := uint64(0)
	if moved {
		request.Note("moved_after")
		value, ok := parseMovedAfter(query.Get(evsMovedAfterParameter))
		if !ok {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
			return
		}
		movedAfter = value
	}
	repo, err := self.repos.Read(ctx, cluster, repoId)
	if !self.answerTransition(request, err) {
		return
	}
	reply := &protocol.EvsRefsReply{Format: repo.Object.GetFormat()}
	sequence, sequenceErr := ReadPushSequence(ctx, self.host.Redis, repoId)
	if sequenceErr == nil {
		reply.PushSequence = sequence
	}
	refSequences, refSequencesErr := self.heads.Cache().PushSequences(ctx, repoId)
	if refSequencesErr != nil {
		refSequences = map[sidecar.Id]uint64{}
	}
	prefix := HeadRepoPrefix(repoId)
	refIds := []sidecar.Id{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, prefix, startAfter, self.settings.RefsListPageCount)
		if err != nil {
			request.Unavailable(nil)
			return
		}
		for _, object := range objects {
			refId, err := parseEvsHexId(strings.TrimPrefix(object.Key, prefix))
			if err != nil {
				continue
			}
			refIds = append(refIds, refId)
			startAfter = object.Key
		}
		if !more || len(objects) == 0 {
			break
		}
	}
	all := true
	toRead := refIds
	if moved {
		toRead, all = movedRefCandidates(movedAfter, sequence, sequenceErr == nil, refSequences, refSequencesErr == nil, refIds)
	}
	heads, ok := self.readRefHeads(ctx, cluster, repoId, toRead)
	if !ok {
		request.Unavailable(nil)
		return
	}
	if !all {
		for _, refId := range toRead {
			if refSequences[refId] == 0 && evsRefHeadStands(heads[refId]) {
				// a ref the hash lacks: evs cannot tell whether it moved, so every ref
				all = true
				break
			}
		}
		if all {
			rest := []sidecar.Id{}
			for _, refId := range refIds {
				if _, read := heads[refId]; !read {
					rest = append(rest, refId)
				}
			}
			restHeads, ok := self.readRefHeads(ctx, cluster, repoId, rest)
			if !ok {
				request.Unavailable(nil)
				return
			}
			maps.Copy(heads, restHeads)
		}
	}
	for _, refId := range refIds {
		head := heads[refId]
		if !evsRefHeadStands(head) || (!all && refSequences[refId] <= movedAfter) {
			continue
		}
		read := &readAttempt{engine: self, repoId: repoId, refId: refId, head: head}
		summary := read.headSummary()
		summary.PushSequence = refSequences[refId]
		reply.Refs = append(reply.Refs, summary)
	}
	reply.All = all
	request.Reply(reply)
}

// Each ref's head from the cluster, read together. false when any read failed.
func (self *EvsEngine) readRefHeads(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refIds []sidecar.Id) (map[sidecar.Id]*EvsStoredHead, bool) {
	heads := make([]*EvsStoredHead, len(refIds))
	errs := make([]error, len(refIds))
	var waitGroup sync.WaitGroup
	for i, refId := range refIds {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			heads[i], errs[i] = self.heads.ReadCluster(ctx, cluster, repoId, refId)
		}()
	}
	waitGroup.Wait()
	refHeads := make(map[sidecar.Id]*EvsStoredHead, len(refIds))
	for i, refId := range refIds {
		if errs[i] != nil {
			return nil, false
		}
		refHeads[refId] = heads[i]
	}
	return refHeads, true
}

// Whether a head read stands as a ref: read, present, and no placeholder.
func evsRefHeadStands(head *EvsStoredHead) bool {
	return head != nil && !head.Absent() && evsHeadExists(head.Head)
}
