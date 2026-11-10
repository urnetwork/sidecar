// GET /evs/v1/repos/<id>/refs (§11.9; EVS1-M2-14): the repo's refs as their heads stand, with repo/'s format and the
// repo's push sequence. One LIST of head/<repo>/ pages the keys, each head read from the cluster together, a
// placeholder head (version 0, no kind or mode) left out as absent, and each ref's push sequence from {evsh_}
// where it holds one. The ?moved_after= form is M6's (EVS1-M6-01) and answers every ref until then, as §11.9's moved
// row says a value the sequence cannot place does.

package evsservice

import (
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// See the file header.
func (self *EvsEngine) serveRefs(request *EvsRequest) {
	ctx := request.Ctx
	cluster := request.Cluster
	repoId := request.RepoId
	if request.Http.URL.Query().Has("moved_after") {
		request.Note("moved_after")
	}
	repo, err := self.repos.Read(ctx, cluster, repoId)
	if !self.answerTransition(request, err) {
		return
	}
	reply := &protocol.EvsRefsReply{Format: repo.Object.GetFormat()}
	if sequence, err := ReadPushSequence(ctx, self.host.Redis, repoId); err == nil {
		reply.PushSequence = sequence
	}
	refSequences, err := self.heads.Cache().PushSequences(ctx, repoId)
	if err != nil {
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
	for i, refId := range refIds {
		if errs[i] != nil {
			request.Unavailable(nil)
			return
		}
		head := heads[i]
		if head.Absent() || !evsHeadExists(head.Head) {
			continue
		}
		read := &readAttempt{engine: self, repoId: repoId, refId: refId, head: head}
		summary := read.headSummary()
		summary.PushSequence = refSequences[refId]
		reply.Refs = append(reply.Refs, summary)
	}
	request.Reply(reply)
}
