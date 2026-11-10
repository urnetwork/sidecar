// GET /evs/v1/repos/<id>/log?ref=&since= (§11.9; EVS1-M2-14): the ref's statements from version since, at most 1,000
// an answer, with next_version naming where the next page starts, 0 once the answer reaches the head. Versions the
// window holds come from the records at their entries' places, older ones from their log pages (log/<repo>/<ref>/<n>,
// which never change, so each is read once a process), and nothing is served above the head read for the answer,
// from the cache where §11.9's cache row allows it, since every version below a head is settled.

package evsservice

import (
	"errors"
	"strconv"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.9's log row: at most 1,000 statements a page.
const evsLogReplyMaxStatementCount = 1000

// See the file header.
func (self *EvsEngine) serveLog(request *EvsRequest) {
	query := request.Http.URL.Query()
	refId, err := parseEvsHexId(query.Get("ref"))
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	since, err := strconv.ParseUint(query.Get("since"), 10, 64)
	if err != nil || since == 0 {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	request.NoteRefIds(refId)
	ctx := request.Ctx
	cluster := request.Cluster
	head, err := self.heads.ReadCached(ctx, cluster, request.RepoId, refId, since, false)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	reply := &protocol.EvsLogReply{}
	if head.Absent() || !evsHeadExists(head.Head) || head.Version() < since {
		request.Reply(reply)
		return
	}
	pushes := newReadPushes(self, ctx, cluster, request.RepoId, refId, head.Head)
	last := min(head.Version(), since+uint64(self.settings.LogReplyStatementCount)-1)
	for version := since; version <= last; version += 1 {
		push, err := pushes.at(version)
		if err != nil {
			if errors.Is(err, ErrEvsStatementMismatch) || errors.Is(err, sidecar.ErrEvsPushInvalid) {
				self.log.Errorf("[evs] alarm log: repo %s ref %s version %d: %v", sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(refId), version, err)
				self.metrics.alarms.Add(1, "log")
			}
			request.Unavailable(nil)
			return
		}
		reply.Statements = append(reply.Statements, &protocol.EvsReadStatement{Version: version, Statement: push.statement.Bytes})
	}
	if last < head.Version() {
		reply.NextVersion = last + 1
	}
	request.Reply(reply)
}
