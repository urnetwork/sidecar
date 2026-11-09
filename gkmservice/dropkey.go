// The drop-key route (D-KEYS-17; QD-156, QD-065): GET /gkm/repos/<id>/drop-key?since=<g>, which a depositor reads
// under deposit, and r, rw and admin also reach (QD-177). gkm resolves the repo's newest GroupForm, so a depositor
// needs no group id, and answers the newest GenRotates after since, at most 64 (§10.14), each the stored Signed bytes,
// which a depositor verifies under the depositor rule (§10.5): gkm proves nothing by serving them.
//
// The renewal duty (QD-065): a read whose newest GenRotate's drop key has under DropKeyRenewalWindow (7 days) left
// before drop_not_after_ms hints pending to the repo's writers, at most once per DropKeyRenewalHintInterval (an hour)
// per group and process, so a writer rotates with cause SCHEDULE before deposits stop.

package gkmservice

import (
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §10.14's bound on one drop-key answer: a format value.
const gkmDropKeyReplyMaxCount = 64

// GET /gkm/repos/<id>/drop-key?since=<g>: a GkmGenerationsReply of the repo's newest group's GenRotates after g, the
// newest 64 of them.
func (self *GkmEngine) serveDropKey(request *GkmRequest) {
	since, ok := self.readSince(request)
	if !ok {
		return
	}
	forms, err := self.forms.forms(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if len(forms) == 0 {
		request.NotFound()
		return
	}
	groupId := forms[len(forms)-1].GroupId
	request.GroupId = &groupId
	generations, err := self.generationNumbers(request.Ctx, request.Cluster, groupId, since)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if gkmDropKeyReplyMaxCount < len(generations) {
		generations = generations[len(generations)-gkmDropKeyReplyMaxCount:]
	}
	signeds, err := self.readGenerations(request.Ctx, request.Cluster, groupId, generations)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if 0 < len(generations) {
		newest := generations[len(generations)-1]
		if facts, err := self.generationFacts(request.Ctx, request.Cluster, groupId, newest); err == nil {
			self.hintDropKeyRenewal(request, groupId, facts)
		}
	}
	request.Reply(&protocol.GkmGenerationsReply{Generations: signeds})
}

// pending to the repo's writers when the newest drop key has under DropKeyRenewalWindow left, at most once per
// DropKeyRenewalHintInterval per group in this process.
func (self *GkmEngine) hintDropKeyRenewal(request *GkmRequest, groupId sidecar.Id, facts *gkmGenerationFacts) {
	if !facts.hasDropKey {
		return
	}
	now := request.Now()
	if self.settings.DropKeyRenewalWindow <= time.UnixMilli(facts.dropNotAfterMs).Sub(now) {
		return
	}
	rate := GkmRate{Count: 1, Interval: self.settings.DropKeyRenewalHintInterval}
	if !rate.valid() || !self.rates.Allow(rate, "drop_renew:"+sidecar.EvsKeyId(groupId), now) {
		return
	}
	writerIds, answer := self.deps.AuthState.RepoWriters(request.Principal, request.RepoId, now)
	if answer != GkmAuthAllowed {
		return
	}
	self.hintWork(writerIds, protocol.GkmHintKind_GKM_HINT_PENDING, &groupId, 0, nil)
}
