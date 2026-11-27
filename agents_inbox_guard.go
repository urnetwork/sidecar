//go:build !ios_extension && !sidecar_http

// The inbox refusal (DESIGN-COMPUTE §20.4's inboxes row, D-SKILL-7, D-MCP-17 as Appendix D amends it, I-9;
// SKILL-M11-04): an agent repo's, the agents repo's and the Team inbox's inbox/ take messages only, so kind 24 and the
// tiers of agent_send, agent_broadcast and agent_close, which write them, hold for every message, and no process writes
// around a Harness.
//
//	planner   every plan passes the refusal before anything is read for it, sealed or sent, file mode and git mode
//	          alike (evs_plan.go's EvsWriteGuardCheck): a write or a delete of inbox or anything under it in such a
//	          repo is ErrEvsInboxMessagesOnly, unless it is an agents client's create-only message write, which alone
//	          carries the guard's grant, an unexported type no other package can mint, naming the one message path
//	          inbox/<32 hex>/<32 hex>.json it is for. So evs_write, the in-process evs tools, ur evs, an approved
//	          evs_write's effect, the bundled git's push (GIT-M13-03) and an enclave's container socket (ENC) are
//	          refused alike, wherever they enter
//	mcp       a row of McpGuard refuses evs_write and evs_delete there first, with MCP's refusal text (mcp/guard.go)
//	support   the support client's notices are messages too, written through the agents client (agents_support.go)
//
// The refusal's rule lives in evs_plan.go, which every leg links, so a leg without the agents client refuses every
// write there, the closed direction. AgentsInboxGuard is the rule as one call for a caller that judges a path before it
// plans one.
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"github.com/urnetwork/sidecar/protocol"
)

// The refusal of a write or delete of path in repo, nil where the inbox guard lets it through: anything outside an
// agents' inbox, and nothing inside one, since only an agents client's message write carries the grant.
func AgentsInboxGuard(repo *protocol.AclRepo, path string) error {
	if EvsRepoInboxMessagesOnly(repo) && evsInboxPath(path) {
		return ErrEvsInboxMessagesOnly
	}
	return nil
}

// Whether repoId's inbox/ takes messages only at this Sidecar's verified state: an agents or agent repo, or the Team
// inbox. A repo the state does not hold reads true, the closed direction, as does a Sidecar with no state yet.
func (self *Sidecar) AgentsInboxRepo(repoId Id) bool {
	state, err := self.configState()
	if err != nil || state == nil {
		return true
	}
	repo := state.Repo(repoId)
	return repo == nil || EvsRepoInboxMessagesOnly(repo)
}
