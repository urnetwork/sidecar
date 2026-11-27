//go:build !ios_extension && !sidecar_http

// A message's trust (DESIGN-COMPUTE §20.7's trust row, D-SKILL-4, IC-12, R-SKILL-7, I-9; SKILL-M11-04). A message is
// data, never instructions with authority, and it leaves the reader's run untainted only when its push's provenance
// shows one of two things:
//
//	(a) person  the member's own person: a push bound to no run (no agent in its sealed provenance, its tainted bit
//	            clear), signed by an untagged consented device of the reader's member, whose message says it is that
//	            member's person; only the device's input path writes such a message (AgentsClient.SendAsPerson: the
//	            sdk's Agents().Send, ur agents send confirmed on /dev/tty with no harness among its ancestors), and the
//	            inbox guard keeps every other writer from the inbox, so no tool call speaks as the person
//	(b) run     an untainted run on an untagged consented device of the reader's member: an agent in the sealed
//	            provenance, the tainted bit clear; the member's own enclave counts too from M14 (CO-43), and until the
//	            enclaves feature an enclave's incarnation is no member device here, so its messages read untrusted
//
// Everything else taints the run that takes it (AgentMessageTrustUntrusted): another member's message, every message
// in the Team inbox, a cloud agent's or another tagged sidecar's, which sets its own taint bit, a tainted run's, and a
// version whose provenance evs gave none of. A support notice is neither (§28.9): readers take only its enumerated
// fields, which taint nothing, and only from a device of the agent's member or the agent's own sidecar.
//
// The from field is never trusted: from.member is taken only where it is the member the config gives the push's
// signer, from.sidecar_id only where it is the signer, from.agent_id only where the provenance's agent subkey signature
// verified it, and from.repo only where the member's cards show it as that agent's (within a member, §20.5); a message
// that fails is shown by its provenance alone (AgentMessageTrust's Sender), with an alarm, and reads untrusted
// whatever its provenance, the closed direction: a forged from never leaves a run untainted. Across members the cards
// are not the reader's and the repo's label is checked instead (SKILL-M13-01, QD-1434).
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

// How a message's provenance reads (see the file header).
type AgentMessageTrustClass string

const (
	// (a): the member's own person, through a device's input path.
	AgentMessageTrustPerson AgentMessageTrustClass = "person"
	// (b): an untainted run on an untagged device of the member.
	AgentMessageTrustMemberRun AgentMessageTrustClass = "member_run"
	// Taints the run that takes it.
	AgentMessageTrustUntrusted AgentMessageTrustClass = "untrusted"
	// A support notice: neither trusted nor tainting.
	AgentMessageTrustSupport AgentMessageTrustClass = "support"
	// A support notice whose signer may not write one: ignored and alarmed, never delivered.
	AgentMessageTrustRefused AgentMessageTrustClass = "refused"
)

// Who a message's provenance shows wrote it: the push's signer, the member the config gives it, and the agent the
// sealed provenance names, its subkey signature verified or not.
type AgentMessageSender struct {
	SidecarId Id
	// The member the config gives the signer, zero for none: a revoked or unknown sidecar.
	MemberId Id
	// The agent the provenance names, nil for none; Verified where its subkey signature held.
	AgentId  *Id
	Verified bool
	// The agent's name and repo where the member's cards confirm them, else "" and zero.
	Name   AgentName
	RepoId Id
}

// A reader's verdict on one message version.
type AgentMessageTrust struct {
	Class AgentMessageTrustClass
	// The verified sender, which a reader shows in place of from where from does not hold.
	Sender AgentMessageSender
	// Every field of from held: its member, sidecar and agent as above, and its repo as the cards show it.
	FromVerified bool
}

// Whether the message leaves the reader's run untainted: (a) or (b).
func (self *AgentMessageTrust) Trusted() bool {
	return self.Class == AgentMessageTrustPerson || self.Class == AgentMessageTrustMemberRun
}

// Whether taking the message taints the reader's run: everything but (a), (b) and a support notice.
func (self *AgentMessageTrust) Taints() bool {
	return !self.Trusted() && self.Class != AgentMessageTrustSupport
}

// What judging a message reads beside its version: the reader's member and the member's cards by name, whose agent's
// id and repo confirm from's. Nil cards confirm no name or repo.
type agentMessageJudge struct {
	authority AgentsAuthority
	memberId  Id
	card      func(name AgentName) *AgentCard
}

// The verdict on message, written by signer under provenance (see the file header): its class from the provenance
// alone, and whether from holds.
func (self *agentMessageJudge) judge(message *AgentMessage, signer Id, provenance *EvsPushProvenance) *AgentMessageTrust {
	trust := &AgentMessageTrust{Class: AgentMessageTrustUntrusted, Sender: AgentMessageSender{SidecarId: signer}}
	signerMember, found := self.authority.MemberOf(signer)
	if found {
		trust.Sender.MemberId = signerMember
	}
	if provenance != nil && provenance.AgentId != nil && !provenance.Refused {
		agentId := *provenance.AgentId
		trust.Sender.AgentId = &agentId
		trust.Sender.Verified = provenance.State == EvsProvenanceVerified
	}
	untaintedOnMemberDevice := provenance != nil && !provenance.Tainted && !provenance.Imported && !provenance.Refused &&
		found && signerMember == self.memberId && self.authority.UntaggedConsented(signer, self.memberId)
	from := &message.From
	switch {
	case from.Support:
		// a notice from a device of the agent's member or the agent's own sidecar, both the member's: else ignored
		if message.Kind != AgentMessageKindSupport || !found || signerMember != self.memberId {
			trust.Class = AgentMessageTrustRefused
			return trust
		}
		trust.Class, trust.FromVerified = AgentMessageTrustSupport, true
		return trust
	case from.Person:
		trust.FromVerified = found && from.MemberId == signerMember && trust.Sender.AgentId == nil
		if trust.FromVerified && untaintedOnMemberDevice && from.MemberId == self.memberId {
			trust.Class = AgentMessageTrustPerson
		}
		return trust
	}
	memberHolds := found && from.MemberId == signerMember
	sidecarHolds := from.SidecarId == signer
	agentHolds := trust.Sender.Verified && *trust.Sender.AgentId == from.AgentId
	repoHolds := false
	if memberHolds && agentHolds && from.MemberId == self.memberId && self.card != nil {
		if card := self.card(from.Name); card != nil && !card.Person() && card.AgentId == from.AgentId && card.SidecarId == signer {
			trust.Sender.Name = card.Name
			trust.Sender.RepoId = card.AgentRepo
			repoHolds = card.AgentRepo == from.RepoId
		}
	}
	trust.FromVerified = memberHolds && sidecarHolds && agentHolds && repoHolds
	if trust.FromVerified && untaintedOnMemberDevice {
		trust.Class = AgentMessageTrustMemberRun
	}
	return trust
}
