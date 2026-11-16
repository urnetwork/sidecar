//go:build !ios_extension

// §15.5's and §15.6's mail indexers (R-MAIL-8, D-MAIL-15, I-4, FS-82; owner decisions 58, 150; MAIL-M7-25): the
// receivers an IndexerSet designates for mail (§7.9), which a network receives reliably through, and the reader's
// alarm on mail another receiver took.
//
//	designated  each IndexerSet that holds and whose subject serves (ConfigState.Indexers), its sealed services opened
//	            by the caller's MailIndexerServices and naming mail. A designation whose services do not open leaves
//	            the list unknown, never shorter: a reader that cannot open one cannot tell who is not designated, so
//	            it neither gates nor alarms on the list. The designations grant no key, read or grant: a receiver
//	            still holds only its listen and deposits to the drop key (§15.4)
//	covers      a network-scope designation covers the network's mail, a member-scope one its member's (§15.6: "in a
//	            personal network or a member scope"), and in a personal network, whose one member is everyone, a
//	            designation at either scope covers all of it
//	eligible    under team_mail: indexers a tagged device, a tag:mail one, registers a receiver's listener only once a
//	            network-scope designation names it for mail. That is its own choice: nothing server side refuses it,
//	            since services is sealed, and designations never gate the receive path for anyone else. An untagged
//	            device, and every device under another mode, receives as policy grants its listen. A tagged device
//	            that cannot tell its mode or its designation registers none
//	alarm       under team_mail: indexers, with the network's mail indexers known and at least one standing, internet
//	            mail whose receiver is none of them raises mail_receiver_alarm on every reader (reading 8), and so
//	            does a member scope's deposit from a receiver that is no consented device of that member. With none
//	            designated, any online receiver takes mail and nothing alarms (§15.6)
//
// The alarm names the receiver and the repo, never an address (I-13). On every leg but the extension's.

package sidecar

import (
	"errors"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// A reader found a receiver or a record it alarms on (reading 8, reading 15; QD-534): SidecarId the receiver or the
// record's signer, RepoId the repo, MailReceiverAlarm why.
const SidecarEventMailReceiverAlarm SidecarEventKind = "mail_receiver_alarm"

// Why a mail_receiver_alarm fired.
type SidecarMailReceiverAlarm string

const (
	// Internet mail a receiver that is none of the network's mail indexers took, under team_mail: indexers.
	SidecarMailReceiverAlarmUndesignated SidecarMailReceiverAlarm = "undesignated"
	// A member scope's deposit from a receiver that is no consented device of the scope's member.
	SidecarMailReceiverAlarmScope SidecarMailReceiverAlarm = "scope"
	// A deposit ingest passed over or wrote as evidence unavailable: a wrong signer, evidence of another message, a
	// depositor with no right there (MailIngestAlarm).
	SidecarMailReceiverAlarmDeposit SidecarMailReceiverAlarm = "deposit"
	// A mailcfg version a reader passed over: a creator that is not the push's signer, a signer that may not change
	// the record (MailConfigAlarm; reading 15).
	SidecarMailReceiverAlarmRecord SidecarMailReceiverAlarm = "record"
)

// Opens a designation's sealed services with the config generation's key, as ConfigState.SearchIndexersFor's argument
// does; false where it cannot.
type MailIndexerServices func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)

// One mail indexer: a designation naming mail.
type MailDesignatedReceiver struct {
	SidecarId Id
	Scope     protocol.IndexerScope
	// The subject's member, whose mail a member-scope designation covers; zero for a tagged subject.
	MemberId Id
}

// The mail indexers state designates (the file header's designated row), by subject then scope. known is false where a
// designation stands whose services do not open, nil services opening none.
func MailDesignatedReceivers(state *ConfigState, services MailIndexerServices) (receivers []MailDesignatedReceiver, known bool) {
	receivers = []MailDesignatedReceiver{}
	if state == nil {
		return receivers, false
	}
	known = true
	for _, indexer := range state.Indexers() {
		if services == nil {
			return []MailDesignatedReceiver{}, false
		}
		offered, opened := services(indexer)
		if !opened {
			known = false
			continue
		}
		if !slices.Contains(offered, protocol.IndexerService_INDEXER_SERVICE_MAIL) {
			continue
		}
		receiver := MailDesignatedReceiver{SidecarId: indexer.SidecarId, Scope: indexer.Scope}
		if row, ok := state.sidecars[indexer.SidecarId]; ok {
			if memberId, untagged := configRowMember(row); untagged {
				receiver.MemberId = memberId
			}
		}
		receivers = append(receivers, receiver)
	}
	return receivers, known
}

// Whether a network holds one member: a personal network (DESIGN-DETAILS 7.2.2's E5 reading).
func mailPersonalNetwork(state *ConfigState) bool {
	return len(state.members) == 1
}

// The network's team_mail, and whether this reader could open the head that holds it.
func mailTeamMailMode(state *ConfigState) (protocol.TeamMailMode, bool) {
	settings, known := state.HeadSettings()
	if !known {
		return protocol.TeamMailMode_TEAM_MAIL_MODE_UNSPECIFIED, false
	}
	return settings.GetTeamMail(), true
}

// The receivers whose designations cover memberId's mail (the file header's covers row).
func mailDesignatedFor(state *ConfigState, receivers []MailDesignatedReceiver, memberId Id) []Id {
	personal := mailPersonalNetwork(state)
	covering := []Id{}
	for _, receiver := range receivers {
		covers := receiver.Scope == protocol.IndexerScope_INDEXER_SCOPE_NETWORK || personal ||
			(receiver.Scope == protocol.IndexerScope_INDEXER_SCOPE_MEMBER && receiver.MemberId == memberId && memberId != (Id{}))
		if covers && !slices.Contains(covering, receiver.SidecarId) {
			covering = append(covering, receiver.SidecarId)
		}
	}
	return covering
}

// The network's own mail indexers, those that see its mail in transit and that members' devices list (§15.5): the
// network-scope designations, or in a personal network every designation.
func mailNetworkIndexers(state *ConfigState, receivers []MailDesignatedReceiver) []Id {
	personal := mailPersonalNetwork(state)
	indexers := []Id{}
	for _, receiver := range receivers {
		if (receiver.Scope == protocol.IndexerScope_INDEXER_SCOPE_NETWORK || personal) && !slices.Contains(indexers, receiver.SidecarId) {
			indexers = append(indexers, receiver.SidecarId)
		}
	}
	return indexers
}

// Whether sidecarId registers a receiver's listener by its own choice (the file header's eligible row). Policy's grant
// of the listen is asked beside this, never instead.
func MailReceiverEligible(state *ConfigState, sidecarId Id, services MailIndexerServices) bool {
	if state == nil {
		return false
	}
	row, ok := state.sidecars[sidecarId]
	if !ok {
		return false
	}
	if _, untagged := configRowMember(row); untagged {
		return true
	}
	mode, known := mailTeamMailMode(state)
	if !known {
		// a tagged device that cannot tell its mode registers none
		return false
	}
	if mode != protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS {
		return true
	}
	receivers, _ := MailDesignatedReceivers(state, services)
	// a designation of this device that opened and names mail; one that did not open designates nothing here
	return slices.Contains(mailNetworkIndexers(state, receivers), sidecarId)
}

// Why internet mail receiverId took raises an alarm on a reader at state, "" for none (the file header's alarm row).
func MailUndesignatedReceiver(state *ConfigState, receiverId Id, services MailIndexerServices) SidecarMailReceiverAlarm {
	if state == nil {
		return ""
	}
	if mode, known := mailTeamMailMode(state); !known || mode != protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS {
		return ""
	}
	receivers, known := MailDesignatedReceivers(state, services)
	if !known {
		return ""
	}
	indexers := mailNetworkIndexers(state, receivers)
	if len(indexers) == 0 || slices.Contains(indexers, receiverId) {
		return ""
	}
	return SidecarMailReceiverAlarmUndesignated
}

// Why a member scope's deposit receiverId made raises an alarm (reading 8), "" for none: only that member's consented
// devices may receive its scope's mail (§15.5; owner decision 126).
func MailScopeReceiver(acl *AclState, scopeMemberId Id, receiverId Id) SidecarMailReceiverAlarm {
	if acl != nil && scopeMemberId != (Id{}) && acl.ConsentedFor(receiverId, scopeMemberId) {
		return ""
	}
	return SidecarMailReceiverAlarmScope
}

// Whether a mail indexer covers sidecarId's member's mail at state, as MailBinding.MailIndexer answers it:
// errMailIndexerServicesSealed where none covers and a designation stands whose services do not open, so who covers
// cannot be told.
func mailIndexerCovers(state *ConfigState, sidecarId Id, services MailIndexerServices) (bool, error) {
	memberId := Id{}
	if row, ok := state.sidecars[sidecarId]; ok {
		if rowMemberId, untagged := configRowMember(row); untagged {
			memberId = rowMemberId
		}
	}
	receivers, known := MailDesignatedReceivers(state, services)
	if 0 < len(mailDesignatedFor(state, receivers, memberId)) {
		return true, nil
	}
	if !known {
		return false, errMailIndexerServicesSealed
	}
	return false, nil
}

// Whether a standing designation serves mail cannot be told here: its services are sealed under its statement's
// header, which ConfigIndexer does not carry.
var errMailIndexerServicesSealed = errors.New("mail: an indexer's services are sealed")

// Raises mail_receiver_alarm on the bound Sidecar, and logs its ids, never an address (I-13).
func (self *MailClient) raiseReceiverAlarm(reason SidecarMailReceiverAlarm, sidecarId Id, repoId Id) {
	binding := func() *MailBinding {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.binding
	}()
	self.log.Warningf("[mail]%s %s: %s on %s", SidecarEventMailReceiverAlarm, reason, sidecarId, repoId)
	if binding != nil && binding.Event != nil {
		binding.Event(SidecarEvent{Kind: SidecarEventMailReceiverAlarm, SidecarId: &sidecarId, RepoId: &repoId, MailReceiverAlarm: reason})
	}
}

// The alarm a reader raises over one message its ingest wrote (the file header's alarm row): internet mail an
// undesignated receiver took, or a member scope's deposit from a receiver that is no consented device of the scope's
// member. A scope's member is resolved by no source yet (team_mail's member scopes, MAIL-M10-04), so every scope
// deposit alarms until one is: no scope routes either (MAIL-M7-22), so none is expected.
func (self *MailClient) judgeReceiver(binding *MailBinding, message *MailMessage) {
	if binding == nil || message == nil || !message.ReceiverDeposit {
		return
	}
	if _, scoped := mailSniScope(self.networkRow().Root, message.Sni); scoped {
		var acl *AclState
		if binding.Engine != nil {
			acl = binding.Engine.State()
		}
		if reason := MailScopeReceiver(acl, Id{}, message.DepositorId); reason != "" {
			self.raiseReceiverAlarm(reason, message.DepositorId, message.RepoId)
		}
		return
	}
	if binding.Config == nil {
		return
	}
	state, err := binding.Config()
	if err != nil {
		return
	}
	if reason := MailUndesignatedReceiver(state, message.DepositorId, binding.IndexerServices); reason != "" {
		self.raiseReceiverAlarm(reason, message.DepositorId, message.RepoId)
	}
}

// The scope an SNI's mail host names under root, mx.<scope>.<net>.<root>, and whether it names one: false for the
// network's own mx.<net>.<root>, a custom host and anything else.
func mailSniScope(root string, sni string) (string, bool) {
	root = strings.TrimSuffix(dnsAsciiLower(root), ".")
	sni = strings.TrimSuffix(dnsAsciiLower(sni), ".")
	if root == "" {
		return "", false
	}
	host, ok := strings.CutSuffix(sni, "."+root)
	if !ok {
		return "", false
	}
	labels := strings.Split(host, ".")
	if len(labels) != 3 || labels[0] != "mx" || labels[1] == "" {
		return "", false
	}
	return labels[1], true
}
