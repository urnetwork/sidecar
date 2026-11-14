//go:build !sidecar_http && !ios_extension

// D-ACL-12's mail authorization, split as §8.10 says (ACL-M7-01; I-5, X6, X7). No edge sees an alias, inbound or
// outbound, so the server side is coarse and the client side exact:
//
//	mxedge, /dns/key-record   listen on smtp/25/mx, or a Team scope's smtp/25/mx.<scope>, a member scope's only from
//	                          its member's consented devices (owner decision 126): MayReceive
//	smtpedge                  mail_send, the one bit rows hold of mail:<alias>: MaySendMail; the From domain beside it is
//	                          smtpedge's own check (§14.5), wired with M9's SMTP tasks
//	receivers, local server   mail:<alias> for send or listen through AclEngine.AllowAlias, which reads the aliases
//	                          AclLocalPolicy keeps on the device (§15.10)
//	mailcfg records           a receiver honors a creator-signed record for an alias only while policy grants its
//	                          creator mail:<alias>#listen (§15.10): HonorsMailcfgRecord
//
// Rows carry only mail_send, so no gate is ever handed an alias, and none of these takes one at a gate. A Find for
// ur/smtpedge needs no §8 grant (§9.4): it is smtpedge's service name, which the service authorizes.
//
// Safe for concurrent use. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The receiver socket of a network's mail, and the prefix of a Team scope's (§9.4: smtp/25/mx.<scope>).
const aclMailReceiverName = "smtp/25/mx"

// Whether a receiver may take a network's mail: listen on smtp/25/mx, or for a Team scope smtp/25/mx.<scope>, which in
// a member scope only that member's consented devices take, whatever the grants say. mxedge's routing gate and POST
// /dns/key-record's ask this. A zero scope is the network's own receiver.
func (self *AclGateView) MayReceive(networkId Id, receiver AclSubject, scope AclScope, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	name := aclMailReceiverName
	if scope.Label != "" {
		name = aclMailReceiverName + "." + scope.Label
	}
	return state.MayListenInScope(receiver, AclSocketName{PublicName: name}, scope, now)
}

// Whether a subject may send mail through smtpedge: a send grant with mail_send (D-ACL-12). The From domain is
// smtpedge's to check beside it (§14.5).
func (self *AclGateView) MaySendMail(networkId Id, subject AclSubject, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.MaySend(subject, now)
}

// Whether a receiver honors a mailcfg record its creator signed for an alias (§15.10): only while policy grants the
// creator mail:<alias>#listen, judged at each read on the installed state, so a record outlives no grant.
func (self *AclEngine) HonorsMailcfgRecord(creatorSidecarId Id, alias string, now time.Time) bool {
	return self.AllowAlias(AclSidecarSubject(creatorSidecarId), protocol.AclAction_ACL_ACTION_LISTEN, alias, now).Allowed
}
