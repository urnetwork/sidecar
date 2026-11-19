//go:build !ios_extension

// A Team scope's mail on a device (MAIL-M8-09; D-MAIL-12, D-MAIL-15, R-MAIL-3, I-5, I-15; owner decisions 40, 58, 126):
// under team_mail: member scopes each member scope has its own mail host mx.<scope>, its own mailcfg and its own
// certificate pair, and only its member's consented devices receive or read its mail.
//
//	scopes    the network's Team scopes as its verified state lists them, each label with its member for a member
//	          scope, through the host's MailScopeSource. ProjectionRows keeps field 6 for TeamScopeRow, which no state
//	          carries yet (protos-bridge-row-fields #3), so no host gives a source, and every scope reads unknown: no
//	          scope receiver is planned, and every scope deposit alarms
//	receive   a device receives for a scope, at smtp/25/mx.<scope> (MailScopeReceiverHosts), only under team_mail:
//	          member scopes, only for a member scope whose member it is a consented device of, and only while policy
//	          grants it that listen in the scope (AclState.MayListenInScope), as ValidateListen (mxedgeservice) and
//	          POST /dns/key-record hold it server side. A tag scope takes no mail: owner decision 58's second choice
//	          is per member. Teams designate two indexers per scope as §7.9's IndexerSet at member scope, which the
//	          designations already read (mail_indexer.go); nothing here gates on them
//	mailcfg   a scope's own mailcfg is the mailcfg repo whose row names the scope's member as its owner
//	          (MailRepos.ScopeMailConfigRepo), and the network's is the one whose row names none (QD-1093: a consented
//	          device of the member creates it, and the access log's fold owner-binds a mailcfg RepoCreate from a member
//	          device that is no config writer). Neither the fold nor EvsClient.CreateRepo does that yet, so none is
//	          found, and a scope's receiver has no directory to resolve a recipient against: the composition that
//	          would start one does not run
//	address   <name>@<scope>.<net>.<root> is MailScopeZone's: ParseMailAddress reads it as MailZone{Scope}, and a
//	          scope's MailConfig resolves only its own scope's addresses (mail_config_read.go)
//	alarm     a reader alarms on a scope deposit whose receiver is no consented device of the scope's member, and on
//	          every scope deposit while the scope's member cannot be told (mail_indexer.go's judgeReceiver)
//	key       a scope's network mail key is its member's mailbox's drop key (§15.8): an admin's device never holds it,
//	          since a mailbox is owner-bound to its member (§8.5)
//
// Nothing here logs a scope label, an address or a member (I-13). Safe for concurrent use.

package sidecar

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The socket name a scope's receiver listens on, before its host: smtp/25/mx.<scope> (§9.4). An identifier, which
// mail_receiver.go's own prefix spells on the legs a receiver builds on.
const mailScopeListenPrefix = "smtp/25/"

// Where a device reads the network's Team scopes in its verified state: each scope's label, with its member for a
// member scope and none for a tag scope; known false while the state names none this device can read.
type MailScopeSource func(state *AclState) (scopes []AclScope, known bool)

// The scope label names in state as source reads it, false where source, the state or the scope is unknown.
func mailScopeOf(source MailScopeSource, state *AclState, label string) (AclScope, bool) {
	if source == nil || state == nil || label == "" {
		return AclScope{}, false
	}
	scopes, known := source(state)
	if !known {
		return AclScope{}, false
	}
	index := slices.IndexFunc(scopes, func(scope AclScope) bool { return scope.Label == label })
	if index < 0 {
		return AclScope{}, false
	}
	return scopes[index], true
}

// A scope's mail host, mx.<scope>, which smtp/25/<host>, mail_host_key and POST /dns/key-record name.
func MailScopeHost(scope string) string {
	return "mx." + scope
}

// The zone a scope's addresses are spelled under: <scope>.<net>.<root>.
func MailScopeZone(root string, net string, scope string) MailZone {
	return MailZone{Root: root, Net: net, Scope: scope}
}

// The scope hosts sidecarId receives for at the verified config and acl state (the file header's receive row), in the
// scopes' order: mx.<scope> for each member scope whose member sidecarId is a consented device of, under team_mail:
// member scopes, where policy grants the listen in that scope. None under any other mode, or where the mode cannot be
// read.
func MailScopeReceiverHosts(config *ConfigState, acl *AclState, scopes []AclScope, sidecarId Id, now time.Time) []string {
	hosts := []string{}
	if config == nil || acl == nil {
		return hosts
	}
	if mode, known := mailTeamMailMode(config); !known || mode != protocol.TeamMailMode_TEAM_MAIL_MODE_MEMBER_SCOPES {
		return hosts
	}
	for _, scope := range scopes {
		if scope.Label == "" || scope.MemberId == (Id{}) || !acl.ConsentedFor(sidecarId, scope.MemberId) {
			continue
		}
		socket := AclSocketName{PublicName: mailScopeListenPrefix + MailScopeHost(scope.Label)}
		if !acl.MayListenInScope(AclSidecarSubject(sidecarId), socket, scope, now).Allowed {
			continue
		}
		if host := MailScopeHost(scope.Label); !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}
