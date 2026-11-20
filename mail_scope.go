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
//	          (MailRepos.ScopeMailConfigRepo), and the network's is the first standing one whose row names none
//	          (QD-1093): a consented device of the member creates it (MailRepos.EnsureScopeMailConfig), and the access
//	          log's fold owner-binds that RepoCreate to its creator's member, so only that member's consented devices,
//	          and the scope's receivers by their kind default, read it; it follows the owner-bound rules as a mailbox
//	          does, out of every admin's reach and the tag:mail indexers' (QD-1107). A scope whose member is in the
//	          AdminSet, whose devices all write config heads, gets its own once the network's stands, since the fold
//	          reads a config writer's mailcfg created then as its member's scope's (QD-1108); until the network's
//	          stands its receiver stays unplanned
//	setup     a device's scope receivers are MailScopeReceiverPlans': each host it receives for whose scope's own mailcfg
//	          stands, with that mailcfg, which the receiver's sessions resolve a recipient against. A scope with no
//	          mailcfg plans no receiver, since it would have no directory. MailRepos.EnsureScopeReceivers is the
//	          setup a scope member's device runs: it creates the mailcfg of each scope it receives for where the log
//	          holds none, and answers the receivers ready to start. The mail component does not run it yet: no state
//	          gives a scope source, and a scope's certificate pair has no composer source (TLS-M6-03)
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
	"context"
	"errors"
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

// The member scopes sidecarId receives for at the verified config and acl state (the file header's receive row), in
// the scopes' order, one per host: each member scope whose member sidecarId is a consented device of, under team_mail:
// member scopes, where policy grants the listen in that scope. None under any other mode, or where the mode cannot be
// read.
func mailScopeReceiverScopes(config *ConfigState, acl *AclState, scopes []AclScope, sidecarId Id, now time.Time) []AclScope {
	received := []AclScope{}
	if config == nil || acl == nil {
		return received
	}
	if mode, known := mailTeamMailMode(config); !known || mode != protocol.TeamMailMode_TEAM_MAIL_MODE_MEMBER_SCOPES {
		return received
	}
	for _, scope := range scopes {
		if scope.Label == "" || scope.MemberId == (Id{}) || !acl.ConsentedFor(sidecarId, scope.MemberId) {
			continue
		}
		socket := AclSocketName{PublicName: mailScopeListenPrefix + MailScopeHost(scope.Label)}
		if !acl.MayListenInScope(AclSidecarSubject(sidecarId), socket, scope, now).Allowed {
			continue
		}
		if !slices.ContainsFunc(received, func(listed AclScope) bool { return listed.Label == scope.Label }) {
			received = append(received, scope)
		}
	}
	return received
}

// The scope hosts sidecarId receives for at the verified config and acl state (the file header's receive row), in the
// scopes' order: mx.<scope> for each member scope whose member sidecarId is a consented device of, under team_mail:
// member scopes, where policy grants the listen in that scope. None under any other mode, or where the mode cannot be
// read.
func MailScopeReceiverHosts(config *ConfigState, acl *AclState, scopes []AclScope, sidecarId Id, now time.Time) []string {
	hosts := []string{}
	for _, scope := range mailScopeReceiverScopes(config, acl, scopes, sidecarId, now) {
		hosts = append(hosts, MailScopeHost(scope.Label))
	}
	return hosts
}

// One scope receiver a device runs: its scope, the host its MailReceiver names (MailReceiverArgs.Host), and the
// scope's own mailcfg, which its sessions resolve a recipient against.
type MailScopeReceiverPlan struct {
	Scope AclScope
	// mx.<scope>.
	Host string
	// The scope's own mailcfg: the first standing mailcfg whose row names the scope's member.
	MailConfigRepoId Id
}

// The socket name the receiver listens on: smtp/25/mx.<scope>.
func (self MailScopeReceiverPlan) ListenName() string {
	return mailScopeListenPrefix + self.Host
}

// The scope receivers sidecarId starts at the verified config and acl state (the file header's setup row), in the
// scopes' order: each host MailScopeReceiverHosts gives whose scope's own mailcfg stands in acl. A scope with no
// mailcfg is left out: its receiver would have no directory to resolve a recipient against, so none starts.
func MailScopeReceiverPlans(config *ConfigState, acl *AclState, scopes []AclScope, sidecarId Id, now time.Time) []MailScopeReceiverPlan {
	plans := []MailScopeReceiverPlan{}
	for _, scope := range mailScopeReceiverScopes(config, acl, scopes, sidecarId, now) {
		repoId, found := mailScopeConfigRepo(acl, scope.MemberId)
		if !found {
			continue
		}
		plans = append(plans, MailScopeReceiverPlan{Scope: scope, Host: MailScopeHost(scope.Label), MailConfigRepoId: repoId})
	}
	return plans
}

// A scope member's device's setup (the file header's setup row): for each scope this device receives for at config and
// its verified state, the scope's own mailcfg, created where the log holds none and taken up again where this device's
// creation was cut short (EnsureScopeMailConfig), then the receivers ready to start at the state as it stands after,
// as MailScopeReceiverPlans gives them. A creation the state does not show yet plans no receiver until it does. The
// error joins what kept a scope's mailcfg from being made; a read_only device, which files nothing, waits for another
// of its member's and is no error.
func (self *MailRepos) EnsureScopeReceivers(ctx context.Context, config *ConfigState, scopes []AclScope, now time.Time) ([]MailScopeReceiverPlan, error) {
	state, err := self.verifiedState()
	if err != nil {
		return nil, err
	}
	var ensureErr error
	for _, scope := range mailScopeReceiverScopes(config, state, scopes, self.sidecarId, now) {
		if _, err := self.EnsureScopeMailConfig(ctx, scope.MemberId); err != nil && !errors.Is(err, ErrMailReposNotConsented) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ensureErr = errors.Join(ensureErr, err)
		}
	}
	state, err = self.verifiedState()
	if err != nil {
		return nil, err
	}
	return MailScopeReceiverPlans(config, state, scopes, self.sidecarId, now), ensureErr
}
