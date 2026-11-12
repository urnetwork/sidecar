//go:build !ios_extension

// §8.8's Saving: what a writer's device refuses before it compiles, tests, previews and signs a policy head. Each
// refusal names its rule and field for the preview, never a value (I-13). The list is §8.8's:
//
//	atoms         a tag or group the head's tables do not hold, a user, network or client resolve does not hold, a
//	              user whose member the log no longer holds (plan-ACL-selector-resolution), and a group no groups
//	              entry defines unless SCIM keeps it (group:<name>@<domain>, §7.6)
//	approvers     autogroup:sponsor or autogroup:dst-owner outside approver, which the parser refuses as well
//	tags          a tag named anywhere that tagOwners does not list
//	ports         an ip field on a rule with no subject or ip: destination, or allowing neither dial nor route, and
//	              a via on a rule that does not allow route
//	overruns      the tier's acl_rules, acl_groups, acl_requests and acl_network_shares (§20.4)
//	paths         an evs: resource that is a path (X2), which the parser refuses as well
//	owner-bound   a read, write or admin on a vault, mailbox or secret repo, which only its owner's EvsShare or the
//	              audit block adds (D-ACL-13, owner decision 126); a deposit to a vault or mailbox stands
//	config        any grant on the config repo or the directory (D-ACL-13, D-ACL-24)
//	audit         an audit block while no k-of-n AuditOptIn stands at the head's time (ACL-M6-02)
//	publishes     a standing publish outside a Pro or Team document (§8.5); a publish request past the tier's
//	              publish expiry (§13.9: 7 days on Community)
//	raw           app_mode raw outside audience public and link, and a raw link without link_spki_sha256 (§13.7)
//	network:      one the injected resolver does not resolve, label or alias, to resolve's id, never a legacy name
//	              (D-DNS-2); with no resolver, before §12's labels, every network: but the shares wildcard
//	tier          group:, network: and two approvers where the tier's acl_* keys turn them off
//	sockets       a sock: name in the ur/ or a reserved namespace, which no policy names (§9.4)
//	scope hosts   a dns: host or a tls/ or smtp/ socket's host <label>.<scope> whose scope the network's Team scopes do
//	              not hold, or is a glob (Q-TLS-3, ACL-M6-01); with no scopes injected, before M6's, every scope host,
//	              so a scope label never stands for a client name (§7.7)
//
// Row sizes are AclRowsCheckLimits', on the compiled rows. Limits judge new heads only: after a downgrade a head that
// fit stands and keeps evaluating, and the next must fit (§20.7).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// One refusal: the rule, as grants[i], requests[j], groups, tagOwners or audit, the field within it, and why.
type AclValidationRefusal struct {
	Rule   string
	Field  string
	Reason string
}

// The refusal as a preview line.
func (self AclValidationRefusal) String() string {
	if self.Field == "" {
		return self.Rule + ": " + self.Reason
	}
	return self.Rule + "." + self.Field + ": " + self.Reason
}

// Every refusal of one document, wrapping ErrAclPolicyInvalid.
type AclValidationError struct {
	Refusals []AclValidationRefusal
}

// The refusals as one line.
func (self *AclValidationError) Error() string {
	lines := make([]string, 0, len(self.Refusals))
	for _, refusal := range self.Refusals {
		lines = append(lines, refusal.String())
	}
	return fmt.Sprintf("%s: %s", ErrAclPolicyInvalid, strings.Join(lines, "; "))
}

// ErrAclPolicyInvalid.
func (self *AclValidationError) Unwrap() error {
	return ErrAclPolicyInvalid
}

// What ValidateAclPolicy judges a document against.
type AclValidateInput struct {
	// The head's tables and the log's rows at the writer's state, as CompileAcl reads them, and the document's source
	// as its Policy.
	Compile *AclCompileInput
	// The tier's acl_* limits; nil judges the format alone.
	Limits *AclLimits
	// §12's ResolveNetworkLabel, label or alias and never a legacy name (D-DNS-2), injected. nil before M5's labels,
	// and then every network: selector but the shares wildcard refuses.
	ResolveNetworkLabel func(text string) (Id, bool)
	// The network's Team scopes by label (§13.8, Q-TLS-3), from TEAM's scope rows, injected. nil before M6's scopes,
	// and then every scope host refuses.
	ResolveScope func(label string) (AclScope, bool)
}

// Refuses exactly §8.8's Saving list, every refusal at once.
func ValidateAclPolicy(input *AclValidateInput) error {
	if input == nil || input.Compile == nil || input.Compile.Policy == nil {
		return fmt.Errorf("%w: no document", ErrAclPolicyInvalid)
	}
	tables, err := newAclCompilerTables(input.Compile)
	if err != nil {
		return err
	}
	validator := &aclValidator{input: input, tables: tables, policy: tables.policy, repoKinds: map[Id]protocol.RepoKind{}}
	for _, repo := range input.Compile.Statements.GetRepos() {
		if repoId, err := IdFromBytes(repo.GetRepoId()); err == nil {
			validator.repoKinds[repoId] = repo.GetKind()
		}
	}
	validator.validate()
	if len(validator.refusals) == 0 {
		return nil
	}
	return &AclValidationError{Refusals: validator.refusals}
}

// One validation's working state.
type aclValidator struct {
	input     *AclValidateInput
	tables    *aclCompiler
	policy    *AclPolicy
	repoKinds map[Id]protocol.RepoKind
	refusals  []AclValidationRefusal
	// the network: selectors named, for acl_network_shares
	networkCount int
}

// Records one refusal.
func (self *aclValidator) refuse(rule string, field string, reason string) {
	self.refusals = append(self.refusals, AclValidationRefusal{Rule: rule, Field: field, Reason: reason})
}

// Every check, in document order.
func (self *aclValidator) validate() {
	limits := self.input.Limits
	if self.policy.Audit != nil {
		if notAfter, ok := aclAuditNotAfter(self.input.Compile.Statements.GetAudit().GetAuditOptIn()); !ok || notAfter <= self.input.Compile.HeadTimeMs {
			self.refuse("audit", "", "an audit block counts only under a k-of-n AuditOptIn, and none stands")
		}
	}
	if limits != nil {
		if 0 < len(self.policy.Groups) && limits.Groups == 0 {
			self.refuse("groups", "", "this tier's documents hold no groups (acl_groups)")
		} else if !aclLimitFits(len(self.policy.Groups), limits.Groups) {
			self.refuse("groups", "", "more groups than this tier's acl_groups")
		}
		if !aclLimitFits(len(self.policy.Grants)+len(self.policy.Requests), limits.Rules) {
			self.refuse("grants", "", "more rules than this tier's acl_rules")
		}
		if !aclLimitFits(len(self.policy.Requests), limits.Requests) {
			self.refuse("requests", "", "more requests rules than this tier's acl_requests")
		}
	}
	for i, group := range self.policy.Groups {
		self.selector("groups", fmt.Sprintf("[%d]", i), group.Group, aclPositionSrc)
		for j, member := range group.Members {
			self.selector("groups", fmt.Sprintf("[%d].members[%d]", i, j), member, aclPositionGroupMember)
		}
	}
	for i, tagOwner := range self.policy.TagOwners {
		self.selector("tagOwners", fmt.Sprintf("[%d]", i), tagOwner.Tag, aclPositionSrc)
		for j, owner := range tagOwner.Owners {
			self.selector("tagOwners", fmt.Sprintf("[%d].owners[%d]", i, j), owner, aclPositionTagOwner)
		}
	}
	for i := range self.policy.Grants {
		self.grant(fmt.Sprintf("grants[%d]", i), &self.policy.Grants[i])
	}
	for j := range self.policy.Requests {
		self.request(fmt.Sprintf("requests[%d]", j), &self.policy.Requests[j])
	}
	if limits != nil && 0 < self.networkCount {
		if limits.NetworkShares == 0 {
			self.refuse("grants", "", "this tier's documents name no other network (acl_network_shares)")
		} else if !aclLimitFits(self.networkCount, limits.NetworkShares) {
			self.refuse("grants", "", "more network: selectors than this tier's acl_network_shares")
		}
	}
}

// One grant's checks.
func (self *aclValidator) grant(rule string, grant *AclGrant) {
	for k, selector := range grant.Src {
		self.selector(rule, fmt.Sprintf("src[%d]", k), selector, aclPositionSrc)
	}
	for k, resource := range grant.Dst {
		self.resource(rule, fmt.Sprintf("dst[%d]", k), resource, grant.Allow)
	}
	routes := false
	dials := false
	for _, action := range grant.Allow {
		routes = routes || action == protocol.AclAction_ACL_ACTION_ROUTE
		dials = dials || action == protocol.AclAction_ACL_ACTION_DIAL
	}
	for k, selector := range grant.Via {
		self.selector(rule, fmt.Sprintf("via[%d]", k), selector, aclPositionVia)
	}
	if grant.Via != nil && !routes {
		self.refuse(rule, "via", "a via on a rule that does not allow route")
	}
	if grant.Ip != nil {
		portable := false
		for _, resource := range grant.Dst {
			switch resource.Kind {
			case AclResourceSubject, AclResourceIp, AclResourceAll:
				portable = true
			}
		}
		if !portable || !(routes || dials) {
			self.refuse(rule, "ip", "ports on a rule with no subject or ip: destination to dial or route")
		}
	}
	if aclActionsHold(grant.Allow, protocol.AclAction_ACL_ACTION_PUBLISH) {
		if limits := self.input.Limits; limits != nil && !limits.StandingPublishes {
			self.refuse(rule, "allow", "a standing publish needs a Pro or Team document (§8.5)")
		}
	}
	if grant.AppMode == protocol.AclAppMode_ACL_APP_MODE_RAW {
		switch grant.Audience {
		case protocol.AclAudience_ACL_AUDIENCE_PUBLIC:
		case protocol.AclAudience_ACL_AUDIENCE_LINK:
			if grant.LinkSpkiSha256 == nil {
				self.refuse(rule, "link_spki_sha256", "a raw link with no pin (§13.7)")
			}
		default:
			self.refuse(rule, "app_mode", "raw outside audience public and link (§13.7)")
		}
	}
	if grant.Sock != nil {
		self.resource(rule, "sock", *grant.Sock, []protocol.AclAction{protocol.AclAction_ACL_ACTION_LISTEN})
	}
}

// One requests rule's checks.
func (self *aclValidator) request(rule string, request *AclRequest) {
	for k, selector := range request.Src {
		self.selector(rule, fmt.Sprintf("src[%d]", k), selector, aclPositionSrc)
	}
	for k, resource := range request.Dst {
		self.resource(rule, fmt.Sprintf("dst[%d]", k), resource, request.Allow)
	}
	for k, selector := range request.Approver {
		self.selector(rule, fmt.Sprintf("approver[%d]", k), selector, aclPositionApprover)
	}
	limits := self.input.Limits
	if limits == nil {
		return
	}
	if 2 <= request.Approvers && !limits.ApproversTwo {
		self.refuse(rule, "approvers", "two approvers need a Team document (acl_approvers_two)")
	}
	if aclActionsHold(request.Allow, protocol.AclAction_ACL_ACTION_PUBLISH) && 0 < limits.PublishMaxExpiry &&
		limits.PublishMaxExpiry < request.MaxExpiry {
		self.refuse(rule, "maxExpiry", "a publish lasting past this tier's limit (§13.9)")
	}
}

// Whether actions hold one.
func aclActionsHold(actions []protocol.AclAction, action protocol.AclAction) bool {
	for _, held := range actions {
		if held == action {
			return true
		}
	}
	return false
}

// One selector's checks at a position.
func (self *aclValidator) selector(rule string, field string, selector AclSelector, position aclPosition) {
	if !selector.fits(position) {
		self.refuse(rule, field, "a selector this position does not take")
		return
	}
	tables := self.tables
	limits := self.input.Limits
	switch selector.Kind {
	case AclSelectorTag:
		if _, found := tables.tagIds[selector.Name]; !found {
			self.refuse(rule, field, "a tag the tags file does not hold")
		}
		owned := false
		for _, tagOwner := range self.policy.TagOwners {
			owned = owned || tagOwner.Tag == selector
		}
		if !owned {
			self.refuse(rule, field, "a tag tagOwners does not list")
		}
	case AclSelectorGroup:
		if limits != nil && limits.Groups == 0 && rule != "groups" {
			self.refuse(rule, field, "this tier's documents hold no groups (acl_groups)")
		}
		if _, found := tables.groupIds[selector.Name]; !found {
			self.refuse(rule, field, "a group the groups file does not hold")
		}
		defined := strings.Contains(selector.Name, "@")
		for _, group := range self.policy.Groups {
			defined = defined || group.Group == selector
		}
		if !defined {
			self.refuse(rule, field, "a group no groups entry defines")
		}
	case AclSelectorUser:
		memberId, found := tables.memberIds[selector.Name]
		if !found {
			self.refuse(rule, field, "a user resolve does not hold")
		} else if tables.members[memberId] == nil {
			self.refuse(rule, field, "a user whose member the log no longer holds")
		}
	case AclSelectorClient:
		if _, found := tables.clientIds[selector.Id]; !found {
			self.refuse(rule, field, "a client resolve does not hold")
		}
	case AclSelectorNetwork:
		self.networkCount += 1
		if selector.Name == "*" {
			return
		}
		networkId, found := tables.networkIds[selector.Name]
		if !found {
			self.refuse(rule, field, "a network resolve does not hold")
			return
		}
		resolve := self.input.ResolveNetworkLabel
		if resolve == nil {
			self.refuse(rule, field, "a network: label, which resolves only once §12's labels do (D-DNS-2)")
			return
		}
		if resolved, ok := resolve(selector.Name); !ok || resolved != networkId {
			self.refuse(rule, field, "a network: that is no label or alias of the network resolve names (D-DNS-2)")
		}
	}
}

// One destination's checks, for a rule allowing actions.
func (self *aclValidator) resource(rule string, field string, resource AclResource, actions []protocol.AclAction) {
	switch resource.Kind {
	case AclResourceSubject:
		self.selector(rule, field, resource.Subject, aclPositionDst)
	case AclResourceSocket:
		first, _, _ := strings.Cut(resource.Name, "/")
		if strings.Contains(first, "*") {
			return
		}
		switch socketFirstSegmentNamespace(first) {
		case SocketNamespaceApplication, SocketNamespaceShare:
		case SocketNamespaceTls, SocketNamespaceSmtp:
			if host, ok := aclSocketHost(resource.Name); ok {
				self.scopeHost(rule, field, host)
			}
		default:
			self.refuse(rule, field, "a socket in a namespace no policy names (§9.4)")
		}
	case AclResourceDns:
		self.scopeHost(rule, field, resource.Name)
	case AclResourceRepo:
		if strings.ContainsAny(resource.Name, `/\`) {
			self.refuse(rule, field, "a path, which an evs: resource never is (X2)")
			return
		}
		for _, repoId := range self.repoIds(rule, field, resource) {
			kind, known := self.repoKinds[repoId]
			if !known {
				continue
			}
			self.repoKind(rule, field, kind, actions)
		}
	}
}

// A host's Team scope, when it names one: a scope the network's Team scopes hold, one label and never a glob, so never
// a client name, which no scope takes (§7.7, §13.8).
func (self *aclValidator) scopeHost(rule string, field string, host string) {
	scope, scoped := aclScopeOfHost(host)
	if !scoped {
		return
	}
	if strings.Contains(scope, "*") {
		self.refuse(rule, field, "a scope host's scope is one label, never a glob (Q-TLS-3)")
		return
	}
	if self.input.ResolveScope == nil {
		self.refuse(rule, field, "a scope host, which names a Team scope only once the network's scopes resolve (Q-TLS-3)")
		return
	}
	if _, found := self.input.ResolveScope(scope); !found {
		self.refuse(rule, field, "a scope the network's Team scopes do not hold (Q-TLS-3)")
	}
}

// The repos an evs: resource names, refusing a label the labels file does not hold. evs:* names none here: it reaches
// general and record repos alone (§8.4).
func (self *aclValidator) repoIds(rule string, field string, resource AclResource) []Id {
	switch {
	case resource.RepoId != (Id{}):
		return []Id{resource.RepoId}
	case resource.Name == "*":
		return nil
	case !strings.Contains(resource.Name, "*"):
		repoId, found := self.tables.labelRepoIds[resource.Name]
		if !found {
			self.refuse(rule, field, "a repo label the labels file does not hold")
			return nil
		}
		return []Id{repoId}
	}
	repoIds := []Id{}
	for _, label := range self.tables.labels {
		if aclGlobMatches(resource.Name, label) {
			repoIds = append(repoIds, self.tables.labelRepoIds[label])
		}
	}
	return repoIds
}

// A grant on one repo of a kind.
func (self *aclValidator) repoKind(rule string, field string, kind protocol.RepoKind, actions []protocol.AclAction) {
	switch kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_DIRECTORY:
		self.refuse(rule, field, "a grant on the config or the directory, whose readers the binary fixes (D-ACL-13, D-ACL-24)")
		return
	}
	if !aclRepoKindOwnerBound(kind) {
		return
	}
	kindDefault, _ := aclKindDefault(kind)
	for _, action := range actions {
		var rights AclEvsRights
		switch action {
		case protocol.AclAction_ACL_ACTION_DEPOSIT:
			rights = AclEvsDeposit
		case protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE, protocol.AclAction_ACL_ACTION_ADMIN:
			rights = AclEvsRead
		default:
			continue
		}
		if !kindDefault.DocumentRights.Has(rights) {
			self.refuse(rule, field, "an owner-bound repo's readers, which only its owner's EvsShare or the audit block add (owner decision 126)")
			return
		}
	}
}
