// §8.4's grammar: the selectors that name subjects and the resources a grant reaches. Parsing keeps
// positions apart, so a selector that means something only as an approver cannot stand in a src, and
// keeps the values typed, so nothing downstream reads a prefix out of a string.
//
// This is what a selector or resource says, not what it resolves to. Which subjects a selector holds
// is compiled from the config head (ACL-M2-04), and whether a document may use one is the writer's
// validation (ACL-M2-05). Readers parse every head that writers validated, so the grammar takes the
// whole of §8.4 from the start, a Team's scope hosts and SCIM's groups included: a reader on older code
// refusing them would fork from the rows a newer writer compiled.
//
// A refusal never repeats the text it refuses (I-13), since a name in a policy is member-chosen.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// §9.4's bounds on a socket name, so a policy cannot name what no listener can register.
const (
	aclSocketNameMaxByteCount    = 112
	aclSocketNameMaxSegmentCount = 8
	aclSocketSegmentMaxByteCount = 63
)

// The most a name holds: a dns label; a host, which sits in one socket segment and reaches at most
// <host>.<scope> (§9.4); a repo label, as a dns label does; §7.7's tag; and §15.8's local part.
const (
	aclDnsLabelMaxByteCount  = 63
	aclDnsHostMaxByteCount   = 63
	aclDnsHostMaxLabelCount  = 2
	aclRepoLabelMaxByteCount = 63
	aclTagMaxByteCount       = 50
	aclAliasMaxByteCount     = 64
)

// The bytes a name may hold, * standing for a glob where the grammar takes one.
const (
	aclLowerAlphanumerics = "abcdefghijklmnopqrstuvwxyz0123456789"
	aclTagAlphabet        = aclLowerAlphanumerics + "-"
	aclSocketAlphabet     = aclLowerAlphanumerics + "-_.@*/"
	aclRepoLabelAlphabet  = aclLowerAlphanumerics + "-_*"
	aclAliasAlphabet      = aclLowerAlphanumerics + "._-*"
)

// The IP protocol numbers §8.4's ports name. AclPortRange's protocol keeps the number, as
// protocol.AclPortRange does.
const (
	aclIpProtocolIcmp = 1
	aclIpProtocolTcp  = 6
	aclIpProtocolUdp  = 17
)

// What a selector names.
type AclSelectorKind int

const (
	// user:<email>, or a bare email where a position takes one
	AclSelectorUser AclSelectorKind = iota + 1
	// group:<name>, or SCIM's group:<name>@<domain>
	AclSelectorGroup
	// tag:<name>
	AclSelectorTag
	// sidecar:<id>, across client generations (D-ACL-14)
	AclSelectorSidecar
	// client:<id>, resolved through §5's binding
	AclSelectorClient
	// role:<name>, on Embed networks
	AclSelectorRole
	// principal:<name>, on Embed networks
	AclSelectorPrincipal
	// autogroup:<name>
	AclSelectorAutogroup
	// network:<net>, or network:* for every other network
	AclSelectorNetwork
)

// One subject selector (§8.4). Comparable, so a list of them can be searched.
type AclSelector struct {
	Kind AclSelectorKind
	// The email, lowercase as the server's user auth is, or the group, tag, role, principal or
	// network name without its prefix. Empty for the two id kinds and for an autogroup.
	Name string
	// AclSelectorSidecar's and AclSelectorClient's, never the zero id.
	Id Id
	// AclSelectorAutogroup's.
	Autogroup protocol.AclAutogroup
}

// Where a selector stands in a document, which decides what it may be. §8.4 writes its table for src
// and dst and notes the rest; the other positions name people or subjects as their sections need.
type aclPosition int

const (
	aclPositionSrc aclPosition = iota + 1
	aclPositionDst
	// a grant's via (§8.4)
	aclPositionVia
	// a requests rule's approver: people, since only a member approves (§16.6)
	aclPositionApprover
	// a tagOwners list: people, since a tag atom's owners expand to members
	aclPositionTagOwner
	// a groups list: groups are of members (§7.7)
	aclPositionGroupMember
	// the audit block's reader: a visible tag (owner decision 63)
	aclPositionAuditReader
	// a test's src, which §8.5's example writes as a bare email
	aclPositionTestSrc
)

// §8.4's autogroups by name. protocol.AclAutogroup numbers them for the rows.
var aclNameAutogroups = map[string]protocol.AclAutogroup{
	"member":    protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER,
	"owner":     protocol.AclAutogroup_ACL_AUTOGROUP_OWNER,
	"admin":     protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN,
	"auditor":   protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR,
	"sidecar":   protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR,
	"tagged":    protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED,
	"network":   protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK,
	"untagged":  protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED,
	"ephemeral": protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL,
	"public":    protocol.AclAutogroup_ACL_AUTOGROUP_PUBLIC,
	"internet":  protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET,
	"self":      protocol.AclAutogroup_ACL_AUTOGROUP_SELF,
	"sponsor":   protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR,
	"dst-owner": protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER,
}

// §8.4's text for this selector, which parses back to it.
func (self AclSelector) String() string {
	switch self.Kind {
	case AclSelectorUser:
		return "user:" + self.Name
	case AclSelectorGroup:
		return "group:" + self.Name
	case AclSelectorTag:
		return "tag:" + self.Name
	case AclSelectorSidecar:
		return "sidecar:" + self.Id.String()
	case AclSelectorClient:
		return "client:" + self.Id.String()
	case AclSelectorRole:
		return "role:" + self.Name
	case AclSelectorPrincipal:
		return "principal:" + self.Name
	case AclSelectorNetwork:
		return "network:" + self.Name
	case AclSelectorAutogroup:
		for name, autogroup := range aclNameAutogroups {
			if autogroup == self.Autogroup {
				return "autogroup:" + name
			}
		}
	}
	return ""
}

// Whether this selector means one or more members, and so may own a tag or approve.
func (self AclSelector) namesMembers() bool {
	switch self.Kind {
	case AclSelectorUser, AclSelectorGroup:
		return true
	case AclSelectorAutogroup:
		switch self.Autogroup {
		case protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, protocol.AclAutogroup_ACL_AUTOGROUP_OWNER,
			protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN, protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR:
			return true
		}
	}
	return false
}

// Whether this selector may stand in a position. §8.4's notes: autogroup:public and
// autogroup:ephemeral are src-only, autogroup:internet dst-only, autogroup:sponsor and
// autogroup:dst-owner approver-only, and autogroup:self both dst and approver.
func (self AclSelector) fits(position aclPosition) bool {
	autogroup := protocol.AclAutogroup_ACL_AUTOGROUP_UNSPECIFIED
	if self.Kind == AclSelectorAutogroup {
		autogroup = self.Autogroup
	}
	source := position == aclPositionSrc || position == aclPositionTestSrc
	switch position {
	case aclPositionGroupMember:
		return self.Kind == AclSelectorUser
	case aclPositionTagOwner:
		return self.namesMembers()
	case aclPositionAuditReader:
		return self.Kind == AclSelectorTag
	case aclPositionApprover:
		return self.namesMembers() ||
			autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_SELF ||
			autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR ||
			autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER
	}
	switch autogroup {
	case protocol.AclAutogroup_ACL_AUTOGROUP_PUBLIC, protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL:
		return source
	case protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET:
		return position == aclPositionDst
	case protocol.AclAutogroup_ACL_AUTOGROUP_SELF:
		return position == aclPositionDst || position == aclPositionVia
	case protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR, protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER:
		return false
	}
	if self.Kind == AclSelectorNetwork {
		// network:* holds no id, so only a src can say it: a dst names the network (§8.4's * row)
		return source || (position == aclPositionDst && self.Name != "*")
	}
	return true
}

// One selector's text, for a position.
func parseAclSelector(text string, position aclPosition) (AclSelector, error) {
	scheme, value, hasScheme := strings.Cut(text, ":")
	selector := AclSelector{}
	var err error
	switch {
	case !hasScheme:
		if position != aclPositionGroupMember && position != aclPositionTagOwner && position != aclPositionTestSrc {
			return AclSelector{}, aclPolicyRefusal("not a selector")
		}
		selector, err = parseAclUser(text)
	case scheme == "user":
		selector, err = parseAclUser(value)
	case scheme == "group":
		// §7.7's group:<name>, or SCIM's group:<name>@<domain>
		name, domain, hasDomain := strings.Cut(value, "@")
		if !aclIsName(name, "._-") || (hasDomain && !aclIsName(domain, ".-")) {
			return AclSelector{}, aclPolicyRefusal("not a group name")
		}
		selector = AclSelector{Kind: AclSelectorGroup, Name: value}
	case scheme == "tag":
		// §7.7's tag:[a-z0-9-]{1,50}
		if value == "" || aclTagMaxByteCount < len(value) || strings.Trim(value, aclTagAlphabet) != "" {
			return AclSelector{}, aclPolicyRefusal("not a tag name")
		}
		selector = AclSelector{Kind: AclSelectorTag, Name: value}
	case scheme == "sidecar":
		selector, err = parseAclIdSelector(AclSelectorSidecar, value)
	case scheme == "client":
		selector, err = parseAclIdSelector(AclSelectorClient, value)
	case scheme == "role":
		selector, err = parseAclOpaqueName(AclSelectorRole, value)
	case scheme == "principal":
		selector, err = parseAclOpaqueName(AclSelectorPrincipal, value)
	case scheme == "network":
		// §9.4's net, a dns label, or network:*, which §8.5's shares rule writes. No other glob: a label
		// resolves to one network (D-DNS-2), and a partial one to no set a compile could name.
		if value != "*" && !aclIsDnsLabel(value, false) {
			return AclSelector{}, aclPolicyRefusal("not a network label")
		}
		selector = AclSelector{Kind: AclSelectorNetwork, Name: value}
	case scheme == "autogroup":
		autogroup, known := aclNameAutogroups[value]
		if !known {
			return AclSelector{}, aclPolicyRefusal("an unknown autogroup")
		}
		selector = AclSelector{Kind: AclSelectorAutogroup, Autogroup: autogroup}
	default:
		return AclSelector{}, aclPolicyRefusal("not a selector")
	}
	if err != nil {
		return AclSelector{}, err
	}
	if !selector.fits(position) {
		return AclSelector{}, aclPolicyRefusal("a selector this position does not take")
	}
	return selector, nil
}

// An email, one @ between a local part and a domain, folded as server's NormalUserAuth folds it so an
// address compares equal however a document spells it.
func parseAclUser(email string) (AclSelector, error) {
	local, domain, hasDomain := strings.Cut(email, "@")
	if !hasDomain || local == "" || domain == "" || strings.Contains(domain, "@") {
		return AclSelector{}, aclPolicyRefusal("not an email")
	}
	for _, c := range email {
		if c <= ' ' || c == 0x7f || c == utf8.RuneError || strings.ContainsRune(`"(),:;<>[\]*#`, c) {
			return AclSelector{}, aclPolicyRefusal("not an email")
		}
	}
	return AclSelector{Kind: AclSelectorUser, Name: strings.ToLower(email)}, nil
}

// An id in either of ParseId's forms, which is never the zero id.
func parseAclIdSelector(kind AclSelectorKind, value string) (AclSelector, error) {
	id, err := ParseId(value)
	if err != nil || id == (Id{}) {
		return AclSelector{}, aclPolicyRefusal("not an id")
	}
	return AclSelector{Kind: kind, Id: id}, nil
}

// A role or principal, which the server holds as free text (server/model/network_client_model.go), so
// this refuses only what could not have been meant: nothing, and spaces or control characters.
func parseAclOpaqueName(kind AclSelectorKind, value string) (AclSelector, error) {
	if value == "" {
		return AclSelector{}, aclPolicyRefusal("no name")
	}
	for _, c := range value {
		if c <= ' ' || c == 0x7f || c == utf8.RuneError {
			return AclSelector{}, aclPolicyRefusal("not a name")
		}
	}
	return AclSelector{Kind: kind, Name: value}, nil
}

// What a resource names.
type AclResourceKind int

const (
	// a subject (§8.4); its ports, if any, are its grant's ip
	AclResourceSubject AclResourceKind = iota + 1
	// sock:<name>
	AclResourceSocket
	// ip:<cidr>, or ip:<name> for an entry in the document's hosts
	AclResourceIp
	// evs:<repo>, an id or a config label
	AclResourceRepo
	// dns:<host>
	AclResourceDns
	// mail:<alias>
	AclResourceMail
	// a bare *
	AclResourceAll
)

// One entry of a grant's dst (§8.4). In a Name, * stands for any run within one label or segment, and
// a bare * for all of a kind. Comparable, so a list of them can be searched.
type AclResource struct {
	Kind AclResourceKind
	// AclResourceSubject's.
	Subject AclSelector
	// The socket name, repo label, dns host, alias or hosts entry, canonical and without its prefix.
	// Empty for a repo named by id and an ip named by cidr.
	Name string
	// AclResourceRepo's when named by id.
	RepoId Id
	// AclResourceIp's, with its host bits clear. ParseAclPolicy fills it in from hosts for an ip named
	// by a hosts entry; parseAclResource alone leaves that one invalid.
	Cidr netip.Prefix
}

// §8.4's text for this resource, which parses back to it.
func (self AclResource) String() string {
	switch self.Kind {
	case AclResourceSubject:
		return self.Subject.String()
	case AclResourceSocket:
		return "sock:" + self.Name
	case AclResourceIp:
		if self.Name != "" {
			return "ip:" + self.Name
		}
		return "ip:" + self.Cidr.String()
	case AclResourceRepo:
		if self.RepoId != (Id{}) {
			return "evs:" + self.RepoId.String()
		}
		return "evs:" + self.Name
	case AclResourceDns:
		return "dns:" + self.Name
	case AclResourceMail:
		return "mail:" + self.Name
	case AclResourceAll:
		return "*"
	}
	return ""
}

// One dst's text. A subject here takes a dst's position, and ports are never part of it: §8.5 writes
// them once per rule, in ip, which is where §8.4's "optional ip ports" go.
func parseAclResource(text string) (AclResource, error) {
	if text == "*" {
		return AclResource{Kind: AclResourceAll}, nil
	}
	scheme, value, hasScheme := strings.Cut(text, ":")
	if !hasScheme {
		return AclResource{}, aclPolicyRefusal("not a resource")
	}
	switch scheme {
	case "sock":
		// §9.4's name with * allowed inside a segment. Uppercase ASCII folds, as §9.4 folds it, and only
		// ASCII: a Unicode fold would turn U+212A, which is no socket byte, into a k. A sock: resource is
		// this network's only, so §9.4's net: prefix has no place here, and its colon is refused with
		// every other byte. Which namespace a name is in matters to the compile, not to the grammar.
		canonical := []byte(value)
		for i, c := range canonical {
			if 'A' <= c && c <= 'Z' {
				canonical[i] = c - 'A' + 'a'
			}
		}
		name := string(canonical)
		if name == "" || aclSocketNameMaxByteCount < len(name) || strings.Trim(name, aclSocketAlphabet) != "" {
			return AclResource{}, aclPolicyRefusal("not a socket name")
		}
		segments := strings.Split(name, "/")
		if aclSocketNameMaxSegmentCount < len(segments) {
			return AclResource{}, aclPolicyRefusal("not a socket name")
		}
		for _, segment := range segments {
			if segment == "@" {
				continue
			}
			if segment == "" || segment == "." || segment == ".." || aclSocketSegmentMaxByteCount < len(segment) ||
				strings.Contains(segment, "@") {
				return AclResource{}, aclPolicyRefusal("not a socket name")
			}
		}
		return AclResource{Kind: AclResourceSocket, Name: name}, nil
	case "ip":
		// a cidr, or a name for the document's hosts to resolve
		if strings.ContainsAny(value, "/:.") {
			cidr, err := parseAclCidr(value)
			if err != nil {
				return AclResource{}, err
			}
			return AclResource{Kind: AclResourceIp, Cidr: cidr}, nil
		}
		if !aclIsDnsLabel(value, false) {
			return AclResource{}, aclPolicyRefusal("not a cidr or hosts name")
		}
		return AclResource{Kind: AclResourceIp, Name: value}, nil
	case "evs":
		// an id or a config label, and never a path: paths are encrypted and no rule may name one (X2).
		// So / and \ are refused by name, and a dot, which a label does not need, keeps file names and ..
		// out as well.
		if strings.ContainsAny(value, `/\`) {
			return AclResource{}, aclPolicyRefusal("a path, which an evs: resource never is (X2)")
		}
		if repoId, err := ParseId(value); err == nil {
			if repoId == (Id{}) {
				return AclResource{}, aclPolicyRefusal("not an id")
			}
			return AclResource{Kind: AclResourceRepo, RepoId: repoId}, nil
		}
		if value == "" || aclRepoLabelMaxByteCount < len(value) || value[0] == '-' || value[0] == '_' ||
			strings.Trim(value, aclRepoLabelAlphabet) != "" {
			return AclResource{}, aclPolicyRefusal("not a repo label")
		}
		return AclResource{Kind: AclResourceRepo, Name: value}, nil
	case "dns":
		// §8.4's host: @, one label, or <host>.<scope> in a Team scope, deeper names refused. A label may
		// hold *, and a bare * is every host.
		if value == "*" || value == "@" {
			return AclResource{Kind: AclResourceDns, Name: value}, nil
		}
		labels := strings.Split(value, ".")
		if aclDnsHostMaxByteCount < len(value) || aclDnsHostMaxLabelCount < len(labels) {
			return AclResource{}, aclPolicyRefusal("not a dns host")
		}
		for _, label := range labels {
			if !aclIsDnsLabel(label, true) {
				return AclResource{}, aclPolicyRefusal("not a dns host")
			}
		}
		return AclResource{Kind: AclResourceDns, Name: value}, nil
	case "mail":
		// §15.8's local part, [a-z0-9][a-z0-9._-]{0,63}, which may hold *
		if value == "" || aclAliasMaxByteCount < len(value) || value[0] == '.' || value[0] == '-' || value[0] == '_' ||
			strings.Trim(value, aclAliasAlphabet) != "" {
			return AclResource{}, aclPolicyRefusal("not a mail alias")
		}
		return AclResource{Kind: AclResourceMail, Name: value}, nil
	}
	subject, err := parseAclSelector(text, aclPositionDst)
	if err != nil {
		return AclResource{}, err
	}
	return AclResource{Kind: AclResourceSubject, Subject: subject}, nil
}

// One canonical range. One with host bits set is refused and not masked, since it may mean either its
// network or its one address, and an IPv4-mapped one because no IPv4 rule or comparison would see it.
func parseAclCidr(value string) (netip.Prefix, error) {
	cidr, err := netip.ParsePrefix(value)
	if err != nil || cidr.Addr().Is4In6() || cidr.Masked() != cidr {
		return netip.Prefix{}, aclPolicyRefusal("not a cidr")
	}
	return cidr, nil
}

// Whether this dst reaches a concrete socket, repo label, dns host or alias, as §8.4's * reads: * stays
// within a label or segment, and a bare * takes all of a kind. A dst of one kind reaches only that kind.
// A subject or ip range is the compile's to expand, so those answer false, as a pattern in concrete
// does.
//
// A socket's last segment of a bare * is the one thing wider: it takes every name below its prefix,
// since sock:tls/* has to reach tls/443/blog (§8.5) and AclTarget.socket_prefix carries such a prefix.
// Where a glob stands in the first segment it stays among application sockets, and so does a bare *
// dst, because §8.4 has tls/ and smtp/ named outright: a self-approved sock:* must not reach what
// §8.5's admin-approved rule holds. share/ counts as application here (SOCK-M5-15).
//
// A repo's kind is not in its label, so this says nothing about §8.5's kinds that * never matches.
// AclState holds that rule (ACL-M2-02).
func (self AclResource) covers(concrete AclResource) bool {
	if strings.Contains(concrete.Name, "*") || (concrete.Name == "" && concrete.RepoId == (Id{})) {
		return false
	}
	// A concrete socket is a canonical name, folded as §9.4 folds it. An unfolded TLS/443/x is tls/443/x,
	// and its first segment would read as an application name that a glob reaches, so it matches nothing.
	if concrete.Kind == AclResourceSocket && strings.Trim(concrete.Name, aclSocketAlphabet) != "" {
		return false
	}
	if self.Kind == AclResourceAll {
		switch concrete.Kind {
		case AclResourceSocket:
			return !aclSocketMustBeNamed(concrete.Name)
		case AclResourceRepo:
			return true
		}
		return false
	}
	if self.Kind != concrete.Kind {
		return false
	}
	switch self.Kind {
	case AclResourceSocket:
		patternSegments := strings.Split(self.Name, "/")
		nameSegments := strings.Split(concrete.Name, "/")
		if strings.Contains(patternSegments[0], "*") && aclSocketMustBeNamed(concrete.Name) {
			return false
		}
		matchCount := len(patternSegments)
		if patternSegments[matchCount-1] == "*" {
			matchCount -= 1
			if len(nameSegments) <= matchCount {
				return false
			}
		} else if len(nameSegments) != matchCount {
			return false
		}
		for i := range matchCount {
			if !aclGlobMatches(patternSegments[i], nameSegments[i]) {
				return false
			}
		}
		return true
	case AclResourceRepo:
		if self.Name != "*" && (self.RepoId != (Id{}) || concrete.RepoId != (Id{})) {
			return self.RepoId == concrete.RepoId
		}
		return aclGlobMatches(self.Name, concrete.Name)
	case AclResourceMail:
		return aclGlobMatches(self.Name, concrete.Name)
	case AclResourceDns:
		// label by label, so dns:*.<scope> covers one scope and dns:*-preview no scope at all
		if self.Name == "*" {
			return true
		}
		patternLabels := strings.Split(self.Name, ".")
		hostLabels := strings.Split(concrete.Name, ".")
		if len(patternLabels) != len(hostLabels) {
			return false
		}
		for i, patternLabel := range patternLabels {
			if !aclGlobMatches(patternLabel, hostLabels[i]) {
				return false
			}
		}
		return true
	}
	return false
}

// Whether a socket's namespace keeps it from every glob: all but application names and share/. A policy
// reaches tls/ and smtp/ only by writing them out, and the rest it never reaches. This reads §9.4's own
// namespaces, so a first segment a later §9 reserves stays out of a glob's reach with no change here.
func aclSocketMustBeNamed(name string) bool {
	first, _, _ := strings.Cut(name, "/")
	if first == "" {
		return true
	}
	namespace := socketFirstSegmentNamespace(first)
	return namespace != SocketNamespaceApplication && namespace != SocketNamespaceShare
}

// Whether text matches pattern, each * taking any run of bytes, an empty one included. Both are one
// label or segment, so the backtracking stays within 64 bytes.
func aclGlobMatches(pattern string, text string) bool {
	patternIndex := 0
	textIndex := 0
	starIndex := -1
	starTextIndex := 0
	for textIndex < len(text) {
		switch {
		case patternIndex < len(pattern) && pattern[patternIndex] == '*':
			starIndex = patternIndex
			starTextIndex = textIndex
			patternIndex += 1
		case patternIndex < len(pattern) && pattern[patternIndex] == text[textIndex]:
			patternIndex += 1
			textIndex += 1
		case 0 <= starIndex:
			starTextIndex += 1
			textIndex = starTextIndex
			patternIndex = starIndex + 1
		default:
			return false
		}
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex += 1
	}
	return patternIndex == len(pattern)
}

// A port range of §8.4's ip field, as protocol.AclPortRange carries it.
type AclPortRange struct {
	// The IP protocol number; 0 any.
	Protocol uint32
	First    uint32
	Last     uint32
}

// One entry of an ip field: *, a port or range, or either after tcp:, udp: or icmp:, whose only form
// is icmp:*. A range is first-last, first at most last, with no port 0 and no leading zero.
func parseAclPortRange(text string) (AclPortRange, error) {
	ports := AclPortRange{}
	if name, rest, hasProtocol := strings.Cut(text, ":"); hasProtocol {
		switch name {
		case "tcp":
			ports.Protocol = aclIpProtocolTcp
		case "udp":
			ports.Protocol = aclIpProtocolUdp
		case "icmp":
			if rest != "*" {
				return AclPortRange{}, aclPolicyRefusal("ports on icmp")
			}
			ports.Protocol = aclIpProtocolIcmp
		default:
			return AclPortRange{}, aclPolicyRefusal("an unknown ip protocol")
		}
		text = rest
	}
	if text == "*" {
		ports.Last = 65535
		return ports, nil
	}
	// one port, 1 to 65535, in digits with no leading zero
	parsePort := func(portText string) (uint32, error) {
		if portText == "" || portText[0] == '0' {
			return 0, aclPolicyRefusal("not a port")
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return 0, aclPolicyRefusal("not a port")
		}
		return uint32(port), nil
	}
	firstText, lastText, isRange := strings.Cut(text, "-")
	if !isRange {
		lastText = firstText
	}
	var err error
	if ports.First, err = parsePort(firstText); err != nil {
		return AclPortRange{}, err
	}
	if ports.Last, err = parsePort(lastText); err != nil {
		return AclPortRange{}, err
	}
	if ports.Last < ports.First {
		return AclPortRange{}, aclPolicyRefusal("a port range running backward")
	}
	return ports, nil
}

// Whether a byte is [a-z0-9].
func aclIsLowerAlphanumeric(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9'
}

// Whether text starts and ends with [a-z0-9] and holds nothing else but those and the extra bytes.
func aclIsName(text string, extra string) bool {
	if text == "" || !aclIsLowerAlphanumeric(text[0]) || !aclIsLowerAlphanumeric(text[len(text)-1]) {
		return false
	}
	for i := 0; i < len(text); i += 1 {
		if !aclIsLowerAlphanumeric(text[i]) && !strings.ContainsRune(extra, rune(text[i])) {
			return false
		}
	}
	return true
}

// Whether text is one lowercase LDH label, which with glob may also hold *. A hyphen never starts or
// ends one, whatever a * beside it might stand for.
func aclIsDnsLabel(text string, glob bool) bool {
	if text == "" || aclDnsLabelMaxByteCount < len(text) || text[0] == '-' || text[len(text)-1] == '-' {
		return false
	}
	for i := 0; i < len(text); i += 1 {
		if c := text[i]; !aclIsLowerAlphanumeric(c) && c != '-' && !(glob && c == '*') {
			return false
		}
	}
	return true
}
