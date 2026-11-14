//go:build !sidecar_http && !ios_extension

// What a state's rules publish, for §21.6's hourly check (QD-770, question tls-m5-16-published-names-enumeration):
// AclState.PublishedNames lists every host and port the rules allow to be published, one name each, with the audience
// and expiry the gates enforce, by the one agreement rule PublishGrant reads (aclPublishRules, acl_gate_view.go).
//
//	names      every host a rule in force allowing publish names by a dns: pattern, and every host a tls/ name of a
//	           rule allowing publish or listen ends in, each on tlsedge's four ports and on every port a tls/ name
//	           spells out; a host keeps its glob as the document wrote it (*-preview, or * for every host)
//	publishers every sidecar the state admits that no hard deny holds at now: only a sidecar registers a tls/ name
//	per name   each publisher's reading by the agreement rule: its bound rules, or with none its host-only rules and a
//	           listen of its own; a name is listed when some publisher's reading takes it with the listen it needs,
//	           and a host-only reading with no listen gives nothing, as PublishGrant refuses it
//	agreed     every publisher's grant matches on audience, mode and pin: the name lists that audience, mode and pin
//	closed     one publisher's rules disagree, give raw where §13.9 refuses it, or two publishers' grants differ: the
//	           gates serve no such registration, or serve the name under more than one audience, and the name lists
//	           members-device, the closed audience, with no mode or pin
//	expiry     when the last rule any publisher reads for it ends; 0 when one has none. A rule past its expiry at now
//	           is in no class, so a name whose rules have all ended is not listed
//	system     tls/443/mta-sts stands on a receiver's smtp/25/mx listen grant (§13.9), public and http, as PublishGrant
//	           has it, whatever rules name that host there
//
// For a host with no glob the per-name reading is PublishGrant's to the byte, so a name lists what a gate answers each
// sidecar. A glob host is read by subsumption: a rule takes it only where it takes every host the glob names, as
// dns:* takes *-preview and tls/443/*-preview takes itself; a rule taking only part of it (dns:a*-preview) is left
// out of that name's reading, where it would still count for a registration it takes. Subsumption of two globs is
// read conservatively: only equal globs and a bare * take a glob.
//
// Pure over the state, and safe for concurrent use as the state is. It allocates as it lists, which no gate's hot path
// does: one pass costs a reading per name and publisher.

package sidecar

import (
	"bytes"
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The ports tlsedge serves and ValidateListen allows (owner decisions 68 and 121; §13.4, §13.9): facts of the edge, as
// ParseSocketName's tls/ form and tlsedgeservice's list hold them, not tunables. A name a rule spells with another port
// is listed on that port too, as PublishGrant reads it.
var aclPublishPorts = []int{443, 8443, 8883, 5671}

// One host and port a state's rules publish, as PublishedNames lists it. A copy, which the caller may keep.
type AclPublishedName struct {
	// @, one label or a scope host, as the rules name it, a glob kept.
	Host string
	Port int
	// Whether every grant the rules give the name agrees. False lists the closed audience: a publisher's rules
	// disagree, give raw under an audience §13.9 refuses it or a raw link with no pin, or two publishers' grants differ.
	Agreed bool
	// members, members-device, link or public: the grants' audience, or members-device where they do not agree.
	Audience protocol.AclAudience
	// http or raw, and a raw link's 32-byte pin, where the grants agree; unspecified and nil where they do not.
	AppMode        protocol.AclAppMode
	LinkSpkiSha256 []byte
	// Every rule any publisher's reading took, in rule order.
	GrantIds [][]byte
	// When the last of those rules ends, ms since the epoch; 0 for none.
	ExpiresMs int64
}

// Every host and port the rules allow to be published at now, in (host, port) order (the file header).
func (self *AclState) PublishedNames(now time.Time) []*AclPublishedName {
	nowMs := now.UnixMilli()
	subjects := make([]AclSubject, len(self.sidecars))
	publishers := make([]aclResolved, 0, len(self.sidecars))
	for i := range self.sidecars {
		subjects[i] = AclSidecarSubject(self.sidecars[i].id)
		if resolved := self.resolve(&subjects[i], nowMs); resolved.deny == 0 {
			publishers = append(publishers, resolved)
		}
	}
	names := []*AclPublishedName{}
	if name := self.systemPublishedName(publishers, nowMs); name != nil {
		names = append(names, name)
	}
	hosts, ports := self.publishedNameCandidates(nowMs)
	for _, host := range hosts {
		for _, port := range ports {
			socketName := "tls/" + strconv.Itoa(port) + "/" + host
			if socketName == aclSystemPublishName {
				// the system publish's, above
				continue
			}
			if name := self.publishedName(publishers, socketName, host, port, nowMs); name != nil {
				names = append(names, name)
			}
		}
	}
	slices.SortFunc(names, func(a *AclPublishedName, b *AclPublishedName) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port))
	})
	return names
}

// The hosts and ports a pass reads, each sorted and once: the file header's names.
func (self *AclState) publishedNameCandidates(nowMs int64) (hosts []string, ports []int) {
	hostSet := map[string]bool{}
	portSet := map[int]bool{}
	for _, port := range aclPublishPorts {
		portSet[port] = true
	}
	for i := range self.rules {
		rule := &self.rules[i]
		publishes := rule.allows(protocol.AclAction_ACL_ACTION_PUBLISH)
		if !rule.activeAt(nowMs) || (!publishes && !rule.allows(protocol.AclAction_ACL_ACTION_LISTEN)) {
			continue
		}
		for _, pattern := range rule.publicNames {
			if !strings.Contains(pattern, "/") {
				if publishes {
					hostSet[pattern] = true
				}
				continue
			}
			namespace, rest, _ := strings.Cut(pattern, "/")
			portText, host, found := strings.Cut(rest, "/")
			if namespace != "tls" || !found || host == "" || strings.Contains(host, "/") {
				continue
			}
			hostSet[host] = true
			// a port spelled out, in its one spelling; a glob's ports are the four above
			if port, err := strconv.ParseUint(portText, 10, 16); err == nil && strconv.FormatUint(port, 10) == portText {
				portSet[int(port)] = true
			}
		}
	}
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	for port := range portSet {
		ports = append(ports, port)
	}
	slices.Sort(hosts)
	slices.Sort(ports)
	return hosts, ports
}

// The name as the publishers' readings give it, nil when none of their rules takes it.
func (self *AclState) publishedName(publishers []aclResolved, socketName string, host string, port int, nowMs int64) *AclPublishedName {
	name := &AclPublishedName{Host: host, Port: port, Agreed: true}
	var ruleBits aclBits
	// the first grant read, which every other must match
	var agreedFirst *aclRule
	unbounded := false
	for i := range publishers {
		resolved := &publishers[i]
		rules := self.publishRules(resolved, socketName, host, nowMs, true)
		if rules.first == nil || !rules.listens {
			continue
		}
		if ruleBits == nil {
			ruleBits = make(aclBits, self.ruleWordCount)
		}
		self.publishClassRules(resolved, socketName, host, nowMs, rules.class, true, func(rule *aclRule) {
			ruleBits.set(rule.index)
		})
		if rules.expiresMs == 0 {
			unbounded = true
		} else if name.ExpiresMs < rules.expiresMs {
			name.ExpiresMs = rules.expiresMs
		}
		_, _, _, valid := aclPublishGrantFields(rules.first)
		switch {
		case !rules.agree || !valid:
			name.Agreed = false
		case agreedFirst == nil:
			agreedFirst = rules.first
		case !aclPublishRulesAgree(agreedFirst, rules.first):
			name.Agreed = false
		}
	}
	if ruleBits == nil {
		return nil
	}
	if unbounded {
		name.ExpiresMs = 0
	}
	if name.Agreed {
		audience, appMode, pin, _ := aclPublishGrantFields(agreedFirst)
		name.Audience, name.AppMode, name.LinkSpkiSha256 = audience, appMode, bytes.Clone(pin)
	} else {
		name.Audience = protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE
	}
	for index := range self.rules {
		if ruleBits.has(int32(index)) {
			name.GrantIds = append(name.GrantIds, bytes.Clone(self.rules[index].row.GetRuleId()))
		}
	}
	return name
}

// The system publish as the publishers hold it (§13.9): public and http while some publisher holds listen on
// smtp/25/mx, ending with the last such rule; nil while none does.
func (self *AclState) systemPublishedName(publishers []aclResolved, nowMs int64) *AclPublishedName {
	// tls/<port>/<host>
	_, rest, _ := strings.Cut(aclSystemPublishName, "/")
	portText, host, _ := strings.Cut(rest, "/")
	port, _ := strconv.Atoi(portText)
	name := &AclPublishedName{
		Host:     host,
		Port:     port,
		Agreed:   true,
		Audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC,
		AppMode:  protocol.AclAppMode_ACL_APP_MODE_HTTP,
	}
	var ruleBits aclBits
	unbounded := false
	for i := range publishers {
		rule := self.publicNameListenRule(&publishers[i], aclSystemPublishListen, nowMs, false)
		if rule == nil {
			continue
		}
		if ruleBits == nil {
			ruleBits = make(aclBits, self.ruleWordCount)
		}
		// PublishGrant names the first rule a receiver's listen check finds, as here
		ruleBits.set(rule.index)
		if rule.expiresMs == 0 {
			unbounded = true
		} else if name.ExpiresMs < rule.expiresMs {
			name.ExpiresMs = rule.expiresMs
		}
	}
	if ruleBits == nil {
		return nil
	}
	if unbounded {
		name.ExpiresMs = 0
	}
	for index := range self.rules {
		if ruleBits.has(int32(index)) {
			name.GrantIds = append(name.GrantIds, bytes.Clone(self.rules[index].row.GetRuleId()))
		}
	}
	return name
}

// Whether a dns pattern takes a host: aclDnsHostCovers, or with patterns, where the host may be a glob,
// aclDnsHostSubsumes.
func aclDnsHostTakes(pattern string, host string, patterns bool) bool {
	if patterns {
		return aclDnsHostSubsumes(pattern, host)
	}
	return aclDnsHostCovers(pattern, host)
}

// Whether a tls/ or smtp/ pattern takes a name: aclPublicSocketCovers, or with patterns, where the name's segments
// may be globs, aclPublicSocketSubsumes.
func aclPublicSocketTakes(pattern string, name string, patterns bool) bool {
	if patterns {
		return aclPublicSocketSubsumes(pattern, name)
	}
	return aclPublicSocketCovers(pattern, name)
}

// Whether a dns pattern takes every host a host glob names: aclDnsHostCovers for a host with no glob, and for a glob,
// a bare * or label by label, each of the pattern's labels taking the host's (aclGlobSubsumes).
func aclDnsHostSubsumes(pattern string, host string) bool {
	if !strings.Contains(host, "*") {
		return aclDnsHostCovers(pattern, host)
	}
	if pattern == "*" {
		return true
	}
	for {
		patternLabel, patternRest, patternMore := strings.Cut(pattern, ".")
		hostLabel, hostRest, hostMore := strings.Cut(host, ".")
		if !aclGlobSubsumes(patternLabel, hostLabel) {
			return false
		}
		if !patternMore || !hostMore {
			return patternMore == hostMore
		}
		pattern = patternRest
		host = hostRest
	}
}

// Whether a tls/ or smtp/ pattern takes every name a name glob names: aclPublicSocketCovers for a name with no glob,
// and for a glob, segment by segment as aclPublicSocketCovers reads them, a last segment of * taking every name below
// its prefix, each other segment taking the name's (aclGlobSubsumes).
func aclPublicSocketSubsumes(pattern string, name string) bool {
	if !strings.Contains(name, "*") {
		return aclPublicSocketCovers(pattern, name)
	}
	for {
		patternSegment, patternRest, patternMore := strings.Cut(pattern, "/")
		nameSegment, nameRest, nameMore := strings.Cut(name, "/")
		if !patternMore && patternSegment == "*" {
			return nameSegment != ""
		}
		if !aclGlobSubsumes(patternSegment, nameSegment) {
			return false
		}
		if !patternMore || !nameMore {
			return patternMore == nameMore
		}
		pattern = patternRest
		name = nameRest
	}
}

// Whether a glob takes every text another glob takes, read conservatively: the same glob, a bare *, or a text with no
// glob that it matches. Any other pair answers false, the narrower reading.
func aclGlobSubsumes(pattern string, text string) bool {
	switch {
	case pattern == text, pattern == "*":
		return true
	case !strings.Contains(text, "*"):
		return aclGlobMatches(pattern, text)
	}
	return false
}
