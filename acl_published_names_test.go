//go:build !sidecar_http && !ios_extension

// AclState.PublishedNames on T2's hand-made rows (QD-770): every name the rules publish listed once, with the audience
// and expiry PublishGrant gives every sidecar for it; rules that disagree, in one sidecar's reading or between two
// sidecars', and raw that §13.9 refuses listed as the closed audience; an expired grant, a revoked or lapsed publisher
// and a publish with no listen listing nothing; the system publish on a receiver's listen grant; glob hosts read by
// subsumption; and the ports read held to ParseSocketName's.

package sidecar

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A rule of one sidecar's on public names, publish and listen unless actions are given, with a publish's fields and
// an expiry, zero for none.
func aclPublishedNamesRule(fixture *aclTestFixture, sidecarId Id, names []string, audience protocol.AclAudience, appMode protocol.AclAppMode,
	pin []byte, expires time.Time, actions ...protocol.AclAction) *protocol.AclRule {
	targets := []*protocol.AclTarget{}
	for _, name := range names {
		targets = append(targets, &protocol.AclTarget{PublicName: name})
	}
	if len(actions) == 0 {
		actions = []protocol.AclAction{protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN}
	}
	rule := fixture.rule([]Id{fixture.sidecarAtom(sidecarId)}, targets, actions...)
	rule.Audience, rule.AppMode, rule.LinkSpkiSha256 = audience, appMode, pin
	if !expires.IsZero() {
		rule.Expires = expires.UnixMilli()
	}
	return rule
}

// What a test expects of one listed name.
type aclPublishedNamesWant struct {
	host      string
	port      int
	agreed    bool
	audience  protocol.AclAudience
	appMode   protocol.AclAppMode
	expiresMs int64
}

// The listing against want, name by name, and each name's fields.
func aclPublishedNamesCheck(t *testing.T, names []*AclPublishedName, want []aclPublishedNamesWant) {
	t.Helper()
	if len(names) != len(want) {
		listed := []string{}
		for _, name := range names {
			listed = append(listed, name.Host+":"+strconv.Itoa(name.Port))
		}
		t.Fatalf("listed %d names %v, want %d", len(names), listed, len(want))
	}
	for i, name := range names {
		w := want[i]
		if name.Host != w.host || name.Port != w.port || name.Agreed != w.agreed || name.Audience != w.audience ||
			name.AppMode != w.appMode || name.ExpiresMs != w.expiresMs || len(name.GrantIds) == 0 {
			t.Errorf("name %d: %s:%d agreed %t %s %s expires %d with %d rules, want %+v", i, name.Host, name.Port, name.Agreed,
				name.Audience, name.AppMode, name.ExpiresMs, len(name.GrantIds), w)
		}
		if !name.Agreed && (name.Audience != protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE || name.AppMode != protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED ||
			name.LinkSpkiSha256 != nil) {
			t.Errorf("%s:%d disagrees and lists %s %s %x", name.Host, name.Port, name.Audience, name.AppMode, name.LinkSpkiSha256)
		}
	}
}

// For every sidecar and every tls/ name, each grant PublishGrant gives is listed: its rules among the name's, its
// expiry within the name's, and where the name agrees, its audience, mode and pin. An agreed name is exactly its
// grants: every rule of theirs, and the last of their expiries.
func aclPublishedNamesAgree(t *testing.T, state *AclState, sidecarIds []Id, socketNames []string) {
	t.Helper()
	listed := map[string]*AclPublishedName{}
	for _, name := range state.PublishedNames(aclTestNow) {
		socketName := "tls/" + strconv.Itoa(name.Port) + "/" + name.Host
		if listed[socketName] != nil {
			t.Fatalf("%s listed twice", socketName)
		}
		listed[socketName] = name
	}
	modes := []protocol.AclAppMode{protocol.AclAppMode_ACL_APP_MODE_HTTP, protocol.AclAppMode_ACL_APP_MODE_RAW}
	for _, socketName := range socketNames {
		name := listed[socketName]
		grantIds := [][]byte{}
		grantCount := 0
		unbounded, lastExpiresMs := false, int64(0)
		for _, sidecarId := range sidecarIds {
			for _, mode := range modes {
				grant, decision := state.PublishGrant(AclSidecarSubject(sidecarId), socketName, mode, aclTestNow)
				if !decision.Allowed {
					continue
				}
				grantCount += 1
				if name == nil {
					t.Errorf("%s: %s holds a grant, and the name is not listed", socketName, sidecarId)
					continue
				}
				for _, grantId := range grant.GrantIds {
					if !slices.ContainsFunc(name.GrantIds, func(listedId []byte) bool { return bytes.Equal(listedId, grantId) }) {
						t.Errorf("%s: a rule of %s's grant is not listed", socketName, sidecarId)
					}
					if !slices.ContainsFunc(grantIds, func(seenId []byte) bool { return bytes.Equal(seenId, grantId) }) {
						grantIds = append(grantIds, grantId)
					}
				}
				if grant.ExpiresMs == 0 {
					unbounded = true
					if name.ExpiresMs != 0 {
						t.Errorf("%s: %s's grant has no end, and the name ends at %d", socketName, sidecarId, name.ExpiresMs)
					}
				} else {
					lastExpiresMs = max(lastExpiresMs, grant.ExpiresMs)
					if name.ExpiresMs != 0 && name.ExpiresMs < grant.ExpiresMs {
						t.Errorf("%s: %s's grant ends at %d, after the name's %d", socketName, sidecarId, grant.ExpiresMs, name.ExpiresMs)
					}
				}
				if name.Agreed && (name.Audience != grant.Audience || name.AppMode != grant.AppMode || !bytes.Equal(name.LinkSpkiSha256, grant.LinkSpkiSha256)) {
					t.Errorf("%s: listed %s %s, and %s's grant is %s %s", socketName, name.Audience, name.AppMode, sidecarId, grant.Audience, grant.AppMode)
				}
			}
		}
		if name == nil || !name.Agreed {
			continue
		}
		if grantCount == 0 {
			t.Errorf("%s: listed as agreed, and no sidecar holds a grant", socketName)
			continue
		}
		if len(grantIds) != len(name.GrantIds) {
			t.Errorf("%s: listed %d rules, and the grants hold %d", socketName, len(name.GrantIds), len(grantIds))
		}
		if wantExpiresMs := lastExpiresMs; (unbounded && name.ExpiresMs != 0) || (!unbounded && name.ExpiresMs != wantExpiresMs) {
			t.Errorf("%s: listed to end at %d, and the grants' last ends at %d (unbounded %t)", socketName, name.ExpiresMs, wantExpiresMs, unbounded)
		}
	}
}

// Every tls/ name a test's rules name: each host a rule names, on the ports the listing reads and each port a rule
// spells out, with no glob, as a registration names it.
func aclPublishedNamesSockets(fixture *aclTestFixture, extraHosts ...string) []string {
	hosts := slices.Clone(extraHosts)
	ports := slices.Clone(aclPublishPorts)
	for _, rule := range fixture.rows.Rules {
		for _, target := range rule.Targets {
			name := target.GetPublicName()
			if name == "" || strings.Contains(name, "*") {
				continue
			}
			if !strings.Contains(name, "/") {
				hosts = append(hosts, name)
				continue
			}
			segments := strings.Split(name, "/")
			if len(segments) != 3 || segments[0] != "tls" {
				continue
			}
			hosts = append(hosts, segments[2])
			if port, err := strconv.Atoi(segments[1]); err == nil {
				ports = append(ports, port)
			}
		}
	}
	socketNames := []string{}
	for _, host := range hosts {
		for _, port := range ports {
			socketName := "tls/" + strconv.Itoa(port) + "/" + host
			if !slices.Contains(socketNames, socketName) {
				socketNames = append(socketNames, socketName)
			}
		}
	}
	return socketNames
}

// The listing of a network with publishers in each form, against what PublishGrant answers every sidecar for every
// name the rules name.
func TestAclPublishedNamesAgreeWithPublishGrant(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	listener, second, receiver := fixture.device(owner), fixture.device(owner), fixture.device(owner)
	revoked, lapsed, stranger := fixture.device(owner), fixture.device(owner), fixture.device(owner)
	fixture.admission(revoked).Row.RevokedAt = fixture.next()
	fixture.admission(lapsed).Row.NotAfter = aclTestNow.UnixMilli()

	members, membersDevice := protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE
	link, public := protocol.AclAudience_ACL_AUDIENCE_LINK, protocol.AclAudience_ACL_AUDIENCE_PUBLIC
	unspecified := protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED
	http, raw := protocol.AclAppMode_ACL_APP_MODE_HTTP, protocol.AclAppMode_ACL_APP_MODE_RAW
	publish, listen := protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN
	pin := bytes.Repeat([]byte{0x5a}, 32)
	hour := aclTestNow.Add(time.Hour)
	twoHours := aclTestNow.Add(2 * time.Hour)
	threeHours := aclTestNow.Add(3 * time.Hour)
	never := time.Time{}
	rule := func(sidecarId Id, host string, port int, audience protocol.AclAudience, appMode protocol.AclAppMode, pin []byte, expires time.Time) {
		aclPublishedNamesRule(fixture, sidecarId, []string{host, "tls/" + strconv.Itoa(port) + "/" + host}, audience, appMode, pin, expires)
	}

	rule(listener, "blog", 443, public, http, nil, never)
	rule(listener, "@", 443, unspecified, protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED, nil, never)
	// a host-only publish takes its port from a listen rule of its own; one with no listen publishes nothing
	aclPublishedNamesRule(fixture, listener, []string{"split"}, public, http, nil, never, publish)
	aclPublishedNamesRule(fixture, listener, []string{"tls/8443/split"}, unspecified, 0, nil, never, listen)
	aclPublishedNamesRule(fixture, listener, []string{"no-listen"}, public, http, nil, never, publish)
	// one sidecar's rules that disagree, and raw that §13.9 refuses
	rule(listener, "disagree", 443, public, http, nil, never)
	rule(listener, "disagree", 443, members, http, nil, never)
	rule(listener, "raw-members", 443, members, raw, nil, never)
	rule(listener, "raw-link", 443, link, raw, nil, never)
	rule(listener, "raw-pinned", 443, link, raw, pin, never)
	// expiries: past, one ending, the later of two, and none beside one
	rule(listener, "expired", 443, public, http, nil, aclTestNow.Add(-time.Second))
	rule(listener, "ending", 443, members, http, nil, hour)
	rule(listener, "twice", 443, public, http, nil, hour)
	rule(second, "twice", 443, public, http, nil, twoHours)
	rule(listener, "both", 443, public, http, nil, never)
	rule(second, "both", 443, public, http, nil, hour)
	// two sidecars' grants that differ
	rule(listener, "shared", 443, public, http, nil, never)
	rule(second, "shared", 443, members, http, nil, never)
	// the closed audience granted as itself, which agrees
	rule(second, "devices", 8883, membersDevice, http, nil, never)
	// a port spelled out that no edge serves, as PublishGrant reads it
	rule(listener, "odd", 9443, public, http, nil, never)
	// publishers no name may stand on
	rule(revoked, "gone", 443, public, http, nil, never)
	rule(lapsed, "lapsed", 443, public, http, nil, never)
	// the system publish on the receiver's listen grant; a document's own rule for its host is not read
	aclPublishedNamesRule(fixture, receiver, []string{"smtp/25/mx"}, unspecified, 0, nil, threeHours, listen)
	rule(listener, "mta-sts", 443, members, http, nil, never)
	state := fixture.state(t)

	none := protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED
	aclPublishedNamesCheck(t, state.PublishedNames(aclTestNow), []aclPublishedNamesWant{
		{host: "@", port: 443, agreed: true, audience: members, appMode: http},
		{host: "blog", port: 443, agreed: true, audience: public, appMode: http},
		{host: "both", port: 443, agreed: true, audience: public, appMode: http},
		{host: "devices", port: 8883, agreed: true, audience: membersDevice, appMode: http},
		{host: "disagree", port: 443, audience: membersDevice, appMode: none},
		{host: "ending", port: 443, agreed: true, audience: members, appMode: http, expiresMs: hour.UnixMilli()},
		{host: "mta-sts", port: 443, agreed: true, audience: public, appMode: http, expiresMs: threeHours.UnixMilli()},
		{host: "odd", port: 9443, agreed: true, audience: public, appMode: http},
		{host: "raw-link", port: 443, audience: membersDevice, appMode: none},
		{host: "raw-members", port: 443, audience: membersDevice, appMode: none},
		{host: "raw-pinned", port: 443, agreed: true, audience: link, appMode: raw},
		{host: "shared", port: 443, audience: membersDevice, appMode: none},
		{host: "split", port: 8443, agreed: true, audience: public, appMode: http},
		{host: "twice", port: 443, agreed: true, audience: public, appMode: http, expiresMs: twoHours.UnixMilli()},
	})
	for _, name := range state.PublishedNames(aclTestNow) {
		if name.Host == "raw-pinned" && !bytes.Equal(name.LinkSpkiSha256, pin) {
			t.Errorf("the pinned grant lists pin %x", name.LinkSpkiSha256)
		}
	}

	sidecarIds := []Id{listener, second, receiver, revoked, lapsed, stranger}
	aclPublishedNamesAgree(t, state, sidecarIds, aclPublishedNamesSockets(fixture, "elsewhere"))
}

// A name lists the rules of every reading that took it, the closed ones' included, and nothing of a rule that took
// none: a sidecar's rules binding another port, its host-only rule beside a bound one, and a rule past its expiry.
func TestAclPublishedNamesListTheRulesTheReadingsTook(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	listener, second := fixture.device(owner), fixture.device(owner)
	public, members := protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAudience_ACL_AUDIENCE_MEMBERS
	http := protocol.AclAppMode_ACL_APP_MODE_HTTP
	publish := protocol.AclAction_ACL_ACTION_PUBLISH
	never := time.Time{}
	bound := aclPublishedNamesRule(fixture, listener, []string{"blog", "tls/443/blog"}, public, http, nil, never)
	// a host-only rule of the same sidecar, which its bound rule takes precedence over
	hostOnly := aclPublishedNamesRule(fixture, listener, []string{"blog"}, members, http, nil, never, publish)
	otherPort := aclPublishedNamesRule(fixture, listener, []string{"blog", "tls/8443/blog"}, members, http, nil, never)
	expired := aclPublishedNamesRule(fixture, listener, []string{"blog", "tls/443/blog"}, members, http, nil, aclTestNow.Add(-time.Millisecond))
	disagreeing := aclPublishedNamesRule(fixture, second, []string{"blog", "tls/443/blog"}, members, http, nil, never)
	state := fixture.state(t)

	names := state.PublishedNames(aclTestNow)
	var blog443, blog8443 *AclPublishedName
	for _, name := range names {
		switch {
		case name.Host == "blog" && name.Port == 443:
			blog443 = name
		case name.Host == "blog" && name.Port == 8443:
			blog8443 = name
		}
	}
	if blog443 == nil || blog8443 == nil {
		t.Fatalf("listed %d names, and not both of blog's", len(names))
	}
	holds := func(name *AclPublishedName, rule *protocol.AclRule) bool {
		return slices.ContainsFunc(name.GrantIds, func(grantId []byte) bool { return bytes.Equal(grantId, rule.RuleId) })
	}
	if !holds(blog443, bound) || !holds(blog443, disagreeing) || holds(blog443, hostOnly) || holds(blog443, otherPort) || holds(blog443, expired) ||
		len(blog443.GrantIds) != 2 {
		t.Errorf("blog on 443 lists %d rules", len(blog443.GrantIds))
	}
	if blog443.Agreed {
		t.Error("blog on 443 agrees, and its two sidecars' grants differ")
	}
	// on 8443 the listener's bound rule there decides, and the second sidecar binds only 443
	if !holds(blog8443, otherPort) || len(blog8443.GrantIds) != 1 || !blog8443.Agreed || blog8443.Audience != members {
		t.Errorf("blog on 8443: agreed %t %s with %d rules", blog8443.Agreed, blog8443.Audience, len(blog8443.GrantIds))
	}
	aclPublishedNamesAgree(t, state, []Id{listener, second}, aclPublishedNamesSockets(fixture))
}

// A grant whose rules have all ended is listed by no pass after its end, and a pass before it lists it to that end.
func TestAclPublishedNamesDropAnEndedGrant(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	listener := fixture.device(owner)
	ends := aclTestNow.Add(time.Minute)
	aclPublishedNamesRule(fixture, listener, []string{"blog", "tls/443/blog"}, protocol.AclAudience_ACL_AUDIENCE_PUBLIC,
		protocol.AclAppMode_ACL_APP_MODE_HTTP, nil, ends)
	state := fixture.state(t)
	before := state.PublishedNames(ends.Add(-time.Millisecond))
	if len(before) != 1 || before[0].ExpiresMs != ends.UnixMilli() {
		t.Fatalf("before its end: %d names", len(before))
	}
	if after := state.PublishedNames(ends); len(after) != 0 {
		t.Fatalf("at its end: %d names", len(after))
	}
	if _, decision := state.PublishGrant(AclSidecarSubject(listener), "tls/443/blog", protocol.AclAppMode_ACL_APP_MODE_HTTP, ends); decision.Allowed {
		t.Fatal("a gate allowed the ended grant")
	}
}

// Glob hosts are listed as the rules write them, each read by the rules that take every host it names: a bound glob,
// a trailing tls/* over the four ports, a concrete host a listen rule names under a host-only dns:*, and a narrower
// glob read apart from the wider one.
func TestAclPublishedNamesGlobHosts(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	previewer, any, scoped := fixture.device(owner), fixture.device(owner), fixture.device(owner)
	public, members := protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAudience_ACL_AUDIENCE_MEMBERS
	http := protocol.AclAppMode_ACL_APP_MODE_HTTP
	publish, listen := protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN
	never := time.Time{}
	aclPublishedNamesRule(fixture, previewer, []string{"*-preview", "tls/443/*-preview"}, members, http, nil, never)
	aclPublishedNamesRule(fixture, previewer, []string{"a*-preview", "tls/443/a*-preview"}, public, http, nil, never)
	aclPublishedNamesRule(fixture, any, []string{"*"}, public, http, nil, never, publish)
	aclPublishedNamesRule(fixture, any, []string{"tls/8443/api"}, public, http, nil, never, listen)
	aclPublishedNamesRule(fixture, scoped, []string{"*.team", "tls/*"}, public, http, nil, never)
	state := fixture.state(t)

	want := []aclPublishedNamesWant{
		{host: "*-preview", port: 443, agreed: true, audience: members, appMode: http},
	}
	for _, port := range []int{443, 5671, 8443, 8883} {
		want = append(want, aclPublishedNamesWant{host: "*.team", port: port, agreed: true, audience: public, appMode: http})
	}
	want = append(want,
		aclPublishedNamesWant{host: "a*-preview", port: 443, agreed: true, audience: public, appMode: http},
		aclPublishedNamesWant{host: "api", port: 8443, agreed: true, audience: public, appMode: http},
	)
	aclPublishedNamesCheck(t, state.PublishedNames(aclTestNow), want)
	aclPublishedNamesAgree(t, state, []Id{previewer, any, scoped}, aclPublishedNamesSockets(fixture))
}

// Subsumption reads a name with no glob as a gate does, and a glob only by a pattern that takes all of it.
func TestAclPublishedNamesSubsumption(t *testing.T) {
	hostCases := []struct {
		pattern string
		host    string
		takes   bool
	}{
		{pattern: "blog", host: "blog", takes: true},
		{pattern: "b*", host: "blog", takes: true},
		{pattern: "blog", host: "*", takes: false},
		{pattern: "*", host: "*", takes: true},
		{pattern: "*", host: "*-preview", takes: true},
		{pattern: "*", host: "*.team", takes: true},
		{pattern: "*-preview", host: "*-preview", takes: true},
		{pattern: "*-preview", host: "a*-preview", takes: false},
		{pattern: "a*-preview", host: "*-preview", takes: false},
		{pattern: "*.team", host: "*.team", takes: true},
		{pattern: "*.team", host: "*", takes: false},
		{pattern: "*.team", host: "x.*", takes: false},
	}
	for _, c := range hostCases {
		if takes := aclDnsHostSubsumes(c.pattern, c.host); takes != c.takes {
			t.Errorf("dns %q takes %q: %t", c.pattern, c.host, takes)
		}
		if !strings.Contains(c.host, "*") && aclDnsHostSubsumes(c.pattern, c.host) != aclDnsHostCovers(c.pattern, c.host) {
			t.Errorf("dns %q reads %q apart from a gate", c.pattern, c.host)
		}
	}
	socketCases := []struct {
		pattern string
		name    string
		takes   bool
	}{
		{pattern: "tls/443/blog", name: "tls/443/blog", takes: true},
		{pattern: "tls/*/blog", name: "tls/8443/blog", takes: true},
		{pattern: "tls/*", name: "tls/443/*", takes: true},
		{pattern: "tls/443/*", name: "tls/443/*-preview", takes: true},
		{pattern: "tls/443/*-preview", name: "tls/443/*-preview", takes: true},
		{pattern: "tls/443/blog", name: "tls/443/*", takes: false},
		{pattern: "tls/8443/*", name: "tls/443/*", takes: false},
		{pattern: "smtp/25/mx", name: "tls/443/*", takes: false},
	}
	for _, c := range socketCases {
		if takes := aclPublicSocketSubsumes(c.pattern, c.name); takes != c.takes {
			t.Errorf("socket %q takes %q: %t", c.pattern, c.name, takes)
		}
		if !strings.Contains(c.name, "*") && aclPublicSocketSubsumes(c.pattern, c.name) != aclPublicSocketCovers(c.pattern, c.name) {
			t.Errorf("socket %q reads %q apart from a gate", c.pattern, c.name)
		}
	}
}

// The four ports a pass reads are exactly those ParseSocketName's tls/ form takes, so the copy cannot drift.
func TestAclPublishPortsAreTheTlsNamesPorts(t *testing.T) {
	ports := []int{}
	for port := 0; port <= 65535; port += 1 {
		if _, namespace, err := ParseSocketName("tls/" + strconv.Itoa(port) + "/blog"); err == nil && namespace == SocketNamespaceTls {
			ports = append(ports, port)
		}
	}
	want := slices.Sorted(slices.Values(aclPublishPorts))
	if !slices.Equal(ports, want) {
		t.Fatalf("ParseSocketName takes %v, and the listing reads %v", ports, want)
	}
}

// A state with no publish rule and no receiver lists nothing, and an empty answer is a list, never nil.
func TestAclPublishedNamesOfAStateThatPublishesNothing(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	device := fixture.device(owner)
	aclPublishedNamesRule(fixture, device, []string{"tls/443/blog"}, protocol.AclAudience_ACL_AUDIENCE_PUBLIC,
		protocol.AclAppMode_ACL_APP_MODE_HTTP, nil, time.Time{}, protocol.AclAction_ACL_ACTION_LISTEN)
	names := fixture.state(t).PublishedNames(aclTestNow)
	if names == nil || len(names) != 0 {
		t.Fatalf("listed %v", names)
	}
}
