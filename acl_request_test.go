// §8.6's requests: grant_dst and grant_allow parsed and refused, MatchAclRequest picking the rule for an ask by its
// src, actions and destinations, and the grant's lifetime: the ask's, else expiresDefault, never past maxExpiry.
// Pure, on every leg.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Each grant_dst form parses to its target, a worker's port among them, and every other form is refused.
func TestParseAclGrantDst(t *testing.T) {
	id := testConfigId("grant dst")
	idText := hex.EncodeToString(id.Bytes())
	tokenPath := aclTestTokenPath(1, 2)
	cases := []struct {
		dst    string
		target *protocol.AclTarget
		port   *protocol.AclPortRange
	}{
		{dst: "sidecar:" + idText, target: &protocol.AclTarget{SidecarId: id.Bytes()}},
		{dst: "sidecar:" + idText + ":tcp:8080", target: &protocol.AclTarget{SidecarId: id.Bytes()}, port: &protocol.AclPortRange{Protocol: 6, First: 8080, Last: 8080}},
		{dst: "sidecar:" + idText + ":udp:53", target: &protocol.AclTarget{SidecarId: id.Bytes()}, port: &protocol.AclPortRange{Protocol: 17, First: 53, Last: 53}},
		{dst: "client:" + idText, target: &protocol.AclTarget{ClientId: id.Bytes()}},
		{dst: "network:" + idText, target: &protocol.AclTarget{NetworkId: id.Bytes()}},
		{dst: "evs:" + idText, target: &protocol.AclTarget{RepoId: id.Bytes()}},
		{dst: "sock:" + hex.EncodeToString(tokenPath), target: &protocol.AclTarget{SocketTokens: [][]byte{tokenPath}}},
		{dst: "sock:tls/443/app-preview", target: &protocol.AclTarget{PublicName: "tls/443/app-preview"}},
		{dst: "dns:app-preview", target: &protocol.AclTarget{PublicName: "app-preview"}},
		{dst: "mail:*", target: &protocol.AclTarget{MailSend: true}},
	}
	for _, c := range cases {
		target, port, err := ParseAclGrantDst(c.dst)
		if err != nil || !bytes.Equal(testConfigMarshal(t, target), testConfigMarshal(t, c.target)) ||
			(c.port == nil) != (port == nil) || (port != nil && (port.GetProtocol() != c.port.GetProtocol() || port.GetFirst() != c.port.GetFirst())) {
			t.Errorf("%s: %v, %v, %v", c.dst, target, port, err)
		}
	}
	refused := []string{
		"", "sidecar", "sidecar:", "sidecar:" + strings.ToUpper(idText), "sidecar:" + idText[:30], "sidecar:" + idText + ":sctp:1",
		"sidecar:" + idText + ":tcp:0", "sidecar:" + idText + ":tcp:65536", "sidecar:" + idText + ":tcp:080", "evs:" + strings.Repeat("0", 32),
		"sock:" + hex.EncodeToString(tokenPath[:5]), "sock:zz", "dns:a/b", "mail:alias", "ip:10.0.0.0/8", "tag:" + idText, "autogroup:member",
	}
	for _, dst := range refused {
		if _, _, err := ParseAclGrantDst(dst); !errors.Is(err, ErrAclGrantFieldInvalid) {
			t.Errorf("%q: %v", dst, err)
		}
	}
	for action := protocol.AclAction_ACL_ACTION_DIAL; action <= aclActionMax; action += 1 {
		if parsed, err := ParseAclGrantAllow(aclActionName(action)); err != nil || parsed != action {
			t.Errorf("%s: %v, %v", action, parsed, err)
		}
	}
	for _, allow := range []string{"", "*", "Dial", "create"} {
		if _, err := ParseAclGrantAllow(allow); !errors.Is(err, ErrAclGrantFieldInvalid) {
			t.Errorf("%q: %v", allow, err)
		}
	}
}

// MatchAclRequest takes the first rule whose src holds the requester, whose actions hold every one asked and whose
// targets take every destination; a rule_id picks one rule alone.
func TestMatchAclRequestPicksTheRule(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	tagged := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED)
	dial := protocol.AclAction_ACL_ACTION_DIAL
	listen := protocol.AclAction_ACL_ACTION_LISTEN
	read := protocol.AclAction_ACL_ACTION_READ
	tokenPath := aclTestTokenPath(4, 5)
	generalId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	teamRecordId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, []protocol.AclAction{dial}, nil, 0)
	taggedRule := fixture.requestRule([]Id{tagged}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), aclSocketRowTarget(true),
		aclWildcardRepoTarget(), {PublicName: "tls/443/*-preview"}, {PublicName: "*-preview"}}, []protocol.AclAction{dial, listen, read}, nil, 0)
	state := fixture.state(t)
	ask := func(subject Id, dst []*protocol.AclTarget, allow ...protocol.AclAction) *AclGrantAsk {
		return &AclGrantAsk{Subject: subject, Dst: dst, Allow: allow}
	}
	cases := []struct {
		name string
		ask  *AclGrantAsk
		rule []byte
	}{
		{name: "a member's own device", ask: ask(cast.laptop, []*protocol.AclTarget{aclSidecarTarget(cast.phone)}, dial), rule: selfRule},
		{name: "a member reaching another's device", ask: ask(cast.laptop, []*protocol.AclTarget{aclSidecarTarget(cast.stranger)}, dial)},
		{name: "a member asking listen", ask: ask(cast.laptop, []*protocol.AclTarget{aclSidecarTarget(cast.phone)}, listen)},
		{name: "an agent dialing a member's device", ask: ask(cast.agent, []*protocol.AclTarget{aclSidecarTarget(cast.stranger)}, dial), rule: taggedRule},
		{name: "an agent on a socket", ask: ask(cast.agent, []*protocol.AclTarget{{SocketTokens: [][]byte{tokenPath}}}, dial, listen), rule: taggedRule},
		{name: "an agent reading a general repo", ask: ask(cast.agent, []*protocol.AclTarget{aclRepoTarget(generalId)}, read), rule: taggedRule},
		{name: "an agent reading the team record", ask: ask(cast.agent, []*protocol.AclTarget{aclRepoTarget(teamRecordId)}, read)},
		{name: "an agent listening on a preview name", ask: ask(cast.agent, []*protocol.AclTarget{{PublicName: "tls/443/app-preview"}}, listen), rule: taggedRule},
		{name: "an agent on another name", ask: ask(cast.agent, []*protocol.AclTarget{{PublicName: "tls/443/app"}}, listen)},
		{name: "a dns host by the host rule", ask: ask(cast.agent, []*protocol.AclTarget{{PublicName: "app-preview"}}, listen), rule: taggedRule},
		{name: "a revoked requester", ask: ask(cast.revoked, []*protocol.AclTarget{aclSidecarTarget(cast.phone)}, dial)},
		{name: "an unknown requester", ask: ask(NewId(), []*protocol.AclTarget{aclSidecarTarget(cast.phone)}, dial)},
	}
	for _, c := range cases {
		match, err := MatchAclRequest(state, c.ask, aclTestNow)
		if c.rule == nil {
			if !errors.Is(err, ErrAclRequestNoMatch) {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || !bytes.Equal(match.Rule.GetRuleId(), c.rule) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a rule_id picks that rule alone
	picked := ask(cast.agent, []*protocol.AclTarget{aclSidecarTarget(cast.stranger)}, dial)
	picked.RuleId = selfRule
	if _, err := MatchAclRequest(state, picked, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a rule_id another rule would take: %v", err)
	}
}

// A grant lasts what it asks, else expiresDefault, never past maxExpiry, and never one already over.
func TestMatchAclRequestLifetime(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	targets := []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}
	dial := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}
	defaultRule := fixture.requestRule([]Id{member}, targets, dial, nil, 0)
	shortRule := fixture.requestRule([]Id{member}, targets, dial, nil, 0)
	fixture.rows.Requests[1].DefaultExpirySeconds = 600
	fixture.rows.Requests[1].MaxExpirySeconds = 24 * 60 * 60
	state := fixture.state(t)
	nowMs := aclTestNow.UnixMilli()
	cases := []struct {
		name      string
		rule      []byte
		expiresMs int64
		want      int64
	}{
		{name: "the format's default", rule: defaultRule, want: nowMs + aclRequestDefaultExpiryMs},
		{name: "the rule's default", rule: shortRule, want: nowMs + 600*1000},
		{name: "the ask's, within the maximum", rule: defaultRule, expiresMs: nowMs + 10*24*60*60*1000, want: nowMs + 10*24*60*60*1000},
		{name: "past the format's maximum", rule: defaultRule, expiresMs: nowMs + aclRequestMaxExpiryMs + 1},
		{name: "past the rule's maximum", rule: shortRule, expiresMs: nowMs + 25*60*60*1000},
		{name: "already over", rule: defaultRule, expiresMs: nowMs},
	}
	for _, c := range cases {
		match, err := MatchAclRequest(state, &AclGrantAsk{Subject: cast.laptop, Dst: []*protocol.AclTarget{aclSidecarTarget(cast.phone)},
			Allow: dial, ExpiresMs: c.expiresMs, RuleId: c.rule}, aclTestNow)
		if c.want == 0 {
			if !errors.Is(err, ErrAclRequestNoMatch) {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || match.ExpiresMs != c.want {
			t.Errorf("%s: %v, %v", c.name, match, err)
		}
	}
}

// ParseAclGrantAction reads a CanonicalAction's grant fields and refuses one with no subject, rule, destination or
// action. A forward's action, version 4, names its target alone in the clear, so its ask holds no port (QD-740); port
// text, which only a sealed_detail's grant_dst holds, reads as one port however often it is written.
func TestParseAclGrantAction(t *testing.T) {
	subject, ruleId := testConfigId("action subject"), testConfigId("action rule")
	action := aclTestGrantAction(ruleId.Bytes(), subject, []string{aclTestDst(subject) + ":tcp:22", aclTestDst(subject) + ":tcp:22", aclTestDst(testConfigId("action target"))},
		[]string{"dial", "dial"}, 77)
	if _, err := ParseStoredCanonicalAction(testConfigMarshal(t, action)); err != nil {
		t.Fatal(err)
	}
	ask, err := ParseAclGrantAction(action)
	if err != nil || ask.Subject != subject || !bytes.Equal(ask.RuleId, ruleId.Bytes()) || ask.ExpiresMs != 77 || len(ask.Dst) != 2 ||
		len(ask.Ports) != 0 || len(ask.Allow) != 1 {
		t.Fatalf("%+v, %v", ask, err)
	}
	detailed := &protocol.CanonicalAction{
		RuleId: action.RuleId, Subject: action.Subject,
		GrantDst: []string{aclTestDst(subject) + ":tcp:22", aclTestDst(subject) + ":tcp:22"}, GrantAllow: action.GrantAllow,
	}
	if ask, err := ParseAclGrantAction(detailed); err != nil || len(ask.Dst) != 2 || len(ask.Ports) != 1 {
		t.Fatalf("a detail's port text: %+v, %v", ask, err)
	}
	for _, edit := range []func(action *protocol.CanonicalAction){
		func(action *protocol.CanonicalAction) { action.Subject = nil },
		func(action *protocol.CanonicalAction) { action.RuleId = action.RuleId[:8] },
		func(action *protocol.CanonicalAction) { action.GrantDst = nil },
		func(action *protocol.CanonicalAction) { action.GrantAllow = nil },
		func(action *protocol.CanonicalAction) { action.ExpiresMillis = -1 },
		func(action *protocol.CanonicalAction) { action.GrantAllow = []string{"fly"} },
	} {
		broken := &protocol.CanonicalAction{RuleId: action.RuleId, Subject: action.Subject, GrantDst: action.GrantDst, GrantAllow: action.GrantAllow}
		edit(broken)
		if _, err := ParseAclGrantAction(broken); !errors.Is(err, ErrAclGrantFieldInvalid) {
			t.Errorf("%+v: %v", broken, err)
		}
	}
}

// Request rules are no part of what NewAclState checks, and an ask's targets are its caller's: ids of the wrong size
// in either match nothing and never panic, so a malformed requests row from a writer cannot stop a gate.
func TestMatchAclRequestTakesMalformedIdsAsNoMatch(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	short := []byte{1, 2, 3}
	dial := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}
	fixture.rows.Requests = append(fixture.rows.Requests, &protocol.AclRequestRule{
		RuleId: NewId().Bytes(), SrcAtoms: [][]byte{short}, Actions: []uint32{uint32(dial[0])},
		Targets: []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)},
	})
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	for _, target := range []*protocol.AclTarget{{SidecarId: short}, {NetworkId: short}, {ClientId: short}, {RepoId: short}, {Atom: short}} {
		fixture.requestRule([]Id{member}, []*protocol.AclTarget{target}, dial, nil, 0)
	}
	fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF), aclWildcardRepoTarget(),
		{NetworkId: NewId().Bytes()}, {ClientId: NewId().Bytes()}}, dial, nil, 0)
	state := fixture.state(t)
	for _, target := range []*protocol.AclTarget{{SidecarId: short}, {NetworkId: short}, {ClientId: short}, {RepoId: short}, {Atom: short}} {
		if _, err := MatchAclRequest(state, &AclGrantAsk{Subject: cast.laptop, Dst: []*protocol.AclTarget{target}, Allow: dial}, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
			t.Errorf("%v: %v", target, err)
		}
	}
	if _, err := MatchAclRequest(state, &AclGrantAsk{Subject: cast.laptop, Dst: []*protocol.AclTarget{aclSidecarTarget(cast.stranger)}, Allow: dial}, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a well-formed ask against malformed rules: %v", err)
	}
}
