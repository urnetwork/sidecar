// §8.4's grammar, row by row: each selector and resource form, where each may stand, what each refuses
// and what a * reaches. Every name here is synthetic and every address a documentation range.

package sidecar

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

const (
	testSidecarIdText = "0190ee54-3a3e-7a1a-8d2f-0123456789ab"
	testClientIdText  = "0190ee543a3e7a1a8d2f0123456789ac"
	testRepoIdText    = "0190ee54-3a3e-7a1a-8d2f-0123456789ad"
)

func testParseId(t *testing.T, text string) Id {
	t.Helper()
	id, err := ParseId(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testAutogroup(autogroup protocol.AclAutogroup) AclSelector {
	return AclSelector{Kind: AclSelectorAutogroup, Autogroup: autogroup}
}

func TestParseAclSelectorEveryForm(t *testing.T) {
	sidecarId := testParseId(t, testSidecarIdText)
	clientId := testParseId(t, testClientIdText)
	cases := []struct {
		text     string
		position aclPosition
		want     AclSelector
	}{
		{text: "user:dana@acme.example", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"}},
		{text: "user:Dana@Acme.Example", position: aclPositionDst, want: AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"}},
		{text: "user:dana.q+tag@acme.example", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorUser, Name: "dana.q+tag@acme.example"}},
		{text: "group:eng", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorGroup, Name: "eng"}},
		{text: "group:eng.platform_2-a", position: aclPositionDst, want: AclSelector{Kind: AclSelectorGroup, Name: "eng.platform_2-a"}},
		{text: "group:eng@acme.example", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorGroup, Name: "eng@acme.example"}},
		{text: "tag:recurd", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorTag, Name: "recurd"}},
		{text: "tag:" + strings.Repeat("a", 50), position: aclPositionDst, want: AclSelector{Kind: AclSelectorTag, Name: strings.Repeat("a", 50)}},
		{text: "tag:a-0", position: aclPositionVia, want: AclSelector{Kind: AclSelectorTag, Name: "a-0"}},
		{text: "sidecar:" + testSidecarIdText, position: aclPositionSrc, want: AclSelector{Kind: AclSelectorSidecar, Id: sidecarId}},
		{text: "sidecar:0190ee543a3e7a1a8d2f0123456789ab", position: aclPositionDst, want: AclSelector{Kind: AclSelectorSidecar, Id: sidecarId}},
		{text: "client:" + testClientIdText, position: aclPositionSrc, want: AclSelector{Kind: AclSelectorClient, Id: clientId}},
		{text: "role:reviewer", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorRole, Name: "reviewer"}},
		{text: "principal:urn:synthetic:worker", position: aclPositionDst, want: AclSelector{Kind: AclSelectorPrincipal, Name: "urn:synthetic:worker"}},
		{text: "network:partner-y", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorNetwork, Name: "partner-y"}},
		{text: "network:partner-y", position: aclPositionDst, want: AclSelector{Kind: AclSelectorNetwork, Name: "partner-y"}},
		{text: "network:*", position: aclPositionSrc, want: AclSelector{Kind: AclSelectorNetwork, Name: "*"}},
		// §8.5's example writes both of these bare
		{text: "dana@acme.example", position: aclPositionGroupMember, want: AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"}},
		{text: "user:dana@acme.example", position: aclPositionGroupMember, want: AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"}},
		{text: "dana@acme.example", position: aclPositionTestSrc, want: AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"}},
		{text: "dana@acme.example", position: aclPositionTagOwner, want: AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"}},
		{text: "group:eng", position: aclPositionTagOwner, want: AclSelector{Kind: AclSelectorGroup, Name: "eng"}},
		{text: "tag:audit", position: aclPositionAuditReader, want: AclSelector{Kind: AclSelectorTag, Name: "audit"}},
	}
	for _, c := range cases {
		got, err := parseAclSelector(c.text, c.position)
		if err != nil {
			t.Errorf("%s at %d: %v", c.text, c.position, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s at %d: %+v", c.text, c.position, got)
		}
	}
}

// §8.4's notes, as a whole table: every autogroup at every position, so a position cannot drift. The
// bare column is what a selector may do in each place, in the order of aclPositions.
func TestAclAutogroupsKeepTheirPositions(t *testing.T) {
	positions := []aclPosition{
		aclPositionSrc, aclPositionDst, aclPositionVia, aclPositionApprover, aclPositionTagOwner,
		aclPositionGroupMember, aclPositionAuditReader, aclPositionTestSrc,
	}
	//                       src   dst   via   approver owner member audit test
	everywhere := []bool{true, true, true, true, true, false, false, true}
	subjects := []bool{true, true, true, false, false, false, false, true}
	cases := map[string][]bool{
		"autogroup:member":    everywhere,
		"autogroup:owner":     everywhere,
		"autogroup:admin":     everywhere,
		"autogroup:auditor":   everywhere,
		"autogroup:sidecar":   subjects,
		"autogroup:tagged":    subjects,
		"autogroup:network":   subjects,
		"autogroup:untagged":  subjects,
		"autogroup:public":    {true, false, false, false, false, false, false, true},
		"autogroup:ephemeral": {true, false, false, false, false, false, false, true},
		"autogroup:internet":  {false, true, false, false, false, false, false, false},
		"autogroup:self":      {false, true, true, true, false, false, false, false},
		"autogroup:sponsor":   {false, false, false, true, false, false, false, false},
		"autogroup:dst-owner": {false, false, false, true, false, false, false, false},
	}
	if len(cases) != len(aclNameAutogroups) {
		t.Fatalf("%d cases for %d autogroups", len(cases), len(aclNameAutogroups))
	}
	for text, wants := range cases {
		for i, position := range positions {
			got, err := parseAclSelector(text, position)
			if wants[i] && err != nil {
				t.Errorf("%s at %d: %v", text, position, err)
			}
			if !wants[i] && err == nil {
				t.Errorf("%s at %d passed as %+v", text, position, got)
			}
		}
	}
}

// Every kind that is not an autogroup, at every position.
func TestAclSelectorsKeepTheirPositions(t *testing.T) {
	positions := []aclPosition{
		aclPositionSrc, aclPositionDst, aclPositionVia, aclPositionApprover, aclPositionTagOwner,
		aclPositionGroupMember, aclPositionAuditReader, aclPositionTestSrc,
	}
	cases := map[string][]bool{
		//                                src  dst   via   approver owner member audit test
		"user:dana@acme.example":       {true, true, true, true, true, true, false, true},
		"dana@acme.example":            {false, false, false, false, true, true, false, true},
		"group:eng":                    {true, true, true, true, true, false, false, true},
		"tag:recurd":                   {true, true, true, false, false, false, true, true},
		"sidecar:" + testSidecarIdText: {true, true, true, false, false, false, false, true},
		"client:" + testClientIdText:   {true, true, true, false, false, false, false, true},
		"role:reviewer":                {true, true, true, false, false, false, false, true},
		"principal:worker":             {true, true, true, false, false, false, false, true},
		"network:partner-y":            {true, true, false, false, false, false, false, true},
		"network:*":                    {true, false, false, false, false, false, false, true},
	}
	for text, wants := range cases {
		for i, position := range positions {
			got, err := parseAclSelector(text, position)
			if wants[i] && err != nil {
				t.Errorf("%s at %d: %v", text, position, err)
			}
			if !wants[i] && err == nil {
				t.Errorf("%s at %d passed as %+v", text, position, got)
			}
		}
	}
}

func TestParseAclSelectorRefusals(t *testing.T) {
	cases := []struct {
		text   string
		reason string
	}{
		{text: "", reason: "not a selector"},
		{text: "*", reason: "not a selector"},
		{text: "dana", reason: "not a selector"},
		{text: "sock:db", reason: "not a selector"},
		{text: "evs:repo-x", reason: "not a selector"},
		{text: "posture:compliant", reason: "not a selector"},
		{text: "User:dana@acme.example", reason: "not a selector"},
		{text: "user:", reason: "not an email"},
		{text: "user:dana", reason: "not an email"},
		{text: "user:@acme.example", reason: "not an email"},
		{text: "user:dana@", reason: "not an email"},
		{text: "user:dana@acme@example", reason: "not an email"},
		{text: "user:da na@acme.example", reason: "not an email"},
		{text: "user:da\x00na@acme.example", reason: "not an email"},
		{text: "user:da\xffna@acme.example", reason: "not an email"},
		{text: "user:da�na@acme.example", reason: "not an email"},
		{text: "user:*@acme.example", reason: "not an email"},
		{text: "user:<dana@acme.example>", reason: "not an email"},
		{text: "group:", reason: "not a group name"},
		{text: "group:Eng", reason: "not a group name"},
		{text: "group:-eng", reason: "not a group name"},
		{text: "group:eng-", reason: "not a group name"},
		{text: "group:e ng", reason: "not a group name"},
		{text: "group:*", reason: "not a group name"},
		{text: "group:eng@", reason: "not a group name"},
		{text: "group:eng@acme@example", reason: "not a group name"},
		{text: "tag:", reason: "not a tag name"},
		{text: "tag:Recurd", reason: "not a tag name"},
		{text: "tag:re_curd", reason: "not a tag name"},
		{text: "tag:*", reason: "not a tag name"},
		{text: "tag:" + strings.Repeat("a", 51), reason: "not a tag name"},
		{text: "sidecar:", reason: "not an id"},
		{text: "sidecar:name", reason: "not an id"},
		{text: "sidecar:00000000-0000-0000-0000-000000000000", reason: "not an id"},
		{text: "client:00000000000000000000000000000000", reason: "not an id"},
		{text: "role:", reason: "no name"},
		{text: "role:a b", reason: "not a name"},
		{text: "principal:", reason: "no name"},
		{text: "principal:a\tb", reason: "not a name"},
		{text: "principal:a�b", reason: "not a name"},
		{text: "network:", reason: "not a network label"},
		{text: "network:Partner", reason: "not a network label"},
		{text: "network:-partner", reason: "not a network label"},
		{text: "network:partner-", reason: "not a network label"},
		{text: "network:partner-*", reason: "not a network label"},
		{text: "network:a.b", reason: "not a network label"},
		{text: "network:" + strings.Repeat("a", 64), reason: "not a network label"},
		{text: "autogroup:", reason: "an unknown autogroup"},
		{text: "autogroup:everyone", reason: "an unknown autogroup"},
		{text: "autogroup:Member", reason: "an unknown autogroup"},
		{text: "autogroup:dst_owner", reason: "an unknown autogroup"},
	}
	for _, c := range cases {
		got, err := parseAclSelector(c.text, aclPositionSrc)
		if err == nil {
			t.Errorf("%q passed as %+v", c.text, got)
			continue
		}
		if !errors.Is(err, ErrAclPolicyInvalid) || !strings.HasSuffix(err.Error(), ": "+c.reason) {
			t.Errorf("%q: %v", c.text, err)
		}
	}
}

// A new autogroup in protocol must get a name here, or a document could never say it.
func TestEveryAutogroupHasAName(t *testing.T) {
	names := map[int32]string{}
	for name, autogroup := range aclNameAutogroups {
		names[int32(autogroup)] = name
	}
	for number, name := range protocol.AclAutogroup_name {
		if number != 0 && names[number] == "" {
			t.Errorf("%s has no name", name)
		}
	}
	if len(names) != len(protocol.AclAutogroup_name)-1 {
		t.Errorf("%d names for %d autogroups", len(names), len(protocol.AclAutogroup_name)-1)
	}
	for number, name := range names {
		text := testAutogroup(protocol.AclAutogroup(number)).String()
		if text != "autogroup:"+name {
			t.Errorf("%s reads as %s", name, text)
		}
	}
}

func TestParseAclResourceEveryForm(t *testing.T) {
	repoId := testParseId(t, testRepoIdText)
	cases := []struct {
		text string
		want AclResource
	}{
		{text: "*", want: AclResource{Kind: AclResourceAll}},
		{text: "tag:api", want: AclResource{Kind: AclResourceSubject, Subject: AclSelector{Kind: AclSelectorTag, Name: "api"}}},
		{text: "autogroup:self", want: AclResource{Kind: AclResourceSubject, Subject: testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}},
		{text: "autogroup:internet", want: AclResource{Kind: AclResourceSubject, Subject: testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET)}},
		{text: "network:partner-y", want: AclResource{Kind: AclResourceSubject, Subject: AclSelector{Kind: AclSelectorNetwork, Name: "partner-y"}}},
		{text: "sock:db", want: AclResource{Kind: AclResourceSocket, Name: "db"}},
		{text: "sock:db/primary", want: AclResource{Kind: AclResourceSocket, Name: "db/primary"}},
		{text: "sock:DB/Primary", want: AclResource{Kind: AclResourceSocket, Name: "db/primary"}},
		{text: "sock:a.b_c-d/e", want: AclResource{Kind: AclResourceSocket, Name: "a.b_c-d/e"}},
		{text: "sock:tls/443/blog", want: AclResource{Kind: AclResourceSocket, Name: "tls/443/blog"}},
		{text: "sock:tls/443/@", want: AclResource{Kind: AclResourceSocket, Name: "tls/443/@"}},
		{text: "sock:smtp/25/mx.team", want: AclResource{Kind: AclResourceSocket, Name: "smtp/25/mx.team"}},
		{text: "sock:share/a0b1", want: AclResource{Kind: AclResourceSocket, Name: "share/a0b1"}},
		{text: "sock:tls/443/*-preview", want: AclResource{Kind: AclResourceSocket, Name: "tls/443/*-preview"}},
		{text: "sock:tls/*", want: AclResource{Kind: AclResourceSocket, Name: "tls/*"}},
		{text: "sock:smtp/*", want: AclResource{Kind: AclResourceSocket, Name: "smtp/*"}},
		{text: "sock:*", want: AclResource{Kind: AclResourceSocket, Name: "*"}},
		{text: "sock:" + strings.Repeat("a/", 7) + "a", want: AclResource{Kind: AclResourceSocket, Name: strings.Repeat("a/", 7) + "a"}},
		{text: "sock:" + strings.Repeat("a", 63) + "/" + strings.Repeat("b", 48), want: AclResource{Kind: AclResourceSocket, Name: strings.Repeat("a", 63) + "/" + strings.Repeat("b", 48)}},
		{text: "ip:192.0.2.0/24", want: AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("192.0.2.0/24")}},
		{text: "ip:198.51.100.7/32", want: AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("198.51.100.7/32")}},
		{text: "ip:2001:db8::/32", want: AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("2001:db8::/32")}},
		{text: "ip:0.0.0.0/0", want: AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("0.0.0.0/0")}},
		{text: "ip:::/0", want: AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("::/0")}},
		{text: "ip:office", want: AclResource{Kind: AclResourceIp, Name: "office"}},
		{text: "evs:repo-x", want: AclResource{Kind: AclResourceRepo, Name: "repo-x"}},
		{text: "evs:repo_x-2", want: AclResource{Kind: AclResourceRepo, Name: "repo_x-2"}},
		{text: "evs:*", want: AclResource{Kind: AclResourceRepo, Name: "*"}},
		{text: "evs:repo-*", want: AclResource{Kind: AclResourceRepo, Name: "repo-*"}},
		{text: "evs:" + strings.Repeat("a", 63), want: AclResource{Kind: AclResourceRepo, Name: strings.Repeat("a", 63)}},
		{text: "evs:" + testRepoIdText, want: AclResource{Kind: AclResourceRepo, RepoId: repoId}},
		{text: "evs:" + strings.ReplaceAll(testRepoIdText, "-", ""), want: AclResource{Kind: AclResourceRepo, RepoId: repoId}},
		{text: "dns:@", want: AclResource{Kind: AclResourceDns, Name: "@"}},
		{text: "dns:blog", want: AclResource{Kind: AclResourceDns, Name: "blog"}},
		{text: "dns:api-dev", want: AclResource{Kind: AclResourceDns, Name: "api-dev"}},
		{text: "dns:*-preview", want: AclResource{Kind: AclResourceDns, Name: "*-preview"}},
		{text: "dns:*", want: AclResource{Kind: AclResourceDns, Name: "*"}},
		{text: "dns:blog.team", want: AclResource{Kind: AclResourceDns, Name: "blog.team"}},
		{text: "dns:*.team", want: AclResource{Kind: AclResourceDns, Name: "*.team"}},
		{text: "dns:" + strings.Repeat("a", 63), want: AclResource{Kind: AclResourceDns, Name: strings.Repeat("a", 63)}},
		{text: "mail:agent", want: AclResource{Kind: AclResourceMail, Name: "agent"}},
		{text: "mail:agent.one_two-3", want: AclResource{Kind: AclResourceMail, Name: "agent.one_two-3"}},
		{text: "mail:*", want: AclResource{Kind: AclResourceMail, Name: "*"}},
		{text: "mail:agent-*", want: AclResource{Kind: AclResourceMail, Name: "agent-*"}},
		{text: "mail:" + strings.Repeat("a", 64), want: AclResource{Kind: AclResourceMail, Name: strings.Repeat("a", 64)}},
	}
	for _, c := range cases {
		got, err := parseAclResource(c.text)
		if err != nil {
			t.Errorf("%s: %v", c.text, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: %+v", c.text, got)
		}
	}
}

func TestParseAclResourceRefusals(t *testing.T) {
	cases := []struct {
		text   string
		reason string
	}{
		{text: "", reason: "not a resource"},
		{text: "db", reason: "not a resource"},
		{text: "**", reason: "not a resource"},
		{text: "dana@acme.example", reason: "not a resource"},
		{text: "posture:compliant", reason: "not a selector"},
		// a selector no dst takes
		{text: "autogroup:public", reason: "a selector this position does not take"},
		{text: "autogroup:ephemeral", reason: "a selector this position does not take"},
		{text: "autogroup:sponsor", reason: "a selector this position does not take"},
		{text: "autogroup:dst-owner", reason: "a selector this position does not take"},
		{text: "network:*", reason: "a selector this position does not take"},
		// ports live in a rule's ip, not its dst
		{text: "tag:api:443", reason: "not a tag name"},
		{text: "tag:api:tcp:443", reason: "not a tag name"},
		{text: "sock:", reason: "not a socket name"},
		{text: "sock:/db", reason: "not a socket name"},
		{text: "sock:db/", reason: "not a socket name"},
		{text: "sock:db//primary", reason: "not a socket name"},
		{text: "sock:.", reason: "not a socket name"},
		{text: "sock:..", reason: "not a socket name"},
		{text: "sock:db/../primary", reason: "not a socket name"},
		{text: "sock:db@x", reason: "not a socket name"},
		{text: "sock:d b", reason: "not a socket name"},
		{text: "sock:acme:db", reason: "not a socket name"},
		{text: "sock:db%2fprimary", reason: "not a socket name"},
		{text: "sock:dbK", reason: "not a socket name"},
		{text: "sock:db\xff", reason: "not a socket name"},
		{text: "sock:" + strings.Repeat("a", 64), reason: "not a socket name"},
		{text: "sock:" + strings.Repeat("a/", 8) + "a", reason: "not a socket name"},
		{text: "sock:" + strings.Repeat("a", 63) + "/" + strings.Repeat("b", 49), reason: "not a socket name"},
		{text: "ip:", reason: "not a cidr or hosts name"},
		{text: "ip:*", reason: "not a cidr or hosts name"},
		{text: "ip:Office", reason: "not a cidr or hosts name"},
		{text: "ip:192.0.2.1", reason: "not a cidr"},
		{text: "ip:192.0.2.1/24", reason: "not a cidr"},
		{text: "ip:192.0.2.0/33", reason: "not a cidr"},
		{text: "ip:192.0.2.0/024", reason: "not a cidr"},
		{text: "ip:2001:db8::1/32", reason: "not a cidr"},
		{text: "ip:::ffff:192.0.2.0/120", reason: "not a cidr"},
		{text: "ip:fe80::%eth0/64", reason: "not a cidr"},
		{text: "evs:", reason: "not a repo label"},
		{text: "evs:Repo", reason: "not a repo label"},
		{text: "evs:-repo", reason: "not a repo label"},
		{text: "evs:_repo", reason: "not a repo label"},
		{text: "evs:repo x", reason: "not a repo label"},
		{text: "evs:repo.txt", reason: "not a repo label"},
		{text: "evs:..", reason: "not a repo label"},
		{text: "evs:repo%2fx", reason: "not a repo label"},
		{text: "evs:" + strings.Repeat("a", 64), reason: "not a repo label"},
		{text: "evs:00000000-0000-0000-0000-000000000000", reason: "not an id"},
		// X2: a value is an id or a label, never a path
		{text: "evs:repo-x/src", reason: "a path, which an evs: resource never is (X2)"},
		{text: "evs:repo-x/", reason: "a path, which an evs: resource never is (X2)"},
		{text: "evs:/repo-x", reason: "a path, which an evs: resource never is (X2)"},
		{text: "evs:../repo-x", reason: "a path, which an evs: resource never is (X2)"},
		{text: "evs:repo-x\\src", reason: "a path, which an evs: resource never is (X2)"},
		{text: "evs:" + testRepoIdText + "/src", reason: "a path, which an evs: resource never is (X2)"},
		{text: "dns:", reason: "not a dns host"},
		{text: "dns:Blog", reason: "not a dns host"},
		{text: "dns:-blog", reason: "not a dns host"},
		{text: "dns:blog-", reason: "not a dns host"},
		{text: "dns:bl_og", reason: "not a dns host"},
		{text: "dns:@.team", reason: "not a dns host"},
		{text: "dns:.team", reason: "not a dns host"},
		{text: "dns:blog.", reason: "not a dns host"},
		{text: "dns:a.b.c", reason: "not a dns host"},
		{text: "dns:" + strings.Repeat("a", 64), reason: "not a dns host"},
		{text: "dns:" + strings.Repeat("a", 32) + "." + strings.Repeat("b", 31), reason: "not a dns host"},
		{text: "mail:", reason: "not a mail alias"},
		{text: "mail:Agent", reason: "not a mail alias"},
		{text: "mail:.agent", reason: "not a mail alias"},
		{text: "mail:-agent", reason: "not a mail alias"},
		{text: "mail:agent@acme.example", reason: "not a mail alias"},
		{text: "mail:" + strings.Repeat("a", 65), reason: "not a mail alias"},
	}
	for _, c := range cases {
		got, err := parseAclResource(c.text)
		if err == nil {
			t.Errorf("%q passed as %+v", c.text, got)
			continue
		}
		if !errors.Is(err, ErrAclPolicyInvalid) || !strings.HasSuffix(err.Error(), ": "+c.reason) {
			t.Errorf("%q: %v", c.text, err)
		}
	}
}

// Canonical text parses back to the same value, whatever spelling it came from.
func TestAclCanonicalTextParsesBack(t *testing.T) {
	for _, text := range []string{
		"*", "tag:api", "autogroup:self", "sock:DB/Primary", "sock:tls/*", "sock:*", "ip:192.0.2.0/24", "ip:2001:db8::/32",
		"ip:office", "evs:repo-x", "evs:*", "evs:" + strings.ReplaceAll(testRepoIdText, "-", ""), "dns:@", "dns:*.team",
		"mail:agent-*", "network:partner-y", "user:Dana@Acme.Example", "group:eng@acme.example",
		"sidecar:" + testSidecarIdText, "client:" + testClientIdText, "role:reviewer", "principal:urn:synthetic:worker",
	} {
		resource, err := parseAclResource(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		again, err := parseAclResource(resource.String())
		if err != nil {
			t.Fatalf("%s as %s: %v", text, resource, err)
		}
		if again != resource {
			t.Errorf("%s: %+v, then %+v", text, resource, again)
		}
	}
}

func TestAclResourceCovers(t *testing.T) {
	cases := []struct {
		pattern  string
		concrete string
		want     bool
	}{
		// a socket: * stays within a segment
		{pattern: "sock:db", concrete: "sock:db", want: true},
		{pattern: "sock:db", concrete: "sock:db/primary", want: false},
		{pattern: "sock:db", concrete: "sock:dbx", want: false},
		{pattern: "sock:db*", concrete: "sock:db-primary", want: true},
		{pattern: "sock:db*", concrete: "sock:db/primary", want: false},
		{pattern: "sock:db/*-1", concrete: "sock:db/primary-1", want: true},
		{pattern: "sock:db/*-1/x", concrete: "sock:db/primary-1/x", want: true},
		{pattern: "sock:db/*-1", concrete: "sock:db/a/b-1", want: false},
		{pattern: "sock:db/*/x", concrete: "sock:db/a/b/x", want: false},
		// §8.5's example 5
		{pattern: "sock:tls/443/*-preview", concrete: "sock:tls/443/app-preview", want: true},
		{pattern: "sock:tls/443/*-preview", concrete: "sock:tls/443/preview", want: false},
		{pattern: "sock:tls/443/*-preview", concrete: "sock:tls/8443/app-preview", want: false},
		// a last segment of a bare * takes everything below its prefix, as §8.5's sock:tls/* must
		{pattern: "sock:tls/*", concrete: "sock:tls/443/blog", want: true},
		{pattern: "sock:smtp/*", concrete: "sock:smtp/25/mx", want: true},
		{pattern: "sock:tls/*", concrete: "sock:smtp/25/mx", want: false},
		{pattern: "sock:tls/*", concrete: "sock:tlsx/443/blog", want: false},
		{pattern: "sock:db/*", concrete: "sock:db/primary", want: true},
		{pattern: "sock:db/*", concrete: "sock:db/primary/replica", want: true},
		{pattern: "sock:db/*", concrete: "sock:db", want: false},
		// a bare * and a first-segment glob take application sockets only: tls/ and smtp/ are named
		{pattern: "sock:*", concrete: "sock:db", want: true},
		{pattern: "sock:*", concrete: "sock:db/primary", want: true},
		{pattern: "sock:*", concrete: "sock:share/a0b1", want: true},
		{pattern: "sock:*", concrete: "sock:tls/443/blog", want: false},
		{pattern: "sock:*", concrete: "sock:smtp/25/mx", want: false},
		{pattern: "sock:*", concrete: "sock:ur/smtpedge", want: false},
		{pattern: "sock:*", concrete: "sock:sys/x", want: false},
		{pattern: "sock:*", concrete: "sock:c/x", want: false},
		{pattern: "sock:*", concrete: "sock:_x/y", want: false},
		{pattern: "sock:*", concrete: "sock:x/y", want: false},
		{pattern: "sock:t*/443/blog", concrete: "sock:tls/443/blog", want: false},
		{pattern: "sock:*/443/blog", concrete: "sock:tls/443/blog", want: false},
		{pattern: "sock:*/25/mx", concrete: "sock:smtp/25/mx", want: false},
		{pattern: "sock:*/primary", concrete: "sock:db/primary", want: true},
		{pattern: "*", concrete: "sock:db", want: true},
		{pattern: "*", concrete: "sock:share/a0b1", want: true},
		{pattern: "*", concrete: "sock:tls/443/blog", want: false},
		{pattern: "*", concrete: "sock:smtp/25/mx", want: false},
		{pattern: "*", concrete: "sock:ur/smtpedge", want: false},
		// a dns host: * stays within a label, and a bare one takes every host
		{pattern: "dns:*-preview", concrete: "dns:app-preview", want: true},
		{pattern: "dns:*-preview", concrete: "dns:app", want: false},
		{pattern: "dns:*-preview", concrete: "dns:app-preview.team", want: false},
		{pattern: "dns:*", concrete: "dns:blog", want: true},
		{pattern: "dns:*", concrete: "dns:@", want: true},
		{pattern: "dns:*", concrete: "dns:blog.team", want: true},
		{pattern: "dns:@", concrete: "dns:@", want: true},
		{pattern: "dns:@", concrete: "dns:blog", want: false},
		{pattern: "dns:*.team", concrete: "dns:blog.team", want: true},
		{pattern: "dns:*.team", concrete: "dns:blog.other", want: false},
		{pattern: "dns:*.team", concrete: "dns:team", want: false},
		{pattern: "dns:blog", concrete: "dns:blog", want: true},
		{pattern: "dns:blog", concrete: "dns:blog.team", want: false},
		// outward kinds must be named, so a bare * never reaches them
		{pattern: "*", concrete: "dns:blog", want: false},
		{pattern: "*", concrete: "mail:agent", want: false},
		// an alias and a repo label are one unit each
		{pattern: "mail:*", concrete: "mail:agent.one", want: true},
		{pattern: "mail:agent-*", concrete: "mail:agent-one", want: true},
		{pattern: "mail:agent-*", concrete: "mail:agent", want: false},
		{pattern: "mail:agent", concrete: "mail:agent", want: true},
		{pattern: "evs:*", concrete: "evs:repo-x", want: true},
		{pattern: "evs:repo-*", concrete: "evs:repo-x", want: true},
		{pattern: "evs:repo-*", concrete: "evs:other", want: false},
		{pattern: "evs:*", concrete: "evs:" + testRepoIdText, want: true},
		{pattern: "evs:repo-*", concrete: "evs:" + testRepoIdText, want: false},
		{pattern: "*", concrete: "evs:" + testRepoIdText, want: true},
		{pattern: "evs:" + testRepoIdText, concrete: "evs:" + strings.ReplaceAll(testRepoIdText, "-", ""), want: true},
		{pattern: "evs:" + testRepoIdText, concrete: "evs:repo-x", want: false},
		{pattern: "*", concrete: "evs:repo-x", want: true},
		// a dst of one kind reaches no other
		{pattern: "sock:*", concrete: "dns:blog", want: false},
		{pattern: "dns:*", concrete: "sock:db", want: false},
		{pattern: "evs:*", concrete: "mail:agent", want: false},
		// a concrete name has no glob in it
		{pattern: "sock:*", concrete: "sock:db*", want: false},
		{pattern: "dns:*", concrete: "dns:*", want: false},
		{pattern: "*", concrete: "evs:*", want: false},
		// these expand at compile, and answer false until they do
		{pattern: "tag:api", concrete: "tag:api", want: false},
		{pattern: "*", concrete: "tag:api", want: false},
		{pattern: "ip:192.0.2.0/24", concrete: "ip:192.0.2.0/24", want: false},
		{pattern: "*", concrete: "ip:192.0.2.0/24", want: false},
	}
	for _, c := range cases {
		pattern, err := parseAclResource(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		concrete, err := parseAclResource(c.concrete)
		if err != nil {
			t.Fatalf("%s: %v", c.concrete, err)
		}
		if got := pattern.covers(concrete); got != c.want {
			t.Errorf("%s over %s: %t", c.pattern, c.concrete, got)
		}
	}
}

// A hand-built resource never parsed has no business panicking a check.
func TestAclResourceCoversANameParsingNeverMade(t *testing.T) {
	all := AclResource{Kind: AclResourceAll}
	if all.covers(AclResource{Kind: AclResourceSocket}) {
		t.Error("* covered a socket with no name")
	}
	socket := AclResource{Kind: AclResourceSocket, Name: "*"}
	if socket.covers(AclResource{Kind: AclResourceSocket}) {
		t.Error("sock:* covered a socket with no name")
	}
}

func TestAclGlobMatches(t *testing.T) {
	cases := []struct {
		pattern string
		text    string
		want    bool
	}{
		{pattern: "", text: "", want: true},
		{pattern: "", text: "a", want: false},
		{pattern: "*", text: "", want: true},
		{pattern: "*", text: "abc", want: true},
		{pattern: "**", text: "abc", want: true},
		{pattern: "a", text: "a", want: true},
		{pattern: "a", text: "b", want: false},
		{pattern: "a*", text: "a", want: true},
		{pattern: "a*", text: "abc", want: true},
		{pattern: "a*", text: "ba", want: false},
		{pattern: "*c", text: "abc", want: true},
		{pattern: "*c", text: "cb", want: false},
		{pattern: "a*c", text: "ac", want: true},
		{pattern: "a*c", text: "abbc", want: true},
		{pattern: "a*c", text: "abcd", want: false},
		{pattern: "a*b*c", text: "axbxc", want: true},
		{pattern: "a*b*c", text: "axcxb", want: false},
		// backtracking past a first partial match
		{pattern: "*ab", text: "aab", want: true},
		{pattern: "*aab", text: "aaab", want: true},
		{pattern: "a*ab", text: "aaab", want: true},
	}
	for _, c := range cases {
		if got := aclGlobMatches(c.pattern, c.text); got != c.want {
			t.Errorf("%q over %q: %t", c.pattern, c.text, got)
		}
	}
}

func TestParseAclPortRange(t *testing.T) {
	cases := []struct {
		text string
		want AclPortRange
	}{
		{text: "*", want: AclPortRange{Last: 65535}},
		{text: "443", want: AclPortRange{First: 443, Last: 443}},
		{text: "8000-8100", want: AclPortRange{First: 8000, Last: 8100}},
		{text: "1-65535", want: AclPortRange{First: 1, Last: 65535}},
		{text: "443-443", want: AclPortRange{First: 443, Last: 443}},
		{text: "tcp:443", want: AclPortRange{Protocol: 6, First: 443, Last: 443}},
		{text: "tcp:*", want: AclPortRange{Protocol: 6, Last: 65535}},
		{text: "tcp:8000-8100", want: AclPortRange{Protocol: 6, First: 8000, Last: 8100}},
		{text: "udp:53", want: AclPortRange{Protocol: 17, First: 53, Last: 53}},
		{text: "udp:*", want: AclPortRange{Protocol: 17, Last: 65535}},
		{text: "icmp:*", want: AclPortRange{Protocol: 1, Last: 65535}},
	}
	for _, c := range cases {
		got, err := parseAclPortRange(c.text)
		if err != nil {
			t.Errorf("%s: %v", c.text, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: %+v", c.text, got)
		}
	}
	for _, text := range []string{
		"", "0", "00", "0443", "+443", "-1", "65536", "443-", "-443", "8100-8000", "1-2-3", "a", "1.5", "tcp", "tcp:", "tcp:0",
		"tcp:65536", "tcp:443:80", "icmp", "icmp:8", "sctp:443", "6:443", "TCP:443", " 443", "443 ", "*-5", "5-*",
	} {
		if got, err := parseAclPortRange(text); err == nil {
			t.Errorf("%q passed as %+v", text, got)
		} else if !errors.Is(err, ErrAclPolicyInvalid) {
			t.Errorf("%q: %v", text, err)
		}
	}
}
