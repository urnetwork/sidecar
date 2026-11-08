// ParseAclPolicy over §8.5's two documents and a document holding every key, each refusal, the bounds,
// and aclStandardizeHujson. Fixtures and fuzz seeds are embedded, so these run the same on every leg:
// the sidecar_http Worker has no file system. acl_policy_host_test.go holds what needs one, and what
// is too heavy for that leg.

package sidecar

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/acl/policy testdata/fuzz/FuzzParseAclPolicy
var testAclPolicyFiles embed.FS

func testAclPolicyFixture(t *testing.T, name string) []byte {
	t.Helper()
	source, err := testAclPolicyFiles.ReadFile("testdata/acl/policy/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func testParseAclPolicy(t *testing.T, source []byte) *AclPolicy {
	t.Helper()
	policy, err := ParseAclPolicy(source)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testTag(name string) AclSelector {
	return AclSelector{Kind: AclSelectorTag, Name: name}
}

func testSubject(selector AclSelector) AclResource {
	return AclResource{Kind: AclResourceSubject, Subject: selector}
}

func testNamed(kind AclResourceKind, name string) AclResource {
	return AclResource{Kind: kind, Name: name}
}

var (
	testAutogroupMember   = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	testAutogroupAdmin    = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)
	testAutogroupTagged   = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED)
	testAutogroupNetwork  = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK)
	testAutogroupUntagged = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED)
	testAutogroupSelf     = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)
	testAutogroupSponsor  = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR)
	testAutogroupDstOwner = testAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER)
)

const (
	testActionDial    = protocol.AclAction_ACL_ACTION_DIAL
	testActionListen  = protocol.AclAction_ACL_ACTION_LISTEN
	testActionRoute   = protocol.AclAction_ACL_ACTION_ROUTE
	testActionRead    = protocol.AclAction_ACL_ACTION_READ
	testActionWrite   = protocol.AclAction_ACL_ACTION_WRITE
	testActionAdmin   = protocol.AclAction_ACL_ACTION_ADMIN
	testActionDeposit = protocol.AclAction_ACL_ACTION_DEPOSIT
	testActionPublish = protocol.AclAction_ACL_ACTION_PUBLISH
	testActionSend    = protocol.AclAction_ACL_ACTION_SEND
)

var (
	testEvidenceAll = []AclEvidence{AclEvidenceDevice, AclEvidencePresence, AclEvidenceHarness}
	testEvidenceTwo = []AclEvidence{AclEvidenceDevice, AclEvidencePresence}
)

// §8.5's worked example, every value of it, compared whole.
func TestParseAclPolicyWorkedExample(t *testing.T) {
	policy := testParseAclPolicy(t, testAclPolicyFixture(t, "worked_example.hujson"))
	group := AclSelector{Kind: AclSelectorGroup, Name: "eng"}
	want := &AclPolicy{
		Groups: []AclGroup{{Group: group, Members: []AclSelector{
			{Kind: AclSelectorUser, Name: "dana@acme.example"},
			{Kind: AclSelectorUser, Name: "amir@acme.example"},
		}}},
		TagOwners: []AclTagOwner{
			{Tag: testTag("recurd"), Owners: []AclSelector{group}},
			{Tag: testTag("db"), Owners: []AclSelector{testAutogroupAdmin}},
			{Tag: testTag("api"), Owners: []AclSelector{testAutogroupAdmin}},
			{Tag: testTag("audit"), Owners: []AclSelector{testAutogroupAdmin}},
		},
		Grants: []AclGrant{
			{
				Src:   []AclSelector{testAutogroupUntagged},
				Dst:   []AclResource{testSubject(testAutogroupSelf)},
				Allow: []protocol.AclAction{testActionDial, testActionRoute},
			},
			{
				Src:   []AclSelector{testTag("recurd")},
				Dst:   []AclResource{testNamed(AclResourceRepo, "repo-x")},
				Allow: []protocol.AclAction{testActionWrite},
			},
			{
				Src:   []AclSelector{group},
				Dst:   []AclResource{testNamed(AclResourceSocket, "db")},
				Allow: []protocol.AclAction{testActionDial},
			},
			{
				Src:   []AclSelector{testTag("db")},
				Dst:   []AclResource{testNamed(AclResourceSocket, "db")},
				Allow: []protocol.AclAction{testActionListen},
			},
			{
				Src:     []AclSelector{{Kind: AclSelectorNetwork, Name: "partner-y"}},
				Dst:     []AclResource{testSubject(testTag("api"))},
				Allow:   []protocol.AclAction{testActionDial},
				Ip:      []AclPortRange{{Protocol: 6, First: 443, Last: 443}},
				Expires: time.Date(2026, time.December, 31, 0, 0, 0, 0, time.UTC),
			},
			{
				Src:   []AclSelector{testTag("recurd")},
				Dst:   []AclResource{testSubject(testAutogroupSelf)},
				Allow: []protocol.AclAction{testActionDial},
				Ip:    []AclPortRange{{Protocol: 6, First: 443, Last: 443}},
			},
		},
		Requests: []AclRequest{{
			Src:       []AclSelector{testTag("recurd")},
			Dst:       []AclResource{testNamed(AclResourceDns, "*-preview"), testNamed(AclResourceSocket, "tls/443/*-preview")},
			Allow:     []protocol.AclAction{testActionListen, testActionPublish},
			Approver:  []AclSelector{testAutogroupSponsor},
			Approvers: 1,
			MaxExpiry: 24 * time.Hour,
			Evidence:  testEvidenceTwo,
		}},
		Audit: &AclAuditBlock{
			Reader: testTag("audit"),
			RepoKinds: []protocol.RepoKind{
				protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX,
			},
		},
		Tests: []AclPolicyTest{{
			Src:    AclSelector{Kind: AclSelectorUser, Name: "dana@acme.example"},
			Accept: []AclPolicyCheck{{Resource: testNamed(AclResourceSocket, "db"), Action: testActionDial}},
			Deny:   []AclPolicyCheck{{Resource: testNamed(AclResourceRepo, "secrets"), Action: testActionRead}},
		}},
		ExpiresDefault:  time.Hour,
		EvidenceDefault: testEvidenceAll,
	}
	if !reflect.DeepEqual(policy, want) {
		t.Errorf("got %+v", policy)
	}
}

// §8.5's implicit document, every value of it, compared whole.
func TestParseAclPolicyImplicitDocument(t *testing.T) {
	policy := testParseAclPolicy(t, testAclPolicyFixture(t, "implicit_document.hujson"))
	allActions := []protocol.AclAction{
		testActionDial, testActionListen, testActionRoute, testActionRead, testActionWrite,
		testActionAdmin, testActionDeposit, testActionPublish, testActionSend,
	}
	want := &AclPolicy{
		Grants: []AclGrant{
			{
				Src:   []AclSelector{testAutogroupMember, testAutogroupUntagged},
				Dst:   []AclResource{{Kind: AclResourceAll}},
				Allow: allActions,
			},
			{
				Src:   []AclSelector{testAutogroupMember},
				Dst:   []AclResource{testNamed(AclResourceRepo, "*")},
				Allow: []protocol.AclAction{testActionWrite, testActionAdmin},
			},
			{
				Src:   []AclSelector{testAutogroupTagged},
				Dst:   []AclResource{testNamed(AclResourceRepo, "*")},
				Allow: []protocol.AclAction{testActionDeposit},
			},
			{
				Src:   []AclSelector{testAutogroupTagged},
				Dst:   []AclResource{testSubject(testAutogroupSelf)},
				Allow: []protocol.AclAction{testActionDial},
				Ip:    []AclPortRange{{Protocol: 6, First: 443, Last: 443}},
			},
		},
		Requests: []AclRequest{
			{
				Src: []AclSelector{testAutogroupNetwork},
				Dst: []AclResource{
					testNamed(AclResourceDns, "*"), testNamed(AclResourceSocket, "tls/*"), testNamed(AclResourceSocket, "smtp/*"),
				},
				Allow:     []protocol.AclAction{testActionListen, testActionPublish},
				Approver:  []AclSelector{testAutogroupAdmin},
				Approvers: 1,
				MaxExpiry: 7 * 24 * time.Hour,
			},
			{
				Src: []AclSelector{testAutogroupTagged},
				Dst: []AclResource{
					{Kind: AclResourceAll}, testNamed(AclResourceSocket, "*"), testNamed(AclResourceRepo, "*"), testNamed(AclResourceMail, "*"),
				},
				Allow: []protocol.AclAction{
					testActionDial, testActionListen, testActionRoute, testActionRead, testActionWrite, testActionSend,
				},
				Approver:  []AclSelector{testAutogroupSelf},
				Approvers: 1,
				MaxExpiry: 30 * 24 * time.Hour,
			},
			{
				Src:       []AclSelector{{Kind: AclSelectorNetwork, Name: "*"}},
				Dst:       []AclResource{{Kind: AclResourceAll}},
				Allow:     []protocol.AclAction{testActionDial, testActionRoute},
				Approver:  []AclSelector{testAutogroupAdmin},
				Approvers: 1,
				MaxExpiry: 30 * 24 * time.Hour,
			},
			{
				Src: []AclSelector{testAutogroupMember, testAutogroupTagged},
				Dst: []AclResource{
					testSubject(testAutogroupMember), testSubject(testAutogroupTagged), testNamed(AclResourceSocket, "*"),
				},
				Allow:     []protocol.AclAction{testActionDial},
				Approver:  []AclSelector{testAutogroupDstOwner},
				Approvers: 1,
				MaxExpiry: 30 * 24 * time.Hour,
				Evidence:  testEvidenceTwo,
			},
		},
		ExpiresDefault:  time.Hour,
		EvidenceDefault: testEvidenceAll,
	}
	if !reflect.DeepEqual(policy, want) {
		t.Errorf("got %+v", policy)
	}
}

// A document that writes every key, read for each value a key takes that §8.5's two do not.
func TestParseAclPolicyEveryField(t *testing.T) {
	policy := testParseAclPolicy(t, testAclPolicyFixture(t, "every_field.hujson"))

	if got := len(policy.Groups); got != 3 {
		t.Fatalf("%d groups", got)
	}
	if got := policy.Groups[0].Members[1]; got != (AclSelector{Kind: AclSelectorUser, Name: "amir@acme.example"}) {
		t.Errorf("a folded member: %+v", got)
	}
	if got := policy.Groups[1].Group; got != (AclSelector{Kind: AclSelectorGroup, Name: "scim-synced@acme.example"}) {
		t.Errorf("a SCIM group: %+v", got)
	}
	if got := policy.Groups[2].Members; got == nil || len(got) != 0 {
		t.Errorf("an empty group: %+v", got)
	}
	if got := len(policy.TagOwners[0].Owners); got != 4 {
		t.Errorf("%d tag owners", got)
	}
	if got := policy.TagOwners[1].Owners; got == nil || len(got) != 0 {
		t.Errorf("no owners: %+v", got)
	}

	wantHosts := []AclHost{
		{Name: "office", Cidr: netip.MustParsePrefix("192.0.2.0/24")},
		{Name: "printer", Cidr: netip.MustParsePrefix("198.51.100.7/32")},
		{Name: "lab-v6", Cidr: netip.MustParsePrefix("2001:db8::/32")},
		{Name: "router-v6", Cidr: netip.MustParsePrefix("2001:db8::1/128")},
	}
	if !reflect.DeepEqual(policy.Hosts, wantHosts) {
		t.Errorf("hosts %+v", policy.Hosts)
	}

	first := policy.Grants[0]
	if first.Id != "rule-one" {
		t.Errorf("id %q", first.Id)
	}
	if first.Note != `one note with /* no comment */ and // none here, "quoted"` {
		t.Errorf("note %q", first.Note)
	}
	if len(first.Src) != 12 || len(first.Dst) != 5 {
		t.Errorf("%d src and %d dst", len(first.Src), len(first.Dst))
	}
	wantPorts := []AclPortRange{
		{Protocol: 6, First: 443, Last: 443},
		{Protocol: 17, First: 53, Last: 53},
		{Protocol: 6, First: 8000, Last: 8100},
		{First: 22, Last: 22},
		{First: 6000, Last: 6010},
		{Protocol: 17, Last: 65535},
		{Protocol: 1, Last: 65535},
		{Last: 65535},
	}
	if !reflect.DeepEqual(first.Ip, wantPorts) {
		t.Errorf("ip %+v", first.Ip)
	}

	routes := policy.Grants[1]
	if got := routes.Dst[2]; got != (AclResource{Kind: AclResourceIp, Name: "office", Cidr: netip.MustParsePrefix("192.0.2.0/24")}) {
		t.Errorf("a hosts name did not resolve: %+v", got)
	}
	if got := len(routes.Via); got != 3 {
		t.Errorf("%d via", got)
	}

	publish := policy.Grants[4]
	if publish.Sock == nil || *publish.Sock != testNamed(AclResourceSocket, "tls/443/blog") {
		t.Errorf("sock %+v", publish.Sock)
	}
	if publish.Audience != protocol.AclAudience_ACL_AUDIENCE_LINK || publish.AppMode != protocol.AclAppMode_ACL_APP_MODE_RAW {
		t.Errorf("audience %d, app mode %d", publish.Audience, publish.AppMode)
	}
	wantPin := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}
	if !bytes.Equal(publish.LinkSpkiSha256, wantPin) {
		t.Errorf("pin %x", publish.LinkSpkiSha256)
	}
	if want := time.Date(2026, time.December, 31, 0, 0, 0, 500_000_000, time.UTC); !publish.Expires.Equal(want) || publish.Expires.Location() != time.UTC {
		t.Errorf("expires %s", publish.Expires)
	}
	// members and http written out read as the zero values a grant leaving them out gets
	if got := policy.Grants[5]; got.Audience != protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED || got.AppMode != protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED {
		t.Errorf("audience %d, app mode %d", got.Audience, got.AppMode)
	}
	if got := policy.Grants[6].Audience; got != protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE {
		t.Errorf("audience %d", got)
	}
	if got := policy.Grants[7].Audience; got != protocol.AclAudience_ACL_AUDIENCE_PUBLIC {
		t.Errorf("audience %d", got)
	}
	// an action named twice, here through *, counts once
	if got := len(policy.Grants[9].Allow); got != 9 {
		t.Errorf("%d actions", got)
	}

	request := policy.Requests[0]
	if request.Id != "rule-two" || request.Note != "a request" {
		t.Errorf("id %q, note %q", request.Id, request.Note)
	}
	if request.Approvers != 2 || len(request.Approver) != 6 || request.MaxExpiry != 24*time.Hour {
		t.Errorf("%d of %d approvers, %s", request.Approvers, len(request.Approver), request.MaxExpiry)
	}
	if !reflect.DeepEqual(request.Evidence, testEvidenceAll) {
		t.Errorf("evidence %+v", request.Evidence)
	}
	if got := request.Dst[2].Cidr; got != netip.MustParsePrefix("198.51.100.7/32") {
		t.Errorf("a request's hosts name did not resolve: %s", got)
	}
	if got := policy.Requests[1].MaxExpiry; got != 90*time.Minute {
		t.Errorf("maxExpiry %s", got)
	}
	if got := policy.Requests[2].MaxExpiry; got != 7*24*time.Hour {
		t.Errorf("maxExpiry %s", got)
	}
	// a rule naming no evidence keeps nil, so naming harness stays visible (owner decision 142)
	if got := policy.Requests[1].Evidence; got != nil {
		t.Errorf("evidence %+v", got)
	}

	if got := policy.Audit.Repos; len(got) != 2 || got[0] != testNamed(AclResourceRepo, "repo-x") ||
		got[1].RepoId != testParseId(t, testRepoIdText) {
		t.Errorf("audit repos %+v", got)
	}

	wantChecks := []AclPolicyCheck{
		{Resource: testNamed(AclResourceSocket, "db"), Action: testActionDial},
		{
			Resource: testSubject(testTag("recurd")),
			Action:   testActionDial,
			Ports:    &AclPortRange{Protocol: 6, First: 443, Last: 443},
		},
	}
	if !reflect.DeepEqual(policy.Tests[0].Accept, wantChecks) {
		t.Errorf("accept %+v", policy.Tests[0].Accept)
	}
	if got := policy.Tests[1].Src; got != testTag("recurd") {
		t.Errorf("a test's src %+v", got)
	}
	if got := policy.Tests[1].Accept[0]; got.Resource.Cidr != netip.MustParsePrefix("192.0.2.0/24") || *got.Ports != (AclPortRange{First: 443, Last: 443}) {
		t.Errorf("a hosts name in a test %+v", got)
	}
	if got := policy.Tests[2].Deny[1]; got.Resource.Kind != AclResourceAll || *got.Ports != (AclPortRange{Protocol: 17, First: 53, Last: 53}) {
		t.Errorf("a check on * %+v", got)
	}

	if policy.ExpiresDefault != 2*time.Hour || !reflect.DeepEqual(policy.EvidenceDefault, testEvidenceTwo) {
		t.Errorf("defaults %s, %+v", policy.ExpiresDefault, policy.EvidenceDefault)
	}
}

// §8.5's and §8.6's defaults, and what an empty document holds: nothing, so deny.
func TestParseAclPolicyDefaults(t *testing.T) {
	want := &AclPolicy{ExpiresDefault: time.Hour, EvidenceDefault: testEvidenceAll}
	if got := testParseAclPolicy(t, []byte(`{}`)); !reflect.DeepEqual(got, want) {
		t.Errorf("empty: %+v", got)
	}
	policy := testParseAclPolicy(t, []byte(`{"requests": [{"src": ["tag:a"], "dst": ["sock:db"], "allow": ["dial"]}]}`))
	request := policy.Requests[0]
	if !reflect.DeepEqual(request.Approver, []AclSelector{testAutogroupSelf}) {
		t.Errorf("approver %+v", request.Approver)
	}
	if request.Approvers != 1 {
		t.Errorf("approvers %d", request.Approvers)
	}
	if request.MaxExpiry != 30*24*time.Hour {
		t.Errorf("maxExpiry %s", request.MaxExpiry)
	}
	if request.Evidence != nil {
		t.Errorf("evidence %+v", request.Evidence)
	}
}

// A default written out reads as the same value as one left out, so writing it changes nothing a
// compile could see. A rule's own evidence is the one exception, kept apart on purpose: harness counts
// in a tainted run only where the rule itself names it (owner decision 142).
func TestParseAclPolicyWrittenDefaultsReadAsLeftOut(t *testing.T) {
	grant := `"src": ["tag:a"], "dst": ["dns:blog"], "allow": ["publish"]`
	request := `"src": ["tag:a"], "dst": ["sock:db"], "allow": ["dial"]`
	cases := []struct {
		written string
		leftOut string
	}{
		{written: `{"grants": [{` + grant + `, "audience": "members"}]}`, leftOut: `{"grants": [{` + grant + `}]}`},
		{written: `{"grants": [{` + grant + `, "app_mode": "http"}]}`, leftOut: `{"grants": [{` + grant + `}]}`},
		{written: `{"requests": [{` + request + `, "approver": ["autogroup:self"]}]}`, leftOut: `{"requests": [{` + request + `}]}`},
		{written: `{"requests": [{` + request + `, "approvers": 1}]}`, leftOut: `{"requests": [{` + request + `}]}`},
		{written: `{"requests": [{` + request + `, "maxExpiry": "30d"}]}`, leftOut: `{"requests": [{` + request + `}]}`},
		{written: `{"expiresDefault": "1h"}`, leftOut: `{}`},
		{written: `{"evidenceDefault": ["device", "presence", "harness"]}`, leftOut: `{}`},
	}
	for _, c := range cases {
		if written, leftOut := testParseAclPolicy(t, []byte(c.written)), testParseAclPolicy(t, []byte(c.leftOut)); !reflect.DeepEqual(written, leftOut) {
			t.Errorf("%s reads as %+v, and %s as %+v", c.written, written, c.leftOut, leftOut)
		}
	}
	named := testParseAclPolicy(t, []byte(`{"requests": [{`+request+`, "evidence": ["device", "presence", "harness"]}]}`))
	if leftOut := testParseAclPolicy(t, []byte(`{"requests": [{`+request+`}]}`)); reflect.DeepEqual(named, leftOut) {
		t.Error("a rule naming every channel reads as one naming none")
	}
}

// One refusal per row: the document, then the field and reason it must be refused for, so a case can't
// pass on some nearer fault than the one it plants.
var testAclPolicyRefusals = []struct {
	source string
	want   string
}{
	// not a document at all
	{source: ``, want: "not HuJSON"},
	{source: `   `, want: "not HuJSON"},
	{source: `// only a comment`, want: "not HuJSON"},
	{source: `{`, want: "not HuJSON"},
	{source: `}`, want: "not HuJSON"},
	{source: `{} {}`, want: "not HuJSON"},
	{source: `{},`, want: "not HuJSON"},
	{source: `,{}`, want: "not HuJSON"},
	{source: `{"grants": [`, want: "not HuJSON"},
	{source: `{"grants" []}`, want: "not HuJSON"},
	{source: `{"a": "unterminated`, want: "not HuJSON"},
	{source: `{"note": "tab	inside"}`, want: "not HuJSON"},
	{source: "\xef\xbb\xbf{}", want: "not HuJSON"},
	{source: "{}\x00", want: "not HuJSON"},
	{source: `{/* never closed`, want: "a block comment does not end"},
	{source: "{\"a\xff\": 1}", want: "not UTF-8"},
	{source: "{} // \xff", want: "not UTF-8"},
	{source: `[]`, want: "not an object"},
	{source: `null`, want: "not an object"},
	{source: `1`, want: "not an object"},
	{source: `"grants"`, want: "not an object"},
	// a comma that trails nothing
	{source: `{"grants": [,]}`, want: "not HuJSON"},
	{source: `{,}`, want: "not HuJSON"},
	{source: `{"grants": [{"src": ["tag:a"],,}]}`, want: "not HuJSON"},
	// comments do not join tokens
	{source: `{"tests": [{"src": "tag:a", "accept": ["*#dial"]}], "expiresDefault": tr/**/ue}`, want: "not HuJSON"},

	// an unknown key at every level, in the spellings a typo or Tailscale's own files would use
	{source: `{"grant": []}`, want: ": an unknown key"},
	{source: `{"Grants": []}`, want: ": an unknown key"},
	{source: `{"GRANTS": []}`, want: ": an unknown key"},
	{source: `{"acls": []}`, want: ": an unknown key"},
	{source: `{"postures": {}}`, want: ": an unknown key"},
	{source: `{"ssh": []}`, want: ": an unknown key"},
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "srcPosture": []}]}`, want: "grants[0]: invalid acl policy: an unknown key"},
	// no deny grants exist (D-ACL-2), so nothing a grant can say takes access away
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "deny": ["dial"]}]}`, want: "grants[0]: invalid acl policy: an unknown key"},
	{source: `{"grants": [{"action": "deny", "src": ["tag:a"], "dst": ["*"], "allow": ["dial"]}]}`, want: "grants[0]: invalid acl policy: an unknown key"},
	{source: `{"grants": [{"Src": ["tag:a"], "dst": ["*"], "allow": ["dial"]}]}`, want: "grants[0]: invalid acl policy: an unknown key"},
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "maxExpiry": "1h"}]}`, want: "grants[0]: invalid acl policy: an unknown key"},
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "approver": ["autogroup:admin"]}]}`, want: "grants[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "aprover": []}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"audit": {"reader": "tag:a", "repos": ["kind:vault"], "extra": 1}}`, want: "audit: invalid acl policy: an unknown key"},
	{source: `{"tests": [{"src": "tag:a", "accept": ["*#dial"], "proto": "tcp"}]}`, want: "tests[0]: invalid acl policy: an unknown key"},
	// the fields rows cannot carry on a requests rule (question acl-policy-request-rule-fields)
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "ip": ["tcp:443"]}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "via": ["tag:b"]}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "expires": "2026-12-31T00:00:00Z"}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["dns:*"], "allow": ["publish"], "sock": "sock:tls/*"}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["dns:*"], "allow": ["publish"], "audience": "public"}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["dns:*"], "allow": ["publish"], "app_mode": "raw"}]}`, want: "requests[0]: invalid acl policy: an unknown key"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["dns:*"], "allow": ["publish"], "link_spki_sha256": ""}]}`, want: "requests[0]: invalid acl policy: an unknown key"},

	// a key given twice at every level, however it is spelled
	{source: `{"grants": [], "grants": []}`, want: ": a key given twice"},
	{source: `{"grants": [], "\u0067rants": []}`, want: ": a key given twice"},
	{source: `{"groups": {"group:a": [], "group:a": []}}`, want: "groups: invalid acl policy: a key given twice"},
	{source: `{"groups": {"group:a": [], "group:\u0061": []}}`, want: "groups: invalid acl policy: a key given twice"},
	{source: `{"tagOwners": {"tag:a": [], "tag:a": []}}`, want: "tagOwners: invalid acl policy: a key given twice"},
	{source: `{"hosts": {"a": "192.0.2.1", "a": "192.0.2.2"}}`, want: "hosts: invalid acl policy: a key given twice"},
	{source: `{"grants": [{"src": ["tag:a"], "src": ["tag:b"], "dst": ["*"], "allow": ["dial"]}]}`, want: "grants[0]: invalid acl policy: a key given twice"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "approvers": 1, "approvers": 2}]}`, want: "requests[0]: invalid acl policy: a key given twice"},
	{source: `{"audit": {"reader": "tag:a", "reader": "tag:b", "repos": ["kind:vault"]}}`, want: "audit: invalid acl policy: a key given twice"},
	{source: `{"tests": [{"src": "tag:a", "accept": ["*#dial"], "accept": ["*#route"]}]}`, want: "tests[0]: invalid acl policy: a key given twice"},

	// a fault past a list's first entry names that entry, in a list of rules, of strings and of keys
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"]}, {"src": ["tag:a"], "dst": ["*", "sock:"], "allow": ["dial"]}]}`, want: "grants[1].dst[1]: invalid acl policy: not a socket name"},
	{source: `{"tests": [{"src": "tag:a", "accept": ["*#dial"]}, {"src": "tag:a", "deny": ["*#dial", "*#route", "*#leave"]}]}`, want: "tests[1].deny[2]: invalid acl policy: an unknown action"},
	{source: `{"groups": {"group:a": [], "group:b": ["dana@acme.example", "dana"]}}`, want: "groups[1][1]: invalid acl policy: not an email"},

	// a value of the wrong type, null included, at every key
	{source: `{"groups": []}`, want: "groups: invalid acl policy: not an object"},
	{source: `{"groups": null}`, want: "groups: invalid acl policy: not an object"},
	{source: `{"groups": {"group:a": "dana@acme.example"}}`, want: "groups[0]: invalid acl policy: not a list"},
	{source: `{"groups": {"group:a": [1]}}`, want: "groups[0][0]: invalid acl policy: not a string"},
	{source: `{"tagOwners": []}`, want: "tagOwners: invalid acl policy: not an object"},
	{source: `{"tagOwners": {"tag:a": "group:b"}}`, want: "tagOwners[0]: invalid acl policy: not a list"},
	{source: `{"hosts": []}`, want: "hosts: invalid acl policy: not an object"},
	{source: `{"hosts": {"a": 1}}`, want: "hosts[0]: invalid acl policy: not a string"},
	{source: `{"grants": {}}`, want: "grants: invalid acl policy: not a list"},
	{source: `{"grants": null}`, want: "grants: invalid acl policy: not a list"},
	{source: `{"grants": ["tag:a"]}`, want: "grants[0]: invalid acl policy: not an object"},
	{source: `{"grants": [{"src": "tag:a"}]}`, want: "grants[0].src: invalid acl policy: not a list"},
	{source: `{"grants": [{"src": [true]}]}`, want: "grants[0].src[0]: invalid acl policy: not a string"},
	{source: `{"grants": [{"dst": "*"}]}`, want: "grants[0].dst: invalid acl policy: not a list"},
	{source: `{"grants": [{"allow": "dial"}]}`, want: "grants[0].allow: invalid acl policy: not a list"},
	{source: `{"grants": [{"allow": [1]}]}`, want: "grants[0].allow[0]: invalid acl policy: not a string"},
	{source: `{"grants": [{"ip": "tcp:443"}]}`, want: "grants[0].ip: invalid acl policy: not a list"},
	{source: `{"grants": [{"ip": [443]}]}`, want: "grants[0].ip[0]: invalid acl policy: not a string"},
	{source: `{"grants": [{"via": "tag:a"}]}`, want: "grants[0].via: invalid acl policy: not a list"},
	{source: `{"grants": [{"expires": 1}]}`, want: "grants[0].expires: invalid acl policy: not a string"},
	{source: `{"grants": [{"id": 1}]}`, want: "grants[0].id: invalid acl policy: not a string"},
	{source: `{"grants": [{"note": null}]}`, want: "grants[0].note: invalid acl policy: not a string"},
	{source: `{"grants": [{"sock": ["sock:db"]}]}`, want: "grants[0].sock: invalid acl policy: not a string"},
	{source: `{"grants": [{"audience": 1}]}`, want: "grants[0].audience: invalid acl policy: not a string"},
	{source: `{"grants": [{"app_mode": 1}]}`, want: "grants[0].app_mode: invalid acl policy: not a string"},
	{source: `{"grants": [{"link_spki_sha256": 1}]}`, want: "grants[0].link_spki_sha256: invalid acl policy: not a string"},
	{source: `{"requests": {}}`, want: "requests: invalid acl policy: not a list"},
	{source: `{"requests": [{"approver": "autogroup:admin"}]}`, want: "requests[0].approver: invalid acl policy: not a list"},
	{source: `{"requests": [{"approvers": "2"}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"maxExpiry": 3600}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a string"},
	{source: `{"requests": [{"evidence": "device"}]}`, want: "requests[0].evidence: invalid acl policy: not a list"},
	{source: `{"audit": []}`, want: "audit: invalid acl policy: not an object"},
	{source: `{"audit": null}`, want: "audit: invalid acl policy: not an object"},
	{source: `{"audit": {"reader": ["tag:a"]}}`, want: "audit.reader: invalid acl policy: not a string"},
	{source: `{"audit": {"repos": "kind:vault"}}`, want: "audit.repos: invalid acl policy: not a list"},
	{source: `{"audit": {"reader": "tag:a", "repos": [1]}}`, want: "audit.repos[0]: invalid acl policy: not a string"},
	{source: `{"tests": {}}`, want: "tests: invalid acl policy: not a list"},
	{source: `{"tests": [{"src": ["tag:a"]}]}`, want: "tests[0].src: invalid acl policy: not a string"},
	{source: `{"tests": [{"accept": "*#dial"}]}`, want: "tests[0].accept: invalid acl policy: not a list"},
	{source: `{"tests": [{"deny": [1]}]}`, want: "tests[0].deny[0]: invalid acl policy: not a string"},
	{source: `{"expiresDefault": 3600}`, want: "expiresDefault: invalid acl policy: not a string"},
	{source: `{"evidenceDefault": "device"}`, want: "evidenceDefault: invalid acl policy: not a list"},

	// what makes a rule a rule
	{source: `{"grants": [{}]}`, want: "grants[0]: invalid acl policy: a rule with no src"},
	{source: `{"grants": [{"src": ["tag:a"], "allow": ["dial"]}]}`, want: "grants[0]: invalid acl policy: a rule with no dst"},
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"]}]}`, want: "grants[0]: invalid acl policy: a rule with no allow"},
	{source: `{"requests": [{"dst": ["*"], "allow": ["dial"]}]}`, want: "requests[0]: invalid acl policy: a rule with no src"},
	{source: `{"requests": [{"src": ["tag:a"], "allow": ["dial"]}]}`, want: "requests[0]: invalid acl policy: a rule with no dst"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["*"]}]}`, want: "requests[0]: invalid acl policy: a rule with no allow"},
	// an empty list must not read as the default, or as nothing to check
	{source: `{"grants": [{"src": []}]}`, want: "grants[0].src: invalid acl policy: an empty list"},
	{source: `{"grants": [{"dst": []}]}`, want: "grants[0].dst: invalid acl policy: an empty list"},
	{source: `{"grants": [{"allow": []}]}`, want: "grants[0].allow: invalid acl policy: an empty list"},
	{source: `{"grants": [{"ip": []}]}`, want: "grants[0].ip: invalid acl policy: an empty list"},
	{source: `{"grants": [{"via": []}]}`, want: "grants[0].via: invalid acl policy: an empty list"},
	{source: `{"requests": [{"approver": []}]}`, want: "requests[0].approver: invalid acl policy: an empty list"},
	{source: `{"requests": [{"evidence": []}]}`, want: "requests[0].evidence: invalid acl policy: an empty list"},
	{source: `{"evidenceDefault": []}`, want: "evidenceDefault: invalid acl policy: an empty list"},
	{source: `{"tests": [{"src": "tag:a", "accept": []}]}`, want: "tests[0].accept: invalid acl policy: an empty list"},
	{source: `{"tests": [{"src": "tag:a", "deny": []}]}`, want: "tests[0].deny: invalid acl policy: an empty list"},

	// each position refuses its own, by name
	{source: `{"grants": [{"src": ["*"]}]}`, want: "grants[0].src[0]: invalid acl policy: not a selector"},
	{source: `{"grants": [{"src": ["dana@acme.example"]}]}`, want: "grants[0].src[0]: invalid acl policy: not a selector"},
	{source: `{"grants": [{"src": ["autogroup:internet"]}]}`, want: "grants[0].src[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"src": ["autogroup:self"]}]}`, want: "grants[0].src[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"src": ["autogroup:sponsor"]}]}`, want: "grants[0].src[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"src": ["autogroup:dst-owner"]}]}`, want: "grants[0].src[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"dst": ["autogroup:public"]}]}`, want: "grants[0].dst[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"dst": ["autogroup:ephemeral"]}]}`, want: "grants[0].dst[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"dst": ["autogroup:sponsor"]}]}`, want: "grants[0].dst[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"dst": ["autogroup:dst-owner"]}]}`, want: "grants[0].dst[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"dst": ["evs:repo-x/src"]}]}`, want: "grants[0].dst[0]: invalid acl policy: a path, which an evs: resource never is (X2)"},
	{source: `{"grants": [{"via": ["autogroup:internet"]}]}`, want: "grants[0].via[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"grants": [{"via": ["network:partner-y"]}]}`, want: "grants[0].via[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"requests": [{"approver": ["tag:a"]}]}`, want: "requests[0].approver[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"requests": [{"approver": ["autogroup:tagged"]}]}`, want: "requests[0].approver[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"requests": [{"approver": ["autogroup:public"]}]}`, want: "requests[0].approver[0]: invalid acl policy: a selector this position does not take"},
	{source: `{"requests": [{"approver": ["dana@acme.example"]}]}`, want: "requests[0].approver[0]: invalid acl policy: not a selector"},
	{source: `{"tagOwners": {"tag:a": ["tag:b"]}}`, want: "tagOwners[0][0]: invalid acl policy: a selector this position does not take"},
	{source: `{"tagOwners": {"tag:a": ["autogroup:tagged"]}}`, want: "tagOwners[0][0]: invalid acl policy: a selector this position does not take"},
	{source: `{"groups": {"group:a": ["group:b"]}}`, want: "groups[0][0]: invalid acl policy: a selector this position does not take"},
	{source: `{"groups": {"group:a": ["autogroup:member"]}}`, want: "groups[0][0]: invalid acl policy: a selector this position does not take"},
	{source: `{"groups": {"group:a": ["dana"]}}`, want: "groups[0][0]: invalid acl policy: not an email"},
	{source: `{"audit": {"reader": "autogroup:member"}}`, want: "audit.reader: invalid acl policy: a selector this position does not take"},
	{source: `{"audit": {"reader": "group:a"}}`, want: "audit.reader: invalid acl policy: a selector this position does not take"},
	{source: `{"tests": [{"src": "autogroup:internet"}]}`, want: "tests[0].src: invalid acl policy: a selector this position does not take"},
	{source: `{"tests": [{"src": "*"}]}`, want: "tests[0].src: invalid acl policy: not an email"},

	// a section's keys
	{source: `{"groups": {"eng": []}}`, want: "groups[0]: invalid acl policy: not a selector"},
	{source: `{"groups": {"tag:a": []}}`, want: "groups[0]: invalid acl policy: a groups key that is not group:<name>"},
	{source: `{"groups": {"group:a": [], "group:B": []}}`, want: "groups[1]: invalid acl policy: not a group name"},
	{source: `{"tagOwners": {"recurd": []}}`, want: "tagOwners[0]: invalid acl policy: not a selector"},
	{source: `{"tagOwners": {"group:a": []}}`, want: "tagOwners[0]: invalid acl policy: a tagOwners key that is not tag:<name>"},
	{source: `{"tagOwners": {"tag:A": []}}`, want: "tagOwners[0]: invalid acl policy: not a tag name"},
	{source: `{"hosts": {"Office": "192.0.2.1"}}`, want: "hosts[0]: invalid acl policy: not a hosts name"},
	{source: `{"hosts": {"192.0.2.1": "192.0.2.1"}}`, want: "hosts[0]: invalid acl policy: not a hosts name"},
	// a name and not a pattern, since ip: names one entry
	{source: `{"hosts": {"of*ce": "192.0.2.1"}}`, want: "hosts[0]: invalid acl policy: not a hosts name"},
	{source: `{"hosts": {"a": "printer"}}`, want: "hosts[0]: invalid acl policy: not an address or cidr"},
	{source: `{"hosts": {"a": ""}}`, want: "hosts[0]: invalid acl policy: not an address or cidr"},
	{source: `{"hosts": {"a": "192.0.2.1/24"}}`, want: "hosts[0]: invalid acl policy: not a cidr"},
	{source: `{"hosts": {"a": "::ffff:192.0.2.1"}}`, want: "hosts[0]: invalid acl policy: not an address or cidr"},
	{source: `{"hosts": {"a": "fe80::1%eth0"}}`, want: "hosts[0]: invalid acl policy: not an address or cidr"},

	// an ip: name hosts does not hold, wherever it is written
	{source: `{"grants": [{"src": ["tag:a"], "dst": ["*", "ip:office"], "allow": ["route"]}]}`, want: "grants[0].dst[1]: invalid acl policy: an ip: name that hosts does not hold"},
	{source: `{"requests": [{"src": ["tag:a"], "dst": ["ip:office"], "allow": ["route"]}]}`, want: "requests[0].dst[0]: invalid acl policy: an ip: name that hosts does not hold"},
	{source: `{"tests": [{"src": "tag:a", "accept": ["ip:office#route"]}]}`, want: "tests[0].accept[0]: invalid acl policy: an ip: name that hosts does not hold"},
	{source: `{"tests": [{"src": "tag:a", "accept": ["*#dial"], "deny": ["ip:office#route"]}]}`, want: "tests[0].deny[0]: invalid acl policy: an ip: name that hosts does not hold"},

	// each field's values
	{source: `{"grants": [{"allow": ["connect"]}]}`, want: "grants[0].allow[0]: invalid acl policy: an unknown action"},
	{source: `{"grants": [{"allow": ["Dial"]}]}`, want: "grants[0].allow[0]: invalid acl policy: an unknown action"},
	{source: `{"grants": [{"ip": ["tcp:0"]}]}`, want: "grants[0].ip[0]: invalid acl policy: not a port"},
	{source: `{"grants": [{"ip": ["tcp:9000-8000"]}]}`, want: "grants[0].ip[0]: invalid acl policy: a port range running backward"},
	{source: `{"grants": [{"ip": ["sctp:443"]}]}`, want: "grants[0].ip[0]: invalid acl policy: an unknown ip protocol"},
	{source: `{"grants": [{"ip": ["icmp:8"]}]}`, want: "grants[0].ip[0]: invalid acl policy: ports on icmp"},
	{source: `{"grants": [{"expires": "tomorrow"}]}`, want: "grants[0].expires: invalid acl policy: not an RFC 3339 time after the epoch"},
	{source: `{"grants": [{"expires": "2026-12-31"}]}`, want: "grants[0].expires: invalid acl policy: not an RFC 3339 time after the epoch"},
	{source: `{"grants": [{"expires": "2026-12-31T00:00:00"}]}`, want: "grants[0].expires: invalid acl policy: not an RFC 3339 time after the epoch"},
	{source: `{"grants": [{"expires": "2026-02-30T00:00:00Z"}]}`, want: "grants[0].expires: invalid acl policy: not an RFC 3339 time after the epoch"},
	// rows read 0 as no expiry, so this would never end
	{source: `{"grants": [{"expires": "1970-01-01T00:00:00Z"}]}`, want: "grants[0].expires: invalid acl policy: not an RFC 3339 time after the epoch"},
	{source: `{"grants": [{"expires": "1969-12-31T23:59:59Z"}]}`, want: "grants[0].expires: invalid acl policy: not an RFC 3339 time after the epoch"},
	{source: `{"grants": [{"sock": "dns:blog"}]}`, want: "grants[0].sock: invalid acl policy: not a sock: resource"},
	{source: `{"grants": [{"sock": "tls/443/blog"}]}`, want: "grants[0].sock: invalid acl policy: not a resource"},
	{source: `{"grants": [{"audience": "everyone"}]}`, want: "grants[0].audience: invalid acl policy: an unknown audience"},
	{source: `{"grants": [{"app_mode": "tcp"}]}`, want: "grants[0].app_mode: invalid acl policy: an unknown app_mode"},
	{source: `{"grants": [{"link_spki_sha256": "00"}]}`, want: "grants[0].link_spki_sha256: invalid acl policy: not a lowercase hex SHA-256"},
	{source: `{"grants": [{"link_spki_sha256": "AABB0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}]}`, want: "grants[0].link_spki_sha256: invalid acl policy: not a lowercase hex SHA-256"},
	{source: `{"grants": [{"link_spki_sha256": "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}]}`, want: "grants[0].link_spki_sha256: invalid acl policy: not a lowercase hex SHA-256"},
	{source: `{"requests": [{"approvers": 0}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"approvers": -1}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"approvers": 1.5}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"approvers": 1.0}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"approvers": 2e0}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"approvers": 4294967296}]}`, want: "requests[0].approvers: invalid acl policy: not a count"},
	{source: `{"requests": [{"maxExpiry": "0h"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "24"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "h"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": ""}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "1s"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "01h"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "-1h"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "1.5h"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "1h30m"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "107000d"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"maxExpiry": "99999999999999999999d"}]}`, want: "requests[0].maxExpiry: invalid acl policy: not a duration"},
	{source: `{"requests": [{"evidence": ["email"]}]}`, want: "requests[0].evidence[0]: invalid acl policy: an unknown evidence channel"},
	{source: `{"expiresDefault": "0h"}`, want: "expiresDefault: invalid acl policy: not a duration"},
	{source: `{"evidenceDefault": ["Device"]}`, want: "evidenceDefault[0]: invalid acl policy: an unknown evidence channel"},

	// the audit block
	{source: `{"audit": {}}`, want: "invalid acl policy: an audit block with no reader"},
	{source: `{"audit": {"repos": ["kind:vault"]}}`, want: "invalid acl policy: an audit block with no reader"},
	{source: `{"audit": {"reader": "tag:a"}}`, want: "invalid acl policy: an audit block with no repos"},
	{source: `{"audit": {"reader": "tag:a", "repos": []}}`, want: "invalid acl policy: an audit block with no repos"},
	{source: `{"audit": {"reader": "tag:a", "repos": ["kind:nothing"]}}`, want: "audit.repos[0]: invalid acl policy: an unknown repo kind"},
	{source: `{"audit": {"reader": "tag:a", "repos": ["evs:*"]}}`, want: "audit.repos[0]: invalid acl policy: not a repo kind or an exact repo"},
	{source: `{"audit": {"reader": "tag:a", "repos": ["evs:repo-*"]}}`, want: "audit.repos[0]: invalid acl policy: not a repo kind or an exact repo"},
	{source: `{"audit": {"reader": "tag:a", "repos": ["sock:db"]}}`, want: "audit.repos[0]: invalid acl policy: not a repo kind or an exact repo"},
	{source: `{"audit": {"reader": "tag:a", "repos": ["repo-x"]}}`, want: "audit.repos[0]: invalid acl policy: not a resource"},

	// tests
	{source: `{"tests": [{}]}`, want: "tests[0]: invalid acl policy: a test with no src"},
	{source: `{"tests": [{"accept": ["*#dial"]}]}`, want: "tests[0]: invalid acl policy: a test with no src"},
	{source: `{"tests": [{"src": "tag:a"}]}`, want: "tests[0]: invalid acl policy: a test with no accept or deny"},
	{source: `{"tests": [{"accept": ["sock:db"]}]}`, want: "tests[0].accept[0]: invalid acl policy: no #action"},
	{source: `{"tests": [{"accept": ["#dial"]}]}`, want: "tests[0].accept[0]: invalid acl policy: not a resource"},
	{source: `{"tests": [{"accept": ["sock:db#"]}]}`, want: "tests[0].accept[0]: invalid acl policy: an unknown action"},
	{source: `{"tests": [{"accept": ["sock:db#*"]}]}`, want: "tests[0].accept[0]: invalid acl policy: an unknown action"},
	{source: `{"tests": [{"accept": ["sock:db#connect"]}]}`, want: "tests[0].accept[0]: invalid acl policy: an unknown action"},
	{source: `{"tests": [{"accept": ["sock:db#dial:443"]}]}`, want: "tests[0].accept[0]: invalid acl policy: ports on a resource that has none"},
	{source: `{"tests": [{"accept": ["evs:repo-x#read:443"]}]}`, want: "tests[0].accept[0]: invalid acl policy: ports on a resource that has none"},
	{source: `{"tests": [{"accept": ["tag:a#dial:0"]}]}`, want: "tests[0].accept[0]: invalid acl policy: not a port"},
	{source: `{"tests": [{"deny": ["evs:a/b#read"]}]}`, want: "tests[0].deny[0]: invalid acl policy: a path, which an evs: resource never is (X2)"},
}

func TestParseAclPolicyRefusals(t *testing.T) {
	for _, c := range testAclPolicyRefusals {
		policy, err := ParseAclPolicy([]byte(c.source))
		if err == nil {
			t.Errorf("%s passed as %+v", c.source, policy)
			continue
		}
		if policy != nil {
			t.Errorf("%s: a policy beside the error", c.source)
		}
		if !errors.Is(err, ErrAclPolicyInvalid) {
			t.Errorf("%s: %v does not wrap ErrAclPolicyInvalid", c.source, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, not %q", c.source, err, c.want)
		}
	}
}

// Each refusal's nearest document that passes, so a rule above cannot be refusing everything near it.
func TestParseAclPolicyNearestAccepted(t *testing.T) {
	for _, source := range []string{
		`{"grants": [],}`,
		`{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"],},],}`,
		`{"grants": [/*a*/{"src"/*b*/:/*c*/["tag:a"/*d*/,/*e*/]/*f*/,"dst":["*"],"allow":["dial"]}/*g*/,/*h*/]/*i*/}/*j*/`,
		"// first\n{ // second\r\n}\n// last",
		"{}\n/* last */\n",
		`{"tests": [{"src": "tag:a", "deny": ["*#dial"]}]}`,
		`{"tests": [{"src": "dana@acme.example", "accept": ["autogroup:internet#dial:tcp:443"]}]}`,
		`{"groups": {}, "tagOwners": {}, "hosts": {}, "grants": [], "requests": [], "tests": []}`,
		`{"groups": {"group:a": []}, "tagOwners": {"tag:a": []}}`,
		`{"grants": [{"\u0073rc": ["tag:\u0061"], "dst": ["*"], "allow": ["dial"]}]}`,
		`{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "expires": "1970-01-01T00:00:00.001Z"}]}`,
		`{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "expires": "9999-12-31T23:59:59Z"}]}`,
		`{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "id": "", "note": ""}]}`,
		`{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "approvers": 4294967295}]}`,
		`{"requests": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "maxExpiry": "106751d"}]}`,
		`{"audit": {"reader": "tag:a", "repos": ["evs:repo-x"]}}`,
		`{"hosts": {"192": "192.0.2.1"}, "grants": [{"src": ["tag:a"], "dst": ["ip:192"], "allow": ["route"]}]}`,
	} {
		if _, err := ParseAclPolicy([]byte(source)); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
}

// A refusal names where and which field, and never what it refused (I-13).
func TestAclPolicyRefusalsRepeatNoValue(t *testing.T) {
	const canary = "synthetic-canary"
	for _, source := range []string{
		`{"` + canary + `": 1}`,
		`{"grants": [{"` + canary + `": 1}]}`,
		`{"groups": {"group:` + canary + `": [], "group:` + canary + `": []}}`,
		`{"groups": {"group:a": ["` + canary + `"]}}`,
		`{"groups": {"` + canary + `": []}}`,
		`{"tagOwners": {"` + canary + `": []}}`,
		`{"hosts": {"` + canary + `": "` + canary + `"}}`,
		`{"hosts": {"` + canary + `!": "192.0.2.1"}}`,
		`{"grants": [{"src": ["` + canary + `"]}]}`,
		`{"grants": [{"src": ["tag:` + canary + `!"]}]}`,
		`{"grants": [{"src": ["autogroup:` + canary + `"]}]}`,
		`{"grants": [{"src": ["user:` + canary + `"]}]}`,
		`{"grants": [{"dst": ["` + canary + `"]}]}`,
		`{"grants": [{"dst": ["evs:` + canary + `/path"]}]}`,
		`{"grants": [{"dst": ["sock:` + canary + `!"]}]}`,
		`{"grants": [{"dst": ["dns:` + canary + `!"]}]}`,
		`{"grants": [{"dst": ["mail:` + canary + `!"]}]}`,
		`{"grants": [{"dst": ["ip:` + canary + `/8"]}]}`,
		`{"grants": [{"src": ["tag:a"], "dst": ["ip:` + canary + `"], "allow": ["route"]}]}`,
		`{"grants": [{"allow": ["` + canary + `"]}]}`,
		`{"grants": [{"expires": "` + canary + `"}]}`,
		`{"grants": [{"ip": ["` + canary + `:443"]}]}`,
		`{"grants": [{"audience": "` + canary + `"}]}`,
		`{"grants": [{"link_spki_sha256": "` + canary + `"}]}`,
		`{"requests": [{"maxExpiry": "` + canary + `"}]}`,
		`{"requests": [{"evidence": ["` + canary + `"]}]}`,
		`{"tests": [{"accept": ["` + canary + `"]}]}`,
		`{"audit": {"reader": "tag:a", "repos": ["kind:` + canary + `"]}}`,
		`{"note": "` + canary + `` + "\n" + `"}`,
	} {
		_, err := ParseAclPolicy([]byte(source))
		if err == nil {
			t.Errorf("%s passed", source)
			continue
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("%s: %v", source, err)
		}
	}
}

// A refusal's line and column are the source's, past comments, which standardizing keeps the place of.
func TestAclPolicyRefusalsNameTheirPlace(t *testing.T) {
	cases := []struct {
		source string
		want   string
	}{
		{source: "{\n  // a comment\n  \"grants\": [\n    { /* a\n    block */ \"src\": [\"nothing\"] }\n  ]\n}\n", want: "line 5, column 31, grants[0].src[0]: "},
		{source: "{\n\n  \"nothing\": 1\n}\n", want: "line 3, column 12: "},
		{source: "{\n  \"grants\": [,]\n}\n", want: "line 2, column 15: "},
		{source: "\n\n{\"a\xff\": 1}", want: "not UTF-8"},
	}
	for _, c := range cases {
		_, err := ParseAclPolicy([]byte(c.source))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v", c.source, err)
		}
	}
}

// Nesting stops before encoding/json, which recurses per level and on the Worker leg overflows a stack
// no recover reaches, so this test fails there by killing the leg's whole run. The deepest cases sit
// just under encoding/json's own limit of 10,000, which is as far as it would ever recurse.
func TestParseAclPolicyRefusesNesting(t *testing.T) {
	arrays := func(prefix string, count int, suffix string) []byte {
		return []byte(prefix + strings.Repeat("[", count) + strings.Repeat("]", count) + suffix)
	}
	objects := func(count int) []byte {
		return []byte(strings.Repeat(`{"a":`, count) + "1" + strings.Repeat("}", count))
	}
	for _, source := range [][]byte{
		arrays(``, 5, ``),
		arrays(`{"tests": [{"accept": `, 2, `}]}`),
		arrays(`{"tests": [{"accept": `, 9000, `}]}`),
		arrays(`{"grants": `, 9000, `}`),
		arrays(`{"groups": {"group:a": `, 9000, `}}`),
		arrays(`{"expiresDefault": `, 9000, `}`),
		arrays(``, 9000, ``),
		objects(5),
		objects(9000),
		// unbalanced, where a closer never comes
		[]byte(strings.Repeat("[", 9000)),
		[]byte(strings.Repeat(`{"a":`, 9000)),
		// a closer ahead of them must not buy depth back
		[]byte(strings.Repeat("]", 100) + strings.Repeat("[", 9000)),
	} {
		_, err := ParseAclPolicy(source)
		if err == nil || !errors.Is(err, ErrAclPolicyInvalid) || !strings.Contains(err.Error(), "nested too deep") {
			t.Errorf("%.40s: %v", source, err)
		}
	}
}

// Exactly the schema's depth reaches the schema, which refuses what it has no place for by name.
func TestParseAclPolicyNestingBelowTheBound(t *testing.T) {
	for _, c := range []struct {
		source string
		want   string
	}{
		{source: `{"tests": [{"src": "tag:a", "accept": ["*#dial"]}]}`, want: ""},
		{source: `{"grants": [[]]}`, want: "grants[0]: invalid acl policy: not an object"},
		{source: `{"grants": [[[]]]}`, want: "grants[0]: invalid acl policy: not an object"},
		{source: `{"grants": [{"src": []}]}`, want: "grants[0].src: invalid acl policy: an empty list"},
		{source: `{"grants": [{"src": [{}]}]}`, want: "nested too deep"},
		{source: `{"tests": [{"accept": [[]]}]}`, want: "nested too deep"},
		{source: `{"tests": [{"accept": [1]}]}`, want: "tests[0].accept[0]: invalid acl policy: not a string"},
		{source: `{"groups": {"group:a": [[]]}}`, want: "groups[0][0]: invalid acl policy: not a string"},
		{source: `{"a": {"b": {"c": {"d": 1}}}}`, want: ": an unknown key"},
		{source: `{"a": {"b": {"c": {"d": {}}}}}`, want: "nested too deep"},
		// a closed list gives back the one level it took, so a sibling after it is held to the same bound
		{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"]}], "tests": [{"accept": [[]]}]}`, want: "nested too deep"},
		// and a closed document gives back its own, so a second value after it is refused as one
		{source: `{} [[[[]]]]`, want: "not HuJSON"},
		// brackets inside a string or comment are not nesting
		{source: `{"grants": [{"src": ["tag:a"], "dst": ["*"], "allow": ["dial"], "note": "[[[[[[{{{{{{"}]}`, want: ""},
		{source: `{/* [[[[[[ {{{{{{ */} // [[[[[[`, want: ""},
	} {
		_, err := ParseAclPolicy([]byte(c.source))
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.source, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, not %q", c.source, err, c.want)
		}
	}
}

// What one parse allocates in all, its garbage included.
func testAclPolicyAllocatedByteCount(parse func()) uint64 {
	var before runtime.MemStats
	var after runtime.MemStats
	runtime.ReadMemStats(&before)
	parse()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// What a parse may allocate in all, garbage included, as a multiple of its source and a fixed part for
// the decoder's buffers. The worst source below measures 170x, nearly all of it a list of bare stars
// reallocated as it grows, and this holds a little above that, so a change that grows a parse faster
// than its source fails here.
const (
	testAclPolicyAllocationFactor    = 200
	testAclPolicyAllocationByteCount = 256 * 1024
)

func testAclPolicyAllocationBound(source []byte) uint64 {
	return testAclPolicyAllocationFactor*uint64(len(source)) + testAclPolicyAllocationByteCount
}

// aclStandardizeHujson: what becomes spaces, what must not, and that bytes stay where they were.
func TestAclStandardizeHujson(t *testing.T) {
	cases := []struct {
		source string
		want   string
	}{
		{source: ``, want: ``},
		{source: `{}`, want: `{}`},
		{source: `[1,2]`, want: `[1,2]`},
		// comments
		{source: "// a\n{}", want: "    \n{}"},
		{source: "{} // a", want: "{}     "},
		{source: "{}//", want: "{}  "},
		{source: "/* a */{}", want: "       {}"},
		{source: "/**/{}", want: "    {}"},
		{source: "/***/{}", want: "     {}"},
		{source: "/* a\nb */{}", want: "    \n    {}"},
		{source: "/* // */{}", want: "        {}"},
		{source: "// /* a\n{}", want: "       \n{}"},
		{source: "// a\r\n{}", want: "    \r\n{}"},
		{source: "/* é */{}", want: "        {}"},
		{source: "{\"a\": /* b */ 1}", want: "{\"a\":         1}"},
		// a comment holds its place: it joins nothing
		{source: "tr/**/ue", want: "tr    ue"},
		{source: "1/**/2", want: "1    2"},
		{source: `"a"/**/"b"`, want: `"a"    "b"`},
		// not comments
		{source: `"//"`, want: `"//"`},
		{source: `"/* a */"`, want: `"/* a */"`},
		{source: `{"a": "http://x"} // b`, want: `{"a": "http://x"}     `},
		{source: `"\"//"`, want: `"\"//"`},
		{source: `"\\"//`, want: `"\\"  `},
		{source: `"\\\"//"`, want: `"\\\"//"`},
		{source: `/`, want: `/`},
		{source: `{}/`, want: `{}/`},
		{source: `/ /`, want: `/ /`},
		// trailing commas
		{source: `[1,]`, want: `[1 ]`},
		{source: `{"a":1,}`, want: `{"a":1 }`},
		{source: `[[1,],]`, want: `[[1 ] ]`},
		{source: `[{"a":[1,],},]`, want: `[{"a":[1 ] } ]`},
		{source: "[1, // a\n /* b */ ]", want: "[1      \n         ]"},
		{source: `["a",]`, want: `["a" ]`},
		{source: `[true,]`, want: `[true ]`},
		{source: `[null,]`, want: `[null ]`},
		{source: `[1.5e3,]`, want: `[1.5e3 ]`},
		{source: `[[],]`, want: `[[] ]`},
		{source: `[{},]`, want: `[{} ]`},
		// any of JSON's spaces between it and the closer, as an editor on any system leaves them
		{source: "[1,\t]", want: "[1 \t]"},
		{source: "[1,\r\n]", want: "[1 \r\n]"},
		{source: "{\"a\":1,\n}", want: "{\"a\":1 \n}"},
		{source: "[1,\r\n\t// a\r\n]", want: "[1 \r\n\t    \r\n]"},
		// not trailing
		{source: `[1,2]`, want: `[1,2]`},
		{source: `[1,/* a */2]`, want: `[1,       2]`},
		{source: `{"a":1,"b":2}`, want: `{"a":1,"b":2}`},
		{source: `",]"`, want: `",]"`},
		// a comma that follows no value stays, for encoding/json to refuse
		{source: `[,]`, want: `[,]`},
		{source: `{,}`, want: `{,}`},
		{source: `[1,,]`, want: `[1,,]`},
		{source: `[,,]`, want: `[,,]`},
		{source: `{"a":,}`, want: `{"a":,}`},
		{source: `,]`, want: `,]`},
		{source: `{},`, want: `{},`},
		{source: `,`, want: `,`},
		// a closer that opens the text stays, as does the byte it is
		{source: `]`, want: `]`},
		{source: `}`, want: `}`},
		// one that never closes passes through, to be refused there
		{source: `"abc`, want: `"abc`},
		{source: `"abc\`, want: `"abc\`},
		{source: `[1,`, want: `[1,`},
	}
	for _, c := range cases {
		source := []byte(c.source)
		got, err := aclStandardizeHujson(source)
		if err != nil {
			t.Errorf("%q: %v", c.source, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%q: %q, not %q", c.source, got, c.want)
		}
		if len(got) != len(c.source) {
			t.Errorf("%q: %d bytes became %d", c.source, len(c.source), len(got))
		}
		if string(source) != c.source {
			t.Errorf("%q: the source changed to %q", c.source, source)
		}
		again, err := aclStandardizeHujson(got)
		if err != nil || !bytes.Equal(again, got) {
			t.Errorf("%q: standardized again to %q, %v", c.source, again, err)
		}
	}
	for _, source := range []string{"/*", "/* a", "/* a *", "/*/", "{} /*", "/* /* */ /*", "[[[[[", "{{{{{", "[{[{["} {
		if got, err := aclStandardizeHujson([]byte(source)); err == nil {
			t.Errorf("%q passed as %q", source, got)
		}
	}
	for _, source := range []string{"\xff", "{} // \xff", "/* \xff */", "\"\xff\"", "\xc0\x80", "\xed\xa0\x80"} {
		if got, err := aclStandardizeHujson([]byte(source)); err == nil {
			t.Errorf("%q passed as %q", source, got)
		}
	}
}

// What every source must hold, for the fuzz target and for its seeds on every leg: decoding is total,
// it leaves its input alone, it allocates no more than a multiple of the source, its refusals wrap the
// one error, and what it accepts is deterministic and made of values that read back as themselves.
func testAclPolicySourceHolds(t *testing.T, source []byte) {
	t.Helper()
	original := bytes.Clone(source)
	var policy *AclPolicy
	var err error
	allocatedByteCount := testAclPolicyAllocatedByteCount(func() {
		policy, err = ParseAclPolicy(source)
	})
	if !bytes.Equal(source, original) {
		t.Fatalf("the parse changed its input")
	}
	if bound := testAclPolicyAllocationBound(source); bound < allocatedByteCount {
		t.Fatalf("%d B allocated for %d B of source, over %d B", allocatedByteCount, len(source), bound)
	}
	if err != nil {
		if policy != nil {
			t.Fatalf("a policy beside %v", err)
		}
		if !errors.Is(err, ErrAclPolicyInvalid) {
			t.Fatalf("%v does not wrap ErrAclPolicyInvalid", err)
		}
		return
	}
	again, err := ParseAclPolicy(source)
	if err != nil {
		t.Fatalf("a second parse: %v", err)
	}
	if !reflect.DeepEqual(policy, again) {
		t.Fatalf("two parses differ: %+v and %+v", policy, again)
	}
	if policy.ExpiresDefault <= 0 || len(policy.EvidenceDefault) == 0 {
		t.Fatalf("no defaults: %+v", policy)
	}
	checkSelector := func(selector AclSelector, position aclPosition) {
		text := selector.String()
		got, err := parseAclSelector(text, position)
		if err != nil || got != selector {
			t.Fatalf("%q at %d reads back as %+v, %v", text, position, got, err)
		}
	}
	checkResource := func(resource AclResource) {
		text := resource.String()
		got, err := parseAclResource(text)
		if err != nil {
			t.Fatalf("%q does not read back: %v", text, err)
		}
		if resource.Kind == AclResourceIp && resource.Name != "" {
			// the hosts entry fills in the cidr, which parseAclResource alone cannot
			if !resource.Cidr.IsValid() {
				t.Fatalf("%q did not resolve", text)
			}
			got.Cidr = resource.Cidr
		}
		if got != resource {
			t.Fatalf("%q reads back as %+v", text, got)
		}
	}
	for _, group := range policy.Groups {
		checkSelector(group.Group, aclPositionSrc)
		for _, member := range group.Members {
			checkSelector(member, aclPositionGroupMember)
		}
	}
	for _, tagOwner := range policy.TagOwners {
		checkSelector(tagOwner.Tag, aclPositionSrc)
		for _, owner := range tagOwner.Owners {
			checkSelector(owner, aclPositionTagOwner)
		}
	}
	for _, grant := range policy.Grants {
		if len(grant.Src) == 0 || len(grant.Dst) == 0 || len(grant.Allow) == 0 {
			t.Fatalf("a grant missing what a rule needs: %+v", grant)
		}
		if !grant.Expires.IsZero() && grant.Expires.UnixMilli() <= 0 {
			t.Fatalf("a grant whose expiry rows read as none: %s", grant.Expires)
		}
		if grant.Audience == protocol.AclAudience_ACL_AUDIENCE_MEMBERS || grant.AppMode == protocol.AclAppMode_ACL_APP_MODE_HTTP {
			t.Fatalf("a default with a second value: %+v", grant)
		}
		for _, selector := range grant.Src {
			checkSelector(selector, aclPositionSrc)
		}
		for _, selector := range grant.Via {
			checkSelector(selector, aclPositionVia)
		}
		for _, resource := range grant.Dst {
			checkResource(resource)
		}
	}
	for _, request := range policy.Requests {
		if len(request.Src) == 0 || len(request.Dst) == 0 || len(request.Allow) == 0 {
			t.Fatalf("a request missing what a rule needs: %+v", request)
		}
		if len(request.Approver) == 0 || request.Approvers == 0 || request.MaxExpiry <= 0 {
			t.Fatalf("a request with no answer to who or how long: %+v", request)
		}
		for _, selector := range request.Src {
			checkSelector(selector, aclPositionSrc)
		}
		for _, selector := range request.Approver {
			checkSelector(selector, aclPositionApprover)
		}
		for _, resource := range request.Dst {
			checkResource(resource)
		}
	}
	for _, test := range policy.Tests {
		checkSelector(test.Src, aclPositionTestSrc)
		for _, check := range slices.Concat(test.Accept, test.Deny) {
			checkResource(check.Resource)
		}
	}
	if policy.Audit != nil {
		checkSelector(policy.Audit.Reader, aclPositionAuditReader)
	}
}

// A seed file's bytes: go's fuzz corpus format, one []byte value.
func testAclPolicySeedSource(t *testing.T, name string, seed []byte) []byte {
	t.Helper()
	header, body, found := strings.Cut(string(seed), "\n")
	if !found || header != "go test fuzz v1" {
		t.Fatalf("%s: not a corpus file", name)
	}
	body = strings.TrimSpace(body)
	quoted, found := strings.CutPrefix(body, "[]byte(")
	if !found {
		t.Fatalf("%s: not a []byte value", name)
	}
	source, err := strconv.Unquote(strings.TrimSuffix(quoted, ")"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return []byte(source)
}

// The seeds in testdata/fuzz, on every leg: go test runs them through FuzzParseAclPolicy only where a
// file system lets it read them, and the Worker has none.
func TestAclPolicyFuzzSeedsHold(t *testing.T) {
	const directory = "testdata/fuzz/FuzzParseAclPolicy"
	entries, err := fs.ReadDir(testAclPolicyFiles, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 20 {
		t.Fatalf("%d seeds", len(entries))
	}
	for _, entry := range entries {
		seed, err := testAclPolicyFiles.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		testAclPolicySourceHolds(t, testAclPolicySeedSource(t, entry.Name(), seed))
	}
}

// A comment or trailing comma changes no meaning: a document reads the same once they are gone.
func TestAclPolicyCommentsChangeNoMeaning(t *testing.T) {
	for _, name := range []string{"worked_example.hujson", "implicit_document.hujson", "every_field.hujson"} {
		source := testAclPolicyFixture(t, name)
		standard, err := aclStandardizeHujson(source)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(standard) {
			t.Fatalf("%s is not JSON once standardized", name)
		}
		if !reflect.DeepEqual(testParseAclPolicy(t, source), testParseAclPolicy(t, standard)) {
			t.Errorf("%s reads differently once standardized", name)
		}
	}
}

// Line ends and indents change no meaning either: each document saved with CRLF line ends and tab
// indents, as an editor on another system leaves it, reads as written, its trailing commas and line
// comments included.
func TestAclPolicyLineEndingsChangeNoMeaning(t *testing.T) {
	for _, name := range []string{"worked_example.hujson", "implicit_document.hujson", "every_field.hujson"} {
		source := testAclPolicyFixture(t, name)
		lines := strings.Split(string(source), "\n")
		for i, line := range lines {
			indent := len(line) - len(strings.TrimLeft(line, " "))
			lines[i] = strings.Repeat("\t", indent) + line[indent:]
		}
		other := []byte(strings.Join(lines, "\r\n"))
		if bytes.Equal(other, source) || !bytes.Contains(other, []byte(",\r\n\t")) {
			t.Fatalf("%s did not change as this test needs", name)
		}
		if !reflect.DeepEqual(testParseAclPolicy(t, source), testParseAclPolicy(t, other)) {
			t.Errorf("%s reads differently with CRLF and tabs", name)
		}
	}
}

// A place in the source, 1-based, counted in bytes from the last line feed, and never past the end.
func TestAclSourcePosition(t *testing.T) {
	source := []byte("ab\ncd\r\n\nx")
	cases := []struct {
		offset int
		line   int
		column int
	}{
		{offset: 0, line: 1, column: 1},
		{offset: 2, line: 1, column: 3},
		{offset: 3, line: 2, column: 1},
		{offset: 6, line: 2, column: 4},
		{offset: 7, line: 3, column: 1},
		{offset: 8, line: 4, column: 1},
		{offset: 9, line: 4, column: 2},
		// past the end, as no offset a parser reports should be, the end
		{offset: 100, line: 4, column: 2},
	}
	for _, c := range cases {
		if line, column := aclSourcePosition(source, c.offset); line != c.line || column != c.column {
			t.Errorf("%d: line %d, column %d", c.offset, line, column)
		}
	}
}

// Each kind protocol numbers reads by the name §11.12 gives it, its enum name lowercased, as an audit
// block's kind: entry writes it: a kind added there, or a name drifting here, fails.
func TestEveryRepoKindHasAName(t *testing.T) {
	if len(aclNameRepoKinds) != len(protocol.RepoKind_name)-1 {
		t.Errorf("%d names for %d kinds", len(aclNameRepoKinds), len(protocol.RepoKind_name)-1)
	}
	for number, enumName := range protocol.RepoKind_name {
		if number == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(enumName, "REPO_KIND_"))
		policy, err := ParseAclPolicy([]byte(`{"audit": {"reader": "tag:a", "repos": ["kind:` + name + `"]}}`))
		if err != nil {
			t.Errorf("kind:%s: %v", name, err)
			continue
		}
		if got := policy.Audit.RepoKinds; len(got) != 1 || got[0] != protocol.RepoKind(number) {
			t.Errorf("kind:%s reads as %v", name, got)
		}
	}
}
