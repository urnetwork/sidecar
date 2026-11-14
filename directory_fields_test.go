// §16.11's field classes and caps (directory_fields.go) and §22.6's directory.proto decoders (directory_decode.go):
// a charset table per identifier class, bidi and control stripping in prose, every cap at its value and one past it,
// each kind holding only its fields, the redactor turning a matching field into [REDACTED:<rule>] whole after
// normalizing, the request, decision, notice and erasure request rules, each decoder refusing past its bound before it
// parses, and hashes and signatures over the bytes as received. Tests whose subject is a reader in a world of streams
// are directory_decode_reader_test.go's; FuzzDirectoryDecode is directory_fuzz_test.go's.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	mathrand "math/rand/v2"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A time every fixture renews at.
const testDirectoryRenewedMillis int64 = 1762387200000

// A 16-byte id of one repeated byte.
func testDirectoryId(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 16)
}

// A run item every check takes, with one claim.
func testDirectoryRunItem() *protocol.Announcement {
	expiresMillis, _ := DirectoryAnnouncementExpiresMillis(DirectoryAnnouncementKindRun, testDirectoryRenewedMillis)
	return &protocol.Announcement{
		AnnouncementId: testDirectoryId(0x11),
		Kind:           uint32(DirectoryAnnouncementKindRun),
		Version:        1,
		StartedMillis:  testDirectoryRenewedMillis - 60*1000,
		RenewedMillis:  testDirectoryRenewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(DirectoryAnnouncementStateActive),
		Who: &protocol.AnnounceWho{
			MemberId:    testDirectoryId(0x21),
			SidecarId:   testDirectoryId(0x22),
			MemberLabel: "Ana Mar\u00eda",
			AgentId:     testDirectoryId(0x23),
			AgentLabel:  "builder",
			Harness:     "claude-code",
			Model:       "model-7.1",
		},
		What: &protocol.AnnounceWhat{Title: "Fix the deploy script's retry", RunId: testDirectoryId(0x24)},
		Where: &protocol.AnnounceWhere{
			RepoId:    testDirectoryId(0x25),
			Project:   "git.example/team/billing",
			Branch:    "fix/deploy-retry",
			HostLabel: "ana-laptop",
		},
		Claims: []*protocol.Claim{{
			ClaimId:       testDirectoryId(0x26),
			Text:          "the deploy script",
			Targets:       []string{"deploy/", "scripts/retry.sh"},
			ExpiresMillis: expiresMillis,
			State:         uint32(DirectoryClaimStateActive),
		}},
	}
}

// A worker item every check takes, one service of each kind.
func testDirectoryWorkerItem() *protocol.Announcement {
	expiresMillis, _ := DirectoryAnnouncementExpiresMillis(DirectoryAnnouncementKindWorker, testDirectoryRenewedMillis)
	return &protocol.Announcement{
		AnnouncementId: testDirectoryId(0x31),
		Kind:           uint32(DirectoryAnnouncementKindWorker),
		Version:        3,
		StartedMillis:  testDirectoryRenewedMillis - 24*60*60*1000,
		RenewedMillis:  testDirectoryRenewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(DirectoryAnnouncementStateActive),
		Who:            &protocol.AnnounceWho{MemberId: testDirectoryId(0x21), SidecarId: testDirectoryId(0x32), TagIds: [][]byte{testDirectoryId(0x33)}},
		What: &protocol.AnnounceWhat{
			Description: "A build box with the staging database.",
			Harnesses:   []string{"claude-code", "codex"},
			AgentLabels: []string{"builder", "reviewer"},
			Services: []*protocol.Service{
				{Kind: uint32(DirectoryServiceKindSocket), Name: "db/primary", Description: "staging Postgres"},
				{Kind: uint32(DirectoryServiceKindTlsHost), Name: "blog.team.example", Description: "the blog"},
				{Kind: uint32(DirectoryServiceKindBridgePort), Name: "tcp:8080", Description: "a dev server"},
			},
			Requests: uint32(DirectoryRequestsOpen),
		},
		Where: &protocol.AnnounceWhere{HostLabel: "build-box", Platform: 2, Ephemeral: true},
	}
}

// A repo item every check takes, padded as its announce entry is.
func testDirectoryRepoItem(t testing.TB) *protocol.Announcement {
	t.Helper()
	repoId := Id(testDirectoryId(0x41))
	announcementId := DirectoryRepoAnnouncementId(repoId)
	item := &protocol.Announcement{
		AnnouncementId: announcementId[:],
		Kind:           uint32(DirectoryAnnouncementKindRepo),
		Version:        1,
		StartedMillis:  testDirectoryRenewedMillis,
		RenewedMillis:  testDirectoryRenewedMillis,
		State:          uint32(DirectoryAnnouncementStateActive),
		Who:            &protocol.AnnounceWho{MemberId: testDirectoryId(0x21), SidecarId: testDirectoryId(0x22)},
		What: &protocol.AnnounceWhat{
			Title:       "Billing API",
			Description: "The billing service and its migrations.",
			Requests:    uint32(DirectoryRequestsOpen),
			Topics:      []string{"billing", "api"},
			RepoKind:    uint32(protocol.RepoKind_REPO_KIND_GENERAL),
			Roles:       []uint32{uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER), uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)},
		},
		Where: &protocol.AnnounceWhere{RepoId: repoId.Bytes()},
	}
	if _, err := DirectoryPadRepoAnnouncement(item); err != nil {
		t.Fatal(err)
	}
	return item
}

// testDirectoryRepoItem's private marker: only who, repo_id, repo_kind and requests, padded alike.
func testDirectoryPrivateMarker(t testing.TB) *protocol.Announcement {
	t.Helper()
	item := testDirectoryRepoItem(t)
	item.What = &protocol.AnnounceWhat{Requests: uint32(DirectoryRequestsClosed), RepoKind: item.GetWhat().GetRepoKind()}
	item.Where = &protocol.AnnounceWhere{RepoId: item.GetWhere().GetRepoId(), Private: true}
	if _, err := DirectoryPadRepoAnnouncement(item); err != nil {
		t.Fatal(err)
	}
	return item
}

// testDirectoryRunItem's withdrawal: only announcement_id, kind, version, renewed_millis, expires_millis, state and
// who's member_id and sidecar_id.
func testDirectoryWithdrawal() *protocol.Announcement {
	run := testDirectoryRunItem()
	return &protocol.Announcement{
		AnnouncementId: run.GetAnnouncementId(),
		Kind:           run.GetKind(),
		Version:        run.GetVersion() + 1,
		RenewedMillis:  run.GetRenewedMillis(),
		ExpiresMillis:  run.GetExpiresMillis(),
		State:          uint32(DirectoryAnnouncementStateWithdrawn),
		Who:            &protocol.AnnounceWho{MemberId: run.GetWho().GetMemberId(), SidecarId: run.GetWho().GetSidecarId()},
	}
}

// A member's own request for read on a repo.
func testDirectoryRepoRequest() *protocol.DirectoryRequest {
	return &protocol.DirectoryRequest{
		RequestId:       testDirectoryId(0x51),
		Target:          &protocol.RequestTarget{RepoId: testDirectoryId(0x41)},
		Subject:         testDirectoryId(0x52),
		SubjectIsMember: true,
		Role:            uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
		NotAfterMillis:  testDirectoryRenewedMillis + DirectoryRequestDefaultExpiry.Milliseconds(),
		Reason:          "to review the billing migrations",
		FiledBy:         uint32(DirectoryFiledByPerson),
	}
}

// A CanonicalAction of kind access_request at version 3, to dial a worker's one port, as stored: its clear grant_dst
// names the worker alone, and the port and its text ride sealed_detail (QD-740), sealed beside the clear fields
// (QD-771).
func testDirectoryReachAction(t testing.TB, workerId []byte, subject []byte) []byte {
	t.Helper()
	worker := "sidecar:" + directoryIdText(Id(workerId))
	action, err := proto.MarshalOptions{Deterministic: true}.Marshal(testWithSealedDetail(&protocol.CanonicalAction{
		Kind:            uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST),
		Version:         3,
		ExpiresMillis:   testDirectoryRenewedMillis + 60*60*1000,
		GrantDst:        []string{worker},
		GrantAllow:      []string{"dial"},
		TargetSidecarId: workerId,
		Subject:         subject,
	}, &protocol.CanonicalActionDetail{TargetPort: 8080, GrantDst: []string{worker + ":tcp:8080"}}))
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// An agent's request to reach a worker's port, endorsed by device evidence, with its approval.
func testDirectoryReachRequest(t testing.TB) *protocol.DirectoryRequest {
	t.Helper()
	requestId := testDirectoryId(0x61)
	workerId := testDirectoryId(0x32)
	subject := testDirectoryId(0x62)
	action := testDirectoryReachAction(t, workerId, subject)
	payloadSha256 := ApprovalPayloadSha256(action)
	actionId := ApprovalActionId(Id(requestId), action)
	return &protocol.DirectoryRequest{
		RequestId:          requestId,
		Target:             &protocol.RequestTarget{SidecarId: workerId, TcpPorts: []uint32{8080}},
		Subject:            subject,
		Role:               uint32(protocol.AclAction_ACL_ACTION_DIAL),
		NotAfterMillis:     testDirectoryRenewedMillis + DirectoryRequestDefaultExpiry.Milliseconds(),
		Reason:             "to run the integration tests against staging",
		FiledBy:            uint32(DirectoryFiledByAgent),
		EndorsementChannel: uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		EndorsementSha256:  bytes.Repeat([]byte{0x63}, 32),
		Tainted:            true,
		Approval: &protocol.ApprovalRequest{
			ApprovalId:         requestId,
			ActionId:           actionId[:],
			CanonicalAction:    action,
			PayloadSha256:      payloadSha256[:],
			Risk:               uint32(protocol.SidecarRisk_SIDECAR_RISK_NORMAL),
			RequesterSidecarId: subject,
			Tainted:            true,
			Approvers:          [][]byte{testDirectoryId(0x21)},
			NotAfterMillis:     testDirectoryRenewedMillis + DirectoryRequestDefaultExpiry.Milliseconds(),
			Version:            1,
		},
	}
}

// A repo approval naming its RepoGrant's position.
func testDirectoryRepoApproval() *protocol.DirectoryDecision {
	return &protocol.DirectoryDecision{
		RequestId:          testDirectoryId(0x51),
		RequestEntrySha256: bytes.Repeat([]byte{0x71}, 32),
		Outcome:            uint32(DirectoryOutcomeApproved),
		StatementSha256:    bytes.Repeat([]byte{0x72}, 32),
		StatementPosition:  412,
		Subject:            testDirectoryId(0x52),
		Note:               "approved for the migration review",
	}
}

// An ApprovalDecision approving request requestId on channel, signed by key over its body as encoded, which may be
// any valid encoding.
func testDirectoryApprovalDecision(t testing.TB, key ed25519.PrivateKey, requestId []byte, channel protocol.ApprovalChannel, encode func(*protocol.ApprovalDecision) []byte) []byte {
	t.Helper()
	decision := &protocol.ApprovalDecision{
		ApprovalId:         requestId,
		RequestSha256:      bytes.Repeat([]byte{0x81}, 32),
		PayloadSha256:      bytes.Repeat([]byte{0x82}, 32),
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     testDirectoryRenewedMillis + 60*60*1000,
		ApproverMemberId:   testDirectoryId(0x21),
		Channel:            uint32(channel),
		RequesterSidecarId: testDirectoryId(0x62),
		AuthPin:            &bridge.AuthPin{Version: 412, Chain: bytes.Repeat([]byte{0x83}, 32)},
		Version:            1,
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		decision.EvidenceSha256 = bytes.Repeat([]byte{0x84}, 32)
	}
	body := encode(decision)
	signed, err := proto.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  testDirectoryId(0x22),
		Signature: ed25519.Sign(key, bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A message's deterministic encoding.
func testDirectoryMarshal(t testing.TB, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// A reach approval of testDirectoryReachRequest's request, on device evidence.
func testDirectoryReachApproval(t testing.TB, key ed25519.PrivateKey) *protocol.DirectoryDecision {
	t.Helper()
	requestId := testDirectoryId(0x61)
	return &protocol.DirectoryDecision{
		RequestId:          requestId,
		RequestEntrySha256: bytes.Repeat([]byte{0x71}, 32),
		Outcome:            uint32(DirectoryOutcomeApproved),
		StatementSha256:    bytes.Repeat([]byte{0x72}, 32),
		ApprovalDecision: testDirectoryApprovalDecision(t, key, requestId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, func(decision *protocol.ApprovalDecision) []byte {
			return testDirectoryMarshal(t, decision)
		}),
		Subject: testDirectoryId(0x62),
	}
}

// A notice decided approved by a rule's two approvals.
func testDirectoryNotice() *protocol.DirectoryNotice {
	return &protocol.DirectoryNotice{
		RequestId:          testDirectoryId(0x51),
		RequesterSidecarId: testDirectoryId(0x62),
		EntrySeq:           7,
		NotAfterMillis:     testDirectoryRenewedMillis + DirectoryRequestDefaultExpiry.Milliseconds(),
		State:              uint32(DirectoryNoticeStateDecided),
		Outcome:            uint32(DirectoryOutcomeApproved),
		Decisions: []*protocol.DecisionRef{
			{DeciderSidecarId: testDirectoryId(0x22), Seq: 3, HeaderSha256: bytes.Repeat([]byte{0x91}, 32)},
			{DeciderSidecarId: testDirectoryId(0x27), Seq: 9, HeaderSha256: bytes.Repeat([]byte{0x92}, 32)},
		},
	}
}

func testDirectoryErasureRequest() *protocol.DirectoryErasureRequest {
	return &protocol.DirectoryErasureRequest{RequestId: testDirectoryId(0xa1), RepoId: testDirectoryId(0x41), MarkerVersion: 2}
}

// A synthetic GitHub token in the redactor's github-pat form, drawn from seed: no real secret.
func testDirectorySecret(seed uint64) string {
	random := mathrand.New(mathrand.NewPCG(seed, 0x5ec2e7))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 36)
	for index := range token {
		token[index] = alphabet[random.IntN(len(alphabet))]
	}
	return "ghp_" + string(token)
}

func testDirectoryRedactor(t testing.TB) *Redactor {
	t.Helper()
	redactor, err := NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return redactor
}

// Labels: [a-z0-9-]{1,cap}, or exactly one shared marker within the cap.
func TestDirectoryLabelsTakeTheirCharset(t *testing.T) {
	for _, c := range []struct {
		text         string
		maxByteCount int
		want         bool
	}{
		{text: "builder", maxByteCount: DirectoryLabelByteCount, want: true},
		{text: "claude-code", maxByteCount: DirectoryLabelByteCount, want: true},
		{text: "a-1-b", maxByteCount: DirectoryLabelByteCount, want: true},
		{text: "-", maxByteCount: DirectoryLabelByteCount, want: true},
		{text: strings.Repeat("a", 64), maxByteCount: DirectoryLabelByteCount, want: true},
		{text: strings.Repeat("a", 65), maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "Builder", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "build_er", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "build er", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "build.er", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "b\u00fc", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "ignore-previous-instructions", maxByteCount: DirectoryLabelByteCount, want: true},
		{text: "[REDACTED:github-pat]", maxByteCount: DirectoryLabelByteCount, want: true},
		{text: "[REDACTED:github-pat:0a1b2c3d]", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: "x[REDACTED:github-pat]", maxByteCount: DirectoryLabelByteCount, want: false},
		{text: strings.Repeat("t", 32), maxByteCount: DirectoryTopicByteCount, want: true},
		{text: strings.Repeat("t", 33), maxByteCount: DirectoryTopicByteCount, want: false},
		// a marker for a long rule name does not fit a topic, so the writer refuses the item
		{text: "[REDACTED:huggingface-organization-api-token]", maxByteCount: DirectoryTopicByteCount, want: false},
	} {
		if got := directoryIdentifierValid(directoryIdentifierLabel, c.text, c.maxByteCount); got != c.want {
			t.Errorf("%+q within %d: %t", c.text, c.maxByteCount, got)
		}
	}
}

// Branches: git check-ref-format --branch, within 128 B, and path text besides.
func TestDirectoryBranchesFollowCheckRefFormat(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{
		{text: "main", want: true},
		{text: "fix/deploy-retry", want: true},
		{text: "release-1.2", want: true},
		{text: "a.b/c_d", want: true},
		{text: "user/caf\u00e9", want: true},
		{text: "ignore-previous-instructions", want: true},
		{text: strings.Repeat("b", 128), want: true},
		{text: strings.Repeat("b", 129), want: false},
		{text: "", want: false},
		{text: "-main", want: false},
		{text: "HEAD", want: false},
		{text: "@", want: false},
		{text: "a..b", want: false},
		{text: "a/", want: false},
		{text: "/a", want: false},
		{text: "a//b", want: false},
		{text: "a.lock", want: false},
		{text: "a/b.lock/c", want: false},
		{text: ".a", want: false},
		{text: "a/.b", want: false},
		{text: "a.", want: false},
		{text: "a@{1}", want: false},
		{text: "a\\b", want: false},
		{text: "a b", want: false},
		{text: "a~1", want: false},
		{text: "a^1", want: false},
		{text: "a:b", want: false},
		{text: "a?", want: false},
		{text: "a*", want: false},
		{text: "a[b", want: false},
		{text: "a\tb", want: false},
		{text: "a\x7fb", want: false},
		// what git takes and the identifier class does not: a C1 control, a bidi override, an invisible tag
		// character, a form out of NFC
		{text: "a\u0085b", want: false},
		{text: "fix/\u202egnp", want: false},
		{text: "fix/\U000E0069x", want: false},
		{text: "user/cafe\u0301", want: false},
		{text: "[REDACTED:github-pat]", want: true},
	} {
		if got := directoryIdentifierValid(directoryIdentifierBranch, c.text, DirectoryBranchByteCount); got != c.want {
			t.Errorf("%+q: %t", c.text, got)
		}
	}
}

// Path text: NFC, with no C0 or C1 control, bidi control, invisible format character, line separator or whitespace
// run, within its cap.
func TestDirectoryIdentifierTextRefusesControlsInvisiblesAndRuns(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{
		{text: "", want: true},
		{text: "git.example/team/billing", want: true},
		{text: "My Project/src", want: true},
		{text: "na\u00efve/paths", want: true},
		{text: "model-7.1", want: true},
		{text: "vendor:model@2026-01:0", want: true},
		{text: "[REDACTED:pii-email]", want: true},
		{text: "nai\u0308ve", want: false},
		{text: "a  b", want: false},
		{text: "a \u00a0b", want: false},
		{text: "a\u3000\u3000b", want: false},
		{text: "a\u2028b", want: false},
		{text: "a\u2029b", want: false},
		{text: "\x00a", want: false},
		{text: "a\nb", want: false},
		{text: "a\tb", want: false},
		{text: "a\x1bb", want: false},
		{text: "a\x7fb", want: false},
		{text: "a\u0085b", want: false},
		{text: "a\u009bb", want: false},
		{text: "a\u202ab", want: false},
		{text: "a\u202eb", want: false},
		{text: "a\u2066b", want: false},
		{text: "a\u2069b", want: false},
		{text: "a\u200eb", want: false},
		{text: "a\u061cb", want: false},
		{text: "a\u200bb", want: false},
		{text: "a\u200db", want: false},
		{text: "a\ufeffb", want: false},
		{text: "a\u00adb", want: false},
		{text: "a\ufe0fb", want: false},
		{text: "a\U000E0041b", want: false},
		{text: "a\u3164b", want: false},
		{text: "a\xffb", want: false},
	} {
		if got := directoryIdentifierTextValid(c.text, DirectoryProjectByteCount); got != c.want {
			t.Errorf("%+q: %t", c.text, got)
		}
	}
	if !directoryIdentifierTextValid(strings.Repeat("p", DirectoryProjectByteCount), DirectoryProjectByteCount) ||
		directoryIdentifierTextValid(strings.Repeat("p", DirectoryProjectByteCount+1), DirectoryProjectByteCount) {
		t.Error("the project's cap is not 128 B")
	}
}

// A service is named by its kind's grammar: an application socket's canonical §9.4 name, a TLS host's lowercase DNS
// name, a bridge port's tcp:<port>.
func TestDirectoryServiceNamesTakeTheirKindsGrammar(t *testing.T) {
	for _, c := range []struct {
		kind DirectoryServiceKind
		name string
		want bool
	}{
		{kind: DirectoryServiceKindSocket, name: "db/primary", want: true},
		{kind: DirectoryServiceKindSocket, name: "api", want: true},
		{kind: DirectoryServiceKindSocket, name: "DB/primary", want: false},
		{kind: DirectoryServiceKindSocket, name: "tls/443/blog", want: false},
		{kind: DirectoryServiceKindSocket, name: "share/abc", want: false},
		{kind: DirectoryServiceKindSocket, name: "db//primary", want: false},
		{kind: DirectoryServiceKindSocket, name: "", want: false},
		{kind: DirectoryServiceKindTlsHost, name: "blog.team.example", want: true},
		{kind: DirectoryServiceKindTlsHost, name: "xn--caf-dma.example", want: true},
		{kind: DirectoryServiceKindTlsHost, name: "Blog.team.example", want: false},
		{kind: DirectoryServiceKindTlsHost, name: "blog..example", want: false},
		{kind: DirectoryServiceKindTlsHost, name: "blog.example.", want: false},
		{kind: DirectoryServiceKindTlsHost, name: "-blog.example", want: false},
		{kind: DirectoryServiceKindTlsHost, name: "caf\u00e9.example", want: false},
		{kind: DirectoryServiceKindTlsHost, name: strings.Repeat("a.", 126) + "ab", want: false},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:8080", want: true},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:1", want: true},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:65535", want: true},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:65536", want: false},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:0", want: false},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:08080", want: false},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:+80", want: false},
		{kind: DirectoryServiceKindBridgePort, name: "udp:53", want: false},
		{kind: DirectoryServiceKindBridgePort, name: "tcp:", want: false},
		{kind: 4, name: "tcp:80", want: false},
	} {
		if got := directoryServiceNameValid(c.kind, c.name); got != c.want {
			t.Errorf("kind %d %+q: %t", c.kind, c.name, got)
		}
	}
}

// Prose: controls and bidi controls dropped, a line or word break a space, invalid UTF-8 U+FFFD, then NFC; what comes
// out is prose, and normalizing it again changes nothing.
func TestDirectoryNormalizeProse(t *testing.T) {
	for _, c := range []struct {
		text string
		want string
	}{
		{text: "Fix the deploy", want: "Fix the deploy"},
		{text: "line one\nline two", want: "line one line two"},
		{text: "a\r\nb", want: "a  b"},
		{text: "tab\tstop", want: "tab stop"},
		{text: "bell\x07less", want: "bellless"},
		{text: "esc\x1b[31mred", want: "esc[31mred"},
		{text: "c1\u009bcsi\u0085nel", want: "c1csi nel"},
		{text: "safe \u202egnp.exe", want: "safe gnp.exe"},
		{text: "\u2066isolated\u2069", want: "isolated"},
		{text: "mark\u200eed", want: "marked"},
		{text: "cafe\u0301", want: "caf\u00e9"},
		{text: "e\x00\u0301", want: "\u00e9"},
		{text: "bad\xffbyte", want: "bad\ufffdbyte"},
		{text: "line\u2028sep", want: "line\u2028sep"},
		{text: "zero\u200bwidth", want: "zero\u200bwidth"},
	} {
		got := DirectoryNormalizeProse(c.text)
		if got != c.want {
			t.Errorf("%+q: %+q, want %+q", c.text, got, c.want)
		}
		if !directoryProseValid(got, len(got)) || DirectoryNormalizeProse(got) != got {
			t.Errorf("%+q normalized to %+q, which is no fixed point of prose", c.text, got)
		}
	}
	// a fixed walk over the characters that matter: every result is prose and a fixed point
	random := mathrand.New(mathrand.NewPCG(1, 2))
	pool := []rune{'a', 'e', ' ', '\n', '\t', 0x00, 0x1b, 0x7f, 0x85, 0x9b, 0x0301, 0x0308, 0x200b, 0x200e, 0x202e,
		0x2066, 0x2028, 0x3000, 0xfeff, 0x1100, 0x1161, 0xac00, 0x11a8, 0xe0041, utf8.RuneError}
	for range 2000 {
		text := make([]rune, random.IntN(16))
		for index := range text {
			text[index] = pool[random.IntN(len(pool))]
		}
		got := DirectoryNormalizeProse(string(text))
		if !directoryProseValid(got, len(got)) || DirectoryNormalizeProse(got) != got {
			t.Fatalf("%+q normalized to %+q", string(text), got)
		}
		identifier := directoryNormalizeIdentifierText(string(text))
		if !directoryIdentifierTextValid(identifier, len(identifier)) || directoryNormalizeIdentifierText(identifier) != identifier {
			t.Fatalf("%+q normalized as an identifier to %+q", string(text), identifier)
		}
	}
}

// Path text's normalization: controls and invisibles dropped, each whitespace run one space, trimmed, NFC.
func TestDirectoryNormalizeIdentifierText(t *testing.T) {
	for _, c := range []struct {
		text string
		want string
	}{
		{text: "git.example/team/billing", want: "git.example/team/billing"},
		{text: "  My   Project\n", want: "My Project"},
		{text: "a\u00a0\u3000b", want: "a b"},
		{text: "a\u2028b", want: "a b"},
		{text: "pro\u200bject", want: "project"},
		{text: "pro\U000E0069\U000E0067ject", want: "project"},
		{text: "safe\u202e", want: "safe"},
		{text: "nai\u0308ve", want: "na\u00efve"},
		{text: "e\u200b\u0301", want: "\u00e9"},
	} {
		if got := directoryNormalizeIdentifierText(c.text); got != c.want {
			t.Errorf("%+q: %+q, want %+q", c.text, got, c.want)
		}
	}
}

// Every fixture item passes, a repo item and a private marker padded alike.
func TestDirectoryCheckItemTakesEveryKind(t *testing.T) {
	for name, item := range map[string]*protocol.Announcement{
		"a run":            testDirectoryRunItem(),
		"a worker":         testDirectoryWorkerItem(),
		"a repo":           testDirectoryRepoItem(t),
		"a private marker": testDirectoryPrivateMarker(t),
		"a withdrawal":     testDirectoryWithdrawal(),
	} {
		if err := DirectoryCheckItem(item); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := DirectoryDecodeAnnouncement(testDirectoryMarshal(t, item)); err != nil {
			t.Errorf("%s as its announce entry: %v", name, err)
		}
	}
	if DirectoryCheckItem(nil) == nil {
		t.Error("no item passed")
	}
}

// Each cap at its value passes and one past it is refused, as are values directory.proto does not name.
func TestDirectoryCheckItemHoldsEachCap(t *testing.T) {
	type itemCase struct {
		name   string
		item   func() *protocol.Announcement
		mutate func(item *protocol.Announcement)
		want   bool
	}
	run := testDirectoryRunItem
	worker := testDirectoryWorkerItem
	repo := func() *protocol.Announcement {
		item := testDirectoryRepoItem(t)
		item.Pad = nil
		return item
	}
	cases := []itemCase{
		{name: "a title at 120 B", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = strings.Repeat("t", 120) }, want: true},
		{name: "a title at 121 B", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = strings.Repeat("t", 121) }},
		{name: "a two-byte title character past 120 B", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = strings.Repeat("t", 119) + "\u00e9" }},
		{name: "a title with a control", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = "fix\x1b[2Jit" }},
		{name: "a title with a bidi override", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = "fix \u202eit" }},
		{name: "a title out of NFC", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = "cafe\u0301" }},
		{name: "a title with a zero-width character", item: run, mutate: func(item *protocol.Announcement) { item.What.Title = "fix\u200bit" }, want: true},
		{name: "a model at 64 B", item: run, mutate: func(item *protocol.Announcement) { item.Who.Model = strings.Repeat("m", 64) }, want: true},
		{name: "a model at 65 B", item: run, mutate: func(item *protocol.Announcement) { item.Who.Model = strings.Repeat("m", 65) }},
		{name: "a model with a tag character", item: run, mutate: func(item *protocol.Announcement) { item.Who.Model = "m\U000E0041" }},
		{name: "no harness", item: run, mutate: func(item *protocol.Announcement) { item.Who.Harness = "" }},
		{name: "harness none", item: run, mutate: func(item *protocol.Announcement) { item.Who.Harness = "none" }, want: true},
		{name: "an uppercase harness", item: run, mutate: func(item *protocol.Announcement) { item.Who.Harness = "Claude" }},
		{name: "a person's task with no agent", item: run, mutate: func(item *protocol.Announcement) {
			item.Who.AgentId, item.Who.AgentLabel, item.Who.Harness = nil, "", "none"
		}, want: true},
		{name: "an agent label at 65 B", item: run, mutate: func(item *protocol.Announcement) { item.Who.AgentLabel = strings.Repeat("a", 65) }},
		{name: "an agent label with an underscore", item: run, mutate: func(item *protocol.Announcement) { item.Who.AgentLabel = "a_b" }},
		{name: "a member label at 64 B", item: run, mutate: func(item *protocol.Announcement) { item.Who.MemberLabel = strings.Repeat("m", 64) }, want: true},
		{name: "a member label at 65 B", item: run, mutate: func(item *protocol.Announcement) { item.Who.MemberLabel = strings.Repeat("m", 65) }},
		{name: "a host label at 63 B", item: run, mutate: func(item *protocol.Announcement) { item.Where.HostLabel = strings.Repeat("h", 63) }, want: true},
		{name: "a host label at 64 B", item: run, mutate: func(item *protocol.Announcement) { item.Where.HostLabel = strings.Repeat("h", 64) }},
		{name: "a host label that is no DNS label", item: run, mutate: func(item *protocol.Announcement) { item.Where.HostLabel = "-laptop" }},
		{name: "a project at 128 B", item: run, mutate: func(item *protocol.Announcement) { item.Where.Project = strings.Repeat("p", 128) }, want: true},
		{name: "a project at 129 B", item: run, mutate: func(item *protocol.Announcement) { item.Where.Project = strings.Repeat("p", 129) }},
		{name: "a project with a whitespace run", item: run, mutate: func(item *protocol.Announcement) { item.Where.Project = "a  b" }},
		{name: "a branch at 129 B", item: run, mutate: func(item *protocol.Announcement) { item.Where.Branch = strings.Repeat("b", 129) }},
		{name: "a branch git refuses", item: run, mutate: func(item *protocol.Announcement) { item.Where.Branch = "fix..it" }},
		{name: "a private run naming its project", item: run, mutate: func(item *protocol.Announcement) { item.Where.Private = true }},
		{name: "a private run", item: run, mutate: func(item *protocol.Announcement) {
			item.Where.Private, item.Where.Project, item.Where.Branch = true, "", ""
		}, want: true},
		{name: "four claims", item: run, mutate: func(item *protocol.Announcement) {
			for range 3 {
				item.Claims = append(item.Claims, proto.CloneOf(item.Claims[0]))
			}
		}, want: true},
		{name: "a fifth claim", item: run, mutate: func(item *protocol.Announcement) {
			for range 4 {
				item.Claims = append(item.Claims, proto.CloneOf(item.Claims[0]))
			}
		}},
		{name: "a claim's text at 513 B", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].Text = strings.Repeat("c", 513) }},
		{name: "a claim's sixteen targets of 256 B", item: run, mutate: func(item *protocol.Announcement) {
			item.Claims[0].Targets = slices.Repeat([]string{strings.Repeat("p", 256)}, 16)
		}, want: true},
		{name: "a claim's seventeenth target", item: run, mutate: func(item *protocol.Announcement) {
			item.Claims[0].Targets = slices.Repeat([]string{"p"}, 17)
		}},
		{name: "a claim's target at 257 B", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].Targets[0] = strings.Repeat("p", 257) }},
		{name: "a claim's empty target", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].Targets[0] = "" }},
		{name: "a claim's target with a line break", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].Targets[0] = "a\nb" }},
		{name: "a claim expiring past its run", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].ExpiresMillis = item.ExpiresMillis + 1 }},
		{name: "a claim with no expiry of its own", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].ExpiresMillis = 0 }, want: true},
		{name: "a claim's state 4", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].State = 4 }},
		{name: "a claim's id of 15 bytes", item: run, mutate: func(item *protocol.Announcement) { item.Claims[0].ClaimId = item.Claims[0].ClaimId[:15] }},
		{name: "a handoff note at 512 B", item: run, mutate: func(item *protocol.Announcement) {
			item.Handoff = &protocol.Handoff{ToAgentLabel: "reviewer", Note: strings.Repeat("n", 512)}
		}, want: true},
		{name: "a handoff note at 513 B", item: run, mutate: func(item *protocol.Announcement) {
			item.Handoff = &protocol.Handoff{ToAgentLabel: "reviewer", Note: strings.Repeat("n", 513)}
		}},
		{name: "handed off to no one", item: run, mutate: func(item *protocol.Announcement) {
			item.State = uint32(DirectoryAnnouncementStateHandedOff)
			item.Handoff = &protocol.Handoff{Note: "over to you"}
		}},
		{name: "handed off to a member", item: run, mutate: func(item *protocol.Announcement) {
			item.State = uint32(DirectoryAnnouncementStateHandedOff)
			item.Handoff = &protocol.Handoff{ToMemberId: testDirectoryId(0x28), Millis: testDirectoryRenewedMillis}
		}, want: true},
		{name: "no run_id", item: run, mutate: func(item *protocol.Announcement) { item.What.RunId = nil }},

		{name: "eight harnesses", item: worker, mutate: func(item *protocol.Announcement) { item.What.Harnesses = slices.Repeat([]string{"h"}, 8) }, want: true},
		{name: "a ninth harness", item: worker, mutate: func(item *protocol.Announcement) { item.What.Harnesses = slices.Repeat([]string{"h"}, 9) }},
		{name: "sixteen agent labels", item: worker, mutate: func(item *protocol.Announcement) { item.What.AgentLabels = slices.Repeat([]string{"a"}, 16) }, want: true},
		{name: "a seventeenth agent label", item: worker, mutate: func(item *protocol.Announcement) { item.What.AgentLabels = slices.Repeat([]string{"a"}, 17) }},
		{name: "thirty-two services", item: worker, mutate: func(item *protocol.Announcement) {
			item.What.Services = slices.Repeat([]*protocol.Service{{Kind: uint32(DirectoryServiceKindBridgePort), Name: "tcp:22"}}, 32)
		}, want: true},
		{name: "a thirty-third service", item: worker, mutate: func(item *protocol.Announcement) {
			item.What.Services = slices.Repeat([]*protocol.Service{{Kind: uint32(DirectoryServiceKindBridgePort), Name: "tcp:22"}}, 33)
		}},
		{name: "a service description at 257 B", item: worker, mutate: func(item *protocol.Announcement) { item.What.Services[0].Description = strings.Repeat("d", 257) }},
		{name: "a service of kind 4", item: worker, mutate: func(item *protocol.Announcement) { item.What.Services[0].Kind = 4 }},
		{name: "a service off its kind's grammar", item: worker, mutate: func(item *protocol.Announcement) { item.What.Services[2].Name = "tcp:http" }},
		{name: "a redacted service name", item: worker, mutate: func(item *protocol.Announcement) { item.What.Services[0].Name = "[REDACTED:jwt]" }, want: true},
		{name: "a worker description at 513 B", item: worker, mutate: func(item *protocol.Announcement) { item.What.Description = strings.Repeat("d", 513) }},
		{name: "a worker with requests 0", item: worker, mutate: func(item *protocol.Announcement) { item.What.Requests = 0 }},
		{name: "a tag id of 17 bytes", item: worker, mutate: func(item *protocol.Announcement) { item.Who.TagIds[0] = append(item.Who.TagIds[0], 0) }},

		{name: "a display name at 128 B", item: repo, mutate: func(item *protocol.Announcement) { item.What.Title = strings.Repeat("n", 128) }, want: true},
		{name: "a display name at 129 B", item: repo, mutate: func(item *protocol.Announcement) { item.What.Title = strings.Repeat("n", 129) }},
		{name: "eight topics of 32 B", item: repo, mutate: func(item *protocol.Announcement) {
			item.What.Topics = slices.Repeat([]string{strings.Repeat("t", 32)}, 8)
		}, want: true},
		{name: "a ninth topic", item: repo, mutate: func(item *protocol.Announcement) { item.What.Topics = slices.Repeat([]string{"t"}, 9) }},
		{name: "a topic at 33 B", item: repo, mutate: func(item *protocol.Announcement) { item.What.Topics[0] = strings.Repeat("t", 33) }},
		{name: "every role", item: repo, mutate: func(item *protocol.Announcement) { item.What.Roles = []uint32{1, 2, 3} }, want: true},
		{name: "a role twice", item: repo, mutate: func(item *protocol.Announcement) { item.What.Roles = []uint32{2, 2} }},
		{name: "role 0", item: repo, mutate: func(item *protocol.Announcement) { item.What.Roles = []uint32{0} }},
		{name: "role 4", item: repo, mutate: func(item *protocol.Announcement) { item.What.Roles = []uint32{4} }},
		{name: "a config repo", item: repo, mutate: func(item *protocol.Announcement) { item.What.RepoKind = uint32(protocol.RepoKind_REPO_KIND_CONFIG) }},
		{name: "a mailcfg repo", item: repo, mutate: func(item *protocol.Announcement) { item.What.RepoKind = uint32(protocol.RepoKind_REPO_KIND_MAILCFG) }},
		{name: "the directory", item: repo, mutate: func(item *protocol.Announcement) { item.What.RepoKind = uint32(protocol.RepoKind_REPO_KIND_DIRECTORY) }},
		{name: "a vault", item: repo, mutate: func(item *protocol.Announcement) { item.What.RepoKind = uint32(protocol.RepoKind_REPO_KIND_VAULT) }, want: true},
		{name: "repo kind 99", item: repo, mutate: func(item *protocol.Announcement) { item.What.RepoKind = 99 }},
		{name: "a repo with requests 3", item: repo, mutate: func(item *protocol.Announcement) { item.What.Requests = 3 }},
		{name: "a repo item for another repo", item: repo, mutate: func(item *protocol.Announcement) { item.Where.RepoId = testDirectoryId(0x42) }},
		{name: "a repo item with no repo_id", item: repo, mutate: func(item *protocol.Announcement) { item.Where.RepoId = nil }},
		{name: "a pad of non-zero bytes", item: repo, mutate: func(item *protocol.Announcement) { item.Pad = []byte{0, 1} }},
	}
	for _, c := range cases {
		item := c.item()
		c.mutate(item)
		err := DirectoryCheckItem(item)
		if (err == nil) != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s refused as %v", c.name, err)
		}
	}
}

// Times, versions, ids and states by the format: no item stays active past the format's expiry.
func TestDirectoryCheckItemHoldsTimesIdsAndStates(t *testing.T) {
	for name, mutate := range map[string]func(item *protocol.Announcement){
		"an expiry past the format's":   func(item *protocol.Announcement) { item.ExpiresMillis += 1 },
		"an expiry before the format's": func(item *protocol.Announcement) { item.ExpiresMillis -= 1 },
		"no expiry":                     func(item *protocol.Announcement) { item.ExpiresMillis = 0 },
		"renewed before started":        func(item *protocol.Announcement) { item.StartedMillis = item.RenewedMillis + 1 },
		"never renewed":                 func(item *protocol.Announcement) { item.RenewedMillis, item.StartedMillis = 0, 0 },
		"started before 1970":           func(item *protocol.Announcement) { item.StartedMillis = -1 },
		"renewed where its expiry wraps": func(item *protocol.Announcement) {
			item.RenewedMillis = 1<<63 - 1
			item.ExpiresMillis = item.RenewedMillis + DirectoryRunExpiry.Milliseconds()
		},
		"version 0":                         func(item *protocol.Announcement) { item.Version = 0 },
		"kind 0":                            func(item *protocol.Announcement) { item.Kind = 0 },
		"kind 4":                            func(item *protocol.Announcement) { item.Kind = 4 },
		"state 0":                           func(item *protocol.Announcement) { item.State = 0 },
		"state 5":                           func(item *protocol.Announcement) { item.State = 5 },
		"an announcement_id of 15 bytes":    func(item *protocol.Announcement) { item.AnnouncementId = item.AnnouncementId[:15] },
		"no who":                            func(item *protocol.Announcement) { item.Who = nil },
		"a sidecar_id of 17 bytes":          func(item *protocol.Announcement) { item.Who.SidecarId = append(item.Who.SidecarId, 0) },
		"a member_id of 8 bytes":            func(item *protocol.Announcement) { item.Who.MemberId = item.Who.MemberId[:8] },
		"an agent_id of 1 byte":             func(item *protocol.Announcement) { item.Who.AgentId = []byte{1} },
		"a repo_id of 15 bytes":             func(item *protocol.Announcement) { item.Where.RepoId = item.Where.RepoId[:15] },
		"a run_id of 17 bytes":              func(item *protocol.Announcement) { item.What.RunId = append(item.What.RunId, 0) },
		"a to_member_id of 3 bytes":         func(item *protocol.Announcement) { item.Handoff = &protocol.Handoff{ToMemberId: []byte{1, 2, 3}} },
		"a handoff before 1970":             func(item *protocol.Announcement) { item.Handoff = &protocol.Handoff{ToAgentLabel: "r", Millis: -1} },
		"a member_id of none, sponsor gone": func(item *protocol.Announcement) { item.Who.MemberId = nil },
	} {
		item := testDirectoryRunItem()
		mutate(item)
		err := DirectoryCheckItem(item)
		if name == "a member_id of none, sponsor gone" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a repo item carries no expiry
	repo := testDirectoryRepoItem(t)
	repo.ExpiresMillis = repo.RenewedMillis + DirectoryRunExpiry.Milliseconds()
	if DirectoryCheckItem(repo) == nil {
		t.Error("a repo item with an expiry passed")
	}
	// a worker's expiry is its own 26 h
	worker := testDirectoryWorkerItem()
	worker.ExpiresMillis = worker.RenewedMillis + DirectoryRunExpiry.Milliseconds()
	if DirectoryCheckItem(worker) == nil {
		t.Error("a worker item expiring as a run passed")
	}
}

// Each kind holds only its own fields (I-20): a run carries no services or description, a worker no title or claims, a
// repo no claims or project; a withdrawal holds only its own fields, and a private marker only who, repo_id, repo_kind
// and requests.
func TestDirectoryItemsHoldOnlyTheirFields(t *testing.T) {
	for _, c := range []struct {
		name   string
		item   func() *protocol.Announcement
		mutate func(item *protocol.Announcement)
	}{
		{name: "a run's services", item: testDirectoryRunItem, mutate: func(item *protocol.Announcement) {
			item.What.Services = []*protocol.Service{{Kind: 3, Name: "tcp:22"}}
		}},
		{name: "a run's description", item: testDirectoryRunItem, mutate: func(item *protocol.Announcement) { item.What.Description = "more" }},
		{name: "a run's requests", item: testDirectoryRunItem, mutate: func(item *protocol.Announcement) { item.What.Requests = 1 }},
		{name: "a run's tag ids", item: testDirectoryRunItem, mutate: func(item *protocol.Announcement) { item.Who.TagIds = [][]byte{testDirectoryId(1)} }},
		{name: "a run's platform", item: testDirectoryRunItem, mutate: func(item *protocol.Announcement) { item.Where.Platform = 1 }},
		{name: "a run's pad", item: testDirectoryRunItem, mutate: func(item *protocol.Announcement) { item.Pad = []byte{0} }},
		{name: "a worker's title", item: testDirectoryWorkerItem, mutate: func(item *protocol.Announcement) { item.What.Title = "t" }},
		{name: "a worker's claims", item: testDirectoryWorkerItem, mutate: func(item *protocol.Announcement) {
			item.Claims = testDirectoryRunItem().GetClaims()
		}},
		{name: "a worker's handoff", item: testDirectoryWorkerItem, mutate: func(item *protocol.Announcement) { item.Handoff = &protocol.Handoff{} }},
		{name: "a worker's run_id", item: testDirectoryWorkerItem, mutate: func(item *protocol.Announcement) { item.What.RunId = testDirectoryId(1) }},
		{name: "a worker's repo_id", item: testDirectoryWorkerItem, mutate: func(item *protocol.Announcement) { item.Where.RepoId = testDirectoryId(1) }},
		{name: "a worker's agent label in who", item: testDirectoryWorkerItem, mutate: func(item *protocol.Announcement) { item.Who.AgentLabel = "builder" }},
		{name: "a repo's project", item: func() *protocol.Announcement { return testDirectoryRepoItem(t) }, mutate: func(item *protocol.Announcement) {
			item.Where.Project = "p"
		}},
		{name: "a repo's agent", item: func() *protocol.Announcement { return testDirectoryRepoItem(t) }, mutate: func(item *protocol.Announcement) {
			item.Who.AgentId = testDirectoryId(1)
		}},
		{name: "a repo's services", item: func() *protocol.Announcement { return testDirectoryRepoItem(t) }, mutate: func(item *protocol.Announcement) {
			item.What.Services = []*protocol.Service{{Kind: 3, Name: "tcp:22"}}
		}},
		{name: "a private marker's display name", item: func() *protocol.Announcement { return testDirectoryPrivateMarker(t) }, mutate: func(item *protocol.Announcement) {
			item.What.Title = "Billing API"
		}},
		{name: "a private marker's topics", item: func() *protocol.Announcement { return testDirectoryPrivateMarker(t) }, mutate: func(item *protocol.Announcement) {
			item.What.Topics = []string{"billing"}
		}},
		{name: "a private marker's roles", item: func() *protocol.Announcement { return testDirectoryPrivateMarker(t) }, mutate: func(item *protocol.Announcement) {
			item.What.Roles = []uint32{2}
		}},
		{name: "a private marker's host label", item: func() *protocol.Announcement { return testDirectoryPrivateMarker(t) }, mutate: func(item *protocol.Announcement) {
			item.Where.HostLabel = "ana-laptop"
		}},
		{name: "a withdrawal's title", item: testDirectoryWithdrawal, mutate: func(item *protocol.Announcement) {
			item.What = &protocol.AnnounceWhat{Title: "still here"}
		}},
		{name: "a withdrawal's empty where", item: testDirectoryWithdrawal, mutate: func(item *protocol.Announcement) { item.Where = &protocol.AnnounceWhere{} }},
		{name: "a withdrawal's start", item: testDirectoryWithdrawal, mutate: func(item *protocol.Announcement) { item.StartedMillis = 1 }},
		{name: "a withdrawal's taint", item: testDirectoryWithdrawal, mutate: func(item *protocol.Announcement) { item.Tainted = true }},
		{name: "a withdrawal's agent label", item: testDirectoryWithdrawal, mutate: func(item *protocol.Announcement) { item.Who.AgentLabel = "builder" }},
		{name: "a withdrawal's claims", item: testDirectoryWithdrawal, mutate: func(item *protocol.Announcement) {
			item.Claims = testDirectoryRunItem().GetClaims()
		}},
		{name: "a repo's withdrawal", item: func() *protocol.Announcement { return testDirectoryRepoItem(t) }, mutate: func(item *protocol.Announcement) {
			item.State = uint32(DirectoryAnnouncementStateWithdrawn)
		}},
	} {
		item := c.item()
		c.mutate(item)
		if err := DirectoryCheckItem(item); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// §16.11's redaction row: a field with a secret, a marker of either form, or PII while the config hashes it becomes
// [REDACTED:<rule>] whole, with no HMAC; every other field stays as normalized; the result passes the check; twice
// changes nothing.
func TestDirectoryRedactReplacesAMatchingFieldWhole(t *testing.T) {
	redactor := testDirectoryRedactor(t)
	secret := testDirectorySecret(1)
	item := testDirectoryRunItem()
	item.What.Title = "fix the deploy, token " + secret + " expired"
	item.Who.Model = "model " + secret
	item.Where.Project = "git.example/" + secret
	item.Where.Branch = "fix/" + secret
	item.Who.AgentLabel = "builder"
	item.Claims[0].Text = "mail ana@team.example about it"
	item.Claims[0].Targets = []string{"deploy/", "secrets/" + secret}
	item.Handoff = &protocol.Handoff{ToAgentLabel: "reviewer", Note: "the vault key was [REDACTED:github-pat:0a1b2c3d] before"}
	redactions, err := DirectoryRedact(redactor, item)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		field string
		got   string
		want  string
	}{
		{field: "what.title", got: item.GetWhat().GetTitle(), want: "[REDACTED:github-pat]"},
		{field: "who.model", got: item.GetWho().GetModel(), want: "[REDACTED:github-pat]"},
		{field: "where.project", got: item.GetWhere().GetProject(), want: "[REDACTED:github-pat]"},
		{field: "where.branch", got: item.GetWhere().GetBranch(), want: "[REDACTED:github-pat]"},
		{field: "claims[0].text", got: item.GetClaims()[0].GetText(), want: "[REDACTED:pii-email]"},
		{field: "claims[0].targets[1]", got: item.GetClaims()[0].GetTargets()[1], want: "[REDACTED:github-pat]"},
		{field: "handoff.note", got: item.GetHandoff().GetNote(), want: "[REDACTED:github-pat]"},
		{field: "who.agent_label", got: item.GetWho().GetAgentLabel(), want: "builder"},
		{field: "claims[0].targets[0]", got: item.GetClaims()[0].GetTargets()[0], want: "deploy/"},
		{field: "who.member_label", got: item.GetWho().GetMemberLabel(), want: "Ana Mar\u00eda"},
	} {
		if c.got != c.want {
			t.Errorf("%s: %+q, want %+q", c.field, c.got, c.want)
		}
	}
	fields := []string{}
	for _, redaction := range redactions {
		fields = append(fields, redaction.Field+" "+redaction.Rule)
	}
	want := []string{"who.model github-pat", "what.title github-pat", "where.project github-pat", "where.branch github-pat",
		"claims[0].text pii-email", "claims[0].targets[1] github-pat", "handoff.note github-pat"}
	if !slices.Equal(fields, want) {
		t.Errorf("redactions %v, want %v", fields, want)
	}
	if err := DirectoryCheckItem(item); err != nil {
		t.Errorf("the redacted item: %v", err)
	}
	encoded := testDirectoryMarshal(t, item)
	if bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, []byte("0a1b2c3d")) || bytes.Contains(encoded, []byte("ana@team.example")) {
		t.Error("the redacted item holds a secret, an HMAC or an address")
	}
	again := proto.CloneOf(item)
	if redactions, err := DirectoryRedact(redactor, again); err != nil || len(redactions) != 0 || !proto.Equal(again, item) {
		t.Errorf("redacting twice changed %d fields: %v", len(redactions), err)
	}

	// PII is the harness config's to hash: off, an address stays
	redactor.SetPiiHashing(false)
	request := testDirectoryRepoRequest()
	request.Reason = "ask ana@team.example"
	if _, err := DirectoryRedact(redactor, request); err != nil || request.GetReason() != "ask ana@team.example" {
		t.Errorf("PII off redacted the reason to %+q: %v", request.GetReason(), err)
	}
	redactor.SetPiiHashing(true)
	request.Reason = "my token " + secret
	decision := testDirectoryRepoApproval()
	decision.Note = "denied: " + secret
	for _, message := range []proto.Message{request, decision, testDirectoryErasureRequest()} {
		if _, err := DirectoryRedact(redactor, message); err != nil {
			t.Fatal(err)
		}
	}
	if request.GetReason() != "[REDACTED:github-pat]" || decision.GetNote() != "[REDACTED:github-pat]" {
		t.Errorf("a reason %+q and a note %+q", request.GetReason(), decision.GetNote())
	}
	if _, err := DirectoryRedact(nil, testDirectoryRunItem()); err == nil {
		t.Error("no redactor redacted")
	}
	if _, err := DirectoryRedact(redactor, testDirectoryNotice()); !errors.Is(err, ErrDirectoryFormatInvalid) {
		t.Errorf("a notice redacted: %v", err)
	}
}

// The record writer's backstop: a directory draft whose covered field still holds a secret, or a marker anywhere but
// alone, is refused before it is sealed, as a message and as stored, naming the field; what DirectoryRedact leaves
// passes. PII is the harness config's to hash, so the backstop leaves it, and a coordination entry is its route's to
// refuse (§16.7's shared writes), not this backstop's.
func TestDirectoryWriterRefusesWhatRedactionReplaces(t *testing.T) {
	secret := testDirectorySecret(3)
	titled := testDirectoryRunItem()
	titled.What.Title = "deploy " + secret
	marked := testDirectoryRunItem()
	marked.Claims[0].Text = "the key [REDACTED:github-pat:0a1b2c3d] again"
	targeted := testDirectoryRunItem()
	targeted.Claims[0].Targets[1] = "keys/" + secret
	described := testDirectoryWorkerItem()
	described.What.Services[0].Description = "staging, password=" + secret
	reasoned := testDirectoryRepoRequest()
	reasoned.Reason = "my token is " + secret
	noted := testDirectoryRepoApproval()
	noted.Note = "use " + secret
	for _, c := range []struct {
		field string
		kind  RecordKind
		body  proto.Message
	}{
		{field: "what.title", kind: RecordKindAnnounce, body: titled},
		{field: "claims[0].text", kind: RecordKindAnnounce, body: marked},
		{field: "claims[0].targets[1]", kind: RecordKindAnnounce, body: targeted},
		{field: "what.services[0].description", kind: RecordKindAnnounce, body: described},
		{field: "reason", kind: RecordKindRequest, body: reasoned},
		{field: "note", kind: RecordKindDecision, body: noted},
	} {
		if err := RecordBodyValidate(c.kind, c.body); err != nil {
			t.Fatalf("%s: the body is within its caps, so only the backstop refuses it: %v", c.field, err)
		}
		for _, draft := range []*RecordDraft{
			{Kind: c.kind, Body: c.body},
			{Kind: c.kind, StoredBody: testDirectoryMarshal(t, c.body)},
		} {
			_, err := draft.bodyBytes()
			if !errors.Is(err, ErrRecordDraftInvalid) || !strings.Contains(err.Error(), c.field) {
				t.Errorf("%s, as stored %t: %v", c.field, draft.StoredBody != nil, err)
			}
		}
		redacted := proto.Clone(c.body)
		if _, err := DirectoryRedact(testDirectoryRedactor(t), redacted); err != nil {
			t.Fatal(err)
		}
		draft := &RecordDraft{Kind: c.kind, Body: redacted}
		if _, err := draft.bodyBytes(); err != nil {
			t.Errorf("%s redacted: %v", c.field, err)
		}
	}
	addressed := testDirectoryRunItem()
	addressed.Claims[0].Text = "mail ana@team.example"
	note := &protocol.CoordinationBody{Text: "token " + secret}
	for _, draft := range []*RecordDraft{
		{Kind: RecordKindAnnounce, Body: addressed},
		{Kind: RecordKindErasureRequest, Body: testDirectoryErasureRequest()},
		{Kind: RecordKindNote, Body: note},
	} {
		if _, err := draft.bodyBytes(); err != nil {
			t.Errorf("kind %s: %v", draft.Kind, err)
		}
	}
}

// Normalizing comes before the redactor reads: a secret split by a control in prose, or by an invisible character in a
// project, is joined by normalization and then redacted, never signed whole.
func TestDirectoryRedactNormalizesBeforeItReads(t *testing.T) {
	redactor := testDirectoryRedactor(t)
	secret := testDirectorySecret(2)
	item := testDirectoryRunItem()
	item.What.Title = "deploy " + secret[:10] + "\x00" + secret[10:]
	item.Where.Project = "git.example/" + secret[:20] + "\u200b" + secret[20:]
	item.Claims[0].Text = "line one\nline\u202e two"
	if _, err := DirectoryRedact(redactor, item); err != nil {
		t.Fatal(err)
	}
	if item.GetWhat().GetTitle() != "[REDACTED:github-pat]" || item.GetWhere().GetProject() != "[REDACTED:github-pat]" {
		t.Errorf("a split secret came through as %+q and %+q", item.GetWhat().GetTitle(), item.GetWhere().GetProject())
	}
	if item.GetClaims()[0].GetText() != "line one line two" {
		t.Errorf("a claim's text normalized to %+q", item.GetClaims()[0].GetText())
	}
	if err := DirectoryCheckItem(item); err != nil {
		t.Error(err)
	}
}

// A request's form: each filer's endorsement, reach carrying its approval and a sidecar subject, and its caps.
func TestDirectoryRequestRules(t *testing.T) {
	for name, request := range map[string]*protocol.DirectoryRequest{
		"a member's own request for a repo": testDirectoryRepoRequest(),
		"an agent's request to reach":       testDirectoryReachRequest(t),
	} {
		if err := DirectoryCheckRequest(request); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, c := range []struct {
		name   string
		reach  bool
		mutate func(request *protocol.DirectoryRequest)
		want   bool
	}{
		{name: "a reason at 512 B", mutate: func(request *protocol.DirectoryRequest) { request.Reason = strings.Repeat("r", 512) }, want: true},
		{name: "a reason at 513 B", mutate: func(request *protocol.DirectoryRequest) { request.Reason = strings.Repeat("r", 513) }},
		{name: "a reason with a bidi override", mutate: func(request *protocol.DirectoryRequest) { request.Reason = "please \u202e" }},
		{name: "no target", mutate: func(request *protocol.DirectoryRequest) { request.Target = nil }},
		{name: "two targets", mutate: func(request *protocol.DirectoryRequest) { request.Target.SidecarId = testDirectoryId(1) }},
		{name: "ports on a repo", mutate: func(request *protocol.DirectoryRequest) { request.Target.TcpPorts = []uint32{22} }},
		{name: "role 4 on a repo", mutate: func(request *protocol.DirectoryRequest) { request.Role = 4 }},
		{name: "role 0", mutate: func(request *protocol.DirectoryRequest) { request.Role = 0 }},
		{name: "a request_id of 15 bytes", mutate: func(request *protocol.DirectoryRequest) { request.RequestId = request.RequestId[:15] }},
		{name: "no subject", mutate: func(request *protocol.DirectoryRequest) { request.Subject = nil }},
		{name: "no expiry of its own", mutate: func(request *protocol.DirectoryRequest) { request.NotAfterMillis = 0 }},
		{name: "a grant expiry before 1970", mutate: func(request *protocol.DirectoryRequest) { request.GrantExpiresMillis = -1 }},
		{name: "an announcement_id of 3 bytes", mutate: func(request *protocol.DirectoryRequest) { request.AnnouncementId = []byte{1, 2, 3} }},
		{name: "filed_by 0", mutate: func(request *protocol.DirectoryRequest) { request.FiledBy = 0 }},
		{name: "filed_by 4", mutate: func(request *protocol.DirectoryRequest) { request.FiledBy = 4 }},
		{name: "an endorsement on a person's request", mutate: func(request *protocol.DirectoryRequest) {
			request.EndorsementChannel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
			request.EndorsementSha256 = bytes.Repeat([]byte{1}, 32)
		}},
		{name: "an agent's request with no endorsement", mutate: func(request *protocol.DirectoryRequest) {
			request.FiledBy = uint32(DirectoryFiledByAgent)
		}},
		{name: "an agent's request on harness in an untainted run", mutate: func(request *protocol.DirectoryRequest) {
			request.FiledBy = uint32(DirectoryFiledByAgent)
			request.EndorsementChannel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS)
			request.EndorsementSha256 = bytes.Repeat([]byte{1}, 32)
		}, want: true},
		{name: "an agent's request on harness in a tainted run", mutate: func(request *protocol.DirectoryRequest) {
			request.FiledBy = uint32(DirectoryFiledByAgent)
			request.EndorsementChannel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS)
			request.EndorsementSha256 = bytes.Repeat([]byte{1}, 32)
			request.Tainted = true
		}},
		{name: "a tagged sidecar's request on presence with a short hash", mutate: func(request *protocol.DirectoryRequest) {
			request.FiledBy = uint32(DirectoryFiledByTaggedSidecar)
			request.EndorsementChannel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)
			request.EndorsementSha256 = bytes.Repeat([]byte{1}, 31)
		}},
		{name: "an approval on a repo request", mutate: func(request *protocol.DirectoryRequest) {
			request.Approval = &protocol.ApprovalRequest{ApprovalId: request.RequestId}
		}},
		{name: "reach with no approval", reach: true, mutate: func(request *protocol.DirectoryRequest) { request.Approval = nil }},
		{name: "reach whose approval names another request", reach: true, mutate: func(request *protocol.DirectoryRequest) {
			request.Approval.ApprovalId = testDirectoryId(0x99)
		}},
		{name: "reach for a member", reach: true, mutate: func(request *protocol.DirectoryRequest) { request.SubjectIsMember = true }},
		{name: "reach at a reader's role", reach: true, mutate: func(request *protocol.DirectoryRequest) {
			request.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER)
		}},
		{name: "reach to thirty-two ports", reach: true, mutate: func(request *protocol.DirectoryRequest) {
			request.Target.TcpPorts = nil
			for port := range uint32(32) {
				request.Target.TcpPorts = append(request.Target.TcpPorts, 1000+port)
			}
		}, want: true},
		{name: "reach to thirty-three ports", reach: true, mutate: func(request *protocol.DirectoryRequest) {
			request.Target.TcpPorts = nil
			for port := range uint32(33) {
				request.Target.TcpPorts = append(request.Target.TcpPorts, 1000+port)
			}
		}},
		{name: "reach to a port twice", reach: true, mutate: func(request *protocol.DirectoryRequest) { request.Target.TcpPorts = []uint32{22, 22} }},
		{name: "reach to port 0", reach: true, mutate: func(request *protocol.DirectoryRequest) { request.Target.TcpPorts = []uint32{0} }},
		{name: "reach to port 65,536", reach: true, mutate: func(request *protocol.DirectoryRequest) { request.Target.TcpPorts = []uint32{65536} }},
		{name: "reach to a socket", reach: true, mutate: func(request *protocol.DirectoryRequest) {
			request.Target = &protocol.RequestTarget{SocketToken: bytes.Repeat([]byte{5}, 32)}
		}, want: true},
	} {
		request := testDirectoryRepoRequest()
		if c.reach {
			request = testDirectoryReachRequest(t)
		}
		c.mutate(request)
		err := DirectoryCheckRequest(request)
		if (err == nil) != c.want || (err != nil && !errors.Is(err, ErrDirectoryFormatInvalid)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if DirectoryCheckRequest(nil) == nil {
		t.Error("no request passed")
	}
}

// A decision's form: an approval names its statement, subject and one of a log position and an ApprovalDecision that
// approves this request on device or presence; a denial and a cancel name none.
func TestDirectoryDecisionRules(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	denial := &protocol.DirectoryDecision{
		RequestId:          testDirectoryId(0x51),
		RequestEntrySha256: bytes.Repeat([]byte{0x71}, 32),
		Outcome:            uint32(DirectoryOutcomeDenied),
		Note:               "not for this quarter",
	}
	cancel := proto.CloneOf(denial)
	cancel.Outcome = uint32(DirectoryOutcomeCancelled)
	for name, decision := range map[string]*protocol.DirectoryDecision{
		"a repo approval":  testDirectoryRepoApproval(),
		"a reach approval": testDirectoryReachApproval(t, key),
		"a denial":         denial,
		"a cancel":         cancel,
	} {
		if err := DirectoryCheckDecision(decision); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, c := range []struct {
		name     string
		decision func() *protocol.DirectoryDecision
		mutate   func(decision *protocol.DirectoryDecision)
	}{
		{name: "a note at 513 B", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) { decision.Note = strings.Repeat("n", 513) }},
		{name: "a note with a control", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) { decision.Note = "ok\x1b[0m" }},
		{name: "outcome 0", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) { decision.Outcome = 0 }},
		{name: "outcome 4", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) { decision.Outcome = 4 }},
		{name: "a request_entry_sha256 of 31 bytes", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) {
			decision.RequestEntrySha256 = decision.RequestEntrySha256[:31]
		}},
		{name: "an approval naming no statement", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) { decision.StatementSha256 = nil }},
		{name: "an approval naming no subject", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) { decision.Subject = nil }},
		{name: "an approval naming no position or decision", decision: testDirectoryRepoApproval, mutate: func(decision *protocol.DirectoryDecision) {
			decision.StatementPosition = 0
		}},
		{name: "an approval naming a position and a decision", decision: func() *protocol.DirectoryDecision { return testDirectoryReachApproval(t, key) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.StatementPosition = 9
		}},
		{name: "a reach approval whose decision does not parse", decision: func() *protocol.DirectoryDecision { return testDirectoryReachApproval(t, key) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.ApprovalDecision = []byte{0xff}
		}},
		{name: "a reach approval on harness evidence", decision: func() *protocol.DirectoryDecision { return testDirectoryReachApproval(t, key) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.ApprovalDecision = testDirectoryApprovalDecision(t, key, decision.RequestId, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS, func(approval *protocol.ApprovalDecision) []byte {
				return testDirectoryMarshal(t, approval)
			})
		}},
		{name: "a reach approval of another request", decision: func() *protocol.DirectoryDecision { return testDirectoryReachApproval(t, key) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.ApprovalDecision = testDirectoryApprovalDecision(t, key, testDirectoryId(0x99), protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, func(approval *protocol.ApprovalDecision) []byte {
				return testDirectoryMarshal(t, approval)
			})
		}},
		{name: "a reach approval carrying a denial", decision: func() *protocol.DirectoryDecision { return testDirectoryReachApproval(t, key) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.ApprovalDecision = testDirectoryApprovalDecision(t, key, decision.RequestId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, func(approval *protocol.ApprovalDecision) []byte {
				approval.Decision = uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY)
				return testDirectoryMarshal(t, approval)
			})
		}},
		{name: "a denial naming a statement", decision: func() *protocol.DirectoryDecision { return proto.CloneOf(denial) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.StatementSha256 = bytes.Repeat([]byte{1}, 32)
		}},
		{name: "a denial naming a subject", decision: func() *protocol.DirectoryDecision { return proto.CloneOf(denial) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.Subject = testDirectoryId(1)
		}},
		{name: "a cancel naming an expiry", decision: func() *protocol.DirectoryDecision { return proto.CloneOf(cancel) }, mutate: func(decision *protocol.DirectoryDecision) {
			decision.GrantExpiresMillis = 1
		}},
	} {
		decision := c.decision()
		c.mutate(decision)
		if err := DirectoryCheckDecision(decision); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A notice's form and its 256 B.
func TestDirectoryNoticeRules(t *testing.T) {
	pending := testDirectoryNotice()
	pending.State, pending.Outcome, pending.Decisions = uint32(DirectoryNoticeStatePending), 0, pending.Decisions[:1]
	denied := testDirectoryNotice()
	denied.Outcome, denied.Decisions = uint32(DirectoryOutcomeDenied), denied.Decisions[1:]
	for name, notice := range map[string]*protocol.DirectoryNotice{
		"approved by two":     testDirectoryNotice(),
		"pending, one of two": pending,
		"denied":              denied,
	} {
		if err := DirectoryCheckNotice(notice); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := DirectoryDecodeNotice(testDirectoryMarshal(t, notice)); err != nil {
			t.Errorf("%s decoded: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(notice *protocol.DirectoryNotice){
		"three decisions": func(notice *protocol.DirectoryNotice) {
			notice.Decisions = append(notice.Decisions, &protocol.DecisionRef{DeciderSidecarId: testDirectoryId(3), Seq: 1, HeaderSha256: bytes.Repeat([]byte{3}, 32)})
		},
		"a decider twice": func(notice *protocol.DirectoryNotice) {
			notice.Decisions[1].DeciderSidecarId = notice.Decisions[0].DeciderSidecarId
		},
		"approved by none":     func(notice *protocol.DirectoryNotice) { notice.Decisions = nil },
		"denied by two":        func(notice *protocol.DirectoryNotice) { notice.Outcome = uint32(DirectoryOutcomeDenied) },
		"decided as cancelled": func(notice *protocol.DirectoryNotice) { notice.Outcome = uint32(DirectoryOutcomeCancelled) },
		"pending with two": func(notice *protocol.DirectoryNotice) {
			notice.State, notice.Outcome = uint32(DirectoryNoticeStatePending), 0
		},
		"pending, approved": func(notice *protocol.DirectoryNotice) {
			notice.State, notice.Decisions = uint32(DirectoryNoticeStatePending), notice.Decisions[:1]
		},
		"state 3":                 func(notice *protocol.DirectoryNotice) { notice.State = 3 },
		"entry_seq 0":             func(notice *protocol.DirectoryNotice) { notice.EntrySeq = 0 },
		"no expiry":               func(notice *protocol.DirectoryNotice) { notice.NotAfterMillis = 0 },
		"a request_id of 8 bytes": func(notice *protocol.DirectoryNotice) { notice.RequestId = notice.RequestId[:8] },
		"no requester":            func(notice *protocol.DirectoryNotice) { notice.RequesterSidecarId = nil },
		"a decision at seq 0":     func(notice *protocol.DirectoryNotice) { notice.Decisions[0].Seq = 0 },
		"a decision's short hash": func(notice *protocol.DirectoryNotice) {
			notice.Decisions[0].HeaderSha256 = notice.Decisions[0].HeaderSha256[:16]
		},
		"a nil decision": func(notice *protocol.DirectoryNotice) { notice.Decisions[0] = nil },
	} {
		notice := testDirectoryNotice()
		mutate(notice)
		if err := DirectoryCheckNotice(notice); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// past 256 B, by bytes a v1 field cannot hold: refused before it parses, and by the check
	notice := testDirectoryNotice()
	notice.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), make([]byte, 256-proto.Size(notice))))
	if proto.Size(notice) <= DirectoryNoticeByteCount {
		t.Fatalf("a notice of %d bytes", proto.Size(notice))
	}
	if DirectoryCheckNotice(notice) == nil {
		t.Error("a notice past 256 B passed")
	}
	if _, err := DirectoryDecodeNotice(testDirectoryMarshal(t, notice)); !errors.Is(err, ErrDirectoryFormatInvalid) {
		t.Errorf("a notice past 256 B decoded: %v", err)
	}
}

func TestDirectoryErasureRequestRules(t *testing.T) {
	if err := DirectoryCheckErasureRequest(testDirectoryErasureRequest()); err != nil {
		t.Error(err)
	}
	for name, mutate := range map[string]func(request *protocol.DirectoryErasureRequest){
		"marker_version 0":        func(request *protocol.DirectoryErasureRequest) { request.MarkerVersion = 0 },
		"a request_id of 0 bytes": func(request *protocol.DirectoryErasureRequest) { request.RequestId = nil },
		"a repo_id of 17 bytes":   func(request *protocol.DirectoryErasureRequest) { request.RepoId = append(request.RepoId, 0) },
	} {
		request := testDirectoryErasureRequest()
		mutate(request)
		if err := DirectoryCheckErasureRequest(request); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if DirectoryCheckErasureRequest(nil) == nil {
		t.Error("no erasure request passed")
	}
}

// §22.6: each decoder refuses bytes past its bound before it parses them, however well formed, takes what is within
// it, and refuses bytes that do not parse.
func TestDirectoryDecodersRefusePastTheirBounds(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// a message grown past bound by an unknown field a v1 reader would keep, so only the bound refuses it
	grow := func(message proto.Message, bound int) []byte {
		message = proto.Clone(message)
		size := proto.Size(message)
		filler := protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), make([]byte, bound-size))
		message.ProtoReflect().SetUnknown(filler)
		return testDirectoryMarshal(t, message)
	}
	for _, c := range []struct {
		name    string
		message proto.Message
		bound   int
		decode  func(body []byte) error
	}{
		{name: "an announce entry", message: testDirectoryRunItem(), bound: DirectoryEntryBodyMaxByteCount, decode: func(body []byte) error {
			_, err := DirectoryDecodeAnnouncement(body)
			return err
		}},
		{name: "a request", message: testDirectoryReachRequest(t), bound: DirectoryEntryBodyMaxByteCount, decode: func(body []byte) error {
			_, err := DirectoryDecodeRequest(body)
			return err
		}},
		{name: "a decision", message: testDirectoryReachApproval(t, key), bound: DirectoryEntryBodyMaxByteCount, decode: func(body []byte) error {
			_, err := DirectoryDecodeDecision(body)
			return err
		}},
		{name: "a notice", message: testDirectoryNotice(), bound: DirectoryNoticeByteCount, decode: func(body []byte) error {
			_, err := DirectoryDecodeNotice(body)
			return err
		}},
		{name: "an erasure request", message: testDirectoryErasureRequest(), bound: DirectoryEntryBodyMaxByteCount, decode: func(body []byte) error {
			_, err := DirectoryDecodeErasureRequest(body)
			return err
		}},
	} {
		if err := c.decode(testDirectoryMarshal(t, c.message)); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		// the largest a filler of 3 B or more reaches is the bound itself, which passes
		within := grow(c.message, c.bound-4)
		if len(within) < c.bound-2 || c.bound < len(within) {
			t.Fatalf("%s grew to %d, not to its bound %d", c.name, len(within), c.bound)
		}
		if err := c.decode(within); err != nil {
			t.Errorf("%s of %d bytes, within its bound: %v", c.name, len(within), err)
		}
		past := grow(c.message, c.bound)
		if len(past) <= c.bound {
			t.Fatalf("%s grew to %d, not past its bound %d", c.name, len(past), c.bound)
		}
		if err := c.decode(past); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s of %d bytes, past its bound: %v", c.name, len(past), err)
		}
		for _, broken := range [][]byte{{0xff}, {0x0a, 0x05, 0x01}, {0x08}} {
			if err := c.decode(broken); !errors.Is(err, ErrDirectoryFormatInvalid) {
				t.Errorf("%s from %x: %v", c.name, broken, err)
			}
		}
	}
}

// A repo announce entry is a whole number of 2,048 B steps, an announcement and a private marker alike; one unpadded
// is refused. A run's or a worker's carries no pad.
func TestDirectoryRepoAnnounceEntriesTakeTheirSteps(t *testing.T) {
	for name, item := range map[string]*protocol.Announcement{
		"an announcement":  testDirectoryRepoItem(t),
		"a private marker": testDirectoryPrivateMarker(t),
	} {
		encoded := testDirectoryMarshal(t, item)
		if len(encoded) != DirectoryRepoEntryStepByteCount {
			t.Fatalf("%s padded to %d bytes", name, len(encoded))
		}
		if _, err := DirectoryDecodeAnnouncement(encoded); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		item.Pad = nil
		if err := DirectoryCheckItem(item); err != nil {
			t.Errorf("%s as a card's or repo file's item: %v", name, err)
		}
		if _, err := DirectoryDecodeAnnouncement(testDirectoryMarshal(t, item)); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s unpadded: %v", name, err)
		}
		if err := RecordBodyValidate(RecordKindAnnounce, item); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("%s unpadded, to its writer: %v", name, err)
		}
	}
}

// Signatures and hashes cover the bytes as received: a request keeps its approval's own bytes however they were
// encoded, refuses a body holding them twice or a payload hash not over its action, and its approval, parsed for an
// approver, refuses a CanonicalAction version this build's approvers do not know.
func TestDirectoryDecodeRequestKeepsItsApprovalAsReceived(t *testing.T) {
	request := testDirectoryReachRequest(t)
	approval := request.GetApproval()
	canonical := testDirectoryMarshal(t, approval)
	// the approval's fields in reverse order: valid, and no deterministic marshal writes it
	reversed := []byte{}
	fields := approval.ProtoReflect().Descriptor().Fields()
	for index := fields.Len() - 1; 0 <= index; index -= 1 {
		number := fields.Get(index).Number()
		single := proto.Clone(approval)
		single.ProtoReflect().Range(func(other protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			if other.Number() != number {
				single.ProtoReflect().Clear(other)
			}
			return true
		})
		reversed = append(reversed, testDirectoryMarshal(t, single)...)
	}
	if bytes.Equal(reversed, canonical) || len(reversed) != len(canonical) {
		t.Fatalf("the reversed approval is %d bytes, the canonical %d", len(reversed), len(canonical))
	}
	withoutApproval := proto.CloneOf(request)
	withoutApproval.Approval = nil
	body := protowire.AppendBytes(protowire.AppendTag(testDirectoryMarshal(t, withoutApproval), 14, protowire.BytesType), reversed)
	stored, err := DirectoryDecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.ApprovalBytes, reversed) || !bytes.Equal(stored.Bytes, body) {
		t.Fatal("the approval or the body was not kept as received")
	}
	if ApprovalRequestSha256(stored.ApprovalBytes) == ApprovalRequestSha256(testDirectoryMarshal(t, stored.Request.GetApproval())) {
		t.Error("a re-marshal hashed as the received bytes do, so this test shows nothing")
	}
	// an approver parses the approval, version 3 (MCP-M6-01), from the bytes as received
	if approval, err := stored.Approval(); err != nil || approval == nil {
		t.Errorf("an approval of version 3 did not parse for an approver: %v", err)
	}

	twice := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(body), 14, protowire.BytesType), reversed)
	if _, err := DirectoryDecodeRequest(twice); !errors.Is(err, ErrDirectoryFormatInvalid) {
		t.Errorf("an approval held twice: %v", err)
	}
	wrongPayload := proto.CloneOf(request)
	wrongPayload.Approval.PayloadSha256 = bytes.Repeat([]byte{0x01}, 32)
	if _, err := DirectoryDecodeRequest(testDirectoryMarshal(t, wrongPayload)); !errors.Is(err, ErrDirectoryFormatInvalid) {
		t.Errorf("a payload hash not over its action: %v", err)
	}
	repo, err := DirectoryDecodeRequest(testDirectoryMarshal(t, testDirectoryRepoRequest()))
	if err != nil || len(repo.ApprovalBytes) != 0 {
		t.Fatalf("a repo request: %v", err)
	}
	if _, err := repo.Approval(); !errors.Is(err, ErrDirectoryFormatInvalid) {
		t.Errorf("a repo request's approval: %v", err)
	}
}

// A decision's ApprovalDecision verifies over its body as received, however it was encoded, and a re-marshal of what
// was parsed would not.
func TestDirectoryDecodeDecisionVerifiesOverReceivedBytes(t *testing.T) {
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDirectoryReachApproval(t, key)
	// the decision's version written first: valid, and no deterministic marshal writes it
	decision.ApprovalDecision = testDirectoryApprovalDecision(t, key, decision.RequestId, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE, func(approval *protocol.ApprovalDecision) []byte {
		version := approval.GetVersion()
		approval.Version = 0
		encoded := protowire.AppendVarint(protowire.AppendTag(nil, 13, protowire.VarintType), uint64(version))
		return append(encoded, testDirectoryMarshal(t, approval)...)
	})
	stored, err := DirectoryDecodeDecision(testDirectoryMarshal(t, decision))
	if err != nil {
		t.Fatal(err)
	}
	if stored.ApprovalDecision == nil {
		t.Fatal("a reach approval decoded with no ApprovalDecision")
	}
	if err := stored.ApprovalDecision.Verify(bridge.SignedKeyAlgEd25519, publicKey); err != nil {
		t.Errorf("the ApprovalDecision did not verify over its received body: %v", err)
	}
	remarshaled := testDirectoryMarshal(t, stored.ApprovalDecision.Decision)
	if bytes.Equal(remarshaled, stored.ApprovalDecision.Bytes) {
		t.Fatal("the re-marshal equals the received body, so this test shows nothing")
	}
	signed := proto.CloneOf(stored.ApprovalDecision.Signed)
	signed.Body = remarshaled
	if err := bridge.VerifySigned(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, bridge.SignedKeyAlgEd25519, publicKey); err == nil {
		t.Error("a re-marshaled body verified")
	}
	repo, err := DirectoryDecodeDecision(testDirectoryMarshal(t, testDirectoryRepoApproval()))
	if err != nil || repo.ApprovalDecision != nil {
		t.Errorf("a repo approval: %v", err)
	}
}

// RecordBodyValidate, a writer's refusal, and RecordBodyValidateStored, a reader's, hold the directory's kinds to these
// checks, refusing as over_cap.
func TestDirectoryRecordBodyValidateTakesTheDirectoryKinds(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	overCapItem := testDirectoryRunItem()
	overCapItem.What.Title = strings.Repeat("t", 121)
	overCapRequest := testDirectoryRepoRequest()
	overCapRequest.Reason = strings.Repeat("r", 513)
	overCapDecision := testDirectoryRepoApproval()
	overCapDecision.Note = strings.Repeat("n", 513)
	overCapErasure := testDirectoryErasureRequest()
	overCapErasure.MarkerVersion = 0
	for _, c := range []struct {
		kind  RecordKind
		valid proto.Message
		past  proto.Message
	}{
		{kind: RecordKindAnnounce, valid: testDirectoryWorkerItem(), past: overCapItem},
		{kind: RecordKindAnnounce, valid: testDirectoryRepoItem(t), past: testDirectoryPrivateMarker(t)},
		{kind: RecordKindRequest, valid: testDirectoryReachRequest(t), past: overCapRequest},
		{kind: RecordKindDecision, valid: testDirectoryReachApproval(t, key), past: overCapDecision},
		{kind: RecordKindErasureRequest, valid: testDirectoryErasureRequest(), past: overCapErasure},
	} {
		if c.kind == RecordKindAnnounce && DirectoryAnnouncementKind(c.past.(*protocol.Announcement).GetKind()) == DirectoryAnnouncementKindRepo {
			// a private marker its writer forgot to pad
			c.past.(*protocol.Announcement).Pad = nil
		}
		if err := RecordBodyValidate(c.kind, c.valid); err != nil {
			t.Errorf("%s: %v", c.kind, err)
		}
		if err := RecordBodyValidateStored(c.kind, testDirectoryMarshal(t, c.valid)); err != nil {
			t.Errorf("%s stored: %v", c.kind, err)
		}
		err := RecordBodyValidate(c.kind, c.past)
		if !errors.Is(err, ErrRecordBodyOverCap) || !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s past its caps: %v", c.kind, err)
		}
		err = RecordBodyValidateStored(c.kind, testDirectoryMarshal(t, c.past))
		if !errors.Is(err, ErrRecordBodyOverCap) || !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s stored past its caps: %v", c.kind, err)
		}
	}
	if err := RecordBodyValidateStored(RecordKindRequest, make([]byte, DirectoryEntryBodyMaxByteCount+1)); !errors.Is(err, ErrRecordBodyOverCap) {
		t.Errorf("a request past its bound: %v", err)
	}
	// the record's other kinds are untouched
	if err := RecordBodyValidate(RecordKindNote, &protocol.CoordinationBody{Text: "a note"}); err != nil {
		t.Error(err)
	}
}

// The shared marker and both marker forms by their patterns, so a field holding a local marker takes the shared form.
func TestDirectoryMarkerForms(t *testing.T) {
	for _, c := range []struct {
		text   string
		shared bool
		any    bool
	}{
		{text: "[REDACTED:jwt]", shared: true, any: true},
		{text: "[REDACTED:jwt:0a1b2c3d]", shared: false, any: true},
		{text: "x [REDACTED:jwt] y", shared: false, any: true},
		{text: "[REDACTED:JWT]", shared: false, any: false},
		{text: "[REDACTED:]", shared: false, any: false},
		{text: "[redacted:jwt]", shared: false, any: false},
	} {
		if got := directorySharedMarker(c.text); got != c.shared {
			t.Errorf("%+q shared: %t", c.text, got)
		}
		if got := directoryAnyMarkerPattern.MatchString(c.text); got != c.any {
			t.Errorf("%+q any: %t", c.text, got)
		}
	}
	if !norm.NFC.IsNormalString("[REDACTED:jwt]") || !directoryProseValid("[REDACTED:jwt]", DirectoryRunTitleByteCount) {
		t.Error("the shared marker is no prose")
	}
}
