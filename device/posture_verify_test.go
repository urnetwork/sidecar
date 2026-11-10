// The posture's offline checks: has_document read from rows streamed field by field, rows that do not decode
// refused, and each statement this role applies held to its signer and class.

package device

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Rows holding acl as given, after one member row.
func postureRowsWithAcl(acls ...[]byte) []byte {
	rows := []byte{}
	member, _ := proto.Marshal(&bridge.MemberRow{MemberId: postureFixtureId(0x02), Role: bridge.MemberRole_MEMBER_ROLE_OWNER})
	rows = protowire.AppendTag(rows, postureRowsFieldMembers, protowire.BytesType)
	rows = protowire.AppendBytes(rows, member)
	for _, acl := range acls {
		rows = protowire.AppendTag(rows, postureRowsFieldAcl, protowire.BytesType)
		rows = protowire.AppendBytes(rows, acl)
	}
	return rows
}

// has_document is AclRows' field 1, absent meaning false, the last of each standing, and the last acl standing whole.
func TestHasDocumentReadsAclFieldOne(t *testing.T) {
	field := func(number protowire.Number, value uint64) []byte {
		return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), value)
	}
	other := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), []byte("atoms"))
	cases := []struct {
		name string
		rows []byte
		want bool
	}{
		{name: "no acl", rows: postureRowsWithAcl(), want: false},
		{name: "an empty acl", rows: postureRowsWithAcl([]byte{}), want: false},
		{name: "has_document", rows: postureRowsWithAcl(field(1, 1)), want: true},
		{name: "has_document after another field", rows: postureRowsWithAcl(append(bytes.Clone(other), field(1, 1)...)), want: true},
		{name: "has_document then false", rows: postureRowsWithAcl(append(field(1, 1), field(1, 0)...)), want: false},
		{name: "a second acl without it", rows: postureRowsWithAcl(field(1, 1), other), want: false},
		{name: "a second acl with it", rows: postureRowsWithAcl(other, field(1, 1)), want: true},
		{name: "another field numbered 1 in rows", rows: append(postureRowsWithAcl(), field(9, 1)...), want: false},
	}
	for _, c := range cases {
		scan, err := scanPostureRows(bytes.NewReader(c.rows), testPostureSettings(), nil)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if scan.hasDocument != c.want {
			t.Errorf("%s: has_document %v", c.name, scan.hasDocument)
		}
		if scan.sha256 != sha256.Sum256(c.rows) || scan.byteCount != int64(len(c.rows)) {
			t.Errorf("%s: hashed %d bytes wrong", c.name, scan.byteCount)
		}
		if _, admin := scan.adminMemberRoles[[16]byte(postureFixtureId(0x02))]; !admin {
			t.Errorf("%s: the owner is not in the AdminSet", c.name)
		}
	}
}

// Rows that do not decode as ProjectionRows, or pass a bound, are refused.
func TestRowsThatDoNotDecodeAreRefused(t *testing.T) {
	settings := testPostureSettings()
	settings.RowMaxByteCount = 64
	big, _ := proto.Marshal(&bridge.MemberRow{MemberId: bytes.Repeat([]byte{0x02}, 100)})
	cases := map[string][]byte{
		"members as a varint":          protowire.AppendVarint(protowire.AppendTag(nil, postureRowsFieldMembers, protowire.VarintType), 1),
		"a group":                      protowire.AppendTag(nil, 9, protowire.StartGroupType),
		"field 0":                      {0x02, 0x00},
		"a row over its bound":         protowire.AppendBytes(protowire.AppendTag(nil, postureRowsFieldMembers, protowire.BytesType), big),
		"a row cut short":              append(protowire.AppendTag(nil, postureRowsFieldSidecars, protowire.BytesType), 0x05, 0x0a),
		"an acl cut short":             append(protowire.AppendTag(nil, postureRowsFieldAcl, protowire.BytesType), 0x05, 0x08),
		"has_document as bytes":        protowire.AppendBytes(protowire.AppendTag(nil, postureRowsFieldAcl, protowire.BytesType), protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{1})),
		"a varint that does not end":   bytes.Repeat([]byte{0xff}, 11),
		"an unknown field cut short":   append(protowire.AppendTag(nil, 9, protowire.BytesType), 0x09, 0x01),
		"a member row that is garbage": protowire.AppendBytes(protowire.AppendTag(nil, postureRowsFieldMembers, protowire.BytesType), []byte{0xff, 0xff}),
	}
	for name, rows := range cases {
		if _, err := scanPostureRows(bytes.NewReader(rows), settings, nil); !errors.Is(err, ErrPostureRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	over := make([]byte, postureRowsMaxByteCount+1)
	over = append(protowire.AppendTag(nil, 9, protowire.BytesType), protowire.AppendVarint(nil, uint64(len(over)))...)
	over = append(over, make([]byte, postureRowsMaxByteCount)...)
	if _, err := scanPostureRows(bytes.NewReader(over), settings, nil); !errors.Is(err, ErrPostureRefused) {
		t.Errorf("rows over 4 MiB: %v", err)
	}
}

// Each statement this role applies, by each class of signer: what the overlay holds after it, or that it alarmed.
func TestStatementSignerRules(t *testing.T) {
	type outcome struct {
		kind    PostureOverlayKind
		covered bool
	}
	revoked := &postureFixtureSidecar{id: postureFixtureId(0x76), key: postureFixtureKey(0x76), revoked: true}
	cases := []struct {
		name string
		// changes the network before its rows are built, when set
		prepare func(fixture *postureFixture)
		// appends the statement to the fixture's log and returns its position
		file func(fixture *postureFixture) uint64
		// nil for a refusal
		want *outcome
	}{
		{
			name: "a sidecar's own sign-out",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.aliceLaptop, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			},
			want: &outcome{kind: PostureOverlaySidecarRevoke, covered: false},
		},
		{
			name: "a sidecar's own sign-out for compromise",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.aliceLaptop, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE)
			},
			want: &outcome{kind: PostureOverlaySidecarRevoke, covered: true},
		},
		{
			name: "a read_only device's own sign-out",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.aliceWorker, fixture.aliceWorker, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			},
			want: &outcome{kind: PostureOverlaySidecarRevoke, covered: false},
		},
		{
			name: "the member's device revoking its own other device",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.aliceLaptop, fixture.aliceWorker, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
			want: &outcome{kind: PostureOverlaySidecarRevoke, covered: true},
		},
		{
			name: "an admin's device revoking another's",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.ownerPhone, fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			},
			want: &outcome{kind: PostureOverlaySidecarRevoke, covered: true},
		},
		{
			name: "a member's device revoking another member's",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.aliceLaptop, fixture.ownerPhone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
		},
		{
			name: "a read_only device revoking another",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.aliceWorker, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
		},
		{
			name: "an Owner's device revoking a member",
			file: func(fixture *postureFixture) uint64 {
				return fixture.statement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_MEMBER_REVOKE,
					&bridge.MemberRevoke{Header: fixture.header(), MemberId: fixture.alice.id})
			},
			want: &outcome{kind: PostureOverlayMemberRevoke, covered: true},
		},
		{
			name: "a member's device revoking a member",
			file: func(fixture *postureFixture) uint64 {
				return fixture.statement(fixture.aliceLaptop, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_MEMBER_REVOKE,
					&bridge.MemberRevoke{Header: fixture.header(), MemberId: fixture.owner.id})
			},
		},
		{
			name: "the sponsor suspending its tagged sidecar",
			file: func(fixture *postureFixture) uint64 {
				return fixture.suspend(fixture.aliceLaptop, fixture.agent.id, postureFixtureId(0x71))
			},
			want: &outcome{kind: PostureOverlaySuspend, covered: true},
		},
		{
			name: "a member suspending another member's device",
			file: func(fixture *postureFixture) uint64 {
				return fixture.suspend(fixture.aliceLaptop, fixture.ownerPhone.id, postureFixtureId(0x72))
			},
		},
		{
			name: "a GrantRevoke by a standing device",
			file: func(fixture *postureFixture) uint64 {
				return fixture.statement(fixture.aliceLaptop, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_GRANT_REVOKE,
					&bridge.GrantRevoke{Header: fixture.header(), GrantId: postureFixtureId(0x73)})
			},
			want: &outcome{kind: PostureOverlayGrantRevoke},
		},
		{
			name: "a GrantRevoke by a read_only device",
			file: func(fixture *postureFixture) uint64 {
				return fixture.statement(fixture.aliceWorker, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_GRANT_REVOKE,
					&bridge.GrantRevoke{Header: fixture.header(), GrantId: postureFixtureId(0x73)})
			},
		},
		{
			name: "a BridgeWithdraw",
			file: func(fixture *postureFixture) uint64 {
				return fixture.statement(fixture.ownerPhone, bridge.SignedPurposeBridge, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
					&bridge.BridgeWithdraw{Header: fixture.header(), RuleId: postureFixtureId(0x74), Mode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN})
			},
			want: &outcome{kind: PostureOverlayBridgeWithdraw},
		},
		{
			name: "a statement under another purpose",
			file: func(fixture *postureFixture) uint64 {
				return fixture.statement(fixture.ownerPhone, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
					&bridge.SidecarRevoke{Header: fixture.header(), SidecarId: fixture.agent.id})
			},
		},
		{
			name: "a statement past its not_after",
			file: func(fixture *postureFixture) uint64 {
				header := fixture.header()
				header.NotAfterMs = fixture.timeMs
				return fixture.statement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
					&bridge.SidecarRevoke{Header: header, SidecarId: fixture.agent.id})
			},
		},
		{
			name: "another network's statement",
			file: func(fixture *postureFixture) uint64 {
				header := fixture.header()
				header.NetworkId = postureFixtureId(0x75)
				return fixture.statement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
					&bridge.SidecarRevoke{Header: header, SidecarId: fixture.agent.id})
			},
		},
		{
			name: "a statement by a sidecar the rows revoked",
			prepare: func(fixture *postureFixture) {
				revoked.member = fixture.owner
				fixture.sidecars = append(fixture.sidecars, revoked)
			},
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(revoked, fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
		},
		{
			name: "a statement by a sidecar the rows do not hold",
			file: func(fixture *postureFixture) uint64 {
				stranger := &postureFixtureSidecar{id: postureFixtureId(0x7a), key: postureFixtureKey(0x7a), member: fixture.owner}
				return fixture.sidecarRevoke(stranger, fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
		},
		{
			name: "a statement whose signature is another key's",
			file: func(fixture *postureFixture) uint64 {
				impostor := &postureFixtureSidecar{id: fixture.ownerPhone.id, key: postureFixtureKey(0x77), member: fixture.owner}
				return fixture.sidecarRevoke(impostor, fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
		},
	}
	for _, c := range cases {
		fixture := newPostureFixture(t)
		if c.prepare != nil {
			c.prepare(fixture)
		}
		store := newMemoryPostureStore()
		posture := fixture.enforcing(store, true)
		n := c.file(fixture)
		decision, err := posture.ApplyDeltas(fixture.log(n, n))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if decision.Pin.GetVersion() != n {
			t.Errorf("%s: the chain stopped at %d", c.name, decision.Pin.GetVersion())
		}
		if c.want == nil {
			if len(decision.Overlay) != 0 || !postureAlarmed(decision, PostureAlarmStatementRefused) {
				t.Errorf("%s: overlay %v, alarms %v", c.name, decision.Overlay, decision.Alarms)
			}
			continue
		}
		if len(decision.Overlay) != 1 || decision.Overlay[0].Kind != c.want.kind || decision.Overlay[0].Covered != c.want.covered ||
			decision.Overlay[0].N != n || len(decision.Alarms) != 0 {
			t.Errorf("%s: overlay %+v, alarms %v", c.name, decision.Overlay, decision.Alarms)
		}
	}
}
