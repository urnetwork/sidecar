// §7.9's apply(e) on the test network: FS-14's log cases on entries' own times (no reader reads a clock), the replay
// rules for a long-running reader and a new device alike, bases and their re-applied tails, ticks, refusals that keep
// their positions, and the rule table's hooks that refuse until their rules land.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A MemberAdmit of a fresh member at the tip, for statements whose content does not matter.
func (self *testConfigNet) memberAdmitStatement(label string) *protocol.MemberAdmit {
	return &protocol.MemberAdmit{Header: self.header(), MemberId: testConfigId(label).Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER}
}

// The fork evidence an error carries, failing the test when it is none.
func testConfigForkOf(t *testing.T, err error) *ConfigForkError {
	t.Helper()
	fork := &ConfigForkError{}
	if !errors.As(err, &fork) || !errors.Is(err, ErrConfigFork) {
		t.Fatalf("got %v, want a fork", err)
	}
	return fork
}

// The chain digest an entry carries.
func testConfigEntryChain(t *testing.T, entryBytes []byte) [sha256.Size]byte {
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// FS-14: two readers with one base and different statements at n+1 report a fork with both A_{n+1}, and stop there.
func TestTwoReadersWithDifferentStatementsAtOnePositionFork(t *testing.T) {
	net := newTestConfigNet(t)
	readerB := net.newReader()
	entryX := net.makeEntry(bridge.AuthEntryKindStatement, net.sign(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("x")))
	entryY := net.makeEntry(bridge.AuthEntryKindStatement, net.sign(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("y")))
	if verdict := net.push(entryX); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if verdict, err := readerB.Apply(entryY, net.source); err != nil || !verdict.Accepted() {
		t.Fatalf("reader B: %v, %v", verdict.Refusal, err)
	}
	chainX, chainY := testConfigEntryChain(t, entryX), testConfigEntryChain(t, entryY)

	_, err := net.log.Apply(entryY, net.source)
	forkA := testConfigForkOf(t, err)
	if forkA.N != 2 || !forkA.HasLocalChain || forkA.LocalChain != chainX || forkA.RemoteChain != chainY {
		t.Errorf("reader A's evidence: %+v", forkA)
	}
	_, err = readerB.Apply(entryX, net.source)
	forkB := testConfigForkOf(t, err)
	if forkB.LocalChain != chainY || forkB.RemoteChain != chainX {
		t.Errorf("reader B's evidence: %+v", forkB)
	}
	if net.log.Fork() == nil || readerB.Fork() == nil {
		t.Error("a forked reader goes on")
	}
	if _, err := net.log.Apply(net.makeEntry(bridge.AuthEntryKindTick, nil), net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("after the fork: %v", err)
	}
}

// FS-14: a base signed at tip n loses the position to a statement; appended at n+2 as signed it is a fork, and
// re-signed for n+2 it lands.
func TestABaseThatLosesItsPositionLandsReSigned(t *testing.T) {
	net := newTestConfigNet(t)
	tip := net.n
	staleBase := net.makeBase(net.owner, net.statesAt[tip].Rows(), tip, 2, 0)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("racer"))

	stale := &bridge.AuthEntry{}
	if err := proto.Unmarshal(staleBase, stale); err != nil {
		t.Fatal(err)
	}
	stale.N, stale.PrevChain, stale.TimeMs = net.n+1, bytes.Clone(net.chain[:]), net.timeMs+1000
	reader := net.newReader()
	_, err := reader.Apply(testConfigMarshal(t, stale), net.source)
	testConfigForkOf(t, err)

	if verdict := net.fold(net.owner, tip, 2); !verdict.Accepted() || verdict.Pin.GetVersion() != tip+2 {
		t.Fatalf("the re-signed base: %v at %d", verdict.Refusal, verdict.Pin.GetVersion())
	}
	if net.log.State().Member(testConfigId("racer")) == nil {
		t.Error("the statement the base did not fold re-applies on it")
	}
}

// FS-14: a stale compile, an older config head or a lower fold, is a fork if appended (D-TEAM-19).
func TestAStaleCompileIsAForkIfAppended(t *testing.T) {
	net := newTestConfigNet(t)
	for range 4 {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(string(rune('a'+net.n))))
	}
	if verdict := net.fold(net.owner, 4, 3); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	cases := []struct {
		name          string
		foldedThrough uint64
		configVersion uint64
	}{
		{name: "a lower fold", foldedThrough: 3, configVersion: 3},
		{name: "an older head", foldedThrough: 4, configVersion: 2},
	}
	for _, c := range cases {
		reader := net.newReader()
		stale := net.makeBase(net.owner, net.statesAt[c.foldedThrough].Rows(), c.foldedThrough, c.configVersion, 0)
		if _, err := reader.Apply(stale, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if verdict := net.fold(net.owner, 4, 3); !verdict.Accepted() {
		t.Errorf("an equal head and fold: %v", verdict.Refusal)
	}
}

// A base fails as a fork, never as a refusal, when its signer writes no config, its rows miss their hash or do not
// build, or its config head fails the full reader's check.
func TestABaseThatFailsItsChecksIsAFork(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("plain member")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	plain := net.device("plain device", member)
	net.admitDevice(net.owner, plain, 0)
	rows := net.log.State().Rows()

	reader := net.newReader()
	if _, err := reader.Apply(net.makeBase(plain, rows, net.n, 2, 0), net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a member device's base: %v", err)
	}

	badAcl := proto.Clone(rows).(*bridge.ProjectionRows)
	badAcl.Acl = testConfigMarshal(t, &protocol.AclRows{Atoms: []*protocol.AclAtom{{Atom: []byte("short")}}})
	reader = net.newReader()
	if _, err := reader.Apply(net.makeBase(net.owner, badAcl, net.n, 2, 0), net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("acl rows that do not build: %v", err)
	}

	doubled := proto.Clone(rows).(*bridge.ProjectionRows)
	doubled.Members = append(doubled.Members, doubled.Members[0])
	reader = net.newReader()
	if _, err := reader.Apply(net.makeBase(net.owner, doubled, net.n, 2, 0), net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a member twice: %v", err)
	}

	missing := net.makeBase(net.owner, rows, net.n, 2, 0)
	unpublished := newTestConfigRowsSource()
	reader = net.newReader()
	if _, err := reader.Apply(missing, unpublished); !errors.Is(err, ErrConfigFork) {
		t.Errorf("rows nowhere: %v", err)
	}

	reader = net.newReader()
	net.source.headError = errors.New("the head misses a folded statement")
	if _, err := reader.Apply(missing, net.source); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a failed head check: %v", err)
	}
	net.source.headError = nil
}

// The full reader's head check gets exactly the statement and tick entries in (the previous base's folded_through,
// folded_through], each by id and position, base entries left out (plan-TEAM-config-head-format #1).
func TestTheHeadCheckGetsExactlyTheFoldedRecords(t *testing.T) {
	net := newTestConfigNet(t)
	first := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("first"))
	net.tick(&bridge.ApiTick{})
	refused := net.post(net.owner, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{Header: net.header(), KeyId: []byte("no key")})
	if refused.Accepted() {
		t.Fatal("a KeyRevoke has no rule yet")
	}
	net.fold(net.owner, net.n, 2)
	foldedThrough := net.n - 1
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("second"))
	net.fold(net.owner, net.n, 3)

	firstCheck := net.source.checks[len(net.source.checks)-2]
	if !firstCheck.FoldedKnown || len(firstCheck.Folded) != 3 {
		t.Fatalf("the first fold holds %d records", len(firstCheck.Folded))
	}
	if firstCheck.Folded[0].N != 2 || !bytes.Equal(firstCheck.Folded[0].Id, first.StatementId[:]) || firstCheck.Folded[0].Kind != bridge.AuthEntryKindStatement {
		t.Errorf("record 0: %+v", firstCheck.Folded[0])
	}
	if firstCheck.Folded[1].Kind != bridge.AuthEntryKindTick || len(firstCheck.Folded[1].Id) != 0 {
		t.Errorf("record 1 is the tick, with no id: %+v", firstCheck.Folded[1])
	}
	if !bytes.Equal(firstCheck.Folded[2].Id, refused.StatementId[:]) {
		t.Error("a refused statement is a record too")
	}
	secondCheck := net.source.checks[len(net.source.checks)-1]
	if len(secondCheck.Folded) != 1 || secondCheck.Folded[0].N != foldedThrough+2 {
		t.Errorf("the second fold skips the base: %+v", secondCheck.Folded)
	}
}

// A refused statement keeps its position, changes no row and leaves the chain going on; the next statement lands on
// it (FS-102's refusal at every reader).
func TestARefusedStatementKeepsItsPosition(t *testing.T) {
	net := newTestConfigNet(t)
	before := testConfigRowsBytes(t, net.log.State())
	stranger := net.device("stranger", testConfigId("nobody"))
	verdict := net.post(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("by a stranger"))
	if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) || verdict.Pin.GetVersion() != 2 {
		t.Fatalf("got %v at %d", verdict.Refusal, verdict.Pin.GetVersion())
	}
	state := net.log.State()
	if state.n != 2 || !bytes.Equal(testConfigRowsBytes(t, state), before) {
		t.Error("a refusal moved the rows or not the pin")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after"))
}

// An entry applied again returns its kept verdict; a gap is no fork; bytes that are no entry change nothing.
func TestAnEntryAgainAheadOrMalformed(t *testing.T) {
	net := newTestConfigNet(t)
	verdict := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("once"))
	again, err := net.log.Apply(net.entries[len(net.entries)-1], net.source)
	if err != nil || !proto.Equal(again.Pin, verdict.Pin) || !again.Accepted() {
		t.Errorf("again: %v, %v", again, err)
	}

	ahead := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.makeEntry(bridge.AuthEntryKindTick, nil), ahead); err != nil {
		t.Fatal(err)
	}
	ahead.N += 1
	if _, err := net.log.Apply(testConfigMarshal(t, ahead), net.source); !errors.Is(err, ErrConfigEntryAhead) {
		t.Errorf("ahead: %v", err)
	}
	if _, err := net.log.Apply([]byte{0x0A, 0xFF}, net.source); !errors.Is(err, ErrConfigEntryMalformed) {
		t.Errorf("malformed: %v", err)
	}
	ahead.N -= 1
	ahead.NetworkId = testConfigId("other network").Bytes()
	if _, err := net.log.Apply(testConfigMarshal(t, ahead), net.source); !errors.Is(err, ErrConfigEntryMalformed) {
		t.Errorf("another network's: %v", err)
	}
	if net.log.Fork() != nil || net.log.State().n != net.n {
		t.Error("none of these moves or forks the log")
	}
}

// Each type whose rule another task builds is refused until it lands, so nothing passes unchecked: §8.8's statements
// until ACL's rules are wired in, the presence keys, recovery bindings and Delegations of TEAM-M2-04 to -06, the
// indexer, sponsor and veto records, §17.8's bridge statements, and the records that ride config heads only.
func TestTypesWithNoRuleYetAreRefused(t *testing.T) {
	net := newTestConfigNet(t)
	cases := []struct {
		signedType bridge.SignedType
		body       proto.Message
		want       error
	}{
		{signedType: bridge.SignedType_SIGNED_OWNER_CONFIRM, body: &protocol.OwnerConfirm{Header: net.header(), SidecarId: net.owner.sidecarId.Bytes()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_SUSPEND, body: &bridge.Suspend{Header: net.header(), Subject: testConfigId("s").Bytes()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_KEY_REGISTER, body: &protocol.KeyRegister{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_RECOVERY_BIND, body: &protocol.RecoveryBind{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_DELEGATION, body: &protocol.Delegation{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_DELEGATION_REVOKE, body: &protocol.DelegationRevoke{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_SPONSOR_SET, body: &protocol.SponsorSet{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_INDEXER_SET, body: &protocol.IndexerSet{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_RECOVERY_VETO, body: &protocol.RecoveryVeto{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, body: &bridge.BridgeRoute{Header: net.header()}, want: ErrConfigRuleMissing},
		{signedType: bridge.SignedType_SIGNED_SERVICE_SETTINGS, body: &protocol.ServiceSettings{}, want: ErrConfigRule},
		{signedType: bridge.SignedType_SIGNED_VERSIONING_RULES, body: &protocol.VersioningRules{}, want: ErrConfigRule},
	}
	for _, c := range cases {
		verdict := net.post(net.owner, c.signedType, c.body)
		if verdict.Accepted() || !errors.Is(verdict.Refusal, c.want) {
			t.Errorf("%s: %v", c.signedType, verdict.Refusal)
		}
	}
}

// A statement signed by a recovery key or a Delegation's key is refused at its signer until TEAM-M2-05 and
// TEAM-M2-04 land; an unknown signer, a bad signature or signer ids of no known form are refused as signers.
func TestSignersOfOtherKindsAreRefused(t *testing.T) {
	net := newTestConfigNet(t)
	body := testConfigMarshal(t, net.memberAdmitStatement("recovered"))
	wrap := func(signerId []byte, keyId []byte, signature []byte) []byte {
		return testConfigMarshal(t, &bridge.Signed{Body: body, SignerId: signerId, KeyId: keyId, Signature: signature, Type: uint32(bridge.SignedType_SIGNED_MEMBER_ADMIT)})
	}
	cases := []struct {
		name   string
		signed []byte
		want   error
	}{
		{name: "a recovery key", signed: wrap(net.ownerMemberId.Bytes(), make([]byte, 32), make([]byte, 64)), want: ErrConfigRuleMissing},
		{name: "a Delegation", signed: wrap(make([]byte, 32), make([]byte, 32), make([]byte, 64)), want: ErrConfigRuleMissing},
		{name: "no signer_id", signed: wrap(nil, nil, make([]byte, 64)), want: ErrConfigSigner},
		{name: "a bad signature", signed: wrap(net.owner.sidecarId.Bytes(), nil, make([]byte, 64)), want: ErrConfigSigner},
	}
	for _, c := range cases {
		verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, c.signed))
		if verdict.Accepted() || !errors.Is(verdict.Refusal, c.want) {
			t.Errorf("%s: %v", c.name, verdict.Refusal)
		}
	}
}

// §7.9's replay row, at a long-running reader and at a new device alike: an at 4,097 positions old, an expired
// statement, one expiring over 7 days on, a repeat, another network's, a short nonce, and an at before the retention
// point are refused, and an at exactly 4,096 positions old passes.
func TestReplayRulesRefuseAlikeOnANewDeviceAndALongRunningReader(t *testing.T) {
	net := newTestConfigNet(t)
	first := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("first"))
	firstBytes := net.entries[len(net.entries)-1]
	firstEntry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(firstBytes, firstEntry); err != nil {
		t.Fatal(err)
	}
	for range configStatementWindow + 2 {
		net.tick(&bridge.ApiTick{})
	}
	foldedThrough := net.n

	tooOld := net.memberAdmitStatement("too old")
	tooOld.Header.At = net.statesAt[net.n+1-configStatementWindow-1].Pin()
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, tooOld, ErrConfigReplay)
	oldest := net.memberAdmitStatement("oldest")
	oldest.Header.At = net.statesAt[net.n+1-configStatementWindow].Pin()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, oldest)

	expired := net.memberAdmitStatement("expired")
	expired.Header.NotAfterMs = net.timeMs
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, expired, ErrConfigReplay)
	tooLong := net.memberAdmitStatement("too long")
	tooLong.Header.NotAfterMs = net.timeMs + 1000 + configStatementMaxLifetimeMs + 1
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, tooLong, ErrConfigReplay)
	elsewhere := net.memberAdmitStatement("elsewhere")
	elsewhere.Header.NetworkId = testConfigId("other network").Bytes()
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, elsewhere, ErrConfigReplay)
	shortNonce := net.memberAdmitStatement("short nonce")
	shortNonce.Header.Nonce = shortNonce.Header.Nonce[:8]
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, shortNonce, ErrConfigReplay)

	// the first statement's bytes again, under a new wrapper: the same id
	repeated := &bridge.Signed{}
	if err := proto.Unmarshal(firstEntry.GetBody(), repeated); err != nil {
		t.Fatal(err)
	}
	repeated.KeyId = nil
	repeated.Webauthn = &bridge.WebAuthnEvidence{KeyId: []byte("a countersignature no row asks for")}
	repeatVerdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, testConfigMarshal(t, repeated)))
	if repeatVerdict.Accepted() || !errors.Is(repeatVerdict.Refusal, ErrConfigReplay) || repeatVerdict.StatementId != first.StatementId {
		t.Errorf("the repeat: %v", repeatVerdict.Refusal)
	}

	// two bases move the retention point past base 1: min(the previous base, folded_through + 1)
	tailFrom := foldedThrough + 1
	net.fold(net.owner, foldedThrough, 2)
	previousBase := net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("between"))
	net.fold(net.owner, previousBase+1, 3)
	if point := net.log.State().RetentionPoint(); point != previousBase {
		t.Fatalf("the retention point is %d", point)
	}
	beforeRetention := net.memberAdmitStatement("before retention")
	beforeRetention.Header.At = net.statesAt[previousBase-1].Pin()
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, beforeRetention, ErrConfigReplay)
	atRetention := net.memberAdmitStatement("at retention")
	atRetention.Header.At = net.statesAt[previousBase].Pin()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, atRetention)

	// a new device from what the long-running reader keeps judges every entry it holds alike
	restored, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
	if err != nil {
		t.Fatal(err)
	}
	testConfigStatesEqual(t, restored.State(), net.log.State())
	if restored.keptFrom != previousBase {
		t.Errorf("the new device keeps from %d", restored.keptFrom)
	}
	for n := tailFrom; n <= net.n; n += 1 {
		want, got := net.log.keptEntry(n), restored.keptEntry(n)
		if want == nil || got == nil {
			continue
		}
		if want.verdict.Accepted() != got.verdict.Accepted() || want.verdict.StatementId != got.verdict.StatementId {
			t.Errorf("entry %d: long-running %v, new device %v", n, want.verdict.Refusal, got.verdict.Refusal)
		}
	}

	// a new device that starts at base 2, whose tail holds every refusal above, judges them alike at their positions
	partial := &ConfigRetained{SignedGenesis: net.signedGenesis, Rows: net.source.rows}
	for n := uint64(1); n <= previousBase; n += 1 {
		partial.Entries = append(partial.Entries, net.entries[n-1])
	}
	early, err := RestoreConfigLog(testConfigLogSettings(), partial, net.source)
	if err != nil {
		t.Fatal(err)
	}
	for n := tailFrom; n < previousBase; n += 1 {
		want, got := net.log.keptEntry(n), early.keptEntry(n)
		if want == nil {
			want = &configKeptEntry{verdict: net.verdictAt(t, n)}
		}
		if got == nil || want.verdict.Accepted() != got.verdict.Accepted() {
			t.Errorf("tail entry %d: long-running %v, new device %v", n, want.verdict.Refusal, got)
		}
	}
	testConfigStatesEqual(t, early.State(), net.statesAt[previousBase])
}

// The verdict the long-running reader gave entry n, applying it again to a fresh reader up to n.
func (self *testConfigNet) verdictAt(t *testing.T, n uint64) ConfigVerdict {
	reader, err := NewConfigLog(testConfigLogSettings(), self.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	verdict := ConfigVerdict{}
	for i := uint64(1); i <= n; i += 1 {
		if verdict, err = reader.Apply(self.entries[i-1], self.source); err != nil {
			t.Fatal(err)
		}
	}
	return verdict
}

// FS-14: a new device that starts after 30 days of retention, at a base folded below the previous one, reaches the
// long-running reader's S(n): the base's rows plus its tail re-applied, then everything after.
func TestANewDeviceAfterRetentionReachesALongRunningReadersState(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("member m")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := net.device("m laptop", member)
	net.admitDevice(net.owner, laptop, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	foldPoint := net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: net.header(), SidecarId: phone.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
	})
	net.post(phone, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("by a revoked phone"))
	net.fold(net.owner, foldPoint-1, 2)
	previousBase := net.n
	tablet := net.device("m tablet", member)
	net.admitDevice(laptop, tablet, 0)

	net.timeMs += 31 * 24 * 60 * 60 * 1000
	net.fold(net.owner, foldPoint, 3)
	if base := net.log.State().Base(); base.GetFoldedThrough() >= previousBase {
		t.Fatalf("the newest base folds through %d, not below the previous base at %d", base.GetFoldedThrough(), previousBase)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after"))
	net.tick(&bridge.ApiTick{})

	retained := net.log.Retained()
	if len(retained.Rows) != 2 {
		t.Errorf("%d bases' rows kept", len(retained.Rows))
	}
	restored, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	testConfigStatesEqual(t, restored.State(), net.log.State())
	if restored.State().SidecarRow(tablet.sidecarId) == nil || restored.State().SidecarRow(phone.sidecarId).GetRevokedAt() == 0 {
		t.Error("the new device misses the tail's admission or revocation")
	}
	for _, basePin := range net.log.State().basePins {
		if basePin.n == 1 {
			t.Error("base 1's pin outlived 30 days")
		}
	}
	if !net.log.State().OnChain(net.statesAt[previousBase].Pin()) {
		t.Error("the previous base's pin is off the chain")
	}

	// the new device goes on as a reader
	net.log = restored
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("on the new device"))
}

// A base re-applies its tail keeping each verdict: a revocation stays though a later authority change took its
// signer's role, and a statement refused at its position stays refused though the new rows would allow it.
func TestABaseReappliesItsTailKeepingEachVerdict(t *testing.T) {
	net := newTestConfigNet(t)
	itAdmin := testConfigId("it admin")
	net.admitMember(net.owner, itAdmin, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}, ItAdmins: [][]byte{itAdmin.Bytes()},
	})
	itDevice := net.device("it device", itAdmin)
	net.admitDevice(net.owner, itDevice, 0)
	member := testConfigId("member")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	target := net.device("target", member)
	net.admitDevice(net.owner, target, 0)
	foldPoint := net.n

	net.mustPost(itDevice, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: net.header(), SidecarId: target.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
	})
	late := net.device("late", member)
	refused := net.post(target, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(late, nil, false, 0, 0))
	if refused.Accepted() {
		t.Fatal("a revoked device admitted")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()},
	})

	// the new base's rows make the revoked target an IT admin's live device, which would admit
	rows := net.statesAt[foldPoint].Rows()
	for _, row := range rows.Members {
		if bytes.Equal(row.MemberId, member.Bytes()) {
			row.Role = bridge.MemberRole_MEMBER_ROLE_IT_ADMIN
		}
	}
	net.pushBase(net.owner, rows, foldPoint, 2, 0)
	state := net.log.State()
	if state.SidecarRow(target.sidecarId).GetRevokedAt() == 0 {
		t.Error("an authority change undid the revocation")
	}
	if state.SidecarRow(late.sidecarId) != nil {
		t.Error("a statement refused at its position took effect on the new rows")
	}
	testConfigStatesEqual(t, net.newReader().State(), state)
}

// A tick revokes each reaped ephemeral admission at its position; one naming a member device, or carrying an
// activation before TEAM-M2-05's window rule, is refused and changes nothing.
func TestATickReapsOnlyEphemeralAdmissions(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("member")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	worker := net.device("worker", member)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(worker, nil, true, net.timeMs+60*60*1000, 0))
	laptop := net.device("laptop", member)
	net.admitDevice(net.owner, laptop, 0)

	refused := net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{worker.sidecarId.Bytes(), laptop.sidecarId.Bytes()}})
	if refused.Accepted() || !errors.Is(refused.Refusal, ErrConfigRule) {
		t.Errorf("a member device reaped: %v", refused.Refusal)
	}
	activation := net.tick(&bridge.ApiTick{ActivatedProposalIds: [][]byte{make([]byte, 32)}})
	if activation.Accepted() || !errors.Is(activation.Refusal, ErrConfigRuleMissing) {
		t.Errorf("an activation: %v", activation.Refusal)
	}
	if net.log.State().SidecarRow(worker.sidecarId).GetRevokedAt() != 0 {
		t.Fatal("a refused tick reaped")
	}
	reap := net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{worker.sidecarId.Bytes()}})
	if !reap.Accepted() || net.log.State().SidecarRow(worker.sidecarId).GetRevokedAt() != reap.Pin.GetVersion() {
		t.Errorf("the reap: %v", reap.Refusal)
	}
	again := net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{worker.sidecarId.Bytes()}})
	if !again.Accepted() || net.log.State().SidecarRow(worker.sidecarId).GetRevokedAt() != reap.Pin.GetVersion() {
		t.Error("a second reap moved the revocation")
	}
}

// api's retry identity: a statement applied among the last 4,096 entries is found by its id, a refused one is not.
func TestFindStatementAnswersARetry(t *testing.T) {
	net := newTestConfigNet(t)
	applied := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("applied"))
	refused := net.post(net.owner, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{Header: net.header(), KeyId: []byte("k")})
	if pin, found := net.log.FindStatement(applied.StatementId); !found || !proto.Equal(pin, applied.Pin) {
		t.Errorf("applied: %v, %t", pin, found)
	}
	if _, found := net.log.FindStatement(refused.StatementId); found {
		t.Error("a refused statement burned its id")
	}
}

// An in-memory ConfigStateStore.
type testConfigStore struct {
	saved map[Id]*ConfigRetained
}

// What was saved.
func (self *testConfigStore) LoadConfigRetained(networkId Id) (*ConfigRetained, error) {
	return self.saved[networkId], nil
}

// Saves.
func (self *testConfigStore) SaveConfigRetained(networkId Id, retained *ConfigRetained) error {
	self.saved[networkId] = retained
	return nil
}

// A restart from what the store kept resumes at the same pin and state, never a lower one.
func TestARestartFromTheStoreResumesAtTheSamePin(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("member")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.fold(net.owner, net.n, 2)
	net.admitDevice(net.owner, net.device("laptop", member), 0)
	store := &testConfigStore{saved: map[Id]*ConfigRetained{}}
	if err := net.log.SaveTo(store); err != nil {
		t.Fatal(err)
	}
	retained, err := store.LoadConfigRetained(net.networkId)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	testConfigStatesEqual(t, restored.State(), net.log.State())
}

// Kept entries that do not chain, or hold no base, are refused rather than restored.
func TestRestoreRefusesEntriesThatDoNotChain(t *testing.T) {
	net := newTestConfigNet(t)
	net.tick(&bridge.ApiTick{})
	net.tick(&bridge.ApiTick{})
	broken := &ConfigRetained{SignedGenesis: net.signedGenesis, Rows: net.source.rows, Entries: [][]byte{net.entries[0], net.entries[2]}}
	if _, err := RestoreConfigLog(testConfigLogSettings(), broken, net.source); err == nil {
		t.Error("a gap restored")
	}
	baseless := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: [][]byte{net.entries[1], net.entries[2]}}
	if _, err := RestoreConfigLog(testConfigLogSettings(), baseless, net.source); err == nil {
		t.Error("no base restored")
	}
}

// api's statement row: Check gives the verdict Apply then gives at the next position, accepted or refused, and moves
// nothing; a repeat of an applied statement is refused there, and FindStatement answers it.
func TestCheckGivesApplysVerdictWithoutApplying(t *testing.T) {
	team := newTestConfigTeam(t)
	memberX := testConfigId("x")
	team.admitMember(team.owner, memberX, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	statements := []struct {
		signer     testConfigDevice
		signedType bridge.SignedType
		body       func() proto.Message
	}{
		{signer: team.owner, signedType: bridge.SignedType_SIGNED_MEMBER_ADMIT, body: func() proto.Message { return team.memberAdmitStatement("checked") }},
		{signer: team.owner, signedType: bridge.SignedType_SIGNED_ADMIN_SET, body: func() proto.Message { return team.adminSet(0, memberX) }},
		{signer: team.owner, signedType: bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, body: func() proto.Message {
			return &protocol.AuthorityProposal{
				Header: team.header(), StatementType: uint32(bridge.SignedType_SIGNED_ADMIN_SET), Statement: testConfigMarshal(t, team.adminSet(0, memberX)),
			}
		}},
		{signer: team.adminB, signedType: bridge.SignedType_SIGNED_MEMBER_REVOKE, body: func() proto.Message {
			return &bridge.MemberRevoke{Header: team.header(), MemberId: team.ownerMemberId.Bytes()}
		}},
	}
	for _, statement := range statements {
		signedBytes := team.sign(statement.signer, statement.signedType, statement.body())
		before := team.log.Pin()
		checked := team.log.Check(signedBytes, team.timeMs+1000)
		if !proto.Equal(team.log.Pin(), before) {
			t.Fatal("Check moved the log")
		}
		applied := team.push(team.makeEntry(bridge.AuthEntryKindStatement, signedBytes))
		if checked.Accepted() != applied.Accepted() || checked.StatementId != applied.StatementId || !proto.Equal(checked.Pin, applied.Pin) {
			t.Errorf("%s: checked %v at %v, applied %v at %v", statement.signedType, checked.Refusal, checked.Pin, applied.Refusal, applied.Pin)
		}
		if applied.Accepted() {
			retry := team.log.Check(signedBytes, team.timeMs+1000)
			if retry.Accepted() || !errors.Is(retry.Refusal, ErrConfigReplay) {
				t.Errorf("%s again: %v", statement.signedType, retry.Refusal)
			}
			if pin, found := team.log.FindStatement(applied.StatementId); !found || !proto.Equal(pin, applied.Pin) {
				t.Errorf("%s's retry identity: %v, %t", statement.signedType, pin, found)
			}
		}
	}
}

// §22.5's config-repo replay in T1: a fresh reader walking a mixed log from genesis stands, at every position, on the
// state the long-running reader stood on there, bases, proposals, refusals and reaps included.
func TestConfigRepoReplaysFromGenesisAtEveryPosition(t *testing.T) {
	team := newTestConfigTeam(t)
	memberM, first := team.consentedMember("m")
	second := team.device("m second", memberM)
	team.admitDevice(first, second, 0)
	worker := team.device("m worker", memberM)
	team.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(worker, nil, true, team.timeMs+60*60*1000, 0))
	foldPoint := team.n
	phone := team.device("owner phone", team.ownerMemberId)
	_, admitId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0))
	team.post(team.adminB, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: team.header(), MemberId: memberM.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER,
	})
	team.cosign(team.adminB, admitId)
	team.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{worker.sidecarId.Bytes()}})
	team.fold(team.owner, foldPoint, 2)
	team.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	_, openId := team.propose(team.adminC, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: team.header(), MemberId: memberM.Bytes()})
	team.fold(team.owner, team.n, 3)
	if open := team.log.State().OpenProposalIds(); len(open) != 0 {
		t.Errorf("a proposal the last base folded is open: %x, %x", open, openId)
	}

	reader, err := NewConfigLog(testConfigLogSettings(), team.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	for i, entryBytes := range team.entries {
		if _, err := reader.Apply(entryBytes, team.source); err != nil {
			t.Fatalf("entry %d: %v", i+1, err)
		}
		testConfigStatesEqual(t, reader.State(), team.statesAt[uint64(i+1)])
	}
}
