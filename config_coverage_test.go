// TEAM-M2-17's causal identities on the test network: a shrink advances holders_shrunk_at at its entry and closes the
// gate to an older generation, through KEYS's GkmGatePasses; an expired grant fails a generation older than its expiry;
// a compromise rebind shrinks with the holder's identity unchanged; time alone with no expiring grant shrinks nothing;
// every kind of reader holds the same values after a base; and a head change at a base shrinks every repo, the
// fail-closed rule question team-m2-09-base-shrinks keeps.

package sidecar

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A general repo the owner made, and a member device it granted reading, which a KeyHolders leaf holds.
func (self *testConfigNet) repoWithReader(label string, expires int64) (Id, testConfigDevice) {
	self.t.Helper()
	reader := self.admitMemberDevice(label + " reader")
	repoId := testConfigId(label + " repo")
	self.mustPost(self.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: self.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	self.mustPost(self.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: self.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: expires,
	})
	holders, err := KeyHolders(self.log.State(), repoId, time.UnixMilli(self.timeMs))
	if err != nil || !holders.Contains(GkmHolderLeaf, reader.sidecarId.Bytes()) {
		self.t.Fatalf("the reader holds no key: %v", err)
	}
	return repoId, reader
}

// FS-14: a generation rotated at n1, then a shrink at n2 > n1: holders_shrunk_at is n2, the gate refuses the n1
// generation, and a generation at n2 passes; a grant to another reader shrinks nothing.
func TestAShrinkAfterARotationReopensNoGate(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, reader := net.repoWithReader("r", 0)
	rotatedAt := net.log.Pin()
	other := net.admitMemberDevice("other")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: other.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	if shrunk := net.log.State().ShrunkAt(repoId); rotatedAt.GetVersion() < shrunk {
		t.Fatalf("a grant shrank the repo at %d", shrunk)
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	state := net.log.State()
	if shrunk := state.ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
		t.Fatalf("holders_shrunk_at %d, the revoke at %d", shrunk, revoked.Pin.GetVersion())
	}
	now := time.UnixMilli(net.timeMs)
	if GkmGatePasses(state, repoId, rotatedAt, now, now) {
		t.Error("the generation from before the shrink passes the gate")
	}
	if !GkmGatePasses(state, repoId, revoked.Pin, now, now) {
		t.Error("a generation at the shrink does not pass")
	}
	net.everyReaderAgrees()
}

// FS-14: an expired grant fails a generation older than its expiry, at its expiry and no entry; one at or after it
// passes. ExpiriesFor finds the expiry.
func TestAnExpiredGrantFailsAnOlderGeneration(t *testing.T) {
	net := newTestConfigNet(t)
	expires := net.timeMs + 60*60*1000
	repoId, _ := net.repoWithReader("expiring", expires)
	pin := net.log.Pin()
	state := net.log.State()
	before := time.UnixMilli(net.timeMs)
	after := time.UnixMilli(expires + 1000)
	expiry, found, err := state.ExpiriesFor(repoId, before, after)
	if err != nil || !found || expiry.UnixMilli() != expires {
		t.Fatalf("the expiry: %v %v %v", expiry, found, err)
	}
	if GkmGatePasses(state, repoId, pin, before, after) {
		t.Error("a generation from before the expiry passes after it")
	}
	if !GkmGatePasses(state, repoId, pin, time.UnixMilli(expires), after) {
		t.Error("a generation at the expiry does not pass")
	}
	// time with no expiring holder shrinks and expires nothing: a ReaderKey's lapse is no expiry
	plain, _ := net.repoWithReader("plain", 0)
	if _, found, err := net.log.State().ExpiriesFor(plain, before, after.Add(30*24*time.Hour)); err != nil || found {
		t.Errorf("an expiry with no expiring grant: %v %v", found, err)
	}
}

// A compromise rebind of a member who reads a repo shrinks it, though the member's recovery identity stays: the new
// binding is current.
func TestACompromiseRebindShrinksWithTheIdentityUnchanged(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	key := testConfigRecovery(member, "m")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	repoId := testConfigId("m repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: laptop.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	at := time.UnixMilli(net.timeMs)
	holders, err := KeyHolders(net.log.State(), repoId, at)
	if err != nil || !holders.Contains(GkmHolderRecovery, member.Bytes()) {
		t.Fatalf("the member's recovery holds no key: %v", err)
	}
	next := testConfigRecovery(member, "m next")
	rebound := net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, &protocol.RecoveryRebind{
		Header: net.header(), MemberId: member.Bytes(), PrevSha256: key.sha256(), Ed25519PublicKeySha256: next.sha256(),
		Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE,
	})
	state := net.log.State()
	if after, err := KeyHolders(state, repoId, time.UnixMilli(net.timeMs)); err != nil || !after.Contains(GkmHolderRecovery, member.Bytes()) {
		t.Fatalf("the recovery identity left: %v", err)
	}
	if shrunk := state.ShrunkAt(repoId); shrunk != rebound.Pin.GetVersion() {
		t.Errorf("holders_shrunk_at %d, the rebind at %d", shrunk, rebound.Pin.GetVersion())
	}
	net.everyReaderAgrees()
}

// A shrink in a base's tail re-applies to the same holders_shrunk_at at a long-running reader, a new device and a
// rows-only gate (DESIGN-DETAILS 5.7's TEAM-M2-17 note).
func TestShrunkAtIsEqualAtEveryReaderAfterABase(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, reader := net.repoWithReader("r", 0)
	foldedThrough := net.n
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes()})
	net.fold(net.owner, foldedThrough, 1)
	for _, reader := range net.everyReader() {
		if shrunk := reader.State().ShrunkAt(repoId); shrunk != revoked.Pin.GetVersion() {
			t.Errorf("a reader's holders_shrunk_at %d, the revoke at %d", shrunk, revoked.Pin.GetVersion())
		}
	}
	net.everyReaderAgrees()
}

// Question team-m2-09-base-shrinks' fail-closed rule: a base naming a newer config head shrinks every repo at its
// position, at every reader alike; a base keeping the head shrinks none.
func TestABaseWithANewerHeadShrinksEveryRepo(t *testing.T) {
	net := newTestConfigNet(t)
	repoId, _ := net.repoWithReader("r", 0)
	before := net.log.State().ShrunkAt(repoId)
	net.fold(net.owner, net.n, 1)
	if shrunk := net.log.State().ShrunkAt(repoId); shrunk != before {
		t.Errorf("a base keeping its head shrank the repo at %d", shrunk)
	}
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{WitnessBoundHours: 48}
	net.fold(net.owner, net.n, 2)
	if shrunk := net.log.State().ShrunkAt(repoId); shrunk != net.n {
		t.Errorf("a base with a newer head left holders_shrunk_at at %d", shrunk)
	}
	net.everyReaderAgrees()
}
