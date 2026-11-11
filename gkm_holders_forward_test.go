// KeyHolders' forwarding term (KEYS-M8-01; D-KEYS-16; owner decision 197; DESIGN-DETAILS 4.2.2) over the real
// ConfigState, so TEAM-M8-01's forwarding row decides what is live: a sidecar's live forwarding Delegation is a
// holder of the config alone, by its sidecar's identity, kind 5; a newer one keeps the holder and shrinks nothing;
// its DelegationRevoke, its sidecar's revocation and a Suspend each drop it, a shrink the next generation covers as
// REMOVE; a DelegationWrap to it is judged at its own state, a superseded one's refused; and a rotator's lookup of its
// reader key takes the statement while the log keeps the entry, else gkm's object, held to the row's digest. Pure, on
// every leg.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The test network at base 2, whose acl rows hold the config repo as its bootstrap leaves it, with a member's laptop
// and phone admitted and a general repo the phone reads.
type gkmForwardNet struct {
	*testConfigNet
	configId  Id
	generalId Id
	laptop    testConfigDevice
	phone     testConfigDevice
}

func newGkmForwardNet(t *testing.T) *gkmForwardNet {
	net := newTestConfigNet(t)
	configId := testConfigId("config repo")
	rows := net.statesAt[net.n].Rows()
	rows.Acl = testConfigMarshal(t, &protocol.AclRows{Repos: []*protocol.AclRepo{{RepoId: configId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG}}})
	if verdict := net.pushBase(net.owner, rows, net.n, 2, 0); !verdict.Accepted() {
		t.Fatalf("base 2: %v", verdict.Refusal)
	}
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	generalId := testConfigId("general repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: generalId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: generalId.Bytes(), Subject: phone.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	return &gkmForwardNet{testConfigNet: net, configId: configId, generalId: generalId, laptop: laptop, phone: phone}
}

// A forwarding Delegation of device whose reader key is a real X-Wing key, which takes effect: its id and the key.
func (self *gkmForwardNet) forwardWithKey(device testConfigDevice, label string) ([]byte, hpke.PrivateKey) {
	self.t.Helper()
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		self.t.Fatal(err)
	}
	statement, _ := self.forwardingStatement(device, label)
	statement.ReaderXwingPublicKey = privateKey.PublicKey().Bytes()
	verdict := self.mustPost(device, bridge.SignedType_SIGNED_DELEGATION, statement)
	return bytes.Clone(verdict.StatementId[:]), privateKey
}

// The state's time.
func gkmForwardAt(state *ConfigState) time.Time {
	return time.UnixMilli(state.TimeMs())
}

// The holders of a repo at the reader's state and its time.
func (self *gkmForwardNet) holders(repoId Id) GkmHolders {
	self.t.Helper()
	state := self.log.State()
	holders, err := KeyHolders(state, repoId, gkmForwardAt(state))
	if err != nil {
		self.t.Fatal(err)
	}
	return holders
}

// The forwarding holder of a sidecar among holders, false for none.
func gkmForwardHolder(holders GkmHolders, sidecarId Id) (GkmHolder, bool) {
	for _, holder := range holders {
		if holder.Kind == GkmHolderForwarding && bytes.Equal(holder.Id, sidecarId.Bytes()) {
			return holder, true
		}
	}
	return GkmHolder{}, false
}

// SHA-256 of a reader key's public bytes.
func gkmForwardKeySha256(privateKey hpke.PrivateKey) []byte {
	digest := sha256.Sum256(privateKey.PublicKey().Bytes())
	return digest[:]
}

// Signs as device's identity key, GkmSignFunction's shape.
func gkmForwardSigner(device testConfigDevice) GkmSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  device.sidecarId.Bytes(),
			Signature: ed25519.Sign(device.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// A sidecar's live forwarding Delegation is a holder of the config alone, kind 5 by its sidecar's id, carrying the
// Delegation's id and its row's key digest; a sidecar with none is no forwarding holder; a repo the sidecar reads
// otherwise holds its leaf and no forwarding holder.
func TestKeyHoldersHoldALiveForwardingDelegationInTheConfigAlone(t *testing.T) {
	net := newGkmForwardNet(t)
	delegationId, readerKey := net.forwardWithKey(net.phone, "phone")
	configHolders := net.holders(net.configId)
	holder, found := gkmForwardHolder(configHolders, net.phone.sidecarId)
	if !found {
		t.Fatalf("no forwarding holder among the config's: %v", gkmTestIdentities(configHolders))
	}
	if !bytes.Equal(holder.ForwardDelegationId, delegationId) || !bytes.Equal(holder.ForwardReaderKeySha256, gkmForwardKeySha256(readerKey)) {
		t.Errorf("the holder names %x with %x", holder.ForwardDelegationId, holder.ForwardReaderKeySha256)
	}
	if want := append([]byte{5}, net.phone.sidecarId.Bytes()...); !bytes.Equal(holder.Identity(), want) || len(holder.Identity()) != 17 {
		t.Errorf("the forwarding identity is %x", holder.Identity())
	}
	if _, found := gkmForwardHolder(configHolders, net.laptop.sidecarId); found {
		t.Error("a sidecar with no forwarding Delegation holds a forwarding identity")
	}
	if !configHolders.Contains(GkmHolderLeaf, net.phone.sidecarId.Bytes()) {
		t.Error("the phone's own leaf left the config")
	}
	generalHolders := net.holders(net.generalId)
	if _, found := gkmForwardHolder(generalHolders, net.phone.sidecarId); found {
		t.Error("a forwarding Delegation holds a repo other than the config")
	}
	if !generalHolders.Contains(GkmHolderLeaf, net.phone.sidecarId.Bytes()) {
		t.Error("the phone does not read the general repo it was granted")
	}
	state := net.log.State()
	for _, c := range []struct {
		repoId Id
		want   bool
	}{{repoId: net.configId, want: true}, {repoId: net.generalId, want: false}} {
		holds, err := GkmDelegationHolds(state, c.repoId, delegationId, gkmForwardAt(state))
		if err != nil || holds != c.want {
			t.Errorf("a DelegationWrap to the forwarding Delegation in %s reaches a holder: %v %v", c.repoId, holds, err)
		}
	}
	net.everyReaderAgrees()
}

// A newer forwarding Delegation of the sidecar keeps its holder: holders_sha256 does not change, no repo's
// holders_shrunk_at moves, no REMOVE is due, and a DelegationWrap reaches the newer one and not the superseded one.
func TestAForwardingSupersessionKeepsTheHolderAndShrinksNothing(t *testing.T) {
	net := newGkmForwardNet(t)
	first, _ := net.forwardWithKey(net.phone, "first")
	before := net.holders(net.configId)
	pinBefore, timeBefore := net.log.Pin(), gkmForwardAt(net.log.State())
	shrunkBefore := net.log.State().ShrunkAt(net.configId)
	second, secondKey := net.forwardWithKey(net.phone, "second")
	after := net.holders(net.configId)
	if !bytes.Equal(before.Sha256(), after.Sha256()) {
		t.Errorf("a supersession changed holders_sha256")
	}
	state := net.log.State()
	if shrunk := state.ShrunkAt(net.configId); shrunk != shrunkBefore {
		t.Errorf("a supersession shrank the config at %d", shrunk)
	}
	if removeDue, err := GkmRemoveDue(state, net.configId, pinBefore, timeBefore, gkmForwardAt(state)); err != nil || removeDue {
		t.Errorf("a supersession makes the next generation REMOVE: %v %v", removeDue, err)
	}
	holder, found := after.DelegationRecipient(second)
	if !found || holder.Kind != GkmHolderForwarding || !bytes.Equal(holder.ForwardReaderKeySha256, gkmForwardKeySha256(secondKey)) {
		t.Error("a DelegationWrap to the newer forwarding Delegation reaches no holder at its key")
	}
	if _, found := after.DelegationRecipient(first); found {
		t.Error("a DelegationWrap to the superseded forwarding Delegation reaches a holder")
	}
	if _, found := before.DelegationRecipient(first); !found {
		t.Error("before the supersession, the first was no recipient")
	}
	net.everyReaderAgrees()
}

// The live forwarding Delegation's DelegationRevoke, and its sidecar's revocation, drop the forwarding holder: a shrink
// of the config at that entry, so the next generation is REMOVE, and no repo it never reached shrinks for it.
func TestAForwardingEndShrinksTheConfigSoTheNextGenerationIsRemove(t *testing.T) {
	cases := []struct {
		name string
		end  func(net *gkmForwardNet, delegationId []byte) ConfigVerdict
		// whether the sidecar itself leaves, its leaf with it
		sidecarLeaves bool
	}{
		{name: "its DelegationRevoke", end: func(net *gkmForwardNet, delegationId []byte) ConfigVerdict {
			return net.mustPost(net.phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(delegationId, 0))
		}},
		{name: "an admin's DelegationRevoke", end: func(net *gkmForwardNet, delegationId []byte) ConfigVerdict {
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(delegationId, 0))
		}},
		{name: "its sidecar's revocation", sidecarLeaves: true, end: func(net *gkmForwardNet, delegationId []byte) ConfigVerdict {
			return net.mustPost(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
		}},
	}
	for _, c := range cases {
		net := newGkmForwardNet(t)
		delegationId, _ := net.forwardWithKey(net.phone, c.name)
		pinBefore, timeBefore := net.log.Pin(), gkmForwardAt(net.log.State())
		generalShrunk := net.log.State().ShrunkAt(net.generalId)
		ended := c.end(net, delegationId)
		state := net.log.State()
		if shrunk := state.ShrunkAt(net.configId); shrunk != ended.Pin.GetVersion() {
			t.Errorf("%s: the config shrank at %d, the end at %d", c.name, shrunk, ended.Pin.GetVersion())
		}
		configHolders := net.holders(net.configId)
		if _, found := gkmForwardHolder(configHolders, net.phone.sidecarId); found {
			t.Errorf("%s: the forwarding holder stands", c.name)
		}
		if _, found := configHolders.DelegationRecipient(delegationId); found {
			t.Errorf("%s: a DelegationWrap to the ended Delegation reaches a holder", c.name)
		}
		if removeDue, err := GkmRemoveDue(state, net.configId, pinBefore, timeBefore, gkmForwardAt(state)); err != nil || !removeDue {
			t.Errorf("%s: the next generation is not REMOVE: %v %v", c.name, removeDue, err)
		}
		// the forwarding Delegation never reached the general repo: only its sidecar's own leaving shrinks it
		if shrunk := state.ShrunkAt(net.generalId); (shrunk != generalShrunk) != c.sidecarLeaves {
			t.Errorf("%s: the general repo shrank at %d", c.name, shrunk)
		}
		net.everyReaderAgrees()
	}
}

// A Suspend of the sidecar drops its forwarding holder, a shrink; the Unsuspend returns it with the same Delegation,
// which shrinks nothing.
func TestASuspendDropsTheForwardingHolderUntilTheUnsuspend(t *testing.T) {
	net := newGkmForwardNet(t)
	delegationId, _ := net.forwardWithKey(net.phone, "phone")
	suspended := net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: net.phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("forward")})
	if _, found := gkmForwardHolder(net.holders(net.configId), net.phone.sidecarId); found {
		t.Error("a suspended sidecar's forwarding Delegation holds the config")
	}
	if shrunk := net.log.State().ShrunkAt(net.configId); shrunk != suspended.Pin.GetVersion() {
		t.Errorf("the Suspend shrank the config at %d", shrunk)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.header(), Subject: net.phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("forward")})
	holder, found := gkmForwardHolder(net.holders(net.configId), net.phone.sidecarId)
	if !found || !bytes.Equal(holder.ForwardDelegationId, delegationId) {
		t.Error("the forwarding holder did not return with the Unsuspend")
	}
	if shrunk := net.log.State().ShrunkAt(net.configId); shrunk != suspended.Pin.GetVersion() {
		t.Errorf("the Unsuspend moved holders_shrunk_at to %d", shrunk)
	}
	net.everyReaderAgrees()
}

// gen/1 of repoId's group at the reader's state and time, signed by signer, counting wrapCount deliveries: its key
// and its parsed statement.
func (self *gkmForwardNet) firstGeneration(repoId Id, groupId Id, signer testConfigDevice, wrapCount uint32) (*EvsRepoKey, *GkmGeneration) {
	self.t.Helper()
	state := self.log.State()
	holders := self.holders(repoId)
	key, rotate, err := NewGkmFirstGeneration(repoId, groupId, &GkmGenerationArgs{
		Cause: GkmCauseRequest, Auth: state.Pin(), Time: gkmForwardAt(state), HoldersSha256: holders.Sha256(), WrapCount: wrapCount,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := SignGenRotate(rotate, gkmForwardSigner(signer))
	if err != nil {
		self.t.Fatal(err)
	}
	signedBytes, err := gkmSignedBytes(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	generation, err := ParseGenRotate(signedBytes, groupId, 1, GkmIdentityKeys(state))
	if err != nil {
		self.t.Fatal(err)
	}
	return key, generation
}

// A DelegationWrap of key to delegationId sealed to publicKey, by signer: STAGED, or LATE at the reader's state.
func (self *gkmForwardNet) delegationWrap(key *EvsRepoKey, groupId Id, delegationId []byte, publicKey []byte, signer testConfigDevice, kind GkmDeliveryKind) *GkmDelivery {
	self.t.Helper()
	args := &GkmDeliveryArgs{GroupId: groupId, Type: GkmWrapTypeDelegation, Recipient: delegationId, RecipientPublicKey: publicKey, Kind: kind}
	if kind == GkmDeliveryLate {
		state := self.log.State()
		args.Auth = state.Pin()
		args.Time = gkmForwardAt(state)
	}
	body, err := SealGkmDelivery(key, args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := SignGkmDelivery(body, GkmWrapTypeDelegation, gkmForwardSigner(signer))
	if err != nil {
		self.t.Fatal(err)
	}
	delivery, err := ParseGkmDelivery(signed, GkmWrapTypeDelegation, GkmIdentityKeys(self.log.State()))
	if err != nil {
		self.t.Fatal(err)
	}
	return delivery
}

// A DelegationWrap to a forwarding Delegation is judged at its own state, as members judge every delivery: a STAGED
// one of the config's generation to the live one passes, and its key opens; a LATE one after a supersession to the
// superseded one is refused and to the newer one passes; one of a general repo's generation is refused, since a
// forwarding Delegation reaches the config alone.
func TestADelegationWrapToAForwardingDelegationIsJudgedAtItsState(t *testing.T) {
	net := newGkmForwardNet(t)
	first, firstKey := net.forwardWithKey(net.phone, "first")
	groupId := testConfigId("config group")
	key1, generation1 := net.firstGeneration(net.configId, groupId, net.laptop, 1)
	staged := net.delegationWrap(key1, groupId, first, firstKey.PublicKey().Bytes(), net.laptop, GkmDeliveryStaged)
	check := func(repoId Id, delivery *GkmDelivery, generation *GkmGeneration) GkmVerdict {
		t.Helper()
		verdict, err := CheckDelivery(net.log.State(), &GkmDeliveryCheckArgs{RepoId: repoId, Delivery: delivery, Generation: generation, Now: gkmForwardAt(net.log.State())})
		if err != nil {
			t.Fatal(err)
		}
		return verdict
	}
	if verdict := check(net.configId, staged, generation1); verdict.Refused {
		t.Fatalf("a staged wrap to the live forwarding Delegation: %v", verdict)
	}
	opened, verdict, err := GkmUseDelivery(net.log.State(), &GkmDeliveryCheckArgs{RepoId: net.configId, Delivery: staged, Generation: generation1, Now: gkmForwardAt(net.log.State())}, first, firstKey)
	if err != nil || verdict.Refused || opened == nil || !bytes.Equal(opened.Commitment(), key1.Commitment()) {
		t.Fatalf("the forwarding reader key does not open its wrap: %v %v", verdict, err)
	}

	second, secondKey := net.forwardWithKey(net.phone, "second")
	toFirst := net.delegationWrap(key1, groupId, first, firstKey.PublicKey().Bytes(), net.laptop, GkmDeliveryLate)
	if verdict := check(net.configId, toFirst, generation1); !verdict.Refused {
		t.Error("a late wrap to the superseded forwarding Delegation passes")
	}
	toSecond := net.delegationWrap(key1, groupId, second, secondKey.PublicKey().Bytes(), net.laptop, GkmDeliveryLate)
	if verdict := check(net.configId, toSecond, generation1); verdict.Refused {
		t.Errorf("a late wrap to the newer forwarding Delegation: %v", verdict)
	}
	// the staged one stays valid at its own state, the supersession after it notwithstanding (§10.9's history row)
	if verdict := check(net.configId, staged, generation1); verdict.Refused {
		t.Errorf("the staged wrap judged again after the supersession: %v", verdict)
	}

	generalGroupId := testConfigId("general group")
	generalKey, generalGeneration := net.firstGeneration(net.generalId, generalGroupId, net.owner, 1)
	toGeneral := net.delegationWrap(generalKey, generalGroupId, second, secondKey.PublicKey().Bytes(), net.owner, GkmDeliveryStaged)
	if verdict := check(net.generalId, toGeneral, generalGeneration); !verdict.Refused {
		t.Error("a wrap of a general repo's generation to a forwarding Delegation passes")
	}
}

// The config's state that hides its kept entries, as a view with no log behind it is.
type gkmForwardViewWithoutEntries struct {
	GkmAuthView
}

// A rotator's lookup takes the key from the statement while the log keeps the entry that filed it, else from gkm's
// object, and only a key whose SHA-256 is the row's digest: no object is ErrGkmKeyMissing, other bytes are
// ErrGkmKeyMissing and ErrGkmReplyInvalid, and a fetch's failure is its own. Past two folds the window no longer keeps
// the entry, and the object is what answers.
func TestGkmForwardingReaderKeyTakesTheStatementThenTheObjectHeldToTheDigest(t *testing.T) {
	net := newGkmForwardNet(t)
	ctx := context.Background()
	delegationId, readerKey := net.forwardWithKey(net.phone, "phone")
	publicKey := readerKey.PublicKey().Bytes()
	state := net.log.State()
	holder, found := gkmForwardHolder(net.holders(net.configId), net.phone.sidecarId)
	if !found {
		t.Fatal("no forwarding holder")
	}
	if key, found := state.ForwardingStatementReaderKey(delegationId); !found || !bytes.Equal(key, publicKey) {
		t.Fatalf("the statement's key: %v", found)
	}
	fetchCount := 0
	fetched := func(answer []byte, answerErr error) GkmDelegationKeyFetch {
		return func(ctx context.Context, id []byte) ([]byte, error) {
			fetchCount += 1
			if !bytes.Equal(id, delegationId) {
				t.Errorf("a fetch of %x", id)
			}
			return answer, answerErr
		}
	}
	if key, err := GkmForwardingReaderKey(ctx, state, holder, fetched(nil, nil)); err != nil || !bytes.Equal(key, publicKey) || fetchCount != 0 {
		t.Errorf("from the statement: %v, %d fetches", err, fetchCount)
	}

	hidden := gkmForwardViewWithoutEntries{GkmAuthView: state}
	if _, err := GkmForwardingReaderKey(ctx, hidden, holder, fetched(nil, nil)); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no entry and no object: %v", err)
	}
	if _, err := GkmForwardingReaderKey(ctx, hidden, holder, nil); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no entry and no source of objects: %v", err)
	}
	strayKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GkmForwardingReaderKey(ctx, hidden, holder, fetched(strayKey.PublicKey().Bytes(), nil)); !errors.Is(err, ErrGkmKeyMissing) || !errors.Is(err, ErrGkmReplyInvalid) {
		t.Errorf("gkm's bytes that are not the row's key: %v", err)
	}
	if _, err := GkmForwardingReaderKey(ctx, hidden, holder, fetched(publicKey[1:], nil)); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("gkm's short bytes: %v", err)
	}
	unreachable := errors.New("gkm unreachable")
	if _, err := GkmForwardingReaderKey(ctx, hidden, holder, fetched(nil, unreachable)); !errors.Is(err, unreachable) || errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("a fetch that fails: %v", err)
	}
	if key, err := GkmForwardingReaderKey(ctx, hidden, holder, fetched(publicKey, nil)); err != nil || !bytes.Equal(key, publicKey) {
		t.Errorf("from the object: %v", err)
	}
	if _, err := GkmForwardingReaderKey(ctx, state, GkmHolder{Kind: GkmHolderLeaf, Id: net.phone.sidecarId.Bytes()}, nil); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a holder that is not a forwarding one: %v", err)
	}
	if _, found := state.ForwardingStatementReaderKey(bytes.Repeat([]byte{0x77}, gkmDelegationIdByteCount)); found {
		t.Error("an id no row holds has a statement's key")
	}

	// two folds past the entry: the window no longer keeps it
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	folded := net.log.State()
	if _, found := folded.ForwardingStatementReaderKey(delegationId); found {
		t.Error("the window still keeps an entry two folds old")
	}
	fetchCount = 0
	if key, err := GkmForwardingReaderKey(ctx, folded, holder, fetched(publicKey, nil)); err != nil || !bytes.Equal(key, publicKey) || fetchCount != 1 {
		t.Errorf("past the window, from the object: %v, %d fetches", err, fetchCount)
	}
}

// KEYS-M8-02 (QD-637): a rotator reads every forwarding holder's key the log does not give in one batched call, before
// it seals to any, and still holds each key to its own row's digest: a holder gkm has no key for, and one whose key is
// off its digest, each lose their wrap and cost the other holder nothing; a holder whose entry the log keeps is not
// asked; the batch's own failure refuses the read.
func TestGkmForwardingReaderKeysFetchedReadsOnceAndHoldsEachKeyToItsRow(t *testing.T) {
	net := newGkmForwardNet(t)
	ctx := context.Background()
	laptopId, laptopKey := net.forwardWithKey(net.laptop, "laptop")
	phoneId, phoneKey := net.forwardWithKey(net.phone, "phone")
	state := net.log.State()
	holders := net.holders(net.configId)
	laptopHolder, found := gkmForwardHolder(holders, net.laptop.sidecarId)
	if !found {
		t.Fatal("no forwarding holder of the laptop")
	}
	phoneHolder, found := gkmForwardHolder(holders, net.phone.sidecarId)
	if !found {
		t.Fatal("no forwarding holder of the phone")
	}
	strayKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// gkm's objects, as a fetch answers them, and what each call asked
	objects := map[string][]byte{}
	calls := [][][]byte{}
	var fetchErr error
	fetch := func(ctx context.Context, delegationIds [][]byte) ([][]byte, error) {
		calls = append(calls, delegationIds)
		if fetchErr != nil {
			return nil, fetchErr
		}
		keys := [][]byte{}
		for _, delegationId := range delegationIds {
			keys = append(keys, objects[string(delegationId)])
		}
		return keys, nil
	}
	hidden := gkmForwardViewWithoutEntries{GkmAuthView: state}

	// the laptop's object stands and the phone's does not: one call names both
	objects[string(laptopId)] = laptopKey.PublicKey().Bytes()
	read, err := GkmForwardingReaderKeysFetched(ctx, hidden, holders, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || len(calls[0]) != 2 {
		t.Fatalf("the reads: %d calls", len(calls))
	}
	if key, err := GkmForwardingReaderKey(ctx, hidden, laptopHolder, read); err != nil || !bytes.Equal(key, laptopKey.PublicKey().Bytes()) {
		t.Errorf("the laptop's key from the batch: %v", err)
	}
	if _, err := GkmForwardingReaderKey(ctx, hidden, phoneHolder, read); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("the phone's key, which gkm has none of: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("a lookup after the batch read again: %d calls", len(calls))
	}

	// the phone's object holds another key than its row names: that holder alone loses its wrap
	objects[string(phoneId)] = strayKey.PublicKey().Bytes()
	read, err = GkmForwardingReaderKeysFetched(ctx, hidden, holders, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GkmForwardingReaderKey(ctx, hidden, phoneHolder, read); !errors.Is(err, ErrGkmKeyMissing) || !errors.Is(err, ErrGkmReplyInvalid) {
		t.Errorf("the phone's key off its digest: %v", err)
	}
	if key, err := GkmForwardingReaderKey(ctx, hidden, laptopHolder, read); err != nil || !bytes.Equal(key, laptopKey.PublicKey().Bytes()) {
		t.Errorf("the laptop's key beside a bad one: %v", err)
	}
	// the twin: the phone's own key
	objects[string(phoneId)] = phoneKey.PublicKey().Bytes()
	read, err = GkmForwardingReaderKeysFetched(ctx, hidden, holders, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := GkmForwardingReaderKey(ctx, hidden, phoneHolder, read); err != nil || !bytes.Equal(key, phoneKey.PublicKey().Bytes()) {
		t.Errorf("the phone's own key: %v", err)
	}

	// the log keeps both entries: nothing is asked of gkm
	calls = nil
	read, err = GkmForwardingReaderKeysFetched(ctx, state, holders, fetch)
	if err != nil || len(calls) != 0 {
		t.Fatalf("with the entries kept: %v, %d calls", err, len(calls))
	}
	if key, err := GkmForwardingReaderKey(ctx, state, phoneHolder, read); err != nil || !bytes.Equal(key, phoneKey.PublicKey().Bytes()) {
		t.Errorf("the phone's key from its entry: %v", err)
	}

	// a batch that fails refuses the read, and no source of objects leaves each holder missing
	unreachable := errors.New("gkm unreachable")
	fetchErr = unreachable
	if _, err := GkmForwardingReaderKeysFetched(ctx, hidden, holders, fetch); !errors.Is(err, unreachable) {
		t.Errorf("a batch that fails: %v", err)
	}
	read, err = GkmForwardingReaderKeysFetched(ctx, hidden, holders, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GkmForwardingReaderKey(ctx, hidden, laptopHolder, read); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no source of objects: %v", err)
	}
	fetchErr = nil
	short := func(ctx context.Context, delegationIds [][]byte) ([][]byte, error) { return nil, nil }
	if _, err := GkmForwardingReaderKeysFetched(ctx, hidden, holders, short); !errors.Is(err, ErrGkmReplyInvalid) {
		t.Errorf("a batch that answers fewer keys than it was asked: %v", err)
	}
}

// The key digest a DelegationWrap names: a forwarding row's reader_key_sha256, any other's its reader key's SHA-256;
// a row with neither at its size has none.
func TestGkmDelegationKeySha256ByRowKind(t *testing.T) {
	readerKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := readerKey.PublicKey().Bytes()
	keySha256 := sha256.Sum256(publicKey)
	for _, c := range []struct {
		name  string
		row   *bridge.DelegationRow
		want  []byte
		found bool
	}{
		{name: "an auth key's", row: &bridge.DelegationRow{ReaderXwingPublicKey: publicKey}, want: keySha256[:], found: true},
		{name: "a forwarding one's", row: &bridge.DelegationRow{ForwardSidecarId: testConfigId("s").Bytes(), ReaderKeySha256: keySha256[:]}, want: keySha256[:], found: true},
		{name: "a forwarding one's with its key in the row only", row: &bridge.DelegationRow{ForwardSidecarId: testConfigId("s").Bytes(), ReaderXwingPublicKey: publicKey}},
		{name: "a short key", row: &bridge.DelegationRow{ReaderXwingPublicKey: publicKey[1:]}},
		{name: "a short digest", row: &bridge.DelegationRow{ForwardSidecarId: testConfigId("s").Bytes(), ReaderKeySha256: keySha256[1:]}},
	} {
		digest, found := GkmDelegationKeySha256(c.row)
		if found != c.found || !bytes.Equal(digest, c.want) {
			t.Errorf("%s: %x %v", c.name, digest, found)
		}
	}
}

// QD-442's form of the key object's key: gkm/dkey/ and 64 lowercase hex characters; an id of another size is refused.
func TestGkmDelegationKeyPathIsQd442s(t *testing.T) {
	delegationId := sha256.Sum256([]byte("a forwarding Delegation"))
	path, err := GkmDelegationKeyPath(delegationId[:])
	if err != nil || path != "gkm/dkey/"+hex.EncodeToString(delegationId[:]) || strings.ToLower(path) != path {
		t.Errorf("the path: %s %v", path, err)
	}
	if _, err := GkmDelegationKeyPath(delegationId[:31]); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a short id: %v", err)
	}
}
