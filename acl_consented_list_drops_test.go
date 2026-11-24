//go:build !ios_extension

// QD-1191 on the test network: an owner-bound repo's consented_sidecar_ids hold exactly its owner's consented devices
// now (acl_access_log.go's consented row, config_coverage.go's configAdvanceConsents). A device whose consent rested on
// what a compromise cascade's P signed leaves the list at the revocation that voids it and stays out once an admin's
// AdmissionConfirm lifts its park, so every rows-only check refuses it as AclState does: gkm's GroupForm signer rule,
// the members' Add check (mayJoin), a commit's joiner row and evs's drop signer check. A confirmation by its owner's
// consented device lists it again, and so does the lift of a park that alone kept it out. A revoked device and a
// removed member's devices leave the list at the entry that ends their consent. A past act, a GroupForm, a DROP or a
// commit's Add, judged at its own pin still verifies where the list named its device then. Every reader folds the
// same lists, a rows-only gate and a reader started at a later base, whose tail re-applies the drops, included.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The cascade's case: member m's invited first device, the laptop, makes m's vault; the laptop admits the phone, which
// admits the tablet after since_n, each listed at its admission; and the laptop adds the tablet to the vault's admins.
type testConsentDropWorld struct {
	net      *testConfigNet
	memberId Id
	laptop   testConfigDevice
	phone    testConfigDevice
	tablet   testConfigDevice
	vaultId  Id
	sinceN   uint64
	// the state right after the vault's making, a floor for the test commits' previous epoch and generation
	vaultPin *bridge.AuthPin
	// the state at which the tablet is listed and one of the vault's admins
	listedPin *bridge.AuthPin
}

func newTestConsentDropWorld(t *testing.T) *testConsentDropWorld {
	t.Helper()
	net := newTestConfigNet(t)
	memberId, laptop := net.consentedMember("m")
	world := &testConsentDropWorld{net: net, memberId: memberId, laptop: laptop}
	world.vaultId = testConsentRowsRepo(net, laptop, "consent drops vault", protocol.RepoKind_REPO_KIND_VAULT)
	world.vaultPin = net.log.Pin()
	world.phone, world.tablet = net.device("m phone", memberId), net.device("m tablet", memberId)
	net.admitDevice(laptop, world.phone, 0)
	world.sinceN = net.n + 1
	net.admitDevice(world.phone, world.tablet, 0)
	net.mustPost(laptop, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
		Header: net.header(), RepoId: world.vaultId.Bytes(), SidecarId: world.tablet.sidecarId.Bytes(),
		Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
	})
	world.listedPin = net.log.Pin()
	world.requireListed(t, "before the cascade", world.laptop, world.phone, world.tablet)
	return world
}

// Fails unless the vault's row at the tip lists exactly devices, in their order.
func (self *testConsentDropWorld) requireListed(t *testing.T, label string, devices ...testConfigDevice) {
	t.Helper()
	listed := self.net.log.State().Repo(self.vaultId).GetConsentedSidecarIds()
	want := [][]byte{}
	for _, device := range devices {
		want = append(want, device.sidecarId.Bytes())
	}
	if !slices.EqualFunc(listed, want, bytes.Equal) {
		t.Errorf("%s: the vault lists %x, want %x", label, listed, want)
	}
}

// The laptop's compromise revocation of the phone from since_n, which parks the tablet, the phone having admitted it
// in P (§7.9's cascade).
func (self *testConsentDropWorld) revokePhone(t *testing.T) {
	t.Helper()
	self.net.mustPost(self.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, self.net.compromise(self.phone, self.sinceN))
	if !self.net.log.State().Parked(self.tablet.sidecarId) {
		t.Fatal("the cascade did not park the tablet")
	}
}

// An AdmissionConfirm of the tablet by signer.
func (self *testConsentDropWorld) confirmTablet(signer testConfigDevice) {
	self.net.mustPost(signer, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{
		Header: self.net.header(), SidecarId: self.tablet.sidecarId.Bytes(),
	})
}

// A state whose readers of one repo name more sidecars than AclState's: gkm's members checks stand behind KeyHolders,
// whose readers AclState judges by consented(d, M), which already leaves an unconsented device out, so a test reaches
// the rows' own consent check behind them only through readers that name the device anyway. At answers the same view
// over the state at a pin.
type testConsentDropReadersView struct {
	*ConfigState
	repoId   Id
	extraIds []Id
}

// The state's readers of the repo at a time, with the extra ones, sorted.
func (self testConsentDropReadersView) RepoReadersAt(repoId Id, at time.Time) []Id {
	return self.withExtra(repoId, self.ConfigState.RepoReadersAt(repoId, at))
}

// The state's readers of the repo, with the extra ones, sorted.
func (self testConsentDropReadersView) RepoReaders(repoId Id) []Id {
	return self.withExtra(repoId, self.ConfigState.RepoReaders(repoId))
}

func (self testConsentDropReadersView) withExtra(repoId Id, readerIds []Id) []Id {
	if repoId != self.repoId {
		return readerIds
	}
	readerIds = append(slices.Clone(readerIds), self.extraIds...)
	slices.SortFunc(readerIds, Id.Cmp)
	return slices.Compact(readerIds)
}

// The same view at the state of pin.
func (self testConsentDropReadersView) At(pin *bridge.AuthPin) (GkmAuthView, error) {
	at, err := self.ConfigState.At(pin)
	if err != nil {
		return nil, err
	}
	state, ok := at.(*ConfigState)
	if !ok {
		return nil, errors.New("a pinned state that is no ConfigState")
	}
	return testConsentDropReadersView{ConfigState: state, repoId: self.repoId, extraIds: self.extraIds}, nil
}

// An epoch's tree as an engine hands it to CheckCommit: its leaves and this device's, and nothing of MLS's secrets,
// which the rows' checks never reach.
type testConsentDropGroup struct {
	groupId Id
	epoch   uint64
	self    MlsMember
	roster  []MlsMember
}

func (self *testConsentDropGroup) Exporter(label string, context []byte, length int) ([]byte, error) {
	return nil, errors.New("a test tree exports nothing")
}

func (self *testConsentDropGroup) GroupId() Id {
	return self.groupId
}

func (self *testConsentDropGroup) Epoch() uint64 {
	return self.epoch
}

func (self *testConsentDropGroup) EpochAuthenticator() []byte {
	return nil
}

func (self *testConsentDropGroup) Self() MlsMember {
	return self.self
}

func (self *testConsentDropGroup) Roster() []MlsMember {
	return self.roster
}

func (self *testConsentDropGroup) GroupInfo() ([]byte, error) {
	return nil, errors.New("a test tree has no GroupInfo")
}

func (self *testConsentDropGroup) Commit(args *MlsCommitArgs) (MlsStagedCommit, error) {
	return nil, errors.New("a test tree stages nothing")
}

func (self *testConsentDropGroup) Process(message []byte) (MlsStagedCommit, error) {
	return nil, errors.New("a test tree processes nothing")
}

// A commit staged on a testConsentDropGroup: who committed, what it adds and removes, and its header.
type testConsentDropCommit struct {
	epoch     uint64
	committer MlsMember
	added     []MlsMember
	removed   []MlsMember
	header    []byte
}

func (self *testConsentDropCommit) Exporter(label string, context []byte, length int) ([]byte, error) {
	return nil, errors.New("a test commit exports nothing")
}

func (self *testConsentDropCommit) Message() []byte {
	return nil
}

func (self *testConsentDropCommit) Epoch() uint64 {
	return self.epoch
}

func (self *testConsentDropCommit) EpochAuthenticator() []byte {
	return nil
}

func (self *testConsentDropCommit) Committer() MlsMember {
	return self.committer
}

func (self *testConsentDropCommit) Added() []MlsMember {
	return self.added
}

func (self *testConsentDropCommit) Removed() []MlsMember {
	return self.removed
}

func (self *testConsentDropCommit) AuthenticatedData() []byte {
	return self.header
}

func (self *testConsentDropCommit) Welcome() []byte {
	return nil
}

func (self *testConsentDropCommit) GroupInfo() ([]byte, error) {
	return nil, errors.New("a test commit has no GroupInfo")
}

func (self *testConsentDropCommit) Adopt() (MlsGroup, error) {
	return nil, errors.New("a test commit is never adopted")
}

func (self *testConsentDropCommit) Discard() {
}

// CheckCommit at view of the laptop's commit pinned at pin that adds the tablet's leaf and removes the network owner's
// device's, as the owner's device receives it. That device reads nothing of m's vault, so its Remove has its input at
// any pin, and a receiver its commit removes judges it by its rows alone (gkm_verify_commit.go's R4), so the verdict
// is the committer, Add, Remove and roster rows'.
func (self *testConsentDropWorld) checkTabletAdd(t *testing.T, view GkmAuthView, pin *bridge.AuthPin) *GkmCommitCheck {
	t.Helper()
	state := self.net.log.State()
	now := time.UnixMilli(state.timeMs)
	signer := &gkmTestSigner{sidecarId: self.tablet.sidecarId, privateKey: self.tablet.key}
	credential, err := SignUrMlsCredential(&UrMlsCredentialArgs{
		SidecarId: self.tablet.sidecarId, IdentityPublicKey: self.tablet.publicKey(), MlsSignaturePublicKey: self.tablet.publicKey(),
		NotAfter: now.Add(90 * 24 * time.Hour), AdmissionSha256: state.SidecarRow(self.tablet.sidecarId).GetAdmissionSha256(),
	}, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	header, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: 1, Auth: pin})
	if err != nil {
		t.Fatal(err)
	}
	laptopLeaf := MlsMember{LeafIndex: 0, SidecarId: self.laptop.sidecarId}
	ownerLeaf := MlsMember{LeafIndex: 1, SidecarId: self.net.owner.sidecarId}
	group := &testConsentDropGroup{groupId: testConfigId("consent drops group"), epoch: 1, self: ownerLeaf, roster: []MlsMember{laptopLeaf, ownerLeaf}}
	staged := &testConsentDropCommit{
		epoch:     2,
		committer: laptopLeaf,
		added:     []MlsMember{{LeafIndex: 1, SidecarId: self.tablet.sidecarId, Credential: credential}},
		removed:   []MlsMember{ownerLeaf},
		header:    header,
	}
	check, err := CheckCommit(view, group, staged, &GkmCommitCheckArgs{
		RepoId:         self.vaultId,
		PreviousHeader: &protocol.GkmCommitHeader{Generation: 1, Auth: self.vaultPin},
		Generation: &GkmGeneration{Rotate: &protocol.GenRotate{
			RepoId: self.vaultId.Bytes(), GroupId: group.groupId.Bytes(), Generation: 1, Auth: self.vaultPin,
		}},
		Time: now,
		Now:  now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return check
}

// GkmPendingChanges at view for the laptop's one-leaf tree of the vault.
func (self *testConsentDropWorld) pending(t *testing.T, view GkmAuthView) *GkmPending {
	t.Helper()
	pending, err := GkmPendingChanges(view, &GkmPendingArgs{
		RepoId:            self.vaultId,
		Roster:            []MlsMember{{LeafIndex: 0, SidecarId: self.laptop.sidecarId}},
		SeatCount:         GkmSeatCount,
		ScheduleInterval:  30 * 24 * time.Hour,
		StaleRemoveMargin: 24 * time.Hour,
		Now:               time.UnixMilli(self.net.log.State().timeMs),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

// A reader whose config is the net's log as it stands, and the DROP statement signer signs in the vault pinned at pin:
// what evs's client-side signer check (evsDropSignedBy) judges.
func (self *testConsentDropWorld) dropReader(t *testing.T) *EvsVerifier {
	t.Helper()
	reader := newEvsTestWorld(t).reader(t, evsTestId("consent drops reader"))
	reader.client.args.Config = func() GkmAuthView { return self.net.log.State() }
	return reader.client.verifier
}

func (self *testConsentDropWorld) drop(t *testing.T, signer testConfigDevice, pin *bridge.AuthPin) *EvsStatement {
	t.Helper()
	evsSigner := &evsTestSigner{sidecarId: signer.sidecarId, privateKey: signer.key}
	plan := evsTestPlan(t, evsSigner, "consent drops drop", 1)
	plan.RepoId, plan.Auth = self.vaultId, pin
	built, err := NewEvsStatementBuilder(evsSigner.sign).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	return built.Statement
}

// §22.7's cascade case at the rows: the phone admitted the tablet after since_n, so the compromise revocation of the
// phone parks the tablet and voids the consent its admission gave it, and the vault's list drops both at that entry.
// The network owner's AdmissionConfirm, an admin's, lifts the park and restores all but owner-bound reads (§7.9's
// lift), so the tablet stays out of the list, as AclState judges it: no read, no write and no admin in the vault, its
// owner's other subjects' deposit alone, and no vault scope at the exchange. Neither step moves a holder or the vault's
// holders_shrunk_at past what the revocation's own shrink made. A base whose tail holds all three entries re-applies
// the same drops, and every reader agrees before and after it.
func TestAclADeviceAnAdminUnparksAfterACascadeIsNotListed(t *testing.T) {
	world := newTestConsentDropWorld(t)
	net := world.net
	beforeRevocation := net.n

	world.revokePhone(t)
	world.requireListed(t, "at the compromise revocation", world.laptop)
	revokedState := net.log.State()

	world.confirmTablet(net.owner)
	state := net.log.State()
	if state.Parked(world.tablet.sidecarId) || !gkmRowStanding(state.SidecarRow(world.tablet.sidecarId)) {
		t.Fatal("the admin's confirmation did not lift the tablet's park")
	}
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if acl.Consented(world.tablet.sidecarId) {
		t.Fatal("an admin's confirmation restored the tablet's consent")
	}
	world.requireListed(t, "at the admin's lift", world.laptop)
	for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
		if rights := testConsentRowsRights(t, state, world.tablet.sidecarId, world.vaultId, audience); rights != AclEvsDeposit {
			t.Errorf("the unparked tablet in m's vault at audience %d: %b", audience, rights)
		}
	}
	scopes := []string{testConsentRowsScope(world.vaultId, "r"), testConsentRowsScope(world.vaultId, "rw"), testConsentRowsScope(world.vaultId, "admin")}
	if granted := testConsentRowsExchange(t, state, world.tablet.sidecarId, AclTokenAudienceGkm, scopes...); len(granted) != 0 {
		t.Errorf("the exchange's table grants the unparked tablet %v", granted)
	}
	revokedHolders, err := KeyHolders(revokedState, world.vaultId, time.UnixMilli(state.timeMs))
	if err != nil {
		t.Fatal(err)
	}
	holders, err := KeyHolders(state, world.vaultId, time.UnixMilli(state.timeMs))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(holders, revokedHolders, func(a GkmHolder, b GkmHolder) bool { return gkmHolderCmp(a, b) == 0 }) ||
		holders.Contains(GkmHolderLeaf, world.tablet.sidecarId.Bytes()) {
		t.Errorf("the admin's lift moved the vault's holders: %v, before it %v", holders, revokedHolders)
	}
	if shrunkAt := state.ShrunkAt(world.vaultId); shrunkAt != revokedState.ShrunkAt(world.vaultId) || shrunkAt != revokedState.n {
		t.Errorf("the vault's holders_shrunk_at %d, the revocation at %d", shrunkAt, revokedState.n)
	}
	net.everyReaderAgrees()

	// a base folding through the entry before the revocation re-applies the revocation and the lift in its tail
	listedBefore := slices.Clone(state.Repo(world.vaultId).GetConsentedSidecarIds())
	net.fold(net.owner, beforeRevocation, 2)
	if listed := net.log.State().Repo(world.vaultId).GetConsentedSidecarIds(); !slices.EqualFunc(listed, listedBefore, bytes.Equal) {
		t.Errorf("after the base the vault lists %x, before it %x", listed, listedBefore)
	}
	net.everyReaderAgrees()
}

// The tablet an admin unparked fails every check that reads the vault's list beside its row, where the list kept it
// before QD-1191: gkm's GroupForm signer rule, the members' Add check, which reports it as waiting for consent, a
// commit's joiner row, and evs's drop signer check, locally and at a DROP's own pin. The members' checks stand behind
// KeyHolders, which already leave the tablet out (a plain state refuses its Add for that), so a view whose readers
// name it shows the list itself refusing it. At the state where the list named it, each check takes it.
func TestAclEveryRowsOnlyCheckRefusesADeviceAnAdminUnparked(t *testing.T) {
	world := newTestConsentDropWorld(t)
	net := world.net
	listedState := net.log.State()
	listedView := testConsentDropReadersView{ConfigState: listedState, repoId: world.vaultId, extraIds: []Id{world.tablet.sidecarId}}
	verifier := world.dropReader(t)

	// where the list names it
	if err := GkmFormSignerAllowed(listedState, world.vaultId, world.tablet.sidecarId); err != nil {
		t.Errorf("a GroupForm by the listed tablet: %v", err)
	}
	if pending := world.pending(t, listedState); !slices.Contains(pending.Adds, world.tablet.sidecarId) || len(pending.Unconsented) != 0 {
		t.Errorf("the listed tablet: adds %v, unconsented %v", pending.Adds, pending.Unconsented)
	}
	if check := world.checkTabletAdd(t, listedView, listedState.Pin()); !check.Verdict.Passed() {
		t.Errorf("an Add of the listed tablet: %s (%s)", check.Verdict.Reason, check.Verdict.Detail)
	}
	if !evsDropOwnerDevice(listedState, listedState.Repo(world.vaultId), world.tablet.sidecarId) {
		t.Error("the listed tablet is no owner's device to evs's drop check")
	}
	if err := evsDropSignedBy(verifier, world.drop(t, world.tablet, listedState.Pin()), world.vaultId, false); err != nil {
		t.Errorf("a DROP by the listed tablet: %v", err)
	}

	world.revokePhone(t)
	world.confirmTablet(net.owner)
	state := net.log.State()
	view := testConsentDropReadersView{ConfigState: state, repoId: world.vaultId, extraIds: []Id{world.tablet.sidecarId}}
	if err := GkmFormSignerAllowed(state, world.vaultId, world.tablet.sidecarId); !errors.Is(err, ErrGkmNotWriter) {
		t.Errorf("a GroupForm by the unparked tablet: %v", err)
	}
	if err := GkmFormSignerAllowed(view, world.vaultId, world.tablet.sidecarId); !errors.Is(err, ErrGkmNotWriter) {
		t.Errorf("a GroupForm by the unparked tablet, its reads named: %v", err)
	}
	if pending := world.pending(t, view); slices.Contains(pending.Adds, world.tablet.sidecarId) || !slices.Equal(pending.Unconsented, []Id{world.tablet.sidecarId}) {
		t.Errorf("the unparked tablet, its reads named: adds %v, unconsented %v", pending.Adds, pending.Unconsented)
	}
	if pending := world.pending(t, state); slices.Contains(pending.Adds, world.tablet.sidecarId) {
		t.Errorf("the unparked tablet: adds %v", pending.Adds)
	}
	check := world.checkTabletAdd(t, view, state.Pin())
	if !check.Verdict.Refused || check.Verdict.Reason != GkmRefusalAdd || check.Verdict.Detail != "an unconsented device in an owner-bound repo" {
		t.Errorf("an Add of the unparked tablet, its reads named: %+v", check.Verdict)
	}
	if check := world.checkTabletAdd(t, state, state.Pin()); !check.Verdict.Refused || check.Verdict.Reason != GkmRefusalAdd {
		t.Errorf("an Add of the unparked tablet: %+v", check.Verdict)
	}
	if evsDropOwnerDevice(state, state.Repo(world.vaultId), world.tablet.sidecarId) {
		t.Error("the unparked tablet is an owner's device to evs's drop check")
	}
	if !evsRepoAdmin(state, state.Repo(world.vaultId), world.tablet.sidecarId) {
		t.Fatal("the tablet's admin row did not stand")
	}
	if err := evsDropSignedBy(verifier, world.drop(t, world.tablet, state.Pin()), world.vaultId, false); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a DROP by the unparked tablet, still a standing admin: %v", err)
	}
}

// A device dropped is listed again at the entry from which consented(d, M) holds again, appended after the devices that
// stayed: the laptop's AdmissionConfirm of the tablet an admin unparked, a confirmation by m's consented device
// outside P (§8.5's confirmed clause), after which every rows-only check takes it; and, in a second network, the
// laptop's OwnerConfirm of the parked tablet, which lifts its park as it consents it (§7.9's lift).
func TestAclADeviceConsentedAgainIsListedAgain(t *testing.T) {
	world := newTestConsentDropWorld(t)
	net := world.net
	world.revokePhone(t)
	world.confirmTablet(net.owner)
	world.requireListed(t, "at the admin's lift", world.laptop)
	world.confirmTablet(world.laptop)
	world.requireListed(t, "at the laptop's confirmation", world.laptop, world.tablet)
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !acl.ConsentedFor(world.tablet.sidecarId, world.memberId) {
		t.Fatal("the laptop's confirmation did not consent the tablet")
	}
	if rights := testConsentRowsRights(t, state, world.tablet.sidecarId, world.vaultId, AclTokenAudienceGkm); !rights.Has(AclEvsRead) || !rights.Has(AclEvsWrite) || !rights.Has(AclEvsAdmin) {
		t.Errorf("the confirmed tablet in m's vault: %b", rights)
	}
	if err := GkmFormSignerAllowed(state, world.vaultId, world.tablet.sidecarId); err != nil {
		t.Errorf("a GroupForm by the confirmed tablet: %v", err)
	}
	if pending := world.pending(t, state); !slices.Contains(pending.Adds, world.tablet.sidecarId) || len(pending.Unconsented) != 0 {
		t.Errorf("the confirmed tablet: adds %v, unconsented %v", pending.Adds, pending.Unconsented)
	}
	if check := world.checkTabletAdd(t, state, state.Pin()); !check.Verdict.Passed() {
		t.Errorf("an Add of the confirmed tablet: %s (%s)", check.Verdict.Reason, check.Verdict.Detail)
	}
	if !evsDropOwnerDevice(state, state.Repo(world.vaultId), world.tablet.sidecarId) {
		t.Error("the confirmed tablet is no owner's device to evs's drop check")
	}
	net.everyReaderAgrees()

	parked := newTestConsentDropWorld(t)
	parked.revokePhone(t)
	parked.requireListed(t, "at the second network's revocation", parked.laptop)
	parked.net.mustPost(parked.laptop, bridge.SignedType_SIGNED_OWNER_CONFIRM, parked.net.ownerConfirm(parked.tablet))
	if parked.net.log.State().Parked(parked.tablet.sidecarId) {
		t.Fatal("the laptop's OwnerConfirm left the tablet parked")
	}
	parked.requireListed(t, "at the laptop's OwnerConfirm of the parked tablet", parked.laptop, parked.tablet)
	parked.net.everyReaderAgrees()
}

// A park that alone kept a device unconsented: the laptop's OwnerConfirm of the tablet before the cascade adds nothing
// then, the tablet already listed, but it is a consent outside P, so once the compromise revocation parks the tablet,
// which drops it, the admin's AdmissionConfirm that lifts the park makes it consented again (§8.5's confirmed clause),
// and the list takes it back at that entry, as AclState and every rows-only check do.
func TestAclALiftOfAParkThatAloneKeptADeviceOutListsItAgain(t *testing.T) {
	world := newTestConsentDropWorld(t)
	net := world.net
	net.mustPost(world.laptop, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(world.tablet))
	world.requireListed(t, "at the laptop's OwnerConfirm of the listed tablet", world.laptop, world.phone, world.tablet)
	world.revokePhone(t)
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if acl.Consented(world.tablet.sidecarId) {
		t.Fatal("the parked tablet is consented")
	}
	world.requireListed(t, "at the compromise revocation", world.laptop)
	world.confirmTablet(net.owner)
	state := net.log.State()
	if acl, err = state.Acl(); err != nil {
		t.Fatal(err)
	}
	if !acl.ConsentedFor(world.tablet.sidecarId, world.memberId) {
		t.Fatal("the lift left the tablet the laptop confirmed unconsented")
	}
	world.requireListed(t, "at the admin's lift", world.laptop, world.tablet)
	if err := GkmFormSignerAllowed(state, world.vaultId, world.tablet.sidecarId); err != nil {
		t.Errorf("a GroupForm by the tablet consented again: %v", err)
	}
	if check := world.checkTabletAdd(t, state, state.Pin()); !check.Verdict.Passed() {
		t.Errorf("an Add of the tablet consented again: %s (%s)", check.Verdict.Reason, check.Verdict.Detail)
	}
	net.everyReaderAgrees()
}

// The other endings of consent drop a listed device at their own entry: a revocation for loss drops the revoked device
// alone, and a member's removal, which revokes each of its devices, empties the member's vault's list. A base folding
// through the entries before them re-applies the drops in its tail.
func TestAclARevokedDeviceAndARemovedMembersDevicesLeaveTheList(t *testing.T) {
	net := newTestConfigNet(t)
	memberId, laptop := net.consentedMember("m")
	vaultId := testConsentRowsRepo(net, laptop, "consent drops ending vault", protocol.RepoKind_REPO_KIND_VAULT)
	mailboxId := testConsentRowsRepo(net, laptop, "consent drops ending mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
	phone, tablet := net.device("m ending phone", memberId), net.device("m ending tablet", memberId)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(laptop, tablet, 0)
	beforeEndings := net.n
	listed := func(repoId Id) [][]byte {
		return net.log.State().Repo(repoId).GetConsentedSidecarIds()
	}
	want := func(devices ...testConfigDevice) [][]byte {
		sidecarIds := [][]byte{}
		for _, device := range devices {
			sidecarIds = append(sidecarIds, device.sidecarId.Bytes())
		}
		return sidecarIds
	}
	for _, repoId := range []Id{vaultId, mailboxId} {
		if !slices.EqualFunc(listed(repoId), want(laptop, phone, tablet), bytes.Equal) {
			t.Fatalf("repo %s lists %x", repoId, listed(repoId))
		}
	}

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	for _, repoId := range []Id{vaultId, mailboxId} {
		if !slices.EqualFunc(listed(repoId), want(laptop, tablet), bytes.Equal) {
			t.Errorf("at the phone's revocation repo %s lists %x", repoId, listed(repoId))
		}
	}
	if err := GkmFormSignerAllowed(net.log.State(), vaultId, phone.sidecarId); !errors.Is(err, ErrGkmNotWriter) {
		t.Errorf("a GroupForm by the revoked phone: %v", err)
	}
	net.everyReaderAgrees()

	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: memberId.Bytes()})
	state := net.log.State()
	if state.Member(memberId) != nil {
		t.Fatal("the member stands")
	}
	for _, repoId := range []Id{vaultId, mailboxId} {
		if 0 < len(listed(repoId)) {
			t.Errorf("at the member's removal repo %s lists %x", repoId, listed(repoId))
		}
	}
	for _, device := range []testConfigDevice{laptop, tablet} {
		if evsDropOwnerDevice(state, state.Repo(vaultId), device.sidecarId) {
			t.Errorf("%s of the removed member is an owner's device to evs's drop check", device.sidecarId)
		}
	}
	net.everyReaderAgrees()

	net.fold(net.owner, beforeEndings, 2)
	for _, repoId := range []Id{vaultId, mailboxId} {
		if 0 < len(listed(repoId)) {
			t.Errorf("after the base repo %s lists %x", repoId, listed(repoId))
		}
	}
	net.everyReaderAgrees()
}

// A past act is judged at its own pin, so the list's drops undo none that stood: a GroupForm, a DROP and a commit's
// Add pinned where the list named the tablet verify after its drop, judged by a reader at the newest state, and the
// phone's GroupForm pinned before its revocation does too; the same acts pinned at the newest state are refused.
func TestAclAPastActJudgedAtItsPinVerifiesWhereTheListNamedItsDevice(t *testing.T) {
	world := newTestConsentDropWorld(t)
	net := world.net
	verifier := world.dropReader(t)
	world.revokePhone(t)
	world.confirmTablet(net.owner)
	state := net.log.State()
	pinned := func(device testConfigDevice, pin *bridge.AuthPin) GkmVerdict {
		t.Helper()
		verdict, err := gkmJudgeFormSigner(state, world.vaultId, &gkmVerifiedForm{signerId: device.sidecarId, auth: pin})
		if err != nil {
			t.Fatal(err)
		}
		return verdict
	}

	for _, device := range []testConfigDevice{world.tablet, world.phone} {
		if verdict := pinned(device, world.listedPin); !verdict.Passed() {
			t.Errorf("a GroupForm by %s pinned where the list named it: %s (%s)", device.sidecarId, verdict.Reason, verdict.Detail)
		}
		if verdict := pinned(device, state.Pin()); !verdict.Refused || verdict.Reason != GkmRefusalSigner {
			t.Errorf("a GroupForm by %s pinned at the newest state: %+v", device.sidecarId, verdict)
		}
	}
	if err := evsDropSignedBy(verifier, world.drop(t, world.tablet, world.listedPin), world.vaultId, false); err != nil {
		t.Errorf("a DROP by the tablet pinned where the list named it: %v", err)
	}
	if err := evsDropSignedBy(verifier, world.drop(t, world.tablet, state.Pin()), world.vaultId, false); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a DROP by the tablet pinned at the newest state: %v", err)
	}
	if check := world.checkTabletAdd(t, state, world.listedPin); !check.Verdict.Passed() {
		t.Errorf("an Add of the tablet pinned where the list named it: %s (%s)", check.Verdict.Reason, check.Verdict.Detail)
	}
	view := testConsentDropReadersView{ConfigState: state, repoId: world.vaultId, extraIds: []Id{world.tablet.sidecarId}}
	if check := world.checkTabletAdd(t, view, state.Pin()); !check.Verdict.Refused || check.Verdict.Reason != GkmRefusalAdd {
		t.Errorf("an Add of the tablet pinned at the newest state: %+v", check.Verdict)
	}
}
