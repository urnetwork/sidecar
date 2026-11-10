// EVS1-M2-11's tests: step 5's checks as pure functions over views built from real signed statements and checked
// payloads. Every row of §11.8's refs table and every refusal of §11.20's list the checks make has a case and a twin
// that passes; FS-3's gate cases run as two calls over the states before and after a removal; FS-9's two-way
// directory cases and its bound from 3,584 real sealed names; FS-47's at-the-limit rows through the real QuotaGate;
// and §22.5's path-level CAS races over the newest rule on a real history (newest_test.go's world).

package evsservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A repo, its writers and the state evs holds, for building views.
type checkFixture struct {
	t           *testing.T
	repoId      sidecar.Id
	refId       sidecar.Id
	signerId    sidecar.Id
	clientId    sidecar.Id
	otherId     sidecar.Id
	signingKey  ed25519.PrivateKey
	otherKey    ed25519.PrivateKey
	groupId     sidecar.Id
	commitment  []byte
	now         time.Time
	authLog     *sidecartest.FakeGkmAuthLog
	auth        *sidecartest.FakeGkmAuthView
	firstView   *sidecartest.FakeGkmAuthView
	receiptKeys *ReceiptKeys
	quota       *quotaGateFixture
	networkId   sidecar.Id
	pushSeq     int
}

// A seeded Ed25519 key.
func checkTestKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("check key " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func newCheckFixture(t *testing.T) *checkFixture {
	fixture := &checkFixture{
		t:          t,
		repoId:     testId("check repo"),
		refId:      testId("check ref"),
		signerId:   testId("check signer"),
		clientId:   testId("check client"),
		otherId:    testId("check other"),
		signingKey: checkTestKey("signer"),
		otherKey:   checkTestKey("other"),
		groupId:    testId("check group"),
		commitment: bytes.Repeat([]byte{7}, 32),
		now:        sidecartest.DefaultClockStart(),
		authLog:    sidecartest.NewFakeGkmAuthLog(),
		networkId:  testId("check network"),
	}
	fixture.firstView = fixture.appendState(0, nil)
	keys, err := NewReceiptKeys([]*ReceiptKey{testReceiptKey(1, fixture.now.Add(-48*time.Hour))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.receiptKeys = keys
	fixture.quota = newQuotaGateFixture(t)
	return fixture
}

// Appends the state's next position: the repo with holdersShrunkAt, both sidecars admitted, readers and writers,
// and readerExpiries for readers that stop reading.
func (self *checkFixture) appendState(holdersShrunkAt uint64, readerExpiries map[sidecar.Id]time.Time) *sidecartest.FakeGkmAuthView {
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, HoldersShrunkAt: holdersShrunkAt,
	})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(testId("check member"), self.signerId, self.otherId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	self.auth = self.authLog.Append(&sidecartest.FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			self.signerId: self.signingKey.Public().(ed25519.PublicKey),
			self.otherId:  self.otherKey.Public().(ed25519.PublicKey),
		},
		RepoReaders:        map[sidecar.Id][]sidecar.Id{self.repoId: {self.signerId, self.otherId}},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{self.repoId: {self.signerId, self.otherId}},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{self.repoId: readerExpiries},
	})
	return self.auth
}

// What signs as signerId under key, as Sidecar.Sign does.
func checkTestSign(key ed25519.PrivateKey, signerId sidecar.Id) sidecar.EvsSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body: bytes.Clone(body), SignerId: signerId.Bytes(), Type: uint32(signedType),
			Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, signedType, body)),
		}, nil
	}
}

// A plan for a push on the shared file-mode ref at base 0, under the generation the fixture's record names.
func (self *checkFixture) plan() *sidecar.EvsPushPlan {
	self.pushSeq += 1
	return &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: testId(fmt.Sprintf("check push %d", self.pushSeq)), BaseChain: sidecar.EvsChainStart(self.repoId, self.refId),
		Generation: 1, GroupId: self.groupId, GenerationCommitment: self.commitment, PathEpoch: 1, Auth: self.firstView.Pin(),
		SignerSidecarId: self.signerId, ClientId: self.clientId, TimeMs: self.now.UnixMilli(),
		SealedMetadata: []byte("sealed metadata"),
	}
}

// A file entry version plan's push writes at version, its chain the locators given or one inline record.
func (self *checkFixture) fileEntry(plan *sidecar.EvsPushPlan, version uint64, locators []*protocol.EvsLocator, slotIds ...sidecar.Id) []byte {
	if locators == nil {
		locators = []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}}
	}
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"), Chain: locators,
	}
	for _, slotId := range slotIds {
		entry.SlotIds = append(entry.SlotIds, slotId.Bytes())
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// A directory entry version: a delta adding rows and removing tokens.
func (self *checkFixture) directoryEntry(plan *sidecar.EvsPushPlan, version uint64, rows []*protocol.EvsName, removed [][]byte) []byte {
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY), Names: &protocol.EvsNameTable{Names: rows, RemovedTokens: removed},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// A creation of path at version, a write of it on base, or a removal (version 0).
func (self *checkFixture) change(plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64) *sidecar.EvsPlannedChange {
	change := &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: base}
	if version != 0 {
		change.EntryVersion = self.fileEntry(plan, version, nil)
	}
	return change
}

// gen/1's record, its pin the fixture's first state's and its time now.
func (self *checkFixture) record() *protocol.GenRotate {
	return &protocol.GenRotate{
		GroupId: self.groupId.Bytes(), RepoId: self.repoId.Bytes(), Generation: 1, Commitment: bytes.Clone(self.commitment),
		Auth: self.firstView.Pin(), TimeMs: self.now.UnixMilli(),
	}
}

// Builds plan's push, checks its payload as evs does, and gives the view of a one-part push on an absent head that
// every check passes, rw honored: each changed path absent.
func (self *checkFixture) view(plan *sidecar.EvsPushPlan) *PushView {
	return self.viewSigned(plan, checkTestSign(self.signingKey, self.signerId))
}

// As view, signed by sign.
func (self *checkFixture) viewSigned(plan *sidecar.EvsPushPlan, sign sidecar.EvsSignFunction) *PushView {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(sign).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	payload, err := sidecar.EvsCheckPayload(built.Statement, built.Payload)
	if err != nil {
		self.t.Fatal(err)
	}
	baseChain := sidecar.EvsChainStart(self.repoId, self.refId)
	view := &PushView{
		Stage:          PushStageOnePart,
		RepoId:         self.repoId,
		Statement:      built.Statement,
		Payload:        payload,
		TokenSidecarId: self.signerId,
		TokenClientId:  self.clientId,
		Rights:         sidecar.AclEvsWrite | sidecar.AclEvsRead,
		Repo: &protocol.EvsRepoObject{
			RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
			Format: 1, NetworkId: self.networkId.Bytes(),
		},
		BaseChain:   &baseChain,
		Now:         self.now,
		Auth:        self.auth,
		Generation:  self.record(),
		Paths:       map[string]*PathRead{},
		ReceiptKeys: self.receiptKeys,
		NetworkId:   self.networkId,
		Quota:       self.quota.gate,
		// the fixture's checks are format 1's; format2_gate_test.go holds a format-2 instance's
		InstanceFormat: sidecar.EvsRepoFormat1,
	}
	for _, change := range payload.Changes {
		view.Paths[change.TokenPath.KeyString()] = &PathRead{Newest: &EvsNewest{}}
	}
	return view
}

// A head of kind and mode at version, its chain for the view's base chain at that version.
func checkTestHead(view *PushView, version uint64) *protocol.EvsHead {
	push := view.Statement.Push
	chain := bytes.Repeat([]byte{byte(version)}, 32)
	baseChain := [32]byte(chain)
	view.BaseChain = &baseChain
	return &protocol.EvsHead{
		Version: version, Chain: chain, PushId: testId(fmt.Sprintf("head push %d", version)).Bytes(),
		RefKind: push.GetRefKind(), RefMode: push.GetRefMode(), OwnerSidecarId: push.GetOwnerSidecarId(),
		Auth: push.GetAuth(), GroupId: push.GetGroupId(), Generation: push.GetGeneration(),
		GenerationCommitment: push.GetGenerationCommitment(), PathEpoch: &protocol.EvsPathEpoch{Current: 1},
	}
}

// Holds a refusal to its reason, and the reason's code and fate to the table's.
func requireCheckRefusal(t *testing.T, name string, refusal *EvsCheckRefusal, reason EvsCheckReason) {
	t.Helper()
	if refusal == nil {
		t.Errorf("%s: passed, want %s", name, reason)
		return
	}
	if refusal.Reason != reason {
		t.Errorf("%s: %v, want %s", name, refusal, reason)
		return
	}
	row := evsCheckReasonRows[reason]
	if refusal.Fate != row.fate {
		t.Errorf("%s: fate %d, the table's %d", name, refusal.Fate, row.fate)
	}
	if refusal.Code != row.code && reason != EvsCheckReasonQuota {
		t.Errorf("%s: code %s, the table's %s", name, refusal.Code, row.code)
	}
}

// Holds a check to passing.
func requireCheckPass(t *testing.T, name string, refusal *EvsCheckRefusal) {
	t.Helper()
	if refusal != nil {
		t.Errorf("%s: %v", name, refusal)
	}
}

// Every reason has a name and a code the fixed table holds, in the range its fate needs: a recorded one's below 64, one
// refusing nothing from 128, a final one below 128.
func TestCheckRefusalTableKeepsEachFateInItsRange(t *testing.T) {
	for _, reason := range EvsCheckReasons() {
		row := evsCheckReasonRows[reason]
		if row.name == "" {
			t.Errorf("reason %d has no name", reason)
		}
		if _, ok := sidecar.EvsRefusalStatus(row.code); !ok {
			t.Errorf("%s: code %d has no status", reason, row.code)
		}
		switch row.fate {
		case EvsRefusalRecorded:
			if !sidecar.EvsRefusalRecordable(row.code) {
				t.Errorf("%s: recorded with code %s, which a record cannot hold", reason, row.code)
			}
		case EvsRefusalNothing:
			if !sidecar.EvsRefusalRefusesNothing(row.code) {
				t.Errorf("%s: refusing nothing with code %s", reason, row.code)
			}
		case EvsRefusalFinal:
			if sidecar.EvsRefusalRefusesNothing(row.code) {
				t.Errorf("%s: final with code %s, which refuses nothing", reason, row.code)
			}
		default:
			t.Errorf("%s: no fate", reason)
		}
	}
	if refusal := newEvsCheckRefusal(EvsCheckReason(9999), "unknown"); refusal.Reason != EvsCheckReasonUnchecked || refusal.Fate != EvsRefusalNothing {
		t.Errorf("a reason the table lacks: %v", refusal)
	}
}

// A reply carries the code, the paths, the wait rounded up, needs_format, the quota and a deposit head.
func TestCheckRefusalReply(t *testing.T) {
	refusal := newEvsCheckRefusal(EvsCheckReasonPathConflict, "test")
	refusal.Paths = []sidecar.EvsTokenPath{worldPath("a")}
	refusal.RetryAfter = 1500*time.Microsecond + time.Millisecond
	reply := refusal.Reply(testId("reply push"))
	if reply.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT || len(reply.GetPaths()) != 1 || reply.GetRetryAfterMs() != 3 ||
		!bytes.Equal(reply.GetPushId(), testId("reply push").Bytes()) {
		t.Errorf("reply %v", reply)
	}
	quota := newEvsCheckRefusal(EvsCheckReasonQuota, "test")
	quota.Quota = &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 10, Used: 10, Upgrade: true}
	if reply := quota.Reply(testId("reply push")); reply.GetQuota().GetLimitKey() != "storage" || !reply.GetQuota().GetUpgrade() {
		t.Errorf("quota reply %v", reply)
	}
	format := EvsCheckRefusalOfCodec(fmt.Errorf("%w: a DROP", sidecar.ErrEvsFormatUnsupported))
	if format.Reason != EvsCheckReasonFormatUnsupported || format.NeedsFormat != 2 || !format.Recorded() {
		t.Errorf("format-2 codec error: %v", format)
	}
	if invalid := EvsCheckRefusalOfCodec(sidecar.ErrEvsPushInvalid); invalid.Reason != EvsCheckReasonInvalid || invalid.Recorded() {
		t.Errorf("invalid codec error: %v", invalid)
	}
}

// A path's token path from labels, as the world names them.
func checkTestPath(labels ...string) sidecar.EvsTokenPath {
	return worldPath(labels...)
}

// A plain one-part push creating a file passes every check, and so does it as a part and as a seal under their own
// bounds.
func TestCheckPassesAPlainPush(t *testing.T) {
	fixture := newCheckFixture(t)
	plan := fixture.plan()
	plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
	view := fixture.view(plan)
	requireCheckPass(t, "a one-part push", CheckPush(view))
	part := fixture.view(plan)
	part.Stage = PushStagePart
	requireCheckPass(t, "as a part", CheckPush(part))
	seal := fixture.view(plan)
	seal.Stage = PushStageSeal
	requireCheckPass(t, "as a seal", CheckPush(seal))
	none := fixture.view(plan)
	none.Stage = 0
	requireCheckRefusal(t, "no stage", CheckPush(none), EvsCheckReasonUnchecked)
	requireCheckRefusal(t, "no view", CheckPush(nil), EvsCheckReasonUnchecked)
}

// 5b: the repo, the signer and client, the identity key and signature, and the time bounds, each beside its twin.
func TestCheckSignatureAndTime(t *testing.T) {
	fixture := newCheckFixture(t)
	third := testId("check third")
	thirdKey := checkTestKey("third")
	viewAt := func(timeMs int64, stage PushStage) *PushView {
		plan := fixture.plan()
		plan.TimeMs = timeMs
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
		view := fixture.view(plan)
		view.Stage = stage
		return view
	}
	now := fixture.now.UnixMilli()
	cases := []struct {
		name   string
		view   func() *PushView
		reason EvsCheckReason
		wait   time.Duration
	}{
		{name: "the twin", view: func() *PushView { return viewAt(now, PushStageOnePart) }},
		{name: "another repo's statement", reason: EvsCheckReasonRepoMismatch, view: func() *PushView {
			view := viewAt(now, PushStageOnePart)
			view.RepoId = testId("check other repo")
			return view
		}},
		{name: "signed for another sidecar than the token's", reason: EvsCheckReasonSignerMismatch, view: func() *PushView {
			view := viewAt(now, PushStageOnePart)
			view.TokenSidecarId = fixture.otherId
			return view
		}},
		{name: "another client than the token's", reason: EvsCheckReasonSignerMismatch, view: func() *PushView {
			view := viewAt(now, PushStageOnePart)
			view.TokenClientId = testId("check client 2")
			return view
		}},
		{name: "a signer the state admits no key for", reason: EvsCheckReasonSignature, view: func() *PushView {
			plan := fixture.plan()
			plan.SignerSidecarId = third
			plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
			view := fixture.viewSigned(plan, checkTestSign(thirdKey, third))
			view.TokenSidecarId = third
			return view
		}},
		{name: "signed under another key", reason: EvsCheckReasonSignature, view: func() *PushView {
			plan := fixture.plan()
			plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
			return fixture.viewSigned(plan, checkTestSign(fixture.otherKey, fixture.signerId))
		}},
		{name: "no authorization state", reason: EvsCheckReasonGateUnknown, view: func() *PushView {
			view := viewAt(now, PushStageOnePart)
			view.Auth = nil
			return view
		}},
		{name: "10 min behind", view: func() *PushView { return viewAt(now-(10*time.Minute).Milliseconds(), PushStageOnePart) }},
		{name: "past 10 min behind", reason: EvsCheckReasonTimeStale, view: func() *PushView {
			return viewAt(now-(10*time.Minute).Milliseconds()-1, PushStageOnePart)
		}},
		{name: "10 min ahead", view: func() *PushView { return viewAt(now+(10*time.Minute).Milliseconds(), PushStageOnePart) }},
		{name: "past 10 min ahead", reason: EvsCheckReasonTimeAhead, wait: 250 * time.Millisecond, view: func() *PushView {
			return viewAt(now+(10*time.Minute).Milliseconds()+250, PushStageOnePart)
		}},
		{name: "a part 29 min behind", view: func() *PushView { return viewAt(now-(29*time.Minute).Milliseconds(), PushStagePart) }},
		{name: "a part past 30 min behind", reason: EvsCheckReasonTimeStale, view: func() *PushView {
			return viewAt(now-(30*time.Minute).Milliseconds()-1, PushStagePart)
		}},
		{name: "a seal 30 min ahead", view: func() *PushView { return viewAt(now+(30*time.Minute).Milliseconds(), PushStageSeal) }},
		{name: "a seal past 30 min ahead", reason: EvsCheckReasonTimeAhead, wait: time.Second, view: func() *PushView {
			return viewAt(now+(30*time.Minute).Milliseconds()+1000, PushStageSeal)
		}},
	}
	for _, c := range cases {
		refusal := CheckSignature(c.view())
		if c.reason == 0 {
			requireCheckPass(t, c.name, refusal)
			continue
		}
		requireCheckRefusal(t, c.name, refusal, c.reason)
		if refusal != nil && refusal.RetryAfter != c.wait {
			t.Errorf("%s: waits %s, want %s", c.name, refusal.RetryAfter, c.wait)
		}
	}
}

// 5c's repo/ row: only an active format-1 repo takes a push; keying and deleted are recorded, shredding final.
func TestCheckRepoState(t *testing.T) {
	fixture := newCheckFixture(t)
	plan := fixture.plan()
	plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
	cases := []struct {
		state  protocol.EvsRepoState
		format uint32
		reason EvsCheckReason
	}{
		{state: protocol.EvsRepoState_EVS_REPO_ACTIVE, format: 1},
		{state: protocol.EvsRepoState_EVS_REPO_KEYING, format: 1, reason: EvsCheckReasonRepoKeying},
		{state: protocol.EvsRepoState_EVS_REPO_DELETED, format: 1, reason: EvsCheckReasonRepoDeleted},
		{state: protocol.EvsRepoState_EVS_REPO_SHREDDING, format: 1, reason: EvsCheckReasonRepoShredding},
		{state: protocol.EvsRepoState_EVS_REPO_SHREDDED, format: 1, reason: EvsCheckReasonRepoShredding},
		{state: protocol.EvsRepoState_EVS_REPO_ACTIVE, format: 2, reason: EvsCheckReasonRepoFormat},
	}
	for _, c := range cases {
		view := fixture.view(plan)
		view.Repo.State = c.state
		view.Repo.Format = c.format
		name := fmt.Sprintf("%s format %d", c.state, c.format)
		if c.reason == 0 {
			requireCheckPass(t, name, CheckRefs(view))
		} else {
			requireCheckRefusal(t, name, CheckRefs(view), c.reason)
		}
	}
	view := fixture.view(plan)
	view.Repo = nil
	requireCheckRefusal(t, "no repo/ read", CheckRefs(view), EvsCheckReasonUnchecked)
}

// One refs-table case: a push on a ref, its rights and the head it meets.
type refsCase struct {
	name   string
	reason EvsCheckReason
	// what the plan is: its ref, owner and flags, and the changes it makes
	repoKind protocol.RepoKind
	refKind  protocol.EvsRefKind
	refMode  protocol.EvsRefMode
	owner    *sidecar.Id
	refId    *sidecar.Id
	flags    uint32
	// creation, write, removal
	changeKind string
	signer     *sidecar.Id
	rights     sidecar.AclEvsRights
	// a head the push meets: its kind, mode and owner the push's unless set here
	head        bool
	headMode    protocol.EvsRefMode
	headOwner   *sidecar.Id
	headFlags   uint32
	headDeleted bool
	headBase    bool
	paths       int
}

// The view of one case.
func (self *checkFixture) refsView(c *refsCase) *PushView {
	plan := self.plan()
	plan.RefKind = protocol.EvsRefKind_EVS_REF_SHARED
	if c.refKind != 0 {
		plan.RefKind = c.refKind
	}
	plan.RefMode = protocol.EvsRefMode_EVS_REF_FILE
	if c.refMode != 0 {
		plan.RefMode = c.refMode
	}
	plan.OwnerSidecarId = c.owner
	switch {
	case c.refId != nil:
		plan.RefId = *c.refId
	case plan.RefKind == protocol.EvsRefKind_EVS_REF_ERASURE:
		plan.RefId = sidecar.EvsErasureRefId(self.repoId)
	case plan.RefKind == protocol.EvsRefKind_EVS_REF_DEPOSIT && c.owner != nil:
		plan.RefId = sidecar.EvsDepositRefId(self.repoId, *c.owner)
	}
	plan.Flags = c.flags
	signer, key := self.signerId, self.signingKey
	if c.signer != nil && *c.signer == self.otherId {
		signer, key = self.otherId, self.otherKey
	}
	plan.SignerSidecarId = signer
	if c.head {
		plan.BaseVersion = 3
	}
	path := checkTestPath("a")
	switch c.changeKind {
	case "write":
		plan.Changes = []*sidecar.EvsPlannedChange{self.change(plan, path, 1, 2)}
	case "removal":
		plan.Changes = []*sidecar.EvsPlannedChange{self.change(plan, path, 1, 0)}
	default:
		plan.Changes = []*sidecar.EvsPlannedChange{self.change(plan, path, 0, plan.BaseVersion+1)}
	}
	view := self.viewSigned(plan, checkTestSign(key, signer))
	view.TokenSidecarId = signer
	view.Rights = sidecar.AclEvsWrite | sidecar.AclEvsRead
	if c.rights != 0 {
		view.Rights = c.rights
	}
	if c.repoKind != 0 {
		view.Repo.Kind = c.repoKind
	}
	if c.head {
		view.Head = checkTestHead(view, 3)
		if c.headMode != 0 {
			view.Head.RefMode = uint32(c.headMode)
		}
		if c.headOwner != nil {
			view.Head.OwnerSidecarId = c.headOwner.Bytes()
		}
		view.HeadFlags = c.headFlags
		view.Head.Deleted = c.headDeleted
		if c.headBase {
			view.Head.Base = &protocol.EvsOverlay{RefId: testId("check base ref").Bytes(), Version: 2}
		}
	}
	return view
}

// Every row of §11.8's refs table, and every rule beside it, each refusal with a twin that passes.
func TestCheckRefsTable(t *testing.T) {
	fixture := newCheckFixture(t)
	signer := fixture.signerId
	other := fixture.otherId
	otherDeposit := sidecar.EvsDepositRefId(fixture.repoId, other)
	erasureId := sidecar.EvsErasureRefId(fixture.repoId)
	plainId := testId("check plain ref")
	flag := func(flags ...protocol.EvsPushFlag) uint32 {
		all := uint32(0)
		for _, f := range flags {
			all |= uint32(f)
		}
		return all
	}
	admin := sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	record := protocol.RepoKind_REPO_KIND_RECORD
	owned, deposit, erasure := protocol.EvsRefKind_EVS_REF_OWNED, protocol.EvsRefKind_EVS_REF_DEPOSIT, protocol.EvsRefKind_EVS_REF_ERASURE
	git := protocol.EvsRefMode_EVS_REF_GIT
	cases := []*refsCase{
		// shared
		{name: "shared: rw writes"},
		{name: "shared: read only", reason: EvsCheckReasonScope, rights: sidecar.AclEvsRead},
		{name: "shared: deposit only", reason: EvsCheckReasonScope, rights: sidecar.AclEvsDeposit},
		{name: "shared: FORCE at rw", reason: EvsCheckReasonScope, flags: flag(protocol.EvsPushFlag_EVS_PUSH_FORCE), head: true},
		{name: "shared: FORCE at admin", flags: flag(protocol.EvsPushFlag_EVS_PUSH_FORCE), rights: admin, head: true},
		{name: "shared: DELETE at rw", reason: EvsCheckReasonScope, flags: flag(protocol.EvsPushFlag_EVS_PUSH_DELETE), changeKind: "removal", head: true},
		{name: "shared: DELETE at admin", flags: flag(protocol.EvsPushFlag_EVS_PUSH_DELETE), changeKind: "removal", rights: admin, head: true},
		{name: "shared: with an owner", reason: EvsCheckReasonRefRule, owner: &signer},
		{name: "shared: an IMMUTABLE ref's write", reason: EvsCheckReasonRefRule, refMode: git, head: true,
			headFlags: flag(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE), changeKind: "write"},
		{name: "shared: an IMMUTABLE ref's DELETE", refMode: git, head: true, headFlags: flag(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE),
			flags: flag(protocol.EvsPushFlag_EVS_PUSH_DELETE), changeKind: "removal", rights: admin},
		{name: "shared: a deleted IMMUTABLE ref written again", refMode: git, head: true, headFlags: flag(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE),
			headDeleted: true},
		{name: "shared: IMMUTABLE on a file-mode ref", reason: EvsCheckReasonRefRule, flags: flag(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)},
		{name: "shared: IMMUTABLE on a git-mode ref", refMode: git, flags: flag(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)},
		{name: "shared: BASE", reason: EvsCheckReasonRefRule, flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE), changeKind: "removal", rights: admin},
		{name: "shared: CONSUME", reason: EvsCheckReasonRefRule, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CONSUME), changeKind: "removal"},
		{name: "shared: ERASE", reason: EvsCheckReasonRefRule, flags: flag(protocol.EvsPushFlag_EVS_PUSH_ERASE), rights: admin},
		{name: "shared: CLOSURE below admin", reason: EvsCheckReasonScope, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), changeKind: "write", head: true},
		{name: "shared: CLOSURE at admin", flags: flag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), changeKind: "write", head: true, rights: admin},
		// the head fixes kind, mode and owner, and overlays are git mode's
		{name: "a mode other than the head's", reason: EvsCheckReasonRefRule, head: true, headMode: git},
		{name: "the head's mode", head: true},
		{name: "an owner other than the head's", reason: EvsCheckReasonRefRule, refKind: owned, owner: &signer, head: true, headOwner: &other},
		{name: "the head's owner", refKind: owned, owner: &signer, head: true},
		{name: "an overlay in file mode", reason: EvsCheckReasonRefRule, head: true, headBase: true},
		{name: "an overlay in git mode", refMode: git, head: true, headBase: true},
		// owned, general
		{name: "owned general: its sidecar", refKind: owned, owner: &signer},
		{name: "owned general: another sidecar's", reason: EvsCheckReasonRefRule, refKind: owned, owner: &other},
		{name: "owned general: no owner", reason: EvsCheckReasonRefRule, refKind: owned},
		{name: "owned general: read only", reason: EvsCheckReasonScope, refKind: owned, owner: &signer, rights: sidecar.AclEvsRead},
		{name: "owned general: FORCE by its sidecar at rw", refKind: owned, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_FORCE), head: true},
		{name: "owned general: git mode", refKind: owned, owner: &signer, refMode: git},
		// owned, record-class
		{name: "record stream: a creation", repoKind: record, refKind: owned, owner: &signer},
		{name: "record stream: a write", reason: EvsCheckReasonChangeShape, repoKind: record, refKind: owned, owner: &signer, changeKind: "write", head: true, paths: 1},
		{name: "record stream: a removal", reason: EvsCheckReasonChangeShape, repoKind: record, refKind: owned, owner: &signer, changeKind: "removal", head: true, paths: 1},
		{name: "record stream: git mode", reason: EvsCheckReasonRefRule, repoKind: record, refKind: owned, owner: &signer, refMode: git},
		{name: "record stream: FORCE", reason: EvsCheckReasonRefRule, repoKind: record, refKind: owned, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_FORCE), rights: admin},
		{name: "record stream: another sidecar's creation", reason: EvsCheckReasonRefRule, repoKind: record, refKind: owned, owner: &other},
		{name: "record stream: an admin's BASE of removals", repoKind: record, refKind: owned, owner: &other, flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE), changeKind: "removal", rights: admin, head: true},
		{name: "record stream: a BASE below admin", reason: EvsCheckReasonScope, repoKind: record, refKind: owned, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE), changeKind: "removal", head: true},
		{name: "record stream: a BASE that writes", reason: EvsCheckReasonChangeShape, repoKind: record, refKind: owned, owner: &other, flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE), changeKind: "write", rights: admin, head: true, paths: 1},
		{name: "record stream: an admin's CLOSURE", repoKind: record, refKind: owned, owner: &other, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), changeKind: "write", rights: admin, head: true},
		{name: "record stream: an ERASE", reason: EvsCheckReasonRefRule, repoKind: record, refKind: owned, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_ERASE), rights: admin},
		// deposit
		{name: "deposit: its depositor's creation", refKind: deposit, owner: &signer, rights: sidecar.AclEvsDeposit},
		{name: "deposit: its depositor at rw", refKind: deposit, owner: &signer},
		{name: "deposit: below deposit", reason: EvsCheckReasonScope, refKind: deposit, owner: &signer, rights: sidecar.AclEvsRead},
		{name: "deposit: at another id", reason: EvsCheckReasonRefRule, refKind: deposit, owner: &signer, refId: &plainId, rights: sidecar.AclEvsDeposit},
		{name: "deposit: to another's deposit ref", reason: EvsCheckReasonRefRule, refKind: deposit, owner: &other, rights: sidecar.AclEvsDeposit},
		{name: "deposit: a write", reason: EvsCheckReasonChangeShape, refKind: deposit, owner: &signer, changeKind: "write", head: true, paths: 1},
		{name: "deposit: git mode", reason: EvsCheckReasonRefRule, refKind: deposit, owner: &signer, refMode: git},
		{name: "deposit: DELETE", reason: EvsCheckReasonRefRule, refKind: deposit, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_DELETE), changeKind: "removal", rights: admin},
		{name: "deposit: a reader's CONSUME at rw", refKind: deposit, owner: &other, refId: &otherDeposit, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CONSUME), changeKind: "removal", head: true},
		{name: "deposit: a CONSUME below rw", reason: EvsCheckReasonScope, refKind: deposit, owner: &other, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CONSUME), changeKind: "removal", rights: sidecar.AclEvsDeposit, head: true},
		{name: "deposit: a CONSUME that writes", reason: EvsCheckReasonChangeShape, refKind: deposit, owner: &other, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CONSUME), changeKind: "write", head: true, paths: 1},
		{name: "deposit: PATH_EPOCH", reason: EvsCheckReasonRefRule, refKind: deposit, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)},
		{name: "deposit: CLOSURE", reason: EvsCheckReasonRefRule, refKind: deposit, owner: &signer, flags: flag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), rights: admin},
		// erasure
		{name: "erasure: an admin's creation", refKind: erasure, rights: admin},
		{name: "erasure: below admin", reason: EvsCheckReasonScope, refKind: erasure},
		{name: "erasure: a write", reason: EvsCheckReasonChangeShape, refKind: erasure, rights: admin, changeKind: "write", head: true, paths: 1},
		{name: "erasure: its id as a shared ref", reason: EvsCheckReasonRefRule, refId: &erasureId},
		{name: "erasure: its kind at another id", reason: EvsCheckReasonRefRule, refKind: erasure, refId: &plainId, rights: admin},
		{name: "erasure: with an owner", reason: EvsCheckReasonRefRule, refKind: erasure, owner: &signer, rights: admin},
		{name: "erasure: git mode", reason: EvsCheckReasonRefRule, refKind: erasure, refMode: git, rights: admin},
		{name: "erasure: PATH_EPOCH", reason: EvsCheckReasonRefRule, refKind: erasure, flags: flag(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH), rights: admin},
	}
	for _, c := range cases {
		if c.flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			// a PATH_EPOCH statement names its map, which only parsing needs here
			continue
		}
		view := fixture.refsView(c)
		refusal := CheckRefs(view)
		if c.reason == 0 {
			requireCheckPass(t, c.name, refusal)
			continue
		}
		requireCheckRefusal(t, c.name, refusal, c.reason)
		if refusal != nil && len(refusal.Paths) != c.paths {
			t.Errorf("%s: names %d paths, want %d", c.name, len(refusal.Paths), c.paths)
		}
	}
	for _, c := range cases {
		if c.flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) == 0 {
			continue
		}
		plan := fixture.plan()
		plan.RefKind = c.refKind
		plan.OwnerSidecarId = c.owner
		if c.refKind == erasure {
			plan.RefId = erasureId
		} else {
			plan.RefId = sidecar.EvsDepositRefId(fixture.repoId, *c.owner)
		}
		plan.Flags = c.flags
		plan.PathMapSha256 = bytes.Repeat([]byte{1}, 32)
		plan.MapSourceChain = bytes.Repeat([]byte{2}, 32)
		plan.PathEpoch = 2
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
		view := fixture.view(plan)
		view.Rights = c.rights | sidecar.AclEvsWrite | sidecar.AclEvsDeposit
		requireCheckRefusal(t, c.name, CheckRefs(view), c.reason)
	}
}

// A quota checker answering one refusal to every push, for the rate row QuotaGate never makes on a push.
type checkTestQuota struct {
	refusal *sidecar.QuotaRefusal
}

func (self *checkTestQuota) CheckPush(push *QuotaPush) *sidecar.QuotaRefusal {
	return self.refusal
}

// FS-47's rows at 5c's call into QuotaGate: at the exact storage limit new payload is refused and recorded, 402 where
// a purchase lifts it, 507 at the cluster's cohort limit; a push adding no payload, a BASE, a CONSUME and a config
// push pass; under the limit everything passes; a rate refuses nothing; and no gate refuses 503.
func TestCheckStorageLimitAtTheLimit(t *testing.T) {
	fixture := newCheckFixture(t)
	creation := func() *PushView {
		plan := fixture.plan()
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
		return fixture.view(plan)
	}
	removal := func() *PushView {
		plan := fixture.plan()
		plan.BaseVersion = 3
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 1, 0)}
		view := fixture.view(plan)
		view.Head = checkTestHead(view, 3)
		return view
	}
	requireCheckPass(t, "a creation under the limit", CheckRefs(creation()))

	limit := fixture.quota.atLimit(connect.Id(fixture.networkId))
	refusal := CheckRefs(creation())
	requireCheckRefusal(t, "a creation at the limit", refusal, EvsCheckReasonQuota)
	if refusal != nil && (refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT || *refusal.Quota != *limit) {
		t.Errorf("at the limit: %s with %+v", refusal.Code, refusal.Quota)
	}
	// the network's own refusal comes first, as for an upload: a purchase lifts it (cluster_limit.go)
	full := creation()
	full.ClusterFull = true
	requireCheckRefusal(t, "a creation at the limit and the cohort limit", CheckRefs(full), EvsCheckReasonQuota)
	requireCheckPass(t, "a removal at the limit", CheckRefs(removal()))

	configPush := creation()
	configPush.Repo.Kind = protocol.RepoKind_REPO_KIND_CONFIG
	requireCheckPass(t, "a config push at the limit", CheckRefs(configPush))

	basePlan := fixture.plan()
	basePlan.RefKind = protocol.EvsRefKind_EVS_REF_OWNED
	basePlan.OwnerSidecarId = &fixture.otherId
	basePlan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_BASE)
	basePlan.BaseVersion = 3
	basePlan.Changes = []*sidecar.EvsPlannedChange{fixture.change(basePlan, checkTestPath("a"), 1, 0)}
	base := fixture.view(basePlan)
	base.Repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
	base.Rights = sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	base.Head = checkTestHead(base, 3)
	requireCheckPass(t, "a BASE at the limit", CheckRefs(base))

	consumePlan := fixture.plan()
	consumePlan.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
	consumePlan.OwnerSidecarId = &fixture.otherId
	consumePlan.RefId = sidecar.EvsDepositRefId(fixture.repoId, fixture.otherId)
	consumePlan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME)
	consumePlan.BaseVersion = 3
	consumePlan.Changes = []*sidecar.EvsPlannedChange{fixture.change(consumePlan, checkTestPath("a"), 1, 0)}
	consume := fixture.view(consumePlan)
	consume.Head = checkTestHead(consume, 3)
	requireCheckPass(t, "a CONSUME at the limit", CheckRefs(consume))

	limitOnly := &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1000, Used: 1000}
	fixture.quota.host.Quota.SetStorageRefusal(connect.Id(fixture.networkId), limitOnly)
	fixture.quota.gate.refresh(fixture.quota.ctx)
	if refusal := CheckRefs(creation()); refusal == nil || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT || !refusal.Recorded() {
		t.Errorf("at a limit no purchase lifts: %v", refusal)
	}

	rate := creation()
	rate.Quota = &checkTestQuota{refusal: &sidecar.QuotaRefusal{LimitKey: "evs_closure_uploads_per_s", RetryAfterMs: 1500}}
	rateRefusal := CheckRefs(rate)
	requireCheckRefusal(t, "a rate", rateRefusal, EvsCheckReasonQuotaRate)
	if rateRefusal != nil && rateRefusal.RetryAfter != 1500*time.Millisecond {
		t.Errorf("a rate waits %s", rateRefusal.RetryAfter)
	}
	none := creation()
	none.Quota = nil
	requireCheckRefusal(t, "no quota gate", CheckRefs(none), EvsCheckReasonUnchecked)
}

// 5d, and FS-3's gate cases as pure functions: the pins against the head's, gen/<g>'s record, the push's own pin,
// and the predicate before and after a removal, the same view refused on its rerun once the state shows the removal.
func TestCheckGateFs3(t *testing.T) {
	fixture := newCheckFixture(t)
	viewOf := func(adjust func(plan *sidecar.EvsPushPlan)) *PushView {
		plan := fixture.plan()
		if adjust != nil {
			adjust(plan)
		}
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 1)}
		return fixture.view(plan)
	}
	requireCheckPass(t, "at the state", CheckGate(viewOf(nil)))

	// the fence against the head's pins
	second := fixture.appendState(0, nil)
	headAhead := viewOf(nil)
	headAhead.Head = checkTestHead(headAhead, 3)
	headAhead.Head.Auth = second.Pin()
	requireCheckRefusal(t, "an auth pin below the head's", CheckGate(headAhead), EvsCheckReasonPinBelowHead)
	forked := viewOf(nil)
	forked.Head = checkTestHead(forked, 3)
	forked.Head.Auth = sidecartest.FakeGkmForkPin(1)
	requireCheckRefusal(t, "the head's auth pin under another chain", CheckGate(forked), EvsCheckReasonPinBelowHead)
	generationAhead := viewOf(nil)
	generationAhead.Head = checkTestHead(generationAhead, 3)
	generationAhead.Head.Generation = 2
	requireCheckRefusal(t, "a generation below the head's", CheckGate(generationAhead), EvsCheckReasonPinBelowHead)
	otherCommitment := viewOf(nil)
	otherCommitment.Head = checkTestHead(otherCommitment, 3)
	otherCommitment.Head.GenerationCommitment = bytes.Repeat([]byte{9}, 32)
	requireCheckRefusal(t, "the head's generation under another commitment", CheckGate(otherCommitment), EvsCheckReasonPinBelowHead)
	equalPins := viewOf(nil)
	equalPins.Head = checkTestHead(equalPins, 3)
	requireCheckPass(t, "the head's own pins", CheckGate(equalPins))

	// gen/<g>'s record
	noRecord := viewOf(nil)
	noRecord.Generation = nil
	requireCheckRefusal(t, "no record of the generation", CheckGate(noRecord), EvsCheckReasonGateUnknown)
	otherRepo := viewOf(nil)
	otherRepo.Generation.RepoId = testId("check other repo").Bytes()
	requireCheckRefusal(t, "a record of another repo", CheckGate(otherRepo), EvsCheckReasonPinForked)
	wrongCommitment := viewOf(func(plan *sidecar.EvsPushPlan) { plan.GenerationCommitment = bytes.Repeat([]byte{8}, 32) })
	requireCheckRefusal(t, "a commitment that is not gen/<g>'s", CheckGate(wrongCommitment), EvsCheckReasonPinForked)

	// the push's own pin
	ahead := viewOf(func(plan *sidecar.EvsPushPlan) {
		plan.Auth = &bridge.AuthPin{Version: 9, Chain: bytes.Repeat([]byte{3}, 32)}
	})
	requireCheckRefusal(t, "an auth pin above evs's state", CheckGate(ahead), EvsCheckReasonGateUnknown)
	fork := viewOf(func(plan *sidecar.EvsPushPlan) { plan.Auth = sidecartest.FakeGkmForkPin(1) })
	requireCheckRefusal(t, "an auth pin off evs's chain", CheckGate(fork), EvsCheckReasonPinForked)
	noState := viewOf(nil)
	noState.Auth = nil
	requireCheckRefusal(t, "no state", CheckGate(noState), EvsCheckReasonGateUnknown)

	// FS-3: A validated before the removal passes; the same push rerun after the state shows the removal refuses,
	// recorded; a push under the generation that covers it passes
	beforeRemoval := viewOf(nil)
	beforeRemoval.Auth = second
	requireCheckPass(t, "A before the removal", CheckGate(beforeRemoval))
	removal := fixture.appendState(3, nil)
	rerun := *beforeRemoval
	rerun.Auth = removal
	requireCheckRefusal(t, "A rerun after the removal", CheckGate(&rerun), EvsCheckReasonGateClosed)
	covering := viewOf(func(plan *sidecar.EvsPushPlan) {
		plan.Generation = 2
		plan.GenerationCommitment = bytes.Repeat([]byte{6}, 32)
		plan.Auth = removal.Pin()
	})
	covering.Generation = &protocol.GenRotate{
		GroupId: fixture.groupId.Bytes(), RepoId: fixture.repoId.Bytes(), Generation: 2, Commitment: bytes.Repeat([]byte{6}, 32),
		Auth: removal.Pin(), TimeMs: fixture.now.UnixMilli(),
	}
	covering.Auth = removal
	requireCheckPass(t, "a generation covering the removal", CheckGate(covering))

	// an expiry of a key holder after the generation's time closes the gate once now passes it
	expiry := fixture.now.Add(time.Hour)
	expiring := fixture.appendState(3, map[sidecar.Id]time.Time{fixture.otherId: expiry})
	beforeExpiry := *covering
	beforeExpiry.Auth = expiring
	beforeExpiry.Now = expiry.Add(-time.Millisecond)
	requireCheckPass(t, "before the expiry", CheckGate(&beforeExpiry))
	afterExpiry := beforeExpiry
	afterExpiry.Now = expiry.Add(time.Hour)
	requireCheckRefusal(t, "after the expiry", CheckGate(&afterExpiry), EvsCheckReasonGateClosed)
}

// 5e: the head's current epoch, 1 for a ref with no head; a creation while due or blocked; a PATH_EPOCH push's own
// rules through its seam.
func TestCheckPathEpoch(t *testing.T) {
	fixture := newCheckFixture(t)
	viewOf := func(epoch uint64, create bool, flags uint32) *PushView {
		plan := fixture.plan()
		plan.PathEpoch = epoch
		plan.Flags = flags
		if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			plan.PathMapSha256 = bytes.Repeat([]byte{1}, 32)
			plan.MapSourceChain = bytes.Repeat([]byte{2}, 32)
		}
		plan.BaseVersion = 3
		if create {
			plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("new"), 0, 4)}
		} else {
			plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("old"), 1, 2)}
		}
		return fixture.view(plan)
	}
	absent := viewOf(1, true, 0)
	requireCheckPass(t, "epoch 1 on a ref with no head", CheckPathEpoch(absent))
	requireCheckRefusal(t, "epoch 2 on a ref with no head", CheckPathEpoch(viewOf(2, true, 0)), EvsCheckReasonPathEpoch)

	atEpoch := func(epoch uint64, create bool, pathEpoch *protocol.EvsPathEpoch) *PushView {
		view := viewOf(epoch, create, 0)
		view.Head = checkTestHead(view, 3)
		view.Head.PathEpoch = pathEpoch
		return view
	}
	requireCheckPass(t, "the head's epoch", CheckPathEpoch(atEpoch(3, true, &protocol.EvsPathEpoch{Current: 3})))
	requireCheckRefusal(t, "an older epoch", CheckPathEpoch(atEpoch(2, true, &protocol.EvsPathEpoch{Current: 3})), EvsCheckReasonPathEpoch)
	requireCheckRefusal(t, "a newer epoch", CheckPathEpoch(atEpoch(4, false, &protocol.EvsPathEpoch{Current: 3})), EvsCheckReasonPathEpoch)

	due := &protocol.EvsPathEpoch{Current: 1, DueGeneration: 2, DueBlocksCreation: true}
	dueRefusal := CheckPathEpoch(atEpoch(1, true, due))
	requireCheckRefusal(t, "a creation while due", dueRefusal, EvsCheckReasonPathEpochDue)
	if dueRefusal != nil && (len(dueRefusal.Paths) != 1 || !dueRefusal.Paths[0].Equal(checkTestPath("new"))) {
		t.Errorf("a creation while due names %v", dueRefusal.Paths)
	}
	requireCheckPass(t, "a write while due", CheckPathEpoch(atEpoch(1, false, due)))
	blocked := &protocol.EvsPathEpoch{Current: 1, BlockUntilMs: fixture.now.Add(time.Minute).UnixMilli()}
	requireCheckRefusal(t, "a creation while blocked", CheckPathEpoch(atEpoch(1, true, blocked)), EvsCheckReasonPathEpochDue)
	lapsed := &protocol.EvsPathEpoch{Current: 1, BlockUntilMs: fixture.now.UnixMilli()}
	requireCheckPass(t, "a creation once the block lapsed", CheckPathEpoch(atEpoch(1, true, lapsed)))

	pathEpochPush := viewOf(2, false, uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH))
	requireCheckRefusal(t, "a PATH_EPOCH push with no rules", CheckPathEpoch(pathEpochPush), EvsCheckReasonUnchecked)
	seen := false
	pathEpochPush.PathEpochRules = func(view *PushView) *EvsCheckRefusal {
		seen = true
		return nil
	}
	requireCheckPass(t, "a PATH_EPOCH push its rules pass", CheckPathEpoch(pathEpochPush))
	if !seen {
		t.Error("the PATH_EPOCH rules were not asked")
	}
}

// 5f: TIP and the live lease in git mode; the 63-version window in file mode; C_b; and BASE_STALE carrying the head
// on the caller's own deposit ref.
func TestCheckBase(t *testing.T) {
	fixture := newCheckFixture(t)
	viewOf := func(mode protocol.EvsRefMode, base uint64, headVersion uint64) *PushView {
		plan := fixture.plan()
		plan.RefMode = mode
		plan.BaseVersion = base
		plan.BaseChain = [32]byte(bytes.Repeat([]byte{byte(base)}, 32))
		plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, base+1)}
		view := fixture.view(plan)
		view.Head = checkTestHead(view, headVersion)
		baseChain := plan.BaseChain
		view.BaseChain = &baseChain
		return view
	}
	git, file := protocol.EvsRefMode_EVS_REF_GIT, protocol.EvsRefMode_EVS_REF_FILE
	requireCheckPass(t, "git: TIP", CheckBase(viewOf(git, 5, 5)))
	requireCheckRefusal(t, "git: below TIP", CheckBase(viewOf(git, 4, 5)), EvsCheckReasonNonFastForward)
	wrongChain := viewOf(git, 5, 5)
	otherChain := [32]byte(bytes.Repeat([]byte{0xee}, 32))
	wrongChain.BaseChain = &otherChain
	requireCheckRefusal(t, "git: a chain the history does not hold", CheckBase(wrongChain), EvsCheckReasonNonFastForward)

	leased := viewOf(git, 5, 5)
	leased.Head.Lease = &protocol.EvsSealLease{PushId: testId("check lease push").Bytes(), UntilMs: fixture.now.Add(40 * time.Second).UnixMilli()}
	leaseRefusal := CheckBase(leased)
	requireCheckRefusal(t, "git: another push's live lease", leaseRefusal, EvsCheckReasonLeaseHeld)
	if leaseRefusal != nil && leaseRefusal.RetryAfter != 40*time.Second {
		t.Errorf("a lease waits %s", leaseRefusal.RetryAfter)
	}
	own := viewOf(git, 5, 5)
	own.Head.Lease = &protocol.EvsSealLease{PushId: own.Statement.Push.GetPushId(), UntilMs: fixture.now.Add(time.Minute).UnixMilli()}
	requireCheckPass(t, "git: its own lease", CheckBase(own))
	expired := viewOf(git, 5, 5)
	expired.Head.Lease = &protocol.EvsSealLease{PushId: testId("check lease push").Bytes(), UntilMs: fixture.now.UnixMilli()}
	requireCheckPass(t, "git: an expired lease", CheckBase(expired))

	requireCheckPass(t, "file: v - 63", CheckBase(viewOf(file, 37, 100)))
	requireCheckRefusal(t, "file: v - 64", CheckBase(viewOf(file, 36, 100)), EvsCheckReasonBaseStale)
	requireCheckRefusal(t, "file: past v", CheckBase(viewOf(file, 101, 100)), EvsCheckReasonBaseStale)
	fileChain := viewOf(file, 90, 100)
	fileChain.BaseChain = &otherChain
	requireCheckRefusal(t, "file: a chain the history does not hold", CheckBase(fileChain), EvsCheckReasonBaseStale)
	noChain := viewOf(file, 90, 100)
	noChain.BaseChain = nil
	requireCheckRefusal(t, "file: no chain at the base", CheckBase(noChain), EvsCheckReasonUnchecked)
	if refusal := CheckBase(viewOf(file, 36, 100)); refusal != nil && refusal.DepositHead != nil {
		t.Error("a shared ref's BASE_STALE carries a deposit head")
	}

	// a depositor's own ref: BASE_STALE carries its head as the check read it
	plan := fixture.plan()
	plan.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT
	plan.OwnerSidecarId = &fixture.signerId
	plan.RefId = sidecar.EvsDepositRefId(fixture.repoId, fixture.signerId)
	plan.BaseVersion = 1
	plan.Changes = []*sidecar.EvsPlannedChange{fixture.change(plan, checkTestPath("a"), 0, 2)}
	deposit := fixture.view(plan)
	deposit.Head = checkTestHead(deposit, 130)
	deposit.Head.ConsumedThrough = 120
	depositRefusal := CheckBase(deposit)
	requireCheckRefusal(t, "a deposit 129 versions behind", depositRefusal, EvsCheckReasonBaseStale)
	if head := depositRefusal.DepositHead; head == nil || head.GetVersion() != 130 || !bytes.Equal(head.GetChain(), deposit.Head.GetChain()) ||
		head.GetConsumedThrough() != 120 {
		t.Errorf("the deposit head %v", depositRefusal.DepositHead)
	}
}

// A view of a push at base on the world's history: each change's newest by the world's rule, read at its head.
func (self *checkFixture) worldView(world *evsWorld, base uint64, changes func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange) *PushView {
	plan := self.plan()
	plan.BaseVersion = base
	plan.Changes = changes(plan)
	view := self.view(plan)
	for _, change := range view.Payload.Changes {
		newest, err := world.newest(change.TokenPath)
		if err != nil {
			self.t.Fatal(err)
		}
		read := &PathRead{Newest: newest}
		if newest.Directory {
			read.Listing = world.listing(change.TokenPath)
		}
		view.Paths[change.TokenPath.KeyString()] = read
	}
	return view
}

// §22.5's path-level CAS races on a real history: two pushes based on one version both writing X, the first
// committing, the second refused naming X and passing rebuilt on the new version, while a path-disjoint push from the
// old base lands; a creation after a removal continues the path's versions, max(b, m) + 1 and nothing else; a write
// based on the removed version, a removal of an absent path and a file over a directory conflict.
func TestCheckPathsCasRaces(t *testing.T) {
	fixture := newCheckFixture(t)
	world := newEvsWorld(t)
	x, y, z := worldPath("x"), worldPath("y"), worldPath("z")
	world.push(&worldChange{path: x, version: 1}, &worldChange{path: y, version: 1})
	// P and Q both read version 1; P commits X's version 2
	world.push(&worldChange{path: x, base: 1, version: 2})
	q := fixture.worldView(world, 1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.fileEntry(plan, 2, nil)}}
	})
	refusal := CheckPaths(q)
	requireCheckRefusal(t, "Q writing X after P", refusal, EvsCheckReasonPathConflict)
	if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(x)) {
		t.Errorf("Q's conflict names %v", refusal.Paths)
	}
	rebuilt := fixture.worldView(world, 2, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 2, EntryVersion: fixture.fileEntry(plan, 3, nil)}}
	})
	requireCheckPass(t, "Q rebuilt on X's version 2", CheckPaths(rebuilt))
	disjoint := fixture.worldView(world, 1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: y, BaseEntryVersion: 1, EntryVersion: fixture.fileEntry(plan, 2, nil)}}
	})
	requireCheckPass(t, "a path-disjoint push from the old base", CheckPaths(disjoint))
	both := fixture.worldView(world, 1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.fileEntry(plan, 2, nil)},
			{TokenPath: y, BaseEntryVersion: 0, EntryVersion: fixture.fileEntry(plan, 2, nil)},
		}
	})
	if refusal := CheckPaths(both); refusal == nil || len(refusal.Paths) != 2 {
		t.Errorf("two conflicts name %v", refusal)
	}

	// X removed at version 3, its path version 3; a push based before the removal
	removed := world.push(&worldChange{path: x, base: 2})
	creationAt := func(base uint64, version uint64) *PushView {
		return fixture.worldView(world, base, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
			return []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.fileEntry(plan, version, nil)}}
		})
	}
	requireCheckRefusal(t, "a creation restarting X's versions", CheckPaths(creationAt(2, 3)), EvsCheckReasonVersionRule)
	requireCheckPass(t, "a creation from before the removal at max(b, m) + 1", CheckPaths(creationAt(2, 4)))
	requireCheckPass(t, "a creation after the removal at max(b, m) + 1", CheckPaths(creationAt(removed, 4)))
	requireCheckRefusal(t, "a creation off max(b, m) + 1", CheckPaths(creationAt(removed, 5)), EvsCheckReasonVersionRule)
	stale := fixture.worldView(world, 2, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 2, EntryVersion: fixture.fileEntry(plan, 3, nil)}}
	})
	requireCheckRefusal(t, "a write based on the removed version", CheckPaths(stale), EvsCheckReasonPathConflict)
	absent := fixture.worldView(world, removed, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: z, BaseEntryVersion: 1}}
	})
	requireCheckRefusal(t, "a removal of an absent path", CheckPaths(absent), EvsCheckReasonPathConflict)

	directory := worldPath("d")
	world.push(&worldChange{path: directory, version: removed + 2, directory: true, names: []sidecar.EvsToken{worldToken("n")}})
	overDirectory := fixture.worldView(world, removed+1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: directory, EntryVersion: fixture.fileEntry(plan, removed+2, nil)}}
	})
	requireCheckRefusal(t, "a file over a standing directory", CheckPaths(overDirectory), EvsCheckReasonPathConflict)
	directoryOverFile := fixture.worldView(world, removed+1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: y, BaseEntryVersion: 1, EntryVersion: fixture.directoryEntry(plan, 2, nil, nil)}}
	})
	requireCheckRefusal(t, "a delta to a file", CheckPaths(directoryOverFile), EvsCheckReasonPathConflict)
	unread := fixture.worldView(world, removed+1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: z, EntryVersion: fixture.fileEntry(plan, removed+2, nil)}}
	})
	delete(unread.Paths, z.KeyString())
	requireCheckRefusal(t, "a path step 4 did not read", CheckPaths(unread), EvsCheckReasonUnchecked)
}

// FS-9's two-way check of a removed directory, both orders, each beside its twin: a push removing D after a delta to
// D past its base, and a push creating D/n, with D's delta, after D's removal past its base.
func TestCheckTwoWayDirectory(t *testing.T) {
	fixture := newCheckFixture(t)
	directory := worldPath("d")
	child := worldPath("d", "n")

	// a delta to D after the push's base, then the push removing D
	world := newEvsWorld(t)
	world.push(&worldChange{path: directory, version: 1, directory: true, names: []sidecar.EvsToken{worldToken("a")}})
	deltaAt := world.push(&worldChange{path: directory, base: 1, version: 2, directory: true, names: []sidecar.EvsToken{worldToken("b")}})
	removeAt := func(base uint64) *PushView {
		return fixture.worldView(world, base, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
			return []*sidecar.EvsPlannedChange{{TokenPath: directory, BaseEntryVersion: 1}}
		})
	}
	refusal := CheckPaths(removeAt(deltaAt - 1))
	requireCheckRefusal(t, "D removed by a push based before a delta to it", refusal, EvsCheckReasonDirectoryRemoved)
	if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(directory)) {
		t.Errorf("the removal's conflict names %v", refusal.Paths)
	}
	requireCheckPass(t, "D removed by a push based after the delta", CheckPaths(removeAt(deltaAt)))

	// D's removal first, then a push based before it creating D/n with D's delta
	world = newEvsWorld(t)
	world.push(&worldChange{path: directory, version: 1, directory: true, names: []sidecar.EvsToken{worldToken("a")}})
	removedAt := world.push(&worldChange{path: directory, base: 1})
	rows := []*protocol.EvsName{{Token: child.Last().Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed n")}}
	late := fixture.worldView(world, removedAt-1, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: directory, BaseEntryVersion: 1, EntryVersion: fixture.directoryEntry(plan, 2, rows, nil)},
			{TokenPath: child, EntryVersion: fixture.fileEntry(plan, removedAt, nil)},
		}
	})
	refusal = CheckPaths(late)
	requireCheckRefusal(t, "D/n created by a push based before D's removal", refusal, EvsCheckReasonDirectoryRemoved)
	if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(directory)) {
		t.Errorf("the delta's conflict names %v", refusal.Paths)
	}
	recreated := fixture.worldView(world, removedAt, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: directory, EntryVersion: fixture.directoryEntry(plan, removedAt+1, rows, nil)},
			{TokenPath: child, EntryVersion: fixture.fileEntry(plan, removedAt+1, nil)},
		}
	})
	requireCheckPass(t, "D re-created with D/n after its removal", CheckPaths(recreated))
	twice := fixture.worldView(world, removedAt, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: directory, EntryVersion: fixture.directoryEntry(plan, removedAt, rows, nil)}}
	})
	requireCheckRefusal(t, "D re-created off the versions rule", CheckPaths(twice), EvsCheckReasonVersionRule)
	world.push(&worldChange{path: directory, version: removedAt + 1, directory: true, names: []sidecar.EvsToken{worldToken("c")}})
	again := fixture.worldView(world, removedAt, func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{{TokenPath: directory, EntryVersion: fixture.directoryEntry(plan, removedAt+1, rows, nil)}}
	})
	requireCheckRefusal(t, "D created again while it stands", CheckPaths(again), EvsCheckReasonPathConflict)
}

// FS-9's bound from real sealed names: 3,584 children under 64 B fill a directory's 448 KiB, so a delta adding one
// more is refused, recorded and naming D, while one replacing a child passes, as does a creation at the bound and
// not one past it.
func TestCheckDirectoryBoundFromRealSealedNames(t *testing.T) {
	fixture := newCheckFixture(t)
	repoKey, _, err := sidecar.NewGkmFirstGeneration(fixture.repoId, fixture.groupId, &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, Time: fixture.now,
		HoldersSha256: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestKey, err := sidecar.NewEvsManifestKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	pathKey, err := sidecar.NewEvsPathKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	directoryToken, err := sidecar.EvsPathToken(pathKey, sidecar.EvsRootToken, []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	directory := sidecar.EvsTokenPath{directoryToken}
	sealedRow := func(name string) *protocol.EvsName {
		token, err := sidecar.EvsPathToken(pathKey, directoryToken, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := sidecar.EvsNameSeal(manifestKey, directoryToken, token, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsName{Token: token.Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: sealed}
	}
	rows := []*protocol.EvsName{}
	for i := 0; i < 3584; i += 1 {
		rows = append(rows, sealedRow(fmt.Sprintf("child-%04d.txt", i)))
	}
	if bound := sidecar.EvsNameTableBoundByteCount(&protocol.EvsNameTable{Names: rows}); bound != sidecar.EvsNameTableMaxBoundByteCount {
		t.Fatalf("3,584 real names count %d bytes", bound)
	}
	standing := &PathRead{
		Newest:  &EvsNewest{Exists: true, Directory: true, CommitVersion: 2},
		Listing: &EvsListing{Exists: true, Names: rows, TableThrough: 2},
	}
	deltaView := func(added []*protocol.EvsName, removed [][]byte) *PushView {
		plan := fixture.plan()
		plan.BaseVersion = 2
		plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: directory, BaseEntryVersion: 1, EntryVersion: fixture.directoryEntry(plan, 2, added, removed)}}
		view := fixture.view(plan)
		view.Paths[directory.KeyString()] = standing
		return view
	}
	refusal := CheckPaths(deltaView([]*protocol.EvsName{sealedRow("child-more.txt")}, nil))
	requireCheckRefusal(t, "a child past the bound", refusal, EvsCheckReasonDirectoryFull)
	if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(directory) || !refusal.Recorded()) {
		t.Errorf("the bound's refusal: %v", refusal)
	}
	requireCheckPass(t, "a child replaced at the bound", CheckPaths(deltaView([]*protocol.EvsName{sealedRow("child-new.txt")}, [][]byte{rows[0].GetToken()})))
	requireCheckPass(t, "a delta adding nothing at the bound", CheckPaths(deltaView(nil, nil)))
	noListing := deltaView(nil, nil)
	noListing.Paths[directory.KeyString()] = &PathRead{Newest: standing.Newest}
	requireCheckRefusal(t, "a delta with no listing read", CheckPaths(noListing), EvsCheckReasonUnchecked)

	creationView := func(rows []*protocol.EvsName) *PushView {
		plan := fixture.plan()
		plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: directory, EntryVersion: fixture.directoryEntry(plan, 1, rows, nil)}}
		return fixture.view(plan)
	}
	requireCheckPass(t, "a creation at the bound", CheckPaths(creationView(rows)))
	requireCheckRefusal(t, "a creation past the bound", CheckPaths(creationView(append(append([]*protocol.EvsName{}, rows...), sealedRow("child-more.txt")))), EvsCheckReasonDirectoryFull)
}

// A segment locator naming id at offset 64.
func checkTestSegmentLocator(id [32]byte) *protocol.EvsLocator {
	return &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: id[:], Offset: 104, Length: uint32(sidecar.EvsRecordByteCount(100))}
}

// One new segment of 4 KiB uploaded at uploadTime by uploader, its new-objects item and its receipt.
func (self *checkFixture) upload(label string, uploadTime time.Time, uploader sidecar.Id) ([32]byte, *sidecar.EvsNewObject, *protocol.EvsUploadReceipt) {
	segmentId := sha256.Sum256([]byte("check segment " + label))
	receipt, err := IssueUploadReceipt(self.receiptKeys, self.repoId, segmentId, 4096, uploadTime, uploader, false, self.now)
	if err != nil {
		self.t.Fatal(err)
	}
	object := &sidecar.EvsNewObject{
		Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId[:], PaddedSize: 4096,
		UploadDay: uint32(uploadTime.UnixMilli() / evsUploadDayMs),
	}
	return segmentId, object, receipt
}

// A new slot's id, its new-objects item and its body.
func checkTestSlot(t *testing.T, label string) (sidecar.Id, *sidecar.EvsNewObject, []byte) {
	slotId := testId("check slot " + label)
	body, err := sidecar.EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 1, Wrapped: make([]byte, sidecar.EvsWrappedKeyByteCount)}}})
	if err != nil {
		t.Fatal(err)
	}
	return slotId, &sidecar.EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()}, body
}

// 5h: receipts valid, fresh, for this repo and signer, one per new segment and alike; every segment a version names
// uploaded or named by a version step 4 read, the path's base or a reuse source; every slot introduced or read; a
// part's uploads its receipts and its slots the seal's; the seal's age check and slot rule.
func TestCheckObjectsReceiptsSegmentsAndSlots(t *testing.T) {
	fixture := newCheckFixture(t)
	path := checkTestPath("a")
	segmentId, segmentObject, receipt := fixture.upload("s", fixture.now.Add(-time.Hour), fixture.signerId)
	viewOf := func(locators []*protocol.EvsLocator, objects []*sidecar.EvsNewObject, receipts []*protocol.EvsUploadReceipt, slotBodies [][]byte, slotIds ...sidecar.Id) *PushView {
		plan := fixture.plan()
		plan.NewObjects = objects
		plan.SlotBodies = slotBodies
		plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: path, EntryVersion: fixture.fileEntry(plan, 1, locators, slotIds...)}}
		view := fixture.view(plan)
		view.Receipts = receipts
		return view
	}
	uploaded := func() *PushView {
		return viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(segmentId)}, []*sidecar.EvsNewObject{segmentObject}, []*protocol.EvsUploadReceipt{receipt}, nil)
	}
	requireCheckPass(t, "a new segment with its receipt", CheckObjects(uploaded()))

	missing := viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(segmentId)}, []*sidecar.EvsNewObject{segmentObject}, nil, nil)
	requireCheckRefusal(t, "a new segment with no receipt", CheckObjects(missing), EvsCheckReasonReceiptInvalid)
	_, _, otherSigners := fixture.upload("s", fixture.now.Add(-time.Hour), fixture.otherId)
	other := viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(segmentId)}, []*sidecar.EvsNewObject{segmentObject}, []*protocol.EvsUploadReceipt{otherSigners}, nil)
	requireCheckRefusal(t, "another signer's receipt", CheckObjects(other), EvsCheckReasonReceiptInvalid)
	tampered := proto.Clone(receipt).(*protocol.EvsUploadReceipt)
	tampered.PaddedSize = 8192
	requireCheckRefusal(t, "a receipt whose mac fails", CheckObjects(viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(segmentId)},
		[]*sidecar.EvsNewObject{segmentObject}, []*protocol.EvsUploadReceipt{tampered}, nil)), EvsCheckReasonReceiptInvalid)
	oldId, oldObject, oldReceipt := fixture.upload("old", fixture.now.Add(-24*time.Hour), fixture.signerId)
	requireCheckRefusal(t, "a receipt 24 h old", CheckObjects(viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(oldId)},
		[]*sidecar.EvsNewObject{oldObject}, []*protocol.EvsUploadReceipt{oldReceipt}, nil)), EvsCheckReasonSegmentGone)
	wrongDay := *segmentObject
	wrongDay.UploadDay -= 1
	requireCheckRefusal(t, "a new segment of another day than its receipt", CheckObjects(viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(segmentId)},
		[]*sidecar.EvsNewObject{&wrongDay}, []*protocol.EvsUploadReceipt{receipt}, nil)), EvsCheckReasonReceiptInvalid)
	noKeys := uploaded()
	noKeys.ReceiptKeys = nil
	requireCheckRefusal(t, "no receipt keys", CheckObjects(noKeys), EvsCheckReasonUnchecked)

	// a cited segment: unknown, then the path's base names it, then a reuse source does
	cited := sha256.Sum256([]byte("check cited segment"))
	cite := func() *PushView {
		return viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(cited)}, nil, nil, nil)
	}
	refusal := CheckObjects(cite())
	requireCheckRefusal(t, "a segment neither uploaded nor read", refusal, EvsCheckReasonSegmentUnknown)
	if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(path)) {
		t.Errorf("the unknown segment names %v", refusal.Paths)
	}
	baseEntry := &protocol.EvsEntryVersion{Version: 1, PushId: testId("check base push").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
		Chain: []*protocol.EvsLocator{checkTestSegmentLocator(cited)}, SlotIds: [][]byte{testId("check base slot").Bytes()}}
	baseBytes, err := proto.Marshal(baseEntry)
	if err != nil {
		t.Fatal(err)
	}
	fromBase := cite()
	fromBase.Paths[path.KeyString()] = &PathRead{Newest: &EvsNewest{Exists: true, Version: 1, CommitVersion: 1,
		IndexVersion: &protocol.EvsIndexVersion{CommitVersion: 1, EntryVersion: baseBytes}}}
	requireCheckPass(t, "a segment the path's base names", CheckObjects(fromBase))
	fromWindow := cite()
	fromWindow.Paths[path.KeyString()] = &PathRead{Newest: &EvsNewest{Exists: true, Version: 1, CommitVersion: 1, FromWindow: true,
		Change: &EvsCommittedChange{TokenPath: path, EntryVersion: baseBytes, EntrySha256: make([]byte, 32)}}}
	requireCheckPass(t, "a segment the path's base in the window names", CheckObjects(fromWindow))
	reuse := &sidecar.EvsReuse{RefId: testId("check source ref"), EntryVersion: 1, TokenPath: checkTestPath("source")}
	fromReuse := cite()
	fromReuse.Reuses = []*ReuseRead{{Reuse: reuse, EntryVersion: baseEntry}}
	requireCheckPass(t, "a segment a reuse source names", CheckObjects(fromReuse))
	unread := cite()
	unread.Reuses = []*ReuseRead{{Reuse: reuse}}
	requireCheckRefusal(t, "a reuse source step 4 found no version of", CheckObjects(unread), EvsCheckReasonSegmentUnknown)
	otherVersion := cite()
	otherVersion.Reuses = []*ReuseRead{{Reuse: &sidecar.EvsReuse{RefId: reuse.RefId, EntryVersion: 2, TokenPath: reuse.TokenPath}, EntryVersion: baseEntry}}
	requireCheckRefusal(t, "a reuse source read at another version", CheckObjects(otherVersion), EvsCheckReasonSegmentUnknown)

	// slots: unknown, introduced, read
	slotId, slotObject, slotBody := checkTestSlot(t, "new")
	inline := []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}}
	requireCheckRefusal(t, "a slot neither introduced nor read", CheckObjects(viewOf(inline, nil, nil, nil, slotId)), EvsCheckReasonSlotUnknown)
	requireCheckPass(t, "a slot the push introduces", CheckObjects(viewOf(inline, []*sidecar.EvsNewObject{slotObject}, nil, [][]byte{slotBody}, slotId)))
	readSlot := viewOf(inline, nil, nil, nil, testId("check base slot"))
	readSlot.Paths[path.KeyString()] = fromBase.Paths[path.KeyString()]
	requireCheckPass(t, "a slot the path's base names", CheckObjects(readSlot))

	// a part: its receipts are its uploads, and its slots the seal's
	part := uploaded()
	part.Stage = PushStagePart
	part.Payload.NewObjects = nil
	requireCheckPass(t, "a part's upload by its receipt", CheckObjects(part))
	partNoReceipt := uploaded()
	partNoReceipt.Stage = PushStagePart
	partNoReceipt.Payload.NewObjects = nil
	partNoReceipt.Receipts = nil
	requireCheckRefusal(t, "a part citing an upload it carries no receipt of", CheckObjects(partNoReceipt), EvsCheckReasonSegmentUnknown)
	partSlot := viewOf(inline, nil, nil, nil, slotId)
	partSlot.Stage = PushStagePart
	requireCheckPass(t, "a part's unknown slot, left to the seal", CheckObjects(partSlot))

	// a seal: every part's receipts' age, each new segment's receipt and the slot rule
	seal := uploaded()
	seal.Stage = PushStageSeal
	requireCheckPass(t, "a seal", CheckObjects(seal))
	sealOld := viewOf([]*protocol.EvsLocator{checkTestSegmentLocator(oldId)}, []*sidecar.EvsNewObject{oldObject}, []*protocol.EvsUploadReceipt{oldReceipt}, nil)
	sealOld.Stage = PushStageSeal
	requireCheckRefusal(t, "a seal whose part's receipt aged past 24 h", CheckObjects(sealOld), EvsCheckReasonSegmentGone)
	sealSlot := viewOf(inline, nil, nil, nil, slotId)
	sealSlot.Stage = PushStageSeal
	requireCheckRefusal(t, "a seal naming an unknown slot", CheckObjects(sealSlot), EvsCheckReasonSlotUnknown)
}

// The rules other tasks own refuse 503 until their seams are set, then answer as the seam does: an ERASE's and a
// CLOSURE's at 5h, after every other check passed.
func TestCheckSeamsFailClosed(t *testing.T) {
	fixture := newCheckFixture(t)
	plan := fixture.plan()
	plan.RefKind = protocol.EvsRefKind_EVS_REF_ERASURE
	plan.RefId = sidecar.EvsErasureRefId(fixture.repoId)
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE)
	plan.Erased = []*sidecar.EvsErasedKey{{SlotId: testId("check erased slot"), KeyIndex: 0}}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, EntryVersion: fixture.fileEntry(plan, 1, nil)}}
	erase := fixture.view(plan)
	erase.Rights = sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	requireCheckRefusal(t, "an ERASE with no rules", CheckPush(erase), EvsCheckReasonUnchecked)
	asked := 0
	erase.ErasureRules = func(view *PushView) *EvsCheckRefusal {
		asked += 1
		return nil
	}
	requireCheckPass(t, "an ERASE its rules pass", CheckPush(erase))
	erase.ErasureRules = func(view *PushView) *EvsCheckRefusal {
		asked += 1
		return newEvsCheckRefusal(EvsCheckReasonSlotUnknown, "nothing to erase")
	}
	requireCheckRefusal(t, "an ERASE its rules refuse", CheckPush(erase), EvsCheckReasonSlotUnknown)
	if asked != 2 {
		t.Errorf("the rules were asked %d times", asked)
	}
	below := fixture.view(plan)
	below.ErasureRules = erase.ErasureRules
	requireCheckRefusal(t, "an ERASE below admin never reaches its rules", CheckPush(below), EvsCheckReasonScope)
	if asked != 2 {
		t.Error("the rules ran for a push 5c refused")
	}
}
