package gkmschedule

// FS-103 on T2 and T3 and FS-104 on T2 (KEYS-M2-29; §10.9's delivery checks, D-KEYS-24, D-KEYS-25, FI-28,
// DESIGN-DETAILS 6.6's added rows), on the real subset against gkmservice's engine:
//
//   - FS-104, delivery authority: g claimed at P0; at P1 a member device and agents are admitted with no shrink, and
//     the rotator delivers RK_g LATE to them at P1. Every member and the oracle (sidecartest.DeliveryOracle, which
//     judges from the log alone and shares no code with the members' checks) judge each valid, and nothing rotates.
//     A delivery pinned at P0, before its recipient's admission, is judged invalid by all; replayed past a colluding
//     gkm to members, as the winner of a late delivery's path or among the recipient's own, each holds g as poisoned
//     and alarms naming the signer, and a writer among them rotates REMOVE past it. Then, each judged by members and
//     the oracle alike and offered to the honest gkm: a pin off the chain (a fork as well), a signer revoked before
//     its pin, a recipient revoked before its pin, a STAGED delivery carrying an auth, a STAGED one by another than
//     the claim's signer, one by a read_only device. After its recipient's revocation the P1 delivery still judges
//     valid; a member whose log ends below a delivery's pin waits; one whose previous base passed the pin judges
//     nothing of it while its recipient still opens it; and one signed just after a claim by a holder whose clock
//     trails the rotator's by 50 s is valid.
//   - KEYS-M2-29's mutants: three mutants of the members' check each disagree with the oracle on FS-104's shapes.
//   - 6.6's row: a hostile leaf's commit over a tree that holds a dropped leaf is refused by every member and by
//     the oracle's roster check, and the generation it carried is held as poisoned.
//   - FS-103, late delivery identity: an agent replaces its ReaderKey every 6 days for 42 days without fetching g,
//     and drops each private key 30 days past its not_after; with no writer online it asks for g under its current
//     key, gkm hints the writers at once and, the ask 15 minutes old, a reader-only holder, which delivers LATE at
//     the current key's path while the first key's object stays; the agent opens it; neither delivery opens under
//     the other's key. Two late deliverers held on one target: one 201, the other's 412 carrying the winner, which it
//     judges. A deliverer killed before its PUT and one whose answer is lost each retry to one valid object. gkm
//     refuses a LATE delivery to a key it does not serve and of a generation that is not the newest, and a STAGED
//     one after the claim.
//   - FS-103's retention: the sweep collects an older key's object 30 days after the newer one's, and not before.
//   - FS-103's rebind: a same-generation RecoveryRebind's wraps land at the new binding's b8 before the old binding's
//     go; a kill at the first deletion leaves both, the resumed rebind deletes only the old, and the new code opens
//     the generation.
//
// What a schedule here does not run is in KEYS-M2-29's record.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One position as the facts FS-104's oracle reads: the rows, each repo's kind and readers with the time each stops
// reading, and the repos a tag atom's grants read. Built from what Advance appends, never through a view's methods.
func (self *FsKeysWorld) oracleState(pin *bridge.AuthPin, rows *bridge.ProjectionRows, repoReaders map[sidecar.Id][]sidecar.Id, expiries map[sidecar.Id]time.Time, atomRepos map[sidecar.Id][]sidecar.Id) *sidecartest.DeliveryOracleState {
	state := &sidecartest.DeliveryOracleState{
		Pin:       pin,
		Repos:     map[sidecartest.DeliveryOracleId]*sidecartest.DeliveryOracleRepo{},
		AtomRepos: map[sidecartest.DeliveryOracleId][]sidecartest.DeliveryOracleId{},
	}
	for _, row := range rows.GetSidecars() {
		state.Sidecars = append(state.Sidecars, proto.Clone(row).(*bridge.SidecarRow))
	}
	for _, row := range rows.GetMembers() {
		state.Members = append(state.Members, proto.Clone(row).(*bridge.MemberRow))
	}
	for _, row := range rows.GetDelegations() {
		state.Delegations = append(state.Delegations, proto.Clone(row).(*bridge.DelegationRow))
	}
	for repoId, readerIds := range repoReaders {
		repo := &sidecartest.DeliveryOracleRepo{Kind: self.Kind, Readers: map[sidecartest.DeliveryOracleId]time.Time{}}
		if repoId == self.ConfigRepoId {
			repo.Kind = protocol.RepoKind_REPO_KIND_CONFIG
		}
		for _, readerId := range readerIds {
			until := time.Time{}
			if repoId == self.RepoId {
				until = expiries[readerId]
			}
			repo.Readers[sidecartest.DeliveryOracleId(readerId)] = until
		}
		state.Repos[sidecartest.DeliveryOracleId(repoId)] = repo
	}
	for atom, repoIds := range atomRepos {
		for _, repoId := range repoIds {
			state.AtomRepos[sidecartest.DeliveryOracleId(atom)] = append(state.AtomRepos[sidecartest.DeliveryOracleId(atom)], sidecartest.DeliveryOracleId(repoId))
		}
	}
	return state
}

// FS-104's oracle over every position the world's log holds now.
func (self *FsKeysWorld) Oracle() *sidecartest.DeliveryOracle {
	self.t.Helper()
	oracle := sidecartest.NewDeliveryOracle(nil)
	for _, state := range self.oracleStates {
		if err := oracle.Append(state); err != nil {
			self.t.Fatal(err)
		}
	}
	return oracle
}

// Moves every device's previous base to version: a pin below it is retained by none (§7.9's retain row).
func (self *FsKeysWorld) Retain(version uint64) {
	self.Log.Retain(version)
	self.previousBase = version
}

// One delivery: the wrap/ key it lies at, or would, and its Signed bytes.
type FsKeysDelivery struct {
	Key  string
	Body []byte
}

// The last two segments of the delivery's key: its recipient and k8.
func (self *FsKeysDelivery) pathEnd() (recipient string, k8 string) {
	parts := strings.Split(self.Key, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

// The delivery's body, whatever signed it.
func (self *FsKeysDelivery) delivery(t FsKeysT) *protocol.KeyDelivery {
	t.Helper()
	signed := &bridge.Signed{}
	wrap := &protocol.ReaderWrap{}
	if err := proto.Unmarshal(self.Body, signed); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(signed.GetBody(), wrap); err != nil {
		t.Fatal(err)
	}
	return wrap.GetWrap()
}

// The sidecar that signed the delivery.
func (self *FsKeysDelivery) signerId(t FsKeysT) []byte {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(self.Body, signed); err != nil {
		t.Fatal(err)
	}
	return signed.GetSignerId()
}

// The ReaderWraps gkm holds of the group's generation to recipient, by key.
func (self *FsKeysWorld) Deliveries(generation uint64, recipient *FsKeysDevice) []*FsKeysDelivery {
	self.t.Helper()
	deliveries := []*FsKeysDelivery{}
	segment := "/" + fsKeysRecipient(recipient.SidecarId()) + "/"
	for key, body := range self.objects(gkmservice.GkmWrapGenerationPrefix(self.GroupId, generation)) {
		if strings.Contains(key, segment) {
			deliveries = append(deliveries, &FsKeysDelivery{Key: key, Body: body})
		}
	}
	slices.SortFunc(deliveries, func(a *FsKeysDelivery, b *FsKeysDelivery) int { return strings.Compare(a.Key, b.Key) })
	return deliveries
}

// The X-Wing key of the ReaderKey a device published last.
func (self *FsKeysDevice) readerPublicKey() []byte {
	self.world.t.Helper()
	readerKey := &protocol.ReaderKey{}
	if err := proto.Unmarshal(self.ReaderKey.GetBody(), readerKey); err != nil {
		self.world.t.Fatal(err)
	}
	return readerKey.GetXwingPublicKey()
}

// A ReaderWrap of generation that signer seals to recipient's current ReaderKey and signs, past every check its
// client makes, as a hostile holder would: STAGED with a nil pin, else LATE at pin and at. Nothing is uploaded.
func (self *FsKeysWorld) SealDelivery(signer *FsKeysDevice, generation uint64, recipient *FsKeysDevice, pin *bridge.AuthPin, at time.Time) *FsKeysDelivery {
	self.t.Helper()
	key, err := signer.Client.RepoKey(self.Ctx, self.RepoId, generation)
	if err != nil {
		self.t.Fatalf("%s's generation %d: %v", signer.Label, generation, err)
	}
	args := &sidecar.GkmDeliveryArgs{
		GroupId: self.GroupId, Type: sidecar.GkmWrapTypeReader, Recipient: recipient.SidecarId().Bytes(),
		RecipientPublicKey: recipient.readerPublicKey(), Kind: sidecar.GkmDeliveryStaged,
	}
	if pin != nil {
		args.Kind = sidecar.GkmDeliveryLate
		args.Auth = pin
		args.Time = at
	}
	body, err := sidecar.SealGkmDelivery(key, args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(body, sidecar.GkmWrapTypeReader, signer.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.deliveryOf(body, signed)
}

// A delivery's key and bytes from its body and Signed.
func (self *FsKeysWorld) deliveryOf(body *protocol.KeyDelivery, signed *bridge.Signed) *FsKeysDelivery {
	self.t.Helper()
	path, err := sidecar.GkmWrapPath(self.GroupId, body.GetGeneration(), body.GetCommitment(), sidecar.GkmWrapTypeReader, body.GetRecipient(), body.GetRecipientKeySha256())
	if err != nil {
		self.t.Fatal(err)
	}
	return &FsKeysDelivery{Key: path, Body: self.marshal(signed)}
}

// SealDelivery's LATE delivery with its kind rewritten to STAGED, its pin and time kept, signed by signer: a body
// no honest client can sign.
func (self *FsKeysWorld) SealStagedWithAuth(signer *FsKeysDevice, generation uint64, recipient *FsKeysDevice, pin *bridge.AuthPin, at time.Time) *FsKeysDelivery {
	self.t.Helper()
	body := self.SealDelivery(signer, generation, recipient, pin, at).delivery(self.t)
	body.DeliveryKind = uint32(sidecar.GkmDeliveryStaged)
	wrapBytes := self.marshal(&protocol.ReaderWrap{Wrap: body})
	signed, err := signer.signer.Sign("reader-wrap", bridge.SignedType_SIGNED_READER_WRAP, wrapBytes, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.deliveryOf(body, signed)
}

// Offers one delivery to gkm as sender: gkm's answer for it, 201 where it stored it.
func (self *FsKeysWorld) UploadDelivery(sender *FsKeysDevice, delivery *FsKeysDelivery) int {
	self.t.Helper()
	body := delivery.delivery(self.t)
	reply, err := sender.Api.UploadWraps(self.Ctx, self.RepoId, self.GroupId, body.GetGeneration(), body.GetCommitment(), &protocol.GkmWrapBatch{Deliveries: [][]byte{delivery.Body}})
	if err != nil {
		if gkmError, ok := sidecar.GkmErrorOf(err); ok {
			return gkmError.Status
		}
		self.t.Fatalf("the upload of a delivery: %v", err)
	}
	if len(reply.GetResults()) != 1 {
		self.t.Fatalf("gkm answered %d results for one delivery", len(reply.GetResults()))
	}
	return int(reply.GetResults()[0].GetStatus())
}

// gen/<generation>'s stored bytes.
func (self *FsKeysWorld) generationBytes(generation uint64) []byte {
	self.t.Helper()
	body, err := self.readObject(self.cluster(), gkmservice.GkmGenerationKey(self.GroupId, generation))
	if err != nil {
		self.t.Fatalf("gen/%d: %v", generation, err)
	}
	return body
}

// What device's own check answers of one delivery, at device's state and the world's clock, as the oracle's kinds:
// the members' CheckDelivery, with a delivery its parse refuses, a malformed one or one whose signature does not
// verify, counted invalid as the flows count it.
func (self *FsKeysWorld) MemberJudges(device *FsKeysDevice, delivery *FsKeysDelivery) (kind sidecartest.DeliveryOracleVerdictKind, fork bool) {
	self.t.Helper()
	return self.memberJudges(device, delivery, fsKeysCheckExact)
}

// A member's delivery check with one clause broken on purpose, so a schedule proves the oracle sees the clause.
type fsKeysCheckMutant int

const (
	// the members' check as it is
	fsKeysCheckExact fsKeysCheckMutant = iota
	// judges a delivery at the judge's newest state, not at the delivery's own pin
	fsKeysCheckMutantNewestState
	// never holds a delivery to the path it was served at
	fsKeysCheckMutantNoPath
	// takes every signer's row as standing and not read_only
	fsKeysCheckMutantStanding
)

// A state as a mutant of the members' check reads it.
type fsKeysMutantView struct {
	sidecar.GkmAuthView
	mutant fsKeysCheckMutant
}

func (self *fsKeysMutantView) At(pin *bridge.AuthPin) (sidecar.GkmAuthView, error) {
	if self.mutant == fsKeysCheckMutantNewestState && self.GkmAuthView.OnChain(pin) {
		return self, nil
	}
	at, err := self.GkmAuthView.At(pin)
	if err != nil {
		return nil, err
	}
	return &fsKeysMutantView{GkmAuthView: at, mutant: self.mutant}, nil
}

func (self *fsKeysMutantView) SidecarRow(sidecarId sidecar.Id) *bridge.SidecarRow {
	row := self.GkmAuthView.SidecarRow(sidecarId)
	if self.mutant != fsKeysCheckMutantStanding || row == nil {
		return row
	}
	standing := proto.Clone(row).(*bridge.SidecarRow)
	standing.RevokedAt = 0
	standing.ParkedAt = 0
	standing.Capabilities &^= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	return standing
}

// MemberJudges under a mutant of the check.
func (self *FsKeysWorld) memberJudges(device *FsKeysDevice, delivery *FsKeysDelivery, mutant fsKeysCheckMutant) (kind sidecartest.DeliveryOracleVerdictKind, fork bool) {
	self.t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(delivery.Body, signed); err != nil {
		self.t.Fatal(err)
	}
	generationNumber := delivery.delivery(self.t).GetGeneration()
	generation, err := sidecar.ParseGenRotate(self.generationBytes(generationNumber), self.GroupId, generationNumber, sidecar.GkmIdentityKeys(device.state))
	if err != nil {
		self.t.Fatalf("%s's read of gen/%d: %v", device.Label, generationNumber, err)
	}
	parsed, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(device.state))
	if err != nil {
		return sidecartest.DeliveryOracleInvalid, false
	}
	var view sidecar.GkmAuthView = device.state
	path := delivery.Key
	if mutant != fsKeysCheckExact {
		view = &fsKeysMutantView{GkmAuthView: device.state, mutant: mutant}
	}
	if mutant == fsKeysCheckMutantNoPath {
		path = ""
	}
	verdict, err := sidecar.CheckDelivery(view, &sidecar.GkmDeliveryCheckArgs{
		RepoId: self.RepoId, Delivery: parsed, Generation: generation, Path: path, Now: self.Clock.Now(),
	})
	switch {
	case errors.Is(err, sidecar.ErrGkmAuthAhead) || errors.Is(err, sidecar.ErrGkmTimeAhead):
		return sidecartest.DeliveryOracleWaits, false
	case err != nil:
		self.t.Fatalf("%s's check of a delivery: %v", device.Label, err)
	case verdict.NotJudged:
		return sidecartest.DeliveryOracleNotJudged, false
	case verdict.Refused:
		return sidecartest.DeliveryOracleInvalid, verdict.Fork
	}
	return sidecartest.DeliveryOracleValid, false
}

// What the oracle answers of one delivery for a judge whose log ends where device's does.
func (self *FsKeysWorld) OracleJudges(oracle *sidecartest.DeliveryOracle, device *FsKeysDevice, delivery *FsKeysDelivery) sidecartest.DeliveryOracleVerdict {
	self.t.Helper()
	recipient, k8 := delivery.pathEnd()
	return oracle.Judge(&sidecartest.DeliveryOracleCase{
		RepoId:        sidecartest.DeliveryOracleId(self.RepoId),
		Delivery:      delivery.Body,
		Generation:    self.generationBytes(delivery.delivery(self.t).GetGeneration()),
		PathRecipient: recipient,
		PathKey8:      k8,
		Tip:           device.state.Pin().GetVersion(),
		PreviousBase:  self.previousBase,
		Now:           self.Clock.Now(),
	})
}

// Holds each device's verdict of one delivery to the oracle's and to want, a fork to fork (FI-28: every verifier,
// the oracle among them, judges each delivery at its own state to one verdict).
func (self *FsKeysWorld) Judged(label string, delivery *FsKeysDelivery, want sidecartest.DeliveryOracleVerdictKind, fork bool, devices ...*FsKeysDevice) {
	self.t.Helper()
	oracle := self.Oracle()
	for _, device := range devices {
		oracleVerdict := self.OracleJudges(oracle, device, delivery)
		memberKind, memberFork := self.MemberJudges(device, delivery)
		if oracleVerdict.Kind != want || oracleVerdict.Fork != fork {
			self.t.Errorf("%s: the oracle, for %s: %s (fork %v), want %s (fork %v)", label, device.Label, oracleVerdict, oracleVerdict.Fork, want, fork)
		}
		if memberKind != oracleVerdict.Kind || memberFork != oracleVerdict.Fork {
			self.t.Errorf("%s: %s judges %s (fork %v), the oracle %s (fork %v)", label, device.Label, memberKind, memberFork, oracleVerdict, oracleVerdict.Fork)
		}
	}
}

// Holds the oracle's key holders to each generation's rotator's: holders_sha256 of gen/1 to the newest equals the
// oracle's at that generation's pin and time.
func (self *FsKeysWorld) OracleHoldersAgree() {
	self.t.Helper()
	oracle := self.Oracle()
	for generation := uint64(1); generation <= uint64(self.GenerationCount()); generation += 1 {
		rotate := self.Generation(generation).Rotate
		holdersSha256, ok := oracle.HoldersSha256(sidecartest.DeliveryOracleId(self.RepoId), rotate.GetAuth(), time.UnixMilli(rotate.GetTimeMs()))
		if !ok || !bytes.Equal(holdersSha256, rotate.GetHoldersSha256()) {
			self.t.Errorf("the oracle's key holders at gen/%d's pin are not the rotator's", generation)
		}
	}
}

// Whether device raised a refusal naming signer about generation.
func (self *FsKeysDevice) refusedDelivery(signer *FsKeysDevice, generation uint64) bool {
	for _, alarm := range self.Alarms {
		if alarm.Kind == sidecar.GkmAlarmRefused && alarm.SidecarId == signer.SidecarId() && alarm.Generation == generation {
			return true
		}
	}
	return false
}

// Whether a request uploads deliveries: POST /gkm/groups/<id>/wraps/<g>/<c8>.
func fsKeysWrapUpload(request *http.Request) bool {
	parts := strings.Split(request.URL.Path, "/")
	return request.Method == http.MethodPost && len(parts) == 7 && parts[2] == "groups" && parts[4] == "wraps"
}

// Whether a request reads a caller's deliveries: GET /gkm/groups/<id>/wraps/<g>.
func fsKeysWrapRead(request *http.Request) bool {
	parts := strings.Split(request.URL.Path, "/")
	return request.Method == http.MethodGet && len(parts) == 6 && parts[2] == "groups" && parts[4] == "wraps"
}

// A colluding gkm in front of device: every upload of a delivery answers 412 with winner as the object that holds
// its path, and every read of its own deliveries of winner's generation serves winner among them.
func (self *FsKeysWorld) Collude(device *FsKeysDevice, winner *FsKeysDelivery) {
	self.t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(winner.Body, signed); err != nil {
		self.t.Fatal(err)
	}
	device.Transport.Respond = func(request *http.Request) *http.Response {
		switch {
		case fsKeysWrapUpload(request):
			return FsKeysAnswer(&protocol.GkmWrapBatchReply{Results: []*protocol.GkmWrapResult{{Status: http.StatusPreconditionFailed, Winner: winner.Body}}})
		case fsKeysWrapRead(request):
			return FsKeysAnswer(&protocol.GkmWrapsReply{Wraps: []*bridge.Signed{signed}})
		}
		return nil
	}
}

// The devices' alarms so far, counted.
func fsKeysAlarmCount(devices ...*FsKeysDevice) int {
	count := 0
	for _, device := range devices {
		count += len(device.Alarms)
	}
	return count
}

// FS-104: see the file header.
func FsKeysScheduleDeliveryAuthority(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	m := world.AddMember("m", false)
	w := world.AddMember("w", true)
	x := world.AddMember("x", false)
	behind := world.AddMember("l", false)
	y := world.AddAgent("y")
	world.Grant(true, a, m, x)
	world.Grant(false, w, behind, y)
	world.Admin(a)
	p0 := world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	repoId := world.RepoId

	// P1: a member device and two agents are admitted, no shrink and no new generation; the leaf whose log trails
	// takes nothing from here on
	behind.Offline = true
	b := world.AddMember("b", false)
	c := world.AddAgent("c")
	c2 := world.AddAgent("c2")
	world.Grant(false, b, c, c2)
	p1 := world.Advance()
	world.Publish()
	for _, recipient := range []*FsKeysDevice{b, c} {
		if err := a.Client.DeliverLate(world.Ctx, repoId, fsKeysRecipient(recipient.SidecarId())); err != nil {
			t.Fatalf("the late delivery to %s: %v", recipient.Label, err)
		}
	}
	toBs := world.Deliveries(1, b)
	toCs := world.Deliveries(1, c)
	if len(toBs) != 1 || len(toCs) != 1 {
		t.Fatalf("gkm holds %d deliveries to b and %d to c", len(toBs), len(toCs))
	}
	toB, toC := toBs[0], toCs[0]
	if pin := toC.delivery(t).GetAuth(); pin.GetVersion() != p1.Pin().GetVersion() {
		t.Fatalf("the late delivery is pinned at %d, not P1", pin.GetVersion())
	}
	judges := []*FsKeysDevice{a, m, w, x, b, c, y}
	world.Judged("the late delivery to the new member device", toB, sidecartest.DeliveryOracleValid, false, judges...)
	world.Judged("the late delivery to the new agent", toC, sidecartest.DeliveryOracleValid, false, judges...)
	world.OracleHoldersAgree()
	for _, recipient := range []*FsKeysDevice{b, c} {
		world.Again(recipient.Label+"'s read", func() error {
			key, err := recipient.Client.CurrentRepoKey(world.Ctx, repoId)
			if err == nil && key.Generation() != 1 {
				t.Errorf("%s reads generation %d", recipient.Label, key.Generation())
			}
			return err
		})
	}
	if world.GenerationCount() != 1 || fsKeysAlarmCount(world.Devices...) != 0 {
		t.Fatalf("valid late deliveries rotated or alarmed: %d generations, %d alarms", world.GenerationCount(), fsKeysAlarmCount(world.Devices...))
	}
	// a member whose log ends at P0 waits for a delivery pinned at P1
	world.Judged("a pin above the judge's tip", toC, sidecartest.DeliveryOracleWaits, false, behind)

	// signed at P0, before its recipient's admission: invalid for every verifier
	beforeAdmission := world.SealDelivery(a, 1, c2, p0.Pin(), world.Clock.Now())
	world.Judged("a delivery pinned before its recipient's admission", beforeAdmission, sidecartest.DeliveryOracleInvalid, false, judges...)

	// replayed past a colluding gkm: as the winner of a late delivery's path for m, x and b, and among its own
	// deliveries for c2; each holds generation 1 as poisoned and alarms naming a
	for _, device := range []*FsKeysDevice{m, x, b} {
		world.Collude(device, beforeAdmission)
		if err := device.Client.DeliverLate(world.Ctx, repoId, fsKeysRecipient(c2.SidecarId())); err != nil {
			t.Fatalf("%s's late delivery under a colluding gkm: %v", device.Label, err)
		}
		device.Transport.Respond = nil
		if !device.refusedDelivery(a, 1) {
			t.Errorf("%s raised no refusal naming the signer: %+v", device.Label, device.Alarms)
		}
	}
	world.Collude(c2, beforeAdmission)
	if _, err := c2.Client.CurrentRepoKey(world.Ctx, repoId); err == nil {
		t.Errorf("the recipient read by a delivery pinned before its admission")
	}
	c2.Transport.Respond = nil
	if !c2.refusedDelivery(a, 1) {
		t.Errorf("the recipient raised no refusal naming the signer: %+v", c2.Alarms)
	}
	// a writer among them rotates REMOVE past the poisoned generation, with no shrink in the log
	key2, err := m.Client.EnsureWritable(world.Ctx, repoId)
	if err != nil {
		t.Fatalf("the rotation past the poisoned generation: %v", err)
	}
	generation2 := world.Generation(2)
	if key2.Generation() != 2 || sidecar.GkmCause(generation2.Rotate.GetCause()) != sidecar.GkmCauseRemove || generation2.SignerId != m.SidecarId() {
		t.Fatalf("the rotation past the poisoned generation: generation %d, cause %d", key2.Generation(), generation2.Rotate.GetCause())
	}
	// m's leaf waited while the newest generation was poisoned; its pending run now seats b, carrying generation 2.
	// Those that saw the poison follow and raise nothing more
	alarmsBefore := fsKeysAlarmCount(x, b, c2)
	world.Again("m's pending run", func() error { return m.Client.RunPending(world.Ctx, repoId) })
	world.Again("b's join", func() error {
		_, err := b.Client.JoinWelcomes(world.Ctx)
		return err
	})
	for _, device := range []*FsKeysDevice{x, b, c2} {
		world.Again(device.Label+"'s sync", func() error { return device.Client.SyncRepo(world.Ctx, repoId) })
		world.Again(device.Label+"'s read of generation 2", func() error {
			_, err := device.Client.RepoKey(world.Ctx, repoId, 2)
			return err
		})
	}
	if raised := fsKeysAlarmCount(x, b, c2) - alarmsBefore; raised != 0 {
		t.Errorf("following the rotation past the poison raised %d alarms", raised)
	}
	world.OracleHoldersAgree()

	// P2: b is revoked, and an agent with no delivery yet is admitted. The P1 delivery to b still judges valid
	e := world.AddAgent("e")
	world.Grant(false, e)
	world.Revoke(b)
	p2 := world.Advance()
	world.Publish()
	afterRevocation := []*FsKeysDevice{a, m, w, x, c, y}
	world.Judged("the P1 delivery after its recipient's revocation", toB, sidecartest.DeliveryOracleValid, false, afterRevocation...)
	if fsKeysAlarmCount(a, w, c, y) != 0 {
		t.Errorf("a delivery valid at its own state alarmed after its recipient's revocation")
	}

	// each of these is invalid for every verifier, and the honest gkm stores none
	now := world.Clock.Now()
	refused := func(label string, sender *FsKeysDevice, delivery *FsKeysDelivery, fork bool, devices ...*FsKeysDevice) {
		t.Helper()
		world.Judged(label, delivery, sidecartest.DeliveryOracleInvalid, fork, devices...)
		if status := world.UploadDelivery(sender, delivery); status == http.StatusCreated || status == http.StatusOK {
			t.Errorf("%s: gkm stored it (%d)", label, status)
		}
	}
	refused("a pin off the chain", a, world.SealDelivery(a, 2, e, sidecartest.FakeGkmForkPin(p2.Pin().GetVersion()), now), true, afterRevocation...)
	refused("a STAGED delivery carrying an auth", m, world.SealStagedWithAuth(m, 2, e, p2.Pin(), now), false, afterRevocation...)
	refused("a STAGED delivery by another than the claim's signer", a, world.SealDelivery(a, 2, c, nil, time.Time{}), false, afterRevocation...)
	refused("a delivery by a read_only device", w, world.SealDelivery(w, 2, e, p2.Pin(), now), false, afterRevocation...)

	// P3: x and y are revoked. A delivery x signs at P3, and one to y at P3, are invalid
	world.Revoke(x)
	world.Revoke(y)
	p3 := world.Advance()
	afterRevocations := []*FsKeysDevice{a, m, w, c}
	refused("a signer revoked before its pin", x, world.SealDelivery(x, 2, e, p3.Pin(), now), false, afterRevocations...)
	refused("a recipient revoked before its pin", a, world.SealDelivery(a, 2, y, p3.Pin(), now), false, afterRevocations...)

	// the leaf whose log trailed reaches the tip, and judges what it waited for
	behind.Offline = false
	behind.Take(world.Log.Tip())
	world.Judged("the delivery a member waited for", toC, sidecartest.DeliveryOracleValid, false, behind)

	// a member whose previous base passed a delivery's pin judges nothing of it, while its recipient still opens it
	world.Retain(p2.Pin().GetVersion())
	world.Judged("a pin before the judge's previous base", toC, sidecartest.DeliveryOracleNotJudged, false, a, m, w, c)
	if !world.OpensWrapOf(c, 1, c.CopyReaderKeys()) {
		t.Errorf("the recipient no longer opens a delivery nobody judges")
	}
}

// KEYS-M2-29's mutants: on four deliveries of FS-104's shapes, a valid one whose recipient was revoked later, one
// pinned before its recipient's admission, one by a read_only device and one served at another key's path, the
// members' check agrees with the oracle everywhere, and each mutant of it, one that judges at the newest state, one
// that ignores the path and one that ignores the signer's standing, disagrees with the oracle somewhere.
func FsKeysScheduleOracleSeesCheckMutants(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	m := world.AddMember("m", false)
	w := world.AddMember("w", true)
	world.Grant(true, a, m)
	world.Grant(false, w)
	world.Admin(a)
	p0 := world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	b := world.AddMember("b", false)
	c := world.AddAgent("c")
	world.Grant(false, b, c)
	world.Advance()
	world.Publish()
	if err := a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(b.SidecarId())); err != nil {
		t.Fatalf("the late delivery: %v", err)
	}
	toBs := world.Deliveries(1, b)
	if len(toBs) != 1 {
		t.Fatalf("gkm holds %d deliveries to b", len(toBs))
	}
	toB := toBs[0]
	now := world.Clock.Now()
	beforeAdmission := world.SealDelivery(a, 1, c, p0.Pin(), now)
	world.Revoke(b)
	p2 := world.Advance()
	byReadOnly := world.SealDelivery(w, 1, c, p2.Pin(), now)
	moved := &FsKeysDelivery{Key: toB.Key[:len(toB.Key)-16] + strings.Repeat("0", 16), Body: toB.Body}
	deliveries := []*FsKeysDelivery{toB, beforeAdmission, byReadOnly, moved}
	oracle := world.Oracle()
	disagreements := func(mutant fsKeysCheckMutant) int {
		count := 0
		for _, delivery := range deliveries {
			for _, device := range []*FsKeysDevice{a, m} {
				oracleVerdict := world.OracleJudges(oracle, device, delivery)
				if kind, fork := world.memberJudges(device, delivery, mutant); kind != oracleVerdict.Kind || fork != oracleVerdict.Fork {
					count += 1
				}
			}
		}
		return count
	}
	if count := disagreements(fsKeysCheckExact); count != 0 {
		t.Errorf("the members' check disagrees with the oracle on %d verdicts", count)
	}
	for _, mutant := range []fsKeysCheckMutant{fsKeysCheckMutantNewestState, fsKeysCheckMutantNoPath, fsKeysCheckMutantStanding} {
		if disagreements(mutant) == 0 {
			t.Errorf("mutant %d of the members' check went unseen by the oracle", mutant)
		}
	}
}

// FS-104's clock case: a delivery signed just after the claim by a holder whose clock trails the rotator's by 50 s
// carries the claim's time, and gkm and every verifier take it.
func FsKeysScheduleDeliveryByATrailingClock(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	m := world.AddMember("m", false)
	world.Grant(true, a, m)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the rotation: %v", err)
	}
	claimed := world.Generation(2)
	e := world.AddAgent("e")
	world.Grant(false, e)
	world.Advance()
	world.Publish()
	m.ClockOffset = -50 * time.Second
	m.Restart()
	world.Again("m's sync", func() error { return m.Client.SyncRepo(world.Ctx, world.RepoId) })
	if err := m.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(e.SidecarId())); err != nil {
		t.Fatalf("the trailing holder's late delivery: %v", err)
	}
	deliveries := world.Deliveries(2, e)
	if len(deliveries) != 1 {
		t.Fatalf("gkm holds %d deliveries to the new agent", len(deliveries))
	}
	if timeMs := deliveries[0].delivery(t).GetTimeMs(); timeMs != claimed.Rotate.GetTimeMs() {
		t.Errorf("a delivery by a clock that trails the claim carries %d, not the claim's time %d", timeMs, claimed.Rotate.GetTimeMs())
	}
	world.Judged("a delivery by a clock 50 s behind the rotator's", deliveries[0], sidecartest.DeliveryOracleValid, false, a, m, e)
	if key, err := e.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Errorf("the new agent's read: %v", err)
	}
	if world.GenerationCount() != 2 || fsKeysAlarmCount(world.Devices...) != 0 {
		t.Errorf("a valid delivery rotated or alarmed")
	}
}

// DESIGN-DETAILS 6.6's FS-104 row: x is revoked and an agent's rotation excludes it; the hostile leaf h commits a
// path over the tree that still holds x's leaf, carrying the new generation, which gkm, reading no tree, takes. a,
// processing it, refuses it, never adopts its epoch, holds the carried generation as poisoned and alarms naming h;
// the oracle's roster check refuses the same tree at the commit's pin; and x opens that generation from the store,
// which is the leak the refusal contains.
func FsKeysScheduleInjectedCommitJudged(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	h := world.AddMember("h", false)
	x := world.AddMember("x", false)
	d := world.AddAgent("d")
	world.Grant(true, a, h, x, d)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	world.Again("d's first wrap", func() error {
		_, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		return err
	})
	world.Revoke(x)
	x.Offline = true
	revoked := world.Advance()
	if key, err := d.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the agent's REMOVE rotation: %v", err)
	}
	world.Again("h's sync", func() error { return h.Client.SyncRepo(world.Ctx, world.RepoId) })
	epoch := world.NewestEpoch()
	if status := world.InjectPathCommit(h, 2); status != http.StatusOK {
		t.Fatalf("gkm refused the hostile commit, which it cannot judge: %d", status)
	}
	// a's sync takes the commit as refused, whatever it answers
	a.Client.SyncRepo(world.Ctx, world.RepoId)
	if !a.RefusedBy(h) {
		t.Errorf("a raised no refusal naming the hostile leaf: %+v", a.Alarms)
	}
	group, err := a.Mls.LoadGroup(world.GroupId)
	if err != nil {
		t.Fatal(err)
	}
	if group.Epoch() != epoch {
		t.Errorf("a adopted the hostile commit's epoch %d", group.Epoch())
	}
	if _, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a's rotation past the poisoned generation: %v", err)
	}
	if generation3 := world.Generation(3); sidecar.GkmCause(generation3.Rotate.GetCause()) != sidecar.GkmCauseRemove || generation3.SignerId != a.SidecarId() {
		t.Errorf("a did not rotate REMOVE past the generation the hostile commit carried")
	}
	// the oracle judges the tree the commit left, which is the one h holds, at the commit's pin and generation 2's time
	hostile, err := h.Mls.LoadGroup(world.GroupId)
	if err != nil {
		t.Fatal(err)
	}
	roster := [][]byte{}
	for _, member := range hostile.Roster() {
		roster = append(roster, member.SidecarId.Bytes())
	}
	verdict := world.Oracle().JudgeRoster(sidecartest.DeliveryOracleId(world.RepoId), revoked.Pin(), world.GenerationTime(world.Generation(2)), roster, 0, 0)
	if verdict.Kind != sidecartest.DeliveryOracleInvalid || !strings.Contains(verdict.Reason, hex.EncodeToString(x.SidecarId().Bytes())) {
		t.Errorf("the oracle's roster verdict: %s", verdict)
	}
	// the leak a refusal contains: x opens the generation the hostile commit carried, and nothing past it
	if reached := world.RemovedReach(x); reached != 2 {
		t.Errorf("the revoked leaf reaches generation %d, not the poisoned 2 alone", reached)
	}
	paths := []string{}
	for key := range world.objects(gkmservice.GkmGroupPrefix(world.GroupId) + "wrap/") {
		paths = append(paths, key)
	}
	if reached := sidecartest.DeliveryOracleWrapReach(paths, fsKeysRecipient(x.SidecarId())); 1 < reached {
		t.Errorf("gkm holds a delivery of generation %d to the revoked leaf", reached)
	}
}

// The agent's reader keys other than its current one are dropped: it kept none.
func (self *FsKeysDevice) dropOlderReaderKeys() {
	for keySha256 := range self.readerPrivateKeys {
		if !bytes.Equal([]byte(keySha256), self.readerKeySha256) {
			delete(self.readerPrivateKeys, keySha256)
		}
	}
	self.Restart()
}

// A late ask of generation under the device's current key's k8, first made at since.
func (self *FsKeysWorld) AskLate(device *FsKeysDevice, generation uint64, since time.Time) {
	self.t.Helper()
	self.Again(device.Label+"'s late ask", func() error {
		_, err := device.Api.Wraps(self.Ctx, self.RepoId, self.GroupId, generation, &sidecar.GkmWrapsQuery{
			Recipient: fsKeysRecipient(device.SidecarId()), Want: device.readerKeySha256[:8], Since: since,
		})
		return err
	})
}

// A wrap-pending hint naming device as the recipient.
func fsKeysWrapPendingFor(device *FsKeysDevice) func(hint *FsKeysHint) bool {
	return func(hint *FsKeysHint) bool {
		return hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING && string(hint.Hint.GetRecipient()) == fsKeysRecipient(device.SidecarId())
	}
}

// The delivery among deliveries whose key ends in the device's current key's k8, nil for none.
func (self *FsKeysDevice) deliveryToCurrentKey(deliveries []*FsKeysDelivery) *FsKeysDelivery {
	k8 := hex.EncodeToString(self.readerKeySha256[:8])
	for _, delivery := range deliveries {
		if strings.HasSuffix(delivery.Key, "/"+k8) {
			return delivery
		}
	}
	return nil
}

// Whether privateKeySha256's key, which device signed, opens delivery.
func (self *FsKeysWorld) keyOpens(device *FsKeysDevice, keySha256 string, delivery *FsKeysDelivery) bool {
	self.t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(delivery.Body, signed); err != nil {
		self.t.Fatal(err)
	}
	parsed, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(self.Log.Tip()))
	if err != nil {
		self.t.Fatal(err)
	}
	_, err = sidecar.OpenGkmDelivery(parsed, self.Generation(parsed.Body.GetGeneration()), device.SidecarId().Bytes(), device.readerPrivateKeys[keySha256])
	return err == nil
}

// FS-103: see the file header.
func FsKeysScheduleLateDeliveryIdentity(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	m := world.AddMember("m", false)
	r := world.AddMember("r", false)
	agent := world.AddAgent("g")
	world.Grant(true, a, m)
	world.Grant(false, r, agent)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	repoId := world.RepoId
	if _, err := a.Client.RotateRepo(world.Ctx, repoId); err != nil {
		t.Fatalf("the rotation: %v", err)
	}
	// every leaf holds generation 2 before the writers go offline
	for _, device := range []*FsKeysDevice{m, r} {
		world.Again(device.Label+"'s sync", func() error { return device.Client.SyncRepo(world.Ctx, repoId) })
		world.Again(device.Label+"'s read", func() error {
			_, err := device.Client.CurrentRepoKey(world.Ctx, repoId)
			return err
		})
	}
	k0Sha256 := string(agent.readerKeySha256)
	staged := world.Deliveries(2, agent)
	if len(staged) != 1 {
		t.Fatalf("generation 2 holds %d staged deliveries to the agent", len(staged))
	}
	k0Delivery := staged[0]

	// 42 days: a fresh key every 6, each kept 30 days past its not_after, generation 2 never fetched
	notAfters := map[string]time.Time{k0Sha256: world.Clock.Now().Add(6 * 24 * time.Hour)}
	for day := 6; day <= 42; day += 6 {
		world.Clock.Advance(6 * 24 * time.Hour)
		agent.PublishReaderKey()
		notAfters[string(agent.readerKeySha256)] = world.Clock.Now().Add(6 * 24 * time.Hour)
	}
	k0PrivateKey := agent.readerPrivateKeys[k0Sha256]
	for keySha256, notAfter := range notAfters {
		if world.Clock.Now().After(notAfter.Add(30 * 24 * time.Hour)) {
			delete(agent.readerPrivateKeys, keySha256)
		}
	}
	if _, kept := agent.readerPrivateKeys[k0Sha256]; kept {
		t.Fatalf("the agent still keeps its first key 36 days past its not_after")
	}
	agent.Restart()

	// no writer online, no rotation run: the ask reaches the writers at once and, 15 minutes old, a reader-only holder
	a.Offline, m.Offline = true, true
	asked := world.Clock.Now()
	world.AskLate(agent, 2, asked)
	world.AwaitHint(a, fsKeysWrapPendingFor(agent))
	if world.HintCount(r, fsKeysWrapPendingFor(agent)) != 0 {
		t.Errorf("gkm hinted a reader-only holder before the ask was 15 minutes old")
	}
	world.Clock.Advance(world.engineSettings.LateAskWidenAge + time.Minute)
	world.AskLate(agent, 2, asked)
	hint := world.AwaitHint(r, fsKeysWrapPendingFor(agent))
	world.Again("the reader-only holder's late delivery", func() error {
		return r.Client.DeliverLate(world.Ctx, repoId, string(hint.Hint.GetRecipient()))
	})
	deliveries := world.Deliveries(2, agent)
	k1Delivery := agent.deliveryToCurrentKey(deliveries)
	if len(deliveries) != 2 || k1Delivery == nil || !slices.ContainsFunc(deliveries, func(delivery *FsKeysDelivery) bool { return delivery.Key == k0Delivery.Key }) {
		t.Fatalf("gkm holds %d deliveries to the agent, the first key's and the current key's among them: %v", len(deliveries), k1Delivery != nil)
	}
	if !bytes.Equal(k1Delivery.signerId(t), r.SidecarId().Bytes()) || sidecar.GkmDeliveryKind(k1Delivery.delivery(t).GetDeliveryKind()) != sidecar.GkmDeliveryLate {
		t.Errorf("the delivery at the current key is not the reader-only holder's LATE one")
	}
	world.Again("the agent's read by its current key", func() error {
		key, err := agent.Client.CurrentRepoKey(world.Ctx, repoId)
		if err == nil && key.Generation() != 2 {
			t.Errorf("the agent reads generation %d", key.Generation())
		}
		return err
	})
	world.Judged("the late delivery to the current key", k1Delivery, sidecartest.DeliveryOracleValid, false, a, m, r, agent)
	world.Judged("the staged delivery to the first key", k0Delivery, sidecartest.DeliveryOracleValid, false, a, m, r, agent)
	// neither opens under the other's key: wrap_aad binds the key digest
	k1Sha256 := string(agent.readerKeySha256)
	agent.readerPrivateKeys[k0Sha256] = k0PrivateKey
	if !world.keyOpens(agent, k0Sha256, k0Delivery) || !world.keyOpens(agent, k1Sha256, k1Delivery) {
		t.Fatalf("a delivery does not open under the key it was sealed to")
	}
	if world.keyOpens(agent, k1Sha256, k0Delivery) || world.keyOpens(agent, k0Sha256, k1Delivery) {
		t.Errorf("a delivery opens under another key than the one it was sealed to")
	}
	delete(agent.readerPrivateKeys, k0Sha256)
	// nor at the other key's path: every verifier refuses the first key's delivery served at the current key's path
	moved := &FsKeysDelivery{Key: k1Delivery.Key, Body: k0Delivery.Body}
	world.Judged("a delivery served at another key's path", moved, sidecartest.DeliveryOracleInvalid, false, r, agent)

	// two late deliverers held on one target: m's lands while r's upload is held; r takes the 412 and judges its winner
	a.Offline, m.Offline = false, false
	world.Clock.Advance(25 * time.Hour)
	agent.PublishReaderKey()
	held := false
	r.Transport.Before = func(request *http.Request) FsKeysFault {
		if fsKeysWrapUpload(request) && !held {
			held = true
			if err := m.Client.DeliverLate(world.Ctx, repoId, fsKeysRecipient(agent.SidecarId())); err != nil {
				t.Fatalf("the second deliverer's late delivery: %v", err)
			}
		}
		return FsKeysFaultNone
	}
	alarmsBefore := fsKeysAlarmCount(m, r)
	if err := r.Client.DeliverLate(world.Ctx, repoId, fsKeysRecipient(agent.SidecarId())); err != nil {
		t.Fatalf("the held deliverer's late delivery: %v", err)
	}
	r.Transport.Before = nil
	winner := agent.deliveryToCurrentKey(world.Deliveries(2, agent))
	if !held || winner == nil || !bytes.Equal(winner.signerId(t), m.SidecarId().Bytes()) {
		t.Fatalf("the target does not hold the first deliverer's object")
	}
	if raised := fsKeysAlarmCount(m, r) - alarmsBefore; raised != 0 {
		t.Errorf("a valid winner raised %d alarms", raised)
	}
	world.Judged("the winner of two late deliverers", winner, sidecartest.DeliveryOracleValid, false, m, r, agent)

	// a deliverer killed before its PUT, then one whose PUT's answer is lost: each retried, one valid object
	for _, fault := range []FsKeysFault{FsKeysFaultFailBefore, FsKeysFaultDropAnswer} {
		world.Clock.Advance(25 * time.Hour)
		agent.PublishReaderKey()
		faulted := false
		r.Transport.Before = func(request *http.Request) FsKeysFault {
			if fsKeysWrapUpload(request) && !faulted {
				faulted = true
				return fault
			}
			return FsKeysFaultNone
		}
		if err := r.Client.DeliverLate(world.Ctx, repoId, fsKeysRecipient(agent.SidecarId())); err == nil {
			t.Fatalf("a late delivery whose PUT was faulted answered no error")
		}
		r.Restart()
		world.Again("the retried late delivery", func() error {
			return r.Client.DeliverLate(world.Ctx, repoId, fsKeysRecipient(agent.SidecarId()))
		})
		r.Transport.Before = nil
		retried := agent.deliveryToCurrentKey(world.Deliveries(2, agent))
		if retried == nil {
			t.Fatalf("no object at the target after the retry (fault %d)", fault)
		}
		world.Judged("a retried late delivery", retried, sidecartest.DeliveryOracleValid, false, r, agent)
		if fsKeysAlarmCount(r) != 0 {
			t.Errorf("a retried late delivery alarmed: %+v", r.Alarms)
		}
	}
	world.Again("the agent's read by its newest key", func() error {
		agent.dropOlderReaderKeys()
		key, err := agent.Client.CurrentRepoKey(world.Ctx, repoId)
		if err == nil && key.Generation() != 2 {
			t.Errorf("the agent reads generation %d", key.Generation())
		}
		return err
	})

	// gkm's refusals, each 409: a LATE delivery to a key it does not serve for the agent, of a generation that is
	// not the newest, and a STAGED one after the claim
	now := world.Clock.Now()
	tip := world.Log.Tip().Pin()
	servedKey := agent.ReaderKey
	unserved, _, err := sidecar.NewGkmReaderKey(agent.SidecarId(), now, now.Add(6*24*time.Hour), agent.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	agent.ReaderKey = unserved
	toUnservedKey := world.SealDelivery(a, 2, agent, tip, now)
	agent.ReaderKey = servedKey
	if status := world.UploadDelivery(a, toUnservedKey); status != http.StatusConflict {
		t.Errorf("a LATE delivery to a key gkm does not serve: %d", status)
	}
	world.Clock.Advance(25 * time.Hour)
	agent.PublishReaderKey()
	now = world.Clock.Now()
	if status := world.UploadDelivery(a, world.SealDelivery(a, 1, agent, tip, now)); status != http.StatusConflict {
		t.Errorf("a LATE delivery of a generation that is not the newest: %d", status)
	}
	if status := world.UploadDelivery(a, world.SealDelivery(a, 2, agent, nil, time.Time{})); status != http.StatusConflict {
		t.Errorf("a STAGED delivery after the claim: %d", status)
	}
	if world.GenerationCount() != 2 {
		t.Fatalf("a rotation ran: %d generations", world.GenerationCount())
	}
}

// FS-103's retention: the agent's staged delivery of generation 2 lies at its first key; a day on it replaces the
// key and a holder delivers LATE to the new one. Both stand through the sweeps of the next 30 days, since the agent
// may still hold the first key, and the sweep past 30 days of the newer delivery collects the older one alone.
func FsKeysScheduleOlderKeyDeliveryAgesOut(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	agent := world.AddAgent("g")
	world.Grant(true, a)
	world.Grant(false, agent)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the rotation: %v", err)
	}
	staged := world.Deliveries(2, agent)
	if len(staged) != 1 {
		t.Fatalf("generation 2 holds %d staged deliveries to the agent", len(staged))
	}
	world.Clock.Advance(25 * time.Hour)
	agent.PublishReaderKey()
	world.Again("the delivery to the newer key", func() error {
		return a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(agent.SidecarId()))
	})
	newest := agent.deliveryToCurrentKey(world.Deliveries(2, agent))
	if newest == nil || newest.Key == staged[0].Key {
		t.Fatalf("no delivery at the newer key")
	}
	reconciler := world.StartReconciler(nil)
	world.Clock.Advance(24 * time.Hour)
	world.Sweep(reconciler)
	if count := len(world.Deliveries(2, agent)); count != 2 {
		t.Fatalf("a sweep a day past the newer delivery left %d deliveries to the agent", count)
	}
	world.Clock.Advance(28 * 24 * time.Hour)
	world.Sweep(reconciler)
	if count := len(world.Deliveries(2, agent)); count != 2 {
		t.Fatalf("a sweep 29 days past the newer delivery left %d deliveries to the agent", count)
	}
	world.Clock.Advance(2 * 24 * time.Hour)
	world.Sweep(reconciler)
	remaining := world.Deliveries(2, agent)
	if len(remaining) != 1 || remaining[0].Key != newest.Key {
		t.Errorf("30 days past the newer key's delivery, %d deliveries to the agent stand", len(remaining))
	}
	if world.GenerationCount() != 2 {
		t.Errorf("the retention schedule rotated")
	}
}

// FS-103's rebind: a same-generation RecoveryRebind. The new binding's RecoveryWraps of the current generation land
// at their own b8 before the old binding's go; the rebind is killed at its first deletion, leaving both; the resumed
// rebind deletes only the old binding's, and the new code opens the generation.
func FsKeysScheduleSameGenerationRebind(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, _, old := newFsKeysRebindWorld(t, newWorld)
	newer := world.RebindRecovery("m'", a, false)
	world.Advance()
	bothAtTheKill := false
	killed := false
	world.BlobWrite = func(op string, key string) FsKeysFault {
		if op != http.MethodDelete || killed || !strings.HasPrefix(key, gkmservice.GkmRecoveryMemberPrefix(world.MemberId)) {
			return FsKeysFaultNone
		}
		killed = true
		bothAtTheKill = true
		for _, groupId := range world.groupIds() {
			newest := uint64(world.GenerationCountIn(groupId))
			bindings := world.RecoveryWrapBindings(groupId, newest)
			if !bindings[old.B8()] || !bindings[newer.B8()] {
				bothAtTheKill = false
			}
		}
		return FsKeysFaultFailBefore
	}
	args := &sidecar.GkmRecoveryRebindArgs{MemberId: world.MemberId, New: newer.Key(), RetiredKeySha256: old.KeySha256}
	if err := a.Client.RebindRecovery(world.Ctx, args); err == nil {
		t.Fatalf("a rebind killed at its first deletion answered no error")
	}
	world.BlobWrite = nil
	if !killed || !bothAtTheKill {
		t.Fatalf("at the first deletion the new binding's wraps did not stand beside the old one's: killed %v", killed)
	}
	if world.GenerationCount() != 2 {
		t.Fatalf("the rebind rotated before its deletions finished")
	}
	// the new process resumes from its keychain, and deletes only the old binding's
	a.Restart()
	world.Again("the resumed rebind", func() error {
		resumed, err := a.Client.ResumeRecoveryRebind(world.Ctx)
		if err == nil && !resumed {
			return errors.New("fs keys: nothing to resume")
		}
		return err
	})
	for _, groupId := range world.groupIds() {
		// the generation the rebind re-wrapped is the one before its closing rotation
		rewrapped := uint64(world.GenerationCountIn(groupId)) - 1
		bindings := world.RecoveryWrapBindings(groupId, rewrapped)
		if bindings[old.B8()] {
			t.Errorf("group %s keeps the old binding's wrap of generation %d", groupId, rewrapped)
		}
		if reached := world.RecoveryReach(old, groupId); reached != 0 {
			t.Errorf("the old code opens generation %d of group %s", reached, groupId)
		}
		if reached := world.RecoveryReach(newer, groupId); reached < rewrapped {
			t.Errorf("the new code opens generation %d of group %s, below the %d it was re-wrapped", reached, groupId, rewrapped)
		}
	}
}
