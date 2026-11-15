//go:build !sidecar_http && !ios_extension

// RECORD-M8-01's phones over the fake world, each phone reaching evs through sidecartest's FakeDirectoryPhone, T4's
// surrogate: a phone leasing only its member's targets' prefixes and its own requests' notice paths, its member's
// workers learned from its open view; FS-100's wake case, R woken once for a denial and reading that notice and the
// one entry it names and nothing else; FS-85's wake case, an approver's phone woken for a new request; no wake naming
// a directory, target or request; a phone that slept past its leases' expiry renewing and reading at its next resync;
// one woken while its app was closed reading its decision in its next process; a DecisionRef naming another request's
// entry refused on a phone; a breach of its notice alarmed and repaired; a repo approval that beat a denial received
// as the approval; expiry never read as denied; and with no head reads nothing taken.

package sidecar_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// device made a phone: its client reaches evs through T4's surrogate, which takes its leases and serves its head
// reads, and its phone part is bound. A phone never syncs.
func (self *testDecideEnv) phone(device *testDirectoryDevice) (*sidecartest.FakeDirectoryPhone, *sidecar.DirectoryPhoneNotices) {
	self.t.Helper()
	surrogate := sidecartest.NewFakeDirectoryPhone(self.world.cards, device.writer.sidecarId, nil)
	device.client.Bind(surrogate, nil)
	phone, err := device.client.BindPhoneNotices(nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return surrogate, phone
}

// The phone's next process: a client over the same store and record, its requests bound again, its phone part bound.
func (self *testDecideEnv) restartPhone(device *testDirectoryDevice, surrogate *sidecartest.FakeDirectoryPhone) *sidecar.DirectoryPhoneNotices {
	self.t.Helper()
	sidecarId := device.writer.sidecarId
	reader := device.testDirectoryReader
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  sidecarId,
		Store:      reader.store,
		Cards:      surrogate,
		Streams:    func() sidecar.RecordStreams { return self.world.streams.For(sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.world.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			reader.stateLock.Lock()
			defer reader.stateLock.Unlock()
			reader.alarms = append(reader.alarms, alarm)
		},
		Clock:    self.world.clock,
		Settings: sidecar.DefaultSidecarSettings().Directory,
		Writer:   device.record.Writer(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	reader.client = client
	self.bind(device)
	phone, err := client.BindPhoneNotices(nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return phone
}

// A phone of the approver's member that is itself an admin of the env's repo, so it decides the repo's requests.
func (self *testDecideEnv) approverPhone() *testDirectoryDevice {
	self.t.Helper()
	writer := self.world.memberWriter(self.approverMember)
	repo := self.world.directoryFixture.Repos[self.repoId]
	repo.Admins = append(repo.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: writer.sidecarId, At: self.world.directoryAuth.Tip().Pin().GetVersion() + 1})
	self.world.publish()
	device := self.device(writer)
	self.bind(device)
	return device
}

// One Resync, which must succeed.
func testPhoneResync(t *testing.T, phone *sidecar.DirectoryPhoneNotices) *sidecar.DirectoryPhoneResynced {
	t.Helper()
	resynced, err := phone.Resync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return resynced
}

// A wake names nothing (WK4): APNs' body is exactly {"aps":{"content-available":1},"t":"evs","v":<n>}, and no id it
// could name appears in it in either text form.
func testPhoneWakeNamesNothing(t *testing.T, wake *sidecartest.FakeDirectoryWake, ids ...sidecar.Id) {
	t.Helper()
	body := map[string]json.RawMessage{}
	if err := json.Unmarshal(wake.Body, &body); err != nil {
		t.Fatalf("a wake's body %q: %v", wake.Body, err)
	}
	keys := []string{}
	for key := range body {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"aps", "t", "v"}) || string(body["aps"]) != `{"content-available":1}` || string(body["t"]) != `"evs"` {
		t.Fatalf("a wake's body %q", wake.Body)
	}
	if wake.Payload.TopicClass != "evs" || wake.Payload.Version == 0 {
		t.Fatalf("a wake's payload %+v", wake.Payload)
	}
	text := strings.ToLower(string(wake.Body))
	for _, id := range ids {
		if strings.Contains(text, hex.EncodeToString(id.Bytes())) || strings.Contains(text, id.String()) {
			t.Fatalf("a wake names %s: %q", id, wake.Body)
		}
	}
}

// How many of device's events in env read event.
func testPhoneEventCount(env *testDecideEnv, device *testDirectoryDevice, event string) int {
	count := 0
	for _, raised := range env.events[device.writer.sidecarId] {
		if raised == event {
			count += 1
		}
	}
	return count
}

// A phone leases q/<h>/<tgt>/ for the targets it decides and each own request's notice path, nothing else, and never
// the cards ref, d/ or r/; a second resync within PhoneLeaseRenewAge takes and renews nothing, never for a reconnect;
// and Close releases nothing, so evs keeps the leases for the closed app.
func TestDirectoryPhoneLeasesItsTargetsAndOwnPaths(t *testing.T) {
	env := newTestDecideEnv(t)
	approverDevice := env.approverPhone()
	approverSurrogate, approverPhone := env.phone(approverDevice)
	requesterSurrogate, requesterPhone := env.phone(env.requester)
	testPhoneResync(t, approverPhone)
	testPhoneResync(t, requesterPhone)
	repoPrefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: env.repoId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	filed := env.mustFile(env.requester, env.ask())
	prefixes := func(surrogate *sidecartest.FakeDirectoryPhone) []string {
		prefixes := []string{}
		for _, lease := range surrogate.Leases() {
			if !lease.Live || lease.Holders != 1 {
				t.Fatalf("a lease %+v", lease)
			}
			prefixes = append(prefixes, lease.Prefix)
		}
		return prefixes
	}
	if leased := prefixes(approverSurrogate); !slices.Equal(leased, []string{repoPrefix}) {
		t.Fatalf("the approver's phone leases %v, not its repo's prefix alone", leased)
	}
	if leased := prefixes(requesterSurrogate); !slices.Equal(leased, []string{filed.NoticePath}) {
		t.Fatalf("the requester's phone leases %v, not its notice's path alone", leased)
	}
	if leased := requesterPhone.Leased(); !slices.Equal(leased, []string{filed.NoticePath}) {
		t.Fatalf("the requester's phone holds %v", leased)
	}
	env.world.clock.Advance(time.Hour)
	for _, phone := range []*sidecar.DirectoryPhoneNotices{approverPhone, requesterPhone} {
		if resynced := testPhoneResync(t, phone); resynced.LeasesTaken != 0 || resynced.LeasesRenewed != 0 || resynced.LeasesReleased != 0 {
			t.Fatalf("a resync within a day: %+v", resynced)
		}
	}
	requesterPhone.Close()
	if leases := requesterSurrogate.Leases(); len(leases) != 1 || !leases[0].Live {
		t.Fatalf("a closed phone's leases at evs: %+v", leases)
	}
	if _, err := requesterPhone.Resync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryPhoneClosed) {
		t.Fatalf("a closed phone's resync answered %v", err)
	}
}

// FS-100's wake case: approver A denies R's repo request. R, a phone leasing only its notice's path, with no view open,
// no indexer and no stream sync, gets exactly one wake, naming nothing; at its resync it reads that notice and the one
// decision entry its DecisionRef names, by head reads, and nothing else, then shows denied with A's note through
// access_decided, once, recorded in its vault. The denied notice stays leased until not_after + 1 d.
func TestDirectoryPhoneDenialWakesItOnce(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate, phone := env.phone(env.requester)
	requesterId := env.requester.writer.sidecarId
	filed := env.mustFile(env.requester, env.ask())
	if !filed.NoticeWritten || len(surrogate.Wakes()) != 0 {
		t.Fatalf("filed %+v with %d wakes", filed, len(surrogate.Wakes()))
	}
	before := surrogate.Counts()
	env.mustDecide(env.approver, filed.RequestId, false)
	wakes := surrogate.Wakes()
	if len(wakes) != 1 {
		t.Fatalf("R got %d wakes for one denial", len(wakes))
	}
	testPhoneWakeNamesNothing(t, wakes[0], env.world.directoryId, env.repoId, filed.RequestId, requesterId, env.approver.writer.sidecarId)
	resynced := testPhoneResync(t, phone)
	after := surrogate.Counts()
	if after.NoticeReads-before.NoticeReads != 1 || after.EntryReads-before.EntryReads != 1 || after.Listings != 0 {
		t.Fatalf("R read %d notices, %d entries and %d listings", after.NoticeReads-before.NoticeReads, after.EntryReads-before.EntryReads, after.Listings)
	}
	if after.Refs != 0 || after.ReadStreams != 0 || after.ReadStreamLogs != 0 || after.ReadCards != 0 {
		t.Fatalf("a phone synced: %+v", after)
	}
	if resynced.Decided != 1 || testPhoneEventCount(env, env.requester, "access_decided/denied/"+filed.RequestId.String()) != 1 {
		t.Fatalf("resynced %+v, events %v", resynced, env.events[requesterId])
	}
	recorded := env.receipts[requesterId].recorded
	if len(recorded) != 1 || recorded[0].Outcome != sidecar.SidecarAccessDecidedDenied || len(recorded[0].Decisions) != 1 ||
		recorded[0].Decisions[0].Decision.GetNote() != "seen" {
		t.Fatalf("the vault recorded %+v", recorded)
	}
	// nothing more is read or raised, and the denial stays leased, so a repo approval that beats it still arrives
	again := testPhoneResync(t, phone)
	if again.NoticeReads != 0 || again.EntryReads != 0 || again.Decided != 0 {
		t.Fatalf("a second resync %+v", again)
	}
	if leased := phone.Leased(); !slices.Equal(leased, []string{filed.NoticePath}) {
		t.Fatalf("after the denial the phone holds %v", leased)
	}
}

// FS-85's wake case: an approver's phone leasing its repo's prefix is woken once by a new request's notice, naming
// nothing; at its resync it lists the prefix and reads the request's entry, raising access_request once, and Incoming
// shows the request as one it decides. A second resync raises nothing again.
func TestDirectoryPhoneApproverWokenForANewRequest(t *testing.T) {
	env := newTestDecideEnv(t)
	approverDevice := env.approverPhone()
	surrogate, phone := env.phone(approverDevice)
	testPhoneResync(t, phone)
	filed := env.mustFile(env.requester, env.ask())
	wakes := surrogate.Wakes()
	if len(wakes) != 1 {
		t.Fatalf("the approver's phone got %d wakes for one request", len(wakes))
	}
	testPhoneWakeNamesNothing(t, wakes[0], env.world.directoryId, env.repoId, filed.RequestId, env.requester.writer.sidecarId)
	resynced := testPhoneResync(t, phone)
	if resynced.ListingReads != 1 || resynced.EntryReads != 1 || resynced.Requested != 1 {
		t.Fatalf("the approver's phone's resync %+v", resynced)
	}
	if count := testPhoneEventCount(env, approverDevice, "access_request/"+filed.RequestId.String()); count != 1 {
		t.Fatalf("access_request raised %d times", count)
	}
	incoming := phone.Incoming()
	if len(incoming) != 1 || incoming[0].RequestId != filed.RequestId || !incoming[0].Decidable || incoming[0].Notice == nil {
		t.Fatalf("incoming %+v", incoming)
	}
	if again := testPhoneResync(t, phone); again.Requested != 0 || again.ListingReads != 0 {
		t.Fatalf("a second resync %+v", again)
	}
	// the decision's rewrite wakes it too, and the request leaves Incoming
	env.mustDecide(env.approver, filed.RequestId, true)
	if wakes := surrogate.Wakes(); len(wakes) != 2 {
		t.Fatalf("%d wakes after the decision", len(wakes))
	}
	testPhoneResync(t, phone)
	if incoming := phone.Incoming(); len(incoming) != 0 {
		t.Fatalf("a decided request is still incoming: %+v", incoming)
	}
}

// A lease lapses unless renewed: R files, then sleeps eight days, so its lease lapsed at seven and A's denial wakes
// nothing. At R's next resync the lease is renewed at once and, since it had lapsed, its notice read again, so R takes
// the denial it slept through.
func TestDirectoryPhoneLeaseRenewsAtItsNextResync(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate, phone := env.phone(env.requester)
	ask := env.ask()
	ask.NotAfter = 30 * 24 * time.Hour
	filed := env.mustFile(env.requester, ask)
	env.world.clock.Advance(8 * 24 * time.Hour)
	env.world.publish()
	if leases := surrogate.Leases(); len(leases) != 1 || leases[0].Live {
		t.Fatalf("after eight days asleep: %+v", leases)
	}
	env.mustDecide(env.approver, filed.RequestId, false)
	if wakes := surrogate.Wakes(); len(wakes) != 0 {
		t.Fatalf("a lapsed lease woke the phone %d times", len(wakes))
	}
	resynced := testPhoneResync(t, phone)
	if resynced.LeasesRenewed != 1 || resynced.NoticeReads != 1 || resynced.EntryReads != 1 || resynced.Decided != 1 {
		t.Fatalf("the resync after the sleep %+v", resynced)
	}
	if leases := surrogate.Leases(); len(leases) != 1 || !leases[0].Live {
		t.Fatalf("after the resync: %+v", leases)
	}
	if testPhoneEventCount(env, env.requester, "access_decided/denied/"+filed.RequestId.String()) != 1 {
		t.Fatalf("events %v", env.events[env.requester.writer.sidecarId])
	}
}

// R's app is closed when A decides: evs still holds R's lease and wakes it once. R's next process, from its store
// alone, takes the lease again and reads its notice and the one entry, raising access_decided once.
func TestDirectoryPhoneWokenWhileClosedReadsItsDecision(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate, phone := env.phone(env.requester)
	filed := env.mustFile(env.requester, env.ask())
	phone.Close()
	surrogate.Kill()
	env.mustDecide(env.approver, filed.RequestId, false)
	if wakes := surrogate.Wakes(); len(wakes) != 1 {
		t.Fatalf("a closed app got %d wakes", len(wakes))
	}
	next := env.restartPhone(env.requester, surrogate)
	resynced := testPhoneResync(t, next)
	if resynced.LeasesTaken != 1 || resynced.NoticeReads != 1 || resynced.EntryReads != 1 || resynced.Decided != 1 {
		t.Fatalf("the next process's resync %+v", resynced)
	}
	if testPhoneEventCount(env, env.requester, "access_decided/denied/"+filed.RequestId.String()) != 1 {
		t.Fatalf("events %v", env.events[env.requester.writer.sidecarId])
	}
	if leases := surrogate.Leases(); len(leases) != 1 || leases[0].Holders != 1 {
		t.Fatalf("the next process's leases %+v", leases)
	}
}

// A decided notice whose DecisionRef names A's decision on another request is refused on a phone as on a desktop: a
// bad_decision alarm, no access_decided and nothing recorded for it, while the real approval of the first is taken.
func TestDirectoryPhoneReceiptRefusesAnotherRequestsDecision(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate, phone := env.phone(env.requester)
	requesterId := env.requester.writer.sidecarId
	first := env.mustFile(env.requester, env.ask())
	second := env.mustFile(env.requester, env.ask())
	env.mustDecide(env.approver, first.RequestId, true)
	env.approver.mustSync(t)
	decided := testNoticeAt(t, env.approver, first.NoticePath)
	forged := proto.Clone(decided).(*protocol.DirectoryNotice)
	forged.RequestId, forged.EntrySeq, forged.NotAfterMillis = second.RequestId.Bytes(), second.EntrySeq, second.NotAfterMillis
	testPutNotice(t, env.testRequestsEnv, env.approver, second.NoticePath, forged)
	if wakes := surrogate.Wakes(); len(wakes) != 2 {
		t.Fatalf("%d wakes for the approval and the forged rewrite", len(wakes))
	}
	if _, err := phone.Resync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReceiptRefused) {
		t.Fatalf("a resync over a forged notice answered %v", err)
	}
	if count := testAlarmCount(env.requester, sidecar.SidecarRecordAlarmBadDecision); count != 1 {
		t.Fatalf("%d bad_decision alarms", count)
	}
	if testPhoneEventCount(env, env.requester, "access_decided/approved/"+first.RequestId.String()) != 1 {
		t.Fatalf("the first's approval was not taken: %v", env.events[requesterId])
	}
	for _, event := range env.events[requesterId] {
		if strings.HasSuffix(event, second.RequestId.String()) {
			t.Fatalf("the forged approval raised %s", event)
		}
	}
	for _, recorded := range env.receipts[requesterId].recorded {
		if recorded.RequestId == second.RequestId {
			t.Fatal("the forged approval was recorded")
		}
	}
	// the refused version is not read again until the notice's next rewrite hints
	again := testPhoneResync(t, phone)
	if again.EntryReads != 0 || testAlarmCount(env.requester, sidecar.SidecarRecordAlarmBadDecision) != 1 {
		t.Fatalf("a resync after the refusal %+v", again)
	}
}

// A request past not_after with no decision is expired on a phone, never denied: its next resync reads its notice once,
// raises access_decided expired once and reads no entry.
func TestDirectoryPhoneExpiryIsNeverDenied(t *testing.T) {
	env := newTestDecideEnv(t)
	_, phone := env.phone(env.requester)
	ask := env.ask()
	ask.NotAfter = time.Hour
	filed := env.mustFile(env.requester, ask)
	env.world.clock.Advance(2 * time.Hour)
	resynced := testPhoneResync(t, phone)
	if resynced.NoticeReads != 1 || resynced.EntryReads != 0 || resynced.Decided != 1 {
		t.Fatalf("the resync past not_after %+v", resynced)
	}
	if testPhoneEventCount(env, env.requester, "access_decided/expired/"+filed.RequestId.String()) != 1 ||
		testPhoneEventCount(env, env.requester, "access_decided/denied/"+filed.RequestId.String()) != 0 {
		t.Fatalf("events %v", env.events[env.requester.writer.sidecarId])
	}
	if again := testPhoneResync(t, phone); again.Decided != 0 || again.NoticeReads != 0 {
		t.Fatalf("a second resync %+v", again)
	}
}

// With nothing serving head reads a phone still holds its leases, but at a hint reads nothing and takes no outcome: its
// resync answers ErrDirectoryHeadReadUnavailable, and the hinted path stays due.
func TestDirectoryPhoneWithoutHeadReadsTakesNothing(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate := sidecartest.NewFakeDirectoryPhone(env.world.cards, env.requester.writer.sidecarId, nil)
	// a binding that leases and serves no head read
	env.requester.client.Bind(&testLeaseOnlyCards{DirectoryCards: surrogate}, nil)
	phone, err := env.requester.client.BindPhoneNotices(nil)
	if err != nil {
		t.Fatal(err)
	}
	filed := env.mustFile(env.requester, env.ask())
	if leased := phone.Leased(); !slices.Equal(leased, []string{filed.NoticePath}) {
		t.Fatalf("the phone holds %v", leased)
	}
	env.mustDecide(env.approver, filed.RequestId, false)
	for range 2 {
		if _, err := phone.Resync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryHeadReadUnavailable) {
			t.Fatalf("a resync with no head reads answered %v", err)
		}
	}
	if len(env.events[env.requester.writer.sidecarId]) != 0 || len(env.receipts[env.requester.writer.sidecarId].recorded) != 0 {
		t.Fatalf("an outcome taken with no head reads: %v", env.events[env.requester.writer.sidecarId])
	}
	if counts := surrogate.Counts(); counts.NoticeReads != 0 || counts.EntryReads != 0 {
		t.Fatalf("reads %+v", counts)
	}
}

// DirectoryCards alone, hiding any head reads under it.
type testLeaseOnlyCards struct {
	sidecar.DirectoryCards
}

// A read_only client takes no phone part, and a phone's leases never name the cards ref, d/ or r/.
func TestDirectoryPhoneRefusesReadOnlyAndForeignPaths(t *testing.T) {
	env := newTestDecideEnv(t)
	reader := env.world.clientFor(sidecar.NewId(), nil, true)
	if _, err := reader.client.BindPhoneNotices(nil); !errors.Is(err, sidecar.ErrDirectoryReadOnly) {
		t.Fatalf("a read_only client's phone part: %v", err)
	}
	surrogate, phone := env.phone(env.requester)
	env.mustFile(env.requester, env.ask())
	testPhoneResync(t, phone)
	for _, lease := range surrogate.Leases() {
		if !sidecar.DirectoryLeasePathAllowed(lease.Prefix) || !bytes.HasPrefix([]byte(lease.Prefix), []byte("q/")) {
			t.Fatalf("a phone leases %q", lease.Prefix)
		}
	}
}

// A notice version its signer may not write is ignored on a phone as by every reader: a forged approval written over
// R's notice by a member who decides nothing for the repo wakes R, alarms path_rule once and raises nothing, and R's
// next resync writes its pending notice over the breach from its own entry, which the repo's approver then shows.
func TestDirectoryPhoneRepairsABreachOfItsNotice(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate, phone := env.phone(env.requester)
	requesterId := env.requester.writer.sidecarId
	filed := env.mustFile(env.requester, env.ask())
	intruderWriter := env.world.memberWriter(sidecar.NewId())
	env.world.publish()
	intruder := env.device(intruderWriter)
	forged := &protocol.DirectoryNotice{
		RequestId:          filed.RequestId.Bytes(),
		RequesterSidecarId: requesterId.Bytes(),
		EntrySeq:           filed.EntrySeq,
		NotAfterMillis:     filed.NotAfterMillis,
		State:              uint32(sidecar.DirectoryNoticeStateDecided),
		Outcome:            uint32(sidecar.DirectoryOutcomeApproved),
		Decisions:          []*protocol.DecisionRef{{DeciderSidecarId: intruderWriter.sidecarId.Bytes(), Seq: 1, HeaderSha256: make([]byte, 32)}},
	}
	testPutNotice(t, env.testRequestsEnv, intruder, filed.NoticePath, forged)
	if wakes := surrogate.Wakes(); len(wakes) != 1 {
		t.Fatalf("%d wakes for the breach", len(wakes))
	}
	resynced := testPhoneResync(t, phone)
	if resynced.Decided != 0 || resynced.EntryReads != 0 || testAlarmCount(env.requester, sidecar.SidecarRecordAlarmPathRule) != 1 {
		t.Fatalf("the breach read as %+v with %d path_rule alarms", resynced, testAlarmCount(env.requester, sidecar.SidecarRecordAlarmPathRule))
	}
	if len(env.events[requesterId]) != 0 {
		t.Fatalf("a breach raised %v", env.events[requesterId])
	}
	repaired := testPhoneResync(t, phone)
	if repaired.Repaired != 1 {
		t.Fatalf("the repair %+v", repaired)
	}
	view := env.request(env.approver, filed.RequestId)
	if view.State != sidecar.DirectoryRequestPending || view.Notice == nil || len(view.Notice.GetDecisions()) != 0 || !view.Decidable {
		t.Fatalf("the approver's view after the repair %+v", view)
	}
}

// A repo approval that a denial beat still reaches a phone: the denial's rewrite wakes R, cues its app host and is
// taken; a second admin's approval rewrites the notice to approved, which R still leases, so it wakes R again and is
// received as the approval, its statement checked in the log and recorded, and R closes the approved notice.
func TestDirectoryPhoneApprovalOverADenial(t *testing.T) {
	env := newTestDecideEnv(t)
	surrogate, phone := env.phone(env.requester)
	hints := 0
	if _, err := env.requester.client.BindPhoneNotices(&sidecar.DirectoryPhoneNoticesArgs{Hinted: func() { hints += 1 }}); err != nil {
		t.Fatal(err)
	}
	second := env.secondApprover()
	requesterId := env.requester.writer.sidecarId
	filed := env.mustFile(env.requester, env.ask())
	env.mustDecide(env.approver, filed.RequestId, false)
	if hints != 1 {
		t.Fatalf("the denial cued the app host %d times", hints)
	}
	if resynced := testPhoneResync(t, phone); resynced.Decided != 1 {
		t.Fatalf("the denial's resync %+v", resynced)
	}
	env.mustDecide(second, filed.RequestId, true)
	if wakes := surrogate.Wakes(); len(wakes) != 2 {
		t.Fatalf("%d wakes for the denial and the approval over it", len(wakes))
	}
	resynced := testPhoneResync(t, phone)
	if resynced.Decided != 1 || resynced.NoticeReads != 1 || resynced.EntryReads != 1 {
		t.Fatalf("the approval's resync %+v", resynced)
	}
	if testPhoneEventCount(env, env.requester, "access_decided/denied/"+filed.RequestId.String()) != 1 ||
		testPhoneEventCount(env, env.requester, "access_decided/approved/"+filed.RequestId.String()) != 1 {
		t.Fatalf("events %v", env.events[requesterId])
	}
	recorded := env.receipts[requesterId].recorded
	if len(recorded) != 2 || recorded[1].Outcome != sidecar.SidecarAccessDecidedApproved {
		t.Fatalf("the vault recorded %+v", recorded)
	}
	env.approver.mustSync(t)
	if notice := testNoticeAt(t, env.approver, filed.NoticePath); notice != nil {
		t.Fatalf("the approved notice stands after it was recorded: %v", notice)
	}
}

// A phone sees its member's workers only in its open view, so it learns them there and leases each worker's notice
// prefix at its next resync, re-judged at the state then: a request's notice under the worker wakes it. A worker of
// another member's shown in the same view is no target of the phone's.
func TestDirectoryPhoneLeasesItsMembersWorkersFromItsView(t *testing.T) {
	env := newTestDecideEnv(t)
	approverDevice := env.approverPhone()
	surrogate, phone := env.phone(approverDevice)
	workerWriter := env.world.memberWriter(env.approverMember)
	otherMember := sidecar.NewId()
	otherWriter := env.world.memberWriter(otherMember)
	env.world.publish()
	nowMillis := env.world.clock.Now().UnixMilli()
	workerWriter.announce(testWorkerItem(workerWriter.sidecarId, &env.approverMember, sidecar.NewId(), 1, nowMillis))
	otherWriter.announce(testWorkerItem(otherWriter.sidecarId, &otherMember, sidecar.NewId(), 1, nowMillis))
	workerPrefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{SidecarId: workerWriter.sidecarId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	otherPrefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{SidecarId: otherWriter.sidecarId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	testPhoneResync(t, phone)
	if slices.Contains(phone.Leased(), workerPrefix) {
		t.Fatal("a worker's prefix leased before any view showed it")
	}
	view, err := approverDevice.client.View(&sidecar.DirectoryViewArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if coverage := view.Coverage(); !coverage.Complete {
		t.Fatalf("the view's coverage %+v", coverage)
	}
	view.Close()
	testPhoneResync(t, phone)
	leased := phone.Leased()
	if !slices.Contains(leased, workerPrefix) || slices.Contains(leased, otherPrefix) {
		t.Fatalf("the phone leases %v after its view", leased)
	}
	before := len(surrogate.Wakes())
	notice := &protocol.DirectoryNotice{
		RequestId:          sidecar.NewId().Bytes(),
		RequesterSidecarId: env.requester.writer.sidecarId.Bytes(),
		EntrySeq:           1,
		NotAfterMillis:     nowMillis + time.Hour.Milliseconds(),
		State:              uint32(sidecar.DirectoryNoticeStatePending),
	}
	testPutNotice(t, env.testRequestsEnv, env.requester, workerPrefix+hex.EncodeToString(notice.GetRequestId()), notice)
	wakes := surrogate.Wakes()
	if len(wakes) != before+1 {
		t.Fatalf("%d wakes for a notice under the worker", len(wakes)-before)
	}
	testPhoneWakeNamesNothing(t, wakes[len(wakes)-1], env.world.directoryId, workerWriter.sidecarId)
}
