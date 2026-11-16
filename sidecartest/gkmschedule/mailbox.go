package gkmschedule

// FS-23's mailbox case on T2 and T3 (KEYS-M7-01; I-15, D-KEYS-8, D-KEYS-17, §10.5's depositor rule, §10.6's drop keys
// duty, §15.7's readers row; owner decision 357, plan-KEYS-drop-key-lifetime): a member's mailbox, owner-bound by the
// world's member and read by two of its consented devices, and its receiver, a tag:mail mail indexer that only
// deposits, on the real subset. Each schedule runs with evs's gate off, which here means with no evs at all: what
// refuses is the receiver's own depositor rule.
//
//	receiver  it takes generation 1's drop key, and a deposit's key it seals there opens for each consented device by
//	          that generation's drop key pair; it follows a writer's rotation to generation 2's, under which the older
//	          deposit's key does not open; every read route refuses its deposit scope, and a read scope it was never
//	          given; and no generation is ever delivered to it
//	removal   after a consented device's revocation the receiver refuses the newest drop key gkm serves, unexpired,
//	          until a writer's REMOVE rotation covers the shrink, and a server replaying an older one is refused
//	          before and after; the revoked device opens none of the new generation's deposits
//	renewal   the readers offline as the key nears its end: from 7 days before drop_not_after_ms the receiver's reads
//	          hint pending to the writers, at most once an hour, while it deposits on; a writer back with nothing to
//	          ingest renews the key at its resync by a SCHEDULE rotation, with no write of its own, and the receiver
//	          moves to it without a lapse
//	lapse     the readers offline past the key's life: from drop_not_after_ms the receiver refuses the key gkm still
//	          serves and it still holds, waiting, with no alarm, while its reads go on hinting the writers; a writer
//	          back with nothing to ingest renews it as above, and the receiver deposits again at the new generation,
//	          which the readers open
//
// A deposit here is its key's slot alone, sealed as EvsRepo.Deposit seals it. What the receiver answers its senders
// through all of this, 250 or 451 4.3.0, is the session's, which sidecartest's fs_keys_mailbox_test.go runs on T2
// over evs's engine with this world's keys.

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A member's mailbox (§15.7): owner-bound by the world's member; a, its creator and admin, and b, consented devices
// of the owner that read and write it; and r, its receiver, a tag:mail mail indexer: a tagged sidecar that only
// deposits.
func NewFsKeysMailboxWorld(t FsKeysT, newWorld FsKeysNewWorld) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice) {
	world := newWorld(protocol.RepoKind_REPO_KIND_MAILBOX)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	receiver := world.AddAgent("r")
	world.Grant(true, a, b)
	world.Consent(a, b)
	world.Admin(a)
	world.Depositor(receiver)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	return world, a, b, receiver
}

// One deposit's key slot as the receiver seals it (EvsRepo.Deposit): a fresh object key, HPKE-XWing to the drop key
// of the generation the depositor rule gave it.
type FsKeysMailboxDeposit struct {
	Generation uint64
	wrapped    []byte
}

// The receiver seals a deposit's key to the drop key its depositor rule gives it now, which must be generation's, as
// gkm holds that generation's GenRotate.
func (self *FsKeysWorld) MailboxDeposit(receiver *FsKeysDevice, generation uint64) *FsKeysMailboxDeposit {
	self.t.Helper()
	dropKey, err := receiver.Client.DropKey(self.Ctx, self.RepoId)
	if err != nil {
		self.t.Fatalf("%s's drop key: %v", receiver.Label, err)
	}
	if dropKey.Generation != generation || dropKey.RepoId != self.RepoId || dropKey.GroupId != self.GroupId {
		self.t.Fatalf("%s's drop key is generation %d's, not %d's", receiver.Label, dropKey.Generation, generation)
	}
	rotate := self.Generation(generation).Rotate
	if !bytes.Equal(dropKey.PublicKey, rotate.GetDropPublicKey()) || !bytes.Equal(dropKey.Commitment, rotate.GetCommitment()) ||
		dropKey.NotAfter.UnixMilli() != rotate.GetDropNotAfterMs() {
		self.t.Fatalf("%s's drop key is not gen/%d's", receiver.Label, generation)
	}
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(dropKey.PublicKey)
	if err != nil {
		self.t.Fatalf("gen/%d's drop key: %v", generation, err)
	}
	wrapped, err := sidecar.EvsWrapDepositKey(publicKey, self.RepoId, dropKey.Generation, sidecar.NewEvsObjectKey())
	if err != nil {
		self.t.Fatal(err)
	}
	return &FsKeysMailboxDeposit{Generation: dropKey.Generation, wrapped: wrapped}
}

// Whether device opens deposit's key by the drop key pair of generation, which it reaches by its own keys: false
// when it holds no key of that generation.
func (self *FsKeysWorld) OpensMailboxDeposit(device *FsKeysDevice, generation uint64, deposit *FsKeysMailboxDeposit) bool {
	self.t.Helper()
	key, err := device.Client.RepoKey(self.Ctx, self.RepoId, generation)
	if err != nil {
		return false
	}
	privateKey, err := key.DropKeyPair()
	if err != nil {
		self.t.Fatal(err)
	}
	_, err = sidecar.EvsUnwrapDepositKey(privateKey, self.RepoId, deposit.Generation, deposit.wrapped)
	return err == nil
}

// Every route that reads the group, its epochs, generations, group-info, deliveries or the member's recovery wraps
// refuses the receiver, under its own deposit scope and under a read scope it was never given; the drop-key route
// alone answers its deposit scope.
func (self *FsKeysWorld) RefusesReceiver(receiver *FsKeysDevice, generation uint64) {
	self.t.Helper()
	repoId := sidecar.EvsKeyId(self.RepoId)
	group := "/gkm/groups/" + sidecar.EvsKeyId(self.GroupId)
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: group},
		{method: http.MethodGet, path: "/gkm/repos/" + repoId + "/forms"},
		{method: http.MethodGet, path: group + "/epochs?after=0"},
		{method: http.MethodGet, path: group + "/gen?since=0"},
		{method: http.MethodGet, path: group + "/group-info"},
		{method: http.MethodGet, path: group + "/wraps/" + strconv.FormatUint(generation, 10) + "?recipient=" + fsKeysRecipient(receiver.SidecarId())},
		{method: http.MethodGet, path: "/gkm/recovery/" + sidecar.EvsKeyId(self.MemberId) + "/wraps"},
	}
	depositScope := "repo:" + self.RepoId.String() + ":deposit"
	for _, scope := range []string{depositScope, "repo:" + self.RepoId.String() + ":r"} {
		for _, route := range routes {
			status := self.RawStatus(receiver, route.method, route.path, nil, scope)
			if status != http.StatusForbidden && status != http.StatusUnauthorized {
				self.t.Errorf("%s %s under %s: %d", route.method, route.path, scope, status)
			}
		}
	}
	// a deposit scope reaches no route of the caller's own reads either (QD-177)
	if status := self.RawStatus(receiver, http.MethodGet, "/gkm/welcomes", nil, depositScope); status != http.StatusForbidden && status != http.StatusUnauthorized {
		self.t.Errorf("GET /gkm/welcomes under the receiver's deposit scope: %d", status)
	}
	if status := self.RawStatus(receiver, http.MethodGet, "/gkm/repos/"+repoId+"/drop-key?since=0", nil, depositScope); status != http.StatusOK {
		self.t.Errorf("the drop-key route under the receiver's deposit scope: %d", status)
	}
	for g := uint64(1); g <= uint64(self.GenerationCount()); g += 1 {
		if self.WrapRecipients(g)[receiver.SidecarId()] {
			self.t.Errorf("a ReaderWrap of generation %d to %s", g, receiver.Label)
		}
	}
}

// How many pending hints naming the world's group device was told.
func (self *FsKeysWorld) PendingHintCount(device *FsKeysDevice) int {
	self.t.Helper()
	count := 0
	for _, hint := range self.Hints(device) {
		if self.pendingHint(hint) {
			count += 1
		}
	}
	return count
}

// The receiver's drop key, read through gkm, after which every hint the read queued has been sent.
func (self *FsKeysWorld) receiverDropKey(receiver *FsKeysDevice) (*sidecar.GkmDropKey, error) {
	self.t.Helper()
	dropKey, err := receiver.Client.DropKey(self.Ctx, self.RepoId)
	if hintErr := self.Engine.AwaitHints(self.Ctx); hintErr != nil {
		self.t.Fatal(hintErr)
	}
	return dropKey, err
}

// The device comes back online: it takes the newest state, as its log applier catches up on reconnecting, and runs
// its resync's work on the repo with nothing of its own to write: catch-up, its due self-update and the drop key's
// renewal (GkmGroupClient.AttachHints' resync).
func (self *FsKeysWorld) BackOnline(device *FsKeysDevice) {
	self.t.Helper()
	device.Offline = false
	device.Take(self.Log.Tip())
	self.Again(device.Label+"'s catch-up", func() error { return device.Client.SyncRepo(self.Ctx, self.RepoId) })
	self.Again(device.Label+"'s self-update", func() error { return device.Client.RunSelfUpdate(self.Ctx, self.RepoId) })
	self.Again(device.Label+"'s drop key renewal", func() error { return device.Client.RenewDropKey(self.Ctx, self.RepoId) })
}

// Fails the schedule unless generation is a SCHEDULE rotation signed by signer, whose drop key lives DropKeyLifetime
// from its time.
func (self *FsKeysWorld) checkRenewal(generation uint64, signer *FsKeysDevice) {
	self.t.Helper()
	renewal := self.Generation(generation)
	rotate := renewal.Rotate
	lifetime := sidecar.DefaultGkmSettings().DropKeyLifetime
	if sidecar.GkmCause(rotate.GetCause()) != sidecar.GkmCauseSchedule || renewal.SignerId != signer.SidecarId() ||
		len(rotate.GetDropPublicKey()) == 0 || rotate.GetDropNotAfterMs() != rotate.GetTimeMs()+lifetime.Milliseconds() {
		self.t.Fatalf("generation %d is no renewal by %s: cause %d", generation, signer.Label, rotate.GetCause())
	}
}

// FS-23's mailbox case: the receiver takes generation 1's drop key, and a deposit it seals there opens for both
// consented devices; a writer's rotation moves it to generation 2's, and the first deposit's key does not open under
// generation 2's pair; every read route refuses it, and nothing is delivered to it.
func FsKeysScheduleMailboxReceiver(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, receiver := NewFsKeysMailboxWorld(t, newWorld)
	first := world.MailboxDeposit(receiver, 1)
	for _, reader := range []*FsKeysDevice{a, b} {
		if !world.OpensMailboxDeposit(reader, 1, first) {
			t.Errorf("%s does not open the first deposit", reader.Label)
		}
	}
	world.RefusesReceiver(receiver, 1)

	// b rotates; the receiver follows, and its next deposit opens only under generation 2's pair
	world.Clock.Advance(time.Minute)
	if key, err := b.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("b's rotation: %v", err)
	}
	second := world.MailboxDeposit(receiver, 2)
	if _, err := a.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	for _, reader := range []*FsKeysDevice{a, b} {
		if !world.OpensMailboxDeposit(reader, 2, second) {
			t.Errorf("%s does not open the deposit at generation 2", reader.Label)
		}
		if world.OpensMailboxDeposit(reader, 2, first) || world.OpensMailboxDeposit(reader, 1, second) {
			t.Errorf("a deposit opened under another generation's drop key")
		}
	}
	world.RefusesReceiver(receiver, 2)
	if len(receiver.Alarms) != 0 {
		t.Errorf("the receiver alarmed: %+v", receiver.Alarms[0])
	}
}

// FS-23's depositor check in the mailbox, with evs's gate off: after b's revocation, gkm's newest drop key, generation
// 2's and unexpired, does not cover the shrink the receiver's own state shows, and it seals nothing to it; nor to an
// older one a replaying server serves; once a's REMOVE rotation stands it takes generation 3's, below which a replay
// is refused, and b, revoked, opens none of generation 3's deposits.
func FsKeysScheduleMailboxReceiverAfterARemoval(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, receiver := NewFsKeysMailboxWorld(t, newWorld)
	world.Clock.Advance(time.Minute)
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	world.MailboxDeposit(receiver, 2)
	// what a replaying server keeps: the generations gkm served before the removal
	before := []*bridge.Signed{}
	for generation := uint64(1); generation <= 2; generation += 1 {
		before = append(before, world.Generation(generation).Signed)
	}
	replay := fsKeysDropKeyReplay(t, before)

	world.Revoke(b)
	world.Advance()
	if _, err := receiver.Client.DropKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("gkm's unexpired generation 2 after the removal: %v", err)
	}
	receiver.Transport.Respond = replay
	if _, err := receiver.Client.DropKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a replayed older drop key after the removal: %v", err)
	}
	receiver.Transport.Respond = nil

	if key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Generation() != 3 {
		t.Fatalf("a's REMOVE rotation: %v", err)
	}
	if rotate := world.Generation(3).Rotate; sidecar.GkmCause(rotate.GetCause()) != sidecar.GkmCauseRemove {
		t.Fatalf("generation 3's cause: %d", rotate.GetCause())
	}
	third := world.MailboxDeposit(receiver, 3)
	if !world.OpensMailboxDeposit(a, 3, third) {
		t.Errorf("a does not open the deposit at generation 3")
	}
	if reach := world.RemovedReach(b); 3 <= reach {
		t.Errorf("revoked b reaches generation %d", reach)
	}
	if world.OpensMailboxDeposit(b, 3, third) {
		t.Errorf("revoked b opens the deposit at generation 3")
	}
	if len(receiver.Alarms) != 0 {
		t.Errorf("the receiver alarmed: %+v", receiver.Alarms[0])
	}

	// a replay below the receiver's pin is a rollback: alarmed as a fork, after which it deposits nothing, gkm's
	// honest answer included, until the chain extends its pin
	receiver.Transport.Respond = replay
	if _, err := receiver.Client.DropKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Errorf("a replayed drop key below the receiver's pin: %v", err)
	}
	receiver.Transport.Respond = nil
	if len(receiver.Alarms) != 1 || receiver.Alarms[0].Kind != sidecar.GkmAlarmHead || receiver.Alarms[0].Generation != 3 {
		t.Errorf("the rollback's alarm: %+v", receiver.Alarms)
	}
	if _, err := receiver.Client.DropKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Errorf("a deposit at the forked pin: %v", err)
	}
	world.Clock.Advance(time.Minute)
	if key, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 4 {
		t.Fatalf("a's rotation past the forked pin: %v", err)
	}
	fourth := world.MailboxDeposit(receiver, 4)
	if !world.OpensMailboxDeposit(a, 4, fourth) {
		t.Errorf("a does not open the deposit at generation 4")
	}
}

// A server that answers the drop-key route from generations it kept, after the since asked; nil for any other
// request, which goes on to gkm.
func fsKeysDropKeyReplay(t FsKeysT, kept []*bridge.Signed) func(request *http.Request) *http.Response {
	return func(request *http.Request) *http.Response {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/drop-key") {
			return nil
		}
		since, err := strconv.ParseUint(request.URL.Query().Get("since"), 10, 64)
		if err != nil {
			t.Fatalf("a drop-key read's since: %v", err)
		}
		reply := &protocol.GkmGenerationsReply{}
		if since < uint64(len(kept)) {
			reply.Generations = kept[since:]
		}
		return FsKeysAnswer(reply)
	}
}

// The drop-key answer's renewal (owner decision 357; §10.6's drop keys duty): both readers are offline as the drop key
// nears its end. With 8 days left the receiver's read hints nothing; with under 7 it hints pending to both writers,
// a second read within the hour nothing more, and a read an hour on hints again, while the receiver deposits all the
// while. a, back with nothing to ingest, renews the key at its resync by a SCHEDULE rotation, the receiver moves to it
// with no lapse, and b, back later, opens the new generation's deposits.
func FsKeysScheduleMailboxRenewal(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, receiver := NewFsKeysMailboxWorld(t, newWorld)
	first := world.MailboxDeposit(receiver, 1)
	notAfter := time.UnixMilli(world.Generation(1).Rotate.GetDropNotAfterMs())
	renewBefore := sidecar.DefaultGkmSettings().DropKeyRenewBefore
	a.Offline = true
	b.Offline = true
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	aHints, bHints := world.PendingHintCount(a), world.PendingHintCount(b)

	world.Clock.AdvanceTo(notAfter.Add(-renewBefore - 24*time.Hour))
	if dropKey, err := world.receiverDropKey(receiver); err != nil || dropKey.Generation != 1 {
		t.Fatalf("the drop key with 8 days left: %v", err)
	}
	if world.PendingHintCount(a) != aHints || world.PendingHintCount(b) != bHints {
		t.Errorf("a drop key with 8 days left hinted the writers")
	}
	world.Clock.AdvanceTo(notAfter.Add(-renewBefore + time.Hour))
	if dropKey, err := world.receiverDropKey(receiver); err != nil || dropKey.Generation != 1 {
		t.Fatalf("the drop key with under 7 days left: %v", err)
	}
	if world.PendingHintCount(a) != aHints+1 || world.PendingHintCount(b) != bHints+1 {
		t.Errorf("the writers' pending hints with under 7 days left: %d, %d", world.PendingHintCount(a)-aHints, world.PendingHintCount(b)-bHints)
	}
	world.Clock.Advance(time.Hour - time.Minute)
	world.MailboxDeposit(receiver, 1)
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	if world.PendingHintCount(a) != aHints+1 {
		t.Errorf("a second read within the hour hinted again")
	}
	world.Clock.Advance(time.Minute)
	if _, err := world.receiverDropKey(receiver); err != nil {
		t.Fatal(err)
	}
	if world.PendingHintCount(a) != aHints+2 || world.PendingHintCount(b) != bHints+2 {
		t.Errorf("a read an hour on did not hint again")
	}

	// a is back with nothing to ingest: its resync renews, and the receiver moves to the renewal without a lapse
	world.BackOnline(a)
	if world.GenerationCount() != 2 {
		t.Fatalf("a's resync renewed nothing: %d generations", world.GenerationCount())
	}
	world.checkRenewal(2, a)
	second := world.MailboxDeposit(receiver, 2)
	if !world.OpensMailboxDeposit(a, 2, second) || !world.OpensMailboxDeposit(a, 1, first) {
		t.Errorf("a does not open the deposits")
	}
	world.BackOnline(b)
	if key, err := b.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("b's newest generation once back: %v", err)
	}
	if !world.OpensMailboxDeposit(b, 2, second) {
		t.Errorf("b does not open the renewal's deposit")
	}
	if 2 < world.GenerationCount() {
		t.Errorf("b's resync renewed a key with 90 days left")
	}
	if len(receiver.Alarms) != 0 {
		t.Errorf("the receiver alarmed: %+v", receiver.Alarms[0])
	}
}

// The drop-key answer's lapse (owner decision 357; D-KEYS-8): both readers stay offline past the drop key's life. The
// receiver deposits until drop_not_after_ms; from then it refuses the key, which gkm still serves and it still holds,
// with gkm reachable and with gkm down, raising no alarm, while its reads go on hinting the writers, a day on too. a,
// back with nothing to ingest, renews by a SCHEDULE rotation at its resync, and the receiver deposits again at
// generation 2, which a and, once back, b open.
func FsKeysScheduleMailboxReadersOffline(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, receiver := NewFsKeysMailboxWorld(t, newWorld)
	world.MailboxDeposit(receiver, 1)
	notAfter := time.UnixMilli(world.Generation(1).Rotate.GetDropNotAfterMs())
	a.Offline = true
	b.Offline = true

	world.Clock.AdvanceTo(notAfter.Add(-time.Millisecond))
	world.MailboxDeposit(receiver, 1)
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	aHints := world.PendingHintCount(a)
	world.Clock.AdvanceTo(notAfter.Add(time.Hour))
	if _, err := world.receiverDropKey(receiver); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a lapsed drop key: %v", err)
	}
	if world.PendingHintCount(a) != aHints+1 {
		t.Errorf("a read of the lapsed key did not hint the writers")
	}
	// with gkm down too it holds nothing it may seal to
	receiver.Transport.Before = func(request *http.Request) FsKeysFault { return FsKeysFaultFailBefore }
	if _, err := receiver.Client.DropKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("the lapsed key it holds with gkm down: %v", err)
	}
	receiver.Transport.Before = nil
	world.Clock.Advance(24 * time.Hour)
	if _, err := world.receiverDropKey(receiver); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a lapsed drop key a day on: %v", err)
	}
	if world.PendingHintCount(a) != aHints+2 {
		t.Errorf("a read a day on did not hint the writers again")
	}
	if world.GenerationCount() != 1 || len(receiver.Alarms) != 0 {
		t.Fatalf("while the readers are away: %d generations, %d alarms", world.GenerationCount(), len(receiver.Alarms))
	}

	// a is back with nothing to ingest: its resync renews, and deposits go on at the renewal
	world.BackOnline(a)
	world.checkRenewal(2, a)
	deposit := world.MailboxDeposit(receiver, 2)
	if !world.OpensMailboxDeposit(a, 2, deposit) {
		t.Errorf("a does not open the deposit after the renewal")
	}
	world.BackOnline(b)
	if !world.OpensMailboxDeposit(b, 2, deposit) {
		t.Errorf("b does not open the deposit after the renewal")
	}
	if len(receiver.Alarms) != 0 {
		t.Errorf("the receiver alarmed: %+v", receiver.Alarms[0])
	}
}
