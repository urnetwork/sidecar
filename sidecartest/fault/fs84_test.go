//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-84's M6 case on T2 (§22.8; §16.11's writers, repo, revoke and repair rows, QD-105, QD-166, FI-25, I-EVS-14,
// I-EVS-16; RECORD-M6-25), and the authorship world FS-84, FS-99 and FS-101 share: the directory world
// (fs85_test.go) with surrogate writers that seal with their own key and chain and push their stream themselves, so
// a schedule writes what an honest daemon never would, and a ledger of what each schedule forged.
//
//	writers   a run item signed by another sidecar, pushed in another's stream, by a sidecar parked for consent,
//	          parked by a cascade, revoked, reaped or suspended at its pin, renewed past its push's time by more than
//	          the skew, naming another member, forked below its writer's last seq, or at a pin over 4,096 positions
//	          old: every reader ignores it and alarms naming its signer, while a rightful item written beside it shows
//	repos     a repo announcement by a non-admin, by an admin for an owner-bound repo, for a mailcfg repo and for the
//	          directory: ignored with an alarm; the repo admin's announcement and the owner's own both show
//	ids       two writers on one run id are two items, each under its own writer, with an id_reuse alarm (QD-105); a
//	          withdrawal hides its writer's item at once (QD-166)
//	notices   a notice rewritten by a non-approver activates nothing and alarms, the approver's decision then reaching
//	          the requester; a pending notice another member removes is restored by its requester's upkeep, the
//	          request entry never lost
//	erasure   a non-admin's ERASE is refused at evs before any slot changes; a non-admin's erasure request erases
//	          nothing and alarms on the runner's device, and the repo admin's revoke is completed by the runner over
//	          exactly the copies naming its repo; a directory admin's moderation is accepted, with a moderation alarm
//	          on the member's devices and on no other's
//	expiry    a run item is active up to its expires_millis and never past it, a repo item past any age
//
// After every step, FI-25 as these cases hold it (fi25Shown): every item an honest reader shows was signed by the
// sidecar it names, in that sidecar's own stream, by a signer the authorization state has standing at the push's pin
// and now, naming its own member; a run or worker item at a pin within 4,096 positions, renewed within the skew of
// its push and not active past its expiry; a repo item by a signer holding the right at its push's pin by the
// ledger of rights the schedule keeps, never for a kind readers ignore; no version a schedule forged shows; and no
// reader counts an ERASE the schedule made from outside the directory's admins. The oracle judges from the fakes'
// state and the schedule's ledger, not from the client's rules, and TestFs84Fi25FailsAReaderWithoutTheRules feeds it
// what a reader without each rule would show.
//
// Not here: cards and their repair (the card case at the later of M6-out and M10-out), a repo announcement written
// at creation and the private marker's padding (RECORD-M6-15's unit tests hold them; the gate's create path is not
// in this world), the cleanup of a revoked sidecar's notices (FS-87's case), and CLOSURE, closure uploads and slot
// deletion, which sidecartest's streams do not serve (FS-99's T3 run).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs84M6 = Register("FS-84", "entries", []Tier{TierT2}, Fs84DirectoryWriters)

// A surrogate writer: an admitted device that is never opened, sealing and pushing by hand.
type dirForger struct {
	*dirDevice
	env     *sidecar.RecordSealEnv
	counter uint64
}

// One version a schedule forged, as it was pushed.
type dirBreach struct {
	label      string
	item       *protocol.Announcement
	signerId   sidecar.Id
	streamId   sidecar.Id
	pin        *bridge.AuthPin
	pushMillis int64
}

// A sidecar's right on a repo, by positions: from, and until when it ended, 0 while it stands.
type dirRight struct {
	from        uint64
	until       uint64
	untilMillis int64
}

// The directory world with its forgers and the ledger FI-25 is judged by.
type authorWorld struct {
	*dirWorld
	forgers map[string]*dirForger
	// an honest member device that only reads
	reader   *dirDevice
	breaches []*dirBreach
	rights   map[sidecar.Id]map[sidecar.Id]*dirRight
	// a compromise revocation's since_n, by signer
	compromised map[sidecar.Id]uint64
	// entries an ERASE from outside the directory's admins named
	uncounted []sidecar.Id
	// format 2's files as the cards ref held them (fs84_card_test.go), nil until a schedule writes one
	fileLedger *fileLedger
}

func newAuthorWorld(ctx context.Context) (*authorWorld, error) {
	base, err := newDirWorld(ctx)
	if err != nil {
		return nil, err
	}
	world := &authorWorld{
		dirWorld:    base,
		forgers:     map[string]*dirForger{},
		rights:      map[sidecar.Id]map[sidecar.Id]*dirRight{base.repoId: {base.approver.sidecarId: {from: 1}}},
		compromised: map[sidecar.Id]uint64{},
	}
	if world.reader, err = world.member(ctx, "reader F", sidecar.NewId()); err != nil {
		return nil, err
	}
	return world, nil
}

// A new member device, admitted at the next position and opened.
func (self *authorWorld) member(ctx context.Context, name string, memberId sidecar.Id) (*dirDevice, error) {
	device, err := self.device(name, memberId, false)
	if err != nil {
		return nil, err
	}
	self.publish()
	if err := self.open(ctx, device); err != nil {
		return nil, err
	}
	return device, nil
}

// A forger admitted as a member device of memberId, in the fixtures and not yet published.
func (self *authorWorld) forger(name string, memberId sidecar.Id) (*dirForger, error) {
	device, err := self.device(name, memberId, false)
	if err != nil {
		return nil, err
	}
	store, err := sidecartest.NewFakeStore().Root().Directory("forger", "record")
	if err != nil {
		return nil, err
	}
	forger := &dirForger{dirDevice: device}
	forger.env = &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, device.sidecarId), Sign: device.sign}
	self.forgers[name] = forger
	return forger, nil
}

// Seals item as forger's announce entry and pushes it in stream's own stream, forger's when stream is nil, at pin,
// the tip when pin is nil.
func (self *authorWorld) announceIn(ctx context.Context, forger *dirForger, item *protocol.Announcement, stream *dirForger, pin *bridge.AuthPin) error {
	return self.seal(ctx, forger, stream, pin, &sidecar.RecordSealArgs{Kind: sidecar.RecordKindAnnounce, Source: sidecar.RecordSourceObserved, Body: item})
}

// A coordination note of forger's in its own stream.
func (self *authorWorld) note(ctx context.Context, forger *dirForger, text string) error {
	return self.seal(ctx, forger, nil, nil, &sidecar.RecordSealArgs{
		Kind: sidecar.RecordKindNote, Source: sidecar.RecordSourceAgent, Tainted: true, Body: &protocol.CoordinationBody{Text: text},
	})
}

// Seals args as forger's entry of the directory log, timed now at pin, and pushes it in stream's own stream.
func (self *authorWorld) seal(ctx context.Context, forger *dirForger, stream *dirForger, pin *bridge.AuthPin, args *sidecar.RecordSealArgs) error {
	if stream == nil {
		stream = forger
	}
	if pin == nil {
		pin = self.recordAuth.Tip().Pin()
	}
	args.LogId = self.directoryId
	args.TimeMillis = self.clock.Now().UnixMilli()
	args.PolicyVersion = pin.GetVersion()
	sealed, err := sidecar.RecordSeal(forger.env, args)
	if err != nil {
		return err
	}
	stream.counter += 1
	path, err := sidecar.RecordStreamPath(stream.counter)
	if err != nil {
		return err
	}
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewId(),
		WriterSidecarId: stream.sidecarId,
		SlotId:          sidecar.NewId(),
		AuthPin:         pin,
		SlotRows:        []*sidecar.RecordSlotRow{sealed.SlotRow(0)},
	}
	push.Entries = []*sidecar.RecordStreamEntry{{Path: path, Entry: sealed.EntryBytes(&push.SlotId, 0)}}
	_, err = self.streams.For(stream.sidecarId).Append(ctx, self.directoryId, push)
	return err
}

func (self *authorWorld) announce(ctx context.Context, forger *dirForger, item *protocol.Announcement) error {
	return self.announceIn(ctx, forger, item, nil, nil)
}

// announceIn for a version no reader may count, kept in the ledger under its title.
func (self *authorWorld) breach(ctx context.Context, forger *dirForger, item *protocol.Announcement, stream *dirForger, pin *bridge.AuthPin) error {
	if stream == nil {
		stream = forger
	}
	if pin == nil {
		pin = self.recordAuth.Tip().Pin()
	}
	self.breaches = append(self.breaches, &dirBreach{
		label: item.GetWhat().GetTitle(), item: item, signerId: forger.sidecarId, streamId: stream.sidecarId, pin: pin, pushMillis: self.clock.Now().UnixMilli(),
	})
	return self.announceIn(ctx, forger, item, stream, pin)
}

// A run item of writer's for its member under title: version, renewed at renewedMillis and expiring 90 min on.
func dirRunItem(writer *dirDevice, announcementId sidecar.Id, version uint64, renewedMillis int64, title string) *protocol.Announcement {
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, renewedMillis)
	return &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRun),
		Version:        version,
		StartedMillis:  renewedMillis,
		RenewedMillis:  renewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateActive),
		Who: &protocol.AnnounceWho{
			SidecarId:  writer.sidecarId.Bytes(),
			MemberId:   writer.memberId.Bytes(),
			AgentId:    sidecar.NewId().Bytes(),
			AgentLabel: "builder",
			Harness:    "claude-code",
		},
		What:  &protocol.AnnounceWhat{Title: title, RunId: sidecar.NewId().Bytes()},
		Where: &protocol.AnnounceWhere{Project: "example.org/team/app", Branch: "main"},
	}
}

// A repo item of writer's for repoId of kind under title, offering reader and writer with requests open, padded.
func dirRepoItem(writer *dirDevice, repoId sidecar.Id, kind protocol.RepoKind, version uint64, renewedMillis int64, title string) (*protocol.Announcement, error) {
	announcementId := sidecar.DirectoryRepoAnnouncementId(repoId)
	item := &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRepo),
		Version:        version,
		StartedMillis:  renewedMillis,
		RenewedMillis:  renewedMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateActive),
		Who:            &protocol.AnnounceWho{SidecarId: writer.sidecarId.Bytes(), MemberId: writer.memberId.Bytes()},
		What: &protocol.AnnounceWhat{
			RepoKind: uint32(kind), Requests: uint32(sidecar.DirectoryRequestsOpen), Title: title,
			Roles: []uint32{uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER), uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)},
		},
		Where: &protocol.AnnounceWhere{RepoId: repoId.Bytes()},
	}
	if _, err := sidecar.DirectoryPadRepoAnnouncement(item); err != nil {
		return nil, err
	}
	return item, nil
}

// The alarms device raised for reason naming sidecarId.
func (self *dirDevice) alarmsNaming(reason sidecar.SidecarRecordAlarm, sidecarId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, alarm := range self.alarms {
		if alarm.Reason == reason && alarm.SidecarId != nil && *alarm.SidecarId == sidecarId {
			count += 1
		}
	}
	return count
}

// Every item device's client lists, private markers included.
func (self *dirDevice) items() ([]*sidecar.DirectoryItem, error) {
	return self.client.List(&sidecar.DirectoryFilter{IncludePrivate: true})
}

// The item device shows under title, nil for none.
func (self *dirDevice) shown(title string) (*sidecar.DirectoryItem, error) {
	items, err := self.items()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Announcement.GetWhat().GetTitle() == title {
			return item, nil
		}
	}
	return nil, nil
}

// Syncs device and answers the item it shows under title.
func (self *authorWorld) syncShown(ctx context.Context, device *dirDevice, title string) (*sidecar.DirectoryItem, error) {
	if err := device.client.Sync(ctx); err != nil {
		return nil, err
	}
	return device.shown(title)
}

// FI-25's rule for one item a reader shows, carried in streamId's stream: see the file header. It reads the fakes'
// state and the ledger alone.
func (self *authorWorld) fi25Shown(item *sidecar.DirectoryItem, streamId sidecar.Id) error {
	announcement := item.Announcement
	title := announcement.GetWhat().GetTitle()
	signer := item.SignerSidecarId
	if streamId != signer {
		return fmt.Errorf("FI-25: %q was pushed in %s's stream, not its signer's", title, streamId)
	}
	if sidecar.Id(announcement.GetWho().GetSidecarId()) != signer {
		return fmt.Errorf("FI-25: %q names another sidecar than its signer", title)
	}
	row := self.directoryFixture.Sidecars[signer]
	if row == nil {
		return fmt.Errorf("FI-25: %q is signed by a sidecar no state admits", title)
	}
	if memberId := announcement.GetWho().GetMemberId(); 0 < len(memberId) && (row.MemberId == nil || !bytes.Equal(memberId, row.MemberId.Bytes())) {
		return fmt.Errorf("FI-25: %q names another member than its signer's", title)
	}
	tip := self.directoryAuth.Tip()
	pinVersion := item.PushPin.GetVersion()
	standing, standingErr := tip.SignerStanding(signer, item.PushPin)
	if standingErr == nil && standing != sidecar.DirectoryStandingStanding {
		return fmt.Errorf("FI-25: %q was signed with standing %d at its pin", title, standing)
	}
	if sidecar.DirectoryAnnouncementKind(announcement.GetKind()) != sidecar.DirectoryAnnouncementKindRepo {
		if standingErr != nil {
			return fmt.Errorf("FI-25: %q shows at a pin the state cannot judge: %w", title, standingErr)
		}
		if now, err := tip.SignerStanding(signer, tip.Pin()); err != nil || now != sidecar.DirectoryStandingStanding {
			return fmt.Errorf("FI-25: %q shows for a signer with standing %d now", title, now)
		}
		if pinVersion+uint64(sidecar.DirectoryPinPositionCount) < tip.Pin().GetVersion() {
			return fmt.Errorf("FI-25: %q shows at pin %d, over 4,096 positions before %d", title, pinVersion, tip.Pin().GetVersion())
		}
		if item.PushTimeMillis+sidecar.DirectoryClockSkew.Milliseconds() < announcement.GetRenewedMillis() {
			return fmt.Errorf("FI-25: %q was renewed %d ms past its push", title, announcement.GetRenewedMillis()-item.PushTimeMillis)
		}
		if item.Display == sidecar.DirectoryItemActive && announcement.GetExpiresMillis() <= self.clock.Now().UnixMilli() {
			return fmt.Errorf("FI-25: %q shows active past its expires_millis", title)
		}
		return nil
	}
	repoId := sidecar.Id(announcement.GetWhere().GetRepoId())
	repo := self.directoryFixture.Repos[repoId]
	if repo == nil {
		return fmt.Errorf("FI-25: %q is for a repo no state holds", title)
	}
	switch repo.Kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_DIRECTORY:
		return fmt.Errorf("FI-25: %q announces a repo of a kind readers ignore", title)
	}
	if uint32(repo.Kind) != announcement.GetWhat().GetRepoKind() {
		return fmt.Errorf("FI-25: %q names another kind than its repo's", title)
	}
	if since, ok := self.compromised[signer]; ok && since <= pinVersion {
		return fmt.Errorf("FI-25: %q was signed at %d by a signer compromised since %d", title, pinVersion, since)
	}
	if repo.Kind == protocol.RepoKind_REPO_KIND_VAULT {
		if row.MemberId == nil || repo.OwnerMemberId == nil || *row.MemberId != *repo.OwnerMemberId {
			return fmt.Errorf("FI-25: %q announces an owner-bound repo from no device of its owner", title)
		}
		return nil
	}
	right := self.rights[repoId][signer]
	if right == nil || pinVersion < right.from || (right.until != 0 && right.until <= pinVersion) {
		return fmt.Errorf("FI-25: %q was signed at pin %d by a signer holding no right on its repo there", title, pinVersion)
	}
	// evs bounds a push's pin only by its ref's head pin: a version at an older pin counts within 10 min of the removal
	if right.until != 0 && right.untilMillis+(10*time.Minute).Milliseconds() < item.PushTimeMillis {
		return fmt.Errorf("FI-25: %q was pushed over 10 min after its signer's right ended", title)
	}
	return nil
}

// FI-25 over every opened device, after every step: see the file header.
func (self *authorWorld) checkAuthorship(ctx context.Context) error {
	for _, device := range self.devices {
		if device.client == nil {
			continue
		}
		items, err := device.items()
		if err != nil {
			// a client with no copy yet shows nothing
			continue
		}
		for _, item := range items {
			if err := self.fi25Shown(item, item.SignerSidecarId); err != nil {
				return fmt.Errorf("%s: %w", device.name, err)
			}
			for _, breach := range self.breaches {
				if breach.signerId == item.SignerSidecarId && breach.label == item.Announcement.GetWhat().GetTitle() && breach.item.GetVersion() == item.Announcement.GetVersion() {
					return fmt.Errorf("FI-25: %s shows %q, a version the schedule forged", device.name, breach.label)
				}
			}
		}
		for _, entryId := range self.uncounted {
			if erasure, ok := device.client.ErasureOf(entryId); ok {
				return fmt.Errorf("FI-25: %s counts an ERASE of %s by %s, no directory admin", device.name, entryId, erasure.EraserSidecarId)
			}
		}
	}
	return nil
}

// The world a schedule's steps share, made by its first step.
type authorState struct {
	world *authorWorld
	// what a step leaves for a later one
	ids    map[string]sidecar.Id
	counts map[string]int
}

func authorSchedule(state *authorState, steps []*Step) *Schedule {
	built := append([]*Step{{Actor: "authority", Action: func(ctx context.Context, net *Net) error {
		world, err := newAuthorWorld(ctx)
		if err != nil {
			return err
		}
		state.world = world
		state.ids = map[string]sidecar.Id{}
		state.counts = map[string]int{}
		return nil
	}}}, steps...)
	return &Schedule{
		Steps: built,
		Check: []Invariant{NewInvariant("FI-25/authorship", func(ctx context.Context, oracle *Oracle) error {
			if state.world == nil {
				return nil
			}
			return state.world.checkAuthorship(ctx)
		})},
		Tiers: []Tier{TierT2},
	}
}

func authorStep(state *authorState, actor string, action func(ctx context.Context, world *authorWorld) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		if state.world == nil {
			return errors.New("the authorship world was not set up")
		}
		return action(ctx, state.world)
	}}
}

// One forged run version of FS-84's writers clause.
type fs84Breach struct {
	title string
	alarm sidecar.SidecarRecordAlarm
	// Forges the version as bad, a forger made for this breach and published; honest is the rightful writer.
	forge func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error
}

// A breach by a standing at the pin, set before the push and lifted after where lift is set.
func fs84Standing(title string, alarm sidecar.SidecarRecordAlarm, set func(row *sidecartest.FakeDirectorySidecar, next uint64), lift func(row *sidecartest.FakeDirectorySidecar)) *fs84Breach {
	return &fs84Breach{title: title, alarm: alarm, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error {
		row := world.directoryFixture.Sidecars[bad.sidecarId]
		set(row, world.directoryAuth.Tip().Pin().GetVersion()+1)
		world.publish()
		if err := world.breach(ctx, bad, item, nil, nil); err != nil {
			return err
		}
		if lift != nil {
			lift(row)
			world.publish()
		}
		return nil
	}}
}

// FS-84's forged run versions, the stale pin last since it moves the log 4,097 positions on.
func fs84Breaches() []*fs84Breach {
	return []*fs84Breach{
		{title: "signed by another sidecar", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error {
			item.Who.SidecarId = honest.sidecarId.Bytes()
			item.Who.MemberId = honest.memberId.Bytes()
			return world.breach(ctx, bad, item, nil, nil)
		}},
		{title: "pushed by another sidecar", alarm: sidecar.SidecarRecordAlarmPathRule, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error {
			return world.breach(ctx, bad, item, honest, nil)
		}},
		fs84Standing("parked for consent", sidecar.SidecarRecordAlarmParkedWriter, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.Standing = sidecar.DirectoryStandingUnconsented
		}, nil),
		fs84Standing("parked by a cascade", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.Standing = sidecar.DirectoryStandingParked
		}, nil),
		fs84Standing("revoked", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.RevokedAt = next
		}, nil),
		fs84Standing("reaped", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.RevokedAt = next
			row.Ephemeral = true
		}, nil),
		fs84Standing("suspended", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.SuspendedAt = next
		}, func(row *sidecartest.FakeDirectorySidecar) {
			row.SuspendedAt = 0
		}),
		{title: "renewed past its push by more than the skew", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error {
			item.RenewedMillis = world.clock.Now().UnixMilli() + sidecar.DirectoryClockSkew.Milliseconds() + 1
			item.ExpiresMillis, _ = sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, item.RenewedMillis)
			return world.breach(ctx, bad, item, nil, nil)
		}},
		{title: "naming another member", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error {
			item.Who.MemberId = honest.memberId.Bytes()
			return world.breach(ctx, bad, item, nil, nil)
		}},
		{title: "a pin out of range", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, honest *dirForger, item *protocol.Announcement) error {
			old := world.recordAuth.Tip().Pin()
			for range sidecar.DirectoryPinPositionCount + 1 {
				world.clock.Advance(time.Millisecond)
				world.publish()
			}
			// renewed now, and so live by its times, at a pin past the bound
			item.RenewedMillis = world.clock.Now().UnixMilli()
			item.StartedMillis = item.RenewedMillis
			item.ExpiresMillis, _ = sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, item.RenewedMillis)
			return world.breach(ctx, bad, item, nil, old)
		}},
	}
}

// One step a forged run version: every reader ignores it and alarms once naming its signer, and the rightful
// writer's item written after it shows.
func fs84BreachStep(state *authorState, breach *fs84Breach) *Step {
	return authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
		honest := world.forgers["honest H"]
		bad, err := world.forger("forger of "+breach.title, sidecar.NewId())
		if err != nil {
			return err
		}
		world.publish()
		item := dirRunItem(bad.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), breach.title)
		if err := breach.forge(ctx, world, bad, honest, item); err != nil {
			return err
		}
		twin := "rightful beside " + breach.title
		if err := world.announce(ctx, honest, dirRunItem(honest.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), twin)); err != nil {
			return err
		}
		shown, err := world.syncShown(ctx, world.reader, breach.title)
		if err != nil {
			return err
		}
		if shown != nil {
			return fmt.Errorf("%s: the version shows, signed by %s", breach.title, shown.SignerSidecarId)
		}
		if rightful, err := world.reader.shown(twin); err != nil || rightful == nil || rightful.SignerSidecarId != honest.sidecarId {
			return fmt.Errorf("%s: the rightful item beside it does not show: %v", breach.title, err)
		}
		if count := world.reader.alarmsNaming(breach.alarm, bad.sidecarId); count != 1 {
			return fmt.Errorf("%s: %d %s alarms naming its signer", breach.title, count, breach.alarm)
		}
		if count := world.reader.alarmsNaming(breach.alarm, honest.sidecarId); count != state.honestAlarms(world, breach.alarm) {
			return fmt.Errorf("%s: an alarm names the rightful writer", breach.title)
		}
		// a later view raises nothing again
		if _, err := world.reader.items(); err != nil {
			return err
		}
		if count := world.reader.alarmsNaming(breach.alarm, bad.sidecarId); count != 1 {
			return fmt.Errorf("%s: the alarm was raised again", breach.title)
		}
		return nil
	})
}

// The alarms for reason the reader holds naming the rightful writer, which no breach may add to.
func (self *authorState) honestAlarms(world *authorWorld, reason sidecar.SidecarRecordAlarm) int {
	key := "honest/" + string(reason)
	held, ok := self.counts[key]
	if !ok {
		held = world.reader.alarmsNaming(reason, world.forgers["honest H"].sidecarId)
		self.counts[key] = held
	}
	return held
}

// An ERASE of entryId's copies as sidecarId, moderation its reason.
func (self *authorWorld) eraseAs(ctx context.Context, sidecarId sidecar.Id, entry *sidecar.RecordReadEntry) error {
	erasureId := sidecar.NewId()
	note, err := proto.Marshal(&protocol.ErasureBody{ErasureId: erasureId.Bytes(), EntryIds: [][]byte{entry.EntryId.Bytes()}, Reason: uint32(sidecar.RecordErasureReasonModeration)})
	if err != nil {
		return err
	}
	keys := []*sidecar.RecordSlotKey{}
	for _, held := range entry.Copies {
		keys = append(keys, &sidecar.RecordSlotKey{SlotId: held.SlotId, KeyIndex: held.KeyIndex})
	}
	_, err = self.streams.For(sidecarId).Erase(ctx, self.directoryId, &sidecar.RecordStreamErase{
		PushId: sidecar.NewId(), ErasureId: erasureId, Complete: true, SealedNote: note, Keys: keys,
	})
	return err
}

// The directory's announce entries as device's own record reads them at evs now, and the one whose item is titled
// title, nil for none.
func (self *authorWorld) entryAtEvs(ctx context.Context, device *dirDevice, title string) (*sidecar.RecordReadEntry, []*sidecar.RecordReadEntry, error) {
	reader := device.record.Reader()
	if err := reader.Sync(ctx, self.directoryId); err != nil {
		return nil, nil, err
	}
	entries, _ := reader.EntriesOfKinds(self.directoryId, 0, sidecar.RecordKindAnnounce)
	for _, entry := range entries {
		if entry.State != sidecar.RecordEntryLive || entry.Body == nil {
			continue
		}
		item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body)
		if err == nil && item.GetWhat().GetTitle() == title {
			return entry, entries, nil
		}
	}
	return nil, entries, nil
}

// FS-84's M6 case: see the file header.
func Fs84DirectoryWriters(net *Net) *Schedule {
	return Fs84DirectoryWritersOf(&authorState{})
}

// The case over state, which a test reads the world from once it ran.
func Fs84DirectoryWritersOf(state *authorState) *Schedule {
	steps := []*Step{
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			honest, err := world.forger("honest H", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			if err := world.announce(ctx, honest, dirRunItem(honest.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "the rightful run")); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, world.reader, "the rightful run")
			if err != nil {
				return err
			}
			if shown == nil || shown.Display != sidecar.DirectoryItemActive || shown.SignerSidecarId != honest.sidecarId {
				return fmt.Errorf("the rightful run: %+v", shown)
			}
			return nil
		}),
	}
	breaches := fs84Breaches()
	// every breach but the stale pin, which runs last
	for _, breach := range breaches[:len(breaches)-1] {
		steps = append(steps, fs84BreachStep(state, breach))
	}
	steps = append(steps,
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// a second chain for H's key seals its seq 1 again: a fork below its last, which no reader counts
			honest := world.forgers["honest H"]
			store, err := sidecartest.NewFakeStore().Root().Directory("fork", "record")
			if err != nil {
				return err
			}
			forked := &dirForger{dirDevice: honest.dirDevice}
			forked.env = &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, honest.sidecarId), Sign: honest.sign}
			world.clock.Advance(time.Minute)
			item := dirRunItem(honest.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "a seq not above the last")
			if err := world.breach(ctx, forked, item, honest, nil); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, world.reader, "a seq not above the last")
			if err != nil {
				return err
			}
			if shown != nil {
				return errors.New("a forked version shows")
			}
			if world.reader.alarmsNaming(sidecar.SidecarRecordAlarmChainFork, honest.sidecarId) == 0 {
				return errors.New("a forked version raised no chain_fork alarm")
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// QD-105: two writers on one run id are two items, with an id_reuse alarm; QD-166: a withdrawal hides its
			// writer's item at once and leaves the other's
			first, err := world.forger("writer W1", sidecar.NewId())
			if err != nil {
				return err
			}
			second, err := world.forger("writer W2", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			runId := sidecar.NewId()
			nowMillis := world.clock.Now().UnixMilli()
			if err := world.announce(ctx, first, dirRunItem(first.dirDevice, runId, 1, nowMillis, "the run of W1")); err != nil {
				return err
			}
			if err := world.announce(ctx, second, dirRunItem(second.dirDevice, runId, 1, nowMillis, "the copied id of W2")); err != nil {
				return err
			}
			own, err := world.syncShown(ctx, world.reader, "the run of W1")
			if err != nil {
				return err
			}
			copied, err := world.reader.shown("the copied id of W2")
			if err != nil {
				return err
			}
			if own == nil || copied == nil || own.SignerSidecarId != first.sidecarId || copied.SignerSidecarId != second.sidecarId {
				return fmt.Errorf("two writers on one id: %v, %v", own, copied)
			}
			if world.reader.alarmCount(sidecar.SidecarRecordAlarmIdReuse) == 0 {
				return errors.New("a reused announcement id raised no id_reuse alarm")
			}
			withdrawal := &protocol.Announcement{
				AnnouncementId: runId.Bytes(), Kind: uint32(sidecar.DirectoryAnnouncementKindRun), Version: 2, RenewedMillis: nowMillis,
				State: uint32(sidecar.DirectoryAnnouncementStateWithdrawn),
				Who:   &protocol.AnnounceWho{SidecarId: second.sidecarId.Bytes(), MemberId: second.memberId.Bytes()},
			}
			withdrawal.ExpiresMillis, _ = sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, nowMillis)
			if err := world.announce(ctx, second, withdrawal); err != nil {
				return err
			}
			if own, err = world.syncShown(ctx, world.reader, "the run of W1"); err != nil || own == nil {
				return fmt.Errorf("W2's withdrawal hid W1's item: %v", err)
			}
			if copied, err = world.reader.shown("the copied id of W2"); err != nil || copied != nil {
				return fmt.Errorf("a withdrawn item shows: %v", err)
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// repo items: a non-admin's for P, an admin's for the owner-bound V, one for a mailcfg repo and one for the
			// directory are ignored with an alarm; A's announcement of P and O's of its own vault show
			stranger, err := world.forger("non-admin N", sidecar.NewId())
			if err != nil {
				return err
			}
			vaultAdmin, err := world.forger("vault admin G", sidecar.NewId())
			if err != nil {
				return err
			}
			owner, err := world.forger("vault owner's second device", world.owner.memberId)
			if err != nil {
				return err
			}
			next := world.directoryAuth.Tip().Pin().GetVersion() + 1
			mailcfgId := sidecar.NewId()
			world.directoryFixture.Repos[mailcfgId] = &sidecartest.FakeDirectoryRepo{
				Kind: protocol.RepoKind_REPO_KIND_MAILCFG, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: vaultAdmin.sidecarId, At: next}},
			}
			vault := world.directoryFixture.Repos[world.vaultId]
			vault.Admins = append(vault.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: vaultAdmin.sidecarId, At: next})
			world.directoryFixture.Sidecars[vaultAdmin.sidecarId].ConfigWriter = true
			world.publish()
			nowMillis := world.clock.Now().UnixMilli()
			refused := []struct {
				title  string
				signer *dirForger
				repoId sidecar.Id
				kind   protocol.RepoKind
				alarm  sidecar.SidecarRecordAlarm
			}{
				{title: "a non-admin's repo", signer: stranger, repoId: world.repoId, kind: protocol.RepoKind_REPO_KIND_GENERAL, alarm: sidecar.SidecarRecordAlarmBadEntry},
				{title: "an admin's owner-bound repo", signer: vaultAdmin, repoId: world.vaultId, kind: protocol.RepoKind_REPO_KIND_VAULT, alarm: sidecar.SidecarRecordAlarmBadEntry},
				{title: "a mailcfg repo", signer: vaultAdmin, repoId: mailcfgId, kind: protocol.RepoKind_REPO_KIND_GENERAL, alarm: sidecar.SidecarRecordAlarmBadEntry},
				{title: "the directory itself", signer: vaultAdmin, repoId: world.directoryId, kind: protocol.RepoKind_REPO_KIND_DIRECTORY, alarm: sidecar.SidecarRecordAlarmOverCap},
			}
			for _, c := range refused {
				before := world.reader.alarmsNaming(c.alarm, c.signer.sidecarId)
				item, err := dirRepoItem(c.signer.dirDevice, c.repoId, c.kind, 1, nowMillis, c.title)
				if err != nil {
					return err
				}
				if err := world.breach(ctx, c.signer, item, nil, nil); err != nil {
					return err
				}
				shown, err := world.syncShown(ctx, world.reader, c.title)
				if err != nil {
					return err
				}
				if shown != nil {
					return fmt.Errorf("%s shows", c.title)
				}
				if count := world.reader.alarmsNaming(c.alarm, c.signer.sidecarId); count != before+1 {
					return fmt.Errorf("%s: %d %s alarms naming its signer, %d before", c.title, count, c.alarm, before)
				}
			}
			// the passing twins: the owner's consented device for V, and P's admin through its own client
			ownVault, err := dirRepoItem(owner.dirDevice, world.vaultId, protocol.RepoKind_REPO_KIND_VAULT, 2, nowMillis, "my notes")
			if err != nil {
				return err
			}
			if err := world.announce(ctx, owner, ownVault); err != nil {
				return err
			}
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			if _, err := world.approver.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.repoId, DisplayName: "launch plans", Confirmed: true}); err != nil {
				return err
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "my notes"); err != nil || shown == nil || shown.SignerSidecarId != owner.sidecarId {
				return fmt.Errorf("the owner's own vault item: %v, %v", shown, err)
			}
			if shown, err := world.reader.shown("launch plans"); err != nil || shown == nil || shown.SignerSidecarId != world.approver.sidecarId {
				return fmt.Errorf("the repo admin's item: %v, %v", shown, err)
			}
			return nil
		}),
		authorStep(state, "daemonR", func(ctx context.Context, world *authorWorld) error {
			return world.file(ctx, "read", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, 0)
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// a non-approver rewrites R's notice as decided and approved
			notice, file, err := world.notice(ctx, "read")
			if err != nil || notice == nil {
				return fmt.Errorf("R's notice: %v", err)
			}
			forged := proto.Clone(notice).(*protocol.DirectoryNotice)
			forged.State = uint32(sidecar.DirectoryNoticeStateDecided)
			forged.Outcome = uint32(sidecar.DirectoryOutcomeApproved)
			content, err := proto.MarshalOptions{Deterministic: true}.Marshal(forged)
			if err != nil {
				return err
			}
			stranger := world.forgers["non-admin N"]
			if _, err := world.cards.For(stranger.sidecarId).PutCard(ctx, world.directoryId, &sidecar.DirectoryCardWrite{
				PushId: sidecar.NewId(), Path: world.filed["read"].NoticePath, IfVersion: file.Version, Content: content, AuthPin: world.directoryAuth.Tip().Pin(),
			}); err != nil {
				return err
			}
			return nil
		}),
		authorStep(state, "daemonR", func(ctx context.Context, world *authorWorld) error {
			// it activates nothing at R and alarms
			if err := world.upkeep(ctx, world.requester); err != nil && !errors.Is(err, sidecar.ErrDirectoryReceiptRefused) {
				return err
			}
			requestId := world.filed["read"].RequestId
			approved := slices.ContainsFunc(world.requester.recordedReceipts(), func(receipt *sidecar.DirectoryReceipt) bool {
				return receipt.RequestId == requestId && receipt.Outcome == sidecar.SidecarAccessDecidedApproved
			})
			if approved || world.requester.raisedCount("access_decided/approved/"+requestId.String()) != 0 {
				return fmt.Errorf("a non-approver's rewrite activated: %v", world.requester.raised())
			}
			if world.requester.alarmCount(sidecar.SidecarRecordAlarmPathRule)+world.requester.alarmCount(sidecar.SidecarRecordAlarmBadDecision) == 0 {
				return errors.New("a non-approver's rewrite raised no alarm at the requester")
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// another member removes R's notice; R's upkeep restores it from its request entry, which was never lost
			_, file, err := world.notice(ctx, "read")
			if err != nil || file == nil {
				return fmt.Errorf("R's notice before the removal: %v", err)
			}
			stranger := world.forgers["non-admin N"]
			if err := world.cards.For(stranger.sidecarId).RemoveCard(ctx, world.directoryId, &sidecar.DirectoryCardWrite{
				PushId: sidecar.NewId(), Path: world.filed["read"].NoticePath, IfVersion: file.Version, AuthPin: world.directoryAuth.Tip().Pin(),
			}); err != nil {
				return err
			}
			if notice, _, err := world.notice(ctx, "read"); err != nil || notice != nil {
				return fmt.Errorf("the notice after another member's removal: %v, %v", notice, err)
			}
			if err := world.upkeep(ctx, world.requester); err != nil && !errors.Is(err, sidecar.ErrDirectoryReceiptRefused) {
				return err
			}
			notice, _, err := world.notice(ctx, "read")
			if err != nil || notice == nil {
				return fmt.Errorf("R's upkeep restored no notice: %v", err)
			}
			if sidecar.DirectoryNoticeState(notice.GetState()) != sidecar.DirectoryNoticeStatePending || sidecar.Id(notice.GetRequesterSidecarId()) != world.requester.sidecarId {
				return fmt.Errorf("the restored notice: %v", notice)
			}
			return nil
		}),
		authorStep(state, "daemonA", func(ctx context.Context, world *authorWorld) error {
			// the twin: the approver's own decision reaches R
			view, err := world.request(ctx, world.approver, "read")
			if err != nil {
				return err
			}
			if view.State != sidecar.DirectoryRequestPending || !view.Decidable {
				return fmt.Errorf("A's view of the restored request: %+v", view)
			}
			decided, err := world.decide(ctx, world.approver, "read", true, "welcome")
			if err != nil {
				return err
			}
			if decided.Outcome != sidecar.DirectoryOutcomeApproved {
				return fmt.Errorf("A's approval: %+v", decided)
			}
			if err := world.upkeep(ctx, world.requester); err != nil {
				return err
			}
			if count := world.requester.raisedCount("access_decided/approved/" + world.filed["read"].RequestId.String()); count != 1 {
				return fmt.Errorf("R raised the approver's decision %d times: %v", count, world.requester.raised())
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// a non-admin's ERASE naming the rightful run's slot: refused at evs before any slot changes
			honest := world.forgers["honest H"]
			entry, _, err := world.entryAtEvs(ctx, world.admin, "the rightful run")
			if err != nil || entry == nil || len(entry.Copies) == 0 {
				return fmt.Errorf("the rightful run's entry at evs: %v", err)
			}
			before, err := world.streams.For(world.admin.sidecarId).ReadSlot(ctx, world.directoryId, entry.Copies[0].SlotId)
			if err != nil {
				return err
			}
			err = world.eraseAs(ctx, world.forgers["non-admin N"].sidecarId, entry)
			refusal := &sidecar.RecordStreamRefusal{}
			if !errors.As(err, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
				return fmt.Errorf("a non-admin's ERASE: %v", err)
			}
			after, err := world.streams.For(world.admin.sidecarId).ReadSlot(ctx, world.directoryId, entry.Copies[0].SlotId)
			if err != nil {
				return err
			}
			if len(before.Rows) != len(after.Rows) {
				return fmt.Errorf("a refused ERASE changed a slot: %d rows, then %d", len(before.Rows), len(after.Rows))
			}
			for i, row := range before.Rows {
				if !bytes.Equal(row.Row, after.Rows[i].Row) {
					return errors.New("a refused ERASE changed a slot row")
				}
			}
			if erasures, err := world.streams.For(world.admin.sidecarId).ReadErasures(ctx, world.directoryId, 0); err != nil || len(erasures) != 0 {
				return fmt.Errorf("%d ERASEs after a refused one: %v", len(erasures), err)
			}
			if shown, err := world.syncShown(ctx, world.reader, "the rightful run"); err != nil || shown == nil || shown.SignerSidecarId != honest.sidecarId {
				return fmt.Errorf("the rightful run after a refused ERASE: %v", err)
			}
			return nil
		}),
		authorStep(state, "daemonD", func(ctx context.Context, world *authorWorld) error {
			// the twin: a directory admin's moderation is accepted, alarming the member's devices and no other's
			memberId := sidecar.NewId()
			device, err := world.member(ctx, "member M", memberId)
			if err != nil {
				return err
			}
			sibling, err := world.member(ctx, "member M's second device", memberId)
			if err != nil {
				return err
			}
			if err := device.client.Sync(ctx); err != nil {
				return err
			}
			runId := sidecar.NewId()
			if err := device.client.Runs().Started(&sidecar.DirectoryRunStart{
				RunId: runId, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "notes", AgentLabel: "scribe", Harness: "codex",
				Title: "a run to moderate", Project: "example.org/team/notes", Branch: "main",
			}); err != nil {
				return err
			}
			world.clock.Advance(10 * time.Second)
			if err := device.record.Flush(ctx); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, world.admin, "a run to moderate")
			if err != nil || shown == nil {
				return fmt.Errorf("D does not show M's run: %v", err)
			}
			world.admin.client.BindEraser(world.admin.record.Eraser().Erase)
			announcementId := sidecar.Id(shown.Announcement.GetAnnouncementId())
			sibling.client.BindEraser(sibling.record.Eraser().Erase)
			if err := sibling.client.Sync(ctx); err != nil {
				return err
			}
			if _, err := sibling.client.Moderate(ctx, &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryEraseNotAdmin) {
				return fmt.Errorf("a moderation by no directory admin: %v", err)
			}
			result, err := world.admin.client.Moderate(ctx, &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true})
			if err != nil {
				return err
			}
			if result.Reason != sidecar.RecordErasureReasonModeration || len(result.EntryIds) == 0 {
				return fmt.Errorf("the moderation: %+v", result)
			}
			if err := world.admin.record.Flush(ctx); err != nil {
				return err
			}
			for _, own := range []*dirDevice{device, sibling} {
				for range 2 {
					if err := own.client.Sync(ctx); err != nil {
						return err
					}
				}
				if count := own.alarmsNaming(sidecar.SidecarRecordAlarmModeration, device.sidecarId); count != 1 {
					return fmt.Errorf("%d moderation alarms on %s", count, own.name)
				}
				if shown, err := own.shown("a run to moderate"); err != nil || shown != nil {
					return fmt.Errorf("the moderated item still shows on %s: %v", own.name, err)
				}
			}
			for range 2 {
				if err := world.reader.client.Sync(ctx); err != nil {
					return err
				}
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmModeration, device.sidecarId); count != 0 {
				return fmt.Errorf("%d moderation alarms on another member's device", count)
			}
			if shown, err := world.reader.shown("a run to moderate"); err != nil || shown != nil {
				return fmt.Errorf("the moderated item still shows at a reader: %v", err)
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// a member with no right on P files an erasure request for it: the runner erases nothing and alarms
			stranger, err := world.member(ctx, "stranger S", sidecar.NewId())
			if err != nil {
				return err
			}
			forgedId := sidecar.NewId()
			if _, err := stranger.record.Writer().Append(&sidecar.RecordDraft{
				Kind: sidecar.RecordKindErasureRequest, Source: sidecar.RecordSourceApprover, NoSession: true,
				Body: &protocol.DirectoryErasureRequest{RequestId: forgedId.Bytes(), RepoId: world.repoId.Bytes(), MarkerVersion: 2},
			}); err != nil {
				return err
			}
			if err := stranger.record.Flush(ctx); err != nil {
				return err
			}
			runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
				Client: world.admin.client, Erase: world.admin.record.Eraser().Erase, Random: zeroReader{},
			})
			if err != nil {
				return err
			}
			erasedBefore, err := world.streams.For(world.admin.sidecarId).ReadErasures(ctx, world.directoryId, 0)
			if err != nil {
				return err
			}
			if err := world.admin.client.Sync(ctx); err != nil {
				return err
			}
			pass, err := runner.Pass(ctx)
			if err != nil {
				return err
			}
			if !slices.Contains(pass.Refused, forgedId) || len(pass.Erased) != 0 {
				return fmt.Errorf("the pass over a non-admin's request: %+v", pass)
			}
			if count := world.admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, stranger.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_erasure alarms naming the signer with no right", count)
			}
			if erasures, err := world.streams.For(world.admin.sidecarId).ReadErasures(ctx, world.directoryId, 0); err != nil || len(erasures) != len(erasedBefore) {
				return fmt.Errorf("an ERASE for a refused request: %v", err)
			}
			if shown, err := world.syncShown(ctx, world.reader, "launch plans"); err != nil || shown == nil {
				return fmt.Errorf("P's item after a non-admin's request: %v", err)
			}

			// the twin: A's revoke files a request the runner completes over exactly the copies naming P
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			revocation, err := world.approver.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.repoId, Confirmed: true})
			if err != nil {
				return err
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			for range 2 {
				if err := world.admin.client.Sync(ctx); err != nil {
					return err
				}
				if _, err := runner.Pass(ctx); err != nil {
					return err
				}
				if err := world.admin.record.Flush(ctx); err != nil {
					return err
				}
			}
			if readable, err := world.readableNaming(ctx, world.repoId); err != nil || readable != 0 {
				return fmt.Errorf("%d announce entries naming the revoked repo keep a readable key: %v", readable, err)
			}
			erasures, err := world.streams.For(world.admin.sidecarId).ReadErasures(ctx, world.directoryId, 0)
			if err != nil || len(erasures) <= len(erasedBefore) {
				return fmt.Errorf("no ERASE for the admin's revoke: %v", err)
			}
			for _, erasure := range erasures[len(erasedBefore):] {
				if erasure.ErasureId != revocation.RequestId || erasure.EraserSidecarId != world.admin.sidecarId {
					return fmt.Errorf("an ERASE %s by %s, not the request's by the runner", erasure.ErasureId, erasure.EraserSidecarId)
				}
			}
			// exactly those: the owner's vault item and the rightful run keep their keys
			if entry, _, err := world.entryAtEvs(ctx, world.admin, "my notes"); err != nil || entry == nil {
				return fmt.Errorf("the vault's item was erased with P's: %v", err)
			}
			if shown, err := world.syncShown(ctx, world.reader, "launch plans"); err != nil || shown != nil {
				return fmt.Errorf("the revoked repo's name still shows: %v", err)
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// expiry under skew: a run renewed the skew ahead of its push is active up to its expires_millis and stale
			// at it; the vault's item, a repo's, stays
			ahead, err := world.forger("writer ahead", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			item := dirRunItem(ahead.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli()+sidecar.DirectoryClockSkew.Milliseconds(), "a run ahead by the skew")
			if err := world.announce(ctx, ahead, item); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, world.reader, "a run ahead by the skew")
			if err != nil || shown == nil || shown.Display != sidecar.DirectoryItemActive {
				return fmt.Errorf("a run renewed the skew ahead: %v, %v", shown, err)
			}
			world.clock.AdvanceTo(time.UnixMilli(item.GetExpiresMillis() - 1))
			if shown, err = world.reader.shown("a run ahead by the skew"); err != nil || shown == nil || shown.Display != sidecar.DirectoryItemActive {
				return fmt.Errorf("a millisecond before its expiry: %v, %v", shown, err)
			}
			world.clock.AdvanceTo(time.UnixMilli(item.GetExpiresMillis()))
			if shown, err = world.reader.shown("a run ahead by the skew"); err != nil || shown == nil || shown.Display != sidecar.DirectoryItemStale {
				return fmt.Errorf("at its expiry: %v, %v", shown, err)
			}
			world.clock.Advance(40 * 24 * time.Hour)
			world.publish()
			if shown, err = world.syncShown(ctx, world.reader, "my notes"); err != nil || shown == nil || shown.Display != sidecar.DirectoryItemActive {
				return fmt.Errorf("a repo item 40 days on: %v, %v", shown, err)
			}
			return nil
		}),
		fs84BreachStep(state, breaches[len(breaches)-1]),
	)
	return authorSchedule(state, steps)
}

func TestFs84M6(t *testing.T) {
	RunRow(t, "FS-84", "entries", nil)
}

// FI-25's oracle against a reader without the rules: run to its end, the schedule leaves every forged version at evs,
// and a reader that showed any one of them, as a reader lacking that version's rule would, fails the oracle on the
// rule alone, the ledger of forged titles left out.
func TestFs84Fi25FailsAReaderWithoutTheRules(t *testing.T) {
	ctx := context.Background()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	state := &authorState{}
	schedule := Fs84DirectoryWritersOf(state)
	schedule.Id = "FS-84's entries"
	if result := Run(ctx, schedule, net); result.Err != nil {
		t.Fatal(result)
	}
	world := state.world
	if len(world.breaches) < 14 {
		t.Fatalf("%d forged versions in the ledger", len(world.breaches))
	}
	// the fork is its writer's own signature in its own stream: only the chain tells it, which the record reader holds
	structural := 0
	for _, breach := range world.breaches {
		if breach.label == "a seq not above the last" {
			continue
		}
		shown := &sidecar.DirectoryItem{
			Announcement:    breach.item,
			Display:         sidecar.DirectoryItemActive,
			SignerSidecarId: breach.signerId,
			PushPin:         breach.pin,
			PushTimeMillis:  breach.pushMillis,
		}
		if err := world.fi25Shown(shown, breach.streamId); err == nil {
			t.Errorf("a reader showing %q passes FI-25", breach.label)
		} else {
			structural += 1
		}
	}
	if structural < 13 {
		t.Errorf("%d forged versions judged by rule", structural)
	}
	// and the items the honest reader does show pass it
	items, err := world.reader.items()
	if err != nil || len(items) == 0 {
		t.Fatalf("the reader shows %d items: %v", len(items), err)
	}
	for _, item := range items {
		if err := world.fi25Shown(item, item.SignerSidecarId); err != nil {
			t.Errorf("an honest reader's item: %v", err)
		}
	}
}
