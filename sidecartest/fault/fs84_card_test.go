//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-84's card case on T2 (§22.8; §16.11's ref cards block, its card, path rules and repair rows, D-MCP-28, FI-25,
// I-EVS-14; RECORD-M10-06), in the authorship world (fs84_test.go) once its directory reads format 2, and the format 2
// parts FS-84's, FS-87's, FS-99's and FS-101's later cases share: files put and removed on the cards ref by hand, as
// a writer no honest daemon is would, cards and repo files signed by a chosen key, and a ledger of every version the
// cards ref ever held, read before the store purges a versionless path's replaced content.
//
//	rightful  member H's daemon writes its card through DirectoryClient.WriteCard; every reader folds its run from the
//	          card, no announce entry beside it
//	breaches  at H's path: a card another sidecar signed and pushed, H's own earlier card pushed by another sidecar,
//	          and a removal of the live card by another member. Each is ignored with a path_rule alarm naming its
//	          pusher, readers showing the version they accepted last, still a minute on when the store has purged
//	          that version's content; H's repair then puts its card again at a higher seq, which readers take with no
//	          further alarm (§16.11's repair row)
//	writers   at a forger's own path: a card naming it under another sidecar's signature, and one signed with
//	          another's key; a card from a sidecar parked for consent, parked by a cascade, revoked, reaped or
//	          suspended at its pin; a seq not above the last; a 17th item; an auth pin over 4,096 positions old: each
//	          ignored with its alarm, a rightful card written beside it showing
//	removals  a directory admin's removal of a card is accepted, a moderation alarm on the member's own devices and
//	          on no other's; once a sidecar is revoked any writer removes its card
//	carriers  an announce entry and a card of one run fold to one item, the higher (version, renewed_millis) standing
//	          whichever carrier holds it, and a repo's entry and its r/ file to one item
//	expiry    a run on a card is active up to its expires_millis and never past it
//
// After every step, FI-25 as the authorship world holds it (fs84_test.go's fi25Shown) and, for every item a reader
// shows from a file (fi25File): the cards ref held a version at the item's path whose Signed verifies under its
// signer's identity key, names the path's sidecar or repo and this network and carries the item at the seq shown,
// pushed by its signer or, its bytes being ones the signer pushed, by a directory admin (an erasure's CLOSURE); a
// card within 16 items; a repo file's own pin at or within 4,096 positions before its push's; and no version a
// schedule forged shows. TestFs84CardsFi25FailsAReaderWithoutTheRules feeds the oracle what a reader without each
// rule would show.
//
// Not here: the cards ref on evs's engine (the fake's cards ref keeps plaintext and takes any writer's put, as evs,
// which sees no path, does; fs99_cards_evs.go runs a card's CLOSURE and ERASE on the real engine); a card's padding to
// 2 KiB steps at the binding (RECORD-M10-02's unit tests hold StoredByteCount; no production binding seals one yet);
// phones' views; and the T3 run of this row, which §22.8 puts on T2 alone.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs84Cards = Register("FS-84", "cards", []Tier{TierT2}, Fs84DirectoryCards)

// What the authorship world keeps of format 2: every version the cards ref held, by path, and the files a schedule
// forged.
type fileLedger struct {
	// the cards ref's version the ledger has read through
	through  uint64
	versions map[string][]*sidecar.DirectoryCardFile
	// sha256 of each file content a schedule forged, by path
	forged map[string]map[[sha256.Size]byte]bool
}

// The world's file ledger, made on first use.
func (self *authorWorld) files() *fileLedger {
	if self.fileLedger == nil {
		self.fileLedger = &fileLedger{versions: map[string][]*sidecar.DirectoryCardFile{}, forged: map[string]map[[sha256.Size]byte]bool{}}
	}
	return self.fileLedger
}

// Raises the directory to format 2, as its first format-2 push does at evs (§11.6's format row).
func (self *authorWorld) raiseFormat2() {
	self.cards.RaiseFormat(self.directoryId)
}

// Reads the cards ref's statements the ledger has not seen into it, before the store purges what they replaced.
func (self *authorWorld) observeFiles(ctx context.Context) error {
	ledger := self.files()
	for {
		changes, err := self.cards.For(self.reader.sidecarId).ReadCards(ctx, self.directoryId, ledger.through)
		if err != nil {
			return err
		}
		for _, file := range changes.Files {
			ledger.versions[file.Path] = append(ledger.versions[file.Path], file)
		}
		if changes.ThroughVersion <= ledger.through {
			return nil
		}
		ledger.through = changes.ThroughVersion
		if !changes.More {
			return nil
		}
	}
}

// The cards ref's file at path as the store holds it now: its version, 0 for none or a removal.
func (self *authorWorld) fileVersion(ctx context.Context, path string) (uint64, error) {
	if err := self.observeFiles(ctx); err != nil {
		return 0, err
	}
	versions := self.files().versions[path]
	if len(versions) == 0 || versions[len(versions)-1].Removed {
		return 0, nil
	}
	return versions[len(versions)-1].Version, nil
}

// Puts content at path as pusherId's push declaring pin, the tip when pin is nil, from the version the store holds.
func (self *authorWorld) putFile(ctx context.Context, pusherId sidecar.Id, path string, content []byte, pin *bridge.AuthPin) error {
	if pin == nil {
		pin = self.directoryAuth.Tip().Pin()
	}
	version, err := self.fileVersion(ctx, path)
	if err != nil {
		return err
	}
	if _, err := self.cards.For(pusherId).PutCard(ctx, self.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: path, IfVersion: version, Content: content, AuthPin: pin,
	}); err != nil {
		return err
	}
	return self.observeFiles(ctx)
}

// putFile for a version no reader may count, its bytes kept in the ledger.
func (self *authorWorld) forgeFile(ctx context.Context, pusherId sidecar.Id, path string, content []byte, pin *bridge.AuthPin) error {
	ledger := self.files()
	if ledger.forged[path] == nil {
		ledger.forged[path] = map[[sha256.Size]byte]bool{}
	}
	ledger.forged[path][sha256.Sum256(content)] = true
	return self.putFile(ctx, pusherId, path, content, pin)
}

// Removes path as removerId's push at the tip, from the version the store holds.
func (self *authorWorld) removeFile(ctx context.Context, removerId sidecar.Id, path string) error {
	version, err := self.fileVersion(ctx, path)
	if err != nil {
		return err
	}
	if err := self.cards.For(removerId).RemoveCard(ctx, self.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: path, IfVersion: version, AuthPin: self.directoryAuth.Tip().Pin(),
	}); err != nil {
		return err
	}
	return self.observeFiles(ctx)
}

// body Signed by signer as signedType under purpose directory, naming signerId as its signer, marshaled.
func dirSignedFile(signer *dirDevice, signerId sidecar.Id, signedType bridge.SignedType, body proto.Message) ([]byte, error) {
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	signed, err := signer.sign(sidecar.DirectorySignedPurpose, signedType, bodyBytes, nil)
	if err != nil {
		return nil, err
	}
	signed.SignerId = signerId.Bytes()
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// A card file naming sidecarId at seq and at, the tip when at is nil, holding items, signed by signer under its own
// id: what a writer, honest or not, builds.
func (self *authorWorld) cardContent(signer *dirDevice, sidecarId sidecar.Id, seq uint64, at *bridge.AuthPin, items ...*protocol.Announcement) ([]byte, error) {
	if at == nil {
		at = self.directoryAuth.Tip().Pin()
	}
	return dirSignedFile(signer, signer.sidecarId, bridge.SignedType_SIGNED_DIRECTORY_CARD, &protocol.DirectoryCard{
		NetworkId: self.networkId.Bytes(), SidecarId: sidecarId.Bytes(), Seq: seq, At: at,
		WrittenMillis: self.clock.Now().UnixMilli(), Items: items, Version: 1,
	})
}

// A repo file for repoId at seq and at, the tip when at is nil, holding item, signed by signer.
func (self *authorWorld) repoFileContent(signer *dirDevice, repoId sidecar.Id, seq uint64, at *bridge.AuthPin, item *protocol.Announcement) ([]byte, error) {
	if at == nil {
		at = self.directoryAuth.Tip().Pin()
	}
	return dirSignedFile(signer, signer.sidecarId, bridge.SignedType_SIGNED_DIRECTORY_REPO, &protocol.RepoAnnouncement{
		NetworkId: self.networkId.Bytes(), RepoId: repoId.Bytes(), Seq: seq, At: at, Item: item,
	})
}

// A forged version's ledger row, so that no reader showing its item under shownAs passes: see dirBreach.
func (self *authorWorld) noteForged(item *protocol.Announcement, shownAs sidecar.Id, pin *bridge.AuthPin) {
	if pin == nil {
		pin = self.directoryAuth.Tip().Pin()
	}
	self.breaches = append(self.breaches, &dirBreach{
		label: item.GetWhat().GetTitle(), item: item, signerId: shownAs, streamId: shownAs, pin: pin, pushMillis: self.clock.Now().UnixMilli(),
	})
}

// Whether sidecarId is a directory admin in the fixture now.
func (self *authorWorld) directoryAdmin(sidecarId sidecar.Id) bool {
	for _, admin := range self.directoryFixture.Repos[self.directoryId].Admins {
		if admin.SidecarId == sidecarId {
			return true
		}
	}
	return false
}

// FI-25's rule for one item a reader shows from a card or a repo file: see the file header. It reads the ledger and
// the fakes' state alone.
func (self *authorWorld) fi25File(item *sidecar.DirectoryItem) error {
	announcement := item.Announcement
	title := announcement.GetWhat().GetTitle()
	signer := item.SignerSidecarId
	repoItem := sidecar.DirectoryAnnouncementKind(announcement.GetKind()) == sidecar.DirectoryAnnouncementKindRepo
	path := sidecar.DirectoryCardPath(signer)
	if repoItem {
		path = sidecar.DirectoryRepoPath(sidecar.Id(announcement.GetWhere().GetRepoId()))
	}
	ledger := self.files()
	key := self.recordFixture.IdentityKeys[signer]
	settings := sidecar.DefaultDirectoryCardSettings()
	// the bytes the signer itself pushed at the path, which alone a directory admin's CLOSURE may carry
	own := map[[sha256.Size]byte]bool{}
	for _, file := range ledger.versions[path] {
		if !file.Removed && file.Content != nil && file.SignerSidecarId == signer {
			own[sha256.Sum256(file.Content)] = true
		}
	}
	var last error
	for _, file := range ledger.versions[path] {
		if file.Removed || file.Content == nil {
			continue
		}
		sum := sha256.Sum256(file.Content)
		err := func() error {
			if ledger.forged[path][sum] {
				return fmt.Errorf("FI-25: %q shows from a version the schedule forged", title)
			}
			if file.SignerSidecarId != signer && !(self.directoryAdmin(file.SignerSidecarId) && own[sum]) {
				return fmt.Errorf("FI-25: %q shows from a version %s pushed, not its signer", title, file.SignerSidecarId)
			}
			var signed *bridge.Signed
			var seq uint64
			var held []*protocol.Announcement
			if repoItem {
				stored, err := sidecar.DirectoryDecodeRepoFile(file.Content, settings)
				if err != nil {
					return fmt.Errorf("FI-25: %q shows from a repo file that does not decode: %w", title, err)
				}
				signed, seq, held = stored.Signed, stored.File.GetSeq(), []*protocol.Announcement{stored.File.GetItem()}
				at := stored.File.GetAt().GetVersion()
				if file.AuthPin.GetVersion() < at || settings.PinPositionCount < file.AuthPin.GetVersion()-at {
					return fmt.Errorf("FI-25: %q shows from a repo file whose pin %d is not within 4,096 positions before its push's %d", title, at, file.AuthPin.GetVersion())
				}
				if !bytes.Equal(stored.File.GetNetworkId(), self.networkId.Bytes()) {
					return fmt.Errorf("FI-25: %q shows from a repo file of another network", title)
				}
			} else {
				stored, err := sidecar.DirectoryDecodeCard(file.Content, settings)
				if err != nil {
					return fmt.Errorf("FI-25: %q shows from a card that does not decode: %w", title, err)
				}
				signed, seq, held = stored.Signed, stored.Card.GetSeq(), stored.Card.GetItems()
				if !bytes.Equal(stored.Card.GetSidecarId(), signer.Bytes()) || !bytes.Equal(stored.Card.GetNetworkId(), self.networkId.Bytes()) {
					return fmt.Errorf("FI-25: %q shows from a card naming another sidecar or network", title)
				}
				if settings.ItemCount < len(held) {
					return fmt.Errorf("FI-25: %q shows from a card of %d items", title, len(held))
				}
				if stored.Card.GetAt().GetVersion() != item.PushPin.GetVersion() {
					return fmt.Errorf("FI-25: %q shows at pin %d, not its card's %d", title, item.PushPin.GetVersion(), stored.Card.GetAt().GetVersion())
				}
			}
			if seq != item.Seq {
				return fmt.Errorf("FI-25: %q shows at seq %d, which no version at its path holds", title, item.Seq)
			}
			if !bytes.Equal(signed.GetSignerId(), signer.Bytes()) || len(key) == 0 {
				return fmt.Errorf("FI-25: %q shows from a file another sidecar signed", title)
			}
			signedType := bridge.SignedType_SIGNED_DIRECTORY_CARD
			if repoItem {
				signedType = bridge.SignedType_SIGNED_DIRECTORY_REPO
			}
			if err := bridge.VerifySigned(signed, sidecar.DirectorySignedPurpose, signedType, bridge.SignedKeyAlgEd25519, key); err != nil {
				return fmt.Errorf("FI-25: %q shows from a file whose signature does not verify: %w", title, err)
			}
			for _, each := range held {
				if bytes.Equal(each.GetAnnouncementId(), announcement.GetAnnouncementId()) && each.GetVersion() == announcement.GetVersion() && each.GetRenewedMillis() == announcement.GetRenewedMillis() {
					return nil
				}
			}
			return fmt.Errorf("FI-25: %q shows at seq %d from a file that does not hold it", title, item.Seq)
		}()
		if err == nil {
			return nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("FI-25: %q shows from a file the cards ref never held at its path", title)
	}
	return last
}

// FI-25 over every opened device's items that a file carries, after every step, beside checkAuthorship.
func (self *authorWorld) checkFiles(ctx context.Context) error {
	if self.fileLedger == nil {
		return nil
	}
	if err := self.observeFiles(ctx); err != nil {
		return err
	}
	for _, device := range self.devices {
		if device.client == nil {
			continue
		}
		items, err := device.items()
		if err != nil {
			continue
		}
		for _, item := range items {
			if item.EntryId != (sidecar.Id{}) {
				continue
			}
			if err := self.fi25File(item); err != nil {
				return fmt.Errorf("%s: %w", device.name, err)
			}
		}
	}
	return nil
}

// authorSchedule with the file oracle beside the authorship one.
func fileSchedule(state *authorState, steps []*Step) *Schedule {
	schedule := authorSchedule(state, steps)
	schedule.Check = append(schedule.Check, NewInvariant("FI-25/files", func(ctx context.Context, oracle *Oracle) error {
		if state.world == nil {
			return nil
		}
		return state.world.checkFiles(ctx)
	}))
	return schedule
}

// Syncs device and writes its card with items.
func (self *authorWorld) writeCard(ctx context.Context, device *dirDevice, items ...*protocol.Announcement) (*sidecar.DirectoryCardWritten, error) {
	if err := device.client.Sync(ctx); err != nil {
		return nil, err
	}
	written, err := device.client.WriteCard(ctx, &sidecar.DirectoryCardWriteArgs{Items: items})
	if err != nil {
		return nil, err
	}
	return written, self.observeFiles(ctx)
}

// Syncs every opened device.
func (self *authorWorld) syncAll(ctx context.Context) error {
	for _, device := range self.devices {
		if device.client == nil {
			continue
		}
		if err := device.client.Sync(ctx); err != nil {
			return fmt.Errorf("%s: %w", device.name, err)
		}
	}
	return nil
}

// One forged card of FS-84's card case at its forger's own path.
type fs84CardBreach struct {
	title string
	alarm sidecar.SidecarRecordAlarm
	// Puts the forged card as bad, a forger made for this breach and published, holding item; other is another
	// admitted sidecar.
	forge func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error
}

// A card from a signer whose standing at the card's pin is set, and lifted after where lift is set.
func fs84CardStanding(title string, alarm sidecar.SidecarRecordAlarm, set func(row *sidecartest.FakeDirectorySidecar, next uint64), lift func(row *sidecartest.FakeDirectorySidecar)) *fs84CardBreach {
	return &fs84CardBreach{title: title, alarm: alarm, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error {
		row := world.directoryFixture.Sidecars[bad.sidecarId]
		set(row, world.directoryAuth.Tip().Pin().GetVersion()+1)
		world.publish()
		content, err := world.cardContent(bad.dirDevice, bad.sidecarId, 1, nil, item)
		if err != nil {
			return err
		}
		if err := world.forgeFile(ctx, bad.sidecarId, sidecar.DirectoryCardPath(bad.sidecarId), content, nil); err != nil {
			return err
		}
		if lift != nil {
			lift(row)
			world.publish()
		}
		return nil
	}}
}

// FS-84's forged cards at their forger's own path, the stale pin last since it moves the log 4,097 positions on.
func fs84CardBreaches() []*fs84CardBreach {
	own := func(ctx context.Context, world *authorWorld, bad *dirForger, content []byte, pin *bridge.AuthPin) error {
		return world.forgeFile(ctx, bad.sidecarId, sidecar.DirectoryCardPath(bad.sidecarId), content, pin)
	}
	return []*fs84CardBreach{
		{title: "a card under another sidecar's signature", alarm: sidecar.SidecarRecordAlarmPathRule, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error {
			// other signs, under its own id, a card naming bad, which bad pushes at its own path
			content, err := world.cardContent(other.dirDevice, bad.sidecarId, 1, nil, item)
			if err != nil {
				return err
			}
			return own(ctx, world, bad, content, nil)
		}},
		{title: "a card signed with another's key", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error {
			// other's key signs a card that names bad as its signer too
			content, err := dirSignedFile(other.dirDevice, bad.sidecarId, bridge.SignedType_SIGNED_DIRECTORY_CARD, &protocol.DirectoryCard{
				NetworkId: world.networkId.Bytes(), SidecarId: bad.sidecarId.Bytes(), Seq: 1, At: world.directoryAuth.Tip().Pin(),
				WrittenMillis: world.clock.Now().UnixMilli(), Items: []*protocol.Announcement{item}, Version: 1,
			})
			if err != nil {
				return err
			}
			return own(ctx, world, bad, content, nil)
		}},
		fs84CardStanding("a card from a sidecar parked for consent", sidecar.SidecarRecordAlarmParkedWriter, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.Standing = sidecar.DirectoryStandingUnconsented
		}, nil),
		fs84CardStanding("a card from a sidecar parked by a cascade", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.Standing = sidecar.DirectoryStandingParked
		}, nil),
		fs84CardStanding("a card from a revoked sidecar", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.RevokedAt = next
		}, nil),
		fs84CardStanding("a card from a reaped sidecar", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.RevokedAt = next
			row.Ephemeral = true
		}, nil),
		fs84CardStanding("a card from a suspended sidecar", sidecar.SidecarRecordAlarmBadEntry, func(row *sidecartest.FakeDirectorySidecar, next uint64) {
			row.SuspendedAt = next
		}, func(row *sidecartest.FakeDirectorySidecar) {
			row.SuspendedAt = 0
		}),
		{title: "a card naming another member", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error {
			item.Who.MemberId = other.memberId.Bytes()
			content, err := world.cardContent(bad.dirDevice, bad.sidecarId, 1, nil, item)
			if err != nil {
				return err
			}
			return own(ctx, world, bad, content, nil)
		}},
		{title: "a card of 17 items", alarm: sidecar.SidecarRecordAlarmOverCap, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error {
			items := []*protocol.Announcement{item}
			for range sidecar.DefaultDirectoryCardSettings().ItemCount {
				items = append(items, dirRunItem(bad.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), item.GetWhat().GetTitle()))
			}
			content, err := world.cardContent(bad.dirDevice, bad.sidecarId, 1, nil, items...)
			if err != nil {
				return err
			}
			return own(ctx, world, bad, content, nil)
		}},
		{title: "a card at an auth pin out of range", alarm: sidecar.SidecarRecordAlarmBadEntry, forge: func(ctx context.Context, world *authorWorld, bad *dirForger, other *dirForger, item *protocol.Announcement) error {
			old := world.directoryAuth.Tip().Pin()
			for range sidecar.DirectoryPinPositionCount + 1 {
				world.clock.Advance(time.Millisecond)
				world.publish()
			}
			// renewed now, and so live by its times, on a card at a pin past the bound
			item.RenewedMillis = world.clock.Now().UnixMilli()
			item.StartedMillis = item.RenewedMillis
			item.ExpiresMillis, _ = sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, item.RenewedMillis)
			content, err := world.cardContent(bad.dirDevice, bad.sidecarId, 1, old, item)
			if err != nil {
				return err
			}
			return own(ctx, world, bad, content, nil)
		}},
	}
}

// One step a forged card at its forger's own path: every reader ignores it and alarms once naming its pusher, and a
// rightful card another forger writes after it shows.
func fs84CardBreachStep(state *authorState, breach *fs84CardBreach) *Step {
	return authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
		bad, err := world.forger("forger of "+breach.title, sidecar.NewId())
		if err != nil {
			return err
		}
		other, err := world.forger("beside "+breach.title, sidecar.NewId())
		if err != nil {
			return err
		}
		world.publish()
		item := dirRunItem(bad.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), breach.title)
		world.noteForged(item, bad.sidecarId, nil)
		if err := breach.forge(ctx, world, bad, other, item); err != nil {
			return err
		}
		twin := "rightful beside " + breach.title
		content, err := world.cardContent(other.dirDevice, other.sidecarId, 1, nil, dirRunItem(other.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), twin))
		if err != nil {
			return err
		}
		if err := world.putFile(ctx, other.sidecarId, sidecar.DirectoryCardPath(other.sidecarId), content, nil); err != nil {
			return err
		}
		shown, err := world.syncShown(ctx, world.reader, breach.title)
		if err != nil {
			return err
		}
		if shown != nil {
			return fmt.Errorf("%s: the card's item shows, signed by %s", breach.title, shown.SignerSidecarId)
		}
		if rightful, err := world.reader.shown(twin); err != nil || rightful == nil || rightful.SignerSidecarId != other.sidecarId || rightful.EntryId != (sidecar.Id{}) {
			return fmt.Errorf("%s: the rightful card beside it does not show: %v", breach.title, err)
		}
		if count := world.reader.alarmsNaming(breach.alarm, bad.sidecarId); count != 1 {
			return fmt.Errorf("%s: %d %s alarms naming its pusher", breach.title, count, breach.alarm)
		}
		if count := world.reader.alarmsNaming(breach.alarm, other.sidecarId); count != 0 {
			return fmt.Errorf("%s: an alarm names the rightful writer", breach.title)
		}
		// a later view and a later sync raise nothing again
		if _, err := world.syncShown(ctx, world.reader, breach.title); err != nil {
			return err
		}
		if count := world.reader.alarmsNaming(breach.alarm, bad.sidecarId); count != 1 {
			return fmt.Errorf("%s: the alarm was raised again", breach.title)
		}
		return nil
	})
}

// FS-84's card case: see the file header.
func Fs84DirectoryCards(net *Net) *Schedule {
	return Fs84DirectoryCardsOf(&authorState{})
}

// The case over state, which a test reads the world from once it ran.
func Fs84DirectoryCardsOf(state *authorState) *Schedule {
	const rightfulTitle = "the rightful run"
	var writer *dirDevice
	var laptop *dirDevice
	runId := sidecar.NewId()
	// H's card with its run renewed now
	renew := func(ctx context.Context, world *authorWorld) (*sidecar.DirectoryCardWritten, error) {
		return world.writeCard(ctx, writer, dirRunItem(writer, runId, 1, world.clock.Now().UnixMilli(), rightfulTitle))
	}
	// the reader shows H's run from a card at seq, raising no alarm naming H
	rightful := func(ctx context.Context, world *authorWorld, what string, seq uint64) error {
		shown, err := world.syncShown(ctx, world.reader, rightfulTitle)
		if err != nil {
			return err
		}
		if shown == nil || shown.SignerSidecarId != writer.sidecarId || shown.EntryId != (sidecar.Id{}) || shown.Seq != seq {
			return fmt.Errorf("%s: H's run %+v, not from its card at seq %d", what, shown, seq)
		}
		for _, reason := range []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmPathRule, sidecar.SidecarRecordAlarmBadEntry, sidecar.SidecarRecordAlarmOverCap} {
			if count := world.reader.alarmsNaming(reason, writer.sidecarId); count != 0 {
				return fmt.Errorf("%s: %d %s alarms name the rightful writer", what, count, reason)
			}
		}
		return nil
	}
	// a breach at H's path by intruder: ignored with a path_rule alarm naming it, H's version showing meanwhile and
	// after the store purged it, then H's repair restoring the file
	breachAndRepair := func(what string, breach func(ctx context.Context, world *authorWorld, intruder *dirForger, written *sidecar.DirectoryCardWritten) error) *Step {
		return authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			intruder, err := world.forger("intruder of "+what, sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			written, err := renew(ctx, world)
			if err != nil {
				return err
			}
			if err := rightful(ctx, world, what+", before", written.Seq); err != nil {
				return err
			}
			if err := breach(ctx, world, intruder, written); err != nil {
				return err
			}
			if err := rightful(ctx, world, what, written.Seq); err != nil {
				return err
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, intruder.sidecarId); count != 1 {
				return fmt.Errorf("%s: %d path_rule alarms naming its pusher", what, count)
			}
			// two minutes on the store holds none of the content the breach replaced: the reader shows what it accepted
			world.clock.Advance(2 * time.Minute)
			world.publish()
			if err := rightful(ctx, world, what+", once the store purged H's version", written.Seq); err != nil {
				return err
			}
			if err := writer.client.Sync(ctx); err != nil {
				return err
			}
			pass, err := writer.client.Repair(ctx)
			if err != nil {
				return err
			}
			if pass.Card == nil || pass.Card.Seq <= written.Seq || len(pass.Card.Items) != 1 {
				return fmt.Errorf("%s: H's repair put %+v", what, pass.Card)
			}
			if err := world.observeFiles(ctx); err != nil {
				return err
			}
			if err := rightful(ctx, world, what+", after H's repair", pass.Card.Seq); err != nil {
				return err
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, intruder.sidecarId); count != 1 {
				return fmt.Errorf("%s: the repaired card alarmed", what)
			}
			if err := writer.client.Sync(ctx); err != nil {
				return err
			}
			if again, err := writer.client.Repair(ctx); err != nil || again.Card != nil {
				return fmt.Errorf("%s: a repair with nothing breached put %+v: %v", what, again.Card, err)
			}
			return nil
		})
	}
	steps := []*Step{
		authorStep(state, "daemonH", func(ctx context.Context, world *authorWorld) error {
			world.raiseFormat2()
			memberId := sidecar.NewId()
			var err error
			if writer, err = world.member(ctx, "writer H", memberId); err != nil {
				return err
			}
			if laptop, err = world.member(ctx, "H's laptop", memberId); err != nil {
				return err
			}
			written, err := renew(ctx, world)
			if err != nil {
				return err
			}
			if written.Seq != 1 || len(written.Items) != 1 {
				return fmt.Errorf("H's first card: %+v", written)
			}
			if err := rightful(ctx, world, "H's first card", 1); err != nil {
				return err
			}
			if !world.reader.client.Format2() {
				return errors.New("the reader does not read the directory at format 2")
			}
			if announces, _, err := world.entryAtEvs(ctx, world.reader, rightfulTitle); err != nil || announces != nil {
				return fmt.Errorf("H's run rides an announce entry beside its card: %v", err)
			}
			return nil
		}),
		breachAndRepair("a card another sidecar signed and pushed", func(ctx context.Context, world *authorWorld, intruder *dirForger, written *sidecar.DirectoryCardWritten) error {
			item := dirRunItem(writer, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "signed and pushed by another sidecar")
			world.noteForged(item, writer.sidecarId, nil)
			content, err := world.cardContent(intruder.dirDevice, writer.sidecarId, written.Seq+8, nil, item)
			if err != nil {
				return err
			}
			return world.forgeFile(ctx, intruder.sidecarId, written.Path, content, nil)
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// H's own earlier card, its bytes as H pushed them, pushed again by another sidecar once H wrote a later one
			intruder, err := world.forger("replayer", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			earlier, err := world.writeCard(ctx, writer,
				dirRunItem(writer, runId, 1, world.clock.Now().UnixMilli(), rightfulTitle),
				dirRunItem(writer, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "a run H ended since"))
			if err != nil {
				return err
			}
			versions := world.files().versions[earlier.Path]
			replayed := versions[len(versions)-1].Content
			if _, err := world.syncShown(ctx, world.reader, rightfulTitle); err != nil {
				return err
			}
			world.clock.Advance(time.Second)
			written, err := renew(ctx, world)
			if err != nil {
				return err
			}
			if err := rightful(ctx, world, "before the replay", written.Seq); err != nil {
				return err
			}
			if err := world.putFile(ctx, intruder.sidecarId, written.Path, replayed, nil); err != nil {
				return err
			}
			if err := rightful(ctx, world, "H's earlier card pushed by another sidecar", written.Seq); err != nil {
				return err
			}
			if ended, err := world.reader.shown("a run H ended since"); err != nil || ended != nil {
				return fmt.Errorf("a replayed card's item shows again: %v", err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, intruder.sidecarId); count != 1 {
				return fmt.Errorf("H's earlier card pushed by another sidecar: %d path_rule alarms naming its pusher", count)
			}
			if err := writer.client.Sync(ctx); err != nil {
				return err
			}
			pass, err := writer.client.Repair(ctx)
			if err != nil || pass.Card == nil || pass.Card.Seq <= written.Seq {
				return fmt.Errorf("H's repair after the replay: %+v, %v", pass, err)
			}
			return rightful(ctx, world, "after the replay's repair", pass.Card.Seq)
		}),
		breachAndRepair("a removal of a live sidecar's card by another member", func(ctx context.Context, world *authorWorld, intruder *dirForger, written *sidecar.DirectoryCardWritten) error {
			return world.removeFile(ctx, intruder.sidecarId, written.Path)
		}),
	}
	breaches := fs84CardBreaches()
	// every breach but the stale pin, which runs last
	for _, breach := range breaches[:len(breaches)-1] {
		steps = append(steps, fs84CardBreachStep(state, breach))
	}
	steps = append(steps,
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// a seq not above the last: a forger's second card at the seq of its first, and one below it
			bad, err := world.forger("replayer of its own seq", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			path := sidecar.DirectoryCardPath(bad.sidecarId)
			put := func(seq uint64, title string, forged bool) error {
				item := dirRunItem(bad.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), title)
				content, err := world.cardContent(bad.dirDevice, bad.sidecarId, seq, nil, item)
				if err != nil {
					return err
				}
				if forged {
					world.noteForged(item, bad.sidecarId, nil)
					return world.forgeFile(ctx, bad.sidecarId, path, content, nil)
				}
				return world.putFile(ctx, bad.sidecarId, path, content, nil)
			}
			if err := put(5, "the card at seq 5", false); err != nil {
				return err
			}
			// every device accepts seq 5 first: a copy that never held it has no last seq to hold a lower one to
			if err := world.syncAll(ctx); err != nil {
				return err
			}
			if shown, err := world.reader.shown("the card at seq 5"); err != nil || shown == nil || shown.Seq != 5 {
				return fmt.Errorf("the card at seq 5: %v, %v", shown, err)
			}
			for _, seq := range []uint64{5, 4} {
				title := fmt.Sprintf("a second card at seq %d", seq)
				if err := put(seq, title, true); err != nil {
					return err
				}
				if shown, err := world.syncShown(ctx, world.reader, title); err != nil || shown != nil {
					return fmt.Errorf("%s shows: %v", title, err)
				}
			}
			if shown, err := world.reader.shown("the card at seq 5"); err != nil || shown == nil {
				return fmt.Errorf("the card the reader accepted last no longer shows: %v", err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, bad.sidecarId); count != 2 {
				return fmt.Errorf("a seq not above the last: %d bad_entry alarms naming its writer", count)
			}
			return nil
		}),
		authorStep(state, "admin", func(ctx context.Context, world *authorWorld) error {
			// a directory admin's removal is a moderation: accepted, alarming H's member's own devices and no other's
			written, err := renew(ctx, world)
			if err != nil {
				return err
			}
			if err := rightful(ctx, world, "before the moderation", written.Seq); err != nil {
				return err
			}
			if err := laptop.client.Sync(ctx); err != nil {
				return err
			}
			if err := world.removeFile(ctx, world.admin.sidecarId, written.Path); err != nil {
				return err
			}
			for _, device := range []*dirDevice{world.reader, laptop} {
				if shown, err := world.syncShown(ctx, device, rightfulTitle); err != nil || shown != nil {
					return fmt.Errorf("a moderated card's run still shows at %s: %v", device.name, err)
				}
			}
			if count := laptop.alarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.sidecarId); count != 1 {
				return fmt.Errorf("%d moderation alarms on the member's other device", count)
			}
			if count := world.reader.alarmCount(sidecar.SidecarRecordAlarmModeration); count != 0 {
				return fmt.Errorf("%d moderation alarms on another member's device", count)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, world.admin.sidecarId); count != 0 {
				return fmt.Errorf("an admin's moderation raised %d path_rule alarms", count)
			}
			// H writes on: its next card shows again
			written, err = renew(ctx, world)
			if err != nil {
				return err
			}
			return rightful(ctx, world, "H's card after the moderation", written.Seq)
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// any writer may remove a revoked sidecar's card
			gone, err := world.forger("revoked G", sidecar.NewId())
			if err != nil {
				return err
			}
			remover, err := world.forger("remover", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			path := sidecar.DirectoryCardPath(gone.sidecarId)
			content, err := world.cardContent(gone.dirDevice, gone.sidecarId, 1, nil, dirRunItem(gone.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "a run of G's"))
			if err != nil {
				return err
			}
			if err := world.putFile(ctx, gone.sidecarId, path, content, nil); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "a run of G's"); err != nil || shown == nil {
				return fmt.Errorf("G's run before its revocation: %v", err)
			}
			world.directoryFixture.Sidecars[gone.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
			world.publish()
			if err := world.removeFile(ctx, remover.sidecarId, path); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "a run of G's"); err != nil || shown != nil {
				return fmt.Errorf("a revoked sidecar's run shows: %v", err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, remover.sidecarId); count != 0 {
				return fmt.Errorf("the removal of a revoked sidecar's card raised %d path_rule alarms", count)
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// announce entries and cards of one announcement fold to the same state
			both, err := world.forger("writer on both carriers", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			announcementId := sidecar.NewId()
			const title = "a run on both carriers"
			one := func(what string, renewedMillis int64, fromEntry bool) error {
				if err := world.reader.client.Sync(ctx); err != nil {
					return err
				}
				items, err := world.reader.items()
				if err != nil {
					return err
				}
				count := 0
				for _, item := range items {
					if item.SignerSidecarId != both.sidecarId {
						continue
					}
					count += 1
					if item.Announcement.GetRenewedMillis() != renewedMillis || (item.EntryId != (sidecar.Id{})) != fromEntry {
						return fmt.Errorf("%s: the item stands at %d from an entry %t", what, item.Announcement.GetRenewedMillis(), item.EntryId != (sidecar.Id{}))
					}
				}
				if count != 1 {
					return fmt.Errorf("%s: %d items of one announcement", what, count)
				}
				return nil
			}
			first := dirRunItem(both.dirDevice, announcementId, 1, world.clock.Now().UnixMilli(), title)
			if err := world.announce(ctx, both, first); err != nil {
				return err
			}
			if err := one("its entry alone", first.GetRenewedMillis(), true); err != nil {
				return err
			}
			world.clock.Advance(time.Minute)
			world.publish()
			renewed := dirRunItem(both.dirDevice, announcementId, 1, world.clock.Now().UnixMilli(), title)
			renewed.StartedMillis = first.GetStartedMillis()
			content, err := world.cardContent(both.dirDevice, both.sidecarId, 1, nil, renewed)
			if err != nil {
				return err
			}
			if err := world.putFile(ctx, both.sidecarId, sidecar.DirectoryCardPath(both.sidecarId), content, nil); err != nil {
				return err
			}
			if err := one("its entry and a later card", renewed.GetRenewedMillis(), false); err != nil {
				return err
			}
			world.clock.Advance(time.Minute)
			world.publish()
			later := dirRunItem(both.dirDevice, announcementId, 1, world.clock.Now().UnixMilli(), title)
			later.StartedMillis = first.GetStartedMillis()
			if err := world.announce(ctx, both, later); err != nil {
				return err
			}
			if err := one("a later entry over the card", later.GetRenewedMillis(), true); err != nil {
				return err
			}

			// a repo's entry and its r/ file at one version: one item
			admin, err := world.forger("repo admin on both carriers", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			repoId := world.repo(admin.sidecarId)
			world.publish()
			item, err := dirRepoItem(admin.dirDevice, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "a repo on both carriers")
			if err != nil {
				return err
			}
			if err := world.announce(ctx, admin, item); err != nil {
				return err
			}
			file, err := world.repoFileContent(admin.dirDevice, repoId, 1, nil, item)
			if err != nil {
				return err
			}
			if err := world.putFile(ctx, admin.sidecarId, sidecar.DirectoryRepoPath(repoId), file, nil); err != nil {
				return err
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			items, err := world.reader.items()
			if err != nil {
				return err
			}
			count := 0
			for _, each := range items {
				if sidecar.DirectoryAnnouncementKind(each.Announcement.GetKind()) == sidecar.DirectoryAnnouncementKindRepo && bytes.Equal(each.Announcement.GetWhere().GetRepoId(), repoId.Bytes()) {
					count += 1
				}
			}
			if count != 1 {
				return fmt.Errorf("%d items of one repo from its entry and its file", count)
			}
			return nil
		}),
		authorStep(state, "forger", func(ctx context.Context, world *authorWorld) error {
			// expiry under skew: a run on a card, renewed the skew ahead of its push, is active up to its expires_millis
			// and stale at it
			ahead, err := world.forger("card writer ahead", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			const title = "a card's run ahead by the skew"
			item := dirRunItem(ahead.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli()+sidecar.DirectoryClockSkew.Milliseconds(), title)
			content, err := world.cardContent(ahead.dirDevice, ahead.sidecarId, 1, nil, item)
			if err != nil {
				return err
			}
			if err := world.putFile(ctx, ahead.sidecarId, sidecar.DirectoryCardPath(ahead.sidecarId), content, nil); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, world.reader, title)
			if err != nil || shown == nil || shown.Display != sidecar.DirectoryItemActive {
				return fmt.Errorf("a card's run renewed the skew ahead: %v, %v", shown, err)
			}
			world.clock.AdvanceTo(time.UnixMilli(item.GetExpiresMillis() - 1))
			if shown, err = world.reader.shown(title); err != nil || shown == nil || shown.Display != sidecar.DirectoryItemActive {
				return fmt.Errorf("a millisecond before its expiry: %v, %v", shown, err)
			}
			world.clock.AdvanceTo(time.UnixMilli(item.GetExpiresMillis()))
			if shown, err = world.reader.shown(title); err != nil || shown == nil || shown.Display != sidecar.DirectoryItemStale {
				return fmt.Errorf("at its expiry: %v, %v", shown, err)
			}
			return nil
		}),
		fs84CardBreachStep(state, breaches[len(breaches)-1]),
		authorStep(state, "daemonH", func(ctx context.Context, world *authorWorld) error {
			// past 4,097 positions H's next card, at a fresh pin, shows
			written, err := renew(ctx, world)
			if err != nil {
				return err
			}
			return rightful(ctx, world, "H's card at a fresh pin", written.Seq)
		}),
	)
	return fileSchedule(state, steps)
}

func TestFs84Cards(t *testing.T) {
	RunRow(t, "FS-84", "cards", nil)
}

// FI-25's oracle against a reader without the rules: run to its end, the schedule leaves every forged file in the
// ledger, and a reader that showed an item from any one of them, as a reader lacking that file's rule would, fails
// the oracle. A forger's replay of its own seq is left out: only the reader's own last seq tells it.
func TestFs84CardsFi25FailsAReaderWithoutTheRules(t *testing.T) {
	ctx := context.Background()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	state := &authorState{}
	schedule := Fs84DirectoryCardsOf(state)
	schedule.Id = "FS-84's cards"
	if result := Run(ctx, schedule, net); result.Err != nil {
		t.Fatal(result)
	}
	world := state.world
	settings := sidecar.DefaultDirectoryCardSettings()
	settings.ItemCount = 64
	judged := 0
	for path, sums := range world.files().forged {
		for _, file := range world.files().versions[path] {
			if file.Removed || file.Content == nil || !sums[sha256.Sum256(file.Content)] {
				continue
			}
			stored, err := sidecar.DirectoryDecodeCard(file.Content, settings)
			if err != nil {
				t.Fatalf("a forged card does not decode under any cap: %v", err)
			}
			if title := stored.Card.GetItems()[0].GetWhat().GetTitle(); title == "a second card at seq 5" || title == "a second card at seq 4" {
				continue
			}
			shown := &sidecar.DirectoryItem{
				Announcement:    stored.Card.GetItems()[0],
				Display:         sidecar.DirectoryItemActive,
				SignerSidecarId: sidecar.Id(stored.Card.GetSidecarId()),
				Seq:             stored.Card.GetSeq(),
				PushPin:         stored.Card.GetAt(),
				PushTimeMillis:  file.TimeMillis,
			}
			// the ledger's own mark left out, each forged file must fail on a rule
			delete(sums, sha256.Sum256(file.Content))
			fileErr := world.fi25File(shown)
			shownErr := world.fi25Shown(shown, shown.SignerSidecarId)
			sums[sha256.Sum256(file.Content)] = true
			if fileErr == nil && shownErr == nil {
				t.Errorf("a reader showing %q passes FI-25", shown.Announcement.GetWhat().GetTitle())
			} else {
				judged += 1
			}
		}
	}
	if judged < 10 {
		t.Errorf("%d forged cards judged by rule", judged)
	}
	// and the file items the honest reader does show pass it
	items, err := world.reader.items()
	if err != nil {
		t.Fatal(err)
	}
	fromFiles := 0
	for _, item := range items {
		if item.EntryId != (sidecar.Id{}) {
			continue
		}
		fromFiles += 1
		if err := world.fi25File(item); err != nil {
			t.Errorf("an honest reader's item: %v", err)
		}
	}
	if fromFiles == 0 {
		t.Error("the reader shows no item from a file")
	}
}
