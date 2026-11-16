//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-101's M6 case on T2 (§22.8, meta review CC-07; §16.11's repo file row at M6, FI-25, I-EVS-14; RECORD-M6-25), in
// the authorship world (fs84_test.go), on the fake clock:
//
//	horizon     repo admin E announces repo K, an announce entry, at pin n0, and a run at the same pin; the log grows
//	            4,097 positions: K's item stands, the run's card rule refusing its stale pin; the log then runs 30 days
//	            and 10 folds past n0, each a position three days on, and the states drop n0 as api does past
//	            retention; a fresh member device accepts K's item, judging E's right from the positions the state still
//	            holds; after E's RepoAdmin remove the item still stands at the reader that accepted it
//	refused     E, removed as admin of T with no push since to its own stream, pushes a version at its stream's older
//	            head pin, where it still held the right: within 10 min of the removal it stands, over 10 min after it
//	            is refused; E's version at a pin after the removal, and a non-admin's at a fresh pin, are refused; each
//	            refusal alarms naming its signer
//	compromise  after a compromise revocation of E from a since_n at or before its pin, its version of C is void and
//	            alarms, and another admin's device re-signs it at a higher version from its attested fields alone
//	lost        after E's lost revocation its version of L still stands, and that admin's device re-signs it whole
//
// After every step, FI-25 as the authorship world holds it, the ledger of rights carrying each removal's position and
// time. TestFs101MutantAStateWithoutTheRemovalFails runs the case where the removal of T's admin never reaches the
// readers' state, which must fail it.
//
// The fold and retention constants are §7.9's as RECORD-M6-15's unit test takes them, 24 h a fold and 30 days kept,
// the fakes dropping what api would by RetainFrom. Not here: a version whose own pin lies over 4,096 positions before
// its push's, which has no M6 form, an announce entry's pin being its push's (directory_repo.go's age row), and is
// the r/ file case's at the later of M6-out and M10-out; and a device that starts after E's removal and past n0's
// retention, which cannot tell E's right from the head and fails closed until question
// acl-m2-06-access-log-positions gives removed admins' rows their positions.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs101M6 = Register("FS-101", "entries", []Tier{TierT2}, Fs101RepoItemsAcrossRetention)

// A general repo at the next position whose admins are the sidecars given, their rights in the ledger. Not yet
// published.
func (self *authorWorld) repo(admins ...sidecar.Id) sidecar.Id {
	repoId := sidecar.NewId()
	next := self.directoryAuth.Tip().Pin().GetVersion() + 1
	repo := &sidecartest.FakeDirectoryRepo{Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	self.rights[repoId] = map[sidecar.Id]*dirRight{}
	for _, admin := range admins {
		repo.Admins = append(repo.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: admin, At: next})
		self.rights[repoId][admin] = &dirRight{from: next}
	}
	self.directoryFixture.Repos[repoId] = repo
	return repoId
}

// Ends every admin's right on repoId at the next position, in the ledger and, unless withheld, in the state. Not yet
// published.
func (self *authorWorld) removeAdmins(repoId sidecar.Id, withheld bool) {
	next := self.directoryAuth.Tip().Pin().GetVersion() + 1
	for _, right := range self.rights[repoId] {
		if right.until == 0 {
			right.until = next
			right.untilMillis = self.clock.Now().UnixMilli()
		}
	}
	if !withheld {
		self.directoryFixture.Repos[repoId].Admins = nil
	}
}

// The item device shows for repoId, private markers included, nil for none.
func (self *dirDevice) shownRepo(repoId sidecar.Id) (*sidecar.DirectoryItem, error) {
	items, err := self.items()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if sidecar.DirectoryAnnouncementKind(item.Announcement.GetKind()) == sidecar.DirectoryAnnouncementKindRepo && bytes.Equal(item.Announcement.GetWhere().GetRepoId(), repoId.Bytes()) {
			return item, nil
		}
	}
	return nil, nil
}

func Fs101RepoItemsAcrossRetention(net *Net) *Schedule {
	return Fs101RepoItemsAcrossRetentionOf(&authorState{}, false)
}

// FS-101's M6 case over state; with mutant, the removal of T's admin never reaches the readers' state.
func Fs101RepoItemsAcrossRetentionOf(state *authorState, mutant bool) *Schedule {
	var fresh *dirDevice
	var second *dirDevice
	n0 := uint64(0)
	return authorSchedule(state, []*Step{
		authorStep(state, "daemonE", func(ctx context.Context, world *authorWorld) error {
			// E announces K at n0, and a run at the same pin
			admin, err := world.forger("repo admin E", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			state.ids["K"] = world.repo(admin.sidecarId)
			world.publish()
			n0 = world.directoryAuth.Tip().Pin().GetVersion()
			nowMillis := world.clock.Now().UnixMilli()
			item, err := dirRepoItem(admin.dirDevice, state.ids["K"], protocol.RepoKind_REPO_KIND_GENERAL, 1, nowMillis, "payroll exports")
			if err != nil {
				return err
			}
			if err := world.announce(ctx, admin, item); err != nil {
				return err
			}
			if err := world.announce(ctx, admin, dirRunItem(admin.dirDevice, sidecar.NewId(), 1, nowMillis, "a run at n0")); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "a run at n0"); err != nil || shown == nil {
				return fmt.Errorf("the run at its own pin: %v", err)
			}
			return nil
		}),
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			// 4,097 positions of log growth: K's item stands, and the run's card rule refuses its pin
			for range sidecar.DirectoryPinPositionCount + 1 {
				world.clock.Advance(time.Millisecond)
				world.publish()
			}
			shown, err := world.syncShown(ctx, world.reader, "payroll exports")
			if err != nil || shown == nil || shown.Display != sidecar.DirectoryItemActive {
				return fmt.Errorf("K's item past 4,096 positions: %v, %v", shown, err)
			}
			if run, err := world.reader.shown("a run at n0"); err != nil || run != nil {
				return fmt.Errorf("a run item at a pin past 4,096 positions shows: %v", err)
			}
			return nil
		}),
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			// 30 days and 10 folds past n0, then the states drop n0
			for range 10 {
				world.clock.Advance(3 * 24 * time.Hour)
				world.publish()
			}
			world.directoryAuth.RetainFrom(n0 + 1)
			world.recordAuth.RetainFrom(n0 + 1)
			return nil
		}),
		authorStep(state, "daemonF", func(ctx context.Context, world *authorWorld) error {
			// a fresh member device accepts K's item
			admin := world.forgers["repo admin E"]
			var err error
			if fresh, err = world.member(ctx, "fresh device", sidecar.NewId()); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, fresh, "payroll exports")
			if err != nil || shown == nil || shown.SignerSidecarId != admin.sidecarId || shown.PushPin.GetVersion() != n0 {
				return fmt.Errorf("a fresh device past n0's retention: %v, %v", shown, err)
			}
			if count := fresh.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, admin.sidecarId); count != 0 {
				return fmt.Errorf("%d bad_entry alarms naming E on a fresh device", count)
			}
			// E's RepoAdmin remove: the version it wrote while it held the right stands
			world.removeAdmins(state.ids["K"], false)
			world.publish()
			if shown, err = world.syncShown(ctx, fresh, "payroll exports"); err != nil || shown == nil || shown.SignerSidecarId != admin.sidecarId {
				return fmt.Errorf("a RepoAdmin remove voided a version standing at a reader that accepted it: %v", err)
			}
			return nil
		}),
		authorStep(state, "daemonE", func(ctx context.Context, world *authorWorld) error {
			// T: its admin removed with no push since to its own stream
			admin, err := world.forger("removed admin", sidecar.NewId())
			if err != nil {
				return err
			}
			stranger, err := world.forger("non-admin N", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			repoId := world.repo(admin.sidecarId)
			state.ids["T"] = repoId
			world.publish()
			version := func(number uint64, title string) (*protocol.Announcement, error) {
				return dirRepoItem(admin.dirDevice, repoId, protocol.RepoKind_REPO_KIND_GENERAL, number, world.clock.Now().UnixMilli(), title)
			}
			first, err := version(1, "first")
			if err != nil {
				return err
			}
			if err := world.announce(ctx, admin, first); err != nil {
				return err
			}
			held := world.recordAuth.Tip().Pin()
			world.clock.Advance(time.Minute)
			world.removeAdmins(repoId, mutant)
			world.publish()

			// within 10 min of the removal, at the older pin: stands
			world.clock.Advance(5 * time.Minute)
			second, err := version(2, "second")
			if err != nil {
				return err
			}
			if err := world.announceIn(ctx, admin, second, nil, held); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "second"); err != nil || shown == nil {
				return fmt.Errorf("a push at an older pin within 10 min of the removal: %v", err)
			}

			// over 10 min after the removal at the older pin; at a pin after the removal; a non-admin's at a fresh pin
			world.clock.Advance(6 * time.Minute)
			third, err := version(3, "third")
			if err != nil {
				return err
			}
			if err := world.breach(ctx, admin, third, nil, held); err != nil {
				return err
			}
			fourth, err := version(4, "fourth")
			if err != nil {
				return err
			}
			if err := world.breach(ctx, admin, fourth, nil, nil); err != nil {
				return err
			}
			fifth, err := dirRepoItem(stranger.dirDevice, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 5, world.clock.Now().UnixMilli(), "fifth")
			if err != nil {
				return err
			}
			if err := world.breach(ctx, stranger, fifth, nil, nil); err != nil {
				return err
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err := world.reader.shownRepo(repoId)
			if err != nil || shown == nil || shown.Announcement.GetWhat().GetTitle() != "second" {
				return fmt.Errorf("T's item after the refused versions: %v, %v", shown, err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, admin.sidecarId); count != 2 {
				return fmt.Errorf("%d bad_entry alarms naming the removed admin, not its two refused versions'", count)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, stranger.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_entry alarms naming the non-admin", count)
			}
			return nil
		}),
		authorStep(state, "daemonF", func(ctx context.Context, world *authorWorld) error {
			// C and L: two repos with a second admin's device, which reads both items before either revocation
			var err error
			if second, err = world.member(ctx, "second admin F", sidecar.NewId()); err != nil {
				return err
			}
			compromised, err := world.forger("compromised admin", sidecar.NewId())
			if err != nil {
				return err
			}
			lost, err := world.forger("lost admin", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			state.ids["C"] = world.repo(compromised.sidecarId, second.sidecarId)
			state.ids["L"] = world.repo(lost.sidecarId, second.sidecarId)
			world.publish()
			state.counts["nc"] = int(world.directoryAuth.Tip().Pin().GetVersion())
			nowMillis := world.clock.Now().UnixMilli()
			for _, write := range []struct {
				signer *dirForger
				repo   string
				title  string
			}{{signer: compromised, repo: "C", title: "release notes"}, {signer: lost, repo: "L", title: "design notes"}} {
				item, err := dirRepoItem(write.signer.dirDevice, state.ids[write.repo], protocol.RepoKind_REPO_KIND_GENERAL, 1, nowMillis, write.title)
				if err != nil {
					return err
				}
				if err := world.announce(ctx, write.signer, item); err != nil {
					return err
				}
			}
			for _, device := range []*dirDevice{world.reader, second} {
				if err := device.client.Sync(ctx); err != nil {
					return err
				}
				for _, title := range []string{"release notes", "design notes"} {
					if shown, err := device.shown(title); err != nil || shown == nil {
						return fmt.Errorf("%s does not show %q before the revocations: %v", device.name, title, err)
					}
				}
			}
			return nil
		}),
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			// a compromise revocation of C's signer from a since_n at its pin: void, alarming; F re-signs it
			compromised := world.forgers["compromised admin"]
			since := uint64(state.counts["nc"])
			row := world.directoryFixture.Sidecars[compromised.sidecarId]
			row.RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
			row.CompromisedSince = since
			world.recordFixture.CompromisedSince = map[sidecar.Id]uint64{compromised.sidecarId: since}
			world.compromised[compromised.sidecarId] = since
			world.publish()
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			if shown, err := world.reader.shownRepo(state.ids["C"]); err != nil || shown != nil {
				return fmt.Errorf("a compromised signer's version shows: %v", err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, compromised.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_entry alarms naming the compromised signer", count)
			}
			if err := second.client.Sync(ctx); err != nil {
				return err
			}
			writes, err := second.client.MaintainRepos(ctx)
			if err != nil || len(writes) != 1 {
				return fmt.Errorf("F's re-signing after the compromise: %d writes, %v", len(writes), err)
			}
			if again, err := second.client.MaintainRepos(ctx); err != nil || len(again) != 0 {
				return fmt.Errorf("a second pass wrote %d: %v", len(again), err)
			}
			if err := second.record.Flush(ctx); err != nil {
				return err
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err := world.reader.shownRepo(state.ids["C"])
			if err != nil || shown == nil || shown.SignerSidecarId != second.sidecarId || shown.Announcement.GetVersion() != 2 {
				return fmt.Errorf("the re-signed item: %v, %v", shown, err)
			}
			// from its attested fields alone: the void version's prose is not carried over
			if title := shown.Announcement.GetWhat().GetTitle(); title != "" {
				return fmt.Errorf("re-signed with the void version's display name %q", title)
			}
			return nil
		}),
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			// a lost revocation of L's signer: its version still stands, and F re-signs it whole
			lost := world.forgers["lost admin"]
			world.directoryFixture.Sidecars[lost.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
			world.publish()
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err := world.reader.shownRepo(state.ids["L"])
			if err != nil || shown == nil || shown.SignerSidecarId != lost.sidecarId {
				return fmt.Errorf("a lost revocation voided its signer's version: %v, %v", shown, err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, lost.sidecarId); count != 0 {
				return fmt.Errorf("%d bad_entry alarms naming a signer revoked as lost", count)
			}
			if err := second.client.Sync(ctx); err != nil {
				return err
			}
			writes, err := second.client.MaintainRepos(ctx)
			if err != nil || len(writes) != 1 {
				return fmt.Errorf("F's re-signing after the lost revocation: %d writes, %v", len(writes), err)
			}
			if err := second.record.Flush(ctx); err != nil {
				return err
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err = world.reader.shownRepo(state.ids["L"])
			if err != nil || shown == nil || shown.SignerSidecarId != second.sidecarId || shown.Announcement.GetVersion() != 2 || shown.Announcement.GetWhat().GetTitle() != "design notes" {
				return fmt.Errorf("the item re-signed whole: %v, %v", shown, err)
			}
			return nil
		}),
	})
}

func TestFs101M6(t *testing.T) {
	RunRow(t, "FS-101", "entries", nil)
}

// The mechanism FS-101 holds readers to, a signer's right judged at its push's pin by the state's history, with the
// history gone: where the removal of T's admin never reaches the readers' state, its later versions show, and the
// case fails, FI-25 judging by the ledger's removal.
func TestFs101MutantAStateWithoutTheRemovalFails(t *testing.T) {
	ctx := context.Background()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	state := &authorState{}
	schedule := Fs101RepoItemsAcrossRetentionOf(state, true)
	schedule.Id = "FS-101's entries mutant"
	result := Run(ctx, schedule, net)
	if result.Err == nil {
		t.Fatal("the mutant passed")
	}
	if !strings.Contains(result.Err.Error(), "T's item after the refused versions") {
		t.Fatalf("the mutant failed elsewhere: %v", result.Err)
	}
	// and FI-25 alone, by the ledger's removal, fails what the mutant's reader shows
	world := state.world
	shown, err := world.reader.shownRepo(state.ids["T"])
	if err != nil || shown == nil {
		t.Fatalf("the mutant's reader shows no item for T: %v", err)
	}
	if title := shown.Announcement.GetWhat().GetTitle(); title == "second" {
		t.Fatal("the mutant's reader shows the rightful version")
	}
	if err := world.fi25Shown(shown, shown.SignerSidecarId); err == nil || !strings.Contains(err.Error(), "FI-25") {
		t.Fatalf("FI-25 passes a version signed past its signer's right: %v", err)
	}
}
