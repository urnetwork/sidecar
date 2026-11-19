//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-101's r/ file case on T2 (§22.8, meta review CC-07; §16.11's repo file row, D-MCP-35, FI-25, I-EVS-14;
// RECORD-M10-06), in the authorship world at format 2 (fs84_card_test.go), on the fake clock:
//
//	horizon     repo admin E's daemon writes repo K's item as its r/ file at pin n0, and a run on its card at the same
//	            pin; the log grows 4,097 positions: K's item stands, the run's card rule refusing its stale pin; the
//	            log then runs 30 days and 10 folds past n0, each a position three days on, and the states drop n0 as
//	            api does past retention; a fresh member device accepts K's item, judging E's right from the positions
//	            the state still holds; after E's RepoAdmin remove the item still stands at the reader that accepted it
//	idle        T's admin, removed with no push since to the cards ref, pushes a version at that ref's older head pin,
//	            where it still held the right: within 10 min of the removal it stands, over 10 min after it is refused
//	            by every reader holding the removal
//	refused     the removed admin's version whose own pin lies within 4,096 positions of its push's, pushed at a pin
//	            after the removal: refused, it holding no right at the push's pin; a non-admin's version at a fresh
//	            pin: refused; S's admin, its right standing, signs a version whose pin lies over 4,096 positions
//	            before its push's: refused, and its next version at a fresh pin stands. Each refusal alarms naming its
//	            signer, readers showing the version they accepted last
//	compromise  after a compromise revocation of C's signer from a since_n at or before its pin, its file is void and
//	            alarms, and another admin's device re-signs the item onto the r/ file at a higher seq, from its
//	            attested fields alone
//	lost        after L's signer's lost revocation its file still stands, and that admin's device re-signs it whole
//
// After every step, FI-25 as the authorship world holds it, the ledger of rights carrying each removal's position and
// time, and for each item a file carries FI-25's file rule (fs84_card_test.go's fi25File).
// TestFs101FileMutantAStateWithoutTheRemovalFails runs the case where the removal of T's admin never reaches the
// readers' state, which must fail it.
//
// The fold and retention constants are §7.9's as RECORD-M6-15's unit test takes them, 24 h a fold and 30 days kept,
// the fakes dropping what api would by RetainFrom. Not here: a device that starts after E's removal and past n0's
// retention, which cannot tell E's right from the head and fails closed until question
// acl-m2-06-access-log-positions gives removed admins' rows their positions; and evs's own bound on a push's pin by
// its ref's head pin, which the fake's cards ref does not hold and FS-99's evs clause's world does.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs101File = Register("FS-101", "r-file", []Tier{TierT2}, Fs101RepoFilesAcrossRetention)

func Fs101RepoFilesAcrossRetention(net *Net) *Schedule {
	return Fs101RepoFilesAcrossRetentionOf(&authorState{}, false)
}

// FS-101's r/ file case over state; with mutant, the removal of T's admin never reaches the readers' state.
func Fs101RepoFilesAcrossRetentionOf(state *authorState, mutant bool) *Schedule {
	var admin *dirDevice
	var fresh *dirDevice
	var second *dirDevice
	n0 := uint64(0)
	// signer's version of repoId's item at seq and version number, under title, its own pin at
	version := func(world *authorWorld, signer *dirDevice, repoId sidecar.Id, number uint64, title string) (*protocol.Announcement, error) {
		return dirRepoItem(signer, repoId, protocol.RepoKind_REPO_KIND_GENERAL, number, world.clock.Now().UnixMilli(), title)
	}
	return fileSchedule(state, []*Step{
		authorStep(state, "daemonE", func(ctx context.Context, world *authorWorld) error {
			// E's daemon writes K's r/ file at n0, and a run on its card at the same pin
			world.raiseFormat2()
			var err error
			if admin, err = world.member(ctx, "repo admin E", sidecar.NewId()); err != nil {
				return err
			}
			runner, err := world.forger("runner at n0", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			state.ids["K"] = world.repo(admin.sidecarId)
			world.publish()
			n0 = world.directoryAuth.Tip().Pin().GetVersion()
			if err := admin.client.Sync(ctx); err != nil {
				return err
			}
			item, err := version(world, admin, state.ids["K"], 1, "payroll exports")
			if err != nil {
				return err
			}
			written, err := admin.client.WriteRepoFile(ctx, item)
			if err != nil {
				return err
			}
			settings := sidecar.DefaultDirectoryCardSettings()
			if written.Seq != 1 || settings.RepoFileByteCount < written.ByteCount || written.StoredByteCount%settings.FileStepByteCount != 0 {
				return fmt.Errorf("K's r/ file as written: %+v", written)
			}
			// the run is another sidecar's, so that a fresh device's alarm at its card's stale pin names no signer of K's
			card, err := world.cardContent(runner.dirDevice, runner.sidecarId, 1, nil, dirRunItem(runner.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "a run at n0"))
			if err != nil {
				return err
			}
			if err := world.putFile(ctx, runner.sidecarId, sidecar.DirectoryCardPath(runner.sidecarId), card, nil); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "a run at n0"); err != nil || shown == nil {
				return fmt.Errorf("the run at its own pin: %v", err)
			}
			shown, err := world.reader.shownRepo(state.ids["K"])
			if err != nil || shown == nil || shown.EntryId != (sidecar.Id{}) || shown.PushPin.GetVersion() != n0 {
				return fmt.Errorf("K's item from its r/ file at n0: %+v, %v", shown, err)
			}
			if entry, _, err := world.entryAtEvs(ctx, world.reader, "payroll exports"); err != nil || entry != nil {
				return fmt.Errorf("K's item rides an announce entry beside its file: %v", err)
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
				return fmt.Errorf("a run on a card at a pin past 4,096 positions shows: %v", err)
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
				return fmt.Errorf("a RepoAdmin remove voided a file standing at a reader that accepted it: %v", err)
			}
			return nil
		}),
		authorStep(state, "daemonE", func(ctx context.Context, world *authorWorld) error {
			// T: its admin removed with no push since to the idle cards ref
			removed, err := world.forger("removed admin", sidecar.NewId())
			if err != nil {
				return err
			}
			stranger, err := world.forger("non-admin N", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			repoId := world.repo(removed.sidecarId)
			state.ids["T"] = repoId
			world.publish()
			path := sidecar.DirectoryRepoPath(repoId)
			first, err := version(world, removed.dirDevice, repoId, 1, "first")
			if err != nil {
				return err
			}
			content, err := world.repoFileContent(removed.dirDevice, repoId, 1, nil, first)
			if err != nil {
				return err
			}
			if err := world.putFile(ctx, removed.sidecarId, path, content, nil); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "first"); err != nil || shown == nil {
				return fmt.Errorf("T's first file: %v", err)
			}
			// the cards ref's head pin, where the admin still holds the right, and nothing pushed there since
			idle := world.directoryAuth.Tip().Pin()
			world.clock.Advance(time.Minute)
			world.removeAdmins(repoId, mutant)
			world.publish()

			// within 10 min of the removal, at the idle pin: stands
			world.clock.Advance(5 * time.Minute)
			second, err := version(world, removed.dirDevice, repoId, 2, "second")
			if err != nil {
				return err
			}
			if content, err = world.repoFileContent(removed.dirDevice, repoId, 2, idle, second); err != nil {
				return err
			}
			if err := world.putFile(ctx, removed.sidecarId, path, content, idle); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "second"); err != nil || shown == nil {
				return fmt.Errorf("a push at the idle pin within 10 min of the removal: %v", err)
			}

			// over 10 min after the removal at the idle pin; its own pin where it held the right, pushed at a pin after
			// the removal; a non-admin's at a fresh pin
			world.clock.Advance(6 * time.Minute)
			world.publish()
			refused := func(signer *dirForger, seq uint64, title string, at bool, pushAtIdle bool) error {
				item, err := version(world, signer.dirDevice, repoId, seq, title)
				if err != nil {
					return err
				}
				world.noteForged(item, signer.sidecarId, nil)
				atPin, pushPin := world.directoryAuth.Tip().Pin(), world.directoryAuth.Tip().Pin()
				if at {
					atPin = idle
				}
				if pushAtIdle {
					pushPin = idle
				}
				content, err := world.repoFileContent(signer.dirDevice, repoId, seq, atPin, item)
				if err != nil {
					return err
				}
				if err := world.forgeFile(ctx, signer.sidecarId, path, content, pushPin); err != nil {
					return err
				}
				return world.reader.client.Sync(ctx)
			}
			if err := refused(removed, 3, "third", true, true); err != nil {
				return err
			}
			if err := refused(removed, 4, "fourth", true, false); err != nil {
				return err
			}
			if err := refused(stranger, 5, "fifth", false, false); err != nil {
				return err
			}
			shown, err := world.reader.shownRepo(repoId)
			if err != nil || shown == nil || shown.Announcement.GetWhat().GetTitle() != "second" {
				return fmt.Errorf("T's item after the refused versions: %v, %v", shown, err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, removed.sidecarId); count != 2 {
				return fmt.Errorf("%d bad_entry alarms naming the removed admin, not its two refused versions'", count)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, stranger.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_entry alarms naming the non-admin", count)
			}
			return nil
		}),
		authorStep(state, "daemonE", func(ctx context.Context, world *authorWorld) error {
			// S: its admin's own pin over 4,096 positions before its push's, its right standing throughout
			standing, err := world.forger("standing admin", sidecar.NewId())
			if err != nil {
				return err
			}
			world.publish()
			repoId := world.repo(standing.sidecarId)
			state.ids["S"] = repoId
			world.publish()
			path := sidecar.DirectoryRepoPath(repoId)
			put := func(seq uint64, title string, forged bool, at *bridge.AuthPin) error {
				item, err := version(world, standing.dirDevice, repoId, seq, title)
				if err != nil {
					return err
				}
				content, err := world.repoFileContent(standing.dirDevice, repoId, seq, at, item)
				if err != nil {
					return err
				}
				if forged {
					world.noteForged(item, standing.sidecarId, nil)
					return world.forgeFile(ctx, standing.sidecarId, path, content, nil)
				}
				return world.putFile(ctx, standing.sidecarId, path, content, nil)
			}
			if err := put(1, "S at its first pin", false, nil); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "S at its first pin"); err != nil || shown == nil {
				return fmt.Errorf("S's first file: %v", err)
			}
			old := world.directoryAuth.Tip().Pin()
			for range sidecar.DirectoryPinPositionCount + 1 {
				world.clock.Advance(time.Millisecond)
				world.publish()
			}
			if err := put(2, "S at a pin over 4,096 before its push's", true, old); err != nil {
				return err
			}
			shown, err := world.syncShown(ctx, world.reader, "S at its first pin")
			if err != nil || shown == nil {
				return fmt.Errorf("S's item after a stale pin: %v, %v", shown, err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, standing.sidecarId); count != 1 {
				return fmt.Errorf("a pin over 4,096 before its push's: %d bad_entry alarms naming its signer", count)
			}
			if err := put(3, "S at a fresh pin", false, nil); err != nil {
				return err
			}
			if shown, err := world.syncShown(ctx, world.reader, "S at a fresh pin"); err != nil || shown == nil || shown.Seq != 3 {
				return fmt.Errorf("S's version at a fresh pin: %v, %v", shown, err)
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
			for _, write := range []struct {
				signer *dirForger
				repo   string
				title  string
			}{{signer: compromised, repo: "C", title: "release notes"}, {signer: lost, repo: "L", title: "design notes"}} {
				item, err := version(world, write.signer.dirDevice, state.ids[write.repo], 1, write.title)
				if err != nil {
					return err
				}
				content, err := world.repoFileContent(write.signer.dirDevice, state.ids[write.repo], 1, nil, item)
				if err != nil {
					return err
				}
				if err := world.putFile(ctx, write.signer.sidecarId, sidecar.DirectoryRepoPath(state.ids[write.repo]), content, nil); err != nil {
					return err
				}
			}
			for _, device := range []*dirDevice{world.reader, second} {
				if err := device.client.Sync(ctx); err != nil {
					return err
				}
				for _, title := range []string{"release notes", "design notes"} {
					if shown, err := device.shown(title); err != nil || shown == nil || shown.EntryId != (sidecar.Id{}) {
						return fmt.Errorf("%s does not show %q from its file before the revocations: %v", device.name, title, err)
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
				return fmt.Errorf("a compromised signer's file shows: %v", err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, compromised.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_entry alarms naming the compromised signer", count)
			}
			if err := second.client.Sync(ctx); err != nil {
				return err
			}
			writes, err := second.client.MaintainRepos(ctx)
			if err != nil || len(writes) != 1 || writes[0].Entry != nil {
				return fmt.Errorf("F's re-signing after the compromise: %+v, %v", writes, err)
			}
			if err := second.client.Sync(ctx); err != nil {
				return err
			}
			if again, err := second.client.MaintainRepos(ctx); err != nil || len(again) != 0 {
				return fmt.Errorf("a second pass wrote %d: %v", len(again), err)
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err := world.reader.shownRepo(state.ids["C"])
			if err != nil || shown == nil || shown.SignerSidecarId != second.sidecarId || shown.Announcement.GetVersion() != 2 || shown.Seq <= 1 || shown.EntryId != (sidecar.Id{}) {
				return fmt.Errorf("the re-signed file: %+v, %v", shown, err)
			}
			// from its attested fields alone: the void version's prose is not carried over
			if title := shown.Announcement.GetWhat().GetTitle(); title != "" {
				return fmt.Errorf("re-signed with the void version's display name %q", title)
			}
			return nil
		}),
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			// a lost revocation of L's signer: its file still stands, and F re-signs it whole
			lost := world.forgers["lost admin"]
			world.directoryFixture.Sidecars[lost.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
			world.publish()
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err := world.reader.shownRepo(state.ids["L"])
			if err != nil || shown == nil || shown.SignerSidecarId != lost.sidecarId {
				return fmt.Errorf("a lost revocation voided its signer's file: %v, %v", shown, err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, lost.sidecarId); count != 0 {
				return fmt.Errorf("%d bad_entry alarms naming a signer revoked as lost", count)
			}
			if err := second.client.Sync(ctx); err != nil {
				return err
			}
			writes, err := second.client.MaintainRepos(ctx)
			if err != nil || len(writes) != 1 || writes[0].Entry != nil {
				return fmt.Errorf("F's re-signing after the lost revocation: %+v, %v", writes, err)
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			shown, err = world.reader.shownRepo(state.ids["L"])
			if err != nil || shown == nil || shown.SignerSidecarId != second.sidecarId || shown.Announcement.GetVersion() != 2 || shown.Announcement.GetWhat().GetTitle() != "design notes" {
				return fmt.Errorf("the file re-signed whole: %v, %v", shown, err)
			}
			if fresh == nil {
				return errors.New("no fresh device was made")
			}
			return nil
		}),
	})
}

func TestFs101File(t *testing.T) {
	RunRow(t, "FS-101", "r-file", nil)
}

// The mechanism FS-101 holds readers to, a signer's right judged at its push's pin by the state's history, with the
// history gone: where the removal of T's admin never reaches the readers' state, its later files show, and the case
// fails, FI-25 judging by the ledger's removal.
func TestFs101FileMutantAStateWithoutTheRemovalFails(t *testing.T) {
	ctx := context.Background()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	state := &authorState{}
	schedule := Fs101RepoFilesAcrossRetentionOf(state, true)
	schedule.Id = "FS-101's r/ file mutant"
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
		t.Fatalf("FI-25 passes a file signed past its signer's right: %v", err)
	}
}
