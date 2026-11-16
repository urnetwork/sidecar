//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-99's M6 case on T2 (§22.8, meta review F01; §16.11's Erasure and removal block, FI-25, I-EVS-16; RECORD-M6-25),
// in the authorship world (fs84_test.go): writers A and B with announce entries and coordination notes, and an
// ordinary agent X with rw.
//
//	refused   X's ERASE naming A's entry slots, and a list mixing a slot X's own push introduced with one of A's,
//	          each get evs's scope refusal before any slot changes, every slot's rows and the erasure ref unchanged;
//	          again from a device parked for consent under an ordinary member and under an AdminSet member, whose
//	          tokens are rw and no admin, and from a read_only sidecar
//	admin     a directory admin's ERASE of A's entry destroys its keys, every reader counting it
//	breach    where evs breaches its scope rule and takes X's ERASE, every reader that held the entry keeps it, alarms
//	          bad_erasure naming X and counts no erasure
//	revoke    a repo's admin revokes it and announces it again before any runner: the request lapsed, the runner erases
//	          nothing and alarms; a request by a member with no right on P likewise; P's admin revokes P with no
//	          directory admin daemon running: the marker hides P's name from every honest reader at once, nothing is
//	          erased, and the revoker's status reads pending; past 24 h a directory admin's daemon starts, raises
//	          directory_erasure pending, and erases exactly the copies naming P, each ERASE naming the request, while
//	          a second admin's runner that synced the same work commits none
//	fresh     a fresh member device with an empty cache then opens every entry of A and B that names no P
//
// After every step, FI-25 as the authorship world holds it. TestFs99MutantEvsWithoutTheAdminScopeRuleFails runs the
// case against an evs that takes X's ERASE, which must fail it.
//
// Not here: CLOSURE, a ?closure=1 upload and POST .../slots/delete, the preservation hold and slot ETags, which are
// evs's own surface and sidecartest's streams do not serve (the T3 run, server's sidecar_directory_t3_test.go); ur
// directory revoke's and ur status's own lines past the client's; the runner killed between its CLOSURE and its
// ERASE, and the card and index cases, at the later of M6-out and M10-out.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs99M6 = Register("FS-99", "entries", []Tier{TierT2}, Fs99ErasureAuthority)

// Randomness that answers every 8-byte draw with delay, so a runner's wait is delay.
type fs99Delay struct {
	delay time.Duration
}

func (self *fs99Delay) Read(p []byte) (int, error) {
	clear(p)
	if 8 <= len(p) {
		binary.BigEndian.PutUint64(p, uint64(self.delay))
	}
	return len(p), nil
}

// Every slot row the directory's entries are held under and every ERASE evs took, as one digest: what a refused
// erasure must leave as it was.
func (self *authorWorld) slotsDigest(ctx context.Context) ([sha256.Size]byte, error) {
	digest := sha256.New()
	reader := self.admin.record.Reader()
	if err := reader.Sync(ctx, self.directoryId); err != nil {
		return [sha256.Size]byte{}, err
	}
	streams := self.streams.For(self.admin.sidecarId)
	seen := map[sidecar.Id]bool{}
	for _, entry := range reader.Entries(self.directoryId) {
		for _, held := range entry.Copies {
			if seen[held.SlotId] {
				continue
			}
			seen[held.SlotId] = true
			slot, err := streams.ReadSlot(ctx, self.directoryId, held.SlotId)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
			digest.Write(held.SlotId[:])
			for _, row := range slot.Rows {
				digest.Write(row.Row)
			}
		}
	}
	erasures, err := streams.ReadErasures(ctx, self.directoryId, 0)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	for _, erasure := range erasures {
		digest.Write(erasure.ErasureId[:])
	}
	return [sha256.Size]byte(digest.Sum(nil)), nil
}

// The ERASEs evs holds for the directory.
func (self *authorWorld) erasures(ctx context.Context) ([]*sidecar.RecordStreamErasure, error) {
	return self.streams.For(self.admin.sidecarId).ReadErasures(ctx, self.directoryId, 0)
}

func Fs99ErasureAuthority(net *Net) *Schedule {
	return Fs99ErasureAuthorityOf(&authorState{}, false)
}

// FS-99's M6 case over state; with mutant, against an evs that gives X's token admin scope.
func Fs99ErasureAuthorityOf(state *authorState, mutant bool) *Schedule {
	var runner *sidecar.DirectoryErasureRunner
	var secondRunner *sidecar.DirectoryErasureRunner
	var second *dirDevice
	raised := []string{}
	var revocation *sidecar.DirectoryRevocation
	baseline := 0
	return authorSchedule(state, []*Step{
		authorStep(state, "authority", func(ctx context.Context, world *authorWorld) error {
			for _, name := range []string{"writer A", "writer B", "writer C", "agent X", "parked device", "parked admin's device", "read-only sidecar"} {
				if _, err := world.forger(name, sidecar.NewId()); err != nil {
					return err
				}
			}
			world.directoryFixture.Sidecars[world.forgers["parked device"].sidecarId].Standing = sidecar.DirectoryStandingUnconsented
			parkedAdmin := world.forgers["parked admin's device"]
			world.directoryFixture.Sidecars[parkedAdmin.sidecarId].Standing = sidecar.DirectoryStandingUnconsented
			world.directoryFixture.AdminMemberIds = append(world.directoryFixture.AdminMemberIds, parkedAdmin.memberId)
			if err := world.streams.Grant(world.directoryId, world.forgers["read-only sidecar"].sidecarId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
				return err
			}
			if mutant {
				if err := world.streams.Grant(world.directoryId, world.forgers["agent X"].sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
					return err
				}
			}
			world.publish()
			nowMillis := world.clock.Now().UnixMilli()
			for _, write := range []struct {
				writer string
				title  string
			}{
				{writer: "writer A", title: "A's run"}, {writer: "writer A", title: "A's run to erase"}, {writer: "writer B", title: "B's run"},
				{writer: "writer C", title: "C's run"}, {writer: "agent X", title: "X's own run"},
			} {
				forger := world.forgers[write.writer]
				if err := world.announce(ctx, forger, dirRunItem(forger.dirDevice, sidecar.NewId(), 1, nowMillis, write.title)); err != nil {
					return err
				}
			}
			for _, writer := range []string{"writer A", "writer B"} {
				if err := world.note(ctx, world.forgers[writer], "the loader's tests pass; taking the review next"); err != nil {
					return err
				}
			}
			if err := world.reader.client.Sync(ctx); err != nil {
				return err
			}
			for _, title := range []string{"A's run", "A's run to erase", "B's run", "C's run", "X's own run"} {
				if shown, err := world.reader.shown(title); err != nil || shown == nil {
					return fmt.Errorf("%q does not show: %v", title, err)
				}
			}
			return nil
		}),
		authorStep(state, "agentX", func(ctx context.Context, world *authorWorld) error {
			target, _, err := world.entryAtEvs(ctx, world.admin, "A's run")
			if err != nil || target == nil {
				return fmt.Errorf("A's entry at evs: %v", err)
			}
			own, _, err := world.entryAtEvs(ctx, world.admin, "X's own run")
			if err != nil || own == nil {
				return fmt.Errorf("X's own entry at evs: %v", err)
			}
			before, err := world.slotsDigest(ctx)
			if err != nil {
				return err
			}
			// a list mixing X's own slot with A's, as X
			mixed := &sidecar.RecordReadEntry{EntryId: own.EntryId, Copies: append(slices.Clone(own.Copies), target.Copies...)}
			attempts := []struct {
				name  string
				actor string
				entry *sidecar.RecordReadEntry
			}{
				{name: "X's ERASE naming A's entry slots", actor: "agent X", entry: target},
				{name: "X's ERASE mixing its own slot with A's", actor: "agent X", entry: mixed},
				{name: "an ERASE from a device parked for consent", actor: "parked device", entry: target},
				{name: "an ERASE from an AdminSet member's parked device", actor: "parked admin's device", entry: target},
				{name: "an ERASE from a read_only sidecar", actor: "read-only sidecar", entry: target},
			}
			for _, attempt := range attempts {
				err := world.eraseAs(ctx, world.forgers[attempt.actor].sidecarId, attempt.entry)
				refusal := &sidecar.RecordStreamRefusal{}
				if !errors.As(err, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
					return fmt.Errorf("%s was not refused for its scope: %v", attempt.name, err)
				}
				after, err := world.slotsDigest(ctx)
				if err != nil {
					return err
				}
				if after != before {
					return fmt.Errorf("%s changed a slot or the erasure ref", attempt.name)
				}
			}
			if erasures, err := world.erasures(ctx); err != nil || len(erasures) != 0 {
				return fmt.Errorf("%d ERASEs after the refused ones: %v", len(erasures), err)
			}
			for _, title := range []string{"A's run", "X's own run"} {
				if shown, err := world.syncShown(ctx, world.reader, title); err != nil || shown == nil {
					return fmt.Errorf("%q after the refused ERASEs: %v", title, err)
				}
			}
			return nil
		}),
		authorStep(state, "daemonD", func(ctx context.Context, world *authorWorld) error {
			// the positive: a directory admin's ERASE of A's entry destroys its keys
			world.admin.client.BindEraser(world.admin.record.Eraser().Erase)
			shown, err := world.syncShown(ctx, world.admin, "A's run to erase")
			if err != nil || shown == nil {
				return fmt.Errorf("D does not show A's entry: %v", err)
			}
			result, err := world.admin.client.Erase(ctx, &sidecar.DirectoryEraseArgs{Id: sidecar.Id(shown.Announcement.GetAnnouncementId()), Confirmed: true})
			if err != nil {
				return err
			}
			if !slices.Equal(result.EntryIds, []sidecar.Id{shown.EntryId}) {
				return fmt.Errorf("the admin's erasure: %+v", result)
			}
			if err := world.admin.record.Flush(ctx); err != nil {
				return err
			}
			if entry, _, err := world.entryAtEvs(ctx, world.admin, "A's run to erase"); err != nil || entry != nil {
				return fmt.Errorf("the erased entry keeps a readable key: %v", err)
			}
			for range 2 {
				if err := world.reader.client.Sync(ctx); err != nil {
					return err
				}
			}
			if still, err := world.reader.shown("A's run to erase"); err != nil || still != nil {
				return fmt.Errorf("the erased item still shows: %v", err)
			}
			erasure, ok := world.reader.client.ErasureOf(shown.EntryId)
			if !ok || erasure.EraserSidecarId != world.admin.sidecarId {
				return fmt.Errorf("the admin's ERASE as a reader counts it: %+v, %v", erasure, ok)
			}
			if count := world.reader.alarmCount(sidecar.SidecarRecordAlarmBadErasure); count != 0 {
				return fmt.Errorf("%d bad_erasure alarms on an admin's ERASE", count)
			}
			if other, err := world.reader.shown("A's run"); err != nil || other == nil {
				return fmt.Errorf("A's other entry went with the erased one: %v", err)
			}
			return nil
		}),
		authorStep(state, "agentX", func(ctx context.Context, world *authorWorld) error {
			// evs breaching its scope rule takes X's ERASE of C's entry: readers that held it keep it and alarm
			rogue := world.forgers["agent X"]
			if err := world.streams.Grant(world.directoryId, rogue.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
				return err
			}
			entry, _, err := world.entryAtEvs(ctx, world.admin, "C's run")
			if err != nil || entry == nil {
				return fmt.Errorf("C's entry at evs: %v", err)
			}
			world.uncounted = append(world.uncounted, entry.EntryId)
			if err := world.eraseAs(ctx, rogue.sidecarId, entry); err != nil {
				return err
			}
			if err := world.streams.Grant(world.directoryId, rogue.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
				return err
			}
			for range 2 {
				if err := world.reader.client.Sync(ctx); err != nil {
					return err
				}
			}
			if shown, err := world.reader.shown("C's run"); err != nil || shown == nil {
				return fmt.Errorf("a non-admin's ERASE hid C's item at a reader that held it: %v", err)
			}
			if count := world.reader.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, rogue.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_erasure alarms naming X", count)
			}
			if _, ok := world.reader.client.ErasureOf(entry.EntryId); ok {
				return errors.New("a non-admin's ERASE reads as an erasure")
			}
			return nil
		}),
		authorStep(state, "daemonA", func(ctx context.Context, world *authorWorld) error {
			// P announced with a run of A's in it; a second repo Q of the same admin announced, revoked and announced
			// again before any runner, so its request lapsed
			queueId := sidecar.NewId()
			next := world.directoryAuth.Tip().Pin().GetVersion() + 1
			world.directoryFixture.Repos[queueId] = &sidecartest.FakeDirectoryRepo{
				Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: world.approver.sidecarId, At: next}},
			}
			world.rights[queueId] = map[sidecar.Id]*dirRight{world.approver.sidecarId: {from: next}}
			world.publish()
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			if _, err := world.approver.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.repoId, DisplayName: "launch plans", Confirmed: true}); err != nil {
				return err
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			writer := world.forgers["writer A"]
			inRepo := dirRunItem(writer.dirDevice, sidecar.NewId(), 1, world.clock.Now().UnixMilli(), "A's run in P")
			inRepo.Where.RepoId = world.repoId.Bytes()
			if err := world.announce(ctx, writer, inRepo); err != nil {
				return err
			}
			if _, err := world.approver.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: queueId, DisplayName: "old drafts", Confirmed: true}); err != nil {
				return err
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			lapsed, err := world.approver.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: queueId, Confirmed: true})
			if err != nil {
				return err
			}
			if _, err := world.approver.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: queueId, DisplayName: "old drafts", Confirmed: true}); err != nil {
				return err
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			state.ids["lapsed"] = lapsed.RequestId

			// and a member with no right on P files a request for it
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
			state.ids["forged"] = forgedId
			state.ids["stranger"] = stranger.sidecarId
			return stranger.record.Flush(ctx)
		}),
		authorStep(state, "daemonD", func(ctx context.Context, world *authorWorld) error {
			var err error
			runner, err = sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
				Client: world.admin.client, Erase: world.admin.record.Eraser().Erase, Random: &fs99Delay{delay: 4 * time.Minute},
				Raise: func(repoId sidecar.Id, requestId sidecar.Id, outcome string) error {
					raised = append(raised, outcome)
					return nil
				},
			})
			if err != nil {
				return err
			}
			held, err := world.erasures(ctx)
			if err != nil {
				return err
			}
			baseline = len(held)
			if err := world.admin.client.Sync(ctx); err != nil {
				return err
			}
			pass, err := runner.Pass(ctx)
			if err != nil {
				return err
			}
			if !slices.Contains(pass.Refused, state.ids["lapsed"]) || !slices.Contains(pass.Refused, state.ids["forged"]) || len(pass.Erased) != 0 || len(pass.Pending) != 0 {
				return fmt.Errorf("the pass over a lapsed and a rightless request: %+v", pass)
			}
			if count := world.admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, state.ids["stranger"]); count != 1 {
				return fmt.Errorf("%d bad_erasure alarms naming the signer with no right", count)
			}
			if count := world.admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, world.approver.sidecarId); count != 1 {
				return fmt.Errorf("%d bad_erasure alarms naming the signer of the lapsed request", count)
			}
			if held, err := world.erasures(ctx); err != nil || len(held) != baseline {
				return fmt.Errorf("an ERASE for a refused request: %v", err)
			}
			if len(raised) != 0 {
				return fmt.Errorf("directory_erasure raised for refused requests: %v", raised)
			}
			if shown, err := world.syncShown(ctx, world.reader, "old drafts"); err != nil || shown == nil {
				return fmt.Errorf("Q's item announced again: %v", err)
			}
			if shown, err := world.reader.shown("launch plans"); err != nil || shown == nil {
				return fmt.Errorf("P's item after a rightless request: %v", err)
			}
			return nil
		}),
		authorStep(state, "daemonA", func(ctx context.Context, world *authorWorld) error {
			// P's admin revokes with no directory admin daemon running
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			var err error
			if revocation, err = world.approver.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.repoId, Confirmed: true}); err != nil {
				return err
			}
			if revocation.State != sidecar.DirectoryRevocationPending {
				return fmt.Errorf("the revocation: %+v", revocation)
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			// the marker hides P's name from every honest reader at once
			if shown, err := world.syncShown(ctx, world.reader, "launch plans"); err != nil || shown != nil {
				return fmt.Errorf("P's name after the marker: %v", err)
			}
			items, err := world.reader.items()
			if err != nil {
				return err
			}
			marked := slices.ContainsFunc(items, func(item *sidecar.DirectoryItem) bool {
				return bytes.Equal(item.Announcement.GetWhere().GetRepoId(), world.repoId.Bytes()) && item.Display == sidecar.DirectoryItemPrivate
			})
			if !marked {
				return errors.New("no private marker stands for P")
			}
			// nothing is erased, and the revoker reads pending with its age
			if held, err := world.erasures(ctx); err != nil || len(held) != baseline {
				return fmt.Errorf("an ERASE with no runner: %v", err)
			}
			if readable, err := world.readableNaming(ctx, world.repoId); err != nil || readable == 0 {
				return fmt.Errorf("%d copies naming P are readable before any runner: %v", readable, err)
			}
			world.clock.Advance(25 * time.Hour)
			world.publish()
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			lines := world.approver.client.ErasureStatusLines(nil)
			if len(lines) == 0 || !strings.Contains(lines[0], "is pending for 25h") {
				return fmt.Errorf("the revoker's status 25 h on: %q", lines)
			}
			return nil
		}),
		authorStep(state, "daemonD", func(ctx context.Context, world *authorWorld) error {
			// two directory admins' daemons start; both sync the work before either's ERASE commits
			var err error
			if second, err = world.device("directory admin D2", sidecar.NewId(), true); err != nil {
				return err
			}
			world.publish()
			if err := world.open(second); err != nil {
				return err
			}
			if secondRunner, err = sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
				Client: second.client, Erase: second.record.Eraser().Erase, Random: zeroReader{},
			}); err != nil {
				return err
			}
			if err := world.admin.client.Sync(ctx); err != nil {
				return err
			}
			if err := second.client.Sync(ctx); err != nil {
				return err
			}
			// the pass that first shows the work, a day and an hour old, raises pending and waits its delay
			pass, err := runner.Pass(ctx)
			if err != nil {
				return err
			}
			if !pass.Runs || len(pass.Erased) != 0 || !slices.Equal(pass.Delayed, []sidecar.Id{revocation.RequestId}) || len(pass.Pending) != 1 || pass.Pending[0].Age < 25*time.Hour {
				return fmt.Errorf("the pass that first shows the work: %+v", pass)
			}
			if !slices.Equal(raised, []string{sidecar.SidecarDirectoryErasurePending}) {
				return fmt.Errorf("directory_erasure past 24 h: %v", raised)
			}
			if held, err := world.erasures(ctx); err != nil || len(held) != baseline {
				return fmt.Errorf("an ERASE inside the runner's delay: %v", err)
			}
			world.clock.Advance(4 * time.Minute)
			if pass, err = runner.Pass(ctx); err != nil {
				return err
			}
			if len(pass.Erased) != 1 || len(pass.Erased[revocation.RequestId]) == 0 {
				return fmt.Errorf("the first runner erased %v", pass.Erased)
			}
			if _, err := secondRunner.Pass(ctx); err != nil {
				return fmt.Errorf("the second runner: %w", err)
			}
			if err := world.admin.record.Flush(ctx); err != nil {
				return err
			}
			if err := second.record.Flush(ctx); err != nil {
				return err
			}
			held, err := world.erasures(ctx)
			if err != nil || len(held) <= baseline {
				return fmt.Errorf("no ERASE for the revocation: %v", err)
			}
			for _, erasure := range held[baseline:] {
				if erasure.ErasureId != revocation.RequestId || erasure.EraserSidecarId != world.admin.sidecarId {
					return fmt.Errorf("an ERASE %s by %s: not the request's by the first runner", erasure.ErasureId, erasure.EraserSidecarId)
				}
			}
			// exactly the copies naming P
			if readable, err := world.readableNaming(ctx, world.repoId); err != nil || readable != 0 {
				return fmt.Errorf("%d copies naming P keep a readable key: %v", readable, err)
			}
			for _, title := range []string{"A's run", "B's run", "X's own run"} {
				if entry, _, err := world.entryAtEvs(ctx, world.admin, title); err != nil || entry == nil {
					return fmt.Errorf("%q was erased with P's copies: %v", title, err)
				}
			}
			if entry, _, err := world.entryAtEvs(ctx, world.admin, "A's run in P"); err != nil || entry != nil {
				return fmt.Errorf("A's run in P keeps a readable key: %v", err)
			}
			// the runner raises done, and the revoker reads done by the first runner
			if err := world.admin.client.Sync(ctx); err != nil {
				return err
			}
			if pass, err = runner.Pass(ctx); err != nil || len(pass.Erased) != 0 || len(pass.Pending) != 0 {
				return fmt.Errorf("the pass after the erasure: %+v, %v", pass, err)
			}
			if !slices.Contains(raised, sidecar.SidecarDirectoryErasureDone) {
				return fmt.Errorf("directory_erasure once erased: %v", raised)
			}
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			revocations, err := world.approver.client.Revocations()
			if err != nil {
				return err
			}
			done := slices.ContainsFunc(revocations, func(held *sidecar.DirectoryRevocation) bool {
				return held.RequestId == revocation.RequestId && held.State == sidecar.DirectoryRevocationDone && held.EraserSidecarId != nil && *held.EraserSidecarId == world.admin.sidecarId
			})
			if !done {
				return fmt.Errorf("the revocation at its revoker: %+v", revocations)
			}
			return nil
		}),
		authorStep(state, "daemonF", func(ctx context.Context, world *authorWorld) error {
			// a fresh member device with an empty cache opens every entry of A and B that names no P
			fresh, err := world.member(ctx, "fresh device", sidecar.NewId())
			if err != nil {
				return err
			}
			if err := fresh.client.Sync(ctx); err != nil {
				return err
			}
			reader := fresh.record.Reader()
			if err := reader.Sync(ctx, world.directoryId); err != nil {
				return err
			}
			writers := map[sidecar.Id]string{world.forgers["writer A"].sidecarId: "A", world.forgers["writer B"].sidecarId: "B"}
			opened := map[string]int{}
			closed := 0
			for _, entry := range reader.Entries(world.directoryId) {
				name, ok := writers[sidecar.Id(entry.Header.Header.GetWriterSidecarId())]
				if !ok {
					continue
				}
				if entry.State == sidecar.RecordEntryLive && entry.Body != nil {
					if item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body); err == nil && bytes.Equal(item.GetWhere().GetRepoId(), world.repoId.Bytes()) {
						return fmt.Errorf("a fresh device opens %s's entry naming P", name)
					}
					opened[name] += 1
				} else {
					closed += 1
				}
			}
			// A's run and note and B's run and note open; A's erased run and its run in P do not
			if opened["A"] != 2 || opened["B"] != 2 || closed != 2 {
				return fmt.Errorf("a fresh device opens %v entries of A and B, %d closed", opened, closed)
			}
			if count := fresh.alarmCount(sidecar.SidecarRecordAlarmBadEntry); count != 0 {
				return fmt.Errorf("%d bad_entry alarms on a fresh device", count)
			}
			return nil
		}),
	})
}

func TestFs99M6(t *testing.T) {
	RunRow(t, "FS-99", "entries", nil)
}

// The mechanism FS-99 holds evs to, gone: an evs that gives X's rw token admin scope takes its ERASE of A's entry
// slots, and the case fails at that step.
func TestFs99MutantEvsWithoutTheAdminScopeRuleFails(t *testing.T) {
	ctx := context.Background()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	schedule := Fs99ErasureAuthorityOf(&authorState{}, true)
	schedule.Id = "FS-99's entries mutant"
	result := Run(ctx, schedule, net)
	if result.Err == nil {
		t.Fatal("the mutant passed")
	}
	if !strings.Contains(result.Err.Error(), "X's ERASE naming A's entry slots was not refused") {
		t.Fatalf("the mutant failed elsewhere: %v", result.Err)
	}
}
