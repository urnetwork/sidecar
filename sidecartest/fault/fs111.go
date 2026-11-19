//go:build sidecar_testhooks

// FS-111 on real engines (§11.14's cut, epoch, erase and writers rows; §11.12's cut and reconcile rows; D-EVS-66,
// I-EVS-17, FI-2, FI-19; SEARCH-M10-37): an erasure's CUT fencing an index push paused before its head CAS, on the evs
// world at format 2 (fs74.go's settings), the index's own eraser (SEARCH-M10-16, SEARCH-M10-17) reaching evs through
// EvsRepo (search_erase_evs_testhooks.go) as every index builder does, through evsservice's engine on T2's fakes and,
// through server's evshost, on T3's stores.
//
//	Fs111CutFencesAPausedPushOnEvs  writerA's in-ref push writes a note D into its head; its next push, of another
//	                                note, planned with D still in that head, is paused at evs1 just before its head
//	                                CAS; eraser B, the repo's admin, CUTs D through EvsRepo, moving the ref's
//	                                index_epoch to the CUT's version, then rewrites writerA's head by CLOSURE and dies
//	                                right after it; the paused push, released, is refused 409 INDEX_EPOCH, its push id
//	                                never committing (FI-2), and is planned again from the head and the erasure set,
//	                                committing the new note without D; the clock passes 20 min, and B's device
//	                                starting again resumes the erasure from evs's state; the reader's view of the index
//	                                holds D nowhere live and the new note live
//
// Not here, beside what fs111_test.go's header names: a slot-keyed repo's ERASEs and its keys (the world is a
// general repo, whose CLOSUREs no ERASE follows, their keys riding segments) and the purge of the old ciphertext
// (EVSB-M10-01's purge is not wired: nothing calls PurgeSink.Certain), so FI-19's stored-version clause is the search
// world's (fs111_test.go); and completion, since EvsRepo's Retained names no removed index path and answers
// incomplete, so no erasure on the real store says complete yet (SEARCH-M10-17's draft). The index's seams here are the
// root's under sidecar_testhooks alone, so the case is registered only on that build.

package fault

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs111 = Register("FS-111", "", []Tier{TierT2, TierT3}, Fs111CutFencesAPausedPushOnEvs)

// fs74.go's world, writerB the repo's admin: the eraser.
func fs111EvsWorldSettings() *EvsWorldSettings {
	settings := fs74EvsWorldSettings()
	for _, device := range settings.Devices {
		if device.Name == "writerB" {
			device.Admin = true
		}
	}
	return settings
}

// See the file header.
func Fs111CutFencesAPausedPushOnEvs(net *Net) *Schedule {
	world := NewEvsWorld(net, fs111EvsWorldSettings())
	digest := sha256.Sum256([]byte("fs111 evs erasure"))
	erasureId := sidecar.Id(digest[:16])
	notes := map[string][]byte{
		"notes/cormorant.md":  []byte("the cormorant at noon\n"),
		"notes/lighthouse.md": []byte("a lighthouse keeper's log\n"),
	}
	// the repo's admin, whose erasure set versions count
	isAdmin := func(signer sidecar.Id) bool {
		eraser := world.Device("writerB")
		return eraser != nil && signer == eraser.Signer.SidecarId
	}
	install := func(ctx context.Context, net *Net) error {
		for _, name := range []string{"writerA", "writerB"} {
			device := world.Device(name)
			if device == nil || device.Client == nil {
				return fmt.Errorf("device %s is not started", name)
			}
			remove, err := sidecar.InstallSearchTestIndexWriter(device.Client, &sidecar.SearchTestIndexWriterArgs{IsAdmin: isAdmin})
			if err != nil {
				return err
			}
			context.AfterFunc(net.Context(), remove)
		}
		return nil
	}
	docKey := func(ctx context.Context, path string) ([16]byte, error) {
		return sidecar.SearchTestEvsDocKey(ctx, world.Device("reader").Repo, world.RefId(), path)
	}
	read := func(ctx context.Context) (*sidecar.SearchTestEvsIndex, error) {
		return sidecar.ReadSearchTestEvsIndex(ctx, world.Device("reader").Repo, nil, isAdmin)
	}
	eraser := func(ctx context.Context) (*sidecar.IndexEraser, error) {
		return sidecar.NewSearchTestEvsEraser(ctx, world.Device("writerB").Repo, nil, isAdmin)
	}
	var cutVersion uint64
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: install},
		{Actor: "writerA", Action: world.Write("writerA", "notes/cormorant.md", notes["notes/cormorant.md"])},
		// planned with D in writerA's head, and paused at its head CAS: the cormorant note's CAS passed first
		{Actor: "writerA", Action: world.Write("writerA", "notes/lighthouse.md", notes["notes/lighthouse.md"]), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 1},
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			key, err := docKey(ctx, "notes/cormorant.md")
			if err != nil {
				return err
			}
			b, err := eraser(ctx)
			if err != nil {
				return err
			}
			result, err := b.Cut(ctx, &sidecar.IndexCutArgs{ErasureId: erasureId, Documents: []*sidecar.IndexCutDocument{{Key: key, Version: 1}}})
			if err != nil {
				return fmt.Errorf("B's CUT: %w", err)
			}
			if !result.Pushed || result.Version == 0 {
				return fmt.Errorf("B's CUT pushed nothing: %+v", result)
			}
			cutVersion = result.Version
			epoch, err := sidecar.SearchTestEvsIndexEpoch(ctx, world.Device("reader").Repo, nil)
			if err != nil {
				return err
			}
			if epoch != cutVersion {
				return fmt.Errorf("after the CUT at %d the ref's index_epoch is %d", cutVersion, epoch)
			}
			return nil
		}},
		// B rewrites writerA's head, which still holds D, and dies right after its first CLOSURE
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			b, err := eraser(ctx)
			if err != nil {
				return err
			}
			_, err = b.Rewrite(ctx, &sidecar.IndexRewriteArgs{ErasureId: erasureId})
			return err
		}, Background: true},
		{Actor: "writerB", Await: "evs.index.erase.closed"},
		{Actor: "writerB", Kill: true},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectCommitted("writerA", "notes/lighthouse.md")},
		// the paused attempt was refused 409 INDEX_EPOCH, and its push id never commits (FI-2)
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			refused := 0
			for _, attempt := range world.Attempts() {
				if attempt.Answer == nil || attempt.Answer.Code != protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH {
					continue
				}
				refused += 1
				if _, committed := world.committedVersionOf(attempt.PushId); committed {
					return fmt.Errorf("a push refused 409 INDEX_EPOCH committed")
				}
			}
			if refused == 0 {
				return fmt.Errorf("no attempt was refused 409 INDEX_EPOCH: %v", world.Attempts())
			}
			return nil
		}},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			index, err := read(ctx)
			if err != nil {
				return err
			}
			if index.Version <= cutVersion {
				return fmt.Errorf("the paused push committed nothing after the CUT at %d: the ref at %d", cutVersion, index.Version)
			}
			erased, err := docKey(ctx, "notes/cormorant.md")
			if err != nil {
				return err
			}
			kept, err := docKey(ctx, "notes/lighthouse.md")
			if err != nil {
				return err
			}
			if index.Live[erased] != 0 || index.Live[kept] == 0 {
				return fmt.Errorf("after the rebuilt push the index holds D at %d and the new note at %d", index.Live[erased], index.Live[kept])
			}
			return nil
		}},
		// 20 min pass, and B's device starts again
		{Advance: 20 * time.Minute},
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			restarted, err := eraser(ctx)
			if err != nil {
				return err
			}
			resumed, err := restarted.Resume(ctx, &sidecar.IndexResumeArgs{ErasureId: erasureId, Role: sidecar.IndexResumeEraser})
			if err != nil {
				return fmt.Errorf("B's resume: %w", err)
			}
			if resumed.Rewrite == nil || resumed.Cut != nil {
				return fmt.Errorf("B's resume: %+v", resumed)
			}
			closures, err := sidecar.SearchTestEvsClosureCount(ctx, world.Device("writerB").Repo, nil, erasureId)
			if err != nil {
				return err
			}
			if closures == 0 {
				return fmt.Errorf("evs holds no CLOSURE of the erasure")
			}
			return nil
		}},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			index, err := read(ctx)
			if err != nil {
				return err
			}
			erased, err := docKey(ctx, "notes/cormorant.md")
			if err != nil {
				return err
			}
			kept, err := docKey(ctx, "notes/lighthouse.md")
			if err != nil {
				return err
			}
			if index.Live[erased] != 0 || index.Live[kept] == 0 {
				return fmt.Errorf("after the erasure's resume the index holds D at %d and the new note at %d", index.Live[erased], index.Live[kept])
			}
			return nil
		}},
	}
	return &Schedule{Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
