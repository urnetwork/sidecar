//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// The git-lfs store's daily prune (EVS2-M10-28; FS-73's prune clauses on T2 with a fake clock): an object past N that
// no tip and no recent commit requires removed, a required one and a young one kept; a device missing a ref's tip
// refusing; a touch racing the prune winning at path-level CAS and the rerun keeping the object; two devices pruning
// at once, the second losing harmlessly; and the settings file: absent, 0, under 7 and as written, its write held to
// 7 to 365, and a version no admin signed read as the default.

package sidecar

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A prune's world: the store's stand-in evs, a bare repository, and one ref whose tip the device holds.
type evsTestPrune struct {
	lfs  *evsTestLfsStore
	repo *evsTestLfsRepo
	tip  *EvsGitOid
}

func newEvsTestPrune(t *testing.T) *evsTestPrune {
	return &evsTestPrune{lfs: newEvsTestLfsStore(t), repo: newEvsTestLfsRepo(t)}
}

// The prune's args over the world's one ref.
func (self *evsTestPrune) args() *EvsLfsPruneArgs {
	return &EvsLfsPruneArgs{
		Store: self.lfs.store,
		Git:   self.repo.lfs(),
		Tips: func(ctx context.Context) ([]*EvsLfsPruneTip, error) {
			return []*EvsLfsPruneTip{{RefName: []byte("refs/heads/main"), Version: 1, Tip: self.tip}}, nil
		},
	}
}

func (self *evsTestPrune) clock() *evsTestClock {
	return self.lfs.writer.test.clock
}

// Stores content, returning its oid.
func (self *evsTestPrune) put(t *testing.T, content []byte) EvsLfsOid {
	t.Helper()
	_, oid := evsTestLfsPointerOf(content)
	if _, err := self.lfs.put(t, oid, content); err != nil {
		t.Fatal(err)
	}
	return oid
}

// Whether the store holds oid now.
func (self *evsTestPrune) present(t *testing.T, oid EvsLfsOid) bool {
	t.Helper()
	objects, err := self.lfs.store.Newest(context.Background(), []EvsLfsOid{oid}, true)
	if err != nil {
		t.Fatal(err)
	}
	return objects[0].Present()
}

// Objects past N that nothing requires go; a tip's object and a young one stay.
func TestEvsLfsPruneRemovesOldUnrequiredObjects(t *testing.T) {
	prune := newEvsTestPrune(t)
	required := prune.put(t, []byte("required object"))
	old := prune.put(t, []byte("old object"))
	pointer, _ := evsTestLfsPointerOf([]byte("required object"))
	tip := prune.repo.commit(map[string]string{".gitattributes": "*.bin filter=lfs\n", "required.bin": pointer})
	prune.tip = &tip
	prune.clock().advance(31 * 24 * time.Hour)
	young := prune.put(t, []byte("young object"))
	result, err := EvsLfsPrune(context.Background(), prune.args())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 1 || result.Removed[0] != old || result.RequiredCount != 1 || result.YoungCount != 1 || result.Window != 30*24*time.Hour {
		t.Fatalf("the prune: %+v", result)
	}
	if prune.present(t, old) || !prune.present(t, required) || !prune.present(t, young) {
		t.Fatal("the prune removed what it should keep, or kept what it should remove")
	}
}

// A device missing a ref's tip refuses, removing nothing: a tip it cannot see could need an object.
func TestEvsLfsPruneRefusesOnADeviceMissingARef(t *testing.T) {
	prune := newEvsTestPrune(t)
	old := prune.put(t, []byte("old object"))
	prune.clock().advance(31 * 24 * time.Hour)
	_, err := EvsLfsPrune(context.Background(), prune.args())
	if !errors.Is(err, ErrEvsLfsPruneRefMissing) {
		t.Fatalf("a device missing a ref's tip: %v", err)
	}
	if !prune.present(t, old) {
		t.Fatal("a refused prune removed an object")
	}
}

// A git push's touch racing the prune, between its read and its removal: the removal fails path-level CAS, the rerun
// reads the object fresh, and it stays.
func TestEvsLfsPruneLosesToARacingTouch(t *testing.T) {
	prune := newEvsTestPrune(t)
	raced := prune.put(t, []byte("raced object"))
	tip := prune.repo.commit(map[string]string{"plain.txt": "no pointer"})
	prune.tip = &tip
	prune.clock().advance(31 * 24 * time.Hour)
	args := prune.args()
	touched := false
	args.beforeRemove = func(ctx context.Context) {
		if touched {
			return
		}
		touched = true
		// another device's touch, on the version it read before the prune's removal
		other := NewEvsLfsStore(prune.lfs.writer.repo)
		objects, err := other.Newest(ctx, []EvsLfsOid{raced}, true)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := other.Touch(ctx, objects); err != nil {
			t.Error(err)
		}
	}
	result, err := EvsLfsPrune(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	if result.RerunCount != 1 || len(result.Removed) != 0 || !prune.present(t, raced) {
		t.Fatalf("a touch racing the prune: %+v", result)
	}
}

// Two devices pruning at once: the second's removal lands first, the first's loses CAS and its rerun finds nothing.
func TestEvsLfsPruneTwoDevicesAtOnce(t *testing.T) {
	prune := newEvsTestPrune(t)
	old := prune.put(t, []byte("old object"))
	tip := prune.repo.commit(map[string]string{"plain.txt": "no pointer"})
	prune.tip = &tip
	prune.clock().advance(31 * 24 * time.Hour)
	first := prune.args()
	ran := false
	first.beforeRemove = func(ctx context.Context) {
		if ran {
			return
		}
		ran = true
		second := prune.args()
		second.Store = NewEvsLfsStore(prune.lfs.writer.repo)
		if _, err := EvsLfsPrune(ctx, second); err != nil {
			t.Error(err)
		}
	}
	result, err := EvsLfsPrune(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if result.RerunCount != 1 || len(result.Removed) != 0 || prune.present(t, old) {
		t.Fatalf("two prunes at once: %+v", result)
	}
}

// The settings file's window: absent 30 days, under 7 read as 7, as written from 7; its write held to 7 to 365; and a
// version no admin signed read as the default, alarming.
func TestEvsLfsWindowFromItsSettingsFile(t *testing.T) {
	settings := DefaultEvsSettings()
	for _, c := range []struct {
		days uint32
		want time.Duration
	}{
		{days: 0, want: 30 * 24 * time.Hour},
		{days: 3, want: 7 * 24 * time.Hour},
		{days: 7, want: 7 * 24 * time.Hour},
		{days: 90, want: 90 * 24 * time.Hour},
	} {
		decoded, err := DecodeEvsLfsSettings(EncodeEvsLfsSettings(c.days))
		if err != nil || decoded != c.days {
			t.Fatalf("window_days %d round-tripped as %d: %v", c.days, decoded, err)
		}
		if got := EvsLfsWindow(decoded, settings); got != c.want {
			t.Errorf("window_days %d reads %s, want %s", c.days, got, c.want)
		}
	}
	prune := newEvsTestPrune(t)
	ctx := context.Background()
	store := prune.lfs.store
	if window, err := store.Window(ctx, nil, nil); err != nil || window != 30*24*time.Hour {
		t.Fatalf("no settings file: %s, %v", window, err)
	}
	for _, days := range []uint32{5, 366} {
		if _, err := store.SetWindow(ctx, days); !errors.Is(err, ErrEvsLfsWindowInvalid) {
			t.Fatalf("a window of %d days: %v", days, err)
		}
	}
	prune.lfs.writer.server.know(EvsLfsSettingsPath)
	if _, err := store.SetWindow(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if window, err := store.Window(ctx, func(Id, time.Time) bool { return true }, nil); err != nil || window != 10*24*time.Hour {
		t.Fatalf("a window of 10 days written: %s, %v", window, err)
	}
	alarms := 0
	window, err := store.Window(ctx, func(Id, time.Time) bool { return false }, func(error) { alarms += 1 })
	if err != nil || window != 30*24*time.Hour || alarms != 1 {
		t.Fatalf("a version no admin signed: %s, %d alarms, %v", window, alarms, err)
	}
}
