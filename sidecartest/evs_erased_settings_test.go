//go:build !sidecar_http && !ios_extension

package sidecartest

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The same signer admissions and repo admin rows as the engine, made available to the index settings judge.
type erasedSettingsConfig struct {
	*FakeGkmAuthView
	acl *sidecar.AclState
}

func (self *erasedSettingsConfig) Acl() (*sidecar.AclState, error) { return self.acl, nil }

// A retained older setting still governs when a later checkpoint's slot is erased. The next admin write replaces
// that erased checkpoint under a new key and leaves the readable setting's slot intact.
func TestEvsIndexSettingsReadPastAnErasedCheckpoint(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	ctx := world.ctx
	auth := world.currentView()
	admissions := NewFakeAclView()
	admissions.pin = auth.Pin()
	admissions.members[world.memberId] = auth.Member(world.memberId)
	for _, signer := range world.signers {
		admissions.sidecars[signer.SidecarId] = &sidecar.AclSidecar{Row: auth.SidecarRow(signer.SidecarId), MemberId: world.memberId}
	}
	acl, err := sidecar.NewAclState(auth.acl, admissions)
	if err != nil {
		t.Fatal(err)
	}
	world.config = func() sidecar.GkmAuthView { return &erasedSettingsConfig{auth, acl} }
	writer, reader := world.format2Device("w"), world.format2Device("r")
	if _, err := writer.write("initialize", []byte("record")); err != nil {
		t.Fatal(err)
	}
	const path = ".ur-index/i1/settings"
	set := func(days uint32) uint64 {
		t.Helper()
		result, err := writer.repo.IndexSettings(ctx, &sidecar.EvsIndexSettingsArgs{Action: sidecar.EvsIndexWindow, WindowDays: days})
		if err != nil || len(result.Roots) != 1 || result.Roots[0].Version == 0 {
			t.Fatalf("window %d: %+v, %v", days, result, err)
		}
		return result.Roots[0].Version
	}
	first := set(14)
	var content bytes.Buffer
	if _, err := reader.repo.ReadVersion(ctx, &sidecar.EvsReadArgs{Path: path, Version: first}, &content); err != nil {
		t.Fatal(err)
	}
	// A checkpoint over unchanged content has its own key. It can be erased independently.
	second, err := writer.repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{
		Path: path, Content: bytes.NewReader(content.Bytes()), ForceCheckpoint: true, IfVersion: &first,
		Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex, Versioning: sidecar.EvsVersioningOn},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	history, err := reader.repo.History(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != 2 || len(history.Versions[0].SlotIds) != 1 || len(history.Versions[1].SlotIds) != 1 {
		t.Fatalf("settings history: %+v, %v", history, err)
	}
	erased, kept := history.Versions[0], history.Versions[1]
	if kept.Version != first || kept.SlotIds[0] == erased.SlotIds[0] {
		t.Fatal("checkpoints do not have independent slots")
	}
	if result, err := writer.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: []*sidecar.EvsErasedKey{{SlotId: erased.SlotIds[0], KeyIndex: 0}}, Complete: true}); err != nil || result.Version != 1 {
		t.Fatalf("erasure: %+v, %v", result, err)
	}
	status := func(days uint32, version uint64) {
		t.Helper()
		s, err := reader.repo.IndexStatus(ctx, &sidecar.EvsIndexStatusArgs{})
		if err != nil || len(s.Roots) != 1 || s.Roots[0].WindowDays != days || s.Roots[0].SettingsVersion != version || s.Roots[0].AlarmCount != 0 {
			t.Fatalf("window %d at %d: %+v, %v", days, version, s, err)
		}
	}
	status(14, first)
	third := set(21)
	if third != erased.Version+1 || erased.CommitVersion != second.Version {
		t.Fatalf("new version %d after path version %d at commit %d", third, erased.Version, second.Version)
	}
	status(21, third)
	if _, err := reader.repo.ReadVersion(ctx, &sidecar.EvsReadArgs{Path: path, Version: erased.Version}, io.Discard); !errors.Is(err, sidecar.ErrEvsErased) {
		t.Fatalf("superseded erased settings: %v", err)
	}
	if world.slotKeyCount(kept.SlotIds[0]) != 1 || world.slotKeyCount(erased.SlotIds[0]) != 0 {
		t.Fatal("repair altered the old slots")
	}
}
