//go:build !ios_extension

// QD-1178 for the readers the network extensions' leg links none of (evs_unretained_pin_test.go has the head reader's
// own): a format-2 versionless version whose statement is pinned before two bases reads where it sits, the repo's kind
// its creation's and its lock at the pin unjudged, and the two rows that turn on the lock take a version either way
// while it is unjudged.

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A versionless version written before two bases reads on a format-2 reader that read it then and on a new format-2
// device started at the newest base, neither ignored nor refused, with no alarm.
func TestEvsFormat2VersionlessVersionWrittenBeforeTwoBasesReads(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "big.bin", content: []byte("one"), segment: true,
		format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, "one")})
	device := retained.follower(t, "format 2 device")
	device.client.EnableFormat2Reader()
	if _, err := evsTestVerifiedPath(t, device, retained.world, nil, "big.bin", 0); err != nil {
		t.Fatal(err)
	}

	retained.foldPast(t, written)
	newDevice, _ := retained.started(t, "new format 2 device")
	newDevice.client.EnableFormat2Reader()
	for label, reader := range map[string]*evsTestClient{"the device that read it": device, "the new device": newDevice} {
		verified, err := evsTestVerifiedPath(t, reader, retained.world, nil, "big.bin", 0)
		if err != nil {
			t.Errorf("%s: %v", label, err)
			continue
		}
		if verified.Entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) || verified.Ignored || verified.Absent {
			t.Errorf("%s: verified %+v", label, verified)
		}
		evsTestRequireNoAlarm(t, label, reader)
	}
}

// A lock unjudged at a push's pin takes the version under both rows that turn on it: a versionless version, which a
// lock standing at the pin refuses, and a kept object on ur/lfs, which only a locked repo's store writes.
func TestEvsCheckVersioningTakesAVersionWhereTheLockIsUnjudged(t *testing.T) {
	general := func(reserved EvsReservedRef, locked bool, unjudged bool) *EvsVersioningContext {
		return &EvsVersioningContext{
			RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
			RefMode: protocol.EvsRefMode_EVS_REF_FILE, Reserved: reserved, Locked: locked, LockUnjudged: unjudged,
		}
	}
	versionless := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)}
	kept := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)}
	object := [][]byte{[]byte("objects"), []byte("ab"), []byte("cdef")}
	cases := []struct {
		label   string
		context *EvsVersioningContext
		names   [][]byte
		entry   *protocol.EvsEntryVersion
		want    error
	}{
		{label: "versionless under a standing lock", context: general(EvsReservedRefNone, true, false), names: [][]byte{[]byte("big.bin")}, entry: versionless, want: ErrEvsVersioningRefused},
		{label: "versionless, the lock unjudged", context: general(EvsReservedRefNone, false, true), names: [][]byte{[]byte("big.bin")}, entry: versionless},
		{label: "a kept lfs object, unlocked", context: general(EvsReservedRefLfs, false, false), names: object, entry: kept, want: ErrEvsVersionIgnored},
		{label: "a kept lfs object, locked", context: general(EvsReservedRefLfs, true, false), names: object, entry: kept},
		{label: "a kept lfs object, the lock unjudged", context: general(EvsReservedRefLfs, false, true), names: object, entry: kept},
	}
	for _, c := range cases {
		err := EvsCheckVersioning(c.context, c.names, c.entry)
		if (c.want == nil && err != nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.label, err, c.want)
		}
	}
}
