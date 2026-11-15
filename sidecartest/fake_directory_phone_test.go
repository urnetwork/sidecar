package sidecartest

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// FakeDirectoryPhone's leases and wakes (RECORD-M8-01): a second Lease of a prefix renews the one lease, and a
// commit under it is one wake carrying the repo's push sequence; a lease lapses LeaseExpiry after its last renewal and
// wakes nothing then, until a Lease takes it again; Kill drops the callbacks and the lease still wakes; and the head
// reads answer a path, a listing and an entry.
func TestFakeDirectoryPhoneLeasesAndWakes(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	streams := NewFakeRecordStreams(clock, nil, nil)
	repoId, err := streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	phoneId, writerId := sidecar.NewId(), sidecar.NewId()
	for _, sidecarId := range []sidecar.Id{phoneId, writerId} {
		if err := streams.Grant(repoId, sidecarId, RecordStreamsScope{Read: true, Write: true}); err != nil {
			t.Fatal(err)
		}
	}
	cards := NewFakeDirectoryCards(streams, nil)
	phone := NewFakeDirectoryPhone(cards, phoneId, nil)
	targetId, requestId := sidecar.NewId(), sidecar.NewId()
	prefix := "q/ab/" + hex.EncodeToString(targetId.Bytes()) + "/"
	path := prefix + hex.EncodeToString(requestId.Bytes())
	hints := 0
	release, err := phone.Lease(repoId, prefix, func(repoId sidecar.Id) { hints += 1 })
	if err != nil {
		t.Fatal(err)
	}
	renewHints := 0
	if _, err := phone.Lease(repoId, prefix, func(repoId sidecar.Id) { renewHints += 1 }); err != nil {
		t.Fatal(err)
	}
	// the first callback goes and the lease stands on the second
	release()
	if counts := phone.Counts(); counts.LeasesTaken != 1 || counts.LeasesRenewed != 1 || counts.LeasesReleased != 0 {
		t.Fatalf("counts %+v", counts)
	}
	writer := cards.For(writerId)
	write := func(ifVersion uint64) {
		t.Helper()
		if _, err := writer.PutCard(t.Context(), repoId, &sidecar.DirectoryCardWrite{
			PushId: sidecar.NewId(), Path: path, IfVersion: ifVersion, Content: []byte("a notice"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	write(0)
	wakes := phone.Wakes()
	sequence, err := streams.PushSequence(repoId)
	if err != nil {
		t.Fatal(err)
	}
	if len(wakes) != 1 || wakes[0].Payload.TopicClass != "evs" || wakes[0].Payload.Version != sequence.Sequence || hints != 0 || renewHints != 1 {
		t.Fatalf("wakes %+v, hints %d and %d", wakes, hints, renewHints)
	}
	if strings.Contains(string(wakes[0].Body), hex.EncodeToString(repoId.Bytes())) || strings.Contains(string(wakes[0].Body), repoId.String()) {
		t.Fatalf("a wake names its repo: %q", wakes[0].Body)
	}
	// lapsed: no wake, no hint
	clock.Advance(7 * 24 * time.Hour)
	write(1)
	if leases := phone.Leases(); len(phone.Wakes()) != 1 || renewHints != 1 || len(leases) != 1 || leases[0].Live {
		t.Fatalf("a lapsed lease: %+v, %d wakes", leases, len(phone.Wakes()))
	}
	// taken again after the lapse
	if _, err := phone.Lease(repoId, prefix, func(repoId sidecar.Id) {}); err != nil {
		t.Fatal(err)
	}
	if counts := phone.Counts(); counts.LeasesTaken != 2 {
		t.Fatalf("counts after the lapse %+v", counts)
	}
	// a killed process holds no callback, and evs still wakes the phone
	phone.Kill()
	write(2)
	if len(phone.Wakes()) != 2 || renewHints != 1 {
		t.Fatalf("after a kill: %d wakes, %d hints", len(phone.Wakes()), renewHints)
	}
	// head reads
	file, err := phone.ReadCard(t.Context(), repoId, path)
	if err != nil || file == nil || file.Version != 3 || file.SignerSidecarId != writerId {
		t.Fatalf("the path's head %+v, %v", file, err)
	}
	files, err := phone.ListCards(t.Context(), repoId, prefix)
	if err != nil || len(files) != 1 || files[0].Path != path {
		t.Fatalf("the prefix's listing %+v, %v", files, err)
	}
	if missing, err := phone.ReadStreamEntry(t.Context(), repoId, writerId, 1); err != nil || missing != nil {
		t.Fatalf("an entry the stream does not hold %+v, %v", missing, err)
	}
	if counts := phone.Counts(); counts.NoticeReads != 1 || counts.Listings != 1 || counts.EntryReads != 1 {
		t.Fatalf("head read counts %+v", counts)
	}
}
