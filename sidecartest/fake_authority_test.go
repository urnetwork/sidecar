// FakeAuthority's own behavior: entries reach every callback in order and move the pin, the retained tail answers
// ProposedSince, a member's devices are its untagged admissions, and PresenceRequired's default reads the covers list
// over the signer's live keys.

package sidecartest

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestFakeAuthorityAppliesEntriesInOrder(t *testing.T) {
	authority := NewFakeAuthority()
	seen := []uint64{}
	remove := authority.AddEntryCallback(func(entry *sidecar.SidecarAuthorityEntry) {
		seen = append(seen, entry.Pin.GetVersion())
	})
	start := time.UnixMilli(1_700_000_000_000)
	for n := uint64(1); n <= 3; n += 1 {
		chain := sha256.Sum256([]byte{byte(n)})
		authority.Apply(&sidecar.SidecarAuthorityEntry{Pin: &bridge.AuthPin{Version: n, Chain: chain[:]}, TimeMs: start.Add(time.Duration(n) * time.Minute).UnixMilli()})
	}
	remove()
	authority.Apply(&sidecar.SidecarAuthorityEntry{Pin: &bridge.AuthPin{Version: 4, Chain: make([]byte, 32)}})
	if len(seen) != 3 || seen[0] != 1 || seen[2] != 3 || authority.Pin().GetVersion() != 4 {
		t.Fatalf("seen %v, pin %d", seen, authority.Pin().GetVersion())
	}
	n, at, ok := authority.ProposedSince(start.Add(90 * time.Second))
	if !ok || n != 2 || !at.Equal(start.Add(2*time.Minute)) {
		t.Errorf("proposed since: %d %s %v", n, at, ok)
	}
	if _, _, ok := authority.ProposedSince(start.Add(time.Hour)); ok {
		t.Error("an entry after the newest")
	}
}

func TestFakeAuthorityMemberDevicesAndPresence(t *testing.T) {
	authority := NewFakeAuthority()
	memberId := sidecar.NewId()
	laptop := sidecar.NewId()
	phone := sidecar.NewId()
	agent := sidecar.NewId()
	authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: laptop, MemberId: memberId})
	authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: phone, MemberId: memberId})
	authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: agent, TagIds: []sidecar.Id{sidecar.NewId()}})
	if devices := authority.MemberDevices(memberId); len(devices) != 2 {
		t.Fatalf("%d devices", len(devices))
	}
	admit := &sidecar.SidecarStatement{SignerId: laptop, Type: bridge.SignedType_SIGNED_SIDECAR_ADMIT}
	if authority.PresenceRequired(admit) {
		t.Error("presence with no live key")
	}
	authority.AddLiveKey(laptop, &bridge.KeyRow{KeyId: []byte("key"), Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE})
	if !authority.PresenceRequired(admit) {
		t.Error("no presence for a covered statement of a signer with a live key")
	}
	if authority.PresenceRequired(&sidecar.SidecarStatement{SignerId: laptop, Type: bridge.SignedType_SIGNED_REPO_CREATE}) {
		t.Error("presence for an uncovered statement")
	}
}
