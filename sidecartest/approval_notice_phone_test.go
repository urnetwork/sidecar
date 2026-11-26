// CTXH-M11-07's phone tests on the approval devices world (DESIGN-COMPUTE §24.7, §24.16's "wakes for approval
// notices, not for session pushes", D-CTXH-10; owner decision 573's remedy): a phone whose approval part leases its
// vault's a/ notices is woken by each request's notice and its decision's rewrite and never by the session pushes
// interleaved with them, and a whole-vault lease an older release left standing at evs is dropped at its next renew.

package sidecartest

import (
	"slices"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The devices world with a phone sidecar beside the laptop, its approval part bound over a surrogate on the net's
// clock, which follows the world's log's stream pushes and its notices; hints counted.
func newTestNoticePhone(t *testing.T) (*approvalDevicesWorld, *FakeApprovalPhone, func() *sidecar.ApprovalPhone, *atomic.Int32) {
	t.Helper()
	devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "a phone app with a CLI"})
	t.Cleanup(devices.net.Close)
	world := devices.world
	phone, _, _ := devices.addMemberSidecar("phone")
	surrogate := NewFakeApprovalPhone(devices.net.Clock(), nil)
	t.Cleanup(surrogate.Follow(world.LogId(), world.Log()))
	t.Cleanup(surrogate.FollowNotices(world.LogId(), world.Log()))
	hints := &atomic.Int32{}
	bind := func() *sidecar.ApprovalPhone {
		part, err := phone.Sidecar().BindApprovalPhone(&sidecar.ApprovalPhoneArgs{
			Leaser: surrogate,
			Logs: func() ([]sidecar.ApprovalPhoneLog, error) {
				return []sidecar.ApprovalPhoneLog{{LogId: world.LogId(), Vault: true}}, nil
			},
			Hinted: func() { hints.Add(1) },
		})
		if err != nil {
			t.Fatal(err)
		}
		return part
	}
	return devices, surrogate, bind, hints
}

// A closed phone app, its notice lease kept at evs, is woken once by each request's notice and once by its decision's
// rewrite, and never by the session pushes the laptop's runs make between them, many to each notice; while the app
// runs the same notices are hints and wake nothing, and the session pushes hint nothing either.
func TestPhoneWakesForNoticeNotSessionPush(t *testing.T) {
	devices, surrogate, bind, hints := newTestNoticePhone(t)
	world := devices.world
	part := bind()
	resynced, err := part.Resync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	notices := sidecar.ApprovalPhoneLease{RepoId: world.LogId(), Prefix: "a/"}
	if resynced.LeasesTaken != 1 || !slices.Equal(resynced.Leased, []sidecar.ApprovalPhoneLease{notices}) {
		t.Fatalf("the open app's first resync: %+v", resynced)
	}
	sessionPushes := func(count int) {
		for range count {
			world.Log().PushSession()
		}
	}

	// the open app: session pushes hint nothing, a request's notice is one hint and no wake
	sessionPushes(5)
	if hints.Load() != 0 || surrogate.Counts().Hints != 0 {
		t.Fatalf("session pushes hinted the open app %d times", hints.Load())
	}
	_, _, firstId := devices.call("first@recipient.example")
	if hints.Load() != 1 || len(surrogate.Wakes()) != 0 {
		t.Fatalf("the open app: %d hints, %d wakes", hints.Load(), len(surrogate.Wakes()))
	}
	if resynced, err := part.Resync(t.Context()); err != nil || !slices.Equal(resynced.Raised, []sidecar.Id{firstId}) {
		t.Fatalf("the hinted resync: %+v, %v", resynced, err)
	}

	// the app closes, its lease kept at evs: session pushes interleaved with notices wake it for the notices alone
	part.Close()
	surrogate.Kill()
	sessionPushes(20)
	if wakes := surrogate.Wakes(); len(wakes) != 0 {
		t.Fatalf("session pushes woke the closed app %d times", len(wakes))
	}
	_, _, secondId := devices.call("second@recipient.example")
	sessionPushes(20)
	if wakes := surrogate.Wakes(); len(wakes) != 1 {
		t.Fatalf("a request among session pushes woke the closed app %d times", len(wakes))
	}
	notAfter := devices.net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
	if err := world.Approve(t.Context(), secondId, 1, notAfter, nil); err != nil {
		t.Fatal(err)
	}
	sessionPushes(20)
	wakes := surrogate.Wakes()
	if len(wakes) != 2 || hints.Load() != 1 {
		t.Fatalf("after the decision: %d wakes, %d hints", len(wakes), hints.Load())
	}
	for _, wake := range wakes {
		approvalDevicesWakeNamesNothing(t, wake, wake.Payload.Version, firstId, secondId, world.LogId(), world.Member, world.Laptop.SidecarId)
	}
	// every wake carries the notice's own push sequence, none a session push's
	if wakes[0].Payload.Version == wakes[1].Payload.Version {
		t.Fatalf("two wakes at one push sequence: %+v", wakes)
	}
}

// A whole-vault lease an older release took is left standing at evs when its process ends; the new release's part
// takes its a/ lease at its first resync and drops the whole one there, at its renew, never renewing it, so a session
// push wakes nothing and a request's notice still does.
func TestPhoneDropsWholeLogLeaseAtRenew(t *testing.T) {
	devices, surrogate, bind, _ := newTestNoticePhone(t)
	world := devices.world
	// the older release's process: the whole vault, every ref, then its end
	whole := sidecar.ApprovalPhoneLease{RepoId: world.LogId(), EveryRef: true}
	if _, err := surrogate.Lease(whole, func(sidecar.ApprovalPhoneLease) {}); err != nil {
		t.Fatal(err)
	}
	surrogate.Kill()
	world.Log().PushSession()
	if len(surrogate.Wakes()) != 1 {
		t.Fatalf("the older release's lease: %d wakes for a session push", len(surrogate.Wakes()))
	}

	part := bind()
	defer part.Close()
	resynced, err := part.Resync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	notices := sidecar.ApprovalPhoneLease{RepoId: world.LogId(), Prefix: "a/"}
	if resynced.LeasesDropped != 1 || resynced.LeasesTaken != 1 || !slices.Equal(resynced.Leased, []sidecar.ApprovalPhoneLease{notices}) {
		t.Fatalf("the new release's first resync: %+v", resynced)
	}
	if leases := surrogate.Leases(); len(leases) != 1 || leases[0].Lease != notices {
		t.Fatalf("the leases evs holds: %+v", leases)
	}
	if counts := surrogate.Counts(); counts.LeasesDropped != 1 || counts.LeasesRenewed != 0 {
		t.Fatalf("the surrogate's counts: %+v", counts)
	}

	// the app's process ends: a session push wakes nothing, a request's notice wakes it
	part.Close()
	surrogate.Kill()
	world.Log().PushSession()
	if len(surrogate.Wakes()) != 1 {
		t.Fatalf("a session push after the drop: %d wakes", len(surrogate.Wakes()))
	}
	devices.call("after@recipient.example")
	if len(surrogate.Wakes()) != 2 {
		t.Fatalf("a request's notice after the drop: %d wakes", len(surrogate.Wakes()))
	}
}
