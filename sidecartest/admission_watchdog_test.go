package sidecartest

// The admission world's row bound (admission_watchdog.go) on a FakeClock of the row's own, which only these tests move:
// a row that keeps moving outlives RowTimeout of its clock, and a wait that stalls ends the world's context RowTimeout
// after the row's last progress. Each check runs inside the Advance that reaches it, so nothing here races.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A T2 tier whose row bound runs on rowClock.
func admissionWatchdogTier(t *testing.T, rowClock *FakeClock) *AdmissionTier {
	t.Helper()
	tier := admissionT2Tier(t)
	tier.Settings = DefaultAdmissionSuiteSettings()
	tier.Settings.RowClock = rowClock
	return tier
}

// The tip-check failure at 7215073e (TestTeamAdmissionsMeetNoMemberDeviceCap: "the writer's follower at 1033: config
// client closed") made deterministic: the row's work between two of its statements takes three quarters of RowTimeout,
// as a loaded host lends a row of some 25 s of CPU its time, over four statements and a base, three RowTimeouts of the
// row's clock, and each statement lands, the writer's follower keeps up and the world's context stands. A deadline fixed
// at the row's start ended the context in the second step, closing the writer's follower under the row.
func TestAdmissionRowOutlivesRowTimeoutWhileItProgresses(t *testing.T) {
	rowClock := NewFakeClock(DefaultClockStart())
	tier := admissionWatchdogTier(t, rowClock)
	net := NewAdmissionNet(t, tier)
	defer net.Close()
	step := tier.Settings.RowTimeout * 3 / 4
	for i := range 4 {
		rowClock.Advance(step)
		memberId := net.AdmitMember(net.Owner(), fmt.Sprintf("member %d", i), bridge.MemberRole_MEMBER_ROLE_MEMBER)
		if net.State().Member(memberId) == nil {
			t.Fatalf("member %d is not admitted", i)
		}
	}
	rowClock.Advance(step)
	net.Fold(true)
	if err := net.Context().Err(); err != nil {
		t.Fatalf("the world's context ended %s into the row: %v", rowClock.Now().Sub(DefaultClockStart()), context.Cause(net.Context()))
	}
	if !proto.Equal(net.follower.Pin(), net.Tip()) {
		t.Fatalf("the writer's follower stands at %d, the tip %d", net.follower.Pin().GetVersion(), net.Tip().GetVersion())
	}
}

// A wait that stalls still fails the row: a second short of RowTimeout after the row's last progress nothing has
// ended, and at it the world's context ends with ErrAdmissionRowStalled, which ends a wait on the writer's follower
// for an entry api never serves.
func TestAdmissionRowTimeoutEndsAStalledWait(t *testing.T) {
	rowClock := NewFakeClock(DefaultClockStart())
	tier := admissionWatchdogTier(t, rowClock)
	net := NewAdmissionNet(t, tier)
	defer net.Close()
	rowClock.Advance(tier.Settings.RowTimeout / 2)
	net.AdmitMember(net.Owner(), "the last progress", bridge.MemberRole_MEMBER_ROLE_MEMBER)

	waited := make(chan error, 1)
	go func() {
		_, err := net.follower.WaitFor(net.Context(), net.Applied()+1)
		waited <- err
	}()
	rowClock.Advance(tier.Settings.RowTimeout - time.Second)
	if err := net.Context().Err(); err != nil {
		t.Fatalf("the world's context ended a second short of the bound: %v", context.Cause(net.Context()))
	}
	rowClock.Advance(time.Second)
	if cause := context.Cause(net.Context()); !errors.Is(cause, ErrAdmissionRowStalled) {
		t.Fatalf("the world's context at the bound: %v", cause)
	}
	// a real-time guard, which only a bound that ended nothing reaches
	select {
	case err := <-waited:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, sidecar.ErrConfigClientClosed) {
			t.Fatalf("the stalled wait answered %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the stalled wait outlived the world's context")
	}
	if err := net.waitError(sidecar.ErrConfigClientClosed); !errors.Is(err, ErrAdmissionRowStalled) {
		t.Fatalf("a failed wait's error does not name the bound: %v", err)
	}
}

// The bound counts from the row's newest progress, wherever it was noted: entries the readers apply, pages read and the
// follower's catch-ups each move it, and Close ends the context with no stall named.
func TestAdmissionRowTimeoutCountsFromTheNewestProgress(t *testing.T) {
	rowClock := NewFakeClock(DefaultClockStart())
	tier := admissionWatchdogTier(t, rowClock)
	net := NewAdmissionNet(t, tier)
	rowClock.Advance(tier.Settings.RowTimeout - time.Second)
	// a refused statement applies no entry: its page read and the follower's catch-up are its progress
	net.MustRefuse(net.Sign(net.Device("never admitted", net.Id("no member")), bridge.SignedType_SIGNED_MEMBER_ADMIT,
		net.MemberAdmit(net.Id("refused member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)), sidecar.ErrConfigSigner)
	rowClock.Advance(tier.Settings.RowTimeout - time.Second)
	if err := net.Context().Err(); err != nil {
		t.Fatalf("the bound counted from before a refused statement's sync: %v", context.Cause(net.Context()))
	}
	net.Close()
	if cause := context.Cause(net.Context()); !errors.Is(cause, context.Canceled) || errors.Is(cause, ErrAdmissionRowStalled) {
		t.Fatalf("the world's context after Close: %v", cause)
	}
	rowClock.Advance(2 * tier.Settings.RowTimeout)
	if cause := context.Cause(net.Context()); errors.Is(cause, ErrAdmissionRowStalled) {
		t.Fatalf("a check ran after Close: %v", cause)
	}
}
