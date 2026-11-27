//go:build !ios_extension && !sidecar_http && !js

// The disclosure check (CTRUST-M12-01) on the acknowledgment world (disclosure_ack_test.go): the previous version's
// grace on a fake clock, its fail-closed start, a tagged sidecar refused naming --network, disclosure_required's text,
// and a prompt's text taken from the policy alone.

package sidecar

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The previous version covers until the instant the current one took effect plus its grace, and refuses at that
// instant; a grace of 0 refuses at once; a revision keeps coverage and marks nothing; and the version after the next
// is never covered by a grace.
func TestDisclosureNewVersionGrace(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	since := world.clock.Now().Add(-time.Hour)
	graceEnd := since.Add(14 * 24 * time.Hour)
	testDisclosureSetVersion(world.source.policy, "inference:engy", 2, since, 14)
	world.source.policy = testDisclosurePolicyCopy(world.source.policy)

	verdict, err := world.check.Check(t.Context(), "inference:engy")
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Covered || !verdict.InGrace || !verdict.GraceEnd.Equal(graceEnd) || verdict.Acknowledged != 1 || verdict.Version != 2 ||
		verdict.Askable || verdict.Scope != ComputeDisclosureScopePerson || !verdict.Changed {
		t.Fatalf("within the grace: %+v", verdict)
	}
	// a moment before its end, still covered; at its end, refused, and askable by a run the person is attached to
	world.clock.Advance(graceEnd.Sub(world.clock.Now()) - time.Millisecond)
	if err := world.check.Require(t.Context(), "inference:engy", ""); err != nil {
		t.Fatalf("a moment before the grace's end: %v", err)
	}
	world.clock.Advance(time.Millisecond)
	verdict, err = world.check.Check(t.Context(), "inference:engy")
	if err != nil || verdict.Covered || verdict.InGrace || !verdict.Askable {
		t.Fatalf("at the grace's end: %+v, %v", verdict, err)
	}
	if err := world.check.Require(t.Context(), "inference:engy", ""); !errors.Is(err, ErrDisclosureRequired) {
		t.Fatalf("at the grace's end: %v", err)
	}

	// a grace of 0, set where a change widens who reads or keeps what is sent, refuses at once
	zero := newTestDisclosureAckWorld(t)
	if err := zero.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	testDisclosureSetVersion(zero.source.policy, "inference:engy", 2, zero.clock.Now().Add(-time.Hour), 0)
	if err := zero.check.Require(t.Context(), "inference:engy", ""); !errors.Is(err, ErrDisclosureRequired) {
		t.Fatalf("a grace of 0: %v", err)
	}

	// a revision changes nothing: the version's acknowledgment covers it, and nothing is marked
	revised := newTestDisclosureAckWorld(t)
	if err := revised.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	revised.source.policy = testDisclosurePolicyCopy(revised.source.policy)
	revised.source.policy.Disclosure("inference:engy").Revision = 3
	verdict, err = revised.check.Check(t.Context(), "inference:engy")
	if err != nil || !verdict.Covered || verdict.InGrace || verdict.Changed {
		t.Fatalf("a revision: %+v, %v", verdict, err)
	}

	// two versions on, the grace covers nothing
	far := newTestDisclosureAckWorld(t)
	if err := far.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	testDisclosureSetVersion(far.source.policy, "inference:engy", 3, far.clock.Now().Add(-time.Hour), 14)
	if err := far.check.Require(t.Context(), "inference:engy", ""); !errors.Is(err, ErrDisclosureRequired) {
		t.Fatalf("two versions on: %v", err)
	}
}

// policy, its disclosures copied, so the registry reads it as another policy.
func testDisclosurePolicyCopy(policy *ComputePolicy) *ComputePolicy {
	copied := *policy
	copied.Disclosures = []*ComputePolicyDisclosure{}
	for _, disclosure := range policy.Disclosures {
		entry := *disclosure
		copied.Disclosures = append(copied.Disclosures, &entry)
	}
	return &copied
}

// A version whose policy names no instant it took effect has no grace: a new version refuses at once.
func TestDisclosureGraceStartMissingFailsClosed(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	disclosure := world.source.policy.Disclosure("inference:engy")
	disclosure.Version, disclosure.GraceDays, disclosure.SinceMs = 2, 14, 0
	verdict, err := world.check.Check(t.Context(), "inference:engy")
	if err != nil || verdict.Covered || verdict.InGrace || !verdict.GraceEnd.IsZero() {
		t.Fatalf("no instant: %+v, %v", verdict, err)
	}
}

// A tagged sidecar reads no vault, so the person's acknowledgments never cover it: until the network's land
// (CTRUST-M12-02) it is refused, unaskable, naming an Owner's or Admin's --network.
func TestDisclosureTaggedSidecarRefused(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	tagged := world.acksOf(t, world.config.storeOf(t, world.config.tagged))
	check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{Registry: world.registry, Acks: tagged, Now: world.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := check.Check(t.Context(), "inference:engy")
	if err != nil || verdict.Covered || verdict.Askable || verdict.Scope != ComputeDisclosureScopeNetwork || verdict.Acknowledged != 0 {
		t.Fatalf("a tagged sidecar: %+v, %v", verdict, err)
	}
	err = check.Require(t.Context(), "inference:engy", "")
	required := &DisclosureRequiredError{}
	if !errors.As(err, &required) || !strings.Contains(err.Error(), "ur disclosures ack inference:engy --network") ||
		!strings.Contains(err.Error(), "Owner or Admin") {
		t.Fatalf("the refusal: %v", err)
	}
	// what asks nothing is covered there too
	if err := check.Require(t.Context(), "inference:chutes", ""); err != nil {
		t.Errorf("an id that asks nothing: %v", err)
	}
	// and the network's, once CTRUST-M12-02 gives them, cover it
	networked, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{Registry: world.registry, Acks: tagged,
		Network: testDisclosureNetworkAcks{"inference:engy": 1}, Now: world.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := networked.Require(t.Context(), "inference:engy", ""); err != nil {
		t.Errorf("the network's acknowledgment: %v", err)
	}
	if err := networked.Require(t.Context(), "search:parallel", ""); !errors.Is(err, ErrDisclosureRequired) {
		t.Errorf("an id the network did not acknowledge: %v", err)
	}
}

// The network's acknowledgments as CTRUST-M12-02 will give them.
type testDisclosureNetworkAcks map[string]uint32

func (self testDisclosureNetworkAcks) Versions(ctx context.Context) (map[string]uint32, error) {
	return self, nil
}

// disclosure_required names the id, its version, its summary in the caller's locale and the fix, and nothing is
// acknowledged for want of a policy: then it wraps policy_unavailable, and an id the policy does not carry wraps that.
func TestDisclosureRequiredErrorText(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	err := world.check.Require(t.Context(), "search:parallel", "")
	required := &DisclosureRequiredError{}
	if !errors.As(err, &required) || !errors.Is(err, ErrDisclosureRequired) {
		t.Fatalf("not a refusal: %v", err)
	}
	summary := world.source.policy.Disclosure("search:parallel").English().Summary
	want := "disclosure_required: search:parallel version 1 is not acknowledged (" + summary + "); the person acknowledges it " +
		"in the app's settings, or with ur disclosures ack search:parallel"
	if err.Error() != want || required.Id != "search:parallel" || required.Version != 1 || required.Summary != summary ||
		required.Scope != ComputeDisclosureScopePerson {
		t.Fatalf("the refusal %q\nwant %q", err.Error(), want)
	}
	// in the caller's locale
	err = world.check.Require(t.Context(), "inference:local", "de")
	if err != nil {
		t.Fatalf("local asks nothing: %v", err)
	}

	world.source.policy = nil
	err = world.check.Require(t.Context(), "search:parallel", "")
	if !errors.Is(err, ErrDisclosureRequired) || !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) ||
		!strings.HasPrefix(err.Error(), "disclosure_required: ") {
		t.Fatalf("no policy: %v", err)
	}
	world.source.policy = testDisclosurePolicy(t)
	if err := world.check.Require(t.Context(), "inference:nobody", ""); !errors.Is(err, ErrDisclosureRequired) ||
		!errors.Is(err, ErrComputeDisclosureNotCarried) {
		t.Fatalf("an id not carried: %v", err)
	}
	// acknowledgments that do not read refuse, never cover
	world.config.vault.historyErr = errors.New("evs unreachable")
	if err := world.check.Require(t.Context(), "search:parallel", ""); err == nil {
		t.Fatal("an unreadable store covered a use")
	}
	if err := world.check.Require(t.Context(), "inference:local", ""); err != nil {
		t.Fatalf("an id that asks nothing, the store unreadable: %v", err)
	}
}

// What a prompt renders is the signed policy's text for the id and version, byte for byte, whatever the event or a
// server's answer carries; the whole text is the view's, which every surface shows.
func TestDisclosureTextsMatchPolicy(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	renderer, out := newTestHarnessRenderer(false, world.registry.HarnessTexts(""))
	event := NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui_1", Method: HarnessUiDisclosure, DisclosureId: "inference:engy", DisclosureVersion: 1})
	event.SetField("title", "EVIL TITLE")
	event.SetField("message", "EVIL: everything stays private")
	event.SetField("summary", "EVIL SUMMARY")
	renderer.Render(context.Background(), event)
	view, err := world.registry.View("inference:engy", "")
	if err != nil {
		t.Fatal(err)
	}
	english := world.source.policy.Disclosure("inference:engy").English()
	output := out.String()
	for _, line := range append(append([]string{view.HeaderLine(), "Summary: " + english.Summary}, english.Exposed...), english.Private...) {
		if !strings.Contains(output, line) {
			t.Errorf("the prompt lacks the policy's %q", line)
		}
	}
	if strings.Contains(output, "EVIL") {
		t.Fatalf("the event's own text reached the prompt:\n%s", output)
	}
	// the acknowledgment the prompt takes lands in the store the check reads
	answer := renderer.Answer(context.Background(), HarnessDisclosureAcknowledgment, &testDisclosureAcker{acks: world.acks})
	if answer == nil || !answer.Done {
		t.Fatalf("the answer %+v", answer)
	}
	if err := world.check.Require(t.Context(), "inference:engy", ""); err != nil {
		t.Fatalf("after the prompt's acknowledgment: %v", err)
	}
}

// The prompt's acknowledgment through the person's own act, as ur harness's acker sends it.
type testDisclosureAcker struct {
	acks *ComputeDisclosureAcks
}

func (self *testDisclosureAcker) Ack(ctx context.Context, id string, version uint32) error {
	return self.acks.Ack(ctx, testDisclosureConfirmed(id, version))
}
