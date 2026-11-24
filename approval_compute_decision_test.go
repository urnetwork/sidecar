//go:build !ios_extension && !js

package sidecar

// CACL-M12-01: ApprovalDecision's versions 2 and 3 (DESIGN-COMPUTE §23.9, §27.9). Version 2's selection is unique and
// ascending, an approval's naming at least one event and a denial's none, and it spends only on a kind-25 action
// whose events it names; version 3 exists only on channel 4, auto, and channel 4 only at version 3, an approval of one
// use resting on an AutoVerdict that allowed, clean; a reader that predates a version refuses it whole, and the spend
// check refuses channel 4 until its rules land (CACL-M13-01). Synthetic values only.

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A kind-25 request and its parsed form, of the test's calendar action, holding two events.
func testComputeCalendarRequest(t *testing.T) *StoredApprovalRequest {
	t.Helper()
	request, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, testComputeStored(t, SidecarActionCalendarWrite).Bytes)))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// A channel-4 approval of request at version 3, its verdict an allow, clean, as §27.9 writes one.
func testComputeAutoDecision(request *StoredApprovalRequest) *protocol.ApprovalDecision {
	decision := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO)
	decision.Version = approvalDecisionVersionAuto
	decision.EvidenceSha256 = bytes.Repeat([]byte{0x14}, recordHashByteCount)
	decision.Auto = true
	decision.AutoVerdict = &protocol.AutoVerdict{
		Verdict: approvalAutoVerdictAllow, Reason: approvalAutoReasonClean, Score: 300, Threshold: 2000,
		Model: "safety-22m", ModelSha256: bytes.Repeat([]byte{0x15}, recordHashByteCount),
		InputsSha256: bytes.Repeat([]byte{0x16}, recordHashByteCount), Windows: 3, RunCount: 1, DayCount: 4,
	}
	return decision
}

// Version 2's selection: an approval selecting events in ascending order without repeats, a denial selecting none;
// version 1 selects nothing. Whether a selection fits its action: a kind-25 approval names its events, each below the
// action's count, and at version 2 or 3; any other action's decision selects none and is no version 2's.
func TestDecisionSelectedShape(t *testing.T) {
	request := testComputeCalendarRequest(t)
	for name, c := range map[string]struct {
		change func(decision *protocol.ApprovalDecision)
		ok     bool
	}{
		"version 2 selecting both": {change: func(decision *protocol.ApprovalDecision) { decision.Version, decision.Selected = 2, []uint32{0, 1} }, ok: true},
		"version 2 selecting one":  {change: func(decision *protocol.ApprovalDecision) { decision.Version, decision.Selected = 2, []uint32{1} }, ok: true},
		"version 2 selecting none": {change: func(decision *protocol.ApprovalDecision) { decision.Version = 2 }},
		"version 2 out of order":   {change: func(decision *protocol.ApprovalDecision) { decision.Version, decision.Selected = 2, []uint32{1, 0} }},
		"version 2 repeated":       {change: func(decision *protocol.ApprovalDecision) { decision.Version, decision.Selected = 2, []uint32{1, 1} }},
		"version 1 selecting":      {change: func(decision *protocol.ApprovalDecision) { decision.Selected = []uint32{0} }},
		"version 2 denial": {change: func(decision *protocol.ApprovalDecision) {
			decision.Version, decision.Decision, decision.Uses = 2, 2, 0
		}, ok: true},
		"version 2 denial selecting": {change: func(decision *protocol.ApprovalDecision) {
			decision.Version, decision.Decision, decision.Selected = 2, 2, []uint32{0}
		}},
		"version 1 auto set": {change: func(decision *protocol.ApprovalDecision) { decision.Auto = true }},
		"version 2 with auto_verdict": {change: func(decision *protocol.ApprovalDecision) {
			decision.Version, decision.Selected, decision.AutoVerdict = 2, []uint32{0}, &protocol.AutoVerdict{}
		}},
	} {
		decision := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
		c.change(decision)
		_, err := ParseSignedApprovalDecision(testRecordSignDecision(t, decision))
		if (err == nil) != c.ok || (!c.ok && !errors.Is(err, ErrRecordStoredInvalid)) {
			t.Errorf("%s: %v", name, err)
		}
	}

	selecting := func(action *StoredCanonicalAction, version uint32, verdict protocol.ApprovalVerdict, selected ...uint32) error {
		decision := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
		decision.Version, decision.Decision, decision.Selected = version, uint32(verdict), selected
		stored := &StoredApprovalDecision{Decision: decision}
		return CheckApprovalDecisionSelection(stored, action)
	}
	approve, deny := protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY
	calendar := request.Action
	mail := testComputeStored(t, SidecarActionFetchUnlistedUrl)
	for name, c := range map[string]struct {
		err error
		ok  bool
	}{
		"both events":                 {err: selecting(calendar, 2, approve, 0, 1), ok: true},
		"the second":                  {err: selecting(calendar, 2, approve, 1), ok: true},
		"past the events":             {err: selecting(calendar, 2, approve, 0, 2)},
		"a kind-25 approval at 1":     {err: selecting(calendar, 1, approve)},
		"a kind-25 denial at 1":       {err: selecting(calendar, 1, deny), ok: true},
		"a selection on another kind": {err: selecting(mail, 2, approve, 0)},
		"version 2 on another kind":   {err: selecting(mail, 2, deny)},
		"version 1 on another kind":   {err: selecting(mail, 1, approve), ok: true},
		"an automatic one of two":     {err: selecting(calendar, 3, approve, 0)},
		"an automatic one of both":    {err: selecting(calendar, 3, approve, 0, 1), ok: true},
	} {
		if (c.err == nil) != c.ok {
			t.Errorf("%s: %v", name, c.err)
		}
	}
}

// Version 3 on channel 4 alone and channel 4 at version 3 alone: auto set, an AutoVerdict that allowed, clean, under its
// threshold, naming its model and inputs, counting at least one window, run and day; an approval of one use; its
// evidence the SHA-256 of its auto_verdict entry. A kind-25 automatic decision may select, as version 2's does.
func TestDecisionVersion3ChannelAutoOnly(t *testing.T) {
	request := testComputeCalendarRequest(t)
	if _, err := ParseSignedApprovalDecision(testRecordSignDecision(t, testComputeAutoDecision(request))); err != nil {
		t.Fatalf("an automatic decision: %v", err)
	}
	for name, c := range map[string]struct {
		change func(decision *protocol.ApprovalDecision)
		ok     bool
	}{
		"selecting every event":  {change: func(decision *protocol.ApprovalDecision) { decision.Selected = []uint32{0, 1} }, ok: true},
		"channel 4 at version 1": {change: func(decision *protocol.ApprovalDecision) { decision.Version = 1 }},
		"channel 4 at version 2": {change: func(decision *protocol.ApprovalDecision) { decision.Version, decision.Selected = 2, []uint32{0} }},
		"version 3 on device": {change: func(decision *protocol.ApprovalDecision) {
			decision.Channel, decision.EvidenceSha256 = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), nil
		}},
		"version 3 on harness": {change: func(decision *protocol.ApprovalDecision) {
			decision.Channel = uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS)
		}},
		"without auto":             {change: func(decision *protocol.ApprovalDecision) { decision.Auto = false }},
		"without auto_verdict":     {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict = nil }},
		"without evidence":         {change: func(decision *protocol.ApprovalDecision) { decision.EvidenceSha256 = nil }},
		"a denial":                 {change: func(decision *protocol.ApprovalDecision) { decision.Decision, decision.Uses = 2, 0 }},
		"two uses":                 {change: func(decision *protocol.ApprovalDecision) { decision.Uses = 2 }},
		"an ask":                   {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.Verdict = 2 }},
		"reason injection":         {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.Reason = 2 }},
		"a score at its threshold": {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.Score = 2000 }},
		"a threshold past 10,000": {change: func(decision *protocol.ApprovalDecision) {
			decision.AutoVerdict.Threshold, decision.AutoVerdict.Score = 10001, 1
		}},
		"no model":           {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.Model = "" }},
		"a short model hash": {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.ModelSha256 = testComputeId(1) }},
		"no inputs hash":     {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.InputsSha256 = nil }},
		"no windows":         {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.Windows = 0 }},
		"no run count":       {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.RunCount = 0 }},
		"no day count":       {change: func(decision *protocol.ApprovalDecision) { decision.AutoVerdict.DayCount = 0 }},
		"a verdict field this build cannot name": {change: func(decision *protocol.ApprovalDecision) {
			decision.AutoVerdict.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
		}},
	} {
		decision := testComputeAutoDecision(request)
		c.change(decision)
		_, err := ParseSignedApprovalDecision(testRecordSignDecision(t, decision))
		if (err == nil) != c.ok || (!c.ok && !errors.Is(err, ErrRecordStoredInvalid)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a person's channel never sets the automatic fields, whatever the version
	device := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	device.Version, device.Selected, device.Auto = 2, []uint32{0}, true
	if _, err := ParseSignedApprovalDecision(testRecordSignDecision(t, device)); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("a device decision set auto: %v", err)
	}
}

// A reader that predates a decision version refuses it whole: before version 2, a selection's decision; before version
// 3, channel 4's.
func TestDecisionVersionsRefusedByOldReader(t *testing.T) {
	request := testComputeCalendarRequest(t)
	selected := testRecordDecisionBody(request, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)
	selected.Version, selected.Selected = approvalDecisionVersionSelected, []uint32{0}
	automatic := testComputeAutoDecision(request)
	for name, c := range map[string]struct {
		decision *protocol.ApprovalDecision
		known    []uint32
	}{
		"version 2 before it":        {decision: selected, known: []uint32{1}},
		"version 3 before version 2": {decision: automatic, known: []uint32{1}},
		"version 3 before it":        {decision: automatic, known: []uint32{1, 2}},
	} {
		signed := testRecordSignDecision(t, c.decision)
		if _, err := ParseSignedApprovalDecision(signed); err != nil {
			t.Errorf("%s, today: %v", name, err)
		}
		if _, err := parseSignedApprovalDecision(signed, testRecordVersionsKnown(c.known...)); !errors.Is(err, ErrApprovalVersionUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, version := range []uint32{0, 4} {
		decision := proto.Clone(selected).(*protocol.ApprovalDecision)
		decision.Version = version
		if _, err := ParseSignedApprovalDecision(testRecordSignDecision(t, decision)); !errors.Is(err, ErrApprovalVersionUnknown) {
			t.Errorf("version %d: %v", version, err)
		}
	}
}

// The spend check holds a decision's selection to the action it spends on, at its payload step: a version-2 approval
// of the kind-25 action's events passes it, one selecting past them or a version-1 approval of kind 25 is refused,
// and channel 4 spends nowhere until its rules land (CACL-M13-01).
func TestSpendHoldsTheSelectionToItsAction(t *testing.T) {
	world := newTestSpendWorld(t)
	calendar := testComputeStored(t, SidecarActionCalendarWrite)
	input := &SpendInput{Action: calendar, Spender: world.laptop, Now: time.UnixMilli(world.nowMs)}
	body := func(edit func(body *protocol.ApprovalDecision)) *StoredApprovalDecision {
		decision := testSpendDecisionBody(calendar, world.approvalId, world.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
			world.laptop, world.pin, world.nowMs+testConfigHourMs)
		edit(decision)
		return testSpendParse(t, world.signed(t, world.phone, decision))
	}
	testSpendExpect(t, "both events", Spendable(body(func(decision *protocol.ApprovalDecision) {
		decision.Version, decision.Selected = approvalDecisionVersionSelected, []uint32{0, 1}
	}), input, world.state(), nil), "")
	testSpendExpect(t, "past the events", Spendable(body(func(decision *protocol.ApprovalDecision) {
		decision.Version, decision.Selected = approvalDecisionVersionSelected, []uint32{2}
	}), input, world.state(), nil), SpendRefusalPayload)
	testSpendExpect(t, "a version-1 approval of kind 25", Spendable(body(func(decision *protocol.ApprovalDecision) {}), input, world.state(), nil), SpendRefusalPayload)

	auto := testSpendDecisionBody(calendar, world.approvalId, world.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO,
		world.laptop, world.pin, world.nowMs+testConfigHourMs)
	auto.Version, auto.Auto, auto.Selected = approvalDecisionVersionAuto, true, []uint32{0, 1}
	auto.EvidenceSha256 = bytes.Repeat([]byte{0x14}, recordHashByteCount)
	auto.AutoVerdict = testComputeAutoDecision(testComputeCalendarRequest(t)).GetAutoVerdict()
	testSpendExpect(t, "channel 4", Spendable(testSpendParse(t, world.signed(t, world.laptop, auto)), input, world.state(), nil), SpendRefusalSigner)
}
