//go:build !ios_extension && !js

package sidecar

// CACL-M11-04 and CACL-M12-01: DESIGN-COMPUTE.md §16.3's kinds 19 to 26 reach §5.4's gate, each at CanonicalAction
// version 5 alone under its row, and version 5's rules hold in every parser: each kind's required and optional fields,
// another kind's refused; the caps on a send's stdin, a call's body and kind 25's events; field 49 on kind 5 alone and
// field 70 on kinds 23 to 26 alone; no template; the server paths that take kinds 19 and 21 alone; and a build that
// predates version 5, whose known set is 1 to 4, refusing it whole as an approver, a spender and a gate. Until each
// filing area registers its effect lookup the real gate files a version-5 action's request and spends nothing, and an
// approver's device shows version 5's nested fields through version 5's render (CACL-M12-02). Synthetic values only.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §16.3's kinds in their order.
var testComputeKinds = []SidecarActionKind{
	SidecarActionEnclaveCreate, SidecarActionEnclaveEgressDirect, SidecarActionComputeBudgetRaise,
	SidecarActionEnclaveDelete, SidecarActionFetchUnlistedUrl, SidecarActionTaintedSend, SidecarActionCalendarWrite,
	SidecarActionServiceWrite,
}

// A synthetic 16-byte id.
func testComputeId(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, recordIdByteCount)
}

// The SHA-256 a test's kind-24 send names: field 46 as the builder stores it.
func testComputeSendSha256(t testing.TB, send *protocol.SendFields) []byte {
	t.Helper()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(send)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(stored)
	return sum[:]
}

// A kind-26 call's body and its SHA-256.
const testComputeServiceBody = `{"text":"buy milk"}`

func testComputeServiceSha256() []byte {
	sum := sha256.Sum256([]byte(testComputeServiceBody))
	return sum[:]
}

// One full version-5 action of each kind, as its builder fills it, with kind 5's version-5 egress_change beside them;
// kinds 19 and 21 without their sealed detail, which testComputeStored seals. Synthetic values only.
func testComputeActions(t testing.TB) map[SidecarActionKind]*protocol.CanonicalAction {
	t.Helper()
	enclave := &protocol.EnclaveFields{
		EnclaveId: testComputeId(0x51), Name: "builder", Shape: "cpu-2", Provider: "hippius", Label: "AP",
		PricePerHour: 120_000_000, Incarnation: 2,
	}
	send := &protocol.SendFields{
		TargetAgent: "reviewer", TargetAgentId: testComputeId(0x52), Mode: 1, Text: "check the build", Cwd: "/work",
		Refs: []*protocol.RefFields{{RepoId: testComputeId(0x53), Path: "notes/plan.md", Version: 7}},
	}
	return map[SidecarActionKind]*protocol.CanonicalAction{
		SidecarActionEgressChange: {
			Kind: uint32(SidecarActionEgressChange), Version: canonicalActionVersionCompute, Subject: testComputeId(0x50),
			EgressMode: uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO), TookTainted: true,
		},
		SidecarActionEnclaveCreate: {
			Kind: uint32(SidecarActionEnclaveCreate), EgressMode: uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO),
			Enclave: &protocol.EnclaveFields{
				EnclaveId: testComputeId(0x51), Shape: "cpu-2", Provider: "hippius", Label: "AP", PricePerHour: 120_000_000,
				Incarnation: 1,
			},
		},
		SidecarActionEnclaveEgressDirect: {
			Kind: uint32(SidecarActionEnclaveEgressDirect), Subject: testComputeId(0x54), Enclave: enclave,
		},
		SidecarActionComputeBudgetRaise: {
			Kind: uint32(SidecarActionComputeBudgetRaise),
			Budget: &protocol.BudgetFields{
				AgentId: testComputeId(0x55), Period: approvalComputeBudgetPeriodDay, Amount: 10_000_000_000,
				Current: 5_000_000_000,
			},
		},
		SidecarActionEnclaveDelete: {
			Kind: uint32(SidecarActionEnclaveDelete), Subject: testComputeId(0x54), Enclave: enclave,
		},
		SidecarActionFetchUnlistedUrl: {
			Kind: uint32(SidecarActionFetchUnlistedUrl), Host: "xn--bcher-kva.example", Url: "https://xn--bcher-kva.example/a?b=1",
			TaintReasons: []string{"web_fetch"}, Auto: &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint},
		},
		SidecarActionTaintedSend: {
			Kind: uint32(SidecarActionTaintedSend), BodySha256: testComputeSendSha256(t, send), Subject: testComputeId(0x56),
			Tool: "agent_prompt", Send: send, TaintReasons: []string{"mail"},
			Auto:       &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint, Rules: []uint32{1, 9}},
			EgressMode: uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS), Enclave: enclave,
		},
		SidecarActionCalendarWrite: {
			Kind: uint32(SidecarActionCalendarWrite), CalendarLabel: "Work", CalendarHost: "caldav.example.com",
			CalendarEvents: []*protocol.CalendarEventAction{
				{
					Operation: approvalComputeEventOperationAdd, Uid: "u1@example.com", Title: "Lunch with Bo",
					Start: "2026-11-27T12:00:00", End: "2026-11-27T13:00:00", Zone: "Europe/Berlin", Reminders: []string{"-PT15M"},
					Source: "the mail from Bo",
				},
				{
					Operation: approvalComputeEventOperationChange, Uid: "u2@example.com", Expected: "etag-7", Title: "Standup",
					Attendees: []string{"ana@example.com"}, Mails: []string{"an update to ana@example.com"},
					Before: &protocol.CalendarEventFields{Title: "Stand-up", Attendees: []string{"ana@example.com"}},
				},
			},
			CalendarLink: testComputeId(0x57), CalendarTarget: bytes.Repeat([]byte{0x58}, recordHashByteCount),
			CalendarName: "Work", Auto: &protocol.AutoFields{Basis: approvalComputeAutoBasisAlways, Rules: []uint32{2}},
		},
		SidecarActionServiceWrite: {
			Kind: uint32(SidecarActionServiceWrite), BodySha256: testComputeServiceSha256(), Host: "api.example.com",
			TaintReasons: []string{"service_call"},
			ServiceCall: &protocol.ServiceCallFields{
				Connection: testComputeId(0x59), Label: "Notes", Service: "notes", Account: "me@example.com", Method: "POST",
				Path: "/v1/notes", ContentType: "application/json", Body: testComputeServiceBody,
				Class: approvalComputeServiceClassWrite, Feature: "notes",
			},
			Auto: &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint},
		},
	}
}

// What a test's kind-19 and kind-21 actions seal.
func testComputeDetails() map[SidecarActionKind]*protocol.CanonicalActionDetail5 {
	return map[SidecarActionKind]*protocol.CanonicalActionDetail5{
		SidecarActionEnclaveCreate:      {Name: "builder", Role: approvalComputeDetailRoleAgents, Harness: "pig"},
		SidecarActionComputeBudgetRaise: {},
	}
}

// kind's test action as stored: built by NewCanonicalAction, or for kinds 19 and 21 sealed by
// NewSealedCanonicalAction5 under the test key and a fixed nonce in the test's network.
func testComputeStored(t testing.TB, kind SidecarActionKind) *StoredCanonicalAction {
	t.Helper()
	action := testComputeActions(t)[kind]
	if detail, sealed := testComputeDetails()[kind]; sealed {
		stored, err := NewSealedCanonicalAction5(action, detail, testConfigSealKey(testActionDetailGeneration),
			testActionDetailNetworkId(), testActionDetailRandom())
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		return stored
	}
	stored, err := NewCanonicalAction(action)
	if err != nil {
		t.Fatalf("kind %d: %v", kind, err)
	}
	return stored
}

// testComputeStored's action, changed and stored again by hand, as a builder that broke a rule would store it: its
// detail resealed beside the changed fields, so only the rule under test refuses it.
func testComputeChanged(t testing.TB, kind SidecarActionKind, change func(action *protocol.CanonicalAction)) []byte {
	t.Helper()
	action := proto.Clone(testComputeStored(t, kind).Action).(*protocol.CanonicalAction)
	change(action)
	if detail, sealed := testComputeDetails()[kind]; sealed && len(action.GetSealedDetail()) != 0 {
		action.SealedDetail = nil
		clearBytes, err := canonicalActionClearBytes(action)
		if err != nil {
			t.Fatal(err)
		}
		sealContext, err := CanonicalActionDetail5SealContext(testActionDetailNetworkId(), clearBytes)
		if err != nil {
			t.Fatal(err)
		}
		if action.SealedDetail, err = SealConfigBody(testConfigSealKey(testActionDetailGeneration), sealContext, detail, testActionDetailRandom()); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// Each of 19 to 26 is on the gate's list in its place and has its row at version 5 alone. On the real gate an action of
// each files its request, and once approved spends nothing and runs no effect, since no area has registered its effect
// lookup yet: refused before its Reserve.
func TestComputeKindsReachGateRefusedForWantOfALookup(t *testing.T) {
	for i, kind := range testComputeKinds {
		if int(kind) != 19+i || sidecarGateKinds[18+i] != kind || !sidecarGateKindKnown(kind) || !approvalComputeKind(kind) {
			t.Errorf("kind %d is not the gate's %dth", kind, 19+i)
		}
		if row, ok := CanonicalActionFields(kind); !ok || !slices.Equal(row.Versions, []uint32{canonicalActionVersionCompute}) {
			t.Errorf("kind %d's row: %+v", kind, row)
		}
	}
	if !slices.Equal(sidecarGateKinds[18:26], testComputeKinds) || approvalComputeKind(SidecarActionMailTlsUnauthenticated) ||
		approvalComputeKind(SidecarActionSupportSend+1) {
		t.Errorf("the gate's list ends %v", sidecarGateKinds[18:])
	}

	world := newTestApprovalWorld(t)
	sidecar, _, _ := newIdentityTestSidecar(t)
	defer sidecar.InstallGate(world.gate)()
	for _, kind := range testComputeKinds {
		stored := testComputeStored(t, kind)
		request := world.pendingRequest(sidecar.Authorize(t.Context(), world.action(stored), nil))
		decision := world.approve(request)
		if kind == SidecarActionCalendarWrite {
			decision = testComputeSelectingDecision(t, world, request, []uint32{0, 1})
		}
		world.log.putDecision(request.ApprovalId(), decision)
		if err := world.inbox.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := sidecar.Authorize(t.Context(), world.action(stored), nil); !errors.Is(err, ErrApprovalNoLookup) {
			t.Errorf("kind %d approved: %v", kind, err)
		}
		if reserves := world.state(request.ApprovalId()).Reserves; len(reserves) != 0 {
			t.Errorf("kind %d reserved %d uses", kind, len(reserves))
		}
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("an effect ran %d times", runCount)
	}
}

// The phone's version-2 approval of request, selecting selected (DESIGN-COMPUTE §23.9).
func testComputeSelectingDecision(t *testing.T, world *testApprovalWorld, request *StoredApprovalRequest, selected []uint32) []byte {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(world.approve(request), signed); err != nil {
		t.Fatal(err)
	}
	body := &protocol.ApprovalDecision{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		t.Fatal(err)
	}
	body.Version = approvalDecisionVersionSelected
	body.Selected = selected
	stored, err := proto.Marshal(testSpendSignedBy(t, world.spend.phone, world.spend.keys[world.spend.phone], body))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// Each kind's row (D-CACL-5): its full action builds at version 5 and parses; each required field missing is refused;
// a field of another kind, or of version 1, is refused; and kind 5 takes version 5 for field 49 alone.
func TestVersion5KindRows(t *testing.T) {
	actions := testComputeActions(t)
	for kind := range actions {
		stored := testComputeStored(t, kind)
		if stored.Action.GetVersion() != canonicalActionVersionCompute {
			t.Errorf("kind %d built at version %d", kind, stored.Action.GetVersion())
		}
		if _, err := ParseStoredCanonicalAction(stored.Bytes); err != nil {
			t.Errorf("kind %d does not parse: %v", kind, err)
		}
		row, _ := CanonicalActionFields(kind)
		required := row.Required
		if kind == SidecarActionEgressChange {
			required = append(slices.Clone(required), canonicalActionFieldTookTainted)
		}
		for _, number := range required {
			stored := testComputeChanged(t, kind, func(action *protocol.CanonicalAction) {
				action.ProtoReflect().Clear(action.ProtoReflect().Descriptor().Fields().ByNumber(number))
			})
			if _, err := ParseStoredCanonicalAction(stored); !errors.Is(err, ErrCanonicalActionInvalid) {
				t.Errorf("kind %d without field %d: %v", kind, number, err)
			}
		}
	}
	// a field another kind's row names, and fields no version-5 action sets
	others := map[SidecarActionKind]func(action *protocol.CanonicalAction){
		SidecarActionEnclaveCreate:       func(action *protocol.CanonicalAction) { action.Url = "https://example.org" },
		SidecarActionEnclaveEgressDirect: func(action *protocol.CanonicalAction) { action.TaintReasons = []string{"mail"} },
		SidecarActionComputeBudgetRaise: func(action *protocol.CanonicalAction) {
			action.Enclave = &protocol.EnclaveFields{EnclaveId: testComputeId(1)}
		},
		SidecarActionEnclaveDelete:    func(action *protocol.CanonicalAction) { action.Tool = "ssh_exec" },
		SidecarActionFetchUnlistedUrl: func(action *protocol.CanonicalAction) { action.Recipients = []string{"a@example.com"} },
		SidecarActionTaintedSend:      func(action *protocol.CanonicalAction) { action.CalendarName = "Work" },
		SidecarActionCalendarWrite:    func(action *protocol.CanonicalAction) { action.Preview = "text" },
		SidecarActionServiceWrite:     func(action *protocol.CanonicalAction) { action.ExpiresMillis = 1 },
		SidecarActionEgressChange:     func(action *protocol.CanonicalAction) { action.RequireDefaultEgress = true },
	}
	for kind, change := range others {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, kind, change)); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d with another kind's field: %v", kind, err)
		}
		changed := proto.Clone(testComputeActions(t)[kind]).(*protocol.CanonicalAction)
		change(changed)
		if _, err := NewCanonicalAction(changed); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d with another kind's field built: %v", kind, err)
		}
	}
	for _, change := range []func(action *protocol.CanonicalAction){
		func(action *protocol.CanonicalAction) { action.Versioning = 1 },
		func(action *protocol.CanonicalAction) { action.ShareNetworkId = testComputeId(9) },
	} {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionTaintedSend, change)); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("version 5 with a field it never sets: %v", err)
		}
	}
	// kind 5 at version 5 under exits: its exits as at version 1, and never the requirement of default egress, which
	// version 1 would take there (QD-1060)
	exits := func(action *protocol.CanonicalAction) {
		action.EgressMode = uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS)
		action.GrantDst = []string{"sidecar:" + strings.Repeat("62", recordIdByteCount)}
	}
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionEgressChange, exits)); err != nil {
		t.Errorf("kind 5 at version 5 under exits: %v", err)
	}
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionEgressChange, func(action *protocol.CanonicalAction) {
		exits(action)
		action.RequireDefaultEgress = true
	})); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("kind 5 at version 5 requiring default egress: %v", err)
	}
	// each optional field may be set or not
	for kind, change := range map[SidecarActionKind]func(action *protocol.CanonicalAction){
		SidecarActionTaintedSend: func(action *protocol.CanonicalAction) {
			action.Context = &protocol.ContextFields{RunId: testComputeId(0x63), EntryId: testComputeId(0x64), Nodes: 4, Flagged: 1, Act: approvalComputeContextActContinue}
			action.Enclave, action.EgressMode = nil, 0
		},
		SidecarActionCalendarWrite: func(action *protocol.CanonicalAction) { action.CalendarAudience = "shared with 3 people" },
	} {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, kind, change)); err != nil {
			t.Errorf("kind %d with its optional fields changed: %v", kind, err)
		}
	}
	// version 5's kinds at any other version, and version 5's fields on any other version's action
	for _, kind := range testComputeKinds {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, kind, func(action *protocol.CanonicalAction) { action.Version = 1 })); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d at version 1: %v", kind, err)
		}
	}
	mail := testRecordDnsAction()
	mail.Url = "https://example.org"
	if _, err := ParseStoredCanonicalAction(testRecordStored(t, mail)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("field 44 at version 1: %v", err)
	}
	// a kind version 5 has no row for, and one whose row takes no version 5
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionFetchUnlistedUrl, func(action *protocol.CanonicalAction) { action.Kind = uint32(SidecarActionDnsSet) })); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a dns_set at version 5: %v", err)
	}
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionFetchUnlistedUrl, func(action *protocol.CanonicalAction) { action.Kind = uint32(SidecarActionPayment) })); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a payment at version 5: %v", err)
	}
}

// What a row cannot say: ids at their sizes, enumerated values §16.3 names, hosts in their one form, no empty entry,
// no field this build cannot name at any depth, and a body_sha256 over exactly a call's body.
func TestVersion5Shapes(t *testing.T) {
	cases := map[string]struct {
		kind   SidecarActionKind
		change func(action *protocol.CanonicalAction)
	}{
		"an enclave id of 8 bytes":    {kind: SidecarActionEnclaveDelete, change: func(action *protocol.CanonicalAction) { action.Enclave.EnclaveId = testComputeId(1)[:8] }},
		"no enclave id on 20":         {kind: SidecarActionEnclaveEgressDirect, change: func(action *protocol.CanonicalAction) { action.Enclave.EnclaveId = nil }},
		"a create naming its enclave": {kind: SidecarActionEnclaveCreate, change: func(action *protocol.CanonicalAction) { action.Enclave.Name = "builder" }},
		"a create with no shape":      {kind: SidecarActionEnclaveCreate, change: func(action *protocol.CanonicalAction) { action.Enclave.Shape = "" }},
		"a create's egress mode 4":    {kind: SidecarActionEnclaveCreate, change: func(action *protocol.CanonicalAction) { action.EgressMode = 4 }},
		"a send's egress mode 5":      {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.EgressMode = 5 }},
		"a send's other text":         {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.Send.Text = "delete it all" }},
		"a subject of 8 bytes":        {kind: SidecarActionEnclaveDelete, change: func(action *protocol.CanonicalAction) { action.Subject = testComputeId(1)[:8] }},
		"budget period 4":             {kind: SidecarActionComputeBudgetRaise, change: func(action *protocol.CanonicalAction) { action.Budget.Period = 4 }},
		"budget period 0":             {kind: SidecarActionComputeBudgetRaise, change: func(action *protocol.CanonicalAction) { action.Budget.Period = 0 }},
		"a budget of no amount":       {kind: SidecarActionComputeBudgetRaise, change: func(action *protocol.CanonicalAction) { action.Budget.Amount = 0 }},
		"a host with capitals":        {kind: SidecarActionFetchUnlistedUrl, change: func(action *protocol.CanonicalAction) { action.Host = "Example.org" }},
		"a host in unicode":           {kind: SidecarActionFetchUnlistedUrl, change: func(action *protocol.CanonicalAction) { action.Host = "bücher.example" }},
		"a calendar host with a port": {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarHost = "caldav.example.com:8443" }},
		"an empty taint reason":       {kind: SidecarActionFetchUnlistedUrl, change: func(action *protocol.CanonicalAction) { action.TaintReasons = []string{""} }},
		"send mode 4":                 {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.Send.Mode = 4 }},
		"a ref with no path":          {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.Send.Refs[0].Path = "" }},
		"a send's empty tool":         {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.Send.Tools = []string{""} }},
		"a launch budget of period 9": {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) {
			action.Send.Budget = &protocol.BudgetFields{Period: 9, Amount: 1}
		}},
		"a context of act 3": {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) {
			action.Context = &protocol.ContextFields{RunId: testComputeId(1), Act: 3}
		}},
		"a context with no run":         {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.Context = &protocol.ContextFields{Act: 1} }},
		"a body_sha256 of 16 bytes":     {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) { action.BodySha256 = testComputeId(1) }},
		"a calendar_target of 16 bytes": {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarTarget = testComputeId(1) }},
		"a calendar_link of 32 bytes":   {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarLink = bytes.Repeat([]byte{1}, 32) }},
		"event operation 4":             {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[0].Operation = 4 }},
		"an event with no uid":          {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[0].Uid = "" }},
		"an addition expecting":         {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[0].Expected = "etag" }},
		"a change expecting nothing":    {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[1].Expected = "" }},
		"an addition's prior values": {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) {
			action.CalendarEvents[0].Before = &protocol.CalendarEventFields{}
		}},
		"a change with no prior values":  {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[1].Before = nil }},
		"an empty attendee":              {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[1].Attendees = []string{""} }},
		"an empty prior attendee":        {kind: SidecarActionCalendarWrite, change: func(action *protocol.CanonicalAction) { action.CalendarEvents[1].Before.Attendees = []string{""} }},
		"a call of class 3":              {kind: SidecarActionServiceWrite, change: func(action *protocol.CanonicalAction) { action.ServiceCall.Class = 3 }},
		"a call with no method":          {kind: SidecarActionServiceWrite, change: func(action *protocol.CanonicalAction) { action.ServiceCall.Method = "" }},
		"a call's connection of 4 bytes": {kind: SidecarActionServiceWrite, change: func(action *protocol.CanonicalAction) { action.ServiceCall.Connection = []byte{1, 2, 3, 4} }},
		"a body_sha256 of another body":  {kind: SidecarActionServiceWrite, change: func(action *protocol.CanonicalAction) { action.ServiceCall.Body = `{"text":"sell milk"}` }},
		"a nested field this build cannot name": {kind: SidecarActionTaintedSend, change: func(action *protocol.CanonicalAction) {
			action.Send.Refs[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
	}
	for name, c := range cases {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, c.kind, c.change)); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a send into an enclave whose default egress is off names it 4, direct, on kind 24 alone (QD-1391)
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionTaintedSend, func(action *protocol.CanonicalAction) {
		action.EgressMode = approvalComputeEgressModeDirect
	})); err != nil {
		t.Errorf("a send into a direct-egress enclave: %v", err)
	}
	// a send's field 46 stored twice, which protobuf merges, is two sends
	twice := testComputeStored(t, SidecarActionTaintedSend).Bytes
	for _, record := range testWireRecords(t, twice) {
		if number, _, _ := protowire.ConsumeTag(record); number == canonicalActionFieldSend {
			twice = append(bytes.Clone(twice), record...)
		}
	}
	if _, err := ParseStoredCanonicalAction(twice); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("field 46 stored twice: %v", err)
	}
	// a string that is no UTF-8 does not parse at all
	invalid := testComputeChanged(t, SidecarActionFetchUnlistedUrl, func(action *protocol.CanonicalAction) { action.Url = "https://example.org/OK" })
	invalid = bytes.Replace(invalid, []byte("OK"), []byte{0xff, 0xfe}, 1)
	if _, err := ParseStoredCanonicalAction(invalid); err == nil {
		t.Error("a URL that is no UTF-8 parsed")
	}
}

// §16.3's stdin past 32 KiB is refused, and at it taken.
func TestSendStdinCap(t *testing.T) {
	settings := DefaultCanonicalActionSettings()
	for stdinByteCount, ok := range map[int]bool{settings.SendStdinMaxByteCount: true, settings.SendStdinMaxByteCount + 1: false} {
		stored := testComputeChanged(t, SidecarActionTaintedSend, func(action *protocol.CanonicalAction) {
			action.Send.Stdin = strings.Repeat("s", stdinByteCount)
			action.BodySha256 = testComputeSendSha256(t, action.Send)
		})
		if _, err := ParseStoredCanonicalAction(stored); (err == nil) != ok {
			t.Errorf("stdin of %d bytes: %v", stdinByteCount, err)
		}
	}
	if settings.SendStdinMaxByteCount != 32*1024 {
		t.Errorf("the stdin cap is %d", settings.SendStdinMaxByteCount)
	}
}

// §25.10's body up to 32 KiB, field 3 over exactly it; past it refused.
func TestServiceBodyCap(t *testing.T) {
	settings := DefaultCanonicalActionSettings()
	for bodyByteCount, ok := range map[int]bool{settings.ServiceBodyMaxByteCount: true, settings.ServiceBodyMaxByteCount + 1: false} {
		stored := testComputeChanged(t, SidecarActionServiceWrite, func(action *protocol.CanonicalAction) {
			action.ServiceCall.Body = strings.Repeat("b", bodyByteCount)
			sum := sha256.Sum256([]byte(action.ServiceCall.Body))
			action.BodySha256 = sum[:]
		})
		if _, err := ParseStoredCanonicalAction(stored); (err == nil) != ok {
			t.Errorf("a body of %d bytes: %v", bodyByteCount, err)
		}
	}
	if settings.ServiceBodyMaxByteCount != 32*1024 {
		t.Errorf("the body cap is %d", settings.ServiceBodyMaxByteCount)
	}
}

// §23.9's 1 to 20 events on kind 25.
func TestCalendarEventCount(t *testing.T) {
	settings := DefaultCanonicalActionSettings()
	for count, ok := range map[int]bool{0: false, 1: true, settings.CalendarEventMaxCount: true, settings.CalendarEventMaxCount + 1: false} {
		stored := testComputeChanged(t, SidecarActionCalendarWrite, func(action *protocol.CanonicalAction) {
			events := []*protocol.CalendarEventAction{}
			for i := range count {
				event := proto.Clone(action.CalendarEvents[0]).(*protocol.CalendarEventAction)
				event.Uid = strings.Repeat("u", i+1) + "@example.com"
				events = append(events, event)
			}
			action.CalendarEvents = events
		})
		if _, err := ParseStoredCanonicalAction(stored); (err == nil) != ok {
			t.Errorf("%d events: %v", count, err)
		}
	}
	if settings.CalendarEventMaxCount != 20 {
		t.Errorf("the event cap is %d", settings.CalendarEventMaxCount)
	}
}

// Field 49 rides kind 5 at version 5 alone, and kind 5 at version 5 always sets it; at version 1 it is refused.
func TestTookTaintedOnlyOnKind5(t *testing.T) {
	for _, kind := range testComputeKinds {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, kind, func(action *protocol.CanonicalAction) { action.TookTainted = true })); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d with field 49: %v", kind, err)
		}
	}
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionEgressChange, func(action *protocol.CanonicalAction) { action.TookTainted = false })); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("kind 5 at version 5 without field 49: %v", err)
	}
	if _, err := ParseStoredCanonicalAction(testComputeChanged(t, SidecarActionEgressChange, func(action *protocol.CanonicalAction) { action.Version = 1 })); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("field 49 at version 1: %v", err)
	}
	plain := proto.Clone(testComputeActions(t)[SidecarActionEgressChange]).(*protocol.CanonicalAction)
	plain.Version = 0
	plain.TookTainted = false
	if stored, err := NewCanonicalAction(plain); err != nil || stored.Action.GetVersion() != 1 {
		t.Errorf("kind 5 without field 49 builds at version 1: %v", err)
	}
	tookTainted := proto.Clone(plain).(*protocol.CanonicalAction)
	tookTainted.TookTainted = true
	if _, err := NewCanonicalAction(tookTainted); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("field 49 built at version 1: %v", err)
	}
}

// Field 70 rides kinds 23 to 26 alone, basis taint or always, its rules ascending among §27.7's 1 to 10 (QD-1371).
func TestAutoFieldsOnlyOnKinds23To26(t *testing.T) {
	auto := &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint}
	for _, kind := range []SidecarActionKind{SidecarActionEnclaveCreate, SidecarActionEnclaveEgressDirect, SidecarActionComputeBudgetRaise, SidecarActionEnclaveDelete, SidecarActionEgressChange} {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, kind, func(action *protocol.CanonicalAction) { action.Auto = auto })); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d with field 70: %v", kind, err)
		}
	}
	for name, c := range map[string]struct {
		auto *protocol.AutoFields
		ok   bool
	}{
		"basis taint":             {auto: &protocol.AutoFields{Basis: 1}, ok: true},
		"basis always":            {auto: &protocol.AutoFields{Basis: 2}, ok: true},
		"every action rule":       {auto: &protocol.AutoFields{Basis: 1, Rules: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, ok: true},
		"basis 0":                 {auto: &protocol.AutoFields{}},
		"basis 3":                 {auto: &protocol.AutoFields{Basis: 3}},
		"rule 0":                  {auto: &protocol.AutoFields{Basis: 1, Rules: []uint32{0}}},
		"rule 11, the decision's": {auto: &protocol.AutoFields{Basis: 1, Rules: []uint32{11}}},
		"rules repeated":          {auto: &protocol.AutoFields{Basis: 1, Rules: []uint32{2, 2}}},
		"rules out of order":      {auto: &protocol.AutoFields{Basis: 1, Rules: []uint32{3, 2}}},
	} {
		for _, kind := range []SidecarActionKind{SidecarActionFetchUnlistedUrl, SidecarActionTaintedSend, SidecarActionCalendarWrite, SidecarActionServiceWrite} {
			stored := testComputeChanged(t, kind, func(action *protocol.CanonicalAction) { action.Auto = c.auto })
			if _, err := ParseStoredCanonicalAction(stored); (err == nil) != c.ok {
				t.Errorf("%s on kind %d: %v", name, kind, err)
			}
		}
	}
}

// Every use of a version-5 action is its own approval: no template, built or parsed.
func TestVersion5NoTemplate(t *testing.T) {
	for kind := range testComputeActions(t) {
		if _, err := ParseStoredCanonicalAction(testComputeChanged(t, kind, func(action *protocol.CanonicalAction) { action.Scope = true })); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d's template parsed: %v", kind, err)
		}
		template := proto.Clone(testComputeActions(t)[kind]).(*protocol.CanonicalAction)
		template.Scope = true
		if _, err := NewCanonicalAction(template); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d's template built: %v", kind, err)
		}
	}
}

// The build before version 5, whose known set is 1 to 4: every version-5 action of every kind refused whole, as a
// version this build does not know, by the approver's request parse.
func TestVersion5RefusedByOldApprover(t *testing.T) {
	known := testRecordVersionsKnown(1, 2, 3, 4)
	for kind := range testComputeActions(t) {
		stored := testComputeStored(t, kind)
		request := testRecordRequest(t, stored.Bytes)
		storedRequest := testRecordStored(t, request)
		if _, err := ParseStoredApprovalRequest(storedRequest); err != nil {
			t.Errorf("kind %d's request today: %v", kind, err)
		}
		if _, err := parseStoredApprovalRequest(storedRequest, known); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
			t.Errorf("kind %d's request before version 5: %v", kind, err)
		}
	}
}

// The spender before version 5 parses the action a decision hashes as the approver does, and refuses it whole.
func TestVersion5RefusedByOldSpender(t *testing.T) {
	known := testRecordVersionsKnown(1, 2, 3, 4)
	for kind := range testComputeActions(t) {
		stored := testComputeStored(t, kind)
		if _, err := parseStoredCanonicalAction(stored.Bytes, known); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
			t.Errorf("kind %d before version 5: %v", kind, err)
		}
		if _, err := newCanonicalAction(testComputeActions(t)[kind], known); err == nil {
			t.Errorf("kind %d built before version 5", kind)
		}
	}
}

// The gate before version 5 refuses the action before its server column is read; today's gate reads it.
func TestVersion5RefusedByOldGate(t *testing.T) {
	known := testRecordVersionsKnown(1, 2, 3, 4)
	for _, kind := range []SidecarActionKind{SidecarActionEnclaveCreate, SidecarActionComputeBudgetRaise} {
		stored := testComputeStored(t, kind)
		if _, err := parseStoredCanonicalAction(stored.Bytes, known); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
			t.Errorf("kind %d before version 5: %v", kind, err)
		}
		parsed, err := ParseStoredCanonicalAction(stored.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckCanonicalActionForServer(parsed); err != nil {
			t.Errorf("kind %d today: %v", kind, err)
		}
	}
}

// Kinds 19 and 21 pass a server path with their Server fields alone; 20 and 22 to 26, and kind 5 at version 5, are
// refused whole.
func TestVersion5ServerColumns(t *testing.T) {
	for kind := range testComputeActions(t) {
		err := CheckCanonicalActionForServer(testComputeStored(t, kind))
		switch kind {
		case SidecarActionEnclaveCreate, SidecarActionComputeBudgetRaise:
			if err != nil {
				t.Errorf("kind %d: %v", kind, err)
			}
		default:
			if !errors.Is(err, ErrCanonicalActionInvalid) {
				t.Errorf("kind %d on a server path: %v", kind, err)
			}
		}
	}
	// a field outside the column on an action that parses: no row lets 19 or 21 carry another, so a stored action that
	// held one would fail the parse first; the column itself is exactly §16.3's
	for kind, want := range map[SidecarActionKind][]protoreflect.FieldNumber{
		SidecarActionEnclaveCreate:      {canonicalActionFieldSealedDetail, canonicalActionFieldEgressMode, canonicalActionFieldEnclave},
		SidecarActionComputeBudgetRaise: {canonicalActionFieldSealedDetail, canonicalActionFieldBudget},
	} {
		row, _ := CanonicalActionFields(kind)
		if !slices.Equal(row.Server, want) {
			t.Errorf("kind %d's server column %v", kind, row.Server)
		}
	}
	// a version-5 action whose kind a server column names at another version still goes to no server
	planted := &StoredCanonicalAction{Action: &protocol.CanonicalAction{Kind: uint32(SidecarActionDnsSet), Version: canonicalActionVersionCompute}}
	if err := CheckCanonicalActionForServer(planted); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a dns action at version 5 on a server path: %v", err)
	}
}

// Version 5's render (CACL-M12-02) shows a fetch's nested fields field by field, and an approver's device takes an
// approval of it; kind 25, whose per-event cards are MAILCAL-M13-06's, still lists deny alone and takes none, a denial
// still filing. No render panics on a message field, and every kind's render is version 5's.
func TestVersion5RequestTakesApprovalOnceItsRenderShowsIt(t *testing.T) {
	world := newTestApproverWorld(t)
	stored := testComputeStored(t, SidecarActionFetchUnlistedUrl)
	request := world.put(world.requesterId, stored, "fetch the page")
	item := world.item(request.ApprovalId())
	if item.Render == nil || item.Render.Unshown || !slices.Equal(item.Decisions, []string{SidecarDecisionApprove, SidecarDecisionDeny}) {
		t.Fatalf("the item: %+v", item)
	}
	shown := map[string]string{}
	for _, field := range item.Render.Fields {
		shown[field.Name] = field.Value
	}
	if shown["auto.basis"] != "1 (taint)" || shown["url"] != "https://xn--bcher-kva.example/a?b=1" {
		t.Errorf("the fields: %v", shown)
	}
	calendar := world.put(world.requesterId, testComputeStored(t, SidecarActionCalendarWrite), "add lunch")
	if item := world.item(calendar.ApprovalId()); !item.Render.Unshown || !slices.Equal(item.Decisions, []string{SidecarDecisionDeny}) {
		t.Errorf("kind 25's item: %v", item.Decisions)
	}
	if err := world.approver.Decide(t.Context(), calendar.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalUnshown) {
		t.Errorf("kind 25's approval: %v", err)
	}
	if world.decisionCount() != 0 {
		t.Error("an approval of kind 25 was filed")
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
		t.Errorf("an approval: %v", err)
	}
	for kind := range testComputeActions(t) {
		parsed, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, testComputeStored(t, kind).Bytes)))
		if err != nil {
			t.Fatal(err)
		}
		if render := RenderApprovalRequest(parsed); render.Compute == nil {
			t.Errorf("kind %d's render is not version 5's", kind)
		}
	}
	// versions 1 to 4 hold no nested field, and show whole as before
	if !approvalRenderShowsWhole(testRecordDnsAction()) {
		t.Error("a dns action does not show whole")
	}
}
