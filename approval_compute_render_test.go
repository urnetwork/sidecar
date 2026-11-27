//go:build !ios_extension && !js

package sidecar

// CACL-M12-02: how an approver's device shows version 5's kinds (DESIGN-COMPUTE §16.3, §25.10, §28.8; D-MCP-17): one
// golden text per kind and form, in testdata/approval_compute/render/; kind 19's disclosure line; an oversize field, a
// sealed detail that did not open, a host that is not its URL's, kind 25's events and kind 27's files each taking no
// approval; and the approver's device taking an approval once it showed the action whole. Synthetic values only.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A disclosure registry's lines, by id; an id it lacks does not render.
type testApprovalDisclosureLines map[string]string

// See ApprovalComputeDisclosureLines.
func (self testApprovalDisclosureLines) ApprovalDisclosureLine(id string) (string, error) {
	line, ok := self[id]
	if !ok {
		return "", errors.New("no such disclosure")
	}
	return line, nil
}

// The tests' registry: Hippius's enclave line.
func testComputeDisclosures() testApprovalDisclosureLines {
	return testApprovalDisclosureLines{"enclave:hippius": "Hippius's machines run your enclave; the provider sees its traffic's size and timing."}
}

// Opens a version-5 detail under the tests' key and network, as Sidecar.OpenActionDetail5 does with its own.
type testComputeDetailOpener struct{}

// See CanonicalActionDetail5Opener.
func (testComputeDetailOpener) OpenActionDetail5(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail5, error) {
	return OpenCanonicalActionDetail5(action, testActionDetailNetworkId(), testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration)))
}

// stored as a request with the tests' fixed ids, parsed.
func testComputeApprovalRequest(t *testing.T, stored *StoredCanonicalAction) *StoredApprovalRequest {
	t.Helper()
	request, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, stored.Bytes)))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// stored's render on a device that opens its detail with the tests' key and renders disclosures from lines.
func testComputeRender(t *testing.T, stored *StoredCanonicalAction, lines ApprovalComputeDisclosureLines) *ApprovalRender {
	t.Helper()
	request := testComputeApprovalRequest(t, stored)
	detail, err := testComputeDetailOpener{}.OpenActionDetail5(request.Action)
	if err != nil {
		t.Fatal(err)
	}
	return RenderApprovalRequestCompute(&ApprovalComputeRenderArgs{Request: request, Detail: detail, Disclosures: lines})
}

// A version-5 action built and stored, sealing detail where it is given.
func testComputeBuilt(t *testing.T, action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5) *StoredCanonicalAction {
	t.Helper()
	action.Version = canonicalActionVersionCompute
	if detail != nil {
		stored, err := NewSealedCanonicalAction5(action, detail, testConfigSealKey(testActionDetailGeneration),
			testActionDetailNetworkId(), testActionDetailRandom())
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	stored, err := NewCanonicalAction(action)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// kind 24's test action with its send replaced by send, its hash recomputed.
func testComputeSendAction(t *testing.T, change func(action *protocol.CanonicalAction)) *protocol.CanonicalAction {
	t.Helper()
	action := proto.Clone(testComputeActions(t)[SidecarActionTaintedSend]).(*protocol.CanonicalAction)
	change(action)
	if action.GetContext() == nil {
		action.BodySha256 = testComputeSendSha256(t, action.GetSend())
	}
	return action
}

// Every kind and form the render draws, by golden name.
func testComputeRenderForms(t *testing.T) map[string]*StoredCanonicalAction {
	t.Helper()
	actions := testComputeActions(t)
	indexer := proto.Clone(actions[SidecarActionEnclaveCreate]).(*protocol.CanonicalAction)
	grantRaise := proto.Clone(actions[SidecarActionComputeBudgetRaise]).(*protocol.CanonicalAction)
	grantRaise.Budget.AgentId = nil
	message := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Enclave, action.EgressMode = nil, 0
		action.Tool = "agent_send"
		action.Send = &protocol.SendFields{
			TargetAgent: "planner", TargetAgentId: testComputeId(0x61), TargetMemberId: testComputeId(0x62),
			Text: "Subject: the build\nIt passed; see the plan.",
			Refs: []*protocol.RefFields{{RepoId: testComputeId(0x53), Path: "notes/plan.md", Version: 7}},
		}
	})
	command := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Tool = "ssh_exec"
		action.EgressMode = approvalComputeEgressModeDirect
		action.Send = &protocol.SendFields{Text: "make test", Stdin: "y\n", Cwd: "/work"}
	})
	continuation := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Tool = "harness_continue"
		action.BodySha256 = bytes.Repeat([]byte{0x63}, recordHashByteCount)
		action.Send = &protocol.SendFields{Text: "go on"}
		action.Context = &protocol.ContextFields{
			RunId: testComputeId(0x64), EntryId: testComputeId(0x65), Nodes: 12, Flagged: 1, Untrusted: 3,
			MailMessages: 2, CalendarEvents: 1, FetchedPages: 4, ServiceResults: 0, Act: approvalComputeContextActContinue,
		}
	})
	crossing := proto.Clone(continuation).(*protocol.CanonicalAction)
	crossing.Tool = "bash"
	crossing.Context.Act = approvalComputeContextActCross
	release := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Tool = "ur enclave release"
		action.Send = &protocol.SendFields{Refs: []*protocol.RefFields{{RepoId: testComputeId(0x66), Path: "out/report.md", Version: 3}}}
	})
	supportBody := []byte(`{"text":"the build hangs"}`)
	supportSha256 := sha256.Sum256(supportBody)
	support := &protocol.CanonicalAction{
		Kind: uint32(SidecarActionSupportSend), BodySha256: supportSha256[:], TaintReasons: []string{"web_fetch"},
		Auto: &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint},
		Support: &protocol.SupportFields{
			Product: SupportProductUrnetwork, Entry: "100042", Kind: supportKindBug, Text: "The build hangs at step 3.\nLogs attached.",
			Bundle: &protocol.BundleManifest{
				Events: 40, First: 1764201600, Last: 1764205200, Bytes: 2048, Sha256: bytes.Repeat([]byte{0x67}, recordHashByteCount),
				Codes: []*protocol.BundleCodeCount{{Component: "daemon", Code: "started", Count: 2}},
			},
			ClientRef: testComputeId(0x68),
		},
	}
	withFile := proto.Clone(support).(*protocol.CanonicalAction)
	withFile.Auto = &protocol.AutoFields{Basis: approvalComputeAutoBasisAlways, Rules: []uint32{approvalComputeAutoRuleAttachment}}
	withFile.Support.Files = []*protocol.FileFields{{Name: "build.log", Type: supportFileTypeText, Size: 120, Sha256: bytes.Repeat([]byte{0x69}, recordHashByteCount)}}
	return map[string]*StoredCanonicalAction{
		"v5_19_enclave_create":             testComputeStored(t, SidecarActionEnclaveCreate),
		"v5_19_enclave_create_indexer":     testComputeBuilt(t, indexer, &protocol.CanonicalActionDetail5{Name: "mail-indexer", Role: approvalComputeDetailRoleIndexer}),
		"v5_20_enclave_egress_direct":      testComputeStored(t, SidecarActionEnclaveEgressDirect),
		"v5_21_compute_budget_raise":       testComputeStored(t, SidecarActionComputeBudgetRaise),
		"v5_21_compute_budget_raise_grant": testComputeBuilt(t, grantRaise, &protocol.CanonicalActionDetail5{GrantId: testComputeId(0x6a)}),
		"v5_22_enclave_delete":             testComputeStored(t, SidecarActionEnclaveDelete),
		"v5_23_fetch_unlisted_url":         testComputeStored(t, SidecarActionFetchUnlistedUrl),
		"v5_24_tainted_send_prompt":        testComputeStored(t, SidecarActionTaintedSend),
		"v5_24_tainted_send_message":       testComputeBuilt(t, message, nil),
		"v5_24_tainted_send_command":       testComputeBuilt(t, command, nil),
		"v5_24_tainted_send_continue":      testComputeBuilt(t, continuation, nil),
		"v5_24_tainted_send_cross":         testComputeBuilt(t, crossing, nil),
		"v5_24_tainted_send_release":       testComputeBuilt(t, release, nil),
		"v5_25_calendar_write":             testComputeStored(t, SidecarActionCalendarWrite),
		"v5_26_service_write":              testComputeStored(t, SidecarActionServiceWrite),
		"v5_27_support_send":               testComputeBuilt(t, support, nil),
		"v5_27_support_send_file":          testComputeBuilt(t, withFile, nil),
		"v5_5_egress_change":               testComputeStored(t, SidecarActionEgressChange),
	}
}

// The forms whose render takes no approval, and why, in part.
var testComputeRenderWithheld = map[string]string{
	"v5_24_tainted_send_release": "a release's versions",
	"v5_25_calendar_write":       "only by the calendar's card",
	"v5_27_support_send_file":    "only by the support conversation's card",
}

// One golden text per kind 19 to 24 and 26, kind 24's send, prompt, command, continuation, crossing and release among
// them, with kind 27's, kind 25's and kind 5's version-5 forms; the rest take an approval, those withheld say why.
func TestRenderVersion5Goldens(t *testing.T) {
	for name, stored := range testComputeRenderForms(t) {
		render := testComputeRender(t, stored, testComputeDisclosures())
		testApprovalComputeRenderGolden(t, name, render.Text())
		if render.Compute == nil {
			t.Fatalf("%s: no version-5 render", name)
		}
		reason, withheld := testComputeRenderWithheld[name]
		if render.Whole() == withheld {
			t.Errorf("%s: whole %v, withheld %v", name, render.Whole(), render.Compute.Withheld)
		}
		if withheld && !slices.ContainsFunc(render.Compute.Withheld, func(text string) bool { return strings.Contains(text, reason) }) {
			t.Errorf("%s: withheld for %v", name, render.Compute.Withheld)
		}
		for _, field := range render.Fields {
			if field.Value == approvalRenderUnshownValue {
				t.Errorf("%s: %s unshown", name, field.Name)
			}
		}
	}
	// kind 24's and kind 26's whole text are sections of their own, never the preview
	forms := testComputeRenderForms(t)
	for name, section := range map[string]string{
		"v5_24_tainted_send_message": "send.text", "v5_24_tainted_send_command": "send.stdin",
		"v5_26_service_write": "service_call.body", "v5_27_support_send": "support.text",
	} {
		render := testComputeRender(t, forms[name], nil)
		if render.Preview != "" || !slices.ContainsFunc(render.Compute.Sections, func(shown *ApprovalComputeSection) bool {
			return shown.Name == section
		}) {
			t.Errorf("%s: sections %v, preview %q", name, render.Compute.Sections, render.Preview)
		}
	}
}

// Every control, bidi and invisible character is escaped visibly, nothing dropped, a backslash doubled so every escape
// is the render's own; a section keeps its lines; a version-5 render flags a value that held any.
func TestRenderEscapesBidiAndInvisible(t *testing.T) {
	for _, item := range []struct {
		text   string
		shown  string
		hidden bool
	}{
		{text: "a\u202eb\u200bc\U000e0041d\ufe0fe\x1bf\u0085g\x7fh\\i\u2028j\u2066k", hidden: true,
			shown: `a\u{202E}b\u{200B}c\u{E0041}d\u{FE0F}e\u{001B}f\u{0085}g\u{007F}h\\i\u{2028}j\u{2066}k`},
		{text: "tab\there", shown: `tab\u{0009}here`, hidden: true},
		{text: "bad\xffbyte", shown: `bad\x{FF}byte`, hidden: true},
		{text: "line\nfeed", shown: `line\u{000A}feed`, hidden: true},
		{text: "plain ascii 1-2", shown: "plain ascii 1-2"},
		{text: "back\\slash", shown: `back\\slash`},
		{text: "bücher ✓", shown: "bücher ✓"},
		{text: "\u3164hangul", shown: `\u{3164}hangul`, hidden: true},
		{text: "\u034fjoiner", shown: `\u{034F}joiner`, hidden: true},
	} {
		if shown := ApprovalUntrustedText(item.text); shown != item.shown {
			t.Errorf("%q shown as %q, want %q", item.text, shown, item.shown)
		}
		if ApprovalUntrustedHidden(item.text) != item.hidden {
			t.Errorf("%q hidden %v", item.text, ApprovalUntrustedHidden(item.text))
		}
	}
	if lines := ApprovalUntrustedLines("one\r\ntwo\u202e\n"); !slices.Equal(lines, []string{`one\u{000D}`, `two\u{202E}`, ""}) {
		t.Errorf("lines %q", lines)
	}

	hidden := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Send.Text = "approve this\u202e\n\u200bfor me"
	})
	render := testComputeRender(t, testComputeBuilt(t, hidden, nil), nil)
	text := render.Text()
	if !strings.Contains(text, `| approve this\u{202E}`) || !strings.Contains(text, `| \u{200B}for me`) {
		t.Errorf("the section:\n%s", text)
	}
	if strings.ContainsRune(text, '\u202e') || strings.ContainsRune(text, '\u200b') {
		t.Error("an invisible character reached the text")
	}
	if !slices.ContainsFunc(render.Compute.Flags, func(flag string) bool { return strings.Contains(flag, "send.text") }) {
		t.Errorf("flags %v", render.Compute.Flags)
	}
	// an agent's line cannot stand at the margin: every line of the section starts with the render's bar
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "for me") && !strings.HasPrefix(line, "    | ") {
			t.Errorf("an untrusted line at the margin: %q", line)
		}
	}
}

// Hosts show in punycode, IP addresses as they are; a host that does not convert shows escaped and flagged; kind 23's
// host must be its URL's in punycode, else it takes no approval.
func TestRenderHostsInPunycode(t *testing.T) {
	for host, want := range map[string]struct {
		shown     string
		converted bool
	}{
		"bücher.example":    {shown: "xn--bcher-kva.example", converted: true},
		"BÜCHER.Example":    {shown: "xn--bcher-kva.example", converted: true},
		"api.example.com":   {shown: "api.example.com", converted: true},
		"192.0.2.1":         {shown: "192.0.2.1", converted: true},
		"2001:db8::1":       {shown: "2001:db8::1", converted: true},
		"a b.example":       {shown: "a b.example", converted: false},
		"evil\u202ecom.net": {shown: `evil\u{202E}com.net`, converted: false},
	} {
		shown, converted := ApprovalUntrustedHost(host)
		if shown != want.shown || converted != want.converted {
			t.Errorf("%q shown as %q, %v", host, shown, converted)
		}
	}
	if shown, converted := ApprovalUntrustedAddress("ana@bücher.example"); shown != "ana@xn--bcher-kva.example" || !converted {
		t.Errorf("an address shown as %q, %v", shown, converted)
	}
	if host, converted := ApprovalUntrustedUrlHost("https://bücher.example:8443/a?b=1"); host != "xn--bcher-kva.example" || !converted {
		t.Errorf("a URL's host %q, %v", host, converted)
	}

	fetch := func(url string, host string) *ApprovalRender {
		action := proto.Clone(testComputeActions(t)[SidecarActionFetchUnlistedUrl]).(*protocol.CanonicalAction)
		action.Url, action.Host = url, host
		return testComputeRender(t, testComputeBuilt(t, action, nil), nil)
	}
	render := fetch("https://bücher.example/a?b=1", "xn--bcher-kva.example")
	if !render.Whole() || !strings.Contains(render.Text(), "url.host: xn--bcher-kva.example") || !strings.Contains(render.Meaning, "at host xn--bcher-kva.example") {
		t.Errorf("a Unicode URL:\n%s", render.Text())
	}
	for url, host := range map[string]string{
		"https://other.example/a":    "xn--bcher-kva.example",
		"mailto:someone@example.com": "example.com",
		"https://a\u202eb.example/c": "ab.example",
	} {
		if render := fetch(url, host); render.Whole() {
			t.Errorf("%q at %s takes an approval:\n%s", url, host, render.Text())
		}
	}
}

// Kind 19's card opens with its provider's disclosure line, and takes no approval where none renders; an indexer's
// says it reads every member's incoming mail.
func TestRenderKind19DisclosureLine(t *testing.T) {
	forms := testComputeRenderForms(t)
	create := forms["v5_19_enclave_create"]
	render := testComputeRender(t, create, testComputeDisclosures())
	if render.Compute.DisclosureId != "enclave:hippius" || !strings.HasPrefix(render.Compute.Disclosure, "Hippius's machines") || !render.Whole() {
		t.Fatalf("the render: %+v", render.Compute)
	}
	lines := strings.Split(render.Text(), "\n")
	if !strings.HasPrefix(lines[1], "  disclosure enclave:hippius: Hippius's machines") {
		t.Errorf("the disclosure line does not open the card:\n%s", render.Text())
	}
	for name, source := range map[string]ApprovalComputeDisclosureLines{
		"no registry": nil, "no line": testApprovalDisclosureLines{},
	} {
		if render := testComputeRender(t, create, source); render.Whole() || render.Compute.Disclosure != "" {
			t.Errorf("%s: whole %v", name, render.Whole())
		}
	}
	indexer := testComputeRender(t, forms["v5_19_enclave_create_indexer"], testComputeDisclosures())
	if !strings.Contains(indexer.Meaning, "It will read every member's incoming mail and the mailboxes members grant it") {
		t.Errorf("the indexer's meaning: %s", indexer.Meaning)
	}
	if strings.Contains(render.Meaning, "incoming mail") {
		t.Errorf("an agents' enclave's meaning: %s", render.Meaning)
	}
}

// A field past what the device shows whole takes no approval, on the render and on the approver's device; a denial
// still files.
func TestRenderOversizeTakesNoApproval(t *testing.T) {
	settings := DefaultApprovalComputeRenderSettings()
	long := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Send.Text = strings.Repeat("a", settings.TextMaxByteCount+1)
	})
	stored := testComputeBuilt(t, long, nil)
	render := testComputeRender(t, stored, nil)
	if render.Whole() || !render.Unshown || !slices.ContainsFunc(render.Compute.Withheld, func(text string) bool {
		return strings.Contains(text, "more than this device shows whole")
	}) {
		t.Fatalf("the render: %v", render.Compute.Withheld)
	}
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, stored, "send it")
	item := world.item(request.ApprovalId())
	if !slices.Equal(item.Decisions, []string{SidecarDecisionDeny}) {
		t.Errorf("decisions %v", item.Decisions)
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalUnshown) {
		t.Errorf("an approval: %v", err)
	}
	if world.decisionCount() != 0 {
		t.Error("an approval was filed")
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionDeny}, SidecarActConfirmed, nil); err != nil {
		t.Errorf("a denial: %v", err)
	}
	// a list past its bound alike
	many := testComputeSendAction(t, func(action *protocol.CanonicalAction) {
		action.Send.Tools = make([]string, settings.ListMaxCount+1)
		for i := range action.Send.Tools {
			action.Send.Tools[i] = "tool"
		}
	})
	if render := testComputeRender(t, testComputeBuilt(t, many, nil), nil); render.Whole() {
		t.Error("a list past its bound takes an approval")
	}
}

// A version-5 detail that did not open on the approver's device takes no approval: its render says so and lists deny
// alone, and an approval answers ErrApprovalDetailSealed; once it opens, the request takes one.
func TestRenderUnopenedDetailTakesNoApproval(t *testing.T) {
	stored := testComputeStored(t, SidecarActionEnclaveCreate)
	request := testComputeApprovalRequest(t, stored)
	render := RenderApprovalRequestCompute(&ApprovalComputeRenderArgs{Request: request, Disclosures: testComputeDisclosures()})
	if render.Whole() || !render.Sealed || render.Opened || !strings.Contains(render.Text(), "its sealed detail did not open on this device, so it takes no approval here") {
		t.Fatalf("the render:\n%s", render.Text())
	}
	if !strings.Contains(render.Meaning, "an enclave whose name did not open on this device") {
		t.Errorf("the meaning: %s", render.Meaning)
	}

	world := newTestApproverWorld(t)
	world.approver = world.approver.WithDisclosureLines(testComputeDisclosures())
	waiting := world.put(world.requesterId, stored, "make the builder")
	if item := world.item(waiting.ApprovalId()); !slices.Equal(item.Decisions, []string{SidecarDecisionDeny}) || item.Render.Opened {
		t.Errorf("the item: %v", item.Decisions)
	}
	if err := world.approver.Decide(t.Context(), waiting.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalDetailSealed) {
		t.Errorf("an approval: %v", err)
	}

	// opened with the network's key, the same request takes an approval
	world.approver = world.approver.WithDetailOpener5(testComputeDetailOpener{})
	item := world.item(waiting.ApprovalId())
	if !slices.Contains(item.Decisions, SidecarDecisionApprove) || !item.Render.Opened || !strings.Contains(item.Render.Text(), "sealed_detail.name: builder") {
		t.Fatalf("the item %v:\n%s", item.Decisions, item.Render.Text())
	}
	if err := world.approver.Decide(t.Context(), waiting.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
		t.Errorf("an approval: %v", err)
	}
	if world.decisionCount() != 1 {
		t.Errorf("%d decisions filed", world.decisionCount())
	}
}

// Field 70's basis and rules show among the fields by number, a direct egress by its name, and an amount in dollars.
func TestRenderVersion5FieldValues(t *testing.T) {
	forms := testComputeRenderForms(t)
	shown := func(name string) map[string]string {
		values := map[string]string{}
		for _, field := range testComputeRender(t, forms[name], testComputeDisclosures()).Fields {
			values[field.Name] = field.Value
		}
		return values
	}
	prompt := shown("v5_24_tainted_send_prompt")
	if prompt["auto.basis"] != "1 (taint)" || prompt["auto.rules"] != "1, 9" || prompt["send.mode"] != "1 (prompt)" ||
		prompt["egress_mode"] != "2 (exits)" || prompt["enclave.price_per_hour"] != "$0.12 (120000000 nano-USD)" {
		t.Errorf("kind 24's fields: %v", prompt)
	}
	if command := shown("v5_24_tainted_send_command"); command["egress_mode"] != "4 (direct)" || command["send.cwd"] != "/work" {
		t.Errorf("a command's fields: %v", command)
	}
	if raise := shown("v5_21_compute_budget_raise"); raise["budget.amount"] != "$10.00 (10000000000 nano-USD)" || raise["budget.period"] != "1 (day)" {
		t.Errorf("kind 21's fields: %v", raise)
	}
	if create := shown("v5_19_enclave_create"); create["sealed_detail.role"] != "1 (agents)" || create["sealed_detail.name"] != "builder" {
		t.Errorf("kind 19's detail: %v", create)
	}
	for nanoUsd, want := range map[uint64]string{0: "$0.00", 1: "$0.000000001", 120_000_000: "$0.12", 5_000_000_000: "$5.00", 1_234_500_000: "$1.2345"} {
		if shown := approvalComputeUsd(nanoUsd); shown != want {
			t.Errorf("%d nano-USD shown as %s", nanoUsd, shown)
		}
	}
}

// An approver's device takes an approval of a version-5 action it showed whole, kind 26's here, and files it; the
// render it lists is version 5's, with the body in its own section.
func TestRenderVersion5TakesApprovalOnceShownWhole(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testComputeStored(t, SidecarActionServiceWrite), "save the note")
	item := world.item(request.ApprovalId())
	if !slices.Equal(item.Decisions, []string{SidecarDecisionApprove, SidecarDecisionDeny}) || item.Render.Compute == nil {
		t.Fatalf("the item: %v", item.Decisions)
	}
	if !strings.Contains(item.Render.Text(), `    | {"text":"buy milk"}`) || !strings.Contains(item.Render.Meaning, "it changes the person's own data") {
		t.Errorf("the text:\n%s", item.Render.Text())
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if world.decisionCount() != 1 {
		t.Errorf("%d decisions filed", world.decisionCount())
	}
	// a channel this device signs on is device, never auto
	if item.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE {
		t.Errorf("channel %v", item.Channel)
	}
}
