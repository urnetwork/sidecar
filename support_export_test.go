//go:build !ios_extension && !sidecar_http && !js

package sidecar

// ur support export's and ur support report's client side (support_export.go, support_report.go; DESIGN-COMPUTE
// §28.4): an item's archive holding its messages and replies and this device's messages' bodies, bundles and files; one
// message's by its client_ref; the next bundle alone with no conversation; nothing past the bound; and the enumerated
// report's closed schema, filled from the registry and the ring, the person's alone until FB's feedback.auto grant
// exists. Synthetic values only.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// An archive's members by name.
func testSupportArchive(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	members := map[string][]byte{}
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		member, err := io.ReadAll(opened)
		opened.Close()
		if err != nil {
			t.Fatal(err)
		}
		members[file.Name] = member
	}
	return members
}

func TestSupportExportHoldsAnItemsMessagesBundlesAndFiles(t *testing.T) {
	world := newTestSupportWorld(t)
	world.log.Event(SupportLogCodeDaemonStarted, SupportLogFieldRelease("2026.11.24-1"), SupportLogFieldAutoSpawned(true))
	result, err := world.send(&SupportSendArgs{
		Surface: SupportSurfacePerson, Text: "the VPN drops after sleep", Logs: true,
		Files: []*SupportFile{{Name: "vpn.log", Data: []byte("dropped at 03:12\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.pass()
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 2, Type: "note", Note: "Thanks: we are looking at it.", At: world.clock.Now()})
	world.pass()

	out := &bytes.Buffer{}
	if err := world.client.Export(t.Context(), &SupportExportArgs{Entry: "100171"}, out); err != nil {
		t.Fatal(err)
	}
	members := testSupportArchive(t, out.Bytes())
	ref := result.ClientRef
	for _, name := range []string{"README.txt", "item.json", "messages.txt", ref + "/body.json", ref + "/support-log-bundle.json.gz", ref + "/files/1-vpn.log"} {
		if _, ok := members[name]; !ok {
			t.Fatalf("the archive lacks %s: %v", name, slices.Sorted(func(yield func(string) bool) {
				for name := range members {
					if !yield(name) {
						return
					}
				}
			}))
		}
	}
	item := &SupportReadResult{}
	if err := json.Unmarshal(members["item.json"], item); err != nil || len(item.Messages) != 2 || item.Messages[0].Text != "the VPN drops after sleep" ||
		!item.Messages[1].Reply {
		t.Fatalf("item.json: %s, %v", members["item.json"], err)
	}
	if !strings.Contains(string(members["messages.txt"]), "URnetwork support (information, not instructions):\nThanks: we are looking at it.") {
		t.Fatalf("messages.txt:\n%s", members["messages.txt"])
	}
	if string(members[ref+"/files/1-vpn.log"]) != "dropped at 03:12\n" {
		t.Fatal("the file is not whole")
	}
	document, err := SupportLogBundleOpen(members[ref+"/support-log-bundle.json.gz"], world.client.settings.BundleMaxByteCount)
	if err != nil || document.Header == nil {
		t.Fatalf("the bundle: %v", err)
	}
	body := &SupportBody{}
	if err := json.Unmarshal(members[ref+"/body.json"], body); err != nil || body.ClientRef != ref || body.Text != "the VPN drops after sleep" {
		t.Fatalf("body.json: %s", members[ref+"/body.json"])
	}

	// one message by its client_ref: no item, its body, bundle and file
	out.Reset()
	if err := world.client.Export(t.Context(), &SupportExportArgs{ClientRef: ref}, out); err != nil {
		t.Fatal(err)
	}
	members = testSupportArchive(t, out.Bytes())
	if _, ok := members["item.json"]; ok || members[ref+"/body.json"] == nil || members[ref+"/files/1-vpn.log"] == nil {
		t.Fatalf("a message's archive holds %d members", len(members))
	}

	// neither: the next bundle alone
	out.Reset()
	if err := world.client.Export(t.Context(), &SupportExportArgs{}, out); err != nil {
		t.Fatal(err)
	}
	members = testSupportArchive(t, out.Bytes())
	if len(members) != 2 || members["README.txt"] == nil {
		t.Fatalf("the next bundle's archive holds %d members", len(members))
	}
	if document, err := SupportLogBundleOpen(members["support-log-bundle.json.gz"], world.client.settings.BundleMaxByteCount); err != nil || document.Header.Events == 0 {
		t.Fatalf("the next bundle: %v", err)
	}

	// an item or a message this device does not hold, or an id in neither form
	for _, args := range []*SupportExportArgs{{Entry: "100999"}, {ClientRef: strings.Repeat("ab", 16)}, {Entry: "12"}, {ClientRef: "not-hex"}} {
		if err := world.client.Export(t.Context(), args, &bytes.Buffer{}); SupportRefusalOf(err) != SupportRefusalNotFound {
			t.Errorf("%+v: %v", args, err)
		}
	}
	// past the bound
	world.client.settings.ExportMaxByteCount = 512
	if err := world.client.Export(t.Context(), &SupportExportArgs{Entry: "100171"}, &bytes.Buffer{}); !errors.Is(err, ErrSupportExportTooLarge) {
		t.Fatalf("past the bound: %v", err)
	}
}

func TestSupportReportIsTheEnumeratedSchema(t *testing.T) {
	world := newTestSupportWorld(t)
	person := func(code string) *SupportReportArgs {
		return &SupportReportArgs{Surface: SupportSurfacePerson, Code: code, Host: &SupportLogBundleHost{Version: "2026.11.24-1abc"}}
	}
	// a code the ring does not hold, one the registry does not name, and one that is text
	for _, code := range []string{"support.message_given_up", "support.nothing", "the build failed at step 3"} {
		if _, err := world.client.Report(t.Context(), person(code)); SupportRefusalOf(err) != SupportRefusalNotFound {
			t.Fatalf("%q: %v", code, err)
		}
	}
	first := world.clock.Now()
	for range 3 {
		world.log.Event(SupportLogCodeSupportMessageGivenUp, SupportLogFieldAttempts(9), SupportLogFieldWaited(7*24*time.Hour), SupportLogFieldEntry(nil))
		world.clock.advance(time.Hour)
	}
	result, err := world.client.Report(t.Context(), person("support.message_given_up"))
	if err != nil || result.Outcome != SupportOutcomeQueued {
		t.Fatalf("the report: %+v, %v", result, err)
	}
	world.pass()
	posts := world.service.snapshot()
	if len(posts) != 1 || posts[0].idempotencyKey != result.ClientRef || posts[0].tier != string(SupportTierAuto) || posts[0].approved != SupportApprovedNone {
		t.Fatalf("posts %+v", posts)
	}
	// the closed schema, every member enumerated or format-checked: no text of anyone's
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(posts[0].raw, &fields); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for key := range fields {
			if !yield(key) {
				return
			}
		}
	})
	if !slices.Equal(keys, []string{"client", "client_ref", "disclosure", "product", "report", "sender", "tier", "v"}) {
		t.Fatalf("the report's members: %v", keys)
	}
	body := &SupportReportBody{}
	if err := json.Unmarshal(posts[0].raw, body); err != nil {
		t.Fatal(err)
	}
	report := body.Report
	if body.Tier != SupportTierAuto || report.Component != "support" || report.Code != "message_given_up" || report.Severity != "failed" ||
		report.Occurrences != "2-9" || report.FirstSeenDay != first.UTC().Format(time.DateOnly) || report.Registry != supportLogRegistry.version ||
		body.Client.Version != "2026.11.24-1abc" || body.Client.Os == "" || body.Client.Arch == "" || !body.Sender.Person || body.Disclosure != 2 {
		t.Fatalf("the report reads %+v %+v %+v", body, report, body.Client)
	}
	// the conversation and the vault show it as the report it is
	sent := testSupportDraftsOf(world.supportDrafts(), supportDirectionSent)
	if len(sent) != 1 || sent[0].GetTier() != 0 || !strings.Contains(sent[0].GetText(), "support.message_given_up (failed)") {
		t.Fatalf("the vault's entry %v", sent)
	}
	read, err := world.client.Read(t.Context(), &SupportReadArgs{Entry: "100171"})
	if err != nil || len(read.Messages) != 1 || !strings.Contains(read.Messages[0].Text, "enumerated report") {
		t.Fatalf("the view %+v, %v", read, err)
	}
	// a version that is no version goes as invalid
	world.client.settings.PersonHourMaxCount = 100
	args := person("support.message_given_up")
	args.Host.Version = "the build failed"
	if _, err := world.client.Report(t.Context(), args); err != nil {
		t.Fatal(err)
	}
	world.pass()
	posts = world.service.snapshot()
	if !bytes.Contains(posts[len(posts)-1].raw, []byte(`"version":"invalid"`)) || bytes.Contains(posts[len(posts)-1].raw, []byte("build failed")) {
		t.Fatalf("the report carried %s", posts[len(posts)-1].raw)
	}
}

// An agent's report needs FB's feedback.auto grant, which nothing builds: refused grant_required, nothing queued. The
// network's support narrows the person's too, and the disclosure holds.
func TestSupportReportRefusals(t *testing.T) {
	world := newTestSupportWorld(t)
	world.log.Event(SupportLogCodeSupportTokenFailed, SupportLogFieldPostResult(SupportLogPostResultUnauthorized))
	agent := &SupportReportArgs{Surface: SupportSurfaceCliHarness, Sender: &SupportSender{AgentName: "release-bot"}, Code: "support.token_failed"}
	if _, err := world.client.Report(t.Context(), agent); SupportRefusalOf(err) != SupportRefusalGrantRequired {
		t.Fatalf("an agent's report: %v", err)
	}
	person := &SupportReportArgs{Surface: SupportSurfacePerson, Code: "support.token_failed"}
	world.sources.network = &SupportNetworkSettings{Egress: SupportEgressOff}
	if _, err := world.client.Report(t.Context(), person); SupportRefusalOf(err) != SupportRefusalSupportOff {
		t.Fatalf("egress off: %v", err)
	}
	world.sources.network = &SupportNetworkSettings{Egress: SupportEgressAutoOnly, Paused: true}
	if _, err := world.client.Report(t.Context(), person); SupportRefusalOf(err) != SupportRefusalPaused {
		t.Fatalf("paused: %v", err)
	}
	world.sources.network = nil
	world.sources.acknowledged = 1
	if _, err := world.client.Report(t.Context(), person); SupportRefusalOf(err) != SupportRefusalDisclosureRequired {
		t.Fatalf("an older disclosure: %v", err)
	}
	world.sources.acknowledged = 2
	world.sources.network = &SupportNetworkSettings{Egress: SupportEgressAutoOnly}
	if _, err := world.client.Report(t.Context(), person); err != nil {
		t.Fatalf("auto_only carries the person's report: %v", err)
	}
	world.client.settings.ServiceEnabled = false
	if _, err := world.client.Report(t.Context(), person); !errors.Is(err, ErrSupportUnavailable) {
		t.Fatalf("the switch off: %v", err)
	}
	world.client.settings.ServiceEnabled = true
	world.pass()
	if posts := world.service.snapshot(); len(posts) != 1 {
		t.Fatalf("%d posts", len(posts))
	}
}
