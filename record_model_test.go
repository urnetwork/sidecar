//go:build !sidecar_http

// RECORD-M6-08: the model manifest's evidence and change rule, the weights digest against RECORD.md's vector and over
// a fixture tree, a reach receipt naming the manifest in force, the writer's refusal of attested evidence, a port that
// needs a credential never probed again, run cost's sums and its report, and the inventory's day.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// RECORD.md section 20's weights_digest vector.
func TestRecordModelWeightsDigestMatchesTheVector(t *testing.T) {
	files := []*sidecar.RecordModelWeightFile{
		{Path: "b/c.bin", Sha256: [sha256.Size]byte(bytes.Repeat([]byte{0x22}, 32))},
		{Path: "a.bin", Sha256: [sha256.Size]byte(bytes.Repeat([]byte{0x11}, 32))},
	}
	digest, err := sidecar.RecordModelWeightsDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "fe6beeb3275d648269c92a0ba1c24917f9030a8e9b5271a31045194bf14c5456" {
		t.Fatalf("digest %s", digest)
	}
	if _, err := sidecar.RecordModelWeightsDigest(nil); !errors.Is(err, sidecar.ErrRecordModelInvalid) {
		t.Fatalf("no file digested: %v", err)
	}
	if _, err := sidecar.RecordModelWeightsDigest([]*sidecar.RecordModelWeightFile{{Path: "a"}, {Path: "a"}}); !errors.Is(err, sidecar.ErrRecordModelInvalid) {
		t.Fatalf("one path twice digested: %v", err)
	}
}

// A measured digest over a fixture tree is the digest of its files' hashes by relative path, whatever order the
// arguments name them in, and a link is refused, not skipped.
func TestRecordModelMeasuresAFixtureTree(t *testing.T) {
	tree := fstest.MapFS{
		"a.bin":   {Data: []byte("first weights")},
		"b/c.bin": {Data: []byte("second weights, longer")},
	}
	digest, byteCount, files, err := sidecar.RecordModelMeasure(t.Context(), []*sidecar.RecordModelWeights{{Fs: tree, Root: "."}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := sidecar.RecordModelWeightsDigest([]*sidecar.RecordModelWeightFile{
		{Path: "a.bin", Sha256: sha256.Sum256([]byte("first weights"))},
		{Path: "b/c.bin", Sha256: sha256.Sum256([]byte("second weights, longer"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if digest != want || byteCount != uint64(len("first weights")+len("second weights, longer")) || len(files) != 2 {
		t.Fatalf("digest %s of %d bytes in %d files, want %s", digest, byteCount, len(files), want)
	}
	// one file named alone is hashed under its own name
	single, _, _, err := sidecar.RecordModelMeasure(t.Context(), []*sidecar.RecordModelWeights{{Fs: tree, Root: "a.bin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantSingle, _ := sidecar.RecordModelWeightsDigest([]*sidecar.RecordModelWeightFile{{Path: "a.bin", Sha256: sha256.Sum256([]byte("first weights"))}})
	if single != wantSingle {
		t.Fatalf("a single file's digest %s, want %s", single, wantSingle)
	}
	linked := fstest.MapFS{"a.bin": {Data: []byte("x")}, "link": {Mode: fs.ModeSymlink}}
	if _, _, _, err := sidecar.RecordModelMeasure(t.Context(), []*sidecar.RecordModelWeights{{Fs: linked, Root: "."}}, nil); !errors.Is(err, sidecar.ErrRecordModelInvalid) {
		t.Fatalf("a link was measured: %v", err)
	}
}

// The model entries a device's stream holds, in order.
func testRecordManifests(t *testing.T, world *testRecordWorld, writerId sidecar.Id) []*protocol.ModelManifest {
	t.Helper()
	manifests := []*protocol.ModelManifest{}
	for _, stored := range world.storedEntries(writerId) {
		if sidecar.RecordKind(stored.header.GetKind()) != sidecar.RecordKindModel {
			continue
		}
		manifest := &protocol.ModelManifest{}
		if err := proto.Unmarshal(stored.body, manifest); err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, manifest)
	}
	return manifests
}

// A declaration writes a manifest whose fields say how each is known; the same declaration again writes nothing; a
// weight file that changed writes a new entry, and a reach receipt written after names that one.
func TestRecordModelManifestChangeWritesANewEntryLaterReceiptsName(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	models := record.Models()
	tree := fstest.MapFS{"model.gguf": {Data: []byte("weights one"), ModTime: world.clock.Now()}}
	models.SetWeightsOpener(func(path string) (*sidecar.RecordModelWeights, error) {
		return &sidecar.RecordModelWeights{Fs: tree, Root: "."}, nil
	})
	args := &sidecar.RecordModelDeclareArgs{
		Port:        8000,
		Fields:      sidecar.RecordModelFields{ServedName: "local-coder", Engine: "llama.cpp", Quantization: "q4_k_m"},
		WeightPaths: []string{"/weights"},
		Confirmed:   true,
	}
	unconfirmed := *args
	unconfirmed.Confirmed = false
	if _, err := models.Declare(t.Context(), &unconfirmed); !errors.Is(err, sidecar.ErrRecordModelInvalid) {
		t.Fatalf("an unconfirmed declaration: %v", err)
	}
	harness := *args
	harness.HarnessAncestor = true
	if _, err := models.Declare(t.Context(), &harness); !errors.Is(err, sidecar.ErrRecordModelHarness) {
		t.Fatalf("a declaration under a harness: %v", err)
	}
	first, err := models.Declare(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Written || first.Ref == nil {
		t.Fatalf("the first declaration wrote %t, ref %v", first.Written, first.Ref)
	}
	manifest := first.Manifest
	if manifest.GetServedName().GetEvidence() != sidecar.RecordModelEvidenceDeclared || manifest.GetEngine().GetValue() != "llama.cpp" ||
		manifest.GetEngineVersion() != nil || manifest.GetWeightsDigest().GetEvidence() != sidecar.RecordModelEvidenceMeasured ||
		manifest.GetWeightsBytes() != uint64(len("weights one")) {
		t.Fatalf("manifest %v", manifest)
	}
	again, err := models.Declare(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	if again.Written || again.Ref.EntryId != first.Ref.EntryId {
		t.Fatal("the same declaration wrote a second entry")
	}
	// unchanged files are not hashed again, and write nothing
	if same, err := models.Remeasure(t.Context(), 8000); err != nil || same.Written {
		t.Fatalf("unchanged weights rewrote the manifest: %v", err)
	}
	tree["model.gguf"] = &fstest.MapFile{Data: []byte("weights two!"), ModTime: world.clock.Now().Add(time.Minute)}
	changed, err := models.Remeasure(t.Context(), 8000)
	if err != nil {
		t.Fatal(err)
	}
	if !changed.Written || changed.Ref.EntryId == first.Ref.EntryId ||
		changed.Manifest.GetWeightsDigest().GetValue() == manifest.GetWeightsDigest().GetValue() {
		t.Fatal("changed weights wrote no new manifest")
	}
	inForce := models.InForce(8000)
	if inForce == nil || inForce.EntryId != changed.Ref.EntryId || inForce.LogId != world.vaultId {
		t.Fatalf("in force %v, want entry %s", inForce, changed.Ref.EntryId)
	}
	if models.InForce(8001) != nil {
		t.Fatal("a port never declared has a manifest in force")
	}

	// the host's receipt for a forward to the port names the manifest in force in its header content
	grantId := bytes.Repeat([]byte{0x47}, 32)
	if err := record.Reach().Note(&sidecar.RecordReachNote{
		Kind:        sidecar.RecordReachKindForward,
		GrantId:     grantId,
		Peers:       [][]byte{sidecar.NewId().Bytes()},
		StreamCount: 1,
		ByteCount:   512,
		Manifest:    inForce,
	}); err != nil {
		t.Fatal(err)
	}
	record.Reach().Flush()
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if manifests := testRecordManifests(t, world, device.sidecarId); len(manifests) != 2 {
		t.Fatalf("%d model entries, want 2", len(manifests))
	}
	named := false
	for _, stored := range world.storedEntries(device.sidecarId) {
		if sidecar.RecordKind(stored.header.GetKind()) != sidecar.RecordKindReach {
			continue
		}
		for _, content := range stored.header.GetContent() {
			if bytes.Equal(content.GetObjectId(), changed.Ref.EntryId.Bytes()) && bytes.Equal(content.GetRepoId(), world.vaultId.Bytes()) &&
				bytes.Equal(content.GetCommitment(), changed.Ref.Commitment) {
				named = true
			}
		}
	}
	if !named {
		t.Fatal("no reach receipt names the manifest in force")
	}

	// a restart keeps the port's state: the same declaration writes nothing
	reopened := device.open()
	reopened.Models().SetWeightsOpener(func(path string) (*sidecar.RecordModelWeights, error) {
		return &sidecar.RecordModelWeights{Fs: tree, Root: "."}, nil
	})
	shown, held, err := reopened.Models().Show(8000)
	if err != nil || !held || shown.Ref.EntryId != changed.Ref.EntryId {
		t.Fatalf("after a restart: %v, held %t", err, held)
	}
}

// Attested evidence is reserved: the writer refuses a manifest that claims it, and one whose evidence is unknown.
func TestRecordWriterRefusesAttestedModelEvidence(t *testing.T) {
	world := newTestRecordWorld(t)
	record := world.device(true).open()
	draft := func(evidence uint32) *sidecar.RecordDraft {
		return &sidecar.RecordDraft{
			Kind:      sidecar.RecordKindModel,
			Source:    sidecar.RecordSourceObserved,
			NoSession: true,
			Body:      &protocol.ModelManifest{Port: 8000, Engine: &protocol.ModelField{Value: "vllm", Evidence: evidence}},
		}
	}
	if _, err := record.Writer().Append(draft(sidecar.RecordModelEvidenceAttested)); err == nil {
		t.Fatal("the writer took attested evidence")
	}
	if _, err := record.Writer().Append(draft(0)); err == nil {
		t.Fatal("the writer took a field with no evidence")
	}
	if _, err := record.Writer().Append(draft(sidecar.RecordModelEvidenceReported)); err != nil {
		t.Fatal(err)
	}
}

// What a test's engine listing answers, and how often it was asked.
type testRecordModelListing struct {
	fields *sidecar.RecordModelFields
	err    error
	count  int
}

func (self *testRecordModelListing) List(ctx context.Context, port uint32) (*sidecar.RecordModelFields, error) {
	self.count += 1
	return self.fields, self.err
}

// An engine's listing is reported evidence, read at most once a window; a port that asks for a credential is never
// probed again, its reported fields empty, until a person declares it anew (I-7).
func TestRecordModelProbeReportsAndLeavesACredentialedPortAlone(t *testing.T) {
	world := newTestRecordWorld(t)
	record := world.device(true).open()
	models := record.Models()
	listing := &testRecordModelListing{fields: &sidecar.RecordModelFields{ServedName: "served", EngineVersion: "0.9.1"}}
	models.SetListing(listing)
	args := &sidecar.RecordModelDeclareArgs{Port: 11434, Fields: sidecar.RecordModelFields{ServedName: "typed", Engine: "ollama"}, Confirmed: true}
	if _, err := models.Declare(t.Context(), args); err != nil {
		t.Fatal(err)
	}
	probed, err := models.Probe(t.Context(), 11434)
	if err != nil {
		t.Fatal(err)
	}
	if !probed.Written || probed.Manifest.GetServedName().GetValue() != "served" || probed.Manifest.GetServedName().GetEvidence() != sidecar.RecordModelEvidenceReported ||
		probed.Manifest.GetEngine().GetEvidence() != sidecar.RecordModelEvidenceDeclared || probed.Manifest.GetEngineVersion().GetValue() != "0.9.1" {
		t.Fatalf("probed manifest %v", probed.Manifest)
	}
	if _, err := models.Probe(t.Context(), 11434); err != nil || listing.count != 1 {
		t.Fatalf("a second probe inside the window asked the engine: %d, %v", listing.count, err)
	}
	world.clock.Advance(sidecar.DefaultRecordModelSettings().ListingInterval)
	listing.fields, listing.err = nil, sidecar.ErrRecordModelCredential
	marked, err := models.Probe(t.Context(), 11434)
	if err != nil {
		t.Fatal(err)
	}
	if !marked.Credential || listing.count != 2 || marked.Manifest.GetServedName().GetEvidence() != sidecar.RecordModelEvidenceDeclared ||
		marked.Manifest.GetEngineVersion() != nil {
		t.Fatalf("a credentialed port: %v after %d listings", marked.Manifest, listing.count)
	}
	world.clock.Advance(2 * sidecar.DefaultRecordModelSettings().ListingInterval)
	if _, err := models.Probe(t.Context(), 11434); err != nil || listing.count != 2 {
		t.Fatalf("a credentialed port was probed again: %d, %v", listing.count, err)
	}
}

// Run cost sums a run's model calls by model, tokens and the amounts a harness reported alone, and a coverage gap
// that may hide calls marks every model incomplete.
func TestRecordRunCostSumsCallsAndAGapMarksItIncomplete(t *testing.T) {
	cost := &sidecar.RecordRunCost{}
	if _, ok := cost.Body(nil); ok {
		t.Fatal("a run with no model call has a cost body")
	}
	cost.AddCall(&protocol.ModelCallBody{Model: "sonnet", InputTokens: 100, OutputTokens: 20, CacheReadTokens: 5, ReportedMicroUsd: 1500}, nil)
	cost.AddCall(&protocol.ModelCallBody{Model: "local-coder", InputTokens: 7, OutputTokens: 3}, nil)
	cost.AddCall(&protocol.ModelCallBody{Model: "sonnet", InputTokens: 50, OutputTokens: 10, CacheWriteTokens: 9, ReportedMicroUsd: 700}, nil)
	cost.AddMeteredBytes(4096)
	body, ok := cost.Body(nil)
	if !ok || len(body.GetUsage()) != 2 || body.GetMeteredBytes() != 4096 {
		t.Fatalf("body %v", body)
	}
	local, sonnet := body.GetUsage()[0], body.GetUsage()[1]
	if local.GetModel() != "local-coder" || local.GetCalls() != 1 || local.GetReportedMicroUsd() != 0 || !local.GetComplete() {
		t.Fatalf("a self-hosted model's usage %v: no amount is computed", local)
	}
	if sonnet.GetCalls() != 2 || sonnet.GetInputTokens() != 150 || sonnet.GetOutputTokens() != 30 || sonnet.GetCacheReadTokens() != 5 ||
		sonnet.GetCacheWriteTokens() != 9 || sonnet.GetReportedMicroUsd() != 2200 || !sonnet.GetComplete() {
		t.Fatalf("usage %v", sonnet)
	}
	if err := sidecar.RecordBodyValidate(sidecar.RecordKindCost, body); err != nil {
		t.Fatal(err)
	}
	gapped, _ := cost.Body([]string{sidecar.RecordCoverageGapTruncation, sidecar.RecordCoverageGapMissedEvent + ":3"})
	for _, usage := range gapped.GetUsage() {
		if usage.GetComplete() {
			t.Fatalf("%s is complete under a missed event", usage.GetModel())
		}
	}
	if cut, _ := cost.Body([]string{sidecar.RecordCoverageGapTruncation}); !cut.GetUsage()[0].GetComplete() {
		t.Fatal("a truncated field marked the run's calls incomplete")
	}
	// the body holds its cap: models past it fold into the unnamed entry, and no call is left out
	many := &sidecar.RecordRunCost{}
	for i := range 40 {
		many.AddCall(&protocol.ModelCallBody{Model: "model-" + string(rune('a'+i)), InputTokens: 1}, nil)
	}
	capped, _ := many.Body(nil)
	calls := uint64(0)
	for _, usage := range capped.GetUsage() {
		calls += usage.GetCalls()
	}
	if len(capped.GetUsage()) != 16 || calls != 40 || capped.GetUsage()[15].GetModel() != "" {
		t.Fatalf("%d usages of %d calls", len(capped.GetUsage()), calls)
	}
}

// One cost entry of a run for a report.
func testRecordCostEntry(run byte, writer byte, seq uint64, millis int64, member byte, project string, usages ...*protocol.ModelUsage) *sidecar.RecordCostEntry {
	memberId := sidecar.Id(bytes.Repeat([]byte{member}, 16))
	return &sidecar.RecordCostEntry{
		RunId:           sidecar.Id(bytes.Repeat([]byte{run}, 16)),
		WriterSidecarId: sidecar.Id(bytes.Repeat([]byte{writer}, 16)),
		Seq:             seq,
		TimeMillis:      millis,
		MemberId:        &memberId,
		Project:         project,
		Body:            &protocol.RunCostBody{Usage: usages},
	}
}

// The report sums per run only the newest cost entry of its writer's chain, groups by project, client, model or
// month, never by member, orders by group and not by amount, and on a team log folds a group fewer than five members
// wrote into other.
func TestRecordCostReportSumsTheNewestEntryOfEachRunAndRanksNoOne(t *testing.T) {
	november := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC).UnixMilli()
	december := time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC).UnixMilli()
	usage := func(model string, input uint64, micro uint64, complete bool) *protocol.ModelUsage {
		return &protocol.ModelUsage{Model: model, InputTokens: input, Calls: 1, ReportedMicroUsd: micro, Complete: complete}
	}
	entries := []*sidecar.RecordCostEntry{
		// run 1 re-opened: seq 9 supersedes seq 4
		testRecordCostEntry(1, 0xa1, 4, november, 0x01, "zeta", usage("sonnet", 10, 100, true)),
		testRecordCostEntry(1, 0xa1, 9, november, 0x01, "zeta", usage("sonnet", 30, 300, true), usage("local", 5, 0, true)),
		testRecordCostEntry(2, 0xa2, 2, november, 0x02, "alpha", usage("sonnet", 1000, 9000, false)),
		testRecordCostEntry(3, 0xa3, 1, december, 0x03, "alpha", usage("local", 7, 0, true)),
		testRecordCostEntry(4, 0xa4, 1, december, 0x04, "", usage("sonnet", 2, 20, true)),
	}
	rows, err := sidecar.RecordCostReport(entries, &sidecar.RecordCostQuery{By: sidecar.RecordCostByProject}, nil)
	if err != nil {
		t.Fatal(err)
	}
	groups := []string{}
	for _, row := range rows {
		groups = append(groups, row.Group)
	}
	// by name: the costliest group is not first
	if !slices.Equal(groups, []string{sidecar.RecordCostGroupNoProject, "alpha", "zeta"}) {
		t.Fatalf("groups %v", groups)
	}
	alpha, zeta := rows[1], rows[2]
	if zeta.InputTokens != 35 || zeta.ReportedMicroUsd != 300 || zeta.Runs != 1 || zeta.Calls != 2 || !zeta.Complete {
		t.Fatalf("zeta %+v: the older entry of its run counted", zeta)
	}
	if alpha.InputTokens != 1007 || alpha.Runs != 2 || alpha.Complete {
		t.Fatalf("alpha %+v", alpha)
	}
	// the project runs to the last comma
	clients, err := sidecar.ParseRecordCostMap([]byte("# project,client\nalpha,Acme, Inc\nzeta , Acme, Inc\n\n"), nil)
	if err != nil || len(clients) != 2 || clients["alpha,Acme"] != "Inc" || clients["zeta , Acme"] != "Inc" {
		t.Fatalf("map %v, %v", clients, err)
	}
	clients, err = sidecar.ParseRecordCostMap([]byte("alpha,acme\nzeta,acme\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	byClient, err := sidecar.RecordCostReport(entries, &sidecar.RecordCostQuery{By: sidecar.RecordCostByProject, Clients: clients}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(byClient) != 2 || byClient[1].Group != "acme" || byClient[1].InputTokens != 1042 || byClient[1].Runs != 3 {
		t.Fatalf("by client %+v", byClient)
	}
	byMonth, err := sidecar.RecordCostReport(entries, &sidecar.RecordCostQuery{By: sidecar.RecordCostByMonth}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(byMonth) != 2 || byMonth[0].Group != "2026-11" || byMonth[0].InputTokens != 1035 || byMonth[1].Group != "2026-12" || byMonth[1].InputTokens != 9 {
		t.Fatalf("by month %+v", byMonth)
	}
	byModel, err := sidecar.RecordCostReport(entries, &sidecar.RecordCostQuery{By: sidecar.RecordCostByModel, SinceMillis: december}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(byModel) != 2 || byModel[0].Group != "local" || byModel[0].InputTokens != 7 || byModel[1].Group != "sonnet" || byModel[1].InputTokens != 2 {
		t.Fatalf("by model since december %+v", byModel)
	}
	if _, err := sidecar.ParseRecordCostBy("member"); !errors.Is(err, sidecar.ErrRecordCostInvalid) {
		t.Fatalf("--by member: %v", err)
	}
	if _, err := sidecar.RecordCostReport(entries, &sidecar.RecordCostQuery{By: "member"}, nil); !errors.Is(err, sidecar.ErrRecordCostInvalid) {
		t.Fatalf("a report by member: %v", err)
	}
	// a team log: no group here has five members, so each shows as other
	team, err := sidecar.RecordCostReport(entries, &sidecar.RecordCostQuery{By: sidecar.RecordCostByProject, Team: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(team) != 1 || team[0].Group != sidecar.RecordCostGroupOther || team[0].InputTokens != 1044 || team[0].Runs != 4 {
		t.Fatalf("a team log's small groups %+v", team)
	}
	// five members' runs in one project show under its name
	wide := []*sidecar.RecordCostEntry{}
	for member := byte(1); member <= 5; member += 1 {
		wide = append(wide, testRecordCostEntry(0x10+member, 0xb0+member, 1, november, member, "wide", usage("sonnet", 1, 1, true)))
	}
	wide = append(wide, testRecordCostEntry(0x20, 0xc0, 1, november, 1, "narrow", usage("sonnet", 1, 1, true)))
	shown, err := sidecar.RecordCostReport(wide, &sidecar.RecordCostQuery{By: sidecar.RecordCostByProject, Team: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(shown) != 2 || shown[0].Group != "wide" || shown[0].Runs != 5 || shown[1].Group != sidecar.RecordCostGroupOther {
		t.Fatalf("a team log's groups %+v", shown)
	}
	csv, err := sidecar.FormatRecordCost(shown, sidecar.RecordCostFormatCsv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(csv), "group,runs,calls,") || !strings.Contains(string(csv), "\nwide,5,5,5,") {
		t.Fatalf("csv %q", csv)
	}
	if text, err := sidecar.FormatRecordCost(shown, sidecar.RecordCostFormatText); err != nil || !strings.Contains(string(text), "wide") {
		t.Fatalf("text %q, %v", text, err)
	}
	if lines, err := sidecar.FormatRecordCost(shown, sidecar.RecordCostFormatJsonl); err != nil || strings.Count(string(lines), "\n") != 2 {
		t.Fatalf("jsonl %q, %v", lines, err)
	}
}

// The inventory entries a device's stream holds, in order.
func testRecordInventories(t *testing.T, world *testRecordWorld, writerId sidecar.Id) []*protocol.InventoryBody {
	t.Helper()
	bodies := []*protocol.InventoryBody{}
	for _, stored := range world.storedEntries(writerId) {
		if sidecar.RecordKind(stored.header.GetKind()) != sidecar.RecordKindInventory {
			continue
		}
		body := &protocol.InventoryBody{}
		if err := proto.Unmarshal(stored.body, body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// One inventory a UTC day the sidecar ran anything: the day's runs are written once the day has passed, a day with no
// run writes nothing, and a restart keeps the day.
func TestRecordInventoryRollsADayOnTheClock(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	inventory := record.Inventory()
	credential := bytes.Repeat([]byte{0x64}, 16)
	inventory.SetCredentialRef(func() []byte { return credential })
	day := uint32(world.clock.Now().Unix() / 86400)
	agentId := sidecar.NewId()
	repoId := sidecar.NewId()
	runs := []*sidecar.RecordInventoryRun{
		{RunId: sidecar.NewId(), AgentId: &agentId, AgentLabel: "limiter-fix", AgentSource: sidecar.RecordAgentSourceAsserted, Harness: "claude-code/2.1", Model: "sonnet", Project: "github.com/example/limiter"},
		{RunId: sidecar.NewId(), AgentId: &agentId, AgentLabel: "limiter-fix", AgentSource: sidecar.RecordAgentSourceAsserted, Harness: "codex/0.50", Model: "sonnet", RepoId: &repoId, Project: "a private repo's label"},
		{RunId: sidecar.NewId(), AgentLabel: "by-hand", Harness: "claude-code/2.1", Model: "local-coder"},
	}
	for _, run := range runs {
		if err := inventory.NoteRun(run); err != nil {
			t.Fatal(err)
		}
		world.clock.Advance(time.Minute)
	}
	// the same run noted again counts once
	if err := inventory.NoteRun(runs[0]); err != nil {
		t.Fatal(err)
	}
	if err := inventory.Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if bodies := testRecordInventories(t, world, device.sidecarId); len(bodies) != 0 {
		t.Fatalf("%d inventories before the day ended", len(bodies))
	}

	// the process ends, and the next one finds the day in its file
	world.clock.Advance(24 * time.Hour)
	record = device.open()
	record.Inventory().SetCredentialRef(func() []byte { return credential })
	if err := record.Inventory().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := record.Inventory().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	// two days with no run
	world.clock.Advance(48 * time.Hour)
	if err := record.Inventory().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	bodies := testRecordInventories(t, world, device.sidecarId)
	if len(bodies) != 1 {
		t.Fatalf("%d inventories for one day with runs", len(bodies))
	}
	body := bodies[0]
	if body.GetDay() != day || !bytes.Equal(body.GetSponsorMemberId(), world.memberId.Bytes()) || !bytes.Equal(body.GetCredentialRef(), credential) || len(body.GetAgents()) != 2 {
		t.Fatalf("inventory %v", body)
	}
	agent, byHand := body.GetAgents()[0], body.GetAgents()[1]
	if !bytes.Equal(agent.GetAgentId(), agentId.Bytes()) || agent.GetRuns() != 2 || !slices.Equal(agent.GetHarnesses(), []string{"claude-code/2.1", "codex/0.50"}) ||
		!slices.Equal(agent.GetModels(), []string{"sonnet"}) || !slices.Equal(agent.GetProjects(), []string{"github.com/example/limiter"}) ||
		len(agent.GetRepoIds()) != 1 || !bytes.Equal(agent.GetRepoIds()[0], repoId.Bytes()) || agent.GetLastSeenMillis() <= agent.GetFirstSeenMillis() {
		t.Fatalf("agent %v", agent)
	}
	if len(byHand.GetAgentId()) != 0 || byHand.GetAgentLabel() != "by-hand" || byHand.GetRuns() != 1 {
		t.Fatalf("an agent with no id %v", byHand)
	}
	if err := sidecar.RecordBodyValidate(sidecar.RecordKindInventory, body); err != nil {
		t.Fatal(err)
	}

	// a run on the later day starts that day's file, written when it too has passed
	if err := record.Inventory().NoteRun(runs[2]); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(24 * time.Hour)
	if err := record.Inventory().Tend(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	bodies = testRecordInventories(t, world, device.sidecarId)
	if len(bodies) != 2 || bodies[1].GetDay() != day+3 || len(bodies[1].GetAgents()) != 1 {
		t.Fatalf("%d inventories after a second day with a run", len(bodies))
	}
}
