//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// QD-851's evs half on a git-mode ref (QD-042 at M3; §16.5's evs_write row, owner decision 81): WriteAtTip's push seals
// the writing run's tainted bit and its agent through the mount's real receive path, where a git client's push through
// the same path seals neither; §16.6's effect carries both to a git-mode ref; a head-mode reader reads the bit back
// from the version; and an import's versions keep EvsImport's label whoever reads them.

package sidecar

import (
	"context"
	"io"
	"testing"
)

// A git-mode write in a tainted run seals the bit and the agent in its push's provenance, which a head-mode reader of
// the path reads back; a clean write's and a published commit's carry neither.
func TestEvsWriteAtTipSealsItsRunsTaintAndAgent(t *testing.T) {
	writer := newEvsTestTipWriter(t)
	writer.land(map[string]string{"a.txt": "zero\n"})
	server := writer.publisher.writer.server
	server.know("CLAUDE.md", "AGENTS.md", "NOTES.md")
	agentId := evsTestId("tip agent")
	ctx := context.Background()
	tainted, err := writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{
		Path: "CLAUDE.md", Content: []byte("# rules\n"), AgentLabel: "agent one", Tainted: true, AgentId: &agentId,
	})
	if err != nil {
		t.Fatal(err)
	}
	clean, err := writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{Path: "AGENTS.md", Content: []byte("# agents\n"), AgentLabel: "agent one"})
	if err != nil {
		t.Fatal(err)
	}
	effect := &EvsWriteEffect{
		Repo: writer.repo, Path: "NOTES.md", Content: []byte("notes\n"), AgentLabel: "agent one", Tainted: true, AgentId: &agentId,
	}
	effectRef, err := effect.Run(ctx, []byte("effect key"))
	if err != nil {
		t.Fatal(err)
	}
	_, effectVersion, err := ParseEvsEffectRef(effectRef)
	if err != nil {
		t.Fatal(err)
	}
	// main: 1 the landed commit, a git client's push in all but name; then the three writes
	landed := writer.publisher.metadata("main", 1).GetProvenance()
	if landed.GetTainted() || len(landed.GetAgentId()) != 0 {
		t.Fatalf("a published commit's provenance: %v", landed)
	}
	sealed := writer.publisher.metadata("main", tainted.Version).GetProvenance()
	if !sealed.GetTainted() || string(sealed.GetAgentId()) != string(agentId.Bytes()) {
		t.Fatalf("the tainted write's provenance: %v", sealed)
	}
	if sealed := writer.publisher.metadata("main", clean.Version).GetProvenance(); sealed.GetTainted() || len(sealed.GetAgentId()) != 0 {
		t.Fatalf("the clean write's provenance: %v", sealed)
	}

	reader := writer.publisher.writer.provenanceReader(t, "tip reader")
	repo := reader.client.Repo(writer.publisher.writer.world.repoId)
	wants := map[string]struct {
		version uint64
		tainted bool
	}{
		"CLAUDE.md": {version: tainted.PathVersion, tainted: true},
		"AGENTS.md": {version: clean.PathVersion},
		"NOTES.md":  {version: effectVersion, tainted: true},
		"a.txt":     {version: 1},
	}
	for path, want := range wants {
		info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: path, Provenance: true}, io.Discard)
		if err != nil || info.Provenance == nil || info.Version != want.version {
			t.Errorf("%s: %+v %v", path, info, err)
			continue
		}
		read := info.Provenance
		if read.Tainted != want.tainted || read.Imported || read.Refused {
			t.Errorf("%s: provenance %+v", path, read)
		}
		if want.tainted != (read.AgentId != nil) || (read.AgentId != nil && (*read.AgentId != agentId || read.State != EvsProvenanceAsserted)) {
			t.Errorf("%s: the agent %v, state %d", path, read.AgentId, read.State)
		}
	}
	if 0 < len(reader.eventsOf(SidecarEventEvsAlarm)) {
		t.Fatal("a provenance read alarmed")
	}
}

// An import's versions keep EvsImport's label: a reader's provenance of a file an import brought in reads imported,
// untainted, signed by the importing sidecar, in each of its versions; a push that is no import's reads without it
// (TestEvsWriteAtTipSealsItsRunsTaintAndAgent).
func TestEvsImportedVersionKeepsItsLabel(t *testing.T) {
	publisher, _ := newEvsTestImporter(t)
	tip := publisher.foreignLine(3, "lib.c", nil)
	dir := publisher.sourceRepository(tip)
	ctx := context.Background()
	result, err := publisher.writer.repo.Import(ctx, &EvsImportArgs{Dir: dir})
	if err != nil || len(result.PushIds) == 0 {
		t.Fatalf("the import: %+v %v", result, err)
	}
	reader := publisher.writer.provenanceReader(t, "import reader")
	repo := reader.client.Repo(publisher.writer.world.repoId)
	imported, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "lib.c", Provenance: true}, io.Discard)
	if err != nil || imported.Provenance == nil {
		t.Fatalf("the imported file: %+v %v", imported, err)
	}
	if !imported.Provenance.Imported || imported.Provenance.Tainted || imported.SignerSidecarId != publisher.writer.world.signer.sidecarId {
		t.Fatalf("the imported file's provenance: %+v, signer %s", imported.Provenance, imported.SignerSidecarId)
	}
	history, err := repo.History(ctx, &EvsReadArgs{Path: "lib.c", Provenance: true})
	if err != nil || len(history.Versions) == 0 {
		t.Fatalf("its history: %+v %v", history, err)
	}
	for _, version := range history.Versions {
		if version.Provenance == nil || !version.Provenance.Imported {
			t.Errorf("version %d: provenance %+v", version.Version, version.Provenance)
		}
	}
	if 0 < len(reader.eventsOf(SidecarEventEvsAlarm)) {
		t.Fatal("a provenance read alarmed")
	}
}
