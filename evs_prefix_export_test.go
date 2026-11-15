//go:build !js && !ios_extension

// Export of a ruled repo (EVS1-M6-04; DESIGN-DETAILS 16.2.5's export row), with the system git as evs_export_test.go
// runs it.

package sidecar

import (
	"context"
	"path/filepath"
	"testing"
)

// The exported trees of a file-mode ref hold effective versions: a breach's write, creation and removal are left
// out, the version is reported in Ignored with no ref stopped, and the export alarms prefix_rule with the count.
func TestEvsPrefixExportHoldsEffectiveVersions(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	world.push(&evsTestChange{path: "", children: []string{"src", "agents"}}, &evsTestChange{path: "src", children: []string{"main.go", "gone.go"}},
		&evsTestChange{path: "src/main.go", content: []byte("main\n")}, &evsTestChange{path: "src/gone.go", content: []byte("gone\n")},
		&evsTestChange{path: "agents", children: []string{"build"}})
	test.pushAs(test.held, &evsTestChange{path: "agents/build", children: []string{"out"}}, &evsTestChange{path: "agents/build/out", content: []byte("built\n")})
	breach := test.pushAs(test.held, &evsTestChange{path: "src", children: []string{"planted.go"}}, &evsTestChange{path: "src/main.go", content: []byte("breached\n")},
		&evsTestChange{path: "src/planted.go", content: []byte("planted\n")}, &evsTestChange{path: "src/gone.go"})
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "ruled.git")
	exporter := test.reader("exporter")
	result, err := exporter.client.Repo(world.repoId).Export(ctx, &EvsExportArgs{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Refs) != 1 || len(result.Refs[0].Ignored) != 1 || result.Refs[0].Ignored[0].Version != breach || len(result.Refs[0].Refused) != 0 {
		t.Fatalf("exported %+v", result.Refs[0])
	}
	if tree := evsTestGit(t, dir, "ls-tree", "-r", "--name-only", "main"); tree != "agents/build/out\nsrc/gone.go\nsrc/main.go\n" {
		t.Errorf("the tip's tree %q", tree)
	}
	if content := evsTestGit(t, dir, "show", "main:src/main.go"); content != "main\n" {
		t.Errorf("src/main.go at the tip %q", content)
	}
	if alarms := evsPrefixTestAlarms(exporter); len(alarms) != 1 || alarms[0].Count != 4 {
		t.Errorf("the export's alarms %+v", alarms)
	}
}
