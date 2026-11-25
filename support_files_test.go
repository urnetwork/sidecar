//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

package sidecar

// The files a support message names (support_files.go; DESIGN-COMPUTE §28.7): an agent's read beneath one root, a name
// that climbs out by .. or a link refused, an absolute one taken only beneath the root, a directory and a file past its
// bound refused, at most 3; the person's own read where they name them; and the run a caller's ancestry binds, the
// nearest. Synthetic values only.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSupportReadFilesStaysBeneathItsRoot(t *testing.T) {
	settings := DefaultSupportSettings()
	root := t.TempDir()
	outside := t.TempDir()
	write := func(directory string, name string, data string) string {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write(root, "build.log", "step 3 failed\n")
	write(root, "logs/ur.log", "the daemon restarted\n")
	secret := write(outside, "secret.txt", "not the run's\n")
	if err := os.Symlink(secret, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}

	files, err := SupportReadFiles(root, []string{"build.log", filepath.Join(root, "logs", "ur.log")}, settings)
	if err != nil || len(files) != 2 || files[0].Name != "build.log" || string(files[0].Data) != "step 3 failed\n" ||
		files[1].Name != "ur.log" || string(files[1].Data) != "the daemon restarted\n" {
		t.Fatalf("files %+v, %v", files, err)
	}
	if files, err := SupportReadFiles(root, nil, settings); err != nil || files != nil {
		t.Fatalf("no names: %v, %v", files, err)
	}
	for name, names := range map[string][]string{
		"a climb by ..":                 {"../" + filepath.Base(outside) + "/secret.txt"},
		"an absolute path outside":      {secret},
		"a link leaving the root":       {"link.txt"},
		"a directory":                   {"directory"},
		"the root itself":               {"."},
		"a file that is not there":      {"missing.log"},
		"a second name that climbs out": {"build.log", "../x"},
	} {
		if _, err := SupportReadFiles(root, names, settings); SupportRefusalOf(err) != SupportRefusalFileRefused {
			t.Errorf("%s: %v", name, err)
		}
	}
	var refusal *SupportRefusalError
	if _, err := SupportReadFiles(root, []string{"build.log", "../x"}, settings); !errors.As(err, &refusal) || refusal.FileIndex != 1 {
		t.Fatalf("the refusal names the second file: %v", err)
	}
	if _, err := SupportReadFiles(root, []string{"a", "b", "c", "d"}, settings); SupportRefusalOf(err) != SupportRefusalFileRefused {
		t.Fatalf("a fourth file: %v", err)
	}
	if _, err := SupportReadFiles("relative/root", []string{"build.log"}, settings); SupportRefusalOf(err) != SupportRefusalFileRefused {
		t.Fatalf("a relative root: %v", err)
	}
	small := DefaultSupportSettings()
	small.FileMaxByteCount = 4
	if _, err := SupportReadFiles(root, []string{"build.log"}, small); SupportRefusalOf(err) != SupportRefusalFileRefused {
		t.Fatalf("a file past its bound: %v", err)
	}

	// the person's own, where they name them, an absolute path each
	personFiles, err := SupportReadPersonFiles([]string{secret}, settings)
	if err != nil || len(personFiles) != 1 || personFiles[0].Name != "secret.txt" {
		t.Fatalf("the person's file: %+v, %v", personFiles, err)
	}
	for name, paths := range map[string][]string{"a relative path": {"secret.txt"}, "a directory": {outside}, "four": {secret, secret, secret, secret}} {
		if _, err := SupportReadPersonFiles(paths, settings); SupportRefusalOf(err) != SupportRefusalFileRefused {
			t.Errorf("the person's %s: %v", name, err)
		}
	}
}

// The run a caller's ancestry binds is the nearest ancestor's; none where no ancestor holds one; its taint reasons are
// what an external harness's message carries, counted tainted whatever they say.
func TestSupportCallerRunIsTheNearestAncestors(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	table := testProcessTable{}
	table.add(10, 1, 100, "zsh")
	table.add(20, 10, 200, "claude")
	table.add(30, 20, 300, "bash")
	table.add(40, 30, 400, "ur")
	table.add(50, 10, 500, "ur")
	ctx := context.Background()
	ingest := DefaultSidecarSettings().Ingest
	outer := &RunFile{RunId: NewId(), Harness: "claude-code", ProcessId: 10, ProcessStartMillis: 100, Worktree: "/outer"}
	inner := &RunFile{RunId: NewId(), Harness: "claude-code", ProcessId: 20, ProcessStartMillis: 200, Worktree: "/inner",
		Tainted: true, TaintReasons: []RunTaintReason{RunTaintUntrustedData}}
	for _, run := range []*RunFile{outer, inner} {
		if err := runs.Create(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	found, err := supportCallerRunOn(ctx, runs, table, ingest, 40)
	if err != nil || found == nil || found.RunId != inner.RunId || found.Worktree != "/inner" {
		t.Fatalf("the caller's run: %+v, %v", found, err)
	}
	run := SupportRunOfFile(Id{}, found)
	if run.RunId != inner.RunId || !run.Tainted || len(run.TaintReasons) != 1 || run.TaintReasons[0] != string(RunTaintUntrustedData) {
		t.Fatalf("the support run: %+v", run)
	}
	if found, err := supportCallerRunOn(ctx, runs, table, ingest, 50); err != nil || found == nil || found.RunId != outer.RunId {
		t.Fatalf("a caller beside the inner harness: %+v, %v", found, err)
	}
	empty := testProcessTable{}
	empty.add(60, 1, 600, "ur")
	if found, err := supportCallerRunOn(ctx, runs, empty, ingest, 60); err != nil || found != nil {
		t.Fatalf("a caller under no harness: %+v, %v", found, err)
	}
	if run := SupportRunOfFile(Id{7}, nil); run.RunId != (Id{7}) || !run.Tainted || len(run.TaintReasons) != 0 {
		t.Fatalf("a run with no file: %+v", run)
	}
}
