//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FI-9 on ur's real export of stock git pushes (evsgit's world on T2, as FS-5's siblings clause runs it): two clients
// push sibling commits from one base, the second hears non-fast-forward, merges and lands; each push is recorded as
// its porcelain output and the client's own repository name it, the repo is exported by `ur evs export`'s engine, and
// FI-9's parse reads the export clean. The same export with one stored object's bytes changed under its name fails.

package fault

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// Not a test: the hook the world's mounts exec relays to its device's daemon (evsgit.HookHelper).
func TestFi9EvsGitHookHelperProcess(t *testing.T) {
	evsgit.HookHelper()
}

func newFi9GitWorld(t *testing.T) *evsgit.World {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	settings := evsgit.DefaultWorldSettings()
	settings.HookCommand = []string{binary, "-test.run=^TestFi9EvsGitHookHelperProcess$", "--"}
	settings.ClientSettings = evsgit.Fs5ClientSettings()
	return evsgit.NewWorld(t, settings)
}

// Records device's push from dir into ledger, each update's commit, tree and parents as the client's stock git names
// them; cause marks a refusal's cause where the test knows it.
func fi9RecordPush(t *testing.T, ledger *GitLedger, device *evsgit.Device, dir string, output string, cause string) {
	t.Helper()
	push, err := GitPushOf(device.Label, false, output, func(source string) (string, string, []string, error) {
		fields := strings.Fields(device.MustGit(dir, "log", "-1", "--format=%H %T %P", source))
		return fields[0], fields[1], fields[2:], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, update := range push.Updates {
		if update.Status == GitPushRejected {
			update.Cause = cause
		}
	}
	ledger.RecordPush(push)
}

func TestFi9ReadsUrsExportOfSiblingPushesClean(t *testing.T) {
	world := newFi9GitWorld(t)
	a, b := world.Device("fi9-a", nil), world.Device("fi9-b", nil)
	const branch = "fi9-siblings"
	ledger := NewGitLedger()
	dirA := a.Clone()
	a.Commit(dirA, "base", map[string]*string{"siblings.txt": evsgit.Text("base\n"), "d/nested.txt": evsgit.Text("nested\n")})
	out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch)
	if !ok {
		t.Fatalf("the base: %s", out)
	}
	fi9RecordPush(t, ledger, a, dirA, out, "")
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.MustGit(dirB, "checkout", "-q", "-B", "work", "origin/"+branch)
	a.Commit(dirA, "a's sibling", map[string]*string{"siblings.txt": evsgit.Text("from a\n")})
	b.Commit(dirB, "b's sibling", map[string]*string{"b.txt": evsgit.Text("from b\n")})
	if out, ok = a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("a's sibling: %s", out)
	}
	fi9RecordPush(t, ledger, a, dirA, out, "")
	if out, ok = b.Push(dirB, "origin", "HEAD:refs/heads/"+branch); ok || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("b's sibling: %v %s", ok, out)
	}
	fi9RecordPush(t, ledger, b, dirB, out, GitCauseTipMoved)
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	b.MustGit(dirB, "fetch", "-q", "origin")
	b.MustGit(dirB, "merge", "-q", "--no-edit", "origin/"+branch)
	if out, ok = b.Push(dirB, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("b's merge: %s", out)
	}
	fi9RecordPush(t, ledger, b, dirB, out, "")
	exportDir, _ := a.Export(branch)
	ledger.RecordExport(exportDir)
	if err := CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}

	// the same pushes against a copy of the export whose nested file's bytes changed under the name the export gave it
	repository, err := OpenGitRepository(exportDir)
	if err != nil {
		t.Fatal(err)
	}
	tip, _, err := repository.Ref("refs/heads/" + branch)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repository.Commit(tip)
	if err != nil {
		t.Fatal(err)
	}
	altered := filepath.Join(t.TempDir(), "altered.git")
	if err := os.CopyFS(altered, os.DirFS(exportDir)); err != nil {
		t.Fatal(err)
	}
	directoryOid := fi9TreeEntry(t, repository, commit.Tree, "d")
	nestedOid := fi9TreeEntry(t, repository, directoryOid, "nested.txt")
	alteredRepo := &fi9Repo{t: t, dir: altered}
	os.Remove(filepath.Join(altered, "objects", nestedOid[:2], nestedOid[2:]))
	alteredRepo.writeAs(nestedOid, "blob", []byte("not what was pushed\n"))
	alteredLedger := NewGitLedger()
	alteredLedger.events = append(alteredLedger.events, ledger.events[:len(ledger.events)-1]...)
	alteredLedger.RecordExport(altered)
	fi9RequireViolation(t, CheckGitPushes(alteredLedger, true), "the object stored as "+nestedOid+" hashes to")
}

// The oid of name's entry in a tree the parse reads.
func fi9TreeEntry(t *testing.T, repository *GitRepository, tree string, name string) string {
	t.Helper()
	object, err := repository.object(tree)
	if err != nil {
		t.Fatal(err)
	}
	rest := object.content
	for 0 < len(rest) {
		header, after, ok := bytes.Cut(rest, []byte{0})
		if !ok || len(after) < 20 {
			break
		}
		rest = after[20:]
		if _, entryName, _ := strings.Cut(string(header), " "); entryName == name {
			return hex.EncodeToString(after[:20])
		}
	}
	t.Fatalf("tree %s has no %s", tree, name)
	return ""
}
