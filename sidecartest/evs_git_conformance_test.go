//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// §22.9's git row through the local tier (DESIGN-DETAILS 8.6's client matrix; R-EVS-10, D-EVS-8, FI-9; EVS1-M2-43), on
// T2: stock git as the client of a device's mount over git's local transport, its hooks relayed to the device's
// daemon, the push published to evsservice's engine in this process and replayed into a second device's bare
// repository. Each row runs once for every stock git this host has: the one on PATH and the system's /usr/bin/git when
// it is another.
//
//	every client  clone, fetch and push, oids equal on a second device (the client's repository is the reference); a
//	              sibling push refused with the daemon's non-fast-forward, and the merge after it landing with tip,
//	              tree and parents equal to the client's (FS-5's first clause); a two-ref push with one ng; an
//	              annotated tag, which no second push moves; a branch delete; refs/ur/ never advertised
//	stock git     push --atomic refused before any write; push --force refused below admin (SCOPE) and taken from an
//	              admin; a commit whose committer is no client of this sidecar refused before any write, and the same
//	              history through ur evs import accepted, its oids equal on a second device
//
// Left to their hosts and the review phase: Ubuntu's 2.34 and 2.43, Windows' git and Xcode's on other hosts, go-git,
// JGit and libgit2 as clients over http and OpenSSH, and git-remote-ur with no prior mount, whose `ur` binary this
// package cannot build (cli/'s module); the kill between the remote commit and update-ref is evs_git_twins_test.go's.

package sidecartest_test

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// Not a test: the hook a world's mounts exec relays to its device's daemon (evsgit.HookHelper).
func TestEvsGitHookHelperProcess(t *testing.T) {
	evsgit.HookHelper()
}

// The hook command every world in this package names.
func evsGitHookCommand(t *testing.T) []string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{binary, "-test.run=^TestEvsGitHookHelperProcess$", "--"}
}

// The stock gits this host runs, each once by version: PATH's, and /usr/bin/git when it is another.
func evsGitClients(t *testing.T) []string {
	t.Helper()
	clients := []string{}
	versions := []string{}
	for _, candidate := range []string{"git", "/usr/bin/git"} {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "--version").Output()
		if err != nil || slices.Contains(versions, string(out)) {
			continue
		}
		versions = append(versions, string(out))
		clients = append(clients, path)
	}
	if len(clients) == 0 {
		t.Skip("no git on this host")
	}
	return clients
}

// A world whose clients run git at path, with a writer device a and a second device b.
func newEvsGitConformanceWorld(t *testing.T, path string) (*evsgit.World, *evsgit.Device, *evsgit.Device) {
	t.Helper()
	world := evsgit.NewWorld(t, &evsgit.WorldSettings{HookCommand: evsGitHookCommand(t), ClientGit: path})
	return world, world.Device("device-a", nil), world.Device("device-b", nil)
}

// Every client: clone, push and fetch, the second device's oids equal the client's, and refs/ur/ unadvertised.
func TestEvsGitConformanceClonePushFetch(t *testing.T) {
	for _, path := range evsGitClients(t) {
		_, a, b := newEvsGitConformanceWorld(t, path)
		dirA := a.Clone()
		a.Commit(dirA, "first", map[string]*string{"README.md": evsgit.Text("hello\n"), "docs/plan.md": evsgit.Text("plan\n")})
		if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: the push: %s", path, out)
		}
		if err := b.Replay("main"); err != nil {
			t.Fatalf("%s: b's replay: %v", path, err)
		}
		dirB := b.Clone()
		if a.Shape(dirA, "HEAD") != b.Shape(dirB, "origin/main") {
			t.Fatalf("%s: b holds %s, a pushed %s", path, b.Shape(dirB, "origin/main"), a.Shape(dirA, "HEAD"))
		}
		// b pushes on, a fetches it
		b.MustGit(dirB, "checkout", "-q", "-B", "main", "origin/main")
		b.Commit(dirB, "second", map[string]*string{"docs/plan.md": evsgit.Text("plan, revised\n")})
		if out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: b's push: %s", path, out)
		}
		if err := a.Replay("main"); err != nil {
			t.Fatal(err)
		}
		a.MustGit(dirA, "fetch", "-q", "origin")
		if a.Shape(dirA, "origin/main") != b.Shape(dirB, "HEAD") {
			t.Fatalf("%s: a fetched %s, b pushed %s", path, a.Shape(dirA, "origin/main"), b.Shape(dirB, "HEAD"))
		}
		for _, ref := range append(a.Advertised(), b.Advertised()...) {
			if strings.HasPrefix(ref, "refs/ur/") {
				t.Fatalf("%s: a mount advertised %s", path, ref)
			}
		}
		if err := a.Fsck(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

// FS-5's first clause: two clients push sibling commits from one base; the second hears non-fast-forward, merges, and
// its merge lands with export's tip, tree and parents equal to the client's. A two-ref push takes its new branch and
// refuses its stale one, each reported on its own.
func TestEvsGitConformanceSiblingPushAndTwoRefs(t *testing.T) {
	for _, path := range evsGitClients(t) {
		_, a, b := newEvsGitConformanceWorld(t, path)
		dirA := a.Clone()
		a.Commit(dirA, "base", map[string]*string{"a.txt": evsgit.Text("base\n")})
		if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: the base: %s", path, out)
		}
		if err := b.Replay("main"); err != nil {
			t.Fatal(err)
		}
		dirB := b.Clone()
		b.MustGit(dirB, "checkout", "-q", "-B", "main", "origin/main")
		a.Commit(dirA, "a's sibling", map[string]*string{"a.txt": evsgit.Text("from a\n")})
		b.Commit(dirB, "b's sibling", map[string]*string{"b.txt": evsgit.Text("from b\n")})
		if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: a's sibling: %s", path, out)
		}
		out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/feature")
		if ok || !strings.Contains(out, "non-fast-forward") {
			t.Fatalf("%s: b's sibling took: %v %s", path, ok, out)
		}
		// each ref reports its own status: feature took, main did not
		if !strings.Contains(out, "refs/heads/feature") || b.LocalRef("refs/heads/feature") == "" {
			t.Fatalf("%s: the two-ref push: %s", path, out)
		}
		if err := b.Replay("main"); err != nil {
			t.Fatal(err)
		}
		b.MustGit(dirB, "fetch", "-q", "origin")
		b.MustGit(dirB, "merge", "-q", "--no-edit", "origin/main")
		if out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: b's merge: %s", path, out)
		}
		_, tips := a.Export("main")
		if tips["refs/heads/main"] != strings.TrimSpace(b.MustGit(dirB, "rev-parse", "HEAD")) {
			t.Fatalf("%s: export's main %s, b's merge %s", path, tips["refs/heads/main"], b.MustGit(dirB, "rev-parse", "HEAD"))
		}
		if err := a.Replay("main"); err != nil {
			t.Fatal(err)
		}
		a.MustGit(dirA, "fetch", "-q", "origin")
		if a.Shape(dirA, "origin/main") != b.Shape(dirB, "HEAD") {
			t.Fatalf("%s: the merge's tip, tree and parents %s on a, %s on b", path, a.Shape(dirA, "origin/main"), b.Shape(dirB, "HEAD"))
		}
	}
}

// An annotated tag lands IMMUTABLE and a second push to it is refused; a branch delete by an admin is taken; push
// --force by a writer is refused SCOPE and by an admin taken; push --atomic fails before any write.
func TestEvsGitConformanceTagsDeletesForceAndAtomic(t *testing.T) {
	for _, path := range evsGitClients(t) {
		world, admin, _ := newEvsGitConformanceWorld(t, path)
		writer := world.Device("writer", nil)
		dir := admin.Clone()
		first := admin.Commit(dir, "first", map[string]*string{"a.txt": evsgit.Text("one\n")})
		admin.MustGit(dir, "tag", "-a", "v1", "-m", "the first release")
		if out, ok := admin.Push(dir, "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/topic", "refs/tags/v1:refs/tags/v1"); !ok {
			t.Fatalf("%s: main, topic and the tag: %s", path, out)
		}
		admin.Commit(dir, "second", map[string]*string{"a.txt": evsgit.Text("two\n")})
		admin.MustGit(dir, "tag", "-f", "-a", "v1", "-m", "moved")
		if out, ok := admin.Push(dir, "--force", "origin", "refs/tags/v1:refs/tags/v1"); ok || !strings.Contains(out, "tag exists") {
			t.Fatalf("%s: a second push to a tag: %v %s", path, ok, out)
		}
		if out, ok := admin.Push(dir, "origin", "--delete", "refs/heads/topic"); !ok {
			t.Fatalf("%s: an admin's branch delete: %s", path, out)
		}
		if admin.LocalRef("refs/heads/topic") != "" {
			t.Fatalf("%s: the deleted branch stands", path)
		}
		if out, ok := admin.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: main's second: %s", path, out)
		}
		// a rewind needs FORCE: a writer's is refused SCOPE, an admin's taken
		if err := writer.Replay("main"); err != nil {
			t.Fatal(err)
		}
		writerDir := writer.Clone()
		writer.MustGit(writerDir, "checkout", "-q", "-B", "main", first)
		if out, ok := writer.Push(writerDir, "--force", "origin", "HEAD:refs/heads/main"); ok || !strings.Contains(out, "SCOPE") {
			t.Fatalf("%s: a writer's force: %v %s", path, ok, out)
		}
		admin.MustGit(dir, "checkout", "-q", "-B", "main", first)
		if out, ok := admin.Push(dir, "--force", "origin", "HEAD:refs/heads/main"); !ok {
			t.Fatalf("%s: an admin's force: %s", path, out)
		}
		if admin.LocalRef("refs/heads/main") != first {
			t.Fatalf("%s: main after the forced rewind is %s", path, admin.LocalRef("refs/heads/main"))
		}
		before := admin.LocalRef("refs/heads/main")
		admin.Commit(dir, "atomic", map[string]*string{"b.txt": evsgit.Text("b\n")})
		if out, ok := admin.Push(dir, "--atomic", "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/other"); ok {
			t.Fatalf("%s: an atomic push took: %s", path, out)
		}
		if admin.LocalRef("refs/heads/main") != before || admin.LocalRef("refs/heads/other") != "" {
			t.Fatalf("%s: an atomic push wrote", path)
		}
	}
}

// A commit whose committer is no client of this sidecar is refused before any write, naming ur evs import; the same
// history imported by an admin lands, and a second device replays it with equal oids.
func TestEvsGitConformanceForeignCommitRefusedImportAccepted(t *testing.T) {
	for _, path := range evsGitClients(t) {
		_, a, b := newEvsGitConformanceWorld(t, path)
		dir := a.Clone()
		a.MustGit(dir, "config", "committer.email", "someone@example.invalid")
		a.MustGit(dir, "config", "user.email", "someone@example.invalid")
		foreign := a.Commit(dir, "a commit of another's", map[string]*string{"x.txt": evsgit.Text("x\n")})
		out, ok := a.Push(dir, "origin", "HEAD:refs/heads/main")
		if ok || !strings.Contains(out, "ur evs import") {
			t.Fatalf("%s: a foreign commit: %v %s", path, ok, out)
		}
		if a.LocalRef("refs/heads/main") != "" {
			t.Fatalf("%s: the refused push wrote main", path)
		}
		result, err := a.Client.Repo(a.Mount.RepoId).Import(t.Context(), &sidecar.EvsImportArgs{Dir: dir, Ref: "HEAD", Target: []byte("main")})
		if err != nil {
			t.Fatalf("%s: the import: %v", path, err)
		}
		if result.Tip.String() != foreign {
			t.Fatalf("%s: the import ends at %s, not %s", path, result.Tip, foreign)
		}
		if err := b.Replay("main"); err != nil {
			t.Fatalf("%s: b's replay of the import: %v", path, err)
		}
		if b.LocalRef("refs/heads/main") != foreign {
			t.Fatalf("%s: b holds %s", path, b.LocalRef("refs/heads/main"))
		}
		if err := b.Fsck(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
