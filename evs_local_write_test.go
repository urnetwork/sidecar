//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// EVS1-M3-01's git-mode writes (§16.2; owner decisions 81, 141): WriteAtTip on the git-mode stand-in through a mount's
// real receive path and stock git's plumbing. A write commits on evs's tip, made an implicit mount when the repo has
// none, its committer the agent label at <client_id>@ur.invalid, and a second device replays it; a merge landing
// between the commit's build and its push makes the next try build on the newer tip, and three such races end it; a
// race that changes the path itself stops it; a delete removes the path; a client with no local tier answers
// EVS_GIT_REF; and the effect of §16.6 runs a git-mode write through it.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The publisher's world with a mount registry on its writer's client, and no mount yet.
type evsTestTipWriter struct {
	t         *testing.T
	publisher *evsTestPublisher
	mounts    *EvsMounts
	repo      *EvsRepo
}

func newEvsTestTipWriter(t *testing.T) *evsTestTipWriter {
	t.Helper()
	publisher := newEvsTestPublisher(t)
	mounts, err := NewEvsMounts(publisher.writer.test.client, t.TempDir(), evsTestGitRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	return &evsTestTipWriter{t: t, publisher: publisher, mounts: mounts, repo: publisher.writer.repo}
}

// Publishes files on main's tip from the publisher's own history, as another device's merge lands.
func (self *evsTestTipWriter) land(files map[string]string) EvsGitOid {
	self.t.Helper()
	parents := []EvsGitOid{}
	if tip := self.publisher.ref("main").tip; tip != nil {
		parents = append(parents, *tip)
	}
	commit := self.publisher.commit(files, parents...)
	if _, err := self.publisher.publish("main", &commit); err != nil {
		self.t.Fatal(err)
	}
	return commit
}

// The mount's main, and the commit's committer line.
func (self *evsTestTipWriter) main() (*EvsGitOid, string) {
	self.t.Helper()
	mount, ok := self.mounts.Get(self.publisher.writer.world.repoId)
	if !ok {
		self.t.Fatal("no mount")
	}
	local, err := mount.localRef(context.Background(), "refs/heads/main")
	if err != nil || local == nil {
		self.t.Fatalf("main %v %v", local, err)
	}
	object, err := mount.Git(context.Background(), "cat-file", "commit", local.String())
	if err != nil {
		self.t.Fatal(err)
	}
	for _, line := range strings.Split(string(object), "\n") {
		if strings.HasPrefix(line, "committer ") {
			return local, line
		}
	}
	return local, ""
}

// The first parent of a commit in the mount.
func (self *evsTestTipWriter) parentOf(commit EvsGitOid) string {
	self.t.Helper()
	mount, _ := self.mounts.Get(self.publisher.writer.world.repoId)
	out, err := mount.Git(context.Background(), "rev-parse", commit.String()+"^1")
	if err != nil {
		self.t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// Races n merges in ahead of this writer's pushes: as each of its pushes reaches the stand-in, another commit lands
// first, changing path to content of its number when path is set, else b.txt.
func (self *evsTestTipWriter) race(n int, path string) *int {
	raced := 0
	racing := false
	var raceLock sync.Mutex
	self.publisher.writer.server.onPush = func(statement *EvsStatement) {
		raceLock.Lock()
		if racing || n <= raced {
			raceLock.Unlock()
			return
		}
		racing = true
		raced += 1
		number := raced
		raceLock.Unlock()
		defer func() {
			raceLock.Lock()
			racing = false
			raceLock.Unlock()
		}()
		target := path
		if target == "" {
			target = "b.txt"
		}
		self.publisher.writer.server.know(target)
		self.land(map[string]string{"a.txt": "zero\n", target: fmt.Sprint("race ", number, "\n")})
	}
	return &raced
}

// A write on main's tip: an implicit mount made, the commit on evs's tip with the agent label and this client as
// committer, its version found as the path's first after its base, and a second device replaying the file.
func TestEvsWriteAtTipCommitsOnTheTip(t *testing.T) {
	writer := newEvsTestTipWriter(t)
	c0 := writer.land(map[string]string{"a.txt": "zero\n"})
	writer.publisher.writer.server.know("CLAUDE.md")
	ctx := context.Background()
	written, err := writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{
		Path: "CLAUDE.md", Content: []byte("# agents\n"), Message: "add CLAUDE.md", AgentLabel: "agent one",
	})
	if err != nil {
		t.Fatal(err)
	}
	// a creation's version is max(its push's base, 0) + 1 (I-EVS-8): main stood at 1
	if written.PathVersion != 2 || written.Version != 2 {
		t.Fatalf("written %+v", written)
	}
	local, committer := writer.main()
	if *local != written.Commit || writer.parentOf(written.Commit) != c0.String() {
		t.Fatalf("main %v, its parent %s, c0 %s", local, writer.parentOf(written.Commit), c0)
	}
	email := writer.publisher.writer.test.client.args.Identity().ClientId.String() + evsCommitterDomain
	if !strings.HasPrefix(committer, "committer agent one <"+email+"> ") {
		t.Fatalf("the committer: %q", committer)
	}
	device := newEvsTestDevice(t, writer.publisher, "device b")
	device.replay("main")
	if tip := device.local("refs/heads/main"); tip == nil || *tip != written.Commit {
		t.Fatalf("device b's main %v", tip)
	}
	content, err := device.mount.Git(ctx, "show", "main:CLAUDE.md")
	if err != nil || string(content) != "# agents\n" {
		t.Fatalf("device b's file %q %v", content, err)
	}
	// a delete on the file's version
	removed, err := writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{Path: "CLAUDE.md", BaseVersion: 2, Remove: true, AgentLabel: "agent one"})
	if err != nil || removed.PathVersion != 3 {
		t.Fatalf("the delete %+v %v", removed, err)
	}
	if _, err := writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{Path: "CLAUDE.md", BaseVersion: 3, Remove: true, AgentLabel: "agent one"}); !errors.Is(err, ErrEvsGitWriteUnchanged) {
		t.Fatalf("a delete of a path the tree lacks: %v", err)
	}
}

// A merge landing as the write's push arrives makes it non-fast-forward: the next try builds on the newer tip and
// commits; three such races end the write, every try refused and nothing of it committed.
func TestEvsWriteAtTipRetriesOnANewTipAndStopsAfterThree(t *testing.T) {
	writer := newEvsTestTipWriter(t)
	writer.land(map[string]string{"a.txt": "zero\n"})
	writer.publisher.writer.server.know("CLAUDE.md")
	ctx := context.Background()
	raced := writer.race(1, "")
	written, err := writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{Path: "CLAUDE.md", Content: []byte("one\n"), AgentLabel: "agent one"})
	if err != nil || *raced != 1 {
		t.Fatalf("after one race: %+v %v, %d races", written, err, *raced)
	}
	if parent := writer.parentOf(written.Commit); parent != writer.publisher.ref("main").tip.String() {
		t.Fatalf("built on %s, the raced tip %s", parent, writer.publisher.ref("main").tip)
	}
	// in a world of its own, a merge before each of three pushes ends the write
	writer = newEvsTestTipWriter(t)
	writer.land(map[string]string{"a.txt": "zero\n"})
	writer.publisher.writer.server.know("CLAUDE.md")
	raced = writer.race(writer.publisher.writer.test.client.settings.WriteAtTipTryCount, "")
	_, err = writer.repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{Path: "CLAUDE.md", Content: []byte("two\n"), AgentLabel: "agent one"})
	if !errors.Is(err, ErrEvsGitWriteRefused) || !errors.Is(err, ErrEvsGitTipMoved) || *raced != 3 {
		t.Fatalf("past three races: %v, %d races", err, *raced)
	}
	found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: "CLAUDE.md", GitOid: evsTestBlobOid(t, []byte("two\n"))})
	if err != nil || found.State != EvsLookupNone {
		t.Fatalf("the refused write's lookup %+v %v", found, err)
	}
}

// A race that changes the path itself stops the write: it never lands over a change it did not see.
func TestEvsWriteAtTipStopsWhenThePathMoves(t *testing.T) {
	writer := newEvsTestTipWriter(t)
	writer.land(map[string]string{"a.txt": "zero\n"})
	writer.publisher.writer.server.know("CLAUDE.md")
	raced := writer.race(1, "CLAUDE.md")
	_, err := writer.repo.WriteAtTip(context.Background(), &EvsWriteAtTipArgs{Path: "CLAUDE.md", Content: []byte("mine\n"), AgentLabel: "agent one"})
	if !errors.Is(err, ErrEvsPathMoved) || *raced != 1 {
		t.Fatalf("a race on the path: %v, %d races", err, *raced)
	}
}

// A client with no mount registry has no local tier: EVS_GIT_REF, as §16.2 says; and the effect of a git-mode write
// runs through WriteAtTip, answering the version Lookup finds.
func TestEvsWriteAtTipWithNoLocalTierAndTheEffect(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	if _, err := publisher.writer.repo.WriteAtTip(context.Background(), &EvsWriteAtTipArgs{Path: "x", Content: []byte("x"), AgentLabel: "a"}); !errors.Is(err, ErrEvsGitRef) {
		t.Fatalf("no local tier: %v", err)
	}
	writer := newEvsTestTipWriter(t)
	writer.land(map[string]string{"a.txt": "zero\n"})
	writer.publisher.writer.server.know("AGENTS.md")
	effect := &EvsWriteEffect{Repo: writer.repo, Path: "AGENTS.md", Content: []byte("agents\n"), AgentLabel: "agent one", Message: "AGENTS.md"}
	effectRef, err := effect.Run(context.Background(), []byte("effect key"))
	if err != nil {
		t.Fatal(err)
	}
	_, pathVersion, err := ParseEvsEffectRef(effectRef)
	if err != nil || pathVersion != 2 {
		t.Fatalf("the effect's version %d %v", pathVersion, err)
	}
	posts := writer.publisher.writer.server.postCount()
	again, err := effect.Run(context.Background(), []byte("effect key"))
	if err != nil || !bytes.Equal(again, effectRef) || writer.publisher.writer.server.postCount() != posts {
		t.Fatalf("a second run %x %v, %d posts after %d", again, err, writer.publisher.writer.server.postCount(), posts)
	}
	if _, err := writer.repo.WriteAtTip(context.Background(), &EvsWriteAtTipArgs{Path: "AGENTS.md", BaseVersion: 2, Content: []byte("x"), AgentLabel: "bad <label>"}); !errors.Is(err, ErrEvsWriteInvalid) {
		t.Fatalf("a label git takes as no name: %v", err)
	}
}
