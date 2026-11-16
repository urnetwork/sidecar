//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// The git-lfs tip check (EVS2-M10-27; FS-73's tip clauses): on a real git repository over the store's stand-in evs, a
// new ref's whole R checked, a fresh object left, a stale one touched with no upload, a never-stored and a pruned
// object found missing with their paths and the prune's time, a racing touch read again as fresh; the hook's lines
// naming at most 20 objects; and through stock git and the receive path, a push whose object is not stored refused
// `lfs objects missing` with evs's tip unmoved and the journal empty, then committed once the object is stored, and a
// force push to an ancestor whose object aged touching it before its POST.

package sidecar

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A tip check's world: the store's stand-in evs, and a bare repository commits are written into, as a mount's.
type evsTestTipCheck struct {
	lfs   *evsTestLfsStore
	repo  *evsTestLfsRepo
	mount *EvsLocalRepo
}

func newEvsTestTipCheck(t *testing.T) *evsTestTipCheck {
	lfs := newEvsTestLfsStore(t)
	repo := newEvsTestLfsRepo(t)
	return &evsTestTipCheck{lfs: lfs, repo: repo, mount: &EvsLocalRepo{BareDir: repo.dir, git: repo.git}}
}

// A pointer to content, and the content's oid.
func evsTestLfsPointerOf(content []byte) (string, EvsLfsOid) {
	oid := EvsLfsOid(sha256.Sum256(content))
	return fmt.Sprintf("version %s\noid sha256:%s\nsize %d\n", evsLfsPointerVersions[0], oid, len(content)), oid
}

func (self *evsTestTipCheck) check(t *testing.T, old *EvsGitOid, new EvsGitOid) *EvsLfsTipCheckResult {
	t.Helper()
	result, err := EvsLfsTipCheck(context.Background(), &EvsLfsTipCheckArgs{Mount: self.mount, Store: self.lfs.store, Old: old, New: new})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Fresh, stale and missing (see the file header).
func TestEvsLfsTipCheckFreshStaleMissing(t *testing.T) {
	check := newEvsTestTipCheck(t)
	ctx := context.Background()
	clock := check.lfs.writer.test.clock
	staleContent, freshContent, absentContent, prunedContent := []byte("stale object"), []byte("fresh object"), []byte("never stored"), []byte("pruned object")
	stalePointer, staleOid := evsTestLfsPointerOf(staleContent)
	freshPointer, freshOid := evsTestLfsPointerOf(freshContent)
	absentPointer, absentOid := evsTestLfsPointerOf(absentContent)
	prunedPointer, prunedOid := evsTestLfsPointerOf(prunedContent)
	if _, err := check.lfs.put(t, staleOid, staleContent); err != nil {
		t.Fatal(err)
	}
	clock.advance(6 * 24 * time.Hour)
	if _, err := check.lfs.put(t, freshOid, freshContent); err != nil {
		t.Fatal(err)
	}
	attributes := "*.bin filter=lfs\n"
	a := check.repo.commit(map[string]string{".gitattributes": attributes, "stale.bin": stalePointer, "fresh.bin": freshPointer})
	uploads := check.lfs.uploads()
	result := check.check(t, nil, a)
	if len(result.Missing) != 0 || result.FreshCount != 1 || result.TouchedCount != 1 {
		t.Fatalf("a new ref: %+v", result)
	}
	if entry := check.lfs.entry(t, staleOid); entry.GetVersion() != 2 || check.lfs.uploads() != uploads {
		t.Fatalf("the stale object's touch: version %d, %d uploads", entry.GetVersion(), check.lfs.uploads())
	}
	// an ordinary push of a new object: only what it adds is read
	b := check.repo.commit(map[string]string{".gitattributes": attributes, "stale.bin": stalePointer, "fresh.bin": freshPointer, "dir/absent.bin": absentPointer})
	result = check.check(t, &a, b)
	if len(result.Missing) != 1 || result.Missing[0].Requirement.Oid != absentOid || result.Missing[0].Requirement.Path != "dir/absent.bin" || !result.Missing[0].RemovedAt.IsZero() {
		t.Fatalf("a never-stored object: %+v", result.Missing)
	}
	// a pruned object, its prune's time named
	if _, err := check.lfs.put(t, prunedOid, prunedContent); err != nil {
		t.Fatal(err)
	}
	newest, err := check.lfs.store.Newest(ctx, []EvsLfsOid{prunedOid}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := check.lfs.store.RemoveMany(ctx, newest); err != nil {
		t.Fatal(err)
	}
	c := check.repo.commit(map[string]string{".gitattributes": attributes, "pruned.bin": prunedPointer})
	result = check.check(t, nil, c)
	if len(result.Missing) != 1 || result.Missing[0].Requirement.Oid != prunedOid || result.Missing[0].RemovedAt.IsZero() {
		t.Fatalf("a pruned object: %+v", result.Missing)
	}
	lines := EvsLfsMissingLines("refs/heads/main", result.Missing, DefaultEvsSettings())
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "git lfs push --object-id <remote> "+prunedOid.String()) || !strings.Contains(joined, "pruned.bin") || !strings.Contains(joined, "pruned 20") {
		t.Fatalf("the hook's lines: %s", joined)
	}
}

// A touch another device made between the check's read and its own touch: the check's touch loses path-level CAS, and
// the reread's newer version counts as fresh.
func TestEvsLfsTipCheckRacingTouchReadsAsFresh(t *testing.T) {
	check := newEvsTestTipCheck(t)
	ctx := context.Background()
	content := []byte("raced object")
	pointer, oid := evsTestLfsPointerOf(content)
	if _, err := check.lfs.put(t, oid, content); err != nil {
		t.Fatal(err)
	}
	check.lfs.writer.test.clock.advance(6 * 24 * time.Hour)
	// the check's store holds the stale version read before the other device's touch
	if _, err := check.lfs.store.Newest(ctx, []EvsLfsOid{oid}, true); err != nil {
		t.Fatal(err)
	}
	other := NewEvsLfsStore(check.lfs.writer.repo)
	read, err := other.Newest(ctx, []EvsLfsOid{oid}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Touch(ctx, read); err != nil {
		t.Fatal(err)
	}
	a := check.repo.commit(map[string]string{".gitattributes": "*.bin filter=lfs\n", "x.bin": pointer})
	result := check.check(t, nil, a)
	if len(result.Missing) != 0 || result.FreshCount != 1 || result.TouchedCount != 0 {
		t.Fatalf("after a racing touch: %+v", result)
	}
	if entry := check.lfs.entry(t, oid); entry.GetVersion() != 2 {
		t.Fatalf("a second touch landed: version %d", entry.GetVersion())
	}
}

// The hook names at most 20 objects, then how many more.
func TestEvsLfsMissingLinesNameAtMostTwenty(t *testing.T) {
	missing := []*EvsLfsMissingObject{}
	for i := 0; i < 25; i += 1 {
		_, oid := evsTestLfsPointerOf([]byte(fmt.Sprint("object ", i)))
		missing = append(missing, &EvsLfsMissingObject{Requirement: &EvsLfsRequirement{Oid: oid, Path: fmt.Sprintf("f%d.bin", i)}})
	}
	lines := EvsLfsMissingLines("refs/heads/main", missing, DefaultEvsSettings())
	if len(lines) != 2+20+1 || !strings.HasSuffix(lines[len(lines)-1], "and 5 more") {
		t.Fatalf("%d lines: %q", len(lines), lines[len(lines)-1])
	}
}

// Through stock git and the receive path: a push whose object is not stored is refused with evs's tip unmoved and the
// journal empty, its hint printed to the pusher; once the object is stored the push commits; and after it ages, a
// force push to an ancestor touches it before its POST.
func TestEvsLocalReceiveLfsTipCheck(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	writer := publisher.writer
	writer.server.format2 = true
	writer.test.client.SetFormat2Source(func() bool { return true })
	writer.test.client.EnableFormat2Reader()
	// ur/lfs, a file-mode ref beside the git-mode main
	writer.world.otherRef(EvsLfsRefName).mode = protocol.EvsRefMode_EVS_REF_FILE
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	content := []byte("a large object")
	pointer, oid := evsTestLfsPointerOf(content)
	a := receiver.commit(dir, map[string]string{".gitattributes": "*.bin filter=lfs\n", "big.bin": pointer})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if ok || !strings.Contains(out, evsLfsTipCheckRefusal) || !strings.Contains(out, "git lfs push --object-id <remote> "+oid.String()) {
		t.Fatalf("a push of a missing object: %v %s", ok, out)
	}
	if version := receiver.headVersion("main"); version != 0 {
		t.Fatalf("evs's head moved to %d", version)
	}
	if statuses, err := receiver.mount.receiver.JournalStatus(); err != nil || len(statuses) != 0 {
		t.Fatalf("the journal %+v %v", statuses, err)
	}
	store := NewEvsLfsStore(writer.repo)
	writer.server.know(EvsLfsPath(oid))
	if _, err := store.Put(context.Background(), oid, int64(len(content)), strings.NewReader(string(content))); err != nil {
		t.Fatal(err)
	}
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push once stored: %s", out)
	}
	// a later commit drops the object; after it ages, a force push back to the ancestor needs it again
	receiver.commit(dir, map[string]string{".gitattributes": "*.bin filter=lfs\n", "other.txt": "no objects\n"})
	evsTestGit(t, dir, "rm", "-q", "big.bin")
	evsTestGit(t, dir, "commit", "-q", "-m", "drop")
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push dropping it: %s", out)
	}
	writer.test.clock.advance(6 * 24 * time.Hour)
	if out, ok := receiver.push(dir, "--force", "origin", a.String()+":refs/heads/main"); !ok {
		t.Fatalf("the force push to the ancestor: %s", out)
	}
	newest, err := store.Newest(context.Background(), []EvsLfsOid{oid}, true)
	if err != nil || newest[0].Version != 2 {
		t.Fatalf("the aged object was not touched: %+v %v", newest, err)
	}
}
