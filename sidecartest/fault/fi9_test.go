package fault

// FI-9's oracle (fi9.go) on bare repositories this file writes by hand from git's object format, so each export holds
// exactly the bytes a test means: a clean export of acknowledged pushes reads clean, and each mutant (an export
// holding another tree than the client declared, a commit stored under a name its bytes do not hash to, a refused
// update that landed, a refusal git reports in the wrong words, a half-taken atomic push, an acknowledged push no export
// checked) fails on the clause it breaks. fi9_git_test.go runs a stock git push through ur's real export.

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A bare repository written by hand.
type fi9Repo struct {
	t   *testing.T
	dir string
}

func newFi9Repo(t *testing.T) *fi9Repo {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "export.git")
	for _, sub := range []string{"objects", "refs/heads"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &fi9Repo{t: t, dir: dir}
}

// The oid of an object of kind holding content, as git names it.
func fi9Oid(kind string, content []byte) string {
	digest := sha1.Sum(append(fmt.Appendf(nil, "%s %d\x00", kind, len(content)), content...))
	return hex.EncodeToString(digest[:])
}

// Writes an object of kind holding content under name, a loose object zlib-compressed: under its own oid unless a
// mutant names another.
func (self *fi9Repo) writeAs(name string, kind string, content []byte) {
	self.t.Helper()
	compressed := new(bytes.Buffer)
	writer := zlib.NewWriter(compressed)
	writer.Write(fmt.Appendf(nil, "%s %d\x00", kind, len(content)))
	writer.Write(content)
	if err := writer.Close(); err != nil {
		self.t.Fatal(err)
	}
	directory := filepath.Join(self.dir, "objects", name[:2])
	if err := os.MkdirAll(directory, 0o755); err != nil {
		self.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name[2:]), compressed.Bytes(), 0o644); err != nil {
		self.t.Fatal(err)
	}
}

func (self *fi9Repo) write(kind string, content []byte) string {
	oid := fi9Oid(kind, content)
	self.writeAs(oid, kind, content)
	return oid
}

func (self *fi9Repo) blob(text string) string {
	return self.write("blob", []byte(text))
}

// One entry of a tree: a file's blob, or a directory's tree when directory is set.
type fi9Entry struct {
	name      string
	oid       string
	directory bool
}

func fi9TreeContent(entries ...fi9Entry) []byte {
	// git orders entries by name, a directory's name compared as if it ended in /
	sort.Slice(entries, func(i int, j int) bool {
		key := func(entry fi9Entry) string {
			if entry.directory {
				return entry.name + "/"
			}
			return entry.name
		}
		return key(entries[i]) < key(entries[j])
	})
	content := new(bytes.Buffer)
	for _, entry := range entries {
		mode := "100644"
		if entry.directory {
			mode = "40000"
		}
		oidBytes, _ := hex.DecodeString(entry.oid)
		content.WriteString(mode + " " + entry.name + "\x00")
		content.Write(oidBytes)
	}
	return content.Bytes()
}

func (self *fi9Repo) tree(entries ...fi9Entry) string {
	return self.write("tree", fi9TreeContent(entries...))
}

func fi9CommitContent(tree string, parents []string, message string) []byte {
	content := "tree " + tree + "\n"
	for _, parent := range parents {
		content += "parent " + parent + "\n"
	}
	content += "author A <a@example.invalid> 1700000000 +0000\ncommitter A <a@example.invalid> 1700000000 +0000\n\n" + message + "\n"
	return []byte(content)
}

func (self *fi9Repo) commit(tree string, parents []string, message string) string {
	return self.write("commit", fi9CommitContent(tree, parents, message))
}

func (self *fi9Repo) setRef(ref string, oid string) {
	self.t.Helper()
	path := filepath.Join(self.dir, filepath.FromSlash(ref))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		self.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(oid+"\n"), 0o644); err != nil {
		self.t.Fatal(err)
	}
}

// An acknowledged update of ref declaring commit, its tree and parents.
func fi9Ok(ref string, commit string, tree string, parents ...string) *GitPushUpdate {
	return &GitPushUpdate{Ref: ref, Source: "HEAD", New: commit, Tree: tree, Parents: parents, Status: GitPushOk, Summary: "[new branch]"}
}

// A refused update of ref declaring commit, as git printed it, for cause.
func fi9Refused(ref string, commit string, tree string, summary string, reason string, cause string, parents ...string) *GitPushUpdate {
	return &GitPushUpdate{Ref: ref, Source: "HEAD", New: commit, Tree: tree, Parents: parents, Status: GitPushRejected, Summary: summary, Reason: reason, Cause: cause}
}

// A base commit and a second on top of it, both on main: what two acknowledged pushes leave.
type fi9History struct {
	repo        *fi9Repo
	base        string
	baseTree    string
	second      string
	secondTree  string
	secondBlob  string
	directory   string
	nestedBlob  string
	nestedFile  string
	secondFiles string
}

func newFi9History(t *testing.T) *fi9History {
	t.Helper()
	repo := newFi9Repo(t)
	history := &fi9History{repo: repo}
	history.baseTree = repo.tree(fi9Entry{name: "a.txt", oid: repo.blob("base\n")})
	history.base = repo.commit(history.baseTree, nil, "base")
	history.secondBlob = repo.blob("second\n")
	history.nestedBlob = repo.blob("nested\n")
	history.directory = repo.tree(fi9Entry{name: "n.txt", oid: history.nestedBlob})
	history.secondTree = repo.tree(fi9Entry{name: "a.txt", oid: history.secondBlob}, fi9Entry{name: "d", oid: history.directory, directory: true})
	history.second = repo.commit(history.secondTree, []string{history.base}, "second")
	repo.setRef("refs/heads/main", history.second)
	return history
}

// Both pushes acknowledged, then an export, checked at the end.
func (self *fi9History) ledger() *GitLedger {
	ledger := NewGitLedger()
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", self.base, self.baseTree)}})
	ledger.RecordPush(&GitPush{Actor: "deviceB", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", self.second, self.secondTree, self.base)}})
	return ledger
}

func fi9RequireViolation(t *testing.T, err error, texts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the mutant passed")
	}
	for _, text := range texts {
		if !strings.Contains(err.Error(), text) {
			t.Fatalf("the violation does not say %q: %v", text, err)
		}
	}
}

func TestFi9ReadsAnExportOfAcknowledgedPushesClean(t *testing.T) {
	history := newFi9History(t)
	ledger := history.ledger()
	ledger.RecordExport(history.repo.dir)
	if err := CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}
}

// The export's main names a commit of another tree than the one the client declared, its parents the same: the
// acknowledged push lacks its declared tree, whatever oid the export reports for it.
func TestFi9CatchesAPushAcknowledgedWithTheWrongTree(t *testing.T) {
	history := newFi9History(t)
	repo := history.repo
	wrongTree := repo.tree(fi9Entry{name: "a.txt", oid: repo.blob("not what was pushed\n")})
	wrong := repo.commit(wrongTree, []string{history.base}, "second")
	repo.setRef("refs/heads/main", wrong)
	ledger := history.ledger()
	ledger.RecordExport(repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "an acknowledged push has the declared ref", "tree "+wrongTree)
}

// The export stores, under the declared commit's own oid, a commit naming another tree: a reader trusting the
// export's names would pass it, and the parse, hashing the bytes again, does not.
func TestFi9CatchesACommitStoredUnderAnOidItsBytesDoNotHashTo(t *testing.T) {
	history := newFi9History(t)
	repo := history.repo
	wrongTree := repo.tree(fi9Entry{name: "a.txt", oid: repo.blob("not what was pushed\n")})
	repo.writeAs(history.second, "commit", fi9CommitContent(wrongTree, []string{history.base}, "second"))
	ledger := history.ledger()
	ledger.RecordExport(repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "the object stored as "+history.second+" hashes to")
}

// A blob of an acknowledged tree stored with other bytes under its name fails the tree's walk.
func TestFi9CatchesATreeWhoseBlobDoesNotHashToItsName(t *testing.T) {
	history := newFi9History(t)
	history.repo.writeAs(history.nestedBlob, "blob", []byte("altered\n"))
	ledger := history.ledger()
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "d/: n.txt: the object stored as "+history.nestedBlob+" hashes to")
}

// The declared parents differ from the export's: the acknowledged push lacks its declared ancestry.
func TestFi9CatchesAPushAcknowledgedWithOtherParents(t *testing.T) {
	history := newFi9History(t)
	ledger := NewGitLedger()
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.base, history.baseTree)}})
	ledger.RecordPush(&GitPush{Actor: "deviceB", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.second, history.secondTree)}})
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "an acknowledged push has the declared ancestry")
}

// A refused update whose commit is on its ref, carried by no acknowledged update, moved a ref it may not.
func TestFi9CatchesARefusedUpdateThatLanded(t *testing.T) {
	history := newFi9History(t)
	ledger := NewGitLedger()
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.base, history.baseTree)}})
	ledger.RecordPush(&GitPush{Actor: "deviceB", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/main", history.second, history.secondTree, "[remote rejected]", "GATE_CLOSED", "EVS_REFUSAL_GATE_CLOSED", history.base),
	}})
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "a refused update moves no ref")
}

// An update git heard as remote outcome pending that the journal later finds committed is on its ref, the tip, and
// reads clean: an unknown outcome may land either way (FS-5's journal clause).
func TestFi9TakesAPendingOutcomeThatLanded(t *testing.T) {
	history := newFi9History(t)
	ledger := NewGitLedger()
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.base, history.baseTree)}})
	ledger.RecordPush(&GitPush{Actor: "deviceB", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/main", history.second, history.secondTree, "[remote rejected]", "remote outcome pending", "", history.base),
	}})
	ledger.RecordExport(history.repo.dir)
	if err := CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}
}

// A refusal whose commit a later acknowledged update carried, as a merge does after a non-fast-forward, reads clean.
func TestFi9TakesARefusedCommitALaterPushCarried(t *testing.T) {
	history := newFi9History(t)
	repo := history.repo
	sibling := repo.commit(repo.tree(fi9Entry{name: "b.txt", oid: repo.blob("sibling\n")}), []string{history.base}, "sibling")
	mergeTree := repo.tree(fi9Entry{name: "a.txt", oid: history.secondBlob}, fi9Entry{name: "b.txt", oid: repo.blob("sibling\n")}, fi9Entry{name: "d", oid: history.directory, directory: true})
	merge := repo.commit(mergeTree, []string{sibling, history.second}, "merge")
	repo.setRef("refs/heads/main", merge)
	ledger := history.ledger()
	ledger.RecordPush(&GitPush{Actor: "deviceC", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/main", sibling, "", "[rejected]", "non-fast-forward", GitCauseTipMoved, history.base),
	}})
	ledger.RecordPush(&GitPush{Actor: "deviceC", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", merge, mergeTree, sibling, history.second)}})
	ledger.RecordExport(repo.dir)
	if err := CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}
}

// A refusal evs answered SEGMENT_GONE that reaches git as non-fast-forward fails: only a moved tip reads so.
func TestFi9CatchesASegmentGoneReadAsNonFastForward(t *testing.T) {
	history := newFi9History(t)
	ledger := history.ledger()
	ledger.RecordPush(&GitPush{Actor: "deviceC", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/main", strings.Repeat("ab", 20), "", "[remote rejected]", "non-fast-forward", "EVS_REFUSAL_SEGMENT_GONE"),
	}})
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "only a moved tip reaches git as non-fast-forward")
}

// A refusal for a moved tip that git hears as something else fails: a stock client sees git's own words.
func TestFi9CatchesAMovedTipNotReadAsNonFastForward(t *testing.T) {
	history := newFi9History(t)
	ledger := history.ledger()
	ledger.RecordPush(&GitPush{Actor: "deviceC", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/main", strings.Repeat("cd", 20), "", "[remote rejected]", "EVS_REFUSAL_CONFLICT", GitCauseTipMoved),
	}})
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "a stock client sees git's standard non-fast-forward error")
}

// An unknown outcome heard as remote outcome pending, never as non-fast-forward, reads clean.
func TestFi9TakesAnUnknownOutcomeReadAsPending(t *testing.T) {
	history := newFi9History(t)
	ledger := history.ledger()
	ledger.RecordPush(&GitPush{Actor: "deviceC", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/other", strings.Repeat("ef", 20), "", "[remote rejected]", "remote outcome pending", "unknown"),
	}})
	ledger.RecordExport(history.repo.dir)
	if err := CheckGitPushes(ledger, true); err != nil {
		t.Fatal(err)
	}
}

// An atomic push answered ok on one ref and refused on another fails: it takes every ref or none.
func TestFi9CatchesAHalfTakenAtomicPush(t *testing.T) {
	history := newFi9History(t)
	history.repo.setRef("refs/heads/other", history.base)
	ledger := NewGitLedger()
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.base, history.baseTree)}})
	ledger.RecordPush(&GitPush{Actor: "deviceB", Atomic: true, Updates: []*GitPushUpdate{
		fi9Ok("refs/heads/other", history.base, history.baseTree),
		fi9Refused("refs/heads/main", history.second, history.secondTree, "[rejected]", "fetch first", GitCauseTipMoved, history.base),
	}})
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "an atomic push takes every ref or none")
}

// A non-fast-forward whose refused commit, stored on another ref, descends from the tip the export holds was no
// non-fast-forward.
func TestFi9CatchesANonFastForwardTheTipDoesNotBearOut(t *testing.T) {
	history := newFi9History(t)
	repo := history.repo
	third := repo.commit(history.secondTree, []string{history.second}, "third")
	repo.setRef("refs/heads/other", third)
	ledger := history.ledger()
	ledger.RecordPush(&GitPush{Actor: "deviceC", Updates: []*GitPushUpdate{
		fi9Refused("refs/heads/main", third, history.secondTree, "[rejected]", "non-fast-forward", GitCauseTipMoved, history.second),
	}})
	ledger.RecordExport(repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "a non-fast-forward the ref's tip does not bear out")
}

// An acknowledged deletion whose ref the export still holds fails.
func TestFi9CatchesAnAcknowledgedDeletionTheExportHolds(t *testing.T) {
	history := newFi9History(t)
	history.repo.setRef("refs/heads/gone", history.base)
	ledger := history.ledger()
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/gone", history.base, history.baseTree)}})
	ledger.RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{{Ref: "refs/heads/gone", Status: GitPushOk, Summary: "[deleted]"}}})
	ledger.RecordExport(history.repo.dir)
	fi9RequireViolation(t, CheckGitPushes(ledger, true), "refs/heads/gone was deleted by its newest acknowledged push")
}

// FI(9) on a Net: an acknowledged push with no export after it fails at the end, and the same push followed by an
// export reads clean after every step.
func TestFi9OnANetNeedsAnExportAfterEachAcknowledgedPush(t *testing.T) {
	for _, export := range []bool{false, true} {
		history := newFi9History(t)
		net := sidecartest.NewNet(t.Context(), nil)
		steps := []*Step{
			{Actor: "deviceA", Action: func(ctx context.Context, net *Net) error {
				GitLedgerOf(net).RecordPush(&GitPush{Actor: "deviceA", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.base, history.baseTree)}})
				GitLedgerOf(net).RecordPush(&GitPush{Actor: "deviceB", Updates: []*GitPushUpdate{fi9Ok("refs/heads/main", history.second, history.secondTree, history.base)}})
				return nil
			}},
		}
		if export {
			steps = append(steps, &Step{Actor: "deviceA", Action: func(ctx context.Context, net *Net) error {
				GitLedgerOf(net).RecordExport(history.repo.dir)
				return nil
			}})
		}
		result := Run(t.Context(), &Schedule{Id: "fi9-net", Steps: steps, Check: []Invariant{FI(9)}}, net)
		net.Close()
		if export {
			fiRequirePass(t, result)
			continue
		}
		if result.Err == nil || !strings.Contains(result.Err.Error(), "no export after it was recorded") {
			t.Fatalf("an acknowledged push no export checked: %v", result.Err)
		}
	}
}

// git push --porcelain's lines as stock git prints them, the rest of its output left out.
func TestFi9ParsesStockPorcelain(t *testing.T) {
	output := strings.Join([]string{
		"remote: warning: deleting a non-existent ref        ",
		"error: atomic push failed for ref refs/heads/main. status: 5",
		"hint: Updates were rejected because the remote contains work that you do not",
		"To /tmp/remote.git",
		"*\tHEAD:refs/heads/x\t[new branch]",
		" \tHEAD:refs/heads/main\t5262f42..3c215d8",
		"+\tHEAD:refs/heads/f\t5262f42...3c215d8 (forced update)",
		"!\tHEAD:refs/heads/a\t[rejected] (fetch first)",
		"!\tHEAD:refs/heads/b\t[rejected] (atomic push failed)",
		"!\trefs/heads/w:refs/heads/c\t[remote rejected] (remote outcome pending)",
		"-\t:refs/heads/gone\t[deleted]",
		"=\tHEAD:refs/heads/same\t[up to date]",
		"Done",
	}, "\n")
	updates, err := ParseGitPushPorcelain(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []GitPushUpdate{
		{Ref: "refs/heads/x", Source: "HEAD", Status: GitPushOk, Summary: "[new branch]"},
		{Ref: "refs/heads/main", Source: "HEAD", Status: GitPushOk, Summary: "5262f42..3c215d8"},
		{Ref: "refs/heads/f", Source: "HEAD", Status: GitPushOk, Summary: "5262f42...3c215d8", Reason: "forced update"},
		{Ref: "refs/heads/a", Source: "HEAD", Status: GitPushRejected, Summary: "[rejected]", Reason: "fetch first"},
		{Ref: "refs/heads/b", Source: "HEAD", Status: GitPushRejected, Summary: "[rejected]", Reason: "atomic push failed"},
		{Ref: "refs/heads/c", Source: "refs/heads/w", Status: GitPushRejected, Summary: "[remote rejected]", Reason: "remote outcome pending"},
		{Ref: "refs/heads/gone", Source: "", Status: GitPushOk, Summary: "[deleted]"},
		{Ref: "refs/heads/same", Source: "HEAD", Status: GitPushOk, Summary: "[up to date]"},
	}
	if len(updates) != len(want) {
		t.Fatalf("%d updates, want %d: %+v", len(updates), len(want), updates)
	}
	for i, update := range updates {
		if update.Ref != want[i].Ref || update.Source != want[i].Source || update.Status != want[i].Status || update.Summary != want[i].Summary || update.Reason != want[i].Reason {
			t.Errorf("update %d is %+v, want %+v", i, *update, want[i])
		}
	}
	if _, err := ParseGitPushPorcelain("To /tmp/remote.git\nDone\n"); err == nil {
		t.Errorf("an output with no ref's line parsed")
	}
}
