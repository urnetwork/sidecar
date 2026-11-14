//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-5's clauses with stock git as the client (§22's FS-5, FI-9; DESIGN-DETAILS 8.6's client matrix; EVS1-M2-43), each a
// schedule over a World, so T2 (sidecartest's TestEvsGitFs5Clauses, on the engine in this process) and T3 (server's
// evshost TestFs5OnT3, on server/cli/evs's block over the private stores) run the same steps. Each clause takes devices
// of its own and a shared branch of its own, so the clauses share one world in any order.
//
//	siblings    two clients push sibling commits from one base: the second hears non-fast-forward, and its merge lands
//	            with export's tip, and the tip, tree and parents another device fetches, equal to the client's
//	refusals    SEGMENT_GONE, 429 and GATE_CLOSED from evs on every push attempt reach git as an ng that is never a
//	            non-fast-forward, and once evs answers again the same update lands
//	parts       on a warm head cache, a push past 1,024 entry writes takes its lease, posts its parts and seals with no
//	            ng, and a second device replays it with equal oids and a clean git fsck --strict
//	atomic      a two-ref atomic push whose second ref conflicts moves neither ref, at the daemon or on evs
//	journal     every answer of a push's committed attempt lost, as a daemon killed after evs's commit and before its
//	            update-ref loses them: git hears remote outcome pending, never non-fast-forward, and the restart's
//	            resolve finds the commit in the history, moves the local ref and sends nothing again
//
// Left to FS-5's other rows and the review phase: a head moved only by a commitless PATH_EPOCH, the lease races
// (evsservice's push_parts_test.go holds them on T2), an agent branch over a main with unfolded changes, an overlay of
// a file-mode ref, and a ref-lock failure after pre-receive.

package evsgit

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A device's evs settings for FS-5's clauses: receive waits short enough that an answer that cannot come comes back in
// a test's time, and a lost answer asked again twice, at once.
func Fs5ClientSettings() *sidecar.EvsSettings {
	settings := sidecar.DefaultEvsSettings()
	settings.ReceiveWaitTimeout = 3 * time.Second
	settings.QueueFirstDelay = 50 * time.Millisecond
	settings.QueueInterval = 200 * time.Millisecond
	settings.PushRetryCount = 2
	settings.PushRetryMaxWait = 10 * time.Millisecond
	settings.ReadRetryWait = 10 * time.Millisecond
	return settings
}

// The siblings clause: see the file header.
func Fs5Siblings(t testing.TB, world *World) {
	t.Helper()
	a, b := world.Device("fs5-siblings-a", nil), world.Device("fs5-siblings-b", nil)
	const branch = "fs5-siblings"
	dirA := a.Clone()
	a.Commit(dirA, "base", map[string]*string{"siblings.txt": Text("base\n")})
	if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the base: %s", out)
	}
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.MustGit(dirB, "checkout", "-q", "-B", "work", "origin/"+branch)
	a.Commit(dirA, "a's sibling", map[string]*string{"siblings.txt": Text("from a\n")})
	b.Commit(dirB, "b's sibling", map[string]*string{"b.txt": Text("from b\n")})
	if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("a's sibling: %s", out)
	}
	if out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/"+branch); ok || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("b's sibling: %v %s", ok, out)
	}
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	b.MustGit(dirB, "fetch", "-q", "origin")
	b.MustGit(dirB, "merge", "-q", "--no-edit", "origin/"+branch)
	if out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("b's merge: %s", out)
	}
	merge := strings.TrimSpace(b.MustGit(dirB, "rev-parse", "HEAD"))
	if _, tips := a.Export(branch); tips["refs/heads/"+branch] != merge {
		t.Fatalf("export's tip %s, b's merge %s", tips["refs/heads/"+branch], merge)
	}
	if err := a.Replay(branch); err != nil {
		t.Fatal(err)
	}
	a.MustGit(dirA, "fetch", "-q", "origin")
	if a.Shape(dirA, "origin/"+branch) != b.Shape(dirB, "HEAD") {
		t.Fatalf("the merge's tip, tree and parents %s on a, %s on b", a.Shape(dirA, "origin/"+branch), b.Shape(dirB, "HEAD"))
	}
}

// One refusal evs answers on every attempt of the refusals clause.
type fs5Refusal struct {
	name   string
	status int
	code   protocol.EvsRefusalCode
}

// The refusals clause: see the file header.
func Fs5RefusalsAreNoNonFastForward(t testing.TB, world *World) {
	t.Helper()
	a := world.Device("fs5-refusals", nil)
	dir := a.Clone()
	for _, refusal := range []*fs5Refusal{
		{name: "segment-gone", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE},
		{name: "resource-exhausted", status: http.StatusTooManyRequests, code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED},
		{name: "gate-closed", status: http.StatusPreconditionFailed, code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED},
	} {
		branch := "fs5-refused-" + refusal.name
		commit := a.Commit(dir, refusal.name, map[string]*string{refusal.name + ".txt": Text(refusal.name + "\n")})
		refused := &atomic.Int64{}
		world.SetIntercept(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/push") {
				refused.Add(1)
				return Refusal(refusal.status, refusal.code), nil
			}
			return nil, nil
		}, nil)
		out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch)
		world.SetIntercept(nil, nil)
		if ok || strings.Contains(out, "non-fast-forward") {
			t.Fatalf("%s on every attempt: %v %s", refusal.name, ok, out)
		}
		if refused.Load() == 0 {
			t.Fatalf("%s: no attempt reached evs", refusal.name)
		}
		t.Logf("%s on %d attempts: git heard %q", refusal.name, refused.Load(), fs5StatusLine(out, branch))
		// evs answers again: the next receive resolves what the journal holds, and the same update lands
		if err := a.Mount.Receiver().Start(world.ctx); err != nil {
			t.Fatal(err)
		}
		if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok || strings.Contains(out, "non-fast-forward") {
			t.Fatalf("%s, then the same update: %v %s", refusal.name, ok, out)
		}
		if a.LocalRef("refs/heads/"+branch) != commit {
			t.Fatalf("%s: the branch is %q, not %s", refusal.name, a.LocalRef("refs/heads/"+branch), commit)
		}
	}
}

// The status line git's porcelain output gives a branch, or the whole output when none names it.
func fs5StatusLine(out string, branch string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "refs/heads/"+branch) {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(out)
}

// A part's route: POST .../push/<push_id>/<k>.
var fs5PartPath = regexp.MustCompile(`/push/[0-9a-f]+/[0-9]+$`)

// The parts clause: see the file header. fileCount passes PartMaxEntryWriteCount, 1,024.
func Fs5PushInParts(t testing.TB, world *World, fileCount int) {
	t.Helper()
	a, b := world.Device("fs5-parts-a", nil), world.Device("fs5-parts-b", nil)
	const branch = "fs5-parts"
	dir := a.Clone()
	// warms the head cache with the ref's first version
	a.Commit(dir, "first", map[string]*string{"first.txt": Text("first\n")})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the first push: %s", out)
	}
	files := map[string]*string{}
	for i := range fileCount {
		files[fmt.Sprintf("many/%02d/%04d.txt", i%32, i)] = Text(fmt.Sprintf("file %d\n", i))
	}
	commit := a.Commit(dir, "many files", files)
	leases, parts := &atomic.Int64{}, &atomic.Int64{}
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			switch {
			case strings.HasSuffix(request.URL.Path, "/lease"):
				leases.Add(1)
			case fs5PartPath.MatchString(request.URL.Path):
				parts.Add(1)
			}
		}
		return nil, nil
	}, nil)
	out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch)
	world.SetIntercept(nil, nil)
	if !ok || strings.Contains(out, "!") {
		t.Fatalf("the push in parts: %v %s", ok, out)
	}
	if leases.Load() == 0 || parts.Load() < 2 {
		t.Fatalf("the push in parts took %d leases and posted %d parts", leases.Load(), parts.Load())
	}
	t.Logf("the push of %d files took %d leases and posted %d parts", fileCount, leases.Load(), parts.Load())
	if err := b.Replay(branch); err != nil {
		t.Fatalf("b's replay: %v", err)
	}
	if b.LocalRef("refs/heads/"+branch) != commit {
		t.Fatalf("b holds %q, a pushed %s", b.LocalRef("refs/heads/"+branch), commit)
	}
	if err := b.Fsck(); err != nil {
		t.Fatal(err)
	}
}

// The atomic clause: see the file header.
func Fs5AtomicSecondRefConflicts(t testing.TB, world *World) {
	t.Helper()
	a, b := world.Device("fs5-atomic-a", nil), world.Device("fs5-atomic-b", nil)
	const branch, fresh = "fs5-atomic", "fs5-atomic-new"
	dirA := a.Clone()
	a.Commit(dirA, "base", map[string]*string{"atomic.txt": Text("base\n")})
	if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the base: %s", out)
	}
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.MustGit(dirB, "checkout", "-q", "-B", "work", "origin/"+branch)
	tip := a.Commit(dirA, "a's sibling", map[string]*string{"atomic.txt": Text("from a\n")})
	if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("a's sibling: %s", out)
	}
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	b.Commit(dirB, "b's sibling", map[string]*string{"b.txt": Text("from b\n")})
	if out, ok := b.Push(dirB, "--atomic", "origin", "HEAD:refs/heads/"+fresh, "HEAD:refs/heads/"+branch); ok {
		t.Fatalf("an atomic push whose second ref conflicts took: %s", out)
	}
	if b.LocalRef("refs/heads/"+fresh) != "" || b.LocalRef("refs/heads/"+branch) != tip {
		t.Fatalf("the atomic push moved a ref at the daemon: %q, %q", b.LocalRef("refs/heads/"+fresh), b.LocalRef("refs/heads/"+branch))
	}
	refId, err := b.RefId(fresh)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := b.Client.Repo(world.repoId).ListRefs(world.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range listing.Refs {
		if bytes.Equal(summary.GetRefId(), refId.Bytes()) {
			t.Fatalf("the atomic push created %s on evs at version %d", fresh, summary.GetVersion())
		}
	}
}

// The journal clause: see the file header.
func Fs5LostAnswerReconciles(t testing.TB, world *World) {
	t.Helper()
	a := world.Device("fs5-journal", nil)
	const branch = "fs5-journal"
	dir := a.Clone()
	commit := a.Commit(dir, "one", map[string]*string{"journal.txt": Text("one\n")})
	lost := &atomic.Int64{}
	world.SetIntercept(nil, func(request *http.Request) error {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
			lost.Add(1)
			return errors.New("the daemon died after evs's commit")
		}
		return nil
	})
	out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch)
	world.SetIntercept(nil, nil)
	if ok || strings.Contains(out, "non-fast-forward") || !strings.Contains(out, "remote outcome pending") {
		t.Fatalf("a push whose answers were lost: %v %s", ok, out)
	}
	if lost.Load() == 0 {
		t.Fatal("no answer was lost")
	}
	// the restart: the journal resolves from the history before anything else
	if err := a.Mount.Receiver().Start(world.ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Replay(branch); err != nil {
		t.Fatal(err)
	}
	if a.LocalRef("refs/heads/"+branch) != commit {
		t.Fatalf("the branch is %q after the resolve, not %s", a.LocalRef("refs/heads/"+branch), commit)
	}
	statuses, err := a.Mount.Receiver().JournalStatus()
	if err != nil || len(statuses) != 0 {
		t.Fatalf("the journal after the resolve %+v %v", statuses, err)
	}
	pushes := &atomic.Int64{}
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
			pushes.Add(1)
		}
		return nil, nil
	}, nil)
	out, ok = a.Push(dir, "origin", "HEAD:refs/heads/"+branch)
	world.SetIntercept(nil, nil)
	if !ok || strings.Contains(out, "non-fast-forward") {
		t.Fatalf("the same update again: %v %s", ok, out)
	}
	if pushes.Load() != 0 {
		t.Fatalf("the committed update was sent %d times more", pushes.Load())
	}
}
