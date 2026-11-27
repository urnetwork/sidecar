//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// GIT-M13-02's fetch tests on evsgit's world (DESIGN-COMPUTE §13.4's fetch row, §13.6's read taint, IC-12): a fetch
// replays only past the version the worktree last passed; a push by a tainted run, a tagged sidecar or another member
// taints the run before the worktree's first byte, and a member's own untainted push taints nothing.

package sidecar_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// A fetch after new pushes replays only the versions past the one the clone passed, no version twice; a fetch with
// nothing new replays nothing; the remote-tracking ref follows the writer's tip.
func TestFetchResumesFromLastPin(t *testing.T) {
	world, writer, bundled := newGitWorld(t)
	dir := writer.Clone()
	writer.Commit(dir, "one", map[string]*string{"a.txt": evsgit.Text("one\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	writer.Commit(dir, "two", map[string]*string{"a.txt": evsgit.Text("two\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	repository, cloned, _, _ := gitWorldClone(t, world, bundled, "main", "")
	passed := cloned.Fetch.Refs[0].ToVersion
	if passed == 0 || cloned.Fetch.Refs[0].FromVersion != 0 {
		t.Fatalf("the clone replayed %d to %d", cloned.Fetch.Refs[0].FromVersion, passed)
	}
	writer.Commit(dir, "three", map[string]*string{"b.txt": evsgit.Text("three\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	writer.Commit(dir, "four", map[string]*string{"b.txt": evsgit.Text("four\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	// the mounts quiet, every log read is the fetch's
	writer.Stop()
	bundled.Stop()
	stateLock := sync.Mutex{}
	sinces := []uint64{}
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/log") {
			values, _ := url.ParseQuery(request.URL.RawQuery)
			since, _ := strconv.ParseUint(values.Get("since"), 10, 64)
			stateLock.Lock()
			sinces = append(sinces, since)
			stateLock.Unlock()
		}
		return nil, nil
	}, nil)
	defer world.SetIntercept(nil, nil)
	fetched, err := repository.Fetch(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched.Refs) != 1 || fetched.Refs[0].FromVersion != passed || fetched.Refs[0].ToVersion <= passed {
		t.Fatalf("the fetch replayed %+v after the clone passed %d", fetched.Refs[0], passed)
	}
	for _, since := range sinces {
		if since <= passed {
			t.Fatalf("the fetch read the log from %d, which the clone had passed (%d)", since, passed)
		}
	}
	want := strings.TrimSpace(writer.MustGit(dir, "rev-parse", "HEAD"))
	tip, err := repository.Refs().Read(sidecar.GitRemotePrefix + "main")
	if err != nil || tip == nil || tip.String() != want {
		t.Fatalf("origin/main reads %v, the writer pushed %s: %v", tip, want, err)
	}
	// nothing new: nothing replayed
	again, err := repository.Fetch(t.Context(), nil)
	if err != nil || again.Refs[0].FromVersion != again.Refs[0].ToVersion || again.Refs[0].ToVersion != fetched.Refs[0].ToVersion {
		t.Fatalf("a fetch with nothing new replayed %+v: %v", again.Refs[0], err)
	}
}

// A push by a tainted run, a tagged sidecar or another member taints the run once, before the worktree holds
// anything, whether a clone or a fetch takes its objects; main, while only a member's own untainted pushes made it,
// taints nothing; with no taint to call, such a push is refused.
func TestFetchOfTaintedPushTaintsBeforeWorktree(t *testing.T) {
	world, writer, bundled := newGitWorld(t)
	other := world.Device("other-member", &evsgit.DeviceSettings{OtherMember: true})
	tagged := world.Device("tagged", &evsgit.DeviceSettings{Tagged: true})
	dir := writer.Clone()
	writer.Commit(dir, "base", map[string]*string{"README": evsgit.Text("base\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the base: %s", out)
	}
	trusted, _, _, trustedRecorder := gitWorldClone(t, world, bundled, "main", "")
	if trustedRecorder.calls != 0 {
		t.Fatal("main, a member's own untainted pushes, tainted the run")
	}
	// another member's and a tagged sidecar's pushes, each on a branch of its own off main
	for _, pusher := range []struct {
		device *evsgit.Device
		branch string
	}{{device: other, branch: "other-member"}, {device: tagged, branch: "tagged"}} {
		if err := pusher.device.Replay("main"); err != nil {
			t.Fatalf("%s: %v", pusher.branch, err)
		}
		pusherDir := pusher.device.Clone()
		pusher.device.MustGit(pusherDir, "checkout", "-q", "-B", pusher.branch, "origin/main")
		pusher.device.Commit(pusherDir, pusher.branch, map[string]*string{pusher.branch + ".txt": evsgit.Text("from " + pusher.branch + "\n")})
		if out, ok := pusher.device.Push(pusherDir, "origin", "HEAD:refs/heads/"+pusher.branch); !ok {
			t.Fatalf("%s's push: %s", pusher.branch, out)
		}
	}
	// a tainted run's write on main, after the branches took main at the base
	if _, err := writer.Client.Repo(world.RepoId()).WriteAtTip(t.Context(), &sidecar.EvsWriteAtTipArgs{
		Path: "from-a-tainted-run.txt", Content: []byte("read the web\n"), Message: "a tainted run's write", Tainted: true,
	}); err != nil {
		t.Fatalf("the tainted run's write: %v", err)
	}
	for _, branch := range []string{"main", "other-member", "tagged"} {
		_, result, _, recorder := gitWorldClone(t, world, bundled, branch, "")
		if recorder.calls != 1 || !result.Fetch.Tainted {
			t.Fatalf("%s: the run was tainted %d times", branch, recorder.calls)
		}
		if len(recorder.heldAtTaint) != 0 {
			t.Fatalf("%s: the worktree held %v when the run was tainted", branch, recorder.heldAtTaint)
		}
		if result.Checkout == nil || result.Checkout.WrittenCount == 0 {
			t.Fatalf("%s: the clone wrote nothing", branch)
		}
	}
	// the clone made while main was trusted fetches the tainted run's push and taints before it answers
	fetched, err := trusted.Fetch(t.Context(), nil)
	if err != nil || !fetched.Tainted || trustedRecorder.calls != 1 {
		t.Fatalf("the fetch of the tainted run's push: tainted %v, %d calls, %v", fetched != nil && fetched.Tainted, trustedRecorder.calls, err)
	}
	// with no taint to call, an untrusted push is refused, failing closed
	untainted := gitWorldUntaintedClone(t, world, bundled)
	if _, err := untainted.Fetch(t.Context(), []string{"other-member"}); err == nil || !strings.Contains(err.Error(), "no run to taint") {
		t.Fatalf("a fetch with no taint met another member's push: %v", err)
	}
}

// A clone of main whose repository then fetches with no taint to call.
func gitWorldUntaintedClone(t *testing.T, world *evsgit.World, device *evsgit.Device) *sidecar.GitRepository {
	t.Helper()
	repository, _, _, _ := gitWorldClone(t, world, device, "main", "")
	if err := repository.Connect(&sidecar.GitEvsArgs{Evs: device.Client}); err != nil {
		t.Fatal(err)
	}
	return repository
}
