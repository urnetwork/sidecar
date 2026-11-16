//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-73's clauses with stock git and git-lfs as the client (§22's FS-73, FI-9, FI-16; §11.11's store, agent, touch,
// smudge, tip check, journal, import and prune rows; §22.9's git-lfs row; EVS2-M10-29), each a schedule over a World
// with format 2, git-lfs and a moving clock, so T2 (sidecartest's TestEvsGitFs73*, on the engine in this process) and
// T3 (server's evshost TestFs73OnT3, on server/cli/evs's block over the private stores) run the same steps. Every push
// goes through stock git's local transport into the mount's bare repository, behind the daemon's hooks and its tip
// check; every object moves through git-lfs's standalone transfer agent and the device's daemon (lfs.go). Each clause
// takes devices and refs of its own, and reads the prune's window rather than assume it, so the clauses share one world
// in any order; the prune is the repo's, so a clause holds only its own objects to what a prune did.
//
//	store      an ordinary push of a commit with LFS files: the agent stores each object at <oid[0:2]>/<oid[2:4]>/<oid>
//	           before the ref update, once, a creation, and the tip check writes no touch; the pointer blobs are
//	           git-lfs's documented bytes and export's oids are git's; another device's checkout smudges each object
//	           through its agent; `git lfs push --object-id` of an object the store holds touches it, citing the stored
//	           content and uploading nothing
//	pruned     A holds pointer O and B, the tip, removes it; A and O's last version aged past N, a daily prune by a
//	           device holding every ref removes O; an old commit's checkout leaves O's pointer under
//	           lfs.skipdownloaderrors, the agent naming O and when its prune committed, and under GIT_LFS_SKIP_SMUDGE
//	           downloads nothing; a force push from B back to A, a new branch and a tag at A each hear `lfs objects
//	           missing`, naming O and `git lfs push --object-id`, evs's tip staying B; after that upload the force push
//	           commits, O's version fresh, and the branch and the tag land
//	race       O unpruned and its version past N: a prune held between its reads (tip B) and its removal
//	           (evs.lfs.prune.remove) while a force push to A touches O before its POST; the prune's removal fails
//	           path-level CAS and reruns, keeping O
//	skip       a commit whose new object is absent, pushed with --no-verify or with GIT_LFS_SKIP_PUSH=1, is refused
//	           alike, naming the object, evs's tip unmoved; the same commit pushed with neither commits
//	transports over git's http front on loopback and its ssh front (transport.go), an ordinary push storing its object
//	           through the agent, and a push with each skip option refused alike, then committed with neither
//	owned      an owned ref pushed while the device's mount is stopped, so its daemon takes the push and nothing
//	           publishes it, its object pruned meanwhile by a device holding every ref evs holds: once the mount runs
//	           again the queue's check before its first POST holds the entry, ur status naming the object and the
//	           hold; after `git lfs push --object-id`, ur evs retry publishes it
//	attributes a .gitattributes change that puts a stored pointer under filter=lfs checks its object: refused while
//	           the store lacks it, committed once another device stores it
//	import     ur evs import of a repository whose own git-lfs store holds its objects uploads them first, and another
//	           device's checkout of the imported ref smudges them
//	missing    a device whose replay of one ref fails refuses to prune (ErrEvsLfsPruneRefMissing), removing nothing;
//	           the same device, the ref readable, prunes
//	window     a settings file naming 3 days reads as 7: an object of a 5-day-old history is kept, of an 8-day-old one
//	           removed
//
// The twin, a tip check switched off in a sidecar_testhooks build (fs73_testhooks.go), lets the pruned clause's force
// push through, which the clause must catch.
//
// Left to the review phase and other hosts: git-remote-ur, whose ur binary is cli's module's and which no world here
// builds (the other clauses push over git's local transport, behind the same hooks and receive path the http and ssh
// fronts run); §22.9's older matrix rows where the host holds them; the purge following a prune, which evacuation's
// job runs (EVSB-M10-01) and which needs the store clock FS-73's catalog row names; ur status's own lines for a held
// ref, which are cli's.

package evsgit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// .gitattributes as `git lfs track "*.bin"` writes it.
const fs73Attributes = "*.bin filter=lfs diff=lfs merge=lfs -text\n"

// Holds the next arrival at a barrier site, <name> or <name>@<key> (sidecartest.BarrierSite), until release: arrived
// closes once one is held. T2's test gives one on its own barrier hook, and T3's on its Net's driver.
type Fs73Hold func(t testing.TB, site string) (arrived <-chan struct{}, release func())

// A device's evs settings for FS-73's clauses: FS-5's, receive waits short enough that an answer that cannot come comes
// back in a test's time.
func Fs73ClientSettings() *sidecar.EvsSettings {
	return Fs5ClientSettings()
}

// An object's content of byteCount bytes, from label, and its oid.
func fs73Object(label string, byteCount int) ([]byte, sidecar.EvsLfsOid) {
	content := make([]byte, 0, byteCount)
	for counter := 0; len(content) < byteCount; counter += 1 {
		block := sha256.Sum256(fmt.Appendf(nil, "%s %d", label, counter))
		content = append(content, block[:]...)
	}
	content = content[:byteCount]
	return content, sidecar.EvsLfsOid(sha256.Sum256(content))
}

// The pointer git-lfs's clean filter writes for content, byte for byte, as git-lfs documents it.
func fs73PointerOf(content []byte) string {
	return fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%x\nsize %d\n", sha256.Sum256(content), len(content))
}

// A content pointer for Commit's files.
func fs73Text(content []byte) *string {
	return Text(string(content))
}

// Pushes from a clone as Push does, with env added to git's.
func (self *Device) pushWith(dir string, env []string, args ...string) (string, bool) {
	session, closeSession := self.Mounts.OpenReceiveSession(self.Mount, self.Label)
	defer closeSession()
	return self.GitIn(dir, append(self.Mounts.ReceiveEnvironment(session), env...), append([]string{"push", "--porcelain"}, args...)...)
}

// The newest version of each object on ur/lfs, read fresh from evs.
func (self *Device) lfsNewest(t testing.TB, oids ...sidecar.EvsLfsOid) []*sidecar.EvsLfsObject {
	t.Helper()
	if self.Lfs == nil {
		t.Fatal("a world without git-lfs")
	}
	objects, err := self.Lfs.Newest(self.world.ctx, oids, true)
	if err != nil {
		t.Fatalf("ur/lfs's newest versions: %v", err)
	}
	return objects
}

// Whether a world's admin signed as sidecarId: what a prune holds the settings file's signer to.
func (self *World) isAdmin(sidecarId sidecar.Id, signedAt time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Contains(self.admins, sidecarId)
}

// The prune's window as the store's settings file sets it now, read by device.
func (self *World) fs73Window(t testing.TB, device *Device) time.Duration {
	t.Helper()
	window, err := device.Lfs.Window(self.ctx, self.isAdmin, func(err error) { t.Errorf("the settings file alarmed: %v", err) })
	if err != nil {
		t.Fatalf("the prune's window: %v", err)
	}
	return max(window, device.clientSettings.LfsPruneWindowFloor)
}

// The daily prune run by device, its start read the device's mount (sidecar.EvsLfsMountTips).
func (self *World) fs73Prune(ctx context.Context, device *Device) (*sidecar.EvsLfsPruneResult, error) {
	return sidecar.EvsLfsPrune(ctx, &sidecar.EvsLfsPruneArgs{
		Store:   device.Lfs,
		Git:     &sidecar.EvsLfsGitRepo{Git: device.Mount.GitRunner(), Dir: device.Mount.BareDir, Settings: device.clientSettings},
		Tips:    sidecar.EvsLfsMountTips(device.Mount, device.Client.Repo(self.repoId)),
		IsAdmin: self.isAdmin,
	})
}

// The uploads a device's daemon served for oid.
func fs73Uploads(calls []*LfsCall, oid sidecar.EvsLfsOid) []*LfsCall {
	uploads := []*LfsCall{}
	for _, call := range calls {
		if call.Oid == oid && !call.Download {
			uploads = append(uploads, call)
		}
	}
	return uploads
}

// The downloads a device's daemon served for oid.
func fs73Downloads(calls []*LfsCall, oid sidecar.EvsLfsOid) []*LfsCall {
	downloads := []*LfsCall{}
	for _, call := range calls {
		if call.Oid == oid && call.Download {
			downloads = append(downloads, call)
		}
	}
	return downloads
}

// Holds an update's answer to the tip check's refusal of oid: `lfs objects missing`, the upload command and the oid,
// with its prune's time when pruned.
func fs73RefusedMissing(t testing.TB, what string, out string, ok bool, oid sidecar.EvsLfsOid, pruned bool) {
	t.Helper()
	if ok || !strings.Contains(out, "lfs objects missing") || !strings.Contains(out, "git lfs push --object-id") || !strings.Contains(out, oid.String()) {
		t.Fatalf("%s: %v %s", what, ok, out)
	}
	if pruned && !strings.Contains(out, "pruned ") {
		t.Fatalf("%s names no prune: %s", what, out)
	}
}

// The store clause: see the file header.
func Fs73StoreAndSmudge(t testing.TB, world *World) {
	t.Helper()
	a, b := world.Device("fs73-store-a", nil), world.Device("fs73-store-b", nil)
	const branch = "fs73-store"
	small, smallOid := fs73Object("fs73 store small", 300)
	large, largeOid := fs73Object("fs73 store large", 40*1024)
	dirA := a.Clone()
	a.ResetLfsCalls()
	commit := a.Commit(dirA, "lfs objects", map[string]*string{
		".gitattributes": Text(fs73Attributes), "small.bin": fs73Text(small), "large.bin": fs73Text(large),
		"plain.txt": Text("not under filter=lfs\n"),
	})
	if out, ok := a.Push(dirA, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the push: %s", out)
	}
	// each object stored by the agent once, a creation, before the ref update the tip check let through
	calls := a.LfsCalls()
	created := map[sidecar.EvsLfsOid]uint64{}
	for _, oid := range []sidecar.EvsLfsOid{smallOid, largeOid} {
		uploads := fs73Uploads(calls, oid)
		if len(uploads) != 1 || uploads[0].Err != nil || !uploads[0].Created || uploads[0].Touched {
			t.Fatalf("%s's uploads %+v", oid, uploads)
		}
		created[oid] = uploads[0].Version
	}
	// no extra touch: each object's newest version is its creation's
	for _, object := range a.lfsNewest(t, smallOid, largeOid) {
		if !object.Present() || object.Version != created[object.Oid] {
			t.Fatalf("%s's newest version %+v after its creation at %d", object.Oid, object, created[object.Oid])
		}
	}
	// the pointer blobs, byte-exact, and export's oids, git's
	for name, content := range map[string][]byte{"small.bin": small, "large.bin": large} {
		if pointer := a.MustGit(dirA, "cat-file", "-p", "HEAD:"+name); pointer != fs73PointerOf(content) {
			t.Fatalf("%s's pointer blob %q", name, pointer)
		}
	}
	exportDir, tips := a.Export(branch)
	if tips["refs/heads/"+branch] != commit {
		t.Fatalf("export's tip %s, the commit %s", tips["refs/heads/"+branch], commit)
	}
	for _, name := range []string{".gitattributes", "small.bin", "large.bin", "plain.txt"} {
		want := strings.TrimSpace(a.MustGit(dirA, "rev-parse", "HEAD:"+name))
		if got := strings.TrimSpace(a.MustGit(exportDir, "rev-parse", "refs/heads/"+branch+":"+name)); got != want {
			t.Fatalf("export's oid of %s is %s, git's %s", name, got, want)
		}
	}
	// another device's checkout smudges each object through its agent
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.ResetLfsCalls()
	b.MustGit(dirB, "checkout", "-q", "-B", "work", "origin/"+branch)
	for name, content := range map[string][]byte{"small.bin": small, "large.bin": large} {
		if checkedOut := b.readFile(t, dirB, name); !bytes.Equal(checkedOut, content) {
			t.Fatalf("%s checked out as %d bytes, not its content", name, len(checkedOut))
		}
	}
	for _, oid := range []sidecar.EvsLfsOid{smallOid, largeOid} {
		if downloads := fs73Downloads(b.LfsCalls(), oid); len(downloads) != 1 || downloads[0].Err != nil {
			t.Fatalf("%s's downloads %+v", oid, downloads)
		}
	}
	// `git lfs push --object-id` of an object the store holds touches it, citing its content: no segment uploaded
	segmentPuts := &atomic.Int64{}
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/segments/") {
			segmentPuts.Add(1)
		}
		return nil, nil
	}, nil)
	defer world.SetIntercept(nil, nil)
	b.ResetLfsCalls()
	b.MustGit(dirB, "lfs", "push", "--object-id", "origin", smallOid.String())
	world.SetIntercept(nil, nil)
	if uploads := fs73Uploads(b.LfsCalls(), smallOid); len(uploads) != 1 || uploads[0].Err != nil || !uploads[0].Touched || uploads[0].Version <= created[smallOid] {
		t.Fatalf("the touch's uploads %+v after the creation at %d", uploads, created[smallOid])
	}
	if puts := segmentPuts.Load(); puts != 0 {
		t.Fatalf("the touch uploaded %d segments", puts)
	}
	content := &bytes.Buffer{}
	if _, err := b.Lfs.Get(world.ctx, smallOid, content); err != nil || !bytes.Equal(content.Bytes(), small) {
		t.Fatalf("the touched object reads %d bytes: %v", content.Len(), err)
	}
}

// The bytes of a clone's file.
func (self *Device) readFile(t testing.TB, dir string, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// The pruned clause: see the file header.
func Fs73PrunedHistory(t testing.TB, world *World) {
	t.Helper()
	fs73PrunedHistory(t, world, "fs73-pruned", nil)
}

// The pruned clause on branch and refs named after it, adjust called on the pushing device first: the twin switches its
// tip check off there.
func fs73PrunedHistory(t testing.TB, world *World, branch string, adjust func(device *Device)) {
	t.Helper()
	a := world.Device(branch+"-a", &DeviceSettings{Admin: true})
	if adjust != nil {
		adjust(a)
	}
	p, b := world.Device(branch+"-p", nil), world.Device(branch+"-b", nil)
	content, oid := fs73Object(branch+" object", 3000)
	dir := a.Clone()
	commitA := a.Commit(dir, "A holds O", map[string]*string{".gitattributes": Text(fs73Attributes), "o.bin": fs73Text(content)})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("A: %s", out)
	}
	commitB := a.Commit(dir, "B removes O", map[string]*string{"o.bin": nil})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("B: %s", out)
	}
	// A and O's last version aged past N, and a device holding every ref prunes O
	world.Jump(world.fs73Window(t, p) + 24*time.Hour)
	result, err := world.fs73Prune(world.ctx, p)
	if err != nil || !slices.Contains(result.Removed, oid) {
		t.Fatalf("the prune: %+v %v", result, err)
	}
	pruned := p.lfsNewest(t, oid)[0]
	if pruned.Present() || !pruned.Removed {
		t.Fatalf("O after the prune %+v", pruned)
	}

	// the old commit checks out with O's pointer: under lfs.skipdownloaderrors the agent names O and its prune
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.ResetLfsCalls()
	out, ok := b.GitIn(dirB, nil, "checkout", "-q", commitA)
	if !ok {
		t.Fatalf("A's checkout with O pruned: %s", out)
	}
	if !strings.Contains(out, oid.String()) || !strings.Contains(out, "pruned at") {
		t.Fatalf("A's checkout names no pruned object: %s", out)
	}
	if checkedOut := b.readFile(t, dirB, "o.bin"); string(checkedOut) != fs73PointerOf(content) {
		t.Fatalf("O checked out as %q", checkedOut)
	}
	if downloads := fs73Downloads(b.LfsCalls(), oid); len(downloads) == 0 || !errors.Is(downloads[0].Err, sidecar.ErrEvsLfsObjectMissing) {
		t.Fatalf("O's downloads %+v", downloads)
	}
	// and under GIT_LFS_SKIP_SMUDGE git-lfs asks for nothing
	dirSkip := b.Clone()
	b.ResetLfsCalls()
	if out, ok := b.GitIn(dirSkip, []string{"GIT_LFS_SKIP_SMUDGE=1"}, "checkout", "-q", commitA); !ok {
		t.Fatalf("A's checkout under GIT_LFS_SKIP_SMUDGE: %s", out)
	}
	if checkedOut := b.readFile(t, dirSkip, "o.bin"); string(checkedOut) != fs73PointerOf(content) {
		t.Fatalf("O checked out under GIT_LFS_SKIP_SMUDGE as %q", checkedOut)
	}
	if calls := b.LfsCalls(); len(calls) != 0 {
		t.Fatalf("GIT_LFS_SKIP_SMUDGE downloaded %+v", calls)
	}

	// a force push back to A, a new branch and a tag at A: git-lfs uploads nothing, since B reaches A, and the tip
	// check refuses each, naming O, evs's tip staying B
	out, ok = a.Push(dir, "--force", "origin", commitA+":refs/heads/"+branch)
	if ok {
		t.Fatalf("the force push to pruned history went through: %s", out)
	}
	fs73RefusedMissing(t, "the force push to A", out, ok, oid, true)
	out, ok = a.Push(dir, "origin", commitA+":refs/heads/"+branch+"-old")
	fs73RefusedMissing(t, "a new branch at A", out, ok, oid, true)
	a.MustGit(dir, "tag", branch+"-tag", commitA)
	out, ok = a.Push(dir, "origin", "refs/tags/"+branch+"-tag")
	fs73RefusedMissing(t, "a tag at A", out, ok, oid, true)
	if err := p.Replay(branch); err != nil {
		t.Fatal(err)
	}
	if tip := p.LocalRef("refs/heads/" + branch); tip != commitB {
		t.Fatalf("evs's tip is %s, not B %s", tip, commitB)
	}
	// evs names a branch without refs/heads/ and a tag by its whole name
	for _, name := range []string{branch + "-old", "refs/tags/" + branch + "-tag"} {
		refId, err := p.RefId(name)
		if err != nil {
			t.Fatal(err)
		}
		if summary := world.headSummary(t, p, refId); summary != nil && !summary.GetDeleted() {
			t.Fatalf("evs holds %s at version %d", name, summary.GetVersion())
		}
	}

	// after `git lfs push --object-id`, the same updates commit, O's version fresh
	a.ResetLfsCalls()
	a.MustGit(dir, "lfs", "push", "--object-id", "origin", oid.String())
	if uploads := fs73Uploads(a.LfsCalls(), oid); len(uploads) != 1 || uploads[0].Err != nil || !uploads[0].Created {
		t.Fatalf("O's upload %+v", uploads)
	}
	if out, ok := a.Push(dir, "--force", "origin", commitA+":refs/heads/"+branch); !ok {
		t.Fatalf("the force push after O's upload: %s", out)
	}
	if out, ok := a.Push(dir, "origin", commitA+":refs/heads/"+branch+"-old", "refs/tags/"+branch+"-tag"); !ok {
		t.Fatalf("the branch and the tag after O's upload: %s", out)
	}
	if err := p.Replay(branch); err != nil {
		t.Fatal(err)
	}
	if tip := p.LocalRef("refs/heads/" + branch); tip != commitA {
		t.Fatalf("evs's tip is %s, not A %s", tip, commitA)
	}
	fresh := p.lfsNewest(t, oid)[0]
	if !fresh.Present() || p.clientSettings.LfsFreshAge <= world.clock.Now().Sub(fresh.SignedAt) {
		t.Fatalf("O after its upload %+v", fresh)
	}
}

// The race clause: see the file header.
func Fs73PruneLosesToATouch(t testing.TB, world *World, hold Fs73Hold) {
	t.Helper()
	a := world.Device("fs73-race-a", &DeviceSettings{Admin: true})
	p := world.Device("fs73-race-p", nil)
	const branch = "fs73-race"
	content, oid := fs73Object("fs73 race", 2000)
	dir := a.Clone()
	commitA := a.Commit(dir, "A holds O", map[string]*string{".gitattributes": Text(fs73Attributes), "o.bin": fs73Text(content)})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("A: %s", out)
	}
	a.Commit(dir, "B removes O", map[string]*string{"o.bin": nil})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("B: %s", out)
	}
	world.Jump(world.fs73Window(t, p) + 24*time.Hour)
	stale := p.lfsNewest(t, oid)[0]
	if !stale.Present() {
		t.Fatalf("O before the prune %+v", stale)
	}

	// the prune held after its reads, O among what it removes
	arrived, release := hold(t, "evs.lfs.prune.remove")
	defer release()
	type pruneOutcome struct {
		result *sidecar.EvsLfsPruneResult
		err    error
	}
	outcomes := make(chan *pruneOutcome, 1)
	go func() {
		result, err := world.fs73Prune(world.ctx, p)
		outcomes <- &pruneOutcome{result: result, err: err}
	}()
	select {
	case <-arrived:
	case outcome := <-outcomes:
		t.Fatalf("the prune ended before its removal: %+v %v", outcome.result, outcome.err)
	case <-time.After(time.Minute):
		t.Fatal("the prune never reached its removal")
	}
	// the force push to A touches O before its POST
	if out, ok := a.Push(dir, "--force", "origin", commitA+":refs/heads/"+branch); !ok {
		t.Fatalf("the force push to A: %s", out)
	}
	touched := a.lfsNewest(t, oid)[0]
	if !touched.Present() || touched.Version <= stale.Version || a.clientSettings.LfsFreshAge <= world.clock.Now().Sub(touched.SignedAt) {
		t.Fatalf("O after the force push %+v, before it %+v", touched, stale)
	}
	release()
	var outcome *pruneOutcome
	select {
	case outcome = <-outcomes:
	case <-time.After(time.Minute):
		t.Fatal("the released prune never ended")
	}
	if outcome.err != nil || outcome.result.RerunCount < 1 || slices.Contains(outcome.result.Removed, oid) {
		t.Fatalf("the prune %+v %v", outcome.result, outcome.err)
	}
	if kept := p.lfsNewest(t, oid)[0]; !kept.Present() || kept.Version != touched.Version {
		t.Fatalf("O after the prune %+v, touched at %d", kept, touched.Version)
	}
}

// The skip clause: see the file header.
func Fs73SkipOptionsRefusedAlike(t testing.TB, world *World) {
	t.Helper()
	a, r := world.Device("fs73-skip", nil), world.Device("fs73-skip-r", nil)
	const branch = "fs73-skip"
	dir := a.Clone()
	tip := a.Commit(dir, "attributes", map[string]*string{".gitattributes": Text(fs73Attributes)})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the base: %s", out)
	}
	for _, option := range fs73SkipOptions() {
		content, oid := fs73Object("fs73 skip "+option.name, 1500)
		commit := a.Commit(dir, option.name, map[string]*string{option.name + ".bin": fs73Text(content)})
		a.ResetLfsCalls()
		out, ok := a.pushWith(dir, option.env, append(option.args, "origin", "HEAD:refs/heads/"+branch)...)
		fs73RefusedMissing(t, option.name, out, ok, oid, false)
		if calls := a.LfsCalls(); len(calls) != 0 {
			t.Fatalf("%s: git-lfs uploaded %+v", option.name, calls)
		}
		if err := r.Replay(branch); err != nil {
			t.Fatal(err)
		}
		if local := r.LocalRef("refs/heads/" + branch); local != tip {
			t.Fatalf("%s: evs's tip is %s, not %s", option.name, local, tip)
		}
		// the twin: neither option, and git-lfs uploads the object before the same update commits
		if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
			t.Fatalf("%s's commit with no skip option: %s", option.name, out)
		}
		if uploads := fs73Uploads(a.LfsCalls(), oid); len(uploads) != 1 || !uploads[0].Created {
			t.Fatalf("%s's object's uploads %+v", option.name, uploads)
		}
		if err := r.Replay(branch); err != nil {
			t.Fatal(err)
		}
		if local := r.LocalRef("refs/heads/" + branch); local != commit {
			t.Fatalf("%s: evs's tip is %s, not %s", option.name, local, commit)
		}
		tip = commit
	}
}

// One way a push leaves git-lfs's upload out.
type fs73SkipOption struct {
	name string
	args []string
	env  []string
}

// --no-verify, which skips git-lfs's pre-push hook, and GIT_LFS_SKIP_PUSH=1, which has it upload nothing.
func fs73SkipOptions() []*fs73SkipOption {
	return []*fs73SkipOption{
		{name: "no-verify", args: []string{"--no-verify"}},
		{name: "skip-push", env: []string{"GIT_LFS_SKIP_PUSH=1"}},
	}
}

// The transports clause: see the file header.
func Fs73OverHttpAndSsh(t testing.TB, world *World) {
	t.Helper()
	for _, transport := range []string{TransportHttp, TransportSsh} {
		d, r := world.Device("fs73-"+transport, nil), world.Device("fs73-"+transport+"-r", nil)
		branch := "fs73-" + transport
		dir := d.CloneOver(transport)
		push := func(env []string, args ...string) (string, bool) {
			return d.GitIn(dir, env, append([]string{"push", "--porcelain"}, append(args, "origin", "HEAD:refs/heads/"+branch)...)...)
		}
		evsTip := func() string {
			t.Helper()
			if err := r.Replay(branch); err != nil {
				t.Fatal(err)
			}
			return r.LocalRef("refs/heads/" + branch)
		}
		content, oid := fs73Object("fs73 "+transport, 2500)
		d.ResetLfsCalls()
		tip := d.Commit(dir, "over "+transport, map[string]*string{".gitattributes": Text(fs73Attributes), transport + ".bin": fs73Text(content)})
		if out, ok := push(nil); !ok {
			t.Fatalf("%s: the push: %s", transport, out)
		}
		if uploads := fs73Uploads(d.LfsCalls(), oid); len(uploads) != 1 || uploads[0].Err != nil || !uploads[0].Created {
			t.Fatalf("%s: the object's uploads %+v", transport, uploads)
		}
		if local := evsTip(); local != tip {
			t.Fatalf("%s: evs's tip is %s, not %s", transport, local, tip)
		}
		for _, option := range fs73SkipOptions() {
			skipped, skippedOid := fs73Object("fs73 "+transport+" "+option.name, 1700)
			commit := d.Commit(dir, option.name, map[string]*string{transport + "-" + option.name + ".bin": fs73Text(skipped)})
			out, ok := push(option.env, option.args...)
			fs73RefusedMissing(t, transport+" "+option.name, out, ok, skippedOid, false)
			if local := evsTip(); local != tip {
				t.Fatalf("%s %s: evs's tip is %s, not %s", transport, option.name, local, tip)
			}
			if out, ok := push(nil); !ok {
				t.Fatalf("%s %s's commit with no skip option: %s", transport, option.name, out)
			}
			if local := evsTip(); local != commit {
				t.Fatalf("%s %s: evs's tip is %s, not %s", transport, option.name, local, commit)
			}
			tip = commit
		}
	}
}

// The owned clause: see the file header.
func Fs73OwnedRefHoldsWhenPrunedMeanwhile(t testing.TB, world *World, hold Fs73Hold) {
	t.Helper()
	a, p := world.Device("fs73-owned-a", nil), world.Device("fs73-owned-p", nil)
	const base = "fs73-owned"
	owned := "ur/" + a.SidecarId.String() + "/fs73"
	content, oid := fs73Object("fs73 owned", 2200)
	dir := a.Clone()
	commitA := a.Commit(dir, "A holds O", map[string]*string{".gitattributes": Text(fs73Attributes), "o.bin": fs73Text(content)})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+base); !ok {
		t.Fatalf("A: %s", out)
	}
	a.Commit(dir, "B removes O", map[string]*string{"o.bin": nil})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+base); !ok {
		t.Fatalf("B: %s", out)
	}
	world.Jump(world.fs73Window(t, p) + 24*time.Hour)
	// offline: the device's mount stopped, so its daemon takes the owned ref's push at once and its queue publishes
	// nothing; git-lfs uploads nothing, since evs's base reaches A
	a.Stop()
	if out, ok := a.Push(dir, "origin", commitA+":refs/heads/"+owned); !ok {
		t.Fatalf("the owned ref's push, offline: %s", out)
	}
	// meanwhile a prune by a device holding every ref evs holds removes O, which no tip of them needs
	result, err := world.fs73Prune(world.ctx, p)
	if err != nil || !slices.Contains(result.Removed, oid) {
		t.Fatalf("the prune: %+v %v", result, err)
	}
	// online again: the queue's check before its first POST finds O missing and holds the entry, ur status naming it
	refId, err := a.RefId(owned)
	if err != nil {
		t.Fatal(err)
	}
	key := sidecar.EvsKeyId(world.repoId) + ":" + sidecar.EvsKeyId(refId)
	held, releaseHeld := hold(t, sidecartest.BarrierSite("evs.local.queue.held", key))
	defer releaseHeld()
	a.Start()
	select {
	case <-held:
	case <-time.After(time.Minute):
		t.Fatal("the owned ref's queue never held")
	}
	releaseHeld()
	statuses, err := a.Mount.Receiver().JournalStatus()
	if err != nil || len(statuses) != 1 || statuses[0].HoldCode != "lfs objects missing" || !slices.Equal(statuses[0].HoldLfsOids, []string{oid.String()}) {
		t.Fatalf("ur status of the held queue %+v %v", statuses, err)
	}
	if summary := world.headSummary(t, p, refId); summary != nil {
		t.Fatalf("evs holds the owned ref at version %d", summary.GetVersion())
	}
	// after the upload, ur evs retry releases the queue, which publishes A
	a.MustGit(dir, "lfs", "push", "--object-id", "origin", oid.String())
	applied, releaseApplied := hold(t, sidecartest.BarrierSite("evs.local.apply.done", key))
	defer releaseApplied()
	if released, err := a.Mount.Receiver().Retry(world.ctx, []byte(owned)); err != nil || len(released) != 1 {
		t.Fatalf("ur evs retry released %q %v", released, err)
	}
	select {
	case <-applied:
	case <-time.After(time.Minute):
		t.Fatal("the released queue's push never applied")
	}
	releaseApplied()
	if statuses, err := a.Mount.Receiver().JournalStatus(); err != nil || len(statuses) != 0 {
		t.Fatalf("ur status after the retry %+v %v", statuses, err)
	}
	if err := p.Replay(owned); err != nil {
		t.Fatal(err)
	}
	if tip := p.LocalRef("refs/heads/" + owned); tip != commitA {
		t.Fatalf("evs's owned ref is %q, not A %s", tip, commitA)
	}
}

// The attributes clause: see the file header.
func Fs73AttributesChangeChecksTheObject(t testing.TB, world *World) {
	t.Helper()
	a, b := world.Device("fs73-attributes", nil), world.Device("fs73-attributes-b", nil)
	const branch = "fs73-attributes"
	content, oid := fs73Object("fs73 attributes", 900)
	dir := a.Clone()
	// a pointer's text in a file no filter=lfs covers: an ordinary file, which needs no object; pushed with git-lfs's
	// hook skipped, as a client without git-lfs pushes, since git-lfs's own upload refuses a pointer it holds no
	// object of wherever it sits
	a.Commit(dir, "a pointer outside filter=lfs", map[string]*string{".gitattributes": Text(fs73Attributes), "stored.dat": Text(fs73PointerOf(content))})
	if out, ok := a.Push(dir, "--no-verify", "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the pointer outside filter=lfs: %s", out)
	}
	// the attributes put it under filter=lfs, and the tip check reads its object, which the store lacks
	a.Commit(dir, "dat under filter=lfs", map[string]*string{".gitattributes": Text(fs73Attributes + "*.dat filter=lfs diff=lfs merge=lfs -text\n")})
	out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch)
	fs73RefusedMissing(t, "the attributes change", out, ok, oid, false)
	// another device stores it, and the same update commits
	if _, err := b.Lfs.Put(world.ctx, oid, int64(len(content)), bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("the attributes change once its object is stored: %s", out)
	}
}

// The import clause: see the file header.
func Fs73ImportUploadsFirst(t testing.TB, world *World) {
	t.Helper()
	a, b := world.Device("fs73-import", &DeviceSettings{Admin: true}), world.Device("fs73-import-b", nil)
	const branch = "fs73-import"
	content, oid := fs73Object("fs73 import", 5000)
	// a repository of its own, its objects in its own git-lfs store alone
	parent := t.TempDir()
	dir := filepath.Join(parent, "imported")
	if out, ok := a.GitIn(parent, nil, "init", "-q", "-b", "main", dir); !ok {
		t.Fatalf("init: %s", out)
	}
	for _, setting := range [][]string{{"user.name", a.Label}, {"user.email", a.Email()}} {
		a.MustGit(dir, "config", setting[0], setting[1])
	}
	a.MustGit(dir, "lfs", "install", "--local")
	commit := a.Commit(dir, "imported", map[string]*string{".gitattributes": Text(fs73Attributes), "imported.bin": fs73Text(content)})
	if before := a.lfsNewest(t, oid)[0]; before.Present() {
		t.Fatalf("the store holds the imported object before the import %+v", before)
	}
	result, err := a.Client.Repo(world.repoId).Import(world.ctx, &sidecar.EvsImportArgs{Dir: dir, Ref: "HEAD", Target: []byte(branch)})
	if err != nil {
		t.Fatalf("the import: %v", err)
	}
	if result.Tip.String() != commit {
		t.Fatalf("the import ends at %s, not %s", result.Tip, commit)
	}
	if after := a.lfsNewest(t, oid)[0]; !after.Present() {
		t.Fatalf("the import stored no object %+v", after)
	}
	if err := b.Replay(branch); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.MustGit(dirB, "checkout", "-q", "-B", "work", "origin/"+branch)
	if checkedOut := b.readFile(t, dirB, "imported.bin"); !bytes.Equal(checkedOut, content) {
		t.Fatalf("the imported object checked out as %d bytes", len(checkedOut))
	}
}

// The missing clause: see the file header.
func Fs73PruneRefusesWithARefMissing(t testing.TB, world *World) {
	t.Helper()
	a := world.Device("fs73-missing-a", nil)
	const branch = "fs73-missing"
	content, oid := fs73Object("fs73 missing", 1200)
	dir := a.Clone()
	a.Commit(dir, "X holds M", map[string]*string{".gitattributes": Text(fs73Attributes), "m.bin": fs73Text(content)})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("X: %s", out)
	}
	a.Commit(dir, "Y removes M", map[string]*string{"m.bin": nil})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("Y: %s", out)
	}
	refId, err := a.RefId(branch)
	if err != nil {
		t.Fatal(err)
	}
	// the pruning device cannot replay the ref: every read naming it is lost
	refused := &atomic.Int64{}
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/read") || !fs73ReadNames(request, refId) {
			return nil, nil
		}
		refused.Add(1)
		return nil, errors.New("fs73: the ref is unreadable from this device")
	}, nil)
	defer world.SetIntercept(nil, nil)
	p := world.Device("fs73-missing-p", nil)
	world.Jump(world.fs73Window(t, p) + 24*time.Hour)
	if result, err := world.fs73Prune(world.ctx, p); !errors.Is(err, sidecar.ErrEvsLfsPruneRefMissing) {
		t.Fatalf("a prune missing a ref: %+v %v", result, err)
	}
	if refused.Load() == 0 {
		t.Fatal("the prune never tried to replay the missing ref")
	}
	if object := p.lfsNewest(t, oid)[0]; !object.Present() {
		t.Fatalf("a refused prune removed M %+v", object)
	}
	// the twin: the ref readable, the same device syncs it and prunes
	world.SetIntercept(nil, nil)
	result, err := world.fs73Prune(world.ctx, p)
	if err != nil || !slices.Contains(result.Removed, oid) {
		t.Fatalf("the prune with every ref readable: %+v %v", result, err)
	}
}

// Whether a read request names refId, as its ref or among a streams read's: the body read and put back.
func fs73ReadNames(request *http.Request, refId sidecar.Id) bool {
	if request.Body == nil {
		return false
	}
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	read := &protocol.EvsReadRequest{}
	if err := proto.Unmarshal(body, read); err != nil {
		return false
	}
	if bytes.Equal(read.GetRefId(), refId.Bytes()) {
		return true
	}
	return slices.ContainsFunc(read.GetRefs(), func(ref *protocol.EvsReadRef) bool { return bytes.Equal(ref.GetRefId(), refId.Bytes()) })
}

// The window clause: see the file header.
func Fs73WindowBelowSevenReadsAsSeven(t testing.TB, world *World) {
	t.Helper()
	a, p := world.Device("fs73-window", &DeviceSettings{Admin: true}), world.Device("fs73-window-p", nil)
	const branch = "fs73-window"
	ctx := world.ctx
	// a settings file naming 3 days, as a client that does not hold the command's floor would write it
	written, err := a.Client.Repo(world.repoId).WritePaths(ctx, &sidecar.EvsWritePathsArgs{RefName: sidecar.EvsLfsRefName, Writes: []*sidecar.EvsPathWrite{{
		Path: sidecar.EvsLfsSettingsPath, Content: bytes.NewReader(sidecar.EncodeEvsLfsSettings(3)),
		Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedLfs, Versioning: sidecar.EvsVersioningOn},
	}}})
	if err != nil {
		t.Fatalf("the settings file: %+v %v", written, err)
	}
	defer func() {
		// the default again, for the clauses after this one
		if _, err := a.Lfs.SetWindow(ctx, uint32(a.clientSettings.LfsPruneWindow/(24*time.Hour))); err != nil {
			t.Errorf("the settings file back to the default: %v", err)
		}
	}()
	if window := world.fs73Window(t, p); window != 7*24*time.Hour {
		t.Fatalf("3 days read as %s", window)
	}
	content, oid := fs73Object("fs73 window", 700)
	dir := a.Clone()
	a.Commit(dir, "W", map[string]*string{".gitattributes": Text(fs73Attributes), "w.bin": fs73Text(content)})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("W: %s", out)
	}
	a.Commit(dir, "W removed", map[string]*string{"w.bin": nil})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+branch); !ok {
		t.Fatalf("W removed: %s", out)
	}
	// 5 days on, inside 7 and past 3: kept
	world.Jump(5 * 24 * time.Hour)
	result, err := world.fs73Prune(ctx, p)
	if err != nil || slices.Contains(result.Removed, oid) || result.Window != 7*24*time.Hour {
		t.Fatalf("the prune 5 days on: %+v %v", result, err)
	}
	// 8 days on, past 7 and inside 30: removed
	world.Jump(3 * 24 * time.Hour)
	result, err = world.fs73Prune(ctx, p)
	if err != nil || !slices.Contains(result.Removed, oid) {
		t.Fatalf("the prune 8 days on: %+v %v", result, err)
	}
}

// evs's head summary of refId as device lists it, nil for a ref evs does not hold.
func (self *World) headSummary(t testing.TB, device *Device, refId sidecar.Id) *protocol.EvsHeadSummary {
	t.Helper()
	listing, err := device.Client.Repo(self.repoId).ListRefs(self.ctx, nil)
	if err != nil {
		t.Fatalf("the repo's refs: %v", err)
	}
	for _, summary := range listing.Refs {
		if bytes.Equal(summary.GetRefId(), refId.Bytes()) {
			return summary
		}
	}
	return nil
}
