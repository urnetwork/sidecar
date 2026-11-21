//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M10-01's restore points under an executed drop (§16.7, §5.9's dropped row; D-CORE-19, D-MCP-8, FI-8), on a real
// worktree: the holder the points hand a network removes each sealed base copy and each held copy whose bytes only
// the drop's listed versions hold, in a point open in this process and in one on disk alone, so run_restore's dry run
// names the path dropped and an apply restores nothing of it, while a copy whose bytes a live version shares stays and
// restores. Sidecar.ApplyExecutedDrop's reach of its holders is CORE's TestDropDeletesRestorePointCopy.

package mcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A network as the points' drop holder reaches it: its store and identity, its holders kept for the test to apply.
type testRestoreDropHost struct {
	network  *fakeMcpNetwork
	identity *sidecar.SidecarIdentity

	stateLock sync.Mutex
	holders   []sidecar.SidecarDropHolder
}

func (self *testRestoreDropHost) AddDropHolder(holder sidecar.SidecarDropHolder) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holders = append(self.holders, holder)
	return func() {}, nil
}

func (self *testRestoreDropHost) LocalStore() sidecar.SidecarStore {
	return self.network.LocalStore()
}

func (self *testRestoreDropHost) Identity() *sidecar.SidecarIdentity {
	return self.identity
}

// Applies drop to every holder, as Sidecar.ApplyExecutedDrop does.
func (self *testRestoreDropHost) apply(t *testing.T, drop *sidecar.SidecarExecutedDrop) {
	t.Helper()
	self.stateLock.Lock()
	holders := slices.Clone(self.holders)
	self.stateLock.Unlock()
	for _, holder := range holders {
		if err := holder.ApplyExecutedDrop(t.Context(), drop); err != nil {
			t.Fatal(err)
		}
	}
}

// An executed drop listing versions of contents, those of live a live version shares.
func testRestoreDrop(contents []string, live []string) *sidecar.SidecarExecutedDrop {
	drop := &sidecar.SidecarExecutedDrop{RepoId: sidecar.NewId(), RefId: sidecar.NewId(), DropId: sidecar.NewId()}
	for i, content := range contents {
		drop.Versions = append(drop.Versions, &sidecar.SidecarDroppedVersion{Path: "src/file", Version: uint64(i + 1), ContentSha256: sha256.Sum256([]byte(content))})
	}
	liveSums := [][]byte{}
	for _, content := range live {
		sum := sha256.Sum256([]byte(content))
		liveSums = append(liveSums, sum[:])
	}
	drop.Live = func(ctx context.Context, object sidecar.SidecarDropObject) (bool, error) {
		return slices.ContainsFunc(liveSums, func(sum []byte) bool { return string(sum) == string(object.Id) }), nil
	}
	return drop
}

// A path whose needed version is dropped reports dropped and is never partly restored (FI-8): its base copy goes with
// the drop, the dry run naming it dropped and an apply leaving it as it stands, while a copy a live version shares
// stays and restores; a held copy of dropped bytes goes too, and a second application removes nothing more.
func TestRestoreDroppedConflict(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("draft.txt", "a draft only the drop's versions held\n")
	env.write("shared.txt", "a draft a live version shares\n")
	point := env.open()
	env.hookedWrite("toolu_1", "draft.txt", "edited\n")
	env.hookedWrite("toolu_2", "shared.txt", "edited too\n")
	host := &testRestoreDropHost{network: env.network, identity: &sidecar.SidecarIdentity{NetworkId: env.networkId, SidecarId: sidecar.NewId()}}
	if _, err := env.points.AddDropHolder(host); err != nil {
		t.Fatal(err)
	}
	draftBase, err := point.BaseOf(context.Background(), "draft.txt")
	if err != nil || draftBase.Copy == "" {
		t.Fatalf("the draft's base %+v %v", draftBase, err)
	}
	sharedBase, err := point.BaseOf(context.Background(), "shared.txt")
	if err != nil || sharedBase.Copy == "" {
		t.Fatalf("the shared draft's base %+v %v", sharedBase, err)
	}
	// a hold of dropped bytes the next PreToolUse takes
	input := map[string]any{"file_path": env.dir + "/draft.txt", "content": "again\n"}
	env.write("draft.txt", "a draft only the drop's versions held\n")
	env.preToolUse("Write", "toolu_3", input)
	held := func() []string {
		names := []string{}
		point.stateLock.Lock()
		defer point.stateLock.Unlock()
		for _, hold := range point.holds {
			for _, file := range hold.files {
				if file.copyName != "" {
					names = append(names, file.copyName)
				}
			}
		}
		return names
	}()
	if len(held) == 0 {
		t.Fatal("the PreToolUse held no copy")
	}
	present := func(name string) bool {
		ok, err := point.copyPresent(name)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, name := range held {
		if !present(name) {
			t.Fatalf("the held copy %s is not in the point", name)
		}
	}

	// the drop executes while the hold is live
	drop := testRestoreDrop([]string{"a draft only the drop's versions held\n", "a draft a live version shares\n"}, []string{"a draft a live version shares\n"})
	host.apply(t, drop)
	if present(draftBase.Copy) || !present(sharedBase.Copy) {
		t.Fatalf("after the drop: the draft's copy %v, the shared one's %v", present(draftBase.Copy), present(sharedBase.Copy))
	}
	for _, name := range held {
		if present(name) {
			t.Errorf("the held copy %s of dropped bytes stayed", name)
		}
	}
	// the edit's before is then unknown, and the scan goes on
	env.write("draft.txt", "edited\n")
	env.postToolUse("Write", "toolu_3", input)

	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	refused := slices.ContainsFunc(plan.Refusals, func(refusal *RestoreRefusal) bool {
		return refusal.Path == "draft.txt" && refusal.Reason == RestoreReasonDropped
	})
	if !refused || !slices.ContainsFunc(plan.Entries, func(entry *RestorePreviewEntry) bool { return entry.Path == "shared.txt" }) {
		t.Fatalf("the dry run after the drop: %+v %+v", plan.Entries, plan.Refusals)
	}
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := restoreTestOutcome(t, result, "shared.txt"); outcome.Result != "restored" {
		t.Errorf("the shared draft: %+v", outcome)
	}
	if got := string(env.read("draft.txt")); got != "edited\n" {
		t.Errorf("the dropped draft was touched: %q", got)
	}
	if got := string(env.read("shared.txt")); got != "a draft a live version shares\n" {
		t.Errorf("the shared draft: %q", got)
	}
	// once more, nothing more to remove
	host.apply(t, drop)
	if !present(sharedBase.Copy) {
		t.Error("a second application removed a live version's copy")
	}
}

// A point no process holds open, after a restart, loses its copy of dropped bytes all the same: the holder reads
// every run's point the network's store holds, and the point opened later names the path dropped.
func TestRestoreDropReachesAPointOnDiskAlone(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("draft.txt", "a draft only the drop's versions held\n")
	env.open()
	env.hookedWrite("toolu_1", "draft.txt", "edited\n")
	// a restart: a registry holding nothing open
	env.points = env.newPoints()
	host := &testRestoreDropHost{network: env.network, identity: &sidecar.SidecarIdentity{NetworkId: env.networkId, SidecarId: sidecar.NewId()}}
	if _, err := env.points.AddDropHolder(host); err != nil {
		t.Fatal(err)
	}
	host.apply(t, testRestoreDrop([]string{"a draft only the drop's versions held\n"}, nil))
	point := env.open()
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 0 || !slices.ContainsFunc(plan.Refusals, func(refusal *RestoreRefusal) bool {
		return refusal.Path == "draft.txt" && refusal.Reason == RestoreReasonDropped
	}) {
		t.Fatalf("the reopened point's dry run: %+v %+v", plan.Entries, plan.Refusals)
	}
}

// A drop whose liveness cannot be answered keeps every copy, and says so.
func TestRestoreDropKeepsWhatItCannotJudge(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("draft.txt", "a draft only the drop's versions held\n")
	point := env.open()
	host := &testRestoreDropHost{network: env.network, identity: &sidecar.SidecarIdentity{NetworkId: env.networkId, SidecarId: sidecar.NewId()}}
	env.points.AddDropHolder(host)
	base, err := point.BaseOf(context.Background(), "draft.txt")
	if err != nil || base.Copy == "" {
		t.Fatalf("base %+v %v", base, err)
	}
	drop := testRestoreDrop([]string{"a draft only the drop's versions held\n"}, nil)
	failure := errors.New("the mirror cannot be read")
	drop.Live = func(ctx context.Context, object sidecar.SidecarDropObject) (bool, error) { return false, failure }
	host.stateLock.Lock()
	holder := host.holders[0]
	host.stateLock.Unlock()
	if err := holder.ApplyExecutedDrop(t.Context(), drop); !errors.Is(err, failure) {
		t.Errorf("an unanswerable drop: %v", err)
	}
	if ok, err := point.copyPresent(base.Copy); err != nil || !ok {
		t.Errorf("a copy the drop could not judge went: %v %v", ok, err)
	}
}
