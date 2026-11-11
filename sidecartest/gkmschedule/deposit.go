package gkmschedule

// FS-23's M2 case on T2 and T3 (KEYS-M2-28; I-15, D-KEYS-17, §10.5's depositor rule, DESIGN-DETAILS 6.2.5's DropKey): a
// deposit-only principal, an agent that only deposits, into a kind that takes deposits, here the team record, which
// §8.5 has autogroup:member and tagged subjects deposit into and its readers read, on the real subset. It fetches the
// drop key generation 1 publishes, follows a rotation to the next one, and is refused by every read route, its
// group, epochs, generations, group-info, its own ReaderWraps and the recovery read. Then, with evs's gate off, a
// server that serves it an older, unexpired GenRotate after a removal is refused by the depositor itself: the older
// drop key does not cover the shrink its own state shows, and its pin never falls; the honest answer is taken.
//
// The vault and mailbox cases are owner-bound kinds this world does not model; FS-23's mailbox case is M7's
// (KEYS-M7-01).

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The team record's world: a and b its readers and writers, a its creator and admin, and the depositor, an agent
// that only deposits.
func newFsKeysDepositWorld(t testing.TB, newWorld FsKeysNewWorld) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice) {
	world := newWorld(protocol.RepoKind_REPO_KIND_TEAM_RECORD)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	depositor := world.AddAgent("dep")
	world.Grant(true, a, b)
	world.Admin(a)
	world.Depositor(depositor)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	return world, a, b, depositor
}

// FS-23: the depositor takes generation 1's drop key, then generation 2's after a rotation; every read route refuses
// its deposit scope.
func FsKeysScheduleDepositor(t testing.TB, newWorld FsKeysNewWorld) {
	world, a, _, depositor := newFsKeysDepositWorld(t, newWorld)
	dropKey, err := depositor.Client.DropKey(world.Ctx, world.RepoId)
	if err != nil || dropKey.Generation != 1 || len(dropKey.PublicKey) == 0 {
		t.Fatalf("the depositor's first drop key: %v", err)
	}
	if !dropKey.NotAfter.After(world.Clock.Now()) {
		t.Errorf("a drop key already lapsed")
	}
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	rotated, err := depositor.Client.DropKey(world.Ctx, world.RepoId)
	if err != nil || rotated.Generation != 2 || string(rotated.PublicKey) == string(dropKey.PublicKey) {
		t.Fatalf("the depositor does not follow the rotation: %v", err)
	}

	// every other route refuses the deposit scope
	scope := "repo:" + world.RepoId.String() + ":deposit"
	group := "/gkm/groups/" + sidecar.EvsKeyId(world.GroupId)
	for _, route := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: group},
		{method: http.MethodGet, path: group + "/epochs?after=0"},
		{method: http.MethodGet, path: group + "/gen?since=0"},
		{method: http.MethodGet, path: group + "/group-info"},
		{method: http.MethodGet, path: group + "/wraps/2?recipient=" + fsKeysRecipient(depositor.SidecarId())},
		{method: http.MethodGet, path: "/gkm/repos/" + sidecar.EvsKeyId(world.RepoId) + "/forms"},
		{method: http.MethodGet, path: "/gkm/recovery/" + sidecar.EvsKeyId(world.MemberId) + "/wraps"},
	} {
		status := world.RawStatus(depositor, route.method, route.path, nil, scope)
		if status != http.StatusForbidden && status != http.StatusUnauthorized {
			t.Errorf("%s %s under a deposit scope: %d", route.method, route.path, status)
		}
	}
	if status := world.RawStatus(depositor, http.MethodGet, "/gkm/repos/"+sidecar.EvsKeyId(world.RepoId)+"/drop-key?since=0", nil, scope); status != http.StatusOK {
		t.Errorf("the drop-key route under the deposit scope: %d", status)
	}
	// and it holds no generation key: nothing was delivered to it
	if world.WrapRecipients(1)[depositor.SidecarId()] || world.WrapRecipients(2)[depositor.SidecarId()] {
		t.Errorf("a ReaderWrap to the depositor")
	}
}

// FS-23 with evs's gate off: after b's revocation and the REMOVE rotation, a server serving the depositor its older,
// unexpired GenRotates is refused by the depositor, which does not seal to a drop key that does not cover the shrink
// its own state shows; the honest answer is taken; and once it holds generation 3's, a replay of the older one is
// below its pin and refused.
func FsKeysScheduleDepositorReplay(t testing.TB, newWorld FsKeysNewWorld) {
	world, a, b, depositor := newFsKeysDepositWorld(t, newWorld)
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	// the generations gkm serves before the removal, which a replaying server keeps
	before := []*bridge.Signed{}
	for generation := uint64(1); generation <= 2; generation += 1 {
		before = append(before, world.Generation(generation).Signed)
	}
	world.Revoke(b)
	world.Advance()
	if key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Generation() != 3 {
		t.Fatalf("the REMOVE rotation: %v", err)
	}
	// the replaying server answers the drop-key route from what it kept, after the since asked
	replay := func(request *http.Request) *http.Response {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/drop-key") {
			return nil
		}
		since, err := strconv.ParseUint(request.URL.Query().Get("since"), 10, 64)
		if err != nil {
			t.Fatalf("a drop-key read's since: %v", err)
		}
		reply := &protocol.GkmGenerationsReply{}
		if since < uint64(len(before)) {
			reply.Generations = before[since:]
		}
		return FsKeysAnswer(reply)
	}
	depositor.Transport.Respond = replay
	if _, err := depositor.Client.DropKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("an older drop key after the removal: %v", err)
	}
	depositor.Transport.Respond = nil
	dropKey, err := depositor.Client.DropKey(world.Ctx, world.RepoId)
	if err != nil || dropKey.Generation != 3 {
		t.Fatalf("the honest drop key: %v", err)
	}
	depositor.Transport.Respond = replay
	if _, err := depositor.Client.DropKey(world.Ctx, world.RepoId); err == nil {
		t.Errorf("a replayed older drop key below the depositor's pin was taken")
	}
	depositor.Transport.Respond = nil
}
