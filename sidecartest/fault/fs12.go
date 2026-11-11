// FS-12 (§22.8; §11.10's lease, match, hint and loss rows, R-EVS-2, D-EVS-14; EVS1-M2-41) on the evs world
// (evs_world.go, evs_world_hints.go): a subscription misses no commit, whatever became of its lease, since hints only
// speed up what the holder's own reads catch.
//
// The registered case, Fs12LeaseCrashAndReread: writerA writes a.txt; the reader subscribes to main through evsr,
// which crashes after the lease's Redis write and before its 200, so the lease stands in Redis while the client, its
// instance gone, keeps it owed; evsr starts again from the stores and, past the client's retry wait, the reader's next
// round leases until 200; writerA's b.txt commits before the reader's 5 s reread with its hint lost at the push fake
// and its head-cache write failed in Redis, so nothing tells the reader and the cache is a version behind, and the
// reread, fresh, catches b.txt 5 s on; writerB's c.txt, 6 s after the 200, is hinted to the reader, handed over, and
// its round reads it; the lease family is lost, and writerA's d.txt is hinted to no one; an hour on the reader's
// resync reads main fresh, catching d.txt, finds its lease gone and leases again at its next round, and writerB's
// e.txt is hinted and read. FS-12 refuses nothing, so it has no twin.
//
// The subscriber's rounds run on the reader's actor, one a step (evs_world_hints.go): the world answers every wait at
// once, so a schedule drives what StartSubscriptions's loop would. Not here: the lease renewal past 24 h, the
// re-lease under a new path epoch (FS-4's last clause), a hint coalesced inside its repo's 100 ms, and FS-12 with
// several holders and prefixes.

package fault

import (
	"context"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs12 = Register("FS-12", "", []Tier{TierT2, TierT3}, Fs12LeaseCrashAndReread)

// §20.4's evs_subscribers_per_repo for the world's network, which the lease route reads before it writes.
const fs12SubscribersPerRepo = 16

// See the file header.
func Fs12LeaseCrashAndReread(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "admin", Action: world.SetQuotaLimits(map[string]int64{"evs_subscribers_per_repo": fs12SubscribersPerRepo})},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs12 a", 100))},
		// the lease's write lands and evsr dies before its 200
		{Fault: &FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: evsservice.LeaseKey(world.RepoId), Result: CrashAfterApply, Actor: "evsr", WritesOnly: true}},
		{Actor: "reader", Action: world.Subscribe("reader"), Background: true},
		{Actor: "evsr", Await: FaultFired},
		{Actor: "evsr", Kill: true},
		// the client's tries meet no instance, and the lease stays owed
		{Actor: "reader", Join: true},
		{Actor: "check", Action: world.ExpectLease("reader", true)},
		{Actor: "evsr", Restart: "evsr"},
		// past the client's retry wait, which doubles from 1 s to SubscribeRetryMaxWait's 5 min
		{Advance: 5 * time.Minute},
		{Actor: "reader", Action: world.SubscriptionRound("reader")},
		{Actor: "check", Action: world.ExpectLease("reader", true)},
		// a commit before the 5 s reread, hinted to no one and its head-cache write failed
		{Fault: &FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "push.Hint", Result: FailBeforeApply}},
		{Fault: &FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: evsservice.HeadCacheKey(world.RepoId), Result: FailBeforeApply, WritesOnly: true}},
		{Advance: time.Second},
		{Actor: "writerA", Action: world.Write("writerA", "b.txt", EvsWorldContent("fs12 b", 100))},
		{Actor: "reader", Action: world.DeliverHints("reader")},
		{Actor: "check", Action: world.ExpectHinted("reader", "b.txt", false)},
		{Advance: 4 * time.Second},
		{Actor: "reader", Action: world.SubscriptionRound("reader")},
		{Actor: "check", Action: world.ExpectChange("reader", "b.txt")},
		// 6 s after the 200: hinted
		{Advance: time.Second},
		{Actor: "writerB", Action: world.Write("writerB", "c.txt", EvsWorldContent("fs12 c", 100))},
		{Actor: "reader", Action: world.DeliverHints("reader")},
		{Actor: "check", Action: world.ExpectHinted("reader", "c.txt", true)},
		{Actor: "reader", Action: world.SubscriptionRound("reader")},
		{Actor: "check", Action: world.ExpectChange("reader", "c.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "a.txt", "b.txt", "c.txt")},
		// the lease family lost: no hint, and the hourly resync re-creates the lease
		{Actor: "admin", Action: world.LoseLeases()},
		{Actor: "check", Action: world.ExpectLease("reader", false)},
		{Actor: "writerA", Action: world.Write("writerA", "d.txt", EvsWorldContent("fs12 d", 100))},
		{Actor: "reader", Action: world.DeliverHints("reader")},
		{Actor: "check", Action: world.ExpectHinted("reader", "d.txt", false)},
		{Advance: time.Hour},
		{Actor: "reader", Action: world.SubscriptionRound("reader")},
		{Actor: "check", Action: world.ExpectChange("reader", "d.txt")},
		{Actor: "reader", Action: world.SubscriptionRound("reader")},
		{Actor: "check", Action: world.ExpectLease("reader", true)},
		{Actor: "writerB", Action: world.Write("writerB", "e.txt", EvsWorldContent("fs12 e", 100))},
		{Actor: "reader", Action: world.DeliverHints("reader")},
		{Actor: "check", Action: world.ExpectHinted("reader", "e.txt", true)},
		{Actor: "reader", Action: world.SubscriptionRound("reader")},
		{Actor: "check", Action: world.ExpectChange("reader", "e.txt")},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.txt", "c.txt", "d.txt", "e.txt")},
	}
	return &Schedule{Id: "FS-12", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: the network's §20.4 limits as the host's quota answers them, which the lease route's cap reads.
func (self *EvsWorld) SetQuotaLimits(limits map[string]int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		net.Fakes().Quota.SetLimits(connect.Id(self.NetworkId), &sidecar.QuotaLimits{Limits: limits})
		return nil
	}
}
