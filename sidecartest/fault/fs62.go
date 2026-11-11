// FS-62 (§22.8; §11.9's head cache, §11.10's sequence and leases, §10.6's acks, owner decision 136; EVS1-M2-41) on the
// evs world (evs_world.go): Redis holds only soft state, so losing it costs reads and never correctness.
//
// The registered case, Fs62SoftStateLost: two commits raise the repo's push sequence and fill its head cache, and
// the reader reads through the cache; the clock moves on, and {evsq_}, {evsl_}, {evsh_} and the group's {gka_} are
// lost together; the reader's cached read misses and is served from the cluster's head; the next commit's sequence
// is above every earlier one, seeded again from the store's clock; and no device alarms, a lower version included.
//
// FS-62's lease holders re-creating their leases at the hourly resync and missing no later commit, a reader with a
// newer pin sent past a stale cached head, a ref cached over 10 min ago not served while another ref writes, a push
// with a stale cached ETag failing step 7 at one cluster read, FS-1 with {evsh_} a version behind, {acl_} lost and
// stale, the epoch reconciler deleting nothing for 30 d, and the exact sequence vectors through the real publisher on
// every leg are EVS1-M2-41's report's: the world's devices hold no subscription, since a subscriber's loop waits on a
// clock the world answers at once.

package fault

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs62 = Register("FS-62", "", []Tier{TierT2, TierT3}, Fs62SoftStateLost)

// See the file header.
func Fs62SoftStateLost(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	sequenceBefore := uint64(0)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs62 a", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "b.txt", EvsWorldContent("fs62 b", 200))},
		{Actor: "reader", Action: world.VerifyCached("reader", "a.txt", "b.txt")},
		{Actor: "check", Action: world.Expect("the push sequence stands", func(ctx context.Context) error {
			sequence, err := world.PushSequence(ctx)
			if err != nil {
				return err
			}
			if sequence == 0 {
				return errors.New("no push sequence after two commits")
			}
			sequenceBefore = sequence
			return nil
		})},
		{Advance: time.Second},
		{Actor: "admin", Action: world.LoseSoftState()},
		{Actor: "reader", Action: world.VerifyCached("reader", "a.txt", "b.txt")},
		{Actor: "writerB", Action: world.Write("writerB", "c.txt", EvsWorldContent("fs62 c", 200))},
		{Actor: "check", Action: world.Expect("the next sequence is above every earlier one", func(ctx context.Context) error {
			sequence, err := world.PushSequence(ctx)
			if err != nil {
				return err
			}
			if sequence <= sequenceBefore {
				return fmt.Errorf("the sequence %d after the loss, at or below %d before it", sequence, sequenceBefore)
			}
			return nil
		})},
		{Actor: "reader", Action: world.VerifyCached("reader", "a.txt", "b.txt", "c.txt")},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.txt", "c.txt")},
	}
	return &Schedule{Id: "FS-62", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// The repo's push sequence as {evsq_<repo_id>} holds it, 0 while absent, read under an inspecting context.
func (self *EvsWorld) PushSequence(ctx context.Context) (uint64, error) {
	value, found, err := self.redisValue(ctx, evsservice.PushSequenceKey(self.RepoId))
	if err != nil || !found {
		return 0, err
	}
	return strconv.ParseUint(string(value), 10, 64)
}

// A key's value through the Net's host Redis, under an inspecting context.
func (self *EvsWorld) redisValue(ctx context.Context, key string) ([]byte, bool, error) {
	values, err := self.net.Host().Redis.GetMany(sidecartest.InspectContext(ctx), []string{key})
	if err != nil {
		return nil, false, err
	}
	if len(values) != 1 || values[0] == nil {
		return nil, false, nil
	}
	return values[0], true, nil
}

// A step action: the repo's soft state in Redis is lost at once, the push sequence, the leases, the head cache and
// its group's acks, as a Redis restart loses them, under an inspecting context, so it is no write of the row's.
func (self *EvsWorld) LoseSoftState() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		keys := []string{
			evsservice.PushSequenceKey(self.RepoId),
			evsservice.LeaseKey(self.RepoId),
			evsservice.HeadCacheKey(self.RepoId),
		}
		self.stateLock.Lock()
		gkm := self.gkm
		self.stateLock.Unlock()
		if groupId, _, ok := gkm.Newest(self.RepoId); ok {
			keys = append(keys, gkmservice.GkmAckRedisKey(groupId))
		}
		redis := net.Host().Redis
		for _, key := range keys {
			// one key a call: each family is a slot of its own
			if err := redis.Delete(sidecartest.InspectContext(ctx), []string{key}); err != nil {
				return fmt.Errorf("losing %s: %w", key, err)
			}
		}
		return nil
	}
}
