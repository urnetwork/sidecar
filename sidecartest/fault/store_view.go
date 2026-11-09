// The oracle's store view (TEST-M2-01; D-TEST-10, FI-1): §22.8's "an oracle with read access to every store checks
// the named invariants after every step and at the end". One view over T2's fakes and T3's real stores alike, since
// it reads only what the Net's host holds:
//
//   - every cluster's objects, each read under sidecartest.InspectContext, so a look takes no fault plan, counts
//     toward no plan's Nth, adds nothing to the blob history FI-30 reads, and moves no schedule;
//   - Redis, through the same context;
//   - at T3, Postgres, through the reader server's sidecart3 sets on the Net (NetSettings.Postgres); T2 has none;
//   - the authorization log, proj/<network_id>/ on the first metadata cluster (§7.9);
//   - each reader's keys, which the Net held from testHookSecret as each actor created, derived or unwrapped them,
//     so Open gives an oracle a generation's key only where that reader held one, and fails otherwise.
//
// It decodes with the format's own decoders, protocol/EVS-FORMAT.md's keys and the proto messages, and the root's
// byte codecs, never evsservice's behaviour: an oracle sharing evs's push or fold logic would share its bugs.
//
// Reads are whole: List pages through a prefix, and Objects reads each object it lists. An invariant reads only
// what a step can have changed (Oracle.Changed), or a 60-step row walks a large store 60 times.
//
// Safe for concurrent use; it holds no state of its own beyond the Net's.

package fault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	// A reader asked to open what it never held.
	ErrStoreViewNotHeld = errors.New("the reader never held the key")
	// A view asked for a store its tier does not have: Postgres on T2.
	ErrStoreViewNoStore = errors.New("this tier has no such store")
)

// The tunables of a view.
type StoreViewSettings struct {
	// How many keys one List request asks for: the store's page, 1,000.
	ListLimit int
	// T3's Postgres; nil takes the Net's, which sidecart3 sets and T2 leaves nil.
	Postgres sidecartest.PostgresReader
}

func DefaultStoreViewSettings() *StoreViewSettings {
	return &StoreViewSettings{
		ListLimit: 1000,
	}
}

type StoreView struct {
	net      *Net
	settings *StoreViewSettings
}

// A view over net's host and the keys its actors held. settings nil takes the defaults.
func NewStoreView(net *Net, settings *StoreViewSettings) *StoreView {
	if settings == nil {
		settings = DefaultStoreViewSettings()
	}
	if settings.Postgres == nil {
		settingsCopy := *settings
		settingsCopy.Postgres = net.Postgres()
		settings = &settingsCopy
	}
	return &StoreView{net: net, settings: settings}
}

// One object as the view read it, its bytes whole.
type StoreObject struct {
	ClusterId    string
	Key          string
	Etag         string
	LastModified time.Time
	Metadata     map[string]string
	Body         []byte
}

// The host's clusters: every metadata cluster, the first first, then the segment cluster.
func (self *StoreView) ClusterIds() ([]string, error) {
	blobs := self.net.Host().Blobs
	clusterIds := slices.Clone(blobs.MetadataClusterIds())
	segment, err := blobs.SegmentCluster()
	if err != nil {
		return nil, err
	}
	if !slices.Contains(clusterIds, segment.ClusterId()) {
		clusterIds = append(clusterIds, segment.ClusterId())
	}
	return clusterIds, nil
}

func (self *StoreView) cluster(clusterId string) (sidecar.BlobCluster, error) {
	return self.net.Host().Blobs.Cluster(clusterId)
}

// The first metadata cluster's id: where place/, proj/, projrows/ and gkm/ live.
func (self *StoreView) FirstClusterId() (string, error) {
	first, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		return "", err
	}
	return first.ClusterId(), nil
}

// key on clusterId, read under InspectContext; nil with no error when it is not there.
func (self *StoreView) Object(ctx context.Context, clusterId string, key string) (*StoreObject, error) {
	cluster, err := self.cluster(clusterId)
	if err != nil {
		return nil, err
	}
	object, err := cluster.Get(sidecartest.InspectContext(ctx), key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", clusterId, key, err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", clusterId, key, err)
	}
	return &StoreObject{
		ClusterId:    clusterId,
		Key:          key,
		Etag:         object.Etag,
		LastModified: object.LastModified,
		Metadata:     object.Metadata,
		Body:         body,
	}, nil
}

// Every key under prefix on clusterId, ascending, every page read.
func (self *StoreView) List(ctx context.Context, clusterId string, prefix string) ([]*sidecar.BlobInfo, error) {
	cluster, err := self.cluster(clusterId)
	if err != nil {
		return nil, err
	}
	inspect := sidecartest.InspectContext(ctx)
	infos := []*sidecar.BlobInfo{}
	startAfter := ""
	for {
		page, more, err := cluster.List(inspect, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return nil, fmt.Errorf("%s list %s: %w", clusterId, prefix, err)
		}
		infos = append(infos, page...)
		if !more || len(page) == 0 {
			return infos, nil
		}
		startAfter = page[len(page)-1].Key
	}
}

// Every object under prefix on clusterId, each read whole. One deleted between the list and its read is left out,
// as a reader would find it gone.
func (self *StoreView) Objects(ctx context.Context, clusterId string, prefix string) ([]*StoreObject, error) {
	infos, err := self.List(ctx, clusterId, prefix)
	if err != nil {
		return nil, err
	}
	objects := []*StoreObject{}
	for _, info := range infos {
		object, err := self.Object(ctx, clusterId, info.Key)
		if err != nil {
			return nil, err
		}
		if object != nil {
			objects = append(objects, object)
		}
	}
	return objects, nil
}

// The metadata cluster a repo was placed on, from place/ (§11.8); ErrEvsRepoNotPlaced when it has none.
func (self *StoreView) RepoClusterId(ctx context.Context, repoId sidecar.Id) (string, error) {
	first, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		return "", err
	}
	place, err := sidecar.ReadEvsRepoPlace(sidecartest.InspectContext(ctx), first, repoId)
	if err != nil {
		return "", err
	}
	return place.ClusterId, nil
}

// The host's Redis, every read under InspectContext, so a look takes no plan and counts nothing, and every write
// refused.
func (self *StoreView) Redis() sidecar.Redis {
	return &inspectRedis{redis: self.net.Host().Redis}
}

// T3's Postgres, or ErrStoreViewNoStore on T2.
func (self *StoreView) Postgres(ctx context.Context, query string, args ...any) ([][]any, error) {
	if self.settings.Postgres == nil {
		return nil, ErrStoreViewNoStore
	}
	return self.settings.Postgres.Rows(ctx, query, args...)
}

// The keys the Net's actors held, by actor.
func (self *StoreView) HeldSecrets() *sidecartest.HeldSecrets {
	return self.net.HeldSecrets()
}

// Generation g's key as reader holds it, or as a current reader reaches it: an RK_g reader held whose commitment
// matches gen/<g>, or one matching a later generation of ladder, opened down the ladder through each GenLink to g
// (§10.5). ladder is the group's generations, as Generations reads them. A reader that held none of them gets
// ErrStoreViewNotHeld, which is what a removed reader's open must get.
func (self *StoreView) Open(reader string, ladder []*sidecar.GkmGeneration, generation uint64) (*sidecar.EvsRepoKey, error) {
	byGeneration := map[uint64]*sidecar.GkmGeneration{}
	newest := uint64(0)
	for _, each := range ladder {
		if each == nil || each.Rotate == nil {
			continue
		}
		byGeneration[each.Rotate.GetGeneration()] = each
		newest = max(newest, each.Rotate.GetGeneration())
	}
	if byGeneration[generation] == nil {
		return nil, fmt.Errorf("%w: the ladder holds no gen/%d", sidecar.ErrGkmKeyMissing, generation)
	}
	held := self.net.HeldSecrets().Secrets(reader, "RK_g")
	for top := generation; top <= newest; top += 1 {
		topGeneration := byGeneration[top]
		if topGeneration == nil {
			continue
		}
		for _, secret := range held {
			key, err := sidecar.OpenEvsRepoKey(topGeneration, secret)
			if err != nil {
				continue
			}
			for key.Generation() > generation {
				parent := byGeneration[key.Generation()-1]
				if parent == nil {
					return nil, fmt.Errorf("%w: the ladder holds no gen/%d below gen/%d", sidecar.ErrGkmKeyMissing, key.Generation()-1, key.Generation())
				}
				key, err = key.OpenParent(parent)
				if err != nil {
					return nil, err
				}
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: %q held no RK_g of gen/%d or above", ErrStoreViewNotHeld, reader, generation)
}

// sidecar.Redis as an oracle reads it: every read under InspectContext, so a look takes no plan and counts nothing,
// and every write refused, since an oracle that wrote would change the run it checks.
type inspectRedis struct {
	redis sidecar.Redis
}

// What an oracle gets for a write.
var errStoreViewReadOnly = errors.New("the oracle's store view is read-only")

func (self *inspectRedis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return self.redis.Get(sidecartest.InspectContext(ctx), key)
}

func (self *inspectRedis) GetMany(ctx context.Context, keys []string) ([][]byte, error) {
	return self.redis.GetMany(sidecartest.InspectContext(ctx), keys)
}

func (self *inspectRedis) HashGet(ctx context.Context, key string, field string) ([]byte, bool, error) {
	return self.redis.HashGet(sidecartest.InspectContext(ctx), key, field)
}

func (self *inspectRedis) HashGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	return self.redis.HashGetAll(sidecartest.InspectContext(ctx), key)
}

func (self *inspectRedis) StreamRange(ctx context.Context, key string, afterEntryId string, count int64) ([]*sidecar.RedisStreamEntry, error) {
	return self.redis.StreamRange(sidecartest.InspectContext(ctx), key, afterEntryId, count)
}

func (self *inspectRedis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return errStoreViewReadOnly
}

func (self *inspectRedis) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return false, errStoreViewReadOnly
}

func (self *inspectRedis) CompareAndSet(ctx context.Context, key string, expected []byte, value []byte, ttl time.Duration) (bool, error) {
	return false, errStoreViewReadOnly
}

func (self *inspectRedis) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return false, errStoreViewReadOnly
}

func (self *inspectRedis) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return 0, errStoreViewReadOnly
}

func (self *inspectRedis) Delete(ctx context.Context, keys []string) error {
	return errStoreViewReadOnly
}

func (self *inspectRedis) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return false, errStoreViewReadOnly
}

func (self *inspectRedis) HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error {
	return errStoreViewReadOnly
}

func (self *inspectRedis) HashDelete(ctx context.Context, key string, fields []string) error {
	return errStoreViewReadOnly
}

func (self *inspectRedis) HashExpire(ctx context.Context, key string, fields []string, ttl time.Duration) error {
	return errStoreViewReadOnly
}

func (self *inspectRedis) StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	return "", errStoreViewReadOnly
}

func (self *inspectRedis) StreamGroupCreate(ctx context.Context, key string, group string) error {
	return errStoreViewReadOnly
}

// A group read moves the group's cursor, so it is a write here.
func (self *inspectRedis) StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) ([]*sidecar.RedisStreamEntry, error) {
	return nil, errStoreViewReadOnly
}

func (self *inspectRedis) StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error {
	return errStoreViewReadOnly
}

func (self *inspectRedis) StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) ([]*sidecar.RedisStreamEntry, string, error) {
	return nil, "", errStoreViewReadOnly
}

// A script may write, and no oracle needs one.
func (self *inspectRedis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	return nil, errStoreViewReadOnly
}

func (self *inspectRedis) AddKeyEventCallback(keyPattern string, callback sidecar.RedisKeyEventFunction) (func(), error) {
	return nil, errStoreViewReadOnly
}
