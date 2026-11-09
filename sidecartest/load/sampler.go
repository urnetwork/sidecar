// Reads what a soak compares against its baseline (D-TEST-7's "heap, goroutines, Redis keys and
// orphan objects back to baseline"; TEST-M2-14): the process's heap and goroutines, and the keys of a
// Redis through whatever counts them. Orphan objects need the GC's own definition, which EVSB's
// listing gives, so the soak reads them there and not here.
//
// Safe for concurrent use.

package load

import (
	"context"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a sampler counts Redis keys with: on T3 a DBSIZE over every master, on T2 a fake's keys.
type RedisKeyCounter interface {
	CountKeys(ctx context.Context) (int64, error)
}

// One reading.
type Sample struct {
	At             time.Time `json:"at"`
	HeapAllocBytes uint64    `json:"heap_alloc_bytes"`
	HeapInuseBytes uint64    `json:"heap_inuse_bytes"`
	HeapObjects    uint64    `json:"heap_objects"`
	Goroutines     int       `json:"goroutines"`
	// -1 when the sampler counts no Redis.
	RedisKeys int64 `json:"redis_keys"`
	// Why a reading is missing a part, such as a Redis count that failed.
	Error string `json:"error,omitempty"`
}

// When the sampler reads.
type SamplerSettings struct {
	// Between readings of Run. Must be positive for Run.
	Interval time.Duration
	// nil is real time.
	Clock sidecartest.Clock
}

// A reading every 10 s.
func DefaultSamplerSettings() *SamplerSettings {
	return &SamplerSettings{
		Interval: 10 * time.Second,
	}
}

// Takes and keeps readings.
type Sampler struct {
	settings *SamplerSettings
	clock    sidecartest.Clock
	redis    RedisKeyCounter

	stateLock sync.Mutex
	samples   []Sample
}

// A sampler of this process and, when redis is not nil, its keys.
func NewSampler(settings *SamplerSettings, redis RedisKeyCounter) *Sampler {
	clock := settings.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	copied := *settings
	return &Sampler{settings: &copied, clock: clock, redis: redis}
}

// One reading, kept and returned. A Redis count that fails leaves RedisKeys -1 and says why.
func (self *Sampler) Sample(ctx context.Context) Sample {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	sample := Sample{
		At:             self.clock.Now(),
		HeapAllocBytes: stats.HeapAlloc,
		HeapInuseBytes: stats.HeapInuse,
		HeapObjects:    stats.HeapObjects,
		Goroutines:     runtime.NumGoroutine(),
		RedisKeys:      -1,
	}
	if self.redis != nil {
		keys, err := self.redis.CountKeys(ctx)
		if err != nil {
			sample.Error = "redis keys: " + err.Error()
		} else {
			sample.RedisKeys = keys
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.samples = append(self.samples, sample)
	return sample
}

// Reads every Interval until ctx ends, starting at once.
func (self *Sampler) Run(ctx context.Context) {
	for {
		self.Sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.Interval):
		}
	}
}

// Every reading so far, oldest first.
func (self *Sampler) Samples() []Sample {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.samples)
}

// A fake Redis's keys, for T2: what Dump holds.
type FakeRedisKeys struct {
	Redis *sidecartest.FakeRedis
}

func (self *FakeRedisKeys) CountKeys(ctx context.Context) (int64, error) {
	return int64(len(self.Redis.Dump())), nil
}
