// §19.4's push sender's tunables (SDK-M8-10): every bound, interval and cap the sender reads, each with
// §18.7's or §19.4's value as its default. The queue's shard count is the queue's format, which the
// writers' WakeQueueSettings hold too, so the sender carries that object rather than a second copy.

package pushservice

import (
	"errors"
	"time"
)

// A sender setting the sender cannot run on.
var ErrWakeSenderSettings = errors.New("wake sender: settings out of range")

// What the push sender is held to.
type WakeSenderSettings struct {
	// The queue's format, which the writers carry alike: its 16 shards (§18.7). Nil takes
	// DefaultWakeQueueSettings.
	Queue *WakeQueueSettings
	// The consumer group every sender reads the shards through, so an entry has one sender: an
	// identifier, the same in every process.
	ConsumerGroup string
	// Entries one XREADGROUP or XAUTOCLAIM takes: 256.
	ReadCount int64
	// How long a read waits for an entry before it reads again: 5 s.
	ReadBlock time.Duration
	// How long an entry a sender read stays unacknowledged before another may claim it: §19.4's 30 s,
	// so a sender killed after its read loses nothing it had not sent.
	ClaimMinIdle time.Duration
	// How often each shard's pending entries are claimed: 10 s.
	ClaimInterval time.Duration
	// An entry older than this from its hint is dropped and acknowledged unsent: §19.4's 60 s, past
	// §15.6's hold; the client resyncs at its next start (§6.8).
	MaxAge time.Duration
	// One wake per client per window, kept in Redis under {wake_<C>}w and set before the vendor call so
	// a sender killed after the send still holds it (§19.4's rate row, FS-36): 10 s. A hint inside a
	// window gets one wake at its end.
	ClientWindow time.Duration
	// APNs' cap per device: ApnsWindowMaxCount wakes in each ApnsWindow, 3 an hour (§19.4).
	ApnsWindow         time.Duration
	ApnsWindowMaxCount int64
	// FCM's cap per device and topic: FcmWindowMaxCount wakes in each FcmWindow, 1 a minute (§19.4).
	FcmWindow         time.Duration
	FcmWindowMaxCount int64
	// Retries of a vendor's 429, 5xx or transport failure: §19.4's 3, the first after RetryBackoff and
	// each later one after twice the one before.
	RetryCount   int
	RetryBackoff time.Duration
	// Entries one process holds read and not yet settled: 65,536. Past it the readers wait, so a burst
	// stays in the streams, bounded by their MAXLEN, rather than in memory.
	HeldMaxCount int
	// Entries settled at once, each a vendor call: 64.
	SendConcurrency int
	// How long a reader or a claim waits after a Redis error before it tries again: 1 s.
	ErrorBackoff time.Duration
	// How long a reader waits while sidecar.yml's wake switch is off before it asks again: 10 s. While
	// it is off nothing is read, and entries age out in their streams (§19.11).
	GateInterval time.Duration
}

// §18.7's and §19.4's values.
func DefaultWakeSenderSettings() *WakeSenderSettings {
	return &WakeSenderSettings{
		Queue:              DefaultWakeQueueSettings(),
		ConsumerGroup:      "wake",
		ReadCount:          256,
		ReadBlock:          5 * time.Second,
		ClaimMinIdle:       30 * time.Second,
		ClaimInterval:      10 * time.Second,
		MaxAge:             60 * time.Second,
		ClientWindow:       10 * time.Second,
		ApnsWindow:         1 * time.Hour,
		ApnsWindowMaxCount: 3,
		FcmWindow:          1 * time.Minute,
		FcmWindowMaxCount:  1,
		RetryCount:         3,
		RetryBackoff:       1 * time.Second,
		HeldMaxCount:       65536,
		SendConcurrency:    64,
		ErrorBackoff:       1 * time.Second,
		GateInterval:       10 * time.Second,
	}
}

func (self *WakeSenderSettings) validate() error {
	if self.Queue == nil {
		return ErrWakeSenderSettings
	}
	if err := self.Queue.validate(); err != nil {
		return err
	}
	switch {
	case self.ConsumerGroup == "", self.ReadCount <= 0, self.ReadBlock <= 0, self.ClaimMinIdle <= 0, self.ClaimInterval <= 0,
		self.MaxAge <= 0, self.ClientWindow < time.Millisecond, self.ApnsWindow <= 0, self.ApnsWindowMaxCount <= 0,
		self.FcmWindow <= 0, self.FcmWindowMaxCount <= 0, self.RetryCount < 0, self.RetryBackoff < 0,
		self.HeldMaxCount <= 0, self.SendConcurrency <= 0, self.ErrorBackoff <= 0, self.GateInterval <= 0:
		return ErrWakeSenderSettings
	}
	return nil
}
