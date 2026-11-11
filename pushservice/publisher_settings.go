// §6.6's SidecarPublisherSettings: the tunables of a resident's publisher (publisher.go) and of api's
// long-poll's hold (long_poll.go), with the publisher's own beside them, and PushFormatSettings, §6.8's
// wire limits, which every writer and reader of a client's slot carries the same (QD-702: a limit is a
// settings field whose default is the protocol's value, read from the instance where it is used).

package pushservice

import (
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// A setting a publisher cannot run on.
var errPublisherSettings = errors.New("sidecar publisher: settings out of range")

// §6.8's wire limits on push: protocol values, so a change here is a protocol change, which no deployment
// makes on one side alone. The hint writer, the publisher and the long-poll each carry a copy from
// DefaultPushFormatSettings, so the default is in one place.
type PushFormatSettings struct {
	// The most a hint's bytes hold: 256 B, ids, kinds and versions, never content (§6.8's PushHint.hint).
	MaxHintByteCount int
	// The most versions one PushReset part carries, which one envelope holds (§6.5's budget): 48.
	ResetPartVersionCount int
}

// The protocol's values.
func DefaultPushFormatSettings() *PushFormatSettings {
	return &PushFormatSettings{
		MaxHintByteCount:      256,
		ResetPartVersionCount: 48,
	}
}

// Whether the limits can carry anything: both positive.
func (self *PushFormatSettings) validate() error {
	if self.MaxHintByteCount <= 0 || self.ResetPartVersionCount <= 0 {
		return errors.New("push format: limits must be positive")
	}
	return nil
}

// Resident publishers (server/connect) and the api long-poll (§6.6).
type SidecarPublisherSettings struct {
	// How long a publisher gathers hints after the event that woke it before it reads them, so a topic's
	// hints in that window go out as one batch, every one but the last of a topic without its bytes: 100
	// ms (§6.8). It also bounds the reads one client costs: one a window. Must be positive.
	HintCoalesceTimeout time.Duration
	// Resets Reset may queue while one waits to be sent: 1 per resident. A Reset past it joins the one
	// already queued, which reads ver after it anyway. Must be positive.
	PendingResetCount int
	// The most bytes of hints a publisher holds to send at once, counted as their encodings: 64 KiB per
	// resident. A batch past it is dropped for a reset, which says the same in far fewer bytes, so a
	// client far behind costs a reset, never a queue that grows. Must hold at least one envelope.
	QueueByteCount int64
	// How long api's long-poll holds a poll with nothing to answer: 25 s, under the lb's 30 s
	// proxy_read_timeout. LongPollSettings.HoldTimeout takes its default from here.
	LongPollHoldTimeout time.Duration

	// The most entries one XRANGE reads: 256, a stream's length. A read that fills it is followed at once
	// by another, the batch bounded by QueueByteCount.
	ReadHintCount int64
	// How long {scp_<C>}ack lives from each raise: 1 h (§18.7's EX 3600). Whole seconds.
	AckTimeout time.Duration
	// The first wait after a Redis error or a refused send, doubling to RetryMaxInterval: 1 s. The run
	// loop never spins on a store that is down.
	RetryMinInterval time.Duration
	// The longest such wait: 30 s, well inside a client's hourly resync.
	RetryMaxInterval time.Duration
	// How often the publisher sets {scp_<C>}live again while it runs: 30 s (§18.7), a third of
	// LiveTimeout, so one lost write or one long retry wait never lets the marker lapse under a live
	// resident. Must be positive and under LiveTimeout.
	LiveRefreshInterval time.Duration
	// How long {scp_<C>}live lives from each write: 90 s (§18.7's EX 90), so the marker of a resident that
	// went away lapses within it and the client's wake-class hints are woken at once again. Whole seconds.
	LiveTimeout time.Duration
	// §6.8's wire limits.
	Format PushFormatSettings
}

// The defaults: §6.6's, and the publisher's own above.
func DefaultSidecarPublisherSettings() *SidecarPublisherSettings {
	return &SidecarPublisherSettings{
		HintCoalesceTimeout: 100 * time.Millisecond,
		PendingResetCount:   1,
		QueueByteCount:      64 * 1024,
		LongPollHoldTimeout: 25 * time.Second,
		ReadHintCount:       256,
		AckTimeout:          1 * time.Hour,
		RetryMinInterval:    1 * time.Second,
		RetryMaxInterval:    30 * time.Second,
		LiveRefreshInterval: 30 * time.Second,
		LiveTimeout:         90 * time.Second,
		Format:              *DefaultPushFormatSettings(),
	}
}

// Whether a publisher can run on these: every bound positive, the ack's and the live marker's ttls a
// second or more, a refresh inside the marker's life, and room for at least one envelope.
// LongPollHoldTimeout is the long-poll's, which checks it.
func (self *SidecarPublisherSettings) validate() error {
	switch {
	case self.HintCoalesceTimeout <= 0, self.PendingResetCount <= 0, self.ReadHintCount <= 0:
		return errPublisherSettings
	case self.QueueByteCount < sidecar.MaxEnvelopeByteCount:
		return errPublisherSettings
	case self.AckTimeout < time.Second:
		return errPublisherSettings
	case self.RetryMinInterval <= 0, self.RetryMaxInterval < self.RetryMinInterval:
		return errPublisherSettings
	case self.LiveTimeout < time.Second, self.LiveRefreshInterval <= 0, self.LiveTimeout <= self.LiveRefreshInterval:
		return errPublisherSettings
	}
	if err := self.Format.validate(); err != nil {
		return errors.Join(errPublisherSettings, err)
	}
	return nil
}
