// §6.6's SidecarPublisherSettings: the tunables of a resident's publisher (publisher.go) and of api's
// long-poll's hold (long_poll.go), with the publisher's own beside them. Protocol values, such as the 48
// versions a reset part carries and the 256 B of a hint, are constants, not settings.

package pushservice

import (
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// A setting a publisher cannot run on.
var errPublisherSettings = errors.New("sidecar publisher: settings out of range")

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
	}
}

// Whether a publisher can run on these: every bound positive, the ack's ttl a second or more, and room
// for at least one envelope. LongPollHoldTimeout is the long-poll's, which checks it.
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
	}
	return nil
}
