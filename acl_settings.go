//go:build !ios_extension

// AclFollower's tunables (connect/CODESTYLE.md's settings rule), each a field with its default here and nowhere else.

package sidecar

import (
	"time"
)

// Tunables of a sidecar's acl follower.
type AclSettings struct {
	// The least time between two of this sidecar's acks: 1 s. An ack goes as soon as a state installs, and the
	// installs within the interval after it coalesce into one ack of the newest n at its end, so a burst of entries
	// costs api one row write a second at most while §8.9's applied-time targets (p50 1 s, p99 5 s, measured from
	// acks) still see every entry acked within the interval of its install. Non-positive acks every install.
	AckInterval time.Duration
	// How long one POST /acl/ack may take before it is dropped: 10 s. A dropped or failed ack is never retried, since
	// the next state carries a newer n.
	AckTimeout time.Duration
	// The clock the interval and the applied delays run on; nil is real time.
	Clock Clock
	// Where install refusals and failed acks are logged, ids and positions only (I-13). Nil is the leg's default.
	Log Logger
}

// §8.9's values.
func DefaultAclSettings() *AclSettings {
	return &AclSettings{
		AckInterval: 1 * time.Second,
		AckTimeout:  10 * time.Second,
	}
}
