//go:build sidecar_testhooks

// The subscriber's rounds (evs_subscribe.go) for sidecartest/fault's FS-12 schedule (§22.8; EVS1-M2-41), which
// drives a device's subscriptions on the schedule's own actor, one round a step, so a lease, a reread and a resync
// each run where the barrier driver can see them and never on a goroutine of their own. A device there never calls
// StartSubscriptions: the world answers every wait at once, so the subscriber's own loop would spin.
//
// Nothing here holds or derives a key. Only the sidecar_testhooks build has these, which no release leg is (§22.4).

package sidecar

import (
	"context"
	"time"
)

// Runs client's subscriber's due work once, now, on the caller's goroutine: owed leases and renewals, the leases of
// ended subscriptions deleted, a due resync and the queued reads, as one of StartSubscriptions's rounds does. The
// answer is when the next work is due, zero for none.
func EvsTestRunSubscriptionRound(ctx context.Context, client *EvsClient) time.Time {
	return client.subscriber.runDue(ctx)
}

// Sets the draw client's subscriber takes for the hourly resync's offset and a renewal's time, which is uniform in
// [0, limit) unless set: a schedule that must repeat names one.
func EvsTestSetSubscriptionRandom(client *EvsClient, random func(limit time.Duration) time.Duration) {
	subscriber := client.subscriber
	subscriber.stateLock.Lock()
	defer subscriber.stateLock.Unlock()
	subscriber.random = random
}
