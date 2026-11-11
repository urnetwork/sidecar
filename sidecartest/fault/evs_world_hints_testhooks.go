//go:build sidecar_testhooks

// The subscriber's seams the evs world's subscription steps take (evs_world_hints.go), which the root has only under
// sidecar_testhooks.

package fault

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	evsWorldRunSubscriptionRound = sidecar.EvsTestRunSubscriptionRound
	evsWorldSetSubscriptionRandom = sidecar.EvsTestSetSubscriptionRandom
}
