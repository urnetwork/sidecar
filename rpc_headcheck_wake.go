//go:build !sidecar_http

// §6.4's Bound from M8 (D-TRUST-10; owner decision 88; PROTO-M8-02): a scheduled HeadCheck that gets no reply
// within HeadCheckTimeout from one of this member's own app hosts summons it with POST /sidecar/wake, at most once
// a WakeInterval (1 h) a host, so a phone whose app the OS suspended wakes, checks and witnesses again before
// witness_bound_hours stops shared writes. Never a desktop: only a pick the env names an own app host
// (HeadCheckEnv.AppHost) is summoned, and api's wake reaches only a client holding a wake token, which only app
// hosts hold. A woken sidecar checks first, since its start runs a round (rpc_headcheck_rounds.go).
//
// A summons is best effort. It runs on one of the transport's workers, after the round's exchange that found the
// host silent, and a refusal or a failure is counted and left for the next interval, api's own hourly limit
// answering 429 to any device of the member past it; the bound's alarm is what tells a person no witness came.

package sidecar

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The route as errors name it.
const sidecarWakeRoute = "POST /sidecar/wake"

// POST /sidecar/wake's body.
type sidecarWakeArgs struct {
	SidecarId Id `json:"sidecar_id"`
}

// POST /sidecar/wake (§6.16): summons sidecarId, another admitted device of this sidecar's member, with a
// content-free wake. A refusal is a *SidecarApiError: 403 for a device that is not another admitted one of the
// member's, 429 within the hour since anyone summoned it, 503 while wakes are not enabled.
func (self *SidecarApi) WakeSidecar(ctx context.Context, sidecarId Id) error {
	return self.sendJson(ctx, &sidecarApiRequest{
		route:     sidecarWakeRoute,
		operation: "wake",
		method:    "POST",
		url:       self.settings.ApiUrl + "/sidecar/wake",
		bearer:    true,
	}, &sidecarWakeArgs{SidecarId: sidecarId}, nil)
}

// What the summonses have counted.
type HeadCheckWakeStats struct {
	// summonses api took, and those it refused or that failed
	WakeCount       uint64
	WakeFailedCount uint64
	// silent own app hosts left alone, a summons of them already sent within WakeInterval
	WakeHeldCount uint64
}

// The transport's summonses: when each host was last summoned, so one goes at most once a WakeInterval.
type headCheckWakes struct {
	stateLock       sync.Mutex
	wakeTimes       map[Id]time.Time
	wakeCount       uint64
	wakeFailedCount uint64
	wakeHeldCount   uint64
}

// Whether err says the peer never answered within its call's timeout: the summons' trigger.
func headCheckSilent(err error) bool {
	subprotocolError := &SubprotocolError{}
	return errors.As(err, &subprotocolError) && subprotocolError.Code == protocol.ErrorCode_ERR_DEADLINE_EXCEEDED
}

// Called with each round pick whose exchange failed with err: summons the pick when it is silent, an own app
// host, and not summoned within WakeInterval. Returns at once; the call to api runs on a worker.
func (self *headCheckTransport) wakeIfSilent(sidecarId Id, own bool, err error) {
	if !own || !headCheckSilent(err) || self.env.Wake == nil || self.env.AppHost == nil || !self.env.AppHost(sidecarId) {
		return
	}
	now := self.clock.Now()
	due := func() bool {
		wakes := &self.wakes
		wakes.stateLock.Lock()
		defer wakes.stateLock.Unlock()
		if wakeTime, woken := wakes.wakeTimes[sidecarId]; woken && now.Sub(wakeTime) < self.settings.WakeInterval {
			wakes.wakeHeldCount += 1
			return false
		}
		if wakes.wakeTimes == nil {
			wakes.wakeTimes = map[Id]time.Time{}
		}
		// counted at the ask, so a refusal also waits the interval, as api's own limit would make it
		wakes.wakeTimes[sidecarId] = now
		return true
	}()
	if !due {
		return
	}
	self.goWorker(func() {
		testHookBarrier("rpc.head_check_wake.before", sidecarId.String())
		err := self.env.Wake(self.ctx, sidecarId)
		testHookBarrier("rpc.head_check_wake.after", sidecarId.String())
		func() {
			wakes := &self.wakes
			wakes.stateLock.Lock()
			defer wakes.stateLock.Unlock()
			if err != nil {
				wakes.wakeFailedCount += 1
			} else {
				wakes.wakeCount += 1
			}
		}()
		if err != nil && self.subprotocol.log.V(1).Enabled() {
			self.subprotocol.log.Infof("[headcheck]the summons of %s: %s\n", sidecarId, err)
		}
		self.wakeCount.Update(func(count uint64) uint64 {
			return count + 1
		})
	})
}

// Drops summons times past an interval, beside prune's, so the map holds the hosts summoned lately and no more.
func (self *headCheckTransport) pruneWakes() {
	cutoff := self.clock.Now().Add(-self.settings.WakeInterval)
	wakes := &self.wakes
	wakes.stateLock.Lock()
	defer wakes.stateLock.Unlock()
	for sidecarId, wakeTime := range wakes.wakeTimes {
		if wakeTime.Before(cutoff) {
			delete(wakes.wakeTimes, sidecarId)
		}
	}
}

// What the transport's summonses have counted.
func (self *headCheckTransport) wakeStats() HeadCheckWakeStats {
	wakes := &self.wakes
	wakes.stateLock.Lock()
	defer wakes.stateLock.Unlock()
	return HeadCheckWakeStats{
		WakeCount:       wakes.wakeCount,
		WakeFailedCount: wakes.wakeFailedCount,
		WakeHeldCount:   wakes.wakeHeldCount,
	}
}
