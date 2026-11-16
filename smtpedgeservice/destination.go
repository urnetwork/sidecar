// §14.7's destination caps (D-SMTP-14, plan-SMTP-shared-counters): at most
// smtp_destination_connections_per_hour Community connections per destination domain per UTC hour,
// across the fleet, on {smd_<hex(SHA-256(domain)[0:16])>_<yyyymmddhh>}, so no key and no metric names a
// domain; and at most smtp_destination_concurrency live connections per (sending address, destination
// /24), in this edge's memory, which the dial asks before it picks an address (SmtpSendingSet).
//
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

var errSmtpHourCountReply = errors.New("smtp hour count: a reply not of the script's shape")

// One concurrency slot's scope.
type smtpDestinationSlotKey struct {
	sendingAddress netip.Addr
	destination    netip.Prefix
}

// The destination caps of one edge process: the fleet's hourly counters per domain, and this edge's
// concurrency slots per (sending address, destination /24).
type SmtpDestinationCaps struct {
	redis    sidecar.Redis
	clock    sidecar.Clock
	settings *SmtpEdgeSettings
	trips    sidecar.MetricsCounter

	stateLock  sync.Mutex
	slotCounts map[smtpDestinationSlotKey]int64
}

func newSmtpDestinationCaps(redis sidecar.Redis, clock sidecar.Clock, metrics sidecar.Metrics, settings *SmtpEdgeSettings) *SmtpDestinationCaps {
	return &SmtpDestinationCaps{
		redis:    redis,
		clock:    clock,
		settings: settings,
		trips: metrics.Counter("urnetwork_smtpedge_breaker_trips_total",
			"Community preambles §14.7's fleet counters refused, by counter.", "kind"),
		slotCounts: map[smtpDestinationSlotKey]int64{},
	}
}

// A destination domain's counter for the UTC hour holding at.
func smtpDestinationHourKey(domain string, at time.Time) string {
	hash := sha256.Sum256([]byte(strings.TrimSuffix(strings.ToLower(domain), ".")))
	return "{smd_" + hex.EncodeToString(hash[:16]) + "_" + at.UTC().Format("2006010215") + "}"
}

// Counts one Community connection to domain this hour. ok false past the cap, with how long until the
// next hour; counted false when the script did not answer, which passes and counts nothing.
func (self *SmtpDestinationCaps) countHour(ctx context.Context, domain string, cap int64, now time.Time) (counted bool, retryAfter time.Duration, ok bool) {
	hourStart, ttl := smtpHourWindow(now, self.settings)
	counted, err := runSmtpHourCount(ctx, self.redis, self.clock, self.settings, smtpDestinationHourKey(domain, now), cap, ttl)
	if err != nil {
		return false, 0, true
	}
	if !counted {
		self.trips.Add(1, smtpBreakerTripDestination)
		return false, hourStart.Add(time.Hour).Sub(now), false
	}
	return true, 0, true
}

// Takes back one count a later refusal undid. Best effort: a lost answer leaves the count, which only
// tightens.
func (self *SmtpDestinationCaps) uncountHour(ctx context.Context, domain string, now time.Time) {
	callCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.QuotaCallTimeout, cancel)
	defer func() {
		stop()
		cancel()
	}()
	self.redis.RunScript(callCtx, SmtpHourUncountScript, []string{smtpDestinationHourKey(domain, now)}, nil)
}

// The /24 an IPv4 MX address is in.
func smtpDestinationPrefix(mxAddress netip.Addr) netip.Prefix {
	prefix, _ := mxAddress.Unmap().Prefix(24)
	return prefix
}

// Live connections from sendingAddress to mxAddress's /24.
func (self *SmtpDestinationCaps) Count(sendingAddress netip.Addr, mxAddress netip.Addr) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.slotCounts[smtpDestinationSlotKey{sendingAddress: sendingAddress.Unmap(), destination: smtpDestinationPrefix(mxAddress)}]
}

// Takes a slot from sendingAddress to mxAddress's /24 under cap (-1 none), or false when cap are taken.
// release gives it back, once.
func (self *SmtpDestinationCaps) Acquire(sendingAddress netip.Addr, mxAddress netip.Addr, cap int64) (release func(), ok bool) {
	key := smtpDestinationSlotKey{sendingAddress: sendingAddress.Unmap(), destination: smtpDestinationPrefix(mxAddress)}
	acquired := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if cap != -1 && cap <= self.slotCounts[key] {
			return false
		}
		self.slotCounts[key] += 1
		return true
	}()
	if !acquired {
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.slotCounts[key] -= 1
			if self.slotCounts[key] <= 0 {
				delete(self.slotCounts, key)
			}
		})
	}, true
}
