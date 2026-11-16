// §14.7's enforcement (R-SMTP-1, R-SMTP-2, D-SMTP-14): each preamble runs one script on
// {smq_<networkId>} (quota_scripts.go), which checks the network's halts, the per-message caps, its
// concurrency, the day's counters with what live connections hold reserved, and the burst, and makes a
// reservation of one connection and its recipients. A connection costs a unit only once its MAIL record
// is forwarded (DebitMail, which SMTP-M9-13 calls when SmtpProofSession.MailForwarded first reports
// true); an earlier refusal costs the burst token alone, and DNS or MX failure debits nothing (Release).
// Close debits the bytes observed and returns whatever the connection never used. A Community preamble
// then runs the fleet's two single-key counters (breaker.go, destination.go).
//
// The limits come from the gate's memory (SmtpGateDecision.Limits): Quota.Limits' answer, at Community
// caps for a restricted network and halved for Community at §21.5's level 1, so nothing here waits on
// api or Postgres (I-12).
//
// Halts are held twice: in Redis, where ApplyHalt writes them for every edge, and in this process's
// memory, which the engine refills from ActiveHalts each HaltReloadInterval, so a halt holds even while
// Redis does not answer, and Redis's loss loses none (§14.9).
//
// Losing Redis fails open, as §20.7's rates do: while the script does not answer, a preamble passes on
// this process's own count of the network's day, which holds it to one day's connections and recipients
// (§22.5's §14 row), and a lost Redis restarts its counters, which costs at most a day's quota. Every
// fail-open pass is counted.
//
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §20.4's smtp_* keys and §14.7's sidecar_abuse: ones, as QuotaLimits names them. A missing key reads 0,
// not included, so a limit this build does not know refuses.
const (
	SmtpLimitConnectionsPerDay             = "smtp_connections_per_day"
	SmtpLimitBytesPerDay                   = "smtp_bytes_per_day"
	SmtpLimitRecipientsPerMessage          = "smtp_recipients_per_message"
	SmtpLimitRecipientsPerDay              = "smtp_recipients_per_day"
	SmtpLimitMessageBytes                  = "smtp_message_bytes"
	SmtpLimitBurst                         = "smtp_burst"
	SmtpLimitBurstWindow                   = "smtp_burst_window"
	SmtpLimitConcurrentConnections         = "smtp_concurrent_connections"
	SmtpLimitCommunityConnectionsPerHour   = "smtp_community_connections_per_hour"
	SmtpLimitCommunityMedianMultiple       = "smtp_community_median_multiple"
	SmtpLimitDestinationConnectionsPerHour = "smtp_destination_connections_per_hour"
	SmtpLimitDestinationConcurrency        = "smtp_destination_concurrency"
	SmtpLimitHardBouncePercent             = "smtp_hard_bounce_percent"
	SmtpLimitHardBounceFloor               = "smtp_hard_bounce_floor"
)

// The quota's reasons for a refusal, the script's words and these.
const (
	smtpQuotaReasonFailOpenDay  = "fail_open_day"
	smtpQuotaReasonUnconfigured = "unconfigured"
	smtpQuotaReasonCommunity    = "community_breaker"
	smtpQuotaReasonDestination  = "destination"
	smtpQuotaReasonMemoryHalt   = "halt"
	smtpQuotaReasonMemoryLabel  = "label_halt"
	smtpQuotaReasonFallbackFull = "fallback_full"
	// the script's word for the per-message recipient cap, which the fail-open path answers too
	smtpQuotaReasonRecipientsPerMessage = "recipients_per_message"
)

// {smq_<networkId>}, the network's one key (§19.7's tag list).
func smtpQuotaKey(networkId sidecar.Id) string {
	return "{smq_" + networkId.String() + "}"
}

// What a preamble asks of the quota.
type SmtpQuotaRequest struct {
	NetworkId sidecar.Id
	// A burner's <blabel>, whose halt refuses it; empty for network mail.
	Label            string
	RecipientCount   uint32
	MessageByteCount uint64
	// The recipient domain, which the destination counter counts by its hash.
	RecipientDomain string
	// SmtpGateDecision.Limits.
	Limits *sidecar.QuotaLimits
	// SmtpGateDecision.Community: the fleet's counters run too.
	Community bool
}

// What Reserve answered.
type SmtpQuotaDecision struct {
	// OK, HALTED, QUOTA or TRY_LATER.
	Code       protocol.SmtpPreambleCode
	RetryAfter time.Duration
	// Which check answered, a word from the scripts' closed set and the quota's own.
	Reason string
	// On OK.
	Reservation *SmtpQuotaReservation
}

// One live connection's hold on its network's quota: until DebitMail, a reservation of one connection
// and its recipients; then the debited unit; and until Close or Release, a concurrency slot.
type SmtpQuotaReservation struct {
	NetworkId      sidecar.Id
	RecipientCount uint32
	// The UTC day it counts on, from the epoch: the day its preamble was accepted.
	Day int64
	// The cc: member, 16 random octets in hex.
	member string
	// Passed while Redis did not answer: debited only on this process's day count.
	failOpen bool

	stateLock sync.Mutex
	debited   bool
	ended     bool
}

// This process's count of a network's day while Redis does not answer.
type smtpQuotaFallbackDay struct {
	day         int64
	connections int64
	recipients  int64
}

// A halt held in memory.
type smtpQuotaHalts struct {
	// ends by network, and by network and label
	networkIdEnds      map[sidecar.Id]time.Time
	networkIdLabelEnds map[sidecar.Id]map[string]time.Time
}

// One edge's quota: the scripts on Redis, the halts in memory, the in-memory day counts it fails open
// on, and the fleet's counters.
type SmtpQuota struct {
	redis    sidecar.Redis
	clock    sidecar.Clock
	settings *SmtpEdgeSettings
	breaker  *SmtpBreaker
	caps     *SmtpDestinationCaps

	failOpenCount sidecar.MetricsCounter
	refusals      sidecar.MetricsCounter

	stateLock          sync.Mutex
	halts              smtpQuotaHalts
	networkIdFallbacks map[sidecar.Id]*smtpQuotaFallbackDay
}

// The quota over the host's Redis, running the breaker's median refresh until ctx ends. host needs Redis
// and Metrics.
func NewSmtpQuota(ctx context.Context, host *sidecar.ServiceHost, settings *SmtpEdgeSettings) (*SmtpQuota, error) {
	if host == nil || host.Redis == nil || host.Metrics == nil {
		return nil, errors.New("smtp quota needs a host with Redis and Metrics")
	}
	clock := host.ClockOrReal()
	self := &SmtpQuota{
		redis:    host.Redis,
		clock:    clock,
		settings: settings,
		failOpenCount: host.Metrics.Counter("urnetwork_smtpedge_quota_fail_open_total",
			"Preambles passed on this process's own count while Redis did not answer."),
		refusals: host.Metrics.Counter("urnetwork_smtpedge_quota_refusals_total",
			"Preambles the quota refused, by reason.", "reason"),
		halts: smtpQuotaHalts{
			networkIdEnds:      map[sidecar.Id]time.Time{},
			networkIdLabelEnds: map[sidecar.Id]map[string]time.Time{},
		},
		networkIdFallbacks: map[sidecar.Id]*smtpQuotaFallbackDay{},
	}
	self.breaker = newSmtpBreaker(ctx, host.Redis, clock, host.Metrics, settings)
	self.caps = newSmtpDestinationCaps(host.Redis, clock, host.Metrics, settings)
	return self, nil
}

// The breaker this quota runs for Community preambles.
func (self *SmtpQuota) Breaker() *SmtpBreaker {
	return self.breaker
}

// The destination caps: the hourly counter this quota runs and the concurrency the dial takes.
func (self *SmtpQuota) DestinationCaps() *SmtpDestinationCaps {
	return self.caps
}

// A context bounded by QuotaCallTimeout on the quota's clock, and the call that ends it.
func (self *SmtpQuota) callContext(ctx context.Context) (context.Context, func()) {
	callCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.QuotaCallTimeout, cancel)
	return callCtx, func() {
		stop()
		cancel()
	}
}

// A limit, -1 for none and 0, not included, for a key absent.
func smtpLimit(limits *sidecar.QuotaLimits, key string) int64 {
	if limits == nil {
		return 0
	}
	return limits.Limits[key]
}

// A refusal, counted by its reason.
func (self *SmtpQuota) refuse(code protocol.SmtpPreambleCode, retryAfter time.Duration, reason string) *SmtpQuotaDecision {
	self.refusals.Add(1, reason)
	return &SmtpQuotaDecision{Code: code, RetryAfter: retryAfter, Reason: reason}
}

// The memory's halt on the network or the label, and its end.
func (self *SmtpQuota) memoryHalt(networkId sidecar.Id, label string, now time.Time) (time.Time, string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if end, ok := self.halts.networkIdEnds[networkId]; ok && now.Before(end) {
		return end, smtpQuotaReasonMemoryHalt
	}
	if label != "" {
		if end, ok := self.halts.networkIdLabelEnds[networkId][label]; ok && now.Before(end) {
			return end, smtpQuotaReasonMemoryLabel
		}
	}
	return time.Time{}, ""
}

// Reserves one connection for a preamble the gate passed. A refusal leaves nothing behind but a burst
// token the script took, which is not taken back.
func (self *SmtpQuota) Reserve(ctx context.Context, request *SmtpQuotaRequest) (*SmtpQuotaDecision, error) {
	now := self.clock.Now()
	if end, reason := self.memoryHalt(request.NetworkId, request.Label, now); reason != "" {
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, end.Sub(now), reason), nil
	}
	limits := request.Limits
	burst := smtpLimit(limits, SmtpLimitBurst)
	window := smtpLimit(limits, SmtpLimitBurstWindow)
	if burst != -1 && window <= 0 {
		// a burst with no window to count it in: not configured, so nothing is included
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, 0, smtpQuotaReasonUnconfigured), nil
	}
	memberOctets := make([]byte, 16)
	if _, err := rand.Read(memberOctets); err != nil {
		return nil, err
	}
	member := hex.EncodeToString(memberOctets)
	args := []string{
		member,
		request.Label,
		strconv.FormatUint(uint64(request.RecipientCount), 10),
		strconv.FormatUint(request.MessageByteCount, 10),
		strconv.FormatInt(smtpLimit(limits, SmtpLimitConnectionsPerDay), 10),
		strconv.FormatInt(smtpLimit(limits, SmtpLimitRecipientsPerDay), 10),
		strconv.FormatInt(smtpLimit(limits, SmtpLimitRecipientsPerMessage), 10),
		strconv.FormatInt(smtpLimit(limits, SmtpLimitMessageBytes), 10),
		strconv.FormatInt(smtpLimit(limits, SmtpLimitBytesPerDay), 10),
		strconv.FormatInt(burst, 10),
		strconv.FormatInt(window, 10),
		strconv.FormatInt(smtpLimit(limits, SmtpLimitConcurrentConnections), 10),
		strconv.FormatInt(self.settings.QuotaMemberTimeout.Milliseconds(), 10),
		strconv.FormatInt(self.settings.QuotaKeyTimeout.Milliseconds(), 10),
	}
	reply, err := func() (*sidecar.RedisReply, error) {
		callCtx, done := self.callContext(ctx)
		defer done()
		return self.redis.RunScript(callCtx, SmtpQuotaReserveScript, []string{smtpQuotaKey(request.NetworkId)}, args)
	}()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return self.reserveFailOpen(request, member, now)
	}
	code, retryMs, day, reason, err := parseSmtpQuotaReserveReply(reply)
	if err != nil {
		return nil, err
	}
	retryAfter := time.Duration(retryMs) * time.Millisecond
	switch code {
	case smtpQuotaScriptHalted:
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, retryAfter, reason), nil
	case smtpQuotaScriptQuota:
		if retryAfter <= 0 {
			retryAfter = self.settings.QuotaRetryTimeout
		}
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, retryAfter, reason), nil
	case smtpQuotaScriptOk:
	default:
		return nil, fmt.Errorf("smtp quota: the script answered code %d", code)
	}
	reservation := &SmtpQuotaReservation{
		NetworkId:      request.NetworkId,
		RecipientCount: request.RecipientCount,
		Day:            day,
		member:         member,
	}
	if request.Community {
		if decision := self.countFleet(ctx, request, now); decision != nil {
			self.Release(ctx, reservation)
			return decision, nil
		}
	}
	return &SmtpQuotaDecision{Code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, Reservation: reservation}, nil
}

// The fleet's Community counters, the destination domain's first, since it trips the more often: nil
// when both count the connection. A counter whose script does not answer counts nothing and refuses
// nothing (§14.9: Redis loss restarts them).
func (self *SmtpQuota) countFleet(ctx context.Context, request *SmtpQuotaRequest, now time.Time) *SmtpQuotaDecision {
	destinationCounted, retryAfter, ok := self.caps.countHour(ctx, request.RecipientDomain, smtpLimit(request.Limits, SmtpLimitDestinationConnectionsPerHour), now)
	if !ok {
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, retryAfter, smtpQuotaReasonDestination)
	}
	if retryAfter, ok := self.breaker.admit(ctx, request.Limits, now); !ok {
		if destinationCounted {
			self.caps.uncountHour(ctx, request.RecipientDomain, now)
		}
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, retryAfter, smtpQuotaReasonCommunity)
	}
	return nil
}

// A pass while Redis does not answer, on this process's count of the network's day, which holds the
// network to one day's connections and recipients; past it, or with no room left to count a new network
// in memory, QUOTA.
func (self *SmtpQuota) reserveFailOpen(request *SmtpQuotaRequest, member string, now time.Time) (*SmtpQuotaDecision, error) {
	day := SmtpSendDay(now)
	untilTomorrow := time.UnixMilli((day + 1) * 24 * 60 * 60 * 1000).Sub(now)
	connectionLimit := smtpLimit(request.Limits, SmtpLimitConnectionsPerDay)
	recipientLimit := smtpLimit(request.Limits, SmtpLimitRecipientsPerDay)
	recipientMessageLimit := smtpLimit(request.Limits, SmtpLimitRecipientsPerMessage)
	if recipientMessageLimit != -1 && recipientMessageLimit < int64(request.RecipientCount) {
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, self.settings.QuotaRetryTimeout, smtpQuotaReasonRecipientsPerMessage), nil
	}
	refusal := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		fallback, ok := self.networkIdFallbacks[request.NetworkId]
		if !ok || fallback.day != day {
			if !ok && self.settings.QuotaFallbackNetworkMaxCount <= len(self.networkIdFallbacks) {
				// forget other days' counts before refusing for want of room
				for networkId, other := range self.networkIdFallbacks {
					if other.day != day {
						delete(self.networkIdFallbacks, networkId)
					}
				}
				if self.settings.QuotaFallbackNetworkMaxCount <= len(self.networkIdFallbacks) {
					return smtpQuotaReasonFallbackFull
				}
			}
			fallback = &smtpQuotaFallbackDay{day: day}
			self.networkIdFallbacks[request.NetworkId] = fallback
		}
		if connectionLimit != -1 && connectionLimit < fallback.connections+1 {
			return smtpQuotaReasonFailOpenDay
		}
		if recipientLimit != -1 && recipientLimit < fallback.recipients+int64(request.RecipientCount) {
			return smtpQuotaReasonFailOpenDay
		}
		fallback.connections += 1
		fallback.recipients += int64(request.RecipientCount)
		return ""
	}()
	if refusal != "" {
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, untilTomorrow, refusal), nil
	}
	self.failOpenCount.Add(1)
	return &SmtpQuotaDecision{
		Code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK,
		Reservation: &SmtpQuotaReservation{
			NetworkId:      request.NetworkId,
			RecipientCount: request.RecipientCount,
			Day:            day,
			member:         member,
			failOpen:       true,
		},
	}, nil
}

// {code, retry ms, day, reason, burst field}.
func parseSmtpQuotaReserveReply(reply *sidecar.RedisReply) (code int64, retryMs int64, day int64, reason string, err error) {
	if reply == nil || reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 5 {
		return 0, 0, 0, "", errors.New("smtp quota: a reply not of the script's shape")
	}
	for i := range 3 {
		if reply.Replies[i].Kind != sidecar.RedisReplyInteger {
			return 0, 0, 0, "", errors.New("smtp quota: a reply not of the script's shape")
		}
	}
	return reply.Replies[0].Integer, reply.Replies[1].Integer, reply.Replies[2].Integer, string(reply.Replies[3].Bulk), nil
}

// Debits the connection and its recipients, once its MAIL record has been forwarded (§14.7). A second
// call debits nothing. A reservation passed while Redis did not answer was counted then, in memory.
func (self *SmtpQuota) DebitMail(ctx context.Context, reservation *SmtpQuotaReservation) error {
	first := func() bool {
		reservation.stateLock.Lock()
		defer reservation.stateLock.Unlock()
		if reservation.debited || reservation.ended {
			return false
		}
		reservation.debited = true
		return true
	}()
	if !first || reservation.failOpen {
		return nil
	}
	callCtx, done := self.callContext(ctx)
	defer done()
	_, err := self.redis.RunScript(callCtx, SmtpQuotaDebitScript, []string{smtpQuotaKey(reservation.NetworkId)}, []string{
		reservation.member,
		strconv.FormatInt(reservation.Day, 10),
		strconv.FormatUint(uint64(reservation.RecipientCount), 10),
		strconv.FormatInt(self.settings.QuotaMemberTimeout.Milliseconds(), 10),
		strconv.FormatInt(self.settings.QuotaKeyTimeout.Milliseconds(), 10),
	})
	return err
}

// Keeps a live connection's member from lapsing: SMTP-M9-13 calls it each QuotaMemberRenewInterval.
func (self *SmtpQuota) Renew(ctx context.Context, reservation *SmtpQuotaReservation) error {
	if reservation.failOpen {
		return nil
	}
	callCtx, done := self.callContext(ctx)
	defer done()
	return self.redis.HashExpire(callCtx, smtpQuotaKey(reservation.NetworkId), []string{"cc:" + reservation.member}, self.settings.QuotaMemberTimeout)
}

// Ends the connection: its concurrency slot and whatever it held reserved go back, and the bytes it
// relayed count toward smtp_bytes_per_day (§14.7: at close, so one message may pass it). Once only.
func (self *SmtpQuota) Close(ctx context.Context, reservation *SmtpQuotaReservation, byteCount uint64) error {
	first := func() bool {
		reservation.stateLock.Lock()
		defer reservation.stateLock.Unlock()
		if reservation.ended {
			return false
		}
		reservation.ended = true
		return true
	}()
	if !first || reservation.failOpen {
		return nil
	}
	callCtx, done := self.callContext(ctx)
	defer done()
	_, err := self.redis.RunScript(callCtx, SmtpQuotaCloseScript, []string{smtpQuotaKey(reservation.NetworkId)}, []string{
		reservation.member,
		strconv.FormatInt(reservation.Day, 10),
		strconv.FormatUint(byteCount, 10),
		strconv.FormatInt(self.settings.QuotaKeyTimeout.Milliseconds(), 10),
	})
	return err
}

// Ends a reservation that never reached the MX, as on KEYS or a DNS or MX failure: no unit, no bytes,
// the burst token kept (§14.7, §14.9).
func (self *SmtpQuota) Release(ctx context.Context, reservation *SmtpQuotaReservation) error {
	return self.Close(ctx, reservation, 0)
}

// Holds a halt: in this process's memory, and in Redis for every edge. A halt that has ended does
// nothing. The engine calls it for every row ActiveHalts gives, each HaltReloadInterval, which refills
// Redis after its loss (§14.9); SMTP-M9-16's halt rule calls it as it sets each row.
func (self *SmtpQuota) ApplyHalt(ctx context.Context, halt *SmtpHalt) error {
	now := self.clock.Now()
	end := halt.StartTime.Add(SmtpHaltDuration)
	if !now.Before(end) {
		return nil
	}
	label := strings.ToLower(halt.Label)
	if label != "" && !smtpBurnerLabelPattern.MatchString(label) {
		return errors.New("smtp quota: a halt naming a label not of a burner's form")
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// forget what has ended, so the memory holds only standing halts
		for networkId, haltEnd := range self.halts.networkIdEnds {
			if !now.Before(haltEnd) {
				delete(self.halts.networkIdEnds, networkId)
			}
		}
		for networkId, labelEnds := range self.halts.networkIdLabelEnds {
			for otherLabel, haltEnd := range labelEnds {
				if !now.Before(haltEnd) {
					delete(labelEnds, otherLabel)
				}
			}
			if len(labelEnds) == 0 {
				delete(self.halts.networkIdLabelEnds, networkId)
			}
		}
		if label == "" {
			if end.After(self.halts.networkIdEnds[halt.NetworkId]) {
				self.halts.networkIdEnds[halt.NetworkId] = end
			}
			return
		}
		labelEnds, ok := self.halts.networkIdLabelEnds[halt.NetworkId]
		if !ok {
			labelEnds = map[string]time.Time{}
			self.halts.networkIdLabelEnds[halt.NetworkId] = labelEnds
		}
		if end.After(labelEnds[label]) {
			labelEnds[label] = end
		}
	}()
	field := smtpHaltField(label)
	callCtx, done := self.callContext(ctx)
	defer done()
	_, err := self.redis.RunScript(callCtx, SmtpQuotaHaltScript, []string{smtpQuotaKey(halt.NetworkId)}, []string{
		field,
		strconv.FormatInt(end.UnixMilli(), 10),
		strconv.FormatInt(self.settings.QuotaKeyTimeout.Milliseconds(), 10),
	})
	return err
}

// The {smq_} field a halt's flag sits in.
func smtpHaltField(label string) string {
	if label == "" {
		return "h"
	}
	return "h:" + label
}

// Takes a lifted halt out of this process's memory and Redis's flag, then holds again each of remaining, the
// network's halts still standing, which may share that flag (SmtpHaltLadder.Lift).
func (self *SmtpQuota) LiftHalt(ctx context.Context, lifted *SmtpHalt, remaining []*SmtpHalt) error {
	label := strings.ToLower(lifted.Label)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if label == "" {
			delete(self.halts.networkIdEnds, lifted.NetworkId)
			return
		}
		if labelEnds, ok := self.halts.networkIdLabelEnds[lifted.NetworkId]; ok {
			delete(labelEnds, label)
		}
	}()
	err := func() error {
		callCtx, done := self.callContext(ctx)
		defer done()
		return self.redis.HashDelete(callCtx, smtpQuotaKey(lifted.NetworkId), []string{smtpHaltField(label)})
	}()
	for _, halt := range remaining {
		if strings.ToLower(halt.Label) == label {
			err = errors.Join(err, self.ApplyHalt(ctx, halt))
		}
	}
	return err
}

// Makes this process's halts exactly halts, the store's active set (halt_reload.go): each is held, in memory
// and Redis, and a halt memory held that the set no longer has, one lifted since, leaves memory and its flag
// leaves Redis.
func (self *SmtpQuota) ReplaceHalts(ctx context.Context, halts []*SmtpHalt) error {
	now := self.clock.Now()
	type scope struct {
		networkId sidecar.Id
		label     string
	}
	kept := map[scope]bool{}
	for _, halt := range halts {
		if halt.ActiveAt(now) {
			kept[scope{networkId: halt.NetworkId, label: strings.ToLower(halt.Label)}] = true
		}
	}
	gone := func() []scope {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		gone := []scope{}
		for networkId := range self.halts.networkIdEnds {
			if !kept[scope{networkId: networkId}] {
				gone = append(gone, scope{networkId: networkId})
				delete(self.halts.networkIdEnds, networkId)
			}
		}
		for networkId, labelEnds := range self.halts.networkIdLabelEnds {
			for label := range labelEnds {
				if !kept[scope{networkId: networkId, label: label}] {
					gone = append(gone, scope{networkId: networkId, label: label})
					delete(labelEnds, label)
				}
			}
			if len(labelEnds) == 0 {
				delete(self.halts.networkIdLabelEnds, networkId)
			}
		}
		return gone
	}()
	var err error
	for _, scope := range gone {
		err = errors.Join(err, func() error {
			callCtx, done := self.callContext(ctx)
			defer done()
			return self.redis.HashDelete(callCtx, smtpQuotaKey(scope.networkId), []string{smtpHaltField(scope.label)})
		}())
	}
	for _, halt := range halts {
		// a write that fails leaves the halt in memory, and the next reload writes it again
		err = errors.Join(err, self.ApplyHalt(ctx, halt))
	}
	return err
}
