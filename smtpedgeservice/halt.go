// §14.8's halt rule (D-SMTP-9, R-SMTP-4, D-SMTP-14, owner decision 37; SMTP-M9-16): what a complaint, a
// record cut or a self-reported bounce halts, row by row, each a named rule below:
//
//	smtpHaltRuleLabelComplaint     a complaint against one <blabel>.<net>.<root>, any tier: that label
//	smtpHaltRuleCommunityComplaint Community: the first complaint against the network's own names: the network
//	smtpHaltRuleSecondLabel        Community: a second halted label within HaltWindow: the network
//	smtpHaltRuleRate               Pro above 0.5% of the window's recipients, at least 2; Team above 0.1%, at
//	                               least 5: the network
//	smtpHaltRuleFraud              a fraud or virus report, any tier: the network, with §21's review
//	smtpHaltRuleRecordCuts         two record cuts within HaltWindow (§14.7): the network
//	smtpHaltRuleHardBounces        self-reported hard bounces past smtp_hard_bounce_percent of the window's
//	                               recipients, at least smtp_hard_bounce_floor sent (QD-199): the network
//	smtpHaltRuleSuspend            HaltSuspendCount network halts within HaltSuspendWindow: §21 asked once to
//	                               suspend, through SmtpAbuseSink
//
// Only high and medium joins halt (D-SMTP-8). Each (network, Message-ID hash) counts once, and a not-spam for a
// hash cancels it (RFC 6430). Rates count recipients, never connections, through RecipientCount. The RUA check
// is no halt and is SMTP-M9-17's.
//
// A halt is a smtp_halt row (SetHalt) plus, where this process enforces it, the quota's flag in
// {smq_<networkId>} and its memory (SmtpQuota.ApplyHalt). It holds SmtpHaltDuration from the report's arrival.
// The intake's ladder, in mxedge's platform block, has no quota: the edges reload ActiveHalts each
// HaltReloadInterval (halt_reload.go), so a halt reaches every edge within that. New preambles in its scope get
// HALTED, connections already past their preamble finish, and the clients of the network that sent within
// HaltWindow get an SmtpStatus hint on topic mail, which holds their queue (plan-SMTP-wire-gaps#2).
//
// Lift serves POST /smtp/appeal's rechecks (SMTP-M9-19): a halt whose complaints, counted again, no longer meet
// its rule (a duplicate, or one a not-spam cancelled since) is lifted, its row removed, which takes it out of
// every edge at the next reload; record cuts and hard bounces are §21's to review and never lift here.
//
// Every call is off the connection path: the intake calls Apply after it stores a complaint, and the edge's
// connections hand cuts and outcomes to a goroutine that calls it. Nothing here logs a network, a label or an
// address (I-13). Safe for concurrent use: Apply and Lift run one at a time in a process.

package smtpedgeservice

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What the halt rule reads beyond SmtpEdgeStore and SmtpReportLookups, which server implements on
// smtp_complaint, smtp_halt and smtp_send (§14.14). Safe for concurrent use.
type SmtpHaltLookups interface {
	// The network's complaints that key matches, oldest first, their sealed copies left out, at most
	// SmtpEdgeSettings.HaltComplaintReadMaxCount.
	FindComplaints(ctx context.Context, key *SmtpComplaintKey) ([]*SmtpComplaint, error)
	// The network's halts started at or after since, lifted ones gone and ended ones kept, by start.
	FindHalts(ctx context.Context, networkId sidecar.Id, since time.Time) ([]*SmtpHalt, error)
	// How many of the network's sends started at or after since ended with result.
	CountSends(ctx context.Context, networkId sidecar.Id, since time.Time, result string) (uint64, error)
	// The clients of the network with a send started at or after since: whom a status hint reaches.
	SendingClients(ctx context.Context, networkId sidecar.Id, since time.Time) ([]sidecar.Id, error)
	// Removes a lifted halt's row. An absent one is no error.
	DeleteHalt(ctx context.Context, haltId sidecar.Id) error
}

// What FindComplaints matches.
type SmtpComplaintKey struct {
	NetworkId sidecar.Id
	// Only this Message-ID hash's, when set.
	MessageIdHash []byte
	// Only those that arrived at or after it, when set.
	Since time.Time
}

// What §21 is asked when a network reaches HaltSuspendCount halts in HaltSuspendWindow (§14.8, §21.4).
type SmtpSuspensionRequest struct {
	NetworkId sidecar.Id
	// The network halts that reached the count, oldest first.
	HaltIds     []sidecar.Id
	RequestTime time.Time
}

// What happened that the ladder judges.
const (
	// An attributed complaint, stored.
	SmtpHaltEventComplaint = "complaint"
	// A connection a part's refusal cut (§14.7), whose send record is stored.
	SmtpHaltEventRecordCut = "record_cut"
	// Hard bounces a sidecar's SmtpOutcome reported (plan-SMTP-wire-gaps#1).
	SmtpHaltEventHardBounces = "hard_bounces"
)

// One thing the ladder judges.
type SmtpHaltEvent struct {
	// SmtpHaltEvent*.
	Kind      string
	NetworkId sidecar.Id
	// The report's arrival, or when the edge saw the cut or the outcome: a halt holds SmtpHaltDuration from
	// it.
	Time time.Time
	// For a complaint: the row as stored.
	Complaint *SmtpComplaint
	// For hard bounces: the count newly reported.
	HardBounceCount uint32
}

// The ladder's metric words, beside the halt triggers.
const (
	smtpHaltHintOk     = "ok"
	smtpHaltHintFailed = "failed"
)

// What the ladder reads and writes. A nil Quota leaves the halts to the edges' reload, a nil Redis counts no
// hard bounce, and a nil Push hints no client; Store, Lookups and Halts are required, and so is Sink.
type SmtpHaltLadderDeps struct {
	Store   SmtpEdgeStore
	Lookups SmtpReportLookups
	Halts   SmtpHaltLookups
	Quota   *SmtpQuota
	Sink    SmtpAbuseSink
}

// The ladder. NewSmtpHaltLadder makes one.
type SmtpHaltLadder struct {
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	deps     SmtpHaltLadderDeps
	// a network's tier and its sidecar_abuse: limits, off the path (§20.7)
	limits sidecar.Quota
	redis  sidecar.Redis
	push   sidecar.Push

	halts       sidecar.MetricsCounter
	lifts       sidecar.MetricsCounter
	hints       sidecar.MetricsCounter
	suspensions sidecar.MetricsCounter

	// one evaluation at a time in a process, so two complaints racing set one halt
	applyLock sync.Mutex
}

// The ladder on host's Quota, Redis, Push, Clock and Metrics. host needs Quota and Metrics: the ladder reads
// every network's tier from Quota.Limits.
func NewSmtpHaltLadder(host *sidecar.ServiceHost, deps *SmtpHaltLadderDeps, settings *SmtpEdgeSettings) (*SmtpHaltLadder, error) {
	if host == nil || host.Metrics == nil || host.Quota == nil {
		return nil, errors.New("smtp halt ladder needs a host with Quota and Metrics")
	}
	if deps == nil || deps.Store == nil || deps.Lookups == nil || deps.Halts == nil || deps.Sink == nil {
		return nil, errors.New("smtp halt ladder needs its store, lookups and abuse sink")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &SmtpHaltLadder{
		settings:    settings,
		clock:       host.ClockOrReal(),
		deps:        *deps,
		limits:      host.Quota,
		redis:       host.Redis,
		push:        host.Push,
		halts:       host.Metrics.Counter("urnetwork_smtpedge_halts_total", "Halts set, by trigger.", "trigger"),
		lifts:       host.Metrics.Counter("urnetwork_smtpedge_halt_lifts_total", "Halts lifted on a recheck, by trigger.", "trigger"),
		hints:       host.Metrics.Counter("urnetwork_smtpedge_halt_hints_total", "Status hints sent for halts and lifts, by result.", "result"),
		suspensions: host.Metrics.Counter("urnetwork_smtpedge_suspension_requests_total", "Suspensions asked of §21, by result.", "result"),
	}, nil
}

// §14.8's first row: a complaint against one burner label halts that label, on any tier.
func smtpHaltRuleLabelComplaint(label string) bool {
	return label != ""
}

// Community's first complaint against the network's own names halts the network, burners included.
func smtpHaltRuleCommunityComplaint(tier string, label string) bool {
	return tier == smtpTierCommunity && label == ""
}

// Community's second halted label within the window halts the network.
func smtpHaltRuleSecondLabel(tier string, labelHaltCount int, settings *SmtpEdgeSettings) bool {
	return tier == smtpTierCommunity && settings.HaltCommunityLabelCount <= labelHaltCount
}

// Pro's and Team's rates: complaints past basisPoints of the window's recipients, and at least floor of them.
// Rates use recipients, never connections (§14.8).
func smtpHaltRuleRate(complaintCount uint64, recipientCount uint64, basisPoints int, floor int) bool {
	if complaintCount < uint64(floor) {
		return false
	}
	// complaints / recipients > basisPoints / 10,000, in integers
	return recipientCount*uint64(basisPoints) < complaintCount*10000
}

// A verified fraud or virus report (phishing comes as fraud, RFC 5965) halts the network on any tier.
func smtpHaltRuleFraud(complaintType string) bool {
	return complaintType == SmtpComplaintTypeFraud || complaintType == SmtpComplaintTypeVirus
}

// Two record cuts within the window halt the network (§14.7).
func smtpHaltRuleRecordCuts(cutCount uint64, settings *SmtpEdgeSettings) bool {
	return uint64(settings.HaltRecordCutCount) <= cutCount
}

// Self-reported hard bounces past percent of the window's recipients, with at least floor recipients sent
// (QD-199). A limit of -1 or 0 halts nothing.
func smtpHaltRuleHardBounces(bounceCount uint64, recipientCount uint64, percent int64, floor int64) bool {
	if percent <= 0 || floor < 0 || recipientCount < uint64(floor) || recipientCount == 0 {
		return false
	}
	return recipientCount*uint64(percent) < bounceCount*100
}

// The suspension rung: exactly HaltSuspendCount network halts in the window, so the count reaches §21 once.
func smtpHaltRuleSuspend(networkHaltCount int, settings *SmtpEdgeSettings) bool {
	return networkHaltCount == settings.HaltSuspendCount
}

// Whether a complaint of this type and confidence counts toward a halt.
func smtpComplaintHalts(complaint *SmtpComplaint) bool {
	if !SmtpConfidence(complaint.JoinResult).Halts() {
		return false
	}
	switch complaint.Type {
	case SmtpComplaintTypeAbuse, SmtpComplaintTypeFraud, SmtpComplaintTypeVirus, SmtpComplaintTypeOther:
		return true
	}
	return false
}

// The complaints that count, each Message-ID hash once (its first), none whose hash a not-spam names.
func smtpCountedComplaints(complaints []*SmtpComplaint) []*SmtpComplaint {
	cancelled := map[string]bool{}
	for _, complaint := range complaints {
		if complaint.Type == SmtpComplaintTypeNotSpam && len(complaint.MessageIdHash) != 0 {
			cancelled[string(complaint.MessageIdHash)] = true
		}
	}
	seen := map[string]bool{}
	counted := []*SmtpComplaint{}
	for _, complaint := range complaints {
		if !smtpComplaintHalts(complaint) {
			continue
		}
		if len(complaint.MessageIdHash) != 0 {
			hash := string(complaint.MessageIdHash)
			if cancelled[hash] || seen[hash] {
				continue
			}
			seen[hash] = true
		}
		counted = append(counted, complaint)
	}
	return counted
}

// The network's halts still holding at now, from those started within a halt's span.
func (self *SmtpHaltLadder) activeHalts(ctx context.Context, networkId sidecar.Id, now time.Time) ([]*SmtpHalt, error) {
	halts, err := self.deps.Halts.FindHalts(ctx, networkId, now.Add(-SmtpHaltDuration))
	if err != nil {
		return nil, err
	}
	active := []*SmtpHalt{}
	for _, halt := range halts {
		if halt.ActiveAt(now) {
			active = append(active, halt)
		}
	}
	return active, nil
}

// The network's tier and its limits, off the path.
func (self *SmtpHaltLadder) tierLimits(ctx context.Context, networkId sidecar.Id) (*sidecar.QuotaLimits, error) {
	limits, err := self.limits.Limits(ctx, connect.Id(networkId))
	if err != nil {
		return nil, err
	}
	if limits == nil {
		return nil, errors.New("smtp halt ladder: no limits for the network")
	}
	return limits, nil
}

// Judges one event, setting each halt its rules call for, and returns the halts set. An error is a store,
// Redis or quota read that did not answer; a halt already set stays.
func (self *SmtpHaltLadder) Apply(ctx context.Context, event *SmtpHaltEvent) ([]*SmtpHalt, error) {
	if event == nil || event.NetworkId == (sidecar.Id{}) {
		return nil, errors.New("smtp halt ladder: an event with no network")
	}
	self.applyLock.Lock()
	defer self.applyLock.Unlock()
	testHookBarrier("smtpedge.halt_apply.before", "")
	defer testHookBarrier("smtpedge.halt_apply.after", "")
	at := event.Time
	if at.IsZero() {
		at = self.clock.Now()
	}
	active, err := self.activeHalts(ctx, event.NetworkId, self.clock.Now())
	if err != nil {
		return nil, err
	}
	networkHalted := false
	labelHalted := map[string]bool{}
	for _, halt := range active {
		if halt.Label == "" {
			networkHalted = true
		} else {
			labelHalted[halt.Label] = true
		}
	}
	set := []*SmtpHalt{}
	halt := func(label string, trigger string) error {
		if networkHalted || (label != "" && labelHalted[label]) {
			// one halt holds that scope already
			return nil
		}
		newHalt := &SmtpHalt{HaltId: sidecar.NewId(), NetworkId: event.NetworkId, Label: label, Trigger: trigger, StartTime: at}
		if err := self.setHalt(ctx, newHalt); err != nil {
			return err
		}
		set = append(set, newHalt)
		if label == "" {
			networkHalted = true
		} else {
			labelHalted[label] = true
		}
		return nil
	}

	switch event.Kind {
	case SmtpHaltEventComplaint:
		err = self.applyComplaint(ctx, event, halt)
	case SmtpHaltEventRecordCut:
		var cutCount uint64
		cutCount, err = self.deps.Halts.CountSends(ctx, event.NetworkId, at.Add(-self.settings.HaltWindow), smtpConnectionResultCut)
		if err == nil && smtpHaltRuleRecordCuts(cutCount, self.settings) {
			err = halt("", SmtpHaltTriggerRecordCuts)
		}
	case SmtpHaltEventHardBounces:
		err = self.applyHardBounces(ctx, event, halt)
	default:
		err = fmt.Errorf("smtp halt ladder: an event of kind %q", event.Kind)
	}
	if err != nil {
		return set, err
	}
	for _, newHalt := range set {
		if newHalt.Label == "" {
			if err := self.checkSuspension(ctx, event.NetworkId); err != nil {
				return set, err
			}
			break
		}
	}
	return set, nil
}

// A complaint's rows: the label's, Community's, the rates and fraud. A duplicate of a counted complaint, or
// one a not-spam cancelled, halts nothing.
func (self *SmtpHaltLadder) applyComplaint(ctx context.Context, event *SmtpHaltEvent, halt func(label string, trigger string) error) error {
	complaint := event.Complaint
	if complaint == nil || complaint.NetworkId != event.NetworkId {
		return errors.New("smtp halt ladder: a complaint event with no complaint of its network")
	}
	if !smtpComplaintHalts(complaint) {
		return nil
	}
	if len(complaint.MessageIdHash) != 0 {
		earlier, err := self.deps.Halts.FindComplaints(ctx, &SmtpComplaintKey{NetworkId: event.NetworkId, MessageIdHash: complaint.MessageIdHash})
		if err != nil {
			return err
		}
		for _, other := range earlier {
			if other.ComplaintId == complaint.ComplaintId {
				continue
			}
			if other.Type == SmtpComplaintTypeNotSpam {
				return nil
			}
			if smtpComplaintHalts(other) && !other.ArrivalTime.After(complaint.ArrivalTime) {
				// each (network, Message-ID hash) counts once
				return nil
			}
		}
	}
	limits, err := self.tierLimits(ctx, event.NetworkId)
	if err != nil {
		return err
	}
	label := smtpReportLabel(self.settings, complaint.Domain)

	if smtpHaltRuleFraud(complaint.Type) {
		if err := halt("", SmtpHaltTriggerFraud); err != nil {
			return err
		}
		// with §21's review
		if err := self.deps.Sink.OpenSmtpCase(ctx, &SmtpAbuseReport{
			ComplaintId:   complaint.ComplaintId,
			NetworkId:     complaint.NetworkId,
			Domain:        complaint.Domain,
			Category:      complaint.Type,
			JoinResult:    complaint.JoinResult,
			ReporterClass: SmtpReporterClassLoop,
			ArrivalTime:   complaint.ArrivalTime,
		}); err != nil {
			return err
		}
	}
	if smtpHaltRuleLabelComplaint(label) {
		if err := halt(label, SmtpHaltTriggerLabelComplaint); err != nil {
			return err
		}
		labelHalts, err := self.deps.Halts.FindHalts(ctx, event.NetworkId, event.Time.Add(-self.settings.HaltWindow))
		if err != nil {
			return err
		}
		labels := map[string]bool{}
		for _, labelHalt := range labelHalts {
			if labelHalt.Label != "" {
				labels[labelHalt.Label] = true
			}
		}
		if smtpHaltRuleSecondLabel(limits.Tier, len(labels), self.settings) {
			if err := halt("", SmtpHaltTriggerSecondLabel); err != nil {
				return err
			}
		}
	}
	if smtpHaltRuleCommunityComplaint(limits.Tier, label) {
		if err := halt("", SmtpHaltTriggerCommunityComplaint); err != nil {
			return err
		}
	}
	basisPoints, floor, trigger := 0, 0, ""
	switch limits.Tier {
	case smtpTierPro:
		basisPoints, floor, trigger = self.settings.HaltProComplaintBasisPoints, self.settings.HaltProComplaintFloor, SmtpHaltTriggerProRate
	case smtpTierTeam:
		basisPoints, floor, trigger = self.settings.HaltTeamComplaintBasisPoints, self.settings.HaltTeamComplaintFloor, SmtpHaltTriggerTeamRate
	}
	if trigger != "" {
		since := event.Time.Add(-self.settings.HaltWindow)
		complaints, err := self.deps.Halts.FindComplaints(ctx, &SmtpComplaintKey{NetworkId: event.NetworkId, Since: since})
		if err != nil {
			return err
		}
		recipientCount, err := self.deps.Lookups.RecipientCount(ctx, event.NetworkId, since)
		if err != nil {
			return err
		}
		if smtpHaltRuleRate(uint64(len(smtpCountedComplaints(complaints))), recipientCount, basisPoints, floor) {
			if err := halt("", trigger); err != nil {
				return err
			}
		}
	}
	return nil
}

// KEYS[1] {smq_<networkId>}. ARGV: an hour's bounce field, the bounces to add, the field's ttl in ms and the
// key's in ms. Adds to the field, which lives its ttl from its first count, and keeps the key at least its ttl.
// Returns the field's count.
var SmtpQuotaBounceScript = &sidecar.RedisScript{
	Name: "smtp_quota_bounce",
	Source: `
local count = redis.call('HINCRBY', KEYS[1], ARGV[1], tonumber(ARGV[2]))
if count == tonumber(ARGV[2]) then
  redis.call('HPEXPIRE', KEYS[1], tonumber(ARGV[3]), 'FIELDS', 1, ARGV[1])
end
if redis.call('PTTL', KEYS[1]) < tonumber(ARGV[4]) then
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]))
end
return count
`,
}

// {smq_<networkId>}'s hourly hard-bounce field for t's UTC hour (QD-199).
func smtpBounceField(t time.Time) string {
	return "hb:" + t.UTC().Format("2006010215")
}

// Adds the outcome's hard bounces to their hour, then judges the window's against its recipients. With no
// Redis nothing is counted, and the rule halts nothing.
func (self *SmtpHaltLadder) applyHardBounces(ctx context.Context, event *SmtpHaltEvent, halt func(label string, trigger string) error) error {
	if self.redis == nil || event.HardBounceCount == 0 {
		return nil
	}
	key := smtpQuotaKey(event.NetworkId)
	if _, err := self.redis.RunScript(ctx, SmtpQuotaBounceScript, []string{key}, []string{
		smtpBounceField(event.Time),
		strconv.FormatUint(uint64(event.HardBounceCount), 10),
		strconv.FormatInt(self.settings.HaltBounceFieldTimeout.Milliseconds(), 10),
		strconv.FormatInt(self.settings.QuotaKeyTimeout.Milliseconds(), 10),
	}); err != nil {
		return err
	}
	fields, err := self.redis.HashGetAll(ctx, key)
	if err != nil {
		return err
	}
	since := event.Time.Add(-self.settings.HaltWindow)
	var bounceCount uint64
	for field, value := range fields {
		hourText, ok := strings.CutPrefix(field, "hb:")
		if !ok {
			continue
		}
		hour, err := time.Parse("2006010215", hourText)
		if err != nil || hour.Add(time.Hour).Before(since) || hour.After(event.Time) {
			continue
		}
		count, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			continue
		}
		bounceCount += count
	}
	recipientCount, err := self.deps.Lookups.RecipientCount(ctx, event.NetworkId, since)
	if err != nil {
		return err
	}
	limits, err := self.tierLimits(ctx, event.NetworkId)
	if err != nil {
		return err
	}
	if smtpHaltRuleHardBounces(bounceCount, recipientCount, smtpLimit(limits, SmtpLimitHardBouncePercent), smtpLimit(limits, SmtpLimitHardBounceFloor)) {
		return halt("", SmtpHaltTriggerHardBounces)
	}
	return nil
}

// Writes a halt: its row first, so every edge's reload finds it, then this process's quota, then the hints.
func (self *SmtpHaltLadder) setHalt(ctx context.Context, halt *SmtpHalt) error {
	if err := self.deps.Store.SetHalt(ctx, halt); err != nil {
		return err
	}
	self.halts.Add(1, halt.Trigger)
	if self.deps.Quota != nil {
		// a write that fails leaves the halt in memory, and the reload writes it again
		self.deps.Quota.ApplyHalt(ctx, halt)
	}
	retryAfter := halt.StartTime.Add(SmtpHaltDuration).Sub(self.clock.Now())
	self.hint(ctx, halt.NetworkId, protocol.SmtpStatusKind_SMTP_STATUS_HALTED, retryAfter)
	return nil
}

// §14.8's last rung: once the network has HaltSuspendCount halts in the window, §21 is asked to suspend it.
func (self *SmtpHaltLadder) checkSuspension(ctx context.Context, networkId sidecar.Id) error {
	now := self.clock.Now()
	halts, err := self.deps.Halts.FindHalts(ctx, networkId, now.Add(-self.settings.HaltSuspendWindow))
	if err != nil {
		return err
	}
	haltIds := []sidecar.Id{}
	for _, halt := range halts {
		// a burner label's halt is no strike (abuse-core-policy-readings#3)
		if halt.Label == "" {
			haltIds = append(haltIds, halt.HaltId)
		}
	}
	if !smtpHaltRuleSuspend(len(haltIds), self.settings) {
		return nil
	}
	err = self.deps.Sink.RequestSmtpSuspension(ctx, &SmtpSuspensionRequest{NetworkId: networkId, HaltIds: haltIds, RequestTime: now})
	if err != nil {
		self.suspensions.Add(1, smtpHaltHintFailed)
		return err
	}
	self.suspensions.Add(1, smtpHaltHintOk)
	return nil
}

// Hints the network's clients that sent within HaltWindow, off the path: a client that misses it gets HALTED
// at its next preamble, so a failure is counted and goes no further.
func (self *SmtpHaltLadder) hint(ctx context.Context, networkId sidecar.Id, kind protocol.SmtpStatusKind, retryAfter time.Duration) {
	if self.push == nil {
		return
	}
	now := self.clock.Now()
	clientIds, err := self.deps.Halts.SendingClients(ctx, networkId, now.Add(-self.settings.HaltWindow))
	if err != nil {
		self.hints.Add(1, smtpHaltHintFailed)
		return
	}
	if len(clientIds) == 0 {
		return
	}
	status := &protocol.SmtpStatus{Kind: uint32(kind)}
	if kind != protocol.SmtpStatusKind_SMTP_STATUS_CLEAR {
		status.RetryAfterMs = uint32(min(max(retryAfter.Milliseconds(), 1), math.MaxUint32))
	}
	body, err := proto.Marshal(status)
	if err != nil {
		self.hints.Add(1, smtpHaltHintFailed)
		return
	}
	connectIds := make([]connect.Id, 0, len(clientIds))
	for _, clientId := range clientIds {
		connectIds = append(connectIds, connect.Id(clientId))
	}
	err = self.push.Hint(ctx, connectIds, &sidecar.ClientHint{
		Topic:   sidecar.PushTopicMail,
		Version: uint64(now.UnixMilli()),
		Kind:    uint32(protocol.MessageType_SMTP_STATUS),
		Body:    body,
	})
	if err != nil {
		self.hints.Add(1, smtpHaltHintFailed)
		return
	}
	self.hints.Add(1, smtpHaltHintOk)
}

// The complaints of the network that arrived in the halt's window, counted as §14.8 counts them.
func (self *SmtpHaltLadder) countedBefore(ctx context.Context, halt *SmtpHalt) ([]*SmtpComplaint, error) {
	since := halt.StartTime.Add(-self.settings.HaltWindow)
	complaints, err := self.deps.Halts.FindComplaints(ctx, &SmtpComplaintKey{NetworkId: halt.NetworkId, Since: since})
	if err != nil {
		return nil, err
	}
	held := []*SmtpComplaint{}
	for _, complaint := range complaints {
		// a not-spam that came since still cancels what it names
		if complaint.Type == SmtpComplaintTypeNotSpam || !complaint.ArrivalTime.After(halt.StartTime) {
			held = append(held, complaint)
		}
	}
	return smtpCountedComplaints(held), nil
}

// Rechecks a halt for POST /smtp/appeal: its complaints counted again, a duplicate once and one a not-spam
// cancelled not at all, and lifts it when its rule no longer holds. lifted is false for a halt that still
// holds, one not found or ended, and for record cuts and hard bounces, which §21 reviews.
func (self *SmtpHaltLadder) Lift(ctx context.Context, networkId sidecar.Id, haltId sidecar.Id) (lifted bool, err error) {
	self.applyLock.Lock()
	defer self.applyLock.Unlock()
	now := self.clock.Now()
	active, err := self.activeHalts(ctx, networkId, now)
	if err != nil {
		return false, err
	}
	var halt *SmtpHalt
	for _, candidate := range active {
		if candidate.HaltId == haltId {
			halt = candidate
		}
	}
	if halt == nil {
		return false, nil
	}
	holds := true
	switch halt.Trigger {
	case SmtpHaltTriggerLabelComplaint, SmtpHaltTriggerCommunityComplaint, SmtpHaltTriggerFraud, SmtpHaltTriggerProRate, SmtpHaltTriggerTeamRate:
		counted, err := self.countedBefore(ctx, halt)
		if err != nil {
			return false, err
		}
		matching := 0
		for _, complaint := range counted {
			label := smtpReportLabel(self.settings, complaint.Domain)
			switch halt.Trigger {
			case SmtpHaltTriggerLabelComplaint:
				if label == halt.Label {
					matching += 1
				}
			case SmtpHaltTriggerCommunityComplaint:
				if label == "" {
					matching += 1
				}
			case SmtpHaltTriggerFraud:
				if smtpHaltRuleFraud(complaint.Type) {
					matching += 1
				}
			default:
				matching += 1
			}
		}
		switch halt.Trigger {
		case SmtpHaltTriggerProRate, SmtpHaltTriggerTeamRate:
			recipientCount, err := self.deps.Lookups.RecipientCount(ctx, networkId, halt.StartTime.Add(-self.settings.HaltWindow))
			if err != nil {
				return false, err
			}
			basisPoints, floor := self.settings.HaltProComplaintBasisPoints, self.settings.HaltProComplaintFloor
			if halt.Trigger == SmtpHaltTriggerTeamRate {
				basisPoints, floor = self.settings.HaltTeamComplaintBasisPoints, self.settings.HaltTeamComplaintFloor
			}
			holds = smtpHaltRuleRate(uint64(matching), recipientCount, basisPoints, floor)
		default:
			holds = 0 < matching
		}
	case SmtpHaltTriggerSecondLabel:
		labelHalts, err := self.deps.Halts.FindHalts(ctx, networkId, halt.StartTime.Add(-self.settings.HaltWindow))
		if err != nil {
			return false, err
		}
		labels := map[string]bool{}
		for _, labelHalt := range labelHalts {
			if labelHalt.Label != "" && !labelHalt.StartTime.After(halt.StartTime) {
				labels[labelHalt.Label] = true
			}
		}
		holds = smtpHaltRuleSecondLabel(smtpTierCommunity, len(labels), self.settings)
	}
	if holds {
		return false, nil
	}
	if err := self.deps.Halts.DeleteHalt(ctx, halt.HaltId); err != nil {
		return false, err
	}
	self.lifts.Add(1, halt.Trigger)
	if self.deps.Quota != nil {
		remaining := []*SmtpHalt{}
		for _, other := range active {
			if other.HaltId != halt.HaltId {
				remaining = append(remaining, other)
			}
		}
		if err := self.deps.Quota.LiftHalt(ctx, halt, remaining); err != nil {
			return true, err
		}
	}
	self.hint(ctx, networkId, protocol.SmtpStatusKind_SMTP_STATUS_CLEAR, 0)
	return true, nil
}
