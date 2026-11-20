// The send gate (§14.5's authorization, §14.7's send gate, D-SMTP-14): who may send internet mail through
// this edge, from what domain, decided from memory alone. The preamble path never touches Postgres
// (I-12, §22.5), so every fact the gate reads is held in memory that a feed fills off the path: SmtpGate
// for §8's rows, §7.6's domains, §12's labels and §15's mail enable time, ServiceHost.Abuse for §21.7's
// standing and network_verified, and SmtpGate's breaker for §21.5. A fact not loaded answers TRY_LATER,
// and asking for it is what starts its load (plan-SMTP-small-readings#20, plan-SOCK-gate-data), so a
// cold edge holds mail at the sender and never at the edge.
//
// The rows, in order, the first that refuses answering:
//
//	standing           probation and any standing this build does not know: DENIED (same-network deposits
//	                   never reach an edge); suspended: HALTED for SuspendedRetryTimeout, §21.7's mail halt, so
//	                   the mail waits at its sender until the lift and is never failed for it (QD-1124), and
//	                   no smtp_halt row is written, so the halt ladder's 3 network halts in 30 days does not
//	                   count it; restricted sends at Community caps, its halt being the halts' to answer
//	                   (SmtpQuota)
//	verified           an unverified, anonymous-only network: DENIED
//	mail enabled       never enabled: DENIED; enabled less than MailEnableDelay ago: TRY_LATER until then
//	mail_send          §8's send grant for the ticket's sidecar (AclGateView.MaySendMail): DENIED, or QUOTA
//	                   for a spent network
//	from domain        a zone of the network (<net>.<root>, an alias's <alias>.<root>, a scope's
//	                   <scope>.<net>.<root>) or one of its verified network_domain names; a burner's From is
//	                   <blabel>.<zone> with the BURNER flag, and the flag only with one, and its label's word
//	                   is screened (ScreenName): DENIED
//	breaker            §21.5: restricted networks pause at level 1, Community at 2, all but trusted Team at
//	                   3: HALTED
//
// The edge reads the network and sidecar from the ticket, never from the sidecar (§14.5). A live name,
// the network's label, an alias or a scope label, was screened when it was made and is never screened
// again, so a list change withdraws nothing (§21.6); a burner's label lives only in mailcfg and is never
// screened at creation, so its word is screened here, at every send.
//
// Safe for concurrent use: a check reads the interfaces and allocates its answer.

package smtpedgeservice

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §15.9's burner label: a generated word and four digits.
var smtpBurnerLabelPattern = regexp.MustCompile(`^[a-z]+-[0-9]{4}$`)

// §21.5's breaker levels, which ABUSE-M9-02's model.MailBreakerLevel feeds through the gate's refresh.
type SmtpBreakerLevel int

const (
	SmtpBreakerLevelNone SmtpBreakerLevel = 0
	// <root>'s spam or complaint rate at 0.10%: restricted networks pause and Community caps halve.
	SmtpBreakerLevelRestrict SmtpBreakerLevel = 1
	// Either at 0.20%, or a sending address listed: Community pauses too.
	SmtpBreakerLevelCommunity SmtpBreakerLevel = 2
	// 0.30%: Community and Pro pause, and only a trusted Team sends.
	SmtpBreakerLevelAll SmtpBreakerLevel = 3
)

// §21.5's breakers as the edge reads them, refreshed off the path within the feed's refresh.
type SmtpBreakerState struct {
	Level SmtpBreakerLevel
	// Sending addresses on Spamhaus SBL or CSS or SNDS red: out of the sending set (SmtpSendingSet), never
	// out of ingress (owner decision 124).
	ListedAddresses []netip.Addr
}

// Whether address is listed.
func (self *SmtpBreakerState) Listed(address netip.Addr) bool {
	return self != nil && slices.Contains(self.ListedAddresses, address.Unmap())
}

// One network's mail facts, as the gate's feed loaded them: plan-SOCK-gate-data's listen facts,
// network_dns_zone.report_token (plan-SMTP-net-token), §12's labels, §7.6's domains and the network's
// effective limits. A value: the feed replaces it whole and never changes one handed out.
type SmtpGateFacts struct {
	// POST /mail/enable's time, mail_network.create_time. Zero when the network has no mail_network row.
	MailEnableTime time.Time
	// The network's <net> label: its zone <net>.<root>, and b.<net>.<root>, the envelope domain (§14.6).
	Label string
	// Its live aliases, each a zone <alias>.<root> (§12.7).
	Aliases []string
	// Its Team scope labels, each a zone <scope>.<net>.<root> (§12.7; none before M6).
	ScopeLabels []string
	// Its verified network_domain names (§7.6), which a Team may send From (D-SMTP-15).
	VerifiedDomains []string
	// Names a reviewer allowed this network (ABUSE-M5-08's screen_allow), which turn a review into an
	// allow.
	ReviewAllowedNames []string
	// network_dns_zone.report_token: Feedback-ID's nettoken (plan-SMTP-net-token).
	ReportToken string
	// Quota.Limits' answer for the network, its tier among them, refreshed off the path (§20.7's 5 s).
	Limits *sidecar.QuotaLimits
}

// The send gate's memory, which SMTP-M9-20's production gate fills from api's internal gate routes and
// sidecartest.FakeSmtpGate in tests. No method does I/O or blocks. Safe for concurrent use.
type SmtpGate interface {
	// The network's facts. ok false while they are not loaded: the call has asked for their load, off the
	// path, and the preamble answers TRY_LATER.
	Facts(networkId sidecar.Id) (facts *SmtpGateFacts, ok bool)
	// §8's mail_send for the sidecar (AclGateView.MaySendMail). AclReasonNoState while the network's
	// state is not loaded, which asks for its load.
	MaySendMail(networkId sidecar.Id, sidecarId sidecar.Id, now time.Time) sidecar.AclDecision
	// §21.5's breaker state. ok false until first loaded.
	Breaker() (state *SmtpBreakerState, ok bool)
	// The Community tier's limits, which a restricted network sends at (§14.7). ok false until loaded.
	CommunityLimits() (limits *sidecar.QuotaLimits, ok bool)
}

// What the gate judges of one preamble: the ticket's identity and the declared From.
type SmtpGateRequest struct {
	// From the ticket, never from the sidecar.
	NetworkId sidecar.Id
	SidecarId sidecar.Id
	// From the preamble, lowercased, an LDH name already.
	HeaderFromDomain string
	// SmtpPreamble.flags.
	Flags uint32
}

// The gate's answer.
type SmtpGateDecision struct {
	// OK, DENIED, HALTED, QUOTA or TRY_LATER. Never 0.
	Code protocol.SmtpPreambleCode
	// For HALTED, QUOTA and TRY_LATER.
	RetryAfter time.Duration
	// Which row answered, a word from a closed set: never sent, never a label value naming anyone.
	Reason string

	// The rest only on OK.
	Facts    *SmtpGateFacts
	Standing sidecar.AbuseStanding
	// A burner's <blabel>, which its halts name (§14.8); empty for network mail.
	Label  string
	Burner bool
	// QuotaLimits.Tier, which Feedback-ID names.
	Tier string
	// b.<net>.<root> (§14.6): the envelope domain the proofs hold MAIL FROM to (Z4).
	EnvelopeDomain string
	// What the quota applies: the network's limits, at Community caps when restricted (§14.7), with
	// Community's rate caps halved at breaker level 1 (§21.5).
	Limits *sidecar.QuotaLimits
	// Whether §14.7's fleet-wide Community counters count this preamble: a Community network, or a
	// restricted one at Community caps.
	Community bool
}

// The gate's reasons.
const (
	smtpGateReasonUnloaded   = "unloaded"
	smtpGateReasonStanding   = "standing"
	smtpGateReasonSuspended  = "suspended"
	smtpGateReasonUnverified = "unverified"
	smtpGateReasonMailOff    = "mail_off"
	smtpGateReasonMailNew    = "mail_new"
	smtpGateReasonMailSend   = "mail_send"
	smtpGateReasonSpent      = "spent"
	smtpGateReasonFrom       = "from_domain"
	smtpGateReasonScreen     = "screen"
	smtpGateReasonBreaker    = "breaker"
)

// A refusal.
func smtpGateRefusal(code protocol.SmtpPreambleCode, retryAfter time.Duration, reason string) *SmtpGateDecision {
	return &SmtpGateDecision{Code: code, RetryAfter: retryAfter, Reason: reason}
}

// The rate caps §21.5's level 1 halves for Community: what a day or a burst allows, never what one
// message or one connection may carry.
var smtpBreakerHalvedLimitKeys = []string{
	SmtpLimitConnectionsPerDay,
	SmtpLimitRecipientsPerDay,
	SmtpLimitBytesPerDay,
	SmtpLimitBurst,
}

// The smtp_* limits a restricted network takes at Community's value when that is lower (§14.7): every
// tier key, never a sidecar_abuse: one, which is equal on every tier.
var smtpTierLimitKeys = []string{
	SmtpLimitConnectionsPerDay,
	SmtpLimitBytesPerDay,
	SmtpLimitRecipientsPerMessage,
	SmtpLimitRecipientsPerDay,
	SmtpLimitMessageBytes,
	SmtpLimitBurst,
	SmtpLimitBurstWindow,
	SmtpLimitConcurrentConnections,
}

// The lower of two limits, -1 being none.
func smtpLowerLimit(a int64, b int64) int64 {
	switch {
	case a == -1:
		return b
	case b == -1:
		return a
	}
	return min(a, b)
}

// Judges one preamble's identity and From against the gate's memory at now. abuse is the host's
// AbuseGate.
func checkSmtpGate(gate SmtpGate, abuse sidecar.AbuseGate, request *SmtpGateRequest, now time.Time, settings *SmtpEdgeSettings) *SmtpGateDecision {
	unloaded := smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, settings.GateRetryTimeout, smtpGateReasonUnloaded)
	if gate == nil || abuse == nil {
		return unloaded
	}
	// every fact is asked for before any refuses, so one preamble starts every load it lacks
	facts, factsOk := gate.Facts(request.NetworkId)
	standing, standingOk := abuse.Standing(connect.Id(request.NetworkId))
	verified, verifiedOk := abuse.Verified(connect.Id(request.NetworkId))
	breaker, breakerOk := gate.Breaker()
	mailSend := gate.MaySendMail(request.NetworkId, request.SidecarId, now)
	if !factsOk || facts == nil || !standingOk || !verifiedOk || !breakerOk || breaker == nil {
		return unloaded
	}
	if !mailSend.Allowed && mailSend.Reason == sidecar.AclReasonNoState {
		return unloaded
	}

	restricted := false
	switch standing {
	case sidecar.AbuseStandingStandard, sidecar.AbuseStandingTrusted:
	case sidecar.AbuseStandingRestricted:
		restricted = true
	case sidecar.AbuseStandingSuspended:
		// §21.7's mail halt: held at the sender until the lift, and no smtp_halt row (QD-1124)
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, settings.SuspendedRetryTimeout, smtpGateReasonSuspended)
	default:
		// probation, and a standing this build does not know
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, 0, smtpGateReasonStanding)
	}

	if !verified {
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, 0, smtpGateReasonUnverified)
	}

	if facts.MailEnableTime.IsZero() {
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, 0, smtpGateReasonMailOff)
	}
	if start := facts.MailEnableTime.Add(settings.MailEnableDelay); now.Before(start) {
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, start.Sub(now), smtpGateReasonMailNew)
	}

	if !mailSend.Allowed {
		switch mailSend.Reason {
		case sidecar.AclReasonQuota:
			return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, settings.SpentRetryTimeout, smtpGateReasonSpent)
		}
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, 0, smtpGateReasonMailSend)
	}

	if !settings.ldhLabel(facts.Label) {
		return unloaded
	}
	label, reason := checkSmtpFromDomain(facts, standing, request, settings)
	if reason != "" {
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, 0, reason)
	}

	if facts.Limits == nil {
		return unloaded
	}
	tier := facts.Limits.Tier
	if _, ok := smtpFeedbackTierLetters[tier]; !ok {
		return unloaded
	}
	community := tier == smtpTierCommunity || restricted

	pause := false
	switch {
	case breaker.Level >= SmtpBreakerLevelAll:
		pause = !(tier == smtpTierTeam && standing == sidecar.AbuseStandingTrusted)
	case breaker.Level >= SmtpBreakerLevelCommunity:
		pause = community
	case breaker.Level >= SmtpBreakerLevelRestrict:
		pause = restricted
	}
	if pause {
		return smtpGateRefusal(protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, settings.BreakerRetryTimeout, smtpGateReasonBreaker)
	}

	limits := &sidecar.QuotaLimits{Tier: tier, Limits: map[string]int64{}}
	for key, value := range facts.Limits.Limits {
		limits.Limits[key] = value
	}
	if restricted {
		communityLimits, ok := gate.CommunityLimits()
		if !ok || communityLimits == nil {
			return unloaded
		}
		for _, key := range smtpTierLimitKeys {
			// an absent key reads 0, not included, on either side
			limits.Limits[key] = smtpLowerLimit(limits.Limits[key], communityLimits.Limits[key])
		}
	}
	if community && breaker.Level >= SmtpBreakerLevelRestrict {
		for _, key := range smtpBreakerHalvedLimitKeys {
			if value := limits.Limits[key]; 0 < value {
				limits.Limits[key] = max(value/2, 1)
			}
		}
	}

	return &SmtpGateDecision{
		Code:           protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK,
		Facts:          facts,
		Standing:       standing,
		Label:          label,
		Burner:         label != "",
		Tier:           tier,
		EnvelopeDomain: "b." + strings.ToLower(facts.Label) + "." + strings.ToLower(settings.Root),
		Limits:         limits,
		Community:      community,
	}
}

// The From domain's row: whether it is the network's to send from, and a burner's label when it is one.
// A non-empty reason refuses.
func checkSmtpFromDomain(facts *SmtpGateFacts, standing sidecar.AbuseStanding, request *SmtpGateRequest, settings *SmtpEdgeSettings) (label string, reason string) {
	from := strings.ToLower(request.HeaderFromDomain)
	root := strings.ToLower(settings.Root)
	burner := request.Flags&sidecar.SmtpFlagBurner != 0

	zones := []string{strings.ToLower(facts.Label) + "." + root}
	for _, alias := range facts.Aliases {
		zones = append(zones, strings.ToLower(alias)+"."+root)
	}
	for _, scopeLabel := range facts.ScopeLabels {
		zones = append(zones, strings.ToLower(scopeLabel)+"."+zones[0])
	}

	if !burner {
		if slices.Contains(zones, from) {
			return "", ""
		}
		for _, domain := range facts.VerifiedDomains {
			if strings.TrimSuffix(strings.ToLower(domain), ".") == from {
				return "", ""
			}
		}
		// a burner's From without the flag would issue it network mail's Feedback-ID class
		return "", smtpGateReasonFrom
	}

	burnerLabel, zone, found := strings.Cut(from, ".")
	if !found || !slices.Contains(zones, zone) || !smtpBurnerLabelPattern.MatchString(burnerLabel) {
		return "", smtpGateReasonFrom
	}
	word := burnerLabel[:strings.LastIndexByte(burnerLabel, '-')]
	screenFacts := &sidecar.ScreenFacts{
		VerifiedDomains: facts.VerifiedDomains,
		Probation:       standing == sidecar.AbuseStandingProbation || standing == sidecar.AbuseStandingRestricted,
		ReviewAllowed:   slices.Contains(facts.ReviewAllowedNames, word) || slices.Contains(facts.ReviewAllowedNames, burnerLabel),
		ScopeLabels:     facts.ScopeLabels,
	}
	if sidecar.ScreenName(word, screenFacts) != sidecar.ScreenVerdictAllow {
		return "", smtpGateReasonScreen
	}
	return burnerLabel, ""
}
