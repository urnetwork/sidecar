// What rpt.bringyour.com's platform listener calls for each report it takes (§14.8, §15.4's platform
// mail, D-SMTP-12, D-SMTP-19, D-SMTP-23, D-MAIL-10). It runs in-process in mxedge's platform block
// (plan-SMTP-report-intake-home), once per recipient the listener took. This is §2.8's one place a
// URnetwork server reads mail meant for it (mx-4): the envelope stays in memory, the message is parsed
// header-only and for aggregate data only, and its raw bytes are sealed to the network mail key or
// dropped. Nothing here persists plaintext, and no log, row or metric carries report text, an
// envelope, a recipient or an address (I-2, I-13); a failure is logged as a word.
//
// For each report, in order:
//
//  1. Map the recipient: <token>@<report host> to its network (plan-SMTP-net-token), root@<report host>
//     for <root>'s own rua, or abuse@ and postmaster@ on <root>. Anything else, an unknown token
//     included, is dropped unread.
//  2. Walk the MIME, then parse an aggregate or an ARF report, or for role mail the enclosed header
//     block alone.
//  3. One pass over the raw bytes through the reporter's DKIM body hash and the seal, when there is a
//     key to seal to.
//  4. InsertAggregate or InsertComplaint, or nothing.
//
// An aggregate counts only from a reporter whose DKIM verifies, at a network's rua token or <root>'s,
// once per (reporter, report_id). <root>'s rows name many networks, so they split by header_from's
// <net> label, a burner's <blabel>.<net>.<root> counting toward <net>; that copy is sealed to no one,
// since any one network's copy would show it the others' rows (smtp-m5-01-sealed-report-bytes.md). An
// ARF report or a role mail counts only once SMTP-M9-15's join attributes it to a network, and until
// that lands nothing is attributable: every one is dropped unread. An ARF report to a token or to
// <root> counts only from an allowlisted loop operator; a role mail opens a case through SmtpAbuseSink,
// whoever sent it, as a stranger's report reaches only review (§21.8).
//
// With no mail key, the raw bytes are dropped unread and only the fields are kept
// (plan-SMTP-report-seal-key's interim): an aggregate still counts, and an aggregate's sealed-copy row
// is not written, having nothing to hold.

package smtpedgeservice

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// How the intake ended with a report. Every outcome but an error is an accepted message: the listener
// answers 250, and a dropped report tells its sender nothing.
type SmtpReportOutcome string

const (
	// An aggregate's counts stored.
	SmtpReportOutcomeCounted SmtpReportOutcome = "counted"
	// An aggregate already counted for its reporter and report id.
	SmtpReportOutcomeDuplicate SmtpReportOutcome = "duplicate"
	// An aggregate with no row from a sending address.
	SmtpReportOutcomeEmpty SmtpReportOutcome = "empty"
	// An attributed ARF report stored.
	SmtpReportOutcomeComplaint SmtpReportOutcome = "complaint"
	// An attributed role mail stored and handed to §21's case flow.
	SmtpReportOutcomeCase SmtpReportOutcome = "case"
	// Dropped unread: no network's token and no role address.
	SmtpReportOutcomeUnknownRecipient SmtpReportOutcome = "unknown_recipient"
	// Dropped: past a bound, or nothing this intake reads.
	SmtpReportOutcomeRefused SmtpReportOutcome = "refused"
	// Dropped: the reporter's DKIM did not verify, or an ARF reporter is no allowlisted loop.
	SmtpReportOutcomeUnverified SmtpReportOutcome = "unverified"
	// Dropped unread: names no network (§21.8).
	SmtpReportOutcomeUnattributed SmtpReportOutcome = "unattributed"
)

// What a report is, for its metric.
const (
	smtpReportKindDmarc   = "dmarc"
	smtpReportKindTlsRpt  = "tlsrpt"
	smtpReportKindArf     = "arf"
	smtpReportKindRole    = "role"
	smtpReportKindUnknown = "unknown"
	// The metric's result for a report the intake could not finish, which the listener answers 451.
	smtpReportResultFailed = "failed"
)

// A report's recipient, by how it routes.
const (
	smtpReportRouteToken = "token"
	smtpReportRouteRoot  = "root"
	smtpReportRouteRole  = "role"
	// <root>'s rua's fixed local part, which no 26-character token can equal (plan-SMTP-net-token).
	smtpReportRootLocalPart = "root"
)

// A report token: 26 lowercase base32 characters of 16 random octets (plan-SMTP-net-token).
var smtpReportTokenPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

// One message the listener took, for one of its recipients.
type SmtpReportMessage struct {
	// The RCPT the listener took: <token>@<report host>, root@<report host>, or abuse@ or postmaster@
	// on <root>. Memory only (§2.8 mx-4).
	Recipient   string
	ArrivalTime time.Time
	// The message as received. Read once and never kept.
	Raw []byte
}

// network_dns_zone.report_token's index (plan-SMTP-net-token), which server serves. Safe for concurrent
// use.
type SmtpNetTokenSource interface {
	// The network whose zone holds token. ok false for a token no zone holds.
	NetworkForReportToken(ctx context.Context, token string) (networkId sidecar.Id, ok bool, err error)
}

// §12's label map (DNS-M5-10's model.ResolveNetworkLabel), for <root>'s rows. Safe for concurrent use.
type SmtpLabelSource interface {
	// The network a <net> label or alias names. ok false for a label no live network holds.
	NetworkForLabel(ctx context.Context, label string) (networkId sidecar.Id, ok bool, err error)
}

// What §21's case flow takes from a report: api-14's list and nothing more, never the sealed copy, a
// reporter's address or report text.
type SmtpAbuseReport struct {
	// The smtp_complaint row it came with.
	ComplaintId sidecar.Id
	NetworkId   sidecar.Id
	// The reported From domain, a burner's label in it.
	Domain string
	// The complaint's type, an SmtpComplaintType* word.
	Category string
	// Attribution's confidence.
	JoinResult string
	// "loop" for an allowlisted feedback loop, "role" for anyone mailing abuse@ or postmaster@.
	ReporterClass string
	ArrivalTime   time.Time
}

// Reporter classes, which separate a feed from a stranger (§21.17).
const (
	SmtpReporterClassLoop = "loop"
	SmtpReporterClassRole = "role"
)

// §21's case flow, as the intake reaches it: ABUSE-M5-09's model.NewAbuseSmtpSink, and
// sidecartest.FakeSmtpAbuseSink until then. SMTP-M9-16's suspensions and SMTP-M9-17's investigation
// signals add their calls at M9. Safe for concurrent use.
type SmtpAbuseSink interface {
	// Opens or adds to a case for an attributed report.
	OpenSmtpCase(ctx context.Context, report *SmtpAbuseReport) error
}

// SMTP-M9-15's attribution, as the intake calls it. Safe for concurrent use.
type SmtpReportJoin interface {
	// The smtp_complaint row a report would leave, its network, domain, signature and join fields set
	// from the parsed headers alone, or nil when it names no send it can attribute (§14.8). The intake
	// sets the rest.
	JoinReport(ctx context.Context, report *SmtpArfReport) (*SmtpComplaint, error)
}

// What the intake reads beyond the store. Each nil member fails closed: no Tokens and every token is
// unknown, no Labels and <root>'s rows name no network, no Keys and nothing is sealed, no Txt and no
// reporter verifies, no Join and no ARF report or role mail is attributable.
type SmtpReportIntakeDeps struct {
	Tokens SmtpNetTokenSource
	Labels SmtpLabelSource
	Keys   SmtpReportKeySource
	Txt    SmtpDnsTxtSource
	Join   SmtpReportJoin
	// Required with Join, since an attributed role mail must reach §21.
	Sink SmtpAbuseSink
	// nil discards.
	Log sidecar.Logger
}

// The report intake. Safe for concurrent use: Accept holds no state between calls.
type SmtpReportIntake struct {
	store    SmtpEdgeStore
	deps     *SmtpReportIntakeDeps
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	metrics  *smtpMetrics
	verifier *SmtpDkimVerifier
}

// An intake writing to store. host needs Metrics, and its Clock bounds store and DNS calls.
func NewSmtpReportIntake(host *sidecar.ServiceHost, store SmtpEdgeStore, deps *SmtpReportIntakeDeps, settings *SmtpEdgeSettings) (*SmtpReportIntake, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("smtp report intake needs a host with Metrics")
	}
	if store == nil {
		return nil, errors.New("smtp report intake needs a store")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &SmtpReportIntakeDeps{}
	}
	if deps.Join != nil && deps.Sink == nil {
		return nil, errors.New("smtp report intake: an attribution with no abuse sink")
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := host.ClockOrReal()
	return &SmtpReportIntake{
		store:    store,
		deps:     deps,
		settings: settings,
		clock:    clock,
		log:      log,
		metrics:  newSmtpMetrics(host.Metrics),
		verifier: NewSmtpDkimVerifier(settings, deps.Txt, nil, clock),
	}, nil
}

// Takes one message for one recipient, before the listener answers its DATA or BDAT. An error means the
// intake could not finish, a store or DNS that did not answer, and the listener answers 451 so the
// sender retries; it carries no report text, and the listener logs none of it either. For abuse@ or
// postmaster@, any outcome but SmtpReportOutcomeCase is mail the parse could not attribute, which
// plan-ABUSE-auto-reply has the listener refuse with 550 5.7.1 and its pointer to the form instead of
// 250.
func (self *SmtpReportIntake) Accept(ctx context.Context, message *SmtpReportMessage) (SmtpReportOutcome, error) {
	testHookBarrier("smtpedge.report_accept.before", "")
	outcome, kind, err := self.accept(ctx, message)
	testHookBarrier("smtpedge.report_accept.after", "")
	if err != nil {
		self.metrics.reports.Add(1, kind, smtpReportResultFailed)
		self.log.Infof("[smtpedge]a %s report could not be taken; the sender retries", kind)
		return "", err
	}
	self.metrics.reports.Add(1, kind, string(outcome))
	return outcome, nil
}

// A recipient's route.
type smtpReportRoute struct {
	kind string
	// A token's network.
	networkId sidecar.Id
}

// Where a recipient routes, or nil when nowhere: the report is then dropped unread.
func (self *SmtpReportIntake) route(ctx context.Context, recipient string) (*smtpReportRoute, error) {
	recipient = strings.ToLower(strings.Trim(strings.TrimSpace(recipient), "<>"))
	at := strings.LastIndexByte(recipient, '@')
	if at < 0 {
		return nil, nil
	}
	local := recipient[:at]
	domain := strings.TrimSuffix(recipient[at+1:], ".")
	switch domain {
	case strings.ToLower(self.settings.ReportHostName):
		if local == smtpReportRootLocalPart {
			return &smtpReportRoute{kind: smtpReportRouteRoot}, nil
		}
		if !smtpReportTokenPattern.MatchString(local) || self.deps.Tokens == nil {
			return nil, nil
		}
		ctx, done := self.storeContext(ctx)
		defer done()
		networkId, ok, err := self.deps.Tokens.NetworkForReportToken(ctx, local)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		return &smtpReportRoute{kind: smtpReportRouteToken, networkId: networkId}, nil
	case strings.ToLower(self.settings.Root):
		if local == "abuse" || local == "postmaster" {
			return &smtpReportRoute{kind: smtpReportRouteRole}, nil
		}
	}
	return nil, nil
}

// A context bounded by StoreTimeout on the intake's clock, and the call that ends it.
func (self *SmtpReportIntake) storeContext(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// One report, with its kind for the metric.
func (self *SmtpReportIntake) accept(ctx context.Context, message *SmtpReportMessage) (SmtpReportOutcome, string, error) {
	route, err := self.route(ctx, message.Recipient)
	if err != nil {
		return "", smtpReportKindUnknown, err
	}
	if route == nil {
		return SmtpReportOutcomeUnknownRecipient, smtpReportKindUnknown, nil
	}
	parts, err := parseSmtpReportMime(message.Raw, self.settings)
	if err != nil {
		return SmtpReportOutcomeRefused, smtpReportKindUnknown, nil
	}
	if route.kind != smtpReportRouteRole {
		rows, err := parseSmtpAggregate(parts, self.settings)
		if err != nil {
			return SmtpReportOutcomeRefused, smtpReportKindUnknown, nil
		}
		if rows != nil {
			kind := smtpReportKindDmarc
			if rows.Kind == SmtpAggregateKindTlsRpt {
				kind = smtpReportKindTlsRpt
			}
			outcome, err := self.acceptAggregate(ctx, route, message, parts, rows)
			return outcome, kind, err
		}
	}
	arf, err := parseSmtpArf(parts, self.settings)
	if err != nil {
		return SmtpReportOutcomeRefused, smtpReportKindUnknown, nil
	}
	kind := smtpReportKindArf
	if route.kind == smtpReportRouteRole {
		kind = smtpReportKindRole
	} else if arf.FeedbackType == "" {
		// an enclosed message at a token or <root>, with no feedback report: nothing this intake reads
		return SmtpReportOutcomeRefused, smtpReportKindUnknown, nil
	}
	outcome, err := self.acceptComplaint(ctx, route, message, parts, arf)
	return outcome, kind, err
}

// The one pass over the raw bytes: each chunk to the body hash, then to the seal. Returns the sealed
// copy, or nil with no sealer.
func smtpReportPass(raw []byte, sealer *smtpReportSealer, bodyHash *SmtpDkimBodyHash) ([]byte, error) {
	for start := 0; start < len(raw); start += smtpSealChunkByteCount {
		chunk := raw[start:min(start+smtpSealChunkByteCount, len(raw))]
		if bodyHash != nil {
			bodyHash.Write(chunk)
		}
		if sealer != nil {
			sealer.Write(chunk)
		}
	}
	if sealer == nil {
		return nil, nil
	}
	return sealer.finish()
}

// A sealer to the network's mail key, or nil when it has none.
func (self *SmtpReportIntake) sealer(ctx context.Context, networkId sidecar.Id, message *SmtpReportMessage) (*smtpReportSealer, error) {
	if self.deps.Keys == nil {
		return nil, nil
	}
	ctx, done := self.storeContext(ctx)
	defer done()
	publicKey, err := self.deps.Keys.ReportSealKey(ctx, networkId)
	if err != nil {
		return nil, err
	}
	if publicKey == nil {
		return nil, nil
	}
	return newSmtpReportSealer(publicKey, networkId, message.ArrivalTime, len(message.Raw))
}

// The verified reporter of a message whose body hash was fed, or empty. An error when nothing passed and
// a key read did not answer, so the report may pass on a retry.
func (self *SmtpReportIntake) reporter(ctx context.Context, bodyHash *SmtpDkimBodyHash) (string, error) {
	if !bodyHash.Checkable() {
		return "", nil
	}
	results, err := self.verifier.Verify(ctx, bodyHash)
	if err != nil {
		return "", err
	}
	reporter := smtpDkimPassingDomain(results)
	if reporter == "" && smtpDkimTemporary(results) {
		return "", errors.New("smtp report intake: a reporter's key did not answer")
	}
	return reporter, nil
}

// Adds b to a, stopping at the largest count rather than wrapping.
func smtpSaturatingAdd(a uint64, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// The <net> label a domain under <root> names, a burner's included, or empty when it is not under it.
func (self *SmtpReportIntake) netLabel(domain string) string {
	root := strings.ToLower(self.settings.Root)
	if !strings.HasSuffix(domain, "."+root) {
		return ""
	}
	labels := strings.Split(strings.TrimSuffix(domain, "."+root), ".")
	return labels[len(labels)-1]
}

// An aggregate's rows as counts by network and domain: a token's all toward its network, <root>'s by
// each row's label, a row whose label names no network dropped.
func (self *SmtpReportIntake) aggregateCounts(ctx context.Context, route *smtpReportRoute, rows *SmtpAggregateRows) ([]*SmtpAggregateCount, error) {
	type countKey struct {
		networkId  sidecar.Id
		domain     string
		policyType string
	}
	byKey := map[countKey]*SmtpAggregateCount{}
	counts := []*SmtpAggregateCount{}
	labelNetworks := map[string]*sidecar.Id{}
	for _, row := range rows.Rows {
		networkId := route.networkId
		if route.kind == smtpReportRouteRoot {
			label := self.netLabel(row.Domain)
			if label == "" || self.deps.Labels == nil {
				continue
			}
			resolved, seen := labelNetworks[label]
			if !seen {
				err := func() error {
					ctx, done := self.storeContext(ctx)
					defer done()
					id, ok, err := self.deps.Labels.NetworkForLabel(ctx, label)
					if err != nil {
						return err
					}
					if ok {
						resolved = &id
					}
					labelNetworks[label] = resolved
					return nil
				}()
				if err != nil {
					return nil, err
				}
			}
			if resolved == nil {
				continue
			}
			networkId = *resolved
		}
		key := countKey{networkId: networkId, domain: row.Domain, policyType: row.PolicyType}
		count, ok := byKey[key]
		if !ok {
			count = &SmtpAggregateCount{NetworkId: networkId, Domain: row.Domain, PolicyType: row.PolicyType}
			byKey[key] = count
			counts = append(counts, count)
		}
		count.MessageCount = smtpSaturatingAdd(count.MessageCount, row.MessageCount)
		if row.DkimAligned == "pass" {
			count.DkimPassCount = smtpSaturatingAdd(count.DkimPassCount, row.MessageCount)
		}
		if row.SpfAligned == "pass" {
			count.SpfPassCount = smtpSaturatingAdd(count.SpfPassCount, row.MessageCount)
		}
		switch row.Disposition {
		case "quarantine":
			count.QuarantineCount = smtpSaturatingAdd(count.QuarantineCount, row.MessageCount)
		case "reject":
			count.RejectCount = smtpSaturatingAdd(count.RejectCount, row.MessageCount)
		}
		count.SuccessCount = smtpSaturatingAdd(count.SuccessCount, row.SuccessCount)
		count.FailureCount = smtpSaturatingAdd(count.FailureCount, row.FailureCount)
	}
	return counts, nil
}

// An aggregate: verified, counted once, and at a token sealed when the network has a key.
func (self *SmtpReportIntake) acceptAggregate(ctx context.Context, route *smtpReportRoute, message *SmtpReportMessage, parts *SmtpReportParts, rows *SmtpAggregateRows) (SmtpReportOutcome, error) {
	bodyHash, err := self.verifier.NewBodyHash(parts.HeaderBlock)
	if err != nil {
		return SmtpReportOutcomeRefused, nil
	}
	if !bodyHash.Checkable() {
		return SmtpReportOutcomeUnverified, nil
	}
	var sealer *smtpReportSealer
	if route.kind == smtpReportRouteToken {
		if sealer, err = self.sealer(ctx, route.networkId, message); err != nil {
			return "", err
		}
	}
	sealed, err := smtpReportPass(message.Raw, sealer, bodyHash)
	if err != nil {
		return "", err
	}
	reporter, err := self.reporter(ctx, bodyHash)
	if err != nil {
		return "", err
	}
	if reporter == "" {
		return SmtpReportOutcomeUnverified, nil
	}
	counts, err := self.aggregateCounts(ctx, route, rows)
	if err != nil {
		return "", err
	}
	if len(counts) == 0 {
		return SmtpReportOutcomeEmpty, nil
	}
	day := smtpUtcDay(message.ArrivalTime)
	if !rows.Begin.IsZero() && !rows.Begin.After(message.ArrivalTime) {
		day = smtpUtcDay(rows.Begin)
	}
	report := &SmtpAggregateReport{
		Reporter:    reporter,
		ReportId:    rows.ReportId,
		Kind:        rows.Kind,
		Day:         day,
		ArrivalTime: message.ArrivalTime,
		Counts:      counts,
	}
	inserted, err := func() (bool, error) {
		ctx, done := self.storeContext(ctx)
		defer done()
		testHookBarrier("smtpedge.report_insert.before", "")
		defer testHookBarrier("smtpedge.report_insert.after", "")
		return self.store.InsertAggregate(ctx, report)
	}()
	if err != nil {
		return "", err
	}
	if !inserted {
		return SmtpReportOutcomeDuplicate, nil
	}
	if sealed != nil {
		complaintType := SmtpComplaintTypeRua
		if rows.Kind == SmtpAggregateKindTlsRpt {
			complaintType = SmtpComplaintTypeTlsRpt
		}
		complaint := &SmtpComplaint{
			ComplaintId:  sidecar.NewId(),
			NetworkId:    route.networkId,
			Reporter:     reporter,
			Type:         complaintType,
			ArrivalTime:  message.ArrivalTime,
			Domain:       counts[0].Domain,
			SealedReport: sealed,
		}
		// the counts are stored, so a failure here loses only the sealed copy, and is no reason to make
		// the reporter send again, which would count nothing
		err := func() error {
			ctx, done := self.storeContext(ctx)
			defer done()
			return self.store.InsertComplaint(ctx, complaint)
		}()
		if err != nil {
			self.log.Infof("[smtpedge]an aggregate's sealed copy was not stored")
		}
	}
	return SmtpReportOutcomeCounted, nil
}

// An RFC 5965 Feedback-Type as a complaint type, anything outside the registry being other.
func smtpComplaintType(feedbackType string) string {
	switch feedbackType {
	case SmtpComplaintTypeAbuse, SmtpComplaintTypeFraud, SmtpComplaintTypeVirus, SmtpComplaintTypeNotSpam, SmtpComplaintTypeAuthFailure:
		return feedbackType
	}
	return SmtpComplaintTypeOther
}

// An ARF report or a role mail: attributed by the join, sealed to its network, stored, and for role
// mail handed to §21.
func (self *SmtpReportIntake) acceptComplaint(ctx context.Context, route *smtpReportRoute, message *SmtpReportMessage, parts *SmtpReportParts, arf *SmtpArfReport) (SmtpReportOutcome, error) {
	if self.deps.Join == nil || arf.Headers == nil {
		return SmtpReportOutcomeUnattributed, nil
	}
	complaint, err := func() (*SmtpComplaint, error) {
		ctx, done := self.storeContext(ctx)
		defer done()
		return self.deps.Join.JoinReport(ctx, arf)
	}()
	if err != nil {
		return "", err
	}
	if complaint == nil {
		return SmtpReportOutcomeUnattributed, nil
	}
	bodyHash, err := self.verifier.NewBodyHash(parts.HeaderBlock)
	if err != nil {
		return SmtpReportOutcomeRefused, nil
	}
	sealer, err := self.sealer(ctx, complaint.NetworkId, message)
	if err != nil {
		return "", err
	}
	sealed, err := smtpReportPass(message.Raw, sealer, bodyHash)
	if err != nil {
		return "", err
	}
	reporter := ""
	if bodyHash.Checkable() {
		reporter, err = self.reporter(ctx, bodyHash)
		// role mail needs no verified reporter, so a key that did not answer only makes it a stranger's
		if err != nil && route.kind != smtpReportRouteRole {
			return "", err
		}
	}
	loop := reporter != "" && self.settings.isLoopReporter(reporter) && arf.FeedbackType != ""
	if route.kind != smtpReportRouteRole && !loop {
		return SmtpReportOutcomeUnverified, nil
	}
	if complaint.ComplaintId == (sidecar.Id{}) {
		complaint.ComplaintId = sidecar.NewId()
	}
	complaint.ArrivalTime = message.ArrivalTime
	complaint.SealedReport = sealed
	reporterClass := SmtpReporterClassRole
	if loop {
		complaint.Reporter = reporter
		complaint.Type = smtpComplaintType(arf.FeedbackType)
		reporterClass = SmtpReporterClassLoop
	} else {
		complaint.Reporter = ""
		complaint.Type = SmtpComplaintTypeRole
	}
	err = func() error {
		ctx, done := self.storeContext(ctx)
		defer done()
		testHookBarrier("smtpedge.report_insert.before", "")
		defer testHookBarrier("smtpedge.report_insert.after", "")
		return self.store.InsertComplaint(ctx, complaint)
	}()
	if err != nil {
		return "", err
	}
	if route.kind != smtpReportRouteRole {
		return SmtpReportOutcomeComplaint, nil
	}
	err = func() error {
		ctx, done := self.storeContext(ctx)
		defer done()
		return self.deps.Sink.OpenSmtpCase(ctx, &SmtpAbuseReport{
			ComplaintId:   complaint.ComplaintId,
			NetworkId:     complaint.NetworkId,
			Domain:        complaint.Domain,
			Category:      complaint.Type,
			JoinResult:    complaint.JoinResult,
			ReporterClass: reporterClass,
			ArrivalTime:   message.ArrivalTime,
		})
	}()
	if err != nil {
		return "", err
	}
	return SmtpReportOutcomeCase, nil
}
