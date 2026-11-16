// §14.8's attribution (D-SMTP-8, D-SMTP-12, R-SMTP-5; SMTP-M9-15): which network, if any, an ARF report or a
// role mail names, and how surely. SmtpAttribution is the intake's SmtpReportJoin, so it runs where the intake
// does, in mxedge's platform block (plan-SMTP-report-intake-home), off every connection's path, reading the send
// log and the published DKIM keys through the store.
//
// Every level needs the last-hop Received hop that names one of the sending addresses, with its time
// (report_arf.go keeps no other), since the edge's own send log is what a report is joined against:
//
//	high     a signature over the reported headers verifies under a key URnetwork holds for network N
//	         (VerifyHeaders), and the Received hop names one of N's sends from that address within
//	         ReportJoinWindow of its time
//	medium   the X-UR-Ref MAC verifies for the send its send_id names, the Received hop matches that send's
//	         address and time, and the reported headers carry a DKIM-Signature whose d= and s= name a key of
//	         that send's network, which the reporter's changes kept from verifying here (a masked recipient
//	         breaks b= over the headers it covers)
//	low      a Received join alone: the reported Message-ID's hash names sends of exactly one network from
//	         that address within the window. It never halts; §21 reviews it
//
// An X-UR-Ref decides first when a report carries one: one that does not verify, or a report that verifies a
// signature of another network than the MAC's, or none of the MAC's network, is dropped, not demoted, since a
// recipient on the shared addresses could paste another network's reference into a complaint (D-SMTP-8). A
// join to the X-UR-Ref's send from another address or time is a replay, and dropped too.
//
// Reading (D-SMTP-8 leaves it open): high and medium both need a signature of the MAC's network, so they part on
// whether it verifies here. The second signature over from:date:message-id:x-ur-ref:feedback-id (§14.6) survives
// masked recipients and verifies, so such a report is high; medium is a report whose every URnetwork signature
// was broken by the reporter, which the X-UR-Ref and the Received hop then pin to one send.
//
// What a join reads stays in memory: the Received address and time, the send it matched, and every other
// header. The complaint row keeps smtp-5's fields alone (records.go), so no third-party address or Received IP
// reaches a row (§2.8 smtp-5). SmtpOutcome never feeds attribution (§14.8).
//
// Safe for concurrent use: a join holds no state between calls.

package smtpedgeservice

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// A join's confidence, as smtp_complaint.join_result holds it (D-SMTP-8).
type SmtpConfidence string

const (
	SmtpConfidenceHigh   SmtpConfidence = "high"
	SmtpConfidenceMedium SmtpConfidence = "medium"
	SmtpConfidenceLow    SmtpConfidence = "low"
)

// Whether a complaint joined at this confidence may halt: high and medium only (§14.8).
func (self SmtpConfidence) Halts() bool {
	return self == SmtpConfidenceHigh || self == SmtpConfidenceMedium
}

// Why a report named no network, a word from a closed set: never stored, never a label naming anyone.
const (
	SmtpJoinDropNoHeaders  = "no_headers"
	SmtpJoinDropNoReceived = "no_received"
	// An X-UR-Ref that does not parse, names no stored send, or whose MAC does not verify.
	SmtpJoinDropXUrRef = "x_ur_ref"
	// A verifying signature of another network than the X-UR-Ref's, or none of the MAC's network.
	SmtpJoinDropForeignSignature = "foreign_signature"
	// The X-UR-Ref's send left from another address, or at another time, than the Received hop shows.
	SmtpJoinDropReplay = "replay"
	// Nothing joined: no signature's network sent then, and no Message-ID named one network's send.
	SmtpJoinDropUnjoined = "unjoined"
)

// What one join found. Memory only: SmtpComplaint is what a row keeps of it.
type SmtpJoinResult struct {
	// Empty when the report names no network, Dropped then saying why.
	Confidence SmtpConfidence
	Dropped    string
	NetworkId  sidecar.Id
	// A burner's <blabel> when the reported From is <blabel>.<net>.<root>: what a complaint halts first
	// (§14.8's first row). Empty for network mail.
	Label string
	// The reported From domain.
	Domain string
	// The signature the join rests on, empty for a low join.
	DkimDomain   string
	DkimSelector string
	DkimResult   string
	// SmtpMessageIdHash of the reported Message-ID, nil when it carries none.
	MessageIdHash []byte
	XUrRef        string
	FeedbackId    string
	// The send the join matched. Memory only: its address and times are in no complaint field.
	Send *SmtpSendRecord
}

// The smtp_complaint row a join leaves, its network, domain, signature and join fields set: the intake sets
// the rest. nil for a report that names no network.
func (self *SmtpJoinResult) Complaint() *SmtpComplaint {
	if self.Confidence == "" {
		return nil
	}
	return &SmtpComplaint{
		NetworkId:     self.NetworkId,
		Domain:        self.Domain,
		DkimDomain:    self.DkimDomain,
		DkimSelector:  self.DkimSelector,
		DkimResult:    self.DkimResult,
		MessageIdHash: bytes.Clone(self.MessageIdHash),
		XUrRef:        self.XUrRef,
		FeedbackId:    self.FeedbackId,
		JoinResult:    string(self.Confidence),
	}
}

// The join. NewSmtpAttribution makes one.
type SmtpAttribution struct {
	store    SmtpEdgeStore
	lookups  SmtpReportLookups
	settings *SmtpEdgeSettings
	verifier *SmtpDkimVerifier
	// The X-UR-Ref keys a medium join verifies under: the edge's, which the block mounts from vault. None
	// leaves every report that carries an X-UR-Ref dropped, the closed direction.
	xUrRefKeys []*SmtpXUrRefKey
}

var _ SmtpReportJoin = (*SmtpAttribution)(nil)

// A join over store's send log and lookups' DKIM keys, with settings' X-UR-Ref keys. nil clock is real time.
func NewSmtpAttribution(store SmtpEdgeStore, lookups SmtpReportLookups, settings *SmtpEdgeSettings, clock sidecar.Clock) (*SmtpAttribution, error) {
	if store == nil || lookups == nil {
		return nil, errors.New("smtp attribution needs the send log and the DKIM keys")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	keys := []*SmtpXUrRefKey{}
	for _, key := range settings.XUrRefKeys {
		if key == nil {
			continue
		}
		testHookSecret("smtp_x_ur_ref_key", key.Key)
		keys = append(keys, key)
	}
	return &SmtpAttribution{
		store:      store,
		lookups:    lookups,
		settings:   settings,
		verifier:   NewSmtpDkimVerifier(settings, nil, lookups, clock),
		xUrRefKeys: keys,
	}, nil
}

// See SmtpReportJoin: the row Join's result leaves, or nil.
func (self *SmtpAttribution) JoinReport(ctx context.Context, report *SmtpArfReport) (*SmtpComplaint, error) {
	result, err := self.Join(ctx, report)
	if err != nil {
		return nil, err
	}
	return result.Complaint(), nil
}

// The burner label of a From domain <blabel>.<net>.<root>, or empty. A Team scope's <scope>.<net>.<root> is no
// burner's: its first label is no word and four digits.
func smtpReportLabel(settings *SmtpEdgeSettings, domain string) string {
	root := strings.ToLower(settings.Root)
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !strings.HasSuffix(domain, "."+root) {
		return ""
	}
	labels := strings.Split(strings.TrimSuffix(domain, "."+root), ".")
	if len(labels) != 2 || !smtpBurnerLabelPattern.MatchString(labels[0]) {
		return ""
	}
	return labels[0]
}

// Whether at falls within the window of send: from its start less the join window to its end, or its start
// while it has none, plus the window.
func (self *SmtpAttribution) withinSend(send *SmtpSendRecord, at time.Time) bool {
	end := send.StartTime
	if send.EndTime.After(end) {
		end = send.EndTime
	}
	return !at.Before(send.StartTime.Add(-self.settings.ReportJoinWindow)) && !at.After(end.Add(self.settings.ReportJoinWindow))
}

// The sends key finds whose window holds at, nearest start first, and an error past ReportJoinSendMaxCount: a
// key that wide names no one send.
func (self *SmtpAttribution) sendsAt(ctx context.Context, key *SmtpJoinKey, at time.Time) ([]*SmtpSendRecord, error) {
	// a DATA send can start up to its 2 h before the MX's Received time, and the window bounds the rest
	key.Since = at.Add(-self.settings.ReportJoinWindow - self.settings.DataConnectionTimeout)
	key.Until = at.Add(self.settings.ReportJoinWindow)
	sends, err := self.store.FindSends(ctx, key)
	if err != nil {
		return nil, err
	}
	if self.settings.ReportJoinSendMaxCount < len(sends) {
		return nil, errSmtpJoinTooWide
	}
	held := []*SmtpSendRecord{}
	for _, send := range sends {
		if self.withinSend(send, at) {
			held = append(held, send)
		}
	}
	distance := func(send *SmtpSendRecord) time.Duration {
		if d := at.Sub(send.StartTime); 0 <= d {
			return d
		}
		return send.StartTime.Sub(at)
	}
	slices.SortStableFunc(held, func(a *SmtpSendRecord, b *SmtpSendRecord) int {
		return cmp.Compare(distance(a), distance(b))
	})
	return held, nil
}

// A join key that names more sends than one join reads.
var errSmtpJoinTooWide = errors.New("smtp join: more sends than one join reads")

// The send an X-UR-Ref names, its MAC verified under that send's network and the day it was issued, or nil.
func (self *SmtpAttribution) xUrRefSend(ctx context.Context, text string) (*SmtpSendRecord, error) {
	ref, err := ParseSmtpXUrRef(text)
	if err != nil {
		return nil, nil
	}
	sends, err := self.store.FindSends(ctx, &SmtpJoinKey{SendId: ref.SendId})
	if err != nil {
		return nil, err
	}
	for _, send := range sends {
		if _, err := VerifySmtpXUrRef(self.xUrRefKeys, text, send.NetworkId, SmtpXUrRefDay(send.StartTime)); err == nil {
			return send, nil
		}
	}
	return nil, nil
}

// Joins one report. The result is never nil: a report that names no network has an empty Confidence and says
// why. An error is a store or key read that did not answer, after which a retry may join, so the intake answers
// 451 and the reporter sends again.
func (self *SmtpAttribution) Join(ctx context.Context, report *SmtpArfReport) (*SmtpJoinResult, error) {
	testHookBarrier("smtpedge.join.before", "")
	defer testHookBarrier("smtpedge.join.after", "")
	if report == nil || report.Headers == nil {
		return &SmtpJoinResult{Dropped: SmtpJoinDropNoHeaders}, nil
	}
	headers := report.Headers
	result := &SmtpJoinResult{
		Domain:        headers.FromDomain,
		Label:         smtpReportLabel(self.settings, headers.FromDomain),
		MessageIdHash: SmtpMessageIdHash(headers.MessageId),
		XUrRef:        headers.XUrRef,
		FeedbackId:    headers.FeedbackId,
	}
	drop := func(reason string) (*SmtpJoinResult, error) {
		return &SmtpJoinResult{Dropped: reason, Domain: result.Domain}, nil
	}
	received := headers.ReceivedAddress.Unmap()
	if !received.IsValid() || headers.ReceivedTime.IsZero() || !self.settings.isSendingAddress(received) {
		return drop(SmtpJoinDropNoReceived)
	}
	at := headers.ReceivedTime

	signatures, err := self.verifier.VerifyHeaders(ctx, report.HeaderBlock())
	if err != nil {
		return nil, err
	}
	temporary := false
	passing := []*SmtpDkimResult{}
	for _, signature := range signatures {
		switch {
		case signature.Result == SmtpDkimResultPass && signature.NetworkId != (sidecar.Id{}):
			passing = append(passing, signature)
		case signature.Result == SmtpDkimResultTempError:
			temporary = true
		}
	}
	rest := func(confidence SmtpConfidence, networkId sidecar.Id, signature *SmtpDkimResult, send *SmtpSendRecord) (*SmtpJoinResult, error) {
		result.Confidence = confidence
		result.NetworkId = networkId
		result.Send = send
		if signature != nil {
			result.DkimDomain = signature.Domain
			result.DkimSelector = signature.Selector
			result.DkimResult = signature.Result
		}
		return result, nil
	}
	unjoined := func() (*SmtpJoinResult, error) {
		if temporary {
			// a key read did not answer: the same report may join on a retry
			return nil, errors.New("smtp join: a DKIM key read did not answer")
		}
		return drop(SmtpJoinDropUnjoined)
	}

	if headers.XUrRef != "" {
		send, err := self.xUrRefSend(ctx, headers.XUrRef)
		if err != nil {
			return nil, err
		}
		if send == nil {
			return drop(SmtpJoinDropXUrRef)
		}
		var own *SmtpDkimResult
		for _, signature := range passing {
			if signature.NetworkId != send.NetworkId {
				// another network's verifying d= beside the MAC's network: a pasted reference (D-SMTP-8)
				return drop(SmtpJoinDropForeignSignature)
			}
			if own == nil {
				own = signature
			}
		}
		if send.SendingAddress.Unmap() != received || !self.withinSend(send, at) {
			return drop(SmtpJoinDropReplay)
		}
		if own != nil {
			return rest(SmtpConfidenceHigh, send.NetworkId, own, send)
		}
		// no signature verifies here: the d= of one the MAC's network holds a key for
		for _, signature := range signatures {
			if signature.Domain == "" || signature.Selector == "" {
				continue
			}
			key, err := self.lookups.FindDkimKey(ctx, signature.Selector, signature.Domain)
			if err != nil {
				return nil, err
			}
			if key != nil && key.NetworkId == send.NetworkId {
				return rest(SmtpConfidenceMedium, send.NetworkId, signature, send)
			}
		}
		// without that d= the join is dropped, not demoted (D-SMTP-8)
		return drop(SmtpJoinDropForeignSignature)
	}

	seen := map[sidecar.Id]bool{}
	for _, signature := range passing {
		if seen[signature.NetworkId] {
			continue
		}
		seen[signature.NetworkId] = true
		sends, err := self.sendsAt(ctx, &SmtpJoinKey{NetworkId: signature.NetworkId, SendingAddress: received}, at)
		if errors.Is(err, errSmtpJoinTooWide) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(sends) == 0 {
			continue
		}
		send := sends[0]
		for _, candidate := range sends {
			// the signed Message-ID names the very send when the log holds it
			if result.MessageIdHash != nil && bytes.Equal(candidate.MessageIdHash, result.MessageIdHash) {
				send = candidate
				break
			}
		}
		return rest(SmtpConfidenceHigh, signature.NetworkId, signature, send)
	}

	if result.MessageIdHash == nil {
		return unjoined()
	}
	sends, err := self.sendsAt(ctx, &SmtpJoinKey{MessageIdHash: result.MessageIdHash, SendingAddress: received}, at)
	if errors.Is(err, errSmtpJoinTooWide) {
		return unjoined()
	}
	if err != nil {
		return nil, err
	}
	if len(sends) == 0 {
		return unjoined()
	}
	for _, send := range sends[1:] {
		if send.NetworkId != sends[0].NetworkId {
			// a guessable Message-ID that two networks sent names neither
			return unjoined()
		}
	}
	return rest(SmtpConfidenceLow, sends[0].NetworkId, nil, sends[0])
}
