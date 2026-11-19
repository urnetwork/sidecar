// SmtpOutcome at the edge (§14.4's step 5, §14.8's self-reports, plan-SMTP-wire-gaps#1; SMTP-M9-13): a sidecar's
// self-report of a send, taken from the connection's dialer for OutcomeAcceptTimeout after its stream ends, once
// per send, and then forgotten. It only tightens: its hard_bounce_count goes to §14.8's hard-bounce rule, and
// nothing in it lifts a halt, raises a limit or feeds attribution (§14.8). Its other fields are counted as
// metrics with closed labels, and nothing of it is stored.
//
// The outcome travels as a NO_REPLY envelope of type SMTP_OUTCOME to the ticket's listener, which the sidecar sends
// with Subprotocol.SendEdge and no Hello (§6.4, owner decision 624). Serve registers handleOutcome for it on each
// platform client's dispatcher with HandleNoReply (proof_rpc.go's registerHandlers), and it hands the body to
// AcceptOutcome with the source connect authenticated, which must be the connection's dialer, the ticket's
// dialer_client_id. Nothing answers it, so a refusal is its metric alone.
//
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Why an outcome was not taken, a metric's word.
const (
	smtpOutcomeTaken     = "taken"
	smtpOutcomeMalformed = "malformed"
	smtpOutcomeUnknown   = "unknown_send"
	smtpOutcomeLate      = "late"
	smtpOutcomeRepeated  = "repeated"
	smtpOutcomeDialer    = "not_dialer"
)

// A send whose stream ended, waiting for its outcome.
type smtpEndedSend struct {
	networkId sidecar.Id
	// the stream's dialer, from its ticket: the only source taken
	clientId sidecar.Id
	endTime  time.Time
	taken    bool
}

// The ended sends of this edge. See the file header.
type smtpOutcomes struct {
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	// hands a hard-bounce event to the halt rule, off the caller's path; nil drops it
	halt     func(event *SmtpHaltEvent)
	outcomes sidecar.MetricsCounter

	stateLock sync.Mutex
	// by send_id, and the ids in the order they ended, for the bound
	sendIdEnded map[string]*smtpEndedSend
	endedOrder  []string
}

func newSmtpOutcomes(settings *SmtpEdgeSettings, clock sidecar.Clock, metrics sidecar.Metrics, halt func(event *SmtpHaltEvent)) *smtpOutcomes {
	return &smtpOutcomes{
		settings:    settings,
		clock:       clock,
		halt:        halt,
		outcomes:    metrics.Counter("urnetwork_smtpedge_outcomes_total", "SmtpOutcomes received, by what became of each, and the TLS level and mode a taken one reports.", "result", "tls_level", "mode"),
		sendIdEnded: map[string]*smtpEndedSend{},
	}
}

// Remembers a send whose stream ended, forgetting the ones past their window or past OutcomeMaxCount.
func (self *smtpOutcomes) ended(sendId []byte, networkId sidecar.Id, clientId sidecar.Id, endTime time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	forget := 0
	for forget < len(self.endedOrder) {
		oldest := self.sendIdEnded[self.endedOrder[forget]]
		if oldest != nil && now.Sub(oldest.endTime) < self.settings.OutcomeAcceptTimeout && len(self.endedOrder)-forget < self.settings.OutcomeMaxCount {
			break
		}
		delete(self.sendIdEnded, self.endedOrder[forget])
		forget += 1
	}
	self.endedOrder = slices.Clone(self.endedOrder[forget:])
	self.sendIdEnded[string(sendId)] = &smtpEndedSend{networkId: networkId, clientId: clientId, endTime: endTime}
	self.endedOrder = append(self.endedOrder, string(sendId))
}

// An outcome not taken, by why.
var errSmtpOutcomeRefused = errors.New("smtp outcome refused")

// Takes an SmtpOutcome body from sourceId: from its send's dialer, within OutcomeAcceptTimeout of the stream's
// end, once. A refusal is an error and changes nothing.
func (self *SmtpEdgeService) AcceptOutcome(sourceId sidecar.Id, body []byte) error {
	return self.outcomes.accept(sourceId, body)
}

// SMTP_OUTCOME's NO_REPLY function on a platform client's dispatcher: the envelope to AcceptOutcome, from its source
// as connect authenticated it. It runs on that source's worker and does no I/O: the halt rule's event goes to its
// queue with zero wait. The body is borrowed, and AcceptOutcome keeps nothing of it.
func (self *SmtpEdgeService) handleOutcome(ctx context.Context, message *sidecar.SubprotocolNoReply) {
	// a refusal is counted by AcceptOutcome's metric, and nothing answers a NO_REPLY envelope
	self.AcceptOutcome(message.SourceId, message.Body)
}

func (self *smtpOutcomes) accept(sourceId sidecar.Id, body []byte) error {
	refuse := func(why string) error {
		self.outcomes.Add(1, why, smtpTlsLevelLabels[0], smtpModeUnknown)
		return errSmtpOutcomeRefused
	}
	outcome := &protocol.SmtpOutcome{}
	if self.settings.ProofMaxByteCount < len(body) || proto.Unmarshal(body, outcome) != nil || len(outcome.GetSendId()) != SmtpSendIdByteCount {
		return refuse(smtpOutcomeMalformed)
	}
	now := self.clock.Now()
	var event *SmtpHaltEvent
	why := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended, ok := self.sendIdEnded[string(outcome.GetSendId())]
		switch {
		case !ok:
			return smtpOutcomeUnknown
		case ended.clientId != sourceId:
			return smtpOutcomeDialer
		case self.settings.OutcomeAcceptTimeout <= now.Sub(ended.endTime):
			return smtpOutcomeLate
		case ended.taken:
			return smtpOutcomeRepeated
		}
		ended.taken = true
		if 0 < outcome.GetHardBounceCount() {
			event = &SmtpHaltEvent{Kind: SmtpHaltEventHardBounces, NetworkId: ended.networkId, Time: now, HardBounceCount: outcome.GetHardBounceCount()}
		}
		return ""
	}()
	if why != "" {
		return refuse(why)
	}
	tlsLevel, ok := smtpTlsLevelLabels[uint8(min(outcome.GetTlsLevel(), 255))]
	if !ok {
		tlsLevel = smtpTlsLevelLabels[0]
	}
	mode := smtpModeUnknown
	switch sidecar.SmtpMode(outcome.GetMode()) {
	case sidecar.SmtpModeBdat:
		mode = smtpModeBdat
	case sidecar.SmtpModeData:
		mode = smtpModeData
	}
	self.outcomes.Add(1, smtpOutcomeTaken, tlsLevel, mode)
	if event != nil && self.halt != nil {
		self.halt(event)
	}
	return nil
}
