// SmtpOutcome at the edge (§14.4's step 5, §14.8's self-reports, plan-SMTP-wire-gaps#1; SMTP-M9-13): a sidecar's
// self-report of a send, taken from the connection's dialer once per send, from when its connection registers until
// OutcomeAcceptTimeout after its stream ends, and then forgotten. It only tightens: its hard_bounce_count goes to
// §14.8's hard-bounce rule, and nothing in it lifts a halt, raises a limit or feeds attribution (§14.8). Its other
// fields are counted as metrics with closed labels, and nothing of it is stored.
//
// The window opens at registration, not at the end (QD-1112): the driver sends its outcome at its own close, which
// this edge sees end only after its QUIT, 221 and close round trip with the MX and the connection's settling, so an
// outcome from a live connection's dialer is taken, with the connection's network for the hard-bounce rule, and the
// end keeps it taken. Each live connection's send is held here from its registration (started) to its end (ended),
// so the two cannot pass each other.
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

// A send waiting for its outcome: its connection's, while it is live, then its window's.
type smtpOutcomeSend struct {
	networkId sidecar.Id
	// the stream's dialer, from its ticket: the only source taken
	clientId sidecar.Id
	// its connection is registered and has not ended
	live bool
	// when the stream ended, from which the window runs; zero while live
	endTime time.Time
	taken   bool
}

// The live and ended sends of this edge. See the file header.
type smtpOutcomes struct {
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	// hands a hard-bounce event to the halt rule, off the caller's path; nil drops it
	halt     func(event *SmtpHaltEvent)
	outcomes sidecar.MetricsCounter

	stateLock sync.Mutex
	// by send_id: every live connection's send, and the ended ones within their window and the bound
	sendIdSends map[string]*smtpOutcomeSend
	// the ended sends' ids in the order they ended, for the window and the bound; a live send counts toward
	// neither, since its connection bounds it
	endedOrder []string
}

func newSmtpOutcomes(settings *SmtpEdgeSettings, clock sidecar.Clock, metrics sidecar.Metrics, halt func(event *SmtpHaltEvent)) *smtpOutcomes {
	return &smtpOutcomes{
		settings:    settings,
		clock:       clock,
		halt:        halt,
		outcomes:    metrics.Counter("urnetwork_smtpedge_outcomes_total", "SmtpOutcomes received, by what became of each, and the TLS level and mode a taken one reports.", "result", "tls_level", "mode"),
		sendIdSends: map[string]*smtpOutcomeSend{},
	}
}

// Holds a send from its connection's registration, so its dialer's outcome is taken before this edge has seen the
// stream end (QD-1112). Every registered connection ends, and its end moves the send to its window (ended).
func (self *smtpOutcomes) started(sendId []byte, networkId sidecar.Id, clientId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sendIdSends[string(sendId)] = &smtpOutcomeSend{networkId: networkId, clientId: clientId, live: true}
}

// Starts a send's window at its stream's end, keeping an outcome its live connection took, and forgets the ended
// sends past their window or past OutcomeMaxCount.
func (self *smtpOutcomes) ended(sendId []byte, networkId sidecar.Id, clientId sidecar.Id, endTime time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	forget := 0
	for forget < len(self.endedOrder) {
		oldest := self.sendIdSends[self.endedOrder[forget]]
		if oldest != nil && now.Sub(oldest.endTime) < self.settings.OutcomeAcceptTimeout && len(self.endedOrder)-forget < self.settings.OutcomeMaxCount {
			break
		}
		delete(self.sendIdSends, self.endedOrder[forget])
		forget += 1
	}
	self.endedOrder = slices.Clone(self.endedOrder[forget:])
	key := string(sendId)
	send := self.sendIdSends[key]
	if send == nil || !send.live {
		// a send whose connection held no place here
		send = &smtpOutcomeSend{networkId: networkId, clientId: clientId}
		self.sendIdSends[key] = send
	}
	send.live = false
	send.endTime = endTime
	self.endedOrder = append(self.endedOrder, key)
}

// An outcome not taken, by why.
var errSmtpOutcomeRefused = errors.New("smtp outcome refused")

// Takes an SmtpOutcome body from sourceId: from its send's dialer, once, while the send's connection is live or
// within OutcomeAcceptTimeout of its stream's end. A refusal is an error and changes nothing.
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
		send, ok := self.sendIdSends[string(outcome.GetSendId())]
		switch {
		case !ok:
			return smtpOutcomeUnknown
		case send.clientId != sourceId:
			return smtpOutcomeDialer
		case !send.live && self.settings.OutcomeAcceptTimeout <= now.Sub(send.endTime):
			return smtpOutcomeLate
		case send.taken:
			return smtpOutcomeRepeated
		}
		send.taken = true
		if 0 < outcome.GetHardBounceCount() {
			event = &SmtpHaltEvent{Kind: SmtpHaltEventHardBounces, NetworkId: send.networkId, Time: now, HardBounceCount: outcome.GetHardBounceCount()}
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
