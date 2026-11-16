// Bridges for smtpedgeservice_test to the outbound path's private parts: the sending set's checks and
// pick, the MX connector, the pre-TLS dialog, and one preamble through the composed engine.

package smtpedgeservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Waits until at least count sending-set checks have finished.
func (self *SmtpSendingSet) AwaitChecks(ctx context.Context, count int) error {
	for {
		finished, update := self.checkCount.Get()
		if count <= finished {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Waits until the engine's sending set has finished count checks.
func (self *SmtpEdgeService) AwaitSendingChecks(ctx context.Context, count int) error {
	if self.sendingSet == nil {
		return errors.New("no sending set")
	}
	return self.sendingSet.AwaitChecks(ctx, count)
}

// The engine's quota.
func (self *SmtpEdgeService) TestQuota() *SmtpQuota {
	return self.quota
}

// What a preamble came to, for a test.
type TestPreambleOutcome struct {
	Result      *protocol.SmtpPreambleResult
	Reason      string
	Session     sidecar.SmtpProofSession
	Reservation *SmtpQuotaReservation
	Send        *SmtpSendRecord
	// On OK: the MX connection past STARTTLS's 220, the MX's address and the sending address.
	MxConn         net.Conn
	MxAddress      netip.Addr
	SendingAddress netip.Addr

	outcome *smtpPreambleOutcome
	quota   *SmtpQuota
}

func newTestPreambleOutcome(outcome *smtpPreambleOutcome, quota *SmtpQuota) *TestPreambleOutcome {
	test := &TestPreambleOutcome{
		Result:      outcome.Result,
		Reason:      outcome.Reason,
		Session:     outcome.Session,
		Reservation: outcome.Reservation,
		Send:        outcome.Send,
		outcome:     outcome,
		quota:       quota,
	}
	if outcome.Mx != nil {
		test.MxConn = outcome.Mx.conn
		test.MxAddress = outcome.Mx.mxAddress
		test.SendingAddress = outcome.Mx.sendingAddress.Address
	}
	return test
}

// Gives back what an OK outcome holds.
func (self *TestPreambleOutcome) Abandon(ctx context.Context) {
	self.outcome.abandon(ctx, self.quota)
}

// Serves one preamble on conn as SMTP-M9-13's ur/smtpedge listener will hand a stream to the engine,
// the dialer's identity from its ticket.
func (self *SmtpEdgeService) ServeTestPreamble(ctx context.Context, networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id, conn io.ReadWriteCloser) (*TestPreambleOutcome, error) {
	if self.preamble == nil {
		return nil, errors.New("the engine has no preamble path")
	}
	outcome, err := self.preamble.serve(ctx, &smtpPreambleStream{NetworkId: networkId, ClientId: clientId, SidecarId: sidecarId}, conn)
	if err != nil {
		return nil, err
	}
	return newTestPreambleOutcome(outcome, self.quota), nil
}

// The MX connector, for a test of its rows alone.
type TestMxConnector struct {
	connector *smtpMxConnector
}

// What a test connect reached.
type TestMxConnection struct {
	Conn           net.Conn
	MxHost         string
	MxAddress      netip.Addr
	SendingAddress netip.Addr
	Keywords       []string
	Chain          []byte
	Release        func()
}

func NewTestMxConnector(settings *SmtpEdgeSettings, clock sidecar.Clock, resolver sidecar.SmtpMxResolver, dialer sidecar.SmtpMxDialer, sendingSet *SmtpSendingSet, caps *SmtpDestinationCaps) *TestMxConnector {
	return &TestMxConnector{connector: newSmtpMxConnector(settings, clock, resolver, dialer, sendingSet, caps)}
}

func (self *TestMxConnector) Connect(ctx context.Context, domain string, limits *sidecar.QuotaLimits) (*TestMxConnection, protocol.SmtpPreambleCode, time.Duration, string) {
	connection, code, retryAfter, reason := self.connector.connect(ctx, domain, limits)
	if connection == nil {
		return nil, code, retryAfter, reason
	}
	return &TestMxConnection{
		Conn:           connection.conn,
		MxHost:         connection.mxHost,
		MxAddress:      connection.mxAddress,
		SendingAddress: connection.sendingAddress.Address,
		Keywords:       connection.keywords,
		Chain:          connection.chain,
		Release:        connection.release,
	}, code, retryAfter, reason
}

// The edge's pre-TLS dialog on conn.
func SmtpPreTlsForTest(conn io.ReadWriter, heloName string, settings *SmtpEdgeSettings) ([]string, error) {
	return smtpPreTls(conn, heloName, settings)
}

// The sending set's pick.
func (self *SmtpSendingSet) Pick(mxAddress netip.Addr, caps *SmtpDestinationCaps, cap int64) (netip.Addr, func(), bool) {
	picked, release, ok := self.pick(mxAddress, caps, cap)
	if !ok {
		return netip.Addr{}, nil, false
	}
	return picked.Address, release, true
}

// The pre-TLS errors a test tells apart.
var (
	ErrSmtpPreTlsNoStartTlsForTest = errSmtpPreTlsNoStartTls
	ErrSmtpPreTlsInjectedForTest   = errSmtpPreTlsInjected
	ErrSmtpPreTlsBackoffForTest    = errSmtpPreTlsBackoff
)
