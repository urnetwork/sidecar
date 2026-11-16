// Bridges for smtpedgeservice_test to the splice: one stream served as the ur/smtpedge listener hands it over,
// the proof RPCs as the dispatcher calls them, the record splitter and the live connections.

package smtpedgeservice

import (
	"context"
	"io"

	"github.com/urnetwork/sidecar"
)

// Serves conn as the listener would a stream admitted on a ticket naming networkId and clientId, the sidecar
// sidecarId, and returns once its connection ended.
func (self *SmtpEdgeService) ServeTestStream(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id, conn io.ReadWriteCloser) {
	if !self.startStream() {
		conn.Close()
		return
	}
	defer self.streams.Done()
	self.serveStream(conn, &smtpPreambleStream{NetworkId: networkId, ClientId: clientId, SidecarId: sidecarId})
}

// SMTP_PROOF's handler, called as the dispatcher would for sourceId.
func (self *SmtpEdgeService) HandleProofForTest(ctx context.Context, sourceId sidecar.Id, body []byte) ([]byte, error) {
	return self.handleProof(ctx, &sidecar.SubprotocolRequest{SourceId: sourceId, Body: body})
}

// SMTP_HANDSHAKE's handler, as above.
func (self *SmtpEdgeService) HandleHandshakeForTest(ctx context.Context, sourceId sidecar.Id, body []byte) ([]byte, error) {
	return self.handleHandshake(ctx, &sidecar.SubprotocolRequest{SourceId: sourceId, Body: body})
}

// How many connections are live.
func (self *SmtpEdgeService) LiveConnectionCount() int {
	return len(self.liveConnections())
}

// Every record reader holds, as the splitter cuts them, and the error that ended it.
func SplitRecordsForTest(reader io.Reader, recordMaxByteCount int) ([][]byte, error) {
	splitter := newSmtpRecordSplitter(reader, recordMaxByteCount)
	records := [][]byte{}
	for {
		record, err := splitter.next()
		if err != nil {
			return records, err
		}
		records = append(records, record)
	}
}

// The version a ServerHello record names.
func ServerHelloVersionForTest(record []byte) uint16 {
	return smtpServerHelloVersion(record)
}

// Records waiting in the send log.
func (self *SmtpEdgeService) PendingSendCount() int {
	if self.sendLog == nil {
		return 0
	}
	return self.sendLog.pendingCount()
}

// Writes what the send log holds now, as its loop would at its next interval.
func (self *SmtpEdgeService) FlushSendLogForTest(ctx context.Context) {
	if self.sendLog == nil {
		return
	}
	for 0 < self.sendLog.pendingCount() && self.sendLog.flushBatch(ctx) {
	}
	self.sendLog.flushBatch(ctx)
}

// Sends the open usage window at once, as a drain does.
func (self *SmtpEdgeService) DrainUsageForTest(ctx context.Context) error {
	return self.usage.Drain(ctx)
}

// Waits until monitor counts at least count.
func awaitMonitorCount(ctx context.Context, monitor *sidecar.MonitorValue[int], count int) error {
	for {
		value, update := monitor.Get()
		if count <= value {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Waits until the ladder has finished count pieces of halt work.
func (self *SmtpEdgeService) AwaitHaltWork(ctx context.Context, count int) error {
	return awaitMonitorCount(ctx, self.haltWorkCount, count)
}

// Waits until connections have begun count waits for room.
func (self *SmtpEdgeService) AwaitHeldWaits(ctx context.Context, count int) error {
	return awaitMonitorCount(ctx, self.heldWaitCount, count)
}
