// A bridge to private fixtures for smtpedgeservice_test, which is a separate package because sidecartest
// imports this one for FakeSmtpEdgeStore, so a test of this package importing sidecartest would be a
// cycle (connect/CODESTYLE.md:37).

package smtpedgeservice

import (
	"context"
	"crypto/hpke"
	"time"

	"github.com/urnetwork/sidecar"
)

// Waits until at least count probes have finished, each with its next wait armed.
func (self *SmtpEdgeService) AwaitProbes(ctx context.Context, count int) error {
	for {
		finished, update := self.probeCount.Get()
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

// A sealed copy's raw bytes, for tests that hold the network mail key's private half.
func OpenSealedReport(privateKey hpke.PrivateKey, networkId sidecar.Id, arrival time.Time, sealed []byte) ([]byte, error) {
	return openSmtpSealedReport(privateKey, networkId, arrival, sealed)
}

// Waits until the breaker has finished count reads of the median.
func (self *SmtpBreaker) AwaitMedianReads(ctx context.Context, count int) error {
	for {
		median, update := self.median.Get()
		if count <= median.readCount {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// The gate's check.
func CheckSmtpGateForTest(gate SmtpGate, abuse sidecar.AbuseGate, request *SmtpGateRequest, now time.Time, settings *SmtpEdgeSettings) *SmtpGateDecision {
	return checkSmtpGate(gate, abuse, request, now, settings)
}

// A whole report message as the intake parses it, for a test of the join alone.
func ParseArfReportForTest(raw []byte, settings *SmtpEdgeSettings) (*SmtpArfReport, error) {
	parts, err := parseSmtpReportMime(raw, settings)
	if err != nil {
		return nil, err
	}
	return parseSmtpArf(parts, settings)
}
