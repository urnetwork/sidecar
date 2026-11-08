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
