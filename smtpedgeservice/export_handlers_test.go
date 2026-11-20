// The bridge edge_dispatch_test.go reaches the engine's functions on a dispatcher through: what Serve registers on
// each platform client's dispatcher (registerHandlers), registered on one a test made. Tests only.

package smtpedgeservice

import (
	"github.com/urnetwork/sidecar"
)

// Registers SMTP_PROOF's and SMTP_HANDSHAKE's handlers and SMTP_OUTCOME's NO_REPLY function on subprotocol, as Serve
// does on each platform client's dispatcher; remove takes them away.
func (self *SmtpEdgeService) RegisterHandlersForTest(subprotocol *sidecar.Subprotocol) (remove func(), err error) {
	return self.registerHandlers(subprotocol)
}
