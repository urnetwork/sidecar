// What the external tests of the provider hook reach in this package's own tests. connect.Peer's verified session key
// is connect's alone to set, so a test hands VerifyPrincipal's checks the fields it reads of a peer.

package device

import (
	"github.com/urnetwork/connect"
)

// VerifyPrincipal's checks over a contract's source, the session's verified key, C13's sealed network and subject and
// the delegation as sealed, past its profile and provide mode rows.
func (self *BridgeEgressPolicy) VerifyPrincipalForTest(
	sourceId connect.Id,
	sessionKey []byte,
	sealedNetwork connect.Id,
	sealedSubject connect.Id,
	delegation []byte,
) *connect.BridgePrincipal {
	return self.verifyPrincipal(sourceId, sessionKey, sealedNetwork, sealedSubject, delegation)
}

// The same checks on the policy a bridge enforces by, so a test of a bridge's revocations holds a principal as its
// hook answered one.
func (self *Bridge) VerifyPrincipalForTest(
	sourceId connect.Id,
	sessionKey []byte,
	sealedNetwork connect.Id,
	sealedSubject connect.Id,
	delegation []byte,
) *connect.BridgePrincipal {
	return self.policy.verifyPrincipal(sourceId, sessionKey, sealedNetwork, sealedSubject, delegation)
}

// The delegations VerifyPrincipal has checked a signature of, and the contracts it refused for a sealed subject the
// delegation's subject does not bind.
func (self *BridgeEgressPolicy) PrincipalCountsForTest() (verifiedCount uint64, mismatchCount uint64) {
	return self.principalCounts()
}
