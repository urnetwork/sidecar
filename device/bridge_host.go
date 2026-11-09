// §17.10's BridgeHost, verbatim: what builds a bridge's links. The sdk's DeviceLocal and the CLI implement it, since
// each owns the client generator a link's multi client draws its window clients from; device.Bridge only asks.

package device

import (
	"context"
	"net/netip"
	"time"

	"github.com/urnetwork/connect"
)

// Builds one link per target (Q-BRIDGE-2). Implementations are safe for concurrent use.
type BridgeHost interface {
	// One link per target (Q-BRIDGE-2); shareAliases is nil for a same-network link (ProvideMode_Network), and for a
	// share link (FriendsAndFamily) lists the aliases C18's source half may carry. sign returns the Signed
	// WindowDelegation for each window client the link builds, not_after_ms at most notAfter, the client's strict_exp
	// (§7.4), and on a share link the host calls it again for each live one when the sidecar role signals a new
	// BridgeShareSigner (§18.6's ResignShares, or in process), for its later contracts (§17.9).
	NewBridgeLink(ctx context.Context, target connect.Id, subject connect.Id, shareAliases []netip.Prefix,
		sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
	) (connect.UserNatClient, error)
}
