// TlsHint on topic tls (§13.15, §6.8; plan-TLS-small-readings #1): each move of an order, each issuance
// and each revocation tells the row's device to read GET /tls/certs again. A hint carries the row's id
// and a kind and nothing else, and it is never authoritative: a device that misses one finds the change
// at its hourly resync, so a failed hint is counted and passed over.
//
// The topic's version is this writer's clock in milliseconds, which the hint script raises past the
// stored value when it is not above it (plan-PROTO-sync-routes-durable-versions: tls as mail), so skew
// between two writers never makes a hint stale.
//
// A hint goes to the client that ordered, the row's client_id, through Push.Hint, as api's own hints go
// (model.SidecarHint). A sidecar whose client has changed generation since it ordered misses the hint,
// and its hourly resync covers it.

package certsservice

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Publishes one TlsHint of kind for row to its client. Returns whether the host took it: false on a
// host with no Push, and when the hint failed.
func (self *CertsService) hint(ctx context.Context, row *sidecar.TlsCertRecord, kind protocol.TlsHintKind) bool {
	if self.push == nil || row == nil || row.ClientId == (sidecar.Id{}) {
		return false
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.TlsHint{
		Kind:   kind,
		CertId: row.CertId[:],
	})
	if err != nil {
		return false
	}
	// a hint outlives the pass that made it: its own bound, not the pass's end
	callCtx, cancel := self.callContext(context.WithoutCancel(ctx))
	defer cancel()
	err = self.push.Hint(callCtx, []connect.Id{connect.Id(row.ClientId)}, &sidecar.ClientHint{
		Topic:   sidecar.PushTopicTls,
		Version: uint64(max(self.clock.Now().UnixMilli(), 1)),
		Kind:    uint32(protocol.MessageType_TLS_HINT),
		Body:    body,
	})
	return err == nil
}
