// GET /socket/keys (§9.8, §9.15; Public): every key a ticket may verify under, as registration answers carry
// them, for a holder that has none yet. Keys rotate every 30 days with overlap (SOCK-M5-08's SocketTicketKeySet),
// so a holder keeps each key it is given until its expiry. Public keys only, so no caller is authenticated or
// charged, and the lb's per-address limits (§19.5's W2) bound it. An engine with no keys answers none, which
// refuses every ticket at admission's step 1: the closed direction. Safe for concurrent use.

package socketsservice

import (
	"net/http"

	"github.com/urnetwork/sidecar"
)

// Handles GET /socket/keys.
func (self *SocketsService) serveKeys(w http.ResponseWriter, r *http.Request) {
	result := &sidecar.SocketKeysResult{Keys: []*sidecar.SocketTicketKey{}}
	if ticketKeys, _ := self.currentTicketKeys(); ticketKeys != nil {
		if keys := ticketKeys.VerifyKeys(); keys != nil {
			result.Keys = keys
		}
	}
	writeSocketJson(w, result)
}
