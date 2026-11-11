// GET /socket/list (§9.15): one page of the caller's own network's registered names, an edge name as it is and
// any other as its token path with its seal, which only a holder of the network's K_sock opens, so a client
// unseals names locally (D-SOCK-13). A page examines at most ListPageCount names of the listing,
// {sn_<network_id>}names (§2.8's sock-4), and charges one token of the caller's bucket (SOCK.md reading 10),
// so a listing cannot pin Redis as an unbounded one would. The cursor is the store's, passed through.
//
// Steps: authenticate, a removed client answering 401 and a token with no sidecar_id outside urnetwork-edge
// denied (request.go); §19.11's sockets gate; the bucket; the fair queue; one ListNames. No gate verdict is
// taken: a network's clients may list what the network registered, and nothing in a page is a name in the
// clear but an edge one, which is public anyway. A name may come back on two pages. Safe for concurrent use.

package socketsservice

import (
	"errors"
	"net/http"

	"github.com/urnetwork/sidecar"
)

// The longest cursor a page takes: the store's cursors are short, and a longer one is no page's.
const socketListMaxCursorByteCount = 256

// Handles GET /socket/list.
func (self *SocketsService) serveList(w http.ResponseWriter, r *http.Request) {
	result, refusal := self.list(r)
	switch {
	case refusal != nil && refusal.status != http.StatusOK:
		writeSocketStatus(w, refusal)
	case refusal != nil:
		writeSocketJson(w, &sidecar.SocketListResult{Names: []*sidecar.SocketListName{}, Error: refusal.socketError()})
	default:
		writeSocketJson(w, result)
	}
}

// One page.
func (self *SocketsService) list(r *http.Request) (*sidecar.SocketListResult, *socketRefusal) {
	caller, refusal := self.authenticate(r)
	if refusal != nil {
		return nil, refusal
	}
	networkId := caller.principal.NetworkId
	if refusal := self.gateRefusal(networkId); refusal != nil {
		return nil, refusal
	}
	if refusal := self.chargeRefusal(caller); refusal != nil {
		return nil, refusal
	}
	release, refusal := self.queueTurn(r.Context(), networkId)
	if refusal != nil {
		return nil, refusal
	}
	defer release()
	cursor := r.URL.Query().Get("cursor")
	if socketListMaxCursorByteCount < len(cursor) {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeInvalid, 0)
	}
	if self.store == nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}
	names, nextCursor, err := func() ([]*sidecar.SocketListName, string, error) {
		ctx, done := self.storeContext()
		defer done()
		return self.store.ListNames(ctx, networkId, cursor, self.settings.ListPageCount)
	}()
	switch {
	case errors.Is(err, ErrSocketStoreRequest):
		// a cursor no page gave
		return nil, socketRefusalOf(sidecar.SocketErrorCodeInvalid, 0)
	case err != nil:
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}
	if names == nil {
		names = []*sidecar.SocketListName{}
	}
	return &sidecar.SocketListResult{Names: names, NextCursor: nextCursor}, nil
}
