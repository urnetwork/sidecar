//go:build ios_extension && !sidecar_http

// SEARCH on the ios_extension legs (§18.10, §22.5's §18 row; QD-988, sdk-m10-01-ios-leg-links-index-code): the
// forwarding role runs no search, so its legs link neither rpc_search.go nor protocol's search descriptor, and this
// file stands in for the three functions the subprotocol's Call and Handle reach there. Each refuses, the closed
// direction:
//
//   - Call answers a SEARCH request UNIMPLEMENTED before anything is sent, whatever its body;
//   - no response is a SEARCH call's answer, should one ever be read;
//   - Handle takes no handler for SEARCH, so a peer's request is answered as any type nothing serves.
//
// Nothing here reads SearchWireSettings: its sizes are rpc_search.go's to apply, and the leg sends and takes no
// search body to size.

package sidecar

import (
	"github.com/urnetwork/sidecar/protocol"
)

// What Call answers a SEARCH request body: UNIMPLEMENTED for every one, since this leg asks no indexer.
func searchRequestBodyError(body []byte, settings *SearchWireSettings) error {
	return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNIMPLEMENTED, Message: "this build runs no search"}
}

// A SEARCH call's answer: none, whatever the response holds. Call refuses the request first, so this is reached
// only were that check to go.
func searchResponseBody(response *rpcResponse, settings *SearchWireSettings) ([]byte, error) {
	return nil, ErrSubprotocolResponse
}

// SEARCH's handler: nil, which Handle refuses, so this leg serves no search.
func searchHandler(handler SubprotocolHandler, settings *SearchWireSettings, log Logger) SubprotocolHandler {
	return nil
}
