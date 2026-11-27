//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Retries and joins (DESIGN-COMPUTE §8.5's retries table; D-GW-5, Q-GW-7; GW-M12-05). Until the call table lands every
// request is a new call, with its own provider call, charge and record, Q-GW-7's option (a): nothing of one call reaches
// another's caller, at the cost of a second charge for a harness's re-run.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"net/http"
	"strings"
)

// The header a caller names one operation in (draft-ietf-httpapi-idempotency-key-header-09).
const gatewayHeaderIdempotencyKey = "Idempotency-Key"

// A call the table holds, in flight or kept: its answer, which every caller of the same operation follows.
type gatewayCallEntry struct {
	answer *gatewayAnswer
}

// Notes how the entry's caller fared: whether the whole answer reached it.
func (self *gatewayCallEntry) followed(delivered bool) {
}

// The request's Idempotency-Key, empty for none; one past IdempotencyKeyByteCount, or repeated, is refused 400.
func gatewayIdempotencyKey(request *http.Request, settings *GatewaySettings) (string, *gatewayError) {
	values := request.Header.Values(gatewayHeaderIdempotencyKey)
	switch {
	case len(values) == 0:
		return "", nil
	case 1 < len(values):
		return "", gatewayInvalidRequest(GatewayErrorCodeInvalidValue, gatewayHeaderIdempotencyKey, "one Idempotency-Key names one operation")
	}
	key := strings.TrimSpace(values[0])
	if key == "" || settings.IdempotencyKeyByteCount < len(key) {
		return "", gatewayInvalidRequest(GatewayErrorCodeInvalidValue, gatewayHeaderIdempotencyKey,
			"an Idempotency-Key is 1 to %d bytes", settings.IdempotencyKeyByteCount)
	}
	return key, nil
}

// The call a prepared request repeats, and whether it joins it; else the entry a new call is kept as, nil for none.
func (self *GatewayFronts) lookup(ctx context.Context, prepared *gatewayPreparedCall) (*gatewayCallEntry, bool, *gatewayError) {
	return nil, false, nil
}

// Drops an entry whose call was never sent.
func (self *GatewayFronts) forget(entry *gatewayCallEntry) {
}

// Notes that an entry's answer grew or ended.
func (self *GatewayFronts) kept(entry *gatewayCallEntry) {
}

// The calls kept, for ur status.
func (self *GatewayFronts) keptCount() int {
	return 0
}
