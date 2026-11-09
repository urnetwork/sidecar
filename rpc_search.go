//go:build !sidecar_http

// SEARCH's envelope rules (§6.5's search rows, §6.6, §11.14's sizes row; D-PROTO-21, D-EVS-59), in the
// path below SEARCH's handler and caller, so every size and time a relay sees is the requester's to set
// and none tells it what was asked or found:
//
//   - a request is one envelope with no chunk header and a body of exactly SearchRequestByteCount,
//     4,016 B, and its timeout_ms is always 10,000 whatever its caller's ctx says, so the envelope has
//     one length; Call refuses a body of any other size INVALID_ARGUMENT before anything is sent, never
//     sending one short;
//   - a reply body is exactly steps × SearchResultStepByteCount (steps 1 to SearchResultMaxStepCount, 1
//     in v1), which the chunker cuts into 4 × steps envelopes of 4,016 B and a final one of 320 × steps B;
//     an answer of any other size is never sent, the request answering UNAVAILABLE instead, and Call
//     takes no SEARCH_RESULT of another size;
//   - a request whose body is not 4,016 B reaches no handler: it is answered §11.14's INVALID, a padded
//     SearchReply of the request's steps where its body says them, else one, failures after parsing
//     keeping the reply's size; only failures decided before parsing are small Errors;
//   - SEARCH mutates nothing: no idempotency cache, and a retry repeats its (search_id, page), which the
//     indexer answers from its cursor;
//   - it is never cancelled: Call sends no Cancel for it.
//
// Who may ask whom is §11.14's, each side deciding in its own state; on a control contract SEARCH is
// accepted only at a sidecar advertising bit 0 (rpc_contract_class.go). These rules key on the message
// type, so Handle and Call apply them to SEARCH whatever options they are given.

package sidecar

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A SearchReply whose fields leave no room to pad it to its size.
	errSearchReplySize = errors.New("search reply does not fit its steps")
)

// §6.5's and §11.14's fixed values for SEARCH: protocol values, never tunables.
const (
	// A SEARCH request's one body size: one envelope's whole body.
	SearchRequestByteCount = MaxEnvelopeBodyByteCount
	// A SEARCH request's one timeout_ms.
	SearchTimeout = 10 * time.Second
	// A SEARCH_RESULT body's step.
	SearchResultStepByteCount = 16 * 1024
	// The most steps a SEARCH_RESULT body holds; v1 requesters ask 1.
	SearchResultMaxStepCount = 4
	// SearchReply.search_version's one value in v1, and its min and max.
	searchVersion = 1
)

// Whether a body is a SEARCH_RESULT's size: a whole number of steps, 1 to SearchResultMaxStepCount.
func searchResultSized(byteCount int) bool {
	return 0 < byteCount && byteCount%SearchResultStepByteCount == 0 &&
		byteCount/SearchResultStepByteCount <= SearchResultMaxStepCount
}

// reply padded to exactly steps × SearchResultStepByteCount with zeros in pad, whatever it holds
// besides, as §11.14's builder rule sizes every reply. An error when the rest of reply leaves no room.
func padSearchReply(reply *protocol.SearchReply, steps int) ([]byte, error) {
	target := steps * SearchResultStepByteCount
	reply.Pad = nil
	unpadded := proto.Size(reply)
	// pad's tag is one byte; its length varint two or three: try each, as the varint's own length moves
	// the pad's
	for padByteCount := target - unpadded - 4; padByteCount <= target-unpadded; padByteCount += 1 {
		if padByteCount < 0 {
			continue
		}
		reply.Pad = make([]byte, padByteCount)
		if proto.Size(reply) == target {
			return proto.Marshal(reply)
		}
	}
	return nil, errSearchReplySize
}

// §11.14's INVALID reply to a request of the wrong size: a padded SearchReply naming the request's
// search_id and page where its body parses, of its steps where they are 1 to 4, else one step.
func searchInvalidReply(requestBody []byte) ([]byte, error) {
	request := &protocol.SearchRequest{}
	steps := 1
	reply := &protocol.SearchReply{
		SearchVersion: searchVersion,
		MinVersion:    searchVersion,
		MaxVersion:    searchVersion,
		Status:        uint32(protocol.SearchStatus_SEARCH_INVALID),
	}
	if err := proto.Unmarshal(requestBody, request); err == nil {
		reply.SearchId = request.GetSearchId()
		reply.Page = request.GetPage()
		if 1 <= request.GetSteps() && request.GetSteps() <= SearchResultMaxStepCount {
			steps = int(request.GetSteps())
		}
	}
	return padSearchReply(reply, steps)
}

// SEARCH's handler beneath the one SEARCH's task registers: a request of the wrong size is answered
// INVALID at its size without running handler, and an answer of a size no reply may take is refused
// UNAVAILABLE rather than sent.
func searchHandler(handler SubprotocolHandler, log Logger) SubprotocolHandler {
	return func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		if len(request.Body) != SearchRequestByteCount {
			body, err := searchInvalidReply(request.Body)
			if err != nil {
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
			}
			return body, nil
		}
		body, err := handler(ctx, request)
		if err != nil {
			return nil, err
		}
		if !searchResultSized(len(body)) {
			log.Errorf("[subprotocol]a SEARCH answer of %d B, which no reply may be, not sent\n", len(body))
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
		}
		return body, nil
	}
}

// A SEARCH call's answer: the response's body when it is a SEARCH_RESULT of a reply's size, its Error
// when it is one, and ErrSubprotocolResponse otherwise, never retried.
func searchResponseBody(response *rpcResponse) ([]byte, error) {
	switch protocol.MessageType(response.envelope.Type) {
	case protocol.MessageType_SEARCH_RESULT:
		if response.envelope.Flags&EnvelopeFlagError != 0 || !searchResultSized(len(response.envelope.Body)) {
			return nil, ErrSubprotocolResponse
		}
		return response.envelope.Body, nil
	case protocol.MessageType_ERROR:
		return nil, responseError(response.envelope, response.envelope.RequestId)
	}
	return nil, ErrSubprotocolResponse
}
