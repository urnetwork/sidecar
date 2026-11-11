//go:build !sidecar_http

// SEARCH's envelope rules (§6.5's search rows, §6.6, §11.14's sizes row; D-PROTO-21, D-EVS-59), in the
// path below SEARCH's handler and caller, so every size and time a relay sees is the requester's to set
// and none tells it what was asked or found. Every value below is SearchWireSettings', which this side
// carries as SidecarProtocolSettings.Search (rpc_search_settings.go):
//
//   - a request is one envelope with no chunk header and a body of exactly RequestByteCount, 4,016 B,
//     and its timeout_ms is always Timeout, 10 s, whatever its caller's ctx says, so the envelope has one
//     length; Call refuses a body of any other size INVALID_ARGUMENT before anything is sent, never
//     sending one short;
//   - a reply body is exactly steps × StepByteCount (steps 1 to MaxStepCount, 1 in v1), which the chunker
//     cuts into 4 × steps envelopes of 4,016 B and a final one of 320 × steps B; an answer of any other
//     size is never sent, the request answering UNAVAILABLE instead, and Call takes no SEARCH_RESULT of
//     another size;
//   - a request whose body is not 4,016 B reaches no handler: it is answered §11.14's INVALID, a padded
//     SearchReply of the request's steps where its body says them, else one, failures after parsing
//     keeping the reply's size; only failures decided before parsing are small Errors;
//   - SEARCH mutates nothing: no idempotency cache, and a retry repeats its (search_id, page), which the
//     indexer answers from its cursor;
//   - it is never cancelled: Call sends no Cancel for it.
//
// The pad's length (Z1, Z2), which contents can be sized (Z3) and a failure's reply (Z7) of DESIGN-DETAILS
// 11.2.9 are here, since this file links wherever the subprotocol does; remote search's builders and
// parsers, Z4 to Z9, are search_remote_wire.go's.
//
// Who may ask whom is §11.14's, each side deciding in its own state; on a control contract SEARCH is
// accepted only at a sidecar advertising bit 0 (rpc_contract_class.go). These rules key on the message
// type, so Handle and Call apply them to SEARCH whatever options they are given.

package sidecar

import (
	"context"
	"errors"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A SearchReply whose fields leave no room to pad it to its size: a content Z3 does not admit.
	errSearchReplySize = errors.New("search reply does not fit its steps")
)

const (
	// SearchReply.search_version's one value in v1, and its min and max.
	searchVersion = 1
	// pad's field number in SearchRequest and SearchReply, the highest of both, so it is written last.
	searchPadFieldNumber protowire.Number = 15
)

// Whether a body is a SEARCH_RESULT's size: a whole number of steps, 1 to MaxStepCount.
func searchResultSized(byteCount int, settings *SearchWireSettings) bool {
	return 0 < byteCount && byteCount%settings.StepByteCount == 0 &&
		byteCount/settings.StepByteCount <= settings.MaxStepCount
}

// Z2: the length of the pad that makes a body of bodyByteCount whose other fields encode to
// contentByteCount, false when there is none. pad encodes as its tag, its length as a varint and the zeros
// (Z1); the length's varint takes PadLengthMinByteCount to PadLengthMaxByteCount bytes, two or three, so a
// gap of 131 to 16,386 B takes L = gap - 3 and one of 16,388 to 2,097,155 B takes L = gap - 4. A narrower
// length is never used, so every content stops 131 B short of its size and Z3's one rule holds.
func searchRemotePadByteCount(bodyByteCount int, contentByteCount int, settings *SearchWireSettings) (int, bool) {
	gap := bodyByteCount - contentByteCount
	tagByteCount := protowire.SizeTag(searchPadFieldNumber)
	for lengthByteCount := settings.PadLengthMinByteCount; lengthByteCount <= settings.PadLengthMaxByteCount; lengthByteCount += 1 {
		padByteCount := gap - tagByteCount - lengthByteCount
		if 0 < padByteCount && protowire.SizeVarint(uint64(padByteCount)) == lengthByteCount {
			return padByteCount, true
		}
	}
	return 0, false
}

// Z3: whether a content can be sized to bodyByteCount, which for every size SEARCH has is 0 <= content <=
// size - 131 with size - content not 16,387. Builders build only these, and for them Z2 always answers.
func searchRemoteAdmissible(bodyByteCount int, contentByteCount int, settings *SearchWireSettings) bool {
	if contentByteCount < 0 {
		return false
	}
	_, ok := searchRemotePadByteCount(bodyByteCount, contentByteCount, settings)
	return ok
}

// reply padded to exactly steps × StepByteCount with zeros in pad, by Z2's length, whatever it holds
// besides; its other fields are taken with pad empty. errSearchReplySize when they are not admissible.
func padSearchReply(reply *protocol.SearchReply, steps int, settings *SearchWireSettings) ([]byte, error) {
	reply.Pad = nil
	bodyByteCount := steps * settings.StepByteCount
	padByteCount, ok := searchRemotePadByteCount(bodyByteCount, proto.Size(reply), settings)
	if !ok {
		return nil, errSearchReplySize
	}
	reply.Pad = make([]byte, padByteCount)
	return proto.MarshalOptions{Deterministic: true}.Marshal(reply)
}

// The steps a failure's reply takes: the request's where it parsed and asks 1 to MaxStepCount, else one
// (Z8).
func searchRemoteFailureSteps(request *protocol.SearchRequest, settings *SearchWireSettings) int {
	if request != nil && 1 <= request.GetSteps() && int(request.GetSteps()) <= settings.MaxStepCount {
		return int(request.GetSteps())
	}
	return 1
}

// Z7: a failure after parsing, a reply of status alone with the version fields and, where request parsed
// (not nil), its search_id and page, at searchRemoteFailureSteps' size. Its content is at most 90 B, which
// is admissible at every size SEARCH's defaults give (Z-C), so the error is only for settings that break
// the protocol's.
func searchRemoteFailureReply(status protocol.SearchStatus, request *protocol.SearchRequest, settings *SearchWireSettings) ([]byte, error) {
	reply := &protocol.SearchReply{
		SearchVersion: searchVersion,
		MinVersion:    searchVersion,
		MaxVersion:    searchVersion,
		Status:        uint32(status),
	}
	if request != nil {
		reply.SearchId = request.GetSearchId()
		reply.Page = request.GetPage()
	}
	return padSearchReply(reply, searchRemoteFailureSteps(request, settings), settings)
}

// §11.14's INVALID reply to a request of the wrong size: Z7's reply naming the request's search_id and
// page where its body parses, of its steps where they are 1 to MaxStepCount, else one step.
func searchInvalidReply(requestBody []byte, settings *SearchWireSettings) ([]byte, error) {
	request := &protocol.SearchRequest{}
	if err := proto.Unmarshal(requestBody, request); err != nil {
		request = nil
	}
	return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, request, settings)
}

// SEARCH's handler beneath the one SEARCH's task registers: a request of the wrong size is answered
// INVALID at its size without running handler, and an answer of a size no reply may take is refused
// UNAVAILABLE rather than sent.
func searchHandler(handler SubprotocolHandler, settings *SearchWireSettings, log Logger) SubprotocolHandler {
	return func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		if len(request.Body) != settings.RequestByteCount {
			body, err := searchInvalidReply(request.Body, settings)
			if err != nil {
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
			}
			return body, nil
		}
		body, err := handler(ctx, request)
		if err != nil {
			return nil, err
		}
		if !searchResultSized(len(body), settings) {
			log.Errorf("[subprotocol]a SEARCH answer of %d B, which no reply may be, not sent\n", len(body))
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
		}
		return body, nil
	}
}

// A SEARCH call's answer: the response's body when it is a SEARCH_RESULT of a reply's size, its Error
// when it is one, and ErrSubprotocolResponse otherwise, never retried.
func searchResponseBody(response *rpcResponse, settings *SearchWireSettings) ([]byte, error) {
	switch protocol.MessageType(response.envelope.Type) {
	case protocol.MessageType_SEARCH_RESULT:
		if response.envelope.Flags&EnvelopeFlagError != 0 || !searchResultSized(len(response.envelope.Body), settings) {
			return nil, ErrSubprotocolResponse
		}
		return response.envelope.Body, nil
	case protocol.MessageType_ERROR:
		return nil, responseError(response.envelope, response.envelope.RequestId)
	}
	return nil, ErrSubprotocolResponse
}
