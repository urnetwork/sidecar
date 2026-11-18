//go:build ios_extension && !sidecar_http

// SEARCH on the ios_extension legs (rpc_search_leg.go; §18.10, §22.5's §18 row; QD-988): the subprotocol's Call and
// Handle refuse it, no response is its answer, and the leg links neither search.proto's nor evsindex.proto's
// descriptor. The root's other tests are written for the legs that run them and do not build under this tag, so
// check/'s TestLegsRunTheIosExtensionLegsSearchTests runs these with every other test file left out, and they use nothing of
// those files.

package sidecar

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/sidecar/protocol"
)

// A dispatcher of the default settings and nothing else: no client, store or clock, so a call that went on to send
// or to register would fail on a nil one, and a refusal is one made before either.
func testSearchLegSubprotocol() *Subprotocol {
	return &Subprotocol{settings: DefaultSidecarProtocolSettings()}
}

// Call answers a SEARCH request UNIMPLEMENTED before anything is sent, at the request's size as at any other.
func TestSearchLegCallRefusesSearch(t *testing.T) {
	subprotocol := testSearchLegSubprotocol()
	for _, byteCount := range []int{subprotocol.settings.Search.RequestByteCount, 0, 16} {
		answer, err := subprotocol.Call(t.Context(), Id{0x0b}, protocol.MessageType_SEARCH, make([]byte, byteCount), nil)
		code, coded := SubprotocolErrorCode(err)
		if answer != nil || !coded || code != protocol.ErrorCode_ERR_UNIMPLEMENTED {
			t.Errorf("a SEARCH call of %d B: %x %v", byteCount, answer, err)
		}
	}
}

// Handle takes no handler for SEARCH, and gives nothing to remove.
func TestSearchLegHandleRefusesSearch(t *testing.T) {
	subprotocol := testSearchLegSubprotocol()
	ran := false
	remove, err := subprotocol.Handle(protocol.MessageType_SEARCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		ran = true
		return nil, nil
	}, nil)
	if remove != nil || !errors.Is(err, errHandleType) || ran {
		t.Errorf("a SEARCH handler: %v, ran %t", err, ran)
	}
}

// No response is a SEARCH call's answer: a SEARCH_RESULT of a reply's size is refused, as is an Error.
func TestSearchLegTakesNoSearchResult(t *testing.T) {
	settings := DefaultSearchWireSettings()
	for _, envelope := range []*protocol.Envelope{
		{Type: uint32(protocol.MessageType_SEARCH_RESULT), Flags: EnvelopeFlagResponse, Body: make([]byte, settings.StepByteCount)},
		{Type: uint32(protocol.MessageType_ERROR), Flags: EnvelopeFlagResponse},
	} {
		body, err := searchResponseBody(&rpcResponse{envelope: envelope}, settings)
		if body != nil || !errors.Is(err, ErrSubprotocolResponse) {
			t.Errorf("a response of type %d: %x %v", envelope.Type, body, err)
		}
	}
}

// The leg links neither search.proto's nor evsindex.proto's descriptor, while envelope.proto's, which the
// subprotocol reads, is there.
func TestSearchLegLinksNoSearchDescriptor(t *testing.T) {
	if _, err := protoregistry.GlobalFiles.FindFileByPath("protocol/envelope.proto"); err != nil {
		t.Fatalf("CONTROL FAILED: envelope.proto is not registered, so the registry was not read: %v", err)
	}
	for _, path := range []string{"protocol/search.proto", "protocol/evsindex.proto"} {
		if _, err := protoregistry.GlobalFiles.FindFileByPath(path); !errors.Is(err, protoregistry.NotFound) {
			t.Errorf("%s is registered on the leg: %v", path, err)
		}
	}
}
