//go:build !sidecar_http && !js

// The control class's receiver rule (PROTO-M4-03): the per-type table on control, unset and data; unset
// read as control; the class read per frame, so a pair whose contract changes class is judged by each
// frame's own; Hello and HeadCheck passing on control with no grant; streams rejected DENIED and other
// RPCs refused PERMISSION_DENIED. FS-21's schedule itself runs in ACL-M4-04, on the real gate.

package sidecar

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// Every type §6.11 assigns that a peer sends, as a request and as a response, against each class: what
// passes, what is refused, what a StreamOpen gets, and what is dropped.
func TestContractClassTable(t *testing.T) {
	type row struct {
		messageType protocol.MessageType
		flags       uint32
		// on control and unset, without and with bit 0 served
		control       contractClassVerdict
		controlSearch contractClassVerdict
	}
	request := uint32(0)
	response := EnvelopeFlagResponse
	noReply := EnvelopeFlagNoReply
	rows := []row{
		{messageType: protocol.MessageType_HELLO, flags: request, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_HELLO_RESULT, flags: response, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_PING, flags: request, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_PONG, flags: response, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_HEAD_CHECK, flags: request, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_HEAD_CHECK_RESULT, flags: response, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_HEAD_CHECK_PROOF_REQUEST, flags: request, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_HEAD_CHECK_PROOF, flags: response, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_ERROR, flags: response | EnvelopeFlagError, control: contractClassPass, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_SEARCH, flags: request, control: contractClassRefuse, controlSearch: contractClassPass},
		{messageType: protocol.MessageType_SEARCH_RESULT, flags: response, control: contractClassPass, controlSearch: contractClassPass},
		// SEARCH_RESULT only as a reply, and SEARCH never as one
		{messageType: protocol.MessageType_SEARCH_RESULT, flags: request, control: contractClassRefuse, controlSearch: contractClassRefuse},
		{messageType: protocol.MessageType_SEARCH, flags: response, control: contractClassDrop, controlSearch: contractClassDrop},
		{messageType: protocol.MessageType_CANCEL, flags: noReply, control: contractClassDrop, controlSearch: contractClassDrop},
		{messageType: protocol.MessageType_STREAM_OPEN, flags: request, control: contractClassRejectStream, controlSearch: contractClassRejectStream},
		{messageType: protocol.MessageType_STREAM_DATA, flags: noReply, control: contractClassDrop, controlSearch: contractClassDrop},
		{messageType: protocol.MessageType_STREAM_ACCEPT, flags: noReply, control: contractClassDrop, controlSearch: contractClassDrop},
		{messageType: protocol.MessageType_STREAM_RESET, flags: noReply, control: contractClassDrop, controlSearch: contractClassDrop},
		{messageType: protocol.MessageType_TLS_EDGE_OPEN, flags: request, control: contractClassRefuse, controlSearch: contractClassRefuse},
		{messageType: protocol.MessageType_SMTP_PROOF, flags: request, control: contractClassRefuse, controlSearch: contractClassRefuse},
		{messageType: protocol.MessageType_SMTP_PROOF_RESULT, flags: response, control: contractClassDrop, controlSearch: contractClassDrop},
		// a data RPC's response, which rides the reverse data contract, refused on control
		{messageType: testCallType + 1, flags: response, control: contractClassDrop, controlSearch: contractClassDrop},
		{messageType: testCallType, flags: request, control: contractClassRefuse, controlSearch: contractClassRefuse},
	}
	for _, r := range rows {
		for _, class := range []connectprotocol.ContractClass{connectprotocol.ContractClass_ContractClassControl, connectprotocol.ContractClass_ContractClassUnset, connectprotocol.ContractClass(7)} {
			if verdict := contractClassAdmits(class, uint32(r.messageType), r.flags, false); verdict != r.control {
				t.Errorf("%s flags %d on %s: %d, want %d", r.messageType, r.flags, class, verdict, r.control)
			}
			if verdict := contractClassAdmits(class, uint32(r.messageType), r.flags, true); verdict != r.controlSearch {
				t.Errorf("%s flags %d on %s serving search: %d, want %d", r.messageType, r.flags, class, verdict, r.controlSearch)
			}
		}
		for _, servesSearch := range []bool{false, true} {
			if verdict := contractClassAdmits(connectprotocol.ContractClass_ContractClassData, uint32(r.messageType), r.flags, servesSearch); verdict != contractClassPass {
				t.Errorf("%s flags %d on data: %d", r.messageType, r.flags, verdict)
			}
		}
	}
}

// Hello and HeadCheck pass on a control contract with no grant, and a data RPC on it is refused
// PERMISSION_DENIED at the receiver, whose handler never runs.
func TestControlContractCarriesHelloAndHeadCheckOnly(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	b := world.add(testMainChain, 10, nil)
	a.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	b.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	ran := make(chan struct{}, 1)
	if _, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		ran <- struct{}{}
		return []byte("answered"), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("Hello on control: %v", err)
	}
	if witnessed, err := a.subprotocol.HeadCheckNow(t.Context(), Id(b.clientId)); err != nil || !witnessed {
		t.Fatalf("HeadCheck on control: witnessed %t: %v", witnessed, err)
	}
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("a data RPC on control: %v", err)
	}
	select {
	case <-ran:
		t.Errorf("the handler ran for a data RPC on control")
	default:
	}
	// the same RPC on data, its answer on the reverse contract classed data too, passes
	a.setContractClass(connectprotocol.ContractClass_ContractClassData)
	b.setContractClass(connectprotocol.ContractClass_ContractClassData)
	if body, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil); err != nil || string(body) != "answered" {
		t.Errorf("a data RPC on data: %q %v", body, err)
	}
}

// An unset class is control's: a data RPC is refused, Hello passes.
func TestUnsetContractClassIsControl(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	a.setContractClass(connectprotocol.ContractClass_ContractClassUnset)
	if _, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return []byte("answered"), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("Hello on an unset class: %v", err)
	}
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("a data RPC on an unset class: %v", err)
	}
}

// The class is read per frame: a pair whose contract moves from data to control and back is judged by
// each frame's own class, never one kept for the peer.
func TestContractClassReadPerFrame(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	if _, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return []byte("answered"), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		class connectprotocol.ContractClass
		code  protocol.ErrorCode
	}{
		{class: connectprotocol.ContractClass_ContractClassData, code: protocol.ErrorCode_ERR_OK},
		{class: connectprotocol.ContractClass_ContractClassControl, code: protocol.ErrorCode_ERR_PERMISSION_DENIED},
		{class: connectprotocol.ContractClass_ContractClassData, code: protocol.ErrorCode_ERR_OK},
		{class: connectprotocol.ContractClass_ContractClassUnset, code: protocol.ErrorCode_ERR_PERMISSION_DENIED},
	} {
		a.setContractClass(c.class)
		_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ask"), nil)
		code, _ := SubprotocolErrorCode(err)
		if err == nil {
			code = protocol.ErrorCode_ERR_OK
		}
		if code != c.code {
			t.Errorf("on %s: %v", c.class, err)
		}
	}
}

// A StreamOpen on control is answered StreamReject{DENIED} on the open's stream id, and no stream
// layer sees it.
func TestControlContractRejectsStreamOpenDenied(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	a.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	body, err := proto.Marshal(&protocol.StreamOpen{Target: "testnet:echo", Window: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	open := &protocol.Envelope{Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_OPEN), RequestId: newRequestId(), StreamId: 6, Body: body}
	rejects := make(chan *protocol.Envelope, 1)
	b.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == b && envelope.Type == uint32(protocol.MessageType_STREAM_REJECT) {
			rejects <- envelope
			return nil
		}
		return envelope
	})
	if err := a.subprotocol.sendEnvelope(b.clientId, open, 0); err != nil {
		t.Fatal(err)
	}
	reject := testAwait(t, rejects, "StreamReject")
	streamReject := &protocol.StreamReject{}
	if err := proto.Unmarshal(reject.Body, streamReject); err != nil {
		t.Fatal(err)
	}
	if reject.StreamId != open.StreamId || streamReject.Code != uint32(protocol.StreamRejectCode_SR_DENIED) || reject.Flags&EnvelopeFlagNoReply == 0 {
		t.Errorf("reject %+v code %d", reject, streamReject.Code)
	}
	if count := b.subprotocol.stats.contractClassRefusedCount.Load(); count != 1 {
		t.Errorf("%d refused", count)
	}
}
