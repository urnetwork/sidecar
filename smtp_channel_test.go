//go:build !sidecar_http && !ios_extension

// smtpProofChannel over a scripted caller: every field of a part reaches SMTP_PROOF's body and nothing else does, the
// SHTS rides SMTP_HANDSHAKE, INVALID is the edge's refusal and a code of 0 the protocol's error, and a call that
// timed out goes again under its request_id, once, and no more.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// One call the scripted caller took.
type testSmtpChannelCall struct {
	clientId    Id
	messageType protocol.MessageType
	body        []byte
	options     *CallOptions
}

// A caller that records each call and answers it by its script, in order, then by its last answer.
type testSmtpChannelCaller struct {
	stateLock sync.Mutex
	calls     []*testSmtpChannelCall
	answers   []func(call *testSmtpChannelCall) ([]byte, error)
}

func (self *testSmtpChannelCaller) Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	call := &testSmtpChannelCall{clientId: clientId, messageType: messageType, body: bytes.Clone(body), options: options}
	self.calls = append(self.calls, call)
	answer := self.answers[min(len(self.calls), len(self.answers))-1]
	return answer(call)
}

// An answer of message's bytes.
func testSmtpChannelAnswer(message proto.Message) func(call *testSmtpChannelCall) ([]byte, error) {
	return func(call *testSmtpChannelCall) ([]byte, error) {
		return proto.Marshal(message)
	}
}

func testSmtpChannelPart() *SmtpProofPart {
	return &SmtpProofPart{
		SendId:            []byte("not the channel's"),
		Index:             3,
		Mode:              uint32(SmtpModeBdat),
		FirstRecord:       7,
		LastRecord:        9,
		Proof:             bytes.Repeat([]byte{0x11}, 164),
		Last:              true,
		ServerRecordCount: 4,
		Records:           [][]byte{{0x17, 0x03, 0x03, 0x00, 0x01, 0xaa}, {0x17, 0x03, 0x03, 0x00, 0x01, 0xbb}},
		KeyCommitment:     bytes.Repeat([]byte{0xc0}, 64),
		ReplyCount:        5,
		HeaderRecordCount: 2,
		Carry:             bytes.Repeat([]byte{0xca}, 64),
	}
}

func TestSmtpProofChannelEncodesEveryFieldOfAPart(t *testing.T) {
	caller := &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){
		testSmtpChannelAnswer(&protocol.SmtpProofResult{Code: uint32(protocol.SmtpProofCode_SMTP_PROOF_OK)}),
	}}
	edgeClientId := NewId()
	sendId := bytes.Repeat([]byte{0x5e}, SmtpSendIdByteCount)
	channel := newSmtpProofChannel(caller, edgeClientId, sendId, DefaultSmtpSenderSettings())
	part := testSmtpChannelPart()
	if err := channel.SubmitPart(context.Background(), part); err != nil {
		t.Fatal(err)
	}
	if len(caller.calls) != 1 || caller.calls[0].messageType != protocol.MessageType_SMTP_PROOF || caller.calls[0].clientId != edgeClientId {
		t.Fatalf("calls %+v", caller.calls)
	}
	if caller.calls[0].options.Timeout != DefaultSmtpSenderSettings().ProofCallTimeout {
		t.Errorf("a timeout of %v", caller.calls[0].options.Timeout)
	}
	// an edge answers no Hello, so the call is marked for one (owner decision 624)
	if !caller.calls[0].options.Edge {
		t.Error("a part's call not marked for the edge")
	}
	sent := &protocol.SmtpProof{}
	if err := proto.Unmarshal(caller.calls[0].body, sent); err != nil {
		t.Fatal(err)
	}
	want := smtpProofOf(sendId, part)
	if !proto.Equal(sent, want) {
		t.Errorf("sent %v, want %v", sent, want)
	}
	// the channel's send_id stands for the part's, and each of the thirteen fields is set
	if !bytes.Equal(sent.GetSendId(), sendId) || sent.ProtoReflect().Descriptor().Fields().Len() != 13 {
		t.Errorf("send_id %x of %d fields", sent.GetSendId(), sent.ProtoReflect().Descriptor().Fields().Len())
	}
	setCount := 0
	sent.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		setCount += 1
		return true
	})
	if setCount != 13 {
		t.Errorf("%d of 13 fields set", setCount)
	}
}

func TestSmtpProofChannelDisclosesShtsByTheHandshake(t *testing.T) {
	caller := &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){
		testSmtpChannelAnswer(&protocol.SmtpHandshakeResult{Code: uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK)}),
	}}
	sendId := bytes.Repeat([]byte{0x5e}, SmtpSendIdByteCount)
	shts := bytes.Repeat([]byte{0x33}, 32)
	channel := newSmtpProofChannel(caller, NewId(), sendId, DefaultSmtpSenderSettings())
	if err := channel.DiscloseShts(context.Background(), shts); err != nil {
		t.Fatal(err)
	}
	handshake := &protocol.SmtpHandshake{}
	if len(caller.calls) != 1 || caller.calls[0].messageType != protocol.MessageType_SMTP_HANDSHAKE || proto.Unmarshal(caller.calls[0].body, handshake) != nil {
		t.Fatalf("calls %+v", caller.calls)
	}
	if !bytes.Equal(handshake.GetSendId(), sendId) || !bytes.Equal(handshake.GetShts(), shts) {
		t.Errorf("sent %v", handshake)
	}
	if !caller.calls[0].options.Edge {
		t.Error("the handshake's call not marked for the edge")
	}
}

// INVALID is the edge's refusal; a code of 0 or past the enum is the protocol's error; neither is retried.
func TestSmtpProofChannelRefusals(t *testing.T) {
	for _, c := range []struct {
		code uint32
		want error
	}{
		{code: uint32(protocol.SmtpProofCode_SMTP_PROOF_INVALID), want: ErrSmtpProofRefused},
		{code: 0, want: errSmtpProofAnswer},
		{code: 9, want: errSmtpProofAnswer},
	} {
		caller := &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){
			testSmtpChannelAnswer(&protocol.SmtpProofResult{Code: c.code}),
		}}
		channel := newSmtpProofChannel(caller, NewId(), bytes.Repeat([]byte{1}, SmtpSendIdByteCount), DefaultSmtpSenderSettings())
		if err := channel.SubmitPart(context.Background(), testSmtpChannelPart()); !errors.Is(err, c.want) || len(caller.calls) != 1 {
			t.Errorf("code %d: %v after %d calls", c.code, err, len(caller.calls))
		}
	}
	caller := &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){
		testSmtpChannelAnswer(&protocol.SmtpHandshakeResult{Code: uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_INVALID)}),
	}}
	channel := newSmtpProofChannel(caller, NewId(), bytes.Repeat([]byte{1}, SmtpSendIdByteCount), DefaultSmtpSenderSettings())
	if err := channel.DiscloseShts(context.Background(), []byte{1}); !errors.Is(err, ErrSmtpProofRefused) {
		t.Errorf("an invalid handshake: %v", err)
	}
}

// A call that timed out goes again under its request_id, up to ProofCallAttemptCount calls; any other failure is not
// retried.
func TestSmtpProofChannelRetriesATimedOutCallUnderItsRequestId(t *testing.T) {
	timedOut := func(call *testSmtpChannelCall) ([]byte, error) {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: 77}
	}
	caller := &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){
		timedOut, testSmtpChannelAnswer(&protocol.SmtpProofResult{Code: uint32(protocol.SmtpProofCode_SMTP_PROOF_OK)}),
	}}
	channel := newSmtpProofChannel(caller, NewId(), bytes.Repeat([]byte{1}, SmtpSendIdByteCount), DefaultSmtpSenderSettings())
	if err := channel.SubmitPart(context.Background(), testSmtpChannelPart()); err != nil {
		t.Fatal(err)
	}
	if len(caller.calls) != 2 || caller.calls[0].options.RequestId != 0 || caller.calls[1].options.RequestId != 77 || !bytes.Equal(caller.calls[0].body, caller.calls[1].body) {
		t.Errorf("calls %+v", caller.calls)
	}
	if len(caller.calls) == 2 && (!caller.calls[0].options.Edge || !caller.calls[1].options.Edge) {
		t.Error("a call or its retry not marked for the edge")
	}

	// two timeouts end it at the attempt count
	caller = &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){timedOut}}
	channel = newSmtpProofChannel(caller, NewId(), bytes.Repeat([]byte{1}, SmtpSendIdByteCount), DefaultSmtpSenderSettings())
	if err := channel.SubmitPart(context.Background(), testSmtpChannelPart()); err == nil || len(caller.calls) != DefaultSmtpSenderSettings().ProofCallAttemptCount {
		t.Errorf("%v after %d calls", err, len(caller.calls))
	}

	// an unavailable edge is no timeout
	caller = &testSmtpChannelCaller{answers: []func(call *testSmtpChannelCall) ([]byte, error){
		func(call *testSmtpChannelCall) ([]byte, error) {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
		},
	}}
	channel = newSmtpProofChannel(caller, NewId(), bytes.Repeat([]byte{1}, SmtpSendIdByteCount), DefaultSmtpSenderSettings())
	if err := channel.SubmitPart(context.Background(), testSmtpChannelPart()); err == nil || len(caller.calls) != 1 {
		t.Errorf("%v after %d calls", err, len(caller.calls))
	}
}
