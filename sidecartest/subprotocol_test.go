package sidecartest

// §6's M1 exit scenarios on T2 (PROTO-M1-11), through the public entry points of real Sidecars on the
// Net's in-process exchange, with Hello's identity and admission check, retries and refusals on:
// Required RPC between two sidecars after the identity check, the capture holding only ciphertext between
// them (R-PROTO-8); nothing reaching a handler before a verified Hello, a peer the state does not admit
// refused; a session that cannot form refusing UNAVAILABLE with reason encryption, never sending in the
// clear; and a control contract carrying Hello but no data RPC. Connect's own timers run in real time
// here, as net_connect.go says; the dispatcher's waits run on the Net's clock.

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A request type no release uses, in the experiments' range (§6.11).
const testSubprotocolCallType = protocol.MessageType(0x8031)

// Two admitted sidecars of the Net's default network, b answering testSubprotocolCallType with its
// request's body, each run counted.
func newTestSubprotocolPair(t *testing.T) (*Net, *SubprotocolSidecar, *SubprotocolSidecar, *FakeAuthority, chan []byte) {
	t.Helper()
	net := newTestNet(t)
	sidecars, authority, err := net.AddSubprotocolSidecars("laptop", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	a, b := sidecars[0], sidecars[1]
	runs := make(chan []byte, 16)
	if _, err := b.Subprotocol().Handle(testSubprotocolCallType, func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
		select {
		case runs <- bytes.Clone(request.Body):
		default:
		}
		return bytes.Clone(request.Body), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	return net, a, b, authority, runs
}

// Required RPC between two sidecars runs once the identity check, the binding against the session key
// and the admission, has passed both ways; and everything between them on the exchange is ciphertext:
// the body's canary is nowhere in the capture.
func TestSubprotocolRequiredRpcAfterTheIdentityCheck(t *testing.T) {
	net, a, b, authority, runs := newTestSubprotocolPair(t)
	canary := net.Capture().Canary("subprotocol call body")
	answer, err := a.Subprotocol().Call(t.Context(), sidecar.Id(b.ClientId()), testSubprotocolCallType, canary, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(answer, canary) {
		t.Errorf("answered %x", answer)
	}
	if run := <-runs; !bytes.Equal(run, canary) {
		t.Errorf("the handler read %x", run)
	}
	for _, c := range []struct {
		from *SubprotocolSidecar
		to   *SubprotocolSidecar
	}{{from: a, to: b}, {from: b, to: a}} {
		peer, ok := c.from.Subprotocol().PeerIdentity(sidecar.Id(c.to.ClientId()))
		identity := c.to.Sidecar().Identity()
		if !ok || peer.SidecarId != identity.SidecarId || !bytes.Equal(peer.IdentityPublicKey, identity.IdentityPublicKey) ||
			peer.Admission == nil || peer.AdmissionVersion != authority.Pin().GetVersion() {
			t.Errorf("%s holds %+v", c.from.Name, peer)
		}
	}
	if net.Capture().ItemCount(PrivacyClassFrame) == 0 {
		t.Fatalf("the capture saw no frame")
	}
	for _, finding := range net.Capture().Scan() {
		t.Errorf("finding: %+v", finding)
	}
}

// Nothing reaches a handler from a sidecar the network's state does not admit: its Hello is refused, and
// its call fails UNAUTHENTICATED.
func TestSubprotocolNothingBeforeAVerifiedHello(t *testing.T) {
	net, _, b, _, runs := newTestSubprotocolPair(t)
	strangers, _, err := net.AddSubprotocolSidecars("stranger")
	if err != nil {
		t.Fatal(err)
	}
	stranger := strangers[0]
	// the stranger's own state admits it and b, so it sends; b's does not admit the stranger
	strangerView := NewFakeAuthority()
	for _, member := range []*SubprotocolSidecar{stranger, b} {
		identity := member.Sidecar().Identity()
		strangerView.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: identity.SidecarId, MemberId: sidecar.NewId(), IdentityPublicKey: identity.IdentityPublicKey})
	}
	stranger.Sidecar().InstallAuthority(strangerView)
	_, err = stranger.Subprotocol().Call(t.Context(), sidecar.Id(b.ClientId()), testSubprotocolCallType, []byte("ask"), nil)
	if code, _ := sidecar.SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("an unadmitted peer's call: %v", err)
	}
	select {
	case <-runs:
		t.Errorf("a handler ran before a verified Hello")
	default:
	}
}

// A session that cannot form, the peer unreachable for its handshake, fails the call UNAVAILABLE with
// reason encryption: Required holds the frame, and nothing goes in the clear.
func TestSubprotocolNoSessionIsUnavailableEncryption(t *testing.T) {
	net, a, b, _, runs := newTestSubprotocolPair(t)
	canary := net.Capture().Canary("subprotocol call body without a session")
	net.SetLink(a.ClientId(), b.ClientId(), &LinkConditions{Partition: true})
	_, err := a.Subprotocol().Call(t.Context(), sidecar.Id(b.ClientId()), testSubprotocolCallType, canary, &sidecar.CallOptions{Timeout: time.Second})
	subprotocolError := &sidecar.SubprotocolError{}
	if !errors.As(err, &subprotocolError) || subprotocolError.Code != protocol.ErrorCode_ERR_UNAVAILABLE || subprotocolError.Reason != sidecar.SubprotocolReasonEncryption {
		t.Errorf("a call with no session: %v", err)
	}
	select {
	case <-runs:
		t.Errorf("a handler ran with no session")
	default:
	}
	for _, finding := range net.Capture().Scan() {
		t.Errorf("finding: %+v", finding)
	}
}

// A control contract carries Hello, and refuses a data RPC PERMISSION_DENIED at the receiver, whose
// handler never runs; the same pair on data carries it.
func TestSubprotocolControlContractCarriesNoData(t *testing.T) {
	net, a, b, _, runs := newTestSubprotocolPair(t)
	net.SetContractClass(a.ClientId(), b.ClientId(), connectprotocol.ContractClass_ContractClassControl)
	if err := a.Subprotocol().EnsureHello(t.Context(), sidecar.Id(b.ClientId())); err != nil {
		t.Fatalf("Hello on control: %v", err)
	}
	_, err := a.Subprotocol().Call(t.Context(), sidecar.Id(b.ClientId()), testSubprotocolCallType, []byte("ask"), nil)
	if code, _ := sidecar.SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("a data RPC on control: %v", err)
	}
	select {
	case <-runs:
		t.Errorf("the handler ran for a data RPC on control")
	default:
	}
}
