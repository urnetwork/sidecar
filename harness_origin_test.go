//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A session's expectation and the matching statement's arguments, for sidecarId.
func testHarnessAttachExpect(sidecarId Id) (*HarnessAttachExpect, *HarnessAttachOriginArgs) {
	expect := &HarnessAttachExpect{
		NetworkId:    NewId(),
		SidecarId:    sidecarId,
		EnclaveId:    NewId(),
		Incarnation:  7,
		ExchangeHash: bytes.Repeat([]byte{0x5a}, 32),
	}
	args := &HarnessAttachOriginArgs{
		NetworkId:    expect.NetworkId,
		SidecarId:    expect.SidecarId,
		EnclaveId:    expect.EnclaveId,
		Incarnation:  expect.Incarnation,
		ExchangeHash: bytes.Clone(expect.ExchangeHash),
	}
	return expect, args
}

// statement signed by a bare key as the attach origin, as SSH's client signs one under the sidecar's identity key.
func testHarnessSignAttachOrigin(t *testing.T, statement *protocol.HarnessAttachOrigin, privateKey ed25519.PrivateKey, purpose string, signedType bridge.SignedType) *bridge.Signed {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return &bridge.Signed{Body: body, Signature: ed25519.Sign(privateKey, bridge.SignedBytes(purpose, signedType, body)), Type: uint32(signedType)}
}

// The statement signs through the sidecar's identity key as attach-origin, SIGNED_ATTACH_ORIGIN (0x1808), and verifies
// back to the same header in both modes, a run's origin with its taint bit carried whole; its descriptor holds the
// numbers harness.proto writes.
func TestHarnessAttachOriginRoundTrip(t *testing.T) {
	sidecar, _, keys := newIdentityTestSidecar(t)
	sidecarId := sidecar.Identity().SidecarId
	expect, args := testHarnessAttachExpect(sidecarId)
	runId, agentId := NewId(), NewId()
	args.Mode, args.Origin = HarnessAttachModeCarried, HarnessRunOrigin(runId, agentId, true)
	statement, err := NewHarnessAttachOrigin(args)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sidecar.SignHarnessAttachOrigin(statement)
	if err != nil {
		t.Fatal(err)
	}
	if signed.GetType() != 0x1808 || !bytes.Equal(signed.GetSignerId(), sidecarId.Bytes()) {
		t.Fatalf("signed as %#x by %x", signed.GetType(), signed.GetSignerId())
	}
	header, err := VerifyHarnessAttachOrigin(signed, keys.identityPublicKey(), expect)
	if err != nil {
		t.Fatal(err)
	}
	if header.SidecarId != sidecarId || header.Mode != HarnessAttachModeCarried || header.Origin == nil ||
		header.Origin.Kind != HarnessOriginRun || *header.Origin.RunId != runId || *header.Origin.AgentId != agentId ||
		!header.Origin.Tainted || header.Origin.Trusted() {
		t.Fatalf("header %+v origin %+v", header, header.Origin)
	}
	if purpose, ok := sidecarIdentitySignedPurpose(bridge.SignedType_SIGNED_ATTACH_ORIGIN); !ok || purpose != HarnessAttachOriginPurpose {
		t.Fatalf("the identity key signs attach origins as %q, %t", purpose, ok)
	}

	args.Mode, args.Origin = HarnessAttachModeStamped, nil
	stamped, err := NewHarnessAttachOrigin(args)
	if err != nil {
		t.Fatal(err)
	}
	signed, err = sidecar.SignHarnessAttachOrigin(stamped)
	if err != nil {
		t.Fatal(err)
	}
	header, err = VerifyHarnessAttachOrigin(signed, keys.identityPublicKey(), expect)
	if err != nil || header.Mode != HarnessAttachModeStamped || header.Origin != nil {
		t.Fatalf("stamped: %+v, %v", header, err)
	}
	again, _ := sidecar.SignHarnessAttachOrigin(stamped)
	if !bytes.Equal(again.GetBody(), signed.GetBody()) {
		t.Fatal("the body is not deterministic")
	}

	fields := []struct {
		message protoreflect.MessageDescriptor
		number  protoreflect.FieldNumber
		name    protoreflect.Name
		kind    protoreflect.Kind
	}{
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 1, name: "network_id", kind: protoreflect.BytesKind},
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 2, name: "sidecar_id", kind: protoreflect.BytesKind},
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 3, name: "enclave_id", kind: protoreflect.BytesKind},
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 4, name: "incarnation", kind: protoreflect.Uint64Kind},
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 5, name: "exchange_hash", kind: protoreflect.BytesKind},
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 6, name: "mode", kind: protoreflect.EnumKind},
		{message: (&protocol.HarnessAttachOrigin{}).ProtoReflect().Descriptor(), number: 7, name: "origin", kind: protoreflect.MessageKind},
		{message: (&protocol.HarnessOrigin{}).ProtoReflect().Descriptor(), number: 1, name: "kind", kind: protoreflect.EnumKind},
		{message: (&protocol.HarnessOrigin{}).ProtoReflect().Descriptor(), number: 2, name: "run_id", kind: protoreflect.BytesKind},
		{message: (&protocol.HarnessOrigin{}).ProtoReflect().Descriptor(), number: 3, name: "agent_id", kind: protoreflect.BytesKind},
		{message: (&protocol.HarnessOrigin{}).ProtoReflect().Descriptor(), number: 4, name: "tainted", kind: protoreflect.BoolKind},
	}
	for _, c := range fields {
		field := c.message.Fields().ByNumber(c.number)
		if field == nil || field.Name() != c.name || field.Kind() != c.kind {
			t.Errorf("%s field %d: %v", c.message.Name(), c.number, field)
		}
	}
	for _, c := range []struct {
		name   string
		number int32
	}{
		{name: "HARNESS_ATTACH_MODE_CARRIED", number: 1}, {name: "HARNESS_ATTACH_MODE_STAMPED", number: 2},
	} {
		if protocol.HarnessAttachMode_value[c.name] != c.number {
			t.Errorf("%s is %d", c.name, protocol.HarnessAttachMode_value[c.name])
		}
	}
	for _, c := range []struct {
		name   string
		number int32
	}{
		{name: "HARNESS_ORIGIN_KIND_PERSON", number: 1}, {name: "HARNESS_ORIGIN_KIND_RUN", number: 2},
		{name: "HARNESS_ORIGIN_KIND_UNKNOWN", number: 3},
	} {
		if protocol.HarnessOriginKind_value[c.name] != c.number {
			t.Errorf("%s is %d", c.name, protocol.HarnessOriginKind_value[c.name])
		}
	}
	if bridge.SignedType_SIGNED_ATTACH_ORIGIN != 0x1808 {
		t.Fatalf("SIGNED_ATTACH_ORIGIN is %#x", int32(bridge.SignedType_SIGNED_ATTACH_ORIGIN))
	}
}

// An origin signed over another session's exchange hash is refused, as is one naming another network, sidecar, enclave
// or incarnation, one signed by another key, under another purpose or type, and one whose mode and origin do not agree.
func TestHarnessAttachOriginOverOtherExchangeHashRefused(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sidecarId := NewId()
	expect, args := testHarnessAttachExpect(sidecarId)
	args.Mode, args.Origin = HarnessAttachModeCarried, HarnessPersonOrigin()
	statement, err := NewHarnessAttachOrigin(args)
	if err != nil {
		t.Fatal(err)
	}
	signed := testHarnessSignAttachOrigin(t, statement, privateKey, HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_ATTACH_ORIGIN)
	if header, err := VerifyHarnessAttachOrigin(signed, publicKey, expect); err != nil || header.Origin.Kind != HarnessOriginPerson {
		t.Fatalf("the session's own origin: %+v, %v", header, err)
	}
	other := func(change func(expect *HarnessAttachExpect)) *HarnessAttachExpect {
		copied := *expect
		copied.ExchangeHash = bytes.Clone(expect.ExchangeHash)
		change(&copied)
		return &copied
	}
	otherPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	badMode := proto.Clone(statement).(*protocol.HarnessAttachOrigin)
	badMode.Mode = protocol.HarnessAttachMode_HARNESS_ATTACH_MODE_STAMPED
	noOrigin := proto.Clone(statement).(*protocol.HarnessAttachOrigin)
	noOrigin.Origin = nil
	badRun := proto.Clone(statement).(*protocol.HarnessAttachOrigin)
	badRun.Origin = &protocol.HarnessOrigin{Kind: protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_RUN}
	cases := []struct {
		name      string
		signed    *bridge.Signed
		publicKey ed25519.PublicKey
		expect    *HarnessAttachExpect
	}{
		{name: "another session's exchange hash", signed: signed, publicKey: publicKey, expect: other(func(e *HarnessAttachExpect) { e.ExchangeHash[0] ^= 0xff })},
		{name: "another network", signed: signed, publicKey: publicKey, expect: other(func(e *HarnessAttachExpect) { e.NetworkId = NewId() })},
		{name: "another sidecar", signed: signed, publicKey: publicKey, expect: other(func(e *HarnessAttachExpect) { e.SidecarId = NewId() })},
		{name: "another enclave", signed: signed, publicKey: publicKey, expect: other(func(e *HarnessAttachExpect) { e.EnclaveId = NewId() })},
		{name: "another incarnation", signed: signed, publicKey: publicKey, expect: other(func(e *HarnessAttachExpect) { e.Incarnation += 1 })},
		{name: "another key", signed: signed, publicKey: otherPublicKey, expect: expect},
		{name: "another purpose", signed: testHarnessSignAttachOrigin(t, statement, privateKey, "approval", bridge.SignedType_SIGNED_ATTACH_ORIGIN), publicKey: publicKey, expect: expect},
		{name: "another type", signed: testHarnessSignAttachOrigin(t, statement, privateKey, HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION), publicKey: publicKey, expect: expect},
		{name: "stamped with an origin", signed: testHarnessSignAttachOrigin(t, badMode, privateKey, HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_ATTACH_ORIGIN), publicKey: publicKey, expect: expect},
		{name: "carried with none", signed: testHarnessSignAttachOrigin(t, noOrigin, privateKey, HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_ATTACH_ORIGIN), publicKey: publicKey, expect: expect},
		{name: "a run naming no run", signed: testHarnessSignAttachOrigin(t, badRun, privateKey, HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_ATTACH_ORIGIN), publicKey: publicKey, expect: expect},
		{name: "no session", signed: signed, publicKey: publicKey, expect: other(func(e *HarnessAttachExpect) { e.ExchangeHash = nil })},
	}
	for _, c := range cases {
		if header, err := VerifyHarnessAttachOrigin(c.signed, c.publicKey, c.expect); !errors.Is(err, ErrHarnessAttachOriginRefused) {
			t.Errorf("%s: %+v, %v", c.name, header, err)
		}
	}
	// a signer_id naming another sidecar is refused too
	renamed := proto.Clone(signed).(*bridge.Signed)
	renamed.SignerId = NewId().Bytes()
	if _, err := VerifyHarnessAttachOrigin(renamed, publicKey, expect); !errors.Is(err, ErrHarnessAttachOriginRefused) {
		t.Errorf("another signer_id: %v", err)
	}
}

// What no statement may say is refused before anything is signed: no exchange hash, a carried mode without an origin or
// with a run naming no run, a stamped mode with an origin, a person naming a run, a mode this build does not know.
func TestHarnessAttachOriginRefusesWhatCannotBeStated(t *testing.T) {
	_, base := testHarnessAttachExpect(NewId())
	runId := NewId()
	cases := []struct {
		name   string
		change func(args *HarnessAttachOriginArgs)
	}{
		{name: "no exchange hash", change: func(args *HarnessAttachOriginArgs) {
			args.Mode, args.Origin, args.ExchangeHash = HarnessAttachModeCarried, HarnessPersonOrigin(), nil
		}},
		{name: "carried without an origin", change: func(args *HarnessAttachOriginArgs) { args.Mode = HarnessAttachModeCarried }},
		{name: "a run naming no agent", change: func(args *HarnessAttachOriginArgs) {
			args.Mode, args.Origin = HarnessAttachModeCarried, &HarnessOrigin{Kind: HarnessOriginRun, RunId: &runId}
		}},
		{name: "a person naming a run", change: func(args *HarnessAttachOriginArgs) {
			args.Mode, args.Origin = HarnessAttachModeCarried, &HarnessOrigin{Kind: HarnessOriginPerson, RunId: &runId}
		}},
		{name: "stamped with an origin", change: func(args *HarnessAttachOriginArgs) {
			args.Mode, args.Origin = HarnessAttachModeStamped, HarnessPersonOrigin()
		}},
		{name: "no mode", change: func(args *HarnessAttachOriginArgs) { args.Origin = HarnessPersonOrigin() }},
	}
	for _, c := range cases {
		args := *base
		args.ExchangeHash = bytes.Clone(base.ExchangeHash)
		c.change(&args)
		if _, err := NewHarnessAttachOrigin(&args); !errors.Is(err, ErrHarnessAttachOriginInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if header := HarnessAttachUnknownHeader(NewId()); header.Mode != HarnessAttachModeCarried || header.Origin.Kind != HarnessOriginUnknown || header.Origin.Trusted() {
		t.Fatalf("a session without an origin: %+v", header)
	}
}
