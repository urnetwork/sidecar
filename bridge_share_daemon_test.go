//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A daemon backend that offers the share acts, answering what a test set.
type testDaemonBridgeShareBackend struct {
	*testDaemonBridgeBackend
	invites  []*BridgeShareInviteRequest
	codes    [][]byte
	accepted *BridgeShareAccepted
	err      error
}

func (self *testDaemonBridgeShareBackend) Invite(ctx context.Context, origin *BridgeFileOrigin, request *BridgeShareInviteRequest) (*BridgeShareInvite, error) {
	self.invites = append(self.invites, request)
	if self.err != nil {
		return nil, self.err
	}
	return &BridgeShareInvite{ShareId: testConfigId("daemon share"), Code: bytes.Repeat([]byte{0xa5}, bridgeShareCodeByteCount), UseCount: 1}, nil
}

func (self *testDaemonBridgeShareBackend) AcceptInvite(ctx context.Context, origin *BridgeFileOrigin, code []byte) (*BridgeShareAccepted, error) {
	self.codes = append(self.codes, bytes.Clone(code))
	if self.err != nil {
		return nil, self.err
	}
	return self.accepted, nil
}

func newTestDaemonBridgeShares(t *testing.T) (*DaemonBridges, *testDaemonBridgeShareBackend) {
	t.Helper()
	backend := &testDaemonBridgeShareBackend{testDaemonBridgeBackend: &testDaemonBridgeBackend{sidecarId: NewId(), target: NewId()}}
	bridges, err := NewDaemonBridges(context.Background(), &DaemonBridgesArgs{
		Backend: func(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error) {
			return backend, nil
		},
		Listen: newDispatchTestDaemon(t).LocalListen,
		Clock:  newTestEnvelopeClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridges.Close)
	return bridges, backend
}

// bridge.invite and bridge.accept_invite run only for a person's confirmed control call, hand the filer the targets
// and the code as typed, and answer the code once, a share's aliases, or a refusal's figures as an answer.
func TestDaemonBridgeShareMethodsTakeAConfirmedCall(t *testing.T) {
	bridges, backend := newTestDaemonBridgeShares(t)
	ctx := context.Background()
	networkId := NewId()
	confirmed := &BridgeFileOrigin{Act: SidecarActConfirmed}
	for _, method := range bridges.ShareMethods() {
		if !method.Confirm || !method.Network {
			t.Errorf("%s runs without a confirmation or a network", method.Name)
		}
	}
	params := &DaemonBridgeInviteParams{Targets: []*DaemonBridgeShareTargetParams{
		{Host: "peer", Prefix: "192.168.7.9/24"},
		{Host: "peer", Prefix: "100.80.3.7/32", Protocol: "tcp", FirstPort: 443},
		{Host: "peer", Prefix: "10.0.0.0/20", Protocol: "udp", FirstPort: 5000, LastPort: 5010},
	}}
	for _, origin := range []*BridgeFileOrigin{nil, {Act: SidecarActMcp}, {Act: SidecarActHook}, {Act: SidecarActUnconfirmed}} {
		if _, err := bridges.Invite(ctx, networkId, nil, origin, params); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("an invite from %+v: %v", origin, err)
		}
		if _, err := bridges.AcceptInvite(ctx, networkId, nil, origin, &DaemonBridgeAcceptInviteParams{Code: FormatBridgeShareCode(make([]byte, 32))}); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("an accept from %+v: %v", origin, err)
		}
	}
	if len(backend.invites) != 0 || len(backend.codes) != 0 {
		t.Fatal("an unconfirmed call reached the filer")
	}
	reply, err := bridges.Invite(ctx, networkId, nil, confirmed, params)
	if err != nil {
		t.Fatal(err)
	}
	code, err := ParseBridgeShareCode(reply.Code)
	if err != nil || !bytes.Equal(code, bytes.Repeat([]byte{0xa5}, 32)) || reply.ShareId != testConfigId("daemon share") {
		t.Fatalf("the invite's answer: %+v, %v", reply, err)
	}
	request := backend.invites[0]
	if len(request.Targets) != 3 || request.Targets[0].Prefix != netip.MustParsePrefix("192.168.7.0/24") || request.Targets[0].Protocol != 0 ||
		request.Targets[1].Protocol != bridgeProtocolTcp || request.Targets[1].Ports[0].GetFirst() != 443 || request.Targets[1].Ports[0].GetLast() != 443 ||
		request.Targets[2].Protocol != bridgeProtocolUdp || request.Targets[2].Ports[0].GetLast() != 5010 || request.Targets[2].Host != backend.target {
		t.Fatalf("the request: %+v", request.Targets)
	}
	for name, refused := range map[string]*DaemonBridgeInviteParams{
		"no target":              {},
		"an IPv6 prefix":         {Targets: []*DaemonBridgeShareTargetParams{{Host: "peer", Prefix: "fd00::/64"}}},
		"ports and no protocol":  {Targets: []*DaemonBridgeShareTargetParams{{Host: "peer", Prefix: "10.0.0.0/24", FirstPort: 80}}},
		"a protocol and no port": {Targets: []*DaemonBridgeShareTargetParams{{Host: "peer", Prefix: "10.0.0.0/24", Protocol: "tcp"}}},
		"another protocol":       {Targets: []*DaemonBridgeShareTargetParams{{Host: "peer", Prefix: "10.0.0.0/24", Protocol: "icmp", FirstPort: 1}}},
	} {
		if _, err := bridges.Invite(ctx, networkId, nil, confirmed, refused); !errors.Is(err, ErrDaemonBridgeParams) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(backend.invites) != 1 {
		t.Fatal("a refused invite reached the filer")
	}

	// an accept: the code as typed, the aliases answered
	shareId, sharing := testConfigId("daemon share"), testConfigId("daemon sharing network")
	backend.accepted = &BridgeShareAccepted{ShareId: shareId, SharingNetworkId: sharing, Status: BridgeShareAcceptStatusActive,
		Aliases: []*bridge.BridgeShareAlias{{Index: 0, AliasHostBits: 0x8001, Length: 32}}}
	accepted, err := bridges.AcceptInvite(ctx, networkId, nil, confirmed, &DaemonBridgeAcceptInviteParams{Code: " " + reply.Code + "\n"})
	if err != nil || accepted.Status != "active" || *accepted.ShareId != shareId || len(accepted.Aliases) != 1 || accepted.Aliases[0].HostBits != 0x8001 {
		t.Fatalf("the accept's answer: %+v, %v", accepted, err)
	}
	if !bytes.Equal(backend.codes[0], code) {
		t.Fatal("the filer was handed another code")
	}
	// a code out of form is refused before the filer, and the refusal does not quote it
	typed := "not-a-code-but-a-secret-all-the-same"
	if _, err := bridges.AcceptInvite(ctx, networkId, nil, confirmed, &DaemonBridgeAcceptInviteParams{Code: typed}); !errors.Is(err, ErrDaemonBridgeParams) || strings.Contains(err.Error(), typed) {
		t.Errorf("a code out of form: %v", err)
	}
	// a refusal for room is an answer with its figures
	backend.err = &BridgeShareRefusal{Reason: ErrBridgeShareNoSpace, Shortfall: &bridge.BridgeShareShortfall{Index: 2, Length: 20, FreeAddressCount: 900, LargestFreeLength: 23}}
	refusal, err := bridges.AcceptInvite(ctx, networkId, nil, confirmed, &DaemonBridgeAcceptInviteParams{Code: reply.Code})
	if err != nil || refusal.Status != "refused_no_space" || refusal.RefusedIndex != 2 || refusal.RefusedLength != 20 || refusal.FreeAddressCount != 900 || refusal.LargestFreeLength != 23 {
		t.Fatalf("a refusal's answer: %+v, %v", refusal, err)
	}
	backend.err = &BridgeShareRefusal{Reason: ErrBridgeShareTooLarge, Shortfall: &bridge.BridgeShareShortfall{Index: 1, Length: 16}}
	if refusal, err := bridges.AcceptInvite(ctx, networkId, nil, confirmed, &DaemonBridgeAcceptInviteParams{Code: reply.Code}); err != nil || refusal.Status != "refused_too_large" {
		t.Fatalf("a too-large refusal's answer: %+v, %v", refusal, err)
	}
	// any other error is the caller's
	backend.err = ErrBridgeFileRefused
	if _, err := bridges.AcceptInvite(ctx, networkId, nil, confirmed, &DaemonBridgeAcceptInviteParams{Code: reply.Code}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a refused accept: %v", err)
	}

	// a backend with no share acts is unwired
	plain, err := NewDaemonBridges(ctx, &DaemonBridgesArgs{
		Backend: func(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error) {
			return backend.testDaemonBridgeBackend, nil
		},
		Listen: newDispatchTestDaemon(t).LocalListen,
		Clock:  newTestEnvelopeClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plain.Close)
	if _, err := plain.Invite(ctx, networkId, nil, confirmed, params); !errors.Is(err, ErrDaemonBridgeUnwired) {
		t.Errorf("a backend with no share acts: %v", err)
	}
}
