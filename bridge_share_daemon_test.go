//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A daemon backend that offers the share acts, answering what a test set.
type testDaemonBridgeShareBackend struct {
	*testDaemonBridgeBackend
	invites  []*BridgeShareInviteRequest
	codes    [][]byte
	accepted *BridgeShareAccepted
	err      error
	// what PreviewShare answers, and the shares and previews the activation's acts were asked
	preview     *BridgeSharePreview
	previewed   []Id
	activations []*BridgeSharePreview
}

func (self *testDaemonBridgeShareBackend) PreviewShare(ctx context.Context, origin *BridgeFileOrigin, shareId Id) (*BridgeSharePreview, error) {
	self.previewed = append(self.previewed, shareId)
	return self.preview, nil
}

func (self *testDaemonBridgeShareBackend) ActivateShare(ctx context.Context, origin *BridgeFileOrigin, preview *BridgeSharePreview, lifetime time.Duration) (*BridgeFiling, error) {
	self.activations = append(self.activations, preview)
	return &BridgeFiling{GrantId: []byte{7, 7, 7, 7}}, nil
}

// A daemon backend whose share acts are a real filer's.
type testDaemonBridgeFilerShares struct {
	*testDaemonBridgeBackend
	filer *BridgeFiler
}

func (self *testDaemonBridgeFilerShares) Invite(ctx context.Context, origin *BridgeFileOrigin, request *BridgeShareInviteRequest) (*BridgeShareInvite, error) {
	return self.filer.Invite(ctx, origin, request)
}

func (self *testDaemonBridgeFilerShares) AcceptInvite(ctx context.Context, origin *BridgeFileOrigin, code []byte) (*BridgeShareAccepted, error) {
	return self.filer.AcceptInvite(ctx, origin, code)
}

func (self *testDaemonBridgeFilerShares) PreviewShare(ctx context.Context, origin *BridgeFileOrigin, shareId Id) (*BridgeSharePreview, error) {
	return self.filer.PreviewShare(ctx, origin, shareId)
}

func (self *testDaemonBridgeFilerShares) ActivateShare(ctx context.Context, origin *BridgeFileOrigin, preview *BridgeSharePreview, lifetime time.Duration) (*BridgeFiling, error) {
	return self.filer.ActivateShare(ctx, origin, preview, lifetime)
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

	// an accept: the code as typed, the aliases and the ShareKey's fingerprint answered
	shareId, sharing := testConfigId("daemon share"), testConfigId("daemon sharing network")
	sharePublicKey := bytes.Repeat([]byte{0x5c}, 32)
	backend.accepted = &BridgeShareAccepted{ShareId: shareId, SharingNetworkId: sharing, Status: BridgeShareAcceptStatusActive,
		Aliases: []*bridge.BridgeShareAlias{{Index: 0, AliasHostBits: 0x8001, Length: 32}}, SharePublicKey: sharePublicKey}
	accepted, err := bridges.AcceptInvite(ctx, networkId, nil, confirmed, &DaemonBridgeAcceptInviteParams{Code: " " + reply.Code + "\n"})
	if err != nil || accepted.Status != "active" || *accepted.ShareId != shareId || len(accepted.Aliases) != 1 || accepted.Aliases[0].HostBits != 0x8001 ||
		accepted.ShareKeyFingerprint != FormatBridgeShareKeyFingerprint(sharePublicKey) {
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

// bridge.activate is in the daemon's Confirm table beside invite and accept_invite: from mcp or hook, and from control
// with no confirmation, the daemon refuses it before its handler, with or without a preview's digest, and the method
// refuses every origin but a person's confirmation again. Neither act reaches the filer.
func TestDaemonBridgeActivateIsAPersonsConfirmedCallAlone(t *testing.T) {
	bridges, backend := newTestDaemonBridgeShares(t)
	daemon := newDispatchTestDaemon(t)
	for _, method := range bridges.ShareMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	method, ok := daemon.method(DaemonMethodBridgeActivate)
	if !ok || !method.Confirm || !method.Network {
		t.Fatalf("bridge.activate in the daemon's table: %v, %+v", ok, method)
	}
	shareId := testConfigId("daemon activated share")
	digest := hex.EncodeToString(bytes.Repeat([]byte{0x3c}, sha256.Size))
	for _, params := range []string{
		fmt.Sprintf(`{"share_id":%q}`, shareId),
		fmt.Sprintf(`{"share_id":%q,"preview_digest":%q}`, shareId, digest),
	} {
		for _, attempt := range []struct {
			mode      string
			confirmed bool
		}{{mode: DaemonModeMcp, confirmed: true}, {mode: DaemonModeMcp, confirmed: false}, {mode: DaemonModeHook, confirmed: true}, {mode: DaemonModeControl, confirmed: false}} {
			line := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"ur_confirmed":%t,"params":%s}`, DaemonMethodBridgeActivate, attempt.confirmed, params)
			if response := dispatchTest(daemon, attempt.mode, line); response.Error == nil || response.Error.Code != DaemonRpcConfirmationRequired {
				t.Fatalf("%s from %s, confirmed %t: %+v", params, attempt.mode, attempt.confirmed, response.Error)
			}
		}
	}
	ctx := context.Background()
	networkId := NewId()
	for _, origin := range []*BridgeFileOrigin{nil, {Act: SidecarActMcp}, {Act: SidecarActHook}, {Act: SidecarActUnconfirmed}} {
		if _, err := bridges.PreviewShare(ctx, networkId, nil, origin, &DaemonBridgeActivateParams{ShareId: shareId}); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("a preview from %+v: %v", origin, err)
		}
		if _, err := bridges.ActivateShare(ctx, networkId, nil, origin, &DaemonBridgeActivateParams{ShareId: shareId, PreviewDigest: digest}); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("an activation from %+v: %v", origin, err)
		}
	}
	if len(backend.previewed) != 0 || len(backend.activations) != 0 {
		t.Fatal("an agent's or an unconfirmed call reached the filer")
	}
	// a confirmed call naming no share, or sending back no digest a preview answers, is refused before the filer
	confirmed := &BridgeFileOrigin{Act: SidecarActConfirmed}
	if _, err := bridges.PreviewShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{}); !errors.Is(err, ErrDaemonBridgeParams) {
		t.Errorf("a preview of no share: %v", err)
	}
	for _, malformed := range []string{"", "not hex", hex.EncodeToString([]byte{1, 2, 3})} {
		if _, err := bridges.ActivateShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: shareId, PreviewDigest: malformed}); !errors.Is(err, ErrDaemonBridgeParams) {
			t.Errorf("an activation sending back %q: %v", malformed, err)
		}
	}
	if len(backend.previewed) != 0 || len(backend.activations) != 0 {
		t.Fatal("a call out of form reached the filer")
	}
	// a preview of another share than the one asked for is not shown
	backend.preview = &BridgeSharePreview{ShareId: testConfigId("another share")}
	if _, err := bridges.PreviewShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: shareId}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("another share's preview: %v", err)
	}
}

// A ShareKey's fingerprint is its public key's SHA-256 in lowercase hex, sixteen groups of four digits.
func TestBridgeShareKeyFingerprintIsItsKeysSha256InGroups(t *testing.T) {
	sharePublicKey := bytes.Repeat([]byte{0x5c}, 32)
	sum := sha256.Sum256(sharePublicKey)
	fingerprint := FormatBridgeShareKeyFingerprint(sharePublicKey)
	groups := strings.Split(fingerprint, " ")
	if len(groups) != 16 || strings.Join(groups, "") != hex.EncodeToString(sum[:]) {
		t.Fatalf("the fingerprint: %q", fingerprint)
	}
	for _, group := range groups {
		if len(group) != 4 {
			t.Fatalf("a group of %d digits: %q", len(group), fingerprint)
		}
	}
	if FormatBridgeShareKeyFingerprint(bytes.Repeat([]byte{0x5d}, 32)) == fingerprint {
		t.Fatal("two keys share a fingerprint")
	}
}

// §17.9's activation through the daemon, over a real filer (QD-831): bridge.activate with no digest shows the share
// as its row holds it (the other network, each target with its alias, the ShareKey's fingerprint, both tables'
// hashes and versions) and files nothing; with the digest it activates exactly that. A share that changed between
// the preview and the confirmation is refused and files nothing; the share as it is then shows a digest of its own,
// whose confirmation files the grant and writes the pins of the row as it now stands. The same confirmation again
// files nothing twice.
func TestDaemonBridgeActivateShowsTheShareThenActivatesWhatWasShown(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	world.withSharesRule()
	ctx := context.Background()
	// "peer" resolves to the world's host
	backend := &testDaemonBridgeFilerShares{testDaemonBridgeBackend: &testDaemonBridgeBackend{sidecarId: world.hostId, target: world.hostId}, filer: world.filer}
	bridges, err := NewDaemonBridges(ctx, &DaemonBridgesArgs{
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
	confirmed := world.confirmed()
	networkId := world.net.networkId

	invite, err := bridges.Invite(ctx, networkId, nil, confirmed, &DaemonBridgeInviteParams{Targets: []*DaemonBridgeShareTargetParams{
		{Host: "peer", Prefix: "192.168.7.0/24"},
		{Host: "peer", Prefix: "192.168.9.9/32", Protocol: "tcp", FirstPort: 8000, LastPort: 8080},
	}})
	if err != nil {
		t.Fatal(err)
	}
	code, err := ParseBridgeShareCode(invite.Code)
	if err != nil {
		t.Fatal(err)
	}
	params := &DaemonBridgeActivateParams{ShareId: invite.ShareId}

	// while the invite is open the preview shows the targets alone, and its confirmation activates nothing
	open, err := bridges.PreviewShare(ctx, networkId, nil, confirmed, params)
	if err != nil || open.Status != "" || open.AcceptingNetworkId != nil || len(open.Targets) != 2 || open.Targets[0].Alias != nil ||
		open.AliasTableSha256 != "" || open.ShareKeyFingerprint != "" {
		t.Fatalf("an open invite's preview: %+v, %v", open, err)
	}
	if _, err := bridges.ActivateShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: invite.ShareId, PreviewDigest: open.PreviewDigest}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Fatalf("an activation of an open invite: %v", err)
	}

	sharePublicKey := world.completed(&BridgeShareInvite{ShareId: invite.ShareId, Code: code}, 0x8100, 0x8001)
	shown, err := bridges.PreviewShare(ctx, networkId, nil, confirmed, params)
	if err != nil {
		t.Fatal(err)
	}
	row := world.server.row(invite.ShareId)
	if shown.ShareId != invite.ShareId || shown.AcceptingNetworkId == nil || *shown.AcceptingNetworkId != world.other || shown.Status != "active" ||
		shown.ShareKeyFingerprint != FormatBridgeShareKeyFingerprint(sharePublicKey) ||
		shown.TargetTableSha256 != hex.EncodeToString(BridgeShareTableSha256(row.TargetTable)) || shown.TargetTableVersion != row.TargetTableVersion ||
		shown.AliasTableSha256 != hex.EncodeToString(BridgeShareTableSha256(row.AliasTable)) || shown.AliasTableVersion != row.AliasTableVersion {
		t.Fatalf("the preview against the share's row: %+v", shown)
	}
	wantTargets := []DaemonBridgeShareTarget{
		{Index: 0, HostSidecarId: world.hostId, Prefix: "192.168.7.0/24", Alias: &DaemonBridgeShareAlias{Index: 0, HostBits: 0x8100, Length: 24}},
		{Index: 1, HostSidecarId: world.hostId, Prefix: "192.168.9.9/32", Protocol: "tcp", Ports: []string{"8000-8080"}, Alias: &DaemonBridgeShareAlias{Index: 1, HostBits: 0x8001, Length: 32}},
	}
	if len(shown.Targets) != len(wantTargets) {
		t.Fatalf("%d targets shown", len(shown.Targets))
	}
	for i, want := range wantTargets {
		got := shown.Targets[i]
		if got.Index != want.Index || got.HostSidecarId != want.HostSidecarId || got.Prefix != want.Prefix || got.Protocol != want.Protocol ||
			fmt.Sprint(got.Ports) != fmt.Sprint(want.Ports) || got.Alias == nil || *got.Alias != *want.Alias {
			t.Fatalf("target %d shown as %+v (alias %+v)", i, got, got.Alias)
		}
	}
	if head, _ := world.heads.savedHead(); head != nil || world.api.postCount() != 0 {
		t.Fatal("a preview filed or wrote a head")
	}

	// the accepting side changes between the preview and the confirmation: what was confirmed is not activated
	world.completed(&BridgeShareInvite{ShareId: invite.ShareId, Code: code}, 0x8200, 0x8001)
	if _, err := bridges.ActivateShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: invite.ShareId, PreviewDigest: shown.PreviewDigest}); !errors.Is(err, ErrBridgeFileRefused) || !errors.Is(err, ErrBridgeShareTableMismatch) {
		t.Fatalf("an activation of a share that changed after it was shown: %v", err)
	}
	if head, _ := world.heads.savedHead(); head != nil || world.api.postCount() != 0 || len(world.gate.seen()) != 0 {
		t.Fatal("a refused activation reached the gate, filed or wrote a head")
	}

	// the share as it is now: its own digest, and while the decision is awaited, the approval to wait on
	now, err := bridges.PreviewShare(ctx, networkId, nil, confirmed, params)
	if err != nil || now.PreviewDigest == shown.PreviewDigest || now.Targets[0].Alias.HostBits != 0x8200 {
		t.Fatalf("the preview after the change: %+v, %v", now, err)
	}
	world.gate.approves = false
	waiting, err := bridges.ActivateShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: invite.ShareId, PreviewDigest: now.PreviewDigest})
	if err != nil || waiting.ApprovalPendingId == nil || waiting.GrantId != "" {
		t.Fatalf("an activation awaiting its decision: %+v, %v", waiting, err)
	}
	if head, _ := world.heads.savedHead(); head != nil || world.api.postCount() != 0 {
		t.Fatal("an activation awaiting its decision filed or wrote a head")
	}
	world.gate.approves = true
	activated, err := bridges.ActivateShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: invite.ShareId, PreviewDigest: now.PreviewDigest})
	if err != nil || activated.ApprovalPendingId != nil || activated.GrantId == "" || activated.ApprovalId == nil {
		t.Fatalf("the activation: %+v, %v", activated, err)
	}
	if got := world.api.postedTypes(t); len(got) != 1 || got[0] != bridge.SignedType_SIGNED_GRANT_ACTIVATE {
		t.Fatalf("the activation posted %v", got)
	}
	head, saves := world.heads.savedHead()
	pins := ReadBridgeShareGrants(head)
	row = world.server.row(invite.ShareId)
	if len(pins) != 1 || hex.EncodeToString(pins[0].GetGrantId()) != activated.GrantId || !bytes.Equal(pins[0].GetSharePublicKey(), sharePublicKey) ||
		!bytes.Equal(pins[0].GetAcceptingNetworkId(), world.other.Bytes()) ||
		!bytes.Equal(pins[0].GetAliasTableSha256(), BridgeShareTableSha256(row.AliasTable)) ||
		!bytes.Equal(pins[0].GetTargetTableSha256(), BridgeShareTableSha256(row.TargetTable)) {
		t.Fatalf("the pins: %+v", pins)
	}
	// the same confirmation again, as ur asks once a decision lands, finds the grant and the file and does neither twice
	world.install()
	again, err := bridges.ActivateShare(ctx, networkId, nil, confirmed, &DaemonBridgeActivateParams{ShareId: invite.ShareId, PreviewDigest: now.PreviewDigest})
	if _, after := world.heads.savedHead(); err != nil || again.GrantId != activated.GrantId || after != saves || world.api.postCount() != 1 {
		t.Fatalf("the same confirmation again: %+v, %v", again, err)
	}
}
