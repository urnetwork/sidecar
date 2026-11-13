//go:build !ios_extension && !sidecar_http

// Sidecar.SignWindowDelegation's rules (bridge_sign.go; DESIGN-DETAILS 12.2.6): a delegation for this sidecar's own
// network and subject, a 32-byte window client key, a not_after ahead and within the longest a delegation lives, and
// a target the newest compiled state links to, which a host's VerifyWindowDelegation takes under the identity key;
// each refusal alone beside the request that passes, a share link and no compiled state among them.

package sidecar

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestSignWindowDelegationSignsWhatAHostVerifies(t *testing.T) {
	seed := sha256.Sum256([]byte("bridge sign identity"))
	identityKey := ed25519.NewKeyFromSeed(seed[:])
	identity := &SidecarIdentity{
		NetworkId: testConfigId("sign network"), SidecarId: testConfigId("sign sidecar"),
		IdentityPublicKey: identityKey.Public().(ed25519.PublicKey),
	}
	sign := func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body: body, SignerId: identity.SidecarId.Bytes(), Type: uint32(signedType),
			Signature: ed25519.Sign(identityKey, bridge.SignedBytes(purpose, signedType, body)),
		}, nil
	}
	target := testConfigId("sign target")
	compiled := &BridgeCompiled{State: &bridge.BridgeState{}, LinkTargets: []Id{target}}
	now := time.UnixMilli(testConfigStartMs)
	maxLifetime := DefaultBridgeComponentSettings().WindowDelegationMaxLifetime
	clientSeed := sha256.Sum256([]byte("bridge sign window client"))
	clientKey := ed25519.NewKeyFromSeed(clientSeed[:]).Public().(ed25519.PublicKey)
	request := func() *BridgeDelegationRequest {
		return &BridgeDelegationRequest{
			NetworkId: identity.NetworkId, SubjectSidecarId: identity.SidecarId, WindowClientId: testConfigId("sign window client"),
			WindowClientPublicKey: clientKey, TargetSidecarId: target, NotAfter: now.Add(24 * time.Hour),
		}
	}

	signed, err := bridgeSignWindowDelegation(request(), identity, compiled, maxLifetime, now, sign)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := bridge.VerifyWindowDelegation(signed, &bridge.WindowDelegationCheck{
		NetworkId: identity.NetworkId.Bytes(), WindowClientId: testConfigId("sign window client").Bytes(), WindowClientPublicKey: clientKey,
		TargetSidecarId: target.Bytes(), NowMs: now.UnixMilli(),
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			return identity.IdentityPublicKey, Id(sidecarId) == identity.SidecarId
		},
	})
	if err != nil || delegation.GetNotAfterMs() != now.Add(24*time.Hour).UnixMilli() {
		t.Fatalf("the host's verify: %v", err)
	}

	refusals := []struct {
		name     string
		edit     func(request *BridgeDelegationRequest)
		compiled *BridgeCompiled
	}{
		{name: "another network", edit: func(request *BridgeDelegationRequest) { request.NetworkId = testConfigId("another network") }},
		{name: "another subject", edit: func(request *BridgeDelegationRequest) { request.SubjectSidecarId = target }},
		{name: "a short key", edit: func(request *BridgeDelegationRequest) { request.WindowClientPublicKey = clientKey[:31] }},
		{name: "no window client", edit: func(request *BridgeDelegationRequest) { request.WindowClientId = Id{} }},
		{name: "a not_after now", edit: func(request *BridgeDelegationRequest) { request.NotAfter = now }},
		{name: "a not_after past the lifetime", edit: func(request *BridgeDelegationRequest) { request.NotAfter = now.Add(maxLifetime + time.Millisecond) }},
		{name: "a share link", edit: func(request *BridgeDelegationRequest) { request.ShareId = testConfigId("share") }},
		{name: "a target linked nowhere", edit: func(request *BridgeDelegationRequest) { request.TargetSidecarId = testConfigId("unlinked") }},
		{name: "no compiled state", compiled: &BridgeCompiled{}},
	}
	for _, refusal := range refusals {
		refused := request()
		if refusal.edit != nil {
			refusal.edit(refused)
		}
		held := compiled
		if refusal.compiled != nil {
			held = refusal.compiled
		}
		if _, err := bridgeSignWindowDelegation(refused, identity, held, maxLifetime, now, sign); !errors.Is(err, ErrBridgeDelegationRefused) {
			t.Errorf("%s: %v", refusal.name, err)
		}
	}
	if _, err := bridgeSignWindowDelegation(request(), identity, compiled, maxLifetime, now, sign); err != nil {
		t.Errorf("the request again: %v", err)
	}
	if _, err := bridgeSignWindowDelegation(request(), nil, compiled, maxLifetime, now, sign); !errors.Is(err, ErrBridgeDelegationRefused) {
		t.Errorf("no identity: %v", err)
	}
}
