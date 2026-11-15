//go:build !ios_extension && !sidecar_http

// Sidecar.SignWindowDelegation's rules (bridge_sign.go; DESIGN-DETAILS 12.2.6): a delegation for this sidecar's own
// network and subject, a 32-byte window client key, a not_after ahead and within the longest a delegation lives, and
// a target the newest compiled state links to, which a host's VerifyWindowDelegation takes under the identity key;
// each refusal alone beside the request that passes, a share link and no compiled state among them.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

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

	signed, err := bridgeSignWindowDelegation(request(), identity, compiled, maxLifetime, now, sign, nil)
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
		if _, err := bridgeSignWindowDelegation(refused, identity, held, maxLifetime, now, sign, nil); !errors.Is(err, ErrBridgeDelegationRefused) {
			t.Errorf("%s: %v", refusal.name, err)
		}
	}
	if _, err := bridgeSignWindowDelegation(request(), identity, compiled, maxLifetime, now, sign, nil); err != nil {
		t.Errorf("the request again: %v", err)
	}
	if _, err := bridgeSignWindowDelegation(request(), nil, compiled, maxLifetime, now, sign, nil); !errors.Is(err, ErrBridgeDelegationRefused) {
		t.Errorf("no identity: %v", err)
	}
}

// §17.9's sign and use rows on a sidecar: a share link's delegation is signed by the signer the newest compiled head
// carries, never by the identity key, carries the share's id and cert, and verifies at the other network's host under
// the pinned ShareKey. The sidecar never signs below a generation it used, signs nothing once the cert expired or the
// file left the head, and a signer that changed is what the links are signed again for.
func TestAShareLinkIsSignedByItsShareSigner(t *testing.T) {
	keys := newTestBridgeShareKeys(t)
	net := newTestConfigNet(t)
	ctx := context.Background()
	shareId := testConfigId("signed share")
	sharePublicKey, err := keys.keyring.Create(ctx, shareId)
	if err != nil {
		t.Fatal(err)
	}
	headAt := func(generation uint64) *ConfigHead {
		files := map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis}
		if 0 < generation {
			file, err := keys.keyring.Certify(ctx, shareId, generation)
			if err != nil {
				t.Fatal(err)
			}
			files[ConfigHeadBridgeSharePath(shareId)], _ = proto.Marshal(file)
		}
		head, err := NewConfigHead(files)
		if err != nil {
			t.Fatal(err)
		}
		return head
	}
	identity := &SidecarIdentity{NetworkId: testConfigId("accepting network"), SidecarId: testConfigId("accepting sidecar")}
	target := testConfigId("sharing host")
	// the state links to the host over the share alone: a share link's host is no link target of this network's
	compiled := &BridgeCompiled{State: &bridge.BridgeState{}, ShareLinks: []BridgeCompiledShareLink{{ShareId: shareId, TargetSidecarId: target}}}
	maxLifetime := DefaultBridgeComponentSettings().WindowDelegationMaxLifetime
	windowPublicKey := bytes.Repeat([]byte{0x33}, 32)
	request := &BridgeDelegationRequest{
		NetworkId: identity.NetworkId, SubjectSidecarId: identity.SidecarId, WindowClientId: testConfigId("share window client"),
		WindowClientPublicKey: windowPublicKey, TargetSidecarId: target, NotAfter: keys.clock.Now().Add(time.Hour), ShareId: shareId,
	}
	sameNetwork := *request
	sameNetwork.ShareId = Id{}
	if _, err := bridgeSignWindowDelegation(&sameNetwork, identity, compiled, maxLifetime, keys.clock.Now(), nil, nil); !errors.Is(err, ErrBridgeDelegationRefused) {
		t.Fatalf("a delegation of this network to a share's host: %v", err)
	}
	identitySign := func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		t.Fatal("the identity key was asked to sign a share link's delegation")
		return nil, nil
	}
	shares := &bridgeComponentShares{}
	sign := func() ([]byte, error) {
		return bridgeSignWindowDelegation(request, identity, compiled, maxLifetime, keys.clock.Now(), identitySign, shares.use)
	}
	admit := func(signed []byte, ratchet uint64) (*bridge.WindowDelegationAdmission, error) {
		return bridge.VerifyWindowDelegationAdmission(signed, &bridge.WindowDelegationCheck{
			NetworkId: identity.NetworkId.Bytes(), WindowClientId: request.WindowClientId.Bytes(), WindowClientPublicKey: windowPublicKey,
			TargetSidecarId: target.Bytes(), NowMs: keys.clock.Now().UnixMilli(),
			IdentityKey: func(sidecarId []byte) ([]byte, bool) { return nil, false },
			Share: func(got []byte) (*bridge.WindowDelegationShare, bool) {
				return &bridge.WindowDelegationShare{SharePublicKey: sharePublicKey, Generation: ratchet}, bytes.Equal(got, shareId.Bytes())
			},
		})
	}
	// no file: nothing is signed
	if _, err := sign(); !errors.Is(err, ErrBridgeDelegationRefused) || !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Fatalf("a share with no signer: %v", err)
	}
	if _, err := bridgeSignWindowDelegation(request, identity, compiled, maxLifetime, keys.clock.Now(), identitySign, nil); !errors.Is(err, ErrBridgeDelegationRefused) {
		t.Fatalf("a share link where no share signer runs: %v", err)
	}
	head := headAt(8)
	if changed := shares.setHead(head); len(changed) != 1 || changed[0] != shareId {
		t.Fatalf("a first signer changed %v", changed)
	}
	if changed := shares.setHead(head); len(changed) != 0 {
		t.Fatalf("the same head changed %v", changed)
	}
	signed, err := sign()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := admit(signed, 8)
	if err != nil || admission.ShareCert.GetConfigGeneration() != 8 || !bytes.Equal(admission.Delegation.GetShareId(), shareId.Bytes()) {
		t.Fatalf("a host's admission: %v", err)
	}
	if _, err := admit(signed, 9); !errors.Is(err, bridge.ErrShareCertGeneration) {
		t.Errorf("a host whose ratchet passed the cert: %v", err)
	}
	// a target the compiled state links to nowhere is refused for a share as for any link
	elsewhere := *request
	elsewhere.TargetSidecarId = testConfigId("no link")
	if _, err := bridgeSignWindowDelegation(&elsewhere, identity, compiled, maxLifetime, keys.clock.Now(), identitySign, shares.use); !errors.Is(err, ErrBridgeDelegationRefused) {
		t.Errorf("a share link to no compiled target: %v", err)
	}
	// a head that carries an older generation's signer, a stale read or a rollback: never signed with again
	if changed := shares.setHead(headAt(7)); len(changed) != 1 {
		t.Fatalf("an older signer changed %v", changed)
	}
	if _, err := sign(); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Fatalf("a signer below the one used: %v", err)
	}
	// a renewal at the generation used signs again, and once its cert runs out the share lapses here
	if changed := shares.setHead(headAt(8)); len(changed) != 1 {
		t.Fatalf("a renewed signer changed %v", changed)
	}
	if _, err := sign(); err != nil {
		t.Fatal(err)
	}
	keys.clock.advance(169 * time.Hour)
	request.NotAfter = keys.clock.Now().Add(time.Hour)
	if _, err := sign(); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Fatalf("an expired signer: %v", err)
	}
	// the file leaves the head: the share stops signing, and nothing is re-signed for it
	if changed := shares.setHead(headAt(0)); len(changed) != 0 {
		t.Fatalf("a head with no file changed %v", changed)
	}
	if _, err := sign(); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Fatalf("a share whose file left the head: %v", err)
	}
	// a floor that cannot be kept signs nothing
	kept := &bridgeComponentShares{}
	kept.setFloors(NewBridgeShareSignerFloors(nil, func(floors map[Id]uint64) error { return errors.New("the store is full") }))
	kept.setHead(headAt(9))
	if _, err := kept.use(shareId, keys.clock.Now()); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Fatalf("a floor that was not kept: %v", err)
	}
}
