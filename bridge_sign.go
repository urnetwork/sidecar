//go:build !ios_extension && !sidecar_http

// Sidecar.SignWindowDelegation (DESIGN-DETAILS 12.2.6, §17.9's sign row; landed early for SDK-M8-08 by BRIDGE-M4-17,
// since ur tun's links need it at M4): the WindowDelegation a link's window client carries in CreateContract, signed by
// this sidecar's identity key, which a host verifies once per contract before its first flow (bridge.
// VerifyWindowDelegation). It signs only for this sidecar's own network and itself as the subject, a window client key
// of 32 bytes, a not_after ahead and at most WindowDelegationMaxLifetime away, and a target the newest compiled state
// names in a link, an entry's or an exit's; with no compiled state, pending, it signs nothing.
//
// A share link's delegation (BRIDGE-M6-04; §17.9's share signers) is signed by the share's ShareSigner, never by the
// identity key: the signer the newest compiled head carries at bridge/share/<share_id hex>, held to §17.9's use row
// (bridge_share_signer.go), with the newest generation this sidecar signed with saved before it signs, so it never
// signs below one it used. The delegation carries the share's id and the signer's ShareCert, by which the other
// network's host verifies it under the ShareKey its admin pinned. With no usable signer it signs nothing: the share
// lapses on this sidecar until its holder's renewal lands.
//
// Neither the delegation nor the signed bytes reach a log line, an event, BridgeState, a device RPC reply or an MCP
// tool: the bytes go to the caller, the link's generator, alone. The identity key never leaves Sidecar.Sign.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A delegation SignWindowDelegation will not sign, named by the rule it breaks, never by a value (I-13).
var ErrBridgeDelegationRefused = errors.New("window delegation refused")

// What a link asks to have signed for one window client (§17.9's sign row).
type BridgeDelegationRequest struct {
	NetworkId        Id
	SubjectSidecarId Id
	WindowClientId   Id
	// The window client's ClientKey public key, 32 bytes.
	WindowClientPublicKey []byte
	TargetSidecarId       Id
	// The window client's strict_exp (§7.4).
	NotAfter time.Time
	// Zero on a same-network link.
	ShareId Id
}

// Signs a link's WindowDelegation, or refuses it with ErrBridgeDelegationRefused (the file's comment).
func (self *Sidecar) SignWindowDelegation(request *BridgeDelegationRequest) ([]byte, error) {
	component := self.bridgeComponent()
	if component == nil {
		return nil, fmt.Errorf("%w: no bridge component", ErrBridgeDelegationRefused)
	}
	return bridgeSignWindowDelegation(request, self.currentIdentity(), component.Compiled(), component.settings.WindowDelegationMaxLifetime,
		self.clock.Now(), func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return self.Sign(purpose, signedType, body, nil)
		}, component.shares.use)
}

// SignWindowDelegation's rules over this sidecar's identity, the newest compile and the time, signing with sign.
func bridgeSignWindowDelegation(request *BridgeDelegationRequest, identity *SidecarIdentity, compiled *BridgeCompiled,
	maxLifetime time.Duration, now time.Time, sign func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error),
	shareSigner func(shareId Id, now time.Time) (*BridgeShareSignerFile, error)) ([]byte, error) {
	switch {
	case request == nil:
		return nil, fmt.Errorf("%w: no request", ErrBridgeDelegationRefused)
	case identity == nil:
		return nil, fmt.Errorf("%w: no identity", ErrBridgeDelegationRefused)
	case request.NetworkId != identity.NetworkId:
		return nil, fmt.Errorf("%w: another network", ErrBridgeDelegationRefused)
	case request.SubjectSidecarId != identity.SidecarId:
		return nil, fmt.Errorf("%w: another subject", ErrBridgeDelegationRefused)
	case len(request.WindowClientPublicKey) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("%w: a window client key of %d bytes", ErrBridgeDelegationRefused, len(request.WindowClientPublicKey))
	case request.WindowClientId == (Id{}) || request.TargetSidecarId == (Id{}):
		return nil, fmt.Errorf("%w: no window client or target", ErrBridgeDelegationRefused)
	case !request.NotAfter.After(now):
		return nil, fmt.Errorf("%w: a not_after in the past", ErrBridgeDelegationRefused)
	case maxLifetime < request.NotAfter.Sub(now):
		return nil, fmt.Errorf("%w: a not_after past the longest a delegation lives", ErrBridgeDelegationRefused)
	case request.ShareId != (Id{}) && shareSigner == nil:
		return nil, fmt.Errorf("%w: a share link, and no share signer here", ErrBridgeDelegationRefused)
	case compiled == nil || compiled.State == nil:
		return nil, fmt.Errorf("%w: no compiled state", ErrBridgeDelegationRefused)
	case !slices.Contains(compiled.LinkTargets, request.TargetSidecarId):
		return nil, fmt.Errorf("%w: a target the compiled state links to nowhere", ErrBridgeDelegationRefused)
	}
	delegation := &bridge.WindowDelegation{
		NetworkId:             request.NetworkId.Bytes(),
		SubjectSidecarId:      request.SubjectSidecarId.Bytes(),
		WindowClientId:        request.WindowClientId.Bytes(),
		WindowClientPublicKey: append([]byte(nil), request.WindowClientPublicKey...),
		TargetSidecarId:       request.TargetSidecarId.Bytes(),
		NotAfterMs:            request.NotAfter.UnixMilli(),
	}
	if request.ShareId != (Id{}) {
		// the share's signer signs, with its floor raised first; the identity key signs no share link's delegation
		use, err := shareSigner(request.ShareId, now)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBridgeDelegationRefused, err)
		}
		delegation.ShareId, delegation.ShareCert = request.ShareId.Bytes(), use.CertSigned
		sign = use.sign
	}
	return bridge.WindowDelegationSigned(delegation, sign, nil)
}

// This Sidecar's bridge component, nil for none.
func (self *Sidecar) bridgeComponent() *BridgeComponent {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil
	}
	for _, component := range leg.componentList() {
		if bridgeComponent, ok := component.(*BridgeComponent); ok {
			return bridgeComponent
		}
	}
	return nil
}

// A sink that signs a share's links again: the device role, in process or over §18.6's ResignShares.
type BridgeShareResigner interface {
	// The shares whose signer changed. Each live window client of their links is signed again, for its later
	// contracts.
	ResignShares(shareIds []Id) error
}

// The share signers a component signs with (the file's use and resign rows): the ones its newest compiled head
// carries, and the floors. Safe for concurrent use.
type bridgeComponentShares struct {
	stateLock sync.Mutex
	// by share, the signer the newest compiled head carries; a file no sidecar signs with is absent
	signers map[Id]*BridgeShareSignerFile
	// nil until the first use: floors kept in memory alone
	floors *BridgeShareSignerFloors
}

// Takes the head a compile read: every bridge/share/<share_id hex> file a sidecar would sign with. Answers the shares
// whose signer is new or changed, in id order; a share whose file left the head stops signing and is not answered.
func (self *bridgeComponentShares) setHead(head *ConfigHead) []Id {
	signers := map[Id]*BridgeShareSignerFile{}
	if head != nil {
		for _, path := range head.Paths() {
			encoded, ok := strings.CutPrefix(path, ConfigHeadBridgeSharePrefix)
			if !ok {
				continue
			}
			decoded, err := hex.DecodeString(encoded)
			if err != nil {
				continue
			}
			shareId, err := IdFromBytes(decoded)
			if err != nil || ConfigHeadBridgeSharePath(shareId) != path {
				continue
			}
			if use, err := ReadBridgeShareSigner(head, shareId); err == nil && use != nil {
				signers[shareId] = use
			}
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	changed := []Id{}
	for shareId, use := range signers {
		if held := self.signers[shareId]; held == nil || !bytes.Equal(held.CertSigned, use.CertSigned) {
			changed = append(changed, shareId)
		}
	}
	self.signers = signers
	slices.SortFunc(changed, func(a Id, b Id) int { return bytes.Compare(a.Bytes(), b.Bytes()) })
	return changed
}

// Sets where the floors are kept, before the first use: loaded now, and saved at each rise.
func (self *bridgeComponentShares) setFloors(floors *BridgeShareSignerFloors) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.floors = floors
}

// The share's signer for a signature at now, its floor raised first (the file's use row).
// ErrBridgeShareSignerRefused where the head carries none this sidecar signs with.
func (self *bridgeComponentShares) use(shareId Id, now time.Time) (*BridgeShareSignerFile, error) {
	use, floors := func() (*BridgeShareSignerFile, *BridgeShareSignerFloors) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.floors == nil {
			self.floors = NewBridgeShareSignerFloors(nil, nil)
		}
		return self.signers[shareId], self.floors
	}()
	if err := BridgeShareSignerUsable(use, floors.Floor(shareId), now.UnixMilli()); err != nil {
		return nil, err
	}
	// saved before the signature, so a kill after it leaves the floor at least here
	if err := floors.Use(shareId, use.Generation); err != nil {
		return nil, fmt.Errorf("%w: its generation was not kept: %w", ErrBridgeShareSignerRefused, err)
	}
	return use, nil
}

// Has the device role sign the shares' links again (the file's resign row): a share's new signer reaches its live
// window clients' later contracts. A sink that signs no share's links takes nothing.
func (self *BridgeComponent) ResignShares(shareIds []Id) {
	sink := self.currentSink()
	resigner, ok := sink.(BridgeShareResigner)
	if !ok || len(shareIds) == 0 {
		return
	}
	if err := resigner.ResignShares(shareIds); err != nil {
		self.log.Warningf("[bridge]%s the device role did not re-sign %d shares: %v", self.args.NetworkId, len(shareIds), err)
	}
}
