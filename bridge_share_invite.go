//go:build !ios_extension

// A share's three admin acts, and its end (BRIDGE-M6-03; §17.9, §8.11; D-BRIDGE-14, D-BRIDGE-15, D-BRIDGE-20;
// DESIGN-DETAILS 12.2.7; I-2, I-8). Each is a person's confirmed command on an admin's device: none runs from MCP, a
// hook or an unconfirmed control call.
//
//	Invite        X's admin. The code is 32 random bytes, shown once and kept nowhere; K is derived from it. The target
//	              table, one row a target with its host's identity key from X's own state (QD-077), is sealed under K
//	              at version 1 and posted with the code's SHA-256. The table is immutable: a change is a new invite.
//	              K and the table's hash are kept in share/invite/<share_id hex> so the activation finds them.
//	AcceptInvite  Y's admin, with the code. Claims the invite, opens the target table, and runs the preflight on its
//	              own ledger. A table that can never fit, or one with no room, posts its refusal with a sealed shortfall
//	              and files nothing. Otherwise: the ShareKey is created; one BridgeAlias a target is filed, with the
//	              target's host and identity key; once they land, Y's own ledger must show each in force. One that is
//	              void, a concurrent accept having taken its block, releases what landed and plans again,
//	              AcceptAttemptCount times at most, then refuses no_space. Only then is the share's first signer
//	              written to bridge/share/<share_id hex>, and the completion posted: the sealed alias table and the
//	              sealed ShareKey, status active. The bytes posted are kept in share/accept/<share_id hex> first, so a
//	              kill before the server's answer posts the same bytes again.
//	PreviewShare  X's approving admin. Fetches the share, opens both sides under the invite's K, and answers what the
//	              admin is shown: Y's network, the targets, the aliases, the ShareKey, and both tables' hashes.
//	ActivateShare X's approving admin, on what PreviewShare showed. The row is fetched and opened again and must hash
//	              to the preview. The share's inbound grant, a dial on the targets' hosts for Y's network (§8.11; QD-820),
//	              passes §5.4's gate, and the BridgeShareGrant that pins the ShareKey, K, Y and both tables' hashes and
//	              versions is written to bridge/share-grant/<share_id hex> with the grant's id. The grant's action is kept
//	              in the invite's record as its request was filed, before the gate files it, and presented again until
//	              its expiry, so the activation asked again after a person's decision spends it: the gate spends a
//	              decision on the action its request stored alone, and an action built afresh asks a later expiry and
//	              seals its detail under a fresh nonce, as a forward's retries keep theirs (forwardApprovalAction). A
//	              kept action whose grant has since ended is asked afresh. The grant's id is kept in the record too: a
//	              grant whose file did not land compiles nothing, and calling again writes the file for that grant
//	              while it stands, asking for no second one, and once it no longer stands asks for a new one.
//	RevokeShare   X: the grant's GrantRevoke, which ends the share at every host (the pin file counts only while its
//	              grant is live).
//	ReleaseShare  Y: a BridgeAlias release for each alias the share holds, which drain and then free their blocks.
//
// Errors name the rule broken, never a table's rows or a key (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The names a filer keeps its shares' records under, in its own store. Format values.
const (
	bridgeFileShareInvitePrefix = "share/invite/"
	bridgeFileShareAcceptPrefix = "share/accept/"
)

// Tunables of the share acts.
type BridgeShareFilerSettings struct {
	// How many times an accept plans and files its aliases before it refuses no_space: 3 (DESIGN-DETAILS 12.2.2's
	// AcceptRetryCount). Non-positive plans once.
	AcceptAttemptCount int
	// How many networks one invite admits: 1.
	InviteUseCount int
	// How long an invite stays open; 0 takes the server's 7 days.
	InviteWindow time.Duration
	// How long an accept waits for its aliases' entries to apply before it reads its ledger again: 30 s.
	LandTimeout time.Duration
	// The drain a release asks; 0 takes the ledger's AliasDrainTimeout.
	ReleaseDrain time.Duration
	// The seal's limits; nil is its defaults.
	Seal *BridgeShareSettings
}

// DESIGN-DETAILS 12.2.2's values.
func DefaultBridgeShareFilerSettings() *BridgeShareFilerSettings {
	return &BridgeShareFilerSettings{
		AcceptAttemptCount: 3,
		InviteUseCount:     1,
		LandTimeout:        30 * time.Second,
	}
}

// What the share acts are built over, beside the filer's own args.
type BridgeShareFilerArgs struct {
	// The share routes; nil is the sidecar's api.
	Api BridgeShareApi
	// The ShareKeys this device holds; nil refuses an accept.
	Keys *BridgeShareKeyring
	// The config repo's generation as this device holds it; nil reads the generation its seals use.
	Generation func(ctx context.Context) (uint64, error)
	Settings   *BridgeShareFilerSettings
}

// One target of an invite: what a host of the sharing network reaches.
type BridgeShareTargetRequest struct {
	// The host, a sidecar admitted to the sharing network.
	Host Id
	// The host's overlay address as a /32, or a prefix it serves.
	Prefix netip.Prefix
	// 0 for every protocol; 6 or 17 with Ports.
	Protocol uint32
	Ports    []*bridge.BridgePortRange
}

// What an invite shares: its targets, in the order their indexes take.
type BridgeShareInviteRequest struct {
	Targets []*BridgeShareTargetRequest
}

// An invite as its admin is shown it. Code is shown once and kept nowhere.
type BridgeShareInvite struct {
	ShareId    Id
	Code       []byte
	UseCount   int
	ExpireTime time.Time
}

// The code never prints with an invite (I-7).
func (self BridgeShareInvite) String() string {
	return fmt.Sprintf("BridgeShareInvite(share %s)", self.ShareId)
}

// As String, so %#v prints no code either.
func (self BridgeShareInvite) GoString() string {
	return self.String()
}

// What an accept answered.
type BridgeShareAccepted struct {
	ShareId          Id
	SharingNetworkId Id
	Status           BridgeShareAcceptStatus
	// The aliases in force, one a target, for an active share.
	Aliases        []*bridge.BridgeShareAlias
	SharePublicKey []byte
}

// What X's approving admin is shown before a share is activated, and what the activation is held to.
type BridgeSharePreview struct {
	ShareId            Id
	AcceptingNetworkId Id
	Status             BridgeShareAcceptStatus
	Targets            []*bridge.BridgeShareTarget
	Aliases            []*bridge.BridgeShareAlias
	SharePublicKey     []byte
	// A refusal's figures, nil otherwise.
	Shortfall          *bridge.BridgeShareShortfall
	TargetTableSha256  []byte
	TargetTableVersion uint64
	AliasTableSha256   []byte
	AliasTableVersion  uint64
}

// share/invite/<share_id hex>: what the sharing admin's device keeps of an invite. K opens the share's tables and is
// written to the config at activation; the code is not kept.
type bridgeShareInviteRecord struct {
	Version            int    `json:"version"`
	ShareId            Id     `json:"share_id"`
	TableKey           []byte `json:"table_key"`
	TargetTableSha256  []byte `json:"target_table_sha256"`
	TargetTableVersion uint64 `json:"target_table_version"`
	// The share's grant once the gate answered it, and the decision it spent under: kept before the pin file is
	// written, so a call after a kill writes the file for this grant and asks for no second one.
	GrantId    []byte `json:"grant_id,omitempty"`
	ApprovalId Id     `json:"approval_id,omitempty"`
	// The grant's action as its request was filed, as stored, and the lifetime it was asked for in ms, 0 for its
	// rule's default: kept before the gate files it, so the activation asked again presents the bytes a decision
	// names (shareGrantAction).
	GrantAction     []byte `json:"grant_action,omitempty"`
	GrantLifetimeMs int64  `json:"grant_lifetime_ms,omitempty"`
}

// share/accept/<share_id hex>: the completion an accept posts, kept until the server answered it.
type bridgeShareAcceptRecord struct {
	Version           int    `json:"version"`
	ShareId           Id     `json:"share_id"`
	Status            string `json:"status"`
	Accept            []byte `json:"accept"`
	AliasTableVersion uint64 `json:"alias_table_version"`
}

// The share acts' parts, and the checks every one takes: a person's confirmed command, by an admin's device.
type bridgeShareActs struct {
	api      BridgeShareApi
	keys     *BridgeShareKeyring
	settings *BridgeShareFilerSettings
	view     *bridgeFileView
}

// The acts' parts at the newest verified state, or the refusal of an origin or a device that may not run them.
func (self *BridgeFiler) shareActs(ctx context.Context, origin *BridgeFileOrigin) (*bridgeShareActs, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if origin.Act != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: a share is a person's confirmed command", ErrBridgeFileRefused)
	}
	acts := &bridgeShareActs{settings: DefaultBridgeShareFilerSettings()}
	if args := self.args.Share; args != nil {
		acts.api, acts.keys = args.Api, args.Keys
		if args.Settings != nil {
			acts.settings = args.Settings
		}
	}
	if acts.api == nil {
		if api := self.args.Sidecar.sidecarApi; api != nil {
			acts.api = api
		}
	}
	if acts.api == nil {
		return nil, fmt.Errorf("%w: no api to reach the share routes", ErrBridgeFileRefused)
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	if !view.signerAdmin() {
		return nil, fmt.Errorf("%w: a share is an admin's", ErrBridgeFileRefused)
	}
	acts.view = view
	return acts, nil
}

// share/invite/<share_id hex>.
func bridgeShareInviteRecordName(shareId Id) string {
	return bridgeFileShareInvitePrefix + hex.EncodeToString(shareId.Bytes())
}

// share/accept/<share_id hex>.
func bridgeShareAcceptRecordName(shareId Id) string {
	return bridgeFileShareAcceptPrefix + hex.EncodeToString(shareId.Bytes())
}

// Invites another network to the targets (the file's Invite row).
func (self *BridgeFiler) Invite(ctx context.Context, origin *BridgeFileOrigin, request *BridgeShareInviteRequest) (*BridgeShareInvite, error) {
	acts, err := self.shareActs(ctx, origin)
	if err != nil {
		return nil, err
	}
	if request == nil || len(request.Targets) == 0 {
		return nil, fmt.Errorf("%w: an invite with no target", ErrBridgeFileRefused)
	}
	targets := &bridge.BridgeShareTargets{}
	for index, target := range request.Targets {
		if target == nil {
			return nil, fmt.Errorf("%w: an invite with an empty target", ErrBridgeFileRefused)
		}
		// the host's key is read from this network's own state, never from the request
		row := acts.view.state.SidecarRow(target.Host)
		if row == nil || row.GetRevokedAt() != 0 {
			return nil, fmt.Errorf("%w: target %d names no admitted sidecar of this network", ErrBridgeFileRefused, index)
		}
		prefix, err := bridgePrefixWire(target.Prefix)
		if err != nil {
			return nil, fmt.Errorf("%w: target %d: %w", ErrBridgeFileRefused, index, err)
		}
		targets.Targets = append(targets.Targets, &bridge.BridgeShareTarget{
			Index: uint32(index), HostSidecarId: target.Host.Bytes(), HostIdentityPublicKey: bytes.Clone(row.GetIdentityPublicKey()),
			Prefix: prefix, Protocol: target.Protocol, Ports: target.Ports,
		})
	}
	if err := CheckBridgeShareTargets(targets, self.settings.Ledger); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	code := make([]byte, bridgeShareCodeByteCount)
	if _, err := io.ReadFull(self.random, code); err != nil {
		return nil, err
	}
	testHookSecret("bridge-share-code", code)
	networkId := acts.view.state.NetworkId()
	seal, err := NewBridgeShareSeal(code, networkId, acts.settings.Seal)
	if err != nil {
		return nil, err
	}
	sealed, err := seal.Seal(BridgeShareLabelTargets, Id{}, 1, targets, self.random)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	codeHash := sha256.Sum256(code)
	testHookBarrier("bridge_share.invite.before", networkId.String())
	reply, err := acts.api.InviteBridgeShare(ctx, &BridgeShareInviteArgs{
		CodeHash: codeHash[:], UseCount: max(1, acts.settings.InviteUseCount), Window: acts.settings.InviteWindow, TargetTable: sealed,
	})
	testHookBarrier("bridge_share.invite.after", networkId.String())
	if err != nil {
		return nil, fmt.Errorf("%w: the invite was not taken: %w", ErrBridgeFileRefused, err)
	}
	if reply == nil || reply.ShareId == (Id{}) {
		return nil, fmt.Errorf("%w: the invite's answer names no share", ErrBridgeFileUncertain)
	}
	// a kill before this leaves an invite no one holds the code of: the admin invites again
	if err := self.saveRecord(bridgeShareInviteRecordName(reply.ShareId), &bridgeShareInviteRecord{
		Version: bridgeFileRecordVersion, ShareId: reply.ShareId, TableKey: seal.TableKey(),
		TargetTableSha256: BridgeShareTableSha256(sealed), TargetTableVersion: 1,
	}); err != nil {
		return nil, fmt.Errorf("%w: the invite's key was not kept: %w", ErrBridgeFileUncertain, err)
	}
	return &BridgeShareInvite{ShareId: reply.ShareId, Code: code, UseCount: reply.UseCount, ExpireTime: reply.ExpireTime}, nil
}

// This network's in-force aliases of a share, by target index.
func bridgeShareAliasesHeld(ledger *BridgeLedger, shareId Id) map[uint32]*BridgeLedgerAlias {
	held := map[uint32]*BridgeLedgerAlias{}
	for _, alias := range ledger.Aliases() {
		if bytes.Equal(alias.Body.GetShareId(), shareId.Bytes()) {
			held[alias.Body.GetTargetIndex()] = alias
		}
	}
	return held
}

// Whether the ledger holds, in force, exactly the alias planned for each target; and the aliases as it holds them.
func bridgeShareAliasesInForce(ledger *BridgeLedger, shareId Id, targets *bridge.BridgeShareTargets, plan []*bridge.BridgeShareAlias) ([]*bridge.BridgeShareAlias, bool) {
	held := bridgeShareAliasesHeld(ledger, shareId)
	if len(held) != len(targets.GetTargets()) {
		return nil, false
	}
	aliases := make([]*bridge.BridgeShareAlias, 0, len(targets.GetTargets()))
	for position, target := range targets.GetTargets() {
		alias := held[target.GetIndex()]
		if alias == nil || alias.Body.GetAliasPrefix().GetLength() != target.GetPrefix().GetLength() {
			return nil, false
		}
		first, _, err := bridgeUpperRangeOf(alias.Body.GetAliasPrefix())
		if err != nil {
			return nil, false
		}
		if plan != nil && (plan[position].GetAliasHostBits() != first || plan[position].GetIndex() != target.GetIndex()) {
			return nil, false
		}
		aliases = append(aliases, &bridge.BridgeShareAlias{Index: target.GetIndex(), AliasHostBits: first, Length: target.GetPrefix().GetLength()})
	}
	return aliases, true
}

// Files statements one after another and waits for the last entry among them to apply. A statement the tip refused is
// counted, not an error: the ledger read after is what says which stand.
func (self *BridgeFiler) fileAliases(ctx context.Context, origin *BridgeFileOrigin, acts *bridgeShareActs, bodies []*bridge.BridgeAliasBody) (refused int, err error) {
	through := uint64(0)
	for _, body := range bodies {
		testHookBarrier("bridge_share.alias.before", hex.EncodeToString(body.GetShareId()))
		pins, err := self.fileSealed(ctx, origin, bridge.SignedType_SIGNED_BRIDGE_ALIAS, &bridge.BridgeAlias{}, body)
		testHookBarrier("bridge_share.alias.after", hex.EncodeToString(body.GetShareId()))
		switch {
		case err == nil:
		case errors.Is(err, ErrSidecarEffectNotDone):
			refused += 1
			continue
		default:
			return refused, err
		}
		for _, pin := range pins {
			through = max(through, pin.GetVersion())
		}
	}
	if through == 0 {
		return refused, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, acts.settings.LandTimeout)
	defer cancel()
	if _, err := self.args.Config.WaitFor(waitCtx, through); err != nil {
		return refused, fmt.Errorf("%w: the aliases' entries did not apply: %w", ErrBridgeFileUncertain, err)
	}
	return refused, nil
}

// Releases the aliases held, each as its ledger holds it.
func (self *BridgeFiler) releaseAliases(ctx context.Context, origin *BridgeFileOrigin, acts *bridgeShareActs, held map[uint32]*BridgeLedgerAlias) error {
	indexes := make([]uint32, 0, len(held))
	for index := range held {
		indexes = append(indexes, index)
	}
	slices.Sort(indexes)
	bodies := make([]*bridge.BridgeAliasBody, 0, len(held))
	for _, index := range indexes {
		body := proto.Clone(held[index].Body).(*bridge.BridgeAliasBody)
		body.Release, body.DrainSeconds = true, uint32(acts.settings.ReleaseDrain/time.Second)
		bodies = append(bodies, body)
	}
	refused, err := self.fileAliases(ctx, origin, acts, bodies)
	if err != nil {
		return err
	}
	if 0 < refused {
		return fmt.Errorf("%w: %d releases were refused", ErrBridgeFileUncertain, refused)
	}
	return nil
}

// Posts an accept's side, kept first so a kill posts the same bytes, and drops the record once the server answered.
func (self *BridgeFiler) completeShare(ctx context.Context, acts *bridgeShareActs, record *bridgeShareAcceptRecord) error {
	name := bridgeShareAcceptRecordName(record.ShareId)
	if err := self.saveRecord(name, record); err != nil {
		return fmt.Errorf("%w: the completion was not kept: %w", ErrBridgeFileUncertain, err)
	}
	testHookBarrier("bridge_share.complete.before", record.ShareId.String())
	_, err := acts.api.CompleteBridgeShare(ctx, record.ShareId, record.Accept, record.AliasTableVersion, BridgeShareAcceptStatus(record.Status))
	testHookBarrier("bridge_share.complete.after", record.ShareId.String())
	if err != nil {
		return fmt.Errorf("%w: the completion was not answered: %w", ErrBridgeFileUncertain, err)
	}
	if err := self.removeRecord(name); err != nil {
		self.log.Warningf("bridge share %s: its completion's record was not dropped: %v", record.ShareId, err)
	}
	return nil
}

// What an accept posts for a refusal (§17.9's space row; question bridge-m6-03-accept-seals, option 1): the status its
// reason names, refused_too_large or refused_no_space, and the alias table's container holding the shortfall alone,
// sealed under seal for acceptingNetworkId at version 1. random nil is crypto/rand. A refusal of no reason is an error.
func BridgeShareRefusalCompletion(seal *BridgeShareSeal, acceptingNetworkId Id, refusal *BridgeShareRefusal, random io.Reader) ([]byte, BridgeShareAcceptStatus, error) {
	if seal == nil || refusal == nil || refusal.Shortfall == nil {
		return nil, "", fmt.Errorf("%w: no refusal to post", ErrBridgeShareTableInvalid)
	}
	var status BridgeShareAcceptStatus
	switch {
	case errors.Is(refusal.Reason, ErrBridgeShareTooLarge):
		status = BridgeShareAcceptStatusRefusedTooLarge
	case errors.Is(refusal.Reason, ErrBridgeShareNoSpace):
		status = BridgeShareAcceptStatusRefusedNoSpace
	default:
		return nil, "", fmt.Errorf("%w: a refusal of no reason the server stores", ErrBridgeShareTableInvalid)
	}
	sealed, err := seal.Seal(BridgeShareLabelShortfall, acceptingNetworkId, 1, refusal.Shortfall, random)
	if err != nil {
		return nil, "", err
	}
	accept, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.BridgeShareAccept{Shortfall: sealed})
	if err != nil {
		return nil, "", err
	}
	return accept, status, nil
}

// Posts a refusal with its sealed shortfall, and answers the refusal.
func (self *BridgeFiler) refuseShare(ctx context.Context, acts *bridgeShareActs, seal *BridgeShareSeal, shareId Id, refusal *BridgeShareRefusal) error {
	accept, status, err := BridgeShareRefusalCompletion(seal, acts.view.state.NetworkId(), refusal, self.random)
	if err != nil {
		return err
	}
	if err := self.completeShare(ctx, acts, &bridgeShareAcceptRecord{
		Version: bridgeFileRecordVersion, ShareId: shareId, Status: string(status), Accept: accept, AliasTableVersion: 1,
	}); err != nil {
		return err
	}
	return fmt.Errorf("%w: %w", ErrBridgeFileRefused, refusal)
}

// Accepts an invite by its code (the file's AcceptInvite row). A refusal for size or room is posted to the sharing
// network and answered as a *BridgeShareRefusal under ErrBridgeFileRefused.
func (self *BridgeFiler) AcceptInvite(ctx context.Context, origin *BridgeFileOrigin, code []byte) (*BridgeShareAccepted, error) {
	acts, err := self.shareActs(ctx, origin)
	if err != nil {
		return nil, err
	}
	if len(code) != bridgeShareCodeByteCount {
		return nil, fmt.Errorf("%w: a code of %d bytes", ErrBridgeFileRefused, len(code))
	}
	var writer BridgeHeadWriter
	if self.args.HeadWriter != nil {
		writer = self.args.HeadWriter()
	}
	if acts.keys == nil || writer == nil {
		// checked before anything is claimed or filed: an accept that cannot write its signer accepts nothing
		return nil, fmt.Errorf("%w: this device holds no share keyring or runs no config writer", ErrBridgeFileRefused)
	}
	networkId := acts.view.state.NetworkId()
	codeHash := sha256.Sum256(code)
	row, err := acts.api.ClaimBridgeShare(ctx, codeHash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: the invite was not claimed: %w", ErrBridgeFileRefused, err)
	}
	if row == nil || row.ShareId == (Id{}) || row.SharingNetworkId == (Id{}) || row.SharingNetworkId == networkId {
		return nil, fmt.Errorf("%w: the claim names no share of another network", ErrBridgeFileRefused)
	}
	shareId := row.ShareId
	seal, err := NewBridgeShareSeal(code, row.SharingNetworkId, acts.settings.Seal)
	if err != nil {
		return nil, err
	}
	// the target table alone: this side is this device's to make
	opened, err := OpenBridgeShareRow(seal, &BridgeShareRow{
		ShareId: shareId, SharingNetworkId: row.SharingNetworkId, TargetTable: row.TargetTable, TargetTableVersion: row.TargetTableVersion,
	}, self.settings.Ledger)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	targets := opened.Targets
	accepted := &BridgeShareAccepted{ShareId: shareId, SharingNetworkId: row.SharingNetworkId}

	// a completion a kill left unanswered is posted again as it was
	kept := &bridgeShareAcceptRecord{}
	if found, err := self.loadRecord(bridgeShareAcceptRecordName(shareId), kept); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileUncertain, err)
	} else if found && kept.ShareId == shareId && row.AcceptStatus == "" {
		if err := self.completeShare(ctx, acts, kept); err != nil {
			return nil, err
		}
		row.AcceptStatus = BridgeShareAcceptStatus(kept.Status)
	}
	switch row.AcceptStatus {
	case "":
	case BridgeShareAcceptStatusActive:
		aliases, inForce := bridgeShareAliasesInForce(acts.view.ledger, shareId, targets, nil)
		if !inForce {
			return nil, fmt.Errorf("%w: the share is completed, and this network's ledger no longer holds its aliases", ErrBridgeFileRefused)
		}
		accepted.Status, accepted.Aliases = BridgeShareAcceptStatusActive, aliases
		accepted.SharePublicKey, _ = acts.keys.PublicKey(ctx, shareId)
		return accepted, nil
	default:
		return nil, fmt.Errorf("%w: the share was refused already, which is final: the sharing network invites again", ErrBridgeFileRefused)
	}

	var aliases []*bridge.BridgeShareAlias
	var sharePublicKey []byte
	view := acts.view
	for attempt := range max(1, acts.settings.AcceptAttemptCount) {
		// what an earlier attempt, or an accept a kill ended, left in force
		if held, inForce := bridgeShareAliasesInForce(view.ledger, shareId, targets, nil); inForce {
			aliases = held
			break
		} else if held := bridgeShareAliasesHeld(view.ledger, shareId); 0 < len(held) {
			if err := self.releaseAliases(ctx, origin, acts, held); err != nil {
				return nil, err
			}
			if view, err = self.view(ctx); err != nil {
				return nil, err
			}
		}
		plan, err := BridgeSharePreflight(view.ledger, targets)
		if refusal := (*BridgeShareRefusal)(nil); errors.As(err, &refusal) {
			return nil, self.refuseShare(ctx, acts, seal, shareId, refusal)
		} else if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
		}
		if sharePublicKey == nil {
			if sharePublicKey, err = acts.keys.Create(ctx, shareId); err != nil {
				return nil, fmt.Errorf("%w: the share's key: %w", ErrBridgeFileRefused, err)
			}
		}
		block := uint32(0)
		if view.block != nil {
			if prefix, err := bridgePrefixOf(view.block.GetIpv4Prefix()); err == nil {
				block = prefix.address &^ 0xffff
			}
		}
		bodies := make([]*bridge.BridgeAliasBody, 0, len(plan))
		for position, alias := range plan {
			target := targets.GetTargets()[position]
			bodies = append(bodies, &bridge.BridgeAliasBody{
				ShareId: shareId.Bytes(), TargetIndex: alias.GetIndex(),
				AliasPrefix: &bridge.BridgeIpv4Prefix{Address: block | alias.GetAliasHostBits(), Length: alias.GetLength()},
				Host:        bytes.Clone(target.GetHostSidecarId()), HostIdentityPublicKey: bytes.Clone(target.GetHostIdentityPublicKey()),
				SharingNetworkId: row.SharingNetworkId.Bytes(),
			})
		}
		testHookBarrier("bridge_share.accept.plan", fmt.Sprintf("%s/%d", shareId, attempt))
		if _, err := self.fileAliases(ctx, origin, acts, bodies); err != nil {
			return nil, err
		}
		if view, err = self.view(ctx); err != nil {
			return nil, err
		}
		if held, inForce := bridgeShareAliasesInForce(view.ledger, shareId, targets, plan); inForce {
			aliases = held
			break
		}
	}
	if aliases == nil {
		// three plans lost their blocks to others: what landed is released, and the refusal carries the room there is
		if held := bridgeShareAliasesHeld(view.ledger, shareId); 0 < len(held) {
			if err := self.releaseAliases(ctx, origin, acts, held); err != nil {
				return nil, err
			}
			if view, err = self.view(ctx); err != nil {
				return nil, err
			}
		}
		upper := newBridgeUpperMap(view.ledger)
		first := targets.GetTargets()[0]
		return nil, self.refuseShare(ctx, acts, seal, shareId, &BridgeShareRefusal{Reason: ErrBridgeShareNoSpace, Shortfall: &bridge.BridgeShareShortfall{
			Index: first.GetIndex(), Length: first.GetPrefix().GetLength(), FreeAddressCount: upper.freeCount(), LargestFreeLength: upper.largestFreeLength(),
		}})
	}
	if sharePublicKey == nil {
		if sharePublicKey, err = acts.keys.Create(ctx, shareId); err != nil {
			return nil, fmt.Errorf("%w: the share's key: %w", ErrBridgeFileRefused, err)
		}
	}

	// the first signer, before the sharing network is told the share is active
	if err := self.writeShareSigner(ctx, acts, writer, view, shareId); err != nil {
		return nil, err
	}
	sealedAliases, err := seal.Seal(BridgeShareLabelAliases, networkId, 1, &bridge.BridgeShareAliases{Aliases: aliases}, self.random)
	if err != nil {
		return nil, err
	}
	sealedKey, err := seal.Seal(BridgeShareLabelShareKey, networkId, 1, &bridge.BridgeShareKeyBody{SharePublicKey: sharePublicKey}, self.random)
	if err != nil {
		return nil, err
	}
	accept, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.BridgeShareAccept{Aliases: sealedAliases, ShareKey: sealedKey})
	if err != nil {
		return nil, err
	}
	if err := self.completeShare(ctx, acts, &bridgeShareAcceptRecord{
		Version: bridgeFileRecordVersion, ShareId: shareId, Status: string(BridgeShareAcceptStatusActive), Accept: accept, AliasTableVersion: 1,
	}); err != nil {
		return nil, err
	}
	accepted.Status, accepted.Aliases, accepted.SharePublicKey = BridgeShareAcceptStatusActive, aliases, sharePublicKey
	return accepted, nil
}

// Writes the share's first signer where the head holds none a sidecar would sign with.
func (self *BridgeFiler) writeShareSigner(ctx context.Context, acts *bridgeShareActs, writer BridgeHeadWriter, view *bridgeFileView, shareId Id) error {
	generation := uint64(0)
	if args := self.args.Share; args != nil && args.Generation != nil {
		held, err := args.Generation(ctx)
		if err != nil {
			return fmt.Errorf("%w: the config's generation: %w", ErrBridgeFileRefused, err)
		}
		generation = held
	} else {
		repoKey, err := self.sealKey(ctx)
		if err != nil {
			return fmt.Errorf("%w: the config's generation: %w", ErrBridgeFileRefused, err)
		}
		generation = repoKey.Generation()
	}
	if use, err := ReadBridgeShareSigner(view.head, shareId); err == nil && use != nil && generation <= use.Generation &&
		BridgeShareSignerUsable(use, 0, self.clock.Now().UnixMilli()) == nil {
		return nil
	}
	file, err := acts.keys.Certify(ctx, shareId, generation)
	if err != nil {
		return fmt.Errorf("%w: the share's signer: %w", ErrBridgeFileRefused, err)
	}
	fileBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(file)
	if err != nil {
		return err
	}
	testHookBarrier("bridge_share.signer.before", shareId.String())
	_, err = writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		return head.WithFile(ConfigHeadBridgeSharePath(shareId), fileBytes)
	})
	testHookBarrier("bridge_share.signer.after", shareId.String())
	if err != nil {
		return fmt.Errorf("%w: the share's signer did not land: %w", ErrBridgeFileUncertain, err)
	}
	return nil
}

// The invite's key for a share this device invited. ErrBridgeFileRefused where it holds none.
func (self *BridgeFiler) shareInvite(shareId Id) (*bridgeShareInviteRecord, error) {
	record := &bridgeShareInviteRecord{}
	found, err := self.loadRecord(bridgeShareInviteRecordName(shareId), record)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileUncertain, err)
	}
	if !found || record.ShareId != shareId {
		return nil, fmt.Errorf("%w: this device holds no invite for the share", ErrBridgeFileRefused)
	}
	return record, nil
}

// Fetches and opens a share this device invited, held to the invite's own target table.
func (self *BridgeFiler) openInvitedShare(ctx context.Context, acts *bridgeShareActs, shareId Id) (*bridgeShareInviteRecord, *BridgeShareOpened, error) {
	record, err := self.shareInvite(shareId)
	if err != nil {
		return nil, nil, err
	}
	networkId := acts.view.state.NetworkId()
	seal, err := NewBridgeShareSealOfKey(record.TableKey, networkId, acts.settings.Seal)
	if err != nil {
		return nil, nil, err
	}
	row, err := acts.api.GetBridgeShare(ctx, shareId)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the share was not read: %w", ErrBridgeFileRefused, err)
	}
	if row == nil || row.ShareId != shareId {
		return nil, nil, fmt.Errorf("%w: the answer is another share's", ErrBridgeFileRefused)
	}
	// the server stores the target table; the invite's hash is what says it is the one this device sealed
	if !bytes.Equal(BridgeShareTableSha256(row.TargetTable), record.TargetTableSha256) || row.TargetTableVersion != record.TargetTableVersion {
		return nil, nil, fmt.Errorf("%w: %w: the target table is not the invite's", ErrBridgeFileRefused, ErrBridgeShareTableMismatch)
	}
	opened, err := OpenBridgeShareRow(seal, row, self.settings.Ledger)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	return record, opened, nil
}

// What the approving admin is shown of a share this device invited (the file's PreviewShare row).
func (self *BridgeFiler) PreviewShare(ctx context.Context, origin *BridgeFileOrigin, shareId Id) (*BridgeSharePreview, error) {
	acts, err := self.shareActs(ctx, origin)
	if err != nil {
		return nil, err
	}
	_, opened, err := self.openInvitedShare(ctx, acts, shareId)
	if err != nil {
		return nil, err
	}
	return bridgeSharePreviewOf(opened), nil
}

// The preview of an opened share.
func bridgeSharePreviewOf(opened *BridgeShareOpened) *BridgeSharePreview {
	preview := &BridgeSharePreview{
		ShareId: opened.ShareId, AcceptingNetworkId: opened.AcceptingNetworkId, Status: opened.AcceptStatus,
		Targets: opened.Targets.GetTargets(), SharePublicKey: bytes.Clone(opened.SharePublicKey), Shortfall: opened.Shortfall,
		TargetTableSha256: bytes.Clone(opened.TargetTableSha256), TargetTableVersion: opened.TargetTableVersion,
		AliasTableSha256: bytes.Clone(opened.AliasTableSha256), AliasTableVersion: opened.AliasTableVersion,
	}
	if opened.Aliases != nil {
		preview.Aliases = opened.Aliases.GetAliases()
	}
	return preview
}

// Activates a share as its preview showed it (the file's ActivateShare row). lifetime is the grant's, 0 for its
// rule's default.
func (self *BridgeFiler) ActivateShare(ctx context.Context, origin *BridgeFileOrigin, preview *BridgeSharePreview, lifetime time.Duration) (*BridgeFiling, error) {
	acts, err := self.shareActs(ctx, origin)
	if err != nil {
		return nil, err
	}
	grants := self.args.Grants
	var writer BridgeHeadWriter
	if self.args.HeadWriter != nil {
		writer = self.args.HeadWriter()
	}
	if grants == nil || writer == nil {
		return nil, fmt.Errorf("%w: this device files no grant or runs no config writer", ErrBridgeFileRefused)
	}
	if preview == nil || preview.ShareId == (Id{}) {
		return nil, fmt.Errorf("%w: no preview to activate", ErrBridgeFileRefused)
	}
	record, opened, err := self.openInvitedShare(ctx, acts, preview.ShareId)
	if err != nil {
		return nil, err
	}
	switch {
	case opened.AcceptStatus != BridgeShareAcceptStatusActive:
		return nil, fmt.Errorf("%w: the accepting network has not completed the share as active", ErrBridgeFileRefused)
	case opened.AcceptingNetworkId != preview.AcceptingNetworkId || !bytes.Equal(opened.AliasTableSha256, preview.AliasTableSha256) ||
		opened.AliasTableVersion != preview.AliasTableVersion || !bytes.Equal(opened.SharePublicKey, preview.SharePublicKey):
		return nil, fmt.Errorf("%w: %w: the share is not the one shown", ErrBridgeFileRefused, ErrBridgeShareTableMismatch)
	}
	// every target's host must still stand with the key the table sealed
	destinations := []string{}
	// what the grant's sealed detail names: each target's prefix, as the approver saw it
	prefixes := []string{}
	for _, target := range opened.Targets.GetTargets() {
		host, err := IdFromBytes(target.GetHostSidecarId())
		if err != nil {
			return nil, fmt.Errorf("%w: a target with no host", ErrBridgeFileRefused)
		}
		row := acts.view.state.SidecarRow(host)
		if row == nil || row.GetRevokedAt() != 0 || !bytes.Equal(row.GetIdentityPublicKey(), target.GetHostIdentityPublicKey()) {
			return nil, fmt.Errorf("%w: target %d's host no longer stands as the table sealed it", ErrBridgeFileRefused, target.GetIndex())
		}
		destination := "sidecar:" + hex.EncodeToString(host.Bytes())
		if !slices.Contains(destinations, destination) {
			destinations = append(destinations, destination)
		}
		prefix, err := bridgePrefixOf(target.GetPrefix())
		if err != nil {
			return nil, fmt.Errorf("%w: target %d's prefix", ErrBridgeFileRefused, target.GetIndex())
		}
		if detail := "ip:" + prefix.String(); !slices.Contains(prefixes, detail) {
			prefixes = append(prefixes, detail)
		}
	}
	slices.Sort(destinations)
	slices.Sort(prefixes)
	now := self.clock.Now()
	expiresMs := int64(0)
	if 0 < lifetime {
		expiresMs = now.Add(lifetime).UnixMilli()
	}
	grantId, approvalId := record.GrantId, record.ApprovalId
	if len(grantId) == 0 || !bridgeShareGrantStands(grants, grantId, now) {
		// a share's grant is a dial grant (§8.11; QD-820): the forward kind's, naming the other network, its detail sealed
		detail := &protocol.CanonicalActionDetail{GrantDst: prefixes}
		fresh, err := grants.Action(ctx, &protocol.CanonicalAction{Kind: uint32(SidecarActionForward)}, &AclGrantRequest{
			Subject: acts.view.self, GrantDst: destinations, GrantAllow: []string{"dial"}, ExpiresMs: expiresMs,
			Detail:         detail,
			ShareNetworkId: opened.AcceptingNetworkId,
		}, now)
		if err != nil {
			return nil, err
		}
		stored, err := self.shareGrantAction(origin, opened.ShareId, record, fresh, detail, lifetime, now)
		if err != nil {
			return nil, err
		}
		effect := &bridgeShareGrantEffect{inner: grants.Effect(stored)}
		action, err := self.newAction(origin, stored, effect, nil)
		if err != nil {
			return nil, err
		}
		if grantId, err = self.authorize(ctx, origin, action); err != nil {
			return nil, err
		}
		if len(grantId) == 0 {
			return nil, fmt.Errorf("%w: the share's grant answered no id", ErrBridgeFileUncertain)
		}
		approvalId = effect.approvalId
		record.GrantId, record.ApprovalId = bytes.Clone(grantId), approvalId
		if err := self.saveRecord(bridgeShareInviteRecordName(opened.ShareId), record); err != nil {
			return nil, fmt.Errorf("%w: the share's grant was not kept: %w", ErrBridgeFileUncertain, err)
		}
	}
	pin := &bridge.BridgeShareGrant{
		ShareId: opened.ShareId.Bytes(), GrantId: bytes.Clone(grantId), SharePublicKey: bytes.Clone(opened.SharePublicKey),
		TargetTableSha256: bytes.Clone(opened.TargetTableSha256), TableKey: bytes.Clone(record.TableKey),
		AcceptingNetworkId: opened.AcceptingNetworkId.Bytes(), AliasTableSha256: bytes.Clone(opened.AliasTableSha256),
		TargetTableVersion: opened.TargetTableVersion, AliasTableVersion: opened.AliasTableVersion,
	}
	if err := CheckBridgeShareGrant(pin); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	pinBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(pin)
	if err != nil {
		return nil, err
	}
	path := ConfigHeadBridgeShareGrantPath(opened.ShareId)
	if acts.view.head == nil || !bytes.Equal(acts.view.head.File(path), pinBytes) {
		testHookBarrier("bridge_share.grant_file.before", opened.ShareId.String())
		_, err = writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
			return head.WithFile(path, pinBytes)
		})
		testHookBarrier("bridge_share.grant_file.after", opened.ShareId.String())
		if err != nil {
			// the grant stands and pins nothing: no host compiles the share until a second call writes the file
			return nil, fmt.Errorf("%w: the share's pins did not land: %w", ErrBridgeFileUncertain, err)
		}
	}
	return &BridgeFiling{GrantId: grantId, ApprovalId: approvalId}, nil
}

// Whether the installed state holds grantId as a rule in force at now: a share's grant that was revoked or ended no
// longer stands, and the activation asked again asks for a new one.
func bridgeShareGrantStands(grants *AclGrantFiler, grantId []byte, now time.Time) bool {
	state := grants.engine.State()
	if state == nil {
		return false
	}
	rule := state.grantRule(grantId)
	return rule != nil && rule.activeAt(now.UnixMilli())
}

// The share's grant action to present (the file's ActivateShare row): the one its request was filed with, kept in
// record, while its expiry is ahead, it was asked for the same lifetime, and fresh, the action built now, differs from
// it in its expiry and its detail's seal alone, the detail sealed in it opening to detail; and while the grant a
// decision on it activated has not ended. Else fresh, kept in record in its place before the gate files its request.
// A kept action that does not parse or open is not presented, the closed direction: its request is filed afresh.
func (self *BridgeFiler) shareGrantAction(origin *BridgeFileOrigin, shareId Id, record *bridgeShareInviteRecord, fresh *StoredCanonicalAction,
	detail *protocol.CanonicalActionDetail, lifetime time.Duration, now time.Time) (*StoredCanonicalAction, error) {
	kept := func() *StoredCanonicalAction {
		if len(record.GrantAction) == 0 || record.GrantLifetimeMs != lifetime.Milliseconds() {
			return nil
		}
		kept, err := ParseStoredCanonicalAction(record.GrantAction)
		if err != nil || kept.Action.GetExpiresMillis() <= now.UnixMilli() || fresh.Action.GetExpiresMillis() < kept.Action.GetExpiresMillis() {
			return nil
		}
		freshAsKept := proto.Clone(fresh.Action).(*protocol.CanonicalAction)
		freshAsKept.ExpiresMillis, freshAsKept.SealedDetail = kept.Action.GetExpiresMillis(), kept.Action.GetSealedDetail()
		if !proto.Equal(kept.Action, freshAsKept) {
			return nil
		}
		opened, err := self.args.Sidecar.OpenActionDetail(kept)
		if err != nil || !proto.Equal(opened, detail) {
			return nil
		}
		if self.args.Grants.grantEnded(kept, nil, origin.RunId, origin.AgentId, now) {
			return nil
		}
		return kept
	}()
	if kept != nil {
		return kept, nil
	}
	record.GrantAction, record.GrantLifetimeMs = bytes.Clone(fresh.Bytes), lifetime.Milliseconds()
	if err := self.saveRecord(bridgeShareInviteRecordName(shareId), record); err != nil {
		return nil, fmt.Errorf("%w: the share's grant action was not kept: %w", ErrBridgeFileUncertain, err)
	}
	return fresh, nil
}

// The grant component's effect for a share, noting the decision it spent under.
type bridgeShareGrantEffect struct {
	inner      SidecarEffect
	approvalId Id
}

// The grant component's Run, with the spend's approval noted.
func (self *bridgeShareGrantEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if spend, ok := ApprovalSpendFromContext(ctx); ok {
		self.approvalId = spend.ApprovalId
	}
	return self.inner.Run(ctx, effectKey)
}

// Ends a share this network gave (the file's RevokeShare row): the GrantRevoke of the grant its pin file names.
func (self *BridgeFiler) RevokeShare(ctx context.Context, origin *BridgeFileOrigin, shareId Id) (*BridgeFiling, error) {
	acts, err := self.shareActs(ctx, origin)
	if err != nil {
		return nil, err
	}
	if self.args.Grants == nil {
		return nil, fmt.Errorf("%w: no grant filer", ErrBridgeFileRefused)
	}
	for _, pin := range ReadBridgeShareGrants(acts.view.head) {
		if !bytes.Equal(pin.GetShareId(), shareId.Bytes()) {
			continue
		}
		if err := self.args.Grants.Revoke(ctx, pin.GetGrantId(), origin.Act, origin.Check); err != nil {
			return nil, err
		}
		return &BridgeFiling{GrantId: bytes.Clone(pin.GetGrantId())}, nil
	}
	return nil, fmt.Errorf("%w: this network's config pins no such share", ErrBridgeFileRefused)
}

// Ends a share this network accepted (the file's ReleaseShare row): each alias it holds is released and drains.
// Answers how many were released.
func (self *BridgeFiler) ReleaseShare(ctx context.Context, origin *BridgeFileOrigin, shareId Id) (int, error) {
	acts, err := self.shareActs(ctx, origin)
	if err != nil {
		return 0, err
	}
	held := bridgeShareAliasesHeld(acts.view.ledger, shareId)
	if len(held) == 0 {
		return 0, fmt.Errorf("%w: this network holds no alias of the share", ErrBridgeFileRefused)
	}
	if err := self.releaseAliases(ctx, origin, acts, held); err != nil {
		return 0, err
	}
	return len(held), nil
}
