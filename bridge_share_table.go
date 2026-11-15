//go:build !ios_extension

// A share's row at api and what a host makes of it (BRIDGE-M6-03; §17.9's share pins, §17.16; DESIGN-DETAILS 12.2.7;
// QD-077, QD-670; I-2).
//
// network_bridge_share holds, for each share, X's target table and Y's side, each sealed under K, with their versions
// and the accept status, and nothing else: no prefix, address or key in the clear (§2.8's api-9). The routes here are
// the four that read and write it:
//
//	POST /acl/invite                       X files a code's SHA-256 and its sealed targets -> share_id
//	POST /acl/accept-invite  (claim)       Y names the code's hash -> the share, X's sealed targets with it
//	POST /acl/accept-invite  (complete)    Y files its side and the accept status, once
//	GET  /network/bridge/share/<share_id>  both sides, to a sidecar of either network
//
// A host of the sharing network compiles a share only from tables that hash to the pins its network's approving admin
// wrote (BridgeShareGrant): OpenBridgeShareTables holds a row to them, opens it under K and checks the alias table
// against the target table. A row at another hash or version than the pin is ErrBridgeShareTableMismatch, which the
// compile ignores with bridge_alarm share_table_mismatch: the server holds the row, so what it serves is trusted
// for nothing the pins do not fix.
//
// BridgeShareTableView fetches the rows off the compile path and keeps the newest of each, so a compile reads memory
// alone. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A share's row is not what the share's grant file pins: another hash or version of a table, another accepting
	// network, or another ShareKey. The row is ignored (bridge_alarm share_table_mismatch).
	ErrBridgeShareTableMismatch = errors.New("bridge share table is not the one pinned")
)

// network_bridge_share.accept_status (§17.9's status row). Format values.
type BridgeShareAcceptStatus string

const (
	BridgeShareAcceptStatusActive          BridgeShareAcceptStatus = "active"
	BridgeShareAcceptStatusRefusedTooLarge BridgeShareAcceptStatus = "refused_too_large"
	BridgeShareAcceptStatusRefusedNoSpace  BridgeShareAcceptStatus = "refused_no_space"
)

// One share's row as api answers it. Every table is ciphertext under K.
type BridgeShareRow struct {
	ShareId Id
	// X, the network whose targets are shared, and Y, the zero id before a claim binds one.
	SharingNetworkId   Id
	AcceptingNetworkId Id
	// X's sealed BridgeShareTargets and its version.
	TargetTable        []byte
	TargetTableVersion uint64
	// Y's side, a marshalled BridgeShareAccept of seals, and its version; nil before Y completes.
	AliasTable        []byte
	AliasTableVersion uint64
	// Empty before Y completes.
	AcceptStatus BridgeShareAcceptStatus
}

// POST /acl/invite's arguments.
type BridgeShareInviteArgs struct {
	// SHA-256 of the invite's code.
	CodeHash []byte
	// How many networks may accept it, at least 1.
	UseCount int
	// How long it stays open; 0 takes the server's 7 days.
	Window time.Duration
	// The sealed BridgeShareTargets, at version 1.
	TargetTable []byte
}

// POST /acl/invite's answer.
type BridgeShareInviteReply struct {
	ShareId    Id
	UseCount   int
	ExpireTime time.Time
}

// The share routes a filer and a table view call: SidecarApi is one, and tests pass a fake.
type BridgeShareApi interface {
	InviteBridgeShare(ctx context.Context, args *BridgeShareInviteArgs) (*BridgeShareInviteReply, error)
	// A claim: names the code's hash alone. A claim the same network repeats answers the share it holds.
	ClaimBridgeShare(ctx context.Context, codeHash []byte) (*BridgeShareRow, error)
	// A completion: the accepting side and its status, stored once.
	CompleteBridgeShare(ctx context.Context, shareId Id, aliasTable []byte, version uint64, status BridgeShareAcceptStatus) (*BridgeShareRow, error)
	GetBridgeShare(ctx context.Context, shareId Id) (*BridgeShareRow, error)
}

var _ BridgeShareApi = (*SidecarApi)(nil)

// POST /acl/invite's body.
type bridgeShareInviteWire struct {
	CodeHash           []byte `json:"code_hash"`
	UseCount           int    `json:"use_count"`
	WindowSeconds      int64  `json:"window_seconds,omitempty"`
	TargetTable        []byte `json:"target_table"`
	TargetTableVersion int64  `json:"target_table_version"`
}

// POST /acl/invite's answer.
type bridgeShareInviteReplyWire struct {
	ShareId    *Id        `json:"share_id"`
	UseCount   int        `json:"use_count"`
	ExpireTime *time.Time `json:"expire_time"`
}

// POST /acl/accept-invite's body: a claim's code hash, or a completion's share and side.
type bridgeShareAcceptWire struct {
	CodeHash          []byte `json:"code_hash,omitempty"`
	ShareId           *Id    `json:"share_id,omitempty"`
	AliasTable        []byte `json:"alias_table,omitempty"`
	AliasTableVersion int64  `json:"alias_table_version,omitempty"`
	AcceptStatus      string `json:"accept_status,omitempty"`
}

// A share's row as GET /network/bridge/share/<share_id> and POST /acl/accept-invite answer it.
type bridgeShareRowWire struct {
	ShareId            *Id    `json:"share_id"`
	NetworkId          *Id    `json:"network_id"`
	InvitedNetworkId   *Id    `json:"invited_network_id"`
	TargetTable        []byte `json:"target_table"`
	TargetTableVersion int64  `json:"target_table_version"`
	AliasTable         []byte `json:"alias_table"`
	AliasTableVersion  int64  `json:"alias_table_version"`
	AcceptStatus       string `json:"accept_status"`
}

// The row a reply carries, refusing one that names no share, no sharing network, no target table, or a status api
// never stores.
func (self *bridgeShareRowWire) row(route string) (*BridgeShareRow, error) {
	if self.ShareId == nil || *self.ShareId == (Id{}) || self.NetworkId == nil || *self.NetworkId == (Id{}) ||
		len(self.TargetTable) == 0 || self.TargetTableVersion < 1 || self.AliasTableVersion < 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	row := &BridgeShareRow{
		ShareId: *self.ShareId, SharingNetworkId: *self.NetworkId,
		TargetTable: self.TargetTable, TargetTableVersion: uint64(self.TargetTableVersion),
		AliasTable: self.AliasTable, AliasTableVersion: uint64(self.AliasTableVersion),
		AcceptStatus: BridgeShareAcceptStatus(self.AcceptStatus),
	}
	if self.InvitedNetworkId != nil {
		row.AcceptingNetworkId = *self.InvitedNetworkId
	}
	switch row.AcceptStatus {
	case "", BridgeShareAcceptStatusActive, BridgeShareAcceptStatusRefusedTooLarge, BridgeShareAcceptStatusRefusedNoSpace:
	default:
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return row, nil
}

// POST /acl/invite (§8.11): files the invite's hashed code and X's sealed targets, and answers the share's id.
func (self *SidecarApi) InviteBridgeShare(ctx context.Context, args *BridgeShareInviteArgs) (*BridgeShareInviteReply, error) {
	route := "POST /acl/invite"
	if args == nil || len(args.CodeHash) != sha256.Size || args.UseCount < 1 || args.Window < 0 || len(args.TargetTable) == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &bridgeShareInviteReplyWire{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route: route, operation: "acl_invite", method: "POST", url: self.settings.ApiUrl + "/acl/invite", bearer: true,
	}, &bridgeShareInviteWire{
		CodeHash: args.CodeHash, UseCount: args.UseCount, WindowSeconds: int64(args.Window / time.Second),
		TargetTable: args.TargetTable, TargetTableVersion: 1,
	}, reply)
	if err != nil {
		return nil, err
	}
	if reply.ShareId == nil || *reply.ShareId == (Id{}) || reply.ExpireTime == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return &BridgeShareInviteReply{ShareId: *reply.ShareId, UseCount: reply.UseCount, ExpireTime: *reply.ExpireTime}, nil
}

// POST /acl/accept-invite, a claim (§8.11): binds this network to a share of the code and answers it.
func (self *SidecarApi) ClaimBridgeShare(ctx context.Context, codeHash []byte) (*BridgeShareRow, error) {
	route := "POST /acl/accept-invite"
	if len(codeHash) != sha256.Size {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	return self.acceptBridgeShare(ctx, route, "acl_accept_invite_claim", &bridgeShareAcceptWire{CodeHash: codeHash})
}

// POST /acl/accept-invite, a completion (§8.11): files this network's side of a share it claimed, once.
func (self *SidecarApi) CompleteBridgeShare(ctx context.Context, shareId Id, aliasTable []byte, version uint64, status BridgeShareAcceptStatus) (*BridgeShareRow, error) {
	route := "POST /acl/accept-invite"
	if shareId == (Id{}) || len(aliasTable) == 0 || version < 1 || status == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	return self.acceptBridgeShare(ctx, route, "acl_accept_invite_complete", &bridgeShareAcceptWire{
		ShareId: &shareId, AliasTable: aliasTable, AliasTableVersion: int64(version), AcceptStatus: string(status),
	})
}

func (self *SidecarApi) acceptBridgeShare(ctx context.Context, route string, operation string, wire *bridgeShareAcceptWire) (*BridgeShareRow, error) {
	reply := &bridgeShareRowWire{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route: route, operation: operation, method: "POST", url: self.settings.ApiUrl + "/acl/accept-invite", bearer: true,
	}, wire, reply)
	if err != nil {
		return nil, err
	}
	return reply.row(route)
}

// GET /network/bridge/share/<share_id> (§17.16): both sides of a share, to a sidecar of either network.
func (self *SidecarApi) GetBridgeShare(ctx context.Context, shareId Id) (*BridgeShareRow, error) {
	route := "GET /network/bridge/share/<share_id>"
	if shareId == (Id{}) {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &bridgeShareRowWire{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route: route, operation: "bridge_share", method: "GET", url: self.settings.ApiUrl + "/network/bridge/share/" + shareId.String(), bearer: true,
	}, nil, reply)
	if err != nil {
		return nil, err
	}
	row, err := reply.row(route)
	if err != nil {
		return nil, err
	}
	// an answer about another share than the one asked for is not this route's
	if row.ShareId != shareId {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return row, nil
}

// A share's tables, opened under K and held to each other.
type BridgeShareOpened struct {
	ShareId            Id
	SharingNetworkId   Id
	AcceptingNetworkId Id
	Targets            *bridge.BridgeShareTargets
	// One alias a target, by index; nil for a share that was refused or has not completed.
	Aliases *bridge.BridgeShareAliases
	// Y's ShareKey, Ed25519; nil with no aliases.
	SharePublicKey []byte
	// A refusal's figures, nil for an active share.
	Shortfall *bridge.BridgeShareShortfall
	// SHA-256 of each side as the row stores it, and its version: what X's approving admin pins.
	TargetTableSha256  []byte
	TargetTableVersion uint64
	AliasTableSha256   []byte
	AliasTableVersion  uint64
	AcceptStatus       BridgeShareAcceptStatus
}

// Opens a share's row under seal, K for the row's sharing network: the target table, and, once the accepting network
// completed, its side. ErrBridgeShareSeal for anything that does not open, and ErrBridgeShareTableInvalid for tables
// out of form or an alias table that is not its target table's. The row's sharing network must be the seal's.
func OpenBridgeShareRow(seal *BridgeShareSeal, row *BridgeShareRow, settings *BridgeLedgerSettings) (*BridgeShareOpened, error) {
	if seal == nil || row == nil || row.ShareId == (Id{}) {
		return nil, fmt.Errorf("%w: no row", ErrBridgeShareTableInvalid)
	}
	if row.SharingNetworkId != seal.SharingNetworkId() {
		return nil, fmt.Errorf("%w: a row of another sharing network", ErrBridgeShareSeal)
	}
	opened := &BridgeShareOpened{
		ShareId: row.ShareId, SharingNetworkId: row.SharingNetworkId, AcceptingNetworkId: row.AcceptingNetworkId,
		Targets:           &bridge.BridgeShareTargets{},
		TargetTableSha256: BridgeShareTableSha256(row.TargetTable), TargetTableVersion: row.TargetTableVersion,
		AcceptStatus: row.AcceptStatus,
	}
	if err := seal.Open(BridgeShareLabelTargets, Id{}, row.TargetTableVersion, row.TargetTable, opened.Targets); err != nil {
		return nil, err
	}
	if err := CheckBridgeShareTargets(opened.Targets, settings); err != nil {
		return nil, err
	}
	if len(row.AliasTable) == 0 {
		if row.AcceptStatus != "" {
			return nil, fmt.Errorf("%w: a status with no accepting side", ErrBridgeShareTableInvalid)
		}
		return opened, nil
	}
	if row.AcceptingNetworkId == (Id{}) || row.AcceptingNetworkId == row.SharingNetworkId {
		return nil, fmt.Errorf("%w: an accepting side of no other network", ErrBridgeShareTableInvalid)
	}
	opened.AliasTableSha256, opened.AliasTableVersion = BridgeShareTableSha256(row.AliasTable), row.AliasTableVersion
	accept := &bridge.BridgeShareAccept{}
	if err := proto.Unmarshal(row.AliasTable, accept); err != nil || bridgeLedgerUnknownFields(accept) {
		return nil, fmt.Errorf("%w: the accepting side is no BridgeShareAccept", ErrBridgeShareSeal)
	}
	switch row.AcceptStatus {
	case BridgeShareAcceptStatusActive:
		if len(accept.GetAliases()) == 0 || len(accept.GetShareKey()) == 0 || len(accept.GetShortfall()) != 0 {
			return nil, fmt.Errorf("%w: an active accept without its aliases and key", ErrBridgeShareTableInvalid)
		}
		opened.Aliases = &bridge.BridgeShareAliases{}
		if err := seal.Open(BridgeShareLabelAliases, row.AcceptingNetworkId, row.AliasTableVersion, accept.GetAliases(), opened.Aliases); err != nil {
			return nil, err
		}
		if err := CheckBridgeShareAliases(opened.Aliases, opened.Targets); err != nil {
			return nil, err
		}
		keyBody := &bridge.BridgeShareKeyBody{}
		if err := seal.Open(BridgeShareLabelShareKey, row.AcceptingNetworkId, row.AliasTableVersion, accept.GetShareKey(), keyBody); err != nil {
			return nil, err
		}
		if len(keyBody.GetSharePublicKey()) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: a ShareKey of %d bytes", ErrBridgeShareTableInvalid, len(keyBody.GetSharePublicKey()))
		}
		opened.SharePublicKey = keyBody.GetSharePublicKey()
	case BridgeShareAcceptStatusRefusedNoSpace, BridgeShareAcceptStatusRefusedTooLarge:
		// a refusal carries its figures alone: which target, how wide, and the room there was
		if len(accept.GetAliases()) != 0 || len(accept.GetShareKey()) != 0 || len(accept.GetShortfall()) == 0 {
			return nil, fmt.Errorf("%w: a refusal without its shortfall alone", ErrBridgeShareTableInvalid)
		}
		opened.Shortfall = &bridge.BridgeShareShortfall{}
		if err := seal.Open(BridgeShareLabelShortfall, row.AcceptingNetworkId, row.AliasTableVersion, accept.GetShortfall(), opened.Shortfall); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: an accepting side with no status", ErrBridgeShareTableInvalid)
	}
	return opened, nil
}

// Holds a share's row to its grant file's pins and opens it (the file's comment): the file's share, the sharing
// network K was written for, the accepting network, each table's hash and version, and the ShareKey. A share that is
// not active compiles nothing, so it is a mismatch too.
func OpenBridgeShareTables(grant *bridge.BridgeShareGrant, sharingNetworkId Id, row *BridgeShareRow, settings *BridgeShareSettings, ledgerSettings *BridgeLedgerSettings) (*BridgeShareOpened, error) {
	if err := CheckBridgeShareGrant(grant); err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%w: no row", ErrBridgeShareTableMismatch)
	}
	switch {
	case !bytes.Equal(grant.GetShareId(), row.ShareId.Bytes()) || row.SharingNetworkId != sharingNetworkId:
		return nil, fmt.Errorf("%w: another share's row", ErrBridgeShareTableMismatch)
	case !bytes.Equal(grant.GetAcceptingNetworkId(), row.AcceptingNetworkId.Bytes()):
		return nil, fmt.Errorf("%w: another accepting network", ErrBridgeShareTableMismatch)
	case grant.GetTargetTableVersion() != row.TargetTableVersion || !bytes.Equal(grant.GetTargetTableSha256(), BridgeShareTableSha256(row.TargetTable)):
		return nil, fmt.Errorf("%w: the target table", ErrBridgeShareTableMismatch)
	case grant.GetAliasTableVersion() != row.AliasTableVersion || !bytes.Equal(grant.GetAliasTableSha256(), BridgeShareTableSha256(row.AliasTable)):
		return nil, fmt.Errorf("%w: the alias table", ErrBridgeShareTableMismatch)
	case row.AcceptStatus != BridgeShareAcceptStatusActive:
		return nil, fmt.Errorf("%w: a share that is not active", ErrBridgeShareTableMismatch)
	}
	seal, err := NewBridgeShareSealOfKey(grant.GetTableKey(), sharingNetworkId, settings)
	if err != nil {
		return nil, err
	}
	opened, err := OpenBridgeShareRow(seal, row, ledgerSettings)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(opened.SharePublicKey, grant.GetSharePublicKey()) {
		return nil, fmt.Errorf("%w: another ShareKey", ErrBridgeShareTableMismatch)
	}
	return opened, nil
}

// A grant file held to its form: ids of 16 bytes, a grant id and hashes of 32, K, an Ed25519 ShareKey and versions
// from 1.
func CheckBridgeShareGrant(grant *bridge.BridgeShareGrant) error {
	switch {
	case grant == nil || bridgeLedgerUnknownFields(grant):
		return fmt.Errorf("%w: no grant file this build reads", ErrBridgeShareTableInvalid)
	case len(grant.GetShareId()) != len(Id{}) || len(grant.GetAcceptingNetworkId()) != len(Id{}):
		return fmt.Errorf("%w: a grant file's ids", ErrBridgeShareTableInvalid)
	case len(grant.GetGrantId()) != sha256.Size || len(grant.GetTargetTableSha256()) != sha256.Size || len(grant.GetAliasTableSha256()) != sha256.Size:
		return fmt.Errorf("%w: a grant file's grant or hashes", ErrBridgeShareTableInvalid)
	case len(grant.GetTableKey()) != bridgeShareKeyByteCount || len(grant.GetSharePublicKey()) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: a grant file's keys", ErrBridgeShareTableInvalid)
	case grant.GetTargetTableVersion() == 0 || grant.GetAliasTableVersion() == 0:
		return fmt.Errorf("%w: a grant file's versions", ErrBridgeShareTableInvalid)
	}
	return nil
}

// bridge/share-grant/<share_id hex>, the path of a share's grant file in the sharing network's head.
func ConfigHeadBridgeShareGrantPath(shareId Id) string {
	return ConfigHeadBridgeShareGrantPrefix + fmt.Sprintf("%x", shareId.Bytes())
}

// The grant files a head holds, by share id in path order. A file that is no BridgeShareGrant of its path's share is
// left out: it pins nothing.
func ReadBridgeShareGrants(head *ConfigHead) []*bridge.BridgeShareGrant {
	if head == nil {
		return nil
	}
	grants := []*bridge.BridgeShareGrant{}
	paths := head.Paths()
	slices.Sort(paths)
	for _, path := range paths {
		if len(path) != len(ConfigHeadBridgeShareGrantPrefix)+configHeadShareIdHexLength || path[:len(ConfigHeadBridgeShareGrantPrefix)] != ConfigHeadBridgeShareGrantPrefix {
			continue
		}
		grant := &bridge.BridgeShareGrant{}
		if err := proto.Unmarshal(head.File(path), grant); err != nil || CheckBridgeShareGrant(grant) != nil {
			continue
		}
		shareId, err := IdFromBytes(grant.GetShareId())
		if err != nil || ConfigHeadBridgeShareGrantPath(shareId) != path {
			continue
		}
		grants = append(grants, grant)
	}
	return grants
}

// Tunables of a table view.
type BridgeShareTableViewSettings struct {
	// How long one share's fetch may take: 30 s. Non-positive is the default.
	FetchTimeout time.Duration
	// The most shares a view keeps rows for, the oldest fetched dropped first: 1,024. Non-positive is the default.
	ShareMaxCount int
}

func DefaultBridgeShareTableViewSettings() *BridgeShareTableViewSettings {
	return &BridgeShareTableViewSettings{
		FetchTimeout:  30 * time.Second,
		ShareMaxCount: 1024,
	}
}

// The shares' rows a host's compile reads, fetched off the compile path (the file's comment; DESIGN-DETAILS 12.2.7's
// local.ShareTables): a component refreshes it each ShareTableRefreshInterval and when a head names a share it holds no
// row for. Nothing here is trusted: the compile holds every row to its grant file's pins.
type BridgeShareTableView struct {
	api      BridgeShareApi
	settings *BridgeShareTableViewSettings

	stateLock sync.Mutex
	rows      map[Id]*BridgeShareRow
	// fetch order, oldest first
	order []Id
}

// A view fetching through api; settings nil is the defaults.
func NewBridgeShareTableView(api BridgeShareApi, settings *BridgeShareTableViewSettings) (*BridgeShareTableView, error) {
	if api == nil {
		return nil, fmt.Errorf("%w: a table view needs the share routes", errInvalidSettings)
	}
	defaults := DefaultBridgeShareTableViewSettings()
	read := *defaults
	if settings != nil {
		if 0 < settings.FetchTimeout {
			read.FetchTimeout = settings.FetchTimeout
		}
		if 0 < settings.ShareMaxCount {
			read.ShareMaxCount = settings.ShareMaxCount
		}
	}
	return &BridgeShareTableView{api: api, settings: &read, rows: map[Id]*BridgeShareRow{}}, nil
}

// Fetches each share's row again and keeps it. A share api no longer holds, a 404, is dropped: it was revoked. Any
// other failure keeps the row held and is answered once every share was tried.
func (self *BridgeShareTableView) Refresh(ctx context.Context, shareIds []Id) error {
	var failed error
	for _, shareId := range shareIds {
		fetchCtx, cancel := context.WithTimeout(ctx, self.settings.FetchTimeout)
		row, err := self.api.GetBridgeShare(fetchCtx, shareId)
		cancel()
		var apiErr *SidecarApiError
		switch {
		case err == nil:
			self.keep(row)
		case errors.As(err, &apiErr) && apiErr.Status == 404:
			self.drop(shareId)
		default:
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

func (self *BridgeShareTableView) keep(row *BridgeShareRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, held := self.rows[row.ShareId]; held {
		self.order = slices.DeleteFunc(self.order, func(shareId Id) bool { return shareId == row.ShareId })
	}
	self.rows[row.ShareId] = row
	self.order = append(self.order, row.ShareId)
	for self.settings.ShareMaxCount < len(self.order) {
		delete(self.rows, self.order[0])
		self.order = self.order[1:]
	}
}

func (self *BridgeShareTableView) drop(shareId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.rows, shareId)
	self.order = slices.DeleteFunc(self.order, func(held Id) bool { return held == shareId })
}

// The row held for a share, nil for none. The caller must not change it.
func (self *BridgeShareTableView) Row(shareId Id) *BridgeShareRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.rows[shareId]
}

// Every row held, in share id order: what a compile takes as its ShareTables.
func (self *BridgeShareTableView) Rows() []*BridgeShareRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rows := make([]*BridgeShareRow, 0, len(self.rows))
	for _, row := range self.rows {
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a *BridgeShareRow, b *BridgeShareRow) int { return a.ShareId.Cmp(b.ShareId) })
	return rows
}
