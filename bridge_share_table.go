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
// wrote (BridgeShareGrant; bridge_share_open.go, which every leg links). BridgeShareTableView fetches the rows off the
// compile path and keeps the newest of each, so a compile reads memory alone (BridgeCompileLocal.ShareTables). Safe for
// concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

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

// What a table view fetches a share's row from: SidecarApi, or the component's generation-following adapter.
type BridgeShareRowSource interface {
	GetBridgeShare(ctx context.Context, shareId Id) (*BridgeShareRow, error)
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

// POST /acl/accept-invite with wire, a claim or a completion, answered with the share's row.
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

// Tunables of a table view.
type BridgeShareTableViewSettings struct {
	// How long one share's fetch may take: 30 s. Non-positive is the default.
	FetchTimeout time.Duration
	// The most shares a view keeps rows for, the oldest fetched dropped first: 1,024. Non-positive is the default.
	ShareMaxCount int
}

// The values above.
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
	api      BridgeShareRowSource
	settings *BridgeShareTableViewSettings

	stateLock sync.Mutex
	rows      map[Id]*BridgeShareRow
	// fetch order, oldest first
	order []Id
}

// A view fetching through api; settings nil is the defaults.
func NewBridgeShareTableView(api BridgeShareRowSource, settings *BridgeShareTableViewSettings) (*BridgeShareTableView, error) {
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

// Keeps row as the share's newest.
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

// Forgets the share's row.
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
