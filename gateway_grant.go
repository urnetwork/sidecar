//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §8.6's grants (R-GW-1, D-GW-3, IC-11, I-7; GW-M12-02): what a harness install may spend through the gateway, kept with
// the SHA-256 of each live token in the network's sealed store, gateway/grants (class gateway), never a token. Nothing
// here reaches a server.
//
//	grant    its harness, its agent label and that label's agent_id (Sidecar.ResolveAgentId), which every call carries
//	         so the broker's per-agent and per-device defaults bind it whatever grants exist locally (§16.4); its model
//	         list, §16.4's globs, empty for every model the person's models key allows; its budget per day and month,
//	         none for the agent's default; its expiry; and its network, whose store holds it. One per harness and agent
//	         label on a network: a second install makes the same grant again, changed as asked
//	make     `ur install-harness <h> --gateway` makes one (GW-M12-07) through the daemon's gateway.grants. A grant's
//	         budget never passes the server's default for its agent: an amount above it is filed as kind 21,
//	         compute_budget_raise, naming the grant (§16.3), for a person to approve on an approval-capable device,
//	         since a same-user process can run ur install-harness too, and the grant stands at the default until the
//	         approved raise comes back. Until the defaults are readable (CACL's view, §16.4) a grant names no budget of
//	         its own and stands at the default, the closed reading
//	list     `ur gateway grants` lists every network's, with each one's live tokens, bound and unbound, and the
//	         command that binds a token to its harness, and revokes one, which ends its tokens at once
//	tokens   each live token's hash, its grant, its expiry and the run handle it is (gateway_bind.go), at most
//	         GrantTokenCount a grant, the oldest dropped first; a hash past its expiry is swept at the next write
//	port     a grant made holds the instance's port (gateway_state.go), drawn where none is; once no grant stands on
//	         any network whose grants read, the port is let go
//
// The store is read once, then served from memory, every change written whole and fsynced before it is answered. While
// the network is locked it reads nothing, so a token is refused, never taken on faith. Safe for concurrent use:
// writeLock orders the rewrites and is held across their fsyncs, before stateLock, which guards memory alone.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

// The store's format version, its directory and class, and its file: format values.
const (
	gatewayGrantFileVersion   = 1
	gatewayGrantDirectoryName = "gateway"
	gatewayGrantClass         = "gateway"
	gatewayGrantFileName      = "grants"
	gatewayGrantsComponent    = "gateway_grants"
)

// gateway.grants' actions.
const (
	GatewayGrantsActionList   = "list"
	GatewayGrantsActionMake   = "make"
	GatewayGrantsActionRevoke = "revoke"
)

// What became of a raise above the default (§16.3).
const (
	GatewayRaiseDone     = ComputeBudgetRaiseDone
	GatewayRaisePending  = ComputeBudgetRaisePending
	GatewayRaiseNotFiled = "not_filed"
)

var (
	// No such grant, or it has expired.
	ErrGatewayGrantUnknown = errors.New("no such gateway grant")
	// A token this store holds no hash of.
	ErrGatewayTokenUnknown = errors.New("not a token of this gateway")
	// A token past its hour.
	ErrGatewayTokenExpired = errors.New("the gateway token has expired")
	// A grant refused as asked.
	ErrGatewayGrantInvalid = errors.New("gateway grant refused")
	// The store's file does not read as one.
	errGatewayGrantFile = errors.New("the gateway's grants do not read")
)

// A grant: see the file header. Nothing in it is secret.
type GatewayGrant struct {
	GrantId    Id     `json:"grant_id"`
	Harness    string `json:"harness"`
	AgentLabel string `json:"agent_label"`
	AgentId    Id     `json:"agent_id"`
	// §16.4's globs; empty for every model the person's models key allows.
	Models []string `json:"models,omitempty"`
	// Nil for the agent's default (§16.4).
	DayNanoUsd   *int64 `json:"day_nano_usd,omitempty"`
	MonthNanoUsd *int64 `json:"month_nano_usd,omitempty"`
	// Raises above the default waiting on kind 21's approval.
	PendingRaises []*GatewayGrantRaise `json:"pending_raises,omitempty"`
	CreatedMillis int64                `json:"created_millis"`
	// 0 for none.
	ExpiresMillis int64 `json:"expires_millis,omitempty"`
	// The run an unbound token's calls record into, made on the first (gateway_bind.go).
	UnboundRunId *Id `json:"unbound_run_id,omitempty"`
}

// A raise above the default waiting on its approval.
type GatewayGrantRaise struct {
	// day or month.
	Period        string `json:"period"`
	AmountNanoUsd int64  `json:"amount_nano_usd"`
	ApprovalId    Id     `json:"approval_id"`
}

// A deep copy.
func (self *GatewayGrant) clone() *GatewayGrant {
	cloned := *self
	cloned.Models = slices.Clone(self.Models)
	if self.DayNanoUsd != nil {
		day := *self.DayNanoUsd
		cloned.DayNanoUsd = &day
	}
	if self.MonthNanoUsd != nil {
		month := *self.MonthNanoUsd
		cloned.MonthNanoUsd = &month
	}
	cloned.PendingRaises = []*GatewayGrantRaise{}
	for _, raise := range self.PendingRaises {
		copied := *raise
		cloned.PendingRaises = append(cloned.PendingRaises, &copied)
	}
	if self.UnboundRunId != nil {
		runId := *self.UnboundRunId
		cloned.UnboundRunId = &runId
	}
	return &cloned
}

// Whether the grant stands at now: it has not expired.
func (self *GatewayGrant) standsAt(now time.Time) bool {
	return self.ExpiresMillis == 0 || now.UnixMilli() < self.ExpiresMillis
}

// Whether name is a model the grant's list admits: every model where the list is empty, which the person's models key
// and the router's checks still bound.
func (self *GatewayGrant) AllowsModel(name string) bool {
	return len(self.Models) == 0 || slices.ContainsFunc(self.Models, func(glob string) bool { return harnessModelsGlobMatch(glob, name) })
}

// A live token as the store keeps it: its hash, never the token.
type GatewayTokenRecord struct {
	Sha256        []byte `json:"sha256"`
	GrantId       Id     `json:"grant_id"`
	MintedMillis  int64  `json:"minted_millis"`
	ExpiresMillis int64  `json:"expires_millis"`
	// Nil for an unbound token.
	Handle *GatewayRunHandle `json:"handle,omitempty"`
}

// A copy.
func (self *GatewayTokenRecord) clone() *GatewayTokenRecord {
	cloned := *self
	cloned.Sha256 = slices.Clone(self.Sha256)
	cloned.Handle = self.Handle.clone()
	return &cloned
}

// The store's file.
type gatewayGrantFile struct {
	Version int                   `json:"version"`
	Grants  []*GatewayGrant       `json:"grants"`
	Tokens  []*GatewayTokenRecord `json:"tokens"`
}

// What a grant is made or changed with. The agent's id is resolved before.
type GatewayGrantArgs struct {
	Harness       string
	AgentLabel    string
	AgentId       Id
	Models        []string
	DayNanoUsd    *int64
	MonthNanoUsd  *int64
	ExpiresMillis int64
}

// What a GatewayGrantStore runs on.
type GatewayGrantStoreArgs struct {
	// The store's sealed directory, reached at each use: an error before enrollment and while the network is locked.
	Store func() (SidecarStore, error)
	// Nil is DefaultGatewaySettings.
	Settings *GatewaySettings
	// Nil is real time.
	Clock Clock
	// Where tokens are drawn from: crypto/rand's reader when nil.
	Random io.Reader
}

// One network's grants and live token hashes: see the file header.
type GatewayGrantStore struct {
	store    func() (SidecarStore, error)
	settings *GatewaySettings
	clock    Clock
	random   io.Reader

	writeLock sync.Mutex

	stateLock  sync.Mutex
	loaded     bool
	grants     []*GatewayGrant
	hashTokens map[[sha256.Size]byte]*GatewayTokenRecord
}

// A store over args, read at its first use.
func NewGatewayGrantStore(args *GatewayGrantStoreArgs) *GatewayGrantStore {
	settings := args.Settings
	if settings == nil {
		settings = DefaultGatewaySettings()
	}
	return &GatewayGrantStore{
		store:      args.Store,
		settings:   settings,
		clock:      clockOrReal(args.Clock),
		random:     args.Random,
		hashTokens: map[[sha256.Size]byte]*GatewayTokenRecord{},
	}
}

// Each Sidecar of a daemon's legs keeps its network's grants (§8.6), as a compute component, so one store holds them in
// memory for the Sidecar's life.
func init() {
	registerComputeComponent(gatewayGrantsComponent, func(sidecar *Sidecar) (*GatewayGrantStore, error) {
		settings := sidecar.settings.Gateway
		if settings == nil {
			settings = DefaultGatewaySettings()
		}
		return NewGatewayGrantStore(&GatewayGrantStoreArgs{
			Store: func() (SidecarStore, error) {
				return sidecar.LocalStore().Directory(gatewayGrantDirectoryName, gatewayGrantClass)
			},
			Settings: settings,
			Clock:    sidecar.settings.Clock,
		}), nil
	}, nil)
}

// This Sidecar's grant store, or why it has none.
func (self *Sidecar) GatewayGrants() (*GatewayGrantStore, error) {
	return sidecarComputeComponent[GatewayGrantStore](self, gatewayGrantsComponent)
}

// Reads the file once, its expired tokens dropped from memory. Absent is empty.
func (self *GatewayGrantStore) ensureLoaded() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	return self.loadWithWriteLock()
}

// The file into memory, under writeLock.
func (self *GatewayGrantStore) loadWithWriteLock() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	if self.store == nil {
		return fmt.Errorf("%w: no store", errGatewayGrantFile)
	}
	store, err := self.store()
	if err != nil {
		return err
	}
	file := &gatewayGrantFile{Version: gatewayGrantFileVersion}
	reader, err := store.Open(gatewayGrantFileName)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return err
	default:
		encoded, readErr := io.ReadAll(io.LimitReader(reader, int64(self.settings.GrantFileByteCount)+1))
		reader.Close()
		if readErr != nil {
			return readErr
		}
		if self.settings.GrantFileByteCount < len(encoded) {
			return fmt.Errorf("%w: past its bound", errGatewayGrantFile)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(file); err != nil || file.Version != gatewayGrantFileVersion {
			return fmt.Errorf("%w: it does not decode", errGatewayGrantFile)
		}
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.grants = file.Grants
	self.hashTokens = map[[sha256.Size]byte]*GatewayTokenRecord{}
	for _, record := range file.Tokens {
		if len(record.Sha256) != sha256.Size || record.ExpiresMillis <= now.UnixMilli() {
			continue
		}
		self.hashTokens[[sha256.Size]byte(record.Sha256)] = record
	}
	self.loaded = true
	return nil
}

// Writes grants and tokens whole, durable when this returns, and then holds them in memory: under writeLock. Tokens
// past their expiry are left out.
func (self *GatewayGrantStore) writeWithWriteLock(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) error {
	now := self.clock.Now().UnixMilli()
	file := &gatewayGrantFile{Version: gatewayGrantFileVersion, Grants: grants, Tokens: []*GatewayTokenRecord{}}
	for hash, record := range hashTokens {
		if record.ExpiresMillis <= now {
			delete(hashTokens, hash)
			continue
		}
		file.Tokens = append(file.Tokens, record)
	}
	slices.SortFunc(file.Tokens, func(a *GatewayTokenRecord, b *GatewayTokenRecord) int {
		return bytes.Compare(a.Sha256, b.Sha256)
	})
	encoded, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if self.settings.GrantFileByteCount < len(encoded) {
		return fmt.Errorf("%w: the grants would pass their file's bound", ErrGatewayGrantInvalid)
	}
	store, err := self.store()
	if err != nil {
		return err
	}
	writer, err := store.Create(gatewayGrantFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.grants, self.hashTokens = grants, hashTokens
	return nil
}

// A change to the store: edit takes copies of the grants and tokens and changes them, and what it leaves is written
// whole and then served. An error from edit writes nothing.
func (self *GatewayGrantStore) change(edit func(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) ([]*GatewayGrant, error)) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.loadWithWriteLock(); err != nil {
		return err
	}
	grants, hashTokens := func() ([]*GatewayGrant, map[[sha256.Size]byte]*GatewayTokenRecord) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		grants := []*GatewayGrant{}
		for _, grant := range self.grants {
			grants = append(grants, grant.clone())
		}
		hashTokens := map[[sha256.Size]byte]*GatewayTokenRecord{}
		for hash, record := range self.hashTokens {
			hashTokens[hash] = record.clone()
		}
		return grants, hashTokens
	}()
	grants, err := edit(grants, hashTokens)
	if err != nil {
		return err
	}
	return self.writeWithWriteLock(grants, hashTokens)
}

// Whether a harness's name is one ur takes: [a-z0-9-], not starting with -, at most HarnessNameByteCount bytes.
func (self *GatewayGrantStore) checkHarness(harness string) error {
	if harness == "" || self.settings.HarnessNameByteCount < len(harness) || harness[0] == '-' {
		return fmt.Errorf("%w: a harness's name is 1 to %d bytes", ErrGatewayGrantInvalid, self.settings.HarnessNameByteCount)
	}
	for i := 0; i < len(harness); i += 1 {
		if c := harness[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return fmt.Errorf("%w: a harness's name is [a-z0-9-]", ErrGatewayGrantInvalid)
		}
	}
	return nil
}

// Makes the grant of args' harness and agent label, or changes the one that stands to args, answering it and whether it
// is new. The caller checked the models' globs and the budgets against the defaults.
func (self *GatewayGrantStore) Make(ctx context.Context, args *GatewayGrantArgs) (*GatewayGrant, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := self.checkHarness(args.Harness); err != nil {
		return nil, false, err
	}
	if args.AgentLabel == "" || args.AgentId == (Id{}) {
		return nil, false, fmt.Errorf("%w: a grant names its agent", ErrGatewayGrantInvalid)
	}
	if self.settings.GrantModelCount < len(args.Models) {
		return nil, false, fmt.Errorf("%w: at most %d model globs", ErrGatewayGrantInvalid, self.settings.GrantModelCount)
	}
	for _, amount := range []*int64{args.DayNanoUsd, args.MonthNanoUsd} {
		if amount != nil && *amount < 0 {
			return nil, false, fmt.Errorf("%w: a budget is not negative", ErrGatewayGrantInvalid)
		}
	}
	now := self.clock.Now()
	if args.ExpiresMillis != 0 && args.ExpiresMillis <= now.UnixMilli() {
		return nil, false, fmt.Errorf("%w: its expiry has passed", ErrGatewayGrantInvalid)
	}
	var made *GatewayGrant
	isNew := false
	err := self.change(func(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) ([]*GatewayGrant, error) {
		index := slices.IndexFunc(grants, func(grant *GatewayGrant) bool {
			return grant.Harness == args.Harness && grant.AgentLabel == args.AgentLabel
		})
		grant := &GatewayGrant{GrantId: NewId(), CreatedMillis: now.UnixMilli()}
		if index < 0 {
			if self.settings.GrantCount <= len(grants) {
				return nil, fmt.Errorf("%w: a network holds at most %d grants", ErrGatewayGrantInvalid, self.settings.GrantCount)
			}
			grants = append(grants, grant)
			isNew = true
		} else {
			grant = grants[index]
		}
		grant.Harness, grant.AgentLabel, grant.AgentId = args.Harness, args.AgentLabel, args.AgentId
		grant.Models = slices.Clone(args.Models)
		grant.DayNanoUsd, grant.MonthNanoUsd = args.DayNanoUsd, args.MonthNanoUsd
		grant.ExpiresMillis = args.ExpiresMillis
		made = grant.clone()
		return grants, nil
	})
	if err != nil {
		return nil, false, err
	}
	return made, isNew, nil
}

// Revokes grantId and every token of it, at once. False where no such grant stood.
func (self *GatewayGrantStore) Revoke(ctx context.Context, grantId Id) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	revoked := false
	err := self.change(func(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) ([]*GatewayGrant, error) {
		kept := slices.DeleteFunc(grants, func(grant *GatewayGrant) bool { return grant.GrantId == grantId })
		revoked = len(kept) < len(grants)
		for hash, record := range hashTokens {
			if record.GrantId == grantId {
				delete(hashTokens, hash)
			}
		}
		return kept, nil
	})
	return revoked, err
}

// A copy of grantId, standing. ErrGatewayGrantUnknown where none stands.
func (self *GatewayGrantStore) Grant(grantId Id) (*GatewayGrant, error) {
	if err := self.ensureLoaded(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, grant := range self.grants {
		if grant.GrantId == grantId && grant.standsAt(now) {
			return grant.clone(), nil
		}
	}
	return nil, ErrGatewayGrantUnknown
}

// The standing grant of harness and agentLabel. ErrGatewayGrantUnknown where none stands.
func (self *GatewayGrantStore) GrantOf(harness string, agentLabel string) (*GatewayGrant, error) {
	if err := self.ensureLoaded(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, grant := range self.grants {
		if grant.Harness == harness && grant.AgentLabel == agentLabel && grant.standsAt(now) {
			return grant.clone(), nil
		}
	}
	return nil, ErrGatewayGrantUnknown
}

// One grant as `ur gateway grants` lists it.
type GatewayGrantView struct {
	NetworkId Id            `json:"network_id"`
	Grant     *GatewayGrant `json:"grant"`
	// Its live tokens, and how many of them are run handles.
	LiveTokenCount  int `json:"live_token_count"`
	BoundTokenCount int `json:"bound_token_count"`
	// The command that, run as the harness's credential command, mints a token bound to the harness.
	BindCommand string `json:"bind_command"`
}

// Every standing grant, oldest first, with its live tokens counted.
func (self *GatewayGrantStore) Views(networkId Id) ([]*GatewayGrantView, error) {
	if err := self.ensureLoaded(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	views := []*GatewayGrantView{}
	for _, grant := range self.grants {
		if !grant.standsAt(now) {
			continue
		}
		view := &GatewayGrantView{NetworkId: networkId, Grant: grant.clone(), BindCommand: GatewayTokenCommand(grant.Harness, grant.AgentLabel)}
		for _, record := range self.hashTokens {
			if record.GrantId != grant.GrantId || record.ExpiresMillis <= now.UnixMilli() {
				continue
			}
			view.LiveTokenCount += 1
			if record.Handle != nil {
				view.BoundTokenCount += 1
			}
		}
		views = append(views, view)
	}
	return views, nil
}

// Whether any grant stands.
func (self *GatewayGrantStore) Standing() (bool, error) {
	if err := self.ensureLoaded(); err != nil {
		return false, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.ContainsFunc(self.grants, func(grant *GatewayGrant) bool { return grant.standsAt(now) }), nil
}

// Mints a token of grantId, the run handle handle, nil for an unbound one: its hash kept, fsynced, before the token is
// answered, the grant's oldest token dropped past GrantTokenCount. The token is answered once and kept nowhere.
func (self *GatewayGrantStore) Mint(ctx context.Context, grantId Id, handle *GatewayRunHandle) (string, *GatewayTokenRecord, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	token, hash, err := newGatewayToken(self.settings, self.random)
	if err != nil {
		return "", nil, err
	}
	now := self.clock.Now()
	record := &GatewayTokenRecord{
		Sha256:        hash[:],
		GrantId:       grantId,
		MintedMillis:  now.UnixMilli(),
		ExpiresMillis: now.Add(self.settings.TokenLife).UnixMilli(),
		Handle:        handle.clone(),
	}
	err = self.change(func(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) ([]*GatewayGrant, error) {
		if !slices.ContainsFunc(grants, func(grant *GatewayGrant) bool { return grant.GrantId == grantId && grant.standsAt(now) }) {
			return nil, ErrGatewayGrantUnknown
		}
		granted := [][sha256.Size]byte{}
		for otherHash, other := range hashTokens {
			if other.GrantId == grantId && now.UnixMilli() < other.ExpiresMillis {
				granted = append(granted, otherHash)
			}
		}
		slices.SortFunc(granted, func(a [sha256.Size]byte, b [sha256.Size]byte) int {
			return cmp.Or(cmp.Compare(hashTokens[a].MintedMillis, hashTokens[b].MintedMillis), bytes.Compare(a[:], b[:]))
		})
		for 0 < len(granted) && self.settings.GrantTokenCount <= len(granted) {
			delete(hashTokens, granted[0])
			granted = granted[1:]
		}
		hashTokens[hash] = record.clone()
		return grants, nil
	})
	if err != nil {
		return "", nil, err
	}
	return token, record, nil
}

// The grant and the record of the token whose SHA-256 is hash: ErrGatewayTokenUnknown for none, ErrGatewayTokenExpired
// for one past its hour, ErrGatewayGrantUnknown where its grant was revoked or expired. The hashes are compared in
// constant time; the map's lookup reads the presented token's hash alone.
func (self *GatewayGrantStore) Authenticate(hash [sha256.Size]byte) (*GatewayGrant, *GatewayTokenRecord, error) {
	if err := self.ensureLoaded(); err != nil {
		return nil, nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, ok := self.hashTokens[hash]
	if !ok || subtle.ConstantTimeCompare(record.Sha256, hash[:]) != 1 {
		return nil, nil, ErrGatewayTokenUnknown
	}
	if record.ExpiresMillis <= now.UnixMilli() {
		return nil, nil, ErrGatewayTokenExpired
	}
	for _, grant := range self.grants {
		if grant.GrantId == record.GrantId && grant.standsAt(now) {
			return grant.clone(), record.clone(), nil
		}
	}
	return nil, nil, ErrGatewayGrantUnknown
}

// The distinct run handles of grantId's live tokens, the newest mint's first.
func (self *GatewayGrantStore) Handles(grantId Id) ([]*GatewayRunHandle, error) {
	if err := self.ensureLoaded(); err != nil {
		return nil, err
	}
	now := self.clock.Now().UnixMilli()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	records := []*GatewayTokenRecord{}
	for _, record := range self.hashTokens {
		if record.GrantId == grantId && record.Handle != nil && now < record.ExpiresMillis {
			records = append(records, record)
		}
	}
	slices.SortFunc(records, func(a *GatewayTokenRecord, b *GatewayTokenRecord) int {
		return cmp.Or(cmp.Compare(b.MintedMillis, a.MintedMillis), bytes.Compare(a.Sha256, b.Sha256))
	})
	handles := []*GatewayRunHandle{}
	for _, record := range records {
		if !slices.ContainsFunc(handles, func(handle *GatewayRunHandle) bool { return handle.Key() == record.Handle.Key() }) {
			handles = append(handles, record.Handle.clone())
		}
	}
	return handles, nil
}

// The run handle of key among grantId's live tokens. ErrGatewayTokenUnknown where none of them is it.
func (self *GatewayGrantStore) HandleOf(grantId Id, key string) (*GatewayRunHandle, error) {
	handles, err := self.Handles(grantId)
	if err != nil {
		return nil, err
	}
	for _, handle := range handles {
		if handle.Key() == key {
			return handle, nil
		}
	}
	return nil, ErrGatewayTokenUnknown
}

// Notes the run grantId's unbound calls record into; one noted already stands.
func (self *GatewayGrantStore) SetUnboundRun(ctx context.Context, grantId Id, runId Id) error {
	return self.change(func(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) ([]*GatewayGrant, error) {
		index := slices.IndexFunc(grants, func(grant *GatewayGrant) bool { return grant.GrantId == grantId })
		if index < 0 {
			return nil, ErrGatewayGrantUnknown
		}
		if grants[index].UnboundRunId == nil {
			grants[index].UnboundRunId = &runId
		}
		return grants, nil
	})
}

// Notes what became of a raise of grantId's period to amount: pending, with its approval, until the approved raise comes
// back, which sets the budget and drops the pending one.
func (self *GatewayGrantStore) noteRaise(ctx context.Context, grantId Id, period string, amount int64, approvalId *Id) error {
	return self.change(func(grants []*GatewayGrant, hashTokens map[[sha256.Size]byte]*GatewayTokenRecord) ([]*GatewayGrant, error) {
		index := slices.IndexFunc(grants, func(grant *GatewayGrant) bool { return grant.GrantId == grantId })
		if index < 0 {
			return nil, ErrGatewayGrantUnknown
		}
		grant := grants[index]
		grant.PendingRaises = slices.DeleteFunc(grant.PendingRaises, func(raise *GatewayGrantRaise) bool { return raise.Period == period })
		switch {
		case approvalId != nil:
			grant.PendingRaises = append(grant.PendingRaises, &GatewayGrantRaise{Period: period, AmountNanoUsd: amount, ApprovalId: *approvalId})
		case period == gatewayBudgetDay:
			grant.DayNanoUsd = &amount
		case period == gatewayBudgetMonth:
			grant.MonthNanoUsd = &amount
		}
		return grants, nil
	})
}

// The periods a grant's budget names (§16.4).
const (
	gatewayBudgetDay   = "day"
	gatewayBudgetMonth = "month"
)

// The server's default budgets for an agent (§16.4).
type GatewayBudgetCaps struct {
	DayNanoUsd   int64 `json:"day_nano_usd"`
	MonthNanoUsd int64 `json:"month_nano_usd"`
}

// What a grant's make asks (gateway.grants' params), each field as its action needs it.
type GatewayGrantsParams struct {
	// list, the default, make or revoke.
	Action string `json:"action,omitempty"`
	// make's network argument, as §5.8 resolves one; list's, to list one network's alone.
	Network string `json:"network,omitempty"`
	// revoke's.
	GrantId *Id `json:"grant_id,omitempty"`
	// make's.
	Harness string `json:"harness,omitempty"`
	// make's agent label, the harness's name where empty.
	Agent         string   `json:"agent,omitempty"`
	Models        []string `json:"models,omitempty"`
	DayNanoUsd    *int64   `json:"day_nano_usd,omitempty"`
	MonthNanoUsd  *int64   `json:"month_nano_usd,omitempty"`
	ExpiresMillis int64    `json:"expires_millis,omitempty"`
}

// What became of one raise a make asked.
type GatewayGrantRaiseOutcome struct {
	Period         string `json:"period"`
	AmountNanoUsd  int64  `json:"amount_nano_usd"`
	DefaultNanoUsd int64  `json:"default_nano_usd"`
	// done, approval_pending or not_filed.
	Outcome    string `json:"outcome"`
	ApprovalId *Id    `json:"approval_id,omitempty"`
	// Why it was not filed.
	Reason string `json:"reason,omitempty"`
}

// gateway.grants' answer.
type GatewayGrantsReply struct {
	Grants []*GatewayGrantView `json:"grants,omitempty"`
	// A make's raises above the default.
	Raises []*GatewayGrantRaiseOutcome `json:"raises,omitempty"`
	// A revoke's.
	Revoked bool `json:"revoked,omitempty"`
	// Each network whose grants do not read now, and why.
	Unread []string `json:"unread,omitempty"`
}

// Every hosted network's grants; a network whose grants do not read is named in Unread, never read as none.
func (self *GatewayServer) ListGrants(network string, hello *DaemonHello) (*GatewayGrantsReply, error) {
	hosts := self.gatewayHosts()
	reply := &GatewayGrantsReply{}
	if hosts == nil {
		return reply, nil
	}
	only := Id{}
	if network != "" {
		networkId, err := hosts.ResolveNetwork(hello, network)
		if err != nil {
			return nil, err
		}
		only = networkId
	}
	for _, hosted := range hosts.GatewayNetworks() {
		if only != (Id{}) && hosted.NetworkId != only {
			continue
		}
		store, err := hosted.Network.GatewayGrants()
		var views []*GatewayGrantView
		if err == nil {
			views, err = store.Views(hosted.NetworkId)
		}
		if err != nil {
			reply.Unread = append(reply.Unread, fmt.Sprintf("network %s: %s", hosted.NetworkId, err))
			continue
		}
		reply.Grants = append(reply.Grants, views...)
	}
	return reply, nil
}

// Makes or changes the grant params asks on the network it names (§8.6): its agent's id resolved, its globs checked, a
// budget above the agent's default filed as kind 21 and left at the default until approved, and the port held.
func (self *GatewayServer) MakeGrant(ctx context.Context, hello *DaemonHello, params *GatewayGrantsParams) (*GatewayGrantsReply, error) {
	hosts := self.gatewayHosts()
	if hosts == nil {
		return nil, fmt.Errorf("%w: no network is hosted", ErrGatewayGrantInvalid)
	}
	networkId, err := hosts.ResolveNetwork(hello, params.Network)
	if err != nil {
		return nil, err
	}
	network := gatewayHostedNetwork(hosts, networkId)
	if network == nil {
		return nil, fmt.Errorf("%w: network %s is not hosted", ErrGatewayGrantInvalid, networkId)
	}
	store, err := network.GatewayGrants()
	if err != nil {
		return nil, err
	}
	agentLabel := params.Agent
	if agentLabel == "" {
		agentLabel = params.Harness
	}
	agentId, err := network.ResolveAgentId(agentLabel)
	if err != nil {
		return nil, err
	}
	limits := &harnessModelsLimits{settings: self.modelsKey, infer: self.infer, strict: true}
	if err := limits.checkAllow(params.Models); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGatewayGrantInvalid, err)
	}
	type raiseAsk struct {
		period   string
		amount   int64
		fallback int64
	}
	day, month := params.DayNanoUsd, params.MonthNanoUsd
	asks := []*raiseAsk{}
	if day != nil || month != nil {
		if self.budgetDefaults == nil {
			return nil, fmt.Errorf("%w: a grant's budget never passes its agent's default, which is not readable yet (CACL's view, §16.4): make the grant with the agent's default", ErrGatewayGrantInvalid)
		}
		caps, err := self.budgetDefaults(ctx, network, agentId)
		if err != nil {
			return nil, err
		}
		for _, period := range []struct {
			name     string
			amount   **int64
			fallback int64
		}{{name: gatewayBudgetDay, amount: &day, fallback: caps.DayNanoUsd}, {name: gatewayBudgetMonth, amount: &month, fallback: caps.MonthNanoUsd}} {
			if *period.amount == nil || **period.amount <= period.fallback {
				continue
			}
			// above the default: the grant stands at the default until the person approves the raise
			asks = append(asks, &raiseAsk{period: period.name, amount: **period.amount, fallback: period.fallback})
			*period.amount = nil
		}
	}
	grant, _, err := store.Make(ctx, &GatewayGrantArgs{
		Harness:       params.Harness,
		AgentLabel:    agentLabel,
		AgentId:       agentId,
		Models:        params.Models,
		DayNanoUsd:    day,
		MonthNanoUsd:  month,
		ExpiresMillis: params.ExpiresMillis,
	})
	if err != nil {
		return nil, err
	}
	reply := &GatewayGrantsReply{}
	for _, ask := range asks {
		outcome := &GatewayGrantRaiseOutcome{Period: ask.period, AmountNanoUsd: ask.amount, DefaultNanoUsd: ask.fallback}
		reply.Raises = append(reply.Raises, outcome)
		result, err := self.raiseBudget(ctx, network, &ComputeBudgetRaiseArgs{
			GrantId:        &grant.GrantId,
			Period:         ask.period,
			AmountNanoUsd:  ask.amount,
			CurrentNanoUsd: ask.fallback,
			Summary:        fmt.Sprintf("the gateway grant of %s, agent %s", grant.Harness, grant.AgentLabel),
		})
		switch {
		case err != nil:
			outcome.Outcome, outcome.Reason = GatewayRaiseNotFiled, err.Error()
			continue
		case result.Outcome == ComputeBudgetRaisePending && result.ApprovalId != nil:
			outcome.Outcome, outcome.ApprovalId = GatewayRaisePending, result.ApprovalId
		case result.Outcome == ComputeBudgetRaiseDone:
			outcome.Outcome = GatewayRaiseDone
		default:
			outcome.Outcome, outcome.Reason = GatewayRaiseNotFiled, fmt.Sprintf("the raise answered %q", result.Outcome)
			continue
		}
		if err := store.noteRaise(ctx, grant.GrantId, ask.period, ask.amount, outcome.ApprovalId); err != nil {
			return nil, err
		}
	}
	if err := self.holdPort(); err != nil {
		return nil, err
	}
	views, err := store.Views(networkId)
	if err != nil {
		return nil, err
	}
	for _, view := range views {
		if view.Grant.GrantId == grant.GrantId {
			reply.Grants = append(reply.Grants, view)
		}
	}
	return reply, nil
}

// Revokes grantId wherever it stands, its tokens at once, and lets the port go once no grant stands.
func (self *GatewayServer) RevokeGrant(ctx context.Context, grantId Id) (*GatewayGrantsReply, error) {
	_, store, err := self.grantNetwork(grantId)
	if err != nil {
		return nil, err
	}
	revoked, err := store.Revoke(ctx, grantId)
	if err != nil {
		return nil, err
	}
	if err := self.releasePortIfNoGrant(); err != nil {
		return nil, err
	}
	return &GatewayGrantsReply{Revoked: revoked}, nil
}

// Files kind 21 through args' raiser, the network's compute client's where none is set.
func (self *GatewayServer) raiseBudget(ctx context.Context, network GatewayNetwork, args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
	if self.raiser != nil {
		return self.raiser(ctx, network, args)
	}
	sidecar, ok := network.(*Sidecar)
	if !ok {
		return nil, ErrComputeBudgetRaiseUnavailable
	}
	client, err := sidecar.ComputeClient()
	if err != nil {
		return nil, err
	}
	return client.RaiseBudget(ctx, args)
}

// Holds the port: a port drawn where the state has none, and the hold set; then served.
func (self *GatewayServer) holdPort() error {
	self.stateWriteLock.Lock()
	defer self.stateWriteLock.Unlock()
	state, err := ReadGatewayState(self.stateDirectory, self.settings.StateFileByteCount)
	if err != nil {
		return err
	}
	if !state.Holds() {
		if state.Port == 0 {
			port, err := ChooseGatewayPort(self.settings, self.listen, self.random)
			if err != nil {
				return err
			}
			state.Port = port
		}
		state.Hold = true
		if err := WriteGatewayState(self.stateDirectory, state); err != nil {
			return err
		}
	}
	self.Reload()
	return nil
}

// Lets the port go once no grant stands on any hosted network: one whose grants do not read keeps it, since a grant
// may stand there.
func (self *GatewayServer) releasePortIfNoGrant() error {
	self.stateWriteLock.Lock()
	defer self.stateWriteLock.Unlock()
	if hosts := self.gatewayHosts(); hosts != nil {
		for _, hosted := range hosts.GatewayNetworks() {
			store, err := hosted.Network.GatewayGrants()
			if err != nil {
				return nil
			}
			standing, err := store.Standing()
			if err != nil || standing {
				return nil
			}
		}
	}
	state, err := ReadGatewayState(self.stateDirectory, self.settings.StateFileByteCount)
	if err != nil {
		return err
	}
	if !state.Hold {
		return nil
	}
	state.Hold = false
	if err := WriteGatewayState(self.stateDirectory, state); err != nil {
		return err
	}
	self.Reload()
	return nil
}

// The hosted network of networkId, nil where none is.
func gatewayHostedNetwork(hosts GatewayHosts, networkId Id) GatewayNetwork {
	for _, hosted := range hosts.GatewayNetworks() {
		if hosted.NetworkId == networkId {
			return hosted.Network
		}
	}
	return nil
}
