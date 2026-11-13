// What the bridge compile reads of the host beside the config (DESIGN-DETAILS 12.2.4): BridgeCompileLocal, and the
// binding cache that fills its Bindings off the compile path (QD-161, plan-BRIDGE-subject-resolution).
//
//	current      for each sidecar a compile named in its waits, or reaches: GET /sidecar/identity/<sidecar_id>,
//	             verified under the SidecarRow's identity key, again each BindingRefreshInterval and when a link's
//	             destination check fails (the component's fetcher, bridge_component.go)
//	kept         each (sidecar, client id) for BindingRetainTimeout, the longest a window client lives, after it stopped
//	             being current; at most BindingMaxCount a sidecar, the newest kept
//	client_ids   a subject's current and kept ids, which the hook resolves C13's sealed subject through
//
// The compile reads no clock, no network and no random source, so the cache keeps its own times and hands the compile
// an immutable snapshot: equal snapshots give equal bytes. What it persists is each current binding as api signed it,
// which a load verifies again, and each kept client id with the time it may be dropped, in the component's sealed
// store. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg, with no connect
// import: the forwarding role compiles with these types (DESIGN-DETAILS 4.7).

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The binding cache's file in the component's store.
const bridgeBindingCacheName = "bindings.json"

// The binding cache file's format: a reader refuses a higher one rather than misread it.
const bridgeBindingCacheFormat = 1

// What the host knows of itself, the compile's inputs beside the config: equal inputs give equal bytes
// (DESIGN-DETAILS 12.2.4's local row).
type BridgeCompileLocal struct {
	// S, the host the state is compiled for.
	SidecarId Id
	// Rule 0: DaemonLocalListen's binds, host:port; none in a VPN component.
	DaemonListeners []string
	// Verified identity bindings by sidecar_id. Nil holds none, so every link and subject waits.
	Bindings BridgeBindingView
	// The block last compiled, nil for none: D-BRIDGE-16's "keeps the previous block".
	PreviousBlock *bridge.BridgeBlock
	// <net>.<root> and the alias zone where one is chosen (§12.9): the network's label is the host's label table's
	// (dns_resolve.go), not the config's, so the host hands it in. Empty while labels are not served.
	NameZones []string
	// The labels the network's zone publishes, hosts and record owners, which no client name may shadow (§12.9). The
	// zone is the record API's, not the config's, so the host hands them in; empty before M5's records.
	PublishedNames []string
	// Nil is DefaultBridgeCompileSettings.
	Settings *BridgeCompileSettings
}

// Tunables of the compile that are no ledger's.
type BridgeCompileSettings struct {
	// §17.8's disposition: a withdrawn route or map, or an address of a block a change replaced, stays compiled and
	// draining for max(drain_seconds, this) from its withdrawal: 600 s, §17.5's TCP idle, which is the longest of the
	// device role's idles.
	DrainMinimum time.Duration
}

// §17.5's and §17.8's values.
func DefaultBridgeCompileSettings() *BridgeCompileSettings {
	return &BridgeCompileSettings{
		DrainMinimum: 600 * time.Second,
	}
}

// One sidecar's binding as a verifier accepted it: its signatures over the body api stored, the network and sidecar
// the caller asked about, and an identity key the caller compares with the config's.
type BridgeBinding struct {
	SidecarId         Id
	ClientId          Id
	ClientPublicKey   []byte
	IdentityPublicKey []byte
	Generation        int64
	// The marshalled SignedSidecarIdentityBinding as api answered it, kept so a load verifies it again.
	Signed []byte
}

// The bindings a compile reads. Implementations are immutable snapshots, safe for concurrent use.
type BridgeBindingView interface {
	// The sidecar's current binding, nil for none held.
	Current(sidecarId Id) *BridgeBinding
	// Its current client and every one still kept, ascending, none for none.
	ClientIds(sidecarId Id) []Id
}

// A binding answer verified against what the caller asked: both signatures over the received body
// (VerifySidecarIdentityBinding), the network and the sidecar it names, and its identity key the one the config admits.
// The answer is api's and so untrusted until this passes.
func VerifyBridgeBinding(signedBinding []byte, networkId Id, sidecarId Id, identityPublicKey []byte) (*BridgeBinding, error) {
	binding, err := VerifySidecarIdentityBinding(signedBinding)
	if err != nil {
		return nil, err
	}
	switch {
	case binding.NetworkId != networkId:
		return nil, fmt.Errorf("%w: a binding of another network", ErrSidecarBindingInvalid)
	case binding.SidecarId != sidecarId:
		return nil, fmt.Errorf("%w: a binding of another sidecar", ErrSidecarBindingInvalid)
	case len(identityPublicKey) == 0 || !bytes.Equal(binding.IdentityPublicKey, identityPublicKey):
		return nil, fmt.Errorf("%w: a binding under another identity key than the config admits", ErrSidecarBindingInvalid)
	}
	return &BridgeBinding{
		SidecarId:         sidecarId,
		ClientId:          binding.ClientId,
		ClientPublicKey:   bytes.Clone(binding.ClientPublicKey),
		IdentityPublicKey: bytes.Clone(binding.IdentityPublicKey),
		Generation:        binding.Generation,
		Signed:            bytes.Clone(signedBinding),
	}, nil
}

// One client id kept past its being current.
type bridgeKeptClient struct {
	clientId Id
	// when the cache may drop it, ms since the epoch on the cache's clock
	untilMs int64
}

// One sidecar's bindings in the cache.
type bridgeBindingEntry struct {
	current *BridgeBinding
	// newest first
	kept []bridgeKeptClient
}

// The bindings the bridge component fetched, verified and keeps (the file's comment). Safe for concurrent use.
type BridgeBindingCache struct {
	retainTimeout time.Duration
	maxCount      int

	stateLock sync.Mutex
	entries   map[Id]*bridgeBindingEntry
	// moves at each change, so a component knows to compile again
	version uint64
}

// A cache keeping each client id retainTimeout past its being current, at most maxCount a sidecar: the component's
// BindingRetainTimeout and BindingMaxCount.
func NewBridgeBindingCache(retainTimeout time.Duration, maxCount int) *BridgeBindingCache {
	return &BridgeBindingCache{retainTimeout: retainTimeout, maxCount: max(1, maxCount), entries: map[Id]*bridgeBindingEntry{}}
}

// Takes a verified binding as its sidecar's current one at now: a current one of another client is kept for the
// retain timeout. Whether anything changed.
func (self *BridgeBindingCache) Record(binding *BridgeBinding, now time.Time) bool {
	if binding == nil {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry := self.entries[binding.SidecarId]
	if entry == nil {
		entry = &bridgeBindingEntry{}
		self.entries[binding.SidecarId] = entry
	}
	if entry.current != nil && entry.current.ClientId == binding.ClientId && bytes.Equal(entry.current.Signed, binding.Signed) {
		return false
	}
	// a newer generation is current; an older answer than the one held is kept, never current again
	if entry.current != nil && binding.Generation < entry.current.Generation {
		changed := self.keepWithLock(entry, binding.ClientId, now)
		if changed {
			self.version += 1
		}
		return changed
	}
	if entry.current != nil && entry.current.ClientId != binding.ClientId {
		self.keepWithLock(entry, entry.current.ClientId, now)
	}
	entry.kept = slices.DeleteFunc(entry.kept, func(kept bridgeKeptClient) bool { return kept.clientId == binding.ClientId })
	entry.current = binding
	self.version += 1
	return true
}

// Keeps clientId for the retain timeout from now, newest first, at most maxCount ids with the current one. Whether
// anything changed.
func (self *BridgeBindingCache) keepWithLock(entry *bridgeBindingEntry, clientId Id, now time.Time) bool {
	untilMs := now.Add(self.retainTimeout).UnixMilli()
	index := slices.IndexFunc(entry.kept, func(kept bridgeKeptClient) bool { return kept.clientId == clientId })
	if index != -1 {
		if untilMs <= entry.kept[index].untilMs {
			return false
		}
		entry.kept = slices.Delete(entry.kept, index, index+1)
	}
	entry.kept = slices.Insert(entry.kept, 0, bridgeKeptClient{clientId: clientId, untilMs: untilMs})
	if limit := self.maxCount - 1; limit < len(entry.kept) {
		entry.kept = entry.kept[:max(0, limit)]
	}
	return true
}

// Drops every kept id whose time has passed at now, and every sidecar with nothing left. Whether anything changed.
func (self *BridgeBindingCache) Expire(now time.Time) bool {
	nowMs := now.UnixMilli()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	changed := false
	for _, sidecarId := range self.sidecarIdsWithLock() {
		entry := self.entries[sidecarId]
		kept := len(entry.kept)
		entry.kept = slices.DeleteFunc(entry.kept, func(kept bridgeKeptClient) bool { return kept.untilMs <= nowMs })
		changed = changed || kept != len(entry.kept)
		if entry.current == nil && len(entry.kept) == 0 {
			delete(self.entries, sidecarId)
			changed = true
		}
	}
	if changed {
		self.version += 1
	}
	return changed
}

// Forgets a sidecar's bindings, as for one the config no longer holds. Whether anything changed.
func (self *BridgeBindingCache) Forget(sidecarId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.entries[sidecarId] == nil {
		return false
	}
	delete(self.entries, sidecarId)
	self.version += 1
	return true
}

// A number that moves at each change.
func (self *BridgeBindingCache) Version() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.version
}

// The sidecars the cache holds, ascending.
func (self *BridgeBindingCache) sidecarIdsWithLock() []Id {
	sidecarIds := make([]Id, 0, len(self.entries))
	for sidecarId := range self.entries {
		sidecarIds = append(sidecarIds, sidecarId)
	}
	slices.SortFunc(sidecarIds, Id.Cmp)
	return sidecarIds
}

// The current binding held for a sidecar, nil for none. The caller must not change it.
func (self *BridgeBindingCache) Current(sidecarId Id) *BridgeBinding {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if entry := self.entries[sidecarId]; entry != nil {
		return entry.current
	}
	return nil
}

// An immutable copy of what the cache holds now, for one compile.
func (self *BridgeBindingCache) Snapshot() BridgeBindingView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	snapshot := &bridgeBindingSnapshot{current: map[Id]*BridgeBinding{}, clientIds: map[Id][]Id{}}
	for _, sidecarId := range self.sidecarIdsWithLock() {
		entry := self.entries[sidecarId]
		clientIds := []Id{}
		if entry.current != nil {
			snapshot.current[sidecarId] = entry.current
			clientIds = append(clientIds, entry.current.ClientId)
		}
		for _, kept := range entry.kept {
			if !slices.Contains(clientIds, kept.clientId) {
				clientIds = append(clientIds, kept.clientId)
			}
		}
		slices.SortFunc(clientIds, Id.Cmp)
		snapshot.clientIds[sidecarId] = clientIds
	}
	return snapshot
}

// One compile's bindings.
type bridgeBindingSnapshot struct {
	current   map[Id]*BridgeBinding
	clientIds map[Id][]Id
}

func (self *bridgeBindingSnapshot) Current(sidecarId Id) *BridgeBinding {
	return self.current[sidecarId]
}

func (self *bridgeBindingSnapshot) ClientIds(sidecarId Id) []Id {
	return self.clientIds[sidecarId]
}

// The cache file: each sidecar's current binding as signed, and its kept ids.
type bridgeBindingCacheFile struct {
	Format   int                         `json:"format"`
	Sidecars []*bridgeBindingCacheRecord `json:"sidecars"`
}

type bridgeBindingCacheRecord struct {
	SidecarId Id                        `json:"sidecar_id"`
	Current   []byte                    `json:"current,omitempty"`
	Kept      []*bridgeBindingCacheKept `json:"kept,omitempty"`
}

type bridgeBindingCacheKept struct {
	ClientId Id    `json:"client_id"`
	UntilMs  int64 `json:"until_ms"`
}

// Writes what the cache holds to store, replacing what was there.
func (self *BridgeBindingCache) Save(store SidecarStore) error {
	file := &bridgeBindingCacheFile{Format: bridgeBindingCacheFormat}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, sidecarId := range self.sidecarIdsWithLock() {
			entry := self.entries[sidecarId]
			record := &bridgeBindingCacheRecord{SidecarId: sidecarId}
			if entry.current != nil {
				record.Current = bytes.Clone(entry.current.Signed)
			}
			for _, kept := range entry.kept {
				record.Kept = append(record.Kept, &bridgeBindingCacheKept{ClientId: kept.clientId, UntilMs: kept.untilMs})
			}
			file.Sidecars = append(file.Sidecars, record)
		}
	}()
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	writer, err := store.Create(bridgeBindingCacheName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Reads what store holds into the cache, which must be empty, verifying each current binding again for networkId under
// the identity key identityKey names, and dropping one that no longer verifies or whose sidecar has none. Nothing
// stored is no error.
func (self *BridgeBindingCache) Load(store SidecarStore, networkId Id, identityKey func(sidecarId Id) []byte) error {
	reader, err := store.Open(bridgeBindingCacheName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	file := &bridgeBindingCacheFile{}
	if err := json.Unmarshal(data, file); err != nil {
		return fmt.Errorf("bridge binding cache: %w", err)
	}
	if file.Format != bridgeBindingCacheFormat {
		return fmt.Errorf("bridge binding cache: format %d", file.Format)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, record := range file.Sidecars {
		entry := &bridgeBindingEntry{}
		if 0 < len(record.Current) {
			if binding, err := VerifyBridgeBinding(record.Current, networkId, record.SidecarId, identityKey(record.SidecarId)); err == nil {
				entry.current = binding
			}
		}
		for _, kept := range record.Kept {
			if len(entry.kept) < self.maxCount-1 && !slices.ContainsFunc(entry.kept, func(held bridgeKeptClient) bool { return held.clientId == kept.ClientId }) {
				entry.kept = append(entry.kept, bridgeKeptClient{clientId: kept.ClientId, untilMs: kept.UntilMs})
			}
		}
		if entry.current != nil || 0 < len(entry.kept) {
			self.entries[record.SidecarId] = entry
		}
	}
	self.version += 1
	return nil
}
