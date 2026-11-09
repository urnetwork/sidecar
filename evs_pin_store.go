// The client's durable evs state (§11.9, I-16): ref pins and a head reader's per-path read records, in the evs
// component's sealed directory (§5.9's <component>/), so nothing reaches the disk in the clear and a cut or swapped
// file fails rather than reads as absent (SidecarStore's rule).
//
// A pin is (ref, v, C_v), the newest head this device verified, written before any read it backs is shown. It never
// falls and never forks: a raise to a lower version, or to the same version with another chain, is refused, and only
// a verified EvsReseed lowers one, which is kept as a loss (§11.13, §19.10). A pin re-raised past §11.9's catch-up
// budget keeps the time of that re-pin, which VerifiedSince reports (g0-recheck-0-head-reader-read-paths#3).
//
// A read record is (ref_id, path, entry version, pin at last read), one per path a head reader read, at most
// EvsSettings.HeadReadRecordCount for the network, least recently used out (g0-recheck-0-head-reader-read-paths#1). A
// path whose record was evicted counts as never read. Paths are this device's own plaintext, held only in the sealed
// store and never logged (I-13).
//
// Layout: pins/<repo_id> and reads/<repo_id>, each the repo's records as JSON, rewritten whole by Commit, so a kill
// leaves the old file or the new one. Writes serialize on writeLock, which is never held with stateLock's work on the
// store; memory answers reads under stateLock. Safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

// The store's two directories.
const (
	evsPinDirectory  = "pins/"
	evsReadDirectory = "reads/"
)

var (
	// A pin raise below the pin held (I-16): a rollback, which only a verified EvsReseed may make.
	ErrEvsPinLower = errors.New("evs: head below the pin")
	// A pin raise at the pin's version with another chain: a fork.
	ErrEvsPinFork = errors.New("evs: head forks from the pin")
)

// One ref's pin.
type EvsPin struct {
	RepoId  Id
	RefId   Id
	Version uint64
	Chain   [sha256.Size]byte
	// The §10 group its repo seals under, which HeadCheck's ref rows carry; zero until a read learns it.
	GroupId Id
	// When it was last raised.
	PinnedAt time.Time
	// The newest re-pin past the catch-up budget: zero when nothing was skipped since the first pin.
	VerifiedSince time.Time
	// The newest verified EvsReseed that lowered it, nil when none did.
	Loss *EvsPinLoss
}

// What a verified EvsReseed took from a pin: shown to the person as a loss (§11.13).
type EvsPinLoss struct {
	IncidentId []byte
	// The pin it lowered from.
	FromVersion uint64
	At          time.Time
}

// One path's read record.
type EvsReadRecord struct {
	RepoId Id
	RefId  Id
	// The path as this device names it, raw names joined by /.
	Path string
	// The entry version last read.
	EntryVersion uint64
	// The ref pin the read verified against.
	PinVersion uint64
	UsedAt     time.Time
}

// A pin's stored form.
type evsPinRecord struct {
	RefId         string `json:"ref_id"`
	Version       uint64 `json:"version"`
	Chain         string `json:"chain"`
	GroupId       string `json:"group_id,omitempty"`
	PinnedAtMs    int64  `json:"pinned_at_ms"`
	VerifiedSince int64  `json:"verified_since_ms,omitempty"`
	LossIncident  string `json:"loss_incident,omitempty"`
	LossFrom      uint64 `json:"loss_from,omitempty"`
	LossAtMs      int64  `json:"loss_at_ms,omitempty"`
}

// A read record's stored form.
type evsReadRecordRecord struct {
	RefId        string `json:"ref_id"`
	Path         string `json:"path"`
	EntryVersion uint64 `json:"entry_version"`
	PinVersion   uint64 `json:"pin_version"`
	UsedAtMs     int64  `json:"used_at_ms"`
}

// One repo's state as memory holds it.
type evsRepoState struct {
	refIdPins map[Id]*EvsPin
	// path key (ref id, path) to record
	reads map[evsReadKey]*EvsReadRecord
}

// A read record's key.
type evsReadKey struct {
	refId Id
	path  string
}

// The pins and read records of one network.
type EvsPinStore struct {
	store    SidecarStore
	settings *EvsSettings

	// serializes every file write, outside stateLock
	writeLock sync.Mutex

	stateLock   sync.Mutex
	loaded      bool
	repoIdRepos map[Id]*evsRepoState
}

// The store over the evs component's sealed directory.
func NewEvsPinStore(store SidecarStore, settings *EvsSettings) *EvsPinStore {
	return &EvsPinStore{
		store:       store,
		settings:    settings,
		repoIdRepos: map[Id]*evsRepoState{},
	}
}

// Loads every repo's files once. A file that fails to open is an error, never read as empty (D-CORE-15).
func (self *EvsPinStore) load() error {
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
	repoIdRepos := map[Id]*evsRepoState{}
	repo := func(repoId Id) *evsRepoState {
		state := repoIdRepos[repoId]
		if state == nil {
			state = &evsRepoState{refIdPins: map[Id]*EvsPin{}, reads: map[evsReadKey]*EvsReadRecord{}}
			repoIdRepos[repoId] = state
		}
		return state
	}
	for _, directory := range []string{evsPinDirectory, evsReadDirectory} {
		entries, err := self.store.List(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			repoId, err := ParseId(strings.TrimPrefix(entry.Name, directory))
			if err != nil {
				continue
			}
			data, err := self.readFile(entry.Name)
			if err != nil {
				return err
			}
			if directory == evsPinDirectory {
				records := []*evsPinRecord{}
				if err := json.Unmarshal(data, &records); err != nil {
					return fmt.Errorf("%w: evs pins do not parse", ErrSidecarStoreFailed)
				}
				for _, record := range records {
					pin, err := record.pin(repoId)
					if err != nil {
						return err
					}
					repo(repoId).refIdPins[pin.RefId] = pin
				}
			} else {
				records := []*evsReadRecordRecord{}
				if err := json.Unmarshal(data, &records); err != nil {
					return fmt.Errorf("%w: evs read records do not parse", ErrSidecarStoreFailed)
				}
				for _, record := range records {
					refId, err := ParseId(record.RefId)
					if err != nil {
						return fmt.Errorf("%w: an evs read record's ref", ErrSidecarStoreFailed)
					}
					repo(repoId).reads[evsReadKey{refId: refId, path: record.Path}] = &EvsReadRecord{
						RepoId:       repoId,
						RefId:        refId,
						Path:         record.Path,
						EntryVersion: record.EntryVersion,
						PinVersion:   record.PinVersion,
						UsedAt:       time.UnixMilli(record.UsedAtMs),
					}
				}
			}
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		self.repoIdRepos = repoIdRepos
		self.loaded = true
	}
	return nil
}

// A file's plaintext.
func (self *EvsPinStore) readFile(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Replaces a file durably.
func (self *EvsPinStore) writeFile(name string, data []byte) error {
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// The pin a stored record gives.
func (self *evsPinRecord) pin(repoId Id) (*EvsPin, error) {
	refId, err := ParseId(self.RefId)
	if err != nil {
		return nil, fmt.Errorf("%w: an evs pin's ref", ErrSidecarStoreFailed)
	}
	chainBytes, err := hex.DecodeString(self.Chain)
	if err != nil || len(chainBytes) != sha256.Size {
		return nil, fmt.Errorf("%w: an evs pin's chain", ErrSidecarStoreFailed)
	}
	pin := &EvsPin{
		RepoId:   repoId,
		RefId:    refId,
		Version:  self.Version,
		Chain:    [sha256.Size]byte(chainBytes),
		PinnedAt: time.UnixMilli(self.PinnedAtMs),
	}
	if self.GroupId != "" {
		groupId, err := ParseId(self.GroupId)
		if err != nil {
			return nil, fmt.Errorf("%w: an evs pin's group", ErrSidecarStoreFailed)
		}
		pin.GroupId = groupId
	}
	if self.VerifiedSince != 0 {
		pin.VerifiedSince = time.UnixMilli(self.VerifiedSince)
	}
	if self.LossAtMs != 0 {
		incident, err := hex.DecodeString(self.LossIncident)
		if err != nil {
			return nil, fmt.Errorf("%w: an evs pin's loss", ErrSidecarStoreFailed)
		}
		pin.Loss = &EvsPinLoss{IncidentId: incident, FromVersion: self.LossFrom, At: time.UnixMilli(self.LossAtMs)}
	}
	return pin, nil
}

// The stored form of a pin.
func evsPinRecordOf(pin *EvsPin) *evsPinRecord {
	record := &evsPinRecord{
		RefId:      pin.RefId.String(),
		Version:    pin.Version,
		Chain:      hex.EncodeToString(pin.Chain[:]),
		PinnedAtMs: pin.PinnedAt.UnixMilli(),
	}
	if pin.GroupId != (Id{}) {
		record.GroupId = pin.GroupId.String()
	}
	if !pin.VerifiedSince.IsZero() {
		record.VerifiedSince = pin.VerifiedSince.UnixMilli()
	}
	if pin.Loss != nil {
		record.LossIncident = hex.EncodeToString(pin.Loss.IncidentId)
		record.LossFrom = pin.Loss.FromVersion
		record.LossAtMs = pin.Loss.At.UnixMilli()
	}
	return record
}

// A copy of a pin.
func (self *EvsPin) clone() *EvsPin {
	clone := *self
	if self.Loss != nil {
		loss := *self.Loss
		loss.IncidentId = slices.Clone(self.Loss.IncidentId)
		clone.Loss = &loss
	}
	return &clone
}

// The repo's state, created empty; under stateLock.
func (self *EvsPinStore) repoWithLock(repoId Id) *evsRepoState {
	state := self.repoIdRepos[repoId]
	if state == nil {
		state = &evsRepoState{refIdPins: map[Id]*EvsPin{}, reads: map[evsReadKey]*EvsReadRecord{}}
		self.repoIdRepos[repoId] = state
	}
	return state
}

// The pin of a ref, false when none is held.
func (self *EvsPinStore) Pin(repoId Id, refId Id) (*EvsPin, bool, error) {
	if err := self.load(); err != nil {
		return nil, false, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := self.repoIdRepos[repoId]
	if state == nil || state.refIdPins[refId] == nil {
		return nil, false, nil
	}
	return state.refIdPins[refId].clone(), true, nil
}

// Every pin of one repo, by ref id; every repo's for the zero id.
func (self *EvsPinStore) Pins(repoId *Id) ([]*EvsPin, error) {
	if err := self.load(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pins := []*EvsPin{}
	for stateRepoId, state := range self.repoIdRepos {
		if repoId != nil && stateRepoId != *repoId {
			continue
		}
		for _, pin := range state.refIdPins {
			pins = append(pins, pin.clone())
		}
	}
	slices.SortFunc(pins, func(a *EvsPin, b *EvsPin) int {
		if c := a.RepoId.Cmp(b.RepoId); c != 0 {
			return c
		}
		return a.RefId.Cmp(b.RefId)
	})
	return pins, nil
}

// Raises a ref's pin to pin, durably, before the caller shows anything it backs. Refuses a lower version
// (ErrEvsPinLower) and the same version with another chain (ErrEvsPinFork); the same pin again changes nothing but
// its time, its group and a gap mark the raise carries.
func (self *EvsPinStore) Raise(pin *EvsPin) error {
	return self.update(pin.RepoId, func(state *evsRepoState) error {
		held := state.refIdPins[pin.RefId]
		if held != nil {
			if pin.Version < held.Version {
				return ErrEvsPinLower
			}
			if pin.Version == held.Version && pin.Chain != held.Chain {
				return ErrEvsPinFork
			}
		}
		raised := pin.clone()
		if held != nil {
			if raised.VerifiedSince.IsZero() {
				raised.VerifiedSince = held.VerifiedSince
			}
			if raised.Loss == nil {
				raised.Loss = held.Loss
			}
			if raised.GroupId == (Id{}) {
				raised.GroupId = held.GroupId
			}
		}
		state.refIdPins[pin.RefId] = raised
		return nil
	})
}

// Lowers a ref's pin to pin under a verified EvsReseed (§11.13): the only way a pin falls, kept as a loss.
// reseedVersion and reseedChain are the EvsReseed's, which pin must equal.
func (self *EvsPinStore) lowerByReseed(pin *EvsPin, incidentId []byte, at time.Time) error {
	return self.update(pin.RepoId, func(state *evsRepoState) error {
		held := state.refIdPins[pin.RefId]
		lowered := pin.clone()
		if held != nil && pin.Version < held.Version {
			lowered.Loss = &EvsPinLoss{IncidentId: slices.Clone(incidentId), FromVersion: held.Version, At: at}
		}
		state.refIdPins[pin.RefId] = lowered
		return nil
	})
}

// Drops every pin and read record of a repo, as a shred does (§11.12).
func (self *EvsPinStore) Forget(repoId Id) error {
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if err := self.store.Remove(evsPinDirectory + repoId.String()); err != nil {
		return err
	}
	if err := self.store.Remove(evsReadDirectory + repoId.String()); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoIdRepos, repoId)
	return nil
}

// Runs change on a copy of one repo's pins and writes them, swapping the copy in only once the file is durable.
func (self *EvsPinStore) update(repoId Id, change func(state *evsRepoState) error) error {
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	copied := func() *evsRepoState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.repoWithLock(repoId)
		copied := &evsRepoState{refIdPins: map[Id]*EvsPin{}, reads: state.reads}
		for refId, pin := range state.refIdPins {
			copied.refIdPins[refId] = pin
		}
		return copied
	}()
	if err := change(copied); err != nil {
		return err
	}
	records := []*evsPinRecord{}
	for _, pin := range copied.refIdPins {
		records = append(records, evsPinRecordOf(pin))
	}
	slices.SortFunc(records, func(a *evsPinRecord, b *evsPinRecord) int { return strings.Compare(a.RefId, b.RefId) })
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	if err := self.writeFile(evsPinDirectory+repoId.String(), data); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoWithLock(repoId).refIdPins = copied.refIdPins
	return nil
}

// The read record of one path, false when none is held.
func (self *EvsPinStore) ReadRecord(repoId Id, refId Id, path string) (*EvsReadRecord, bool, error) {
	if err := self.load(); err != nil {
		return nil, false, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := self.repoIdRepos[repoId]
	if state == nil {
		return nil, false, nil
	}
	record := state.reads[evsReadKey{refId: refId, path: path}]
	if record == nil {
		return nil, false, nil
	}
	copied := *record
	return &copied, true, nil
}

// Raises the read records of one repo's reads, each to its entry version and pin, and evicts the network's least
// recently used past HeadReadRecordCount. A record never falls: a lower entry version is the caller's refusal, which
// it makes before calling this.
func (self *EvsPinStore) RaiseReadRecords(repoId Id, records []*EvsReadRecord) error {
	if len(records) == 0 {
		return nil
	}
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	// what changes: this repo's records, and any repo an eviction reaches
	changed := map[Id]map[evsReadKey]*EvsReadRecord{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		copyOf := func(repoId Id) map[evsReadKey]*EvsReadRecord {
			if reads, ok := changed[repoId]; ok {
				return reads
			}
			reads := map[evsReadKey]*EvsReadRecord{}
			for key, record := range self.repoWithLock(repoId).reads {
				reads[key] = record
			}
			changed[repoId] = reads
			return reads
		}
		reads := copyOf(repoId)
		for _, record := range records {
			key := evsReadKey{refId: record.RefId, path: record.Path}
			raised := *record
			raised.RepoId = repoId
			if held := reads[key]; held != nil {
				raised.EntryVersion = max(raised.EntryVersion, held.EntryVersion)
				raised.PinVersion = max(raised.PinVersion, held.PinVersion)
			}
			reads[key] = &raised
		}
		// least recently used out, across the network
		type located struct {
			repoId Id
			key    evsReadKey
			usedAt time.Time
		}
		all := []located{}
		for stateRepoId, state := range self.repoIdRepos {
			stateReads := state.reads
			if reads, ok := changed[stateRepoId]; ok {
				stateReads = reads
			}
			for key, record := range stateReads {
				all = append(all, located{repoId: stateRepoId, key: key, usedAt: record.UsedAt})
			}
		}
		excess := len(all) - self.settings.HeadReadRecordCount
		if 0 < excess {
			slices.SortFunc(all, func(a located, b located) int { return a.usedAt.Compare(b.usedAt) })
			for _, evicted := range all[:excess] {
				delete(copyOf(evicted.repoId), evicted.key)
			}
		}
	}()
	for changedRepoId, reads := range changed {
		stored := []*evsReadRecordRecord{}
		for _, record := range reads {
			stored = append(stored, &evsReadRecordRecord{
				RefId:        record.RefId.String(),
				Path:         record.Path,
				EntryVersion: record.EntryVersion,
				PinVersion:   record.PinVersion,
				UsedAtMs:     record.UsedAt.UnixMilli(),
			})
		}
		slices.SortFunc(stored, func(a *evsReadRecordRecord, b *evsReadRecordRecord) int {
			if c := strings.Compare(a.RefId, b.RefId); c != 0 {
				return c
			}
			return strings.Compare(a.Path, b.Path)
		})
		data, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		if err := self.writeFile(evsReadDirectory+changedRepoId.String(), data); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for changedRepoId, reads := range changed {
		self.repoWithLock(changedRepoId).reads = reads
	}
	return nil
}
