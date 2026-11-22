// The client's durable evs state (§11.9, I-16): ref pins and a head reader's per-path read records, in the evs
// component's sealed directory (§5.9's <component>/), so nothing reaches the disk in the clear and a cut or swapped
// file fails rather than reads as absent (SidecarStore's rule).
//
// A pin is (ref, v, C_v), the newest head this device verified, written before any read it backs is shown. It never
// falls and never forks: a raise to a lower version, or to the same version with another chain, is refused, and only
// a verified EvsReseed lowers one, which is kept as a loss (§11.13, §19.10). A pin re-raised past §11.9's catch-up
// budget keeps the time of that re-pin, which VerifiedSince reports (g0-recheck-0-head-reader-read-paths#3). What lies
// at or below a pin is what this device verified when it was new, each statement judged at its own authorization pin
// then; once two bases pass that pin the config no longer retains it, and the reader takes such a statement on its
// signature rather than judge it again (QD-1178; EvsVerifier.VerifyStatement).
//
// A read record is (ref_id, path, entry version, pin at last read), one per path a head reader read, at most
// EvsSettings.HeadReadRecordCount for the network, least recently used out (g0-recheck-0-head-reader-read-paths#1). A
// path whose record was evicted counts as never read, as does one whose record a gap head dropped, its pin passed by
// the re-pin and the path served absent or its removal (QD-1041, QD-1055). Paths are this device's own plaintext,
// held only in the sealed store and never logged (I-13). A record also keeps the path's floor and the ref's current
// epoch at its pin (DESIGN-DETAILS 9.2.2, 9.2.3): a floor only falls, and a record stored without them reads as no
// floor, which only sends less.
//
// A record also keeps the ref version its entry was committed at (QD-816): exact where the read walked the statement
// that wrote it, else evs's word, as what a never-read path holds below a pin is (Q-EVS-6). A verified EvsReseed,
// which lowers the ref's pin to a re-seeded head h, takes the ref's records with it:
//
//	lost      a record whose entry was committed above h is dropped: the incident lost that entry, so the path's
//	          surviving version reads as part of the ref's loss, never as a rollback refused and alarmed
//	kept      any other keeps its entry version, so the path's rollback check stands, with its pin lowered to h, C_h
//	          and h's current epoch where it lay above h
//	before    a record stored before the field holds no commit version: dropped when its pin lies above h, since
//	          which entry it read cannot be told, else kept as it is
//	floors    a kept record's floor above h's current epoch is lowered to it: a floor holds no commit version either,
//	          and a path that stands at h was named there, by the map that cut the ref over to that epoch or by a
//	          push in it
//
// The records are durable before the pin is written, so a kill between the two leaves the pin above h, the next read
// meets h again under the same EvsReseed, and that changes nothing twice. A read whose head the pin fell below while
// it ran raises no record (RaiseReadRecords), and a read in flight loads its records again when the ref's count of
// reseeds moves (reseedCount).
//
// A path's record is newer than another by where its entry committed once both hold that, else by its entry version.
// The two agree for a file, whose versions only rise (§11.7's 5g); a directory's do not, since its deltas merge
// without a path-level CAS, each at the version its writer read plus one (§11.7's directory row), so a delta its
// writer based on an older table commits a lower version after a higher one, while where each committed only rises.
//
// Overlapping reads of one client (the e2e-client-origins bug): a read asks at the pin it holds then (ask), and its
// answer is judged against that, never against a pin another of the client's calls raised since; the pin only rises.
//
//	ask       the ref's pin and count of reseeds when the read asks, which its head is checked against (EvsVerifier)
//	raise     raiseRead judges a head verified from an ask against the pin as it then stands, under writeLock, so
//	          nothing raises between the judgment and the raise: a walk that crosses the pin's version, the asked
//	          pin's or a kept chain's with another chain is a fork; a head below the pin it was asked at, or below
//	          its own walk's start, a regression; a head at or above the pin raises it
//	passed    a head another raise passed while the read was in flight stands as read, the pin unmoved, when the
//	          chain at its version is one this store holds, the pin it was asked at or a kept one
//	stale     else, and after a reseed while it was in flight, it is a stale read: read again, fresh, never a fork
//	kept      while a read of a ref is in flight (beginRead), each raise keeps C at every version its walk verified,
//	          at most EvsSettings.PinChainCount a ref, the oldest out, in memory only and gone once no read of the ref
//	          is in flight. The raises during a read's flight walk every version from its ask to the pin, each
//	          crossing the pin it met, so a head between them is judged unless a gap head re-pinned past the budget,
//	          whose versions are evs's word, or the count ran out: such a head is stale. Only a walk something this
//	          store held placed, or one raised with no pin standing, is kept
//	own       a reader that walks a ref's statements itself, from C_0 or from its own verified state, a copy's, a
//	          mirror's, a mount's or a replay's, asks and raises so too (evs_pin_walk.go). A walk from its own state
//	          above the pin that nothing this store holds places raises as Raise raises one, keeping its own chains
//	          and dropping those kept of the history below, which are not known to be its history
//	page      a page of a history, a walk that stops short of its ref's head, raises the pin to its end where that
//	          stands above it and else raises nothing, keeping its chains only where something places it; below the
//	          pin it was asked at it is no regression, only a head is
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

// The file version actually returned, at the ref and policy the reader verified. No file body is retained.
type evsSearchObservation struct {
	RefName   string            `json:"ref_name,omitempty"`
	Version   uint64            `json:"version"`
	Commit    uint64            `json:"commit"`
	Push      Id                `json:"push"`
	Signer    Id                `json:"signer"`
	TimeMs    int64             `json:"time_ms"`
	Head      uint64            `json:"head"`
	Chain     [sha256.Size]byte `json:"chain"`
	AuthChain []byte            `json:"auth_chain"`
	Tainted   bool              `json:"tainted,omitempty"`
	Outside   bool              `json:"outside,omitempty"`
}

// One path's read record.
type EvsReadRecord struct {
	search *evsSearchObservation
	RepoId Id
	RefId  Id
	// The path as this device names it, raw names joined by /.
	Path string
	// The entry version last read, and the ref version its push committed at, 0 for a record stored before that was
	// kept (QD-816).
	EntryVersion  uint64
	CommitVersion uint64
	// The ref pin the read verified against, and C there, so the next read of the path checks every statement since.
	PinVersion uint64
	PinChain   *[sha256.Size]byte
	UsedAt     time.Time
	// The lowest epoch in which this device holds evidence evs was shown the path's token, 0 none (DESIGN-DETAILS
	// 9.2.3), and the ref's current epoch at PinVersion, whose statements the next read walks from.
	Floor    uint64
	PinEpoch uint64
	// Under a repo's prefix write rules (DESIGN-DETAILS 16.2.5): the newest version of the path this device does not
	// ignore, nil for none held, and the newest version of the path it ignored, 0 for none. A read whose newest
	// version is at or below IgnoredThrough returns Accepted with no walk and no alarm. They say what this reader
	// believes; the fields above say what evs was shown, and move at every verified read, ignored or not. A record
	// stored before these were kept reads as none, which only walks again.
	Accepted       *EvsReadAccepted
	IgnoredThrough uint64
}

// The newest version of a path a reader of a ruled repo does not ignore (DESIGN-DETAILS 16.2.5's Accepted).
type EvsReadAccepted struct {
	// The path's version and the ref version its push committed at; both 0 where Absent.
	Version       uint64
	CommitVersion uint64
	PushId        Id
	// The path is effectively absent: every version evs holds of it is ignored, or its removal is allowed.
	Absent bool
	// The ignored versions over it when it was accepted, which a read from the record reports.
	IgnoredAbove int
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

// A read record's stored form. A field added later is optional, so a record stored before it opens with its zero.
type evsReadRecordRecord struct {
	Search        *evsSearchObservation `json:"search,omitempty"`
	RefId         string                `json:"ref_id"`
	Path          string                `json:"path"`
	EntryVersion  uint64                `json:"entry_version"`
	CommitVersion uint64                `json:"commit_version,omitempty"`
	PinVersion    uint64                `json:"pin_version"`
	PinChain      string                `json:"pin_chain,omitempty"`
	UsedAtMs      int64                 `json:"used_at_ms"`
	Floor         uint64                `json:"floor,omitempty"`
	PinEpoch      uint64                `json:"pin_epoch,omitempty"`
	// DESIGN-DETAILS 16.2.5's Accepted and IgnoredThrough: accepted is set by any of the first four
	Accepted        bool   `json:"accepted,omitempty"`
	AcceptedVersion uint64 `json:"accepted_version,omitempty"`
	AcceptedCommit  uint64 `json:"accepted_commit,omitempty"`
	AcceptedPushId  string `json:"accepted_push_id,omitempty"`
	AcceptedAbsent  bool   `json:"accepted_absent,omitempty"`
	IgnoredAbove    int    `json:"ignored_above,omitempty"`
	IgnoredThrough  uint64 `json:"ignored_through,omitempty"`
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
	// per ref, the verified EvsReseeds this store took since it opened, in memory only: a read in flight that loaded
	// the ref's records loads them again when it moves
	refReseedCounts map[evsRefKey]uint64
	// per ref, the reads in flight and, while any is, the chains raises walked (see the file header's kept row)
	refReadCounts map[evsRefKey]int
	refChains     map[evsRefKey]*evsRefChains
}

// C at the versions raises walked while a read of the ref was in flight: by version, and the versions in the order
// they were kept, the oldest out first past EvsSettings.PinChainCount.
type evsRefChains struct {
	versionChains map[uint64][sha256.Size]byte
	order         []uint64
}

// A read's view of a ref's pin as it asked (EvsPinStore.ask): what its answer is judged against.
type evsPinAsk struct {
	// The pin, nil when none was held.
	pin *EvsPin
	// The ref's count of reseeds then.
	reseeds uint64
}

// Where a head verified from an ask stands against the ref's pin (see the file header).
type evsPinStanding int

const (
	// At or above the pin, its walk crossing the pin on the pin's chain: a raise takes it.
	evsPinAbove evsPinStanding = iota
	// Below the pin, on the pinned history: it stands as read and the pin does not move.
	evsPinPassed
	// Below the pin, its place on the pinned history unknown here, or the pin fell under it: read again.
	evsPinStale
)

// The store over the evs component's sealed directory.
func NewEvsPinStore(store SidecarStore, settings *EvsSettings) *EvsPinStore {
	return &EvsPinStore{
		store:           store,
		settings:        settings,
		repoIdRepos:     map[Id]*evsRepoState{},
		refReseedCounts: map[evsRefKey]uint64{},
		refReadCounts:   map[evsRefKey]int{},
		refChains:       map[evsRefKey]*evsRefChains{},
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
					read := &EvsReadRecord{
						search:        record.Search,
						RepoId:        repoId,
						RefId:         refId,
						Path:          record.Path,
						EntryVersion:  record.EntryVersion,
						CommitVersion: record.CommitVersion,
						PinVersion:    record.PinVersion,
						UsedAt:        time.UnixMilli(record.UsedAtMs),
						Floor:         record.Floor,
						PinEpoch:      record.PinEpoch,
					}
					if record.Accepted {
						accepted := &EvsReadAccepted{
							Version:       record.AcceptedVersion,
							CommitVersion: record.AcceptedCommit,
							Absent:        record.AcceptedAbsent,
							IgnoredAbove:  record.IgnoredAbove,
						}
						if !accepted.Absent {
							if accepted.PushId, err = ParseId(record.AcceptedPushId); err != nil {
								return fmt.Errorf("%w: an evs read record's accepted push", ErrSidecarStoreFailed)
							}
						}
						read.Accepted, read.IgnoredThrough = accepted, record.IgnoredThrough
					}
					if record.PinChain != "" {
						chainBytes, err := hex.DecodeString(record.PinChain)
						if err != nil || len(chainBytes) != sha256.Size {
							return fmt.Errorf("%w: an evs read record's chain", ErrSidecarStoreFailed)
						}
						chain := [sha256.Size]byte(chainBytes)
						read.PinChain = &chain
					}
					repo(repoId).reads[evsReadKey{refId: refId, path: record.Path}] = read
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

// The ref's pin and count of reseeds as a read asks at them (see the file header's ask row).
func (self *EvsPinStore) ask(repoId Id, refId Id) (*evsPinAsk, error) {
	if err := self.load(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ask := &evsPinAsk{reseeds: self.refReseedCounts[evsRefKey{repoId: repoId, refId: refId}]}
	if state := self.repoIdRepos[repoId]; state != nil && state.refIdPins[refId] != nil {
		ask.pin = state.refIdPins[refId].clone()
	}
	return ask, nil
}

// Notes a read of a ref in flight until the function it returns is called, which may be called more than once: while
// one is, raises keep their walks' chains (see the file header's kept row).
func (self *EvsPinStore) beginRead(repoId Id, refId Id) func() {
	key := evsRefKey{repoId: repoId, refId: refId}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refReadCounts[key] += 1
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.refReadCounts[key] -= 1
			if self.refReadCounts[key] <= 0 {
				delete(self.refReadCounts, key)
				delete(self.refChains, key)
			}
		})
	}
}

// Where a head verified from its ask stands against held, the ref's pin as it stands (nil for none), and the chains
// kept, under stateLock (see the file header), and whether a version its walk verified is one this store holds, which
// places the walk on the pinned history: a regression is ErrEvsPinLower and a fork ErrEvsPinFork, each with the RefHead
// this device holds that the head contradicts, for the alarm's evidence. A page of a history (EvsVerifiedHead.page)
// below the pin it was asked at is no regression, and one the pin stands past raises nothing whether or not anything
// places it; a walk from its reader's own state (ownStart) above the pin raises where nothing places it.
func (self *EvsPinStore) standingWithLock(verified *EvsVerifiedHead, held *EvsPin) (evsPinStanding, bool, *EvsPin, error) {
	ask := verified.ask
	key := evsRefKey{repoId: verified.RepoId, refId: verified.RefId}
	if ask.reseeds != self.refReseedCounts[key] || (ask.pin != nil && held == nil) {
		// a verified EvsReseed lowered the pin while the read was in flight, which may have read the history lost, or
		// a shred forgot it
		return evsPinStale, false, nil, nil
	}
	switch {
	case !verified.page && ask.pin != nil && verified.Version < ask.pin.Version:
		return 0, false, ask.pin.clone(), ErrEvsPinLower
	case verified.Version < verified.FromVersion:
		return 0, false, &EvsPin{RepoId: verified.RepoId, RefId: verified.RefId, Version: verified.FromVersion, Chain: verified.fromChain}, ErrEvsPinLower
	}
	kept := self.refChains[key]
	// the chain this store holds at version, from the pin, the asked pin or a kept one, false for none
	holds := func(version uint64) ([sha256.Size]byte, bool) {
		for _, pin := range []*EvsPin{held, ask.pin} {
			if pin != nil && pin.Version == version {
				return pin.Chain, true
			}
		}
		if kept != nil {
			chain, ok := kept.versionChains[version]
			return chain, ok
		}
		return [sha256.Size]byte{}, false
	}
	placed := false
	check := func(version uint64, chain [sha256.Size]byte) *EvsPin {
		holdsChain, ok := holds(version)
		switch {
		case !ok:
			return nil
		case holdsChain != chain:
			return &EvsPin{RepoId: verified.RepoId, RefId: verified.RefId, Version: version, Chain: holdsChain}
		}
		placed = true
		return nil
	}
	if !verified.Gap {
		// the walk's start and every version it verified; a gap head's carried statements are not chained
		if mine := check(verified.FromVersion, verified.fromChain); mine != nil {
			return 0, false, mine, ErrEvsPinFork
		}
		for version, chain := range verified.walked {
			if mine := check(version, chain); mine != nil {
				return 0, false, mine, ErrEvsPinFork
			}
		}
	}
	if mine := check(verified.Version, verified.Chain); mine != nil {
		return 0, false, mine, ErrEvsPinFork
	}
	switch {
	case held == nil, held.Version == verified.Version:
		return evsPinAbove, placed, nil, nil
	case held.Version < verified.Version:
		if !verified.Gap && held.Version < verified.FromVersion && !verified.ownStart {
			// a walk that starts above the pin crosses nothing: the pin fell, which the reseed count shows first
			return evsPinStale, false, nil, nil
		}
		return evsPinAbove, placed, nil, nil
	}
	if _, ok := holds(verified.Version); ok {
		return evsPinPassed, true, nil, nil
	}
	if verified.page {
		// a page of the history below the pin, its rest read later: nothing to raise
		return evsPinPassed, placed, nil, nil
	}
	return evsPinStale, false, nil, nil
}

// standingWithLock against the pin as it stands now, which a raise judges again: what a read asks of a head it has
// verified before it reads its paths, and what a page of a walk that raises nothing is held to.
func (self *EvsPinStore) standing(verified *EvsVerifiedHead) (evsPinStanding, *EvsPin, error) {
	if err := self.load(); err != nil {
		return 0, nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var held *EvsPin
	if state := self.repoIdRepos[verified.RepoId]; state != nil {
		held = state.refIdPins[verified.RefId]
	}
	standing, _, mine, err := self.standingWithLock(verified, held)
	return standing, mine, err
}

// Raises the ref's pin to pin, the head verified from its ask, durably, judged against the pin as it stands under
// writeLock, which every pin write takes, so the judgment holds until the raise (see the file header's raise row):
// above, raised as Raise raises; passed or stale, nothing moves; a regression or a fork refuses, with the RefHead it
// contradicts. A head above or passed keeps its walk's chains while reads of the ref are in flight, where something
// the store held placed its walk or there was no pin; a raise from a reader's own start that nothing placed keeps its
// own alone, since what was kept of the history below the pin it moved off is not known to be its history.
func (self *EvsPinStore) raiseRead(pin *EvsPin, verified *EvsVerifiedHead) (evsPinStanding, *EvsPin, error) {
	if err := self.load(); err != nil {
		return 0, nil, err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	// keep: whether the walk's chains are kept, which they are where something the store held placed the walk or no
	// pin stood; drop: whether what was kept goes first, the pin moving off the history it was kept of
	var keep, drop bool
	standing, mine, err := func() (evsPinStanding, *EvsPin, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		var held *EvsPin
		if state := self.repoIdRepos[pin.RepoId]; state != nil {
			held = state.refIdPins[pin.RefId]
		}
		standing, placed, mine, err := self.standingWithLock(verified, held)
		switch {
		case err != nil, standing == evsPinStale:
		case placed, held == nil, verified.Gap:
			// a gap head keeps its own chain alone (keepChainsWithLock), its walk being evs's word
			keep = true
		case standing == evsPinAbove:
			// a reader's own start above the pin that nothing places: the pin moves onto it as Raise moves one
			keep, drop = true, true
		}
		return standing, mine, err
	}()
	if err != nil || standing == evsPinStale {
		return standing, mine, err
	}
	if standing == evsPinAbove {
		err := self.updateWithWriteLock(pin.RepoId, func(state *evsRepoState) error {
			raised := pin.clone()
			if held := state.refIdPins[pin.RefId]; held != nil {
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
		if err != nil {
			return 0, nil, err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if drop {
		delete(self.refChains, evsRefKey{repoId: verified.RepoId, refId: verified.RefId})
	}
	if keep {
		self.keepChainsWithLock(verified)
	}
	return standing, nil, nil
}

// Keeps C at every version a head's walk verified while a read of its ref is in flight, at most PinChainCount, the
// oldest out; under stateLock.
func (self *EvsPinStore) keepChainsWithLock(verified *EvsVerifiedHead) {
	key := evsRefKey{repoId: verified.RepoId, refId: verified.RefId}
	if self.refReadCounts[key] <= 0 {
		return
	}
	kept := self.refChains[key]
	if kept == nil {
		kept = &evsRefChains{versionChains: map[uint64][sha256.Size]byte{}}
		self.refChains[key] = kept
	}
	keep := func(version uint64, chain [sha256.Size]byte) {
		if _, ok := kept.versionChains[version]; ok {
			return
		}
		kept.versionChains[version] = chain
		kept.order = append(kept.order, version)
		for self.settings.PinChainCount < len(kept.order) {
			delete(kept.versionChains, kept.order[0])
			kept.order = kept.order[1:]
		}
	}
	if !verified.Gap {
		keep(verified.FromVersion, verified.fromChain)
		for version, chain := range verified.walked {
			keep(version, chain)
		}
	}
	keep(verified.Version, verified.Chain)
}

// Lowers a ref's pin to pin, the re-seeded head a verified EvsReseed names (§11.13): the only way a pin falls, kept
// as a loss, and the ref's read records with it, headEpoch being that head's current path epoch (QD-816; see the file
// header). The records are durable first. The pin keeps the group and gap mark held, and the same head again keeps
// the loss already held.
func (self *EvsPinStore) lowerByReseed(pin *EvsPin, incidentId []byte, at time.Time, headEpoch uint64) error {
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	reads, changed := func() (map[evsReadKey]*EvsReadRecord, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		reads := map[evsReadKey]*EvsReadRecord{}
		changed := false
		for key, record := range self.repoWithLock(pin.RepoId).reads {
			if key.refId != pin.RefId {
				reads[key] = record
				continue
			}
			lowered := evsReseedReadRecord(record, pin, headEpoch)
			if lowered != record {
				changed = true
			}
			if lowered != nil {
				reads[key] = lowered
			}
		}
		return reads, changed
	}()
	if changed {
		if err := self.writeReadsWithWriteLock(pin.RepoId, reads); err != nil {
			return err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if changed {
			self.repoWithLock(pin.RepoId).reads = reads
		}
		key := evsRefKey{repoId: pin.RepoId, refId: pin.RefId}
		self.refReseedCounts[key] += 1
		// what raises kept is of the history the incident lost, above the re-seeded head or not
		delete(self.refChains, key)
	}()
	return self.updateWithWriteLock(pin.RepoId, func(state *evsRepoState) error {
		held := state.refIdPins[pin.RefId]
		lowered := pin.clone()
		if held != nil {
			if pin.Version < held.Version {
				lowered.Loss = &EvsPinLoss{IncidentId: slices.Clone(incidentId), FromVersion: held.Version, At: at}
			} else if lowered.Loss == nil {
				// a second read that met the same head before the first lowered the pin
				lowered.Loss = held.Loss
			}
			if lowered.GroupId == (Id{}) {
				lowered.GroupId = held.GroupId
			}
			if lowered.VerifiedSince.IsZero() {
				lowered.VerifiedSince = held.VerifiedSince
			}
		}
		state.refIdPins[pin.RefId] = lowered
		return nil
	})
}

// What a verified EvsReseed to head, its version and chain, at headEpoch leaves of one of the ref's read records (see
// the file header): nil when it drops it, record itself when nothing changes, else a lowered copy.
func evsReseedReadRecord(record *EvsReadRecord, head *EvsPin, headEpoch uint64) *EvsReadRecord {
	switch {
	case record.CommitVersion != 0 && head.Version < record.CommitVersion:
		// the incident lost the entry read
		return nil
	case record.CommitVersion == 0 && head.Version < record.PinVersion:
		// stored before the commit version was kept, and read above the head
		return nil
	case record.PinVersion <= head.Version && record.Floor <= headEpoch:
		return record
	}
	lowered := *record
	lowered.search = nil
	if lowered.Accepted != nil && head.Version < lowered.PinVersion {
		// what was accepted or ignored above the re-seeded head may be part of the loss: the next read walks again
		lowered.Accepted, lowered.IgnoredThrough = nil, 0
	}
	if head.Version < lowered.PinVersion {
		chain := head.Chain
		lowered.PinVersion, lowered.PinChain, lowered.PinEpoch = head.Version, &chain, headEpoch
	}
	if headEpoch < lowered.Floor {
		lowered.Floor = headEpoch
	}
	return &lowered
}

// How many verified EvsReseeds this store took for a ref since it opened.
func (self *EvsPinStore) reseedCount(repoId Id, refId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refReseedCounts[evsRefKey{repoId: repoId, refId: refId}]
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
	for key := range self.refChains {
		if key.repoId == repoId {
			delete(self.refChains, key)
		}
	}
	return nil
}

// Runs change on a copy of one repo's pins and writes them, swapping the copy in only once the file is durable.
func (self *EvsPinStore) update(repoId Id, change func(state *evsRepoState) error) error {
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	return self.updateWithWriteLock(repoId, change)
}

// update, under writeLock, the store loaded.
func (self *EvsPinStore) updateWithWriteLock(repoId Id, change func(state *evsRepoState) error) error {
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

// Every pin, from memory alone: none before the store has loaded, so a caller that must not block or do I/O, as
// HeadCheck's reads must not, gets what is there.
func (self *EvsPinStore) loadedPins() []*EvsPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		return nil
	}
	pins := []*EvsPin{}
	for _, state := range self.repoIdRepos {
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
	return pins
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

// Raises the read records of one repo's reads, each to its entry version, with that entry's commit version, and pin,
// its floor to the lower of the two, and evicts the network's least recently used past HeadReadRecordCount. A record
// never falls: an older entry is the caller's refusal, which it makes before calling this, unless another read raised
// the record past it meanwhile, which keeps the newer entry and pin. A record pinned above its ref's pin raises
// nothing: a verified EvsReseed lowered the pin after the read pinned a head of the history the incident lost, and a
// record of it would hold that history's entry over the re-seeded one (QD-816).
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
		refIdPins := self.repoWithLock(repoId).refIdPins
		for _, record := range records {
			if pin := refIdPins[record.RefId]; pin != nil && pin.Version < record.PinVersion {
				continue
			}
			key := evsReadKey{refId: record.RefId, path: record.Path}
			raised := *record
			raised.RepoId = repoId
			if held := reads[key]; held != nil {
				switch {
				case raised.CommitVersion != 0 && held.CommitVersion != 0:
					// where each committed orders them, a directory's merged deltas among them (see the file header)
					if raised.CommitVersion < held.CommitVersion {
						raised.EntryVersion, raised.CommitVersion = held.EntryVersion, held.CommitVersion
					}
				case raised.EntryVersion < held.EntryVersion:
					raised.EntryVersion, raised.CommitVersion = held.EntryVersion, held.CommitVersion
				case raised.EntryVersion == held.EntryVersion && held.CommitVersion != 0:
					// an entry version commits once, and the first read of it knew its commit as well as any later one
					raised.CommitVersion = held.CommitVersion
				}
				if raised.PinVersion < held.PinVersion {
					raised.PinVersion, raised.PinChain, raised.PinEpoch = held.PinVersion, held.PinChain, held.PinEpoch
				}
				raised.Floor = evsLowerFloor(raised.Floor, held.Floor)
				// what the reader believes moves only through NoteAccepted
				raised.Accepted, raised.IgnoredThrough = held.Accepted, held.IgnoredThrough
				if raised.PinVersion == held.PinVersion && raised.EntryVersion == held.EntryVersion {
					raised.search = held.search
				}
			} else {
				raised.Accepted, raised.IgnoredThrough = nil, 0
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
		if err := self.writeReadsWithWriteLock(changedRepoId, reads); err != nil {
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

// Drops the read records a read loaded, each only while the store holds it as loaded, at the same entry version and
// pin: one a later read raised, or a reseed lowered, since then stays. A gap head drops the record of a path it
// served absent or its removal whose pin the gap passed, so the path reads as a never-read one does (QD-1041,
// QD-1055; evs_epoch_read.go's finishRead).
func (self *EvsPinStore) DropReadRecords(repoId Id, records []*EvsReadRecord) error {
	if len(records) == 0 {
		return nil
	}
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	reads := func() map[evsReadKey]*EvsReadRecord {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.repoIdRepos[repoId]
		if state == nil {
			return nil
		}
		var reads map[evsReadKey]*EvsReadRecord
		for _, record := range records {
			key := evsReadKey{refId: record.RefId, path: record.Path}
			held := state.reads[key]
			if held == nil || held.EntryVersion != record.EntryVersion || held.PinVersion != record.PinVersion {
				continue
			}
			if reads == nil {
				reads = map[evsReadKey]*EvsReadRecord{}
				for readKey, read := range state.reads {
					reads[readKey] = read
				}
			}
			delete(reads, key)
		}
		return reads
	}()
	if reads == nil {
		return nil
	}
	if err := self.writeReadsWithWriteLock(repoId, reads); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoWithLock(repoId).reads = reads
	return nil
}

// Sets what a reader of a ruled repo believes of one path (DESIGN-DETAILS 16.2.5): the version it accepts and the
// newest it ignored, or with accepted nil clears both, the path's newest version being one it follows. Only a path
// that holds a record takes it: the record's entry, pin, floor and epoch are a verified read's, which this never
// moves, and a path with none is walked again at its next read.
func (self *EvsPinStore) NoteAccepted(repoId Id, refId Id, path string, accepted *EvsReadAccepted, ignoredThrough uint64) error {
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	key := evsReadKey{refId: refId, path: path}
	reads := func() map[evsReadKey]*EvsReadRecord {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.repoIdRepos[repoId]
		if state == nil || state.reads[key] == nil {
			return nil
		}
		held := state.reads[key]
		if accepted == nil && held.Accepted == nil {
			return nil
		}
		if accepted != nil && held.Accepted != nil && *accepted == *held.Accepted && held.IgnoredThrough == ignoredThrough {
			return nil
		}
		reads := map[evsReadKey]*EvsReadRecord{}
		for readKey, record := range state.reads {
			reads[readKey] = record
		}
		noted := *held
		noted.Accepted, noted.IgnoredThrough = nil, 0
		if accepted != nil {
			copied := *accepted
			noted.Accepted, noted.IgnoredThrough = &copied, ignoredThrough
		}
		reads[key] = &noted
		return reads
	}()
	if reads == nil {
		return nil
	}
	if err := self.writeReadsWithWriteLock(repoId, reads); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoWithLock(repoId).reads = reads
	return nil
}

// Writes one repo's read records whole, under writeLock.
func (self *EvsPinStore) writeReadsWithWriteLock(repoId Id, reads map[evsReadKey]*EvsReadRecord) error {
	stored := []*evsReadRecordRecord{}
	for _, record := range reads {
		storedRecord := &evsReadRecordRecord{
			Search:        record.search,
			RefId:         record.RefId.String(),
			Path:          record.Path,
			EntryVersion:  record.EntryVersion,
			CommitVersion: record.CommitVersion,
			PinVersion:    record.PinVersion,
			UsedAtMs:      record.UsedAt.UnixMilli(),
			Floor:         record.Floor,
			PinEpoch:      record.PinEpoch,
		}
		if record.PinChain != nil {
			storedRecord.PinChain = hex.EncodeToString(record.PinChain[:])
		}
		if accepted := record.Accepted; accepted != nil {
			storedRecord.Accepted, storedRecord.IgnoredThrough = true, record.IgnoredThrough
			storedRecord.AcceptedVersion, storedRecord.AcceptedCommit = accepted.Version, accepted.CommitVersion
			storedRecord.AcceptedAbsent, storedRecord.IgnoredAbove = accepted.Absent, accepted.IgnoredAbove
			if !accepted.Absent {
				storedRecord.AcceptedPushId = accepted.PushId.String()
			}
		}
		stored = append(stored, storedRecord)
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
	return self.writeFile(evsReadDirectory+repoId.String(), data)
}
