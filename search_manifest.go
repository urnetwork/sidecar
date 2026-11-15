//go:build !ios_extension

// The search manifest and the sync plan (DESIGN-DETAILS 7.2.7's manifest; §11.14's pin and swap rows; §5.9's holds
// row; SEARCH-M10-19): what a device holds of one index ref for search, one manifest a ref, and the round in progress
// toward a newer version of it.
//
// The manifest is a snapshot's record: the index ref's version its latest set is whole at (pin), every file of that
// set and of the all set with its state and its two times, all's own pin, the roll-ups between all's pin and the pin,
// the coverage rows its heads carry, the last PinRingCount (version, chain) pairs replayed, and the version table's runs
// the snapshot reads. Its write is the swap. The plan beside it holds the round's target, the files the target lists,
// what is staged toward it and the roll-ups replayed, so a round killed anywhere resumes from what it staged.
//
// Both are §5.9's derived parts of the ref (SearchCacheRefPath), sealed JSON as state_search_cache.go's records are,
// format 1. Each write takes a new serial as its part's version and then removes the older serials, so a kill leaves
// one whole copy at least and a load takes the highest that reads; one that does not read is derived state, dropped.
//
// Each file a manifest or plan names carries the version-table run built from it when it was fetched (a reading:
// 7.2.7 names the runs a snapshot reads but no field for them), since a kept record opens only under keys the cache
// never holds (state_search_cache.go), so a later swap merges unchanged files' runs rather than reading those files
// again.
//
// Never stored: a query, a hit, or anything a search asked (§5.9's never row). Paths are this device's index paths and
// go into no log or error (I-13).
//
// On every leg but ios_extension: root Id, no connect type. Not safe for concurrent use: SearchSync holds one ref's
// manifest and plan under that ref's round.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The manifest's and plan's format.
const searchManifestFormat = 1

// A file's state in a manifest or plan.
type SearchManifestFileState string

const (
	// Kept, validated, its run built.
	SearchManifestHeld SearchManifestFileState = "held"
	// Failed content_sha256 or indexValidateFile at this version: listed so the swap does not wait on it, holding
	// nothing (7.2.7's bad file), its index_malformed raised.
	SearchManifestBad SearchManifestFileState = "bad"
	// In a newer format than this build reads: holds nothing and raises no alarm; the ref reads status update (a
	// reading: §11.14's newer row, which 7.2.7's two states leave out).
	SearchManifestNewer SearchManifestFileState = "newer"
)

// A version of the index ref: (v, C_v) and the signed time of the push that made it.
type SearchSyncPin struct {
	Version uint64
	Chain   [sha256.Size]byte
	TimeMs  int64
}

// One file of a manifest, or staged in a plan.
type SearchManifestFile struct {
	// Under the ref, as indexParsePath reads it, and its entry version.
	Path    string
	Version uint64
	// The entry version's content_sha256 and the plaintext's length, pad included.
	ContentSha256 [sha256.Size]byte
	ByteCount     int64
	Partition     SearchCachePartition
	State         SearchManifestFileState
	// The oldest and newest time of any row or entry in the file, tombstones included, in ms; 0 for a file that holds
	// none (a small file, a bad one).
	TimeMinMs int64
	TimeMaxMs int64
	// The signer of the push that wrote the version.
	Signer Id
	// The version-table run built from the file when it was fetched; 0 for a file that fills no slot (a small file, a
	// bad one).
	Run SearchVersionRunId
	// A bucket file's window in days, from its header or manifest; 0 for others.
	WindowDays uint32
	// The coverage rows a head or backfill header carries, per content ref (§11.14's coverage row).
	Coverage []*SearchManifestFileCoverage
	// A small file's plaintext (the settings, the erasure set, a manifest), kept sealed with the manifest so a snapshot
	// reads them with no record keys (a reading, as Run is); nil for the rest.
	Small []byte
}

// One coverage row of a file's header.
type SearchManifestFileCoverage struct {
	RefId   Id
	Version uint64
	Horizon bool
}

// What a manifest holds of the all partition.
type SearchManifestAll struct {
	// Held: all's shards as the pin below lists them are kept.
	Held bool
	// The index ref's version all is whole at: never above the manifest's pin.
	Pin SearchSyncPin
	// a/m's rolled_through_day at all's pin.
	RolledThroughDay uint32
}

// A roll-up between all's pin and the manifest's pin. A bucket kept for it is in the cache's retained list.
type SearchManifestRolled struct {
	StartDay   uint32
	WindowDays uint32
	// The ref version of the push that rolled it up.
	AtVersion uint64
}

// One coverage row a held head or backfill header carries (§11.14's coverage row).
type SearchManifestCoverage struct {
	Writer  Id
	Version uint64
	Horizon bool
}

// What the snapshot's heads say of one content ref the index covers.
type SearchManifestContent struct {
	RefId Id
	// The newest version up to which every push is indexed, as the coverage reader computed it at the swap; 0 where it
	// is not known (no reader given), which claims nothing.
	IndexedThrough uint64
	Rows           []*SearchManifestCoverage
}

// A (version, chain) pair a round replayed: 7.2.6's pin check matches a coverage's pin against these.
type SearchSyncPinPair struct {
	Version uint64
	Chain   [sha256.Size]byte
}

// A version-table run a snapshot reads, the slot it fills, and the files' runs it was merged from, so a swap that
// changes none of them keeps it.
type SearchManifestRun struct {
	Slot   SearchVersionSlot
	RunId  SearchVersionRunId
	Inputs []SearchVersionRunId
}

// The snapshot's record (DESIGN-DETAILS 7.2.7).
type SearchManifest struct {
	// The index root the snapshot follows: .ur-index/i<n> or i<n>.
	Root string
	// The version the latest set is whole at, and the head's index_epoch there (§11.14's epoch row).
	Pin        SearchSyncPin
	IndexEpoch uint64
	Files      []*SearchManifestFile
	All        SearchManifestAll
	Rolled     []*SearchManifestRolled
	Content    []*SearchManifestContent
	Pins       []SearchSyncPinPair
	Runs       []*SearchManifestRun
	// Every file the pin lists under the root and the erasure set, held or not: what a replay from the pin applies its
	// changes to (a reading: 7.2.7 names files held only).
	Listing []*SearchSyncWanted
}

// How a round learned its target.
type SearchSyncBy string

const (
	// The statements (pin, h], each change of the index noted.
	SearchSyncByReplay SearchSyncBy = "replay"
	// A re-pin past the catch-up budget and a listing of the index's directories.
	SearchSyncByListing SearchSyncBy = "listing"
)

// One file the target lists.
type SearchSyncWanted struct {
	Path          string
	Version       uint64
	ContentSha256 [sha256.Size]byte
	ByteCount     int64
	Partition     SearchCachePartition
	Signer        Id
	// The ref version its push committed at.
	CommitVersion uint64
}

// A bucket a replayed push rolled up.
type SearchSyncRolled struct {
	StartDay   uint32
	WindowDays uint32
	AtVersion  uint64
	// No statement between the pin and the roll-up changed a file of the bucket, so the copy this device holds is the
	// roll-up's input.
	InputWhole bool
}

// The round in progress (DESIGN-DETAILS 7.2.7's plan part).
type SearchSyncPlan struct {
	Root       string
	Target     SearchSyncPin
	IndexEpoch uint64
	By         SearchSyncBy
	// Every file the target lists under the root and the erasure set, by path.
	Wanted []*SearchSyncWanted
	// Fetched toward the target: held, bad or newer, each at its version.
	Staged []*SearchManifestFile
	Rolled []*SearchSyncRolled
	// The pairs the round replayed, oldest first, which the swap adds to the ring.
	Pins []SearchSyncPinPair
}

// The wire forms, JSON with hex for hashes and ids.
type searchManifestWire struct {
	Format     int                         `json:"format"`
	Root       string                      `json:"root"`
	Pin        searchPinWire               `json:"pin"`
	IndexEpoch uint64                      `json:"index_epoch,omitempty"`
	Files      []searchManifestFileWire    `json:"files"`
	All        searchManifestAllWire       `json:"all"`
	Rolled     []searchManifestRolledWire  `json:"rolled,omitempty"`
	Content    []searchManifestContentWire `json:"content,omitempty"`
	Pins       []searchPinWire             `json:"pins,omitempty"`
	Runs       []searchManifestRunWire     `json:"runs,omitempty"`
	Listing    []searchWantedWire          `json:"listing,omitempty"`
}

// A pin as stored.
type searchPinWire struct {
	Version uint64 `json:"version"`
	Chain   string `json:"chain"`
	TimeMs  int64  `json:"time_ms,omitempty"`
}

// A manifest's or plan's file as stored.
type searchManifestFileWire struct {
	Path      string                   `json:"path"`
	Version   uint64                   `json:"version"`
	Sha256    string                   `json:"content_sha256"`
	Bytes     int64                    `json:"byte_count"`
	All       bool                     `json:"all,omitempty"`
	StartDay  uint32                   `json:"start_day,omitempty"`
	State     string                   `json:"state"`
	TimeMinMs int64                    `json:"time_min_ms,omitempty"`
	TimeMaxMs int64                    `json:"time_max_ms,omitempty"`
	Signer    string                   `json:"signer"`
	Run       uint64                   `json:"run,omitempty"`
	Window    uint32                   `json:"window_days,omitempty"`
	Coverage  []searchFileCoverageWire `json:"coverage,omitempty"`
	Small     []byte                   `json:"small,omitempty"`
}

// A file header's coverage row as stored.
type searchFileCoverageWire struct {
	RefId   string `json:"ref_id"`
	Version uint64 `json:"version"`
	Horizon bool   `json:"horizon,omitempty"`
}

// What a manifest holds of all, as stored.
type searchManifestAllWire struct {
	Held             bool          `json:"held,omitempty"`
	Pin              searchPinWire `json:"pin"`
	RolledThroughDay uint32        `json:"rolled_through_day,omitempty"`
}

// A roll-up as stored: a manifest's, or a plan's with its input_whole.
type searchManifestRolledWire struct {
	StartDay   uint32 `json:"start_day"`
	WindowDays uint32 `json:"window_days"`
	AtVersion  uint64 `json:"at_version"`
	InputWhole bool   `json:"input_whole,omitempty"`
}

// A content ref's coverage as stored.
type searchManifestContentWire struct {
	RefId          string                       `json:"ref_id"`
	IndexedThrough uint64                       `json:"indexed_through,omitempty"`
	Rows           []searchManifestCoverageWire `json:"rows,omitempty"`
}

// One writer's coverage row for a content ref, as stored.
type searchManifestCoverageWire struct {
	Writer  string `json:"writer"`
	Version uint64 `json:"version"`
	Horizon bool   `json:"horizon,omitempty"`
}

// A version-table run as stored.
type searchManifestRunWire struct {
	Kind     int      `json:"kind"`
	StartDay uint32   `json:"start_day,omitempty"`
	RunId    uint64   `json:"run"`
	Inputs   []uint64 `json:"inputs,omitempty"`
}

// The plan as stored.
type searchPlanWire struct {
	Format     int                        `json:"format"`
	Root       string                     `json:"root"`
	Target     searchPinWire              `json:"target"`
	IndexEpoch uint64                     `json:"index_epoch,omitempty"`
	By         string                     `json:"by"`
	Wanted     []searchWantedWire         `json:"wanted"`
	Staged     []searchManifestFileWire   `json:"staged,omitempty"`
	Rolled     []searchManifestRolledWire `json:"rolled,omitempty"`
	Pins       []searchPinWire            `json:"pins,omitempty"`
}

// A file the target lists, as stored.
type searchWantedWire struct {
	Path          string `json:"path"`
	Version       uint64 `json:"version"`
	Sha256        string `json:"content_sha256"`
	Bytes         int64  `json:"byte_count"`
	All           bool   `json:"all,omitempty"`
	StartDay      uint32 `json:"start_day,omitempty"`
	Signer        string `json:"signer"`
	CommitVersion uint64 `json:"commit_version,omitempty"`
}

// A manifest or plan that does not decode: derived state, dropped and derived again.
var errSearchManifestUndecodable = errors.New("search manifest undecodable")

// A pin's stored form.
func searchPinWireOf(pin SearchSyncPin) searchPinWire {
	return searchPinWire{Version: pin.Version, Chain: hex.EncodeToString(pin.Chain[:]), TimeMs: pin.TimeMs}
}

// The stored pin, or errSearchManifestUndecodable.
func (self searchPinWire) pin() (SearchSyncPin, error) {
	chain, err := searchHash32(self.Chain)
	if err != nil {
		return SearchSyncPin{}, err
	}
	return SearchSyncPin{Version: self.Version, Chain: chain, TimeMs: self.TimeMs}, nil
}

// 32 bytes from hex, an empty string reading as zero.
func searchHash32(text string) ([sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	if text == "" {
		return hash, nil
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != sha256.Size {
		return hash, errSearchManifestUndecodable
	}
	copy(hash[:], decoded)
	return hash, nil
}

// An id from its stored hex, or errSearchManifestUndecodable.
func searchIdOfWire(text string) (Id, error) {
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(Id{}) {
		return Id{}, errSearchManifestUndecodable
	}
	return Id(decoded), nil
}

// A file's stored form.
func searchManifestFileWireOf(file *SearchManifestFile) searchManifestFileWire {
	wire := searchManifestFileWire{
		Path: file.Path, Version: file.Version, Sha256: hex.EncodeToString(file.ContentSha256[:]), Bytes: file.ByteCount,
		All: file.Partition.All, StartDay: file.Partition.StartDay, State: string(file.State),
		TimeMinMs: file.TimeMinMs, TimeMaxMs: file.TimeMaxMs, Signer: hex.EncodeToString(file.Signer[:]), Run: uint64(file.Run),
		Window: file.WindowDays, Small: file.Small,
	}
	for _, row := range file.Coverage {
		wire.Coverage = append(wire.Coverage, searchFileCoverageWire{RefId: hex.EncodeToString(row.RefId[:]), Version: row.Version, Horizon: row.Horizon})
	}
	return wire
}

// The stored file, or errSearchManifestUndecodable.
func (self searchManifestFileWire) file() (*SearchManifestFile, error) {
	sum, err := searchHash32(self.Sha256)
	if err != nil {
		return nil, err
	}
	signer, err := searchIdOfWire(self.Signer)
	if err != nil {
		return nil, err
	}
	state := SearchManifestFileState(self.State)
	switch state {
	case SearchManifestHeld, SearchManifestBad, SearchManifestNewer:
	default:
		return nil, errSearchManifestUndecodable
	}
	if self.Path == "" || self.Version == 0 {
		return nil, errSearchManifestUndecodable
	}
	file := &SearchManifestFile{
		Path: self.Path, Version: self.Version, ContentSha256: sum, ByteCount: self.Bytes,
		Partition: SearchCachePartition{All: self.All, StartDay: self.StartDay}, State: state,
		TimeMinMs: self.TimeMinMs, TimeMaxMs: self.TimeMaxMs, Signer: signer, Run: SearchVersionRunId(self.Run),
		WindowDays: self.Window, Small: self.Small,
	}
	for _, rowWire := range self.Coverage {
		refId, err := searchIdOfWire(rowWire.RefId)
		if err != nil {
			return nil, err
		}
		file.Coverage = append(file.Coverage, &SearchManifestFileCoverage{RefId: refId, Version: rowWire.Version, Horizon: rowWire.Horizon})
	}
	return file, nil
}

// A roll-up's stored form.
func searchRolledWireOf(startDay uint32, windowDays uint32, atVersion uint64, inputWhole bool) searchManifestRolledWire {
	return searchManifestRolledWire{StartDay: startDay, WindowDays: windowDays, AtVersion: atVersion, InputWhole: inputWhole}
}

// A listed file's stored form.
func searchWantedWireOf(wanted *SearchSyncWanted) searchWantedWire {
	return searchWantedWire{
		Path: wanted.Path, Version: wanted.Version, Sha256: hex.EncodeToString(wanted.ContentSha256[:]), Bytes: wanted.ByteCount,
		All: wanted.Partition.All, StartDay: wanted.Partition.StartDay, Signer: hex.EncodeToString(wanted.Signer[:]),
		CommitVersion: wanted.CommitVersion,
	}
}

// The stored listed file, or errSearchManifestUndecodable.
func (self searchWantedWire) wanted() (*SearchSyncWanted, error) {
	sum, err := searchHash32(self.Sha256)
	if err != nil {
		return nil, err
	}
	signer, err := searchIdOfWire(self.Signer)
	if err != nil {
		return nil, err
	}
	if self.Path == "" || self.Version == 0 {
		return nil, errSearchManifestUndecodable
	}
	return &SearchSyncWanted{
		Path: self.Path, Version: self.Version, ContentSha256: sum, ByteCount: self.Bytes,
		Partition: SearchCachePartition{All: self.All, StartDay: self.StartDay}, Signer: signer,
		CommitVersion: self.CommitVersion,
	}, nil
}

// The manifest as stored.
func (self *SearchManifest) encode() ([]byte, error) {
	wire := searchManifestWire{
		Format: searchManifestFormat, Root: self.Root, Pin: searchPinWireOf(self.Pin), IndexEpoch: self.IndexEpoch,
		Files: []searchManifestFileWire{},
		All: searchManifestAllWire{
			Held: self.All.Held, Pin: searchPinWireOf(self.All.Pin), RolledThroughDay: self.All.RolledThroughDay,
		},
	}
	for _, file := range self.Files {
		wire.Files = append(wire.Files, searchManifestFileWireOf(file))
	}
	for _, rolled := range self.Rolled {
		wire.Rolled = append(wire.Rolled, searchRolledWireOf(rolled.StartDay, rolled.WindowDays, rolled.AtVersion, false))
	}
	for _, content := range self.Content {
		contentWire := searchManifestContentWire{RefId: hex.EncodeToString(content.RefId[:]), IndexedThrough: content.IndexedThrough}
		for _, row := range content.Rows {
			contentWire.Rows = append(contentWire.Rows, searchManifestCoverageWire{
				Writer: hex.EncodeToString(row.Writer[:]), Version: row.Version, Horizon: row.Horizon,
			})
		}
		wire.Content = append(wire.Content, contentWire)
	}
	for _, pair := range self.Pins {
		wire.Pins = append(wire.Pins, searchPinWireOf(SearchSyncPin{Version: pair.Version, Chain: pair.Chain}))
	}
	for _, run := range self.Runs {
		runWire := searchManifestRunWire{Kind: int(run.Slot.Kind), StartDay: run.Slot.StartDay, RunId: uint64(run.RunId)}
		for _, input := range run.Inputs {
			runWire.Inputs = append(runWire.Inputs, uint64(input))
		}
		wire.Runs = append(wire.Runs, runWire)
	}
	for _, listed := range self.Listing {
		wire.Listing = append(wire.Listing, searchWantedWireOf(listed))
	}
	return json.Marshal(wire)
}

// A stored manifest, or errSearchManifestUndecodable.
func searchDecodeManifest(content []byte) (*SearchManifest, error) {
	wire := searchManifestWire{}
	if err := json.Unmarshal(content, &wire); err != nil || wire.Format != searchManifestFormat || wire.Root == "" {
		return nil, errSearchManifestUndecodable
	}
	pin, err := wire.Pin.pin()
	if err != nil {
		return nil, err
	}
	allPin, err := wire.All.Pin.pin()
	if err != nil {
		return nil, err
	}
	manifest := &SearchManifest{
		Root: wire.Root, Pin: pin, IndexEpoch: wire.IndexEpoch,
		All: SearchManifestAll{Held: wire.All.Held, Pin: allPin, RolledThroughDay: wire.All.RolledThroughDay},
	}
	if pin.Version < allPin.Version {
		// all is never ahead of the latest set (7.2.7's step 6)
		return nil, errSearchManifestUndecodable
	}
	for _, fileWire := range wire.Files {
		file, err := fileWire.file()
		if err != nil {
			return nil, err
		}
		manifest.Files = append(manifest.Files, file)
	}
	for _, rolled := range wire.Rolled {
		manifest.Rolled = append(manifest.Rolled, &SearchManifestRolled{StartDay: rolled.StartDay, WindowDays: rolled.WindowDays, AtVersion: rolled.AtVersion})
	}
	for _, contentWire := range wire.Content {
		refId, err := searchIdOfWire(contentWire.RefId)
		if err != nil {
			return nil, err
		}
		content := &SearchManifestContent{RefId: refId, IndexedThrough: contentWire.IndexedThrough}
		for _, rowWire := range contentWire.Rows {
			writer, err := searchIdOfWire(rowWire.Writer)
			if err != nil {
				return nil, err
			}
			content.Rows = append(content.Rows, &SearchManifestCoverage{Writer: writer, Version: rowWire.Version, Horizon: rowWire.Horizon})
		}
		manifest.Content = append(manifest.Content, content)
	}
	for _, pairWire := range wire.Pins {
		pair, err := pairWire.pin()
		if err != nil {
			return nil, err
		}
		manifest.Pins = append(manifest.Pins, SearchSyncPinPair{Version: pair.Version, Chain: pair.Chain})
	}
	for _, runWire := range wire.Runs {
		slot := SearchVersionSlot{Kind: SearchVersionSlotKind(runWire.Kind), StartDay: runWire.StartDay}
		if slot.check() != nil || runWire.RunId == 0 {
			return nil, errSearchManifestUndecodable
		}
		run := &SearchManifestRun{Slot: slot, RunId: SearchVersionRunId(runWire.RunId)}
		for _, input := range runWire.Inputs {
			run.Inputs = append(run.Inputs, SearchVersionRunId(input))
		}
		manifest.Runs = append(manifest.Runs, run)
	}
	for _, listedWire := range wire.Listing {
		listed, err := listedWire.wanted()
		if err != nil {
			return nil, err
		}
		manifest.Listing = append(manifest.Listing, listed)
	}
	return manifest, nil
}

// The plan as stored.
func (self *SearchSyncPlan) encode() ([]byte, error) {
	wire := searchPlanWire{
		Format: searchManifestFormat, Root: self.Root, Target: searchPinWireOf(self.Target), IndexEpoch: self.IndexEpoch,
		By: string(self.By), Wanted: []searchWantedWire{},
	}
	for _, wanted := range self.Wanted {
		wire.Wanted = append(wire.Wanted, searchWantedWireOf(wanted))
	}
	for _, staged := range self.Staged {
		wire.Staged = append(wire.Staged, searchManifestFileWireOf(staged))
	}
	for _, rolled := range self.Rolled {
		wire.Rolled = append(wire.Rolled, searchRolledWireOf(rolled.StartDay, rolled.WindowDays, rolled.AtVersion, rolled.InputWhole))
	}
	for _, pair := range self.Pins {
		wire.Pins = append(wire.Pins, searchPinWireOf(SearchSyncPin{Version: pair.Version, Chain: pair.Chain}))
	}
	return json.Marshal(wire)
}

// A stored plan, or errSearchManifestUndecodable.
func searchDecodePlan(content []byte) (*SearchSyncPlan, error) {
	wire := searchPlanWire{}
	if err := json.Unmarshal(content, &wire); err != nil || wire.Format != searchManifestFormat || wire.Root == "" {
		return nil, errSearchManifestUndecodable
	}
	target, err := wire.Target.pin()
	if err != nil {
		return nil, err
	}
	by := SearchSyncBy(wire.By)
	if by != SearchSyncByReplay && by != SearchSyncByListing {
		return nil, errSearchManifestUndecodable
	}
	plan := &SearchSyncPlan{Root: wire.Root, Target: target, IndexEpoch: wire.IndexEpoch, By: by}
	for _, wantedWire := range wire.Wanted {
		wanted, err := wantedWire.wanted()
		if err != nil {
			return nil, err
		}
		plan.Wanted = append(plan.Wanted, wanted)
	}
	for _, stagedWire := range wire.Staged {
		staged, err := stagedWire.file()
		if err != nil {
			return nil, err
		}
		plan.Staged = append(plan.Staged, staged)
	}
	for _, rolled := range wire.Rolled {
		plan.Rolled = append(plan.Rolled, &SearchSyncRolled{StartDay: rolled.StartDay, WindowDays: rolled.WindowDays, AtVersion: rolled.AtVersion, InputWhole: rolled.InputWhole})
	}
	for _, pairWire := range wire.Pins {
		pair, err := pairWire.pin()
		if err != nil {
			return nil, err
		}
		plan.Pins = append(plan.Pins, SearchSyncPinPair{Version: pair.Version, Chain: pair.Chain})
	}
	return plan, nil
}

// The manifest's file at path, nil for none.
func (self *SearchManifest) file(path string) *SearchManifestFile {
	for _, file := range self.Files {
		if file.Path == path {
			return file
		}
	}
	return nil
}

// The plan's staged copy of path at version, nil for none.
func (self *SearchSyncPlan) staged(path string, version uint64) *SearchManifestFile {
	for _, staged := range self.Staged {
		if staged.Path == path && staged.Version == version {
			return staged
		}
	}
	return nil
}

// Where a ref-level part is kept at serial: the ref's path, at that version.
func searchManifestKey(repoId Id, refId Id, serial uint64) SearchCacheKey {
	return SearchCacheKey{RepoId: repoId, RefId: refId, Path: SearchCacheRefPath, Version: serial}
}

// The newest whole copy of a ref-level part and its serial: nil and 0 for none. Copies that do not read, and older
// ones, are removed.
func searchLoadRefPart(cache *SearchCache, repoId Id, refId Id, part SearchCachePart) ([]byte, uint64, error) {
	serials, err := cache.DerivedVersions(repoId, refId, SearchCacheRefPath, part)
	if err != nil {
		return nil, 0, err
	}
	var content []byte
	var serial uint64
	for _, candidate := range slices.Backward(serials) {
		if content != nil {
			if err := cache.RemoveDerived(searchManifestKey(repoId, refId, candidate), part); err != nil {
				return nil, 0, err
			}
			continue
		}
		frames, err := cache.OpenDerived(searchManifestKey(repoId, refId, candidate), part)
		if err != nil {
			if errors.Is(err, ErrSearchCacheRefetch) || errors.Is(err, ErrSidecarStoreAbsent) {
				continue
			}
			return nil, 0, err
		}
		whole, err := frames.ReadAll()
		if err != nil {
			if errors.Is(err, ErrSearchCacheRefetch) {
				continue
			}
			return nil, 0, err
		}
		content, serial = whole, candidate
	}
	return content, serial, nil
}

// Writes a ref-level part whole at the serial after previous, then removes previous: the part's commit.
func searchStoreRefPart(ctx context.Context, cache *SearchCache, repoId Id, refId Id, part SearchCachePart, content []byte, previous uint64) (uint64, error) {
	serial := previous + 1
	err := cache.PutDerived(ctx, &SearchCacheDerived{Key: searchManifestKey(repoId, refId, serial), Part: part, Plaintext: content})
	if err != nil {
		return 0, err
	}
	if previous != 0 {
		if err := cache.RemoveDerived(searchManifestKey(repoId, refId, previous), part); err != nil {
			return 0, err
		}
	}
	return serial, nil
}

// The partition an index path's file belongs to: all's shards and a/m to all, a bucket's files to that bucket. Every
// other path (settings, the lock, the erasure set) belongs to none and answers false.
func searchPartitionOfPath(path indexPath) (SearchCachePartition, bool) {
	switch path.kind {
	case indexPathAllShard:
		return SearchCachePartition{All: true}, true
	case indexPathBucketManifest, indexPathBucketShard, indexPathSlot, indexPathLargeEntry:
		return SearchCachePartition{StartDay: path.bucketStartDay}, true
	}
	return SearchCachePartition{}, false
}

// A short label of a file for a log line: its kind and partition, never its path (I-13).
func searchFileLabel(path indexPath) string {
	label := strconv.Itoa(int(path.kind))
	if path.kind != indexPathErasureSet && path.kind != indexPathSettings {
		label += "@" + strconv.FormatUint(uint64(path.bucketStartDay), 10)
	}
	return label
}

// Whether a manifest's root names a companion index (ur/index), where rows carry their ref_id.
func searchRootCompanion(root string) bool {
	return !strings.HasPrefix(root, indexFileModePrefix)
}

// A manifest check that should never fail on a manifest this code wrote: every file's path parses under its root or
// is the erasure set.
func (self *SearchManifest) check() error {
	companion := searchRootCompanion(self.Root)
	for _, file := range self.Files {
		if _, ok := indexParsePath(file.Path, companion); !ok {
			return fmt.Errorf("%w: a file outside the index", errSearchManifestUndecodable)
		}
	}
	return nil
}
