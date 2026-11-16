// D-TEST-17's golden schedule for FS-86 (RECORD-M6-24; §16.11's cost table, D-MCP-31): DirectoryCostOracle computes,
// from a schedule's events and each reader's sync times alone, every reader's expected requests, path reads and
// ciphertext bytes, and Check holds what a run measured to within Tolerance of them, per reader-day and per team-day.
// It shares no code with the client: it never calls sidecar.DirectoryClient, its store or its fold, and reads nothing
// a sync answered. What it knows is §16.11's sync row and §11.9's read rules, written again here:
//
//	cards     one read of the cards ref's statements after the reader's pin, a page at a time, at least one request
//	listing   one GET .../refs, with moved_after but at the reader's first sync and its first of each UTC day
//	streams   the streams whose head passed what the reader holds, StreamReadCount to a request; a stream holding
//	          more than a frame answers more and is asked again in a later request, and one whose pin is older than
//	          the window answers behind and is paged through GET .../log
//	erasure   one read of the erasure ref when it moved
//
// This is M6's form, announce entries on writers' own streams and only notices on the cards ref. The card case, its
// cards fetched by sync position and index heads reproduced, is RECORD-M10-07's.
//
// Path reads are evs's store GETs. On T2 no store stands behind the fakes, so the oracle and the meter that measures a
// run (DirectoryCostMeter) both price them by the settings here, whose defaults follow §16.11's table, a path read a
// version read and a statement read, heads answered from the head cache; on T3 the measured ones are the stores' own
// counts, and the same settings are the expectation they are held to.
//
// An event whose time is at or before a sync's is seen by that sync, so a run commits every such event before it
// syncs. Not safe for concurrent use.

package sidecartest

import (
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar"
)

// What one committed push of the directory is, as evs holds it.
type DirectoryCostEventKind int

const (
	// One version of a writer's own stream: its statement, entries and slot rows.
	DirectoryCostEventStream DirectoryCostEventKind = iota + 1
	// A notice written or rewritten on the cards ref.
	DirectoryCostEventNotice
	// A notice removed from the cards ref.
	DirectoryCostEventNoticeRemoved
	// An ERASE on the erasure ref.
	DirectoryCostEventErasure
)

// One committed push.
type DirectoryCostEvent struct {
	// evs's time for the commit, Unix milliseconds.
	TimeMillis int64
	Kind       DirectoryCostEventKind
	// A stream version's writer; zero for any other event.
	WriterSidecarId sidecar.Id
	// The ciphertext bytes a reader fetching it transfers past its statement: a version's entries and slot rows, a
	// notice's content, an ERASE's keys and note; 0 for a removal.
	ByteCount int64
}

// One reader: a following daemon and the times it syncs.
type DirectoryCostReader struct {
	SidecarId sidecar.Id
	// Ascending, Unix milliseconds.
	SyncMillis []int64
}

// What happened and who read it: the oracle's whole input.
type DirectoryCostSchedule struct {
	// In commit order, times never falling.
	Events  []*DirectoryCostEvent
	Readers []*DirectoryCostReader
}

// What reading cost.
type DirectoryCost struct {
	RequestCount  int64
	PathReadCount int64
	ByteCount     int64
}

func (self *DirectoryCost) Add(other *DirectoryCost) {
	self.RequestCount += other.RequestCount
	self.PathReadCount += other.PathReadCount
	self.ByteCount += other.ByteCount
}

func (self *DirectoryCost) String() string {
	return fmt.Sprintf("%d requests, %d path reads, %d bytes", self.RequestCount, self.PathReadCount, self.ByteCount)
}

// One reader's UTC day, days since 1970-01-01.
type DirectoryCostDay struct {
	SidecarId sidecar.Id
	Day       int64
}

// Costs by reader-day, expected or measured.
type DirectoryCosts struct {
	ReaderDays map[DirectoryCostDay]*DirectoryCost
}

func NewDirectoryCosts() *DirectoryCosts {
	return &DirectoryCosts{ReaderDays: map[DirectoryCostDay]*DirectoryCost{}}
}

// Adds cost to sidecarId's day holding timeMillis.
func (self *DirectoryCosts) Charge(sidecarId sidecar.Id, timeMillis int64, cost *DirectoryCost) {
	key := DirectoryCostDay{SidecarId: sidecarId, Day: DirectoryCostUtcDay(timeMillis)}
	day, ok := self.ReaderDays[key]
	if !ok {
		day = &DirectoryCost{}
		self.ReaderDays[key] = day
	}
	day.Add(cost)
}

// The reader-days in reader and day order.
func (self *DirectoryCosts) Days() []DirectoryCostDay {
	days := make([]DirectoryCostDay, 0, len(self.ReaderDays))
	for day := range self.ReaderDays {
		days = append(days, day)
	}
	slices.SortFunc(days, func(a DirectoryCostDay, b DirectoryCostDay) int {
		if order := a.SidecarId.Cmp(b.SidecarId); order != 0 {
			return order
		}
		return int(a.Day - b.Day)
	})
	return days
}

// Each UTC day's sum over the readers readerIds holds, every reader when it is nil: a team-day.
func (self *DirectoryCosts) TeamDays(readerIds map[sidecar.Id]bool) map[int64]*DirectoryCost {
	teamDays := map[int64]*DirectoryCost{}
	for key, cost := range self.ReaderDays {
		if readerIds != nil && !readerIds[key.SidecarId] {
			continue
		}
		teamDay, ok := teamDays[key.Day]
		if !ok {
			teamDay = &DirectoryCost{}
			teamDays[key.Day] = teamDay
		}
		teamDay.Add(cost)
	}
	return teamDays
}

// The sum over every reader-day.
func (self *DirectoryCosts) Total() *DirectoryCost {
	total := &DirectoryCost{}
	for _, cost := range self.ReaderDays {
		total.Add(cost)
	}
	return total
}

// Days since 1970-01-01 in UTC.
func DirectoryCostUtcDay(timeMillis int64) int64 {
	return timeMillis / (24 * 60 * 60 * 1000)
}

type DirectoryCostOracleSettings struct {
	// Streams one POST .../read {refs} names: 64 (§11.9's streams row; D-MCP-31).
	StreamReadCount int
	// Versions of one stream a read carries before it answers more: 64, sidecartest's stand-in for the reply's 4 MiB
	// frame (FakeDirectoryCardsSettings.FrameVersionCount). Non-positive bounds nothing.
	StreamFrameVersionCount int
	// Versions back a stream's window reaches, an older pin answering behind: 4,096.
	StreamWindowVersionCount int
	// Versions a GET .../log page carries: 1,000 (§11.9).
	StreamLogPageCount int
	// Statements of the cards ref one read carries: 1,000.
	CardsPageCount int
	// A push statement's bytes, which every version, cards ref statement and ERASE read carries: 800 (§16.11's sizes
	// row, about 0.8 KiB).
	StatementByteCount int64
	// One ref's bytes in a listing: 64, its id, version, sequence value and chain value.
	RefByteCount int64
	// Store GETs a listing costs, and each ref it reads a head for: 1 for the LIST, and 0 a ref, its head answered
	// from the head cache (§11.9's cache row).
	ListingPathReadCount int64
	RefPathReadCount     int64
	// Store GETs a stream named in a read costs before its versions: 0, its head from the head cache.
	StreamPathReadCount int64
	// Store GETs one version read costs: 1 (§16.11's table: a team-day's path reads are about its readers' versions).
	VersionPathReadCount int64
	// Store GETs a GET .../log page costs past its versions: 1.
	LogPagePathReadCount int64
	// Store GETs a read of the cards ref costs, and each statement it carries: 1 and 1; a notice rides its statement
	// inline (256 B), so a file costs none.
	CardsPathReadCount         int64
	CardStatementPathReadCount int64
	// Store GETs a read of the erasure ref costs, and each ERASE it carries: 1 and 1.
	ErasurePathReadCount      int64
	ErasureEntryPathReadCount int64
	// What measured may reach against expected, and expected against measured: 1.25 (D-TEST-17).
	Tolerance float64
	// A count this far or less from its expectation passes whatever the ratio: 2, so a day of two requests is not
	// failed by one request of rounding. Non-positive allows none.
	Slack int64
}

func DefaultDirectoryCostOracleSettings() *DirectoryCostOracleSettings {
	return &DirectoryCostOracleSettings{
		StreamReadCount:            64,
		StreamFrameVersionCount:    64,
		StreamWindowVersionCount:   4096,
		StreamLogPageCount:         1000,
		CardsPageCount:             1000,
		StatementByteCount:         800,
		RefByteCount:               64,
		ListingPathReadCount:       1,
		RefPathReadCount:           0,
		StreamPathReadCount:        0,
		VersionPathReadCount:       1,
		LogPagePathReadCount:       1,
		CardsPathReadCount:         1,
		CardStatementPathReadCount: 1,
		ErasurePathReadCount:       1,
		ErasureEntryPathReadCount:  1,
		Tolerance:                  1.25,
		Slack:                      2,
	}
}

// See the file header.
type DirectoryCostOracle struct {
	settings *DirectoryCostOracleSettings
}

// settings nil takes the defaults.
func NewDirectoryCostOracle(settings *DirectoryCostOracleSettings) *DirectoryCostOracle {
	if settings == nil {
		settings = DefaultDirectoryCostOracleSettings()
	}
	return &DirectoryCostOracle{settings: settings}
}

func (self *DirectoryCostOracle) Settings() *DirectoryCostOracleSettings {
	return self.settings
}

// The schedule as the oracle walks it: each stream a dense index, each event's running totals.
type directoryCostWalk struct {
	events []*DirectoryCostEvent
	// each event's stream index, -1 for an event on no stream
	streams     []int
	streamCount int
	// the streams that hold a version once each event is committed
	streamsSeen []int
	// the first event on the cards ref and on the erasure ref, the event count for none
	firstCard    int
	firstErasure int
}

// One reader's copy as its syncs leave it.
type directoryCostReaderState struct {
	// events before this index are read
	cut int
	// the versions held of each stream, and the events of each still to read
	synced       bool
	listingDay   int64
	held         []int64
	pending      []int64
	pendingBytes []int64
	touched      []int
}

func (self *DirectoryCostOracle) walk(schedule *DirectoryCostSchedule) (*directoryCostWalk, error) {
	walk := &directoryCostWalk{
		events:       schedule.Events,
		streams:      make([]int, len(schedule.Events)),
		streamsSeen:  make([]int, len(schedule.Events)),
		firstCard:    len(schedule.Events),
		firstErasure: len(schedule.Events),
	}
	indexes := map[sidecar.Id]int{}
	lastMillis := int64(0)
	for i, event := range schedule.Events {
		if event == nil {
			return nil, fmt.Errorf("event %d is nil", i)
		}
		if event.TimeMillis < lastMillis {
			return nil, fmt.Errorf("event %d at %d is before the one it follows at %d", i, event.TimeMillis, lastMillis)
		}
		lastMillis = event.TimeMillis
		if event.ByteCount < 0 {
			return nil, fmt.Errorf("event %d carries %d bytes", i, event.ByteCount)
		}
		walk.streams[i] = -1
		switch event.Kind {
		case DirectoryCostEventStream:
			index, ok := indexes[event.WriterSidecarId]
			if !ok {
				index = len(indexes)
				indexes[event.WriterSidecarId] = index
			}
			walk.streams[i] = index
		case DirectoryCostEventNotice, DirectoryCostEventNoticeRemoved:
			walk.firstCard = min(walk.firstCard, i)
		case DirectoryCostEventErasure:
			walk.firstErasure = min(walk.firstErasure, i)
		default:
			return nil, fmt.Errorf("event %d is of kind %d", i, event.Kind)
		}
		walk.streamsSeen[i] = len(indexes)
	}
	walk.streamCount = len(indexes)
	return walk, nil
}

// Requests reading count items takes at pageCount an answer, one at least.
func directoryCostPages(count int64, pageCount int) int64 {
	if pageCount <= 0 || count <= int64(pageCount) {
		return 1
	}
	return (count + int64(pageCount) - 1) / int64(pageCount)
}

// One sync of state at timeMillis: what it costs, the copy moved on.
func (self *DirectoryCostOracle) sync(walk *directoryCostWalk, state *directoryCostReaderState, timeMillis int64) *DirectoryCost {
	settings := self.settings
	cost := &DirectoryCost{}

	// what committed since the reader's last sync
	cut := state.cut
	for cut < len(walk.events) && walk.events[cut].TimeMillis <= timeMillis {
		cut += 1
	}
	cardStatements := int64(0)
	cardBytes := int64(0)
	erasures := int64(0)
	erasureBytes := int64(0)
	state.touched = state.touched[:0]
	for i := state.cut; i < cut; i += 1 {
		event := walk.events[i]
		switch event.Kind {
		case DirectoryCostEventStream:
			stream := walk.streams[i]
			if state.pending[stream] == 0 {
				state.touched = append(state.touched, stream)
			}
			state.pending[stream] += 1
			state.pendingBytes[stream] += event.ByteCount
		case DirectoryCostEventNotice, DirectoryCostEventNoticeRemoved:
			cardStatements += 1
			cardBytes += settings.StatementByteCount + event.ByteCount
		case DirectoryCostEventErasure:
			erasures += 1
			erasureBytes += settings.StatementByteCount + event.ByteCount
		}
	}

	// cards: the statements after the pin, a page at a time
	cardRequests := directoryCostPages(cardStatements, settings.CardsPageCount)
	cost.RequestCount += cardRequests
	cost.PathReadCount += cardRequests*settings.CardsPathReadCount + cardStatements*settings.CardStatementPathReadCount
	cost.ByteCount += cardBytes

	// listing: every ref at the first sync and the first of each UTC day, else the refs that moved
	day := DirectoryCostUtcDay(timeMillis)
	full := !state.synced || state.listingDay != day
	listed := int64(len(state.touched))
	if 0 < cardStatements {
		listed += 1
	}
	if 0 < erasures {
		listed += 1
	}
	if full {
		listed = 0
		if 0 < cut {
			listed = int64(walk.streamsSeen[cut-1])
		}
		if walk.firstCard < cut {
			listed += 1
		}
		if walk.firstErasure < cut {
			listed += 1
		}
	}
	cost.RequestCount += 1
	cost.PathReadCount += settings.ListingPathReadCount + listed*settings.RefPathReadCount
	cost.ByteCount += listed * settings.RefByteCount

	// streams: StreamReadCount to a request, more asked again in a later request, behind paged through the log
	queue := make([]int64, 0, len(state.touched))
	for _, stream := range state.touched {
		queue = append(queue, state.pending[stream])
		cost.ByteCount += state.pending[stream]*settings.StatementByteCount + state.pendingBytes[stream]
		cost.PathReadCount += state.pending[stream] * settings.VersionPathReadCount
		state.held[stream] += state.pending[stream]
		state.pending[stream] = 0
		state.pendingBytes[stream] = 0
	}
	for 0 < len(queue) {
		batchCount := len(queue)
		if 0 < settings.StreamReadCount {
			batchCount = min(batchCount, settings.StreamReadCount)
		}
		batch := queue[:batchCount]
		queue = queue[batchCount:]
		cost.RequestCount += 1
		cost.PathReadCount += int64(batchCount) * settings.StreamPathReadCount
		for _, left := range batch {
			switch {
			case 0 < settings.StreamWindowVersionCount && int64(settings.StreamWindowVersionCount) < left:
				pages := directoryCostPages(left, settings.StreamLogPageCount)
				cost.RequestCount += pages
				cost.PathReadCount += pages * settings.LogPagePathReadCount
			case 0 < settings.StreamFrameVersionCount && int64(settings.StreamFrameVersionCount) < left:
				queue = append(queue, left-int64(settings.StreamFrameVersionCount))
			}
		}
	}

	// the erasure ref, when it moved
	if 0 < erasures {
		cost.RequestCount += 1
		cost.PathReadCount += settings.ErasurePathReadCount + erasures*settings.ErasureEntryPathReadCount
		cost.ByteCount += erasureBytes
	}

	state.cut = cut
	state.synced = true
	state.listingDay = day
	return cost
}

// Every reader-day's expected cost.
func (self *DirectoryCostOracle) Expected(schedule *DirectoryCostSchedule) (*DirectoryCosts, error) {
	if schedule == nil {
		return nil, fmt.Errorf("no schedule")
	}
	walk, err := self.walk(schedule)
	if err != nil {
		return nil, err
	}
	costs := NewDirectoryCosts()
	seen := map[sidecar.Id]bool{}
	for _, reader := range schedule.Readers {
		if reader == nil || seen[reader.SidecarId] {
			return nil, fmt.Errorf("a reader is nil or named twice")
		}
		seen[reader.SidecarId] = true
		state := &directoryCostReaderState{
			held:         make([]int64, walk.streamCount),
			pending:      make([]int64, walk.streamCount),
			pendingBytes: make([]int64, walk.streamCount),
		}
		lastMillis := int64(0)
		for i, syncMillis := range reader.SyncMillis {
			if syncMillis < lastMillis {
				return nil, fmt.Errorf("reader %s's sync %d at %d is before the one it follows", reader.SidecarId, i, syncMillis)
			}
			lastMillis = syncMillis
			costs.Charge(reader.SidecarId, syncMillis, self.sync(walk, state, syncMillis))
		}
	}
	return costs, nil
}

// Whether a measured count stays within the tolerance of its expectation, either way.
func (self *DirectoryCostOracle) within(expected int64, measured int64) bool {
	difference := measured - expected
	if difference < 0 {
		difference = -difference
	}
	if 0 < self.settings.Slack && difference <= self.settings.Slack {
		return true
	}
	return float64(measured) <= self.settings.Tolerance*float64(expected) && float64(expected) <= self.settings.Tolerance*float64(measured)
}

func (self *DirectoryCostOracle) compare(what string, expected *DirectoryCost, measured *DirectoryCost) []error {
	errs := []error{}
	check := func(name string, expectedCount int64, measuredCount int64) {
		if !self.within(expectedCount, measuredCount) {
			errs = append(errs, fmt.Errorf("%s: %d %s measured against %d expected, outside %.2f times", what, measuredCount, name, expectedCount, self.settings.Tolerance))
		}
	}
	check("requests", expected.RequestCount, measured.RequestCount)
	check("path reads", expected.PathReadCount, measured.PathReadCount)
	check("bytes", expected.ByteCount, measured.ByteCount)
	return errs
}

// Holds measured to expected: every reader-day measured, and every team-day summed over the readers measured, within
// Tolerance, a reader-day one side lacks failing too. A measure above its expectation is the implementation costing
// more than the table allows; one below it is a reader that did not read what the schedule gave it, or an oracle that
// is wrong, and fails as well.
func (self *DirectoryCostOracle) Check(expected *DirectoryCosts, measured *DirectoryCosts) []error {
	errs := []error{}
	readerIds := map[sidecar.Id]bool{}
	for _, key := range measured.Days() {
		readerIds[key.SidecarId] = true
		expectedCost, ok := expected.ReaderDays[key]
		if !ok {
			errs = append(errs, fmt.Errorf("reader %s day %d: measured %s where the schedule expects no sync", key.SidecarId, key.Day, measured.ReaderDays[key]))
			continue
		}
		errs = append(errs, self.compare(fmt.Sprintf("reader %s day %d", key.SidecarId, key.Day), expectedCost, measured.ReaderDays[key])...)
	}
	for _, key := range expected.Days() {
		if _, ok := measured.ReaderDays[key]; readerIds[key.SidecarId] && !ok {
			errs = append(errs, fmt.Errorf("reader %s day %d: nothing measured where the schedule expects %s", key.SidecarId, key.Day, expected.ReaderDays[key]))
		}
	}
	if len(readerIds) == 0 {
		return append(errs, fmt.Errorf("nothing was measured"))
	}
	expectedTeam := expected.TeamDays(readerIds)
	measuredTeam := measured.TeamDays(readerIds)
	days := []int64{}
	for day := range measuredTeam {
		days = append(days, day)
	}
	slices.Sort(days)
	for _, day := range days {
		expectedCost, ok := expectedTeam[day]
		if !ok {
			continue
		}
		errs = append(errs, self.compare(fmt.Sprintf("team day %d over %d readers", day, len(readerIds)), expectedCost, measuredTeam[day])...)
	}
	return errs
}
