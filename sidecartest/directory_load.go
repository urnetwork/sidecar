//go:build !ios_extension

// §22.8's directory row harness in M6's form (RECORD-M6-24; D-TEST-17, D-MCP-31, FS-86): §16.11's load model as a plan
// of pushes and reader syncs, a run of that plan against a directory behind sidecar.RecordStreams and
// sidecar.DirectoryCards, and what the run measured, which DirectoryCostOracle's expectation, §16.11's table and its
// ceilings hold it to.
//
//	plan      per member a day 10 runs of 40 min, 1.5 announcing sidecars, 0.3 requests and 2 coordination entries,
//	          80% of pushes in 9 hours, peaking at 1.5x, 2.5 admissions and 1.2 following daemons a member: each
//	          run's start and end and each renewal an announce entry on its sidecar's own stream, each coordination,
//	          request and decision entry a version of its writer's stream, each request a notice created, rewritten
//	          and removed on the cards ref (§16.11's pushes row, M6's form); every following daemon syncs on the
//	          desktops row's cadence, SessionSyncInterval while it serves a harness session, a run of its member's
//	          being open, else IdleSyncInterval, and at its views
//	writers   surrogates of the announcing daemons: each seals its entries for real with its own key and chain
//	          (sidecar.RecordSeal) and pushes them to its own stream, so a reader verifies every one as any log's.
//	          They are not sidecar.DirectoryRuns: the cost a reader pays does not turn on who composed an entry, and
//	          a request's and a decision's entries are written as coordination entries, their protocol being FS-85's
//	          and FS-100's
//	readers   SampledReaderCount of the following daemons run the real sidecar.DirectoryClient, each sync a call of
//	          its Sync at the plan's time, behind a DirectoryCostMeter that counts every request, path read and byte;
//	          the oracle computes every reader's expectation, so a team-day past the sample is the oracle's own
//	cold      after the last push, a desktop that never synced syncs once, and a phone opens a metered view through
//	          sidecar.DirectoryClient.View (RECORD-M6-27): past the cap it must show partial coverage naming what is
//	          left, and reach a complete view once the metered bytes are allowed, reading nothing twice
//	mutants   one at a time, a mutant stands between a reader and the meter and asks evs what a client without the
//	          mechanism would: one read a moved stream, re-reading unmoved streams, refetching unchanged notices.
//	          Each must fail the oracle's check. They are seam mutants, not edits of the client
//	ceilings  M6's stream pushes p99 <= 300 ms from arrival to commit, and the priced NVMe bytes a drive a day within
//	          the table's row. Where the seams give a commit's duration (the fakes' store model, with any injected
//	          head PUT delay) latency is that model's, each ref's commits queueing behind one another; where they do
//	          not, it is measured on the clock
//
// The same plan and run serve a longer or a physical run: the seams name the clock, the streams and the cards, and a
// T3 run passes T3's. The fakes here are T2's.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

type DirectoryLoadSettings struct {
	// The plan's randomness: one seed, one plan.
	Seed uint64
	// The team's members.
	MemberCount int
	// Whole UTC days the plan runs.
	DayCount int
	// §16.11's model row, per member a working day.
	RunsPerMemberDay                float64
	RunDuration                     time.Duration
	AnnouncingSidecarsPerMember     float64
	RequestsPerMemberDay            float64
	CoordinationEntriesPerMemberDay float64
	AdmissionsPerMember             float64
	FollowingDaemonsPerMember       float64
	// §16.11's pushes row: 10.3 renewals a member-day, an hourly renewal of each announcing sidecar's open items.
	RenewalsPerMemberDay float64
	// The working hours, from WorkStart past UTC midnight for WorkDuration, which hold WorkShare of a day's pushes: 9
	// hours and 80%.
	WorkStart    time.Duration
	WorkDuration time.Duration
	WorkShare    float64
	// The peak inside the working hours, from PeakStart past their start for PeakDuration, at PeakFactor times their
	// mean rate: 1.5.
	PeakStart    time.Duration
	PeakDuration time.Duration
	PeakFactor   float64
	// A decision follows its request by up to DecisionDelay, and the requester's removal of the notice its decision
	// by up to NoticeCloseDelay.
	DecisionDelay    time.Duration
	NoticeCloseDelay time.Duration
	// §16.11's desktops row: a following daemon's sync intervals while it serves a harness session, a run of its
	// member's being open, and with none.
	SessionSyncInterval time.Duration
	IdleSyncInterval    time.Duration
	// Syncs a daemon's views and searches add a day, which with the intervals makes the sync row's about 60: 22.
	ViewSyncsPerDaemonDay float64
	// The following daemons that run the real client and are measured. Non-positive measures every one.
	SampledReaderCount int
	// The directory settings every reader runs with; nil takes sidecar's defaults.
	Directory *sidecar.SidecarDirectorySettings
}

// §16.11's model at 500 members for one day, four readers measured.
func DefaultDirectoryLoadSettings() *DirectoryLoadSettings {
	directory := sidecar.DefaultSidecarSettings().Directory
	return &DirectoryLoadSettings{
		Seed:                            1,
		MemberCount:                     500,
		DayCount:                        1,
		RunsPerMemberDay:                10,
		RunDuration:                     40 * time.Minute,
		AnnouncingSidecarsPerMember:     1.5,
		RequestsPerMemberDay:            0.3,
		CoordinationEntriesPerMemberDay: 2,
		AdmissionsPerMember:             2.5,
		FollowingDaemonsPerMember:       1.2,
		RenewalsPerMemberDay:            10.3,
		WorkStart:                       8 * time.Hour,
		WorkDuration:                    9 * time.Hour,
		WorkShare:                       0.8,
		PeakStart:                       2 * time.Hour,
		PeakDuration:                    time.Hour,
		PeakFactor:                      1.5,
		DecisionDelay:                   30 * time.Minute,
		NoticeCloseDelay:                10 * time.Minute,
		SessionSyncInterval:             directory.SessionSyncInterval,
		IdleSyncInterval:                directory.IdleSyncInterval,
		ViewSyncsPerDaemonDay:           22,
		SampledReaderCount:              4,
	}
}

// What one push of the plan is.
type DirectoryLoadPushKind int

const (
	// A run's start, its end and a renewal: announce entries on the sidecar's own stream.
	DirectoryLoadPushRunStart DirectoryLoadPushKind = iota + 1
	DirectoryLoadPushRunEnd
	DirectoryLoadPushRenewal
	// A coordination, request or decision entry on its writer's own stream.
	DirectoryLoadPushEntry
	// A request's notice on the cards ref: created by the requester, rewritten by an approver, removed by the
	// requester.
	DirectoryLoadPushNoticeCreate
	DirectoryLoadPushNoticeRewrite
	DirectoryLoadPushNoticeRemove
)

// Whether the push is a version of a writer's own stream.
func (self DirectoryLoadPushKind) Stream() bool {
	return DirectoryLoadPushRunStart <= self && self <= DirectoryLoadPushEntry
}

func (self DirectoryLoadPushKind) String() string {
	switch self {
	case DirectoryLoadPushRunStart:
		return "run start"
	case DirectoryLoadPushRunEnd:
		return "run end"
	case DirectoryLoadPushRenewal:
		return "renewal"
	case DirectoryLoadPushEntry:
		return "entry"
	case DirectoryLoadPushNoticeCreate:
		return "notice created"
	case DirectoryLoadPushNoticeRewrite:
		return "notice rewritten"
	case DirectoryLoadPushNoticeRemove:
		return "notice removed"
	}
	return fmt.Sprintf("push kind %d", int(self))
}

// One push the plan orders.
type DirectoryLoadPush struct {
	// When it arrives, Unix milliseconds.
	TimeMillis int64
	Kind       DirectoryLoadPushKind
	// The index of its writer in the plan's sidecars.
	Sidecar int
	// A run push's run and a notice push's request, by the plan's numbering; -1 for any other.
	Run     int
	Request int
}

// One admitted sidecar of the plan.
type DirectoryLoadSidecar struct {
	SidecarId sidecar.Id
	MemberId  sidecar.Id
	// Its identity key.
	Key ed25519.PrivateKey
	// It announces: it writes its own stream.
	Announces bool
	// It is a following daemon: it syncs at SyncMillis, ascending.
	Follows    bool
	SyncMillis []int64
}

// §16.11's model made concrete: who is admitted, what is pushed when, and when each reader syncs.
type DirectoryLoadPlan struct {
	Settings *DirectoryLoadSettings
	// The UTC midnight the plan starts at, and where it ends.
	StartMillis int64
	EndMillis   int64
	Sidecars    []*DirectoryLoadSidecar
	// In arrival order.
	Pushes       []*DirectoryLoadPush
	RunCount     int
	RequestCount int
	// The two sidecars that read nothing until the plan's pushes end: a desktop that then syncs once and a phone that
	// opens a metered view.
	ColdDesktop int
	ColdPhone   int
}

// The plan's sidecars that announce, and those that follow.
func (self *DirectoryLoadPlan) Counts() (announcing int, following int) {
	for _, planned := range self.Sidecars {
		if planned.Announces {
			announcing += 1
		}
		if planned.Follows {
			following += 1
		}
	}
	return announcing, following
}

// How many of count a rate gives its nth holder, so that the first n holders hold floor(rate*n) in all.
func directoryLoadShare(rate float64, n int) int {
	return int(math.Floor(rate*float64(n+1)+1e-9)) - int(math.Floor(rate*float64(n)+1e-9))
}

// A day's arrival times by §16.11's model: WorkShare of them in the working hours, the peak at PeakFactor times those
// hours' mean rate.
type directoryLoadDay struct {
	settings *DirectoryLoadSettings
	// each span's start, duration and share of a day's arrivals
	starts    []time.Duration
	durations []time.Duration
	shares    []float64
}

func newDirectoryLoadDay(settings *DirectoryLoadSettings) (*directoryLoadDay, error) {
	day := 24 * time.Hour
	workEnd := settings.WorkStart + settings.WorkDuration
	peakStart := settings.WorkStart + settings.PeakStart
	peakEnd := peakStart + settings.PeakDuration
	if settings.WorkStart < 0 || settings.WorkDuration <= 0 || day < workEnd || settings.PeakDuration < 0 || peakStart < settings.WorkStart || workEnd < peakEnd {
		return nil, fmt.Errorf("the working hours or the peak do not fit a day")
	}
	if settings.WorkShare < 0 || 1 < settings.WorkShare {
		return nil, fmt.Errorf("a work share of %f", settings.WorkShare)
	}
	peakShare := 0.0
	if 0 < settings.PeakDuration {
		peakShare = settings.WorkShare * settings.PeakFactor * float64(settings.PeakDuration) / float64(settings.WorkDuration)
	}
	if settings.WorkShare < peakShare {
		return nil, fmt.Errorf("a peak holding more than the working hours' pushes")
	}
	offDuration := day - settings.WorkDuration
	restDuration := settings.WorkDuration - settings.PeakDuration
	load := &directoryLoadDay{settings: settings}
	add := func(start time.Duration, duration time.Duration, share float64) {
		if 0 < duration && 0 < share {
			load.starts = append(load.starts, start)
			load.durations = append(load.durations, duration)
			load.shares = append(load.shares, share)
		}
	}
	offShare := func(duration time.Duration) float64 {
		if offDuration <= 0 {
			return 0
		}
		return (1 - settings.WorkShare) * float64(duration) / float64(offDuration)
	}
	restShare := func(duration time.Duration) float64 {
		if restDuration <= 0 {
			return 0
		}
		return (settings.WorkShare - peakShare) * float64(duration) / float64(restDuration)
	}
	add(0, settings.WorkStart, offShare(settings.WorkStart))
	add(settings.WorkStart, settings.PeakStart, restShare(settings.PeakStart))
	add(peakStart, settings.PeakDuration, peakShare)
	add(peakEnd, workEnd-peakEnd, restShare(workEnd-peakEnd))
	add(workEnd, day-workEnd, offShare(day-workEnd))
	if len(load.shares) == 0 {
		return nil, fmt.Errorf("a day with no arrivals")
	}
	return load, nil
}

// One arrival's offset into its day.
func (self *directoryLoadDay) sample(random *rand.Rand) time.Duration {
	total := 0.0
	for _, share := range self.shares {
		total += share
	}
	pick := random.Float64() * total
	for i, share := range self.shares {
		if pick < share || i == len(self.shares)-1 {
			return self.starts[i] + time.Duration(random.Float64()*float64(self.durations[i]))
		}
		pick -= share
	}
	return 0
}

// The plan settings give from startMillis, moved on to the next UTC midnight when it is not one. Every sidecar's
// identity key is made here, so a world admits the plan's sidecars before any of them writes.
func NewDirectoryLoadPlan(settings *DirectoryLoadSettings, startMillis int64) (*DirectoryLoadPlan, error) {
	if settings == nil || settings.MemberCount <= 0 || settings.DayCount <= 0 {
		return nil, errors.New("a directory load needs members and days")
	}
	if settings.SessionSyncInterval <= 0 || settings.IdleSyncInterval <= 0 {
		return nil, errors.New("a directory load needs its readers' sync intervals")
	}
	load, err := newDirectoryLoadDay(settings)
	if err != nil {
		return nil, err
	}
	dayMillis := (24 * time.Hour).Milliseconds()
	if startMillis%dayMillis != 0 {
		startMillis = (startMillis/dayMillis + 1) * dayMillis
	}
	plan := &DirectoryLoadPlan{
		Settings:    settings,
		StartMillis: startMillis,
		EndMillis:   startMillis + int64(settings.DayCount)*dayMillis,
	}
	random := rand.New(rand.NewPCG(settings.Seed, 0x6469726563746f72))

	// who: each member's announcing sidecars, its following daemons among them first, and the admissions that do
	// neither
	type member struct {
		announcing []int
		following  []int
	}
	members := make([]*member, settings.MemberCount)
	memberOf := map[int]int{}
	addSidecar := func(memberId sidecar.Id) (int, error) {
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			return 0, err
		}
		plan.Sidecars = append(plan.Sidecars, &DirectoryLoadSidecar{SidecarId: sidecar.NewId(), MemberId: memberId, Key: key})
		return len(plan.Sidecars) - 1, nil
	}
	for m := range members {
		memberId := sidecar.NewId()
		members[m] = &member{}
		announcingCount := directoryLoadShare(settings.AnnouncingSidecarsPerMember, m)
		followingCount := directoryLoadShare(settings.FollowingDaemonsPerMember, m)
		admittedCount := max(directoryLoadShare(settings.AdmissionsPerMember, m), announcingCount, followingCount)
		for n := range admittedCount {
			index, err := addSidecar(memberId)
			if err != nil {
				return nil, err
			}
			memberOf[index] = m
			if n < announcingCount {
				plan.Sidecars[index].Announces = true
				members[m].announcing = append(members[m].announcing, index)
			}
			if n < followingCount {
				plan.Sidecars[index].Follows = true
				members[m].following = append(members[m].following, index)
			}
		}
	}
	coldMemberId := sidecar.NewId()
	if plan.ColdDesktop, err = addSidecar(coldMemberId); err != nil {
		return nil, err
	}
	if plan.ColdPhone, err = addSidecar(coldMemberId); err != nil {
		return nil, err
	}

	// what: each day's pushes by member, and each member's open runs, which set its daemons' sync interval
	type span struct {
		startMillis int64
		endMillis   int64
	}
	sessions := map[int][]span{}
	push := func(timeMillis int64, kind DirectoryLoadPushKind, sidecarIndex int, run int, request int) {
		if plan.EndMillis <= timeMillis {
			return
		}
		plan.Pushes = append(plan.Pushes, &DirectoryLoadPush{TimeMillis: timeMillis, Kind: kind, Sidecar: sidecarIndex, Run: run, Request: request})
	}
	for day := range settings.DayCount {
		dayStart := startMillis + int64(day)*dayMillis
		at := func() int64 {
			return dayStart + load.sample(random).Milliseconds()
		}
		for m, planned := range members {
			if len(planned.announcing) == 0 {
				continue
			}
			pick := func(n int) int {
				return planned.announcing[n%len(planned.announcing)]
			}
			for n := range directoryLoadShare(settings.RunsPerMemberDay, m) {
				run := plan.RunCount
				plan.RunCount += 1
				sidecarIndex := pick(n)
				startAt := at()
				endAt := startAt + settings.RunDuration.Milliseconds()
				push(startAt, DirectoryLoadPushRunStart, sidecarIndex, run, -1)
				push(endAt, DirectoryLoadPushRunEnd, sidecarIndex, run, -1)
				sessions[m] = append(sessions[m], span{startMillis: startAt, endMillis: endAt})
			}
			for n := range directoryLoadShare(settings.RenewalsPerMemberDay, m) {
				push(at(), DirectoryLoadPushRenewal, pick(n), -1, -1)
			}
			for n := range directoryLoadShare(settings.CoordinationEntriesPerMemberDay, m) {
				push(at(), DirectoryLoadPushEntry, pick(n), -1, -1)
			}
			for range directoryLoadShare(settings.RequestsPerMemberDay, m) {
				request := plan.RequestCount
				plan.RequestCount += 1
				requester := pick(0)
				// the next member with an announcing sidecar decides
				approver := requester
				for step := 1; step < len(members); step += 1 {
					if other := members[(m+step)%len(members)]; 0 < len(other.announcing) {
						approver = other.announcing[0]
						break
					}
				}
				filedAt := at()
				decidedAt := filedAt + time.Minute.Milliseconds() + random.Int64N(max(1, settings.DecisionDelay.Milliseconds()))
				closedAt := decidedAt + time.Minute.Milliseconds() + random.Int64N(max(1, settings.NoticeCloseDelay.Milliseconds()))
				push(filedAt, DirectoryLoadPushEntry, requester, -1, -1)
				push(filedAt, DirectoryLoadPushNoticeCreate, requester, -1, request)
				push(decidedAt, DirectoryLoadPushEntry, approver, -1, -1)
				push(decidedAt, DirectoryLoadPushNoticeRewrite, approver, -1, request)
				push(closedAt, DirectoryLoadPushNoticeRemove, requester, -1, request)
			}
		}
	}
	slices.SortStableFunc(plan.Pushes, func(a *DirectoryLoadPush, b *DirectoryLoadPush) int {
		switch {
		case a.TimeMillis < b.TimeMillis:
			return -1
		case b.TimeMillis < a.TimeMillis:
			return 1
		}
		return 0
	})

	// when: each following daemon's syncs
	sessionMillis := settings.SessionSyncInterval.Milliseconds()
	idleMillis := settings.IdleSyncInterval.Milliseconds()
	for index, planned := range plan.Sidecars {
		if !planned.Follows {
			continue
		}
		open := func(atMillis int64) bool {
			for _, session := range sessions[memberOf[index]] {
				if session.startMillis <= atMillis && atMillis < session.endMillis {
					return true
				}
			}
			return false
		}
		times := map[int64]bool{}
		for atMillis := startMillis + random.Int64N(idleMillis); atMillis < plan.EndMillis; {
			times[atMillis] = true
			if open(atMillis) {
				atMillis += sessionMillis
			} else {
				atMillis += idleMillis
			}
		}
		for day := range settings.DayCount {
			dayStart := startMillis + int64(day)*dayMillis
			for range directoryLoadShare(settings.ViewSyncsPerDaemonDay, index) {
				times[dayStart+load.sample(random).Milliseconds()] = true
			}
		}
		for atMillis := range times {
			planned.SyncMillis = append(planned.SyncMillis, atMillis)
		}
		slices.Sort(planned.SyncMillis)
	}
	return plan, nil
}

// What a run reads and writes through, and its clock.
type DirectoryLoadSeams struct {
	Clock Clock
	// Moves the clock to at: a fake clock's AdvanceTo, or a wait on a real one.
	AdvanceTo   func(at time.Time)
	DirectoryId sidecar.Id
	NetworkId   sidecar.Id
	// Each sidecar's reach into the directory's evs.
	Streams func(sidecarId sidecar.Id) sidecar.RecordStreams
	Cards   func(sidecarId sidecar.Id) sidecar.DirectoryCards
	// The authorization state now, as the directory and the record ask it.
	Auth       func() sidecar.DirectoryAuthView
	RecordAuth func() sidecar.RecordAuthView
	// How long a push's commit took where a commit does not move Clock, as on the fakes; nil measures each commit on
	// Clock.
	CommitDuration func(push *DirectoryLoadPush) time.Duration
}

// T2's stand-in for the stores' time, which a fake has none of.
type DirectoryLoadStoreSettings struct {
	// A push's PUTs before its head's, the segment and the batch record, and what each PUT takes: 2 and 40 ms. A stand-in
	// until T3 measures the stores: §11.13 has one ref sustain 20 to 50 pushes a second, a head PUT of 20 to 50 ms.
	BodyPutCount int
	PutDuration  time.Duration
	// A fault's delay on every head PUT: 0 for none (FS-86's injected 200 ms).
	HeadPutDelay time.Duration
}

func DefaultDirectoryLoadStoreSettings() *DirectoryLoadStoreSettings {
	return &DirectoryLoadStoreSettings{
		BodyPutCount: 2,
		PutDuration:  40 * time.Millisecond,
	}
}

// One commit's time on the model: its body PUTs and its head PUT, the head's delayed by a fault.
func (self *DirectoryLoadStoreSettings) CommitDuration() time.Duration {
	return time.Duration(self.BodyPutCount+1)*self.PutDuration + self.HeadPutDelay
}

// T2's directory for a plan: sidecartest's fakes, every sidecar of the plan admitted in one position.
type DirectoryLoadFakes struct {
	Clock         *FakeClock
	Streams       *FakeRecordStreams
	Cards         *FakeDirectoryCards
	DirectoryAuth *FakeDirectoryAuth
	RecordAuth    *FakeRecordAuth
	DirectoryId   sidecar.Id
	NetworkId     sidecar.Id
	Store         *DirectoryLoadStoreSettings
}

// The fakes with every sidecar of plan admitted, reading and writing the directory, the clock at the plan's start.
// clock nil makes one; cards and store nil take the defaults.
func NewDirectoryLoadFakes(ctx context.Context, plan *DirectoryLoadPlan, clock *FakeClock, cards *FakeDirectoryCardsSettings, store *DirectoryLoadStoreSettings) (*DirectoryLoadFakes, error) {
	if clock == nil {
		clock = NewFakeClock(time.UnixMilli(plan.StartMillis))
	}
	if store == nil {
		store = DefaultDirectoryLoadStoreSettings()
	}
	if start := time.UnixMilli(plan.StartMillis); clock.Now().Before(start) {
		clock.AdvanceTo(start)
	}
	streams := NewFakeRecordStreams(clock, nil, nil)
	directoryId, err := streams.NewRepo(ctx)
	if err != nil {
		return nil, err
	}
	fakes := &DirectoryLoadFakes{
		Clock:         clock,
		Streams:       streams,
		Cards:         NewFakeDirectoryCards(streams, cards),
		DirectoryAuth: NewFakeDirectoryAuth(),
		RecordAuth:    NewFakeRecordAuth(),
		DirectoryId:   directoryId,
		NetworkId:     sidecar.NewId(),
		Store:         store,
	}
	directoryFixture := &FakeDirectoryAuthFixture{
		Sidecars:    map[sidecar.Id]*FakeDirectorySidecar{},
		Repos:       map[sidecar.Id]*FakeDirectoryRepo{directoryId: {Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}},
		DirectoryId: &directoryId,
		TimeMillis:  clock.Now().UnixMilli(),
	}
	repo := &FakeRecordRepoAuth{}
	recordFixture := &FakeRecordAuthFixture{
		IdentityKeys: map[sidecar.Id][]byte{},
		Members:      map[sidecar.Id]sidecar.Id{},
		Repos:        map[sidecar.Id]*FakeRecordRepoAuth{directoryId: repo},
		Logs:         &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
		TimeMillis:   clock.Now().UnixMilli(),
	}
	for _, planned := range plan.Sidecars {
		if err := streams.Grant(directoryId, planned.SidecarId, RecordStreamsScope{Read: true, Write: true}); err != nil {
			return nil, err
		}
		memberId := planned.MemberId
		directoryFixture.Sidecars[planned.SidecarId] = &FakeDirectorySidecar{MemberId: &memberId}
		recordFixture.IdentityKeys[planned.SidecarId] = planned.Key.Public().(ed25519.PublicKey)
		recordFixture.Members[planned.SidecarId] = memberId
		repo.Readers = append(repo.Readers, planned.SidecarId)
		repo.Writers = append(repo.Writers, planned.SidecarId)
	}
	fakes.RecordAuth.Append(recordFixture)
	fakes.DirectoryAuth.Append(directoryFixture)
	return fakes, nil
}

// The fakes as a run's seams.
func (self *DirectoryLoadFakes) Seams() *DirectoryLoadSeams {
	return &DirectoryLoadSeams{
		Clock:       self.Clock,
		AdvanceTo:   self.Clock.AdvanceTo,
		DirectoryId: self.DirectoryId,
		NetworkId:   self.NetworkId,
		Streams:     self.Streams.For,
		Cards:       self.Cards.For,
		Auth:        func() sidecar.DirectoryAuthView { return self.DirectoryAuth.Tip() },
		RecordAuth:  func() sidecar.RecordAuthView { return self.RecordAuth.Tip() },
		CommitDuration: func(push *DirectoryLoadPush) time.Duration {
			return self.Store.CommitDuration()
		},
	}
}

// Counts what one reader asks evs, by reader-day: every DirectoryCards read is a request, as is a read of the erasure
// ref, each priced in path reads and bytes by the oracle's settings from what it answered (the file header of
// directory_cost_oracle.go says why on T2). Safe for concurrent use.
type DirectoryCostMeter struct {
	settings *DirectoryCostOracleSettings
	clock    Clock

	stateLock sync.Mutex
	costs     *DirectoryCosts
}

// settings nil takes the oracle's defaults.
func NewDirectoryCostMeter(settings *DirectoryCostOracleSettings, clock Clock) *DirectoryCostMeter {
	if settings == nil {
		settings = DefaultDirectoryCostOracleSettings()
	}
	return &DirectoryCostMeter{settings: settings, clock: clock, costs: NewDirectoryCosts()}
}

// What was measured so far, a copy.
func (self *DirectoryCostMeter) Costs() *DirectoryCosts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	costs := NewDirectoryCosts()
	for key, cost := range self.costs.ReaderDays {
		copied := *cost
		costs.ReaderDays[key] = &copied
	}
	return costs
}

func (self *DirectoryCostMeter) charge(sidecarId sidecar.Id, cost *DirectoryCost) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.costs.Charge(sidecarId, self.clock.Now().UnixMilli(), cost)
}

// cards as sidecarId reaches them, every read counted.
func (self *DirectoryCostMeter) Cards(sidecarId sidecar.Id, cards sidecar.DirectoryCards) sidecar.DirectoryCards {
	return &directoryCostMeterCards{DirectoryCards: cards, meter: self, sidecarId: sidecarId}
}

// streams as sidecarId reaches them, its reads of the erasure ref counted.
func (self *DirectoryCostMeter) Streams(sidecarId sidecar.Id, streams sidecar.RecordStreams) sidecar.RecordStreams {
	return &directoryCostMeterStreams{RecordStreams: streams, meter: self, sidecarId: sidecarId}
}

type directoryCostMeterCards struct {
	sidecar.DirectoryCards
	meter     *DirectoryCostMeter
	sidecarId sidecar.Id
}

// The bytes a read of versions carried: what the binding counted, else each version's statement, entries and slot
// rows.
func (self *directoryCostMeterCards) streamByteCount(result *sidecar.DirectoryStreamVersions) int64 {
	if 0 < result.ByteCount {
		return result.ByteCount
	}
	byteCount := int64(0)
	for _, version := range result.Versions {
		byteCount += self.meter.settings.StatementByteCount
		if version.Version != nil {
			for _, entry := range version.Version.Entries {
				byteCount += int64(len(entry.Entry))
			}
		}
		if version.Slot != nil {
			for _, row := range version.Slot.Rows {
				byteCount += int64(len(row.Row))
			}
		}
	}
	return byteCount
}

func (self *directoryCostMeterCards) Refs(ctx context.Context, repoId sidecar.Id, movedAfter uint64) (*sidecar.DirectoryRefListing, error) {
	listing, err := self.DirectoryCards.Refs(ctx, repoId, movedAfter)
	settings := self.meter.settings
	cost := &DirectoryCost{RequestCount: 1, PathReadCount: settings.ListingPathReadCount}
	if listing != nil {
		cost.PathReadCount += int64(len(listing.Refs)) * settings.RefPathReadCount
		cost.ByteCount += int64(len(listing.Refs)) * settings.RefByteCount
	}
	self.meter.charge(self.sidecarId, cost)
	return listing, err
}

func (self *directoryCostMeterCards) ReadStreams(ctx context.Context, repoId sidecar.Id, reads []*sidecar.DirectoryStreamRead) ([]*sidecar.DirectoryStreamVersions, error) {
	results, err := self.DirectoryCards.ReadStreams(ctx, repoId, reads)
	settings := self.meter.settings
	cost := &DirectoryCost{RequestCount: 1, PathReadCount: int64(len(reads)) * settings.StreamPathReadCount}
	for _, result := range results {
		if result == nil {
			continue
		}
		cost.PathReadCount += int64(len(result.Versions)) * settings.VersionPathReadCount
		cost.ByteCount += self.streamByteCount(result)
	}
	self.meter.charge(self.sidecarId, cost)
	return results, err
}

func (self *directoryCostMeterCards) ReadStreamLog(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryStreamVersions, error) {
	page, err := self.DirectoryCards.ReadStreamLog(ctx, repoId, writerSidecarId, afterVersion)
	settings := self.meter.settings
	cost := &DirectoryCost{RequestCount: 1, PathReadCount: settings.LogPagePathReadCount}
	if page != nil {
		cost.PathReadCount += int64(len(page.Versions)) * settings.VersionPathReadCount
		cost.ByteCount += self.streamByteCount(page)
	}
	self.meter.charge(self.sidecarId, cost)
	return page, err
}

func (self *directoryCostMeterCards) ReadCards(ctx context.Context, repoId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryCardsChanges, error) {
	changes, err := self.DirectoryCards.ReadCards(ctx, repoId, afterVersion)
	settings := self.meter.settings
	cost := &DirectoryCost{RequestCount: 1, PathReadCount: settings.CardsPathReadCount}
	if changes != nil {
		statements := map[uint64]bool{}
		for _, file := range changes.Files {
			statements[file.PushVersion] = true
			cost.ByteCount += int64(len(file.Content))
		}
		cost.PathReadCount += int64(len(statements)) * settings.CardStatementPathReadCount
		cost.ByteCount += int64(len(statements)) * settings.StatementByteCount
	}
	self.meter.charge(self.sidecarId, cost)
	return changes, err
}

type directoryCostMeterStreams struct {
	sidecar.RecordStreams
	meter     *DirectoryCostMeter
	sidecarId sidecar.Id
}

// The bytes one ERASE carries past its statement: its keys and its note.
func directoryLoadErasureByteCount(keyCount int, noteByteCount int) int64 {
	return int64(keyCount)*int64(len(sidecar.Id{})+4) + int64(noteByteCount)
}

func (self *directoryCostMeterStreams) ReadErasures(ctx context.Context, repoId sidecar.Id, afterVersion uint64) ([]*sidecar.RecordStreamErasure, error) {
	erasures, err := self.RecordStreams.ReadErasures(ctx, repoId, afterVersion)
	settings := self.meter.settings
	cost := &DirectoryCost{RequestCount: 1, PathReadCount: settings.ErasurePathReadCount + int64(len(erasures))*settings.ErasureEntryPathReadCount}
	for _, erasure := range erasures {
		cost.ByteCount += settings.StatementByteCount + directoryLoadErasureByteCount(len(erasure.Keys), len(erasure.SealedNote))
	}
	self.meter.charge(self.sidecarId, cost)
	return erasures, err
}

// What a reader's client does without one of the mechanisms FS-86 holds it to.
type DirectoryLoadMutant int

const (
	DirectoryLoadMutantNone DirectoryLoadMutant = iota
	// One read a moved stream, not 64 streams to a request.
	DirectoryLoadMutantOneReadPerStream
	// Every sync lists every ref and reads the streams that did not move too.
	DirectoryLoadMutantRereadUnmovedStreams
	// Every sync reads the cards ref's notices again from its first statement.
	DirectoryLoadMutantRefetchUnchangedNotices
)

func (self DirectoryLoadMutant) String() string {
	switch self {
	case DirectoryLoadMutantNone:
		return "no mutant"
	case DirectoryLoadMutantOneReadPerStream:
		return "one read per moved stream"
	case DirectoryLoadMutantRereadUnmovedStreams:
		return "re-reading unmoved streams"
	case DirectoryLoadMutantRefetchUnchangedNotices:
		return "refetching unchanged notices"
	}
	return fmt.Sprintf("mutant %d", int(self))
}

// A reader's DirectoryCards with one mechanism gone, between its client and the meter: the client is answered as it
// would be, and evs is asked what the mutated client would ask.
type directoryLoadMutantCards struct {
	sidecar.DirectoryCards
	mutant DirectoryLoadMutant

	stateLock sync.Mutex
	// each stream's head as this reader last read it
	held map[sidecar.Id]uint64
}

func (self *directoryLoadMutantCards) note(results []*sidecar.DirectoryStreamVersions) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, result := range results {
		if result == nil {
			continue
		}
		for _, version := range result.Versions {
			if version.Version != nil {
				self.held[result.WriterSidecarId] = max(self.held[result.WriterSidecarId], version.Version.Version)
			}
		}
	}
}

func (self *directoryLoadMutantCards) Refs(ctx context.Context, repoId sidecar.Id, movedAfter uint64) (*sidecar.DirectoryRefListing, error) {
	if self.mutant != DirectoryLoadMutantRereadUnmovedStreams {
		return self.DirectoryCards.Refs(ctx, repoId, movedAfter)
	}
	// every ref, whatever moved, and a read of each stream that stands where this reader holds it
	listing, err := self.DirectoryCards.Refs(ctx, repoId, 0)
	if err != nil {
		return nil, err
	}
	unmoved := func() []*sidecar.DirectoryStreamRead {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		reads := []*sidecar.DirectoryStreamRead{}
		for _, ref := range listing.Refs {
			if ref.Kind == sidecar.DirectoryRefStream && 0 < ref.Version && self.held[ref.WriterSidecarId] == ref.Version {
				reads = append(reads, &sidecar.DirectoryStreamRead{WriterSidecarId: ref.WriterSidecarId, PinVersion: ref.Version})
			}
		}
		return reads
	}()
	for 0 < len(unmoved) {
		batch := unmoved[:min(len(unmoved), sidecar.DefaultEvsFormatSettings().ReadStreamMaxRefCount)]
		unmoved = unmoved[len(batch):]
		if _, err := self.DirectoryCards.ReadStreams(ctx, repoId, batch); err != nil {
			return nil, err
		}
	}
	return listing, nil
}

func (self *directoryLoadMutantCards) ReadStreams(ctx context.Context, repoId sidecar.Id, reads []*sidecar.DirectoryStreamRead) ([]*sidecar.DirectoryStreamVersions, error) {
	if self.mutant != DirectoryLoadMutantOneReadPerStream {
		results, err := self.DirectoryCards.ReadStreams(ctx, repoId, reads)
		self.note(results)
		return results, err
	}
	results := []*sidecar.DirectoryStreamVersions{}
	for _, read := range reads {
		one, err := self.DirectoryCards.ReadStreams(ctx, repoId, []*sidecar.DirectoryStreamRead{read})
		if err != nil {
			return nil, err
		}
		results = append(results, one...)
	}
	self.note(results)
	return results, nil
}

func (self *directoryLoadMutantCards) ReadStreamLog(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryStreamVersions, error) {
	page, err := self.DirectoryCards.ReadStreamLog(ctx, repoId, writerSidecarId, afterVersion)
	if page != nil {
		self.note([]*sidecar.DirectoryStreamVersions{page})
	}
	return page, err
}

func (self *directoryLoadMutantCards) ReadCards(ctx context.Context, repoId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryCardsChanges, error) {
	if self.mutant == DirectoryLoadMutantRefetchUnchangedNotices && 0 < afterVersion {
		// the notices this reader holds, read again
		for after := uint64(0); after < afterVersion; {
			changes, err := self.DirectoryCards.ReadCards(ctx, repoId, after)
			if err != nil {
				return nil, err
			}
			if !changes.More || changes.ThroughVersion <= after {
				break
			}
			after = changes.ThroughVersion
		}
	}
	return self.DirectoryCards.ReadCards(ctx, repoId, afterVersion)
}

// §16.11's ceilings for M6's form, and the prices §11.13's directory row gives its pushes.
type DirectoryLoadCeilings struct {
	// M6's stream pushes, arrival to commit: p99 <= 300 ms.
	StreamPushP99 time.Duration
	// §11.13's price of a push on one metadata drive on 4 KiB blocks: a stream entry about 96 KiB, a notice about 46
	// created, 37 rewritten and 53 removed (owner decision 148's marker).
	StreamEntryDriveByteCount   int64
	NoticeCreateDriveByteCount  int64
	NoticeRewriteDriveByteCount int64
	NoticeRemoveDriveByteCount  int64
	// What a measure may reach against its table row: 1.25.
	Tolerance float64
}

func DefaultDirectoryLoadCeilings() *DirectoryLoadCeilings {
	return &DirectoryLoadCeilings{
		StreamPushP99:               300 * time.Millisecond,
		StreamEntryDriveByteCount:   96 * 1024,
		NoticeCreateDriveByteCount:  46 * 1024,
		NoticeRewriteDriveByteCount: 37 * 1024,
		NoticeRemoveDriveByteCount:  53 * 1024,
		Tolerance:                   1.25,
	}
}

// One column of §16.11's cost table, M6's rows.
type DirectoryCostTableRow struct {
	MemberCount int
	// reader-day, M6: bytes; requests.
	ReaderDayByteCount    int64
	ReaderDayRequestCount int64
	// team-day, M6: bytes; requests; path reads.
	TeamDayByteCount     int64
	TeamDayRequestCount  int64
	TeamDayPathReadCount int64
	// NVMe a drive a day, M6's form.
	DriveDayByteCount int64
	// cold start, a desktop, M6.
	ColdDesktopByteCount int64
}

// §16.11's table: 500 members, the Team limit of 2,000, and the 5,000-member stress case.
func DefaultDirectoryCostTableM6() []*DirectoryCostTableRow {
	mib := int64(1024 * 1024)
	gib := 1024 * mib
	return []*DirectoryCostTableRow{
		{
			MemberCount:        500,
			ReaderDayByteCount: 38 * mib, ReaderDayRequestCount: 420,
			TeamDayByteCount: 22 * gib, TeamDayRequestCount: 250_000, TeamDayPathReadCount: 9_500_000,
			DriveDayByteCount: 3 * gib / 2, ColdDesktopByteCount: 22_000_000,
		},
		{
			MemberCount:        2000,
			ReaderDayByteCount: 153 * mib, ReaderDayRequestCount: 1140,
			TeamDayByteCount: 360 * gib, TeamDayRequestCount: 2_700_000, TeamDayPathReadCount: 150_000_000,
			DriveDayByteCount: 6 * gib, ColdDesktopByteCount: 88_000_000,
		},
		{
			MemberCount:        5000,
			ReaderDayByteCount: 382 * mib, ReaderDayRequestCount: 2640,
			TeamDayByteCount: 2200 * gib, TeamDayRequestCount: 15_900_000, TeamDayPathReadCount: 950_000_000,
			DriveDayByteCount: 15 * gib, ColdDesktopByteCount: 220_000_000,
		},
	}
}

// The row for memberCount, nil when the table has no such column.
func DirectoryCostTableRowOf(table []*DirectoryCostTableRow, memberCount int) *DirectoryCostTableRow {
	for _, row := range table {
		if row.MemberCount == memberCount {
			return row
		}
	}
	return nil
}

// How a run is made.
type DirectoryLoadOptions struct {
	// The oracle's settings, which the meter prices by too; nil takes the defaults.
	Oracle *DirectoryCostOracleSettings
	// One mechanism gone from every measured reader.
	Mutant DirectoryLoadMutant
	// The oracle computes only the measured readers' expectation, not every following daemon's: a team-day past the
	// sample is then not known.
	SampleOracleOnly bool
	// No following daemon runs the client: the oracle's expectation alone stands for the day's readers, and only the
	// cold desktop and the cold phone are measured. A day too large to fold sixty times in a test's time runs so.
	NoReaders bool
	// Leaves out the cold desktop and the cold phone.
	NoCold bool
}

// The cold phone's view as it went.
type DirectoryLoadPhone struct {
	// After the first Fetch on a metered link, and after the metered bytes were allowed.
	Metered  *sidecar.DirectoryCoverage
	Complete *sidecar.DirectoryCoverage
	// The items the metered view listed.
	MeteredItemCount int
	// What the view's reads cost in all.
	Cost *DirectoryCost
}

// What a run did and measured.
type DirectoryLoadResult struct {
	Plan *DirectoryLoadPlan
	// The pushes as they committed, and every following daemon's syncs: the oracle's input.
	Schedule *DirectoryCostSchedule
	// The oracle's expectation and what the measured readers cost.
	Expected *DirectoryCosts
	Measured *DirectoryCosts
	// Whether Expected holds every following daemon, so a team-day is the whole team's.
	WholeTeam bool
	// Whether no following daemon ran the client, the oracle alone standing for the day's readers.
	NoReaders bool
	// The measured readers.
	ReaderIds []sidecar.Id
	// Each stream push's latency, arrival to commit.
	StreamPushLatencies []time.Duration
	PushCounts          map[DirectoryLoadPushKind]int
	// The alarms the measured readers, the cold desktop and the cold phone raised.
	Alarms []*sidecar.RecordAlarm
	// The cold desktop's one sync, expected and measured; nil when left out.
	ColdDesktopExpected *DirectoryCost
	ColdDesktopMeasured *DirectoryCost
	// The cold phone's view; nil when left out.
	Phone *DirectoryLoadPhone
	// The bytes every stream version costs a reader, statements included: what a cold reader fetches.
	StreamByteCount int64
}

// One announcing sidecar's surrogate: its key, its chain and what it has announced.
type directoryLoadWriter struct {
	planned *DirectoryLoadSidecar
	env     *sidecar.RecordSealEnv
	streams sidecar.RecordStreams
	cards   sidecar.DirectoryCards
	counter uint64
	// its newest run item, for a renewal
	runAnnouncementId sidecar.Id
	runVersion        uint64
	runStartedMillis  int64
	runOpen           bool
}

func (self *directoryLoadWriter) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.planned.SidecarId.Bytes(),
		Signature: ed25519.Sign(self.planned.Key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// One run of a plan: see the file header.
type DirectoryLoad struct {
	plan    *DirectoryLoadPlan
	seams   *DirectoryLoadSeams
	options *DirectoryLoadOptions
	oracle  *DirectoryCostOracle
	meter   *DirectoryCostMeter

	writers map[int]*directoryLoadWriter
	// each run's announcement and its writer's state at its start
	runAnnouncementIds map[int]sidecar.Id
	// each request's notice as its pushes leave it
	noticePaths    map[int]string
	noticeVersions map[int]uint64
	noticeIds      map[int]sidecar.Id

	stateLock sync.Mutex
	alarms    []*sidecar.RecordAlarm
}

// options nil takes the defaults.
func NewDirectoryLoad(plan *DirectoryLoadPlan, seams *DirectoryLoadSeams, options *DirectoryLoadOptions) (*DirectoryLoad, error) {
	if plan == nil || seams == nil || seams.Clock == nil || seams.AdvanceTo == nil || seams.Streams == nil || seams.Cards == nil || seams.Auth == nil || seams.RecordAuth == nil {
		return nil, errors.New("a directory load needs a plan, a clock and the directory's seams")
	}
	if options == nil {
		options = &DirectoryLoadOptions{}
	}
	oracle := NewDirectoryCostOracle(options.Oracle)
	return &DirectoryLoad{
		plan:               plan,
		seams:              seams,
		options:            options,
		oracle:             oracle,
		meter:              NewDirectoryCostMeter(oracle.Settings(), seams.Clock),
		writers:            map[int]*directoryLoadWriter{},
		runAnnouncementIds: map[int]sidecar.Id{},
		noticePaths:        map[int]string{},
		noticeVersions:     map[int]uint64{},
		noticeIds:          map[int]sidecar.Id{},
	}, nil
}

func (self *DirectoryLoad) Oracle() *DirectoryCostOracle {
	return self.oracle
}

func (self *DirectoryLoad) raise(alarm *sidecar.RecordAlarm) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.alarms = append(self.alarms, alarm)
}

// The surrogate of the plan's sidecar at index, made at its first push.
func (self *DirectoryLoad) writer(index int) (*directoryLoadWriter, error) {
	if writer, ok := self.writers[index]; ok {
		return writer, nil
	}
	planned := self.plan.Sidecars[index]
	store, err := NewFakeStore().Root().Directory("writer", "record")
	if err != nil {
		return nil, err
	}
	writer := &directoryLoadWriter{
		planned: planned,
		streams: self.seams.Streams(planned.SidecarId),
		cards:   self.seams.Cards(planned.SidecarId),
	}
	writer.env = &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, planned.SidecarId), Sign: writer.sign}
	self.writers[index] = writer
	return writer, nil
}

// Seals body as one entry of kind and pushes it as the next version of writer's stream. Answers the bytes a reader
// fetching the version transfers past its statement.
func (self *DirectoryLoad) pushEntry(ctx context.Context, writer *directoryLoadWriter, kind sidecar.RecordKind, source sidecar.RecordSource, body proto.Message) (int64, error) {
	pin := self.seams.RecordAuth().Pin()
	sealed, err := sidecar.RecordSeal(writer.env, &sidecar.RecordSealArgs{
		LogId:         self.seams.DirectoryId,
		Kind:          kind,
		Source:        source,
		TimeMillis:    self.seams.Clock.Now().UnixMilli(),
		Tainted:       source == sidecar.RecordSourceAgent,
		PolicyVersion: pin.GetVersion(),
		Body:          body,
	})
	if err != nil {
		return 0, err
	}
	writer.counter += 1
	path, err := sidecar.RecordStreamPath(writer.counter)
	if err != nil {
		return 0, err
	}
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewId(),
		WriterSidecarId: writer.planned.SidecarId,
		SlotId:          sidecar.NewId(),
		AuthPin:         pin,
		SlotRows:        []*sidecar.RecordSlotRow{sealed.SlotRow(0)},
	}
	push.Entries = []*sidecar.RecordStreamEntry{{Path: path, Entry: sealed.EntryBytes(&push.SlotId, 0)}}
	if _, err := writer.streams.Append(ctx, self.seams.DirectoryId, push); err != nil {
		return 0, err
	}
	byteCount := int64(0)
	for _, entry := range push.Entries {
		byteCount += int64(len(entry.Entry))
	}
	for _, row := range push.SlotRows {
		byteCount += int64(len(row.Row))
	}
	return byteCount, nil
}

// writer's run item now: announcementId at version in state.
func (self *DirectoryLoad) runItem(writer *directoryLoadWriter, state sidecar.DirectoryAnnouncementState) *protocol.Announcement {
	nowMillis := self.seams.Clock.Now().UnixMilli()
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, nowMillis)
	return &protocol.Announcement{
		AnnouncementId: writer.runAnnouncementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRun),
		Version:        writer.runVersion,
		StartedMillis:  writer.runStartedMillis,
		RenewedMillis:  nowMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(state),
		Who: &protocol.AnnounceWho{
			SidecarId:  writer.planned.SidecarId.Bytes(),
			MemberId:   writer.planned.MemberId.Bytes(),
			AgentId:    writer.runAnnouncementId.Bytes(),
			AgentLabel: "builder",
			Harness:    "claude-code",
		},
		What:  &protocol.AnnounceWhat{Title: "refactor the settings loader and its tests", RunId: writer.runAnnouncementId.Bytes()},
		Where: &protocol.AnnounceWhere{Project: "example.org/team/app", Branch: "main"},
	}
}

// One push of the plan, committed: the event the oracle reads.
func (self *DirectoryLoad) push(ctx context.Context, planned *DirectoryLoadPush) (*DirectoryCostEvent, error) {
	writer, err := self.writer(planned.Sidecar)
	if err != nil {
		return nil, err
	}
	nowMillis := self.seams.Clock.Now().UnixMilli()
	event := &DirectoryCostEvent{TimeMillis: nowMillis, Kind: DirectoryCostEventStream, WriterSidecarId: writer.planned.SidecarId}
	announce := func(state sidecar.DirectoryAnnouncementState) error {
		event.ByteCount, err = self.pushEntry(ctx, writer, sidecar.RecordKindAnnounce, sidecar.RecordSourceObserved, self.runItem(writer, state))
		return err
	}
	start := func(run int) {
		writer.runAnnouncementId = sidecar.NewId()
		writer.runVersion = 1
		writer.runStartedMillis = nowMillis
		writer.runOpen = true
		if 0 <= run {
			self.runAnnouncementIds[run] = writer.runAnnouncementId
		}
	}
	switch planned.Kind {
	case DirectoryLoadPushRunStart:
		start(planned.Run)
		return event, announce(sidecar.DirectoryAnnouncementStateActive)
	case DirectoryLoadPushRunEnd:
		// the run's item ended at a raised version; a run another start replaced on this sidecar ends as its own item
		announcementId, ok := self.runAnnouncementIds[planned.Run]
		if !ok {
			start(planned.Run)
			announcementId = writer.runAnnouncementId
		}
		current := announcementId == writer.runAnnouncementId
		held := *writer
		writer.runAnnouncementId = announcementId
		writer.runVersion = 2
		if !current {
			writer.runStartedMillis = nowMillis - self.plan.Settings.RunDuration.Milliseconds()
		}
		err := announce(sidecar.DirectoryAnnouncementStateEnded)
		if current {
			writer.runOpen = false
		} else {
			writer.runAnnouncementId, writer.runVersion, writer.runStartedMillis, writer.runOpen = held.runAnnouncementId, held.runVersion, held.runStartedMillis, held.runOpen
		}
		return event, err
	case DirectoryLoadPushRenewal:
		// an open run's item again at its version, renewed now; with none open, a new item
		if !writer.runOpen {
			start(-1)
		}
		return event, announce(sidecar.DirectoryAnnouncementStateActive)
	case DirectoryLoadPushEntry:
		event.ByteCount, err = self.pushEntry(ctx, writer, sidecar.RecordKindNote, sidecar.RecordSourceAgent, &protocol.CoordinationBody{Text: "the loader's tests pass on the branch; taking the settings review next"})
		return event, err
	}

	// a notice on the cards ref
	event.WriterSidecarId = sidecar.Id{}
	pin := self.seams.Auth().Pin()
	switch planned.Kind {
	case DirectoryLoadPushNoticeCreate, DirectoryLoadPushNoticeRewrite:
		requestId, ok := self.noticeIds[planned.Request]
		if !ok {
			requestId = sidecar.NewId()
			self.noticeIds[planned.Request] = requestId
			path, err := sidecar.DirectoryNoticePath(&protocol.RequestTarget{RepoId: self.seams.NetworkId.Bytes()}, requestId)
			if err != nil {
				return nil, err
			}
			self.noticePaths[planned.Request] = path
		}
		notice := &protocol.DirectoryNotice{
			RequestId:          requestId.Bytes(),
			RequesterSidecarId: writer.planned.SidecarId.Bytes(),
			EntrySeq:           writer.counter,
			NotAfterMillis:     nowMillis + (7 * 24 * time.Hour).Milliseconds(),
			State:              uint32(sidecar.DirectoryNoticeStatePending),
		}
		event.Kind = DirectoryCostEventNotice
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(notice)
		if err != nil {
			return nil, err
		}
		version, err := writer.cards.PutCard(ctx, self.seams.DirectoryId, &sidecar.DirectoryCardWrite{
			PushId: sidecar.NewId(), Path: self.noticePaths[planned.Request], IfVersion: self.noticeVersions[planned.Request], Content: content, AuthPin: pin,
		})
		if err != nil {
			return nil, err
		}
		self.noticeVersions[planned.Request] = version
		event.ByteCount = int64(len(content))
		return event, nil
	case DirectoryLoadPushNoticeRemove:
		event.Kind = DirectoryCostEventNoticeRemoved
		path, ok := self.noticePaths[planned.Request]
		if !ok {
			return nil, fmt.Errorf("request %d's notice is removed before it is written", planned.Request)
		}
		err := writer.cards.RemoveCard(ctx, self.seams.DirectoryId, &sidecar.DirectoryCardWrite{
			PushId: sidecar.NewId(), Path: path, IfVersion: self.noticeVersions[planned.Request], AuthPin: pin,
		})
		delete(self.noticeVersions, planned.Request)
		return event, err
	}
	return nil, fmt.Errorf("a push of kind %d", planned.Kind)
}

// The real client of the plan's sidecar at index, behind the meter and, for a measured reader, the run's mutant.
func (self *DirectoryLoad) reader(index int, mutant DirectoryLoadMutant) (*sidecar.DirectoryClient, error) {
	planned := self.plan.Sidecars[index]
	store, err := NewFakeStore().Root().Directory("directory", "search")
	if err != nil {
		return nil, err
	}
	cards := self.meter.Cards(planned.SidecarId, self.seams.Cards(planned.SidecarId))
	if mutant != DirectoryLoadMutantNone {
		cards = &directoryLoadMutantCards{DirectoryCards: cards, mutant: mutant, held: map[sidecar.Id]uint64{}}
	}
	settings := self.plan.Settings.Directory
	if settings == nil {
		settings = sidecar.DefaultSidecarSettings().Directory
	}
	return sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: planned.SidecarId,
		Store:     store,
		Cards:     cards,
		Streams: func() sidecar.RecordStreams {
			return self.meter.Streams(planned.SidecarId, self.seams.Streams(planned.SidecarId))
		},
		Auth:       self.seams.Auth,
		RecordAuth: self.seams.RecordAuth,
		Alarm:      self.raise,
		Clock:      self.seams.Clock,
		Settings:   settings,
		NetworkId:  self.seams.NetworkId,
	})
}

// One reader's measured cost over every day.
func directoryLoadReaderCost(costs *DirectoryCosts, sidecarId sidecar.Id) *DirectoryCost {
	total := &DirectoryCost{}
	for key, cost := range costs.ReaderDays {
		if key.SidecarId == sidecarId {
			total.Add(cost)
		}
	}
	return total
}

// Runs the plan: every push at its time, every measured reader's syncs at theirs, then the cold desktop and the cold
// phone.
func (self *DirectoryLoad) Run(ctx context.Context) (*DirectoryLoadResult, error) {
	plan := self.plan
	result := &DirectoryLoadResult{
		Plan:       plan,
		Schedule:   &DirectoryCostSchedule{},
		PushCounts: map[DirectoryLoadPushKind]int{},
		WholeTeam:  !self.options.SampleOracleOnly,
		NoReaders:  self.options.NoReaders,
	}
	if self.options.NoReaders && self.options.SampleOracleOnly {
		return nil, errors.New("a run with no readers has no sample for the oracle to keep to")
	}

	// the measured readers, spread over the following daemons
	following := []int{}
	for index, planned := range plan.Sidecars {
		if planned.Follows {
			following = append(following, index)
		}
	}
	if len(following) == 0 {
		return nil, errors.New("the plan has no following daemon")
	}
	sampleCount := plan.Settings.SampledReaderCount
	if sampleCount <= 0 || len(following) < sampleCount {
		sampleCount = len(following)
	}
	if self.options.NoReaders {
		sampleCount = 0
	}
	type sync struct {
		timeMillis int64
		client     *sidecar.DirectoryClient
		reader     *DirectoryCostReader
	}
	syncs := []*sync{}
	measured := map[int]bool{}
	for n := range sampleCount {
		index := following[n*len(following)/sampleCount]
		measured[index] = true
		client, err := self.reader(index, self.options.Mutant)
		if err != nil {
			return nil, err
		}
		reader := &DirectoryCostReader{SidecarId: plan.Sidecars[index].SidecarId}
		result.Schedule.Readers = append(result.Schedule.Readers, reader)
		result.ReaderIds = append(result.ReaderIds, reader.SidecarId)
		for _, timeMillis := range plan.Sidecars[index].SyncMillis {
			syncs = append(syncs, &sync{timeMillis: timeMillis, client: client, reader: reader})
		}
	}
	slices.SortStableFunc(syncs, func(a *sync, b *sync) int {
		switch {
		case a.timeMillis < b.timeMillis:
			return -1
		case b.timeMillis < a.timeMillis:
			return 1
		}
		return 0
	})
	if !self.options.SampleOracleOnly {
		for _, index := range following {
			if !measured[index] {
				result.Schedule.Readers = append(result.Schedule.Readers, &DirectoryCostReader{
					SidecarId: plan.Sidecars[index].SidecarId, SyncMillis: slices.Clone(plan.Sidecars[index].SyncMillis),
				})
			}
		}
	}

	// each ref's commits queue behind one another where the seams give a commit's duration
	busyUntil := map[sidecar.Id]time.Time{}
	nextSync := 0
	runSyncs := func(throughMillis int64) error {
		for nextSync < len(syncs) && syncs[nextSync].timeMillis <= throughMillis {
			next := syncs[nextSync]
			nextSync += 1
			self.seams.AdvanceTo(time.UnixMilli(next.timeMillis))
			next.reader.SyncMillis = append(next.reader.SyncMillis, self.seams.Clock.Now().UnixMilli())
			if err := next.client.Sync(ctx); err != nil {
				return fmt.Errorf("reader %s's sync: %w", next.reader.SidecarId, err)
			}
		}
		return nil
	}
	for _, planned := range plan.Pushes {
		// a sync sees the pushes at or before its time, so those go first
		if err := runSyncs(planned.TimeMillis - 1); err != nil {
			return nil, err
		}
		arrival := time.UnixMilli(planned.TimeMillis)
		self.seams.AdvanceTo(arrival)
		started := self.seams.Clock.Now()
		event, err := self.push(ctx, planned)
		if err != nil {
			return nil, fmt.Errorf("a %s at %d: %w", planned.Kind, planned.TimeMillis, err)
		}
		result.Schedule.Events = append(result.Schedule.Events, event)
		result.PushCounts[planned.Kind] += 1
		if planned.Kind.Stream() {
			result.StreamByteCount += self.oracle.Settings().StatementByteCount + event.ByteCount
			latency := self.seams.Clock.Now().Sub(started)
			if self.seams.CommitDuration != nil {
				begin := arrival
				if busy := busyUntil[event.WriterSidecarId]; begin.Before(busy) {
					begin = busy
				}
				finish := begin.Add(self.seams.CommitDuration(planned))
				busyUntil[event.WriterSidecarId] = finish
				latency = finish.Sub(arrival)
			}
			result.StreamPushLatencies = append(result.StreamPushLatencies, latency)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := runSyncs(plan.EndMillis); err != nil {
		return nil, err
	}
	self.seams.AdvanceTo(time.UnixMilli(plan.EndMillis))

	// the cold desktop: one sync of a client that never read
	if !self.options.NoCold {
		desktopId := plan.Sidecars[plan.ColdDesktop].SidecarId
		desktop, err := self.reader(plan.ColdDesktop, DirectoryLoadMutantNone)
		if err != nil {
			return nil, err
		}
		coldMillis := self.seams.Clock.Now().UnixMilli()
		if err := desktop.Sync(ctx); err != nil {
			return nil, fmt.Errorf("the cold desktop's sync: %w", err)
		}
		expected, err := self.oracle.Expected(&DirectoryCostSchedule{
			Events:  result.Schedule.Events,
			Readers: []*DirectoryCostReader{{SidecarId: desktopId, SyncMillis: []int64{coldMillis}}},
		})
		if err != nil {
			return nil, err
		}
		result.ColdDesktopExpected = expected.Total()
		result.ColdDesktopMeasured = directoryLoadReaderCost(self.meter.Costs(), desktopId)

		// the cold phone: a metered view, then the metered bytes allowed
		phoneId := plan.Sidecars[plan.ColdPhone].SidecarId
		phone, err := self.reader(plan.ColdPhone, DirectoryLoadMutantNone)
		if err != nil {
			return nil, err
		}
		view, err := phone.View(&sidecar.DirectoryViewArgs{Metered: true})
		if err != nil {
			return nil, err
		}
		if err := view.Fetch(ctx); err != nil {
			return nil, fmt.Errorf("the cold phone's metered fetch: %w", err)
		}
		page := view.List(&sidecar.DirectoryFilter{})
		result.Phone = &DirectoryLoadPhone{Metered: page.Coverage, MeteredItemCount: len(page.Items)}
		view.AllowMetered()
		if err := view.Fetch(ctx); err != nil {
			return nil, fmt.Errorf("the cold phone's allowed fetch: %w", err)
		}
		result.Phone.Complete = view.Coverage()
		result.Phone.Cost = directoryLoadReaderCost(self.meter.Costs(), phoneId)
		view.Close()
	}

	measuredCosts := self.meter.Costs()
	result.Measured = NewDirectoryCosts()
	for key, cost := range measuredCosts.ReaderDays {
		if slices.Contains(result.ReaderIds, key.SidecarId) {
			result.Measured.ReaderDays[key] = cost
		}
	}
	expected, err := self.oracle.Expected(result.Schedule)
	if err != nil {
		return nil, err
	}
	result.Expected = expected
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		result.Alarms = slices.Clone(self.alarms)
	}()
	return result, nil
}

// The p99 of latencies, 0 for none.
func DirectoryLoadP99(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sorted := slices.Clone(latencies)
	slices.Sort(sorted)
	index := int(math.Ceil(0.99*float64(len(sorted)))) - 1
	return sorted[max(0, index)]
}

// The NVMe bytes the run's pushes cost one metadata drive, by §11.13's prices.
func (self *DirectoryLoadResult) DriveByteCount(ceilings *DirectoryLoadCeilings) int64 {
	streamCount := 0
	for kind, count := range self.PushCounts {
		if kind.Stream() {
			streamCount += count
		}
	}
	return int64(streamCount)*ceilings.StreamEntryDriveByteCount +
		int64(self.PushCounts[DirectoryLoadPushNoticeCreate])*ceilings.NoticeCreateDriveByteCount +
		int64(self.PushCounts[DirectoryLoadPushNoticeRewrite])*ceilings.NoticeRewriteDriveByteCount +
		int64(self.PushCounts[DirectoryLoadPushNoticeRemove])*ceilings.NoticeRemoveDriveByteCount
}

// The oracle's check of what the measured readers cost, a reader that raised an alarm failing too: the load writes
// nothing a reader refuses.
func (self *DirectoryLoadResult) CheckOracle(oracle *DirectoryCostOracle) []error {
	errs := []error{}
	switch {
	case !self.NoReaders:
		errs = oracle.Check(self.Expected, self.Measured)
	case self.ColdDesktopExpected == nil:
		errs = append(errs, errors.New("nothing was measured: no reader ran and no cold desktop"))
	}
	if self.ColdDesktopExpected != nil {
		errs = append(errs, oracle.compare("the cold desktop", self.ColdDesktopExpected, self.ColdDesktopMeasured)...)
	}
	if 0 < len(self.Alarms) {
		errs = append(errs, fmt.Errorf("%d alarms, the first %s on %s", len(self.Alarms), self.Alarms[0].Reason, self.Alarms[0].LogId))
	}
	return errs
}

// §16.11's ceilings for M6's form: the stream pushes' p99.
func (self *DirectoryLoadResult) CheckCeilings(ceilings *DirectoryLoadCeilings) []error {
	errs := []error{}
	if p99 := DirectoryLoadP99(self.StreamPushLatencies); ceilings.StreamPushP99 < p99 {
		errs = append(errs, fmt.Errorf("stream pushes' p99 is %s over %d pushes, past %s", p99, len(self.StreamPushLatencies), ceilings.StreamPushP99))
	}
	return errs
}

// The cold phone, by §16.11's phones row with the reader's settings: a view whose state passed the metered cap shows
// partial coverage naming what is left, never complete and never empty, stops near the cap, and once the metered
// bytes are allowed reaches a complete view having read each version once.
func (self *DirectoryLoadResult) CheckPhone(oracle *DirectoryCostOracle, directory *sidecar.SidecarDirectorySettings) []error {
	if self.Phone == nil {
		return []error{errors.New("no cold phone ran")}
	}
	if directory == nil {
		directory = sidecar.DefaultSidecarSettings().Directory
	}
	errs := []error{}
	phone := self.Phone
	if self.StreamByteCount <= directory.PhoneMeteredByteCount {
		if !phone.Metered.Complete {
			errs = append(errs, fmt.Errorf("a phone whose state of %d bytes fits the cap shows partial coverage: %+v", self.StreamByteCount, phone.Metered))
		}
	} else {
		switch {
		case phone.Metered.Complete || phone.Metered.Waiting != sidecar.DirectoryCoverageWaitingMetered:
			errs = append(errs, fmt.Errorf("a phone past the cap shows %+v, not partial coverage waiting on the metered link", phone.Metered))
		case len(phone.Metered.LeftSidecarIds) == 0 || phone.Metered.LeftByteCount <= 0:
			errs = append(errs, fmt.Errorf("a partial view names nothing left: %+v", phone.Metered))
		case len(phone.Metered.FetchedSidecarIds) == 0 || phone.MeteredItemCount == 0:
			errs = append(errs, fmt.Errorf("a partial view is empty: %d sidecars fetched, %d items", len(phone.Metered.FetchedSidecarIds), phone.MeteredItemCount))
		}
		// RECORD-M6-27: at M6 a request can pass the cap by what its streams cost above the plan's estimate
		if limit := int64(oracle.Settings().Tolerance * float64(directory.PhoneMeteredByteCount)); limit < phone.Metered.MeteredByteCount {
			errs = append(errs, fmt.Errorf("a metered view fetched %d bytes against a cap of %d", phone.Metered.MeteredByteCount, directory.PhoneMeteredByteCount))
		}
	}
	if !phone.Complete.Complete || 0 < len(phone.Complete.LeftSidecarIds) {
		errs = append(errs, fmt.Errorf("a phone allowed its metered bytes ends at %+v", phone.Complete))
	}
	if !oracle.within(self.StreamByteCount, phone.Complete.FetchedByteCount) {
		errs = append(errs, fmt.Errorf("the phone fetched %d bytes where every version read once is %d", phone.Complete.FetchedByteCount, self.StreamByteCount))
	}
	return errs
}

// The mean cost of a reader-day: the measured readers', or the oracle's over every following daemon when none ran.
func (self *DirectoryLoadResult) MeanReaderDay() *DirectoryCost {
	costs := self.Measured
	if self.NoReaders {
		costs = self.Expected
	}
	count := int64(len(costs.ReaderDays))
	if count == 0 {
		return &DirectoryCost{}
	}
	total := costs.Total()
	return &DirectoryCost{RequestCount: total.RequestCount / count, PathReadCount: total.PathReadCount / count, ByteCount: total.ByteCount / count}
}

// The costliest team-day: the oracle's over every following daemon when it holds them all, else the measured readers'
// mean reader-day times the following daemons.
func (self *DirectoryLoadResult) TeamDay() *DirectoryCost {
	costliest := &DirectoryCost{}
	if self.WholeTeam {
		for _, cost := range self.Expected.TeamDays(nil) {
			if costliest.ByteCount < cost.ByteCount {
				costliest = cost
			}
		}
		return costliest
	}
	_, following := self.Plan.Counts()
	mean := self.MeanReaderDay()
	return &DirectoryCost{
		RequestCount:  mean.RequestCount * int64(following),
		PathReadCount: mean.PathReadCount * int64(following),
		ByteCount:     mean.ByteCount * int64(following),
	}
}

// Holds the run to its column of §16.11's table, M6's rows: the measured reader-day, the team-day, the priced NVMe
// bytes a drive a day and the cold desktop, each within the ceilings' tolerance of its row. A member count the table
// has no column for checks nothing and says so.
func (self *DirectoryLoadResult) CheckTable(table []*DirectoryCostTableRow, ceilings *DirectoryLoadCeilings) []error {
	row := DirectoryCostTableRowOf(table, self.Plan.Settings.MemberCount)
	if row == nil {
		return []error{fmt.Errorf("§16.11's table has no column for %d members", self.Plan.Settings.MemberCount)}
	}
	errs := []error{}
	check := func(what string, measured int64, ceiling int64) {
		if ceilings.Tolerance*float64(ceiling) < float64(measured) {
			errs = append(errs, fmt.Errorf("%s is %d, past %.2f times the table's %d", what, measured, ceilings.Tolerance, ceiling))
		}
	}
	mean := self.MeanReaderDay()
	check("a reader-day's bytes", mean.ByteCount, row.ReaderDayByteCount)
	check("a reader-day's requests", mean.RequestCount, row.ReaderDayRequestCount)
	team := self.TeamDay()
	check("a team-day's bytes", team.ByteCount, row.TeamDayByteCount)
	check("a team-day's requests", team.RequestCount, row.TeamDayRequestCount)
	check("a team-day's path reads", team.PathReadCount, row.TeamDayPathReadCount)
	check("the NVMe bytes a drive a day", self.DriveByteCount(ceilings)/int64(self.Plan.Settings.DayCount), row.DriveDayByteCount)
	if self.ColdDesktopMeasured != nil {
		check("a cold desktop's bytes", self.ColdDesktopMeasured.ByteCount, row.ColdDesktopByteCount)
	}
	return errs
}

// What the run measured, for a test's log.
func (self *DirectoryLoadResult) String() string {
	announcing, following := self.Plan.Counts()
	pushCount := 0
	for _, count := range self.PushCounts {
		pushCount += count
	}
	text := fmt.Sprintf("%d members, %d announcing, %d following, %d admitted: %d pushes; %d readers measured, a reader-day %s; a team-day %s; stream pushes p99 %s",
		self.Plan.Settings.MemberCount, announcing, following, len(self.Plan.Sidecars), pushCount, len(self.ReaderIds), self.MeanReaderDay(), self.TeamDay(),
		DirectoryLoadP99(self.StreamPushLatencies))
	if self.ColdDesktopMeasured != nil {
		text += fmt.Sprintf("; a cold desktop %s", self.ColdDesktopMeasured)
	}
	if self.Phone != nil {
		text += fmt.Sprintf("; a cold phone %d metered bytes then %d in all", self.Phone.Metered.MeteredByteCount, self.Phone.Complete.FetchedByteCount)
	}
	return text
}
