//go:build !ios_extension

// FS-86's card commits on the evs world (§22.8, D-TEST-17; §16.11's cards ref commits row, D-MCP-31; RECORD-M10-07):
// the load the row's trap names, a team's pushes landing on the one cards ref's head, on the real engine and the real
// client's DirectoryEvsCards, so server's T3 tests run it on T3's stores in physical time: on the local stack's one
// MinIO at reduced scale, logging what misses the row (sidecar_directory_load_t3_test.go), and nightly on T3's 4-host
// file-cluster layouts for a whole peak hour at the Team limit's rate, the row's reading (QD-1068;
// sidecar_directory_load_layout_t3_test.go).
//
//	world     one directory repo, format 1, on one instance. WriterCount devices each write their own card,
//	          d/<h>/<sidecar_id>, by path CAS on the cards ref; a reader reads the ref
//	alone     every writer writes its first card, one after another: what a commit takes with nothing beside it, held
//	          to no ceiling and read beside the phases that are
//	peak      pushes arrive on the wall clock at PushesPerSecond for PeakDuration, their gaps exponential by Seed, each
//	          taken by the next writer that is free and sent on a goroutine of its own; a push's latency runs from its
//	          arrival to its write's return
//	burst     the same at BurstFactor times the rate for BurstDuration
//	reader    the reader reads the cards ref from its first statement: every writer's card stands at the version and
//	          content its last push wrote, and a read from there answers nothing more
//
//	ceilings  with Ceilings set, both phases are held to §16.11's row, after both ran: at the peak p99 <= 300 ms, at
//	          most 0.5 reruns a commit on average and no BUSY; at the burst p99 <= 1 s, at most 1 rerun on average,
//	          BUSY on at most 0.1% of pushes, each committing within 5 s; no FOLD_BEHIND in either
//
// A phase counts its latencies; the pushes evs answered 429 BUSY, as each device's transport saw the answer, with the
// time each took to commit; FOLD_BEHIND answers; and 412 reruns as the Net's store history has them, a conditional PUT
// of one of the repo's heads the store refused. The default rate is the Team limit's peak, 2.3 pushes a second, the
// column whose miss blocks the gate (D-TEST-17); the stress case's 5.8 is a run its caller sets. A run that is no gate
// reading sets Ceilings nil and reads Misses for the record: the stress case, and every run on the local stack, which
// is one MinIO on a machine running whatever else it runs (QD-1068). T2 runs it with no ceiling: its fakes' store takes
// no time, so only what was written and read is held there.
//
// Not here: format 2, so every card version keeps its content and no push carries an index entry or writes an index
// head; the year-one mix beside the directory's pushes; writers' streams and the companion pushes, which never contend
// with the cards ref; and FI-1's and the world's outcome checks, which read at most 64 versions a step.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The world's reader, the prefix of its writers' names, and the phases' names.
const (
	fs86CardsEvsReader       = "reader"
	fs86CardsEvsWriterPrefix = "writer"
	fs86CardsEvsAlone        = "alone"
	fs86CardsEvsPeak         = "peak"
	fs86CardsEvsBurst        = "burst"
)

type Fs86CardsEvsSettings struct {
	// The devices whose cards share the cards ref: 16.
	WriterCount int
	// The column's peak rate on the cards ref, in pushes a second: 2.3, the Team limit's.
	PushesPerSecond float64
	// How long pushes arrive at that rate: 30 s, the peak hour at reduced scale.
	PeakDuration time.Duration
	// The burst's rate as a multiple of the peak's, and how long it lasts: 3 and 15 s.
	BurstFactor   float64
	BurstDuration time.Duration
	// A card's plaintext bytes: 2 KiB.
	CardByteCount int
	// The arrivals' randomness: one seed, one plan of arrivals.
	Seed uint64
	// §16.11's cards ref commits row, which each phase holds; nil holds none.
	Ceilings *sidecartest.DirectoryLoadCeilings
}

func DefaultFs86CardsEvsSettings() *Fs86CardsEvsSettings {
	return &Fs86CardsEvsSettings{
		WriterCount:     16,
		PushesPerSecond: 2.3,
		PeakDuration:    30 * time.Second,
		BurstFactor:     3,
		BurstDuration:   15 * time.Second,
		CardByteCount:   2 * 1024,
		Seed:            1,
		Ceilings:        sidecartest.DefaultDirectoryLoadCeilings(),
	}
}

// What one phase measured.
type Fs86CardsEvsPhase struct {
	Name string
	// Each committed push's time from its arrival to its write's return.
	Latencies []time.Duration
	// Conditional PUTs of a head the store refused: 412 reruns.
	RerunCount int
	// The pushes evs answered 429 BUSY at least once, and each one's time from its arrival to its commit.
	BusyCount     int
	BusyLatencies []time.Duration
	// FOLD_BEHIND answers.
	FoldBehindCount int
}

// The mean 412 reruns a commit.
func (self *Fs86CardsEvsPhase) RerunMean() float64 {
	if len(self.Latencies) == 0 {
		return 0
	}
	return float64(self.RerunCount) / float64(len(self.Latencies))
}

// The median latency, 0 for none.
func (self *Fs86CardsEvsPhase) Median() time.Duration {
	if len(self.Latencies) == 0 {
		return 0
	}
	sorted := slices.Clone(self.Latencies)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

func (self *Fs86CardsEvsPhase) String() string {
	return fmt.Sprintf("%s: %d commits, median %s, p99 %s, %d reruns (%.3f a commit), %d BUSY, %d FOLD_BEHIND",
		self.Name, len(self.Latencies), self.Median(), sidecartest.DirectoryLoadP99(self.Latencies), self.RerunCount, self.RerunMean(), self.BusyCount, self.FoldBehindCount)
}

// See the file header.
type Fs86CardsEvs struct {
	world    *EvsWorld
	settings *Fs86CardsEvsSettings

	stateLock sync.Mutex
	cards     map[string]*sidecar.DirectoryEvsCards
	// each writer's card as its last push left it, and how many it has written
	versions map[string]uint64
	contents map[string][]byte
	counts   map[string]uint64
	// the writers whose push in flight was answered 429 BUSY, and the FOLD_BEHIND answers since the phase began
	busy            map[string]bool
	foldBehindCount int
	phases          []*Fs86CardsEvsPhase
}

// A device's transport: every refusal of a push is noted by its code.
type fs86CardsEvsTransport struct {
	state  *Fs86CardsEvs
	device string
	lb     http.RoundTripper
}

func (self *fs86CardsEvsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.lb.RoundTrip(request)
	if err != nil || response.StatusCode == http.StatusOK || request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/push") {
		return response, err
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(body, reply); err == nil {
		self.state.noteRefusal(self.device, reply.GetCode())
	}
	return response, nil
}

func (self *Fs86CardsEvs) noteRefusal(device string, code protocol.EvsRefusalCode) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch code {
	case protocol.EvsRefusalCode_EVS_REFUSAL_BUSY:
		self.busy[device] = true
	case protocol.EvsRefusalCode_EVS_REFUSAL_FOLD_BEHIND:
		self.foldBehindCount += 1
	}
}

func fs86CardsEvsWriter(index int) string {
	return fmt.Sprintf("%s%02d", fs86CardsEvsWriterPrefix, index)
}

// The phases run so far, in order.
func (self *Fs86CardsEvs) Phases() []*Fs86CardsEvsPhase {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*Fs86CardsEvsPhase{}, self.phases...)
}

// The card writer's count-th push writes: CardByteCount bytes no two pushes share.
func (self *Fs86CardsEvs) content(writer string, count uint64) []byte {
	content := make([]byte, 0, self.settings.CardByteCount+sha256.Size)
	for block := uint64(0); len(content) < self.settings.CardByteCount; block += 1 {
		seed := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64([]byte(writer), count), block)
		sum := sha256.Sum256(seed)
		content = append(content, sum[:]...)
	}
	return content[:self.settings.CardByteCount]
}

// writer's next write of its card. Answers whether evs answered it 429 BUSY on the way.
func (self *Fs86CardsEvs) put(ctx context.Context, writer string) (bool, error) {
	device := self.world.Device(writer)
	cards, version, count, err := func() (*sidecar.DirectoryEvsCards, uint64, uint64, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.cards[writer] == nil {
			cards, err := sidecar.NewDirectoryEvsCards(&sidecar.DirectoryEvsCardsArgs{Client: device.Client})
			if err != nil {
				return nil, 0, 0, err
			}
			self.cards[writer] = cards
		}
		self.busy[writer] = false
		return self.cards[writer], self.versions[writer], self.counts[writer] + 1, nil
	}()
	if err != nil {
		return false, err
	}
	content := self.content(writer, count)
	next, err := cards.PutCard(ctx, self.world.RepoId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: sidecar.DirectoryCardPath(device.Signer.SidecarId), IfVersion: version, Content: content,
		AuthPin: self.world.currentView().Pin(),
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	busy := self.busy[writer]
	if err != nil {
		return busy, fmt.Errorf("%s's card write %d: %w", writer, count, err)
	}
	self.versions[writer] = next
	self.contents[writer] = content
	self.counts[writer] = count
	return busy, nil
}

// A step action: every writer writes its first card, one after another, as the phase alone.
func (self *Fs86CardsEvs) alone() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		phase := &Fs86CardsEvsPhase{Name: fs86CardsEvsAlone}
		for index := range self.settings.WriterCount {
			started := time.Now()
			if _, err := self.put(ctx, fs86CardsEvsWriter(index)); err != nil {
				return err
			}
			phase.Latencies = append(phase.Latencies, time.Since(started))
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.phases = append(self.phases, phase)
		return nil
	}
}

// A step action: pushes arrive at rate a second for duration, and the phase's counts are kept.
func (self *Fs86CardsEvs) phase(name string, rate float64, duration time.Duration) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		settings := self.settings
		phase := &Fs86CardsEvsPhase{Name: name}
		random := rand.New(rand.NewPCG(settings.Seed, uint64(len(self.Phases()))+1))
		offsets := []time.Duration{}
		for at := time.Duration(0); ; {
			at += time.Duration(random.ExpFloat64() / rate * float64(time.Second))
			if duration <= at {
				break
			}
			offsets = append(offsets, at)
		}
		if len(offsets) == 0 {
			return fmt.Errorf("%s: no push arrives in %s at %.1f a second", name, duration, rate)
		}
		free := make(chan string, settings.WriterCount)
		for index := range settings.WriterCount {
			free <- fs86CardsEvsWriter(index)
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.foldBehindCount = 0
		}()
		historyMark := net.BlobHistoryCount()
		pushErrs := []error{}
		var group sync.WaitGroup
		start := time.Now()
	arrivals:
		for _, offset := range offsets {
			arrival := start.Add(offset)
			select {
			case <-time.After(time.Until(arrival)):
			case <-ctx.Done():
				break arrivals
			}
			var writer string
			select {
			case writer = <-free:
			case <-ctx.Done():
				break arrivals
			}
			group.Add(1)
			go func() {
				defer group.Done()
				busy, err := self.put(ctx, writer)
				latency := time.Since(arrival)
				free <- writer
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if err != nil {
					pushErrs = append(pushErrs, err)
					return
				}
				phase.Latencies = append(phase.Latencies, latency)
				if busy {
					phase.BusyCount += 1
					phase.BusyLatencies = append(phase.BusyLatencies, latency)
				}
			}()
		}
		group.Wait()
		headPrefix := evsservice.HeadRepoPrefix(self.world.RepoId)
		history := net.BlobHistory()
		for _, entry := range history[min(historyMark, len(history)):] {
			if entry.Op == sidecartest.BlobHistoryPutIfMatch && entry.Outcome == sidecartest.BlobOutcomePrecondition && strings.HasPrefix(entry.Key, headPrefix) {
				phase.RerunCount += 1
			}
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			phase.FoldBehindCount = self.foldBehindCount
			self.phases = append(self.phases, phase)
		}()
		if err := ctx.Err(); err != nil {
			return err
		}
		if 0 < len(pushErrs) {
			return fmt.Errorf("%s: %d of %d pushes failed: %w", name, len(pushErrs), len(offsets), errors.Join(pushErrs[:min(len(pushErrs), 3)]...))
		}
		return nil
	}
}

// The phases run so far against §16.11's row under ceilings: the peak's ceilings for the peak, the burst's for the
// burst, none for the commits alone. Each miss is an error.
func (self *Fs86CardsEvs) Misses(ceilings *sidecartest.DirectoryLoadCeilings) []error {
	errs := []error{}
	for _, phase := range self.Phases() {
		switch phase.Name {
		case fs86CardsEvsPeak:
			errs = append(errs, fs86CardsEvsMisses(phase, ceilings, false)...)
		case fs86CardsEvsBurst:
			errs = append(errs, fs86CardsEvsMisses(phase, ceilings, true)...)
		}
	}
	return errs
}

// A step action: with Ceilings set, every miss of the phases run fails the schedule.
func (self *Fs86CardsEvs) held() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if self.settings.Ceilings == nil {
			return nil
		}
		return errors.Join(self.Misses(self.settings.Ceilings)...)
	}
}

// One phase against the row: the peak's ceilings, or the burst's.
func fs86CardsEvsMisses(phase *Fs86CardsEvsPhase, ceilings *sidecartest.DirectoryLoadCeilings, burst bool) []error {
	p99Ceiling, rerunCeiling, busyCeiling := ceilings.CardPushP99, ceilings.CardRerunMean, ceilings.CardBusyShare
	if burst {
		p99Ceiling, rerunCeiling, busyCeiling = ceilings.CardBurstPushP99, ceilings.CardBurstRerunMean, ceilings.CardBurstBusyShare
	}
	errs := []error{}
	if len(phase.Latencies) == 0 {
		return []error{fmt.Errorf("%s: no push committed", phase.Name)}
	}
	if p99 := sidecartest.DirectoryLoadP99(phase.Latencies); p99Ceiling < p99 {
		errs = append(errs, fmt.Errorf("%s: the cards ref's commits' p99 is %s over %d pushes, past %s", phase.Name, p99, len(phase.Latencies), p99Ceiling))
	}
	if mean := phase.RerunMean(); rerunCeiling < mean {
		errs = append(errs, fmt.Errorf("%s: the cards ref's commits rerun %.2f times on average, past %.2f", phase.Name, mean, rerunCeiling))
	}
	if share := float64(phase.BusyCount) / float64(len(phase.Latencies)); busyCeiling < share {
		errs = append(errs, fmt.Errorf("%s: %d of %d pushes were answered 429 BUSY, past %.1f%%", phase.Name, phase.BusyCount, len(phase.Latencies), 100*busyCeiling))
	}
	for _, latency := range phase.BusyLatencies {
		if ceilings.CardBurstRetryCommit < latency {
			errs = append(errs, fmt.Errorf("%s: a push answered 429 BUSY committed %s after it arrived, past %s", phase.Name, latency, ceilings.CardBurstRetryCommit))
			break
		}
	}
	if 0 < phase.FoldBehindCount {
		errs = append(errs, fmt.Errorf("%s: %d pushes were answered FOLD_BEHIND", phase.Name, phase.FoldBehindCount))
	}
	return errs
}

// A step action: the reader reads the cards ref whole and finds every writer's card as its last push left it.
func (self *Fs86CardsEvs) read() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		cards, err := sidecar.NewDirectoryEvsCards(&sidecar.DirectoryEvsCardsArgs{Client: self.world.Device(fs86CardsEvsReader).Client})
		if err != nil {
			return err
		}
		newest := map[string]*sidecar.DirectoryCardFile{}
		statements := map[uint64]bool{}
		after := uint64(0)
		for {
			changes, err := cards.ReadCards(ctx, self.world.RepoId, after)
			if err != nil {
				return fmt.Errorf("the reader's read of the cards ref after %d: %w", after, err)
			}
			for _, file := range changes.Files {
				statements[file.PushVersion] = true
				if held := newest[file.Path]; held == nil || held.Version <= file.Version {
					newest[file.Path] = file
				}
			}
			if !changes.More || changes.ThroughVersion <= after {
				after = max(after, changes.ThroughVersion, changes.HeadVersion)
				break
			}
			after = changes.ThroughVersion
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		written := uint64(0)
		for index := range self.settings.WriterCount {
			writer := fs86CardsEvsWriter(index)
			written += self.counts[writer]
			file := newest[sidecar.DirectoryCardPath(self.world.Device(writer).Signer.SidecarId)]
			if file == nil || file.Removed || file.Version != self.versions[writer] || !bytes.Equal(file.Content, self.contents[writer]) {
				return fmt.Errorf("the reader holds %s's card at %v, not at version %d as its last push left it", writer, fs86CardsEvsFileVersion(file), self.versions[writer])
			}
		}
		if uint64(len(statements)) != written {
			return fmt.Errorf("the reader read %d statements of the cards ref for %d pushes", len(statements), written)
		}
		again, err := cards.ReadCards(ctx, self.world.RepoId, after)
		if err != nil {
			return fmt.Errorf("the reader's read from the head: %w", err)
		}
		if 0 < len(again.Files) {
			return fmt.Errorf("a read from the head answered %d files", len(again.Files))
		}
		return nil
	}
}

// A file's version for an error, 0 for none.
func fs86CardsEvsFileVersion(file *sidecar.DirectoryCardFile) uint64 {
	if file == nil {
		return 0
	}
	return file.Version
}

// FS-86's card commits under the defaults: see the file header.
func Fs86CardsEvsCommits(net *Net) *Schedule {
	schedule, _ := Fs86CardsEvsCommitsOf(net, nil)
	return schedule
}

// Runs FS-86's card commits under settings, nil for the defaults, on a Net built from netSettings, closed before this
// returns, and logs each phase to tb: the state the phases are read from, and how the run ended. Each phase is one step
// whose actor waits on the wall clock between arrivals, so netSettings's barriers wait a step out twice over and read
// a waiting actor as no stalled one.
func RunFs86CardsEvs(tb testing.TB, netSettings *sidecartest.NetSettings, settings *Fs86CardsEvsSettings) (*Fs86CardsEvs, error) {
	if settings == nil {
		settings = DefaultFs86CardsEvsSettings()
	}
	ctx := tb.Context()
	barriers := *netSettings.Barriers
	barriers.AwaitTimeout = max(barriers.AwaitTimeout, 2*(settings.PeakDuration+settings.BurstDuration))
	barriers.StallTimeout = 0
	netSettings.Barriers = &barriers
	net := sidecartest.NewNet(ctx, netSettings)
	defer net.Close()
	schedule, state := Fs86CardsEvsCommitsOf(net, settings)
	result := Run(ctx, schedule, net)
	for _, phase := range state.Phases() {
		tb.Log(phase)
	}
	return state, result.Err
}

// FS-86's card commits under settings, nil for the defaults, and the state its phases are read from.
func Fs86CardsEvsCommitsOf(net *Net, settings *Fs86CardsEvsSettings) (*Schedule, *Fs86CardsEvs) {
	if settings == nil {
		settings = DefaultFs86CardsEvsSettings()
	}
	state := &Fs86CardsEvs{
		settings: settings,
		cards:    map[string]*sidecar.DirectoryEvsCards{},
		versions: map[string]uint64{},
		contents: map[string][]byte{},
		counts:   map[string]uint64{},
		busy:     map[string]bool{},
	}
	worldSettings := DefaultEvsWorldSettings()
	worldSettings.Kind = protocol.RepoKind_REPO_KIND_DIRECTORY
	worldSettings.Instances = []string{"evs1"}
	worldSettings.Devices = []*EvsWorldDeviceSettings{}
	for index := range settings.WriterCount {
		worldSettings.Devices = append(worldSettings.Devices, &EvsWorldDeviceSettings{Name: fs86CardsEvsWriter(index), Instances: []string{"evs1"}, Writer: true})
	}
	worldSettings.Devices = append(worldSettings.Devices, &EvsWorldDeviceSettings{Name: fs86CardsEvsReader, Instances: []string{"evs1"}})
	worldSettings.DeviceTransport = func(device string, lb http.RoundTripper) http.RoundTripper {
		return &fs86CardsEvsTransport{state: state, device: device, lb: lb}
	}
	state.world = NewEvsWorld(net, worldSettings)
	return &Schedule{
		Id: "FS-86's card commits",
		Steps: []*Step{
			{Actor: fs86CardsEvsWriter(0), Action: state.world.Setup},
			{Actor: "writers", Action: state.alone()},
			{Actor: "writers", Action: state.phase(fs86CardsEvsPeak, settings.PushesPerSecond, settings.PeakDuration)},
			{Actor: "writers", Action: state.phase(fs86CardsEvsBurst, settings.PushesPerSecond*settings.BurstFactor, settings.BurstDuration)},
			{Actor: fs86CardsEvsReader, Action: state.read()},
			{Actor: "check", Action: state.held()},
		},
		Check: []Invariant{state.world.NoAlarms()},
		Tiers: []Tier{TierT2, TierT3},
	}, state
}
