// §9.7's scheduler as pure functions: every input is an argument, randomness and time included, and
// nothing here reads a clock, a store or a global. sidecartest's fake store and server's Lua script
// both have to repeat a pick exactly, so the arithmetic is what a Lua double holds without rounding:
// integers, (est + 1) / weight compared by cross multiplying, and draws of 32 bits, which Lua's % takes
// exactly. Candidates are ordered here by client id, so what a store happens to return them in cannot
// move a pick.
//
// The clamp bounds est and nothing else. A pick never refuses or delays a ticket for it, so a dialer
// is held only by step 1's est < max_streams, its bucket (§9.10) and the listener's admission (D-SOCK-5;
// meta review CC-06). Nothing here caps names, listeners or streams (owner decision 66).
//
// The store samples: a group above §9.7's 64 listeners comes here as its random 64 (ZRANDMEMBER runs
// in the script, where no draw of this file can reach it). Affinity is SOCK-M6-01's branch beside this.

package socketsservice

import (
	"slices"
	"time"

	"github.com/urnetwork/connect"
)

// The scheduler's tunables (§9.6, §9.7). SOCK-M5-03's SocketsSettings carries these, so that a ticket's
// lifetime has this one default. Every count and time here is positive: a pick has no off switch.
type SocketSchedulerSettings struct {
	// How long a ticket lives, and so how long a primary one counts in est, since an unredeemed ticket
	// expires (§9.7, D-SOCK-4). Default 30 s.
	TicketLifetime time.Duration
	// The clamp's least count, whatever max_streams is. Default 4.
	ClampFloorCount int
	// The clamp's share of max_streams, rounded down. Default 10%.
	ClampPercent int
	// What each consecutive ejection adds to how long it lasts (§9.6). Default 30 s, Envoy's.
	EjectionStep time.Duration
	// The longest an ejection lasts, and the longest its record lives, §2.8's sock-1 and sock-2 ttl,
	// which is what ends a run of them. Default 300 s, Envoy's.
	EjectionMax time.Duration
	// How much of a group may be ejected at once, and of a group how much one dialer may exclude,
	// rounded down. Default 50%.
	EjectionGroupPercent int
	// How close together reports from different networks must come to eject (§9.6). Default 30 s.
	ReporterWindow time.Duration
	// How many networks must report to eject (§9.6, D-SOCK-6). Default 2.
	ReporterNetworkCount int
}

// §9.6's and §9.7's values.
func DefaultSocketSchedulerSettings() *SocketSchedulerSettings {
	return &SocketSchedulerSettings{
		TicketLifetime:       30 * time.Second,
		ClampFloorCount:      4,
		ClampPercent:         10,
		EjectionStep:         30 * time.Second,
		EjectionMax:          300 * time.Second,
		EjectionGroupPercent: 50,
		ReporterWindow:       30 * time.Second,
		ReporterNetworkCount: 2,
	}
}

// What the group holds for one dialer of one listener: §9.8's per-dialer fields, §2.8's sock-2.
type SocketDialerShare struct {
	// When this dialer's primary tickets were issued, in milliseconds. Only the newest c can count,
	// so a store need keep no more than that, and it may drop any from before the listener's report.
	PrimaryIssueMillis []int64
	// This dialer's exclusion of this listener.
	Exclusion SocketEjectionState
}

// One listener of a group as the store read it for this pick (§9.5, §9.8; §2.8's sock-1). A store
// fills these with defaults applied, so a weight is 1 to 1000. A pick only reads them.
type SocketCandidate struct {
	ListenerClientId connect.Id
	// For the ticket: a pick does not read it.
	ListenId connect.Id
	Protocol string
	Version  int
	// ALPN ids served.
	Alpns      []string
	Weight     int
	MaxStreams int
	Serving    bool
	Draining   bool
	// When the lease ends, in milliseconds. At or past it the listener takes no tickets.
	LeaseExpireMillis int64
	// In-flight at the last report, and when it came, in milliseconds.
	ReportedInflight int
	ReportMillis     int64
	// This listener's ejection for all dialers.
	Ejection SocketEjectionState
	// Each dialer it holds a share or an exclusion for.
	DialerClientIdShares map[connect.Id]*SocketDialerShare
}

// One Find's half of a pick, with what would otherwise be read from the world.
type SocketPickRequest struct {
	DialerClientId connect.Id
	// What the dialer asks for. "" and 0 ask nothing, so an application dial takes the group's
	// protocol, which is the listener's (§9.4's table). Alpns empty means none offered, and §13.7
	// dispatches that by AppMode, so it matches every listener.
	Protocol   string
	MinVersion int
	Alpns      []string
	NowMillis  int64
	// Two uniform draws, one per sampled candidate, which the caller makes: random ARGV to a script.
	FirstDraw  uint32
	SecondDraw uint32
}

// What a pick came to.
type SocketPickOutcome int

const (
	// A primary, and a backup when a second candidate remains.
	SocketPickFound SocketPickOutcome = iota + 1
	// Nothing live matches: Find's no_listener.
	SocketPickNoListener
	// Something does, and est alone excludes all of it: Find's busy.
	SocketPickBusy
)

// A pick. Neither candidate is a copy: each is the one the caller passed in.
type SocketPickResult struct {
	Outcome SocketPickOutcome
	Primary *SocketCandidate
	Backup  *SocketCandidate
}

// c, the most one dialer can add to a listener's est: max(4, ⌊10% of max_streams⌋) at the defaults
// (§9.7), so 25 at the default 256.
func SocketClampCount(maxStreams int, settings *SocketSchedulerSettings) int {
	return max(settings.ClampFloorCount, maxStreams*settings.ClampPercent/100)
}

// est, what the service believes is in flight: the last report, plus each dialer's primary tickets
// since then, each for as long as a ticket lives and at most c from any one dialer. A ticket of the
// report's own millisecond counts, so a stopped clock still sees a pick move est. A negative report
// reads as none.
func SocketEstimate(candidate *SocketCandidate, nowMillis int64, settings *SocketSchedulerSettings) int {
	clampCount := SocketClampCount(candidate.MaxStreams, settings)
	ticketLifetimeMillis := settings.TicketLifetime.Milliseconds()
	est := max(candidate.ReportedInflight, 0)
	for _, share := range candidate.DialerClientIdShares {
		issuedCount := 0
		for _, issueMillis := range share.PrimaryIssueMillis {
			if candidate.ReportMillis <= issueMillis && nowMillis < issueMillis+ticketLifetimeMillis {
				issuedCount += 1
			}
		}
		est += min(issuedCount, clampCount)
	}
	return est
}

// The index draw lands on when each candidate but skip takes a part of [0, total weight) as wide as its
// weight, so a draw reaches each in proportion to weight. skip -1 skips none.
func drawSocketCandidate(candidates []*SocketCandidate, draw uint32, skip int) int {
	totalWeight := int64(0)
	for index, candidate := range candidates {
		if index != skip {
			totalWeight += int64(candidate.Weight)
		}
	}
	target := int64(draw) % totalWeight
	chosenIndex := -1
	for index, candidate := range candidates {
		if index == skip {
			continue
		}
		chosenIndex = index
		if target < int64(candidate.Weight) {
			break
		}
		target -= int64(candidate.Weight)
	}
	return chosenIndex
}

// §9.7's steps 1 to 3 over what the store read: filter, sample two distinct candidates in proportion
// to weight, and take the lower (est + 1) / weight, the other being the backup. A tie goes to the first
// sampled, which weight chose. If ejections and exclusions leave nothing, they are ignored, and nothing
// else ever is. The arguments are unchanged, so the caller records the primary's ticket itself.
func PickSocketListeners(candidates []*SocketCandidate, request *SocketPickRequest, settings *SocketSchedulerSettings) *SocketPickResult {
	matches := func(candidate *SocketCandidate) bool {
		if request.NowMillis >= candidate.LeaseExpireMillis || !candidate.Serving || candidate.Draining || candidate.Weight <= 0 {
			return false
		}
		if request.Protocol != "" && request.Protocol != candidate.Protocol {
			return false
		}
		if candidate.Version < request.MinVersion {
			return false
		}
		return len(request.Alpns) == 0 || slices.ContainsFunc(request.Alpns, func(alpn string) bool {
			return slices.Contains(candidate.Alpns, alpn)
		})
	}
	shunned := func(candidate *SocketCandidate) bool {
		if candidate.Ejection.Active(request.NowMillis, settings) {
			return true
		}
		share := candidate.DialerClientIdShares[request.DialerClientId]
		return share != nil && share.Exclusion.Active(request.NowMillis, settings)
	}

	matched := false
	roomyCandidates := []*SocketCandidate{}
	pickCandidates := []*SocketCandidate{}
	for _, candidate := range candidates {
		if !matches(candidate) {
			continue
		}
		matched = true
		if SocketEstimate(candidate, request.NowMillis, settings) < candidate.MaxStreams {
			roomyCandidates = append(roomyCandidates, candidate)
			if !shunned(candidate) {
				pickCandidates = append(pickCandidates, candidate)
			}
		}
	}
	if !matched {
		return &SocketPickResult{Outcome: SocketPickNoListener}
	}
	if len(pickCandidates) == 0 {
		pickCandidates = roomyCandidates
	}
	if len(pickCandidates) == 0 {
		return &SocketPickResult{Outcome: SocketPickBusy}
	}

	slices.SortFunc(pickCandidates, func(a *SocketCandidate, b *SocketCandidate) int {
		return a.ListenerClientId.Cmp(b.ListenerClientId)
	})
	firstIndex := drawSocketCandidate(pickCandidates, request.FirstDraw, -1)
	first := pickCandidates[firstIndex]
	if len(pickCandidates) == 1 {
		return &SocketPickResult{Outcome: SocketPickFound, Primary: first}
	}
	second := pickCandidates[drawSocketCandidate(pickCandidates, request.SecondDraw, firstIndex)]

	firstLoad := int64(SocketEstimate(first, request.NowMillis, settings) + 1)
	secondLoad := int64(SocketEstimate(second, request.NowMillis, settings) + 1)
	if secondLoad*int64(first.Weight) < firstLoad*int64(second.Weight) {
		first, second = second, first
	}
	return &SocketPickResult{Outcome: SocketPickFound, Primary: first, Backup: second}
}
