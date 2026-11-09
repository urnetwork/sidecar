// The one shape a load run reports in (§22.8's harness conventions; R-TEST-7, D-TEST-7). A report
// holds the steady phase's figures: how many arrivals were due and launched, the successes' latency
// percentiles from each arrival's due time, the failed attempts beside them with their own percentiles
// and kinds (connect/CODESTYLE.md:215), the achieved rate, allocations, samples, and what makes the run
// repeatable: the effective settings, the commit set and the host. A run too small or too short to show
// a target sets Smoke, and GateEvidence refuses it, so a smoke never reaches a gate as evidence.

package load

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Latency figures in milliseconds, by nearest rank. Count is how many attempts they cover; with none,
// every figure is zero.
type Percentiles struct {
	Count int64   `json:"count"`
	Min   float64 `json:"min"`
	Mean  float64 `json:"mean"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
	P999  float64 `json:"p999"`
	Max   float64 `json:"max"`
}

// Heap allocated over the steady phase, process-wide, and per attempt that ended in it.
type Allocations struct {
	Bytes             uint64  `json:"bytes"`
	Objects           uint64  `json:"objects"`
	BytesPerAttempt   float64 `json:"bytes_per_attempt"`
	ObjectsPerAttempt float64 `json:"objects_per_attempt"`
}

// One run's report.
type Report struct {
	// The workload.
	Name string `json:"name"`
	// The ids of targets.yml's rows this run measures.
	Targets []string `json:"targets"`
	// A run that proves nothing: too small, too short, or on a host unlike the target's. GateEvidence
	// refuses it.
	Smoke bool `json:"smoke"`
	// Where it ran, by name.
	Host string `json:"host"`

	Started      time.Time `json:"started"`
	Ended        time.Time `json:"ended"`
	WarmupMillis int64     `json:"warmup_ms"`
	SteadyMillis int64     `json:"steady_ms"`

	// The effective settings the run used, as its constructors resolved them, features on (R-TEST-2).
	Settings map[string]string `json:"settings"`
	// Each repository's commit, with "+dirty" where its tree held changes.
	CommitSet map[string]string `json:"commit_set"`

	// The pace set, arrivals a second.
	OfferedPerSecond float64 `json:"offered_per_second"`
	// Steady arrivals due by the schedule.
	Scheduled int64 `json:"scheduled"`
	// Steady arrivals launched, refused ones included. Below Scheduled only when the run was cancelled.
	Arrivals int64 `json:"arrivals"`
	// Steady attempts that succeeded, whenever they ended.
	Succeeded int64 `json:"succeeded"`
	// Successes that ended within the steady phase, a second: the throughput the system kept up, which
	// falls below the offered pace when it cannot, while the arrivals keep it.
	AchievedPerSecond float64 `json:"achieved_per_second"`
	// The successes' latency, from each arrival's due time, so queueing counts.
	LatencyMillis Percentiles `json:"latency_ms"`
	// Failed attempts, beside the successes, with their latency and kinds.
	Failed              int64            `json:"failed"`
	FailedLatencyMillis Percentiles      `json:"failed_latency_ms"`
	FailureKinds        map[string]int64 `json:"failure_kinds"`

	Allocations Allocations `json:"allocations"`
	Samples     []Sample    `json:"samples"`
	// What the run says of itself: a cancellation, a host that lacked something.
	Notes []string `json:"notes"`
}

// Latency figures of durations, by nearest rank.
func PercentilesOf(durations []time.Duration) Percentiles {
	if len(durations) == 0 {
		return Percentiles{}
	}
	sorted := slices.Clone(durations)
	slices.Sort(sorted)
	millis := func(duration time.Duration) float64 {
		return float64(duration) / float64(time.Millisecond)
	}
	rank := func(fraction float64) float64 {
		// nearest rank: the smallest value with at least fraction of the values at or below it
		index := int(fraction*float64(len(sorted))+0.999999999) - 1
		index = max(0, min(index, len(sorted)-1))
		return millis(sorted[index])
	}
	total := time.Duration(0)
	for _, duration := range sorted {
		total += duration
	}
	return Percentiles{
		Count: int64(len(sorted)),
		Min:   millis(sorted[0]),
		Mean:  millis(total) / float64(len(sorted)),
		P50:   rank(0.50),
		P90:   rank(0.90),
		P95:   rank(0.95),
		P99:   rank(0.99),
		P999:  rank(0.999),
		Max:   millis(sorted[len(sorted)-1]),
	}
}

// The report as JSON, indented, for a run's artifact.
func (self *Report) Json() ([]byte, error) {
	return json.MarshalIndent(self, "", "  ")
}

// A report from its JSON, refusing a field the shape does not hold, so a report from another harness
// version is read whole or not at all.
func ParseReport(data []byte) (*Report, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	report := &Report{}
	if err := decoder.Decode(report); err != nil {
		return nil, err
	}
	return report, nil
}

// Why the report cannot stand as a gate's evidence for a target, or nil. A smoke run, a run with no
// steady arrivals, a cancelled one, one naming no target, and one with no commit set or settings are
// each refused: evidence is a full run of a named build at named settings.
func (self *Report) GateEvidence() error {
	reasons := []string{}
	if self.Smoke {
		reasons = append(reasons, "it is a smoke run, which proves nothing")
	}
	if self.Scheduled == 0 {
		reasons = append(reasons, "no arrival was due in its steady phase")
	}
	if self.Arrivals < self.Scheduled {
		reasons = append(reasons, fmt.Sprintf("only %d of its %d steady arrivals ran", self.Arrivals, self.Scheduled))
	}
	if len(self.Targets) == 0 {
		reasons = append(reasons, "it names no target")
	}
	if len(self.CommitSet) == 0 {
		reasons = append(reasons, "it records no commit set")
	}
	if len(self.Settings) == 0 {
		reasons = append(reasons, "it records no settings")
	}
	if self.Host == "" {
		reasons = append(reasons, "it names no host")
	}
	if len(reasons) == 0 {
		return nil
	}
	return errors.New(self.Name + " is no gate evidence: " + strings.Join(reasons, "; "))
}

// Each named repository's commit under monoroot, "+dirty" where its tree holds changes, for
// Report.CommitSet. A repository that is not there is an error, so a report never names a commit set
// it did not read.
func ReadCommitSet(monoroot string, repos ...string) (map[string]string, error) {
	commitSet := map[string]string{}
	for _, repo := range repos {
		directory := filepath.Join(monoroot, repo)
		head, err := exec.Command("git", "-C", directory, "rev-parse", "HEAD").Output()
		if err != nil {
			return nil, fmt.Errorf("reading %s's commit: %v", repo, err)
		}
		status, err := exec.Command("git", "-C", directory, "status", "--porcelain").Output()
		if err != nil {
			return nil, fmt.Errorf("reading %s's tree: %v", repo, err)
		}
		commit := strings.TrimSpace(string(head))
		if 0 < len(bytes.TrimSpace(status)) {
			commit += "+dirty"
		}
		commitSet[repo] = commit
	}
	return commitSet, nil
}
