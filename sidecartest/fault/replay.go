// A failing seed becomes a fixed schedule (§22.8's explorer row): its run's trace is written to
// testdata/fault/seeds/<row>-<seed>.trace, and Replay builds the row's schedule to make the trace's
// choices, the actor each baton went to, each yield and each step's release order, through the barrier
// driver's script. Every run of a row then replays each trace committed for it.
//
// A replay of the code that failed repeats the failure. A replay of fixed code may leave the trace
// where the fix changed what ran, and from there runs in the fixed order; Result.LeftTrace says where,
// so a reviewer can see what the replay still proves. A trace whose run stalled is followed to the
// stall and no further, since a stall is an order no replay repeats.
//
// The file is text: comment lines starting with #, then one event a line, its kind, its actor or -
// and its site or -.

package fault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Where traces live, from the top of the repository.
const seedsDirectoryPath = "testdata/fault/seeds"

// The sibling a consumer's go.mod replace names, where server's T3 tests find the traces.
const seedsSiblingName = "sidecar"

// A run's barrier trace, as a failing seed leaves it.
type Trace struct {
	// The schedule's id: "FS-1", or "FS-19 config-read".
	Id   string
	Seed int64
	// Why the run failed.
	Failure string
	Events  []*sidecartest.BarrierEvent
}

// The trace a run left.
func TraceOf(result *Result) *Trace {
	failure := ""
	if result.Err != nil {
		failure = result.Err.Error()
	}
	return &Trace{Id: result.Id, Seed: result.Seed, Failure: failure, Events: result.Events}
}

var traceFileNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// <row>-<seed>.trace, the id's spaces and quotes made hyphens.
func (self *Trace) FileName() string {
	name := strings.Trim(traceFileNameUnsafe.ReplaceAllString(strings.ReplaceAll(self.Id, "'s ", "-"), "-"), "-")
	return fmt.Sprintf("%s-%d.trace", name, self.Seed)
}

// The file's text. An actor or site holding a space cannot be written, and is an error.
func (self *Trace) Bytes() ([]byte, error) {
	var text bytes.Buffer
	fmt.Fprintf(&text, "# fault trace\n# id %s\n# seed %d\n", self.Id, self.Seed)
	for _, line := range strings.Split(self.Failure, "\n") {
		fmt.Fprintf(&text, "# failed %s\n", line)
	}
	for _, event := range self.Events {
		if event.Kind == sidecartest.BarrierStalled {
			text.WriteString("# a stall: the run's order past here is not the schedule's, and a replay stops following here\n")
		}
		fields := []string{string(event.Kind), event.Actor, sidecartest.BarrierSite(event.Name, event.Key)}
		for index, field := range fields {
			if strings.ContainsAny(field, " \t\n") {
				return nil, fmt.Errorf("trace %s: %q holds a space", self.Id, field)
			}
			if field == "" {
				fields[index] = "-"
			}
		}
		text.WriteString(strings.Join(fields, " "))
		text.WriteByte('\n')
	}
	return text.Bytes(), nil
}

var traceEventKinds = []sidecartest.BarrierEventKind{
	sidecartest.BarrierPassed, sidecartest.BarrierHeld, sidecartest.BarrierReleased,
	sidecartest.BarrierKilled, sidecartest.BarrierRan, sidecartest.BarrierStalled,
}

// Parses a trace file's text.
func ParseTrace(data []byte) (*Trace, error) {
	trace := &Trace{}
	failures := []string{}
	seedSeen := false
	for index, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if comment, ok := strings.CutPrefix(line, "# "); ok {
			switch {
			case strings.HasPrefix(comment, "id "):
				trace.Id = strings.TrimPrefix(comment, "id ")
			case strings.HasPrefix(comment, "seed "):
				seed, err := strconv.ParseInt(strings.TrimPrefix(comment, "seed "), 10, 64)
				if err != nil {
					return nil, fmt.Errorf("line %d: seed: %w", index+1, err)
				}
				trace.Seed = seed
				seedSeen = true
			case strings.HasPrefix(comment, "failed "):
				failures = append(failures, strings.TrimPrefix(comment, "failed "))
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: %q is no event", index+1, line)
		}
		kind := sidecartest.BarrierEventKind(fields[0])
		if !slices.Contains(traceEventKinds, kind) {
			return nil, fmt.Errorf("line %d: no event kind %q", index+1, fields[0])
		}
		event := &sidecartest.BarrierEvent{Kind: kind}
		if fields[1] != "-" {
			event.Actor = fields[1]
		}
		if fields[2] != "-" {
			event.Name, event.Key, _ = strings.Cut(fields[2], "@")
		}
		trace.Events = append(trace.Events, event)
	}
	if trace.Id == "" || !seedSeen {
		return nil, errors.New("the trace names no id or no seed")
	}
	trace.Failure = strings.Join(failures, "\n")
	return trace, nil
}

func ReadTrace(path string) (*Trace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trace, err := ParseTrace(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return trace, nil
}

// Writes trace into directory as its FileName, and returns its path. An empty directory is the
// repository's, found above the working directory.
func WriteTrace(directory string, trace *Trace) (string, error) {
	if directory == "" {
		found, err := SeedsDirectory()
		if err != nil {
			return "", err
		}
		directory = found
	}
	data, err := trace.Bytes()
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, trace.FileName())
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// The repository's testdata/fault/seeds, looking from the working directory up: in this repository
// it is in an ancestor, and in a consumer that replaces this module it is in the sidecar sibling of an
// ancestor. Finding none is an error, so a row that cannot find its traces fails rather than replays
// nothing.
func SeedsDirectory() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		for _, candidate := range []string{
			filepath.Join(directory, seedsDirectoryPath),
			filepath.Join(directory, seedsSiblingName, seedsDirectoryPath),
		} {
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				return candidate, nil
			}
		}
		if directory == filepath.Dir(directory) {
			return "", fmt.Errorf("no %s above %s", seedsDirectoryPath, workingDirectory)
		}
	}
}

// The traces in directory for the schedule with id, by their file names, oldest seed first. An empty
// directory is the repository's.
func Traces(directory string, id string) ([]*Trace, error) {
	if directory == "" {
		found, err := SeedsDirectory()
		if err != nil {
			return nil, err
		}
		directory = found
	}
	prefix := strings.TrimSuffix((&Trace{Id: id}).FileName(), "0.trace")
	paths, err := filepath.Glob(filepath.Join(directory, prefix+"*.trace"))
	if err != nil {
		return nil, err
	}
	traces := []*Trace{}
	for _, path := range paths {
		trace, err := ReadTrace(path)
		if err != nil {
			return nil, err
		}
		// FS-19's glob also finds FS-19's cases' traces: the id decides
		if trace.Id == id {
			traces = append(traces, trace)
		}
	}
	slices.SortFunc(traces, func(a *Trace, b *Trace) int {
		return int(a.Seed - b.Seed)
	})
	return traces, nil
}

// builder's schedule, made to follow trace's choices: a fixed schedule from a failing seed.
func Replay(builder Builder, trace *Trace) Builder {
	return func(net *Net) *Schedule {
		schedule := builder(net)
		schedule.Seed = 0
		schedule.Replay = trace
		return schedule
	}
}
