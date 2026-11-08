// FI-1 to FI-30 (§22.8). An invariant reads every store through an Oracle and says whether the state
// holds. Most need the engine whose state they read, so its owner writes the check in fi<n>.go beside
// this file and registers it. Until then Check on that FI fails, naming what is missing: a schedule
// that asks for a check nobody wrote must not pass.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

type Invariant interface {
	// "FI-1".
	Id() string
	// Runs after every step and at the end. ctx is an inspecting context, so reads through it take
	// no fault and count nothing.
	Check(ctx context.Context, oracle *Oracle) error
}

// What an invariant reads. On T2 a read goes around every fault; on T3 it goes to the real store.
type Oracle struct {
	Net *Net
	// The step just done, counting from 0, or len(Steps) at the end.
	Step int
	// True for the check at the end, where nothing is left in flight.
	Final bool
}

// Every store, as an engine sees it.
func (self *Oracle) Host() *sidecar.ServiceHost {
	return self.Net.Host()
}

// Every store request so far.
func (self *Oracle) BlobHistory() []*sidecartest.BlobHistoryEntry {
	return self.Net.BlobHistory()
}

type invariantFunction struct {
	id    string
	check func(ctx context.Context, oracle *Oracle) error
}

func (self *invariantFunction) Id() string {
	return self.id
}

func (self *invariantFunction) Check(ctx context.Context, oracle *Oracle) error {
	return self.check(ctx, oracle)
}

// An invariant from a function, for a check that has no FI number of its own, such as one a test
// states about its own scenario.
func NewInvariant(id string, check func(ctx context.Context, oracle *Oracle) error) Invariant {
	return &invariantFunction{id: id, check: check}
}

var (
	invariantLock   sync.Mutex
	invariantChecks = map[int]func(ctx context.Context, oracle *Oracle) error{}
)

// Binds FI-n's check. An owner calls this from a package-level var in fi<n>.go. Binding one twice is
// a bug, so it panics. Returns n so the var has a value.
func RegisterInvariant(n int, check func(ctx context.Context, oracle *Oracle) error) int {
	if DefaultCatalog().Invariant(n) == nil {
		panic(fmt.Sprintf("no FI-%d in §22.8", n))
	}
	invariantLock.Lock()
	defer invariantLock.Unlock()
	if _, ok := invariantChecks[n]; ok {
		panic(fmt.Sprintf("a second check for FI-%d", n))
	}
	invariantChecks[n] = check
	return n
}

// A check nobody wrote yet, which fails with this.
var ErrInvariantUnbuilt = errors.New("no check is built for this invariant")

// FI-n as a schedule names it, answered by whichever oracle bound FI-n, so a row names an invariant
// the same way whoever wrote it. One with no bound check fails when run, and an n §22.8 does not hold
// panics, since a schedule naming it is wrong where it was written.
func FI(n int) Invariant {
	catalogInvariant := DefaultCatalog().Invariant(n)
	if catalogInvariant == nil {
		panic(fmt.Sprintf("no FI-%d in §22.8", n))
	}
	return NewInvariant(catalogInvariant.Id, func(ctx context.Context, oracle *Oracle) error {
		invariantLock.Lock()
		check, ok := invariantChecks[n]
		invariantLock.Unlock()
		if !ok {
			return fmt.Errorf("%s %s (%s's oracle): %w", catalogInvariant.Id, catalogInvariant.Name, catalogInvariant.Oracle, ErrInvariantUnbuilt)
		}
		return check(ctx, oracle)
	})
}

// Which FI have a check: what a reviewer reads to see how much of §22.8 can fail today.
func BuiltInvariants() []int {
	invariantLock.Lock()
	defer invariantLock.Unlock()
	built := []int{}
	for n := range invariantChecks {
		built = append(built, n)
	}
	slices.Sort(built)
	return built
}
