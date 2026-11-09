// The oracle a row's invariants read (TEST-M2-01; D-TEST-10): §22.8's "an oracle with read access to every store
// checks the named invariants after every step and at the end". Run checks every invariant Schedule.Check names
// after each step and at the end, through one Oracle per check, and collects every violation at that point, each
// with its step and its invariant, rather than the first alone: a schedule that breaks two invariants at once says
// both. The run stops at the first step with any, since what follows a broken state proves nothing.
//
// An Oracle is valid only for its own check: Changed is what the store took since the previous check.

package fault

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What an invariant reads. On T2 a read goes around every fault; on T3 it goes to the real store.
type Oracle struct {
	Net *Net
	// The step just done, counting from 0, or len(Steps) at the end.
	Step int
	// True for the check at the end, where nothing is left in flight.
	Final bool
	// Every store, decoded: objects, Redis, at T3 Postgres, the authorization log, and the readers' keys.
	View *StoreView
	// The blob history's length at the previous check, so Changed reads only what this step did.
	previousHistoryCount int
}

// Every store, as an engine sees it.
func (self *Oracle) Host() *sidecar.ServiceHost {
	return self.Net.Host()
}

// Every store request so far.
func (self *Oracle) BlobHistory() []*sidecartest.BlobHistoryEntry {
	return self.Net.BlobHistory()
}

// The store requests since the previous check, so an invariant reads only what a step can have changed, not the
// whole store after every step.
func (self *Oracle) Changed() []*sidecartest.BlobHistoryEntry {
	history := self.Net.BlobHistory()
	if self.previousHistoryCount < len(history) {
		return history[self.previousHistoryCount:]
	}
	return nil
}

// The keys written since the previous check, by cluster, each once.
func (self *Oracle) ChangedKeys() map[string][]string {
	clusterKeys := map[string][]string{}
	seen := map[string]bool{}
	for _, entry := range self.Changed() {
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream, sidecartest.BlobHistoryDelete:
		default:
			continue
		}
		if seen[entry.ClusterId+" "+entry.Key] {
			continue
		}
		seen[entry.ClusterId+" "+entry.Key] = true
		clusterKeys[entry.ClusterId] = append(clusterKeys[entry.ClusterId], entry.Key)
	}
	return clusterKeys
}

// One invariant that did not hold at one check.
type Violation struct {
	Invariant string
	// The step after which it failed, or the schedule's length at the end.
	Step  int
	Final bool
	Err   error
}

func (self *Violation) String() string {
	if self.Final {
		return fmt.Sprintf("%s at the end: %v", self.Invariant, self.Err)
	}
	return fmt.Sprintf("%s after step %d: %v", self.Invariant, self.Step, self.Err)
}

// Runs every invariant against oracle, under an inspecting context, and returns each that failed.
func checkInvariants(ctx context.Context, oracle *Oracle, invariants []Invariant) []*Violation {
	inspect := sidecartest.InspectContext(ctx)
	violations := []*Violation{}
	for _, invariant := range invariants {
		if err := invariant.Check(inspect, oracle); err != nil {
			violations = append(violations, &Violation{Invariant: invariant.Id(), Step: oracle.Step, Final: oracle.Final, Err: err})
		}
	}
	return violations
}

// The error a run fails with at a check: every violation, named, each wrapping its invariant's error.
func violationsError(violations []*Violation) error {
	errs := []error{}
	for _, violation := range violations {
		errs = append(errs, fmt.Errorf("%s after step %d: %w", violation.Invariant, violation.Step, violation.Err))
	}
	return errors.Join(errs...)
}
