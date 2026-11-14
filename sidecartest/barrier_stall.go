// How the driver tells an actor blocked where no barrier sees it from one that is only slow, once it
// has kept the baton past settings.StallTimeout (§22.8's determinism row). Wall time alone cannot: on a
// loaded machine a starved actor crosses any bound short of the wait's own. So the driver reads the
// runtime's goroutine dump, whose headers give each goroutine's state and whose last frame names the
// goroutine that started it.
//
// The holder is blocked when its goroutine is parked on a channel, a lock or a sleep, every goroutine
// it started, and those started in turn, is parked the same way, and no goroutine anywhere is running
// or waiting for a processor. Anything else is work that may yet bring it to its next barrier: its own
// goroutine running, runnable or in a system call, a goroutine of its own doing so or waiting on the
// network, or a free goroutine at work, which may be what it waits for. A state this file does not
// know counts as work, so the doubt keeps the baton where it is and the schedule's order with it.
//
// What this cannot see stays as it was, a stall: a holder waiting on a goroutine it did not start that
// is itself in a system call or waiting on the network, as a pooled connection's reader is.

package sidecartest

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
)

// The wait reasons of a goroutine that only another goroutine, or the clock, sets going again
// (runtime's waitReasonStrings).
var goroutineBlockedStates = map[string]bool{
	"chan receive":            true,
	"chan receive (nil chan)": true,
	"chan send":               true,
	"chan send (nil chan)":    true,
	"select":                  true,
	"select (no cases)":       true,
	"semacquire":              true,
	"sleep":                   true,
	"sync.Cond.Wait":          true,
	"sync.Mutex.Lock":         true,
	"sync.RWMutex.Lock":       true,
	"sync.RWMutex.RLock":      true,
	"sync.WaitGroup.Wait":     true,
}

// The states of a goroutine at work on a processor or waiting for one. A dump stops the world, so
// every goroutine it interrupts reads as runnable, and only the one that took it as running.
var goroutineWorkingStates = map[string]bool{
	"running":  true,
	"runnable": true,
}

// One goroutine of a dump.
type goroutineState struct {
	id uint64
	// its header's status or wait reason, without the wait's length and the rest after a comma
	state string
	// its innermost frame's function, for a message
	function string
	// the goroutine that started it; zero when the dump names none
	creatorId uint64
}

// Every goroutine the runtime lists, the caller first. Stops the world while it copies the stacks.
func dumpGoroutines(dumpByteCount int) []*goroutineState {
	dump := make([]byte, max(dumpByteCount, 1))
	for {
		if n := runtime.Stack(dump, true); n < len(dump) {
			return parseGoroutineDump(dump[:n])
		}
		// a full buffer is a cut dump
		dump = make([]byte, 2*len(dump))
	}
}

// Reads runtime.Stack's text: a block for each goroutine, headed `goroutine 7 [chan receive, 2
// minutes]:` with the header's labels after the bracket, and ended, for all but the first of a
// program, by `created by <function> in goroutine 3`.
func parseGoroutineDump(dump []byte) []*goroutineState {
	states := []*goroutineState{}
	var current *goroutineState
	headed := false
	for 0 < len(dump) {
		var line []byte
		line, dump, _ = bytes.Cut(dump, []byte("\n"))
		if after, found := bytes.CutPrefix(line, []byte("goroutine ")); found && bytes.HasSuffix(line, []byte(":")) {
			current = nil
			idText, header, _ := bytes.Cut(after, []byte(" "))
			id, err := strconv.ParseUint(string(idText), 10, 64)
			if err != nil {
				continue
			}
			_, state, bracketed := bytes.Cut(header, []byte("["))
			if !bracketed {
				continue
			}
			state, _, _ = bytes.Cut(state, []byte("]"))
			state, _, _ = bytes.Cut(state, []byte(","))
			current = &goroutineState{id: id, state: string(state)}
			states = append(states, current)
			headed = true
			continue
		}
		if current == nil {
			continue
		}
		if headed {
			headed = false
			function := line
			if index := bytes.LastIndexByte(function, '('); 0 <= index {
				function = function[:index]
			}
			current.function = string(function)
		}
		if after, found := bytes.CutPrefix(line, []byte("created by ")); found {
			if index := bytes.LastIndex(after, []byte(" in goroutine ")); 0 <= index {
				if creatorId, err := strconv.ParseUint(string(after[index+len(" in goroutine "):]), 10, 64); err == nil {
					current.creatorId = creatorId
				}
			}
		}
	}
	return states
}

// Whether the run on goroutine holderId is blocked as this file's head says, and what the dump showed,
// for the trace of a failed wait. states is a dump its caller took, so its first entry, the caller, is
// no one's work. runGoroutineIds are the goroutines of every run: another run a holder's goroutine
// started is under the baton itself, so the holder's own goroutines stop there.
func goroutinesBlocked(states []*goroutineState, holderId uint64, runGoroutineIds map[uint64]bool) (blocked bool, seen string) {
	var holder *goroutineState
	creatorIdStates := map[uint64][]*goroutineState{}
	for index, state := range states {
		if index == 0 {
			continue
		}
		if state.id == holderId {
			holder = state
		}
		creatorIdStates[state.creatorId] = append(creatorIdStates[state.creatorId], state)
	}
	if holder == nil {
		// not started yet, or at its end, where it hands the baton on
		return false, "its goroutine not in the dump"
	}
	if !goroutineBlockedStates[holder.state] {
		return false, fmt.Sprintf("its goroutine %s in %s", holder.state, holder.function)
	}
	own := map[uint64]bool{holder.id: true}
	for queue := []uint64{holder.id}; 0 < len(queue); queue = queue[1:] {
		for _, started := range creatorIdStates[queue[0]] {
			if own[started.id] || runGoroutineIds[started.id] {
				continue
			}
			own[started.id] = true
			if !goroutineBlockedStates[started.state] {
				return false, fmt.Sprintf(
					"its goroutine in %s at %s while goroutine %d, which it started, is %s in %s",
					holder.state, holder.function, started.id, started.state, started.function,
				)
			}
			queue = append(queue, started.id)
		}
	}
	for index, state := range states {
		if index == 0 || own[state.id] {
			continue
		}
		if goroutineWorkingStates[state.state] {
			return false, fmt.Sprintf(
				"its goroutine in %s at %s while goroutine %d, not one it started, is %s in %s",
				holder.state, holder.function, state.id, state.state, state.function,
			)
		}
	}
	return true, fmt.Sprintf("its goroutine in %s at %s, with nothing it started and nothing else at work", holder.state, holder.function)
}
