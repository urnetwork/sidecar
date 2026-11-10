//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's pid ancestry (plan-MCP-taint-new-session, I-9): a process is its pid and its start time, so a pid the
// system hands out again is another process, and a pid's ancestry is its own entry, then its parent's, and so on up
// to the system's first process. The run rules read it: an MCP session joins its harness process's runs, a new run
// inherits that process's taint while it lives, a control-mode caller's run is its harness ancestor's (MCP-M3-15),
// and a ur command an agent's shell runs taints that harness's runs (Sidecar.TaintAncestorRuns). Each system's table
// is its own file: /proc on Linux, kern.proc.pid on macOS, a Toolhelp snapshot on Windows; another system reads
// none, so every lookup there fails, and a session that cannot be placed stays unbound and so tainted.
//
// A parent that started after its child is no parent: the child's parent exited and the system reused its pid,
// which Windows never repairs, so the walk stops there rather than join an unrelated process. A pid the table cannot
// read ends the walk too. Names are base names, lowercase without .exe on Windows, read only by the shell rule; a
// start time is in Unix milliseconds, except on Linux, where it is milliseconds since boot, which tells processes
// apart as well. None of it leaves the device or reaches a log (I-13).

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A pid that names no process the table can read.
var ErrProcessUnknown = errors.New("no such process")

// One process, as the ancestry rules tell it from another.
type ProcessIdentity struct {
	Pid         int   `json:"pid"`
	StartMillis int64 `json:"start_millis"`
}

// Whether the identity names a process at all.
func (self ProcessIdentity) Known() bool {
	return 0 < self.Pid
}

// The identity as a key: pid and start time, which name nothing outside this device.
func (self ProcessIdentity) String() string {
	return fmt.Sprintf("%d@%d", self.Pid, self.StartMillis)
}

// One process's place in the tree.
type ProcessInfo struct {
	Identity  ProcessIdentity
	ParentPid int
	// The executable's base name as the system reports it: at most 15 bytes on Linux and 16 on macOS.
	Name string
}

// What reads the process table: the system's (SystemProcessTable), or a test's. Safe for concurrent use.
type ProcessTable interface {
	// The process of pid, or ErrProcessUnknown.
	Process(pid int) (*ProcessInfo, error)
}

// The system's process table.
type systemProcessTable struct{}

// The system's process table. On a system with no reader every lookup fails.
func SystemProcessTable() ProcessTable {
	return systemProcessTable{}
}

// The process of pid, from the system.
func (self systemProcessTable) Process(pid int) (*ProcessInfo, error) {
	if pid <= 0 {
		return nil, ErrProcessUnknown
	}
	return systemProcess(pid)
}

// pid's ancestry: its own entry first, then each parent's, at most depthCount entries. The walk ends at the
// system's first process (pid 0 or 1, never listed), at a parent the table cannot read, at a parent that started
// after its child, and at a pid seen already. pid itself must be readable, else ErrProcessUnknown.
func ProcessAncestors(table ProcessTable, pid int, depthCount int) ([]*ProcessInfo, error) {
	process, err := table.Process(pid)
	if err != nil {
		return nil, err
	}
	ancestors := []*ProcessInfo{process}
	seenPids := map[int]bool{process.Identity.Pid: true}
	for len(ancestors) < depthCount {
		child := ancestors[len(ancestors)-1]
		if child.ParentPid <= 1 || seenPids[child.ParentPid] {
			break
		}
		parent, err := table.Process(child.ParentPid)
		if err != nil {
			break
		}
		if child.Identity.StartMillis < parent.Identity.StartMillis {
			// the real parent exited and its pid went to a younger process
			break
		}
		seenPids[parent.Identity.Pid] = true
		ancestors = append(ancestors, parent)
	}
	return ancestors, nil
}

// A process name as the shell rule compares it: lowercase, without a trailing .exe.
func processBaseName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}

// The first of ancestors past the first, a process's own entry, that is no shell by shellNames: the process a
// hook or an MCP relay runs under, which a harness may have started it through a shell for. Nil when none is.
func HarnessProcessOf(ancestors []*ProcessInfo, shellNames []string) *ProcessInfo {
	shells := map[string]bool{}
	for _, name := range shellNames {
		shells[processBaseName(name)] = true
	}
	for i := 1; i < len(ancestors); i += 1 {
		if !shells[processBaseName(ancestors[i].Name)] {
			return ancestors[i]
		}
	}
	return nil
}

// Linux's USER_HZ, a format value of /proc: starttime counts clock ticks since boot at 100 a second on every
// architecture Linux ships. /proc/stat's btime would make a start Unix time, but btime moves with the wall clock, and
// an identity must read the same each time, so a Linux start time is milliseconds since boot.
const procClockTicksPerSecond = 100

// One /proc/<pid>/stat line: "pid (comm) state ppid ...", where comm may hold spaces and parentheses, so the fields
// are counted from the last ')'. starttime is field 22, the 20th after comm.
func parseProcStat(pid int, stat []byte) (*ProcessInfo, error) {
	nameStart := bytes.IndexByte(stat, '(')
	nameEnd := bytes.LastIndexByte(stat, ')')
	if nameStart < 0 || nameEnd < nameStart {
		return nil, ErrProcessUnknown
	}
	name := string(stat[nameStart+1 : nameEnd])
	fields := bytes.Fields(stat[nameEnd+1:])
	if len(fields) < 20 {
		return nil, ErrProcessUnknown
	}
	parentPid, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return nil, ErrProcessUnknown
	}
	startTicks, err := strconv.ParseInt(string(fields[19]), 10, 64)
	if err != nil || startTicks < 0 {
		return nil, ErrProcessUnknown
	}
	return &ProcessInfo{
		Identity:  ProcessIdentity{Pid: pid, StartMillis: startTicks * 1000 / procClockTicksPerSecond},
		ParentPid: parentPid,
		Name:      name,
	}, nil
}
