// §19.11's format2 gate as evs reads it (§11.6's format row, D-OPS-10, D-PHASE-10; EVS2-M10-05): the networks
// whose pushes may carry format 2, each repo migrating at its first such push (repo_format.go), and the purge and drop
// modes EVSB-M10-01, -02, -03, -05 and -06 read before they delete anything. The host reads config/<env>/sidecar.yml
// every 60 s (ServiceHost.Gates, host_gates.go), so an engine asks on each request and keeps no answer: a network is
// in when the gate is enabled and the network is listed or its bucket is under the percent, an absent or unparsable
// file reads as off, and a purge or drop mode that is not exactly `on` reads observe, so every failure keeps content.
//
// Every answer here fails closed: a host with no gates admits nothing and observes, as a missing file does.

package evsservice

import (
	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The format2 gate as the engine reads it. Safe for concurrent use; no method does I/O, so each may be called on a
// request's path.
type Format2Gate interface {
	// Whether the network's pushes may carry format 2, and so raise its repos to format 2.
	Admits(networkId sidecar.Id) bool
	// Whether the purge deletes replaced versionless content, or only logs its candidates (D-TEST-12).
	PurgeMode() sidecar.Format2Mode
	// Whether drop jobs delete dropped history, or only run through verify (D-TEST-18).
	DropMode() sidecar.Format2Mode
}

// The gate over a host's ServiceGates, read on each call so a reread moves it within the host's interval. A nil
// host, or one that set no gates, answers closed.
type hostFormat2Gate struct {
	host *sidecar.ServiceHost
}

// The engine's gate on host: see the file header.
func NewFormat2Gate(host *sidecar.ServiceHost) Format2Gate {
	if host == nil {
		return ClosedFormat2Gate{}
	}
	return &hostFormat2Gate{host: host}
}

func (self *hostFormat2Gate) gate() sidecar.Format2Gate {
	return self.host.GatesOrClosed().Format2()
}

func (self *hostFormat2Gate) Admits(networkId sidecar.Id) bool {
	return self.gate().Admits(connect.Id(networkId))
}

func (self *hostFormat2Gate) PurgeMode() sidecar.Format2Mode {
	return self.gate().Purge()
}

func (self *hostFormat2Gate) DropMode() sidecar.Format2Mode {
	return self.gate().Drop()
}

// Every network out and every mode observe: what an absent file answers, and what a job reads when it is given no
// gate, so nothing is deleted on a gate nobody set.
type ClosedFormat2Gate struct{}

// No.
func (self ClosedFormat2Gate) Admits(networkId sidecar.Id) bool {
	return false
}

// Observe.
func (self ClosedFormat2Gate) PurgeMode() sidecar.Format2Mode {
	return sidecar.Format2Observe
}

// Observe.
func (self ClosedFormat2Gate) DropMode() sidecar.Format2Mode {
	return sidecar.Format2Observe
}

// The gate this engine reads: its host's, for a job in the same process that must not delete past it.
func (self *EvsEngine) Format2Gate() Format2Gate {
	return self.format2
}

// Whether this instance runs as format 2 (EvsSettings.InstanceFormat), taking format-2 values and raising repos;
// a format-1 instance refuses each as needing format 2 (format1_guard.go).
func (self *EvsEngine) format2Instance() bool {
	return sidecar.EvsRepoFormat2 <= self.settings.InstanceFormat
}
