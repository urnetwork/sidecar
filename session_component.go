//go:build !ios_extension && !sidecar_http

// Context history's component on a Sidecar (CTXH-M11-03; DESIGN-COMPUTE §3.3, CONTRACTS C-38): every Sidecar on a
// compute leg constructs it, and its session journal is built at its first use from what the network holds then, the
// record, the spool's redactor and the session directory, since a Sidecar constructs its components before it knows
// its network. HARN-M11-08 wires the Harness's journal source through Sidecar.SessionJournal, as the gateway's
// recorder does (CTXH-M12-01).
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"sync"
)

// The component's name, and its sealed directory's.
const sessionComponentName = "session"

// The component: the journal once built.
type sidecarSession struct {
	sidecar *Sidecar

	stateLock sync.Mutex
	journal   *SessionJournal
}

// Registers the component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(sessionComponentName, func(sidecar *Sidecar) (*sidecarSession, error) {
		return &sidecarSession{sidecar: sidecar}, nil
	}, nil)
}

// The network's session journal: built at the first call from its record, its spool's redactor, its settings and the
// session directory, the record's gaps counted against each run. ErrSidecarStoreLocked before enrollment, and the
// component's error where it did not construct.
func (self *Sidecar) SessionJournal() (*SessionJournal, error) {
	component, err := sidecarComputeComponent[sidecarSession](self, sessionComponentName)
	if err != nil {
		return nil, err
	}
	component.stateLock.Lock()
	defer component.stateLock.Unlock()
	if component.journal != nil {
		return component.journal, nil
	}
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	spool, err := self.Spool()
	if err != nil {
		return nil, err
	}
	store, err := self.LocalStore().Directory(sessionComponentName, sessionComponentName)
	if err != nil {
		return nil, err
	}
	args := &SessionJournalArgs{
		Record:   record,
		Store:    store,
		Redactor: spool.Redactor(),
		Settings: self.settings.Session,
		Ingest:   self.settings.Ingest,
		Clock:    self.settings.ClockOrReal(),
	}
	if runs, err := self.Runs(); err == nil {
		args.Gap = func(runId Id, code string) {
			if err := runs.AddGap(context.Background(), runId, code); err != nil {
				self.log.Warningf("[session]a coverage gap was not counted: %s", err)
			}
		}
	}
	journal, err := NewSessionJournal(args)
	if err != nil {
		return nil, err
	}
	component.journal = journal
	return journal, nil
}
