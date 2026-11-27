//go:build !ios_extension && !sidecar_http

// Context history's component on a Sidecar (CTXH-M11-03, CTXH-M11-06; DESIGN-COMPUTE §3.3, CONTRACTS C-38): every Sidecar on
// a compute leg constructs it, and its session journal is built at its first use from what the network holds then, the
// record, the spool's redactor and the session directory, since a Sidecar constructs its components before it knows
// its network. HARN-M11-08 wires the Harness's journal source through Sidecar.SessionJournal, as the gateway's recorder
// does (CTXH-M12-01).
//
// With the journal come §24.10's caps (session_cap.go), installed on the record's writer and the journal, which read
// the network's storage limit from GET /sidecar/limits, the member count from the config state and the compute block's
// history.member_share once CACL-M12-03 reads it (auto until then), and are checked at each
// SessionSettings.CapCheckInterval while the component lives; and the storage view (session_storage.go), whose live-path
// hold retention's expiry takes. The network's stored bytes come from no route yet (compute-plan-ctxh-stored-count's
// answer, a field on GET /sidecar/limits, is not built), so the caps read the vault's totals, an underestimate.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"sync"
)

// The component's name, and its sealed directory's.
const sessionComponentName = "session"

// The component: the journal, its caps and the storage view once built, and the caps' tick.
type sidecarSession struct {
	sidecar *Sidecar

	stateLock sync.Mutex
	journal   *SessionJournal
	caps      *SessionCaps
	storage   *SessionStorage
	// stops the caps' tick; nil while none runs
	stopTick func() bool
	closed   bool
}

// Registers the component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(sessionComponentName, func(sidecar *Sidecar) (*sidecarSession, error) {
		return &sidecarSession{sidecar: sidecar}, nil
	}, func(component *sidecarSession) {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		component.closed = true
		if component.stopTick != nil {
			component.stopTick()
			component.stopTick = nil
		}
	})
}

// The network's session journal: built at the first call from its record, its spool's redactor, its settings and the
// session directory, the record's gaps counted against each run, with its caps installed. ErrSidecarStoreLocked before
// enrollment, and the component's error where it did not construct.
func (self *Sidecar) SessionJournal() (*SessionJournal, error) {
	component, err := sidecarComputeComponent[sidecarSession](self, sessionComponentName)
	if err != nil {
		return nil, err
	}
	component.stateLock.Lock()
	defer component.stateLock.Unlock()
	if err := component.buildWithLock(); err != nil {
		return nil, err
	}
	return component.journal, nil
}

// The network's storage view of its history, built with the journal.
func (self *Sidecar) SessionStorage() (*SessionStorage, error) {
	component, err := sidecarComputeComponent[sidecarSession](self, sessionComponentName)
	if err != nil {
		return nil, err
	}
	component.stateLock.Lock()
	defer component.stateLock.Unlock()
	if err := component.buildWithLock(); err != nil {
		return nil, err
	}
	return component.storage, nil
}

// Builds the journal, the caps and the storage view where they are not built yet, and starts the caps' tick.
func (self *sidecarSession) buildWithLock() error {
	if self.journal != nil {
		return nil
	}
	sidecar := self.sidecar
	record, err := sidecar.Record()
	if err != nil {
		return err
	}
	spool, err := sidecar.Spool()
	if err != nil {
		return err
	}
	store, err := sidecar.LocalStore().Directory(sessionComponentName, sessionComponentName)
	if err != nil {
		return err
	}
	settings := sidecar.settings.Session
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	args := &SessionJournalArgs{
		Record:   record,
		Store:    store,
		Redactor: spool.Redactor(),
		Settings: settings,
		Ingest:   sidecar.settings.Ingest,
		Clock:    sidecar.settings.ClockOrReal(),
	}
	if runs, err := sidecar.Runs(); err == nil {
		args.Gap = func(runId Id, code string) {
			if err := runs.AddGap(context.Background(), runId, code); err != nil {
				sidecar.log.Warningf("[session]a coverage gap was not counted: %s", err)
			}
		}
	}
	journal, err := NewSessionJournal(args)
	if err != nil {
		return err
	}
	caps, err := NewSessionCaps(&SessionCapsArgs{
		Record: record, Journal: journal, Spool: spool, Settings: settings, Ingest: sidecar.settings.Ingest, Clock: args.Clock,
		Sources: &SessionCapSources{
			StorageLimit: func(ctx context.Context) (int64, error) {
				limits, err := sidecar.sidecarApi.Limits(ctx)
				if err != nil {
					return 0, err
				}
				return quotaLocalLimit(limits, sessionStorageLimitKey), nil
			},
			MemberCount: func() (int, error) {
				state, err := sidecar.configState()
				if err != nil {
					// a sidecar with no config state is a network of one member's
					return 1, nil
				}
				return max(len(state.MemberIds()), 1), nil
			},
		},
	})
	if err != nil {
		return err
	}
	storage, err := NewSessionStorage(&SessionStorageArgs{Record: record, Caps: caps, Store: store, Settings: settings,
		Live: &sidecarSessionLiveness{sidecar: sidecar},
		// read at use, never here: the Harness reaches this component in turn as it starts
		Harness: func() *Harness {
			harness, err := sidecar.Harness()
			if err != nil {
				return nil
			}
			return harness
		},
	})
	if err != nil {
		return err
	}
	record.Retention().SetHold(storage.LiveHold)
	self.journal, self.caps, self.storage = journal, caps, storage
	self.armTickWithLock(args.Clock, settings)
	return nil
}

// The storage limit's key in QuotaLimits (§20.4's storage).
const sessionStorageLimitKey = "storage"

// Arms the caps' next tick, CapCheckInterval from now, unless the component closed.
func (self *sidecarSession) armTickWithLock(clock Clock, settings *SessionSettings) {
	if self.closed || settings.CapCheckInterval <= 0 {
		return
	}
	self.stopTick = clock.AfterFunc(settings.CapCheckInterval, func() {
		storage := func() *SessionStorage {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.storage
		}()
		if _, err := storage.Tick(context.Background()); err != nil {
			self.sidecar.log.Warningf("[session]the history caps' check: %s", err)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.armTickWithLock(clock, settings)
	})
}
