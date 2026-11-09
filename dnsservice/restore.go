// §12.6's restore step, §19.10's dns step (D-DNS-10, D-OPS-14, FS-42, FI-12, I-14; DNS-M5-15). After a
// Postgres loss the dumps come back at their age with an empty journal while ns1 and ns2 serve newer
// zones. The step lands the root's serial above every serial the lost primary issued, waits for each
// running NS to serve it, lists what changed, and clears restoring, needing neither api nor the token
// exchange. It runs after §21.10's abuse step, so the snapshot the edges reload withholds what mail
// says to suspend, and before api's replay, so revocations' DKIM and TLSA deletions commit above
// restore_serial as ordinary writes.
//
// In order, each idempotent by incident id, so a crash after any of them reruns to the same result:
//
//  1. SetRestoring(on), the runbook's `dns restoring on`, runs as the dumps load: from then every dns
//     write answers 503 and takes no serial, and only §12.9's hooks touch rows.
//  2. Run reads each NS's SOA over TCP; one that does not answer is stopped (dns_ns), and serves again
//     only from a reload, its local snapshot taken as the replaced one.
//  3. One transaction: serial := restore_serial := max(restored serial, the SOAs read, {dns}serial)
//     + 2^24, recording the incident and raising the key. An SOA holds a serial's low 32 bits, which
//     are lifted to the serial they stand for beside the restored one by RFC 1982, so an NS ahead of
//     the dump counts in full.
//  4. Each edge reloads at restore_serial at its next poll and posts its diff. The step waits until
//     every running NS answers that SOA, a stopped one that does being started again, then up to
//     restore.diff_wait_s for a diff from each.
//  5. Every RRset in a diff posted at or above restore_serial, but challenges' and canaries', is listed
//     by network, owner and type in the incident and each network's admin events, a network with an
//     open §21 case flagged (DnsRestoreStore).
//  6. restoring := false, so later dns writes commit above restore_serial.
//
// A rerun after the step has ended lists what diffs came since, an NS that reloaded late among them.
// The custom-host map's half of §19.10's step, its version raised 2^24 above the restored one, is
// DNS-M6-07's. Barriers mark each step's start and end, keyed by the incident.

package dnsservice

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// The NS's running or stopped state cannot be kept, since dns_ns does not exist yet: the step keeps
// counting the NS, plan-DNS-running-ns's interim and the closed direction.
var ErrDnsNsStateUnavailable = errors.New("dns ns state unavailable")

// The reason the step stops an NS with: it did not answer the SOA read.
const DnsNsStoppedNoSoa = "restore_no_soa"

// One RRset a restore listed (§12.6): by network, owner and type.
type DnsRestoreEntry struct {
	// nil for <root>'s own records and a name no dns_label row holds.
	NetworkId *sidecar.Id
	Owner     string
	Type      uint16
	// Its network had an open §21 case as it was listed (§21.10's check).
	Flagged bool
	// When the abuse role cleared the flag; nil while it stands, or with none.
	FlagClearTime *time.Time
	ListTime      time.Time
}

// An incident's whole list.
type DnsRestoreListing struct {
	Root       string
	IncidentId sidecar.Id
	Entries    []DnsRestoreEntry
}

// What the restore step reads and writes beyond DnsStore: dns_ns (plan-DNS-running-ns) and the incident's
// lists. dnshost.RestoreStore implements it on Postgres. Safe for concurrent use; none may be called
// with a state lock held.
type DnsRestoreStore interface {
	// The NS dns.yml lists that dns_ns marks stopped for root.
	StoppedNs(ctx context.Context, root string) ([]string, error)
	// Marks ns stopped for reason. ErrDnsNsStateUnavailable where no state can be kept, when the step
	// keeps counting ns.
	StopNs(ctx context.Context, root string, ns string, reason string) error
	// Marks ns running again, once it serves at or above restore_serial.
	StartNs(ctx context.Context, root string, ns string) error
	// Lists keys under incidentId in one transaction: each not yet listed under it, mapped to its network
	// through dns_label, its network flagged for an open §21 case, and one admin event for each network
	// the incident lists first. Returns the incident's whole list.
	ListRestoreChanges(ctx context.Context, root string, incidentId sidecar.Id, keys []DnsRecordKey) (*DnsRestoreListing, error)
}

// What the step takes.
type RestoreStepDeps struct {
	// §12.14's tables: restoring, the restore transaction and the posted diffs. Required.
	Store DnsStore
	// dns_ns and the lists. Required.
	Restore DnsRestoreStore
	// Each NS's SOA over TCP. nil reads every NS as not answering, so nothing is ever served at the
	// restore serial and the step waits.
	SoaReader DnsSoaReader
	// nil is the wall clock.
	Clock sidecar.Clock
	// Each step and its findings. nil discards.
	Log sidecar.Logger
}

// Where a run of the step stands, for the runbook and OPS's frame to show.
type DnsRestoreProgress struct {
	Root       string
	IncidentId sidecar.Id
	// Zero until the restore transaction has run.
	RestoreSerial uint64
	// The NS dns_ns holds stopped, by dns.yml label.
	StoppedNs []string
	// The NS that could not be marked stopped, so the step counts them though they did not answer.
	CountedNs []string
	// Running NS not yet answering restore_serial when the run returned.
	WaitingNs []string
	// The diffs posted at or above restore_serial.
	DiffCount int
	// The incident's whole list, nil until it is made.
	Listing *DnsRestoreListing
	// restoring is clear: the step has ended for this incident.
	Done bool
}

// §19.10's dns step for one deployment's dns.yml. Safe for concurrent use, though one incident is one
// run at a time.
type RestoreStep struct {
	settings *DnsSettings
	deps     *RestoreStepDeps
	clock    sidecar.Clock
	log      sidecar.Logger
}

func NewRestoreStep(settings *DnsSettings, deps *RestoreStepDeps) (*RestoreStep, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil || deps.Store == nil || deps.Restore == nil {
		return nil, errors.New("dns restore needs a store and a restore store")
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := deps.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &RestoreStep{settings: settings, deps: deps, clock: clock, log: log}, nil
}

// The root as dns.yml serves it, or an error.
func (self *RestoreStep) servedRoot(root string) (string, error) {
	root = dns.CanonicalName(root)
	if !slices.Contains(self.settings.Roots, root) {
		return "", fmt.Errorf("%w: %s", ErrDnsRootUnknown, root)
	}
	return root, nil
}

// The runbook's `dns restoring on|off` (§19.10): on as the dumps load, before any block reads them.
// Off by hand only to abandon a restore; Run clears it itself at its end.
func (self *RestoreStep) SetRestoring(ctx context.Context, root string, restoring bool) error {
	root, err := self.servedRoot(root)
	if err != nil {
		return err
	}
	if err := self.deps.Store.EnsureRoot(ctx, root); err != nil {
		return err
	}
	return self.deps.Store.SetRestoring(ctx, root, restoring)
}

// One NS's SOA as read: its serial, or that it did not answer.
type dnsRestoreSoa struct {
	serial uint32
	ok     bool
}

// Every NS's SOA for root at once, each bounded by api.soa_read_timeout_s.
func (self *RestoreStep) readSoas(ctx context.Context, root string) map[string]dnsRestoreSoa {
	soas := map[string]dnsRestoreSoa{}
	var soasLock sync.Mutex
	var group sync.WaitGroup
	for _, ns := range self.settings.Ns {
		group.Add(1)
		go func() {
			defer group.Done()
			soa := dnsRestoreSoa{}
			if self.deps.SoaReader != nil {
				readCtx, cancel := context.WithCancel(ctx)
				stop := self.clock.AfterFunc(dnsSeconds(self.settings.Api.SoaReadTimeoutSeconds), cancel)
				serial, err := self.deps.SoaReader.ReadSoa(readCtx, root, ns)
				stop()
				cancel()
				soa = dnsRestoreSoa{serial: serial, ok: err == nil}
			}
			soasLock.Lock()
			defer soasLock.Unlock()
			soas[ns] = soa
		}()
	}
	group.Wait()
	return soas
}

// The serial an SOA's 32 bits stand for beside base, by RFC 1982: the nearer of the two ways around.
func dnsSoaSerialNear(base uint64, soaSerial uint32) uint64 {
	difference := int64(int32(soaSerial - uint32(base)))
	if difference < 0 && uint64(-difference) > base {
		return 0
	}
	return uint64(int64(base) + difference)
}

// Runs the step for incidentId on root (see the file header), from wherever an earlier run left it.
// Returns once restoring is clear, or with ctx's error and where the run stood when ctx ended, for a
// rerun to go on from. ErrDnsNotRestoring when restoring is clear and another incident, or none, ran
// the restore transaction; ErrDnsRestoreIncident when another incident's transaction ran in this
// restoring.
func (self *RestoreStep) Run(ctx context.Context, root string, incidentId sidecar.Id) (*DnsRestoreProgress, error) {
	root, err := self.servedRoot(root)
	if err != nil {
		return nil, err
	}
	key := incidentId.String()
	progress := &DnsRestoreProgress{Root: root, IncidentId: incidentId}
	state, err := self.deps.Store.RootState(ctx, root)
	if err != nil {
		return nil, err
	}
	switch {
	case !state.Restoring && (state.RestoreIncidentId == nil || *state.RestoreIncidentId != incidentId):
		return nil, fmt.Errorf("%w: %s", ErrDnsNotRestoring, root)
	case state.Restoring && state.RestoreIncidentId != nil && *state.RestoreIncidentId != incidentId:
		return nil, fmt.Errorf("%w: %s", ErrDnsRestoreIncident, root)
	}
	progress.RestoreSerial = state.RestoreSerial
	if state.Restoring && state.RestoreIncidentId == nil {
		// steps 2 and 3: the SOAs, then the transaction
		testHookBarrier("dnsservice.restore_soa_read.before", key)
		soas := self.readSoas(ctx, root)
		observedSerial := uint64(0)
		for _, ns := range self.settings.Ns {
			soa := soas[ns]
			if soa.ok {
				observedSerial = max(observedSerial, dnsSoaSerialNear(state.Serial, soa.serial))
				continue
			}
			err := self.deps.Restore.StopNs(ctx, root, ns, DnsNsStoppedNoSoa)
			switch {
			case errors.Is(err, ErrDnsNsStateUnavailable):
				progress.CountedNs = append(progress.CountedNs, ns)
				self.log.Warningf("[dns]restore: %s did not answer its SOA and cannot be marked stopped, so restoring waits for it", ns)
			case err != nil:
				return progress, err
			default:
				self.log.Warningf("[dns]restore: %s did not answer its SOA and is stopped until it serves the restore serial", ns)
			}
		}
		testHookBarrier("dnsservice.restore_soa_read.after", key)
		if err := ctx.Err(); err != nil {
			return progress, err
		}
		testHookBarrier("dnsservice.restore_commit.before", key)
		restoreSerial, err := self.deps.Store.CommitRestore(ctx, root, incidentId, observedSerial)
		if err != nil {
			return progress, err
		}
		testHookBarrier("dnsservice.restore_commit.after", key)
		progress.RestoreSerial = restoreSerial
		self.log.Infof("[dns]restore: %s lands at serial %d", root, restoreSerial)
	}
	// step 4: every running NS serving restore_serial, then the diffs
	running, err := self.awaitServed(ctx, root, progress)
	if err != nil {
		return progress, err
	}
	testHookBarrier("dnsservice.restore_served", key)
	diffs, err := self.awaitDiffs(ctx, root, len(running), progress)
	if err != nil {
		return progress, err
	}
	// step 5: the lists
	testHookBarrier("dnsservice.restore_list.before", key)
	listing, err := self.deps.Restore.ListRestoreChanges(ctx, root, incidentId, dnsRestoreKeys(diffs))
	if err != nil {
		return progress, err
	}
	progress.Listing = listing
	testHookBarrier("dnsservice.restore_list.after", key)
	// step 6
	if state.Restoring {
		testHookBarrier("dnsservice.restore_clear.before", key)
		if err := self.deps.Store.SetRestoring(ctx, root, false); err != nil {
			return progress, err
		}
		testHookBarrier("dnsservice.restore_clear.after", key)
		self.log.Infof("[dns]restore: %s writes again above serial %d; %d RRsets listed", root, progress.RestoreSerial, len(listing.Entries))
	}
	progress.Done = true
	return progress, nil
}

// Waits until every running NS answers an SOA at or above progress's restore serial, starting a
// stopped one that does. Returns the running NS.
func (self *RestoreStep) awaitServed(ctx context.Context, root string, progress *DnsRestoreProgress) ([]string, error) {
	for {
		soas := self.readSoas(ctx, root)
		stoppedNs, err := self.deps.Restore.StoppedNs(ctx, root)
		if err != nil {
			return nil, err
		}
		serving := func(ns string) bool {
			soa := soas[ns]
			return soa.ok && dnsSoaAtOrAbove(soa.serial, progress.RestoreSerial)
		}
		stillStopped := []string{}
		for _, ns := range stoppedNs {
			if !slices.Contains(self.settings.Ns, ns) {
				continue
			}
			if serving(ns) {
				if err := self.deps.Restore.StartNs(ctx, root, ns); err != nil {
					return nil, err
				}
				self.log.Infof("[dns]restore: %s serves the restore serial and runs again", ns)
				continue
			}
			stillStopped = append(stillStopped, ns)
		}
		progress.StoppedNs = stillStopped
		running := slices.DeleteFunc(slices.Clone(self.settings.Ns), func(ns string) bool { return slices.Contains(stillStopped, ns) })
		progress.WaitingNs = slices.DeleteFunc(slices.Clone(running), serving)
		if len(progress.WaitingNs) == 0 {
			return running, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.clock.After(dnsSeconds(self.settings.Restore.PollSeconds)):
		}
	}
}

// Waits up to restore.diff_wait_s for a diff from each running NS, and returns the diffs posted at or
// above progress's restore serial: those of this restore's reloads, since an earlier restore's are
// below it.
func (self *RestoreStep) awaitDiffs(ctx context.Context, root string, runningCount int, progress *DnsRestoreProgress) ([]*DnsReloadDiff, error) {
	waitEnded := self.clock.After(dnsSeconds(self.settings.Restore.DiffWaitSeconds))
	for {
		diffs, err := self.deps.Store.ReloadDiffs(ctx, root)
		if err != nil {
			return nil, err
		}
		diffs = slices.DeleteFunc(diffs, func(diff *DnsReloadDiff) bool { return diff.Serial < progress.RestoreSerial })
		progress.DiffCount = len(diffs)
		if runningCount <= len(diffs) {
			return diffs, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waitEnded:
			self.log.Warningf("[dns]restore: %d diffs from %d running NS; a rerun lists any that come later", len(diffs), runningCount)
			return diffs, nil
		case <-self.clock.After(dnsSeconds(self.settings.Restore.PollSeconds)):
		}
	}
}

// Every RRset the diffs name, once, but challenges' and canaries', in owner then type order. A diff
// with no kinds, from an edge that sends none, lists all its RRsets.
func dnsRestoreKeys(diffs []*DnsReloadDiff) []DnsRecordKey {
	keys := []DnsRecordKey{}
	seen := map[DnsRecordKey]bool{}
	for _, diff := range diffs {
		for index, key := range diff.Rrsets {
			if len(diff.Kinds) == len(diff.Rrsets) {
				if kind := diff.Kinds[index]; kind == DnsRecordKindChallenge || kind == DnsRecordKindCanary {
					continue
				}
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a DnsRecordKey, b DnsRecordKey) int {
		return cmp.Or(cmp.Compare(a.Owner, b.Owner), cmp.Compare(a.Type, b.Type))
	})
	return keys
}
