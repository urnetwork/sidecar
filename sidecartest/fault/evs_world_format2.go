// Format 2 on the evs world (EVS2-M10-30; §11.6's format row, §19.11's format2 gate, D-EVS-39, FS-72's M10 cases):
// what a world sets so a row runs format 2's mechanisms through the client and engine as built, and the steps that
// stand for evs and taskworker rolled back to format 1 and forward again.
//
//	gate        EvsWorldSettings.Format2 lists the world's network in §19.11's format2 gate, with its purge and drop
//	            modes, in the gates Setup writes; nil leaves it out, as format 1's rows run
//	instances   an instance runs at the format EvsWorldSettings.InstanceFormats names, 1 where it names none, and
//	            SetInstanceFormat sets the format of its next start, so a Kill and a Restart over the same stores
//	            stand for evs rolled back to a format-1 binary, or forward to format 2's
//	devices     a device whose settings say Format2 has the format-2 reader installed and core's gates read from the
//	            world's, so it writes format 2 while the gate admits the network; AdjustClient's MaxFormat 1 holds such
//	            a device to format 1 whatever the gate says: the format-1 client FS-72 names
//	taskworker  EvacuateAt runs one evacuation as taskworker's job does, at a format, reading the world's gate, and
//	            hands its check what the run alarmed
//	formats     FormatHolds, read after every step, holds repo/'s format to §11.6's row: it never falls, and it stands
//	            at 2 once the ledger saw a versionless write commit, since the raise precedes its push's step 7
//
// A rolled-back binary is this code at InstanceFormat 1 here, as a rollback deploys it (QD-854: a rollback is a
// configuration of a real binary, its blocks taking InstanceFormat from their config).

package fault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §19.11's format2 gate as a world's Setup writes it.
type EvsWorldFormat2Settings struct {
	// The purge's and the drops' modes as the file spells them: "observe" or "on".
	Purge string
	Drop  string
}

// Both modes observe, as §23.9's rollout opens the gate.
func DefaultEvsWorldFormat2Settings() *EvsWorldFormat2Settings {
	return &EvsWorldFormat2Settings{Purge: "observe", Drop: "observe"}
}

// The gates Setup writes: evs open to the world's network, and format2 too, in its modes as they stand, when the
// settings ask.
func (self *EvsWorld) gatesText() string {
	network := connect.Id(self.NetworkId).String()
	text := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if format2 := self.format2; format2 != nil {
		text += fmt.Sprintf("  format2: {enabled: true, networks: [%q], percent: 0, purge: %q, drop: %q}\n", network, format2.Purge, format2.Drop)
	}
	return text
}

// A step action: the format2 gate's purge and drop modes become modes', as an operator's edit of sidecar.yml reread by
// every process. The world's network must be in the gate already.
func (self *EvsWorld) SetFormat2Modes(modes *EvsWorldFormat2Settings) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		err := func() error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.format2 == nil {
				return errors.New("the world's network is not in the format2 gate")
			}
			self.format2 = &EvsWorldFormat2Settings{Purge: modes.Purge, Drop: modes.Drop}
			return nil
		}()
		if err != nil {
			return err
		}
		return net.Fakes().Gates.Set(self.gatesText())
	}
}

// The format instance's next start runs at.
func (self *EvsWorld) instanceFormat(instance string) uint32 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if format, ok := self.instanceFormats[instance]; ok {
		return format
	}
	return sidecar.EvsRepoFormat1
}

// A step action: instance's next start runs at format, which a Kill and a Restart of it put in force.
func (self *EvsWorld) SetInstanceFormat(instance string, format uint32) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if format != sidecar.EvsRepoFormat1 && format != sidecar.EvsRepoFormat2 {
			return fmt.Errorf("an instance of format %d", format)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.instanceFormats[instance] = format
		return nil
	}
}

// Whether the world's gates admit its network to format 2, read on each call as core's newest answer carries it.
func (self *EvsWorld) Format2Admitted() bool {
	return self.net.Host().GatesOrClosed().Format2().Admits(connect.Id(self.NetworkId))
}

// A device's client as a composition sets it up for format 2: core's gates as the world's say, and the format-2
// reader. Its settings' MaxFormat still holds it to format 1.
func (self *EvsWorld) enableFormat2(client *sidecar.EvsClient) {
	client.SetFormat2Source(self.Format2Admitted)
	client.EnableFormat2Reader()
}

// A step action: device writes content to path with §18.5's versioning setting ("on", "off" or "" for the path's),
// which must commit.
func (self *EvsWorld) WriteVersioning(device string, path string, content []byte, versioning string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		write, err := self.writeSetting(ctx, device, path, content, versioning)
		if err != nil {
			return err
		}
		if write.state != evsWorldWriteCommitted {
			return fmt.Errorf("%s's write of %q with versioning %q did not commit: %v", device, path, versioning, write.err)
		}
		return nil
	}
}

// A step action: device writes content to path with the versioning setting, and the write may end any way, which the
// ledger keeps.
func (self *EvsWorld) WriteVersioningAny(device string, path string, content []byte, versioning string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, err := self.writeSetting(ctx, device, path, content, versioning)
		return err
	}
}

// A step action: device's write of content to path with the versioning setting is refused as needing format 2 before
// the client posts any push, by its own verifying reader or by an evs that cannot serve a record its write must read
// (EvsWorldNeedsFormat2), and no store write is issued meanwhile; the ledger keeps the write refused, never sent.
func (self *EvsWorld) WriteNeedsFormat2(device string, path string, content []byte, versioning string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark := net.BlobHistoryCount()
		pushCount := len(self.DevicePushes(device))
		write, err := self.writeSetting(ctx, device, path, content, versioning)
		if err != nil {
			return err
		}
		if err := evsWorldNoStoreWritesSince(net, mark); err != nil {
			return fmt.Errorf("%s's write of %q, refused: %w", device, path, err)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !EvsWorldNeedsFormat2(write.err) {
			return fmt.Errorf("%s's write of %q with versioning %q ended %v, not as needing format 2", device, path, versioning, write.err)
		}
		write.state = evsWorldWriteRefused
		if posted := len(self.pushIdsOfWithLock(device)) - pushCount; posted != 0 {
			return fmt.Errorf("%s posted %d pushes for a write refused as needing format 2", device, posted)
		}
		return nil
	}
}

// A step action: device's write of content to path with the versioning setting gets 503 with a Retry-After from every
// instance it reaches, refusing nothing, and no store write is issued meanwhile: a format-1 evs meeting a format-2
// repo/ before step 4 (plan-EVS1-format-unsupported#4). The ledger keeps the write's outcome unknown, as a 503 leaves
// it.
func (self *EvsWorld) WriteUnavailable(device string, path string, content []byte, versioning string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark := net.BlobHistoryCount()
		pushCount := len(self.DevicePushes(device))
		write, err := self.writeSetting(ctx, device, path, content, versioning)
		if err != nil {
			return err
		}
		evsError, ok := sidecar.EvsErrorOf(write.err)
		if !ok || evsError.Status != http.StatusServiceUnavailable || evsError.OutcomeUnknown || evsError.RetryAfter <= 0 {
			return fmt.Errorf("%s's write of %q ended %v, not 503 with a Retry-After", device, path, write.err)
		}
		if len(self.DevicePushes(device)) == pushCount {
			return fmt.Errorf("%s's write of %q posted no push", device, path)
		}
		if err := evsWorldNoStoreWritesSince(net, mark); err != nil {
			return fmt.Errorf("%s's write of %q, refused: %w", device, path, err)
		}
		return nil
	}
}

// No PUT and no DELETE in the Net's store history since mark.
func evsWorldNoStoreWritesSince(net *Net, mark int) error {
	history := net.BlobHistory()
	for _, entry := range history[min(mark, len(history)):] {
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream, sidecartest.BlobHistoryDelete:
			return fmt.Errorf("%s issued %s %s", entry.Actor, entry.Op, entry.Key)
		}
	}
	return nil
}

// The push ids device posted, with the world's lock held.
func (self *EvsWorld) pushIdsOfWithLock(device string) []sidecar.Id {
	pushIds := []sidecar.Id{}
	for _, pushId := range self.pushIdList {
		if push := self.pushes[pushId]; push != nil && push.Device == device {
			pushIds = append(pushIds, pushId)
		}
	}
	return pushIds
}

// A step action: device reads each path from the cluster's head and is refused it as needing format 2, by its own
// verifying reader or by an evs that cannot serve the record, raising no alarm (which Checks' NoAlarms reads): §11.6's
// format row, a reader below format 2 refusing a migrated repo's format-2 values and reading every other file.
func (self *EvsWorld) VerifyNeedsFormat2(device string, paths ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		for _, path := range paths {
			_, err := self.Device(device).Repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, io.Discard)
			if !EvsWorldNeedsFormat2(err) {
				return fmt.Errorf("%s's read of %q ended %v, not as needing format 2", device, path, err)
			}
		}
		return nil
	}
}

// Whether err refuses as needing format 2: the client's own ErrEvsFormatUnsupported, or evs's 409 FORMAT_UNSUPPORTED
// {needs_format: 2}.
func EvsWorldNeedsFormat2(err error) bool {
	if evsError, ok := sidecar.EvsErrorOf(err); ok {
		return evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED && evsError.NeedsFormat == sidecar.EvsRepoFormat2
	}
	return errors.Is(err, sidecar.ErrEvsFormatUnsupported)
}

// A step action: repo/ stands at format (RepoObject, evs_world_lifecycle.go).
func (self *EvsWorld) ExpectRepoFormat(format uint32) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		repo, err := self.RepoObject(ctx)
		if err != nil {
			return err
		}
		if repo.GetFormat() != format {
			return fmt.Errorf("repo/ stands at format %d, not %d", repo.GetFormat(), format)
		}
		return nil
	}
}

// See the file header. Each call is a check of its own, holding the highest format it saw.
func (self *EvsWorld) FormatHolds() Invariant {
	highest := uint32(0)
	return NewInvariant("FS-72/format", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		setUp := self.setUp && !self.settings.Unplaced
		versionless := ""
		for path, writes := range self.pathWrites {
			for _, write := range writes {
				if write.versioning == sidecar.EvsVersioningOff && write.state == evsWorldWriteCommitted {
					versionless = path
				}
			}
		}
		self.stateLock.Unlock()
		if !setUp {
			return nil
		}
		repo, err := self.RepoObject(ctx)
		if err != nil {
			return fmt.Errorf("repo/: %w", err)
		}
		format := repo.GetFormat()
		if format < highest {
			return fmt.Errorf("repo/ fell from format %d to %d", highest, format)
		}
		highest = format
		if versionless != "" && format < sidecar.EvsRepoFormat2 {
			return fmt.Errorf("a versionless write of %q committed while repo/ stands at format %d", versionless, format)
		}
		return nil
	})
}

// Where a schedule marks the Net's store history, to check what was issued after it (NoSegmentDeletesSince).
type EvsWorldStoreMark struct {
	stateLock sync.Mutex
	index     int
	set       bool
}

// A step action: mark notes how many store requests the Net's history holds now.
func (self *EvsWorld) MarkStore(mark *EvsWorldStoreMark) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		defer mark.stateLock.Unlock()
		mark.index = net.BlobHistoryCount()
		mark.set = true
		return nil
	}
}

// A step action: no DELETE of a segment, seg/ on any cluster, was issued since mark: a purge deleted nothing.
func (self *EvsWorld) NoSegmentDeletesSince(mark *EvsWorldStoreMark) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		index, set := mark.index, mark.set
		mark.stateLock.Unlock()
		if !set {
			return errors.New("no store mark was set")
		}
		history := net.BlobHistory()
		for _, entry := range history[min(index, len(history)):] {
			if entry.Op == sidecartest.BlobHistoryDelete && strings.HasPrefix(entry.Key, "seg/") {
				return fmt.Errorf("%s deleted %s on %s", entry.Actor, entry.Key, entry.ClusterId)
			}
		}
		return nil
	}
}

// What one EvacuateAt run alarmed, each line as the evacuator logged it.
type evsWorldAlarmLog struct {
	stateLock sync.Mutex
	lines     []string
}

// Keeps line when it is an alarm's.
func (self *evsWorldAlarmLog) add(line string) {
	if !strings.Contains(line, "alarm") {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

// sidecar.Logger's.
func (self *evsWorldAlarmLog) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

// sidecar.Logger's.
func (self *evsWorldAlarmLog) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

// sidecar.Logger's.
func (self *evsWorldAlarmLog) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

// sidecar.Logger's: where the evacuator's alarms go.
func (self *evsWorldAlarmLog) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

// sidecar.Logger's, keeping nothing verbose.
func (self *evsWorldAlarmLog) V(level int32) sidecar.Verbose {
	return sidecar.NewNoopLogger().V(level)
}

// The alarm lines kept so far.
func (self *evsWorldAlarmLog) alarms() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

// taskworker's usage batches as an evacuation reports staged content to them: counted, never refused.
type evsWorldStoredDeltas struct {
	stateLock sync.Mutex
	count     int
}

// evsservice.StoredDeltaSink's.
func (self *evsWorldStoredDeltas) AddStoredDelta(networkId connect.Id, byteDelta int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.count += 1
	return nil
}

// Whether any alarm line names alarm.
func EvsWorldAlarmsName(alarms []string, alarm string) bool {
	return slices.ContainsFunc(alarms, func(line string) bool { return strings.Contains(line, "alarm "+alarm+":") })
}

// A step action: one hourly evacuation run on the repo's cluster as taskworker's job runs it at format (taskworker
// rolled back to a format-1 binary, or forward to format 2's), reading the world's format2 gate, its spool in the
// system's temporary directory, which the run removes; check gets the run's result and every alarm it raised. A run
// a store error ends runs once more, as Evacuate's does, and check reads that run alone.
func (self *EvsWorld) EvacuateAt(format uint32, check func(result *evsservice.EvacuationResult, alarms []string) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		run := func() (*evsservice.EvacuationResult, []string, error) {
			evsSettings := evsservice.DefaultEvsSettings()
			evsSettings.InstanceFormat = format
			log := &evsWorldAlarmLog{}
			evacuator, err := evsservice.NewEvacuator(net.Host(), &evsservice.EvacuatorDeps{
				Settings: evsservice.DefaultEvacuatorSettings(), EvsSettings: evsSettings, Log: log,
				Format2: evsservice.NewFormat2Gate(net.Host()), Usage: &evsWorldStoredDeltas{},
			})
			if err != nil {
				return nil, nil, err
			}
			result, err := evacuator.Run(ctx, first.ClusterId())
			return result, log.alarms(), err
		}
		result, alarms, err := run()
		if err != nil {
			if result, alarms, err = run(); err != nil {
				return err
			}
		}
		if check == nil {
			return nil
		}
		if err := check(result, alarms); err != nil {
			return fmt.Errorf("an evacuation at format %d: %w", format, err)
		}
		return nil
	}
}
