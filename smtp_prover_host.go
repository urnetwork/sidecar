//go:build !sidecar_http && !ios_extension

// A prover host's own record, p/<sidecar_id> (§15.7, D-SMTP-18, D-SMTP-20; DESIGN-DETAILS 3.7's SMTP-M9-09): what
// SmtpProver.Measure found, so a phone's composer shows the DATA cap of the hosts that send for it and prices a send
// in units (3.2.6), and which key set the host proves under with its ready suites. MailProverRecord is its bytes
// (plan-MAIL-format-bytes#5), which SmtpMailbox's implementations encode through MailProverRecord and
// SmtpProverRecordFromMail, so a record means the same on every device.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var errInvalidSmtpProverRecord = errors.New("invalid smtp prover record")

// One prover host's record at p/<sidecar_id>.
type SmtpProverRecord struct {
	// What the host's last SmtpProver.Measure found.
	Measure SmtpProverMeasure
	// The key set the host proves under: keyset.json's SHA-256, as SmtpPreamble.proof_key_set names it.
	KeySet []byte
	// The TLS cipher suites whose family is ready in that set, in the order its client offers them.
	ReadySuites []uint16
}

// The p/ form of a record (plan-MAIL-format-bytes#5, DESIGN-DETAILS 3.7). It refuses a record no reader could take
// back: no measure time, or one before the epoch.
func (self *SmtpProverRecord) MailProverRecord() (*protocol.MailProverRecord, error) {
	measure := &self.Measure
	if measure.MeasureTime.UnixMilli() <= 0 || measure.UnitTime < 0 {
		return nil, fmt.Errorf("%w: no measure time", errInvalidSmtpProverRecord)
	}
	readySuites := make([]uint32, 0, len(self.ReadySuites))
	for _, suite := range self.ReadySuites {
		readySuites = append(readySuites, uint32(suite))
	}
	return &protocol.MailProverRecord{
		SmtpDataProofBytes:    measure.DataProofBytes,
		DataBytesPerS:         measure.DataBytesPerSecond,
		MeasureTimeMs:         uint64(measure.MeasureTime.UnixMilli()),
		UnitMillis:            uint64(measure.UnitTime.Milliseconds()),
		HeadByteCount:         measure.HeadByteCount,
		HeaderRecordByteCount: measure.HeaderRecordByteCount,
		EnvelopeGroupCount:    measure.EnvelopeGroupCount,
		KeySetId:              bytes.Clone(self.KeySet),
		ReadySuites:           readySuites,
	}, nil
}

// A record read back from p/. Another version's device may have written it, so a time no clock reaches or a suite
// past TLS's 16 bits is refused rather than read as something else.
func SmtpProverRecordFromMail(record *protocol.MailProverRecord) (*SmtpProverRecord, error) {
	if record == nil || record.GetMeasureTimeMs() == 0 || math.MaxInt64 < record.GetMeasureTimeMs() ||
		uint64(math.MaxInt64/time.Millisecond) < record.GetUnitMillis() {
		return nil, fmt.Errorf("%w: its times", errInvalidSmtpProverRecord)
	}
	readySuites := make([]uint16, 0, len(record.GetReadySuites()))
	for _, suite := range record.GetReadySuites() {
		if math.MaxUint16 < suite {
			return nil, fmt.Errorf("%w: a suite past 16 bits", errInvalidSmtpProverRecord)
		}
		readySuites = append(readySuites, uint16(suite))
	}
	return &SmtpProverRecord{
		Measure: SmtpProverMeasure{
			DataProofBytes:        record.GetSmtpDataProofBytes(),
			DataBytesPerSecond:    record.GetDataBytesPerS(),
			MeasureTime:           time.UnixMilli(int64(record.GetMeasureTimeMs())),
			UnitTime:              time.Duration(record.GetUnitMillis()) * time.Millisecond,
			HeadByteCount:         record.GetHeadByteCount(),
			HeaderRecordByteCount: record.GetHeaderRecordByteCount(),
			EnvelopeGroupCount:    record.GetEnvelopeGroupCount(),
		},
		KeySet:      bytes.Clone(record.GetKeySetId()),
		ReadySuites: slices.Clip(readySuites),
	}, nil
}

// What a prover host is made of. Prover, Mailbox and Settings must be set.
type SmtpProverHostArgs struct {
	Prover  SmtpProver
	Mailbox SmtpMailbox
	// This host, whose record is p/<sidecar_id>.
	SidecarId Id
	// Whether the member has enabled mail on this device: until then nothing is checked or fetched, since the key
	// check fetches transcripts (§2.8 smtp-7). nil is never.
	MailEnabled func() bool
	// Must have passed validate.
	Settings *SmtpSenderSettings
	Clock    Clock
	Log      Logger
}

// A prover host's idle work (DESIGN-DETAILS 3.7's SMTP-M9-09): at idle, and only once mail is enabled on this
// device, SmtpProver.PrepareKeys one shape a call until a family is ready or every family of every pinned set is
// ready or refused, and once each step after, so what moved since is seen; then
// SmtpProver.Measure when a family has become ready, when the key set changes, and each ProverMeasureInterval;
// and p/<sidecar_id> rewritten after each measure, with the key set and its ready suites. A host with no ready
// family, or whose Measure fails, only queues. Once measured, a send's HoldForSend cancels idle work and keeps it
// off until the send ends, so a send never waits on a shape check. Safe for concurrent use.
type SmtpProverHost struct {
	args     *SmtpProverHostArgs
	settings *SmtpSenderSettings
	clock    Clock
	log      Logger

	stateLock sync.Mutex
	readiness *SmtpProverReadiness
	measure   *SmtpProverMeasure
	// the key set and suites the last measure was taken under
	measuredKeySet []byte
	measuredSuites []uint16
	// sends holding the host now
	sendCount int
	// cancels the idle work running now, nil when none runs
	idleCancel context.CancelFunc
	// rises at each send's release, so Run resumes the idle work
	released chan struct{}
}

// A host over args.
func NewSmtpProverHost(args *SmtpProverHostArgs) (*SmtpProverHost, error) {
	if args == nil || args.Prover == nil || args.Mailbox == nil || args.Settings == nil {
		return nil, errors.New("smtp prover host: missing parts")
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &SmtpProverHost{args: args, settings: args.Settings, clock: clockOrReal(args.Clock), log: log, released: make(chan struct{})}, nil
}

// Holds the host for a send. A hold racing the first measurement of newly ready keys lets that measurement
// finish. Other idle work stops until release, which may be called more than once.
func (self *SmtpProverHost) HoldForSend() (release func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sendCount += 1
	awaitingMeasure := self.measure == nil && self.readiness != nil && len(self.readiness.KeySets) != 0
	if self.idleCancel != nil && !awaitingMeasure {
		self.idleCancel()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.sendCount -= 1
			if self.sendCount == 0 {
				close(self.released)
				self.released = make(chan struct{})
			}
		})
	}
}

// The last measure, a copy, nil before one.
func (self *SmtpProverHost) Measure() *SmtpProverMeasure {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.measure == nil {
		return nil
	}
	measure := *self.measure
	return &measure
}

// The ready key sets a measured host can use, newest first.
func (self *SmtpProverHost) ReadyKeySets() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keySets := [][]byte{}
	if self.measure != nil {
		for _, keySet := range self.readiness.KeySets {
			keySets = append(keySets, bytes.Clone(keySet.Id))
		}
	}
	return keySets
}

// The DATA cap this host records, 0 before a measure.
func (self *SmtpProverHost) Cap() uint64 {
	if measure := self.Measure(); measure != nil {
		return measure.DataProofBytes
	}
	return 0
}

// Starts idle work under ctx, false while a send holds the host or other idle work runs.
func (self *SmtpProverHost) startIdle(ctx context.Context) (context.Context, func(), bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.sendCount || self.idleCancel != nil {
		return nil, nil, false
	}
	idleCtx, cancel := context.WithCancel(ctx)
	self.idleCancel = cancel
	return idleCtx, func() {
		cancel()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.idleCancel = nil
	}, true
}

// Whether a measure is due under readiness: a ready family and no measure, another key set or other ready suites
// than the last measure's, or ProverMeasureInterval since it.
func (self *SmtpProverHost) measureDueWithLock(now time.Time) bool {
	if self.readiness == nil || len(self.readiness.KeySets) == 0 {
		return false
	}
	return self.measure == nil || !now.Before(self.measure.MeasureTime.Add(self.settings.ProverMeasureInterval))
}

// One idle step to its end, unless a send starts: see SmtpProverHost. An error is the prover's or the mailbox's, or
// ctx's when a send cancelled the work; the next step starts over from what is ready.
func (self *SmtpProverHost) Idle(ctx context.Context) error {
	if self.args.MailEnabled == nil || !self.args.MailEnabled() {
		return nil
	}
	idleCtx, end, ok := self.startIdle(ctx)
	if !ok {
		return nil
	}
	defer end()
	// one shape a call: on until a family is ready or every one is ready or refused, and at least once a step, so
	// readiness that moved since (a newer set ready, a cache entry lost) is seen
	for {
		readiness, err := self.args.Prover.PrepareKeys(idleCtx)
		if err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.readiness = readiness
			if len(readiness.KeySets) == 0 || !bytes.Equal(readiness.KeySets[0].Id, self.measuredKeySet) ||
				!slices.Equal(readiness.KeySets[0].ReadySuites, self.measuredSuites) {
				self.measure = nil
			}
		}()
		if readiness.Done || 0 < len(readiness.KeySets) {
			// a family is ready: measure it before checking further shapes, so the host can send meanwhile
			break
		}
	}
	due, keySet, suites := func() (bool, []byte, []uint16) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.measureDueWithLock(self.clock.Now()) {
			return false, nil, nil
		}
		newest := self.readiness.KeySets[0]
		return true, bytes.Clone(newest.Id), slices.Clone(newest.ReadySuites)
	}()
	if !due {
		return nil
	}
	measure, err := self.args.Prover.Measure(idleCtx)
	if err != nil {
		if idleCtx.Err() == nil {
			self.stateLock.Lock()
			self.measure = nil
			self.stateLock.Unlock()
		}
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.measure = measure
		self.measuredKeySet = keySet
		self.measuredSuites = suites
	}()
	return self.args.Mailbox.WriteProverRecord(idleCtx, self.args.SidecarId, &SmtpProverRecord{
		Measure: *measure, KeySet: keySet, ReadySuites: suites,
	})
}

// Runs idle steps until ctx ends: one at once, then each ProverIdleInterval and after each send. Called once, by
// the daemon's composition.
func (self *SmtpProverHost) Run(ctx context.Context) {
	for {
		if err := self.Idle(ctx); err != nil && ctx.Err() == nil && self.log.V(1).Enabled() {
			self.log.Infof("[smtp]prover host idle: %v\n", err)
		}
		released := func() chan struct{} {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.released
		}()
		select {
		case <-ctx.Done():
			return
		case <-released:
		case <-self.clock.After(self.settings.ProverIdleInterval):
		}
	}
}
