//go:build !sidecar_http

// T2's sidecar.SmtpMailbox: a member's o/, or/ and p/ in memory, until MAIL-M9-02's mailSmtpMailbox.
// or/ and p/ are held in their wire forms, MailOutcomeRecord and MailProverRecord (§15.7,
// plan-MAIL-format-bytes#5), so what a sender writes is refused or read back exactly as a mailbox on
// those formats would. PutOutbox stands in for MAIL's write of o/, which the seam has no method for.
// Calls go through hostCall, so a plan under FaultOpHost with the key "smtpmailbox.<Method>" reaches
// them, and each is counted. RunSmtpMailboxSuite holds this fake and the real mailbox to the same
// promises. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var _ sidecar.SmtpMailbox = (*FakeSmtpMailbox)(nil)

var (
	errFakeSmtpMailboxEmptyDsn  = errors.New("a dsn with no bytes")
	errFakeSmtpMailboxNoMeasure = errors.New("a prover measure needs a time after the epoch")
)

// One DepositDsn, as the fake kept it.
type FakeSmtpDsn struct {
	EffectKey []byte
	Dsn       []byte
}

// A member's mailbox, in memory.
type FakeSmtpMailbox struct {
	faults *FaultQueue

	stateLock sync.Mutex
	// by string(effect key)
	outbox map[string]*sidecar.SmtpOutboxFile
	// by string(effect key): MailOutcomeRecord's bytes
	outcomes map[string][]byte
	// MailProverRecord's bytes
	proverRecords map[sidecar.Id][]byte
	dsns          []*FakeSmtpDsn
	opCounts      map[string]int
}

// A nil faults takes a fresh queue.
func NewFakeSmtpMailbox(faults *FaultQueue) *FakeSmtpMailbox {
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeSmtpMailbox{
		faults:        faults,
		outbox:        map[string]*sidecar.SmtpOutboxFile{},
		outcomes:      map[string][]byte{},
		proverRecords: map[sidecar.Id][]byte{},
		opCounts:      map[string]int{},
	}
}

// One call through the fault queue and the count, serve running under the lock.
func (self *FakeSmtpMailbox) call(ctx context.Context, method string, serve func() error) error {
	return hostCall(ctx, self.faults, "smtpmailbox."+method, func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts["smtpmailbox."+method] += 1
		return serve()
	})
}

// How many times method ran, by its seam name, such as "WriteOutcomes".
func (self *FakeSmtpMailbox) OpCount(method string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.opCounts["smtpmailbox."+method]
}

func copySmtpOutboxFile(file *sidecar.SmtpOutboxFile) *sidecar.SmtpOutboxFile {
	return &sidecar.SmtpOutboxFile{
		EffectKey: bytes.Clone(file.EffectKey),
		Signed:    bytes.Clone(file.Signed),
		Message:   bytes.Clone(file.Message),
	}
}

// MAIL's write of o/<h>/<effect_key> (§15.10's step 4), created only if absent: false when an entry
// already holds the key, which keeps its first bytes.
func (self *FakeSmtpMailbox) PutOutbox(effectKey []byte, signed []byte, message []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.outbox[string(effectKey)]; ok {
		return false
	}
	self.outbox[string(effectKey)] = copySmtpOutboxFile(&sidecar.SmtpOutboxFile{EffectKey: effectKey, Signed: signed, Message: message})
	return true
}

// Every DSN deposited, in order.
func (self *FakeSmtpMailbox) Dsns() []*FakeSmtpDsn {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dsns := make([]*FakeSmtpDsn, 0, len(self.dsns))
	for _, dsn := range self.dsns {
		dsns = append(dsns, &FakeSmtpDsn{EffectKey: bytes.Clone(dsn.EffectKey), Dsn: bytes.Clone(dsn.Dsn)})
	}
	return dsns
}

// See sidecar.SmtpMailbox. Keys come back sorted, which the seam does not promise.
func (self *FakeSmtpMailbox) ListOutbox(ctx context.Context) ([][]byte, error) {
	var effectKeys [][]byte
	err := self.call(ctx, "ListOutbox", func() error {
		for _, key := range slices.Sorted(maps.Keys(self.outbox)) {
			effectKeys = append(effectKeys, []byte(key))
		}
		return nil
	})
	return effectKeys, err
}

func (self *FakeSmtpMailbox) ReadOutbox(ctx context.Context, effectKey []byte) (*sidecar.SmtpOutboxFile, error) {
	var file *sidecar.SmtpOutboxFile
	err := self.call(ctx, "ReadOutbox", func() error {
		kept, ok := self.outbox[string(effectKey)]
		if !ok {
			return sidecar.ErrSmtpMailboxNotFound
		}
		file = copySmtpOutboxFile(kept)
		return nil
	})
	return file, err
}

func (self *FakeSmtpMailbox) RemoveOutbox(ctx context.Context, effectKey []byte) error {
	return self.call(ctx, "RemoveOutbox", func() error {
		delete(self.outbox, string(effectKey))
		return nil
	})
}

// Encodes as or/ holds them, refusing what the wire form refuses.
func (self *FakeSmtpMailbox) WriteOutcomes(ctx context.Context, effectKey []byte, outcomes []*sidecar.SmtpDomainOutcome) error {
	record := &protocol.MailOutcomeRecord{}
	for _, outcome := range outcomes {
		mailOutcome, err := outcome.MailOutcome()
		if err != nil {
			return err
		}
		record.Outcomes = append(record.Outcomes, mailOutcome)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return err
	}
	return self.call(ctx, "WriteOutcomes", func() error {
		self.outcomes[string(effectKey)] = encoded
		return nil
	})
}

func (self *FakeSmtpMailbox) ListOutcomes(ctx context.Context) ([][]byte, error) {
	var effectKeys [][]byte
	err := self.call(ctx, "ListOutcomes", func() error {
		for _, key := range slices.Sorted(maps.Keys(self.outcomes)) {
			effectKeys = append(effectKeys, []byte(key))
		}
		return nil
	})
	return effectKeys, err
}

func (self *FakeSmtpMailbox) ReadOutcomes(ctx context.Context, effectKey []byte) ([]*sidecar.SmtpDomainOutcome, error) {
	var encoded []byte
	err := self.call(ctx, "ReadOutcomes", func() error {
		kept, ok := self.outcomes[string(effectKey)]
		if !ok {
			return sidecar.ErrSmtpMailboxNotFound
		}
		encoded = kept
		return nil
	})
	if err != nil {
		return nil, err
	}
	record := &protocol.MailOutcomeRecord{}
	if err := proto.Unmarshal(encoded, record); err != nil {
		return nil, err
	}
	outcomes := make([]*sidecar.SmtpDomainOutcome, 0, len(record.GetOutcomes()))
	for _, mailOutcome := range record.GetOutcomes() {
		outcome, err := sidecar.SmtpDomainOutcomeFromMailOutcome(mailOutcome)
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// Encodes as p/ holds it.
func (self *FakeSmtpMailbox) WriteProverMeasure(ctx context.Context, sidecarId sidecar.Id, measure *sidecar.SmtpProverMeasure) error {
	if measure == nil || measure.MeasureTime.UnixMilli() < 0 {
		return errFakeSmtpMailboxNoMeasure
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailProverRecord{
		SmtpDataProofBytes: measure.DataProofBytes,
		DataBytesPerS:      measure.DataBytesPerSecond,
		MeasureTimeMs:      uint64(measure.MeasureTime.UnixMilli()),
	})
	if err != nil {
		return err
	}
	return self.call(ctx, "WriteProverMeasure", func() error {
		self.proverRecords[sidecarId] = encoded
		return nil
	})
}

func (self *FakeSmtpMailbox) ListProverMeasures(ctx context.Context) (map[sidecar.Id]*sidecar.SmtpProverMeasure, error) {
	encodedRecords := map[sidecar.Id][]byte{}
	err := self.call(ctx, "ListProverMeasures", func() error {
		maps.Copy(encodedRecords, self.proverRecords)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sidecarIdMeasures := map[sidecar.Id]*sidecar.SmtpProverMeasure{}
	for sidecarId, encoded := range encodedRecords {
		record := &protocol.MailProverRecord{}
		if err := proto.Unmarshal(encoded, record); err != nil {
			return nil, err
		}
		sidecarIdMeasures[sidecarId] = &sidecar.SmtpProverMeasure{
			DataProofBytes:     record.GetSmtpDataProofBytes(),
			DataBytesPerSecond: record.GetDataBytesPerS(),
			MeasureTime:        time.UnixMilli(int64(record.GetMeasureTimeMs())),
		}
	}
	return sidecarIdMeasures, nil
}

func (self *FakeSmtpMailbox) DepositDsn(ctx context.Context, effectKey []byte, dsn []byte) error {
	if len(dsn) == 0 {
		return errFakeSmtpMailboxEmptyDsn
	}
	return self.call(ctx, "DepositDsn", func() error {
		self.dsns = append(self.dsns, &FakeSmtpDsn{EffectKey: bytes.Clone(effectKey), Dsn: bytes.Clone(dsn)})
		return nil
	})
}
