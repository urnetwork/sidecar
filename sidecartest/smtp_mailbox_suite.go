//go:build !sidecar_http

// The conformance suite for sidecar.SmtpMailbox (smtp_mailbox.go): what the seam promises, run on
// FakeSmtpMailbox here and on MAIL's mailSmtpMailbox (MAIL-M9-02), so the fake stays honest
// (D-TEST-2). Every case draws effect keys and sidecar ids of its own, so one mailbox serves the whole
// run, and lists are read for what a case put there, never for their length.
//
// The seam has no write for o/, which MAIL makes at §15.10's step 4, so the caller passes its own:
// FakeSmtpMailbox.PutOutbox here, MailOutbox.Queue's path for the real one.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Puts one o/ entry as MAIL would, created only if absent.
type SmtpMailboxPlantOutbox func(ctx context.Context, effectKey []byte, signed []byte, message []byte) error

type smtpMailboxSuiteCase struct {
	name string
	run  func(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error
}

// Runs every case on mailbox. A failure in one does not stop the next.
func RunSmtpMailboxSuite(t *testing.T, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) {
	t.Helper()
	for _, suiteCase := range smtpMailboxSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), smtpSuiteCaseTimeout)
			defer cancel()
			if err := suiteCase.run(ctx, mailbox, plant); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func smtpMailboxSuiteCases() []smtpMailboxSuiteCase {
	return []smtpMailboxSuiteCase{
		{name: "an o/ entry lists and reads back whole", run: caseSmtpMailboxOutboxReadsBack},
		{name: "a missing o/ entry is not found", run: caseSmtpMailboxOutboxNotFound},
		{name: "a removed o/ entry is gone, and removing it again is no error", run: caseSmtpMailboxOutboxRemove},
		{name: "outcomes read back as written, and a write replaces them", run: caseSmtpMailboxOutcomesReplace},
		{name: "a missing or/ record is not found", run: caseSmtpMailboxOutcomesNotFound},
		{name: "an outcome the wire cannot carry is refused and changes nothing", run: caseSmtpMailboxOutcomesRefused},
		{name: "a prover measure lists by its sidecar and a rewrite replaces it", run: caseSmtpMailboxProverMeasure},
		{name: "a dsn is taken, and one with no bytes is refused", run: caseSmtpMailboxDsn},
	}
}

// 32 random octets, as D-MCP-11's keys are.
func smtpMailboxSuiteEffectKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func smtpMailboxSuiteContains(keys [][]byte, key []byte) bool {
	return slices.ContainsFunc(keys, func(listed []byte) bool { return bytes.Equal(listed, key) })
}

func caseSmtpMailboxOutboxReadsBack(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	effectKey := smtpMailboxSuiteEffectKey()
	signed := []byte("signed bytes")
	message := []byte("From: a@n1.root.example\r\n\r\nbody\r\n")
	if err := plant(ctx, effectKey, signed, message); err != nil {
		return err
	}
	listed, err := mailbox.ListOutbox(ctx)
	if err != nil {
		return err
	}
	if !smtpMailboxSuiteContains(listed, effectKey) {
		return errors.New("the entry is not listed")
	}
	file, err := mailbox.ReadOutbox(ctx, effectKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(file.EffectKey, effectKey) || !bytes.Equal(file.Signed, signed) || !bytes.Equal(file.Message, message) {
		return fmt.Errorf("read back %+v", file)
	}
	return nil
}

func caseSmtpMailboxOutboxNotFound(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	if _, err := mailbox.ReadOutbox(ctx, smtpMailboxSuiteEffectKey()); !errors.Is(err, sidecar.ErrSmtpMailboxNotFound) {
		return fmt.Errorf("read a missing entry: %v", err)
	}
	return nil
}

func caseSmtpMailboxOutboxRemove(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	effectKey := smtpMailboxSuiteEffectKey()
	other := smtpMailboxSuiteEffectKey()
	for _, key := range [][]byte{effectKey, other} {
		if err := plant(ctx, key, []byte("signed"), []byte("message")); err != nil {
			return err
		}
	}
	if err := mailbox.RemoveOutbox(ctx, effectKey); err != nil {
		return err
	}
	if _, err := mailbox.ReadOutbox(ctx, effectKey); !errors.Is(err, sidecar.ErrSmtpMailboxNotFound) {
		return fmt.Errorf("read a removed entry: %v", err)
	}
	listed, err := mailbox.ListOutbox(ctx)
	if err != nil {
		return err
	}
	if smtpMailboxSuiteContains(listed, effectKey) || !smtpMailboxSuiteContains(listed, other) {
		return errors.New("the removal reached the wrong entry")
	}
	if err := mailbox.RemoveOutbox(ctx, effectKey); err != nil {
		return fmt.Errorf("removing it again: %v", err)
	}
	return nil
}

func smtpMailboxSuiteOutcomes() []*sidecar.SmtpDomainOutcome {
	updateTime := time.UnixMilli(time.Now().UnixMilli())
	return []*sidecar.SmtpDomainOutcome{
		{Domain: "mail.example", Mode: sidecar.SmtpModeBdat, Outcome: sidecar.SmtpOutcomeSent, UpdateTime: updateTime, TlsLevel: sidecar.SmtpTlsLevelDane},
		{Domain: "other.example", Mode: sidecar.SmtpModeData, ByteCount: 2 * 1024 * 1024, CapByteCount: 1024 * 1024, Outcome: sidecar.SmtpOutcomeTooLarge, UpdateTime: updateTime, TlsLevel: sidecar.SmtpTlsLevelMtaSts},
		{Domain: "third.example", Outcome: sidecar.SmtpOutcomeDeferred, RetryAfter: 30 * time.Minute, UpdateTime: updateTime},
	}
}

func smtpMailboxSuiteSameOutcomes(got []*sidecar.SmtpDomainOutcome, want []*sidecar.SmtpDomainOutcome) error {
	if len(got) != len(want) {
		return fmt.Errorf("%d outcomes, want %d", len(got), len(want))
	}
	for i := range want {
		if *got[i] != *want[i] {
			return fmt.Errorf("outcome %d is %+v, want %+v", i, got[i], want[i])
		}
	}
	return nil
}

func caseSmtpMailboxOutcomesReplace(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	effectKey := smtpMailboxSuiteEffectKey()
	outcomes := smtpMailboxSuiteOutcomes()
	if err := mailbox.WriteOutcomes(ctx, effectKey, outcomes); err != nil {
		return err
	}
	read, err := mailbox.ReadOutcomes(ctx, effectKey)
	if err != nil {
		return err
	}
	if err := smtpMailboxSuiteSameOutcomes(read, outcomes); err != nil {
		return err
	}
	listed, err := mailbox.ListOutcomes(ctx)
	if err != nil {
		return err
	}
	if !smtpMailboxSuiteContains(listed, effectKey) {
		return errors.New("the record is not listed")
	}
	replaced := outcomes[2:]
	replaced[0] = &sidecar.SmtpDomainOutcome{Domain: "third.example", Mode: sidecar.SmtpModeBdat, Outcome: sidecar.SmtpOutcomeSent, UpdateTime: outcomes[0].UpdateTime, TlsLevel: sidecar.SmtpTlsLevelIndependentMx}
	if err := mailbox.WriteOutcomes(ctx, effectKey, replaced); err != nil {
		return err
	}
	read, err = mailbox.ReadOutcomes(ctx, effectKey)
	if err != nil {
		return err
	}
	return smtpMailboxSuiteSameOutcomes(read, replaced)
}

func caseSmtpMailboxOutcomesNotFound(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	if _, err := mailbox.ReadOutcomes(ctx, smtpMailboxSuiteEffectKey()); !errors.Is(err, sidecar.ErrSmtpMailboxNotFound) {
		return fmt.Errorf("read a missing record: %v", err)
	}
	return nil
}

func caseSmtpMailboxOutcomesRefused(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	effectKey := smtpMailboxSuiteEffectKey()
	outcomes := smtpMailboxSuiteOutcomes()
	if err := mailbox.WriteOutcomes(ctx, effectKey, outcomes); err != nil {
		return err
	}
	for _, refused := range []*sidecar.SmtpDomainOutcome{
		{Domain: "mail.example", Outcome: sidecar.SmtpOutcomeUnspecified},
		{Domain: "mail.example", Outcome: sidecar.SmtpOutcomeSent, TlsLevel: sidecar.SmtpTlsLevelUnauthenticated + 1},
	} {
		if err := mailbox.WriteOutcomes(ctx, effectKey, []*sidecar.SmtpDomainOutcome{refused}); err == nil {
			return fmt.Errorf("wrote %+v", refused)
		}
	}
	read, err := mailbox.ReadOutcomes(ctx, effectKey)
	if err != nil {
		return err
	}
	return smtpMailboxSuiteSameOutcomes(read, outcomes)
}

func caseSmtpMailboxProverMeasure(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	sidecarId := sidecar.NewId()
	measure := &sidecar.SmtpProverMeasure{DataProofBytes: 1024 * 1024, DataBytesPerSecond: 150, MeasureTime: time.UnixMilli(time.Now().UnixMilli())}
	if err := mailbox.WriteProverMeasure(ctx, sidecarId, measure); err != nil {
		return err
	}
	measures, err := mailbox.ListProverMeasures(ctx)
	if err != nil {
		return err
	}
	if got := measures[sidecarId]; got == nil || *got != *measure {
		return fmt.Errorf("listed %+v, want %+v", got, measure)
	}
	rewritten := &sidecar.SmtpProverMeasure{DataProofBytes: 600 * 1024, DataBytesPerSecond: 90, MeasureTime: measure.MeasureTime.Add(time.Hour)}
	if err := mailbox.WriteProverMeasure(ctx, sidecarId, rewritten); err != nil {
		return err
	}
	if measures, err = mailbox.ListProverMeasures(ctx); err != nil {
		return err
	}
	if got := measures[sidecarId]; got == nil || *got != *rewritten {
		return fmt.Errorf("after a rewrite listed %+v, want %+v", got, rewritten)
	}
	return nil
}

func caseSmtpMailboxDsn(ctx context.Context, mailbox sidecar.SmtpMailbox, plant SmtpMailboxPlantOutbox) error {
	effectKey := smtpMailboxSuiteEffectKey()
	dsn := []byte("Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n--b--\r\n")
	if err := mailbox.DepositDsn(ctx, effectKey, dsn); err != nil {
		return err
	}
	// a second send of the same entry may end in a second one
	if err := mailbox.DepositDsn(ctx, effectKey, dsn); err != nil {
		return err
	}
	if err := mailbox.DepositDsn(ctx, effectKey, nil); err == nil {
		return errors.New("took a dsn with no bytes")
	}
	return nil
}
