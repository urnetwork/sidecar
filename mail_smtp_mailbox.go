//go:build !sidecar_http && !ios_extension

// mailSmtpMailbox, the real SmtpMailbox (§15.7, §15.10; R-MAIL-1, R-MAIL-12, D-MAIL-5, X7; MAIL-M9-02): the sender's
// one way into a member's mailbox, over the mailbox's file-mode ref by path (mailStore) and its deposit, so SMTP
// builds no mailbox path itself and a path's <h> shard and its sealing stay MAIL's (smtp_mailbox.go).
//
//	o/       o/<h>/<effect_key>: u32be(length) ‖ Signed ‖ the message (plan-SMTP-wire-gaps#4), which MailOutbox.Queue
//	         writes, created only if absent; here it is listed, read back whole and removed. A file whose length runs
//	         past its end, or names a Signed past OutboxSignedMaxByteCount, reads as no entry of this format and is
//	         refused, never handed on in part
//	or/      or/<h>/<effect_key>: MailOutcomeRecord, replaced at each write, its last writer winning over the version
//	         it read; a write racing another reads again, at most WriteRetryCount times. An outcome the wire cannot
//	         carry is refused before anything is written. The record names its send (send_id, QD-1122): the write
//	         that creates it reads the send from its o/ entry's Message-ID (MailOutboxSendIdOf), once, and every
//	         later write keeps the send_id the record holds, so the record names its send after the entry is gone.
//	         A record created with no entry, or one whose message names no send of that form, names none, and is
//	         read as before (ReadSendOutcomes, which MailClient.SendResult reads by)
//	p/       p/<sidecar_id>: MailProverRecord, rewritten as or/ is
//	dsn      a DSN goes to this mailbox as a deposit by this device: a same-network trailer naming the null reverse path,
//	         as RFC 3464's DSNs come, and one recipient, the DSN's To where it names one, else the mailbox's bounce
//	         address, so ingest files it as received mail. Its signer may not send as mailer-daemon, so it reads as
//	         outside mail, untrusted, as a DSN from any MX does
//
// Listing a family reads its 256 <h> directories as they stand, so a pass costs one List a shard that holds an entry.
// Names are effect keys and sidecar ids in lowercase base32 (mail_paths.go), and a name of any other shape is passed
// over. Nothing here logs a path, an address or a byte of a message (I-13). Safe for concurrent use.
//
// Off the sidecar_http leg, as SmtpMailbox is: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	_ SmtpMailbox           = (*mailSmtpMailbox)(nil)
	_ MailSendOutcomeReader = (*mailSmtpMailbox)(nil)
)

// What reads or/ beside SmtpMailbox: each record with the send it names (the file header's or/ row), which a send's
// result by its send_id reads (MailClient.SendResult). mailSmtpMailbox has it, and so does sidecartest.FakeSmtpMailbox,
// which RunSmtpMailboxSuite holds to the same promise.
type MailSendOutcomeReader interface {
	// One or/ record's send and outcomes: the zero Id for a record that names no send, and ErrSmtpMailboxNotFound
	// where no record stands.
	ReadSendOutcomes(ctx context.Context, effectKey []byte) (Id, []*SmtpDomainOutcome, error)
}

var (
	// An o/ file that is not u32be(length) ‖ Signed ‖ message within the outbox's bounds.
	ErrMailOutboxFileInvalid = errors.New("mail outbox: an entry not of its format")
	// A DSN with no bytes, or none that parse as a message.
	ErrMailOutboxDsnInvalid = errors.New("mail outbox: a dsn that is no message")
)

// An o/ file's bytes: u32be(len(signed)) ‖ signed ‖ message.
func mailOutboxFileBytes(signed []byte, message []byte) []byte {
	content := make([]byte, 0, mailOutboxLengthByteCount+len(signed)+len(message))
	content = binary.BigEndian.AppendUint32(content, uint32(len(signed)))
	content = append(content, signed...)
	return append(content, message...)
}

// An o/ file taken apart, not verified: ErrMailOutboxFileInvalid where it is not of its format within settings.
func mailOutboxFileParse(effectKey []byte, content []byte, settings *MailOutboxSettings) (*SmtpOutboxFile, error) {
	if len(content) < mailOutboxLengthByteCount {
		return nil, ErrMailOutboxFileInvalid
	}
	signedByteCount := uint64(binary.BigEndian.Uint32(content))
	rest := content[mailOutboxLengthByteCount:]
	if signedByteCount == 0 || uint64(settings.OutboxSignedMaxByteCount) < signedByteCount || uint64(len(rest)) < signedByteCount {
		return nil, ErrMailOutboxFileInvalid
	}
	return &SmtpOutboxFile{
		EffectKey: bytes.Clone(effectKey),
		Signed:    bytes.Clone(rest[:signedByteCount]),
		Message:   bytes.Clone(rest[signedByteCount:]),
	}, nil
}

// See the file header. Built over one mailbox by MailClient.SmtpMailbox, or by a test over its stand-ins.
type mailSmtpMailbox struct {
	store mailStore
	// the mailbox's deposit, nil where this device may deposit nothing there, which refuses every DSN
	deposit mailSendDepositRepo
	// the recipient a DSN that names no To is filed under: the mailbox's bounce address (MailBounceRecipient)
	dsnRecipient func(ctx context.Context) (string, error)
	settings     *MailOutboxSettings
	clock        Clock
}

// The mailbox over store and deposit, nil settings taking the defaults.
func newMailSmtpMailbox(store mailStore, deposit mailSendDepositRepo, dsnRecipient func(ctx context.Context) (string, error), settings *MailOutboxSettings, clock Clock) *mailSmtpMailbox {
	if settings == nil {
		settings = DefaultMailOutboxSettings()
	}
	return &mailSmtpMailbox{store: store, deposit: deposit, dsnRecipient: dsnRecipient, settings: settings, clock: clockOrReal(clock)}
}

// The binary names under family's 256 shards, each decoded, those of byteCount bytes alone. An absent family or
// shard holds none.
func (self *mailSmtpMailbox) listSharded(ctx context.Context, family string, byteCount int) ([][]byte, error) {
	shards, err := self.store.List(ctx, family)
	if errors.Is(err, ErrEvsPathAbsent) {
		return [][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	keys := [][]byte{}
	for _, shard := range shards {
		if len(shard) != 2 || strings.Trim(shard, "0123456789abcdef") != "" {
			continue
		}
		names, err := self.store.List(ctx, family+"/"+shard)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			key, err := evsTokenEncoding.DecodeString(name)
			// a name of another shape, or one filed under another shard, is no entry of this family
			if err != nil || len(key) != byteCount || mailBinaryName(key) != name || MailShard(name) != shard {
				continue
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// Replaces path with content, whatever stands there: read its version, write over it, read again when another
// writer moved it in between.
func (self *mailSmtpMailbox) replace(ctx context.Context, path string, content []byte, maxByteCount int) error {
	for attempt := 0; ; attempt += 1 {
		_, version, err := self.store.Read(ctx, path, maxByteCount)
		switch {
		case errors.Is(err, ErrEvsPathAbsent):
			version = 0
		case err != nil:
			// a file past the bound is none this side wrote, and is left as it stands
			return err
		}
		_, err = self.store.Write(ctx, []*mailStoreWrite{{Path: path, Content: content, IfVersion: version}})
		if err == nil {
			return nil
		}
		if !mailStoreConflictOn(err, path) || self.settings.WriteRetryCount <= attempt {
			return err
		}
	}
}

// Removes path if it stands: read its version, remove at it, read again when another writer moved it in between.
// Absent is no error.
func (self *mailSmtpMailbox) remove(ctx context.Context, path string, maxByteCount int) error {
	for attempt := 0; ; attempt += 1 {
		_, version, err := self.store.Read(ctx, path, maxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = self.store.Write(ctx, []*mailStoreWrite{{Path: path, Remove: true, IfVersion: version}})
		if err == nil {
			return nil
		}
		if !mailStoreConflictOn(err, path) || self.settings.WriteRetryCount <= attempt {
			return err
		}
	}
}

// See SmtpMailbox.
func (self *mailSmtpMailbox) ListOutbox(ctx context.Context) ([][]byte, error) {
	return self.listSharded(ctx, mailOutboxFamily, mailEffectKeyByteCount)
}

// See SmtpMailbox.
func (self *mailSmtpMailbox) ReadOutbox(ctx context.Context, effectKey []byte) (*SmtpOutboxFile, error) {
	path, err := MailOutboxPath(effectKey)
	if err != nil {
		return nil, ErrSmtpMailboxNotFound
	}
	content, _, err := self.store.Read(ctx, path, self.settings.OutboxFileMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, ErrSmtpMailboxNotFound
	}
	if err != nil {
		return nil, err
	}
	return mailOutboxFileParse(effectKey, content, self.settings)
}

// See SmtpMailbox.
func (self *mailSmtpMailbox) RemoveOutbox(ctx context.Context, effectKey []byte) error {
	path, err := MailOutboxPath(effectKey)
	if err != nil {
		return nil
	}
	testHookBarrier("mail.outbox.remove.before", "")
	err = self.remove(ctx, path, self.settings.OutboxFileMaxByteCount)
	testHookBarrier("mail.outbox.remove.after", "")
	return err
}

// See SmtpMailbox. The record names its send as the file header's or/ row says: a write that creates it reads the send
// from the o/ entry under effectKey, and a later one keeps what the record standing names.
func (self *mailSmtpMailbox) WriteOutcomes(ctx context.Context, effectKey []byte, outcomes []*SmtpDomainOutcome) error {
	path, err := MailOutcomePath(effectKey)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt += 1 {
		standing, version, err := self.store.Read(ctx, path, self.settings.OutcomeRecordMaxByteCount)
		previous := &protocol.MailOutcomeRecord{}
		switch {
		case errors.Is(err, ErrEvsPathAbsent):
			version = 0
			if previous.SendId, err = self.outboxSendId(ctx, effectKey); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if proto.Unmarshal(standing, previous) != nil {
				// Preserve the existing recovery behavior for an unreadable older record.
				previous.Reset()
			}
		}
		record, err := SmtpMailboxOutcomeRecord(outcomes, previous)
		if err != nil {
			return err
		}
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
		if err != nil {
			return err
		}
		if self.settings.OutcomeRecordMaxByteCount < len(content) {
			return ErrMailStoreTooLarge
		}
		_, err = self.store.Write(ctx, []*mailStoreWrite{{Path: path, Content: content, IfVersion: version}})
		if err == nil {
			return nil
		}
		if !mailStoreConflictOn(err, path) || self.settings.WriteRetryCount <= attempt {
			return err
		}
	}
}

// The send_id a record created under effectKey names: the send its o/ entry's Message-ID names, nil where no entry of
// the outbox's format stands there or its message names no send of MailOutboxMessageId's form. An error is a read
// that could not answer, which fails the write as any of its reads would.
func (self *mailSmtpMailbox) outboxSendId(ctx context.Context, effectKey []byte) ([]byte, error) {
	file, err := self.ReadOutbox(ctx, effectKey)
	switch {
	case errors.Is(err, ErrSmtpMailboxNotFound), errors.Is(err, ErrMailOutboxFileInvalid), errors.Is(err, ErrMailStoreTooLarge):
		return nil, nil
	case err != nil:
		return nil, err
	}
	sendId, ok := MailOutboxSendIdOf(file.Message)
	if !ok {
		return nil, nil
	}
	return sendId.Bytes(), nil
}

// See SmtpMailbox.
func (self *mailSmtpMailbox) ListOutcomes(ctx context.Context) ([][]byte, error) {
	return self.listSharded(ctx, mailOutcomeFamily, mailEffectKeyByteCount)
}

// See SmtpMailbox.
func (self *mailSmtpMailbox) ReadOutcomes(ctx context.Context, effectKey []byte) ([]*SmtpDomainOutcome, error) {
	_, outcomes, err := self.ReadSendOutcomes(ctx, effectKey)
	return outcomes, err
}

// See MailSendOutcomeReader.
func (self *mailSmtpMailbox) ReadSendOutcomes(ctx context.Context, effectKey []byte) (Id, []*SmtpDomainOutcome, error) {
	path, err := MailOutcomePath(effectKey)
	if err != nil {
		return Id{}, nil, ErrSmtpMailboxNotFound
	}
	content, _, err := self.store.Read(ctx, path, self.settings.OutcomeRecordMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return Id{}, nil, ErrSmtpMailboxNotFound
	}
	if err != nil {
		return Id{}, nil, err
	}
	record := &protocol.MailOutcomeRecord{}
	if err := proto.Unmarshal(content, record); err != nil {
		return Id{}, nil, err
	}
	outcomes, err := SmtpMailboxOutcomes(record)
	if err != nil {
		return Id{}, nil, err
	}
	// a send_id of another length names no send
	sendId, err := IdFromBytes(record.GetSendId())
	if err != nil {
		sendId = Id{}
	}
	return sendId, outcomes, nil
}

// Removes every or/ record whose newest outcome was last written more than OutcomeKeepDuration ago (§15.7's 30 days),
// and one that does not decode. The count removed.
func (self *mailSmtpMailbox) RemoveExpiredOutcomes(ctx context.Context) (int, error) {
	effectKeys, err := self.ListOutcomes(ctx)
	if err != nil {
		return 0, err
	}
	now := self.clock.Now()
	removed := 0
	for _, effectKey := range effectKeys {
		outcomes, err := self.ReadOutcomes(ctx, effectKey)
		if errors.Is(err, ErrSmtpMailboxNotFound) {
			continue
		}
		expired := err != nil
		if err == nil {
			newest := time.Time{}
			for _, outcome := range outcomes {
				if newest.Before(outcome.UpdateTime) {
					newest = outcome.UpdateTime
				}
			}
			expired = self.settings.OutcomeKeepDuration < now.Sub(newest)
		}
		if !expired {
			continue
		}
		path, err := MailOutcomePath(effectKey)
		if err != nil {
			continue
		}
		if err := self.remove(ctx, path, self.settings.OutcomeRecordMaxByteCount); err != nil {
			return removed, err
		}
		removed += 1
	}
	return removed, nil
}

// See SmtpMailbox.
func (self *mailSmtpMailbox) WriteProverRecord(ctx context.Context, sidecarId Id, record *SmtpProverRecord) error {
	if record == nil {
		return fmt.Errorf("%w: no prover record", ErrMailOutboxFileInvalid)
	}
	mailRecord, err := record.MailProverRecord()
	if err != nil {
		return err
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(mailRecord)
	if err != nil {
		return err
	}
	if self.settings.ProverRecordMaxByteCount < len(content) {
		return ErrMailStoreTooLarge
	}
	return self.replace(ctx, MailProverPath(sidecarId), content, self.settings.ProverRecordMaxByteCount)
}

// See SmtpMailbox. A record that does not decode is passed over, so one bad file hides no other host.
func (self *mailSmtpMailbox) ListProverRecords(ctx context.Context) (map[Id]*SmtpProverRecord, error) {
	names, err := self.store.List(ctx, mailProverFamily)
	if errors.Is(err, ErrEvsPathAbsent) {
		return map[Id]*SmtpProverRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	sidecarIdRecords := map[Id]*SmtpProverRecord{}
	for _, name := range names {
		idBytes, err := evsTokenEncoding.DecodeString(name)
		if err != nil || mailBinaryName(idBytes) != name {
			continue
		}
		sidecarId, err := IdFromBytes(idBytes)
		if err != nil {
			continue
		}
		content, _, err := self.store.Read(ctx, MailProverPath(sidecarId), self.settings.ProverRecordMaxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) || errors.Is(err, ErrMailStoreTooLarge) {
			continue
		}
		if err != nil {
			return nil, err
		}
		mailRecord := &protocol.MailProverRecord{}
		if err := proto.Unmarshal(content, mailRecord); err != nil {
			continue
		}
		record, err := SmtpProverRecordFromMail(mailRecord)
		if err != nil {
			continue
		}
		sidecarIdRecords[sidecarId] = record
	}
	return sidecarIdRecords, nil
}

// The address a DSN is filed under: its To, where that is one address, else the mailbox's bounce address.
func (self *mailSmtpMailbox) dsnRecipientOf(ctx context.Context, dsn []byte) (string, error) {
	if message, err := mail.ReadMessage(bytes.NewReader(dsn)); err == nil {
		if addresses, err := message.Header.AddressList("To"); err == nil && len(addresses) == 1 {
			if address := dnsAsciiLower(addresses[0].Address); address != "" {
				return address, nil
			}
		}
	} else {
		return "", ErrMailOutboxDsnInvalid
	}
	if self.dsnRecipient == nil {
		return "", ErrMailOutboxDsnInvalid
	}
	return self.dsnRecipient(ctx)
}

// See SmtpMailbox and the file header's dsn row.
func (self *mailSmtpMailbox) DepositDsn(ctx context.Context, effectKey []byte, dsn []byte) error {
	if len(dsn) == 0 {
		return ErrMailOutboxDsnInvalid
	}
	if self.deposit == nil {
		return fmt.Errorf("%w: no deposit into this mailbox", ErrMailSendUnavailable)
	}
	recipient, err := self.dsnRecipientOf(ctx, dsn)
	if err != nil {
		return err
	}
	plaintext, err := MailSameNetworkDeposit(dsn, "", []string{recipient})
	if err != nil {
		return err
	}
	testHookBarrier("mail.outbox.dsn.before", "")
	_, err = self.deposit.Deposit(ctx, &EvsDepositArgs{Body: bytes.NewReader(plaintext), Size: int64(len(plaintext))})
	testHookBarrier("mail.outbox.dsn.after", "")
	return err
}
