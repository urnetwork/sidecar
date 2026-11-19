//go:build !sidecar_http && !ios_extension

// A bridge for MAIL-M9-02's external test, which runs sidecartest.RunSmtpMailboxSuite on mailSmtpMailbox: the mailbox
// over an in-memory store, and the write of o/ that MailOutbox.Queue makes, created only if absent.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
)

// A deposit that keeps what it is given.
type mailOutboxTestDeposit struct {
	stateLock sync.Mutex
	bodies    [][]byte
}

func (self *mailOutboxTestDeposit) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	body, err := io.ReadAll(args.Body)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.bodies = append(self.bodies, body)
	return &EvsDepositResult{EntryId: NewEvsRandomToken(), Version: uint64(len(self.bodies))}, nil
}

// MAIL's SmtpMailbox over a fresh in-memory mailbox, and the o/ write Queue makes there: o/<h>/<effect_key> holding
// u32be(length) ‖ signed ‖ message, created only if absent.
func NewMailSmtpMailboxForTest() (SmtpMailbox, func(ctx context.Context, effectKey []byte, signed []byte, message []byte) error) {
	store := newMailTestStore()
	mailbox := newMailSmtpMailbox(store, &mailOutboxTestDeposit{}, func(ctx context.Context) (string, error) {
		return "bounces+testtoken@b.n1.root.example", nil
	}, nil, nil)
	plant := func(ctx context.Context, effectKey []byte, signed []byte, message []byte) error {
		path, err := MailOutboxPath(effectKey)
		if err != nil {
			return err
		}
		_, err = store.Write(ctx, []*mailStoreWrite{{Path: path, Content: mailOutboxFileBytes(signed, message), IfVersion: 0}})
		if errors.Is(err, ErrMailStoreConflict) {
			if file := store.file(path); file != nil && bytes.Equal(file.content, mailOutboxFileBytes(signed, message)) {
				return nil
			}
		}
		return err
	}
	return mailbox, plant
}
