//go:build !sidecar_http && !ios_extension

// Outbox signing fixtures shared by mail and smtp tests, and the in-memory mailbox for MAIL-M9-02's contract suite.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device's identity key, which signs its outbox entries as Sidecar.Sign does.
type testMailOutboxSigner struct {
	sidecarId Id
	key       ed25519.PrivateKey
}

func newTestMailOutboxSigner(sidecarId Id) *testMailOutboxSigner {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &testMailOutboxSigner{sidecarId: sidecarId, key: key}
}

func (self *testMailOutboxSigner) sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *testMailOutboxSigner) publicKey() ed25519.PublicKey {
	return self.key.Public().(ed25519.PublicKey)
}

// 32 random bytes, as D-MCP-11's keys are.
func testMailOutboxEffectKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

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
