//go:build !sidecar_http && !ios_extension

// Reverse aliases (§15.10's forwarding steps 3 and 4, §15.7's ra/; R-MAIL-6, D-MAIL-14, I-8, I-9; MAIL-M9-04): a
// forward goes From r-<token>@<blabel>.<net>.<root>, <token> a MAC of the original sender, and the mailbox keeps
// ra/<h>/<token>, MailReverseAlias{original_sender, burner_address}, so mail the verified address sends back to
// r-<token> is relayed From the burner to the original sender. ra/ is mailbox-only: a receiver checks only that the
// burner is live (MailConfig.Resolve), and its reader finds the record here.
//
//	token    the first 16 bytes of HMAC-SHA-256 over the original sender's lowercase address, in lowercase base32, 26
//	         characters, so r-<token> is 28, under §15.8's 64. The token tells no one who the sender is
//	key      the mailbox's one MAC key, 32 bytes at vault/<h>/reverse-alias-key (MailVault.ReverseAliasKey; QD-1095),
//	         drawn by the first forwarding device and read only by the owner's consented devices, so every device of
//	         the member gives one sender one reverse alias
//	record   created only if absent, so racing readers write one record a token
//
// Nothing here logs an address or a token (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The MAC's bytes a token spells.
const mailReverseAliasTokenByteCount = 16

var (
	// No MAC key to make a token with: a device that may not read the vault, or one with none bound.
	ErrMailReverseAliasKey = errors.New("mail reverse alias: no key")
	// No reverse alias holds the token.
	ErrMailReverseAliasAbsent = errors.New("mail reverse alias: none")
)

// A mailbox's reverse aliases: see the file header.
type MailReverseAlias struct {
	store mailStore
	// the mailbox's MAC key (MailVault.ReverseAliasKey), nil where none may be read, which makes no token
	key func(ctx context.Context) ([]byte, error)
	// the most bytes of one ra/ record
	recordMaxByteCount int
}

// The reverse aliases of the mailbox store, its MAC key read through key.
func newMailReverseAlias(store mailStore, key func(ctx context.Context) ([]byte, error), settings *MailOutboxSettings) *MailReverseAlias {
	if settings == nil {
		settings = DefaultMailOutboxSettings()
	}
	return &MailReverseAlias{store: store, key: key, recordMaxByteCount: settings.ProverRecordMaxByteCount}
}

// The token of originalSender, an addr-spec, under the mailbox's key.
func (self *MailReverseAlias) Token(ctx context.Context, originalSender string) (string, error) {
	if self.key == nil {
		return "", ErrMailReverseAliasKey
	}
	key, err := self.key(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMailReverseAliasKey, err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(dnsAsciiLower(originalSender)))
	return mailBinaryName(mac.Sum(nil)[:mailReverseAliasTokenByteCount]), nil
}

// The token of originalSender, its record created if absent naming burnerAddress, the burner the sender wrote to.
func (self *MailReverseAlias) Ensure(ctx context.Context, originalSender string, burnerAddress string) (string, error) {
	token, err := self.Token(ctx, originalSender)
	if err != nil {
		return "", err
	}
	path, err := MailReverseAliasPath(token)
	if err != nil {
		return "", err
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailReverseAlias{
		OriginalSender: dnsAsciiLower(originalSender),
		BurnerAddress:  dnsAsciiLower(burnerAddress),
	})
	if err != nil {
		return "", err
	}
	if _, err := self.Find(ctx, token); err == nil {
		return token, nil
	} else if !errors.Is(err, ErrMailReverseAliasAbsent) {
		return "", err
	}
	_, err = self.store.Write(ctx, []*mailStoreWrite{{Path: path, Content: content, IfVersion: 0}})
	if err != nil && !mailStoreConflictOn(err, path) {
		return "", err
	}
	// a racing reader's record holds the token: this sender's, since the token is its MAC
	return token, nil
}

// The record of token, ErrMailReverseAliasAbsent for none.
func (self *MailReverseAlias) Find(ctx context.Context, token string) (*protocol.MailReverseAlias, error) {
	path, err := MailReverseAliasPath(token)
	if err != nil {
		return nil, ErrMailReverseAliasAbsent
	}
	content, _, err := self.store.Read(ctx, path, self.recordMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, ErrMailReverseAliasAbsent
	}
	if err != nil {
		return nil, err
	}
	record := &protocol.MailReverseAlias{}
	if err := proto.Unmarshal(content, record); err != nil || record.GetOriginalSender() == "" || record.GetBurnerAddress() == "" {
		return nil, ErrMailReverseAliasAbsent
	}
	return record, nil
}
