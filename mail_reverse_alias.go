//go:build !sidecar_http && !ios_extension

// Reverse aliases (§15.10's forwarding steps 3 and 4, §15.7's ra/; R-MAIL-6, D-MAIL-14, I-8, I-9; MAIL-M9-04): a
// forward goes From r-<token>@<blabel>.<net>.<root>, <token> a MAC of the original sender, and the mailbox keeps
// ra/<h>/<token>, MailReverseAlias{original_sender, burner_address}, so mail the verified address sends back to
// r-<token> is relayed From the burner to the original sender. ra/ is mailbox-only: a receiver checks only that the
// burner is live (MailConfig.Resolve), and its reader finds the record here.
//
//	token    the first 16 bytes of HMAC-SHA-256 over the original sender's lowercase address, in lowercase base32, 26
//	         characters, so r-<token> is 28, under §15.8's 64. The token tells no one who the sender is
//	key      32 random bytes in the mail component's keychain namespace, drawn on first use. The design names a vault
//	         key and no place or bytes for it (question mail-m9-04-reverse-alias-key), so each device holds its own:
//	         the same sender may get another reverse alias from another device's forward, and a relay finds its
//	         record either way, since ra/ is the mailbox's
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

// The reverse alias MAC key's name in the mail component's keychain namespace.
const mailReverseAliasKeyName = "mail/reverse-alias-key"

// The MAC's bytes a token spells, and the key's.
const (
	mailReverseAliasTokenByteCount = 16
	mailReverseAliasKeyByteCount   = 32
)

var (
	// No keychain to hold the MAC key, or one that cannot keep it.
	ErrMailReverseAliasKey = errors.New("mail reverse alias: no key")
	// No reverse alias holds the token.
	ErrMailReverseAliasAbsent = errors.New("mail reverse alias: none")
)

// A mailbox's reverse aliases: see the file header.
type MailReverseAlias struct {
	store   mailStore
	secrets SidecarSecrets
	// the most bytes of one ra/ record
	recordMaxByteCount int
}

// The reverse aliases of the mailbox store, the key in secrets.
func newMailReverseAlias(store mailStore, secrets SidecarSecrets, settings *MailOutboxSettings) *MailReverseAlias {
	if settings == nil {
		settings = DefaultMailOutboxSettings()
	}
	return &MailReverseAlias{store: store, secrets: secrets, recordMaxByteCount: settings.ProverRecordMaxByteCount}
}

// The MAC key, drawn and kept on first use.
func (self *MailReverseAlias) key() ([]byte, error) {
	if self.secrets == nil {
		return nil, ErrMailReverseAliasKey
	}
	key, err := self.secrets.Get(mailReverseAliasKeyName)
	if err == nil && len(key) == mailReverseAliasKeyByteCount {
		testHookSecret("mail_reverse_alias_key", key)
		return key, nil
	}
	if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, err
	}
	random := NewEvsRandomToken()
	other := NewEvsRandomToken()
	key = append(random[:], other[:]...)
	testHookSecret("mail_reverse_alias_key", key)
	if err := self.secrets.Put(mailReverseAliasKeyName, key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailReverseAliasKey, err)
	}
	return key, nil
}

// The token of originalSender, an addr-spec, under this device's key.
func (self *MailReverseAlias) Token(originalSender string) (string, error) {
	key, err := self.key()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(dnsAsciiLower(originalSender)))
	return mailBinaryName(mac.Sum(nil)[:mailReverseAliasTokenByteCount]), nil
}

// The token of originalSender, its record created if absent naming burnerAddress, the burner the sender wrote to.
func (self *MailReverseAlias) Ensure(ctx context.Context, originalSender string, burnerAddress string) (string, error) {
	token, err := self.Token(originalSender)
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
