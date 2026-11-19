//go:build !ios_extension

// Bounce addresses (§14.6, §15.8's bounce row, §15.10's last line; R-MAIL-1, D-SMTP-13, X6, X7; MAIL-M9-05): a send's
// envelope sender is bounces+<token>@b.<net>.<root>, which DSNs come back to, and receivers deposit them to the
// sending mailbox, since the address resolves through a bounce MailAddress in mailcfg naming that mailbox, as any
// recipient resolves (MailConfig.Resolve). An unknown token is an unknown address, 550 5.1.1.
//
//	token    16 random bytes in lowercase base32, 26 characters, drawn by the first device of the member to send
//	         internet mail: never derived from a repo, member or device id, so neither smtpedge, which reads the
//	         envelope, nor a recipient can tell from it which mailbox sent, and the record that names the mailbox is
//	         in mailcfg, sealed (X2)
//	record   MailAddress{kind: bounce, mailbox, creator}, created only if absent, as any address is, and held to the
//	         creator's mail:<local part>#listen as any is (§15.8). Its creation is part of an internet send's effect,
//	         which the gate has passed, so it takes no approval of its own; it carries no effect key, a retry that met
//	         a lost write finding its own by content
//	reuse    every device of the member sends under the mailbox's one honored bounce record, the first in address
//	         order where a race left two; each stays a working address, so a DSN to either arrives
//
// On every leg but the extension's, the page Worker's included, which reads the address and queues nothing. Nothing
// here logs an address or a token (I-13).

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The random bytes of a bounce token.
const mailBounceTokenByteCount = 16

// bounces+<token>@b.<zone>, zone a network's zone (§14.6).
func MailBounceAddress(zone MailZone, token string) string {
	return mailBouncePrefix + token + "@" + mailBounceLabel + "." + zone.Domain()
}

// A fresh bounce token: see the file header's token row.
func newMailBounceToken() string {
	token := NewEvsRandomToken()
	return mailBinaryName(token[:mailBounceTokenByteCount])
}

// This device's member's mailbox's bounce address, its envelope sender for internet mail: the honored bounce record
// naming the mailbox, made if there is none (see the file header). ErrMailNoMailbox for a device with no mailbox of
// its own.
func (self *MailClient) BounceRecipient(ctx context.Context) (string, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return "", err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return "", err
	}
	if address, ok := mailBounceAddressOf(config, mailboxId); ok {
		return address, nil
	}
	lookup, err := config.CreateBounceAddress(ctx, mailboxId, newMailBounceToken())
	if err != nil {
		return "", err
	}
	if !lookup.Known {
		// a creation policy does not honor delivers nothing
		return "", ErrMailConfigNoGrant
	}
	return lookup.Address, nil
}

// The first honored bounce address naming mailboxId in config, in address order.
func mailBounceAddressOf(config *MailConfig, mailboxId Id) (string, bool) {
	lookups, err := config.Addresses()
	if err != nil {
		return "", false
	}
	addresses := []string{}
	for _, lookup := range lookups {
		if lookup.Known && lookup.Kind == protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE && lookup.MailboxRepoId == mailboxId {
			addresses = append(addresses, lookup.Address)
		}
	}
	if len(addresses) == 0 {
		return "", false
	}
	slices.Sort(addresses)
	return addresses[0], true
}

// Creates the bounce record bounces+<token>@b.<zone> for mailboxRepoId, created only if absent (see mail_bounce.go's
// record row): no gate of its own, since only an internet send's effect, which the gate passed, makes one.
// ErrMailConfigNoGrant where policy would not honor this device's record; ErrMailConfigAddressTaken where another
// record holds the token.
func (self *MailConfig) CreateBounceAddress(ctx context.Context, mailboxRepoId Id, token string) (*MailAddressLookup, error) {
	if mailboxRepoId == (Id{}) || !validMailToken(token) || strings.Contains(token, "/") {
		return nil, fmt.Errorf("%w: no bounce address", ErrMailConfigInvalid)
	}
	zone, _, err := self.zone()
	if err != nil {
		return nil, err
	}
	if zone.Scope != "" {
		// §15.8's table has no bounce zone under a scope
		return nil, fmt.Errorf("%w: a scope has no bounce zone", ErrMailConfigInvalid)
	}
	name, ok := mailConfigAddressName(zone, MailBounceAddress(zone, token))
	if !ok {
		return nil, fmt.Errorf("%w: no bounce address of this zone", ErrMailConfigInvalid)
	}
	if err := self.store.Writable(ctx); err != nil {
		return nil, err
	}
	if self.authority == nil || !self.authority.HonorsRecord(self.sidecarId, name.alias, self.clock.Now()) {
		return nil, ErrMailConfigNoGrant
	}
	address := &protocol.MailAddress{
		Kind:    protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE,
		Mailbox: mailboxRepoId.Bytes(),
		Creator: self.sidecarId.Bytes(),
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(address)
	if err != nil {
		return nil, err
	}
	if _, err := self.createRecord(ctx, name, nil, content); err != nil {
		return nil, err
	}
	replay, err := self.refresh(ctx, name)
	if err != nil {
		return nil, err
	}
	return self.lookupOf(name, replay.record), nil
}
