//go:build !ios_extension

// Bounce addresses (§14.6, §15.8's bounce row, §15.10's last line; R-MAIL-1, D-SMTP-13, X6, X7; MAIL-M9-05, QD-1129): a
// send's envelope sender is bounces+<token>@b.<net>.<root>, which DSNs come back to, and receivers deposit them to the
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
//	reuse    every device of the member sends under the mailbox's one honored bounce record of an envelope domain, the
//	         first in address order where a race left two; each stays a working address, so a DSN to either arrives
//	strict   a From in a custom domain in strict mode sends with b.<domain> (§15.4, QD-1129): the domain is one GET
//	         /mail/status names in strict mode, picked by SmtpStrictCustomDomain, the rule smtpedge's gate derives
//	         envelope_domain by over the same set, so the two agree. The mailbox then has a bounce record of its own
//	         there, bounces+<token>@b.<domain> under a token of its own, in the network's mailcfg, which receivers
//	         resolve when a DSN reaches them through the custom MX. A From outside the set, the network's own zones'
//	         and a burner's above all, keeps b.<net>.<root>. BounceSender reads the set at each call, and the
//	         sender asks it again at each connection (SmtpSenderArgs.Envelope), so a message queued before its
//	         domain's strict-mode MX host was mapped or unmapped sends at the envelope the edge derives now. Mapping
//	         that MX host moves the envelope whether or not mail.strict is signed yet
//
// On every leg but the extension's, the page Worker's included, which reads the address and queues nothing. Nothing
// here logs an address, a domain or a token (I-13).

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

// bounces+<token>@b.<domain>, domain a custom domain in strict mode (the file header's strict row).
func MailBounceCustomAddress(domain string, token string) string {
	return mailBouncePrefix + token + "@" + mailBounceLabel + "." + domain
}

// A fresh bounce token: see the file header's token row.
func newMailBounceToken() string {
	token := NewEvsRandomToken()
	return mailBinaryName(token[:mailBounceTokenByteCount])
}

// This device's member's mailbox's bounce address at b.<net>.<root>: the envelope sender of its internet mail From the
// network's own zones, and what a DSN that names no To is filed under. The honored bounce record naming the mailbox
// there, made if there is none (see the file header). ErrMailNoMailbox for a device with no mailbox of its own.
func (self *MailClient) BounceRecipient(ctx context.Context) (string, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return "", err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return "", err
	}
	return self.bounceAddress(ctx, config, mailboxId, "")
}

// The envelope sender of internet mail whose header From is in fromDomain (the file header's strict row): this
// device's member's mailbox's bounce address at b.<fromDomain> where GET /mail/status names fromDomain in strict mode,
// and at b.<net>.<root> otherwise, made if there is none. The set is read at each call for a From outside the root,
// and never for one under it, which no set moves; a read that fails is the call's error, so the caller holds the send
// rather than guess an envelope the edge could refuse. ErrMailNoMailbox for a device with no mailbox of its own.
func (self *MailClient) BounceSender(ctx context.Context, fromDomain string) (string, error) {
	binding, _, err := self.bound()
	if err != nil {
		return "", err
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return "", err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return "", err
	}
	zone, _, err := config.zone()
	if err != nil {
		return "", err
	}
	fromDomain = strings.TrimSuffix(dnsAsciiLower(fromDomain), ".")
	strictDomain := ""
	if fromDomain != "" && !mailNameUnder(fromDomain, zone.Root) {
		if binding.Api == nil {
			return "", fmt.Errorf("%w: no api to read the strict domains through", ErrMailUnbound)
		}
		status, err := binding.Api.MailStatus(ctx)
		if err != nil {
			return "", err
		}
		strictDomain = SmtpStrictCustomDomain(fromDomain, status.StrictDomains, zone.Root)
	}
	return self.bounceAddress(ctx, config, mailboxId, strictDomain)
}

// mailboxId's honored bounce address in config under b.<strictDomain>, or under b.<net>.<root> for "", made with a
// fresh token where config holds none.
func (self *MailClient) bounceAddress(ctx context.Context, config *MailConfig, mailboxId Id, strictDomain string) (string, error) {
	zone, _, err := config.zone()
	if err != nil {
		return "", err
	}
	bounceDomain := mailBounceLabel + "." + zone.Domain()
	if strictDomain != "" {
		bounceDomain = mailBounceLabel + "." + strictDomain
	}
	if address, ok := mailBounceAddressOf(config, mailboxId, bounceDomain); ok {
		return address, nil
	}
	var lookup *MailAddressLookup
	if strictDomain == "" {
		lookup, err = config.CreateBounceAddress(ctx, mailboxId, newMailBounceToken())
	} else {
		lookup, err = config.CreateCustomBounceAddress(ctx, mailboxId, newMailBounceToken(), strictDomain)
	}
	if err != nil {
		return "", err
	}
	if !lookup.Known {
		// a creation policy does not honor delivers nothing
		return "", ErrMailConfigNoGrant
	}
	return lookup.Address, nil
}

// The first honored bounce address naming mailboxId in config under bounceDomain, b.<net>.<root> or b.<domain>, in
// address order.
func mailBounceAddressOf(config *MailConfig, mailboxId Id, bounceDomain string) (string, bool) {
	lookups, err := config.Addresses()
	if err != nil {
		return "", false
	}
	addresses := []string{}
	for _, lookup := range lookups {
		if !lookup.Known || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE || lookup.MailboxRepoId != mailboxId {
			continue
		}
		if _, domain, found := strings.Cut(lookup.Address, "@"); found && domain == bounceDomain {
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
	return self.createBounceRecord(ctx, mailboxRepoId, name)
}

// Creates the bounce record bounces+<token>@b.<domain> for mailboxRepoId, domain a custom domain in strict mode outside
// the root (the file header's strict row), created only if absent as CreateBounceAddress's record is, and in the
// network's own mailcfg alone. Whether domain is in strict mode is the caller's to have read: a record under a domain
// that never was holds no mail, since nothing is sent with that envelope.
func (self *MailConfig) CreateCustomBounceAddress(ctx context.Context, mailboxRepoId Id, token string, domain string) (*MailAddressLookup, error) {
	if mailboxRepoId == (Id{}) || !validMailToken(token) || strings.Contains(token, "/") {
		return nil, fmt.Errorf("%w: no bounce address", ErrMailConfigInvalid)
	}
	zone, _, err := self.zone()
	if err != nil {
		return nil, err
	}
	if zone.Scope != "" {
		return nil, fmt.Errorf("%w: a scope has no bounce zone", ErrMailConfigInvalid)
	}
	address := MailBounceCustomAddress(domain, token)
	// a domain under the root would name one of the network's own bounce zones
	if _, err := ParseMailCustomBounceRecipient(zone.Root, address); err != nil {
		return nil, fmt.Errorf("%w: no bounce address of a custom domain", ErrMailConfigInvalid)
	}
	name, ok := mailConfigAddressName(zone, address)
	if !ok {
		return nil, fmt.Errorf("%w: no bounce address of a custom domain", ErrMailConfigInvalid)
	}
	return self.createBounceRecord(ctx, mailboxRepoId, name)
}

// Writes the bounce record at name for mailboxRepoId, created only if absent, and answers it as a lookup does.
func (self *MailConfig) createBounceRecord(ctx context.Context, mailboxRepoId Id, name *mailConfigName) (*MailAddressLookup, error) {
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
