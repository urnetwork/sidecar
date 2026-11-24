//go:build !sidecar_http && !ios_extension && !js

// The desktop sender the mail component starts on a consented prover host (§14, §15.10's step 4; MAIL-M9-01): its
// prover host, the member's outbox runner and an SmtpSender over the generation's ur/smtpedge socket, the API's HTTPS
// transport for MTA-STS policies, the device's DKIM keys and the member's encrypted mailbox, with every DNS lookup it
// makes from the device over a resolver of its own (mail_sender_resolver.go; CODESTYLE's DoH rule: one owner, one
// cache): TL2's _mta-sts lookup, TL3's MX lookup and the DKIM domain answers, and the anchors TL1 validates to.
//
// The resolver is what MailSendSettings.ResolverFactory builds, else a DohCache over connect's default resolvers,
// public ones (§2.8 ext-3), under the DNS root's keys. In a test binary that default is refused before any part is
// built (ErrMailSenderPublicResolver): testing.Testing reads true only in a binary go test linked, so production's
// senders ask what they always have, while a test that would query public resolvers from the test host gets no sender,
// and so dials nothing, until it names its own DNS.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// Registers the desktop sender factory with the mail component.
func init() {
	mailSidecarSenderFactory = newMailSidecarSender
}

// The resolver a sender on settings asks: settings' ResolverFactory's, else a DohCache of the sender's own over
// connect's default resolvers, under the DNS root's keys. inTest, a test binary's, refuses that default with
// ErrMailSenderPublicResolver before anything is built. A factory's error comes back as it was given, and a resolver
// without its Doh is refused, released first.
func newMailSenderResolver(settings *MailSendSettings, inTest bool) (*MailSenderResolver, error) {
	if settings != nil && settings.ResolverFactory != nil {
		resolver, err := settings.ResolverFactory()
		if err != nil {
			return nil, err
		}
		if resolver == nil || resolver.Doh == nil {
			if resolver != nil && resolver.Close != nil {
				resolver.Close()
			}
			return nil, fmt.Errorf("%w: a sender's resolver with no Doh", ErrMailClientInvalid)
		}
		return resolver, nil
	}
	if inTest {
		return nil, ErrMailSenderPublicResolver
	}
	cache := connect.NewDohCache(connect.DefaultDohSettings())
	return &MailSenderResolver{Doh: cache, Close: cache.Close}, nil
}

// Builds the desktop sender over the generation's actual socket, own DNS and HTTPS transports, and encrypted mailbox:
// its resolver first, so one a test binary refuses builds nothing, then every part over it. A part that fails ends
// what was built before it, the resolver last; a built sender's close ends its workers, then releases the resolver.
func newMailSidecarSender(client *MailClient, run *mailComponentRun, memberId, mailboxId Id) (*mailComponentSmtp, error) {
	sidecar := client.sidecar
	env := run.env
	root := client.networkRow().Root
	if env == nil || env.SidecarApi == nil || env.Subprotocol == nil || sidecar.instance == nil || root == "" {
		return nil, ErrMailUnbound
	}
	// the one guarded resolver every lookup of this sender asks, which a test binary must name
	resolver, err := newMailSenderResolver(client.sendSettings(), testing.Testing())
	if err != nil {
		return nil, err
	}
	release := func() {
		if resolver.Close != nil {
			resolver.Close()
		}
	}
	composed := false
	defer func() {
		if !composed {
			release()
		}
	}()
	mailbox, err := client.SmtpMailbox()
	if err != nil {
		return nil, err
	}
	store, err := sidecar.LocalStore().Directory("smtp", "smtp")
	if err != nil {
		return nil, err
	}
	settings := client.smtpSenderSettings()
	clock := client.clock
	prover := sidecar.settings.Connect.SmtpProver
	memberKey := func(id Id) ed25519.PublicKey {
		_, _, state, err := client.state()
		if err != nil || !state.ConsentedFor(client.sidecarId, memberId) || !state.ConsentedFor(id, memberId) {
			return nil
		}
		device := state.sidecarState(id)
		if device == nil || device.facts == nil {
			return nil
		}
		key := device.facts.Row.GetIdentityPublicKey()
		if len(key) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(bytes.Clone(key))
	}
	consented := func() bool {
		return run.ctx.Err() == nil && client.smtpEnabledLocally() && memberKey(client.sidecarId) != nil
	}
	host, err := NewSmtpProverHost(&SmtpProverHostArgs{
		Prover: prover, Mailbox: mailbox, SidecarId: client.sidecarId, MailEnabled: consented,
		Settings: settings, Clock: clock, Log: client.log,
	})
	if err != nil {
		return nil, err
	}
	pins := NewSmtpPinStore(store, settings, clock, client.log)
	policy := NewSmtpTlsPolicy(NewSmtpDane(resolver.Anchors, clock, nil), NewSmtpMtaSts(resolver.Doh, env.SidecarApi.Transport(), store, settings, clock),
		pins, NewSmtpTlsAllowanceStore(store, settings, clock), sidecar, resolver.Doh, nil, settings, clock)
	dkim := NewSmtpDkimKeys(sidecar.instance.secrets(client.networkId, SmtpDkimSecretsNamespace), env.SidecarApi, settings, clock, client.log)
	dkim.SetDomainAnswers(&SmtpDkimDomainAnswers{Doh: resolver.Doh, Root: root})
	sender, err := NewSmtpSender(&SmtpSenderArgs{
		Dialer: NewSidecarSmtpEdgeDialer(sidecar, settings), Prover: prover, Policy: policy, Pins: pins, Dkim: dkim,
		Mailbox: mailbox, MemberDevice: func(id Id) bool { return memberKey(id) != nil },
		Measure: host.Measure, ReadyKeySets: host.ReadyKeySets, SendHold: host.HoldForSend,
		Envelope: client.BounceSender, Events: sidecar.emitEvent, ReachGrant: client.smtpReachGrant,
		Reach: func(note *RecordReachNote) error {
			record, err := sidecar.Record()
			if err != nil {
				return err
			}
			return record.Reach().Note(note)
		},
		Settings: settings, Clock: clock, Log: client.log,
	})
	if err != nil {
		return nil, err
	}
	hold := NewSmtpStatusHold(settings, clock)
	runner, err := NewSmtpOutboxRunner(&SmtpOutboxRunnerArgs{
		Sender: sender, Mailbox: mailbox, SidecarId: client.sidecarId, MemberDeviceKey: memberKey,
		Consented: consented, OwnCap: host.Cap, Hold: hold, Settings: settings, Clock: clock, Log: client.log,
	})
	if err != nil {
		sender.Close()
		return nil, err
	}
	wake := make(chan struct{}, 1)
	remove, err := env.Subprotocol.Subscribe(PushTopicMail, func(notice PushNotice) {
		hold.Notice(notice)
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	if err != nil {
		sender.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(run.ctx)
	var workers sync.WaitGroup
	workers.Go(func() { host.Run(ctx) })
	workers.Go(func() { runner.Run(ctx, wake) })
	composed = true
	return &mailComponentSmtp{
		memberId: memberId, mailboxId: mailboxId, sender: sender, dkim: dkim,
		close: func() {
			cancel()
			remove()
			sender.Close()
			workers.Wait()
			release()
		},
	}, nil
}

// The device-local grant for this message's From alias at the verified policy position.
func (self *MailClient) smtpReachGrant(outbound *SmtpOutboundMessage) *SmtpReachGrant {
	binding, _, state, err := self.state()
	if err != nil {
		return nil
	}
	from, _, _ := smtpMessageDomains(outbound.Message)
	local, _, ok := SplitSmtpEnvelopeAddress(from)
	if !ok {
		return nil
	}
	decision := binding.Engine.AllowAlias(AclSidecarSubject(self.sidecarId), protocol.AclAction_ACL_ACTION_SEND, local, self.clock.Now())
	if !decision.Allowed || state != binding.Engine.State() || len(decision.Rule.GetRuleId()) != sha256.Size {
		return nil
	}
	return &SmtpReachGrant{GrantId: bytes.Clone(decision.Rule.GetRuleId()), PolicyVersion: state.Pin().GetVersion()}
}
