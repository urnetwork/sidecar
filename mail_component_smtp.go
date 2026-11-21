//go:build !sidecar_http && !ios_extension && !js

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// Registers the desktop sender factory with the mail component.
func init() {
	mailSidecarSenderFactory = newMailSidecarSender
}

// Builds the desktop sender over the generation's actual socket, own DNS and HTTPS transports, and encrypted mailbox.
func newMailSidecarSender(client *MailClient, run *mailComponentRun, memberId, mailboxId Id) (*mailComponentSmtp, error) {
	sidecar := client.sidecar
	env := run.env
	root := client.networkRow().Root
	if env == nil || env.SidecarApi == nil || env.Subprotocol == nil || sidecar.instance == nil || root == "" {
		return nil, ErrMailUnbound
	}
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
	doh := connect.NewDohCache(connect.DefaultDohSettings())
	pins := NewSmtpPinStore(store, settings, clock, client.log)
	policy := NewSmtpTlsPolicy(NewSmtpDane(nil, clock, nil), NewSmtpMtaSts(doh, env.SidecarApi.Transport(), store, settings, clock),
		pins, NewSmtpTlsAllowanceStore(store, settings, clock), sidecar, doh, nil, settings, clock)
	dkim := NewSmtpDkimKeys(sidecar.instance.secrets(client.networkId, SmtpDkimSecretsNamespace), env.SidecarApi, settings, clock, client.log)
	dkim.SetDomainAnswers(&SmtpDkimDomainAnswers{Doh: doh, Root: root})
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
		doh.Close()
		return nil, err
	}
	hold := NewSmtpStatusHold(settings, clock)
	runner, err := NewSmtpOutboxRunner(&SmtpOutboxRunnerArgs{
		Sender: sender, Mailbox: mailbox, SidecarId: client.sidecarId, MemberDeviceKey: memberKey,
		Consented: consented, OwnCap: host.Cap, Hold: hold, Settings: settings, Clock: clock, Log: client.log,
	})
	if err != nil {
		sender.Close()
		doh.Close()
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
		doh.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(run.ctx)
	var workers sync.WaitGroup
	workers.Go(func() { host.Run(ctx) })
	workers.Go(func() { runner.Run(ctx, wake) })
	return &mailComponentSmtp{
		memberId: memberId, mailboxId: mailboxId, sender: sender, dkim: dkim,
		close: func() {
			cancel()
			remove()
			sender.Close()
			workers.Wait()
			doh.Close()
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
