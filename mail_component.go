//go:build !sidecar_http && !ios_extension

// The mail SidecarComponent (§5.4, §15.5-§15.7; MAIL-M7-17): MailClient on a Sidecar's client generations, Name()
// "mail". Each pass, at attach, at each change the client hears of (an enable, the network's status turning mail on)
// and every CheckInterval:
//
//	bind      what the Sidecar holds as it stands (MailBinding): the evs component's EvsClient, with its key client
//	          and statement poster, the config follower's AclEngine, the zone's row from the DnsClient, the Sidecar as
//	          the outward-action gate, the generation's SidecarApi for the mail routes, and the opener of the
//	          designations' sealed services over the key client's config keys (owner decision 634). A host that bound
//	          its own (MailClient made without a Sidecar) keeps it
//	follow    mailcfg, through MailConfig, which follows its repo itself once built
//	send      on a locally enabled, consented prover host, prepare the release keys and drain the member's outbox;
//	          elsewhere, or where its composition fails, Status says why no sender runs (MailClientSenderStatus)
//	ingest    the member's mailbox: one MailIngestor running while the generation lives (MAIL-M7-15)
//	groups    each group repo this device ingests or references a goroutine of its own, its passes brought by the
//	          repo's hints, as the mailbox's ingest's are, and by each pass, the fallback (mail_component_group.go)
//	receive   once mail is on, the receive settings say receive, and policy grants this device the listen on
//	          smtp/25/mx, one receiver (mail_receiver.go) with its sessions (mail_session.go) on the legs that build
//	          them (mail_component_receive.go): started once, retrying its listen itself, ended with the generation or
//	          once mail turns off or the grant goes. Revoking the receiver ends its listen at once
//	mta-sts   while the receiver listens and the device holds a §13 certificate for the network's pair, §15.5's
//	          MTA-STS policy as this receiver's system publish (mail_mta_sts.go), ended with the receiver
//	outcomes  while mail is on, once an OutcomeSweepInterval, the member's or/ records past their 30 days are removed
//	          (§15.7; MAIL-M9-02); and a send watch reads or/ as it changes, raising mail_send for each outcome that
//	          changed (§15.10's step 4; QD-1122, mail_send_result.go)
//	idle      Active while mail is on, so a daemon with mail on never idles out (§5.8); `ur status` says so and
//	          prompts for a mail indexer until one stands (§15.6)
//
// connect legs only: the page Worker runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	_ SidecarComponent       = (*MailClient)(nil)
	_ SidecarActiveComponent = (*MailClient)(nil)
	_ SidecarRestorer        = (*MailClient)(nil)
)

// This Sidecar's mail with its component attached, so a network with mail on keeps its daemon up from the start
// (§5.8): what a host that runs components calls for each network it hosts. A second call answers the same client.
func (self *Sidecar) StartMail() (*MailClient, error) {
	client, err := self.Mail()
	if err != nil {
		return nil, err
	}
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil, fmt.Errorf("%w: this Sidecar runs no components", ErrSidecarClosed)
	}
	if leg.listed(mailComponentName) {
		return client, nil
	}
	if _, err := self.AddComponent(client); err != nil && !leg.listed(mailComponentName) {
		return nil, err
	}
	return client, nil
}

// What builds a receiver over a Sidecar, on the legs whose sessions build (mail_component_receive.go); nil on the js
// leg, which runs no receiver.
var mailSidecarReceiverFactory func(sidecar *Sidecar) mailReceiverFactory

// Desktop and native hosts install the SMTP composition. Other hosts keep using the member's outbox.
var mailSidecarSenderFactory func(*MailClient, *mailComponentRun, Id, Id) (*mailComponentSmtp, error)

// One member mailbox's sender and workers, owned by this component generation.
type mailComponentSmtp struct {
	mailboxId Id
	memberId  Id
	sender    *SmtpSender
	dkim      *SmtpDkimKeys
	close     func()
}

// Builds a receiver for the component, and what closes its parts once the receiver has ended.
type mailReceiverFactory func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error)

// What a receiver is built over.
type mailReceiverFactoryArgs struct {
	// The signed network-scope mail designation of this daemon, checked before each direct bind.
	DirectMxEligible func() bool
	Evs              *EvsClient
	Config           *MailConfig
	Api              MailApi
	Store            SidecarStore
	Settings         *MailReceiveSettings
	Clock            Clock
	Log              Logger
}

// One generation's running parts, under the client's stateLock.
type mailComponentRun struct {
	env    *SidecarEnv
	ctx    context.Context
	cancel context.CancelFunc
	// the ingestor running and its repo
	ingestRepoId Id
	ingestCancel context.CancelFunc
	ingestor     *MailIngestor
	// each group repo's goroutine, by repo (mail_component_group.go)
	groupInboxes map[Id]*mailGroupInbox
	// the receiver running, what ends it, and what closes its parts after
	receiver       *MailReceiver
	receiverCancel context.CancelFunc
	receiverClose  func()
	// the receiver's MTA-STS system publish while it serves one, and when a refused one is tried again
	mtaSts          io.Closer
	mtaStsRetryTime time.Time
	// when the member's or/ is next swept for records past their days
	outcomeSweepTime time.Time
	smtp             *mailComponentSmtp
}

// What the component keeps on the client beside its run: a test's seams.
type mailComponentSeams struct {
	// whether policy grants this device the receiver's listen; nil asks the bound engine
	mayReceive func() bool
	// builds the receiver; nil asks mailSidecarReceiverFactory over the client's Sidecar
	factory mailReceiverFactory
	// whether this device registers a listener by its own choice (MailReceiverEligible); nil asks the bound config
	eligible func() bool
	// serves the receiver's MTA-STS system publish; nil serves through the client's Sidecar
	mtaSts mailMtaStsPublisher
}

// "mail".
func (self *MailClient) Name() string {
	return mailComponentName
}

// Follows one generation: its passes run until env.Ctx ends. A generation of another network is refused.
func (self *MailClient) Attach(env *SidecarEnv) error {
	if env == nil || env.Identity == nil || env.Identity.NetworkId != self.networkId {
		return fmt.Errorf("%w: mail needs a generation of its own network", ErrMailClientInvalid)
	}
	ctx, cancel := context.WithCancel(env.Ctx)
	run := &mailComponentRun{env: env, ctx: ctx, cancel: cancel}
	previous := func() *mailComponentRun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous, _ := self.componentRun.(*mailComponentRun)
		self.componentRun = run
		return previous
	}()
	if previous != nil {
		previous.cancel()
	}
	go self.runGeneration(run)
	return nil
}

// Ends the component for good: the running generation's parts, then what the client built.
func (self *MailClient) Close() {
	run := func() *mailComponentRun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run, _ := self.componentRun.(*mailComponentRun)
		self.componentRun = nil
		return run
	}()
	if run != nil {
		run.cancel()
	}
	self.closeParts()
}

// Whether mail is on, which keeps a daemon from idling out (§5.8).
func (self *MailClient) Active() bool {
	return self.Enabled()
}

// restore_required's step for mail (§19.10): the receiver posts its host key's TLSA again. Nil with no receiver.
func (self *MailClient) Reregister(ctx context.Context) error {
	receiver := func() *MailReceiver {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if run, ok := self.componentRun.(*mailComponentRun); ok {
			return run.receiver
		}
		return nil
	}()
	if receiver == nil {
		return nil
	}
	return receiver.Reregister(ctx)
}

// The client's seams, nil for none.
func (self *MailClient) seams() *mailComponentSeams {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	seams, _ := self.componentSeams.(*mailComponentSeams)
	return seams
}

// A generation's passes until it ends, then its parts stopped.
func (self *MailClient) runGeneration(run *mailComponentRun) {
	defer self.stopRun(run)
	for {
		changed := func() chan struct{} {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.changed
		}()
		wait := self.settings.CheckInterval
		if !self.pass(run) {
			wait = self.settings.UnboundCheckInterval
		}
		select {
		case <-run.ctx.Done():
			return
		case <-changed:
		case <-self.clock.After(wait):
		}
	}
}

// Stops what run started: its MTA-STS publish, its sender, its group repos' goroutines, which it joins, its ingestor
// and its receiver, whose parts close after.
func (self *MailClient) stopRun(run *mailComponentRun) {
	self.stopMtaSts(run)
	self.replaceSmtp(run, nil)
	self.stopGroupInboxes(run)
	ingestCancel, receiverCancel, receiverClose := func() (context.CancelFunc, context.CancelFunc, func()) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ingestCancel, receiverCancel, receiverClose := run.ingestCancel, run.receiverCancel, run.receiverClose
		run.ingestCancel, run.receiverCancel, run.receiverClose, run.receiver, run.ingestor = nil, nil, nil, nil, nil
		return ingestCancel, receiverCancel, receiverClose
	}()
	if ingestCancel != nil {
		ingestCancel()
	}
	if receiverCancel != nil {
		receiverCancel()
	}
	if receiverClose != nil {
		receiverClose()
	}
	self.setReceiverStatus(run, MailClientReceiverStatus{})
	self.setSenderStatus(run, MailClientSenderStatus{})
}

// One pass: see the file header. False while the client has nothing to work on yet.
func (self *MailClient) pass(run *mailComponentRun) bool {
	ctx := run.ctx
	self.bindFromSidecar(ctx, run.env)
	binding, _, err := self.bound()
	if err != nil {
		self.replaceSmtp(run, nil)
		self.setReceiverStatus(run, MailClientReceiverStatus{Problem: "mail has nothing to work on yet"})
		self.setSenderStatus(run, MailClientSenderStatus{Problem: "mail has nothing to work on yet"})
		return false
	}
	if binding.Api != nil {
		if network, err := binding.Api.MailStatus(ctx); err == nil {
			self.setNetworkEnabled(network.Enabled)
		}
	}
	self.passSmtp(run, binding)
	self.passIngest(run, binding)
	self.passReceive(run, binding)
	self.passMtaSts(run, binding)
	self.passOutcomes(run)
	self.passGroupInboxes(run, binding)
	if binding.BurnerSelectors != nil {
		// a burn another device made retires this device's selectors for the label too (MAIL-M9-03)
		if _, err := self.RetireBurnedSelectors(ctx); err != nil {
			self.log.Warningf("[mail]burned labels' selectors did not all retire: %v", err)
		}
	}
	return true
}

// Whether this device explicitly enabled mail. Only such a device may fetch proof transcripts.
func (self *MailClient) smtpEnabledLocally() bool {
	self.loadEnabled()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.enabledLocally
}

// Starts the sending workers only for a consented member device with a prover and its own mailbox, and keeps why none
// run where they do not (MailClientSenderStatus): the gate this device does not pass, or the error the composition
// answered, which the next pass asks again.
func (self *MailClient) passSmtp(run *mailComponentRun, binding *MailBinding) {
	if self.sidecar == nil || self.sidecar.settings == nil || self.sidecar.settings.Connect == nil || mailSidecarSenderFactory == nil {
		self.setSenderStatus(run, MailClientSenderStatus{Problem: "this host composes no sender"})
		return
	}
	if self.sidecar.settings.Connect.SmtpProver == nil {
		self.setSenderStatus(run, MailClientSenderStatus{Problem: "this device is no prover host: its internet mail waits in the member's outbox for one"})
		return
	}
	memberId, mailboxId, why := func() (Id, Id, string) {
		state := binding.Engine.State()
		if state == nil {
			return Id{}, Id{}, "mail has nothing to work on yet"
		}
		if !self.smtpEnabledLocally() {
			if !self.Enabled() {
				return Id{}, Id{}, "mail is off"
			}
			return Id{}, Id{}, "mail was enabled on another device: ur mail enable on this one sends from it"
		}
		memberId, ok := mailMemberOf(state, self.sidecarId)
		if !ok {
			return Id{}, Id{}, "this device sends for no member: it is tagged, or the verified state does not admit it"
		}
		if !state.ConsentedFor(self.sidecarId, memberId) {
			return Id{}, Id{}, "this device is not a consented device of its member"
		}
		mailboxId, err := self.mailboxId()
		if err != nil {
			return Id{}, Id{}, err.Error()
		}
		return memberId, mailboxId, ""
	}()
	if why != "" {
		self.replaceSmtp(run, nil)
		self.setSenderStatus(run, MailClientSenderStatus{Problem: why})
		return
	}
	if run.smtp != nil && run.smtp.mailboxId == mailboxId && run.smtp.memberId == memberId {
		self.setSenderStatus(run, MailClientSenderStatus{Running: true})
		return
	}
	self.replaceSmtp(run, nil)
	smtp, err := mailSidecarSenderFactory(self, run, memberId, mailboxId)
	if err != nil {
		if run.ctx.Err() == nil && self.log.V(1).Enabled() {
			self.log.Infof("[mail]SMTP sender is waiting for its dependencies: %v", err)
		}
		self.setSenderStatus(run, MailClientSenderStatus{Problem: err.Error()})
		return
	}
	self.replaceSmtp(run, smtp)
	self.setSenderStatus(run, MailClientSenderStatus{Running: true})
}

// Replaces the generation-owned binding and joins the old workers without holding the client lock.
func (self *MailClient) replaceSmtp(run *mailComponentRun, next *mailComponentSmtp) {
	self.stateLock.Lock()
	previous := run.smtp
	run.smtp = next
	if self.binding != nil && (previous != nil && self.binding.Sender == previous.sender || next != nil && self.componentRun == run) {
		current := *self.binding
		if previous != nil && current.Sender == previous.sender {
			current.Sender, current.BurnerSelectors = nil, nil
		}
		if next != nil && self.componentRun == run {
			current.Sender, current.BurnerSelectors = next.sender, next.dkim
		}
		self.binding = &current
	}
	self.stateLock.Unlock()
	if previous != nil {
		previous.close()
	}
}

// Binds what the client's Sidecar holds as it stands, where the client was made over a Sidecar.
func (self *MailClient) bindFromSidecar(ctx context.Context, env *SidecarEnv) {
	sidecar := self.sidecar
	if sidecar == nil {
		return
	}
	binding := &MailBinding{Gate: sidecar}
	if evs := sidecar.EvsClient(); evs != nil {
		binding.Evs = evs
		binding.Gkm = evs.args.Gkm
		binding.FileStatement = evs.args.FileStatement
	}
	if follower := sidecar.ConfigFollower(); follower != nil {
		binding.Engine = follower.AclEngine()
	}
	if env != nil && env.SidecarApi != nil {
		binding.Api = env.SidecarApi
		// internet mail's send gate reads the standing before anything is queued (D-SMTP-14)
		binding.Standing = env.SidecarApi.AbuseStatus
	}
	// an outbox entry is signed by this device's identity key (plan-SMTP-wire-gaps#4)
	binding.Sign = func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return sidecar.Sign(purpose, signedType, body, nil)
	}
	binding.RunTainted = sidecar.RunTainted
	// a mail search and IMAP SEARCH run on the Sidecar's engine, which answers unavailable until a host installs one
	binding.Search = sidecar.Search
	if dns, err := sidecar.Dns(); err == nil {
		if zone, err := dns.Zone(ctx); err == nil {
			self.setNetworkRow(NetworkLabelRow{
				Root:      strings.TrimSuffix(zone.Root, "."),
				NetworkId: zone.NetworkId,
				Label:     zone.Label,
				Alias:     zone.Alias,
			})
			// what a burner label must not shadow, as this pass read it
			publishedHosts := mailBurnerPublishedLabels(zone)
			binding.PublishedHosts = func() []string { return publishedHosts }
		}
	}
	binding.Network = self.networkRow
	binding.Config = sidecar.configState
	binding.Designator = sidecar
	if gkm := binding.Gkm; gkm != nil {
		binding.ConfigKey = func(ctx context.Context) (*EvsRepoKey, error) {
			state, err := sidecar.configState()
			if err != nil {
				return nil, err
			}
			acl, err := state.Acl()
			if err != nil {
				return nil, err
			}
			configRepoId, ok := acl.ConfigRepoId()
			if !ok {
				return nil, errors.New("no config repo in the verified state")
			}
			return gkm.CurrentRepoKey(ctx, configRepoId)
		}
	}
	binding.Event = sidecar.emitEvent
	// a designation's services open with the config repo's keys the evs component's GkmClient holds, under the network
	// id and the nonce its row carries (owner decision 634), so coverage, the prompt, the undesignated-receiver alarm
	// and a tag:mail device's registration read them; with no key client none open, and the designations stay unknown
	// (mail_indexer.go)
	binding.IndexerServices = mailIndexerServicesOver(ctx, binding.Gkm, binding.Config, self.settings.IndexerKeyTimeout)
	binding.MailIndexer = func() (bool, error) {
		state, err := sidecar.configState()
		if err != nil {
			return false, err
		}
		return mailIndexerCovers(state, self.sidecarId, binding.IndexerServices)
	}
	self.bindWhen(binding, func(current *MailBinding) bool {
		if env == nil {
			return true
		}
		run, ok := self.componentRun.(*mailComponentRun)
		if !ok || run.env != env || run.ctx.Err() != nil {
			return false
		}
		if run.smtp != nil {
			current.Sender, current.BurnerSelectors = run.smtp.sender, run.smtp.dkim
		}
		return true
	})
}

// Starts the member's mailbox's ingestor, or moves it to a new mailbox, once the mailbox stands.
func (self *MailClient) passIngest(run *mailComponentRun, binding *MailBinding) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return
	}
	_, parts, err := self.bound()
	if err != nil {
		return
	}
	running := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return run.ingestCancel != nil && run.ingestRepoId == mailboxId
	}()
	if running {
		return
	}
	ingestor, err := parts.ingestor(mailboxId, self.ingestArgs(run, binding))
	if err != nil {
		self.log.Warningf("[mail]no ingestor for the mailbox: %v", err)
		return
	}
	ingestCtx, ingestCancel := context.WithCancel(run.ctx)
	previous := func() context.CancelFunc {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous := run.ingestCancel
		run.ingestCancel = ingestCancel
		run.ingestRepoId = mailboxId
		run.ingestor = ingestor
		return previous
	}()
	if previous != nil {
		previous()
	}
	go ingestor.Run(ingestCtx)
}

// Both the personal inbox and group repositories judge deposits at their signed pins.
func (self *MailClient) ingestArgs(run *mailComponentRun, binding *MailBinding) *MailIngestArgs {
	root := self.networkRow().Root
	return &MailIngestArgs{
		SidecarId: self.sidecarId,
		Root:      root,
		Authority: &MailIngestAclAuthority{
			Engine: binding.Engine,
			Root:   root,
			OwnZone: func(zone MailZone) bool {
				return zone.OfNetwork(self.networkRow())
			},
			CustomFrom: func(address string) (MailRecipient, bool) {
				from, _, err := mailVerifiedCustomFrom(run.ctx, binding.Api, self.networkRow(), address)
				return from, err == nil
			},
			Clock: self.clock,
		},
		Message: func(message *MailMessage) {
			self.invalidateMonth(message.RepoId, message.Month)
			self.judgeReceiver(binding, message)
			// an opted-in burner's mail forwarded, and a reply to a reverse alias relayed (MAIL-M9-04)
			if _, err := self.considerForward(run.ctx, message); err != nil {
				self.log.Warningf("[mail]a forward was not queued: %v", err)
			}
		},
		Alarm: func(alarm *MailIngestAlarm) {
			self.log.Warningf("[mail]ingest alarm %s on %s", alarm.Kind, alarm.RepoId)
			self.raiseReceiverAlarm(SidecarMailReceiverAlarmDeposit, alarm.DepositorId, alarm.RepoId)
		},
		Clock:    self.clock,
		Log:      self.log,
		Settings: self.settings.Ingest,
	}
}

// Drops the view's kept month where the mailbox's ingest wrote, so the next list reads it afresh, and raises IDLE's
// hint.
func (self *MailClient) invalidateMonth(repoId Id, month MailYearMonth) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if view := self.views[repoId]; view != nil {
			view.InvalidateMonth(month)
		}
	}()
	self.invalidateSearchJoin()
	// a message written here is IDLE's hint (mail_imap.go)
	self.imapHints.Update(func(revision uint64) uint64 { return revision + 1 })
}

// Whether policy grants this device the receiver's listen on smtp/25/mx at the installed state.
func (self *MailClient) mayReceive(binding *MailBinding) bool {
	if seams := self.seams(); seams != nil && seams.mayReceive != nil {
		return seams.mayReceive()
	}
	state := binding.Engine.State()
	if state == nil {
		return false
	}
	return state.MayListen(AclSidecarSubject(self.sidecarId), AclSocketName{PublicName: aclMailReceiverName}, self.clock.Now()).Allowed
}

// Whether this device registers a receiver's listener by its own choice at the bound config (MailReceiverEligible):
// a host that binds no config gates nothing here, policy's grant of the listen deciding alone.
func (self *MailClient) receiverEligible(binding *MailBinding) bool {
	if seams := self.seams(); seams != nil && seams.eligible != nil {
		return seams.eligible()
	}
	if binding.Config == nil {
		return true
	}
	state, err := binding.Config()
	if err != nil {
		return false
	}
	return MailReceiverEligible(state, self.sidecarId, binding.IndexerServices)
}

// Starts the receiver where mail is on, receive is set and the listen is granted; ends it where any of those stops.
func (self *MailClient) passReceive(run *mailComponentRun, binding *MailBinding) {
	why := ""
	switch {
	case !self.Enabled():
		why = "mail is off"
	case self.settings.Receive == nil || !self.settings.Receive.Enabled:
		why = "this device does not receive"
	case !self.mayReceive(binding):
		why = "policy grants this device no listen on smtp/25/mx"
	case !self.receiverEligible(binding):
		why = "under team_mail: indexers a tag:mail device registers no listener until an IndexerSet designates it for mail"
	case self.inBackground():
		why = "an app listens only while it is open"
	}
	receiver := func() *MailReceiver {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return run.receiver
	}()
	if why != "" {
		if receiver != nil {
			self.stopReceiver(run)
		}
		self.setReceiverStatus(run, MailClientReceiverStatus{Problem: why})
		return
	}
	if receiver == nil {
		var err error
		receiver, err = self.startReceiver(run, binding)
		if err != nil {
			self.setReceiverStatus(run, MailClientReceiverStatus{Problem: err.Error()})
			return
		}
	}
	status := receiver.Status()
	self.setReceiverStatus(run, MailClientReceiverStatus{
		Running:    true,
		Listening:  status.Listening,
		Serving:    status.Serving,
		ApprovalId: status.ApprovalId,
		Problem:    status.Problem,
	})
}

// Builds and starts the receiver for run. Its first listen's waiting on a person is no error here: the receiver asks
// again itself, and Status says what it waits on.
func (self *MailClient) startReceiver(run *mailComponentRun, binding *MailBinding) (*MailReceiver, error) {
	factory := mailReceiverFactory(nil)
	if seams := self.seams(); seams != nil && seams.factory != nil {
		factory = seams.factory
	} else if self.sidecar != nil && mailSidecarReceiverFactory != nil {
		factory = mailSidecarReceiverFactory(self.sidecar)
	}
	if factory == nil {
		return nil, errors.New("this host builds no receiver")
	}
	if binding.Api == nil {
		return nil, errors.New("no api to read the network's limits through")
	}
	config, err := self.mailConfig()
	if err != nil {
		return nil, err
	}
	args := &mailReceiverFactoryArgs{
		Evs:      binding.Evs,
		Config:   config,
		Api:      binding.Api,
		Store:    self.store,
		Settings: self.settings.Receive,
		Clock:    self.clock,
		Log:      self.log,
	}
	if self.Profile().MayIndex() && binding.Config != nil {
		args.DirectMxEligible = func() bool {
			state, err := binding.Config()
			if err != nil || state == nil {
				return false
			}
			receivers, _ := MailDesignatedReceivers(state, binding.IndexerServices)
			return slices.Contains(mailNetworkIndexers(state, receivers), self.sidecarId)
		}
	}
	receiver, closeParts, err := factory(args)
	if err != nil {
		return nil, err
	}
	receiverCtx, receiverCancel := context.WithCancel(run.ctx)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run.receiver = receiver
		run.receiverCancel = receiverCancel
		run.receiverClose = func() {
			<-receiver.done
			if closeParts != nil {
				closeParts()
			}
		}
	}()
	var pending *ApprovalPendingError
	if err := receiver.Start(receiverCtx); err != nil && !errors.As(err, &pending) && self.log.V(1).Enabled() {
		self.log.Infof("[mail]the receiver's first listen did not go through; it asks again: %T", err)
	}
	return receiver, nil
}

// Ends run's receiver, and with it its MTA-STS publish, and closes its parts.
func (self *MailClient) stopReceiver(run *mailComponentRun) {
	self.stopMtaSts(run)
	receiverCancel, receiverClose := func() (context.CancelFunc, func()) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		receiverCancel, receiverClose := run.receiverCancel, run.receiverClose
		run.receiver, run.receiverCancel, run.receiverClose = nil, nil, nil
		return receiverCancel, receiverClose
	}()
	if receiverCancel != nil {
		receiverCancel()
	}
	if receiverClose != nil {
		receiverClose()
	}
}

// An app's wake (§15.6 step 5; owner decision 197): the mailbox's ingest runs now, and nothing listens for it, so a
// wake only resyncs mail a receiver took; the send watch reads or/ now too (mail_send_result.go), and the pass it
// brings wakes each group repo's goroutine. Nothing while no generation runs them.
func (self *MailClient) Resync() {
	ingestor := func() *MailIngestor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if run, ok := self.componentRun.(*mailComponentRun); ok {
			self.notifyWithLock()
			return run.ingestor
		}
		return nil
	}()
	if ingestor != nil {
		ingestor.Wake()
	}
	self.wakeSends()
}
