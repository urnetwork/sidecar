//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-17's MailClient on the access log's, mailcfg's and the mailbox's in-memory stand-ins (MAIL-M7-04, -05,
// -06 and -15's): enable, an alias, a deposit ingested, then the list and the read; the untrusted mark on outside
// mail and the member's on a same-network deposit; the daemon kept up while mail is on, across a restart; the
// address list behind ur://mail/{alias}; Status's indexer prompt; the component starting the receiver only where mail
// is on and policy grants the listen; the read surface on the page Worker's leg; and no alias in a log.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A Logger that keeps every line, safe for concurrent use.
type mailTestLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *mailTestLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *mailTestLogger) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *mailTestLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *mailTestLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *mailTestLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *mailTestLogger) V(level int32) Verbose {
	return &mailTestVerbose{log: self}
}

// Every level enabled, so a guarded line is kept too.
type mailTestVerbose struct {
	log *mailTestLogger
}

func (self *mailTestVerbose) Enabled() bool {
	return true
}

func (self *mailTestVerbose) Info(args ...any) {
	self.log.add(fmt.Sprint(args...))
}

func (self *mailTestVerbose) Infof(format string, args ...any) {
	self.log.add(fmt.Sprintf(format, args...))
}

// The lines so far.
func (self *mailTestLogger) snapshot() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

// The mail routes, as a test sets them.
type mailClientTestApi struct {
	stateLock   sync.Mutex
	enableCount int
	status      *MailNetworkStatus
}

func (self *mailClientTestApi) MailEnable(ctx context.Context) (*MailEnabled, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.enableCount += 1
	self.status = &MailNetworkStatus{Enabled: true}
	return &MailEnabled{EnabledTime: time.UnixMilli(testMailIngestPushMillis)}, nil
}

func (self *mailClientTestApi) MailStatus(ctx context.Context) (*MailNetworkStatus, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.status == nil {
		return &MailNetworkStatus{}, nil
	}
	copied := *self.status
	return &copied, nil
}

func (self *mailClientTestApi) Limits(ctx context.Context) (*QuotaLimits, error) {
	return &QuotaLimits{Tier: "pro", Limits: map[string]int64{
		mailLimitInboundMessageBytes: 50 * 1024 * 1024, mailLimitInboundRecipients: 100, mailLimitInboundReposPerMessage: 8,
	}}, nil
}

// The repos' parts over the worlds' stand-ins: the access log's, mailcfg's and the mailbox's.
type mailClientTestParts struct {
	world *mailClientTestWorld
}

func (self *mailClientTestParts) store(repoId Id) mailStore {
	return self.world.ingest.store
}

func (self *mailClientTestParts) config(repoId Id, args *MailConfigArgs) (*MailConfig, error) {
	args.Authority = self.world.configAuthority
	config := newMailConfig(&mailConfigTestStore{repo: self.world.configRepo, sidecarId: self.world.device}, args)
	self.world.t.Cleanup(config.Close)
	return config, nil
}

func (self *mailClientTestParts) repos(args *MailReposArgs) *MailRepos {
	return self.world.repos.repos(self.world.device)
}

func (self *mailClientTestParts) ingestor(repoId Id, args *MailIngestArgs) (*MailIngestor, error) {
	args.Authority = self.world.ingest.authority
	return newMailIngestor(repoId, self.world.ingest.repo, self.world.ingest.store, args), nil
}

// A member's device with mail on its in-memory stand-ins.
type mailClientTestWorld struct {
	t               *testing.T
	repos           *mailReposTestWorld
	ingest          *mailIngestTestWorld
	configRepo      *mailConfigTestRepo
	configAuthority *mailConfigTestAuthority
	gate            *mailConfigTestGate
	api             *mailClientTestApi
	store           *testMemoryStore
	log             *mailTestLogger
	member          Id
	device          Id
	client          *MailClient
}

func newMailClientTestWorld(t *testing.T) *mailClientTestWorld {
	t.Helper()
	world := &mailClientTestWorld{
		t:               t,
		repos:           newMailReposTestWorld(t),
		ingest:          newMailIngestTestWorld(t),
		configRepo:      newMailConfigTestRepo(),
		configAuthority: newMailConfigTestAuthority(),
		gate:            newMailConfigTestGate(),
		api:             &mailClientTestApi{},
		store:           newTestMemoryStore(),
		log:             &mailTestLogger{},
	}
	world.member, world.device = world.repos.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.repos.rebuild()
	world.configAuthority.grant(world.device, "*")
	world.client = world.newClient()
	return world
}

// A client over the world's store, as a restart makes one.
func (self *mailClientTestWorld) newClient() *MailClient {
	self.t.Helper()
	client, err := NewMailClient(&MailClientArgs{
		NetworkId: testNetworkId,
		SidecarId: self.device,
		Store:     self.store,
		Log:       self.log,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	engine := NewAclEngine(self.device, nil, nil, nil)
	if err := engine.Install(self.repos.state(), nil); err != nil {
		self.t.Fatal(err)
	}
	client.partsOverride = &mailClientTestParts{world: self}
	client.Bind(&MailBinding{
		Engine:  engine,
		Network: testMailIngestNetwork,
		Gate:    self.gate,
		Api:     self.api,
	})
	self.t.Cleanup(client.Close)
	return client
}

// The network the ingest world's recipients are under: label acme under root.example.
func testMailIngestNetwork() NetworkLabelRow {
	return NetworkLabelRow{Root: testMailIngestRoot, NetworkId: testNetworkId, Label: "acme"}
}

// Mail on, as `ur mail enable` turns it on: the mailbox, which the ingest world's deposits then go to.
func (self *mailClientTestWorld) enable() Id {
	self.t.Helper()
	if _, err := self.client.Enable(context.Background()); err != nil {
		self.t.Fatal(err)
	}
	mailboxId, err := self.client.mailboxId()
	if err != nil {
		self.t.Fatal(err)
	}
	self.ingest.repoId = mailboxId
	self.configAuthority.own(mailboxId, self.device)
	return mailboxId
}

// Ingests what the world's deposit refs hold into the mailbox, as the component's ingestor does.
func (self *mailClientTestWorld) ingestAll(mailboxId Id) {
	self.t.Helper()
	_, parts, err := self.client.bound()
	if err != nil {
		self.t.Fatal(err)
	}
	ingestor, err := parts.ingestor(mailboxId, &MailIngestArgs{SidecarId: self.device, Root: testMailIngestRoot})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := ingestor.Ingest(context.Background()); err != nil {
		self.t.Fatal(err)
	}
	self.client.invalidateMonth(mailboxId, MailYearMonthOf(testMailIngestReceiveMillis))
}

// Enable, an alias, a deposit for it, then the list and the read: the message as received, its label and stated
// basis, and the untrusted mark on outside mail.
func TestMailClientEnablesListsAndReads(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	if _, err := world.client.List(ctx, &MailListArgs{}); !errors.Is(err, ErrMailNoMailbox) {
		t.Fatalf("a list before the mailbox: %v", err)
	}
	mailboxId := world.enable()
	if world.api.enableCount != 1 || !world.client.Enabled() {
		t.Fatal("POST /mail/enable did not run, or mail is not on")
	}
	alias, err := world.client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: "bo"})
	if err != nil {
		t.Fatal(err)
	}
	if alias.Address != testMailIngestRecipient || alias.MailboxRepoId != mailboxId || !alias.Known {
		t.Fatalf("the alias %+v", alias)
	}
	aliases, err := world.client.Aliases(ctx)
	if err != nil || len(aliases) != 1 || aliases[0].Address != testMailIngestRecipient {
		t.Fatalf("aliases %v: %v", aliases, err)
	}

	message := testMailIngestMessage("Welcome", "Your code is 482913.")
	world.ingest.depositMessage(message)
	world.ingestAll(mailboxId)
	page, err := world.client.List(ctx, &MailListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Entry.GetSubject() != "Welcome" {
		t.Fatalf("the list: %+v", page.Entries)
	}
	entry := page.Entries[0].Entry
	read, err := world.client.Read(ctx, &MailReadArgs{Month: MailYearMonthOf(testMailIngestReceiveMillis), Id: mailEntryId(entry)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read.Text, "482913") || read.Trust != MailTrustUntrusted || read.RepoId != mailboxId {
		t.Fatalf("the read: %+v", read)
	}
	if read.Label != "opportunistic" || read.LabelStatement == "" || strings.Contains(read.LabelStatement, "end-to-end") {
		t.Fatalf("label %q: %q", read.Label, read.LabelStatement)
	}
	subjects := []string{}
	for _, header := range read.Headers {
		if header.Name == "Subject" {
			subjects = append(subjects, header.Value)
		}
	}
	if !slices.Equal(subjects, []string{"Welcome"}) {
		t.Fatalf("headers %+v", read.Headers)
	}
}

// A same-network deposit whose signer may send as its From reads as a member's, outside mail as untrusted.
func TestMailClientMarksOutsideMailUntrustedAndAMembersMailNot(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	mailboxId := world.enable()
	member := world.repos.fixture.device(world.member)
	from := "bo@acme.root.example"
	world.ingest.authority.maySend[member.String()+" "+from] = true
	sameNetwork := []byte("From: Bo <" + from + ">\r\nTo: " + testMailIngestRecipient + "\r\nSubject: From a member\r\n" +
		"Message-ID: <member@acme.root.example>\r\n\r\nA member's note.\r\n")
	world.ingest.repo.deposit(member, member, testMailIngestPlaintext(t, sameNetwork, &protocol.MailDeposit{
		Version: mailFormatVersion, MailFrom: []byte(from), Recipients: []string{testMailIngestRecipient},
	}))
	world.ingest.depositMessage(testMailIngestMessage("From outside", "An outside note."))
	world.ingestAll(mailboxId)
	trusts := map[string]MailTrust{}
	page, err := world.client.List(ctx, &MailListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range page.Entries {
		read, err := world.client.Read(ctx, &MailReadArgs{Month: MailYearMonthOf(entry.Entry.GetTime()), Id: mailEntryId(entry.Entry)})
		if err != nil {
			t.Fatal(err)
		}
		trusts[entry.Entry.GetSubject()] = read.Trust
	}
	if trusts["From a member"] != MailTrustMember || trusts["From outside"] != MailTrustUntrusted {
		t.Fatalf("trust marks %v", trusts)
	}
}

// A daemon with mail on does not idle out: Active turns true at enable, and a restart reads it back from the store.
func TestMailClientKeepsTheDaemonUpWhileMailIsOn(t *testing.T) {
	world := newMailClientTestWorld(t)
	var component SidecarActiveComponent = world.client
	if component.Active() {
		t.Fatal("active before mail is on")
	}
	world.enable()
	if !component.Active() {
		t.Fatal("not active with mail on")
	}
	if restarted := world.newClient(); !restarted.Active() {
		t.Fatal("a restart forgot mail is on")
	}
	// mail turned on from another device reaches this one through GET /mail/status
	other := newMailClientTestWorld(t)
	other.api.status = &MailNetworkStatus{Enabled: true}
	if _, err := other.client.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !other.client.Active() {
		t.Fatal("not active though the network's status says mail is on")
	}
}

// Status prompts for a mail indexer while mail is on and none is known to stand, and stops once one does.
func TestMailClientStatusPromptsForAnIndexerUntilOneStands(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	status, err := world.client.Status(ctx)
	if err != nil || status.Enabled || status.Prompt != "" {
		t.Fatalf("status with mail off %+v: %v", status, err)
	}
	world.enable()
	status, err = world.client.Status(ctx)
	if err != nil || !status.Enabled || status.Prompt != "" || status.MailIndexerKnown {
		t.Fatalf("status where no one can tell %+v: %v", status, err)
	}
	binding, _, _ := world.client.bound()
	noIndexer := *binding
	noIndexer.MailIndexer = func() (bool, error) { return false, nil }
	world.client.Bind(&noIndexer)
	status, err = world.client.Status(ctx)
	if err != nil || status.Prompt != MailIndexerPrompt || !status.MailIndexerKnown {
		t.Fatalf("status with no indexer %+v: %v", status, err)
	}
	withIndexer := *binding
	withIndexer.MailIndexer = func() (bool, error) { return true, nil }
	world.client.Bind(&withIndexer)
	status, err = world.client.Status(ctx)
	if err != nil || status.Prompt != "" || !status.MailIndexer || !status.MailIndexerKnown {
		t.Fatalf("status with an indexer %+v: %v", status, err)
	}
	if strings.Contains(MailIndexerPrompt, "send") {
		t.Fatal("the coverage copy speaks of sending (FS-123)")
	}
}

// ur://mail/{alias}'s data: one address's entries, the others' passed over.
func TestMailClientListsOneAddress(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	mailboxId := world.enable()
	world.ingest.depositMessage(testMailIngestMessage("First", "one"))
	other := testMailIngestMessage("Second", "two")
	trailer := testMailIngestTrailer(world.ingest.receiverId, other)
	trailer.Recipients = []string{"ann@acme.root.example"}
	world.ingest.repo.deposit(world.ingest.receiverId, world.ingest.receiverId, testMailIngestPlaintext(t, other, trailer))
	world.ingestAll(mailboxId)
	page, err := world.client.ListAddress(ctx, testMailIngestRecipient, &MailListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Entry.GetSubject() != "First" {
		t.Fatalf("entries %v", page.Entries)
	}
	if _, err := world.client.ListAddress(ctx, "", nil); !errors.Is(err, ErrMailClientInvalid) {
		t.Fatalf("no address: %v", err)
	}
}

// Nothing works on an unbound client: every call answers ErrMailUnbound, never a guess.
func TestMailClientAnswersUnboundBeforeItIsBound(t *testing.T) {
	client, err := NewMailClient(&MailClientArgs{NetworkId: testNetworkId, SidecarId: NewId(), Store: newTestMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Enable(ctx); !errors.Is(err, ErrMailUnbound) {
		t.Errorf("Enable: %v", err)
	}
	if _, err := client.List(ctx, &MailListArgs{}); !errors.Is(err, ErrMailUnbound) {
		t.Errorf("List: %v", err)
	}
	if _, err := client.Aliases(ctx); !errors.Is(err, ErrMailUnbound) {
		t.Errorf("Aliases: %v", err)
	}
	if _, err := client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: "bo"}); !errors.Is(err, ErrMailUnbound) {
		t.Errorf("CreateAlias: %v", err)
	}
	if client.Active() {
		t.Error("an unbound client is active")
	}
}

// The component starts the receiver only once mail is on, receive is set and policy grants the listen, and ends it
// when the grant goes.
func TestMailComponentStartsTheReceiverOnlyWhereGranted(t *testing.T) {
	world := newMailClientTestWorld(t)
	receivers := newMailReceiverTestWorld(t, nil)
	var granted sync.Mutex
	grant := false
	started := 0
	world.client.componentSeams = &mailComponentSeams{
		mayReceive: func() bool {
			granted.Lock()
			defer granted.Unlock()
			return grant
		},
		factory: func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error) {
			started += 1
			return receivers.newReceiver(nil), func() {}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	world.client.passReceive(run, binding)
	if status := world.client.receiverStatus; status.Running || status.Problem != "mail is off" {
		t.Fatalf("with mail off %+v", status)
	}
	world.enable()
	world.client.passReceive(run, binding)
	if status := world.client.receiverStatus; status.Running || !strings.Contains(status.Problem, "no listen") {
		t.Fatalf("with no grant %+v", status)
	}
	granted.Lock()
	grant = true
	granted.Unlock()
	world.client.passReceive(run, binding)
	receivers.publisher.awaitCount(1)
	if status := world.client.receiverStatus; !status.Running || started != 1 {
		t.Fatalf("granted %+v, %d started", status, started)
	}
	world.client.passReceive(run, binding)
	if started != 1 {
		t.Fatal("a second pass started a second receiver")
	}
	granted.Lock()
	grant = false
	granted.Unlock()
	world.client.passReceive(run, binding)
	if run.receiver != nil || world.client.receiverStatus.Running {
		t.Fatal("the receiver outlived its grant")
	}
}

// The read surface builds on the page Worker's leg, and the component and the receiver do not.
func TestMailReadSurfaceBuildsOnTheHttpLeg(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	for file, want := range map[string]bool{
		"mail_client.go": true, "mail_read.go": true, "mail_settings.go": true, "mail_settings_receive_http.go": true,
		"mail_component.go": false, "mail_component_receive.go": false, "mail_settings_receive.go": false,
		"mail_receiver.go": false, "mail_session.go": false,
	} {
		matched, err := buildContext.MatchFile(".", file)
		if err != nil {
			t.Fatal(err)
		}
		if matched != want {
			t.Errorf("%s on the sidecar_http leg: %t", file, matched)
		}
	}
}

// Enabling, creating an alias, ingesting, listing and reading log no address and no alias (I-13).
func TestMailClientLogsNoAlias(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	mailboxId := world.enable()
	if _, err := world.client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: "bo"}); err != nil {
		t.Fatal(err)
	}
	world.ingest.depositMessage(testMailIngestMessage("Logged", "nothing"))
	world.ingestAll(mailboxId)
	if _, err := world.client.List(ctx, &MailListArgs{}); err != nil {
		t.Fatal(err)
	}
	for _, line := range world.log.snapshot() {
		if strings.Contains(line, "bo@") || strings.Contains(line, "acme") {
			t.Errorf("a line names an address: %q", line)
		}
	}
}
