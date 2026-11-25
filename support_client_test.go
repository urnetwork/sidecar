//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The host the fake policy names: RFC 2606's, which httptest's certificate holds.
const testSupportServiceHost = "example.com"

// A fake of FB's feedback service: it takes posts, answers lookups and serves the member's events, recording what it
// was sent. failNext answers that many posts 503 first.
type testSupportService struct {
	t      *testing.T
	server *httptest.Server

	stateLock   sync.Mutex
	posts       []*testSupportPost
	attachments []string
	failNext    int
	// the posts whose entry the service makes and whose answer is lost, answered 503
	loseAnswerNext int
	nextEntry      int
	entries        map[string]string
	events         []*SupportServiceEvent
	tokens         []string
	// one signal a post taken, for a test of the run loop
	posted chan struct{}
}

// One post as the service took it, with the tier and the approver it carried beside the body.
type testSupportPost struct {
	path           string
	idempotencyKey string
	tier           string
	approved       string
	body           *SupportBody
	raw            []byte
}

func newTestSupportService(t *testing.T) *testSupportService {
	self := &testSupportService{t: t, nextEntry: 100171, entries: map[string]string{}, posted: make(chan struct{}, 64)}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/entries", self.entries_)
	mux.HandleFunc("/v1/entries/", self.entry)
	mux.HandleFunc("/v1/events", self.eventStream)
	self.server = httptest.NewTLSServer(mux)
	t.Cleanup(self.server.Close)
	return self
}

// An http client that reaches the fake for testSupportServiceHost over TLS, trusting its certificate alone.
func (self *testSupportService) client() *http.Client {
	address := self.server.Listener.Addr().String()
	transport := self.server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network string, target string) (net.Conn, error) {
		if target != testSupportServiceHost+":443" {
			return nil, fmt.Errorf("the test dials only %s, not %s", testSupportServiceHost, target)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	transport.TLSClientConfig.ServerName = testSupportServiceHost
	return &http.Client{Transport: transport}
}

func (self *testSupportService) record(request *http.Request) *testSupportPost {
	raw, _ := io.ReadAll(request.Body)
	post := &testSupportPost{
		path: request.URL.Path, idempotencyKey: request.Header.Get("Idempotency-Key"), tier: request.Header.Get(supportHeaderTier),
		approved: request.Header.Get(supportHeaderApproved), raw: raw,
	}
	body := &SupportBody{}
	if json.Unmarshal(raw, body) == nil {
		post.body = body
	}
	self.tokens = append(self.tokens, request.Header.Get("Authorization"))
	return post
}

func (self *testSupportService) entries_(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch request.Method {
	case http.MethodGet:
		clientRef := request.URL.Query().Get("client_ref")
		entry, ok := self.entries[clientRef]
		if !ok {
			http.Error(writer, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(writer).Encode(map[string]any{"entries": []any{map[string]any{"id": entry, "status": "received", "seq": 1}}})
	case http.MethodPost:
		post := self.record(request)
		if 0 < self.failNext {
			self.failNext -= 1
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		self.posts = append(self.posts, post)
		entry, replayed := self.entries[post.idempotencyKey]
		if !replayed {
			entry = fmt.Sprint(self.nextEntry)
			self.nextEntry += 1
			self.entries[post.idempotencyKey] = entry
		}
		if 0 < self.loseAnswerNext {
			self.loseAnswerNext -= 1
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusCreated)
		json.NewEncoder(writer).Encode(map[string]any{"id": entry, "status": "received", "seq": 1, "replayed": replayed})
		select {
		case self.posted <- struct{}{}:
		default:
		}
	}
}

func (self *testSupportService) entry(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case strings.HasSuffix(request.URL.Path, "/attachments"):
		self.record(request)
		self.attachments = append(self.attachments, request.Header.Get("Idempotency-Key"))
		writer.WriteHeader(http.StatusCreated)
		writer.Write([]byte("{}"))
	case strings.HasSuffix(request.URL.Path, "/followups"):
		post := self.record(request)
		self.posts = append(self.posts, post)
		entry := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/entries/"), "/followups")
		writer.WriteHeader(http.StatusCreated)
		json.NewEncoder(writer).Encode(map[string]any{"id": entry, "status": "in_progress", "seq": 4})
	case request.Method == http.MethodDelete:
		writer.WriteHeader(http.StatusNoContent)
	default:
		http.Error(writer, `{"error":"not_found"}`, http.StatusNotFound)
	}
}

func (self *testSupportService) eventStream(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	events := slices.Clone(self.events)
	self.stateLock.Unlock()
	cursor := request.URL.Query().Get("cursor")
	writer.Header().Set("Content-Type", "text/event-stream")
	for _, event := range events {
		id := fmt.Sprintf("%s.%d", event.Entry, event.Seq)
		if cursor != "" && id <= cursor {
			continue
		}
		data, _ := json.Marshal(event)
		fmt.Fprintf(writer, "event: %s\nid: %s\ndata: %s\n\n", event.Type, id, data)
	}
}

func (self *testSupportService) addEvent(event *SupportServiceEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func (self *testSupportService) snapshot() []*testSupportPost {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.posts)
}

// The sources a test sets: the policy naming testSupportServiceHost, support:urnetwork acknowledged at version 2, a token.
type testSupportSources struct {
	stateLock    sync.Mutex
	host         string
	current      uint32
	acknowledged uint32
	network      *SupportNetworkSettings
}

func (self *testSupportSources) SupportLine() (*SupportPolicyLine, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.host == "" {
		return nil, errors.New("no line")
	}
	return &SupportPolicyLine{Host: self.host}, nil
}

func (self *testSupportSources) SupportDisclosure() (*SupportDisclosureState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &SupportDisclosureState{Current: self.current, Acknowledged: self.acknowledged}, nil
}

func (self *testSupportSources) SupportToken(ctx context.Context) (string, error) {
	return "test-feedback-token", nil
}

func (self *testSupportSources) SupportNetwork() (*SupportNetworkSettings, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.network == nil {
		return defaultSupportNetworkSettings(), nil
	}
	return self.network, nil
}

func (self *testSupportSources) all() *SupportSources {
	return &SupportSources{Policy: self, Disclosures: self, Tokens: self, Network: self}
}

// The parts of a Sidecar the client uses: a matcher of one canary credential, a gate that asks until a test approves,
// and the vault's entries as written.
type testSupportHost struct {
	stateLock sync.Mutex
	approved  bool
	declined  bool
	requests  []*SidecarAction
	lookups   map[SidecarActionKind]SidecarEffectLookup
	drafts    []*RecordDraft
	// the decisions an approved use spends, each a Signed as stored, which the effect runs under; nil runs it under no
	// spend, as a standing grant does
	spendDecisions [][]byte
	// the action the spend's decisions hash, nil for the one filed
	spendAction []byte
}

// The credential the host holds, which the scan refuses.
var testSupportCredential = []byte("sk-test-support-credential-0123456789abcdef")

func (self *testSupportHost) SecretMatcher() (*SecretMatcher, error) {
	return NewSecretMatcher([][]byte{testSupportCredential}, nil), nil
}

func (self *testSupportHost) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	self.stateLock.Lock()
	self.requests = append(self.requests, action)
	approved, declined, decisions, spendAction := self.approved, self.declined, self.spendDecisions, self.spendAction
	self.stateLock.Unlock()
	switch {
	case declined:
		return errors.New("declined")
	case !approved:
		return &ApprovalPendingError{ApprovalId: Id{0x27}}
	}
	if decisions != nil {
		if spendAction == nil {
			spendAction = action.Canonical
		}
		ctx = withApprovalSpend(ctx, &ApprovalSpend{ApprovalId: Id{0x27}, Decisions: decisions, Action: spendAction})
	}
	ref, err := action.Effect.Run(ctx, []byte("effect-key"))
	if err != nil {
		return err
	}
	action.Outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: ref}
	return nil
}

func (self *testSupportHost) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lookups == nil {
		self.lookups = map[SidecarActionKind]SidecarEffectLookup{}
	}
	self.lookups[kind] = lookup
	return func() {}
}

func (self *testSupportHost) Runs() (*RunStore, error) {
	return nil, errors.New("no runs in this test")
}

func (self *testSupportHost) supportRecords() (RecordWriter, error) {
	return self, nil
}

func (self *testSupportHost) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	return nil, nil
}

// A support client over a fake service and host, its switch on, on a test clock; closed at the test's end.
type testSupportWorld struct {
	t       *testing.T
	clock   *supportLogTestClock
	service *testSupportService
	sources *testSupportSources
	host    *testSupportHost
	log     *SupportLog
	client  *SupportClient
}

func newTestSupportWorld(t *testing.T) *testSupportWorld {
	clock := newSupportLogTestClock()
	settings := DefaultSupportSettings()
	settings.ServiceEnabled = true
	world := &testSupportWorld{
		t:       t,
		clock:   clock,
		service: newTestSupportService(t),
		sources: &testSupportSources{host: testSupportServiceHost, current: 2, acknowledged: 2},
		host:    &testSupportHost{},
	}
	world.log = openTestSupportLog(t, t.TempDir(), settings, clock)
	store := newTestMemoryStore()
	client, err := NewSupportClient(&SupportClientArgs{
		Host:       world.host,
		Settings:   settings,
		Log:        world.log,
		Store:      func() (SidecarStore, error) { return store, nil },
		Clock:      clock,
		HttpClient: world.service.client(),
		Sources:    world.sources.all(),
		manual:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	world.client = client
	return world
}

// A Harness run's message.
func (self *testSupportWorld) harnessArgs(text string, run *SupportRun) *SupportSendArgs {
	return &SupportSendArgs{
		Surface: SupportSurfaceHarness,
		Sender:  &SupportSender{AgentName: "release-bot", Where: "this device"},
		Run:     run,
		Text:    text,
	}
}

// A clean run that read nothing untrusted and carries no mark.
func testSupportCleanRun(toolCallId string) *SupportRun {
	return &SupportRun{RunId: Id{0x01, 0x02}, ToolCallId: toolCallId, MarksKnown: true}
}

func (self *testSupportWorld) send(args *SupportSendArgs) (*SupportSendResult, error) {
	return self.client.Send(context.Background(), args)
}

// One pass of the loop, as its wake or interval runs it.
func (self *testSupportWorld) pass() {
	self.client.pass()
}

func TestSupportAnswersUnavailableWhileTheReleaseSwitchIsOff(t *testing.T) {
	world := newTestSupportWorld(t)
	world.client.settings.ServiceEnabled = false
	if _, err := world.send(world.harnessArgs("the build fails", testSupportCleanRun("call-1"))); !errors.Is(err, ErrSupportUnavailable) {
		t.Fatalf("send with the switch off: %v", err)
	}
	world.pass()
	if 0 < len(world.service.snapshot()) {
		t.Fatal("a post with the switch off")
	}
}

func TestSupportCleanHarnessRunsMessageGoesWithoutApproval(t *testing.T) {
	world := newTestSupportWorld(t)
	result, err := world.send(world.harnessArgs("ur git push fails with an index error", testSupportCleanRun("call-1")))
	if err != nil {
		t.Fatal(err)
	}
	wantRef := supportClientRefText(SupportClientRefOfRun(Id{0x01, 0x02}, "call-1"))
	if result.Outcome != SupportOutcomeQueued || result.ClientRef != wantRef || len(world.host.requests) != 0 {
		t.Fatalf("send answered %+v after %d requests", result, len(world.host.requests))
	}
	world.pass()
	posts := world.service.snapshot()
	if len(posts) != 1 || posts[0].path != "/v1/entries" || posts[0].idempotencyKey != wantRef {
		t.Fatalf("posts %+v", posts)
	}
	body := posts[0].body
	if body.Tier != SupportTierAgent || body.Sender.Agent != "release-bot" || body.Sender.Approved != SupportApprovedNone || body.Disclosure != 2 ||
		body.Product != SupportProductUrnetwork || body.Text != "ur git push fails with an index error" {
		t.Fatalf("the body reads %+v %+v", body, body.Sender)
	}
	if posts[0].tier != string(SupportTierAgent) || posts[0].approved != SupportApprovedNone {
		t.Fatalf("beside the body: tier %q, approved %q", posts[0].tier, posts[0].approved)
	}
	if world.service.tokens[0] != "Bearer test-feedback-token" {
		t.Fatal("the post carried no token")
	}
	// the vault's entry as it left, its entry none until the acknowledgment, which its client_ref joins; its text there
	// and none in the team's projection
	if len(world.host.drafts) != 2 || world.host.drafts[0].Kind != RecordKindSupportMessage || world.host.drafts[1].Kind != RecordKindSupportMessage {
		t.Fatalf("%d drafts", len(world.host.drafts))
	}
	message := world.host.drafts[0].Body.(*protocol.SupportMessageBody)
	if message.GetDirection() != supportDirectionSent || message.GetText() == "" || message.GetEntry() != "" || message.GetSeq() != 0 ||
		message.GetDisclosureVersion() != 2 || message.GetTier() != supportTierNumberAgent || message.GetAgentLabel() != "release-bot this device" {
		t.Fatalf("the entry reads %v", message)
	}
	if err := RecordBodyValidate(RecordKindSupportMessage, message); err != nil {
		t.Fatal(err)
	}
	acknowledged := world.host.drafts[1].Body.(*protocol.SupportMessageBody)
	if acknowledged.GetDirection() != supportDirectionReceived || acknowledged.GetEntry() != "100171" || acknowledged.GetSeq() != 1 ||
		!bytes.Equal(acknowledged.GetClientRef(), message.GetClientRef()) || acknowledged.GetText() != "" || acknowledged.GetStatus() != 1 {
		t.Fatalf("the acknowledgment reads %v", acknowledged)
	}
	if err := RecordBodyValidate(RecordKindSupportMessage, acknowledged); err != nil {
		t.Fatal(err)
	}
	projection, err := RecordProjectForTeam(RecordKindSupportMessage, message, false)
	if err != nil {
		t.Fatal(err)
	}
	if projected := projection.(*protocol.SupportMessageBody); projected.GetText() != "" || projected.GetAgentLabel() != "" ||
		!bytes.Equal(projected.GetClientRef(), message.GetClientRef()) || projected.GetTier() != supportTierNumberAgent {
		t.Fatalf("the team's projection reads %v", projected)
	}
	// a resumed run's repeat of the call makes no second message
	if _, err := world.send(world.harnessArgs("ur git push fails with an index error", testSupportCleanRun("call-1"))); err != nil {
		t.Fatal(err)
	}
	world.pass()
	if posts := world.service.snapshot(); len(posts) != 1 {
		t.Fatalf("%d posts after a repeat", len(posts))
	}
}

func TestSupportRefusesWithoutTheCurrentDisclosure(t *testing.T) {
	world := newTestSupportWorld(t)
	for _, state := range []struct{ current, acknowledged uint32 }{{current: 2, acknowledged: 0}, {current: 3, acknowledged: 2}} {
		world.sources.current, world.sources.acknowledged = state.current, state.acknowledged
		_, err := world.send(world.harnessArgs("hello", testSupportCleanRun("call-d")))
		if SupportRefusalOf(err) != SupportRefusalDisclosureRequired || !strings.Contains(err.Error(), SupportDisclosureId) {
			t.Fatalf("version %d of %d: %v", state.acknowledged, state.current, err)
		}
	}
	world.pass()
	if 0 < len(world.service.snapshot()) {
		t.Fatal("a message went without the disclosure")
	}
}

func TestSupportRefusesHiddenTextAndDropsControlCharacters(t *testing.T) {
	for _, hidden := range []string{"look ‮evil", "tag \U000E0041\U000E0042", "plain️ text", "ideograph \U000E0100"} {
		if _, err := supportFormText(hidden, 16*1024); SupportRefusalOf(err) != SupportRefusalHiddenText {
			t.Errorf("%q: %v", hidden, err)
		}
	}
	formed, err := supportFormText("line one\nbell\x07 tab\tdone ❤️", 16*1024)
	if err != nil || formed != "line one\nbell tab\tdone ❤️" {
		t.Fatalf("formed %q, %v", formed, err)
	}
	if _, err := supportFormText(strings.Repeat("a", 16*1024+1), 16*1024); SupportRefusalOf(err) != SupportRefusalTooLong {
		t.Fatalf("past the bound: %v", err)
	}
	if _, err := supportFormText("\xff\xfe", 16*1024); SupportRefusalOf(err) != SupportRefusalNotText {
		t.Fatalf("not UTF-8: %v", err)
	}
}

func TestSupportRefusesAnAgentsSecretAndWarnsThePerson(t *testing.T) {
	world := newTestSupportWorld(t)
	text := "my config holds " + string(testSupportCredential) + " in it"
	_, err := world.send(world.harnessArgs(text, testSupportCleanRun("call-s")))
	var refusal *SupportRefusalError
	if !errors.As(err, &refusal) || refusal.Refusal != SupportRefusalSecretInMessage || refusal.SecretClass != SecretMatchCredential ||
		refusal.SecretOffset != strings.Index(text, "sk-") || refusal.FileIndex != -1 {
		t.Fatalf("an agent's secret: %v", err)
	}
	if strings.Contains(err.Error(), string(testSupportCredential)) {
		t.Fatal("the refusal names the secret")
	}
	// in a file, too
	args := world.harnessArgs("see the attached config", testSupportCleanRun("call-f"))
	args.Files = []*SupportFile{{Name: "config.txt", Data: []byte("token=" + string(testSupportCredential))}}
	if _, err := world.send(args); !errors.As(err, &refusal) || refusal.FileIndex != 0 {
		t.Fatalf("a file's secret: %v", err)
	}
	// the person is warned, and decides
	person := &SupportSendArgs{Surface: SupportSurfacePerson, Text: text}
	if _, err := world.send(person); SupportRefusalOf(err) != SupportRefusalSecretWarned {
		t.Fatalf("the person's secret: %v", err)
	}
	person.SecretConfirmed = true
	if result, err := world.send(person); err != nil || result.Outcome != SupportOutcomeQueued {
		t.Fatalf("the person's confirmed secret: %v", err)
	}
	world.pass()
	posts := world.service.snapshot()
	if len(posts) != 1 || posts[0].body.Tier != SupportTierHuman || !posts[0].body.Sender.Person {
		t.Fatalf("posts %+v", posts)
	}
}

func TestSupportNetworkAndPersonSwitchesOnlyNarrow(t *testing.T) {
	world := newTestSupportWorld(t)
	world.sources.network = &SupportNetworkSettings{Egress: SupportEgressPersons, Agents: true, Logs: true}
	if _, err := world.send(world.harnessArgs("hello", testSupportCleanRun("call-1"))); SupportRefusalOf(err) != SupportRefusalSupportOff {
		t.Fatalf("persons egress, an agent: %v", err)
	}
	if _, err := world.send(&SupportSendArgs{Surface: SupportSurfacePerson, Text: "hello"}); err != nil {
		t.Fatalf("persons egress, the person: %v", err)
	}
	world.sources.network = &SupportNetworkSettings{Egress: SupportEgressOn, Agents: true, Logs: false}
	args := world.harnessArgs("hello", testSupportCleanRun("call-2"))
	args.Logs = true
	if _, err := world.send(args); SupportRefusalOf(err) != SupportRefusalSupportOff {
		t.Fatalf("logs off: %v", err)
	}
	world.sources.network = &SupportNetworkSettings{Egress: SupportEgressOn, Agents: true, Logs: true, Paused: true}
	if _, err := world.send(world.harnessArgs("hello", testSupportCleanRun("call-3"))); SupportRefusalOf(err) != SupportRefusalPaused {
		t.Fatalf("paused: %v", err)
	}
	world.sources.network = nil
	if err := world.client.SetPersonKey(&SupportPersonKey{Agents: false, AgentLogs: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.send(world.harnessArgs("hello", testSupportCleanRun("call-4"))); SupportRefusalOf(err) != SupportRefusalSupportOff {
		t.Fatalf("the person's agents switch: %v", err)
	}
}

// Every case §28.8 sends to kind 27, each with its field 70.
func TestSupportOutwardMessagesFileKind27(t *testing.T) {
	cases := []struct {
		name  string
		args  func(world *testSupportWorld) *SupportSendArgs
		basis uint32
		rules []uint32
	}{
		{
			name: "a tainted run's message",
			args: func(world *testSupportWorld) *SupportSendArgs {
				return world.harnessArgs("the fetch tool fails", &SupportRun{RunId: Id{9}, ToolCallId: "t", Tainted: true, TaintReasons: []string{"web_tool"}, MarksKnown: true})
			},
			basis: approvalComputeAutoBasisTaint,
		},
		{
			name: "a marked run's message",
			args: func(world *testSupportWorld) *SupportSendArgs {
				return world.harnessArgs("mail sync stalls", &SupportRun{RunId: Id{9}, ToolCallId: "p", Private: true, MarksKnown: true})
			},
			basis: approvalComputeAutoBasisAlways, rules: []uint32{approvalComputeAutoRulePrivateData},
		},
		{
			name: "a file's",
			args: func(world *testSupportWorld) *SupportSendArgs {
				args := world.harnessArgs("the build log is attached", testSupportCleanRun("f"))
				args.Files = []*SupportFile{{Name: "build.log", Data: []byte("step 3 failed\n")}}
				return args
			},
			basis: approvalComputeAutoBasisAlways, rules: []uint32{approvalComputeAutoRuleAttachment},
		},
		{
			name: "an MCP session's",
			args: func(world *testSupportWorld) *SupportSendArgs {
				return &SupportSendArgs{Surface: SupportSurfaceMcp, Sender: &SupportSender{AgentName: "claude-code"}, Text: "the MCP tools time out"}
			},
			basis: approvalComputeAutoBasisTaint,
		},
	}
	for _, c := range cases {
		world := newTestSupportWorld(t)
		result, err := world.send(c.args(world))
		if err != nil || result.Outcome != SupportOutcomeApprovalPending || result.ApprovalId == nil {
			t.Fatalf("%s: %+v, %v", c.name, result, err)
		}
		if len(world.host.requests) != 1 {
			t.Fatalf("%s: %d requests", c.name, len(world.host.requests))
		}
		action := world.host.requests[0]
		stored, err := ParseStoredCanonicalAction(action.Canonical)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		auto := stored.Action.GetAuto()
		if action.Kind != SidecarActionSupportSend || auto.GetBasis() != c.basis || !slices.Equal(auto.GetRules(), c.rules) {
			t.Fatalf("%s: kind %d, field 70 %v", c.name, action.Kind, auto)
		}
		support := stored.Action.GetSupport()
		if support.GetText() == "" || support.GetProduct() != SupportProductUrnetwork || len(support.GetClientRef()) != 16 {
			t.Fatalf("%s: field 80 %v", c.name, support)
		}
		// nothing goes until a person decides
		world.pass()
		if posts := world.service.snapshot(); len(posts) != 0 {
			t.Fatalf("%s: posted before the decision", c.name)
		}
		// field 3 binds the body that will go
		world.host.approved = true
		world.pass()
		world.pass()
		posts := world.service.snapshot()
		if len(posts) != 1 {
			t.Fatalf("%s: %d posts after the approval", c.name, len(posts))
		}
		sum := sha256.Sum256(posts[0].raw)
		if !bytes.Equal(stored.Action.GetBodySha256(), sum[:]) {
			t.Fatalf("%s: field 3 does not hash the body posted", c.name)
		}
		// the body names no tier and no approver, which no one had decided when field 3 hashed it; the post carries the
		// person's decision beside it (QD-1398)
		if posts[0].body.Tier != "" || posts[0].body.Sender.Approved != "" || posts[0].tier != string(SupportTierReleased) ||
			posts[0].approved != SupportApprovedPerson {
			t.Fatalf("%s: the body's tier %q and approver %q, beside it %q and %q", c.name, posts[0].body.Tier,
				posts[0].body.Sender.Approved, posts[0].tier, posts[0].approved)
		}
		if c.name == "a file's" && len(world.service.attachments) != 1 {
			t.Fatalf("%s: %d attachments", c.name, len(world.service.attachments))
		}
	}
}

func TestSupportOutboxPostsOnceUnderOneClientRefAndGivesUpAfterItsWindow(t *testing.T) {
	world := newTestSupportWorld(t)
	world.service.failNext = 2
	result, err := world.send(world.harnessArgs("the daemon restarts", testSupportCleanRun("call-r")))
	if err != nil {
		t.Fatal(err)
	}
	world.pass()
	world.pass()
	if posts := world.service.snapshot(); len(posts) != 0 {
		t.Fatal("a post before its backoff passed")
	}
	world.clock.advance(time.Minute)
	world.pass()
	world.clock.advance(2 * time.Minute)
	world.pass()
	posts := world.service.snapshot()
	if len(posts) != 1 || posts[0].idempotencyKey != result.ClientRef {
		t.Fatalf("posts %+v", posts)
	}

	// the service down for longer than the window: given up, shown as not sent
	world.service.failNext = 1 << 20
	if _, err := world.send(world.harnessArgs("again", testSupportCleanRun("call-g"))); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		world.clock.advance(time.Hour)
		world.pass()
	}
	stubs, err := world.client.List(&SupportListArgs{AgentName: "release-bot"})
	if err != nil {
		t.Fatal(err)
	}
	notSent := 0
	for _, stub := range stubs {
		notSent += len(stub.NotSent)
	}
	if notSent != 1 {
		t.Fatalf("stubs %+v", stubs)
	}
}

func TestSupportLimitsAnAgentsMessagesAndTheOutbox(t *testing.T) {
	world := newTestSupportWorld(t)
	for i := range 5 {
		if _, err := world.send(world.harnessArgs("message", testSupportCleanRun(fmt.Sprint("call-", i)))); err != nil {
			t.Fatal(err)
		}
		world.pass()
	}
	_, err := world.send(world.harnessArgs("message", testSupportCleanRun("call-6")))
	var refusal *SupportRefusalError
	if !errors.As(err, &refusal) || refusal.Refusal != SupportRefusalRateLimited || refusal.RetryAfter <= 0 || time.Hour < refusal.RetryAfter {
		t.Fatalf("a sixth in the hour: %v", err)
	}
	world.clock.advance(time.Hour + time.Second)
	if _, err := world.send(world.harnessArgs("message", testSupportCleanRun("call-7"))); err != nil {
		t.Fatalf("after the hour: %v", err)
	}

	// the outbox: 10 waiting for one agent while the service cannot be reached
	world = newTestSupportWorld(t)
	world.sources.host = ""
	world.client.settings.AgentHourMaxCount = 100
	world.client.settings.AgentDayMaxCount = 100
	for i := range 10 {
		if _, err := world.send(world.harnessArgs("message", testSupportCleanRun(fmt.Sprint("wait-", i)))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := world.send(world.harnessArgs("message", testSupportCleanRun("wait-10"))); SupportRefusalOf(err) != SupportRefusalQueueFull {
		t.Fatalf("an eleventh waiting: %v", err)
	}
}

func TestSupportEventsAreReceivedOnceRecordedAndNotifiedWithoutText(t *testing.T) {
	world := newTestSupportWorld(t)
	if _, err := world.send(world.harnessArgs("ur git push fails", testSupportCleanRun("call-1"))); err != nil {
		t.Fatal(err)
	}
	world.pass()
	updates := []*SupportUpdate{}
	remove := world.client.AddListener(func(update *SupportUpdate) { updates = append(updates, update) })
	defer remove()
	reply := "Thanks: run ur doctor and send its output; never paste your token."
	at := world.clock.Now()
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 2, Type: "note", Note: reply, By: "support", At: at})
	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 3, Type: "status", Status: "in_progress", At: at})
	world.pass()
	// a second read finds the cursor past them
	world.pass()
	if len(updates) != 2 || updates[0].Seq != 2 || updates[1].Status != "in_progress" || !slices.Contains(updates[0].Agents, "release-bot") {
		t.Fatalf("updates %+v", updates)
	}
	encoded, _ := json.Marshal(updates)
	if bytes.Contains(encoded, []byte("ur doctor")) {
		t.Fatal("a notice carries the reply's text")
	}
	// one received entry an event: the acknowledgment of seq 1, the reply at 2 and the status at 3
	receivedSeqs := []uint32{}
	for _, draft := range world.host.drafts {
		if body := draft.Body.(*protocol.SupportMessageBody); body.GetDirection() == supportDirectionReceived {
			receivedSeqs = append(receivedSeqs, body.GetSeq())
			if err := RecordBodyValidate(RecordKindSupportMessage, body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !slices.Equal(receivedSeqs, []uint32{1, 2, 3}) {
		t.Fatalf("received entries at %v", receivedSeqs)
	}

	// support_list taints nothing and names no text; support_read taints first
	stubs, err := world.client.List(&SupportListArgs{AgentName: "release-bot"})
	if err != nil || len(stubs) != 1 || stubs[0].UnreadReplies != 1 || stubs[0].Status != "in_progress" {
		t.Fatalf("stubs %+v, %v", stubs, err)
	}
	listed, _ := json.Marshal(stubs)
	if bytes.Contains(listed, []byte("ur doctor")) || bytes.Contains(listed, []byte("git push")) {
		t.Fatal("a stub carries text")
	}
	tainted := false
	read, err := world.client.Read(context.Background(), &SupportReadArgs{
		Entry: "100171", AgentName: "release-bot", Taint: func(ctx context.Context) error { tainted = true; return nil },
	})
	if err != nil || !tainted {
		t.Fatalf("read: %v, tainted %v", err, tainted)
	}
	replies := 0
	for _, message := range read.Messages {
		if message.Reply && message.Text == reply && message.From == "support" {
			replies += 1
		}
	}
	if replies != 1 {
		t.Fatalf("the read holds %+v", read.Messages)
	}
	// a failed taint returns nothing
	if _, err := world.client.Read(context.Background(), &SupportReadArgs{
		Entry: "100171", AgentName: "release-bot", Taint: func(ctx context.Context) error { return errors.New("disk full") },
	}); err == nil {
		t.Fatal("a read returned after its taint failed")
	}
	// another agent's items are no one's but theirs and the person's
	if _, err := world.client.Read(context.Background(), &SupportReadArgs{Entry: "100171", AgentName: "other-bot"}); SupportRefusalOf(err) != SupportRefusalNotFound {
		t.Fatalf("another agent's read: %v", err)
	}
	if _, err := world.client.List(&SupportListArgs{AgentName: "other-bot", Scope: "member"}); SupportRefusalOf(err) != SupportRefusalNotFound {
		t.Fatalf("an unattended agent's member scope: %v", err)
	}
}

func TestSupportPostsOnlyToThePolicysHostOverTls(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "example.com:8443", "http://example.com", ""} {
		if _, err := supportServiceUrl(host, "/v1/entries", nil); err == nil {
			t.Errorf("host %q took", host)
		}
	}
	target, err := supportServiceUrl("example.com", "/v1/entries", nil)
	if err != nil || target != "https://example.com/v1/entries" {
		t.Fatalf("%s, %v", target, err)
	}
	// with no verified policy naming the host, nothing is posted and the message waits
	world := newTestSupportWorld(t)
	world.sources.host = ""
	if _, err := world.send(world.harnessArgs("hello", testSupportCleanRun("call-1"))); err != nil {
		t.Fatal(err)
	}
	world.pass()
	if len(world.service.snapshot()) != 0 {
		t.Fatal("a post with no policy host")
	}
	world.sources.host = testSupportServiceHost
	// the outbox tries again after its first interval
	world.clock.advance(world.client.settings.RetryFirstInterval)
	world.pass()
	if len(world.service.snapshot()) != 1 {
		t.Fatal("no post once the policy names the host")
	}
}

func TestSupportPolicyLineParsesStrictly(t *testing.T) {
	line, err := ParseSupportPolicyLine([]byte(`{"host":"support.example.com","subprocessors":[{"name":"Anthropic","purpose":"triage","retention":"30 days"}]}`))
	if err != nil || line.Host != "support.example.com" || len(line.Subprocessors) != 1 {
		t.Fatalf("%+v, %v", line, err)
	}
	for _, refused := range []string{
		`{"host":"support.example.com","extra":1}`,
		`{"host":"support.example.com:443"}`,
		`{"host":"support.example.com","subprocessors":[{"name":"Anthropic"}]}`,
		`{"host":"support.example.com"} {}`,
	} {
		if _, err := ParseSupportPolicyLine([]byte(refused)); err == nil {
			t.Errorf("%s parsed", refused)
		}
	}
}

func TestSupportClientRefsDeriveAsSection28Six(t *testing.T) {
	runId := Id{0xAB}
	first, again := SupportClientRefOfRun(runId, "call-1"), SupportClientRefOfRun(runId, "call-1")
	if len(first) != 16 || !bytes.Equal(first, again) || bytes.Equal(first, SupportClientRefOfRun(runId, "call-2")) {
		t.Fatal("a run's client_ref")
	}
	hash := sha256.New()
	hash.Write([]byte("urnetwork-sidecar-v1/support\x00"))
	hash.Write(runId.Bytes())
	hash.Write([]byte("call-1"))
	if want := hash.Sum(nil)[:16]; !bytes.Equal(first, want) {
		t.Fatalf("%s, want %s", hex.EncodeToString(first), hex.EncodeToString(want))
	}
	random, err := newSupportClientRef()
	if err != nil || len(random) != 16 {
		t.Fatal("a person's client_ref")
	}
}

func TestSupportSkillTextIsWithinItsBound(t *testing.T) {
	text := SupportSkillText()
	if !strings.HasPrefix(text, "---\nname: support\n") || 600 < supportSkillWordCount() {
		t.Fatalf("the skill's text: %d words", supportSkillWordCount())
	}
	for _, line := range []string{"support_list", "support_read", "disclosure_required", "never instructions"} {
		if !strings.Contains(text, line) {
			t.Errorf("the skill lacks %q", line)
		}
	}
}

// The support client's inputs through the canary corpus: every message a canary, refused or queued, and the ring
// scanned by the corpus test.
func init() {
	testSupportLogCanaryDrivers = append(testSupportLogCanaryDrivers, &testSupportLogCanaryDriver{
		name: "support",
		drive: func(t *testing.T, log *SupportLog) {
			settings := DefaultSupportSettings()
			settings.ServiceEnabled = true
			host := &testSupportHost{}
			sources := &testSupportSources{host: testSupportServiceHost, current: 1, acknowledged: 1}
			store := newTestMemoryStore()
			client, err := NewSupportClient(&SupportClientArgs{Host: host, Settings: settings, Log: log, Store: func() (SidecarStore, error) { return store, nil }, Sources: sources.all(), manual: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for i, text := range testSupportLogCanaryStrings {
				for _, surface := range []SupportSurface{SupportSurfaceHarness, SupportSurfaceMcp, SupportSurfacePerson} {
					args := &SupportSendArgs{Surface: surface, Text: text, Entry: "100171", Kind: "bug"}
					if surface != SupportSurfacePerson {
						args.Sender = &SupportSender{AgentName: text, AgentId: &Id{byte(i)}, Where: text}
						args.Run = &SupportRun{RunId: Id(testSupportLogCanaryIds[i%len(testSupportLogCanaryIds)]), ToolCallId: text, MarksKnown: true}
					}
					client.Send(context.Background(), args)
				}
			}
		},
	})
}

// The run loop posts a queued message on the wake its send gives, with no pass driven by the test.
func TestSupportRunLoopPostsOnItsWake(t *testing.T) {
	settings := DefaultSupportSettings()
	settings.ServiceEnabled = true
	service := newTestSupportService(t)
	sources := &testSupportSources{host: testSupportServiceHost, current: 1, acknowledged: 1}
	store := newTestMemoryStore()
	client, err := NewSupportClient(&SupportClientArgs{
		Host:       &testSupportHost{},
		Settings:   settings,
		Store:      func() (SidecarStore, error) { return store, nil },
		Clock:      newSupportLogTestClock(),
		HttpClient: service.client(),
		Sources:    sources.all(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Send(context.Background(), &SupportSendArgs{Surface: SupportSurfacePerson, Text: "the app's VPN drops"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.posted:
	case <-time.After(30 * time.Second):
		t.Fatal("the run loop never posted")
	}
}
