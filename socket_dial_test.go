//go:build !sidecar_http && !js

// §9.6's dialer on the pipe seam and a scripted Find (SOCK-M5-12): a table over every reject code and the accept
// timeout, 0 and past the five included; at most three Finds; one invalid refetch; denied stopping at once; the failed
// tickets carried, with their reasons; a claim from the wrong sidecar never opened; a listener with no listen grant
// refused; and a foreign <net> refused before any Find.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One scripted listener: its client, its sidecar's identity key, and how it answers an open.
type testDialListener struct {
	clientId Id
	signer   *testSocketSigner
	// reject answers StreamReject with code, 0 included; timeout holds the open until its ctx ends; else it accepts
	reject     bool
	code       protocol.StreamRejectCode
	retryAfter time.Duration
	timeout    bool
	// the claim comes from another sidecar's key
	wrongClaim bool
}

// Rejects with code.
func (self *testDialListener) rejecting(code protocol.StreamRejectCode) *testDialListener {
	self.reject = true
	self.code = code
	return self
}

// A test clock that reports each timer it arms, so a test moves it only once the wait it means is in place.
type testArmedClock struct {
	*testSocketClock
	armed chan time.Duration
}

func newTestArmedClock() *testArmedClock {
	return &testArmedClock{testSocketClock: newTestSocketClock(), armed: make(chan time.Duration, 1024)}
}

// See Clock.
func (self *testArmedClock) After(timeout time.Duration) <-chan time.Time {
	fired := self.testSocketClock.After(timeout)
	self.armed <- timeout
	return fired
}

// See Clock.
func (self *testArmedClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	stop = self.testSocketClock.AfterFunc(timeout, function)
	self.armed <- timeout
	return stop
}

// Forgets the timers armed so far, so the next awaitArmed waits for one armed after this.
func (self *testArmedClock) flushArmed() {
	for {
		select {
		case <-self.armed:
		default:
			return
		}
	}
}

// Waits until the clock has armed a timer of want.
func (self *testArmedClock) awaitArmed(t testing.TB, want time.Duration) {
	t.Helper()
	for {
		if testSocketAwait(t, self.armed, "an armed timer") == want {
			return
		}
	}
}

// The opener a dial runs on: each listener's Hello and answer.
type testDialOpener struct {
	listeners map[Id]*testDialListener
	// a dead listener's open has started and waits for its timeout
	waiting chan Id

	stateLock sync.Mutex
	opened    []Id
	verified  []Id
}

func (self *testDialOpener) verify(ctx context.Context, clientId Id) (*SubprotocolPeerIdentity, error) {
	self.stateLock.Lock()
	self.verified = append(self.verified, clientId)
	self.stateLock.Unlock()
	listener := self.listeners[clientId]
	if listener == nil {
		return nil, errors.New("no such listener")
	}
	return &SubprotocolPeerIdentity{SidecarId: listener.signer.sidecarId, IdentityPublicKey: listener.signer.publicKey()}, nil
}

func (self *testDialOpener) open(ctx context.Context, clientId Id, request *StreamOpenRequest) (socketStream, error) {
	self.stateLock.Lock()
	self.opened = append(self.opened, clientId)
	self.stateLock.Unlock()
	listener := self.listeners[clientId]
	if listener.timeout {
		self.waiting <- clientId
		<-ctx.Done()
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	}
	if listener.reject {
		return nil, &StreamRejectError{Code: listener.code, RetryAfter: listener.retryAfter}
	}
	dialer, _ := newSocketStreamPipe(1024)
	return dialer, nil
}

func (self *testDialOpener) openedIds() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]Id(nil), self.opened...)
}

// A scripted sockets service: each Find answers the next listeners' tickets, and records what it was sent.
type testDialService struct {
	t         testing.TB
	dialer    *testDialFixture
	answers   [][]*testDialListener
	refusals  []*SocketError
	stateLock sync.Mutex
	finds     []*SocketFindArgs
}

func (self *testDialService) send(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *args
	copied.FailedTickets = append([]*SocketFailedTicket(nil), args.FailedTickets...)
	self.finds = append(self.finds, &copied)
	index := len(self.finds) - 1
	if index < len(self.refusals) && self.refusals[index] != nil {
		return &SocketFindResult{Error: self.refusals[index]}, nil
	}
	listeners := self.answers[min(index, len(self.answers)-1)]
	result := &SocketFindResult{}
	for position, listener := range listeners {
		findTicket := self.dialer.findTicket(self.t, listener, position == 1)
		if position == 0 {
			result.Primary = findTicket
		} else {
			result.Backup = findTicket
		}
	}
	return result, nil
}

func (self *testDialService) findArgs() []*SocketFindArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*SocketFindArgs(nil), self.finds...)
}

// A dialer in the test network, its policy granting every listener's sidecar listen.
type testDialFixture struct {
	clock       *testArmedClock
	ring        *SocketKeyRing
	labels      *SocketNetworkLabels
	policy      *testSocketPolicy
	clientId    Id
	opener      *testDialOpener
	service     *testDialService
	dialer      *socketDialer
	nameToken   []byte
	ticketCount int
}

const testDialName = "db/primary"

func newTestDialFixture(t testing.TB, listeners ...*testDialListener) *testDialFixture {
	t.Helper()
	fixture := &testDialFixture{
		clock:    newTestArmedClock(),
		ring:     newTestSocketRing(t, "dial", "", 0),
		labels:   &SocketNetworkLabels{Label: "abcdefghij", Resolver: &testDialResolver{}},
		policy:   newTestSocketPolicy(5),
		clientId: testSocketId("dialer client"),
		opener:   &testDialOpener{listeners: map[Id]*testDialListener{}, waiting: make(chan Id, 16)},
	}
	for _, listener := range listeners {
		fixture.opener.listeners[listener.clientId] = listener
		fixture.policy.listen[listener.signer.sidecarId] = true
	}
	var err error
	if fixture.nameToken, err = fixture.ring.Current().TokenPath(testDialName); err != nil {
		t.Fatal(err)
	}
	fixture.service = &testDialService{t: t, dialer: fixture}
	fixture.dialer = &socketDialer{
		settings:  DefaultSidecarSocketSettings(),
		clock:     fixture.clock,
		random:    func() float64 { return 0.5 },
		networkId: testRegistrarNetworkId,
		clientId:  fixture.clientId,
		labels:    fixture.labels,
		ring:      fixture.ring,
		find:      newSocketFindClient(fixture.service.send),
		opener:    fixture.opener,
		policy:    fixture.policy,
	}
	return fixture
}

// A listener named label, accepting.
func newTestDialListener(label string) *testDialListener {
	return &testDialListener{clientId: testSocketId("listener client " + label), signer: newTestSocketSigner("listener " + label)}
}

// A resolver whose one other label names another network.
type testDialResolver struct{}

func (self *testDialResolver) ResolveNetworkLabel(root string, text string, interactive bool) (Id, NetworkLabelKind, error) {
	if text == "othernetwk" {
		return testSocketId("another network"), NetworkLabelKindLabel, nil
	}
	if text == "mynetalias" {
		return testRegistrarNetworkId, NetworkLabelKindAlias, nil
	}
	return Id{}, NetworkLabelKindLabel, errors.New("unknown")
}

// The Find answer's ticket and claim for listener.
func (self *testDialFixture) findTicket(t testing.TB, listener *testDialListener, backup bool) *SocketFindTicket {
	self.ticketCount += 1
	listenId := testSocketId("listen " + listener.clientId.String())
	ticket := &protocol.SocketTicket{
		TicketId:         testSocketId("dial ticket " + string(rune('a'+self.ticketCount))).Bytes(),
		NetworkId:        testRegistrarNetworkId.Bytes(),
		NameToken:        self.nameToken,
		ListenerClientId: listener.clientId.Bytes(),
		ListenId:         listenId.Bytes(),
		DialerClientId:   self.clientId.Bytes(),
		DialerNetworkId:  testRegistrarNetworkId.Bytes(),
		IssueTimeMillis:  1,
		ExpireTimeMillis: 30_001,
		PolicyVersion:    5,
		Backup:           backup,
	}
	signedTicket, err := SignSocketTicket(testAdmissionKeyId, testAdmissionKey, ticket)
	if err != nil {
		t.Fatal(err)
	}
	ticketBytes, err := proto.Marshal(signedTicket)
	if err != nil {
		t.Fatal(err)
	}
	claimListenId := listenId
	signer := listener.signer
	if listener.wrongClaim {
		signer = newTestSocketSigner("an impostor")
	}
	claimBody, err := proto.Marshal(&protocol.SocketRegistrationClaim{
		NetworkId: testRegistrarNetworkId.Bytes(),
		NameToken: self.nameToken,
		ListenId:  claimListenId.Bytes(),
		Protocol:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.sign(SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, claimBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return &SocketFindTicket{Ticket: ticketBytes, Claim: claim}
}

func (self *testDialFixture) dial(address string) (*SocketConn, error) {
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		return nil, err
	}
	return self.dialer.dial(context.Background(), parsed, nil, false)
}

// Every reject code, the timeout, 0 and a code past the five, on the primary with an accepting backup.
func TestSocketDialRejectCodes(t *testing.T) {
	type dialCase struct {
		name string
		// the primary's answer: a reject of code, or a timeout
		code    protocol.StreamRejectCode
		timeout bool
		// what the dial does: the backup's conn, or this error
		wantErr error
		// how many Finds it took
		wantFinds int
	}
	cases := []dialCase{
		{name: "retry tries the backup", code: protocol.StreamRejectCode_SR_RETRY, wantFinds: 1},
		{name: "busy tries the backup", code: protocol.StreamRejectCode_SR_BUSY, wantFinds: 1},
		{name: "quota waits, then the backup", code: protocol.StreamRejectCode_SR_QUOTA, wantFinds: 1},
		{name: "a timeout tries the backup", timeout: true, wantFinds: 1},
		{name: "denied stops at once", code: protocol.StreamRejectCode_SR_DENIED, wantErr: ErrSocketDenied, wantFinds: 1},
		{name: "invalid refetches once", code: protocol.StreamRejectCode_SR_INVALID, wantFinds: 2},
		{name: "0 is invalid", code: protocol.StreamRejectCode(0), wantFinds: 2},
		{name: "a code past the five is invalid", code: protocol.StreamRejectCode(9), wantFinds: 2},
	}
	settings := DefaultSidecarSocketSettings()
	for _, dialCase := range cases {
		primary := newTestDialListener("primary")
		if dialCase.timeout {
			primary.timeout = true
		} else {
			primary.rejecting(dialCase.code)
			primary.retryAfter = time.Second
		}
		backup := newTestDialListener("backup")
		fixture := newTestDialFixture(t, primary, backup)
		// an invalid refetch's Find answers the backup alone
		fixture.service.answers = [][]*testDialListener{{primary, backup}, {backup}}
		type result struct {
			conn *SocketConn
			err  error
		}
		results := make(chan result, 1)
		go func() {
			conn, err := fixture.dial(testDialName)
			results <- result{conn: conn, err: err}
		}()
		switch {
		case dialCase.timeout:
			testSocketAwait(t, fixture.opener.waiting, "the dead primary's open")
			fixture.clock.advance(settings.DialAcceptTimeout)
		case dialCase.code == protocol.StreamRejectCode_SR_QUOTA:
			fixture.clock.awaitArmed(t, primary.retryAfter)
			fixture.clock.advance(primary.retryAfter)
		}
		got := testSocketAwait(t, results, "the dial")
		finds := fixture.service.findArgs()
		if len(finds) != dialCase.wantFinds {
			t.Errorf("%s: %d finds", dialCase.name, len(finds))
		}
		if dialCase.wantErr != nil {
			if !errors.Is(got.err, dialCase.wantErr) {
				t.Errorf("%s: %v", dialCase.name, got.err)
			}
			for _, opened := range fixture.opener.openedIds() {
				if opened == backup.clientId {
					t.Errorf("%s: the backup opened after a stop", dialCase.name)
				}
			}
			continue
		}
		if got.err != nil || got.conn == nil {
			t.Errorf("%s: %v", dialCase.name, got.err)
			continue
		}
		if remote := got.conn.RemoteAddr().(*SocketAddr); Id(remote.ClientId) != backup.clientId {
			t.Errorf("%s: the conn reached %v", dialCase.name, remote)
		}
		if 1 < dialCase.wantFinds {
			second := finds[1]
			if len(second.FailedTickets) != 1 || second.FailedTickets[0].Reason != SocketFailedReasonRefused {
				t.Errorf("%s: the refetch carried %+v", dialCase.name, second.FailedTickets)
			}
		}
	}
}

// A second invalid answer in one Dial is no second refetch: it tries the next ticket.
func TestSocketDialRefetchesOnce(t *testing.T) {
	first := newTestDialListener("first").rejecting(protocol.StreamRejectCode_SR_INVALID)
	second := newTestDialListener("second").rejecting(protocol.StreamRejectCode_SR_INVALID)
	backup := newTestDialListener("backup")
	fixture := newTestDialFixture(t, first, second, backup)
	fixture.service.answers = [][]*testDialListener{{first, backup}, {second, backup}}
	conn, err := fixture.dial(testDialName)
	if err != nil {
		t.Fatal(err)
	}
	if remote := conn.RemoteAddr().(*SocketAddr); Id(remote.ClientId) != backup.clientId {
		t.Errorf("the conn reached %v", remote)
	}
	if finds := fixture.service.findArgs(); len(finds) != 2 {
		t.Errorf("%d finds", len(finds))
	}
}

// Every ticket refused, every Find: three Finds and no more, each carrying the last one's tickets, then no listener.
func TestSocketDialStopsAfterThreeFinds(t *testing.T) {
	primary := newTestDialListener("primary").rejecting(protocol.StreamRejectCode_SR_RETRY)
	backup := newTestDialListener("backup").rejecting(protocol.StreamRejectCode_SR_RETRY)
	fixture := newTestDialFixture(t, primary, backup)
	fixture.service.answers = [][]*testDialListener{{primary, backup}}
	_, err := fixture.dial(testDialName)
	if !errors.Is(err, ErrSocketNoListener) {
		t.Fatalf("%v", err)
	}
	finds := fixture.service.findArgs()
	if len(finds) != 3 {
		t.Fatalf("%d finds", len(finds))
	}
	if len(finds[0].FailedTickets) != 0 {
		t.Errorf("the first find carried %d tickets", len(finds[0].FailedTickets))
	}
	for index, find := range finds[1:] {
		if len(find.FailedTickets) != 2 {
			t.Errorf("find %d carried %d tickets", index+1, len(find.FailedTickets))
		}
		if !bytes.Equal(find.NameToken, fixture.nameToken) || find.Name != "" {
			t.Errorf("find %d named %+v", index+1, find)
		}
	}
}

// The failed tickets a Find carries say a timeout as timeout and every refusal as refused.
func TestSocketDialReportsTimeoutsAndRefusals(t *testing.T) {
	primary := newTestDialListener("primary")
	primary.timeout = true
	backup := newTestDialListener("backup").rejecting(protocol.StreamRejectCode_SR_BUSY)
	third := newTestDialListener("third")
	fixture := newTestDialFixture(t, primary, backup, third)
	fixture.service.answers = [][]*testDialListener{{primary, backup}, {third}}
	results := make(chan error, 1)
	go func() {
		_, err := fixture.dial(testDialName)
		results <- err
	}()
	testSocketAwait(t, fixture.opener.waiting, "the dead primary's open")
	fixture.clock.advance(DefaultSidecarSocketSettings().DialAcceptTimeout)
	// the busy backup brings a backoff before the next Find: DialBusyBackoff at the middle draw
	backoff := DefaultSidecarSocketSettings().DialBusyBackoff
	fixture.clock.awaitArmed(t, backoff)
	fixture.clock.advance(backoff)
	if err := testSocketAwait(t, results, "the dial"); err != nil {
		t.Fatal(err)
	}
	finds := fixture.service.findArgs()
	if len(finds) != 2 || len(finds[1].FailedTickets) != 2 {
		t.Fatalf("finds %d", len(finds))
	}
	if finds[1].FailedTickets[0].Reason != SocketFailedReasonTimeout || finds[1].FailedTickets[1].Reason != SocketFailedReasonRefused {
		t.Errorf("reasons %q %q", finds[1].FailedTickets[0].Reason, finds[1].FailedTickets[1].Reason)
	}
}

// A claim another sidecar signed is never opened, and a listener this device's config grants no listen is never
// opened: each fails as refused and the backup takes the dial.
func TestSocketDialChecksTheListenerBeforeOpen(t *testing.T) {
	for _, refuse := range []string{"claim", "grant"} {
		primary := newTestDialListener("primary")
		backup := newTestDialListener("backup")
		fixture := newTestDialFixture(t, primary, backup)
		switch refuse {
		case "claim":
			primary.wrongClaim = true
		case "grant":
			fixture.policy.set(func(policy *testSocketPolicy) { delete(policy.listen, primary.signer.sidecarId) })
		}
		fixture.service.answers = [][]*testDialListener{{primary, backup}}
		conn, err := fixture.dial(testDialName)
		if err != nil {
			t.Fatalf("%s: %v", refuse, err)
		}
		if remote := conn.RemoteAddr().(*SocketAddr); Id(remote.ClientId) != backup.clientId {
			t.Errorf("%s: the conn reached %v", refuse, remote)
		}
		for _, opened := range fixture.opener.openedIds() {
			if opened == primary.clientId {
				t.Errorf("%s: the refused listener was opened", refuse)
			}
		}
	}
	// with no policy at all, no listener opens
	only := newTestDialListener("only")
	fixture := newTestDialFixture(t, only)
	fixture.dialer.policy = nil
	fixture.service.answers = [][]*testDialListener{{only}}
	if _, err := fixture.dial(testDialName); !errors.Is(err, ErrSocketNoListener) || len(fixture.opener.openedIds()) != 0 {
		t.Errorf("with no policy: %v, %d opened", err, len(fixture.opener.openedIds()))
	}
}

// A <net> naming another network is refused before any Find, an alias of this one dials, and an edge name, share/,
// a reserved name and ur/ never reach a Find from a sidecar's Dial.
func TestSocketDialResolvesOnlyItsOwnNetwork(t *testing.T) {
	listener := newTestDialListener("primary")
	fixture := newTestDialFixture(t, listener)
	fixture.service.answers = [][]*testDialListener{{listener}}
	if _, err := fixture.dial("othernetwk:" + testDialName); !errors.Is(err, ErrSocketDenied) {
		t.Errorf("a foreign net: %v", err)
	}
	for _, address := range []string{"tls/443/blog", "smtp/25/mx", "share/abcdefghijklmnopqrstuvwxyz", "sys/x", "ur/smtpedge"} {
		if _, err := fixture.dial(address); err == nil {
			t.Errorf("%s dialed", address)
		}
	}
	if len(fixture.service.findArgs()) != 0 {
		t.Fatalf("%d finds for refused addresses", len(fixture.service.findArgs()))
	}
	conn, err := fixture.dial("mynetalias:" + testDialName)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Ticket() == nil {
		t.Error("a conn with no ticket")
	}
	finds := fixture.service.findArgs()
	if len(finds) != 1 || *finds[0].NetworkId != connect.Id(testRegistrarNetworkId) {
		t.Errorf("finds %+v", finds)
	}
}

// A Find's refusal ends the dial as its own error, a busy one after the Finds it may take, and a dial with no K_sock
// ring or labels is unavailable before any Find.
func TestSocketDialFindRefusals(t *testing.T) {
	for _, refusal := range []struct {
		code SocketErrorCode
		want error
	}{
		{code: SocketErrorCodeDenied, want: ErrSocketDenied},
		{code: SocketErrorCodeQuota, want: ErrSocketQuota},
		{code: SocketErrorCodeNoListener, want: ErrSocketNoListener},
		{code: SocketErrorCodeUnavailable, want: ErrSocketUnavailable},
	} {
		fixture := newTestDialFixture(t)
		fixture.service.refusals = []*SocketError{{Code: refusal.code}}
		if _, err := fixture.dial(testDialName); !errors.Is(err, refusal.want) {
			t.Errorf("%s: %v", refusal.code, err)
		}
		if len(fixture.service.findArgs()) != 1 {
			t.Errorf("%s: %d finds", refusal.code, len(fixture.service.findArgs()))
		}
	}

	fixture := newTestDialFixture(t)
	fixture.service.refusals = []*SocketError{{Code: SocketErrorCodeBusy}, {Code: SocketErrorCodeBusy}, {Code: SocketErrorCodeBusy}}
	results := make(chan error, 1)
	go func() {
		_, err := fixture.dial(testDialName)
		results <- err
	}()
	for _, backoff := range []time.Duration{DefaultSidecarSocketSettings().DialBusyBackoff, 2 * DefaultSidecarSocketSettings().DialBusyBackoff} {
		fixture.clock.awaitArmed(t, backoff)
		fixture.clock.advance(backoff)
	}
	if err := testSocketAwait(t, results, "the busy dial"); !errors.Is(err, ErrSocketBusy) {
		t.Errorf("busy: %v", err)
	}
	if len(fixture.service.findArgs()) != 3 {
		t.Errorf("busy: %d finds", len(fixture.service.findArgs()))
	}

	for _, missing := range []string{"ring", "labels"} {
		fixture := newTestDialFixture(t)
		if missing == "ring" {
			fixture.dialer.ring = nil
		} else {
			fixture.dialer.labels = nil
		}
		if _, err := fixture.dial(testDialName); !errors.Is(err, ErrSocketUnavailable) {
			t.Errorf("no %s: %v", missing, err)
		}
		if len(fixture.service.findArgs()) != 0 {
			t.Errorf("no %s: a find went", missing)
		}
	}
}

// The busy backoff doubles from DialBusyBackoff to DialBusyBackoffMax, within ±Jitter, and never under the service's
// own wait.
func TestSocketDialBusyBackoff(t *testing.T) {
	settings := DefaultSidecarSocketSettings()
	dialer := &socketDialer{settings: settings, random: func() float64 { return 0.5 }}
	for _, check := range []struct {
		busyCount  int
		retryAfter time.Duration
		want       time.Duration
	}{
		{busyCount: 1, want: settings.DialBusyBackoff},
		{busyCount: 2, want: 2 * settings.DialBusyBackoff},
		{busyCount: 10, want: settings.DialBusyBackoffMax},
		{busyCount: 1, retryAfter: 5 * time.Second, want: 5 * time.Second},
	} {
		if got := dialer.busyBackoff(check.busyCount, check.retryAfter); got != check.want {
			t.Errorf("after %d busy, retry after %v: %v, want %v", check.busyCount, check.retryAfter, got, check.want)
		}
	}
	dialer.random = func() float64 { return 0 }
	if got := dialer.busyBackoff(1, 0); got != time.Duration(float64(settings.DialBusyBackoff)*(1-settings.Jitter)) {
		t.Errorf("the low draw: %v", got)
	}
}
