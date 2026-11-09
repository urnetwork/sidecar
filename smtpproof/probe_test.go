// The census probe against scripted MXs on a pipe: each row SMTP-M7-01 names, pacing, the stop file,
// and that no MAIL, RCPT, DATA or BDAT byte ever reaches an MX.

package smtpproof

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A clock the test moves, with a way to wait for the probe to start waiting on it. Kept here because
// sidecartest's would bring its dependencies into this module.
type probeClock struct {
	stateLock sync.Mutex
	now       time.Time
	waiters   map[*probeWaiter]bool
	// Closed and replaced at each change to waiters.
	changed chan struct{}
}

// One pending wait.
type probeWaiter struct {
	at   time.Time
	fire func(at time.Time)
}

var _ sidecar.Clock = (*probeClock)(nil)

// A clock at start.
func newProbeClock(start time.Time) *probeClock {
	return &probeClock{now: start, waiters: map[*probeWaiter]bool{}, changed: make(chan struct{})}
}

// The clock's time.
func (self *probeClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Adds a waiter, under the lock.
func (self *probeClock) addWithLock(waiter *probeWaiter) {
	self.waiters[waiter] = true
	close(self.changed)
	self.changed = make(chan struct{})
}

// See sidecar.Clock.
func (self *probeClock) After(timeout time.Duration) <-chan time.Time {
	channel := make(chan time.Time, 1)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if timeout <= 0 {
		channel <- self.now
		return channel
	}
	self.addWithLock(&probeWaiter{at: self.now.Add(timeout), fire: func(at time.Time) { channel <- at }})
	return channel
}

// See sidecar.Clock.
func (self *probeClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	waiter := &probeWaiter{at: self.Now().Add(timeout), fire: func(time.Time) { go function() }}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.addWithLock(waiter)
	}()
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pending := self.waiters[waiter]
		delete(self.waiters, waiter)
		return pending
	}
}

// Moves time and fires what came due.
func (self *probeClock) Advance(timeout time.Duration) {
	due := []*probeWaiter{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.now = self.now.Add(timeout)
		for waiter := range self.waiters {
			if !self.now.Before(waiter.at) {
				due = append(due, waiter)
				delete(self.waiters, waiter)
			}
		}
	}()
	for _, waiter := range due {
		waiter.fire(waiter.at)
	}
}

// Waits until count waits are pending.
func (self *probeClock) awaitWaiters(ctx context.Context, count int) error {
	for {
		pending, changed := func() (int, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return len(self.waiters), self.changed
		}()
		if count <= pending {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// An MX that speaks a script: a banner, EHLO with its keywords, STARTTLS when offered, then TLS under
// tlsConfig and EHLO again. It keeps every line it hears, plaintext or inside TLS.
type scriptedMx struct {
	preTlsKeywords  []string
	postTlsKeywords []string
	// nil offers no STARTTLS, whatever the keywords say.
	tlsConfig *tls.Config
	// Written right after STARTTLS's 220, in the same write.
	afterStartTls string

	stateLock sync.Mutex
	heard     []string
	dials     int
}

// Every line heard so far, on every connection.
func (self *scriptedMx) lines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.heard...)
}

// How many connections it took.
func (self *scriptedMx) dialCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dials
}

// Keeps a line.
func (self *scriptedMx) hear(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heard = append(self.heard, strings.TrimRight(line, "\r\n"))
}

// A multi-line 250 for EHLO.
func scriptedEhloReply(keywords []string) string {
	lines := append([]string{testMxHost + " greets you"}, keywords...)
	reply := ""
	for i, line := range lines {
		separator := "-"
		if i == len(lines)-1 {
			separator = " "
		}
		reply += "250" + separator + line + "\r\n"
	}
	return reply
}

// Serves one connection.
func (self *scriptedMx) serve(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("220 " + testMxHost + " ESMTP\r\n"))
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		self.hear(line)
		switch strings.ToUpper(strings.Fields(line + " x")[0]) {
		case "EHLO":
			conn.Write([]byte(scriptedEhloReply(self.preTlsKeywords)))
		case "STARTTLS":
			if self.tlsConfig == nil {
				conn.Write([]byte("502 not offered\r\n"))
				continue
			}
			conn.Write([]byte("220 ready\r\n" + self.afterStartTls))
			secure := tls.Server(conn, self.tlsConfig)
			if err := secure.Handshake(); err != nil {
				return
			}
			self.serveSecure(secure)
			return
		case "QUIT":
			conn.Write([]byte("221 bye\r\n"))
			return
		default:
			conn.Write([]byte("500 unknown\r\n"))
		}
	}
}

// Serves the dialog inside TLS.
func (self *scriptedMx) serveSecure(conn *tls.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		self.hear(line)
		switch strings.ToUpper(strings.Fields(line + " x")[0]) {
		case "EHLO":
			conn.Write([]byte(scriptedEhloReply(self.postTlsKeywords)))
		case "QUIT":
			conn.Write([]byte("221 bye\r\n"))
			return
		default:
			conn.Write([]byte("500 unknown\r\n"))
		}
	}
}

// Settings whose every dial reaches mx, each domain's one MX resolving to address.
func probeTestSettings(mx *scriptedMx, address string) *MxProbeSettings {
	settings := DefaultMxProbeSettings()
	settings.HeloName = "o1.out.report.example"
	// no pacing on the real clock: TestProbeMxPacesDialsPerDestination24 paces on its own
	settings.DestinationInterval = 0
	settings.LookupMx = func(ctx context.Context, domain string) ([]*net.MX, error) {
		return []*net.MX{{Host: testMxHost + ".", Pref: 10}}, nil
	}
	settings.LookupAddresses = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(address)}, nil
	}
	settings.Dial = func(ctx context.Context, network string, target string) (net.Conn, error) {
		func() {
			mx.stateLock.Lock()
			defer mx.stateLock.Unlock()
			mx.dials += 1
		}()
		client, server := testPipe()
		go mx.serve(server)
		return client, nil
	}
	return settings
}

// The one row of probing domain.
func probeOne(t *testing.T, settings *MxProbeSettings, domain string) *MxProbeResult {
	t.Helper()
	rows := []*MxProbeResult{}
	if err := ProbeMx(context.Background(), []string{domain}, settings, func(result *MxProbeResult) { rows = append(rows, result) }); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	return rows[0]
}

// Fails when the MX heard any command a send makes past EHLO.
func assertNoMailCommand(t *testing.T, mx *scriptedMx) {
	t.Helper()
	for _, line := range mx.lines() {
		command := strings.ToUpper(strings.Fields(line + " x")[0])
		if command == "MAIL" || command == "RCPT" || command == "DATA" || command == "BDAT" {
			t.Fatalf("the MX heard %q", line)
		}
	}
}

func TestProbeMxCoveredTls13WithChunkingAfterTls(t *testing.T) {
	mx := &scriptedMx{
		preTlsKeywords:  []string{"PIPELINING", "STARTTLS"},
		postTlsKeywords: []string{"PIPELINING", "CHUNKING", "SIZE 52428800"},
		tlsConfig:       &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}},
	}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "recipient.example")
	if row.Outcome != MxProbeOutcomeCovered || row.TlsVersion != "TLS 1.3" || row.Failure != "" {
		t.Fatalf("%+v", row)
	}
	if row.TlsSuite != "TLS_AES_128_GCM_SHA256" && row.TlsSuite != "TLS_CHACHA20_POLY1305_SHA256" {
		t.Fatalf("suite %s", row.TlsSuite)
	}
	if !row.PreTlsPipelining || row.PreTlsChunking || !row.PostTlsPipelining || !row.PostTlsChunking {
		t.Fatalf("keywords %+v", row)
	}
	lines := mx.lines()
	if len(lines) != 4 || lines[0] != "EHLO o1.out.report.example" || lines[1] != "STARTTLS" || lines[2] != "EHLO o1.out.report.example" || lines[3] != "QUIT" {
		t.Fatalf("the MX heard %q", lines)
	}
	assertNoMailCommand(t, mx)
}

func TestProbeMxChunkingBeforeTlsOnly(t *testing.T) {
	mx := &scriptedMx{
		preTlsKeywords:  []string{"CHUNKING", "PIPELINING", "STARTTLS"},
		postTlsKeywords: []string{"8BITMIME"},
		tlsConfig:       &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}},
	}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "recipient.example")
	if row.Outcome != MxProbeOutcomeCovered || !row.PreTlsChunking || row.PostTlsChunking || row.PostTlsPipelining {
		t.Fatalf("%+v", row)
	}
	assertNoMailCommand(t, mx)
}

func TestProbeMxWithoutStartTls(t *testing.T) {
	mx := &scriptedMx{preTlsKeywords: []string{"PIPELINING", "CHUNKING"}}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "recipient.example")
	if row.Outcome != MxProbeOutcomeNoStartTls || row.TlsVersion != "" || !row.PreTlsChunking {
		t.Fatalf("%+v", row)
	}
	assertNoMailCommand(t, mx)
}

func TestProbeMxTls12Only(t *testing.T) {
	mx := &scriptedMx{
		preTlsKeywords:  []string{"STARTTLS"},
		postTlsKeywords: []string{"CHUNKING"},
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{testRsaCertificate(t)},
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
	}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "recipient.example")
	if row.Outcome != MxProbeOutcomeCovered || row.TlsVersion != "TLS 1.2" || row.TlsSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || !row.PostTlsChunking {
		t.Fatalf("%+v", row)
	}
	if mx.dialCount() != 1 {
		t.Fatalf("%d dials for a covered MX", mx.dialCount())
	}
	assertNoMailCommand(t, mx)
}

func TestProbeMxUncoveredSuite(t *testing.T) {
	mx := &scriptedMx{
		preTlsKeywords:  []string{"STARTTLS"},
		postTlsKeywords: []string{"PIPELINING"},
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{testRsaCertificate(t)},
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
	}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "recipient.example")
	if row.Outcome != MxProbeOutcomeUncovered || row.TlsVersion != "TLS 1.2" || row.TlsSuite != "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" || !row.PostTlsPipelining {
		t.Fatalf("%+v", row)
	}
	if mx.dialCount() != 2 {
		t.Fatalf("%d dials: the uncovered suite needs a second connection to name", mx.dialCount())
	}
	assertNoMailCommand(t, mx)
}

func TestProbeMxRefusesBytesAfterStartTls(t *testing.T) {
	mx := &scriptedMx{
		preTlsKeywords: []string{"STARTTLS"},
		tlsConfig:      &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}},
		afterStartTls:  "250 injected\r\n",
	}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "recipient.example")
	if row.Outcome != MxProbeOutcomeFailed || row.Failure != "starttls_trailing" {
		t.Fatalf("%+v", row)
	}
}

func TestProbeMxNullMxAndNoMx(t *testing.T) {
	settings := DefaultMxProbeSettings()
	settings.HeloName = "o1.out.report.example"
	settings.LookupMx = func(ctx context.Context, domain string) ([]*net.MX, error) {
		if domain == "null.example" {
			return []*net.MX{{Host: ".", Pref: 0}}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
	settings.LookupAddresses = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, nil
	}
	settings.Dial = func(ctx context.Context, network string, target string) (net.Conn, error) {
		t.Fatal("a domain with no MX was dialed")
		return nil, nil
	}
	if row := probeOne(t, settings, "null.example"); row.Outcome != MxProbeOutcomeNullMx {
		t.Fatalf("%+v", row)
	}
	if row := probeOne(t, settings, "nothing.example"); row.Outcome != MxProbeOutcomeNoMx {
		t.Fatalf("%+v", row)
	}
}

func TestProbeMxDialsNoAddressOutsidePublicIpv4(t *testing.T) {
	mx := &scriptedMx{preTlsKeywords: []string{"STARTTLS"}}
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "2001:db8::25"} {
		row := probeOne(t, probeTestSettings(mx, address), "recipient.example")
		if row.Outcome != MxProbeOutcomeFailed || row.Failure != "no_address" {
			t.Errorf("%s: %+v", address, row)
		}
	}
	if mx.dialCount() != 0 {
		t.Fatal("an address the edge would not dial was dialed")
	}
}

func TestProbeMxPacesDialsPerDestination24(t *testing.T) {
	mx := &scriptedMx{preTlsKeywords: []string{"PIPELINING"}}
	clock := newProbeClock(time.Date(2026, time.November, 3, 0, 0, 0, 0, time.UTC))
	settings := probeTestSettings(mx, "192.0.2.25")
	settings.Clock = clock
	settings.DestinationInterval = 10 * time.Second
	addresses := map[string]string{"a.example": "192.0.2.25", "b.example": "192.0.2.26", "c.example": "198.51.100.25"}
	settings.LookupMx = func(ctx context.Context, domain string) ([]*net.MX, error) {
		return []*net.MX{{Host: domain, Pref: 10}}, nil
	}
	settings.LookupAddresses = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(addresses[host])}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	rows := make(chan *MxProbeResult, 3)
	go func() {
		done <- ProbeMx(ctx, []string{"a.example", "b.example", "c.example"}, settings, func(result *MxProbeResult) { rows <- result })
	}()
	// a.example dials at once; b.example shares its /24, so its dial waits, with its MX timeout armed
	<-rows
	if err := clock.awaitWaiters(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if mx.dialCount() != 1 {
		t.Fatalf("%d dials before the interval passed", mx.dialCount())
	}
	clock.Advance(settings.DestinationInterval)
	// c.example's /24 is another, so it dials without waiting
	<-rows
	<-rows
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if mx.dialCount() != 3 {
		t.Fatalf("%d dials", mx.dialCount())
	}
}

func TestProbeMxStopsAtItsStopFile(t *testing.T) {
	mx := &scriptedMx{preTlsKeywords: []string{"PIPELINING"}}
	settings := probeTestSettings(mx, "192.0.2.25")
	settings.StopFile = filepath.Join(t.TempDir(), "stop")
	rows := []*MxProbeResult{}
	err := ProbeMx(context.Background(), []string{"a.example", "b.example"}, settings, func(result *MxProbeResult) {
		rows = append(rows, result)
		if err := os.WriteFile(settings.StopFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, ErrMxProbeStopped) || len(rows) != 1 {
		t.Fatalf("%v after %d rows", err, len(rows))
	}
}

func TestProbeMxRowNamesOnlyTheDomain(t *testing.T) {
	mx := &scriptedMx{
		preTlsKeywords:  []string{"STARTTLS"},
		postTlsKeywords: []string{"CHUNKING"},
		tlsConfig:       &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}},
	}
	row := probeOne(t, probeTestSettings(mx, "192.0.2.25"), "Recipient.Example.")
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if row.Domain != "recipient.example" {
		t.Fatalf("domain %q", row.Domain)
	}
	for _, named := range []string{testMxHost, "192.0.2.25", "greets you", "o1.out.report.example"} {
		if strings.Contains(string(encoded), named) {
			t.Fatalf("a row names %q: %s", named, encoded)
		}
	}
}

func TestProbeMxRefusesSettingsWithoutAHeloName(t *testing.T) {
	if err := ProbeMx(context.Background(), []string{"a.example"}, DefaultMxProbeSettings(), func(*MxProbeResult) {}); err == nil {
		t.Fatal("a probe ran with no helo name")
	}
}
