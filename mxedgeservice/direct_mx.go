// A Team's direct MX, mxedge's half (§15.4's Team paragraph, §12.8; R-MAIL-2, D-MAIL-12, I-8, I-15, FS-33; owner
// decisions 33, 98; MAIL-M7-23): POST /mail/direct-mx names up to two of the network's mail indexers answering public
// TCP 25 themselves, and this prober verifies each before §12.8 points mx.<net>.<root> at it, then re-probes them.
//
//	probe    one receiver's check, nothing past a TLS handshake: its address is public unicast (the engine's rule, and
//	         the host's §12.7 A rules where it gives them); TCP 25 answers a 220; EHLO's reply lists STARTTLS; STARTTLS
//	         answers 220; and a TLS handshake for the mail host's name presents a key whose SPKI SHA-256 is one of the
//	         receiver's published mail_host_key rows. Then the connection closes: no MAIL, RCPT or byte of mail, so a
//	         probe sends a receiver nothing it would deliver
//	record   each probe's outcome goes to the store: a pass marks the row verified, and the store points §12.8's
//	         records at every verified address and drops the network's {mxr_} routes; a failure marks it failing and
//	         changes no record, since a direct MX reverts only on DELETE (§15.4)
//	alert    a row failing for AlertAfter (15 min) raises MailHint{receiver_needed} to its network's published
//	         receivers, through the host's Alert, which hints them forced, off every connection's path
//	         (plan-MAIL-hints#2), once each AlertInterval while it fails; a device that misses it sees direct_mx in
//	         GET /mail/status. The failure's start is this process's memory, the row's last verify_time standing in
//	         after a restart
//	pace     a pass every ProbeInterval (5 min), at most ProbeConcurrency probes at once, each within ProbeTimeout
//
// The store and the dial are the host's (server/mxedgehost), so the engine imports no server package (§4.5); several
// router processes each probe, and the store's writes are idempotent: §12.8's write changes nothing when mx already
// names exactly the verified addresses. Nothing here logs an address, a name or a network (I-13). Safe for concurrent
// use.

package mxedgeservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// A direct-MX row's states, mail_direct_mx.state's words (MAIL-M7-21).
const (
	MxDirectMxStatePending  = "pending"
	MxDirectMxStateVerified = "verified"
	MxDirectMxStateFailing  = "failing"
)

// What a probe found: a closed set, a metric's words, never an address.
const (
	MxDirectMxProbeNotPublic   = "not_public"
	MxDirectMxProbeDial        = "dial"
	MxDirectMxProbeGreeting    = "greeting"
	MxDirectMxProbeNoStartTls  = "no_starttls"
	MxDirectMxProbeStartTls    = "starttls"
	MxDirectMxProbeHandshake   = "handshake"
	MxDirectMxProbeWrongKey    = "wrong_key"
	MxDirectMxProbeNoKey       = "no_key"
	MxDirectMxProbePassed      = "passed"
	MxDirectMxProbeStoreFailed = "store_failed"
)

// One direct-MX receiver as the prober reads it.
type MxDirectMxRow struct {
	NetworkId         sidecar.Id
	ReceiverSidecarId sidecar.Id
	// Its public server address, which §12.8 publishes as an A or AAAA record.
	Address netip.Addr
	// pending, verified or failing.
	State string
	// When its last probe passed; zero before one did.
	VerifyTime time.Time
	// The name a sender asks for: mx.<label>.<root>.
	Host string
	// The SHA-256 of each SPKI the receiver's published mail_host_key rows for mx hold: the keys its handshake may
	// present.
	SpkiSha256s [][]byte
	// The network's receivers whose key for mx is published, newest first: whom an alert hints.
	HintSidecarIds []sidecar.Id
}

// What the prober keeps in Postgres, behind an interface so the engine imports no server package (§4.5): server's
// model implements it. Called only from the prober's goroutines, never from a session. Safe for concurrent use.
type MxDirectMxStore interface {
	// Every direct-MX row, with what its probe checks.
	ListDirectMx(ctx context.Context) ([]*MxDirectMxRow, error)
	// One probe's outcome (the file header's record row).
	RecordDirectMxProbe(ctx context.Context, row *MxDirectMxRow, passed bool) error
}

// What the prober is tuned by. Every value must be positive.
type MxDirectMxSettings struct {
	// How often every row is probed again (§15.4's 5 min).
	ProbeInterval time.Duration
	// How long a row fails before its network's receivers are hinted (§15.4's 15 min).
	AlertAfter time.Duration
	// How often a failing row's alert is raised again while it fails.
	AlertInterval time.Duration
	// One probe's bound, from the dial to the handshake's end.
	ProbeTimeout time.Duration
	// Probes at once.
	ProbeConcurrency int
	// The most bytes of one reply read, past which the probe fails: a greeting or an EHLO reply far past any real
	// one.
	ReplyMaxByteCount int
	// The name the probe's EHLO gives: mxedge's banner name (MxEdgeSettings.BannerHostName).
	EhloName string
	// TCP 25.
	Port uint16
}

// The one default, but EhloName, which the host gives from mxedge.yml's banner_host.
func DefaultMxDirectMxSettings() *MxDirectMxSettings {
	return &MxDirectMxSettings{
		ProbeInterval:     5 * time.Minute,
		AlertAfter:        15 * time.Minute,
		AlertInterval:     time.Hour,
		ProbeTimeout:      30 * time.Second,
		ProbeConcurrency:  8,
		ReplyMaxByteCount: 16 * 1024,
		Port:              25,
	}
}

// Whether every value is in range.
func (self *MxDirectMxSettings) valid() bool {
	return self != nil && 0 < self.ProbeInterval && 0 < self.AlertAfter && 0 < self.AlertInterval && 0 < self.ProbeTimeout &&
		0 < self.ProbeConcurrency && 0 < self.ReplyMaxByteCount && self.EhloName != "" && 0 < self.Port
}

// What NewMxDirectMxProber builds on.
type MxDirectMxProberArgs struct {
	Store MxDirectMxStore
	// TCP to a receiver's address: the host's dialer, a test's pipe.
	Dial func(ctx context.Context, address netip.AddrPort) (net.Conn, error)
	// The host's §12.7 A rules (dnsservice.ValidateDirectMxAddresses' rule) beside the engine's own; nil adds none.
	PublicAddress func(address netip.Addr) bool
	// Hints a failing row's network's receivers forced with MailHint{receiver_needed} (plan-MAIL-hints#2); nil
	// raises none.
	Alert func(ctx context.Context, row *MxDirectMxRow) error
	// Nil is real time.
	Clock sidecar.Clock
	// Nil discards.
	Log      sidecar.Logger
	Settings *MxDirectMxSettings
}

// The key of one row: its network, receiver and address.
type mxDirectMxKey struct {
	networkId         sidecar.Id
	receiverSidecarId sidecar.Id
	address           netip.Addr
}

// What the prober remembers of a failing row.
type mxDirectMxFailing struct {
	since     time.Time
	alertedAt time.Time
}

// A Team direct MX's prober (see the file header).
type MxDirectMxProber struct {
	args     *MxDirectMxProberArgs
	settings *MxDirectMxSettings
	clock    sidecar.Clock
	log      sidecar.Logger

	stateLock sync.Mutex
	failing   map[mxDirectMxKey]*mxDirectMxFailing
}

// A prober over args, which probes nothing until Run or ProbeAll.
func NewMxDirectMxProber(args *MxDirectMxProberArgs) (*MxDirectMxProber, error) {
	if args == nil || args.Store == nil || args.Dial == nil || !args.Settings.valid() {
		return nil, errors.New("a direct-MX prober needs its store, dial and settings")
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &MxDirectMxProber{args: args, settings: args.Settings, clock: clock, log: log, failing: map[mxDirectMxKey]*mxDirectMxFailing{}}, nil
}

// Probes every row now, then every ProbeInterval, until ctx ends. Its owner calls it once.
func (self *MxDirectMxProber) Run(ctx context.Context) {
	for {
		self.ProbeAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.ProbeInterval):
		}
	}
}

// One pass over every row: each probed, its outcome recorded, a row failing past AlertAfter alerted. Returns once
// every probe of the pass has ended.
func (self *MxDirectMxProber) ProbeAll(ctx context.Context) {
	rows, err := self.args.Store.ListDirectMx(ctx)
	if err != nil {
		self.log.Warningf("[mxedge]the direct-MX rows were not read: %T", err)
		return
	}
	slots := make(chan struct{}, self.settings.ProbeConcurrency)
	var group sync.WaitGroup
	defer group.Wait()
	for _, row := range rows {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		group.Go(func() {
			defer func() { <-slots }()
			self.probeAndRecord(ctx, row)
		})
	}
	group.Wait()
	self.forgetGone(rows)
}

// One row: its probe, its outcome to the store, and its alert where it has failed long enough.
func (self *MxDirectMxProber) probeAndRecord(ctx context.Context, row *MxDirectMxRow) string {
	probeCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.ProbeTimeout, cancel)
	result := self.Probe(probeCtx, row)
	stop()
	cancel()
	passed := result == MxDirectMxProbePassed
	if err := self.args.Store.RecordDirectMxProbe(ctx, row, passed); err != nil {
		self.log.Warningf("[mxedge]a direct-MX probe's outcome was not recorded: %T", err)
		return MxDirectMxProbeStoreFailed
	}
	key := mxDirectMxKey{networkId: row.NetworkId, receiverSidecarId: row.ReceiverSidecarId, address: row.Address}
	now := self.clock.Now()
	alert := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if passed {
			delete(self.failing, key)
			return
		}
		failing := self.failing[key]
		if failing == nil {
			// a restart forgot when it began: the last pass bounds it, else now
			since := now
			if !row.VerifyTime.IsZero() && row.VerifyTime.Before(now) {
				since = row.VerifyTime
			}
			failing = &mxDirectMxFailing{since: since}
			self.failing[key] = failing
		}
		if self.settings.AlertAfter <= now.Sub(failing.since) && (failing.alertedAt.IsZero() || self.settings.AlertInterval <= now.Sub(failing.alertedAt)) {
			failing.alertedAt = now
			alert = true
		}
	}()
	if alert && self.args.Alert != nil {
		if err := self.args.Alert(ctx, row); err != nil {
			self.log.Warningf("[mxedge]a direct-MX alert was not raised: %T", err)
		}
	}
	return result
}

// Drops what is remembered of rows no longer listed: deleted, or their receiver removed.
func (self *MxDirectMxProber) forgetGone(rows []*MxDirectMxRow) {
	listed := map[mxDirectMxKey]bool{}
	for _, row := range rows {
		listed[mxDirectMxKey{networkId: row.NetworkId, receiverSidecarId: row.ReceiverSidecarId, address: row.Address}] = true
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for key := range self.failing {
		if !listed[key] {
			delete(self.failing, key)
		}
	}
}

// Whether address is one a direct MX may name at all, by the engine's own rule: a unicast address with no zone, outside
// loopback, link-local, multicast, the unspecified and the private ranges. The host's §12.7 rules narrow it further.
func MxDirectMxAddressPublic(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsPrivate()
}

// One row's probe (the file header's probe row): MxDirectMxProbePassed, else why it failed. Nothing past the TLS
// handshake is sent.
func (self *MxDirectMxProber) Probe(ctx context.Context, row *MxDirectMxRow) string {
	if !MxDirectMxAddressPublic(row.Address) || (self.args.PublicAddress != nil && !self.args.PublicAddress(row.Address)) {
		return MxDirectMxProbeNotPublic
	}
	if len(row.SpkiSha256s) == 0 {
		// no published key to hold a handshake to: nothing could pass
		return MxDirectMxProbeNoKey
	}
	conn, err := self.args.Dial(ctx, netip.AddrPortFrom(row.Address.Unmap(), self.settings.Port))
	if err != nil {
		return MxDirectMxProbeDial
	}
	defer conn.Close()
	// every wait ends with the probe's context, on the engine's clock
	stopWatch := context.AfterFunc(ctx, func() {
		conn.SetDeadline(mxPastDeadline)
	})
	defer stopWatch()
	reader := bufio.NewReader(conn)
	if code, _, err := self.readReply(reader); err != nil || code != 220 {
		return MxDirectMxProbeGreeting
	}
	if _, err := io.WriteString(conn, "EHLO "+self.settings.EhloName+"\r\n"); err != nil {
		return MxDirectMxProbeGreeting
	}
	code, lines, err := self.readReply(reader)
	if err != nil || code != 250 {
		return MxDirectMxProbeGreeting
	}
	startTls := false
	for _, line := range lines[1:] {
		if strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
			startTls = true
		}
	}
	if !startTls {
		return MxDirectMxProbeNoStartTls
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return MxDirectMxProbeStartTls
	}
	if code, _, err := self.readReply(reader); err != nil || code != 220 || 0 < reader.Buffered() {
		// a byte behind the 220 is the CVE-2011-0411 class: no handshake over it
		return MxDirectMxProbeStartTls
	}
	wrongKey := false
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: row.Host,
		MinVersion: tls.VersionTLS12,
		// the key is held to the published SPKI, as DANE's 3 1 1 does, not to a CA
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				wrongKey = true
				return errors.New("no certificate")
			}
			if !mxDirectMxSpkiPublished(state.PeerCertificates[0], row.SpkiSha256s) {
				wrongKey = true
				return errors.New("a key no published mail_host_key holds")
			}
			return nil
		},
	})
	err = tlsConn.HandshakeContext(ctx)
	tlsConn.Close()
	switch {
	case wrongKey:
		return MxDirectMxProbeWrongKey
	case err != nil:
		return MxDirectMxProbeHandshake
	}
	return MxDirectMxProbePassed
}

// Whether certificate's SPKI SHA-256 is one of spkiSha256s.
func mxDirectMxSpkiPublished(certificate *x509.Certificate, spkiSha256s [][]byte) bool {
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	for _, published := range spkiSha256s {
		if bytes.Equal(published, sum[:]) {
			return true
		}
	}
	return false
}

// One SMTP reply: its code and its lines' text past the code, within ReplyMaxByteCount.
func (self *MxDirectMxProber) readReply(reader *bufio.Reader) (int, []string, error) {
	lines := []string{}
	readByteCount := 0
	for {
		line, err := reader.ReadSlice('\n')
		readByteCount += len(line)
		if err != nil || self.settings.ReplyMaxByteCount < readByteCount {
			return 0, nil, fmt.Errorf("a reply that did not end within its bound")
		}
		text := strings.TrimRight(string(line), "\r\n")
		if len(text) < 3 {
			return 0, nil, errors.New("a reply line with no code")
		}
		code := 0
		if _, err := fmt.Sscanf(text[:3], "%d", &code); err != nil {
			return 0, nil, errors.New("a reply line with no code")
		}
		rest := ""
		if 3 < len(text) {
			rest = text[4:]
		}
		lines = append(lines, rest)
		if len(text) == 3 || text[3] == ' ' {
			return code, lines, nil
		}
		if text[3] != '-' {
			return 0, nil, errors.New("a reply line of no form")
		}
	}
}
