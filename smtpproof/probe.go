// §14.5's coverage probe for §15's census (D-SMTP-16, D-MAIL-9, R-SMTP-13): for each domain of a list,
// what its MX offers an outbound send before MAIL. It resolves MX, dials TCP 25, reads the banner,
// sends EHLO, STARTTLS, handshakes through tlsClient, the provers' own client, with a peer check that
// records and accepts, sends EHLO inside TLS and then QUIT. It never sends MAIL, RCPT, DATA, BDAT or
// any mail. When tlsClient's handshake fails, which it does for any version or suite outside E1's, a
// second connection asks crypto/tls what the MX does offer, so the row can say what is uncovered.
//
// A row names only the domain: no MX host, no address, no certificate, no reply text. Dials are paced
// per destination /24, and a stop file ends the run before its next domain. The domain list is an
// input, so no ranking data and no real name is kept in the repository. The run itself needs port 25
// and is external; smtpproof/mxprobe is the command around ProbeMx.

package smtpproof

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

const (
	// RFC 5321 §4.5.3.1.5: a reply line's octets, CRLF included.
	mxProbeLineMaxByteCount = 512
	// The most lines one reply may take. EHLO replies run to a few dozen.
	mxProbeReplyMaxLineCount = 64
)

// What a row's outcome says.
const (
	// tlsClient's handshake succeeded: the MX speaks a version and suite E1 covers.
	MxProbeOutcomeCovered = "covered"
	// Only crypto/tls's handshake succeeded: the version or suite is outside E1's.
	MxProbeOutcomeUncovered = "uncovered"
	// No MX tried offered STARTTLS.
	MxProbeOutcomeNoStartTls = "no_starttls"
	// No MX and no address: the domain takes no mail.
	MxProbeOutcomeNoMx = "no_mx"
	// RFC 7505's null MX.
	MxProbeOutcomeNullMx = "null_mx"
	// Every MX tried failed before it could say; Failure says where.
	MxProbeOutcomeFailed = "failed"
)

// A run the stop file ended before its list did.
var ErrMxProbeStopped = errors.New("mx probe stopped by its stop file")

// How a run dials, resolves and paces. DefaultMxProbeSettings is the only source of a default.
type MxProbeSettings struct {
	// What EHLO gives: an LDH name whose A record names the probing address, as FCrDNS asks (§14.6).
	// No default.
	HeloName string
	// Dials an MX on TCP 25. nil is a net.Dialer's.
	Dial func(ctx context.Context, network string, address string) (net.Conn, error)
	// MX records. nil is net.DefaultResolver's.
	LookupMx func(ctx context.Context, domain string) ([]*net.MX, error)
	// An MX host's IPv4 addresses. nil is net.DefaultResolver's.
	LookupAddresses func(ctx context.Context, host string) ([]netip.Addr, error)
	// Whether an address may be dialed. nil allows public unicast IPv4 only, as the edge dials
	// (owner decision 34).
	AddressAllowed func(address netip.Addr) bool
	// nil is real time.
	Clock sidecar.Clock
	// How long one MX's whole exchange may take. Default 60 s, a few of RFC 5321's waits.
	MxTimeout time.Duration
	// The least time between two dials into one destination /24. Default 10 s, so a large list
	// costs any one operator no more than a trickle.
	DestinationInterval time.Duration
	// The most MXs tried per domain, in preference order. Default 3.
	MxCount int
	// When a file exists here, the run ends before its next domain. Empty: no stop file.
	StopFile string
}

// The defaults every number is read from. HeloName stays empty.
func DefaultMxProbeSettings() *MxProbeSettings {
	return &MxProbeSettings{
		MxTimeout:           60 * time.Second,
		DestinationInterval: 10 * time.Second,
		MxCount:             3,
	}
}

// One domain's census row.
type MxProbeResult struct {
	Domain string `json:"domain"`
	// MxProbeOutcome*.
	Outcome string `json:"outcome"`
	// The MX's pre-TLS EHLO keywords: hints only, since only the post-TLS reply binds (RFC 3207 §4.2).
	PreTlsChunking   bool `json:"pre_tls_chunking"`
	PreTlsPipelining bool `json:"pre_tls_pipelining"`
	// "TLS 1.3", "TLS 1.2" and so on, and the IANA suite name, covered or not.
	TlsVersion string `json:"tls_version,omitempty"`
	TlsSuite   string `json:"tls_suite,omitempty"`
	// The post-TLS EHLO keywords, which decide BDAT or DATA and pipelining (§14.4).
	PostTlsChunking   bool `json:"post_tls_chunking"`
	PostTlsPipelining bool `json:"post_tls_pipelining"`
	// Where it failed, a word: dial, no_address, banner, ehlo, starttls, starttls_trailing,
	// handshake, post_tls_ehlo, lookup. Empty when nothing did.
	Failure string `json:"failure,omitempty"`
}

// Probes each domain in order, emitting one row each. It ends early with ErrMxProbeStopped when the
// stop file appears, or with ctx's error.
func ProbeMx(ctx context.Context, domains []string, settings *MxProbeSettings, emit func(result *MxProbeResult)) error {
	if settings == nil || settings.HeloName == "" {
		return errors.New("mx probe: no helo name")
	}
	if settings.MxTimeout <= 0 || settings.DestinationInterval < 0 || settings.MxCount <= 0 {
		return errors.New("mx probe: a bound that is not positive")
	}
	prober := &mxProber{settings: settings, clock: settings.Clock, nextDials: map[netip.Prefix]time.Time{}}
	if prober.clock == nil {
		prober.clock = sidecar.RealClock{}
	}
	for _, domain := range domains {
		if err := ctx.Err(); err != nil {
			return err
		}
		if settings.StopFile != "" {
			if _, err := os.Stat(settings.StopFile); err == nil {
				return ErrMxProbeStopped
			}
		}
		emit(prober.probeDomain(ctx, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")))
	}
	return nil
}

// One run's pacing state. Not safe for concurrent use.
type mxProber struct {
	settings *MxProbeSettings
	clock    sidecar.Clock
	// When each destination /24 may next be dialed.
	nextDials map[netip.Prefix]time.Time
}

// Whether address may be dialed.
func (self *mxProber) allowed(address netip.Addr) bool {
	if self.settings.AddressAllowed != nil {
		return self.settings.AddressAllowed(address)
	}
	return address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate()
}

// The domain's MX hosts in preference order, or an outcome when there is none to try.
func (self *mxProber) mxHosts(ctx context.Context, domain string) ([]string, string) {
	lookupMx := self.settings.LookupMx
	if lookupMx == nil {
		lookupMx = net.DefaultResolver.LookupMX
	}
	records, err := lookupMx(ctx, domain)
	if err != nil {
		var dnsError *net.DNSError
		if !errors.As(err, &dnsError) || !dnsError.IsNotFound {
			return nil, MxProbeOutcomeFailed
		}
	}
	if len(records) == 1 && (records[0].Host == "." || records[0].Host == "") {
		return nil, MxProbeOutcomeNullMx
	}
	if len(records) == 0 {
		// RFC 5321 §5.1's implicit MX: the domain's own address (plan-SMTP-small-readings#13)
		return []string{domain}, ""
	}
	slices.SortStableFunc(records, func(a *net.MX, b *net.MX) int { return int(a.Pref) - int(b.Pref) })
	hosts := []string{}
	for _, record := range records {
		hosts = append(hosts, strings.TrimSuffix(strings.ToLower(record.Host), "."))
	}
	return hosts, ""
}

// One domain's row: the first MX tried that reaches TLS decides it, else the best of what the others
// reached.
func (self *mxProber) probeDomain(ctx context.Context, domain string) *MxProbeResult {
	hosts, outcome := self.mxHosts(ctx, domain)
	if outcome != "" {
		result := &MxProbeResult{Domain: domain, Outcome: outcome}
		if outcome == MxProbeOutcomeFailed {
			result.Failure = "lookup"
		}
		return result
	}
	var best *MxProbeResult
	for i, host := range hosts {
		if self.settings.MxCount <= i {
			break
		}
		result := self.probeHost(ctx, domain, host)
		if result.Outcome == MxProbeOutcomeCovered || result.Outcome == MxProbeOutcomeUncovered {
			return result
		}
		if best == nil || (best.Outcome == MxProbeOutcomeFailed && result.Outcome != MxProbeOutcomeFailed) {
			best = result
		}
		if result.Failure == "no_address" && len(hosts) == 1 && host == domain {
			// an implicit MX with no address: the domain takes no mail
			return &MxProbeResult{Domain: domain, Outcome: MxProbeOutcomeNoMx}
		}
	}
	return best
}

// Waits until address's /24 may be dialed, and marks the dial.
func (self *mxProber) pace(ctx context.Context, address netip.Addr) error {
	prefix, err := address.Prefix(24)
	if err != nil {
		return err
	}
	now := self.clock.Now()
	if next, ok := self.nextDials[prefix]; ok && now.Before(next) {
		select {
		case <-self.clock.After(next.Sub(now)):
		case <-ctx.Done():
			return ctx.Err()
		}
		now = self.clock.Now()
	}
	self.nextDials[prefix] = now.Add(self.settings.DestinationInterval)
	return nil
}

// A conn opened to address on TCP 25.
func (self *mxProber) dial(ctx context.Context, address netip.Addr) (net.Conn, error) {
	if err := self.pace(ctx, address); err != nil {
		return nil, err
	}
	dial := self.settings.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return dial(ctx, "tcp4", netip.AddrPortFrom(address, 25).String())
}

// One MX's exchange, bounded by MxTimeout on the run's clock.
func (self *mxProber) probeHost(ctx context.Context, domain string, host string) *MxProbeResult {
	result := &MxProbeResult{Domain: domain, Outcome: MxProbeOutcomeFailed}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.MxTimeout, cancel)
	defer stop()
	lookupAddresses := self.settings.LookupAddresses
	if lookupAddresses == nil {
		lookupAddresses = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		}
	}
	addresses, _ := lookupAddresses(ctx, host)
	var address netip.Addr
	for _, candidate := range addresses {
		if self.allowed(candidate.Unmap()) {
			address = candidate.Unmap()
			break
		}
	}
	if !address.IsValid() {
		result.Failure = "no_address"
		return result
	}
	conn, err := self.dial(ctx, address)
	if err != nil {
		result.Failure = "dial"
		return result
	}
	// a cancelled context wakes any blocked read or write, as tlsClient's own waits do
	defer conn.Close()
	stopDeadline := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stopDeadline()
	reader := bufio.NewReaderSize(conn, mxProbeLineMaxByteCount)
	plain := &mxProbePlainReader{reader: reader}
	if code, _, err := mxProbeReadReply(plain); err != nil || code != "220" {
		result.Failure = "banner"
		return result
	}
	keywords, err := mxProbeEhlo(conn, plain, self.settings.HeloName)
	if err != nil {
		result.Failure = "ehlo"
		return result
	}
	result.PreTlsChunking = keywords["CHUNKING"]
	result.PreTlsPipelining = keywords["PIPELINING"]
	if !keywords["STARTTLS"] {
		result.Outcome = MxProbeOutcomeNoStartTls
		mxProbeQuit(conn, plain)
		return result
	}
	if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
		result.Failure = "starttls"
		return result
	}
	if code, _, err := mxProbeReadReply(plain); err != nil || code != "220" {
		result.Failure = "starttls"
		return result
	}
	if 0 < reader.Buffered() {
		// bytes after STARTTLS's 220 and before any handshake: RFC 3207 §5's injection, refused
		result.Failure = "starttls_trailing"
		return result
	}
	if self.probeCovered(ctx, conn, host, result) {
		return result
	}
	// tlsClient refused or failed: what does the MX offer, on a fresh connection?
	self.probeUncovered(ctx, address, host, result)
	return result
}

// The handshake through tlsClient, then EHLO and QUIT inside TLS. True when it got as far as TLS.
func (self *mxProber) probeCovered(ctx context.Context, conn net.Conn, host string, result *MxProbeResult) bool {
	settings := defaultTlsClientSettings()
	settings.serverName = host
	// a probe authenticates nothing and sends nothing worth protecting: it records and accepts
	settings.verifyPeer = func(chain []*x509.Certificate) error { return nil }
	client := newTlsClient(conn, settings)
	handshake, err := client.handshake(ctx)
	if err != nil {
		return false
	}
	result.Outcome = MxProbeOutcomeCovered
	result.TlsVersion = tls.VersionName(handshake.version)
	result.TlsSuite = tls.CipherSuiteName(handshake.suite)
	if !tlsSuiteCovered(handshake.version, handshake.suite) {
		// tlsClient offers only E1's, so a server choosing another broke the handshake's rules
		result.Outcome = MxProbeOutcomeFailed
		result.Failure = "handshake"
		return true
	}
	secure := &mxProbeTlsReader{ctx: ctx, client: client}
	write := func(line string) error {
		sealed, err := client.sealApplication([]byte(line))
		if err != nil {
			return err
		}
		return client.writeSealed(sealed)
	}
	if err := write("EHLO " + self.settings.HeloName + "\r\n"); err != nil {
		result.Failure = "post_tls_ehlo"
		return true
	}
	code, lines, err := mxProbeReadReply(secure)
	if err != nil || code != "250" {
		result.Failure = "post_tls_ehlo"
		return true
	}
	keywords := mxProbeKeywords(lines)
	result.PostTlsChunking = keywords["CHUNKING"]
	result.PostTlsPipelining = keywords["PIPELINING"]
	// QUIT, then its reply, before closing (RFC 5321 §4.1.1.10)
	if write("QUIT\r\n") == nil {
		mxProbeReadReply(secure)
	}
	return true
}

// A second connection through crypto/tls, offering every version and suite it has, to name what the MX
// speaks that E1 does not.
func (self *mxProber) probeUncovered(ctx context.Context, address netip.Addr, host string, result *MxProbeResult) {
	result.Outcome = MxProbeOutcomeFailed
	result.Failure = "handshake"
	conn, err := self.dial(ctx, address)
	if err != nil {
		return
	}
	defer conn.Close()
	stopDeadline := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stopDeadline()
	plain := &mxProbePlainReader{reader: bufio.NewReaderSize(conn, mxProbeLineMaxByteCount)}
	if code, _, err := mxProbeReadReply(plain); err != nil || code != "220" {
		return
	}
	if keywords, err := mxProbeEhlo(conn, plain, self.settings.HeloName); err != nil || !keywords["STARTTLS"] {
		return
	}
	if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
		return
	}
	if code, _, err := mxProbeReadReply(plain); err != nil || code != "220" {
		return
	}
	suites := []uint16{}
	for _, suite := range slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites()) {
		suites = append(suites, suite.ID)
	}
	secure := tls.Client(conn, &tls.Config{
		ServerName: host,
		// a probe authenticates nothing: it asks only what the MX speaks
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       suites,
	})
	if err := secure.HandshakeContext(ctx); err != nil {
		return
	}
	state := secure.ConnectionState()
	result.Outcome = MxProbeOutcomeUncovered
	result.Failure = ""
	result.TlsVersion = tls.VersionName(state.Version)
	result.TlsSuite = tls.CipherSuiteName(state.CipherSuite)
	secureReader := &mxProbePlainReader{reader: bufio.NewReaderSize(secure, mxProbeLineMaxByteCount)}
	keywords, err := mxProbeEhlo(secure, secureReader, self.settings.HeloName)
	if err != nil {
		result.Failure = "post_tls_ehlo"
		return
	}
	result.PostTlsChunking = keywords["CHUNKING"]
	result.PostTlsPipelining = keywords["PIPELINING"]
	mxProbeQuit(secure, secureReader)
}

// Reads reply lines, each through its CRLF.
type mxProbeLineReader interface {
	readLine() (string, error)
}

// Lines from a plaintext conn, or from crypto/tls's.
type mxProbePlainReader struct {
	reader *bufio.Reader
}

// See mxProbeLineReader. A line past RFC 5321's 512 octets fails.
func (self *mxProbePlainReader) readLine() (string, error) {
	line, err := self.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New("mx probe: a reply line past 512 octets")
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

// Lines from tlsClient's records: application data gathered, a ticket or other handshake message
// skipped, an alert ending the read.
type mxProbeTlsReader struct {
	ctx     context.Context
	client  *tlsClient
	pending []byte
}

// See mxProbeLineReader.
func (self *mxProbeTlsReader) readLine() (string, error) {
	for {
		if end := strings.Index(string(self.pending), "\r\n"); 0 <= end {
			line := string(self.pending[:end+2])
			self.pending = self.pending[end+2:]
			return line, nil
		}
		if mxProbeLineMaxByteCount < len(self.pending) {
			return "", errors.New("mx probe: a reply line past 512 octets")
		}
		record, err := self.client.readRecord(self.ctx)
		if err != nil {
			return "", err
		}
		switch record.recordType {
		case tlsRecordApplicationData:
			self.pending = append(self.pending, record.content...)
		case tlsRecordHandshake:
		default:
			return "", fmt.Errorf("mx probe: a record of type %d", record.recordType)
		}
	}
}

// One reply (RFC 5321 §4.2): its code and each line's text after the code and separator.
func mxProbeReadReply(reader mxProbeLineReader) (string, []string, error) {
	code := ""
	lines := []string{}
	for range mxProbeReplyMaxLineCount {
		line, err := reader.readLine()
		if err != nil {
			return "", nil, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if len(line) < 3 || (code != "" && line[:3] != code) {
			return "", nil, errors.New("mx probe: a malformed reply")
		}
		code = line[:3]
		if len(line) == 3 {
			return code, append(lines, ""), nil
		}
		lines = append(lines, line[4:])
		switch line[3] {
		case ' ':
			return code, lines, nil
		case '-':
		default:
			return "", nil, errors.New("mx probe: a malformed reply")
		}
	}
	return "", nil, errors.New("mx probe: a reply of too many lines")
}

// An EHLO reply's keywords, uppercased (RFC 5321 §4.1.1.1): the first word of each line after the
// greeting.
func mxProbeKeywords(lines []string) map[string]bool {
	keywords := map[string]bool{}
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if fields := strings.Fields(line); 0 < len(fields) {
			keywords[strings.ToUpper(fields[0])] = true
		}
	}
	return keywords
}

// Sends EHLO and reads its keywords.
func mxProbeEhlo(conn net.Conn, reader mxProbeLineReader, heloName string) (map[string]bool, error) {
	if _, err := conn.Write([]byte("EHLO " + heloName + "\r\n")); err != nil {
		return nil, err
	}
	code, lines, err := mxProbeReadReply(reader)
	if err != nil {
		return nil, err
	}
	if code != "250" {
		return nil, fmt.Errorf("mx probe: EHLO answered %s", code)
	}
	return mxProbeKeywords(lines), nil
}

// Sends QUIT and reads its reply before the caller closes (RFC 5321 §4.1.1.10). Errors change nothing:
// the row is already decided.
func mxProbeQuit(conn net.Conn, reader mxProbeLineReader) {
	if _, err := conn.Write([]byte("QUIT\r\n")); err == nil {
		mxProbeReadReply(reader)
	}
}
