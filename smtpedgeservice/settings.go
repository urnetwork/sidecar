// config/<env>/smtpedge.yml (§14.14). DefaultSmtpEdgeSettings is the only source of a default
// (connect/CODESTYLE.md:144), and LoadSmtpEdgeSettings lays a file over it. Protocol and format limits
// are settings too, with the protocol's value as their default (QD-702), and smtpedge.yml never sets
// them (yaml "-"): changing one is a protocol change, never a deployment's.
//
// One file serves both roles that load it: the edge (SMTP-M9-13 on), and the report intake in
// mxedge's platform block (plan-SMTP-report-intake-home), which reads the names, the sending
// addresses, the loop allowlist and the report bounds.
//
// Every number must be positive. Validate refuses anything else, so a zero is never unlimited or off,
// and no reader has to decide what one means.

package smtpedgeservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// An smtpedge.yml that cannot be served from. The wrapping error names the field, never its value.
var ErrSmtpEdgeSettingsRefused = errors.New("smtpedge.yml refused")

// One sending address (owner decision 124) with the PTR name its HELO repeats and the fwmark that
// source-routes a dial from it (plan-SMTP-small-readings#18). Fwmark 0 is the block's own mark.
type SmtpSendingAddress struct {
	// A shared lb IPv4 address.
	Address netip.Addr `yaml:"address"`
	// o<k>.out.bringyour.com in production (§14.6): the address's PTR name.
	HeloName string `yaml:"helo"`
	Fwmark   int    `yaml:"fwmark"`
}

// What config/<env>/smtpedge.yml sets, by the yaml names here. A duration takes Go's form, as 10m.
// DefaultSmtpEdgeSettings or LoadSmtpEdgeSettings make one, and the constructors refuse what Validate
// refuses. Safe to read concurrently once loaded, and never changed after.
type SmtpEdgeSettings struct {
	// <root>, the zone networks' names sit under (§12). No default: it is a production name, which the
	// file sets. An LDH name, compared without case.
	Root string `yaml:"root"`
	// rpt.bringyour.com in production (D-SMTP-19): the host every network's rua names. No default.
	ReportHostName string `yaml:"report_host"`
	// The domain every sending address's HELO name sits under: bringyour.com in production, whose
	// o<k>.out names are the PTRs (owner decision 124, §14.6). No default; the edge's config refuses a file
	// without it (SmtpEdgeConfig), and the intake reads none.
	HeloDomain string `yaml:"helo_domain"`
	// The sending set (§14.6). Report rows from any other source IP are dropped at parse, since
	// third-party addresses are never stored (§2.8 smtp-5). The edge is not ready with none.
	SendingAddresses []SmtpSendingAddress `yaml:"sending_addresses"`
	// Feedback-loop operators, by the DKIM d= their reports verify under (§14.8). Only these count
	// for an ARF report. Empty by default, so no complaint counts until the file names one.
	LoopAllowlist []string `yaml:"loop_allowlist"`

	// How long a stream may take to send its SmtpPreamble once open (§14.5). Default 30 s, the
	// ticket's own (plan-SMTP-data-connection-lifetime).
	PreambleTimeout time.Duration `yaml:"preamble_timeout"`
	// How long the edge's pre-TLS dialog may take for each MX it tries, from the dial to STARTTLS's
	// 220 (§14.4). Default 5 min, RFC 5321 §4.5.3.2's command timeouts.
	PreTlsTimeout time.Duration `yaml:"pre_tls_timeout"`
	// How long a connection may idle after a client record (§14.4, RFC 5321 §4.5.3.2.6). Default 10 min.
	ClientIdleTimeout time.Duration `yaml:"client_idle_timeout"`
	// How long a connection may idle after a server record (§14.4, RFC 5321 §4.5.3.2.7). Default 5 min.
	ServerIdleTimeout time.Duration `yaml:"server_idle_timeout"`
	// The longest a BDAT connection lives (§14.4). Default 30 min.
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	// The longest a DATA-mode connection lives (§14.4, D-SMTP-20). Default 2 h.
	DataConnectionTimeout time.Duration `yaml:"data_connection_timeout"`
	// How often an edge reloads ActiveHalts (§14.8). Default 60 s, as §14.8 has it. The skeleton's
	// readiness probe runs on it too, until SMTP-M9-16's reloader takes it over.
	HaltReloadInterval time.Duration `yaml:"halt_reload_interval"`
	// How long one store call may take before it reads as an error. Default 5 s: every store call is
	// off the connection path, so this bounds a batch or a report, never a preamble.
	StoreTimeout time.Duration `yaml:"store_timeout"`
	// The most send records in one InsertSends. Default 500, a batch Postgres takes in one statement.
	SendBatchCount int `yaml:"send_batch_count"`
	// How long a send record may wait for its batch. Default 10 s, as §15.4's connection records.
	SendBatchInterval time.Duration `yaml:"send_batch_interval"`
	// The longest TLS record a connection relays either way, its 5-octet header included: TLS 1.2's bound on
	// ciphertext, 2^14 + 2,048 (RFC 5246 §6.2.3), past any 1.3 record's 2^14 + 256 (RFC 8446 §5.2). Default
	// 18,437: a protocol limit, never a deployment's.
	RecordMaxByteCount int `yaml:"-"`
	// The largest SmtpProof or SmtpHandshake request taken (DESIGN-DETAILS 3.7): a part is under 3 KiB.
	// Default 16,384.
	ProofMaxByteCount int `yaml:"-"`
	// The most client octets a connection hands its session that the session has not yet cleared for the MX:
	// past it the edge stops reading the sidecar's stream until a part clears them, back-pressure and never a
	// buffer (§14.5's E3 holds records for their part). Default 256 KiB, many times a header block and a
	// pipelined envelope.
	ConnectionHeldMaxByteCount int `yaml:"connection_held_bytes"`
	// How long after a stream ends its dialer's SmtpOutcome is taken (plan-SMTP-wire-gaps#1). Default 15 min.
	OutcomeAcceptTimeout time.Duration `yaml:"-"`
	// The most ended sends remembered for their outcome; past it the oldest is forgotten. Default 100,000.
	OutcomeMaxCount int `yaml:"outcome_max"`
	// How long one Quota.Lease call may take before the connection ends unaccounted. Default 10 s.
	LeaseTimeout time.Duration `yaml:"lease_timeout"`
	// The most send records waiting for their batch; past it the oldest is dropped and counted. Default
	// 50,000, a hundred batches.
	SendLogMaxCount int `yaml:"send_log_max"`
	// The most cuts and outcomes waiting for the halt rule; past it the newest is dropped and counted.
	// Default 1,000.
	HaltEventMaxCount int `yaml:"halt_event_max"`
	// How long Drain waits for connections before Close resets them. Default 10 min, tlsedge's drain_s
	// (§13.5): a longer send retries on the §9 backup ticket (§14.9).
	DrainTimeout time.Duration `yaml:"drain_timeout"`

	// The most bytes read of a header block: a report's own, a part's, or the enclosed message's up
	// to its first CRLF CRLF (§14.8). Default 64 KiB, as §14.8 has it.
	ReportHeaderByteCount int `yaml:"report_header_bytes"`
	// report_inflate_bytes: the most an aggregate attachment inflates to (§14.8). Default 8 MiB.
	ReportInflateByteCount int `yaml:"report_inflate_bytes"`
	// The most an attachment may inflate per compressed byte (§14.8). Default 100.
	ReportInflateRatio int `yaml:"report_inflate_ratio"`
	// The deepest XML or JSON nesting an aggregate may have (§14.8). Default 32.
	ReportNestingDepth int `yaml:"report_nesting_depth"`
	// The longest value an aggregate field may hold. Default 1,024: every field kept is an identifier,
	// a name, a word or a number, and RFC 1035 bounds a name at 253 octets.
	ReportAggregateValueMaxByteCount int `yaml:"-"`
	// The deepest a report's multiparts may nest, the top level being 1. Default 8, deeper than any
	// report shape needs (RFC 5965's is 2).
	ReportMimeDepth int `yaml:"report_mime_depth"`
	// The most leaf parts one report may have. Default 32.
	ReportMimePartCount int `yaml:"report_mime_parts"`
	// The most DKIM signatures checked in one header block. Default 8, D-MAIL-14's bound for mail.
	ReportDkimSignatureCount int `yaml:"report_dkim_signatures"`
	// The most TXT records tried at one key name. Default 4.
	ReportDkimKeyRecordCount int `yaml:"report_dkim_key_records"`
	// The largest RSA key a signature may use, in bits, which bounds a verify's cost. Default 4096.
	ReportDkimRsaKeyBitCount int `yaml:"report_dkim_rsa_key_bits"`
	// The smallest RSA key a signature may use, in bits. Default 1,024, RFC 8301 §3.2's floor, below which
	// a verifier must not accept a key.
	ReportDkimRsaKeyMinBitCount int `yaml:"-"`
	// The longest reported Message-ID kept. Default 998, RFC 5322 §2.1.1's longest line.
	ReportMessageIdMaxByteCount int `yaml:"-"`
	// The longest Feedback-Type token kept. Default 32: RFC 5965's registry's longest is twelve.
	ReportFeedbackTypeMaxByteCount int `yaml:"-"`
	// How long one report's DNS reads may take in all. Default 30 s, D-MAIL-14's bound for mail.
	ReportDnsTimeout time.Duration `yaml:"report_dns_timeout"`
	// How far the last-hop Received time may be from a send's start, either way, for a join (§14.8's ±10
	// min, D-SMTP-8). Default 10 min: a rule of attribution, never a deployment's.
	ReportJoinWindow time.Duration `yaml:"-"`
	// The most sends one join reads back from the store. Default 64: a join keys on a network, an address
	// and a 20 min window, or on a Message-ID's hash, and past this the join is too wide to name one send.
	ReportJoinSendMaxCount int `yaml:"-"`

	// The longest name in text form. Default 253, RFC 1035's.
	HostNameMaxByteCount int `yaml:"-"`
	// The longest label. Default 63, RFC 1035's.
	HostLabelMaxByteCount int `yaml:"-"`

	// X-UR-Ref's keys, by key_id (§14.6, §14.14's vault X-UR-Ref keys), which the host reads from its
	// vault secret file and never from smtpedge.yml. The edge is not ready with none; the intake reads
	// none.
	XUrRefKeys []*SmtpXUrRefKey `yaml:"-"`
	// The key new references are issued under, 1 to 255. Every key held verifies, so a rotation adds the
	// new key everywhere, then moves this. Default 1.
	XUrRefIssueKeyId int `yaml:"x_ur_ref_issue_key_id"`
	// The shortest X-UR-Ref key taken. Default 32, HMAC-SHA256's output (RFC 2104 §3).
	XUrRefKeyMinByteCount int `yaml:"-"`
	// The longest Message-ID a preamble may declare. Default 998, RFC 5322 §2.1.1's longest line.
	PreambleMessageIdMaxByteCount int `yaml:"-"`
	// How long after POST /mail/enable a network's internet mail starts (§14.7). Default 24 h.
	MailEnableDelay time.Duration `yaml:"mail_enable_delay"`
	// retry_after while a fact the gate needs is not loaded, its load asked for (I-12). Default 60 s.
	GateRetryTimeout time.Duration `yaml:"gate_retry_timeout"`
	// retry_after for a spent network's QUOTA. Default 1 h.
	SpentRetryTimeout time.Duration `yaml:"spent_retry_timeout"`
	// retry_after while §21.5's breaker pauses a network's tier. Default 1 h.
	BreakerRetryTimeout time.Duration `yaml:"breaker_retry_timeout"`

	// How long {smq_<networkId>} lives after its last write (§14.7). Default 48 h.
	QuotaKeyTimeout time.Duration `yaml:"quota_key_timeout"`
	// How long a live connection's member lives unrenewed, so a crashed edge's concurrency and
	// reservations heal within it. Default 5 min.
	QuotaMemberTimeout time.Duration `yaml:"quota_member_timeout"`
	// How often a live connection renews its member, under QuotaMemberTimeout (SMTP-M9-13). Default 2 min.
	QuotaMemberRenewInterval time.Duration `yaml:"quota_member_renew_interval"`
	// How long one quota script may take before it reads as Redis not answering. Default 2 s: a preamble
	// waits on it.
	QuotaCallTimeout time.Duration `yaml:"quota_call_timeout"`
	// retry_after for QUOTA when the script names no time: concurrency and the per-message caps.
	// Default 60 s.
	QuotaRetryTimeout time.Duration `yaml:"quota_retry_timeout"`
	// The most networks this process counts in memory while Redis does not answer; past it a network not
	// yet counted gets QUOTA. Default 100,000, a few megabytes.
	QuotaFallbackNetworkMaxCount int `yaml:"quota_fallback_networks"`
	// How long an hour's fleet counter lives after its UTC hour starts (plan-SMTP-shared-counters).
	// Default 2 h.
	HourCounterTimeout time.Duration `yaml:"-"`
	// How often the Community breaker rereads {smg_median}. Default 60 s.
	BreakerMedianRefreshInterval time.Duration `yaml:"breaker_median_refresh_interval"`

	// The trailing window §14.8's rates, record cuts, hard bounces and second label count over. Default 24 h,
	// as §14.8 has it.
	HaltWindow time.Duration `yaml:"-"`
	// Pro's complaint rate past which the network halts, in basis points of its recipients over HaltWindow.
	// Default 50, §14.8's 0.5% (owner decision 37).
	HaltProComplaintBasisPoints int `yaml:"-"`
	// The fewest complaints that halt a Pro network. Default 2.
	HaltProComplaintFloor int `yaml:"-"`
	// Team's rate, in basis points. Default 10, §14.8's 0.1%.
	HaltTeamComplaintBasisPoints int `yaml:"-"`
	// The fewest complaints that halt a Team network. Default 5.
	HaltTeamComplaintFloor int `yaml:"-"`
	// The halted labels within HaltWindow that halt a Community network. Default 2: a second one.
	HaltCommunityLabelCount int `yaml:"-"`
	// The record cuts within HaltWindow that halt any network (§14.7, §14.8). Default 2.
	HaltRecordCutCount int `yaml:"-"`
	// The network halts within HaltSuspendWindow that ask §21 to suspend the network. Default 3.
	HaltSuspendCount int `yaml:"-"`
	// Default 30 days, §14.8's.
	HaltSuspendWindow time.Duration `yaml:"-"`
	// How long an hourly hard-bounce field of {smq_<networkId>} lives (QD-199). Default 48 h.
	HaltBounceFieldTimeout time.Duration `yaml:"-"`
	// The most complaints one count reads back. Default 10,000: Team halts at 0.1% of its 100,000
	// recipients a day, far below.
	HaltComplaintReadMaxCount int `yaml:"-"`

	// mxedge's router interfaces (§19.5's W4): the lb addresses whose TCP 25 is mxedge's router, which a
	// sending host cannot reach by hairpin to its own lb address (D-SMTP-13). An MX on one is reached over the
	// host LAN instead (lan_splice.go). Empty by default: config/<env>/smtpedge.yml names them.
	RouterInterfaces []netip.Addr `yaml:"router_interfaces"`
	// mxedge's LAN listener for these splices (MAIL-M9-05), on the host LAN. Unset by default, which leaves an
	// MX on a router interface unreached, so the preamble answers TRY_LATER.
	RouterLanAddress netip.AddrPort `yaml:"router_lan"`
	// The TCP port an MX listens on. Default 25.
	MxPort int `yaml:"-"`
	// Ranges the edge never dials, beyond what is not public unicast IPv4 (owner decision 34): private,
	// loopback, link-local and multicast addresses are refused whatever this holds. Default the other
	// special-purpose ranges: 0/8, 100.64/10, 192.0.0/24, the three documentation ranges, 192.88.99/24,
	// 198.18/15 and 240/4.
	MxRefusedPrefixes []netip.Prefix `yaml:"-"`
	// The most MX hosts one preamble tries, by preference. Default 8.
	MxHostMaxCount int `yaml:"mx_hosts"`
	// The most addresses tried at one MX host. Default 4.
	MxAddressMaxCount int `yaml:"mx_addresses"`
	// How long one DNS lookup may take. Default 30 s.
	MxLookupTimeout time.Duration `yaml:"mx_lookup_timeout"`
	// retry_after for TRY_LATER when no MX was reached for now. Default 5 min.
	MxRetryTimeout time.Duration `yaml:"mx_retry_timeout"`
	// How long a 421 banner backs its MX host off, in this edge's memory (§14.4). Default 5 min.
	MxBannerBackoffTimeout time.Duration `yaml:"mx_banner_backoff"`
	// The most MX hosts backed off at once; past it a new one is not. Default 10,000.
	MxBackoffMaxCount int `yaml:"mx_backoff_max"`
	// An MX reply's bound before TLS, every line of it. Default 2,048, connect's.
	MxReplyMaxByteCount int `yaml:"-"`
	// One reply line's bound without its line end. Default 510, connect's: RFC 5321's 512 with the CRLF.
	MxReplyLineMaxByteCount int `yaml:"-"`
	// How often the sending addresses' FCrDNS is checked (§14.6). Default 10 min.
	FcrdnsCheckInterval time.Duration `yaml:"fcrdns_check_interval"`
	// How long one address's check may take. Default 30 s.
	FcrdnsTimeout time.Duration `yaml:"fcrdns_timeout"`
}

// The defaults every number here is read from. Root and ReportHostName stay empty, so these alone do
// not pass Validate.
func DefaultSmtpEdgeSettings() *SmtpEdgeSettings {
	return &SmtpEdgeSettings{
		PreambleTimeout:            30 * time.Second,
		PreTlsTimeout:              5 * time.Minute,
		ClientIdleTimeout:          10 * time.Minute,
		ServerIdleTimeout:          5 * time.Minute,
		ConnectionTimeout:          30 * time.Minute,
		DataConnectionTimeout:      2 * time.Hour,
		HaltReloadInterval:         60 * time.Second,
		StoreTimeout:               5 * time.Second,
		SendBatchCount:             500,
		SendBatchInterval:          10 * time.Second,
		DrainTimeout:               10 * time.Minute,
		RecordMaxByteCount:         5 + 16*1024 + 2048,
		ProofMaxByteCount:          16 * 1024,
		ConnectionHeldMaxByteCount: 256 * 1024,
		OutcomeAcceptTimeout:       15 * time.Minute,
		OutcomeMaxCount:            100000,
		LeaseTimeout:               10 * time.Second,
		SendLogMaxCount:            50000,
		HaltEventMaxCount:          1000,
		ReportHeaderByteCount:      64 * 1024,
		ReportInflateByteCount:     8 * 1024 * 1024,
		ReportInflateRatio:         100,
		ReportNestingDepth:         32,
		ReportMimeDepth:            8,
		ReportMimePartCount:        32,
		ReportDkimSignatureCount:   8,
		ReportDkimKeyRecordCount:   4,
		ReportDkimRsaKeyBitCount:   4096,
		ReportDnsTimeout:           30 * time.Second,
		ReportJoinWindow:           10 * time.Minute,
		ReportJoinSendMaxCount:     64,

		ReportAggregateValueMaxByteCount: 1024,
		ReportDkimRsaKeyMinBitCount:      1024,
		ReportMessageIdMaxByteCount:      998,
		ReportFeedbackTypeMaxByteCount:   32,
		HostNameMaxByteCount:             253,
		HostLabelMaxByteCount:            63,

		XUrRefIssueKeyId:              1,
		XUrRefKeyMinByteCount:         32,
		PreambleMessageIdMaxByteCount: 998,
		MailEnableDelay:               24 * time.Hour,
		GateRetryTimeout:              60 * time.Second,
		SpentRetryTimeout:             time.Hour,
		BreakerRetryTimeout:           time.Hour,

		QuotaKeyTimeout:              48 * time.Hour,
		QuotaMemberTimeout:           5 * time.Minute,
		QuotaMemberRenewInterval:     2 * time.Minute,
		QuotaCallTimeout:             2 * time.Second,
		QuotaRetryTimeout:            60 * time.Second,
		QuotaFallbackNetworkMaxCount: 100000,
		HourCounterTimeout:           2 * time.Hour,
		BreakerMedianRefreshInterval: 60 * time.Second,
		HaltWindow:                   24 * time.Hour,
		HaltProComplaintBasisPoints:  50,
		HaltProComplaintFloor:        2,
		HaltTeamComplaintBasisPoints: 10,
		HaltTeamComplaintFloor:       5,
		HaltCommunityLabelCount:      2,
		HaltRecordCutCount:           2,
		HaltSuspendCount:             3,
		HaltSuspendWindow:            30 * 24 * time.Hour,
		HaltBounceFieldTimeout:       48 * time.Hour,
		HaltComplaintReadMaxCount:    10000,

		MxPort: 25,
		MxRefusedPrefixes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/8"),
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("192.0.0.0/24"),
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("192.88.99.0/24"),
			netip.MustParsePrefix("198.18.0.0/15"),
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("240.0.0.0/4"),
		},
		MxHostMaxCount:          8,
		MxAddressMaxCount:       4,
		MxLookupTimeout:         30 * time.Second,
		MxRetryTimeout:          5 * time.Minute,
		MxBannerBackoffTimeout:  5 * time.Minute,
		MxBackoffMaxCount:       10000,
		MxReplyMaxByteCount:     2048,
		MxReplyLineMaxByteCount: 510,
		FcrdnsCheckInterval:     10 * time.Minute,
		FcrdnsTimeout:           30 * time.Second,
	}
}

// Settings from smtpedge.yml. A key left out keeps its default, so root and report_host must be
// there, and a key not listed here is refused rather than ignored: a misspelled bound would otherwise
// run at its default, unseen.
func LoadSmtpEdgeSettings(data []byte) (*SmtpEdgeSettings, error) {
	settings := DefaultSmtpEdgeSettings()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSmtpEdgeSettingsRefused, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one document", ErrSmtpEdgeSettingsRefused)
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}

// Whether name is a dotted LDH name, which also keeps a CR, LF or space out of everything it enters.
func (self *SmtpEdgeSettings) ldhName(name string) bool {
	if name == "" || self.HostNameMaxByteCount < len(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || self.HostLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Whether these settings can run the edge or the intake. A refusal names the field, never its value.
func (self *SmtpEdgeSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrSmtpEdgeSettingsRefused)
	}
	value := reflect.ValueOf(self).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		if (field.Kind() == reflect.Int || field.Kind() == reflect.Int64) && field.Int() <= 0 {
			name := value.Type().Field(i).Tag.Get("yaml")
			if name == "" || name == "-" {
				name = value.Type().Field(i).Name
			}
			return fmt.Errorf("%w: %s is not positive", ErrSmtpEdgeSettingsRefused, name)
		}
	}
	if self.ReportDkimRsaKeyBitCount < self.ReportDkimRsaKeyMinBitCount {
		return fmt.Errorf("%w: report_dkim_rsa_key_bits is under RFC 8301's floor", ErrSmtpEdgeSettingsRefused)
	}
	if !self.ldhName(self.Root) {
		return fmt.Errorf("%w: root is not an LDH name", ErrSmtpEdgeSettingsRefused)
	}
	if !self.ldhName(self.ReportHostName) {
		return fmt.Errorf("%w: report_host is not an LDH name", ErrSmtpEdgeSettingsRefused)
	}
	seenAddresses := map[netip.Addr]bool{}
	for _, sendingAddress := range self.SendingAddresses {
		// IPv4 only, as the edge dials (owner decision 34), and never a broadcast or private range's
		// special forms
		address := sendingAddress.Address
		if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			return fmt.Errorf("%w: sending_addresses holds an address that cannot send", ErrSmtpEdgeSettingsRefused)
		}
		if seenAddresses[address] {
			return fmt.Errorf("%w: sending_addresses repeats an address", ErrSmtpEdgeSettingsRefused)
		}
		seenAddresses[address] = true
		if !self.ldhName(sendingAddress.HeloName) {
			return fmt.Errorf("%w: a sending address's helo is not an LDH name", ErrSmtpEdgeSettingsRefused)
		}
		if sendingAddress.Fwmark < 0 {
			return fmt.Errorf("%w: a sending address's fwmark is negative", ErrSmtpEdgeSettingsRefused)
		}
	}
	for _, domain := range self.LoopAllowlist {
		if !self.ldhName(domain) {
			return fmt.Errorf("%w: loop_allowlist holds a name that is not LDH", ErrSmtpEdgeSettingsRefused)
		}
	}
	if 255 < self.XUrRefIssueKeyId {
		return fmt.Errorf("%w: x_ur_ref_issue_key_id is past one octet", ErrSmtpEdgeSettingsRefused)
	}
	seenKeyIds := map[uint8]bool{}
	issueKeyHeld := false
	for _, key := range self.XUrRefKeys {
		if key == nil || key.KeyId == 0 || seenKeyIds[key.KeyId] {
			return fmt.Errorf("%w: an X-UR-Ref key with no id, or an id twice", ErrSmtpEdgeSettingsRefused)
		}
		seenKeyIds[key.KeyId] = true
		if len(key.Key) < self.XUrRefKeyMinByteCount {
			return fmt.Errorf("%w: an X-UR-Ref key shorter than its bound", ErrSmtpEdgeSettingsRefused)
		}
		issueKeyHeld = issueKeyHeld || int(key.KeyId) == self.XUrRefIssueKeyId
	}
	if len(self.XUrRefKeys) != 0 && !issueKeyHeld {
		return fmt.Errorf("%w: x_ur_ref_issue_key_id names no key held", ErrSmtpEdgeSettingsRefused)
	}
	if self.QuotaMemberTimeout <= self.QuotaMemberRenewInterval {
		return fmt.Errorf("%w: quota_member_renew_interval is not under quota_member_timeout", ErrSmtpEdgeSettingsRefused)
	}
	for _, routerInterface := range self.RouterInterfaces {
		if !routerInterface.Is4() || routerInterface.IsUnspecified() || routerInterface.IsLoopback() {
			return fmt.Errorf("%w: router_interfaces holds an address no MX sits on", ErrSmtpEdgeSettingsRefused)
		}
	}
	if self.RouterLanAddress.IsValid() && self.RouterLanAddress.Port() == 0 {
		return fmt.Errorf("%w: router_lan names no port", ErrSmtpEdgeSettingsRefused)
	}
	if 65535 < self.MxPort {
		return fmt.Errorf("%w: MxPort is past a port", ErrSmtpEdgeSettingsRefused)
	}
	return nil
}

// Whether label is one LDH label.
func (self *SmtpEdgeSettings) ldhLabel(label string) bool {
	return !strings.Contains(label, ".") && self.ldhName(label)
}

// Whether address is in the sending set.
func (self *SmtpEdgeSettings) isSendingAddress(address netip.Addr) bool {
	address = address.Unmap()
	for _, sendingAddress := range self.SendingAddresses {
		if sendingAddress.Address == address {
			return true
		}
	}
	return false
}

// Whether a report verified under domain comes from an allowlisted feedback loop.
func (self *SmtpEdgeSettings) isLoopReporter(domain string) bool {
	for _, allowed := range self.LoopAllowlist {
		if strings.EqualFold(allowed, domain) {
			return true
		}
	}
	return false
}
