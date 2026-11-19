// config/<env>/mxedge.yml (§15.15). DefaultMxEdgeSettings is the only source of a default
// (connect/CODESTYLE.md:144), and LoadMxEdgeSettings lays a file over it. The limits a name or url in
// this file is held to are fields too, set only by the defaults (QD-702). dialog.go's protocol sizes
// are still constants there, as MAIL-M5-01 wrote them, until the review phase's sweep (QD-706) moves
// them.
//
// Every number must be positive. Validate refuses anything else, so a zero is never unlimited or off,
// and no reader has to decide what one means.

package mxedgeservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar"
)

// An entry must not outlive the daily k it is under, or no read finds it. k lives 25 h from its
// creation, which may come at the first moment of its day, so an entry may outlive the day by an hour
// at most. Derived from mxDailyKeyTtl, which closed_handshake.go keeps out of settings on purpose, so
// it is no tunable either.
const mxClosedHandshakeTtlMax = mxDailyKeyTtl - mxSecondsPerDay*time.Second

// An mxedge.yml that cannot be served from. The wrapping error names the field.
var ErrMxEdgeSettingsRefused = errors.New("mxedge.yml refused")

// What config/<env>/mxedge.yml sets, by the yaml names here. A duration takes Go's form, as 5m or 50ms.
// DefaultMxEdgeSettings or LoadMxEdgeSettings make one, and NewMxEdgeService refuses what Validate
// refuses. Safe to read concurrently once loaded, and never changed after.
type MxEdgeSettings struct {
	// The name the banner, EHLO and refusals give (§15.4; owner decision 16). No default: it is a
	// production name, which the file sets, and Validate refuses it empty. An LDH name.
	BannerHostName string `yaml:"banner_host"`
	// §21.11's published RFC 3207 deviation, which the 530 links. No default, for the same reason, and
	// §21.11 must publish it before the 530 goes out. An absolute https url.
	DeviationUrl string `yaml:"deviation_url"`

	// Sessions at once from one sender /64 or /32 in this process, past which 421 4.7.0 (§15.4).
	// Default 8, reading 2's proposal, tuned at T5.
	SenderSessionCount int `yaml:"sender_sessions"`
	// Sessions at once from one sender /48 or /24 in this process, past which 421 4.7.0 (§15.4).
	// Default 32, reading 2's proposal, tuned at T5.
	SenderAggregateSessionCount int `yaml:"sender_aggregate_sessions"`
	// Sessions at once from one sender /24 or /48 to one network in this process, past which the
	// handshake closes (reading 1). Default 2, as §15.4 fixes it.
	NetworkSenderSessionCount int `yaml:"network_sender_sessions"`
	// Sessions at once to one network in this process, past which the handshake closes (reading 1).
	// Default 256, reading 2's proposal, tuned at T5.
	NetworkSessionCount int `yaml:"network_sessions"`
	// Sessions at once in this process, past which 421 4.7.0, so a flood of distinct senders still
	// bounds this process's memory. Default 50,000, tlsedge's max_connections (§13.5).
	ProcessSessionCount int `yaml:"max_connections"`

	// How long the whole pre-TLS dialog may run, from the banner to the handoff. Default 5 min, RFC
	// 5321 §4.5.3.2.7's server timeout, which a sender trickling its 2,048 B cannot stretch.
	DialogTimeout time.Duration `yaml:"dialog_timeout"`
	// How long a read waits behind a STARTTLS line for a byte that would reset the connection, before
	// the 220 goes out. A client waits for that 220 (RFC 3207 §4), so an honest one sends nothing and
	// loses only this much. Default 50 ms, longer than two segments sent back to back take to arrive
	// apart.
	StartTlsQuietTimeout time.Duration `yaml:"starttls_quiet"`
	// How long a sender has to finish its ClientHello after the 220. Default 10 s, tlsedge's (§13.5).
	ClientHelloTimeout time.Duration `yaml:"client_hello_timeout"`
	// The most ClientHello bytes read. Default 16 KiB, tlsedge's (§13.5).
	ClientHelloByteCount int `yaml:"client_hello_max_bytes"`

	// How long a closed handshake is remembered (§15.4). Default 1 h, as §15.4 has it, and at most that,
	// since an entry may not outlive its daily k.
	ClosedHandshakeTtl time.Duration `yaml:"closed_handshake_ttl"`
	// How long a Redis or store call may take before it reads as an error. Default 1 s: a 451 waits
	// on this, and an unanswered read tells the sender to retry anyway.
	StoreTimeout time.Duration `yaml:"store_timeout"`
	// How often Redis and the store are probed for Ready. A probe reads the memory's daily k again,
	// and one also runs at each UTC date change. Default 10 s, so a block leaves the lb soon after
	// losing either, and k is read at least each minute, as the fleet's daily keys are.
	ReadyProbeInterval time.Duration `yaml:"ready_probe_interval"`
	// The pause after a failed Accept, which keeps a run of them from spinning. Default 100 ms.
	AcceptRetryDelay time.Duration `yaml:"accept_retry_delay"`
	// How long Drain waits for sessions to end before Close resets them. Default 10 min, tlsedge's
	// drain_s (§13.5).
	DrainTimeout time.Duration `yaml:"drain_timeout"`

	// How often session records go to the store, as one batch (§15.4: 10 s).
	RecordFlushInterval time.Duration `yaml:"record_flush_interval"`
	// How long one batch's write may take before it reads as failed and waits for the next flush.
	// Default 5 s: a batch is one insert, off every session's path.
	RecordWriteTimeout time.Duration `yaml:"record_write_timeout"`
	// Session records waiting at most, past which a new one is dropped and counted, so a store that
	// lags costs a bounded memory and never a session's wait. Default 100,000, ten times a full
	// process's sessions in one flush.
	RecordQueueCount int `yaml:"record_queue"`
	// Session records one write carries at most. Default 10,000.
	RecordBatchCount int `yaml:"record_batch"`

	// The platform listener's (D-MAIL-10, MAIL-M5-03), which only NewMxEdgePlatformService reads. The
	// three names have no default, as production names, and ValidatePlatform refuses them empty; the
	// router's file need not set them.

	// The report host, rpt.bringyour.com, whose <token>@ and root@ the listener takes (D-SMTP-19). An
	// LDH name.
	PlatformReportHostName string `yaml:"platform_report_host"`
	// <root>, whose postmaster@ and abuse@ the listener takes (R-MAIL-15, RFC 2142). An LDH name.
	PlatformRootDomainName string `yaml:"platform_root"`
	// §21.8's form, which the 550 5.7.1 for unread role mail points a person at (plan-ABUSE-auto-reply).
	// An absolute https url that fits a reply.
	PlatformAbuseUrl string `yaml:"platform_abuse_url"`
	// The most bytes one message may carry, advertised in SIZE, past which 552 5.3.4. Default 16 MiB,
	// reading 17's.
	PlatformMessageByteCount int `yaml:"platform_message_max_bytes"`
	// The most message bytes all platform sessions in this process hold at once, past which a message
	// gets 452 4.3.1, so 50 senders at the cap cannot take 800 MiB. Default 256 MiB, sixteen messages
	// at the cap, tuned at T5.
	PlatformBufferByteCount int `yaml:"platform_buffer_max_bytes"`
	// How much of a message one read takes as a session's buffer grows. No bound: the two above are,
	// and a buffer reaches at most the message cap and one read past it. Default 64 KiB, the receiver's
	// chunk (§15.5).
	PlatformReadByteCount int `yaml:"platform_read_bytes"`
	// Recipients one transaction may name, past which 452 4.5.3 and the sender sends the rest later.
	// Default 100, RFC 5321 §4.5.3.1.8's least.
	PlatformRecipientCount int `yaml:"platform_recipients"`
	// How long a sender has to finish its TLS handshake after the 220. Default 10 s, as
	// client_hello_timeout.
	PlatformHandshakeTimeout time.Duration `yaml:"platform_handshake_timeout"`
	// How long a session after TLS waits for a sender's next byte. Default 5 min, RFC 5321
	// §4.5.3.2.7's server timeout.
	PlatformIdleTimeout time.Duration `yaml:"platform_idle_timeout"`
	// How long a session after TLS may run at all. Default 30 min, a splice's bound (§15.4).
	PlatformSessionTimeout time.Duration `yaml:"platform_session_timeout"`

	// The router's (D-MAIL-1, D-MAIL-2, MAIL-M7-19), which only NewMxEdgeRouterService reads. route_root has
	// no default, as a production name, and ValidateRouter refuses it empty; the platform's file need not
	// set it.

	// <root>, under which mx.<net>.<root> names a network's mail host and mx.<scope>.<net>.<root> a
	// scope's (§15.4). Any other SNI routes by its full name, as a strict-mode custom MX host does. An LDH
	// name.
	RouteRootDomainName string `yaml:"route_root"`
	// How long the router keeps what {mxr_<net>} answered for a name, a route or none, so a connection
	// reads Redis at most once a name in this (§15.15's in-process cache). Default 5 s: a released or
	// tombstoned label stops routing within this of its key's delete (I-14), the most CODESTYLE lets an
	// inline path cache a positive answer.
	RouteCacheTtl time.Duration `yaml:"route_cache_ttl"`
	// Names the cache holds at most, past which the oldest goes, so a scan of random names bounds this
	// process's memory. Default 65,536.
	RouteCacheEntryCount int `yaml:"route_cache_entries"`
	// K, the platform clients the router holds in urnetwork-edge, each a Find names (§13.6, §9.6).
	// Default 4, tlsedge's. A dialer holding fewer leaves the router not ready.
	Clients int `yaml:"clients"`
	// The most one Find may take. Default 2 s, §9.6's.
	FindTimeout time.Duration `yaml:"find_timeout"`
	// The most Finds one dial sends, the first included. Default 3, §9.6's.
	FindCount int `yaml:"find_max"`
	// How long each ticket's open waits for its receiver's accept before the backup is tried, the one
	// failure an edge reports (§9.6). Default 5 s.
	AcceptTicketTimeout time.Duration `yaml:"accept_ticket_timeout"`
	// The whole Find and open's bound, every ticket's included. Default 15 s, tlsedge's (§13.5).
	AcceptSetupTimeout time.Duration `yaml:"accept_setup_timeout"`
	// How long the one alert a closed handshake writes may take once the dialog's watchdog has stopped.
	// Default 2 s, tlsedge's.
	AlertTimeout time.Duration `yaml:"alert_timeout"`
	// How long a Quota.Lease call may take before the network reads as unavailable. Default 2 s, tlsedge's.
	LeaseTimeout time.Duration `yaml:"lease_timeout"`
	// A splice ends after this long with no byte either way. Default 10 min, RFC 5321 §4.5.3.2.6's (§15.4).
	SpliceIdleTimeout time.Duration `yaml:"splice_idle_timeout"`
	// A splice that has passed fewer than SpliceSlowByteCount bytes this long after it began ends then.
	// Default 10 min (§15.4).
	SpliceSlowTimeout time.Duration `yaml:"splice_slow_timeout"`
	// What a splice must have passed by SpliceSlowTimeout. Default 1 MiB (§15.4).
	SpliceSlowByteCount int `yaml:"splice_slow_bytes"`
	// A splice ends this long after it began, whatever it carries. Default 30 min (§15.4).
	SpliceSessionTimeout time.Duration `yaml:"splice_session_timeout"`
	// A splice ends once it has passed this many times its network's message cap, plus
	// SpliceExtraByteCount, both ways. Default 2 (§15.4).
	SpliceMessageMultiple int `yaml:"splice_message_multiple"`
	// See SpliceMessageMultiple. Default 1 MiB (§15.4).
	SpliceExtraByteCount int `yaml:"splice_extra_bytes"`
	// What one read of either side takes at most. Default 16 KiB, tlsedge's.
	SpliceBufferByteCount int `yaml:"splice_buffer_bytes"`
	// The message cap a splice is bounded by before its network's own mail_inbound_message_bytes has
	// loaded (§20.4). Default 50 MiB, the largest tier's: the receiver holds each message to its network's
	// own SIZE, so this only bounds what a cold network's first splice may cost it, and never cuts a
	// message its tier allows.
	ColdMessageByteCount int `yaml:"cold_message_max_bytes"`
	// How often a network's limits are read again while it has sessions. Default 1 min.
	LimitsRefreshInterval time.Duration `yaml:"limits_refresh_interval"`
	// A network with no session for this long is forgotten, and cold again. Default 10 min, tlsedge's.
	LimitsActiveWindow time.Duration `yaml:"limits_active_window"`
	// Networks whose limits are held at most. Default 65,536, tlsedge's.
	LimitsNetworkCount int `yaml:"limits_networks"`
	// How long a sender's forward-confirmed PTR may take, both lookups, from the session's admission. A
	// lookup the handoff outruns leaves MailIngress.ptr_name "". Default 5 s.
	PtrTimeout time.Duration `yaml:"ptr_timeout"`
	// The PTR names forward-confirmed at most. Default 4.
	PtrNameCount int `yaml:"ptr_names"`
	// PTR lookups this process runs at once at most, past which a session goes without, so a flood of
	// senders cannot turn into a flood of lookups. Default 1,024.
	PtrLookupCount int `yaml:"ptr_lookups"`

	// How often the router loads the feed mirror into a new prefix set (owner decision 111). Default 5 min,
	// §15.4's.
	ListingRefreshInterval time.Duration `yaml:"listing_refresh_interval"`
	// A set whose feed was current longer ago than this lists no one, so a feed that is down or stale rejects
	// nothing (§15.4). Default 15 min, three refreshes missed.
	ListingStaleTimeout time.Duration `yaml:"listing_stale_timeout"`
	// How long one load of the mirror may take before it reads as failed and the set in use stays. Default
	// 2 min.
	ListingLoadTimeout time.Duration `yaml:"listing_load_timeout"`
	// The most entries one load takes, past which the load fails whole and the set in use stays, so a mirror
	// that grows past what this process should hold never half-loads. Default 16,777,216, a few bytes each.
	ListingPrefixCount int `yaml:"listing_prefixes"`

	// §15.6's wake hold (M8; owner decision 88; wake_hold.go). Whether a session whose Find misses is held
	// while its network's receivers are woken, rather than closed in the handshake at once. Default false:
	// until plan-KEYS-hint-addressing's internal route lets a host turn a sidecar into its client with no
	// Postgres, every wake hint is lost, and plan-MAIL-hints' interim keeps M7's close.
	WakeHold bool `yaml:"wake_hold"`
	// How long a held session waits for a receiver, from its miss, before it closes in the handshake.
	// Default 30 s, §15.6's, well inside the 300 s Postfix gives a TLS handshake.
	WakeHoldTimeout time.Duration `yaml:"wake_hold_timeout"`
	// Sessions held at once in this process, past which a miss closes at once. Default 1,000 (§15.6).
	WakeHoldCount int `yaml:"wake_holds"`
	// Sessions held at once for one network in this process, past which a miss closes at once. Default 4
	// (§15.6).
	WakeHoldNetworkCount int `yaml:"wake_holds_per_network"`
	// How often a held session asks for its receiver again, each Find and open bounded by what is left of
	// the hold. Default 2 s: a full process asks 500 times a second, a quarter of W2's edge Find limit.
	WakeHoldFindInterval time.Duration `yaml:"wake_hold_find_interval"`
	// Wake hints in flight at once in this process, past which a hold's hint is dropped and counted, the
	// hold going on: a hint is lossy, and a receiver's hourly resync covers it. Default 64.
	WakeHintCount int `yaml:"wake_hints"`
	// How long one hint's call may take before it reads as failed. Default 5 s, off every session's path.
	WakeHintTimeout time.Duration `yaml:"wake_hint_timeout"`

	// MailIngress's bounds, the format's, which a receiver holds it to as well. Set only by the defaults.
	Ingress *sidecar.MailIngressFormatSettings `yaml:"-"`
	// The router's usage windows for meter mx (§20.6). Set only by the defaults.
	Usage *sidecar.QuotaUsageBatcherSettings `yaml:"-"`

	// The limits a name and a url in this file are held to, which no file sets.

	// RFC 1035's longest name, in its dotted text form: 253.
	HostNameMaxByteCount int `yaml:"-"`
	// RFC 1035's longest label: 63.
	HostLabelMaxByteCount int `yaml:"-"`
	// The longest url a reply carries: 400, so a 530's line fits RFC 5321's 512 B, CRLF included, with its
	// fixed text around the url.
	ReplyUrlMaxByteCount int `yaml:"-"`
	// The most receivers a {mxr_} value lists, newest first, and so the most one wake hint names:
	// plan-MAIL-hints #2's 64, the projection's own bound (server's MailRouteSettings.ReceiverMaxCount).
	RouteReceiverCount int `yaml:"-"`
}

// The defaults every number here is read from. BannerHostName and DeviationUrl stay empty, so these
// alone do not pass Validate.
func DefaultMxEdgeSettings() *MxEdgeSettings {
	return &MxEdgeSettings{
		SenderSessionCount:          8,
		SenderAggregateSessionCount: 32,
		NetworkSenderSessionCount:   2,
		NetworkSessionCount:         256,
		ProcessSessionCount:         50000,
		DialogTimeout:               5 * time.Minute,
		StartTlsQuietTimeout:        50 * time.Millisecond,
		ClientHelloTimeout:          10 * time.Second,
		ClientHelloByteCount:        16 * 1024,
		ClosedHandshakeTtl:          1 * time.Hour,
		StoreTimeout:                1 * time.Second,
		ReadyProbeInterval:          10 * time.Second,
		AcceptRetryDelay:            100 * time.Millisecond,
		DrainTimeout:                10 * time.Minute,
		RecordFlushInterval:         10 * time.Second,
		RecordWriteTimeout:          5 * time.Second,
		RecordQueueCount:            100000,
		RecordBatchCount:            10000,
		PlatformMessageByteCount:    16 * 1024 * 1024,
		PlatformBufferByteCount:     256 * 1024 * 1024,
		PlatformReadByteCount:       64 * 1024,
		PlatformRecipientCount:      100,
		PlatformHandshakeTimeout:    10 * time.Second,
		PlatformIdleTimeout:         5 * time.Minute,
		PlatformSessionTimeout:      30 * time.Minute,
		RouteCacheTtl:               5 * time.Second,
		RouteCacheEntryCount:        64 * 1024,
		Clients:                     4,
		FindTimeout:                 2 * time.Second,
		FindCount:                   3,
		AcceptTicketTimeout:         5 * time.Second,
		AcceptSetupTimeout:          15 * time.Second,
		AlertTimeout:                2 * time.Second,
		LeaseTimeout:                2 * time.Second,
		SpliceIdleTimeout:           10 * time.Minute,
		SpliceSlowTimeout:           10 * time.Minute,
		SpliceSlowByteCount:         1024 * 1024,
		SpliceSessionTimeout:        30 * time.Minute,
		SpliceMessageMultiple:       2,
		SpliceExtraByteCount:        1024 * 1024,
		SpliceBufferByteCount:       16 * 1024,
		ColdMessageByteCount:        50 * 1024 * 1024,
		LimitsRefreshInterval:       1 * time.Minute,
		LimitsActiveWindow:          10 * time.Minute,
		LimitsNetworkCount:          64 * 1024,
		PtrTimeout:                  5 * time.Second,
		PtrNameCount:                4,
		PtrLookupCount:              1024,
		ListingRefreshInterval:      5 * time.Minute,
		ListingStaleTimeout:         15 * time.Minute,
		ListingLoadTimeout:          2 * time.Minute,
		ListingPrefixCount:          16 * 1024 * 1024,
		WakeHold:                    false,
		WakeHoldTimeout:             30 * time.Second,
		WakeHoldCount:               1000,
		WakeHoldNetworkCount:        4,
		WakeHoldFindInterval:        2 * time.Second,
		WakeHintCount:               64,
		WakeHintTimeout:             5 * time.Second,
		Ingress:                     sidecar.DefaultMailIngressFormatSettings(),
		Usage:                       sidecar.DefaultQuotaUsageBatcherSettings(),
		HostNameMaxByteCount:        253,
		HostLabelMaxByteCount:       63,
		ReplyUrlMaxByteCount:        400,
		RouteReceiverCount:          64,
	}
}

// Settings from mxedge.yml. A key left out keeps its default, so banner_host and deviation_url must be
// there, and a key not listed here is refused rather than ignored: a misspelled cap would otherwise
// run at its default, unseen.
func LoadMxEdgeSettings(data []byte) (*MxEdgeSettings, error) {
	settings := DefaultMxEdgeSettings()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMxEdgeSettingsRefused, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one document", ErrMxEdgeSettingsRefused)
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}

// Whether these settings can run the engine. A refusal names the field, never its value.
func (self *MxEdgeSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrMxEdgeSettingsRefused)
	}
	value := reflect.ValueOf(self).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		if (field.Kind() == reflect.Int || field.Kind() == reflect.Int64) && field.Int() <= 0 {
			name := value.Type().Field(i).Tag.Get("yaml")
			if name == "-" {
				name = value.Type().Field(i).Name
			}
			return fmt.Errorf("%w: %s is not positive", ErrMxEdgeSettingsRefused, name)
		}
	}
	if !self.ldhNameFits(self.BannerHostName) {
		return fmt.Errorf("%w: banner_host is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	if !self.replyUrlFits(self.DeviationUrl) {
		return fmt.Errorf("%w: deviation_url is not an absolute https url that fits a reply", ErrMxEdgeSettingsRefused)
	}
	if mxClosedHandshakeTtlMax < self.ClosedHandshakeTtl {
		return fmt.Errorf("%w: closed_handshake_ttl would outlive its daily key", ErrMxEdgeSettingsRefused)
	}
	if !self.Ingress.Valid() {
		return fmt.Errorf("%w: Ingress", ErrMxEdgeSettingsRefused)
	}
	if self.Usage == nil || self.Usage.WindowTimeout <= 0 || self.Usage.RetryTimeout <= 0 {
		return fmt.Errorf("%w: Usage needs a positive window and retry timeout", ErrMxEdgeSettingsRefused)
	}
	return nil
}

// Whether these settings can run the router role: Validate's rules and the root it routes under. A
// refusal names the field, never its value.
func (self *MxEdgeSettings) ValidateRouter() error {
	if err := self.Validate(); err != nil {
		return err
	}
	if !self.ldhNameFits(self.RouteRootDomainName) {
		return fmt.Errorf("%w: route_root is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	return nil
}

// Whether these settings can run the platform role: Validate's rules, and the three names the role
// answers with. A refusal names the field, never its value.
func (self *MxEdgeSettings) ValidatePlatform() error {
	if err := self.Validate(); err != nil {
		return err
	}
	if !self.ldhNameFits(self.PlatformReportHostName) {
		return fmt.Errorf("%w: platform_report_host is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	if !self.ldhNameFits(self.PlatformRootDomainName) {
		return fmt.Errorf("%w: platform_root is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	if !self.replyUrlFits(self.PlatformAbuseUrl) {
		return fmt.Errorf("%w: platform_abuse_url is not an absolute https url that fits a reply", ErrMxEdgeSettingsRefused)
	}
	return nil
}

// Dotted LDH labels within RFC 1035's lengths, which also keeps a CR or LF out of every reply the name
// enters.
func (self *MxEdgeSettings) ldhNameFits(name string) bool {
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

// Absolute https, printable ASCII with no space, and short enough for a reply's line to fit around it.
func (self *MxEdgeSettings) replyUrlFits(replyUrl string) bool {
	if replyUrl == "" || self.ReplyUrlMaxByteCount < len(replyUrl) {
		return false
	}
	for i := range len(replyUrl) {
		if replyUrl[i] <= ' ' || 0x7f <= replyUrl[i] {
			return false
		}
	}
	parsed, err := url.Parse(replyUrl)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}
