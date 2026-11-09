// config/<env>/mxedge.yml (§15.15). DefaultMxEdgeSettings is the only source of a default
// (connect/CODESTYLE.md:144), and LoadMxEdgeSettings lays a file over it. Protocol sizes are not
// settings: they stay constants in dialog.go, since §15.4 promises them.
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
)

const (
	// RFC 1035's longest name, which a banner carries.
	mxHostNameMaxByteCount = 253
	// RFC 1035's longest label.
	mxHostLabelMaxByteCount = 63
	// A 530's line has to fit RFC 5321's 512 B, CRLF included, with its fixed text around the url.
	mxDeviationUrlMaxByteCount = 400
	// An entry must not outlive the daily k it is under, or no read finds it. k lives 25 h from its
	// creation, which may come at the first moment of its day, so an entry may outlive the day by an
	// hour at most.
	mxClosedHandshakeTtlMax = mxDailyKeyTtl - mxSecondsPerDay*time.Second
)

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
		PlatformRecipientCount:      100,
		PlatformHandshakeTimeout:    10 * time.Second,
		PlatformIdleTimeout:         5 * time.Minute,
		PlatformSessionTimeout:      30 * time.Minute,
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
	if !mxLdhNameFits(self.BannerHostName) {
		return fmt.Errorf("%w: banner_host is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	if !mxReplyUrlFits(self.DeviationUrl) {
		return fmt.Errorf("%w: deviation_url is not an absolute https url that fits a reply", ErrMxEdgeSettingsRefused)
	}
	value := reflect.ValueOf(self).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		if (field.Kind() == reflect.Int || field.Kind() == reflect.Int64) && field.Int() <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrMxEdgeSettingsRefused, value.Type().Field(i).Tag.Get("yaml"))
		}
	}
	if mxClosedHandshakeTtlMax < self.ClosedHandshakeTtl {
		return fmt.Errorf("%w: closed_handshake_ttl would outlive its daily key", ErrMxEdgeSettingsRefused)
	}
	return nil
}

// Whether these settings can run the platform role: Validate's rules, and the three names the role
// answers with. A refusal names the field, never its value.
func (self *MxEdgeSettings) ValidatePlatform() error {
	if err := self.Validate(); err != nil {
		return err
	}
	if !mxLdhNameFits(self.PlatformReportHostName) {
		return fmt.Errorf("%w: platform_report_host is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	if !mxLdhNameFits(self.PlatformRootDomainName) {
		return fmt.Errorf("%w: platform_root is not an LDH name", ErrMxEdgeSettingsRefused)
	}
	if !mxReplyUrlFits(self.PlatformAbuseUrl) {
		return fmt.Errorf("%w: platform_abuse_url is not an absolute https url that fits a reply", ErrMxEdgeSettingsRefused)
	}
	return nil
}

// Dotted LDH labels within RFC 1035's lengths, which also keeps a CR or LF out of every reply the name
// enters.
func mxLdhNameFits(name string) bool {
	if name == "" || mxHostNameMaxByteCount < len(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || mxHostLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
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
func mxReplyUrlFits(replyUrl string) bool {
	if replyUrl == "" || mxDeviationUrlMaxByteCount < len(replyUrl) {
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
