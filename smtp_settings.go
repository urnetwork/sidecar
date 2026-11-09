//go:build !sidecar_http

// SmtpSender's tunables (§14.4, §14.5, D-SMTP-18), which SidecarConnectSettings carries beside the
// prover, since only connect legs send. Format values every reader applies alike, such as the frame
// bound and the issued headers' widths, are constants beside their formats, not settings. Every
// number here must be positive, as settings.go's header says.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"fmt"
	"reflect"
	"time"
)

// What one host's sender may do and how long it waits.
type SmtpSenderSettings struct {
	// The first retry of a held or failed send: 30 min after it, the interval doubling from there
	// (plan-SMTP-small-readings#9).
	RetryFirstTimeout time.Duration
	// The longest interval between retries, which the doubling stops at: 4 h.
	RetryMaxTimeout time.Duration
	// How long after its creation a message is retried before a DSN gives it up: 5 days. HALTED,
	// QUOTA and TRY_LATER honor retry_after_ms and still end here.
	RetryGiveUpTimeout time.Duration
	// The connection units one message's retries that reach MAIL may spend in a UTC day, past which
	// the message waits for the next UTC day: 2 (plan-SMTP-small-readings#9).
	RetryUnitsPerMessagePerDay int
	// Sends proving at once on this host: 1, since a part's proving does not fit an 8 GB host twice
	// (plan-SMTP-small-readings#19). Proving sits outside MemoryBudgetByteCount.
	ProverConcurrency int
	// How long an MX host's best TLS level and its post-TLS mode stay pinned: 90 days (§14.4, §14.5).
	// Nothing is sent below a pin while it holds.
	PinTimeout time.Duration
	// How many MX hosts' pins, and how many recipient domains' last sessions, the pin store keeps:
	// 4,096 each, the one closest to lapsing leaving first past it, so the sealed file stays small
	// enough to rewrite on every send.
	PinMaxCount int
	// How long one of TL2's or TL3's DoH lookups, the _mta-sts TXT or the recipient domain's MX, may
	// take before that level counts as unavailable for the send: 15 s, well inside the 5 minutes an MX
	// waits for the ClientHello after STARTTLS's 220.
	TlsLookupTimeout time.Duration
	// How long the HTTPS fetch of an MTA-STS policy may take: 1 min, RFC 8461 §3.3's suggestion.
	MtaStsFetchTimeout time.Duration
	// The largest MTA-STS policy body taken: 64 KiB, RFC 8461 §3.3's suggestion.
	MtaStsPolicyMaxByteCount int
	// How long after a failed fetch for one policy id the next fetch waits: 5 min, RFC 8461 §3.3's
	// floor, so a broken policy host is not asked again on every send.
	MtaStsFetchRetryTimeout time.Duration
	// How many recipient domains' MTA-STS policies stay cached: 4,096, the one closest to its max_age
	// leaving first past it.
	MtaStsPolicyMaxCount int
	// How often a prover host rewrites or/ while a send it took runs: 5 min, so another host can see
	// it is alive (plan-SMTP-small-readings#10).
	OutboxProgressInterval time.Duration
	// How long an entry's or/ goes unchanged before the next host takes the send over: 10 min. A crash
	// can still send twice, which §22.7 allows.
	OutboxTakeoverTimeout time.Duration
	// How long a DKIM selector signs before one POST /smtp/dkim-keys publishes its successor and
	// retires it: 90 days (§14.6).
	DkimRotateTimeout time.Duration
	// How long a retired selector's private key stays in the keychain: 7 days, as long as the server
	// keeps the selector in DNS (§14.6), so a send that pinned it before a rotation still signs and
	// still verifies. A pinned selector outlives this until its send releases it.
	DkimRetiredKeepTimeout time.Duration
	// How long a DKIM signature stays valid: x= is t= plus 7 days (§14.6), and a report about the
	// message joins on the fixed signature only while it holds.
	DkimExpireTimeout time.Duration
}

// A fresh value each call, sharing nothing mutable with any other (connect/CODESTYLE.md:151).
func DefaultSmtpSenderSettings() *SmtpSenderSettings {
	return &SmtpSenderSettings{
		RetryFirstTimeout:          30 * time.Minute,
		RetryMaxTimeout:            4 * time.Hour,
		RetryGiveUpTimeout:         5 * 24 * time.Hour,
		RetryUnitsPerMessagePerDay: 2,
		ProverConcurrency:          1,
		PinTimeout:                 90 * 24 * time.Hour,
		PinMaxCount:                4096,
		TlsLookupTimeout:           15 * time.Second,
		MtaStsFetchTimeout:         time.Minute,
		MtaStsPolicyMaxByteCount:   64 * 1024,
		MtaStsFetchRetryTimeout:    5 * time.Minute,
		MtaStsPolicyMaxCount:       4096,
		OutboxProgressInterval:     5 * time.Minute,
		OutboxTakeoverTimeout:      10 * time.Minute,
		DkimRotateTimeout:          90 * 24 * time.Hour,
		DkimRetiredKeepTimeout:     7 * 24 * time.Hour,
		DkimExpireTimeout:          7 * 24 * time.Hour,
	}
}

// What validateLeg holds a sender's settings to: present, every number positive, and the schedules
// in their order, so a retry never waits past giving up and a live host is never taken over.
func (self *SmtpSenderSettings) validate() error {
	if self == nil {
		return fmt.Errorf("%w: Connect.SmtpSender is nil", errInvalidSettings)
	}
	if err := checkSettingsNumbers("Connect.SmtpSender", reflect.ValueOf(self).Elem(), false); err != nil {
		return err
	}
	if self.RetryMaxTimeout < self.RetryFirstTimeout || self.RetryGiveUpTimeout < self.RetryMaxTimeout {
		return fmt.Errorf("%w: Connect.SmtpSender's retry timeouts are out of order", errInvalidSettings)
	}
	if self.OutboxTakeoverTimeout <= self.OutboxProgressInterval {
		return fmt.Errorf("%w: Connect.SmtpSender takes a send over before its host could show progress", errInvalidSettings)
	}
	return nil
}
