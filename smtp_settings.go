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
	// How often a prover host rewrites or/ while a send it took runs: 5 min, so another host can see
	// it is alive (plan-SMTP-small-readings#10).
	OutboxProgressInterval time.Duration
	// How long an entry's or/ goes unchanged before the next host takes the send over: 10 min. A crash
	// can still send twice, which §22.7 allows.
	OutboxTakeoverTimeout time.Duration
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
		OutboxProgressInterval:     5 * time.Minute,
		OutboxTakeoverTimeout:      10 * time.Minute,
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
