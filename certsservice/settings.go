// certs' tunables (§13.8; D-TLS-7). DefaultCertsSettings is the only source of a default
// (connect/CODESTYLE.md:144), and a host lays config/<env>/certs.yml over it (TLS-M5-16). Validate refuses
// what would leave a rule unenforced: a zero is never unlimited unless the field says so.

package certsservice

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// A settings value certs cannot run on. The wrapping error names the field, never its value.
var ErrCertsSettingsRefused = errors.New("certs settings refused")

// One CA's part of the policy.
type CertsCaSettings struct {
	// The ACME profile an order asks for: LE's tlsserver, 45 days and 25 names (§13.8). Empty asks for
	// none.
	Profile string
	// New-set orders at most BudgetCap in any BudgetWindow, under <root>'s budget with this CA
	// ({tcb_<ca>_<registered_domain>}), set below the CA's own limit so a race or a lost key cannot
	// reach it (§13.8's Budget). A BudgetCap of zero keeps no budget at this CA.
	BudgetWindow time.Duration
	BudgetCap    int
	// Whether §13.8's repeated-set rule holds at this CA. It models LE's duplicate-certificate limit,
	// so a set spent there moves on to the next CA, as a team adding devices quickly needs (§13.16).
	RepeatSetLimited bool
	// The CA's ACME directory, from certs.yml. No default: a production URL, which the host sets. Empty:
	// no order reaches this CA, so the policy may admit to it and its order fails.
	DirectoryUrl string
}

// What certs runs on. Safe to read concurrently once built, and never changed after.
type CertsSettings struct {
	// <root>, the registered domain every URnetwork-zone set sits under and the budget keys name (§13.8).
	// No default: it is a production name, which the host sets.
	RootDomain string
	// Each CA's policy. A CA with no entry is never chosen.
	Cas map[CertsCa]*CertsCaSettings
	// The CAs an order tries, in order, the next taken when one holds, is spent or refused on a limit:
	// LE, then GTS, then ZeroSSL (D-TLS-7).
	CaOrder []CertsCa
	// The same for an ephemeral sidecar (CI, cloud agents): GTS, then ZeroSSL, ahead of LE (D-TLS-7).
	EphemeralCaOrder []CertsCa

	// A repeated set's orders at one RepeatSetLimited CA: a bucket of RepeatSetCount, refilling one per
	// RepeatSetRefill, with no overrides (§13.8: 5 per 7 days, one per 34 h). Positive.
	RepeatSetCount  int
	RepeatSetRefill time.Duration
	// A name with FailedAuthorizationCount failed authorizations inside FailedAuthorizationWindow holds
	// until the oldest of them leaves it, so no name reaches LE's 5 per identifier per hour. Positive.
	FailedAuthorizationCount  int
	FailedAuthorizationWindow time.Duration
	// How long past a CA's Retry-After the orders it holds wait, since the CA's clock and this one
	// differ by seconds. Positive.
	RetryAfterMargin time.Duration
	// How long a CA's refusal on a limit holds when it names no Retry-After. Positive.
	DefaultRetryAfter time.Duration

	// A budget key lives this long past its newest order (cert-1: 7 d). At least every BudgetWindow.
	BudgetTtl time.Duration
	// A row stays this long past its expiry, revocation or failure (§13.8, cert-1: 30 d). Positive.
	RowRetention time.Duration
	// A row keeps its issued chain this long past its certificate's expiry or revocation (cert-1: 30 d;
	// QD-741). Positive. A row gone sooner takes its chain with it.
	ChainRetention time.Duration
	// Queued rows one admission pass reads at most. Positive.
	AdmitBatchCount int
	// What GET /tls/cert-order/<id> tells a device to wait before asking again while its order is under
	// way. Positive.
	OrderRetryAfter time.Duration
	// How long one store, budget or DNS call may take before it reads as failed. Positive.
	CallTimeout time.Duration

	// The chains' (TLS-M5-17, run.go).

	// The rows an earlier pass left under way that one order pass takes up again at most, before it
	// admits any. Positive.
	OrderResumeCount int
	// The orders one pass has at its CAs at once. Positive.
	OrderConcurrency int
	// An order that has not issued this long after it was accepted fails, where a younger one queues
	// again; a renewal of a certificate still valid queues again whatever its age. Positive.
	OrderGiveUpAge time.Duration
	// Issued rows one renewal pass reads at most. Positive.
	RenewalBatchCount int
	// Issued rows one revocation pass asks its source about at most, and revoking rows it takes to
	// their CAs at most. Positive.
	RevocationBatchCount int

	// ACME's (TLS-M5-15).

	// How often acmez polls an authorization or an order the CA did not give a Retry-After for.
	// Default 1 s.
	AcmePollInterval time.Duration
	// How long acmez polls one authorization or order before it gives up. Default 5 min.
	AcmePollTimeout time.Duration
	// How long one order may take from its account to its chain, DNS waits included. Default 30 min,
	// past which the order fails and its chain queues it again.
	AcmeOrderTimeout time.Duration
	// How long one request to a CA may take, and one ARI read, revocation or account change. Default 1 min.
	AcmeRequestTimeout time.Duration
	// The first wait after a /dns/* route answered 503 or did not answer, doubling to DnsRetryMaxDelay.
	// Defaults 1 s and 1 min.
	DnsRetryDelay    time.Duration
	DnsRetryMaxDelay time.Duration
	// The wait after GET /dns/ready answered waiting, before asking again. The route holds a request
	// itself, so this only keeps a fast answer from spinning. Default 1 s.
	DnsWaitingDelay time.Duration
	// The wait after the canary read failing or unknown, before asking again with no new write. Default
	// 30 s, the canary's own cadence.
	CanaryRetryDelay time.Duration
	// How long removing an order's challenges may take, on a context of its own. Default 30 s.
	DnsCleanupTimeout time.Duration
	// How old an account key is when it rolls over (RFC 8555 §7.3.5). Default a year (§13.8).
	AccountRolloverAge time.Duration
	// How far into its validity a certificate with no ARI window renews (§13.8: two thirds). Between 0
	// and 1.
	RenewalLifetimeFraction float64
}

// The design's numbers. RootDomain stays empty, so these alone do not pass Validate.
func DefaultCertsSettings() *CertsSettings {
	return &CertsSettings{
		Cas: map[CertsCa]*CertsCaSettings{
			// LE allows 50 new certificates per registered domain per 7 days across accounts
			CertsCaLetsEncrypt: {
				Profile:          "tlsserver",
				BudgetWindow:     7 * 24 * time.Hour,
				BudgetCap:        40,
				RepeatSetLimited: true,
			},
			// GTS allows 100 new orders per hour per project
			CertsCaGts: {
				BudgetWindow: 1 * time.Hour,
				BudgetCap:    90,
			},
			// ZeroSSL's 90-day certificates are unlimited
			CertsCaZeroSsl: {},
		},
		CaOrder:                   []CertsCa{CertsCaLetsEncrypt, CertsCaGts, CertsCaZeroSsl},
		EphemeralCaOrder:          []CertsCa{CertsCaGts, CertsCaZeroSsl, CertsCaLetsEncrypt},
		RepeatSetCount:            5,
		RepeatSetRefill:           34 * time.Hour,
		FailedAuthorizationCount:  4,
		FailedAuthorizationWindow: 1 * time.Hour,
		RetryAfterMargin:          1 * time.Minute,
		DefaultRetryAfter:         1 * time.Hour,
		BudgetTtl:                 7 * 24 * time.Hour,
		RowRetention:              30 * 24 * time.Hour,
		ChainRetention:            30 * 24 * time.Hour,
		AdmitBatchCount:           100,
		OrderRetryAfter:           30 * time.Second,
		CallTimeout:               10 * time.Second,
		OrderResumeCount:          32,
		OrderConcurrency:          4,
		OrderGiveUpAge:            24 * time.Hour,
		RenewalBatchCount:         200,
		RevocationBatchCount:      200,
		AcmePollInterval:          1 * time.Second,
		AcmePollTimeout:           5 * time.Minute,
		AcmeOrderTimeout:          30 * time.Minute,
		AcmeRequestTimeout:        1 * time.Minute,
		DnsRetryDelay:             1 * time.Second,
		DnsRetryMaxDelay:          1 * time.Minute,
		DnsWaitingDelay:           1 * time.Second,
		CanaryRetryDelay:          30 * time.Second,
		DnsCleanupTimeout:         30 * time.Second,
		AccountRolloverAge:        365 * 24 * time.Hour,
		RenewalLifetimeFraction:   2.0 / 3.0,
	}
}

// The CAs to try for a sidecar, in order.
func (self *CertsSettings) caOrder(ephemeral bool) []CertsCa {
	if ephemeral {
		return self.EphemeralCaOrder
	}
	return self.CaOrder
}

// Whether certs can run on these settings. A refusal names the field.
func (self *CertsSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrCertsSettingsRefused)
	}
	root := strings.TrimSuffix(self.RootDomain, ".")
	if root == "" || root != self.RootDomain || !strings.Contains(root, ".") || strings.ToLower(root) != root {
		return fmt.Errorf("%w: RootDomain is not a lowercase registered domain", ErrCertsSettingsRefused)
	}
	for _, order := range [][]CertsCa{self.CaOrder, self.EphemeralCaOrder} {
		if len(order) == 0 {
			return fmt.Errorf("%w: a CA order is empty", ErrCertsSettingsRefused)
		}
		for index, ca := range order {
			caSettings, ok := self.Cas[ca]
			if !ok || caSettings == nil {
				return fmt.Errorf("%w: CA %s has no settings", ErrCertsSettingsRefused, ca)
			}
			if slices.Contains(order[:index], ca) {
				return fmt.Errorf("%w: CA %s is listed twice", ErrCertsSettingsRefused, ca)
			}
		}
	}
	for ca, caSettings := range self.Cas {
		if !ca.valid() {
			return fmt.Errorf("%w: unknown CA %q", ErrCertsSettingsRefused, ca)
		}
		if caSettings == nil || caSettings.BudgetCap < 0 || (0 < caSettings.BudgetCap && caSettings.BudgetWindow <= 0) {
			return fmt.Errorf("%w: CA %s's budget", ErrCertsSettingsRefused, ca)
		}
		if 0 < caSettings.BudgetCap && self.BudgetTtl < caSettings.BudgetWindow {
			return fmt.Errorf("%w: BudgetTtl is shorter than CA %s's window", ErrCertsSettingsRefused, ca)
		}
	}
	for name, value := range map[string]int64{
		"RepeatSetCount":            int64(self.RepeatSetCount),
		"RepeatSetRefill":           int64(self.RepeatSetRefill),
		"FailedAuthorizationCount":  int64(self.FailedAuthorizationCount),
		"FailedAuthorizationWindow": int64(self.FailedAuthorizationWindow),
		"RetryAfterMargin":          int64(self.RetryAfterMargin),
		"DefaultRetryAfter":         int64(self.DefaultRetryAfter),
		"BudgetTtl":                 int64(self.BudgetTtl),
		"RowRetention":              int64(self.RowRetention),
		"ChainRetention":            int64(self.ChainRetention),
		"AdmitBatchCount":           int64(self.AdmitBatchCount),
		"OrderRetryAfter":           int64(self.OrderRetryAfter),
		"CallTimeout":               int64(self.CallTimeout),
		"OrderResumeCount":          int64(self.OrderResumeCount),
		"OrderConcurrency":          int64(self.OrderConcurrency),
		"OrderGiveUpAge":            int64(self.OrderGiveUpAge),
		"RenewalBatchCount":         int64(self.RenewalBatchCount),
		"RevocationBatchCount":      int64(self.RevocationBatchCount),
		"AcmePollInterval":          int64(self.AcmePollInterval),
		"AcmePollTimeout":           int64(self.AcmePollTimeout),
		"AcmeOrderTimeout":          int64(self.AcmeOrderTimeout),
		"AcmeRequestTimeout":        int64(self.AcmeRequestTimeout),
		"DnsRetryDelay":             int64(self.DnsRetryDelay),
		"DnsRetryMaxDelay":          int64(self.DnsRetryMaxDelay),
		"DnsWaitingDelay":           int64(self.DnsWaitingDelay),
		"CanaryRetryDelay":          int64(self.CanaryRetryDelay),
		"DnsCleanupTimeout":         int64(self.DnsCleanupTimeout),
		"AccountRolloverAge":        int64(self.AccountRolloverAge),
	} {
		if value <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrCertsSettingsRefused, name)
		}
	}
	if !(0 < self.RenewalLifetimeFraction && self.RenewalLifetimeFraction < 1) {
		return fmt.Errorf("%w: RenewalLifetimeFraction is not between 0 and 1", ErrCertsSettingsRefused)
	}
	return nil
}
