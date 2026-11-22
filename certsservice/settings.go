// certs' tunables (§13.8; D-TLS-7). DefaultCertsSettings is the only source of a default
// (connect/CODESTYLE.md:144), and a host lays config/<env>/certs.yml over it (TLS-M5-16). Validate refuses
// what would leave a rule unenforced: a zero is never unlimited unless the field says so.
//
// Each number a CA sets says where it comes from. Let's Encrypt's are from its rate-limits page (last
// updated 2026-08-05) and its profiles page, both read 2026-11-15 (QD-784); GTS's and ZeroSSL's are
// §13.8's, from [R:ext-edge], and were not read again. A default no CA sets is this build's choice, or
// cert-1's where its field says so.

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
	// The ACME profile an order asks for: LE's tlsserver, 45-day certificates, 7 h authorization reuse
	// and at most 25 names (§13.8; LE's profiles page, read 2026-11-15). An order that names no profile
	// gets LE's classic, 90 days and 30 days. Empty asks for none.
	Profile string
	// How long an order lives at the CA from its creation, past which the CA calls it invalid however far
	// it got: LE's tlsserver 8 h (LE's profiles page, read 2026-11-15). An order at this CA gives up no
	// later than this (CertsSettings.OrderGiveUpAge). Zero: the CA's lifetime is not known here, and
	// OrderGiveUpAge alone bounds its orders. Never negative.
	OrderLifetime time.Duration
	// New-set orders at most BudgetCap in any BudgetWindow, under <root>'s budget with this CA
	// ({tcb_<ca>_<registered_domain>}), set below the CA's own limit so a race or a lost key cannot
	// reach it (§13.8's Budget). A BudgetCap of zero keeps no budget at this CA.
	BudgetWindow time.Duration
	BudgetCap    int
	// Whether §13.8's repeated-set rule holds at this CA. It models LE's limit on new certificates for an
	// exact set of names, which also counts a renewal that names no replaces, so a set spent there moves
	// on to the next CA, as a team adding devices quickly needs (§13.16).
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
	// RepeatSetRefill, with no overrides: LE's 5 new certificates for an exact set of names in 7 days, one
	// back each 34 h, no override (§13.8; LE's rate-limits page, read 2026-11-15). Positive.
	RepeatSetCount  int
	RepeatSetRefill time.Duration
	// A name with FailedAuthorizationCount failed authorizations inside FailedAuthorizationWindow holds
	// until the oldest of them leaves it, so no name reaches LE's 5 failed authorizations an identifier
	// and account an hour, one back each 12 min, no override (LE's rate-limits page, read 2026-11-15): 4
	// keeps one in hand. Positive.
	FailedAuthorizationCount  int
	FailedAuthorizationWindow time.Duration
	// After a name's k-th failed authorization at a CA since its last success there, no order for it goes
	// to that CA for min(2^(k-1) x FailureBackoff, FailureBackoffMax), while another CA in the order may
	// take it (QD-857). From its seventh failure there on, a failing name fails at a CA about once a day,
	// which LE's daily refill of its 1,152 consecutive failed authorizations a name and account hands back,
	// so LE's count stays near seven, far from the pause LE puts on a name past them (LE's rate-limits page,
	// read 2026-11-15). Defaults 30 min and 24 h, DESIGN-DETAILS 17.2.8's failure backoff for a custom
	// host. The store keeps the count and the time, so a restart keeps them, and a success at the CA ends
	// them. Positive, and FailureBackoff at most FailureBackoffMax.
	FailureBackoff    time.Duration
	FailureBackoffMax time.Duration
	// A name's backoff at a CA stays this long past the time it holds orders until, then goes (cert-1's
	// ttl). By then the CA has handed back, one a day, every failure the backoff lets a name keep counted
	// there. Default 8 d, as DESIGN-DETAILS 17.2.15 keeps a custom host's failures. Positive.
	FailureBackoffRetention time.Duration
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
	// again; a renewal of a certificate still valid queues again whatever its age. At a CA with an
	// OrderLifetime the shorter of the two counts (orderGiveUpAge), so no order outwaits the life the CA
	// gives one. Default a day, this build's choice, which LE's 8 h cuts for its orders. Positive.
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
	// The most TXT values one _acme-challenge name holds: a set's name's and its wildcard's (§12.7, §12.8;
	// RFC 8555 §8.4). A protocol limit, which dns's challenge route holds writes to (server's
	// model.DnsChallengeSettings.ValueMaxCount), so it changes on both sides at once. Default 2. Positive.
	DnsChallengeValueMaxCount int
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
			// LE's numbers, from its rate-limits and profiles pages, read 2026-11-15
			CertsCaLetsEncrypt: {
				// tlsserver's 45-day certificates; its orders live 8 h
				Profile:       "tlsserver",
				OrderLifetime: 8 * time.Hour,
				// LE allows 50 new certificates a registered domain in 7 days, all accounts together, one
				// back each 202 min: 40 in any 7 days keeps a margin for a race, a lost key and <root>'s
				// other issuance
				BudgetWindow: 7 * 24 * time.Hour,
				BudgetCap:    40,
				// LE allows 5 new certificates an exact set of names in 7 days (RepeatSetCount)
				RepeatSetLimited: true,
			},
			// GTS allows 100 new orders an hour a project (§13.8, [R:ext-edge]): 90 keeps a margin. Its order
			// lifetime is not known here.
			CertsCaGts: {
				BudgetWindow: 1 * time.Hour,
				BudgetCap:    90,
			},
			// ZeroSSL's 90-day certificates are unlimited (§13.8, [R:ext-edge]). Its order lifetime is not
			// known here.
			CertsCaZeroSsl: {},
		},
		// D-TLS-7's orders
		CaOrder:          []CertsCa{CertsCaLetsEncrypt, CertsCaGts, CertsCaZeroSsl},
		EphemeralCaOrder: []CertsCa{CertsCaGts, CertsCaZeroSsl, CertsCaLetsEncrypt},
		// LE's 5 an exact set in 7 days, one back each 34 h (rate-limits page, read 2026-11-15)
		RepeatSetCount:  5,
		RepeatSetRefill: 34 * time.Hour,
		// under LE's 5 failed authorizations an identifier and account an hour (rate-limits page, read
		// 2026-11-15)
		FailedAuthorizationCount:  4,
		FailedAuthorizationWindow: 1 * time.Hour,
		FailureBackoff:            30 * time.Minute,
		FailureBackoffMax:         24 * time.Hour,
		FailureBackoffRetention:   8 * 24 * time.Hour,
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
		DnsChallengeValueMaxCount: 2,
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

// How long a name waits at a CA after its failureCount-th failed authorization there since its last
// success there (certsFailureBackoffWait). The store calls it as it counts a failure.
func (self *CertsSettings) failureBackoffWait(failureCount int) time.Duration {
	return certsFailureBackoffWait(failureCount, self.FailureBackoff, self.FailureBackoffMax)
}

// How old an order at ca grows before a failure fails it rather than queueing it again: OrderGiveUpAge,
// or the CA's OrderLifetime when that is shorter, past which the CA has called invalid any order it
// made for the row's first attempt.
func (self *CertsSettings) orderGiveUpAge(ca CertsCa) time.Duration {
	giveUpAge := self.OrderGiveUpAge
	if caSettings := self.Cas[ca]; caSettings != nil && 0 < caSettings.OrderLifetime {
		giveUpAge = min(giveUpAge, caSettings.OrderLifetime)
	}
	return giveUpAge
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
		if caSettings.OrderLifetime < 0 {
			return fmt.Errorf("%w: CA %s's OrderLifetime is negative", ErrCertsSettingsRefused, ca)
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
		"FailureBackoff":            int64(self.FailureBackoff),
		"FailureBackoffMax":         int64(self.FailureBackoffMax),
		"FailureBackoffRetention":   int64(self.FailureBackoffRetention),
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
		"DnsChallengeValueMaxCount": int64(self.DnsChallengeValueMaxCount),
		"AccountRolloverAge":        int64(self.AccountRolloverAge),
	} {
		if value <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrCertsSettingsRefused, name)
		}
	}
	if !(0 < self.RenewalLifetimeFraction && self.RenewalLifetimeFraction < 1) {
		return fmt.Errorf("%w: RenewalLifetimeFraction is not between 0 and 1", ErrCertsSettingsRefused)
	}
	if self.FailureBackoffMax < self.FailureBackoff {
		return fmt.Errorf("%w: FailureBackoff is longer than FailureBackoffMax", ErrCertsSettingsRefused)
	}
	return nil
}
