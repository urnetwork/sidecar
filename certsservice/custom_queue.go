// certs' half of Team custom-domain certificates (TLS-M6-05; DESIGN-DETAILS 17.2.3 to 17.2.15): the numbers the
// server counts a customer's account by (CertsCustomSettings), the bucket every budget replays from its spends
// (CertsCustomBucket, 17.2.8's level and wait), the renewal point of a custom certificate (CertsCustomRenewTime), the
// custom branch's CSR check, and the sweep (RunCustomSweep, 17.2.11), which queues renewals as successor rows,
// expires rows, drops old spends and raises 17.2.14's warnings, and makes no CA call.
//
// A custom row is certs' only in what this file does: certs' own passes (Admit, RunRenewals, RunRevocations,
// FindOpenOrder) read queued, ordering, waiting_dns, issued and revoking, and a custom row is never in one, so no
// custom row is ordered, renewed or revoked under a URnetwork account (17.3's C9). Its claim, progress, register and
// account operations are server's model, one transaction each, under the account's lock (17.2.6).
//
// Every number is a field of CertsCustomSettings, a default the owner may correct (QD-702, QD-784 to QD-790).

package certsservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
)

// The kinds of spend a budget replays (17.2.3's network_tls_custom_spend.kind).
const (
	CertsCustomSpendCertificate = "certificate"
	CertsCustomSpendNewOrder    = "new_order"
	CertsCustomSpendAuthzFailed = "authz_failed"
	CertsCustomSpendNoRoute     = "no_route"
)

// The CA a custom account is at, as rows and spends name it: Let's Encrypt, the one CA the customer's CAA pins
// (owner decision 39).
const CertsCustomCaLetsEncrypt = "letsencrypt"

// What the server counts a customer's account by (17.2.15). DefaultCertsCustomSettings is the only source of a
// default.
type CertsCustomSettings struct {
	// The lock's lease on the database's clock. Positive.
	LockLease time.Duration
	// How often the sweep runs. Positive.
	SweepInterval time.Duration
	// How long a spend is kept: 15 d (QD-990), all a bucket's replay reads, which starts full at its key's newest quiet
	// window within it and else empty at its start (QD-994). At least each bucket's window, so a quiet one fits in it.
	SpendRetention time.Duration
	// A CA's 429: the hold it sets, clamped to [HoldDefault, HoldMax]. Positive.
	HoldDefault time.Duration
	HoldMax     time.Duration
	// How far into a certificate's validity its renewal is queued when it has no ARI window: two thirds. Between 0
	// and 1.
	RenewalLifetimeFraction float64
	// How far into it tls_custom_renewal_due warns: a half. Between 0 and 1, at most RenewalLifetimeFraction.
	LapseWarnFraction float64
	// The certificates a registered chain holds at most. Positive.
	ChainMaxCount int
	// A claimable work row unclaimed this long warns tls_custom_queue_stalled. Positive.
	QueueStallAfter time.Duration
	// An ordering desktop's poll is stamped in orderer_seen when its stamp is older than this. Positive.
	OrdererSeenStamp time.Duration
	// An account with live rows and fewer than OrdererMinCount desktops seen in OrdererSeenWindow warns
	// tls_custom_one_orderer; stamps older than the window are pruned. Positive.
	OrdererMinCount   int
	OrdererSeenWindow time.Duration
	// Each warning at most once a host or account in this interval. Positive.
	EventRepeatInterval time.Duration
	// A host whose row failed is renewed by the sweep again only this long after. Positive.
	RequeueBackoff time.Duration
	// A certificate's lifetime, for the tests' and 17.4's arithmetic: a row's own validity is what counts (A1).
	Lifetime time.Duration
	// The exact-set bucket, per CA and custom host: LE's 5 in 7 days, one back each 34 h (A4), keeping SetReserve
	// back, so a compromised device can be certified again at once.
	SetCap     int
	SetRefill  time.Duration
	SetReserve int
	// Our share of the registered domain's bucket: 25 of LE's 50 in 7 days, one back each 6 h 43 min 12 s (A3).
	DomainCap    int
	DomainRefill time.Duration
	// The account's new orders: 60, one back each 3 min, a fifth of LE's 300 in 3 h (A5).
	OrderCap    int
	OrderRefill time.Duration
	// A host's failed authorizations and route probes: after the k-th since its newest register, no grant for
	// min(2^(k−1) × FailureBackoff, FailureBackoffMax) (A6, A10). Positive.
	FailureBackoff    time.Duration
	FailureBackoffMax time.Duration
	// Custom rows one sweep reads at most. Positive.
	SweepBatchCount int
}

// The numbers of DESIGN-DETAILS 17.2.15, from LE's rate-limits and profiles pages read 2026-11-15 (QD-784).
func DefaultCertsCustomSettings() *CertsCustomSettings {
	return &CertsCustomSettings{
		LockLease:               120 * time.Second,
		SweepInterval:           10 * time.Minute,
		SpendRetention:          15 * 24 * time.Hour,
		HoldDefault:             1 * time.Hour,
		HoldMax:                 7 * 24 * time.Hour,
		RenewalLifetimeFraction: 2.0 / 3.0,
		LapseWarnFraction:       1.0 / 2.0,
		ChainMaxCount:           4,
		QueueStallAfter:         24 * time.Hour,
		OrdererSeenStamp:        1 * time.Hour,
		OrdererMinCount:         2,
		OrdererSeenWindow:       7 * 24 * time.Hour,
		EventRepeatInterval:     24 * time.Hour,
		RequeueBackoff:          6 * time.Hour,
		Lifetime:                45 * 24 * time.Hour,
		SetCap:                  5,
		SetRefill:               34 * time.Hour,
		SetReserve:              1,
		DomainCap:               25,
		DomainRefill:            6*time.Hour + 43*time.Minute + 12*time.Second,
		OrderCap:                60,
		OrderRefill:             3 * time.Minute,
		FailureBackoff:          30 * time.Minute,
		FailureBackoffMax:       24 * time.Hour,
		SweepBatchCount:         500,
	}
}

// A settings value the custom routes and sweep cannot run on. The wrapping error names the field.
var ErrCertsCustomSettingsRefused = errors.New("certs custom settings refused")

// Whether the routes and the sweep can run on these settings. A refusal names the field.
func (self *CertsCustomSettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no settings", ErrCertsCustomSettingsRefused)
	}
	for name, value := range map[string]int64{
		"LockLease":              int64(self.LockLease),
		"SweepInterval":          int64(self.SweepInterval),
		"SpendRetention":         int64(self.SpendRetention),
		"HoldDefault":            int64(self.HoldDefault),
		"HoldMax":                int64(self.HoldMax - self.HoldDefault + 1),
		"ChainMaxCount":          int64(self.ChainMaxCount),
		"QueueStallAfter":        int64(self.QueueStallAfter),
		"OrdererSeenStamp":       int64(self.OrdererSeenStamp),
		"OrdererMinCount":        int64(self.OrdererMinCount),
		"OrdererSeenWindow":      int64(self.OrdererSeenWindow),
		"EventRepeatInterval":    int64(self.EventRepeatInterval),
		"RequeueBackoff":         int64(self.RequeueBackoff),
		"Lifetime":               int64(self.Lifetime),
		"SetCap":                 int64(self.SetCap),
		"SetRefill":              int64(self.SetRefill),
		"DomainCap":              int64(self.DomainCap),
		"DomainRefill":           int64(self.DomainRefill),
		"OrderCap":               int64(self.OrderCap),
		"OrderRefill":            int64(self.OrderRefill),
		"FailureBackoff":         int64(self.FailureBackoff),
		"FailureBackoffMax":      int64(self.FailureBackoffMax - self.FailureBackoff + 1),
		"SweepBatchCount":        int64(self.SweepBatchCount),
		"SetCap less SetReserve": int64(self.SetCap - self.SetReserve),
	} {
		if value <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrCertsCustomSettingsRefused, name)
		}
	}
	if self.SetReserve < 0 {
		return fmt.Errorf("%w: SetReserve is negative", ErrCertsCustomSettingsRefused)
	}
	if !(0 < self.LapseWarnFraction && self.LapseWarnFraction <= self.RenewalLifetimeFraction && self.RenewalLifetimeFraction < 1) {
		return fmt.Errorf("%w: LapseWarnFraction and RenewalLifetimeFraction are not 0 < warn <= renew < 1", ErrCertsCustomSettingsRefused)
	}
	// a retention that holds no whole window holds no quiet one, so the replay could never start full
	for name, bucket := range map[string]CertsCustomBucket{"set": self.SetBucket(), "domain": self.DomainBucket(), "orders": self.OrderBucket()} {
		if self.SpendRetention < time.Duration(bucket.Capacity)*bucket.Refill {
			return fmt.Errorf("%w: SpendRetention is shorter than the %s bucket's window", ErrCertsCustomSettingsRefused, name)
		}
	}
	return nil
}

// 17.2.8's set bucket, per CA and custom host.
func (self *CertsCustomSettings) SetBucket() CertsCustomBucket {
	return CertsCustomBucket{Capacity: self.SetCap, Refill: self.SetRefill, Retention: self.SpendRetention}
}

// 17.2.8's domain bucket, per CA and registered domain.
func (self *CertsCustomSettings) DomainBucket() CertsCustomBucket {
	return CertsCustomBucket{Capacity: self.DomainCap, Refill: self.DomainRefill, Retention: self.SpendRetention}
}

// 17.2.8's orders bucket, per CA and account.
func (self *CertsCustomSettings) OrderBucket() CertsCustomBucket {
	return CertsCustomBucket{Capacity: self.OrderCap, Refill: self.OrderRefill, Retention: self.SpendRetention}
}

// One budget of 17.2.8: Capacity tokens refilling one each Refill, replayed from the spends of the last Retention.
type CertsCustomBucket struct {
	Capacity int
	Refill   time.Duration
	// How far back the replay reads spends: CertsCustomSettings.SpendRetention, all the store keeps (QD-990, QD-994).
	Retention time.Duration
}

// Where the replay at now reads from: it takes the spends after this, which a store reads.
func (self CertsCustomBucket) ReplayStart(now time.Time) time.Time {
	return now.Add(-self.Retention)
}

// The bucket's level at now, in refill units so nothing rounds, replayed from the spends of (now − Retention, now]
// (17.2.8's level, QD-994): full at the key's latest quiet instant, the newest t at or before now whose window
// (t − Capacity × Refill, t] lies within the retention and holds no spend, where the CA's bucket is full whatever came
// before; then each spend after it taking one, after the time since the last refilled it, never above Capacity. Where
// no quiet instant lies within the retained spends it starts empty at the retention's start. So the level is never
// above the truth (C5), and it is the truth while a key's busy stretch, its spends with no quiet window between them,
// is shorter than Retention less one window. A level may go below zero: a spend the replay could not afford.
func (self CertsCustomBucket) levelDuration(spends []time.Time, now time.Time) time.Duration {
	full := time.Duration(self.Capacity) * self.Refill
	horizon := self.ReplayStart(now)
	times := []time.Time{}
	for _, spend := range spends {
		if horizon.Before(spend) && !now.Before(spend) {
			times = append(times, spend)
		}
	}
	slices.SortFunc(times, func(a time.Time, b time.Time) int { return a.Compare(b) })
	// whether the window before at lies within the retention and holds no spend but those at or before its start,
	// previous being the newest spend before at, nil for none
	quiet := func(at time.Time, previous *time.Time) bool {
		windowStart := at.Add(-full)
		return !windowStart.Before(horizon) && (previous == nil || !windowStart.Before(*previous))
	}
	var last *time.Time
	if 0 < len(times) {
		last = &times[len(times)-1]
	}
	if quiet(now, last) {
		return full
	}
	// the newest spend a quiet window precedes starts the replay full just before it; with none, empty at the horizon
	level := time.Duration(0)
	at := horizon
	from := 0
	for index := len(times) - 1; 0 <= index; index -= 1 {
		var previous *time.Time
		if 0 < index {
			previous = &times[index-1]
		}
		if quiet(times[index], previous) {
			level = full
			at = times[index]
			from = index
			break
		}
	}
	for _, spend := range times[from:] {
		level = min(full, level+spend.Sub(at)) - self.Refill
		at = spend
	}
	return min(full, level+now.Sub(at))
}

// 17.2.8's level: the tokens the bucket holds at now, replayed from spends.
func (self CertsCustomBucket) Level(spends []time.Time, now time.Time) float64 {
	return float64(self.levelDuration(spends, now)) / float64(self.Refill)
}

// 17.2.8's wait: zero when the bucket holds need tokens at now, else how long until it does with no further spend.
func (self CertsCustomBucket) Wait(spends []time.Time, now time.Time, need int) time.Duration {
	level := self.levelDuration(spends, now)
	needed := time.Duration(need) * self.Refill
	if needed <= level {
		return 0
	}
	return needed - level
}

// The failure backoff's wait at now (17.2.8): after the k-th of failureTimes, no grant for
// min(2^(k−1) × FailureBackoff, FailureBackoffMax) from it. failureTimes are the host's authz_failed and no_route
// spends since its newest register.
func (self *CertsCustomSettings) FailureWait(failureTimes []time.Time, now time.Time) time.Duration {
	if len(failureTimes) == 0 {
		return 0
	}
	last := slices.MaxFunc(failureTimes, func(a time.Time, b time.Time) int { return a.Compare(b) })
	backoff := self.FailureBackoffMax
	if shift := len(failureTimes) - 1; shift < 62 {
		if doubled := self.FailureBackoff << shift; 0 < doubled && doubled < backoff {
			backoff = doubled
		}
	}
	return max(0, last.Add(backoff).Sub(now))
}

// Where in its life a custom certificate is renewed (17.2.11): a point of its ARI window chosen by its id, so the
// renewals of devices certified together spread across the window as RFC 9773 asks, or RenewalLifetimeFraction into
// its validity when the CA gave no window.
func CertsCustomRenewTime(row *sidecar.TlsCertRecord, renewalLifetimeFraction float64) time.Time {
	if !row.AriWindowStart.IsZero() && row.AriWindowStart.Before(row.AriWindowEnd) {
		hash := sha256.Sum256(row.CertId.Bytes())
		span := uint64(row.AriWindowEnd.Sub(row.AriWindowStart))
		return row.AriWindowStart.Add(time.Duration(binary.BigEndian.Uint64(hash[:8]) % span))
	}
	lifetime := row.NotAfter.Sub(row.NotBefore)
	return row.NotBefore.Add(time.Duration(renewalLifetimeFraction * float64(lifetime)))
}

// What the custom branch of POST /tls/cert-order found of a CSR (17.2.5): its key's hashes, and its one name.
type CertsCustomCsr struct {
	Host                string
	SpkiSha256          [sha256.Size]byte
	IdentifierSetSha256 [sha256.Size]byte
}

// The custom host a CSR names, when it names exactly one dNSName under none of roots: the custom branch's test,
// taken before certs' own acceptance is reached. false for any other CSR, which certs' own branch judges.
func CertsCustomCsrHost(csrDer []byte, roots []string) (string, bool) {
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil || len(csr.DNSNames) != 1 {
		return "", false
	}
	if _, err := sidecar.TlsCustomIdentifierSet(csr.DNSNames[0], roots); err != nil {
		return "", false
	}
	return csr.DNSNames[0], true
}

// Checks a custom CSR and its attestation (17.2.5): a P-256 request, self-signed, with exactly one dNSName, the
// custom host, and no other name; the attestation verifying under identityPublicKey for the CSR's key and
// TlsIdentifierSetHash({host}). ErrCertsCsr or ErrCertsAttestation.
func CertsCheckCustomOrder(csrDer []byte, attestation []byte, host string, roots []string, identityPublicKey []byte, networkId sidecar.Id, sidecarId sidecar.Id) (*CertsCustomCsr, error) {
	set, err := sidecar.TlsCustomIdentifierSet(host, roots)
	if err != nil {
		return nil, fmt.Errorf("%w: not a custom host's name", ErrCertsCsr)
	}
	checked, err := certsCheckCsr(csrDer, set)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not parse", ErrCertsCsr)
	}
	if publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: its key is not P-256", ErrCertsCsr)
	}
	if _, err := sidecar.VerifyTlsKeyAttestation(attestation, identityPublicKey, networkId, sidecarId, checked.spkiSha256, checked.identifierSetSha256); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertsAttestation, err)
	}
	return &CertsCustomCsr{Host: host, SpkiSha256: checked.spkiSha256, IdentifierSetSha256: checked.identifierSetSha256}, nil
}

// One custom_issued row the sweep may renew.
type CertsCustomRenewal struct {
	Row *sidecar.TlsCertRecord
}

// What the sweep reads and writes: server's model over network_tls_cert, network_tls_account and
// network_tls_custom_spend. Safe for concurrent use.
type CertsCustomStore interface {
	// 17.2.4's removal moves for the rows of devices that are gone: their custom_issued rows, and custom_ordering
	// rows with an order recorded, to custom_revoking; the rest to failed. How many moved.
	MoveRemovedDevices(ctx context.Context, now time.Time) (int, error)
	// custom_issued rows with no successor whose device, host and domain are live, and no row of whose sidecar and
	// host ended failed after failedSince, by cert_id after afterCertId, at most count.
	ListCustomRenewalCandidates(ctx context.Context, failedSince time.Time, afterCertId sidecar.Id, count int) ([]*sidecar.TlsCertRecord, error)
	// Inserts a custom_queued successor of predecessorCertId with its CSR, attestation, sidecar, host and domain,
	// and links it, unless the predecessor has a successor already. Whether it queued.
	QueueCustomSuccessor(ctx context.Context, predecessorCertId sidecar.Id, successorCertId sidecar.Id, now time.Time) (bool, error)
	// custom_issued and custom_revoking rows past not_after go to expired. How many.
	ExpireCustomRows(ctx context.Context, now time.Time) (int, error)
	// Spends older than before go. How many.
	PurgeCustomSpends(ctx context.Context, before time.Time) (int, error)
	// 17.2.14's warnings at now, each at most once a host or account in settings' EventRepeatInterval. How many it
	// raised.
	RaiseCustomWarnings(ctx context.Context, now time.Time, settings *CertsCustomSettings) (int, error)
}

// What one sweep did.
type CertsCustomSweepReport struct {
	RemovedCount int
	QueuedCount  int
	ExpiredCount int
	PurgedCount  int
	WarnedCount  int
	// The candidates' cursor, zero once the scan wrapped.
	NextCertId sidecar.Id
}

// One sweep (17.2.11) from afterCertId's candidates: the removed devices' rows moved, expiry, spend retention, renewals queued as successor rows at
// their renew time, and the warnings. It makes no CA call. An error ends it with what it did.
func (self *CertsService) RunCustomSweep(ctx context.Context, store CertsCustomStore, settings *CertsCustomSettings, afterCertId sidecar.Id) (*CertsCustomSweepReport, error) {
	report := &CertsCustomSweepReport{}
	if store == nil {
		return report, errors.New("the custom sweep has no store")
	}
	if err := settings.Validate(); err != nil {
		return report, err
	}
	now := self.clock.Now()
	var err error
	if report.RemovedCount, err = store.MoveRemovedDevices(ctx, now); err != nil {
		return report, err
	}
	if report.ExpiredCount, err = store.ExpireCustomRows(ctx, now); err != nil {
		return report, err
	}
	if report.PurgedCount, err = store.PurgeCustomSpends(ctx, now.Add(-settings.SpendRetention)); err != nil {
		return report, err
	}
	candidates, err := store.ListCustomRenewalCandidates(ctx, now.Add(-settings.RequeueBackoff), afterCertId, settings.SweepBatchCount)
	if err != nil {
		return report, err
	}
	for _, row := range candidates {
		if now.Before(CertsCustomRenewTime(row, settings.RenewalLifetimeFraction)) {
			continue
		}
		queued, err := store.QueueCustomSuccessor(ctx, row.CertId, self.newCertId(), now)
		if err != nil {
			return report, err
		}
		if queued {
			report.QueuedCount += 1
		}
	}
	if len(candidates) == settings.SweepBatchCount {
		report.NextCertId = candidates[len(candidates)-1].CertId
	}
	if report.WarnedCount, err = store.RaiseCustomWarnings(ctx, now, settings); err != nil {
		return report, err
	}
	return report, nil
}
