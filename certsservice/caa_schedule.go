// certs' CAA checks of strong-mode custom hosts (§12.8 step 3, §13.8; D-DNS-9, D-TLS-11, FS-32; TLS-M6-04): a walk
// (sidecar.TlsCaaWalk) and then §12.8's probe (caa_probe.go), each host's verdict applied through
// model.DnsCustomHostResultInTx, which DNS-M6-02 declared for this caller:
//
//   - at setup, every pending strong-mode host, pending and unmapped until a pass makes it active; a walk that meets
//     a URnetwork zone or a failed probe refuses it with custom_host_caa_operator_alias;
//   - again once its newest registered chain has lived RecheckLifetimeFraction of its life (§13.8: half, before the
//     ordering desktops renew at two thirds); a failure clears effective_caa_chain_ok and records §2.8 EX1's exception
//     in an admin event that alarms the network's admins, the host staying mapped, and a pass sets the flag again.
//
// A weak-mode host is never checked: its setup disclosed EX1 instead (DNS-M6-02). The store lists strong-mode hosts
// only, and a host withheld by a downgrade is neither listed nor judged (QD-840).
//
// A walk that ends in a resolver's error and a probe with no verdict judge nothing. A pending host is listed again
// at the next pass; a due one waits in the cursor's retries, at most RetryMaxCount of them and RetryMaxTryCount tries
// each, after which its next chain's check is the next one it gets. The due scan reads windows of recheck times,
// (DueSince, DueUntil], so a host is due once a chain without a column of its own; the first scan's window is open
// below.
//
// One probe a target at a time (§12.8): a pass runs the hosts of one owner one after another, and the taskworker
// chain runs one pass at a time. Different owners' probes run side by side, at most ProbeConcurrency. A pass ends
// only when every probe it started has ended and deleted its canary.

package certsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// What the store did with a verdict: model.DnsCustomHostResultInTx's outcomes.
type CertsCaaOutcome string

const (
	// A pending host passed and went active.
	CertsCaaOutcomeActivated CertsCaaOutcome = "activated"
	// A pending host failed and was refused, its row removed.
	CertsCaaOutcomeRefused CertsCaaOutcome = "refused"
	// An active host passed.
	CertsCaaOutcomeChecked CertsCaaOutcome = "checked"
	// An active host failed: still mapped, exposed as a weak-mode host is, and its admins alarmed.
	CertsCaaOutcomeExposed CertsCaaOutcome = "exposed"
	// No row to judge: the host was removed, withheld, or is not strong-mode, since the check began.
	CertsCaaOutcomeGone CertsCaaOutcome = "gone"
)

// One strong-mode custom host to check.
type CertsCaaHost struct {
	// The customer's name, lowercase with no final dot.
	Host string
	// The host owner it maps to, <host>.<net>.<root>, where its canary goes: never a network's, alias's or scope's @.
	Owner     string
	NetworkId sidecar.Id
	// At setup: pending and unmapped. Else active, at its chain's recheck.
	Pending bool
}

// The custom hosts the checks read, and where their verdicts go: server's model over network_dns_custom_host and
// network_tls_cert. Safe for concurrent use.
type CertsCaaStore interface {
	// Pending strong-mode hosts in host order after afterHost, at most count.
	ListCaaPending(ctx context.Context, afterHost string, count int) ([]*CertsCaaHost, error)
	// Active strong-mode hosts whose newest registered chain reached lifetimeFraction of its validity in
	// (since, until], in host order after afterHost, at most count. A zero since is open below.
	ListCaaDue(ctx context.Context, lifetimeFraction float64, since time.Time, until time.Time, afterHost string, count int) ([]*CertsCaaHost, error)
	// The host as it stands, nil when it is no longer one the checks judge.
	GetCaaHost(ctx context.Context, host string) (*CertsCaaHost, error)
	// Applies a verdict in one transaction: model.DnsCustomHostResultInTx. CertsCaaOutcomeGone for a host no row
	// holds to judge.
	ApplyCaaVerdict(ctx context.Context, host string, pass bool) (CertsCaaOutcome, error)
}

// The checks' tunables. DefaultCertsCaaSettings is the only source of a default.
type CertsCaaSettings struct {
	// The zones URnetwork controls, each <root> and platform domain, which no walk may meet. No default: production
	// names, which the host sets; no zones refuses every check.
	OperatorZones []string
	// The walk's limits.
	Walk *sidecar.TlsCaaWalkSettings
	// §12.8's window: the queries every ProbeInterval for ProbeWindow, 30 s for 10 min, ten times the 60 s negative
	// TTL. Positive.
	ProbeInterval time.Duration
	ProbeWindow   time.Duration
	// A probe still without a verdict this long after it began has none: past the window, a stale or two, and the
	// waits on dns. Above ProbeWindow.
	ProbeTimeout time.Duration
	// Probes one pass runs at once, one an owner. Positive.
	ProbeConcurrency int
	// Pending and due hosts one pass reads at most, each. Positive.
	PendingBatchCount int
	DueBatchCount     int
	// Due hosts with no verdict carried to later passes at most, and the passes each is tried in. Positive.
	RetryMaxCount    int
	RetryMaxTryCount int
	// How far into its newest registered chain's validity an active host is checked again (§13.8: half, before the
	// desktops renew at two thirds). Between 0 and 1.
	RecheckLifetimeFraction float64
}

func DefaultCertsCaaSettings() *CertsCaaSettings {
	return &CertsCaaSettings{
		Walk:                    sidecar.DefaultTlsCaaWalkSettings(),
		ProbeInterval:           30 * time.Second,
		ProbeWindow:             10 * time.Minute,
		ProbeTimeout:            30 * time.Minute,
		ProbeConcurrency:        8,
		PendingBatchCount:       32,
		DueBatchCount:           32,
		RetryMaxCount:           64,
		RetryMaxTryCount:        6,
		RecheckLifetimeFraction: 0.5,
	}
}

// A settings value the checks cannot run on. The wrapping error names the field.
var ErrCertsCaaSettingsRefused = errors.New("certs caa settings refused")

func (self *CertsCaaSettings) Validate() error {
	if self == nil || self.Walk == nil {
		return fmt.Errorf("%w: no settings", ErrCertsCaaSettingsRefused)
	}
	if len(self.OperatorZones) == 0 {
		return fmt.Errorf("%w: OperatorZones is empty", ErrCertsCaaSettingsRefused)
	}
	for name, value := range map[string]int64{
		"ProbeInterval":                 int64(self.ProbeInterval),
		"ProbeWindow":                   int64(self.ProbeWindow),
		"ProbeConcurrency":              int64(self.ProbeConcurrency),
		"PendingBatchCount":             int64(self.PendingBatchCount),
		"DueBatchCount":                 int64(self.DueBatchCount),
		"RetryMaxCount":                 int64(self.RetryMaxCount),
		"RetryMaxTryCount":              int64(self.RetryMaxTryCount),
		"Walk.HopMaxCount":              int64(self.Walk.HopMaxCount),
		"Walk.NameserverMaxCount":       int64(self.Walk.NameserverMaxCount),
		"Walk.RecordMaxCount":           int64(self.Walk.RecordMaxCount),
		"ProbeTimeout less ProbeWindow": int64(self.ProbeTimeout - self.ProbeWindow),
	} {
		if value <= 0 {
			return fmt.Errorf("%w: %s is not positive", ErrCertsCaaSettingsRefused, name)
		}
	}
	if !(0 < self.RecheckLifetimeFraction && self.RecheckLifetimeFraction < 1) {
		return fmt.Errorf("%w: RecheckLifetimeFraction is not between 0 and 1", ErrCertsCaaSettingsRefused)
	}
	return nil
}

// What the checks run on, which taskworker installs (work.SetTlsCaaChecks).
type CertsCaaDeps struct {
	Resolver CertsCaaResolver
	Dns      CertsCaaCanaryDns
	Store    CertsCaaStore
	Settings *CertsCaaSettings
}

// A due host with no verdict, carried to the next pass.
type CertsCaaRetry struct {
	Host string `json:"host"`
	// Passes it was tried in.
	TryCount int `json:"try_count"`
}

// Where the next pass starts, as the chain's args carry it.
type CertsCaaCursor struct {
	// The pending scan, after this host. Empty: from the start.
	AfterPendingHost string `json:"after_pending_host,omitempty"`
	// The due scan's window of recheck times, (DueSince, DueUntil], after AfterDueHost. A zero DueUntil starts the
	// next window, ending at the pass's now.
	DueSince     time.Time        `json:"due_since,omitzero"`
	DueUntil     time.Time        `json:"due_until,omitzero"`
	AfterDueHost string           `json:"after_due_host,omitempty"`
	Retries      []*CertsCaaRetry `json:"retries,omitempty"`
}

// One host's verdict.
type CertsCaaVerdict struct {
	Host    string
	Pending bool
	Pass    bool
	// Why it failed: a CertsCaaReason.
	Reason  string
	Outcome CertsCaaOutcome
}

// What one pass did.
type CertsCaaReport struct {
	Verdicts []*CertsCaaVerdict
	// Hosts checked to no verdict.
	InconclusiveCount int
	// Due hosts dropped from the retries after their last try.
	DroppedCount int
	Next         *CertsCaaCursor
	// More waits: a batch came back full.
	More bool
}

// One host's walk and probe, judged: a verdict, or an error when there is none (see the file header).
func (self *CertsService) checkCaaHost(ctx context.Context, deps *CertsCaaDeps, host *CertsCaaHost) (*CertsCaaVerdict, error) {
	verdict := &CertsCaaVerdict{Host: host.Host, Pending: host.Pending}
	fail := func(reason string) (*CertsCaaVerdict, error) {
		verdict.Reason = reason
		return verdict, nil
	}
	// the canary goes only at a host owner under a URnetwork zone, which the walk never reaches
	ownerInOperatorZone := slices.ContainsFunc(deps.Settings.OperatorZones, func(zone string) bool {
		zone = strings.ToLower(strings.TrimSuffix(zone, "."))
		return strings.HasSuffix(host.Owner, "."+zone)
	})
	if !ownerInOperatorZone {
		return nil, fmt.Errorf("%w: the host owner is under no URnetwork zone", ErrCertsCaaInconclusive)
	}
	walk, err := sidecar.TlsCaaWalk(ctx, deps.Resolver, host.Host, deps.Settings.OperatorZones, deps.Settings.Walk)
	switch {
	case errors.Is(err, sidecar.ErrTlsCaaOperatorAlias):
		return fail(CertsCaaReasonOperatorAlias)
	case err != nil:
		return nil, fmt.Errorf("%w: the walk: %w", ErrCertsCaaInconclusive, err)
	case len(walk.Effective) == 0:
		return fail(CertsCaaReasonNoPin)
	case walk.HoldsCanary():
		// a canary already in the customer's own set was flattened into it
		return fail(CertsCaaReasonNonce)
	}
	pass, reason, err := self.probeCaa(ctx, deps, host.Owner, walk)
	if err != nil {
		return nil, err
	}
	if !pass {
		return fail(reason)
	}
	verdict.Pass = true
	return verdict, nil
}

// One pass of the checks from cursor (nil: the start): pending hosts, retried due hosts and due hosts, each
// walked, probed and judged. See the file header. An error from the store ends the pass with what it did, and the
// cursor it answers takes the next pass on from there.
func (self *CertsService) RunCaaChecks(ctx context.Context, deps *CertsCaaDeps, cursor *CertsCaaCursor) (*CertsCaaReport, error) {
	if cursor == nil {
		cursor = &CertsCaaCursor{}
	}
	next := *cursor
	next.Retries = nil
	report := &CertsCaaReport{Next: &next}
	if deps == nil || deps.Resolver == nil || deps.Dns == nil || deps.Store == nil {
		// nothing installed: no host is judged, and the cursor stays
		report.Next = cursor
		return report, errors.New("the caa checks have no resolver, dns client or store")
	}
	if err := deps.Settings.Validate(); err != nil {
		report.Next = cursor
		return report, err
	}
	settings := deps.Settings
	now := self.clock.Now()

	// the pending scan's batch
	pending, err := deps.Store.ListCaaPending(ctx, cursor.AfterPendingHost, settings.PendingBatchCount)
	if err != nil {
		report.Next = cursor
		return report, err
	}
	if len(pending) < settings.PendingBatchCount {
		next.AfterPendingHost = ""
	} else {
		next.AfterPendingHost = pending[len(pending)-1].Host
		report.More = true
	}

	// the retries, as their hosts stand now
	retryTryCounts := map[string]int{}
	retried := []*CertsCaaHost{}
	for _, retry := range cursor.Retries {
		host, err := deps.Store.GetCaaHost(ctx, retry.Host)
		if err != nil {
			report.Next = cursor
			return report, err
		}
		// a host since removed, refused or made pending needs no retry here
		if host != nil && !host.Pending {
			retried = append(retried, host)
			retryTryCounts[host.Host] = retry.TryCount
		}
	}

	// the due scan's batch, in the window (DueSince, DueUntil]
	if next.DueUntil.IsZero() {
		next.DueUntil = now
		next.AfterDueHost = ""
	}
	due, err := deps.Store.ListCaaDue(ctx, settings.RecheckLifetimeFraction, next.DueSince, next.DueUntil, next.AfterDueHost, settings.DueBatchCount)
	if err != nil {
		report.Next = cursor
		return report, err
	}
	if len(due) < settings.DueBatchCount {
		// the window is done: the next pass reads the one after it
		next.DueSince = next.DueUntil
		next.DueUntil = time.Time{}
		next.AfterDueHost = ""
	} else {
		next.AfterDueHost = due[len(due)-1].Host
		report.More = true
	}

	// each host once, by owner, the hosts of one owner one after another (one probe a target at a time)
	ownerHosts := map[string][]*CertsCaaHost{}
	owners := []string{}
	seen := map[string]bool{}
	for _, host := range slices.Concat(pending, retried, due) {
		if seen[host.Host] {
			continue
		}
		seen[host.Host] = true
		if _, ok := ownerHosts[host.Owner]; !ok {
			owners = append(owners, host.Owner)
		}
		ownerHosts[host.Owner] = append(ownerHosts[host.Owner], host)
	}

	var stateLock sync.Mutex
	var storeErr error
	slots := make(chan struct{}, settings.ProbeConcurrency)
	var waitGroup sync.WaitGroup
	for _, owner := range owners {
		hosts := ownerHosts[owner]
		waitGroup.Add(1)
		slots <- struct{}{}
		go func() {
			defer waitGroup.Done()
			defer func() { <-slots }()
			for _, host := range hosts {
				verdict, err := self.checkCaaHost(ctx, deps, host)
				if err == nil {
					verdict.Outcome, err = deps.Store.ApplyCaaVerdict(ctx, host.Host, verdict.Pass)
					if err != nil {
						func() {
							stateLock.Lock()
							defer stateLock.Unlock()
							storeErr = errors.Join(storeErr, err)
						}()
					}
				}
				func() {
					stateLock.Lock()
					defer stateLock.Unlock()
					if err == nil {
						report.Verdicts = append(report.Verdicts, verdict)
						return
					}
					report.InconclusiveCount += 1
					// a pending host is listed again; a due one is carried, a try at a time
					if host.Pending {
						return
					}
					tryCount := retryTryCounts[host.Host] + 1
					if settings.RetryMaxTryCount <= tryCount || settings.RetryMaxCount <= len(next.Retries) {
						report.DroppedCount += 1
						return
					}
					next.Retries = append(next.Retries, &CertsCaaRetry{Host: host.Host, TryCount: tryCount})
				}()
			}
		}()
	}
	waitGroup.Wait()
	slices.SortFunc(report.Verdicts, func(a *CertsCaaVerdict, b *CertsCaaVerdict) int { return strings.Compare(a.Host, b.Host) })
	// a retry waits a whole interval, so a host whose servers are down is not asked again at once
	slices.SortFunc(next.Retries, func(a *CertsCaaRetry, b *CertsCaaRetry) int { return strings.Compare(a.Host, b.Host) })
	return report, storeErr
}
