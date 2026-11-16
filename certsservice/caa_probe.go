// §12.8's CAA probe for a strong-mode custom host (D-DNS-9, D-TLS-11, FS-32, FI-11; TLS-M6-04), certs' half that no
// walk can do: only a canary shows a customer-side ALIAS that also flattens CAA, since a flattened set looks like
// the customer's own.
//
//	publish  POST /dns/caa-canary at the host owner <host>.<net>.<root>, the ALIAS target: the walk's effective set
//	         (the customer's pin) plus 0 urcanary "<128-bit nonce>", TTL 60, at serial s; then /dns/ready?serial=s
//	query    the walk's CAA queries again, at the authoritative servers of each zone it visited, RD=0, every
//	         ProbeInterval for ProbeWindow (30 s for 10 min, ten times the 60 s negative TTL)
//	verdict  any nonce of this probe's in any answer, or a canary the lint refuses (a CNAME at the owner): fail;
//	         else pass, once /dns/ready?serial=s still answers ready after the last query
//	stale    at either ready, a restore whose edges may lack the canary: publish again under a new nonce, naming
//	         the canary it replaces, and start the window again
//	delete   the canary and its copy in one write, whatever the verdict, on a context of its own
//
// canary_failing reads as ready at both checks, since §13.8 ties §12.6's canary to orders, and the probe's RD=0
// queries validate no DNSSEC (plan-TLS-canary-signal). A nonce stays in the probe's list after a republish, since a
// flattening provider may still serve the set it cached. Every server a query names must answer at least once in the
// window; one that never does leaves the probe with no verdict, as does a dns route that cannot be reached, a busy
// owner (another probe's canary stands there), or a probe past ProbeTimeout. No verdict is never a pass: a pending
// host stays pending and unmapped, an active one keeps its standing.
//
// Every wait is on the service's clock, so a test moves each. Nothing here names a host in a log (I-13).

package certsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

var (
	// POST /dns/caa-canary's 409 lint_refused: the zone lint refused the canary, a CNAME at the owner, which is the
	// probe's failing verdict itself.
	ErrCertsCaaCanaryLint = errors.New("dns refused the caa canary by its lint")
	// POST /dns/caa-canary's 409 busy: another probe's canary stands at the owner.
	ErrCertsCaaCanaryBusy = errors.New("another caa canary stands at the owner")
	// POST /dns/caa-canary's 400: an owner no strong-mode custom host maps to, or a set no canary may hold.
	ErrCertsCaaCanaryRefused = errors.New("dns refused the caa canary")
	// The probe reached no verdict: see the file header.
	ErrCertsCaaInconclusive = errors.New("the caa probe reached no verdict")
)

// Why a host's check failed.
const (
	// The walk met a name in a URnetwork zone (§12.8 step 3).
	CertsCaaReasonOperatorAlias = sidecar.TlsCaaRefusalOperatorAlias
	// The walk found no set, so no pin keeps URnetwork out and no canary can carry one.
	CertsCaaReasonNoPin = "no_pin"
	// A canary's nonce, or §12.8's canary tag, in the customer's answers: an ALIAS that flattens CAA.
	CertsCaaReasonNonce = "nonce"
	// The zone lint refused the canary: a CNAME at the owner.
	CertsCaaReasonLint = "lint_refused"
	// dns refused the canary, so the set cannot be probed.
	CertsCaaReasonCanaryRefused = "canary_refused"
)

// §12.8's canary routes as the probe drives them: TLS-M6-04's server.CertsDnsClient on the dns api, with the
// internal-certs bearer (plan-TLS-internal-credentials). Safe for concurrent use.
type CertsCaaCanaryDns interface {
	// POST /dns/caa-canary: owner's CAA becomes caa plus a fresh nonce's canary, at the serial answered with the
	// nonce. replaces names the nonce of the canary this one replaces after a stale, "" for a first publish.
	// ErrCertsCaaCanaryLint, ErrCertsCaaCanaryBusy, ErrCertsCaaCanaryRefused, or ErrCertsDnsRestoring for a 503.
	PublishCaaCanary(ctx context.Context, owner string, caa []string, replaces string) (serial uint64, nonce string, err error)
	// The same route's delete: the canary and its copy go in one write. A canary already gone is no error.
	DeleteCaaCanary(ctx context.Context, owner string) (serial uint64, err error)
	// GET /dns/ready?serial=s.
	Ready(ctx context.Context, serial uint64) (CertsDnsReadiness, error)
}

// The resolver certs walks and probes with: server.NewCertsCaaResolver. Safe for concurrent use.
type CertsCaaResolver interface {
	sidecar.TlsCaaResolver
	// A CAA query for name, RD=0, at each of nameservers, a zone's authoritative servers by name: the CAA records of
	// each answer, presentation form, keyed by the nameserver that gave it. A server that did not answer is absent.
	// An error only when none answered.
	AuthoritativeCaa(ctx context.Context, name string, nameservers []string) (map[string][]string, error)
}

// Waits timeout on the service's clock, or until ctx ends.
func (self *CertsService) caaWait(ctx context.Context, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-self.clock.After(timeout):
		return nil
	}
}

// One probe of owner for walk's set. See the file header: pass, or the failing reason, with nil; or an error when
// it reached no verdict.
func (self *CertsService) probeCaa(ctx context.Context, deps *CertsCaaDeps, owner string, walk *sidecar.TlsCaaResult) (bool, string, error) {
	settings := deps.Settings
	start := self.clock.Now()
	overdue := func() bool {
		return settings.ProbeTimeout <= self.clock.Now().Sub(start)
	}
	inconclusive := func(format string, arguments ...any) (bool, string, error) {
		return false, "", fmt.Errorf("%w: %s", ErrCertsCaaInconclusive, fmt.Sprintf(format, arguments...))
	}

	nonces := []string{}
	var serial uint64
	// publishes, trying again while a restore runs, backing off from DnsRetryDelay to DnsRetryMaxDelay
	publish := func(replaces string) error {
		delay := self.settings.DnsRetryDelay
		for {
			testHookBarrier("certs.caa_canary.publish.before", "")
			publishedSerial, nonce, err := deps.Dns.PublishCaaCanary(ctx, owner, walk.Effective, replaces)
			testHookBarrier("certs.caa_canary.publish.after", "")
			if err == nil {
				if publishedSerial == 0 || nonce == "" {
					return errors.New("a canary publish answered no serial or no nonce")
				}
				serial = publishedSerial
				nonces = append(nonces, nonce)
				return nil
			}
			if !errors.Is(err, ErrCertsDnsRestoring) || overdue() {
				return err
			}
			if err := self.caaWait(ctx, delay); err != nil {
				return err
			}
			delay = min(2*delay, self.settings.DnsRetryMaxDelay)
		}
	}
	err := publish("")
	switch {
	case errors.Is(err, ErrCertsCaaCanaryLint):
		return false, CertsCaaReasonLint, nil
	case errors.Is(err, ErrCertsCaaCanaryRefused):
		return false, CertsCaaReasonCanaryRefused, nil
	case err != nil:
		return inconclusive("publishing the canary: %v", err)
	}
	// the canary and its copy go whatever the verdict, even once ctx has ended
	defer self.deleteCaaCanary(context.WithoutCancel(ctx), deps, owner)

	// waits until dns answers for serial: true for stale, false for ready or canary_failing
	waitReady := func() (bool, error) {
		for {
			if overdue() {
				return false, errors.New("past the probe's timeout waiting on dns")
			}
			readiness, err := deps.Dns.Ready(ctx, serial)
			switch {
			case err != nil:
				if err := self.caaWait(ctx, self.settings.DnsRetryDelay); err != nil {
					return false, err
				}
			case readiness == CertsDnsStale:
				return true, nil
			case readiness == CertsDnsReady, readiness == CertsDnsCanaryFailing:
				return false, nil
			default:
				// waiting, or an answer this build does not know
				if err := self.caaWait(ctx, self.settings.DnsWaitingDelay); err != nil {
					return false, err
				}
			}
		}
	}
	// whether any answer holds a nonce of this probe's, or the canary's tag with any value
	flattened := func(answers map[string][]string) bool {
		for _, records := range answers {
			for _, text := range records {
				record, err := sidecar.ParseTlsCaaRecord(text)
				if err != nil {
					// a record that does not parse is no canary of ours
					continue
				}
				if strings.EqualFold(record.Tag, sidecar.TlsCaaCanaryTag) {
					return true
				}
				if slices.Contains(nonces, record.Value) {
					return true
				}
			}
		}
		return false
	}
	queries := walk.Queries()
	for {
		stale, err := waitReady()
		if err != nil {
			return inconclusive("waiting for the canary's serial: %v", err)
		}
		if stale {
			if err := publish(nonces[len(nonces)-1]); err != nil {
				return inconclusive("publishing the canary again: %v", err)
			}
			continue
		}
		// every server of every query must answer at least once inside the window
		unheard := map[string]bool{}
		for _, query := range queries {
			for _, nameserver := range query.Nameservers {
				unheard[query.Name+" "+nameserver] = true
			}
		}
		windowStart := self.clock.Now()
		for {
			for _, query := range queries {
				answers, err := deps.Resolver.AuthoritativeCaa(ctx, query.Name, query.Nameservers)
				if err != nil {
					if ctx.Err() != nil {
						return inconclusive("querying: %v", ctx.Err())
					}
					continue
				}
				if flattened(answers) {
					return false, CertsCaaReasonNonce, nil
				}
				for nameserver := range answers {
					delete(unheard, query.Name+" "+nameserver)
				}
			}
			if settings.ProbeWindow <= self.clock.Now().Sub(windowStart) {
				break
			}
			if overdue() {
				return inconclusive("past the probe's timeout inside its window")
			}
			if err := self.caaWait(ctx, settings.ProbeInterval); err != nil {
				return inconclusive("waiting inside the window: %v", err)
			}
		}
		if 0 < len(unheard) {
			return inconclusive("%d of the zones' servers never answered", len(unheard))
		}
		// a pass counts only while the serial still stands: a restore may have dropped the canary mid-window
		stale, err = waitReady()
		if err != nil {
			return inconclusive("waiting for the canary's serial after the window: %v", err)
		}
		if stale {
			if err := publish(nonces[len(nonces)-1]); err != nil {
				return inconclusive("publishing the canary again: %v", err)
			}
			continue
		}
		return true, "", nil
	}
}

// Deletes owner's canary, trying again while a restore runs until DnsCleanupTimeout has passed on the service's
// clock. A canary left behind expires an hour after its write, when taskworker's chain removes it (§12.8).
func (self *CertsService) deleteCaaCanary(ctx context.Context, deps *CertsCaaDeps, owner string) {
	start := self.clock.Now()
	delay := self.settings.DnsRetryDelay
	for {
		testHookBarrier("certs.caa_canary.delete.before", "")
		_, err := deps.Dns.DeleteCaaCanary(ctx, owner)
		testHookBarrier("certs.caa_canary.delete.after", "")
		if !errors.Is(err, ErrCertsDnsRestoring) || self.settings.DnsCleanupTimeout <= self.clock.Now().Sub(start) {
			return
		}
		if err := self.caaWait(ctx, delay); err != nil {
			return
		}
		delay = min(2*delay, self.settings.DnsRetryMaxDelay)
	}
}
