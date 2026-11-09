// §13.8's fenced block for an order's DNS-01 challenges, as an acmez solver, so no CA validates a
// challenge before every edge serves it and the zone is known good (D-DNS-8; plan-TLS-canary-signal):
//
//	write    POST /dns/acme-challenge at serial s; 503 while a restore runs: try again, backing off
//	wait     GET /dns/ready?serial=s: ready, with CanaryClean, lets the CA validate; stale (final for
//	         s): write the same values again and wait on the new serial; canary_failing: wait, with
//	         no new write; waiting: ask again
//	clean    take the values out however the order ended, on a context of its own
//
// certs is the only writer of DNS-01 in URnetwork zones, and only through CertsDns (D-DNS-8). An
// identifier and its wildcard share _acme-challenge.<name>, so the solver keeps each name's values
// together: a write sends every value the name holds, at most two, and a removal waits until the last
// of them is done, so one cleanup never takes the other's value away mid-validation and costs no write
// of the 10 a name has an hour. A canary of unknown state reads as not clean. An authorization the CA
// still holds valid (LE's 7 h reuse) asks for nothing here, since acmez presents only for pending ones.
//
// Every wait is on the service's clock, so a test moves each. Safe for concurrent use; no lock is held
// across a DNS call.

package certsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	"github.com/urnetwork/sidecar"
)

var (
	// A /dns/* route answered 503 while a restore runs (§12.6): the call is tried again after a wait.
	// TLS-M5-16's client returns it for a 503.
	ErrCertsDnsRestoring = errors.New("dns is restoring")
	// POST /dns/acme-challenge refused the write, past its 10 per name per hour (D-DNS-8) or for a
	// suspended zone. Not tried again: the order fails, and its chain queues it again later.
	ErrCertsDnsWriteRefused = errors.New("dns refused the challenge write")
	// More than two values for one name, which no order of a set and its wildcard needs.
	errCertsDnsTooManyValues = errors.New("more than two challenge values for one name")
)

// GET /dns/ready's answer when its hold ended with a running NS still behind: ask again.
const CertsDnsWaiting CertsDnsReadiness = "waiting"

// The most TXT values one _acme-challenge name holds (§12.8).
const certsDnsMaxValueCount = 2

// One name's challenge values and the serial of their newest write.
type certsDnsChallenge struct {
	values []string
	serial uint64
	// rises at each write, so two waits that see one stale serial rewrite once
	generation uint64
}

// The solver. See the file header.
type CertsDnsSolver struct {
	dns      CertsDns
	settings *CertsSettings
	clock    sidecar.Clock

	stateLock sync.Mutex
	names     map[string]*certsDnsChallenge
}

var (
	_ acmez.Solver = (*CertsDnsSolver)(nil)
	_ acmez.Waiter = (*CertsDnsSolver)(nil)
)

// A solver writing through dns, on clock; nil is real time.
func NewCertsDnsSolver(dns CertsDns, settings *CertsSettings, clock sidecar.Clock) *CertsDnsSolver {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &CertsDnsSolver{dns: dns, settings: settings, clock: clock, names: map[string]*certsDnsChallenge{}}
}

// The name whose _acme-challenge label a challenge writes: its identifier, a wildcard's base included.
func certsChallengeName(challenge acme.Challenge) string {
	return strings.TrimPrefix(strings.ToLower(challenge.Identifier.Value), "*.")
}

// Waits timeout on the solver's clock, or until ctx ends.
func (self *CertsDnsSolver) wait(ctx context.Context, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-self.clock.After(timeout):
		return nil
	}
}

// Writes values at name, trying again while a restore runs, backing off from DnsRetryDelay to
// DnsRetryMaxDelay, and answers the serial they were committed at.
func (self *CertsDnsSolver) write(ctx context.Context, name string, values []string) (uint64, error) {
	delay := self.settings.DnsRetryDelay
	for {
		testHookBarrier("certs.dns_write.before", "")
		serial, err := self.dns.WriteAcmeChallenge(ctx, name, values)
		testHookBarrier("certs.dns_write.after", "")
		if !errors.Is(err, ErrCertsDnsRestoring) {
			return serial, err
		}
		if err := self.wait(ctx, delay); err != nil {
			return 0, err
		}
		delay = min(2*delay, self.settings.DnsRetryMaxDelay)
	}
}

// Writes the challenge's value at its name beside any value the name holds already. See acmez.Solver.
func (self *CertsDnsSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	name := certsChallengeName(challenge)
	value := challenge.DNS01KeyAuthorization()
	values, err := func() ([]string, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.names[name]
		if !ok {
			entry = &certsDnsChallenge{}
			self.names[name] = entry
		}
		if !slices.Contains(entry.values, value) {
			if certsDnsMaxValueCount <= len(entry.values) {
				return nil, errCertsDnsTooManyValues
			}
			entry.values = append(entry.values, value)
		}
		return slices.Clone(entry.values), nil
	}()
	if err != nil {
		return err
	}
	serial, err := self.write(ctx, name, values)
	if err != nil {
		return fmt.Errorf("writing the challenge: %w", err)
	}
	self.wrote(name, serial)
	return nil
}

// Records a write at name, unless a newer write landed first.
func (self *CertsDnsSolver) wrote(name string, serial uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.names[name]
	if !ok {
		return
	}
	if serial < entry.serial {
		return
	}
	entry.serial = serial
	entry.generation += 1
}

// The name's newest serial and generation, and false once the name holds nothing.
func (self *CertsDnsSolver) current(name string) (serial uint64, generation uint64, values []string, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.names[name]
	if !ok || len(entry.values) == 0 {
		return 0, 0, nil, false
	}
	return entry.serial, entry.generation, slices.Clone(entry.values), true
}

// Blocks until every edge serves the challenge's newest serial and the canary is clean, writing again
// on stale. See acmez.Waiter.
func (self *CertsDnsSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	name := certsChallengeName(challenge)
	for {
		serial, generation, values, ok := self.current(name)
		if !ok {
			return errors.New("the challenge was never written")
		}
		readiness, err := self.dns.Ready(ctx, serial)
		switch {
		case err != nil:
			// a 503 or a lost answer: ask again after a wait, as the route's caller does
			if err := self.wait(ctx, self.settings.DnsRetryDelay); err != nil {
				return err
			}
		case readiness == CertsDnsStale:
			// final for this serial: the restored edges may lack the value, so write it again,
			// once for every wait that saw this serial go stale
			_, nowGeneration, _, ok := self.current(name)
			if !ok {
				return errors.New("the challenge was removed while waiting")
			}
			if nowGeneration == generation {
				newSerial, err := self.write(ctx, name, values)
				if err != nil {
					return fmt.Errorf("writing the challenge again: %w", err)
				}
				self.wrote(name, newSerial)
			}
		case readiness == CertsDnsReady:
			clean, err := self.dns.CanaryClean(ctx, serial)
			if err == nil && clean {
				return nil
			}
			// unknown reads as not clean (plan-TLS-canary-signal)
			if err := self.wait(ctx, self.settings.CanaryRetryDelay); err != nil {
				return err
			}
		case readiness == CertsDnsCanaryFailing:
			// no new write and no new serial: the zone is not known good
			if err := self.wait(ctx, self.settings.CanaryRetryDelay); err != nil {
				return err
			}
		default:
			// waiting, or an answer this build does not know: ask again
			if err := self.wait(ctx, self.settings.DnsWaitingDelay); err != nil {
				return err
			}
		}
	}
}

// Takes the challenge's value out of its name, and the name out of the zone once it holds no other, on
// a context of its own bounded by DnsCleanupTimeout, since the order's may have ended. See
// acmez.Solver.
func (self *CertsDnsSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	name := certsChallengeName(challenge)
	value := challenge.DNS01KeyAuthorization()
	empty := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.names[name]
		if !ok {
			return false
		}
		entry.values = slices.DeleteFunc(entry.values, func(held string) bool { return held == value })
		if len(entry.values) == 0 {
			delete(self.names, name)
			return true
		}
		return false
	}()
	if !empty {
		return nil
	}
	cleanupCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.DnsCleanupTimeout, cancel)
	defer stop()
	delay := self.settings.DnsRetryDelay
	for {
		err := self.dns.RemoveAcmeChallenge(cleanupCtx, name)
		if !errors.Is(err, ErrCertsDnsRestoring) {
			return err
		}
		if err := self.wait(cleanupCtx, delay); err != nil {
			return err
		}
		delay = min(2*delay, self.settings.DnsRetryMaxDelay)
	}
}
