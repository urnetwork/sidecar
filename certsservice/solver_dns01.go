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
// together: a write sends every value the name holds, at most DnsChallengeValueMaxCount, and a removal
// waits until the last of them is done, so one cleanup never takes the other's value away mid-validation
// and costs no write of the 10 a name has an hour. A canary of unknown state reads as not clean. An
// authorization the CA still holds valid (LE's 7 h reuse) asks for nothing here, since acmez presents
// only for pending ones.
//
// An order writes its name once (QD-1189). Present only adds its value to the name's, and a Wait on the
// name writes every value the name holds when one of them is not in the newest write, so a set's name
// and its wildcard, which acmez presents one after the other before it waits on either, take one of the
// name's ten writes an hour, not two. A value added after a write read the values is owed another, which
// the next Wait on the name makes, and a stale serial owes the same values again. One write at a time
// goes to a name, and a Wait that finds one under way waits for it, so two waits never write the same
// values twice. A write retried through a restore sends the values the name holds by then. A name no
// write was ever sent to is not removed.
//
// The write is thus Wait's, where acmez's Waiter doc would have Present make it. That rests on acmez
// calling a Waiter's Wait before it asks the CA to validate the challenge, which acmez v3's Client,
// pinned in go.mod, does for every pending authorization, and certs' only ACME client is that one
// (acme.go). An order on Pebble (acme_test.go, queue_test.go) issues only if the write came. It also
// keeps Present quick, as acmez's Solver doc asks, with a write's waits through a restore in Wait.
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
	// More values for one name than it holds (DnsChallengeValueMaxCount), which no order of a set and its
	// wildcard needs.
	errCertsDnsTooManyValues = errors.New("more challenge values for one name than it holds")
	// A wait for a value no Present added, or one a cleanup took out.
	errCertsDnsNotPresented = errors.New("the challenge is not presented")
)

// GET /dns/ready's answer when its hold ended with a running NS still behind: ask again.
const CertsDnsWaiting CertsDnsReadiness = "waiting"

// One name's challenge values, the serial of their newest write, and the write they are owed.
type certsDnsChallenge struct {
	values []string
	// what the newest write read; a value outside them, or nil, owes the name a write of them all
	writtenValues []string
	// closed when the write under way ends; nil while none is
	writing chan struct{}
	// a write was sent, so the cleanup that empties the name takes it out of the zone
	sent   bool
	serial uint64
	// rises at each write, so two waits that see one stale serial rewrite once
	generation uint64
}

// Whether a value is not in the newest write.
func (self *certsDnsChallenge) owedWithLock() bool {
	for _, value := range self.values {
		if !slices.Contains(self.writtenValues, value) {
			return true
		}
	}
	return false
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

// The name whose _acme-challenge label a DNS name's challenge writes: the name, a wildcard's base
// included. Admission holds the same names (queue.go).
func certsChallengeNameOf(dnsName string) string {
	return strings.TrimPrefix(strings.ToLower(dnsName), "*.")
}

// The name whose _acme-challenge label a challenge writes: its identifier's.
func certsChallengeName(challenge acme.Challenge) string {
	return certsChallengeNameOf(challenge.Identifier.Value)
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

// Writes entry's values at name, reading them anew at each try, trying again while a restore runs,
// backing off from DnsRetryDelay to DnsRetryMaxDelay, and answers the serial they were committed at.
// The caller holds entry's write.
func (self *CertsDnsSolver) write(ctx context.Context, name string, entry *certsDnsChallenge) (uint64, error) {
	delay := self.settings.DnsRetryDelay
	for {
		values := func() []string {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			entry.writtenValues = slices.Clone(entry.values)
			return slices.Clone(entry.values)
		}()
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

// Adds the challenge's value to its name's, beside any value the name holds already, owing the name a
// write, which the next Wait on it makes. See acmez.Solver.
func (self *CertsDnsSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	name := certsChallengeName(challenge)
	value := challenge.DNS01KeyAuthorization()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.names[name]
	if !ok {
		entry = &certsDnsChallenge{}
		self.names[name] = entry
	}
	if slices.Contains(entry.values, value) {
		return nil
	}
	if self.settings.DnsChallengeValueMaxCount <= len(entry.values) {
		return errCertsDnsTooManyValues
	}
	entry.values = append(entry.values, value)
	return nil
}

// Returns once a write holding value has committed at name: makes the write the name is owed, of every
// value it holds, or waits for the write under way there and looks again.
func (self *CertsDnsSolver) writeOwed(ctx context.Context, name string, value string) error {
	for {
		var entry *certsDnsChallenge
		var writing chan struct{}
		writer := false
		err := func() error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			var ok bool
			entry, ok = self.names[name]
			if !ok || !slices.Contains(entry.values, value) {
				return errCertsDnsNotPresented
			}
			switch {
			case entry.writing != nil:
				writing = entry.writing
			case entry.owedWithLock():
				entry.writing = make(chan struct{})
				entry.sent = true
				writer = true
			}
			return nil
		}()
		if err != nil {
			return err
		}
		if writing != nil {
			testHookBarrier("certs.dns_write.queued", "")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-writing:
				continue
			}
		}
		if !writer {
			// the newest write read every value the name held, this one among them
			return nil
		}
		serial, err := self.write(ctx, name, entry)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			close(entry.writing)
			entry.writing = nil
			if err != nil {
				// owed still, to the next wait on the name
				entry.writtenValues = nil
				return
			}
			if entry.serial < serial {
				entry.serial = serial
				entry.generation += 1
			}
		}()
		if err != nil {
			return err
		}
	}
}

// The name's newest serial and generation, and false once value is not among its values.
func (self *CertsDnsSolver) current(name string, value string) (serial uint64, generation uint64, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.names[name]
	if !ok || !slices.Contains(entry.values, value) {
		return 0, 0, false
	}
	return entry.serial, entry.generation, true
}

// Owes name a write of every value it holds, unless a write has landed or begun there since the one at
// generation, whose serial read stale.
func (self *CertsDnsSolver) oweAfterStale(name string, generation uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.names[name]
	if ok && entry.generation == generation && entry.writing == nil {
		entry.writtenValues = nil
	}
}

// Blocks until a write holding the challenge's value has committed, every edge serves the name's newest
// serial and the canary is clean, writing again on stale. See acmez.Waiter.
func (self *CertsDnsSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	name := certsChallengeName(challenge)
	value := challenge.DNS01KeyAuthorization()
	for {
		if err := self.writeOwed(ctx, name, value); err != nil {
			return fmt.Errorf("writing the challenge: %w", err)
		}
		serial, generation, ok := self.current(name, value)
		if !ok {
			return errors.New("the challenge was removed while waiting")
		}
		readiness, err := self.dns.Ready(ctx, serial)
		switch {
		case err != nil:
			// a 503 or a lost answer: ask again after a wait, as the route's caller does
			if err := self.wait(ctx, self.settings.DnsRetryDelay); err != nil {
				return err
			}
		case readiness == CertsDnsStale:
			// final for this serial: the restored edges may lack the value, so the name is owed its
			// values again, once for every wait that saw this serial go stale
			self.oweAfterStale(name, generation)
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

// Takes the challenge's value out of its name, and the name out of the zone once it holds no other and a
// write was sent there, on a context of its own bounded by DnsCleanupTimeout, since the order's may have
// ended. See acmez.Solver.
func (self *CertsDnsSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	name := certsChallengeName(challenge)
	value := challenge.DNS01KeyAuthorization()
	remove := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.names[name]
		if !ok {
			return false
		}
		entry.values = slices.DeleteFunc(entry.values, func(held string) bool { return held == value })
		if len(entry.values) != 0 {
			return false
		}
		// a write's waiter keeps its value until its wait ends, so none is under way here
		delete(self.names, name)
		return entry.sent
	}()
	if !remove {
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
