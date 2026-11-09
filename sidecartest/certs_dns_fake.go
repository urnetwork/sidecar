// certsservice.CertsDns in memory, standing for TLS-M5-16's server.NewCertsDnsClient on §12.8's routes:
// challenge writes committed at a rising serial, at most two values a name, at most CapPerHour writes
// a name an hour (D-DNS-8), and Ready and CanaryClean answering what a test scripts, ready and clean
// when it scripts nothing. Tied to a Pebble, a write serves its values to Pebble's validation authority
// at once, as a ready serial would. Safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

var _ certsservice.CertsDns = (*FakeCertsDns)(nil)

// What a name's write may hold at most, and writes a name an hour (§12.8, D-DNS-8).
const (
	fakeCertsDnsMaxValueCount = 2
	fakeCertsDnsCapPerHour    = 10
)

// One test's DNS-01 routes.
type FakeCertsDns struct {
	clock Clock
	// Pebble's DNS, nil when the fake stands alone
	server *pebbleDns

	stateLock    sync.Mutex
	serial       uint64
	nameValues   map[string][]string
	nameWrites   map[string][]time.Time
	writeErrors  []error
	readyAnswers []certsservice.CertsDnsReadiness
	cleanAnswers []bool
	writeCount   int
	removeCount  int
	readyCount   int
	readySerials []uint64
	// serve a value that matches no challenge in Pebble's DNS, so its validation fails
	wrongValues bool
}

// A fake standing alone, timing its hourly cap on clock; nil is real time.
func NewFakeCertsDns(clock Clock) *FakeCertsDns {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &FakeCertsDns{clock: clock, nameValues: map[string][]string{}, nameWrites: map[string][]time.Time{}}
}

func newFakeCertsDns(server *pebbleDns) *FakeCertsDns {
	fake := NewFakeCertsDns(nil)
	fake.server = server
	return fake
}

// The next writes fail with these, in order, before anything is written: certsservice.ErrCertsDnsRestoring
// for a 503 while a restore runs.
func (self *FakeCertsDns) ScriptWriteErrors(errs ...error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writeErrors = append(self.writeErrors, errs...)
}

// The next Ready calls answer these, in order; after them, ready.
func (self *FakeCertsDns) ScriptReady(answers ...certsservice.CertsDnsReadiness) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readyAnswers = append(self.readyAnswers, answers...)
}

// The next CanaryClean calls answer these, in order; after them, clean.
func (self *FakeCertsDns) ScriptCanaryClean(answers ...bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cleanAnswers = append(self.cleanAnswers, answers...)
}

// Serves Pebble a value that matches no challenge in place of each write's, so every authorization
// fails, as a CA that cannot see the record does.
func (self *FakeCertsDns) ServeWrongValues(wrong bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.wrongValues = wrong
}

// Writes at name, removes, and Ready calls so far.
func (self *FakeCertsDns) Counts() (writeCount int, removeCount int, readyCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.writeCount, self.removeCount, self.readyCount
}

// The serials Ready was asked about, in order.
func (self *FakeCertsDns) ReadySerials() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.readySerials)
}

// The values at _acme-challenge.<name> now.
func (self *FakeCertsDns) Values(name string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.nameValues[strings.ToLower(name)])
}

// Every name holding values now.
func (self *FakeCertsDns) Names() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.nameValues))
}

// See certsservice.CertsDns.
func (self *FakeCertsDns) WriteAcmeChallenge(ctx context.Context, name string, values []string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	name = strings.ToLower(name)
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writeCount += 1
	if 0 < len(self.writeErrors) {
		err := self.writeErrors[0]
		self.writeErrors = self.writeErrors[1:]
		return 0, err
	}
	if len(values) == 0 || fakeCertsDnsMaxValueCount < len(values) {
		return 0, errors.New("a challenge write holds one or two values")
	}
	recent := []time.Time{}
	for _, writeTime := range self.nameWrites[name] {
		if now.Sub(writeTime) < time.Hour {
			recent = append(recent, writeTime)
		}
	}
	if fakeCertsDnsCapPerHour <= len(recent) {
		self.nameWrites[name] = recent
		return 0, certsservice.ErrCertsDnsWriteRefused
	}
	self.nameWrites[name] = append(recent, now)
	self.serial += 1
	self.nameValues[name] = slices.Clone(values)
	if self.server != nil {
		served := values
		if self.wrongValues {
			served = []string{"a-value-matching-no-challenge"}
		}
		self.server.set("_acme-challenge."+name, served)
	}
	return self.serial, nil
}

// See certsservice.CertsDns.
func (self *FakeCertsDns) RemoveAcmeChallenge(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name = strings.ToLower(name)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.removeCount += 1
	delete(self.nameValues, name)
	if self.server != nil {
		self.server.set("_acme-challenge."+name, nil)
	}
	return nil
}

// See certsservice.CertsDns.
func (self *FakeCertsDns) Ready(ctx context.Context, serial uint64) (certsservice.CertsDnsReadiness, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readyCount += 1
	self.readySerials = append(self.readySerials, serial)
	if 0 < len(self.readyAnswers) {
		answer := self.readyAnswers[0]
		self.readyAnswers = self.readyAnswers[1:]
		return answer, nil
	}
	return certsservice.CertsDnsReady, nil
}

// See certsservice.CertsDns.
func (self *FakeCertsDns) CanaryClean(ctx context.Context, serial uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.cleanAnswers) {
		answer := self.cleanAnswers[0]
		self.cleanAnswers = self.cleanAnswers[1:]
		return answer, nil
	}
	return true, nil
}
