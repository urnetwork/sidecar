//go:build !ios_extension

// Key custody on the device (DESIGN-COMPUTE §2.5; CTRUST-M13-01, CONTRACTS C-41): the compute credentials a device
// holds join the daemon's secret matcher (record_secret_match.go). DESIGN §16.6's secrets row (I-7) reads a credential
// as what no tool result may carry, and IC-18's and IC-20's "never in a tool result, an error or a log", §25.9's
// never-returned row, §27.7's secret rule and §28.6's secret scan rely on that matcher, so compute's credentials must be
// in it beside the identity seeds and the bearer token. Each area that holds one registers a ComputeCustodySource for
// its kind on its Sidecar, from its own file: INFER the member's cache secret S_m, SSH the device's SSH key, MAILCAL
// calendar links' secrets, CONN connections' OAuth credentials and access tokens, ENC an incarnation's provisioning key
// while it holds it. Sidecar.SecretMatcher reads every registered source each time it builds a matcher, so a matcher
// holds what the device holds at that moment.
//
// A source reads its credentials where they are made, so each read reaches its owner's testHookSecret, and what it
// returns is a copy, which the matcher clears once it has encoded it. A source that fails fails the matcher's build,
// whose error names the kind and never the source's own words, which could hold a value, so a caller refuses rather
// than answers unchecked. The matcher's minimum length still applies, so a short value never matches everything.
// Nothing here logs a value.
//
// Gateway tokens are kept as hashes (§2.5), so a leaked one is matched by its token form, the redactor's rule, never by
// this registry; keys URnetwork's servers hold are no device's. compute_custody_table.go holds §2.5's rows and where
// each is held. The registrations live on their Sidecar (Sidecar.computeCustody), so they end with it.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// One of §2.5's device-held credentials, by the row that holds it (compute_custody_table.go). Zero is no kind, and
// refused, so a kind left unset never registers.
type ComputeCustodyKind int

const (
	// A member's compute cache secret S_m (§6.6), or a tagged sidecar's own from its sealed state: INFER's.
	ComputeCustodyKindCacheSecret ComputeCustodyKind = 1
	// The device's SSH key (§12), and any other SSH private key its daemon holds, an enclave incarnation's host key
	// among them: SSH's.
	ComputeCustodyKindSshKey ComputeCustodyKind = 2
	// A calendar link's secret, an app password or a secret address (§23.6): MAILCAL's. An OAuth form's tokens are its
	// connection's.
	ComputeCustodyKindCalendarLinkSecret ComputeCustodyKind = 3
	// A connection's OAuth credentials, its refresh tokens, per-platform tokens and any client secret, and the access
	// tokens the device holds in memory (§25.6, §25.7): CONN's.
	ComputeCustodyKindConnectionCredential ComputeCustodyKind = 4
	// An enclave incarnation's provisioning key while its VM holds it (§11.7): ENC's.
	ComputeCustodyKindEnclaveProvisioningKey ComputeCustodyKind = 5
)

// The kind's name, as an error names it: never a value.
func (self ComputeCustodyKind) String() string {
	switch self {
	case ComputeCustodyKindCacheSecret:
		return "cache_secret"
	case ComputeCustodyKindSshKey:
		return "ssh_key"
	case ComputeCustodyKindCalendarLinkSecret:
		return "calendar_link_secret"
	case ComputeCustodyKindConnectionCredential:
		return "connection_credential"
	case ComputeCustodyKindEnclaveProvisioningKey:
		return "enclave_provisioning_key"
	}
	return fmt.Sprintf("compute_custody_kind(%d)", int(self))
}

// What an area that holds a compute credential gives its Sidecar's matcher.
type ComputeCustodySource interface {
	// Every credential of the source's kind this device holds now, each a copy the caller clears once it has encoded
	// it, and none where it holds none. A matcher is built for every tool result, so a source answers from what its
	// owner holds and reads storage only where it must, under ctx. An error fails the matcher's build.
	CustodyCredentials(ctx context.Context) ([][]byte, error)
}

// What a matcher's build answers, wrapped, where a registered source failed: its text names the source's kind and
// never the source's own words, which could hold a value.
var ErrComputeCustodyUnavailable = errors.New("compute credentials unreadable")

// What RegisterComputeCustody refuses, wrapped: a kind no device-held row of §2.5 names, or a nil source.
var ErrComputeCustodyRefused = errors.New("compute custody registration refused")

// The errors a failed source's may wrap that a matcher's error keeps, each a constant text that holds no value, so a
// caller can still tell a locked or closed store from a failure. Anything else of a source's error is dropped.
var computeCustodyPassedErrors = []error{
	ErrSidecarStoreLocked,
	ErrSidecarClosed,
	context.Canceled,
	context.DeadlineExceeded,
}

// One registration: a source and the kind it holds.
type computeCustodyRegistration struct {
	kind   ComputeCustodyKind
	source ComputeCustodySource
}

// A Sidecar's registrations, in the order made. Safe for concurrent use.
type sidecarComputeCustody struct {
	stateLock     sync.Mutex
	registrations []*computeCustodyRegistration
}

// This Sidecar's registrations, made on its first registration; nil for a Sidecar that has made none.
func (self *Sidecar) computeCustodyRegistry(create bool) *sidecarComputeCustody {
	if custody, ok := self.computeCustody.Load().(*sidecarComputeCustody); ok {
		return custody
	}
	if !create {
		return nil
	}
	// the first registration's store wins, and every caller reads what it stored
	self.computeCustody.CompareAndSwap(nil, &sidecarComputeCustody{})
	return self.computeCustody.Load().(*sidecarComputeCustody)
}

// Adds source's credentials of kind to every matcher this Sidecar builds from now on, until the function returned
// removes them; calling that function again does nothing. A kind no device-held row of §2.5 names, or a nil source, is
// refused with ErrComputeCustodyRefused. Several sources may hold one kind, as two components holding credentials of a
// kind would. Safe for concurrent use.
func (self *Sidecar) RegisterComputeCustody(kind ComputeCustodyKind, source ComputeCustodySource) (func(), error) {
	heldOnDevice := slices.ContainsFunc(computeCustodyTable, func(row *computeCustodyRow) bool {
		return row.held == computeCustodyHeldOnDevice && row.kind == kind
	})
	if !heldOnDevice {
		return nil, fmt.Errorf("%w: %s is no device-held kind of §2.5", ErrComputeCustodyRefused, kind)
	}
	if source == nil {
		return nil, fmt.Errorf("%w: %s with no source", ErrComputeCustodyRefused, kind)
	}
	custody := self.computeCustodyRegistry(true)
	registration := &computeCustodyRegistration{kind: kind, source: source}
	func() {
		custody.stateLock.Lock()
		defer custody.stateLock.Unlock()
		custody.registrations = append(custody.registrations, registration)
	}()
	unregister := func() {
		custody.stateLock.Lock()
		defer custody.stateLock.Unlock()
		custody.registrations = slices.DeleteFunc(custody.registrations, func(each *computeCustodyRegistration) bool {
			return each == registration
		})
	}
	return unregister, nil
}

// The credentials every registered source holds now, read outside every lock, each a copy the caller clears, also
// where the error is set: what a failing source returned is among them. The error wraps ErrComputeCustodyUnavailable
// and names the first failing source's kind, with only computeCustodyPassedErrors of its own words. A source reads
// under the Sidecar's context, which its close ends, or none before NewSidecar set one.
func (self *Sidecar) computeCustodyCredentials() ([][]byte, error) {
	custody := self.computeCustodyRegistry(false)
	if custody == nil {
		return nil, nil
	}
	registrations := func() []*computeCustodyRegistration {
		custody.stateLock.Lock()
		defer custody.stateLock.Unlock()
		return slices.Clone(custody.registrations)
	}()
	ctx := self.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	credentials := [][]byte{}
	for _, registration := range registrations {
		held, err := registration.source.CustodyCredentials(ctx)
		for _, credential := range held {
			if credential != nil {
				credentials = append(credentials, credential)
			}
		}
		if err != nil {
			for _, passed := range computeCustodyPassedErrors {
				if errors.Is(err, passed) {
					return credentials, fmt.Errorf("%w: %s: %w", ErrComputeCustodyUnavailable, registration.kind, passed)
				}
			}
			return credentials, fmt.Errorf("%w: %s", ErrComputeCustodyUnavailable, registration.kind)
		}
	}
	return credentials, nil
}
