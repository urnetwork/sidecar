//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §3.3's components on a Sidecar (CARCH-M11-01). Each compute area registers its component from its own
// file, in an init function, through registerComputeComponent, as cli/ registers its commands, so neither settings.go
// nor sidecar_types.go is edited for one again. A Sidecar constructs every registered component as it starts, in
// registration order, which is the order Go runs the files' init functions, their names' sorted order: after the
// components its host added, and before its run loop starts, so the loop's end can never race a construction. It closes
// the ones that constructed in reverse order as its run loop ends, after its last client generation and before the
// host's components.
//
// A component reaches another only at use, through sidecarComputeComponent, never while it constructs: its order is
// the files' and no design's. One that did not construct leaves its surface refusing, since sidecarComputeComponent
// answers ErrComputeComponentUnavailable with its name and the constructor's error, never a nil component.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), build
// sidecar_compute_leg.go's stand-ins instead, which construct and close nothing, so a compute surface on them is
// refused by its build line rather than left nil.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// What a compute component's surface answers, wrapped with the component's name and the reason, where its Sidecar
// holds no constructed component of that name: its constructor failed or built nothing, no file of this build
// registered it, the Sidecar has not started, or it has closed.
var ErrComputeComponentUnavailable = errors.New("compute component unavailable")

// A constructor that returned neither a component nor an error.
var errComputeComponentNil = errors.New("its constructor built nothing")

// One compute component's registration: its name and closures over its constructor and its close, which hide its type.
type sidecarComputeRegistration struct {
	name      string
	construct func(sidecar *Sidecar) (any, error)
	close     func(component any)
}

// Every registration, in the order the files' init functions made them. Written only during the package's init, so
// read without a lock after it. A test may swap it for a fake set, and puts the original back.
var sidecarComputeRegistrations = []*sidecarComputeRegistration{}

// A registration over construct and close, which registerComputeComponent lists and a test may build alone. construct
// builds the component for one Sidecar and must return promptly: anything it starts ends with the Sidecar's ctx, and
// what it needs of the network, its identity or another component it reads at use. Its error leaves the component
// refusing on that Sidecar; a nil component with a nil error refuses the same way. close, which may be nil, runs once
// as the Sidecar ends, after its last client generation, outside every lock.
func newSidecarComputeRegistration[T any](
	name string,
	construct func(sidecar *Sidecar) (*T, error),
	close func(component *T),
) *sidecarComputeRegistration {
	return &sidecarComputeRegistration{
		name: name,
		construct: func(sidecar *Sidecar) (any, error) {
			component, err := construct(sidecar)
			if err != nil {
				return nil, err
			}
			if component == nil {
				return nil, errComputeComponentNil
			}
			return component, nil
		},
		close: func(component any) {
			if close != nil {
				close(component.(*T))
			}
		},
	}
}

// Registers a compute component under name, from an init function in the component's own file. See
// newSidecarComputeRegistration for construct and close. An empty name, a nil constructor or a name registered twice
// is a build error, which panics as registerUrCommand does.
func registerComputeComponent[T any](name string, construct func(sidecar *Sidecar) (*T, error), close func(component *T)) {
	registered := slices.ContainsFunc(sidecarComputeRegistrations, func(registration *sidecarComputeRegistration) bool {
		return registration.name == name
	})
	if name == "" || construct == nil || registered {
		panic(fmt.Sprintf("compute component %q registered twice or without a constructor", name))
	}
	sidecarComputeRegistrations = append(sidecarComputeRegistrations, newSidecarComputeRegistration(name, construct, close))
}

// What one registration came to on one Sidecar: its component, or why there is none.
type sidecarComputeEntry struct {
	registration *sidecarComputeRegistration
	component    any
	err          error
}

// A Sidecar's compute components, in registration order. Safe for concurrent use: the entries are fixed when it is
// built, and closed moves once, under stateLock.
type sidecarComputeComponents struct {
	entries []*sidecarComputeEntry

	stateLock sync.Mutex
	closed    bool
}

// Constructs each registration for sidecar, in order. A constructor's error is the component's for good on this
// Sidecar, logged once, and every other component constructs regardless.
func newSidecarComputeComponents(sidecar *Sidecar, registrations []*sidecarComputeRegistration) *sidecarComputeComponents {
	components := &sidecarComputeComponents{}
	for _, registration := range registrations {
		component, err := registration.construct(sidecar)
		if err != nil {
			sidecar.log.Warningf("[compute]%s did not construct: %s", registration.name, err)
		}
		components.entries = append(components.entries, &sidecarComputeEntry{
			registration: registration,
			component:    component,
			err:          err,
		})
	}
	return components
}

// The component of name, or an error wrapping ErrComputeComponentUnavailable that names it and says why.
func (self *sidecarComputeComponents) component(name string) (any, error) {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if closed {
		return nil, fmt.Errorf("%w: %s: %w", ErrComputeComponentUnavailable, name, ErrSidecarClosed)
	}
	for _, entry := range self.entries {
		if entry.registration.name != name {
			continue
		}
		if entry.err != nil {
			return nil, fmt.Errorf("%w: %s did not construct: %w", ErrComputeComponentUnavailable, name, entry.err)
		}
		return entry.component, nil
	}
	return nil, fmt.Errorf("%w: this build registers no %s", ErrComputeComponentUnavailable, name)
}

// Closes each component that constructed, once, in reverse registration order, outside stateLock. Later lookups
// refuse with ErrSidecarClosed.
func (self *sidecarComputeComponents) close() {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		return true
	}()
	if !first {
		return
	}
	for index := len(self.entries) - 1; 0 <= index; index -= 1 {
		entry := self.entries[index]
		if entry.err == nil {
			entry.registration.close(entry.component)
		}
	}
}

// The component registered as name for sidecar, as its own type, or an error wrapping ErrComputeComponentUnavailable
// that names it and says why: never a nil component with a nil error. Every compute surface reads its component
// through this, and answers its error.
func sidecarComputeComponent[T any](sidecar *Sidecar, name string) (*T, error) {
	components, ok := sidecar.compute.Load().(*sidecarComputeComponents)
	if !ok {
		return nil, fmt.Errorf("%w: %s: the sidecar has not started", ErrComputeComponentUnavailable, name)
	}
	component, err := components.component(name)
	if err != nil {
		return nil, err
	}
	typed, ok := component.(*T)
	if !ok {
		return nil, fmt.Errorf("%w: %s is a %T, not a %T", ErrComputeComponentUnavailable, name, component, typed)
	}
	return typed, nil
}

// Constructs this Sidecar's compute components from start, once, after the components its host added and before the
// run loop.
func (self *Sidecar) startComputeComponents() {
	self.compute.Store(newSidecarComputeComponents(self, sidecarComputeRegistrations))
}

// Closes them, in reverse, from the run loop's end, after its last generation and before the host's components.
func (self *Sidecar) closeComputeComponents() {
	if components, ok := self.compute.Load().(*sidecarComputeComponents); ok {
		components.close()
	}
}
