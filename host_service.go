//go:build !sidecar_http

// What a hosting process supplies to a server engine, and what the engine gives back (§4.5). Engines
// are the <svc>service child packages. server hosts them, and they never import it, so go-redis,
// minio-go and prometheus stay out of this module, and a host other than URnetwork's could supply
// these same interfaces (D-REPO-3).
//
// Every host_ file carries !sidecar_http, since no hosted engine runs in the page Worker (§4.4), and
// so may name connect types, connect.Id included: §20.7 declares Quota in them.
//
// Every interface a ServiceHost holds is safe for concurrent use, and a call that does I/O takes a ctx
// that bounds it. None of those may be called with a state lock held.

package sidecar

import (
	"net"
	"net/http"
)

// Built by the hosting process and passed to each engine's constructor. An engine needs only some of
// these, and a host may leave the rest nil.
type ServiceHost struct {
	// jwt to Principal (server/session). Engines call Authenticate, which holds this to its rules.
	Authenticator Authenticator
	// Reserve, commit, release (§20).
	Quota Quota
	// prometheus in server.
	Metrics Metrics
	// Once-keyed jobs (taskworker).
	Tasks Tasks
	// Soft state only: evs and gkm keep only what they rebuild here (owner decision 136).
	Redis Redis
	// The segment bucket and each metadata cluster's bucket, by cluster id (X13).
	Blobs BlobStore
	// How far this process's clock may be from true time (§19.6).
	ClockCheck ClockCheck
	// Server to client (X8).
	Push Push
	// jwt and urls for the engine's connect client.
	ServiceClient ServiceClientSource
	// The time this engine reads and waits on (clock.go). Nil is real time; a test gives each host its
	// own view of one fake clock.
	Clock Clock
	// §19.11's gates, reread by the host every 60 s (host_gates.go). Nil answers every gate closed, so a
	// host that forgets them opens nothing.
	Gates ServiceGates
}

// The clock a host gave its engines: Clock, or real time when the host set none.
func (self *ServiceHost) ClockOrReal() Clock {
	return clockOrReal(self.Clock)
}

// The gates a host gave its engines: Gates, or every gate closed when the host set none.
func (self *ServiceHost) GatesOrClosed() ServiceGates {
	if self.Gates == nil {
		return ClosedServiceGates{}
	}
	return self.Gates
}

// What every engine a server/cli/<svc> hosts gives its host, which wraps it with readiness, /status,
// stats and PROXY-unwrapped listeners. pushservice's types run inside existing services instead. Safe
// for concurrent use.
//
// §4.5 declares one interface whose first member is Handler() or Serve. This is a reading of it, since
// no Go interface says "one or the other", and smtpedge dials out and listens on nothing (§14.9), so it
// has neither: an engine serves through HttpEngine, StreamEngine or both, and one that listens on
// nothing is an Engine alone. What that costs is that a Handler of the wrong signature still compiles
// as an Engine, so each engine package says what it is, as var _ sidecar.HttpEngine = (*EvsEngine)(nil).
type Engine interface {
	// Whether the stores this engine needs are reachable and its state is loaded, the column §19.4
	// gives each service. The host gates its /status on this.
	Ready() bool
	// Takes no new work and returns once work in flight has finished or the engine's own bound has
	// passed. New connections are the host's to stop: it closes the listeners.
	Drain()
	// Ends everything at once and releases what the engine holds. Safe after Drain, and more than
	// once.
	Close()
}

// An engine served over HTTP.
type HttpEngine interface {
	Engine
	// One handler for every route of the service, built once. The host mounts it behind readiness
	// and §19.8's route metrics.
	Handler() http.Handler
}

// An engine that serves raw connections, as tlsedge and mxedge do.
type StreamEngine interface {
	Engine
	// §4.5's Serve(net.Listener), returning why it stopped, nil when the engine closed. Accepts on
	// listener until it closes or the engine closes, and then returns. The host's
	// listeners have already taken any PROXY header off. The host calls this once for each listener,
	// each on its own goroutine, as tlsedge's four ports need.
	Serve(listener net.Listener) error
}
