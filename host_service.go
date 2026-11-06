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
	// jwt to Principal (server/session).
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
	// Server to client (X8).
	Push Push
	// jwt and urls for the engine's connect client.
	ServiceClient ServiceClientSource
}

// What every engine a server/cli/<svc> hosts gives its host, which wraps it with readiness, /status,
// stats and PROXY-unwrapped listeners. An engine serves through HttpEngine, StreamEngine or both; one
// that dials out and listens on nothing, as smtpedge does (§14.9), is an Engine alone. pushservice's
// types run inside existing services instead. Safe for concurrent use.
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
	// Accepts on listener until it closes or the engine closes, and then returns. The host's
	// listeners have already taken any PROXY header off. The host calls this once for each listener,
	// each on its own goroutine, as tlsedge's four ports need.
	Serve(listener net.Listener) error
}
