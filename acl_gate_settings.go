//go:build !sidecar_http

// AclGateCache's tunables (§8.9, §8.18), each a field with its default here and nowhere else.

package sidecar

import (
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Tunables of one process's gate cache.
type AclGateSettings struct {
	// How often every loaded network reloads with no {acl_}v event: 5 min (§8.9), so a revocation whose event was lost
	// still reaches the gate within it. Non-positive turns the poll off, leaving events alone.
	PollInterval time.Duration
	// The most each poll is delayed past PollInterval, drawn afresh for every poll, so processes started together do
	// not load together (§8.18's fan-out risk): 30 s. Non-positive adds none.
	PollJitter time.Duration
	// How many networks load at once across the process, the rest waiting their turn outside every packet lock: 16.
	// Non-positive is one.
	LoadConcurrency int
	// How long one network's load may read for before it gives up and keeps its old state: 30 s, three of §19.6's
	// 10 s store deadlines. Non-positive is no deadline but the cache's own.
	LoadTimeout time.Duration
	// How long a network's loader waits after a load that failed or was refused before it takes the next trigger, so
	// a gate that asks on every request while the source fails, or serves a refused copy, costs one read a wait
	// (connect/CODESTYLE.md's retry budget): 5 s, within §8.9's 5 s target once the source recovers. Non-positive
	// waits none.
	FailureBackoff time.Duration
	// The bytes of logs and rows the cache keeps, each network's retained entries and base rows counted: 256 MiB,
	// room for a few dozen networks at §8.8's 4 MiB rows and thousands at common sizes. Past it the networks read
	// longest ago lose their loaded state, keeping their pins, and load again when next asked. Non-positive keeps every
	// network loaded.
	ByteBudget int64
	// How many networks the cache remembers with no loaded state, each with the pin it held, so a network evicted and
	// asked for again reloads no lower and reads as not loaded rather than unknown: 100,000, some 10 MiB. Past it the
	// longest unasked are forgotten. Non-positive forgets each at its eviction.
	UnloadedCount int
	// How many entry objects AclGateDirectSource lists from proj/ in one request: 1,000, the store's page.
	ListPageCount int
	// Each network's rows-only log's settings. Nil is DefaultConfigLogSettings with the cache's Log.
	ConfigLog *ConfigLogSettings
	// Where loads, refusals and alarms are logged, ids and positions only (I-13). Nil is the leg's default.
	Log Logger
	// Called after each load on its network's loading goroutine, which it must not hold: the pin the network then
	// holds, nil for none, and why the load failed, nil when it read cleanly. What a host counts and a test waits on.
	// Nil calls nothing.
	OnLoad func(networkId Id, pin *bridge.AuthPin, err error)
}

// §8.9's values.
func DefaultAclGateSettings() *AclGateSettings {
	return &AclGateSettings{
		PollInterval:    5 * time.Minute,
		PollJitter:      30 * time.Second,
		LoadConcurrency: 16,
		LoadTimeout:     30 * time.Second,
		FailureBackoff:  5 * time.Second,
		ByteBudget:      256 * 1024 * 1024,
		UnloadedCount:   100000,
		ListPageCount:   1000,
	}
}
