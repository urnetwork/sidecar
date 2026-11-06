//go:build !sidecar_http

// Holds the root's require on connect until the first connect-facing root file lands. go mod tidy
// drops a requirement nothing imports, and §4.7 has the root require connect, so without this the
// require, connect's forks and the indirect requirements leave go.mod and go.sum, and every track
// that later imports connect would re-add them in a conflicting change. Delete this file in the
// change that adds a root file importing connect for real.
//
// The tag keeps connect, and the gVisor it links, out of the sidecar_http leg (§4.4).

package sidecar

import (
	_ "github.com/urnetwork/connect"
)
