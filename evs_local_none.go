//go:build sidecar_http || js || ios || android || sdk_mobile_bind

// Head mode's Mount (§11.11's mobile and wasm row): mobile, the page Worker and the sdk read and write single files and
// run no local git tier, so Mount refuses.

package sidecar

import (
	"context"
	"errors"
)

// Head mode has no local tier.
var ErrEvsNoLocalTier = errors.New("evs: head mode has no local git tier")

// Refuses: head mode serves no git.
func (self *EvsRepo) Mount(ctx context.Context, args *EvsMountArgs) (*EvsMountInfo, error) {
	return nil, ErrEvsNoLocalTier
}
