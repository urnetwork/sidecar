//go:build (sidecar_http || js || ios || android || sdk_mobile_bind) && !ios_extension

// Head mode's Mount and WriteAtTip (§11.11's mobile and wasm row; §16.2): mobile, the page Worker and the sdk read and
// write single files and run no local git tier, so Mount refuses, and a git-mode write answers EVS_GIT_REF, as §16.2
// says a daemon with no local tier does.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// Head mode has no local tier.
var ErrEvsNoLocalTier = errors.New("evs: head mode has no local git tier")

// Refuses: head mode serves no git.
func (self *EvsRepo) Mount(ctx context.Context, args *EvsMountArgs) (*EvsMountInfo, error) {
	return nil, ErrEvsNoLocalTier
}

// Refuses with EVS_GIT_REF: head mode builds no commit.
func (self *EvsRepo) WriteAtTip(ctx context.Context, args *EvsWriteAtTipArgs) (*EvsWriteAtTipResult, error) {
	return nil, fmt.Errorf("%w: %w", ErrEvsGitRef, ErrEvsNoLocalTier)
}
