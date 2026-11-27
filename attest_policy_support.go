//go:build !ios_extension && !sidecar_http

// The signed policy's support line as the support client reads it (DESIGN-COMPUTE §5.4, §28.10; ATTEST-M12-02): the
// feedback service's host, the one place a device posts a message, file or log bundle to support, and the
// subprocessors support:urnetwork names. A device posts to the newest policy's host whatever that policy's not_after,
// its release's copy at least, since support must work when nothing else does; with no policy, or a newest policy
// carrying no support line, no host is named, and every message waits in the support client's outbox
// (support_sources.go). Nothing here decides whether support may post: the client's gate and the disclosure do.
//
// Safe for concurrent use, as the store is.

package sidecar

import (
	"errors"
	"fmt"
)

// The newest policy names no support host: none is held, or it carries no support line.
var errComputePolicySupportAbsent = errors.New("the newest compute policy names no support host")

// The store and a Sidecar's source are what the support client reads its host from.
var (
	_ SupportPolicySource = (*ComputePolicyStore)(nil)
	_ SupportPolicySource = (*computePolicySupportSource)(nil)
)

// The newest verified policy's support line, read strictly by ParseSupportPolicyLine; an error where the store holds no
// policy, its newest carries no support line, or the line does not parse.
func (self *ComputePolicyStore) SupportLine() (*SupportPolicyLine, error) {
	policy := self.Newest()
	if policy == nil || len(policy.Support) == 0 {
		return nil, errComputePolicySupportAbsent
	}
	line, err := ParseSupportPolicyLine(policy.Support)
	if err != nil {
		return nil, fmt.Errorf("compute policy %d: %w", policy.Version, err)
	}
	return line, nil
}

// A Sidecar's support line through its attest component's store, resolved at each read, since a component reaches
// another only at use (compute_sidecar.go): with no store, no host is named.
type computePolicySupportSource struct {
	sidecar *Sidecar
}

// See SupportPolicySource.
func (self *computePolicySupportSource) SupportLine() (*SupportPolicyLine, error) {
	store, err := self.sidecar.ComputePolicyStore()
	if err != nil {
		return nil, err
	}
	return store.SupportLine()
}
