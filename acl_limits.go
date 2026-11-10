// §8.8's row limits (owner decision 73): what one projection's AclRows may hold. Two are format constants every
// reader holds alike, at most 4,096 atoms and 4 MiB of ProjectionRows, and the rest are the network's tier's, §20.4's
// acl_* keys from config/all/pro.yml through model.Pro() and GET /sidecar/limits, which AclLimits carries.
// AclRowsCheckLimits is the one size check, called by the writer before it signs a base and by api's verifier before
// it appends one, answering RESOURCE_EXHAUSTED; after a downgrade a new head must fit while the old one still
// evaluates (§20.7), since only a check of a new head reads the limits.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The rows pass a limit: RESOURCE_EXHAUSTED (§8.8), naming the limit and never a value of the policy.
var ErrAclRowsTooLarge = errors.New("acl rows: RESOURCE_EXHAUSTED")

// A tier's acl_* limits (§20.4). Zero for a count means the tier allows none of that thing; a negative one, no limit.
type AclLimits struct {
	// acl_rules: the most rules a document compiles to, its grants and its requests.
	Rules int
	// acl_groups: the most groups a document defines; 0 refuses group:.
	Groups int
	// acl_requests: the most requests rules.
	Requests int
	// acl_approvers_two: whether a requests rule may ask two approvers or more (Team).
	ApproversTwo bool
	// acl_network_shares: the most network: selectors a document names; 0 refuses them.
	NetworkShares int
	// Whether the tier's documents may hold standing publishes (§8.5: Pro and Team).
	StandingPublishes bool
	// The longest a publish request may last, §13.9's 7 days on Community; 0 for no tier bound.
	PublishMaxExpiry time.Duration
}

// Whether a count fits a limit, a negative limit taking any.
func aclLimitFits(count int, limit int) bool {
	return limit < 0 || count <= limit
}

// The one size check (§8.8): at most 4,096 atoms and the tier's acl_rules, rows counting the document's rules and
// requests; rowsByteCount is the encoded ProjectionRows', at most 4 MiB, 0 when the caller checks no encoding.
func AclRowsCheckLimits(rows *protocol.AclRows, rowsByteCount int, limits *AclLimits) error {
	if rows == nil {
		return fmt.Errorf("%w: no rows", ErrAclRowsTooLarge)
	}
	if aclRowsMaxAtomCount < len(rows.GetAtoms()) {
		return fmt.Errorf("%w: %d atoms, over %d", ErrAclRowsTooLarge, len(rows.GetAtoms()), aclRowsMaxAtomCount)
	}
	// ProjectionRows' 4 MiB, the format constant compile holds every base to (config_state.go)
	if configRowsMaxByteCount < rowsByteCount {
		return fmt.Errorf("%w: %d bytes of rows, over %d", ErrAclRowsTooLarge, rowsByteCount, configRowsMaxByteCount)
	}
	if limits == nil {
		return nil
	}
	documentRules := 0
	for _, rule := range rows.GetRules() {
		// an activated grant is a request's spending, which acl_requests and the rule it came from bound
		if len(rule.GetSourceRuleId()) == 0 {
			documentRules += 1
		}
	}
	if !aclLimitFits(documentRules+len(rows.GetRequests()), limits.Rules) {
		return fmt.Errorf("%w: %d rules, over the tier's acl_rules", ErrAclRowsTooLarge, documentRules+len(rows.GetRequests()))
	}
	if !aclLimitFits(len(rows.GetRequests()), limits.Requests) {
		return fmt.Errorf("%w: %d requests rules, over the tier's acl_requests", ErrAclRowsTooLarge, len(rows.GetRequests()))
	}
	return nil
}
