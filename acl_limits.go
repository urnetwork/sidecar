// §8.8's row limits (owner decision 73): what one projection's AclRows may hold. Two are format constants every
// reader holds alike, at most 4,096 atoms and 4 MiB of ProjectionRows, and the rest are the network's tier's, §20.4's
// acl_* keys from config/all/pro.yml through model.Pro() and GET /sidecar/limits, which AclLimits carries.
// AclRowsCheckLimits is the one size check, called by the writer before it signs a base and by api's verifier before
// it appends one, answering RESOURCE_EXHAUSTED; after a downgrade a new head must fit while the old one still
// evaluates (§20.7), since only a check of a new head reads the limits.
//
// §20.7's tls_endpoints row lives here too (QUOTA-M4-04): publish grants per (host, port), counted at grant activation.
// Readers evaluate no tier, so the count sits outside the shared fold: the writer checks its QuotaLimits before it
// signs a GrantActivate (AclCheckGrantActivateQuota) and api's verifier checks NetworkSidecarLimits
// (model.CheckGrantActivationLimits), both on AclCheckTlsEndpoints' one table.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"strings"
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

// §20.4's key for §20.7's tls_endpoints row.
const AclTlsEndpointsLimitKey = "tls_endpoints"

// A tls/ socket name, tls/<port>/<host>, names one endpoint: a (host, port).
const aclTlsEndpointPrefix = "tls/"

// The (host, port) endpoints with a publish grant active at state at timeMs (§13.9's endpoint): each tls/<port>/<host>
// target of a rule that allows publish and has not expired, an activated grant's and a standing publish's alike.
// Custom-domain aliases are tls/ names like any other, so they count; listeners and certificates are no rule, and
// the mta-sts system publish takes no tls/ grant of its own (§13.9, §15.5), so neither does.
func aclActiveTlsEndpoints(state *AclState, timeMs int64) map[string]bool {
	endpoints := map[string]bool{}
	for _, rule := range state.rows.GetRules() {
		if expires := rule.GetExpires(); expires != 0 && expires <= timeMs {
			continue
		}
		if !slices.Contains(rule.GetActions(), uint32(protocol.AclAction_ACL_ACTION_PUBLISH)) {
			continue
		}
		for _, target := range rule.GetTargets() {
			if name := target.GetPublicName(); strings.HasPrefix(name, aclTlsEndpointPrefix) {
				endpoints[name] = true
			}
		}
	}
	return endpoints
}

// A GrantActivate's ask, read from its canonical action as CheckGrantActivate reads it.
func AclGrantActivateAsk(activate *protocol.GrantActivate) (*AclGrantAsk, error) {
	action, err := ParseStoredCanonicalAction(activate.GetCanonicalAction())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	return ParseAclGrantAction(action.Action)
}

// §20.7's tls_endpoints check of a grant activation at state, S(n-1), sequenced at timeMs: each (host, port) the
// grant publishes that no active grant holds takes a unit, and past limit the activation is refused with a
// QuotaRefusal whose Used is the endpoints active. A grant that publishes nothing, or only endpoints already active,
// takes no unit. A negative limit has none, and zero refuses any new endpoint. Only the activation is judged: a grant
// already active keeps running through a downgrade until it expires, and an expired one frees its unit.
func AclCheckTlsEndpoints(state *AclState, ask *AclGrantAsk, timeMs int64, limit int64, upgrade bool) *QuotaRefusal {
	if !slices.Contains(ask.Allow, protocol.AclAction_ACL_ACTION_PUBLISH) {
		return nil
	}
	active := aclActiveTlsEndpoints(state, timeMs)
	added := map[string]bool{}
	for _, target := range ask.Dst {
		if name := target.GetPublicName(); strings.HasPrefix(name, aclTlsEndpointPrefix) && !active[name] {
			added[name] = true
		}
	}
	if len(added) == 0 || limit < 0 || int64(len(active)+len(added)) <= limit {
		return nil
	}
	return &QuotaRefusal{
		LimitKey: AclTlsEndpointsLimitKey,
		Limit:    limit,
		Used:     int64(len(active)),
		Upgrade:  upgrade,
	}
}

// The writer's tls_endpoints check before it signs a GrantActivate at state, the position it files at, timeMs its
// time: limits as GET /sidecar/limits gave them, a key they lack reading 0, which refuses, so a limit this build
// does not know fails closed. A writer cannot tell whether enforce_sidecar_limits is on (question
// quota-m1-02-limits-while-dark), so it applies the limits it reads: the closed direction, where api's verifier
// passes while they are dark.
func AclCheckGrantActivateQuota(state *AclState, activate *protocol.GrantActivate, timeMs int64, limits *QuotaLimits) (*QuotaRefusal, error) {
	ask, err := AclGrantActivateAsk(activate)
	if err != nil {
		return nil, err
	}
	limit := int64(0)
	upgrade := true
	if limits != nil {
		limit = limits.Limits[AclTlsEndpointsLimitKey]
		upgrade = limits.Tier != "team"
	}
	return AclCheckTlsEndpoints(state, ask, timeMs, limit, upgrade), nil
}
