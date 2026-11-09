// §21's types every leg decodes: a network's §21.7 standing, and GET /abuse/status's body, which a
// sidecar reads with its own client token and the page Worker reads too, so nothing here names a
// connect type. host_abuse.go holds ServiceHost.Abuse, which only hosted engines read.
//
// The status tells a network nothing about a hold or a barred case. A hold has no field here
// (D-ABUSE-8), and api lists no action of a case that a sealing order or a CSAM case bars, so such a
// case shows the network its standing alone (plan-ABUSE-small-readings #6). TestAbuseStatusHoldsNoHoldField
// holds every field to that. A change of state reaches a client as a §6 core, sock or mail hint
// (§21.16), which carries none of it: the client takes a hint as a prompt to refetch this, never as
// the state itself.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
)

// A network's §21.7 standing, as ServiceHost.Abuse and GET /abuse/status give it. The values are a
// format: server's model.AbuseStanding holds the same strings.
type AbuseStanding string

const (
	// Under 7 days old: same-network mail deposits only, 1 endpoint publishing at most 24 h, at most
	// probation_dns_entries user RRsets and none A, AAAA or CNAME, and no names held for review,
	// aliases or outbound shares.
	AbuseStandingProbation AbuseStanding = "probation"
	// 7 or more days old, and 30 days without an action: the tier's defaults (§20).
	AbuseStandingStandard AbuseStanding = "standard"
	// A Team with a verified domain, paid 30 days and clean 90: Team thresholds, and brand use.
	AbuseStandingTrusted AbuseStanding = "trusted"
	// A network halt or a kill within 30 days: probation's limits.
	AbuseStandingRestricted AbuseStanding = "restricted"
	// A §8 suspension until reviewed: no reach, publishing or sending, while its data stays kept,
	// readable and exportable.
	AbuseStandingSuspended AbuseStanding = "suspended"
)

// Whether this build knows the standing. A gate refuses one it does not, as it refuses a network it
// has not loaded, so a standing added later never passes an older gate.
func (self AbuseStanding) Known() bool {
	switch self {
	case AbuseStandingProbation, AbuseStandingStandard, AbuseStandingTrusted, AbuseStandingRestricted, AbuseStandingSuspended:
		return true
	}
	return false
}

// GET /abuse/status's body (§21.16): the caller's own network's standing, whether it is verified,
// and the actions on it that have not ended.
type AbuseStatus struct {
	Standing AbuseStanding `json:"standing"`
	// network_verified (§21.7): a payment method, or the owner's verified phone or email, Apple and
	// Google sign-ins counting. Public names and internet mail need it.
	Verified bool `json:"verified"`
	// Neither lifted nor past their own end, oldest first. Empty for a network with none, and for one
	// whose every action belongs to a barred case.
	Actions []*AbuseStatusAction `json:"actions"`
}

// An empty list where Actions is nil, so the body holds a list whoever built it, never null.
func (self AbuseStatus) MarshalJSON() ([]byte, error) {
	// a type with the same fields and none of the methods, so this does not call itself
	type abuseStatusBody AbuseStatus
	body := abuseStatusBody(self)
	if body.Actions == nil {
		body.Actions = []*AbuseStatusAction{}
	}
	return json.Marshal(body)
}

// One action on the network, as §21.8's notice names it to its Owners and Admins: its case, category
// and target, and what it does until when. Never a reporter, a join key, a reviewer or a reason,
// which stay with api-14's rows and the abuse role.
type AbuseStatusAction struct {
	ActionId Id `json:"action_id"`
	// The case an Owner or Admin appeals (POST /abuse/appeal), and reads in GET /abuse/cases.
	CaseId Id `json:"case_id"`
	// §21.4's row, as abuse_case stores it, such as phishing or copyright.
	Category string `json:"category"`
	// What the action does, as abuse_action stores it, such as host_kill, label_kill, zone_suspend,
	// mail_halt or network_suspend.
	Kind string `json:"kind"`
	// The unit it acts on: a host, a label, a sending domain or the network (§21.4's principle 1).
	Target string `json:"target"`
	// pending while a machine's action waits for review (§21.8), which holds it meanwhile, then
	// upheld.
	ReviewState string `json:"review_state"`
	// When it was taken, in ms since the epoch.
	CreateTimeMs int64 `json:"create_time_ms"`
	// When it ends by itself, in ms since the epoch. 0: only a lift ends it.
	UntilTimeMs int64 `json:"until_time_ms"`
}

// The route as errors name it.
const abuseStatusRoute = "GET /abuse/status"

// GET /abuse/status (§21.16; Client class, on §7.4's strict_exp allowlist), with the jwt as bearer:
// the token's own network's status. Never on a packet path. An answer with no standing, or with an
// action missing its id, its case or its kind, is not the route's and is ErrSidecarApiReply. A
// standing this build does not know comes back as it was sent, for the caller to read through Known.
func (self *SidecarApi) AbuseStatus(ctx context.Context) (*AbuseStatus, error) {
	status := &AbuseStatus{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     abuseStatusRoute,
		operation: "abuse_status",
		method:    "GET",
		url:       self.settings.ApiUrl + "/abuse/status",
		bearer:    true,
	}, nil, status)
	if err != nil {
		return nil, err
	}
	if status.Standing == "" {
		return nil, fmt.Errorf("sidecar api %s: %w: no standing", abuseStatusRoute, ErrSidecarApiReply)
	}
	for _, action := range status.Actions {
		if action == nil || action.ActionId == (Id{}) || action.CaseId == (Id{}) || action.Kind == "" {
			return nil, fmt.Errorf("sidecar api %s: %w: an action with no id, case or kind", abuseStatusRoute, ErrSidecarApiReply)
		}
	}
	if status.Actions == nil {
		status.Actions = []*AbuseStatusAction{}
	}
	return status, nil
}
