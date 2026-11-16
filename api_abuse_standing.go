//go:build !sidecar_http && !ios_extension

// A network's §21.7 standing, on every leg that decodes it but sidecar_http: operator-core's (owner
// decision 251), aliased here. The page Worker reads it in GET /abuse/status's body too and links no
// operator-core (QD-856), so api_abuse_standing_http.go declares the same type and values there, and
// TestAbuseStandingTwinHoldsOperatorCoresValues holds them equal on both legs.

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// A network's §21.7 standing, as ServiceHost.Abuse and GET /abuse/status give it: operator-core's
// (owner decision 251), with its Known. The values are a format: server's model.AbuseStanding holds the
// same strings.
type AbuseStanding = operator.AbuseStanding

const (
	// Under 7 days old: probation's limits.
	AbuseStandingProbation = operator.AbuseStandingProbation
	// 7 or more days old, and 30 days without an action: the tier's defaults (§20).
	AbuseStandingStandard = operator.AbuseStandingStandard
	// A Team with a verified domain, paid 30 days and clean 90.
	AbuseStandingTrusted = operator.AbuseStandingTrusted
	// A network halt or a kill within 30 days: probation's limits.
	AbuseStandingRestricted = operator.AbuseStandingRestricted
	// A §8 suspension until reviewed.
	AbuseStandingSuspended = operator.AbuseStandingSuspended
)
