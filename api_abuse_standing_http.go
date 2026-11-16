//go:build sidecar_http && !ios_extension

// A network's §21.7 standing on the sidecar_http leg: the twin of api_abuse_standing.go, whose type is
// operator-core's. This leg, the page Worker's sdk.wasm, links no operator-core (QD-856), so it
// declares the same type, the same values and the same Known, which
// TestAbuseStandingTwinHoldsOperatorCoresValues holds on both legs.

package sidecar

// A network's §21.7 standing, as GET /abuse/status gives it. The values are a format: server's
// model.AbuseStanding and operator-core's hold the same strings.
type AbuseStanding string

const (
	// Under 7 days old: probation's limits.
	AbuseStandingProbation AbuseStanding = "probation"
	// 7 or more days old, and 30 days without an action: the tier's defaults (§20).
	AbuseStandingStandard AbuseStanding = "standard"
	// A Team with a verified domain, paid 30 days and clean 90.
	AbuseStandingTrusted AbuseStanding = "trusted"
	// A network halt or a kill within 30 days: probation's limits.
	AbuseStandingRestricted AbuseStanding = "restricted"
	// A §8 suspension until reviewed.
	AbuseStandingSuspended AbuseStanding = "suspended"
)

// Whether this build knows the standing. A reader refuses one it does not, so a standing added later
// never passes an older build.
func (self AbuseStanding) Known() bool {
	switch self {
	case AbuseStandingProbation, AbuseStandingStandard, AbuseStandingTrusted, AbuseStandingRestricted, AbuseStandingSuspended:
		return true
	}
	return false
}
