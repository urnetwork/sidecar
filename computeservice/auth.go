// §14.2's Auth row: who a compute request is. A sidecar's service token for the compute audience (DESIGN §7.8),
// verified offline through the host's Authenticator, names the sidecar; the broker reads its network, member, role,
// tags and admission flags from the newest verified state, behind ComputeAuthState, so a test runs on a fake and
// auth_state.go supplies the real one over the process's AclGateCache (C-09).
//
// The token is the exchange-minted bearer every DESIGN service verifies: the exchange checked the ClientKey's DPoP
// proof once, at the mint (§7.8). §14.2's "with its DPoP proof" per request, bound by cnf.jkt, waits for the review
// phase with its own replay family and row (compute-plan-compute-token-dpop, QD-1239), so no per-request proof is
// read here.
//
// Every answer of the state is three-valued, and only an answer of the state allows: a network whose state is not
// loaded answers 503, never an allow.
//
// Beside the caller, the broker reads §16.6's authorization features from the same state: a network whose newest
// base turns on a feature this release does not implement is held, 503 upgrade_required, until the broker updates.
//
// Two seams more, each failing closed until its area installs it: ComputeApprovalGate, §16.6's server gate for kinds
// 19 and 21 (CACL, with BAL's and ENC's effects), and ComputeAdmissionCheck, what every broker admission reads before
// its handler (CARCH-M12-01's abuse hold and region refusal).

package computeservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The audience a compute token carries (§7.8; CSRV-M12-03's exchange issues it).
const ComputeAudience = "compute"

// What the newest verified state says to one question.
type ComputeAuthAnswer int

const (
	// The state for the token's network is not loaded, or could not be read: 503, retryable, allowing nothing.
	ComputeAuthUnknown ComputeAuthAnswer = 0
	// The state agrees.
	ComputeAuthAllowed ComputeAuthAnswer = 1
	// The state disagrees: 403.
	ComputeAuthDenied ComputeAuthAnswer = 2
)

// A token one of whose subjects a rev/ object voids (§7.8): 401.
var ErrComputeTokenRevoked = errors.New("compute token revoked")

// §16.6's authorization features, by the bit ProjectionSettings.auth_features (field 3) carries.
type ComputeAuthFeatures uint32

const (
	// RepoCreate's kinds agents and agent and the inbox marker team (§20.4).
	ComputeAuthFeatureAgentRepos ComputeAuthFeatures = 1
	// §16.2's resources and actions and the document's compute block (§16.4): the broker is among its first gates.
	ComputeAuthFeatureComputePolicy ComputeAuthFeatures = 2
	// The listeners kind and listener: resource (§26.6).
	ComputeAuthFeatureListeners ComputeAuthFeatures = 4
	// Capability bit 3 and the enclave predicates (§11.4).
	ComputeAuthFeatureEnclaves ComputeAuthFeatures = 8
)

// The features this release of the broker implements, an identifier set and no tunable: compute_policy, which the
// broker enforces, and agent_repos and listeners, whose entries change nothing the broker reads and which its
// verified state takes through the root's log reader. enclaves joins when ENC's routes and the bit-3 incarnations'
// handling land (M14); until then a network that turns it on is held here. server's compute gate states the same set
// (CACL-M11-03's per-gate bits).
const ComputeFeaturesImplemented = ComputeAuthFeatureAgentRepos | ComputeAuthFeatureComputePolicy | ComputeAuthFeatureListeners

// Who a request is, from the token and the newest verified state. Immutable once the guard has it.
type ComputeCaller struct {
	// The token's.
	Principal *sidecar.Principal
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	SidecarId sidecar.Id
	// An untagged admission's member, the zero id for a tagged one.
	MemberId sidecar.Id
	// The member's role, MEMBER_ROLE_UNSPECIFIED for a tagged sidecar.
	Role bridge.MemberRole
	// A tagged admission's opaque tag ids, empty for an untagged one.
	TagIds []sidecar.Id
	// §8.5's consent: one of its member's consented devices.
	Consented bool
	// Capability bit 1: a page Worker's admission, which reads and deposits.
	ReadOnly  bool
	Ephemeral bool
	// Admitted under a Delegation (the row's delegation_id).
	DelegationAdmitted bool
	// Capability bit 3: an enclave incarnation (§11.4), which ComputeFeaturesImplemented does not yet take.
	EnclaveIncarnation bool
	// The verified state the caller was read from, for the areas' own reads of the projection; nil from a state that
	// keeps none, which an area reading it answers as unknown.
	Snapshot *sidecar.AclGateSnapshot
}

// Whether the caller is a tagged sidecar.
func (self *ComputeCaller) Tagged() bool {
	return 0 < len(self.TagIds)
}

// The newest verified authorization state the broker holds, per network. Safe for concurrent use. CheckRevocation
// may do I/O, under ctx; the others answer from memory, so they may run on every request.
type ComputeAuthState interface {
	// nil when no rev/ object voids the token's client, sidecar or member; ErrComputeTokenRevoked when one does; any
	// other error when the broker cannot tell, which answers 503.
	CheckRevocation(ctx context.Context, principal *sidecar.Principal) error
	// The caller when the newest verified state holds the token's ur_sidecar_id as an admitted, unrevoked sidecar of
	// the token's network in standing: not parked, suspended or past its not_after. Denied otherwise.
	Caller(principal *sidecar.Principal) (*ComputeCaller, ComputeAuthAnswer)
	// The authorization features the network's newest verified base turns on.
	Features(networkId sidecar.Id) (ComputeAuthFeatures, ComputeAuthAnswer)
}

// §16.6's server gate for the approval kinds the broker admits only with (19 and 21), over approval_use in the
// broker's database: CACL's, with BAL's and ENC's effects. Safe for concurrent use.
type ComputeApprovalGate interface {
	// nil admits; a refusal answers instead. Called after every other guard step, on the request's goroutine. For a
	// route whose approval is conditional, the gate decides whether the request needs one.
	Admit(request *ComputeRequest, kind ComputeApprovalKind) *ComputeRefusal
}

// What one broker admission reads before its handler: CARCH-M12-01's abuse hold and region refusal. nil admits; a
// refusal answers instead, and a check that cannot read what it needs refuses, unavailable. Runs on the request's
// goroutine after the gate, the groups and Idempotency-Key, so it reads only an admitted sidecar's request.
type ComputeAdmissionCheck func(request *ComputeRequest) *ComputeRefusal

// One registered check, by name.
type computeNamedAdmissionCheck struct {
	name  string
	check ComputeAdmissionCheck
}

// The checks areas registered, in registration order.
var computeAdmissionChecks = []*computeNamedAdmissionCheck{}

// Registers a check every admission route runs, from an area's file at init. An empty name, a name taken and a nil
// check panic.
func registerComputeAdmissionCheck(name string, check ComputeAdmissionCheck) {
	if name == "" || check == nil {
		panic(errors.New("a compute admission check needs a name and a function"))
	}
	for _, registered := range computeAdmissionChecks {
		if registered.name == name {
			panic(fmt.Errorf("compute admission check %q registered twice", name))
		}
	}
	computeAdmissionChecks = append(computeAdmissionChecks, &computeNamedAdmissionCheck{name: name, check: check})
}

// The gate an area registered, nil until one does.
var computeApprovalGate ComputeApprovalGate

// Installs §16.6's broker gate, from CACL's file at init. A second gate or a nil one panics.
func registerComputeApprovalGate(gate ComputeApprovalGate) {
	if gate == nil {
		panic(errors.New("a nil compute approval gate"))
	}
	if computeApprovalGate != nil {
		panic(errors.New("a second compute approval gate"))
	}
	computeApprovalGate = gate
}
