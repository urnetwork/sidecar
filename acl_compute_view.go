//go:build !ios_extension && !sidecar_http

// ComputePolicyView (DESIGN-COMPUTE §16.4, §16.5; D-CACL-4; CACL-M12-03): the network's compute block as each area
// reads it, typed, with §16.5's defaults wherever the network has neither document nor block, or its block leaves a key
// out:
//
//	models        the network's assurance_floor (none) and providers (`*`), which ComputeModelGate holds a remote
//	              model to beside the person's tee_only and allow (INFER's router, through InferComputeBlockSource)
//	enclaves      the enclaves' floor (AP, Q-PROV-2) and the shapes members may create (every one the policy offers)
//	search        on, every mode, the broker's day cap (Q-SRCH-4)
//	fetch         on, through auto egress (Q-FETCH-2)
//	calendar      on, through auto egress (§23)
//	connect       on, every service, service_call offered, members' own definitions, through auto egress (§25)
//	support       egress on, agents writing and attaching the log (§28.6)
//	approvals     the classifier deciding all five kinds, 23 to 27 (§27.10, CO-40)
//	disclosures   the network's acknowledgments, none by default (§2.8, CO-41), CTRUST-M12-02's to verify
//	history       a member's share of the network's storage, auto (Q-CTXH-16)
//	budgets       the policy's own; the defaults are BudgetSettings', which apply whatever the block says (§16.4)
//
// Sidecar.ComputePolicy reads the block the device's verified head compiled. A device that has not read its head yet
// answers ErrComputePolicyUnread rather than the defaults, so a block that narrows is never read as wide before it
// arrives: every remote call and every switch a consumer reads through it fails closed until then.
//
// A view is a value nothing changes: safe for concurrent use. Device legs only; the forwarding role and the page
// Worker run no compute.

package sidecar

import (
	"context"
	"errors"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The device has not read its network's verified config head yet, so it cannot say what the compute block allows.
var ErrComputePolicyUnread = errors.New("the network's compute policy has not been read on this device yet")

// The network's compute block as one device reads it.
type ComputePolicyView struct {
	// nil for none: §16.5's defaults
	block *AclComputeBlock
	// whether the network's compute_policy feature is on at the state the view read
	featureOn bool
}

// The view of block, nil for none, under a state where the compute_policy feature is on or off.
func NewComputePolicyView(block *AclComputeBlock, featureOn bool) *ComputePolicyView {
	return &ComputePolicyView{block: block, featureOn: featureOn}
}

// The view of this device's network, from the block its verified config head compiled: ErrComputePolicyUnread while
// no follower stands, no state is verified or no head compiled.
func (self *Sidecar) ComputePolicy() (*ComputePolicyView, error) {
	follower := self.ConfigFollower()
	if follower == nil {
		return nil, ErrComputePolicyUnread
	}
	state := follower.VerifiedState()
	local := follower.AclLocal()
	if state == nil || local == nil {
		return nil, ErrComputePolicyUnread
	}
	return NewComputePolicyView(local.Compute, state.AuthFeatureOn(AuthFeatureComputePolicy)), nil
}

// The block, nil for none. The caller must not change it.
func (self *ComputePolicyView) Block() *AclComputeBlock {
	return self.block
}

// Whether the network's compute_policy feature is on: before it, no block exists and every key reads its default.
func (self *ComputePolicyView) FeatureOn() bool {
	return self.featureOn
}

// The label a ComputeAssurance names, fallback for 0.
func computePolicyLabel(assurance protocol.ComputeAssurance, fallback ComputeLabel) ComputeLabel {
	switch assurance {
	case protocol.ComputeAssurance_COMPUTE_ASSURANCE_NONE:
		return ComputeLabelNone
	case protocol.ComputeAssurance_COMPUTE_ASSURANCE_AP:
		return ComputeLabelAp
	case protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1:
		return ComputeLabelA1
	case protocol.ComputeAssurance_COMPUTE_ASSURANCE_A2:
		return ComputeLabelA2
	}
	return fallback
}

// The network's floor and providers for ComputeModelGate: none and `*` unless the block says (CO-18, Q-CACL-3's (a)).
func (self *ComputePolicyView) NetworkModels() *ComputeNetworkModels {
	models := DefaultComputeNetworkModels()
	if self.block == nil {
		return models
	}
	models.Floor = computePolicyLabel(self.block.AssuranceFloor, models.Floor)
	if self.block.Providers != nil {
		models.Providers = slices.Clone(self.block.Providers)
	}
	return models
}

// The enclaves' floor: AP unless the block raises it (Q-PROV-2).
func (self *ComputePolicyView) EnclaveFloor() ComputeLabel {
	if self.block == nil {
		return ComputeLabelAp
	}
	return computePolicyLabel(self.block.EnclaveAssuranceFloor, ComputeLabelAp)
}

// The shapes members may create, nil for every one the policy offers.
func (self *ComputePolicyView) EnclaveShapes() []string {
	if self.block == nil {
		return nil
	}
	return slices.Clone(self.block.EnclaveShapes)
}

// Whether a shape may be created: any while the block names none.
func (self *ComputePolicyView) AllowsEnclaveShape(shape string) bool {
	shapes := self.EnclaveShapes()
	return shapes == nil || slices.Contains(shapes, shape)
}

// Search as the network allows it (§21.9).
type ComputeSearchPolicy struct {
	Enabled bool
	// Nil for every mode.
	Modes []string
	// 0 for the broker's own cap.
	DayMax uint32
}

// Search: on, every mode, the broker's cap, unless the block says.
func (self *ComputePolicyView) Search() *ComputeSearchPolicy {
	search := &ComputeSearchPolicy{Enabled: true}
	if self.block == nil || self.block.Search == nil {
		return search
	}
	if self.block.Search.Enabled != nil {
		search.Enabled = *self.block.Search.Enabled
	}
	search.Modes = slices.Clone(self.block.Search.Modes)
	search.DayMax = self.block.Search.DayMax
	return search
}

// Whether search runs in mode: search on, and the mode among the block's, or any where it names none.
func (self *ComputePolicyView) AllowsSearchMode(mode string) bool {
	search := self.Search()
	return search.Enabled && (search.Modes == nil || slices.Contains(search.Modes, mode))
}

// A tool's switch and egress (§22, §23.7, §25.8).
type ComputeRoutePolicy struct {
	Enabled bool
	Egress  AclComputeEgress
	// Under exits, the exit as the block writes it: a tag: or sidecar: selector; empty otherwise.
	Exit string
}

// A route's policy from the block's, its defaults on and auto.
func computeRoutePolicyOf(route *AclComputeRoute) *ComputeRoutePolicy {
	policy := &ComputeRoutePolicy{Enabled: true, Egress: AclComputeEgressAuto}
	if route == nil {
		return policy
	}
	if route.Enabled != nil {
		policy.Enabled = *route.Enabled
	}
	if route.Egress != "" {
		policy.Egress = route.Egress
	}
	if route.Exit != nil {
		policy.Exit = route.Exit.String()
	}
	return policy
}

// Fetch: on, through auto egress, unless the block says (Q-FETCH-2).
func (self *ComputePolicyView) Fetch() *ComputeRoutePolicy {
	if self.block == nil {
		return computeRoutePolicyOf(nil)
	}
	return computeRoutePolicyOf(self.block.Fetch)
}

// The calendar's tools: on, through auto egress, unless the block says.
func (self *ComputePolicyView) Calendar() *ComputeRoutePolicy {
	if self.block == nil {
		return computeRoutePolicyOf(nil)
	}
	return computeRoutePolicyOf(self.block.Calendar)
}

// Connections as the network allows them (§25.8).
type ComputeConnectPolicy struct {
	ComputeRoutePolicy
	// Nil for every service the policy lists.
	Services []string
	// service_call offered, and members' own definitions on desktops.
	Generic bool
	Custom  bool
}

// Connections: on, every service, service_call and own definitions, through auto egress, unless the block says.
func (self *ComputePolicyView) Connect() *ComputeConnectPolicy {
	connect := &ComputeConnectPolicy{ComputeRoutePolicy: *computeRoutePolicyOf(nil), Generic: true, Custom: true}
	if self.block == nil || self.block.Connect == nil {
		return connect
	}
	block := self.block.Connect
	connect.ComputeRoutePolicy = *computeRoutePolicyOf(&block.AclComputeRoute)
	if block.Services != nil && !slices.Contains(block.Services, aclComputeEvery) {
		connect.Services = slices.Clone(block.Services)
	}
	if block.Generic != nil {
		connect.Generic = *block.Generic
	}
	if block.Custom != nil {
		connect.Custom = *block.Custom
	}
	return connect
}

// Whether members may connect service: connections on, and the service among the block's, or any where it names none.
func (self *ComputePolicyView) AllowsService(service string) bool {
	connect := self.Connect()
	return connect.Enabled && (connect.Services == nil || slices.Contains(connect.Services, service))
}

// Support as the network allows it (§28.6): it only narrows the person's own support key.
type ComputeSupportPolicy struct {
	// FB section 5's feedback.egress: on, persons, auto_only or off.
	Egress string
	Agents bool
	Logs   bool
}

// Support: egress on, agents writing and attaching the log, unless the block says.
func (self *ComputePolicyView) Support() *ComputeSupportPolicy {
	support := &ComputeSupportPolicy{Egress: "on", Agents: true, Logs: true}
	if self.block == nil || self.block.Support == nil {
		return support
	}
	if self.block.Support.Egress != "" {
		support.Egress = self.block.Support.Egress
	}
	if self.block.Support.Agents != nil {
		support.Agents = *self.block.Support.Agents
	}
	if self.block.Support.Logs != nil {
		support.Logs = *self.block.Support.Logs
	}
	return support
}

// The kinds the safety classifier may decide in the network's tainted runs (§27.10): all five unless the block names
// fewer, an empty list sending every such approval to a person.
func (self *ComputePolicyView) ApprovalsAuto() []SidecarActionKind {
	if self.block == nil || self.block.Approvals == nil {
		return slices.Clone(aclComputeApprovalKindsAll)
	}
	return slices.Clone(self.block.Approvals.Auto)
}

// Whether the classifier may decide kind's approvals in this network.
func (self *ComputePolicyView) ApprovalAutoAllowed(kind SidecarActionKind) bool {
	return slices.Contains(self.ApprovalsAuto(), kind)
}

// The network's acknowledgments, by id as the block writes them; none by default.
func (self *ComputePolicyView) Disclosures() []AclComputeDisclosure {
	if self.block == nil {
		return []AclComputeDisclosure{}
	}
	return slices.Clone(self.block.Disclosures)
}

// The statement the network holds for disclosure id, and whether it holds one: opaque here, CTRUST-M12-02's to verify.
func (self *ComputePolicyView) Disclosure(id string) (string, bool) {
	for _, disclosure := range self.Disclosures() {
		if disclosure.Id == id {
			return disclosure.Statement, true
		}
	}
	return "", false
}

// A member's share of the network's storage for history, as CTXH's caps read it (Q-CTXH-16): auto unless the block
// sets one.
func (self *ComputePolicyView) MemberShare() *SessionMemberShare {
	if self.block == nil || self.block.History == nil || self.block.History.MemberShareAuto {
		return &SessionMemberShare{Auto: true}
	}
	return &SessionMemberShare{Fraction: float64(self.block.History.MemberSharePpm) / float64(aclComputePpmWhole)}
}

// The policy's own budgets, in the order written; §16.5's defaults are BudgetSettings' (ComputeBudgetsFor).
func (self *ComputePolicyView) Budgets() []AclComputeBudget {
	if self.block == nil {
		return []AclComputeBudget{}
	}
	return slices.Clone(self.block.Budgets)
}

// The network's floor and providers for INFER's router (InferComputeBlockSource), read at each check.
type sidecarComputeBlockSource struct {
	sidecar *Sidecar
}

// See InferComputeBlockSource: ErrComputePolicyUnread until the device has read its head, which refuses every remote
// call and never a local one.
func (self *sidecarComputeBlockSource) ComputeNetworkModels(ctx context.Context) (*ComputeNetworkModels, error) {
	view, err := self.sidecar.ComputePolicy()
	if err != nil {
		return nil, err
	}
	return view.NetworkModels(), nil
}

// Wires the network's compute block into the router's checks (§6.4, D-CACL-4): CACL-M12-03's InferComputeBlockSource.
func init() {
	registerInferCheckSources("cacl-compute-block", func(sidecar *Sidecar, sources *InferCheckSources) error {
		sources.ComputeBlock = &sidecarComputeBlockSource{sidecar: sidecar}
		return nil
	})
}
