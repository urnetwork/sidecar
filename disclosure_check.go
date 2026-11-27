//go:build !ios_extension && !sidecar_http

// The disclosure check (DESIGN-COMPUTE §2.8's where-checked, refusal and new-version rows; R-CCTX-25, D-CTRUST-3,
// D-CTRUST-4, IC-21, IC-22; CTRUST-M12-01), run on the device that would send, before a request is built, so nothing
// leaves the device unchecked:
//
//	asks      an id that asks nothing is covered
//	whose     the acknowledgments that cover this sidecar are its member's where it reads its member's vault, an
//	          untagged member device (and from M14 the member's agents' enclave, which never takes the network's); else
//	          the network's, an Owner's or Admin's, on a tagged or cloud sidecar, which reads no vault (CO-41): the
//	          entries of the compute block ComputeNetworkDisclosures takes (disclosure_network.go), so with none such a
//	          sidecar is refused, naming --network
//	covered   at the current version, or at the previous one while now is before the instant the current version took
//	          effect plus its grace days (QD-1242's since_ms; 14 unless the signers set 0, and 0 where the policy names
//	          no instant, so a new version refuses at once); a revision changes nothing
//	verdict   covered; or askable, on the person's scope alone, by a caller with a person attached to its run, who
//	          raises §7.6's disclosure request (HARN) and waits on ComputeDisclosureAcks.Await; or, for any other caller,
//	          DisclosureRequiredError: the id, its version, its summary in the caller's locale and the fix
//	no policy every check is disclosure_required, wrapping policy_unavailable
//
// Not the broker's (Q-CTRUST-2): no acknowledgment state reaches a server. The check fills the seams its callers read:
// INFER's InferAcknowledgments, the Harness's HarnessDisclosureAcks and the support client's SupportDisclosureSource;
// LSTN, SAFE, SRCH, CONN, GW and ENC call ComputeDisclosureCheck as they land. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// A day of a disclosure's grace: a unit, not a tunable.
const computeDisclosureGraceDay = 24 * time.Hour

// Whose acknowledgments cover this sidecar's uses (§2.8).
type ComputeDisclosureScope string

const (
	// The member's own compute.disclosures, read from their vault: an untagged member device, and an agents' enclave
	// its sponsor's.
	ComputeDisclosureScopePerson ComputeDisclosureScope = "person"
	// The network's, an Owner's or Admin's, on a tagged or cloud sidecar, which reads no vault (CTRUST-M12-02).
	ComputeDisclosureScopeNetwork ComputeDisclosureScope = "network"
)

// What every refusal for want of an acknowledgment is, errors.Is with DisclosureRequiredError.
var ErrDisclosureRequired = errors.New(ComputeDisclosureCodeRequired)

// disclosure_required (§2.8's refusal row): the id, its version, its summary in the caller's locale and the fix, which
// names `ur disclosures ack <id>` and the app's settings, or on a tagged or cloud sidecar an Owner's or Admin's `--network`.
// Callers check before they build a request, so nothing left the device. errors.Is with ErrDisclosureRequired; where
// the policy holds nothing to acknowledge, also with its reason (ErrComputeDisclosurePolicyUnavailable and the rest).
type DisclosureRequiredError struct {
	Id string
	// The current version, 0 where the policy holds none.
	Version uint32
	// The summary line in the caller's locale, empty where the policy holds none.
	Summary string
	// Whose acknowledgment is missing.
	Scope ComputeDisclosureScope
	// Why there is nothing to acknowledge, nil where there is.
	cause error
}

// The code, the id and version, the summary and the fix.
func (self *DisclosureRequiredError) Error() string {
	if self.cause != nil {
		return fmt.Sprintf("%s: %s cannot be acknowledged: %v", ComputeDisclosureCodeRequired, self.Id, self.cause)
	}
	return fmt.Sprintf("%s: %s version %d is not acknowledged (%s); %s", ComputeDisclosureCodeRequired, self.Id,
		self.Version, self.Summary, self.Fix())
}

// What fixes it, in words: who acknowledges, and where.
func (self *DisclosureRequiredError) Fix() string {
	if self.Scope == ComputeDisclosureScopeNetwork {
		return fmt.Sprintf("an Owner or Admin acknowledges it for the network, in the app's network settings or with ur disclosures ack %s --network", self.Id)
	}
	return fmt.Sprintf("the person acknowledges it in the app's settings, or with ur disclosures ack %s", self.Id)
}

// Matches ErrDisclosureRequired.
func (self *DisclosureRequiredError) Is(target error) bool {
	return target == ErrDisclosureRequired
}

// The reason there is nothing to acknowledge, nil where there is.
func (self *DisclosureRequiredError) Unwrap() error {
	return self.cause
}

// One check's answer for one id.
type ComputeDisclosureVerdict struct {
	Id string
	// The current version.
	Version uint32
	// Whether the id waits for an acknowledgment at all.
	Asks bool
	// Whose acknowledgments cover this sidecar.
	Scope ComputeDisclosureScope
	// The version they hold, 0 for none.
	Acknowledged uint32
	// Whether this use may go ahead.
	Covered bool
	// Covered only by the previous version's acknowledgment, until GraceEnd.
	InGrace  bool
	GraceEnd time.Time
	// Not covered, and a person attached to the caller's run may be asked (§7.6's disclosure request): the person's
	// scope alone, since no person sits at a tagged or cloud sidecar.
	Askable bool
	// The id's lines are marked changed.
	Changed bool
}

// The refusal for a caller that may not ask, in locale.
func (self *ComputeDisclosureVerdict) Required(summary string) *DisclosureRequiredError {
	return &DisclosureRequiredError{Id: self.Id, Version: self.Version, Summary: summary, Scope: self.Scope}
}

// Whether acknowledged covers disclosure at now, and where only the previous version's grace does, when it ends (the
// file header's covered row).
func computeDisclosureCovered(acknowledged uint32, disclosure *ComputeDisclosure, now time.Time) (bool, time.Time) {
	version := disclosure.Version()
	switch {
	case version <= acknowledged:
		return true, time.Time{}
	case acknowledged == 0 || acknowledged+1 != version || disclosure.Entry.GraceDays == 0 || disclosure.Entry.SinceMs <= 0:
		// no instant to run a grace from is a grace of 0, the closed reading
		return false, time.Time{}
	}
	graceEnd := disclosure.Since().Add(time.Duration(disclosure.Entry.GraceDays) * computeDisclosureGraceDay)
	if now.Before(graceEnd) {
		return true, graceEnd
	}
	return false, time.Time{}
}

// The network's acknowledgments a tagged or cloud sidecar takes, by id the version a taken entry names at this device's
// verified state, which the check holds to the current version or the previous one within its grace
// (ComputeNetworkDisclosures).
type ComputeNetworkDisclosureAcks interface {
	Versions(ctx context.Context) (map[string]uint32, error)
}

// A ComputeNetworkDisclosureAcks that lists its entries too, as the Sidecar's does: what the lists name of each id's
// network acknowledgment.
type computeNetworkDisclosureEntries interface {
	Entries(ctx context.Context) ([]*ComputeNetworkDisclosure, error)
}

// What a check is built on.
type ComputeDisclosureCheckArgs struct {
	// Required.
	Registry *ComputeDisclosureRegistry
	// The person's. Required.
	Acks *ComputeDisclosureAcks
	// The network's (ComputeNetworkDisclosures); nil, a tagged or cloud sidecar has none.
	Network ComputeNetworkDisclosureAcks
	// The changed marks; nil marks nothing.
	marks *computeDisclosureMarks
	// The check's time: the gate's, the device's clock never earlier than its floors; nil reads real time.
	Now func() time.Time
}

// The check on the device that would send. See the file header.
type ComputeDisclosureCheck struct {
	registry *ComputeDisclosureRegistry
	acks     *ComputeDisclosureAcks
	network  ComputeNetworkDisclosureAcks
	marks    *computeDisclosureMarks
	now      func() time.Time
}

// A check over args.
func NewComputeDisclosureCheck(args *ComputeDisclosureCheckArgs) (*ComputeDisclosureCheck, error) {
	if args == nil || args.Registry == nil || args.Acks == nil {
		return nil, errors.New("compute disclosure check: a registry and the acknowledgments")
	}
	now := args.Now
	if now == nil {
		now = RealClock{}.Now
	}
	return &ComputeDisclosureCheck{registry: args.Registry, acks: args.Acks, network: args.Network, marks: args.marks, now: now}, nil
}

// Whose acknowledgments cover this sidecar, and the versions they hold. An error reads nothing.
func (self *ComputeDisclosureCheck) covering(ctx context.Context) (ComputeDisclosureScope, map[string]uint32, error) {
	read, err := self.acks.Read(ctx)
	if err != nil {
		return "", nil, err
	}
	if read.Source != MemberHarnessConfigSourceNoVault {
		return ComputeDisclosureScopePerson, read.Versions, nil
	}
	// a tagged or cloud sidecar: the network's, never a person's
	if self.network == nil {
		return ComputeDisclosureScopeNetwork, map[string]uint32{}, nil
	}
	versions, err := self.network.Versions(ctx)
	if err != nil {
		return "", nil, err
	}
	return ComputeDisclosureScopeNetwork, versions, nil
}

// The verdict for one use of id on this sidecar now (the file header's rows). Where the policy holds nothing to
// acknowledge, a DisclosureRequiredError with its reason; where the acknowledgments do not read, that error, and the
// caller refuses.
func (self *ComputeDisclosureCheck) Check(ctx context.Context, id string) (*ComputeDisclosureVerdict, error) {
	disclosure, err := self.registry.Disclosure(id)
	if err != nil {
		if errors.Is(err, ErrComputeDisclosureIdInvalid) {
			return nil, err
		}
		return nil, &DisclosureRequiredError{Id: id, cause: err}
	}
	verdict := &ComputeDisclosureVerdict{Id: disclosure.Id.String(), Version: disclosure.Version(), Asks: disclosure.Asks}
	scope, versions, readErr := self.covering(ctx)
	if readErr == nil {
		verdict.Scope, verdict.Acknowledged = scope, versions[verdict.Id]
	}
	if self.marks != nil {
		// every line of a disclosure is marked at a new version, one that asks nothing included
		verdict.Changed = self.marks.changed([]*ComputeDisclosure{disclosure}, versions)[verdict.Id]
	}
	if !disclosure.Asks {
		verdict.Covered = true
		return verdict, nil
	}
	if readErr != nil {
		return nil, readErr
	}
	verdict.Covered, verdict.GraceEnd = computeDisclosureCovered(verdict.Acknowledged, disclosure, self.now())
	verdict.InGrace = verdict.Covered && verdict.Acknowledged < verdict.Version
	verdict.Askable = !verdict.Covered && scope == ComputeDisclosureScopePerson
	return verdict, nil
}

// nil where a use of id is covered now; else, for a caller that may not ask, the DisclosureRequiredError naming its
// summary in locale and the fix.
func (self *ComputeDisclosureCheck) Require(ctx context.Context, id string, locale string) error {
	verdict, err := self.Check(ctx, id)
	if err != nil {
		return err
	}
	if verdict.Covered {
		return nil
	}
	summary, _ := self.registry.Line(id, locale)
	return verdict.Required(summary)
}

// The check's component parts on a Sidecar, built with the registry's component (disclosure_registry.go).
func newComputeDisclosureParts(sidecar *Sidecar, registry *ComputeDisclosureRegistry, settings *ComputeDisclosureSettings) (*ComputeDisclosureAcks, *computeDisclosureMarks, *ComputeDisclosureCheck, error) {
	acks, err := NewComputeDisclosureAcks(&ComputeDisclosureAcksArgs{
		Store:    sidecar.MemberHarnessConfig,
		Registry: registry,
		Watch: func(vaultId Id, notify func()) func() {
			client := sidecar.EvsClient()
			if client == nil {
				return func() {}
			}
			return client.AddRepoChangeListener(&vaultId, func(change *EvsRepoChange) { notify() })
		},
		Settings: settings,
		Clock:    sidecar.clock,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	marks := &computeDisclosureMarks{
		store: func() (SidecarStore, error) {
			return sidecar.LocalStore().Directory(computeDisclosureMarksDirectory, computeDisclosureMarksClass)
		},
		settings: settings,
	}
	check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{
		Registry: registry,
		Acks:     acks,
		Network:  &computeNetworkDisclosureSidecarAcks{sidecar: sidecar},
		marks:    marks,
		Now: func() time.Time {
			gate, err := sidecar.ComputePolicyGate()
			if err != nil {
				return sidecar.clock.Now()
			}
			return gate.Now()
		},
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return acks, marks, check, nil
}

// This Sidecar's disclosure check, or an error wrapping ErrComputeComponentUnavailable that says why there is none:
// with none, nothing that waits on a disclosure goes ahead.
func (self *Sidecar) ComputeDisclosureCheck() (*ComputeDisclosureCheck, error) {
	component, err := self.computeDisclosures()
	if err != nil {
		return nil, err
	}
	return component.check, nil
}

// This Sidecar's person's acknowledgments, for HARN's disclosure request and LSTN's publisher (Await).
func (self *Sidecar) ComputeDisclosureAcks() (*ComputeDisclosureAcks, error) {
	component, err := self.computeDisclosures()
	if err != nil {
		return nil, err
	}
	return component.acks, nil
}

// The person's acknowledgment of a disclosure, their own act alone (ComputeDisclosureAcks.Ack).
func (self *Sidecar) AckComputeDisclosure(ctx context.Context, args *ComputeDisclosureAckArgs) error {
	component, err := self.computeDisclosures()
	if err != nil {
		return err
	}
	return component.acks.Ack(ctx, args)
}

// Records that the person opened id's whole text at version, the current one, which ends its lines' changed mark
// (§2.8's always-shown row); ErrDisclosureChanged for another version. Only the person's act opens a text.
func (self *Sidecar) OpenedComputeDisclosure(ctx context.Context, id string, version uint32, origin SidecarActOrigin) error {
	if origin != SidecarActConfirmed {
		return fmt.Errorf("%w: only the person opens a disclosure's text", ErrDisclosureAckRefused)
	}
	component, err := self.computeDisclosures()
	if err != nil {
		return err
	}
	disclosure, err := component.registry.Disclosure(id)
	if err != nil {
		return err
	}
	if disclosure.Version() != version {
		return ErrDisclosureChanged
	}
	disclosures, err := component.registry.Disclosures()
	if err != nil {
		return err
	}
	keepIds := []string{}
	for _, held := range disclosures {
		keepIds = append(keepIds, held.Id.String())
	}
	return component.marks.opened(disclosure.Id.String(), version, keepIds)
}

// The disclosure fields of list, whose views are disclosures', index for index: each view's acknowledged version, whose,
// whether it is covered now and whether its lines are marked changed, and the network's acknowledgment where its block
// holds one. Acknowledgments that do not read leave each view unacknowledged and, where it asks, not covered, the
// closed reading; a network state that does not read names no network acknowledgment.
func (self *computeDisclosureComponent) withAcks(ctx context.Context, list *ComputeDisclosureList, disclosures []*ComputeDisclosure) *ComputeDisclosureList {
	scope, versions, err := self.check.covering(ctx)
	if err != nil {
		if self.sidecar.log.V(1).Enabled() {
			self.sidecar.log.Infof("[disclosure]the acknowledgments do not read: %s", err)
		}
		scope, versions = "", map[string]uint32{}
	}
	idChanged := self.marks.changed(disclosures, versions)
	now := self.check.now()
	idNetworks := map[string]*ComputeNetworkDisclosure{}
	if network, ok := self.check.network.(computeNetworkDisclosureEntries); ok {
		entries, err := network.Entries(ctx)
		if err != nil && self.sidecar.log.V(1).Enabled() {
			self.sidecar.log.Infof("[disclosure]the network's acknowledgments do not read: %s", err)
		}
		for _, entry := range entries {
			idNetworks[entry.Id] = entry
		}
	}
	for i, view := range list.Disclosures {
		view.Scope, view.Acknowledged, view.Changed = scope, versions[view.Id], idChanged[view.Id]
		view.Covered = !view.Asks
		if view.Asks && scope != "" {
			view.Covered, _ = computeDisclosureCovered(view.Acknowledged, disclosures[i], now)
		}
		view.Network = idNetworks[view.Id]
	}
	return list
}

// The names the check's seams register under.
const computeDisclosureSourcesName = "disclosures"

// Fills INFER's acknowledgments and the Harness's Await from this file.
func init() {
	registerInferCheckSources(computeDisclosureSourcesName, func(sidecar *Sidecar, sources *InferCheckSources) error {
		sources.Acknowledgments = &computeDisclosureInferAcks{sidecar: sidecar}
		return nil
	})
	RegisterHarnessSources(computeDisclosureSourcesName, func(sidecar *Sidecar, sources *HarnessSources) error {
		sources.Acks = &computeDisclosureHarnessAcks{sidecar: sidecar}
		return nil
	})
}

// INFER's InferAcknowledgments over a Sidecar's check, read at use.
type computeDisclosureInferAcks struct {
	sidecar *Sidecar
}

// See InferAcknowledgments: the person's on a member's device, the network's on a tagged or cloud sidecar.
func (self *computeDisclosureInferAcks) Covering(ctx context.Context) (*InferAcknowledgmentSet, error) {
	check, err := self.sidecar.ComputeDisclosureCheck()
	if err != nil {
		return nil, err
	}
	scope, versions, err := check.covering(ctx)
	if err != nil {
		return nil, err
	}
	set := &InferAcknowledgmentSet{Scope: InferAcknowledgmentPerson, Versions: versions}
	if scope == ComputeDisclosureScopeNetwork {
		set.Scope = InferAcknowledgmentNetwork
	}
	return set, nil
}

// The Harness's HarnessDisclosureAcks over a Sidecar's acknowledgments, read at use.
type computeDisclosureHarnessAcks struct {
	sidecar *Sidecar
}

// See HarnessDisclosureAcks: on a tagged or cloud sidecar no person acknowledges, so it answers disclosure_required at
// once rather than wait.
func (self *computeDisclosureHarnessAcks) Await(ctx context.Context, id string, version uint32) error {
	check, err := self.sidecar.ComputeDisclosureCheck()
	if err != nil {
		return err
	}
	scope, _, err := check.covering(ctx)
	if err != nil {
		return err
	}
	if scope != ComputeDisclosureScopePerson {
		return &DisclosureRequiredError{Id: id, Version: version, Scope: scope}
	}
	return check.acks.Await(ctx, id, version)
}

// The support client's SupportDisclosureSource over a Sidecar's check (support_component.go wires it): support's
// current version, 0 where the policy does not carry it, and the version the acknowledgments that cover this sidecar
// hold. Support's grace is 0 (§28.13), the client's own rule.
type computeDisclosureSupportSource struct {
	sidecar *Sidecar
}

// See SupportDisclosureSource, read within SourceReadTimeout, since the client passes no context.
func (self *computeDisclosureSupportSource) SupportDisclosure() (*SupportDisclosureState, error) {
	component, err := self.sidecar.computeDisclosures()
	if err != nil {
		return nil, err
	}
	state := &SupportDisclosureState{}
	disclosure, err := component.registry.Disclosure(SupportDisclosureId)
	if err != nil {
		// nothing to acknowledge: no message goes
		return state, nil
	}
	state.Current = disclosure.Version()
	ctx, cancel := context.WithTimeout(context.Background(), component.settings.SourceReadTimeout)
	defer cancel()
	_, versions, err := component.check.covering(ctx)
	if err != nil {
		return nil, err
	}
	state.Acknowledged = versions[SupportDisclosureId]
	return state, nil
}
