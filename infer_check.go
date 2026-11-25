//go:build !ios_extension && !sidecar_http

// The router's checks (DESIGN-COMPUTE §6.4, R-INFER-3, R-INFER-8, D-INFER-6, D-INFER-7, D-PROV-1, IC-5, IC-20), which
// every call passes before a route is chosen, and again, through InferRouter.Check, before the gateway's retry joins or
// replays another call (§8.5) and before the Harness's agent_launch and SetModel take a model, so one check covers every
// way a run reaches a model: its first pick, SetModel, §7.4's failure choice, a continuation or a fork, in an enclave
// too, a child's launch, a gateway call, mail read or not (§23.5).
//
// A local model is checked against the person's allow alone (CO-9, IC-5): it runs under every floor and tee_only, past
// every budget, in every state of the balance, whatever a run's marks say, and asks no disclosure, since nothing leaves
// the device. A remote model passes, in this order:
//
//  1. the newest verified policy covers it, its label read from the policy and never from the unsigned catalog, and the
//     policy's remote-work gate lets its path run (§5.4): else model_refused, rule policy;
//  2. its label meets the network's assurance_floor and the person's tee_only, its provider is among the network's
//     providers, and its name matches the person's allow (CACL's ComputeModelGate, D-CACL-4): else model_refused naming
//     the rule;
//  3. the device-side budgets it spends from have room (§16.4: the device enforces budgets before it asks): else
//     insufficient_quota, reason budget;
//  4. a run carrying a connected service's limited_use mark reaches only a model the policy's limited_use line lists,
//     whatever its label, AP included; a gateway call checks the union of the marks of every run its binding may name
//     (§25.10, §8.9): else service_model (infer_check_marks.go);
//  5. a model labeled none waits for its provider's disclosure to be acknowledged (CO-34, infer_check_disclosure.go),
//     asking where a person is attached to the run, else disclosure_required.
//
// The order is §6.4's but for the limited_use mark, which comes before the disclosure here, so a person is never asked
// to acknowledge a disclosure for a call the mark refuses anyway: every refusal that needs no one goes first.
//
// The facts come from InferCheckSources, seams the owning areas fill. This build wires the policy and its gate
// (ATTEST's ComputePolicyGate) and the person's models key (CACL's Sidecar.ModelsKey) itself; the network's compute
// block, the device-side budgets, the acknowledgments, the run marks and the person attached to a run install from
// their owners' files through registerInferCheckSources. A source not wired refuses every remote call and never a
// local one. Nothing here writes an acknowledgment or the models key, and no remote call files an approval (Q-CACL-1).
//
// Safe for concurrent use: the sources are fixed when the checks are built.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// What model_refused's reason names, beside CACL's ComputeModelRule values (floor, provider, tee_only, allow).
const (
	// The newest verified policy does not cover the model, or no policy lets remote work run.
	InferRefusedRulePolicy = "policy"
	// A source the check needs is not wired, or did not read.
	InferRefusedRuleSource = "source"
	// The run's marks did not read.
	InferRefusedRuleMarks = "marks"
	// The policy carries no disclosure for the provider.
	InferRefusedRuleDisclosure = "disclosure"
)

// The newest verified compute policy and the remote-work gate (ATTEST's ComputePolicyGate, §5.4).
type InferPolicySource interface {
	// The newest verified policy while it is current; an error with none.
	PolicyCurrent() (*ComputePolicy, error)
	// Nil where remote work of operation may run now; else why not.
	RemoteWork(ctx context.Context, operation ComputeRemoteOperation) error
	// The gate's time: the device's clock, never earlier than its floors.
	Now() time.Time
}

// The person's models key (§16.4), as this device reads it now: CACL's Sidecar.ModelsKey.
type InferModelsKeySource interface {
	ModelsKey(ctx context.Context) (*HarnessModelsKeyRead, error)
}

// The network's compute block (§16.4): its assurance_floor and providers, CO-18's defaults where the network has none.
// CACL's projection reader fills it (CACL-M12-03).
type InferComputeBlockSource interface {
	ComputeNetworkModels(ctx context.Context) (*ComputeNetworkModels, error)
}

// The device-side budgets (§16.4), which the device enforces before it asks, so most refusals never reach the broker.
// CACL's budget counters fill it.
type InferBudgetGate interface {
	// Nil where every budget call spends from, its Request.Budget's and its agent's and device's, has room for its
	// worst case; else an *InferError, insufficient_quota with reason budget, naming the budget and its period.
	Admit(ctx context.Context, call *InferCall) error
}

// Whose acknowledgments cover this sidecar's calls (§2.8, CO-41).
type InferAcknowledgmentScope string

const (
	// The member's own compute.disclosures, on their own devices.
	InferAcknowledgmentPerson InferAcknowledgmentScope = "person"
	// An agents' enclave's sponsor's, which it reads from the sponsor's vault (§11.4).
	InferAcknowledgmentSponsor InferAcknowledgmentScope = "sponsor"
	// The network's, an Owner's or Admin's, on a tagged or cloud sidecar, which reads no vault.
	InferAcknowledgmentNetwork InferAcknowledgmentScope = "network"
)

// The acknowledgments that cover this sidecar's calls now.
type InferAcknowledgmentSet struct {
	Scope InferAcknowledgmentScope
	// By disclosure id, the version acknowledged.
	Versions map[string]uint32
}

// The acknowledgments that cover this sidecar's calls (§2.8): the person's on their own devices, an enclave's sponsor's,
// a tagged or cloud sidecar's network's. CTRUST fills it (CTRUST-M12-01, CTRUST-M12-02); which set covers is its rule.
type InferAcknowledgments interface {
	Covering(ctx context.Context) (*InferAcknowledgmentSet, error)
}

// A run's marks and a gateway binding's (§25.10, §8.9): HARN's run store holds them, CONN adds limited_use, and GW's
// binder unions a binding's.
type InferMarkSource interface {
	// The marks of the run.
	RunMarks(ctx context.Context, runId Id) ([]string, error)
	// The union of the marks and taint of every run binding may name: a run handle's harness process's runs and each
	// harness process's above it, ended runs included; an unbound token's, every run of its grant's live harness
	// processes. Fails closed: an error where it cannot say.
	BindingMarks(ctx context.Context, binding *InferBinding) ([]string, error)
}

// What the router asks the person attached to a run (§2.8's prompt, §7.6's disclosure ui_request).
type InferDisclosureAsk struct {
	RunId   Id
	AgentId *Id
	// The disclosure and the version the person is to acknowledge.
	DisclosureId      string
	DisclosureVersion uint32
}

// The run a person is attached to (HARN's): it raises §7.6's disclosure request and waits.
type InferDisclosureAsker interface {
	// Whether a person is attached to the run, here or through an attached enclave, to ask.
	Attached(runId Id) bool
	// Raises the disclosure request in the run, naming the id and version alone, and waits: true once the person
	// acknowledged it, false at their "Not now". An error where ctx ended or no request could be raised. The router
	// takes no answer on its word: an acknowledgment must have landed in the acknowledgments that cover the caller.
	Ask(ctx context.Context, ask *InferDisclosureAsk) (bool, error)
}

// The facts the checks read, each a seam its owner fills. A nil source is one this build does not wire: it refuses
// every remote call, and never a local one.
type InferCheckSources struct {
	Policy          InferPolicySource
	ModelsKey       InferModelsKeySource
	ComputeBlock    InferComputeBlockSource
	Budgets         InferBudgetGate
	Acknowledgments InferAcknowledgments
	Marks           InferMarkSource
	// Optional: with none, a none model waiting for its disclosure answers disclosure_required.
	Asker InferDisclosureAsker
}

// Each required source that is not wired, by name.
func (self *InferCheckSources) unwired() []string {
	unwired := []string{}
	if self.Policy == nil {
		unwired = append(unwired, "the compute policy")
	}
	if self.ModelsKey == nil {
		unwired = append(unwired, "the models key")
	}
	if self.ComputeBlock == nil {
		unwired = append(unwired, "the network's compute block")
	}
	if self.Budgets == nil {
		unwired = append(unwired, "the device's budgets")
	}
	if self.Acknowledgments == nil {
		unwired = append(unwired, "the disclosure acknowledgments")
	}
	if self.Marks == nil {
		unwired = append(unwired, "the run marks")
	}
	return unwired
}

// What fills some of a Sidecar's check sources: an owner's installer, which sets its own fields and reads the Sidecar
// at use, never while it installs.
type InferCheckSourcesInstaller func(sidecar *Sidecar, sources *InferCheckSources) error

// One owner's installer.
type inferCheckSourcesRegistration struct {
	name    string
	install InferCheckSourcesInstaller
}

// Every installer, in the order the files' init functions registered them. Written only during the package's init.
var inferCheckSourcesRegistrations = []*inferCheckSourcesRegistration{}

// Registers an owner's installer of check sources under name, from an init function in its own file: CACL's compute
// block and budgets, CTRUST's acknowledgments, HARN's marks and asker, GW's binding marks. An empty name, a nil installer
// or a name registered twice is a build error, which panics.
func registerInferCheckSources(name string, install InferCheckSourcesInstaller) {
	registered := slices.ContainsFunc(inferCheckSourcesRegistrations, func(registration *inferCheckSourcesRegistration) bool {
		return registration.name == name
	})
	if name == "" || install == nil || registered {
		panic(fmt.Sprintf("inference check sources %q registered twice or without an installer", name))
	}
	inferCheckSourcesRegistrations = append(inferCheckSourcesRegistrations, &inferCheckSourcesRegistration{name: name, install: install})
}

// sources after each installer ran over it. An installer that fails, or one that replaces a source another set, leaves
// the sources refusing every remote call, saying why.
func installInferCheckSources(sidecar *Sidecar, sources *InferCheckSources, registrations []*inferCheckSourcesRegistration) error {
	for _, registration := range registrations {
		before := *sources
		if err := registration.install(sidecar, sources); err != nil {
			return fmt.Errorf("%s did not install: %w", registration.name, err)
		}
		replaced := []string{}
		for _, field := range []struct {
			name  string
			was   any
			isNow any
		}{
			{name: "Policy", was: before.Policy, isNow: sources.Policy},
			{name: "ModelsKey", was: before.ModelsKey, isNow: sources.ModelsKey},
			{name: "ComputeBlock", was: before.ComputeBlock, isNow: sources.ComputeBlock},
			{name: "Budgets", was: before.Budgets, isNow: sources.Budgets},
			{name: "Acknowledgments", was: before.Acknowledgments, isNow: sources.Acknowledgments},
			{name: "Marks", was: before.Marks, isNow: sources.Marks},
			{name: "Asker", was: before.Asker, isNow: sources.Asker},
		} {
			if field.was != nil && field.was != field.isNow {
				replaced = append(replaced, field.name)
			}
		}
		if 0 < len(replaced) {
			return fmt.Errorf("%s replaced the sources %s another installer set", registration.name, strings.Join(replaced, ", "))
		}
	}
	return nil
}

// The checks over sources.
type inferSourceChecker struct {
	settings *InferSettings
	sources  *InferCheckSources
	// why the sources do not serve: an installer failed or two set one source
	sourcesErr error
}

// The checks for sidecar's router: the policy and its gate and the person's models key wired here, the rest from the
// registered installers.
func newInferSidecarChecker(sidecar *Sidecar, settings *InferSettings) inferChecker {
	if sidecar == nil {
		// no Sidecar, no source: every remote call refused
		return newInferSourceChecker(settings, &InferCheckSources{}, nil)
	}
	sources := &InferCheckSources{
		Policy:    &inferSidecarPolicy{sidecar: sidecar},
		ModelsKey: sidecar,
	}
	err := installInferCheckSources(sidecar, sources, inferCheckSourcesRegistrations)
	if err != nil {
		sidecar.log.Errorf("[infer]check sources: %s", err)
	}
	return newInferSourceChecker(settings, sources, err)
}

// The checks over sources, refusing every remote call where sourcesErr says the sources do not serve.
func newInferSourceChecker(settings *InferSettings, sources *InferCheckSources, sourcesErr error) *inferSourceChecker {
	if sources == nil {
		sources = &InferCheckSources{}
	}
	return &inferSourceChecker{settings: settings, sources: sources, sourcesErr: sourcesErr}
}

// The Sidecar's compute policy gate, looked up at each use, since components construct in no design's order.
type inferSidecarPolicy struct {
	sidecar *Sidecar
}

// See InferPolicySource.
func (self *inferSidecarPolicy) PolicyCurrent() (*ComputePolicy, error) {
	gate, err := self.sidecar.ComputePolicyGate()
	if err != nil {
		return nil, err
	}
	return gate.PolicyCurrent()
}

// See InferPolicySource.
func (self *inferSidecarPolicy) RemoteWork(ctx context.Context, operation ComputeRemoteOperation) error {
	gate, err := self.sidecar.ComputePolicyGate()
	if err != nil {
		return err
	}
	return gate.RemoteWork(ctx, operation)
}

// See InferPolicySource.
func (self *inferSidecarPolicy) Now() time.Time {
	gate, err := self.sidecar.ComputePolicyGate()
	if err != nil {
		return self.sidecar.clock.Now()
	}
	return gate.Now()
}

// model_refused for call by rule, saying why.
func inferRefused(call *InferCall, rule string, format string, a ...any) *InferError {
	return &InferError{Code: InferErrorModelRefused, Model: call.Name, Reason: rule, Message: fmt.Sprintf(format, a...)}
}

// See inferChecker.
func (self *inferSourceChecker) check(ctx context.Context, call *InferCall) error {
	local := call.Entry.Kind == InferCatalogKindLocal
	facts := self.read(ctx, !local)
	if local {
		if refused := self.localRefusal(call, facts); refused != nil {
			return refused
		}
		return nil
	}
	return self.checkRemote(ctx, call, facts)
}

// What the static checks read, once for a call or a list: the person's models key, and for remote models the newest
// verified policy and the network's compute block.
type inferCheckFacts struct {
	// nil where the source is not wired, which reads as the defaults
	key    *HarnessModelsKeyRead
	keyErr error
	// remote models only
	policy     *ComputePolicy
	policyErr  error
	network    *ComputeNetworkModels
	networkErr error
}

// The facts, remote's too where remote.
func (self *inferSourceChecker) read(ctx context.Context, remote bool) *inferCheckFacts {
	facts := &inferCheckFacts{}
	if self.sources.ModelsKey != nil {
		facts.key, facts.keyErr = self.sources.ModelsKey.ModelsKey(ctx)
	}
	if !remote || self.sourcesErr != nil || 0 < len(self.sources.unwired()) {
		return facts
	}
	facts.policy, facts.policyErr = self.sources.Policy.PolicyCurrent()
	facts.network, facts.networkErr = self.sources.ComputeBlock.ComputeNetworkModels(ctx)
	return facts
}

// model_refused naming the rule of a ComputeModelGate refusal, or nil.
func inferModelGateRefusal(call *InferCall, err error) *InferError {
	if err == nil {
		return nil
	}
	var refused *ComputeModelRefusedError
	if errors.As(err, &refused) {
		return inferRefused(call, string(refused.Rule), "%s", refused.Reason)
	}
	return inferRefused(call, string(ComputeModelRuleAllow), "%s", err)
}

// A local model: the person's allow alone (CO-9, D-INFER-7). A key that does not read refuses under allow, the closed
// reading, as CACL's gate does; an unwired key source reads as the defaults, every model allowed.
func (self *inferSourceChecker) localRefusal(call *InferCall, facts *inferCheckFacts) *InferError {
	if facts.keyErr != nil {
		return inferRefused(call, string(ComputeModelRuleAllow), "the models key does not read: %s", facts.keyErr)
	}
	return inferModelGateRefusal(call, NewComputeModelGate(nil, facts.key, self.settings).Allows(call.Name, ComputeLabelLocal))
}

// The label the policy gives entry's model and the gate operation its path runs, or why the policy does not cover it
// (§5.4, §6.3). The label is the policy's, never the catalog's, which is unsigned: a TEE provider's line gives A1 or AP,
// and an A1 provider whose chips a custody registry vouches for may reach A2 on the instances it vouches for, which the
// TEE path holds each instance to through the call's Floor; a direct provider's model is none.
func inferPolicyCovers(policy *ComputePolicy, entry *InferCatalogEntry) (ComputeLabel, ComputeRemoteOperation, string) {
	switch entry.Kind {
	case InferCatalogKindTee:
		provider := policy.Provider(entry.Provider)
		switch {
		case provider == nil:
			return "", "", "the policy lists no TEE provider " + entry.Provider
		case provider.ProviderModelId(entry.Model) == "":
			return "", "", "the policy lists no model " + entry.Model + " for " + entry.Provider
		case !provider.Label.Tee():
			return "", "", "the policy gives " + entry.Provider + " no TEE label"
		}
		label := provider.Label
		custody := slices.ContainsFunc(policy.Custody, func(custody *ComputePolicyCustody) bool {
			return custody.Provider == entry.Provider
		})
		if label == ComputeLabelA1 && custody {
			label = ComputeLabelA2
		}
		return label, ComputeRemoteModelCallTee, ""
	case InferCatalogKindDirect:
		direct := policy.DirectProvider(entry.Provider)
		switch {
		case direct == nil || policy.Provider(entry.Provider) != nil:
			return "", "", "the policy lists no direct provider " + entry.Provider
		case !slices.ContainsFunc(direct.Models, func(model *ComputePolicyDirectModel) bool { return model.Model == entry.Model }):
			return "", "", "the policy lists no model " + entry.Model + " for " + entry.Provider
		}
		return ComputeLabelNone, ComputeRemoteModelCallDirect, ""
	}
	return "", "", "the catalog kind " + string(entry.Kind) + " is no remote model's"
}

// The static half of a remote model's checks, which turns on no call: the sources, the policy's cover, the floor, the
// providers, tee_only and allow. Answers the label the policy gives and the gate that passed it, or the refusal, and
// the operation the remote-work gate judges.
func (self *inferSourceChecker) remoteRefusal(call *InferCall, facts *inferCheckFacts) (ComputeLabel, ComputeRemoteOperation, *ComputeModelGate, *InferError) {
	if self.sourcesErr != nil {
		return "", "", nil, inferRefused(call, InferRefusedRuleSource, "remote models are refused: %s", self.sourcesErr)
	}
	if unwired := self.sources.unwired(); 0 < len(unwired) {
		return "", "", nil, inferRefused(call, InferRefusedRuleSource, "remote models wait for %s, which this build does not wire", strings.Join(unwired, ", "))
	}
	if facts.policyErr != nil {
		return "", "", nil, inferRefused(call, InferRefusedRulePolicy, "no compute policy is current: %s", facts.policyErr)
	}
	label, operation, uncovered := inferPolicyCovers(facts.policy, call.Entry)
	if uncovered != "" {
		return "", "", nil, inferRefused(call, InferRefusedRulePolicy, "%s, so the model is unusable", uncovered)
	}
	if facts.networkErr != nil {
		return "", "", nil, inferRefused(call, InferRefusedRuleSource, "the network's compute block does not read: %s", facts.networkErr)
	}
	if facts.keyErr != nil {
		return "", "", nil, inferRefused(call, string(ComputeModelRuleAllow), "the models key does not read: %s", facts.keyErr)
	}
	gate := NewComputeModelGate(facts.network, facts.key, self.settings)
	if refused := inferModelGateRefusal(call, gate.Allows(call.Name, label)); refused != nil {
		return "", "", nil, refused
	}
	return label, operation, gate, nil
}

// A remote model's checks, in the file comment's order. Sets the call's policy and floor once they pass.
func (self *inferSourceChecker) checkRemote(ctx context.Context, call *InferCall, facts *inferCheckFacts) error {
	label, operation, gate, refused := self.remoteRefusal(call, facts)
	if refused != nil {
		return refused
	}
	if err := self.sources.Policy.RemoteWork(ctx, operation); err != nil {
		return inferRefused(call, InferRefusedRulePolicy, "%s", err)
	}
	if err := self.sources.Budgets.Admit(ctx, call); err != nil {
		var inferError *InferError
		if errors.As(err, &inferError) {
			refused := inferError.clone()
			refused.Model = call.Name
			return refused
		}
		return &InferError{
			Code:    InferErrorInsufficientQuota,
			Model:   call.Name,
			Reason:  InferQuotaReasonBudget,
			Message: fmt.Sprintf("the device's budgets do not read: %s", err),
		}
	}
	if err := self.checkMarks(ctx, call, facts.policy); err != nil {
		return err
	}
	if label == ComputeLabelNone {
		if err := self.checkDisclosure(ctx, call, facts.policy); err != nil {
			return err
		}
	}
	call.Policy = facts.policy
	call.Floor = gate.Assurance().EffectiveFloor()
	return nil
}

// What a catalog list reads for its entries' keys: provider-model, or a search endpoint's id.
func inferCatalogEntryKey(entry *InferCatalogEntry) string {
	if entry.Kind == InferCatalogKindSearch {
		return entry.SearchId()
	}
	return entry.Provider + "-" + entry.Model
}

// See inferChecker: each entry the static checks refuse listed unavailable with why, the facts read once for the
// list. Budgets, marks and disclosures turn on the call, so they leave an entry listed; the router answers them when it
// is called. Where no remote entry stays usable, why: the one reason every remote refusal gave, else a general one.
func (self *inferSourceChecker) limit(ctx context.Context, catalog *InferCatalog) *InferCatalog {
	facts := self.read(ctx, true)
	refusals := map[string]string{}
	remoteReasons := []string{}
	for _, entry := range catalog.Entries() {
		if entry.Kind == InferCatalogKindSearch || entry.Unavailable != "" {
			continue
		}
		call := &InferCall{Entry: entry, Effort: entry.DefaultEffort, Name: entry.Name(entry.DefaultEffort)}
		var refused *InferError
		if entry.Kind == InferCatalogKindLocal {
			refused = self.localRefusal(call, facts)
		} else {
			_, _, _, refused = self.remoteRefusal(call, facts)
		}
		if refused == nil {
			continue
		}
		refusals[inferCatalogEntryKey(entry)] = refused.Message
		if entry.remote() && !slices.Contains(remoteReasons, refused.Message) {
			remoteReasons = append(remoteReasons, refused.Message)
		}
	}
	remoteUnavailable := "no remote model passes the policy, the network's floor and providers, and the person's tee_only and allow"
	if len(remoteReasons) == 1 {
		remoteUnavailable = remoteReasons[0]
	}
	return catalog.Refuse(func(entry *InferCatalogEntry) string {
		return refusals[inferCatalogEntryKey(entry)]
	}, remoteUnavailable)
}
