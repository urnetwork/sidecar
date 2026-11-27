//go:build !ios_extension && !sidecar_http

// ComputeModelGate (DESIGN-COMPUTE §16.4, D-CACL-4; CACL-M11-01): which inference may run on this device, by the four
// limits D-CACL-4 names, the network's assurance_floor and providers and the person's tee_only and allow, the one check
// the router and the gateway ask before a call (INFER §6.4, GW §8.6):
//
//	local   passes the floor, the providers and tee_only whatever they say, since nothing leaves the device (CO-9,
//	        D-INFER-7), and is checked against allow alone
//	remote  its label at or above the network's floor (none < AP < A1 < A2), and AP where the person's tee_only is set;
//	        its provider among the network's providers, `*` for every one; its name matching one of allow's globs
//
// A glob is never read as a label (R1-56: SayGM's -tee names are labeled none), so TEE-only is tee_only or the floor,
// never a glob. The network's two come from its compute block through ComputePolicyView.NetworkModels (CACL-M12-03),
// which the router reads at each check through its compute block source, and where a network has no block, or its
// block leaves them out, they are CO-18's defaults, none and `*` (Q-CACL-3's (a)); a device that has not read its head
// refuses every remote model rather than reading the defaults (ErrComputePolicyUnread). A refusal names its rule,
// floor, provider, tee_only or allow, for the router's error. A key that does not read refuses every model under rule
// allow, the closed reading. An enclave enforces its sponsor's key, read from the vault as their other devices read
// it (ENC's).
//
// A gate is a value built for one check or one run: safe for concurrent use, since nothing changes it.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
)

// The rule a refusal names (§16.4; D-CACL-4).
type ComputeModelRule string

const (
	// The network's assurance_floor.
	ComputeModelRuleFloor ComputeModelRule = "floor"
	// The network's providers.
	ComputeModelRuleProvider ComputeModelRule = "provider"
	// The person's tee_only, a floor of AP.
	ComputeModelRuleTeeOnly ComputeModelRule = "tee_only"
	// The person's allow.
	ComputeModelRuleAllow ComputeModelRule = "allow"
)

// A model the gate refuses: ComputeModelRefusedError says by which rule.
var ErrComputeModelRefused = errors.New("model refused")

// A refusal, naming its rule and why, never the person's globs.
type ComputeModelRefusedError struct {
	Rule   ComputeModelRule
	Reason string
}

// The rule and why.
func (self *ComputeModelRefusedError) Error() string {
	return fmt.Sprintf("%s by rule %s: %s", ErrComputeModelRefused, self.Rule, self.Reason)
}

// ErrComputeModelRefused.
func (self *ComputeModelRefusedError) Unwrap() error {
	return ErrComputeModelRefused
}

// The network's part of the gate: its assurance_floor and providers, as its compute block gives them.
type ComputeNetworkModels struct {
	// none, AP, A1 or A2.
	Floor ComputeLabel
	// Provider slugs, `*` for every one; empty names none.
	Providers []string
}

// CO-18's defaults, which a network with no compute block takes: every label and every provider (Q-CACL-3's (a)).
func DefaultComputeNetworkModels() *ComputeNetworkModels {
	return &ComputeNetworkModels{Floor: ComputeLabelNone, Providers: []string{computeEveryProvider}}
}

// D-CACL-4's four limits for one device and one person.
type ComputeModelGate struct {
	floor     ComputeLabel
	providers []string
	teeOnly   bool
	// nil allows every model
	allow []string
	// the key did not read, and nothing is allowed
	unreadable bool
	infer      *InferSettings
}

// The gate over the network's floor and providers, nil for CO-18's defaults, and the person's key as read, nil for the
// defaults. infer holds names to §6.3's grammar; nil is its defaults.
func NewComputeModelGate(network *ComputeNetworkModels, key *HarnessModelsKeyRead, infer *InferSettings) *ComputeModelGate {
	if network == nil {
		network = DefaultComputeNetworkModels()
	}
	if infer == nil {
		infer = DefaultInferSettings()
	}
	gate := &ComputeModelGate{floor: network.Floor, providers: slices.Clone(network.Providers), infer: infer}
	if key != nil {
		gate.unreadable = key.Unreadable
		if key.Key != nil {
			gate.teeOnly = key.Key.TeeOnly
			if key.Key.Allow != nil {
				gate.allow = slices.Clone(key.Key.Allow)
			}
		}
	}
	return gate
}

// The network's floor and providers with the person's tee_only, as INFER's catalog limits its list by them
// (InferCatalog.Limit); allow, which names models rather than labels, it checks through Allows.
func (self *ComputeModelGate) Assurance() *ComputeAssurance {
	return &ComputeAssurance{Floor: self.floor, Providers: slices.Clone(self.providers), TeeOnly: self.teeOnly}
}

// Nil where a model named name, of label, may run here; else a *ComputeModelRefusedError naming the rule, or a name
// outside §6.3's grammar. name is the canonical name the call runs, which the router resolves an alias to first; the
// provider is its first part.
func (self *ComputeModelGate) Allows(name string, label ComputeLabel) error {
	parsed, err := InferParseModelName(name, self.infer)
	if err != nil {
		return err
	}
	refuse := func(rule ComputeModelRule, reason string) error {
		return &ComputeModelRefusedError{Rule: rule, Reason: reason}
	}
	local := parsed.Provider == computeLocalProvider
	switch {
	case !label.Valid():
		return refuse(ComputeModelRuleFloor, "an unknown label")
	case local != (label == ComputeLabelLocal):
		return refuse(ComputeModelRuleFloor, "the local label is this device's models' alone")
	}
	if !local {
		switch {
		case !label.Meets(self.floor):
			return refuse(ComputeModelRuleFloor, fmt.Sprintf("below the network's assurance floor %s", self.floor))
		case !slices.Contains(self.providers, computeEveryProvider) && !slices.Contains(self.providers, parsed.Provider):
			return refuse(ComputeModelRuleProvider, "its provider is not among the network's allowed providers")
		case self.teeOnly && !label.Meets(ComputeLabelAp):
			return refuse(ComputeModelRuleTeeOnly, "tee_only allows TEE models alone")
		}
	}
	switch {
	case self.unreadable:
		return refuse(ComputeModelRuleAllow, "the models key does not read")
	case self.allow == nil:
		return nil
	case slices.ContainsFunc(self.allow, func(glob string) bool { return harnessModelsGlobMatch(glob, name) }):
		return nil
	}
	return refuse(ComputeModelRuleAllow, "no glob of allow matches it")
}
