//go:build !ios_extension && !sidecar_http

// A model's label (DESIGN-COMPUTE §4.3, §6.3): who can read what a call sends it. A1, A2 and AP are TEE labels, a
// provider whose evidence the device verifies itself (§5); none is a provider without a TEE, reached by the direct
// path (§6.6); local is a model on this device, which nothing leaves (CO-9). Every surface shows the label: the
// catalog, the badge on each message, the enclave card and the record (§4.3).
//
// A network's floor and provider list, and a person's tee_only, limit which labels remote inference may use (§16.4):
// the floor orders none < AP < A1 < A2, AP being the lowest TEE label (Q-PROV-3), and local meets every floor,
// provider list and tee_only, since a local call sends nothing anywhere (D-INFER-7). A label or floor this file does
// not know admits nothing remote, so an unknown word read from anywhere fails closed.
//
// Everything here is a value, so safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
)

// One of §4.3's labels, as the policy, the catalog, AttestationResult.label and the record write it.
type ComputeLabel string

const (
	// No TEE: the provider and its machines read the conversation, URnetwork's servers do not (§4.3's N1-N5).
	ComputeLabelNone ComputeLabel = "none"
	// tee-platform: E1-E4 hold for the provider's base image, but the provider's own unmeasured code sits inside the
	// boundary, so the provider company is trusted as a cloud is.
	ComputeLabelAp ComputeLabel = "AP"
	// tee: every piece of code inside the TEE that handles plaintext is measured and pinned.
	ComputeLabelA1 ComputeLabel = "A1"
	// tee+custody: A1, with each machine's chip identity in a custody registry the policy names.
	ComputeLabelA2 ComputeLabel = "A2"
	// On this device: nothing leaves it (CO-9).
	ComputeLabelLocal ComputeLabel = "local"
)

// The provider slug of every model on this device, whose names start local- (§6.3), and no remote provider's.
const computeLocalProvider = "local"

// The providers list's word for every provider (§16.4).
const computeEveryProvider = "*"

// A word that is not one of §4.3's labels, or a floor that is not one of none, AP, A1 and A2.
var ErrComputeLabelUnknown = errors.New("unknown compute label")

// The floor order of the labels a floor may name, lowest first (§16.4): none < AP < A1 < A2. local has no place in it,
// since it meets every floor.
var computeLabelFloorOrder = []ComputeLabel{ComputeLabelNone, ComputeLabelAp, ComputeLabelA1, ComputeLabelA2}

// The words §4.3 writes beside each label, for a surface that spells one out.
var computeLabelWords = map[ComputeLabel]string{
	ComputeLabelNone:  "no-tee",
	ComputeLabelAp:    "tee-platform",
	ComputeLabelA1:    "tee",
	ComputeLabelA2:    "tee+custody",
	ComputeLabelLocal: "on this device",
}

// The label text names, exactly as written: labels are case-sensitive identifiers, so "ap" or "None" is unknown. The
// error never repeats the text.
func ParseComputeLabel(text string) (ComputeLabel, error) {
	label := ComputeLabel(text)
	if !label.Valid() {
		return "", ErrComputeLabelUnknown
	}
	return label, nil
}

// The floor text names: none, AP, A1 or A2 (§16.4's assurance_floor, and an enclave's), never local. The error never
// repeats the text.
func ParseComputeFloor(text string) (ComputeLabel, error) {
	floor := ComputeLabel(text)
	if !slices.Contains(computeLabelFloorOrder, floor) {
		return "", fmt.Errorf("%w: not a floor", ErrComputeLabelUnknown)
	}
	return floor, nil
}

// Whether the label is one of §4.3's.
func (self ComputeLabel) Valid() bool {
	return self == ComputeLabelLocal || slices.Contains(computeLabelFloorOrder, self)
}

// Whether a TEE protects the label's calls, the device having verified it: A1, A2 and AP.
func (self ComputeLabel) Tee() bool {
	return self == ComputeLabelAp || self == ComputeLabelA1 || self == ComputeLabelA2
}

// §4.3's words for the label, such as tee-platform for AP; empty for an unknown label.
func (self ComputeLabel) Words() string {
	return computeLabelWords[self]
}

// Whether a model of this label passes floor. local passes every floor, a known one or not, since nothing leaves the
// device (CO-9, D-INFER-7). Of the remote labels, each passes the floors at or below it in none < AP < A1 < A2; a
// label or floor outside that order passes nothing, so a floor that is not none, AP, A1 or A2 admits local alone.
func (self ComputeLabel) Meets(floor ComputeLabel) bool {
	if self == ComputeLabelLocal {
		return true
	}
	labelRank := slices.Index(computeLabelFloorOrder, self)
	floorRank := slices.Index(computeLabelFloorOrder, floor)
	if labelRank < 0 || floorRank < 0 {
		return false
	}
	return floorRank <= labelRank
}

// What a network's compute block and a person's models key let remote inference use (§16.4): the network's
// assurance_floor and providers, and the person's tee_only, their own floor of AP, which narrows and never widens. A
// zero value admits nothing remote, since its floor is no floor and its providers list names no provider.
type ComputeAssurance struct {
	// The network's assurance_floor: none, AP, A1 or A2.
	Floor ComputeLabel
	// The network's providers, by slug, "*" for every one. Empty names none.
	Providers []string
	// The person's tee_only: a floor of AP on top of Floor.
	TeeOnly bool
}

// The assurance of a network that set nothing: every label and every provider (CO-18, §16.5), with the person's
// tee_only off.
func DefaultComputeAssurance() *ComputeAssurance {
	return &ComputeAssurance{
		Floor:     ComputeLabelNone,
		Providers: []string{computeEveryProvider},
	}
}

// Whether a model of label from provider passes the floor, the person's tee_only and the providers list. A local
// model passes all three, whatever they say (§6.3, §16.4); a remote one must meet the floor, AP as well where tee_only
// is set, and come from a listed provider. A provider or label the device does not know passes nothing.
func (self *ComputeAssurance) Admits(provider string, label ComputeLabel) bool {
	if label == ComputeLabelLocal {
		return provider == computeLocalProvider
	}
	if provider == computeLocalProvider || !label.Meets(self.Floor) {
		return false
	}
	if self.TeeOnly && !label.Meets(ComputeLabelAp) {
		return false
	}
	return slices.Contains(self.Providers, computeEveryProvider) || slices.Contains(self.Providers, provider)
}

// The lowest label a remote model may carry here: the floor, raised to AP where tee_only is set. Empty for a floor
// that is no floor, which admits nothing remote.
func (self *ComputeAssurance) EffectiveFloor() ComputeLabel {
	if !slices.Contains(computeLabelFloorOrder, self.Floor) {
		return ""
	}
	if self.TeeOnly && !self.Floor.Meets(ComputeLabelAp) {
		return ComputeLabelAp
	}
	return self.Floor
}
