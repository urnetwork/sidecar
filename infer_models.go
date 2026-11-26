//go:build !ios_extension && !sidecar_http

// The person's view of the catalog (DESIGN-COMPUTE §6.3, §15.1, §15.3; INFER-M11-08, INFER-M11-09): what `ur models`
// prints, an app's Models().Catalog answers and the Bot tab's model pill and model choice bind (DESIGN-UI.md's T
// screens): every model this device and policy see, by canonical name, each with its label, its efforts, whether this
// device may use it and why not, its provider's disclosure line from the newest verified policy, and for a local model
// whether its file is pulled, and the local model §6.5's defaults recommend. The same JSON on every backend: the daemon's
// models.list answers it for a remote-mode app as the local core does in process.
//
// Every name is the catalog's, which the release manifest and the signed policy vouch for (the router's checks refuse
// any remote model the policy does not cover); a disclosure line is the signed policy's text. Search endpoints are no
// model and are left out. A function of its arguments, so safe for concurrent use.

package sidecar

import (
	"context"
	"slices"
)

// What a list of models shows: `ur models`' --local, --tee and --provider, and the picker's TEE switch (§6.3, §15.1).
type InferModelsFilter struct {
	// Local models alone.
	Local bool `json:"local,omitempty"`
	// Models in a TEE, and local ones: the person's tee_only as a filter.
	Tee bool `json:"tee,omitempty"`
	// One provider's models, and local ones; empty for every provider.
	Provider string `json:"provider,omitempty"`
}

// A local model's file on this device, for the list.
type InferModelsLocal struct {
	// The file this device's engine would load, its size in bytes, and how far it is on this device.
	File      string             `json:"file"`
	ByteCount int64              `json:"byte_count"`
	State     InferPullFileState `json:"state"`
	// The least memory it runs in, in bytes.
	MinMemoryByteCount int64 `json:"min_memory_byte_count"`
	// Decode rates measured on reference devices.
	DecodeRates []*InferDecodeRate `json:"decode_rates,omitempty"`
}

// One model, as the person's lists show it.
type InferModelsEntry struct {
	// The canonical name at the model's default effort, which a picker shows, and every canonical name it answers.
	Name  string   `json:"name"`
	Names []string `json:"names"`
	// <provider>-<model>, where the model takes one (§6.3).
	Alias    string           `json:"alias,omitempty"`
	Provider string           `json:"provider"`
	Kind     InferCatalogKind `json:"kind"`
	Label    ComputeLabel     `json:"label"`
	Efforts  []InferEffort    `json:"efforts"`
	// The effort an alias runs at where the request names none.
	DefaultEffort    InferEffort     `json:"default_effort"`
	ContextWindow    int64           `json:"context_window"`
	MaxOutput        int64           `json:"max_output"`
	Tools            bool            `json:"tools"`
	StructuredOutput bool            `json:"structured_output"`
	Modalities       []InferModality `json:"modalities"`
	License          string          `json:"license,omitempty"`
	// Why this device may not use it; empty when it may (§6.3).
	Unavailable string `json:"unavailable,omitempty"`
	// Its provider's disclosure (§2.8), and that disclosure's one line from the newest verified policy, empty where the
	// policy has none.
	DisclosureId   string `json:"disclosure_id"`
	DisclosureLine string `json:"disclosure_line,omitempty"`
	// A local model's file on this device.
	Local *InferModelsLocal `json:"local,omitempty"`
	// A remote model's prices and its TEE's caveat.
	Remote *InferRemoteModel `json:"remote,omitempty"`
	// Whether a signed source vouches for its name and label: the release manifest for a local model, the newest
	// verified policy for a remote one. Any other's shows only between the untrusted-data markers.
	Signed bool `json:"signed"`
}

// The person's list of models.
type InferModelsListing struct {
	Entries []*InferModelsEntry `json:"entries"`
	// The local model §6.5's defaults recommend for this device, empty for none, which the Bot tab offers to pull.
	Recommended string `json:"recommended,omitempty"`
	// Why the list holds no local model, or no remote one, where it says.
	LocalUnavailable  string `json:"local_unavailable,omitempty"`
	RemoteUnavailable string `json:"remote_unavailable,omitempty"`
}

// The summary line of the disclosure id in policy, its first locale's, English: empty where there is none.
func inferDisclosureLine(policy *ComputePolicy, id string) string {
	if policy == nil {
		return ""
	}
	disclosure := policy.Disclosure(id)
	if disclosure == nil || len(disclosure.Locales) == 0 {
		return ""
	}
	return disclosure.Locales[0].Summary
}

// The listing of catalog filtered by filter, its disclosure lines from policy, nil for none, and its local models'
// files from pull, nil to leave their state absent.
func InferModelsListingOf(catalog *InferCatalog, filter *InferModelsFilter, policy *ComputePolicy, pull *InferPull) *InferModelsListing {
	if filter == nil {
		filter = &InferModelsFilter{}
	}
	recommended, _ := catalog.Recommended()
	catalogFilter := &InferCatalogFilter{LocalOnly: filter.Local}
	if filter.Tee || filter.Provider != "" {
		assurance := DefaultComputeAssurance()
		assurance.TeeOnly = filter.Tee
		if filter.Provider != "" {
			assurance.Providers = []string{filter.Provider}
		}
		catalogFilter.Assurance = assurance
	}
	filtered := catalog.Filter(catalogFilter)
	device := filtered.Device()
	listing := &InferModelsListing{
		Entries:           []*InferModelsEntry{},
		Recommended:       recommended,
		LocalUnavailable:  filtered.LocalUnavailable(),
		RemoteUnavailable: filtered.RemoteUnavailable(),
	}
	for _, entry := range filtered.Entries() {
		if entry.Kind == InferCatalogKindSearch {
			continue
		}
		listed := &InferModelsEntry{
			Name:             entry.Name(entry.DefaultEffort),
			Names:            entry.Names(),
			Alias:            entry.Alias(),
			Provider:         entry.Provider,
			Kind:             entry.Kind,
			Label:            entry.Label,
			Efforts:          slices.Clone(entry.Efforts),
			DefaultEffort:    entry.DefaultEffort,
			ContextWindow:    entry.ContextWindow,
			MaxOutput:        entry.MaxOutput,
			Tools:            entry.Tools,
			StructuredOutput: entry.StructuredOutput,
			Modalities:       slices.Clone(entry.Modalities),
			License:          entry.License,
			Unavailable:      entry.Unavailable,
			DisclosureId:     entry.DisclosureId(),
			DisclosureLine:   inferDisclosureLine(policy, entry.DisclosureId()),
			Remote:           entry.Remote,
			Signed:           entry.Kind == InferCatalogKindLocal,
		}
		if entry.remote() && policy != nil {
			_, _, uncovered := inferPolicyCovers(policy, entry)
			listed.Signed = uncovered == ""
		}
		if entry.Kind == InferCatalogKindLocal && entry.Local != nil {
			local := &InferModelsLocal{
				State:              InferPullFileAbsent,
				MinMemoryByteCount: entry.Local.MinMemoryByteCount,
				DecodeRates:        entry.Local.DecodeRates,
			}
			if device != nil {
				if file, _, err := inferLocalModelFile(entry, device); err == nil {
					local.File = file.Name
					local.ByteCount = file.ByteCount
					if pull != nil {
						local.State = pull.FileState(file)
					}
				}
			}
			listed.Local = local
		}
		listing.Entries = append(listing.Entries, listed)
	}
	return listing
}

// The newest verified compute policy, nil while none is current.
func (self *Sidecar) inferCurrentPolicy() *ComputePolicy {
	gate, err := self.ComputePolicyGate()
	if err != nil {
		return nil
	}
	policy, err := gate.PolicyCurrent()
	if err != nil {
		return nil
	}
	return policy
}

// This Sidecar's list of models (§6.3, §15.1, §15.3): its router's catalog, as the checks list it, filtered, with the
// newest verified policy's disclosure lines and, where pull is not nil, each local model's file state.
func (self *Sidecar) InferModels(ctx context.Context, filter *InferModelsFilter, pull *InferPull) (*InferModelsListing, error) {
	router, err := self.InferRouter()
	if err != nil {
		return nil, err
	}
	catalog, err := router.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	return InferModelsListingOf(catalog, filter, self.inferCurrentPolicy(), pull), nil
}
