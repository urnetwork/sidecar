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
	"fmt"
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

// The person's models key as the lists show it (§16.4): models.settings's and models.set's answer, an app's
// Models().Settings.
type InferModelsSettings struct {
	Default string `json:"default,omitempty"`
	// The globs every model must match one of; null for every model, [] for none.
	Allow      []string `json:"allow"`
	TeeOnly    bool     `json:"tee_only"`
	SignInMail string   `json:"sign_in_mail"`
	// Each harness's tiers, harness to tier to canonical name.
	Harness map[string]map[string]string `json:"harness,omitempty"`
	// Each agent label's default model.
	Agents map[string]string `json:"agents,omitempty"`
	// The key does not read: every model is refused under allow, the closed reading (§16.4).
	Unreadable bool     `json:"unreadable,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// The settings key holds, with read's verdict where it was read.
func InferModelsSettingsOf(key *HarnessModelsKey, read *HarnessModelsKeyRead) *InferModelsSettings {
	settings := &InferModelsSettings{
		Default:    key.Default,
		Allow:      key.Allow,
		TeeOnly:    key.TeeOnly,
		SignInMail: string(key.SignInMailMode()),
		Harness:    key.Harness,
	}
	if 0 < len(key.Agents) {
		settings.Agents = map[string]string{}
		for label, agent := range key.Agents {
			settings.Agents[label] = agent.Default
		}
	}
	if read != nil {
		settings.Unreadable = read.Unreadable
		settings.Reason = read.Reason
		settings.Warnings = read.Warnings
	}
	return settings
}

// A change to the person's models key (§16.4), ur models set's and an app's Models().SetSettings: each set field
// changes, each nil or empty one stays.
type InferModelsChange struct {
	// The default model, a canonical name; empty removes it.
	Default *string `json:"default,omitempty"`
	TeeOnly *bool   `json:"tee_only,omitempty"`
	// withhold or allow.
	SignInMail *string `json:"sign_in_mail,omitempty"`
	// The globs allowed; [] allows none.
	Allow *[]string `json:"allow,omitempty"`
	// A harness's tier's model: all three, or none.
	Harness string `json:"harness,omitempty"`
	Tier    string `json:"tier,omitempty"`
	Model   string `json:"model,omitempty"`
}

// Whether the change changes nothing.
func (self *InferModelsChange) Empty() bool {
	return self.Default == nil && self.TeeOnly == nil && self.SignInMail == nil && self.Allow == nil &&
		self.Harness == "" && self.Tier == "" && self.Model == ""
}

// Applies the change to key, refusing a harness's tier named by halves; CACL's writer checks the key whole after.
func (self *InferModelsChange) Apply(key *HarnessModelsKey) error {
	if self.Default != nil {
		key.Default = *self.Default
	}
	if self.TeeOnly != nil {
		key.TeeOnly = *self.TeeOnly
	}
	if self.SignInMail != nil {
		key.SignInMail = HarnessSignInMail(*self.SignInMail)
	}
	if self.Allow != nil {
		key.Allow = append([]string{}, *self.Allow...)
	}
	switch {
	case self.Harness == "" && self.Tier == "" && self.Model == "":
	case self.Harness == "" || self.Tier == "" || self.Model == "":
		return fmt.Errorf("%w: a harness's tier takes the harness, the tier and the model", ErrModelsKeyInvalid)
	default:
		if key.Harness == nil {
			key.Harness = map[string]map[string]string{}
		}
		if key.Harness[self.Harness] == nil {
			key.Harness[self.Harness] = map[string]string{}
		}
		key.Harness[self.Harness][self.Tier] = self.Model
	}
	return nil
}

// The person's models key as this device reads it now (§16.4).
func (self *Sidecar) InferModelsSettings(ctx context.Context) (*InferModelsSettings, error) {
	read, err := self.ModelsKey(ctx)
	if err != nil {
		return nil, err
	}
	return InferModelsSettingsOf(read.Key, read), nil
}

// Changes the person's models key by change: their own act, confirmed on /dev/tty or in an app's UI, which the
// callers vouch for (ur daemon's models.set, a Confirm method refused under a harness; an app's SetSettings), written
// through CACL's writer (Sidecar.SetModelsKey) and never from a run, a tool or MCP. Answers the key as written.
func (self *Sidecar) InferSetModels(ctx context.Context, change *InferModelsChange) (*InferModelsSettings, error) {
	if change == nil || change.Empty() {
		return nil, fmt.Errorf("%w: no change", ErrModelsKeyInvalid)
	}
	written, err := self.SetModelsKey(ctx, &MemberHarnessConfigUpdateArgs{Origin: SidecarActConfirmed}, change.Apply)
	if err != nil {
		return nil, err
	}
	return InferModelsSettingsOf(written, nil), nil
}
