//go:build !ios_extension && !sidecar_http

// The catalog (DESIGN-COMPUTE §6.3, R-INFER-1, D-INFER-1, CO-11): one list of every model this device may use, local or
// remote, in a TEE or not, each with its label, and of the search endpoints, the same for the Harness, the gateway and
// every agent either launches. Its local entries come from the release manifest (infer_manifest.go), judged against
// this device's capabilities; its remote entries, the broker's catalog joined with the signed policy, are joined in
// later (Join; INFER-M12-01), and so are the search endpoints (§21).
//
// An entry is one model: its provider, its model part and the efforts it takes, so its canonical names are
// <provider>-<model>-<effort>, one an effort, and its alias <provider>-<model> where its model part does not end in an
// effort word (infer_name.go). Resolve is the only way a name becomes a model: it reads the name's one reading, finds
// its entry, and settles the effort: a full name's own, which wins over the request's (Q-INFER-5), never one the
// model does not list, and an alias's from the request's, mapped to the nearest the model lists, else the model's
// default. A name no entry answers is unknown; the parse alone never makes a name exist.
//
// The catalog shows only what this device may use, and says why not of the rest: a local entry the device lacks the
// memory, a build or an accelerator for is listed unavailable with the reason, which Resolve answers with, and a
// platform with no engine build lists no local entry at all, saying so (macOS on Intel, Windows on arm64; §6.5). A
// filter or floor that leaves no remote entry keeps the local ones and says why no remote one is offered.
//
// Traps it keeps: no catalog holds two entries of one name, or one model twice, so a catalog that would is refused
// whole; no remote entry calls itself local; and nothing here reads a disclosure's text, which CTRUST renders from the
// signed policy: an entry carries its disclosure's id alone.
//
// A catalog is never changed once built: every method returns copies, so it is safe for concurrent use.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// What serves an entry (§6.3).
type InferCatalogKind string

const (
	// The local engine on this device (§6.5).
	InferCatalogKindLocal InferCatalogKind = "local"
	// A TEE provider, through the broker, end to end encrypted to an instance the device verified (§6.6).
	InferCatalogKindTee InferCatalogKind = "tee"
	// A provider without a TEE, called from the device with the broker's per-request signature (§6.6).
	InferCatalogKindDirect InferCatalogKind = "direct"
	// A search endpoint, not a model (§21).
	InferCatalogKindSearch InferCatalogKind = "search"
)

// The device classes §6.5's defaults name.
type InferDeviceClass string

const (
	InferDeviceClassPhone   InferDeviceClass = "phone"
	InferDeviceClassLaptop  InferDeviceClass = "laptop"
	InferDeviceClassDesktop InferDeviceClass = "desktop"
)

// The disclosure id prefixes of §2.8: inference:<provider> and search:<engine>.
const (
	inferDisclosurePrefix  = "inference:"
	searchDisclosurePrefix = "search:"
)

// A binary gigabyte, for the memory a reason names.
const inferGibByteCount = 1024 * 1024 * 1024

var (
	// A set of entries no catalog may hold: one not whole, two of one name or model, or a joined entry that calls
	// itself local. The message names the first fault.
	ErrInferCatalogInvalid = errors.New("catalog refused")
	// A name the grammar reads but no entry answers.
	ErrInferModelUnknown = errors.New("no such model in the catalog")
	// A full name whose effort its model does not list; the router never sends a model one (§6.4).
	ErrInferEffortUnlisted = errors.New("the model does not take that effort")
	// A model this device may not use, the message saying why (§6.3).
	ErrInferModelUnavailable = errors.New("model unavailable")
)

// What a device can run a local model on: its platform, class, memory and accelerators. ur's desktops read it from
// their OS (INFER-M11-04) and the apps from their host's Capabilities (INFER-M11-06).
type InferDeviceCapabilities struct {
	// GOOS/GOARCH, with ios/arm64 and android/arm64 for the phones.
	Platform string `json:"platform"`
	// Which of §6.5's defaults applies.
	Class InferDeviceClass `json:"class"`
	// Its memory, in bytes; non-positive when unknown, which leaves every local model unavailable.
	MemoryByteCount int64 `json:"memory_byte_count"`
	// Whether the memory is unified, shared by CPU and GPU, as on Apple silicon (§6.5's largest default).
	UnifiedMemory bool `json:"unified_memory"`
	// What it can run a model on beyond its CPU, which every device has.
	Accelerators []InferAccelerator `json:"accelerators"`
}

// A copy sharing nothing.
func (self *InferDeviceCapabilities) clone() *InferDeviceCapabilities {
	clone := *self
	clone.Accelerators = slices.Clone(self.Accelerators)
	return &clone
}

// A local entry's own fields (§6.3): its files for this device's platform, its memory floor, its accelerators and its
// measured decode rates.
type InferLocalModel struct {
	// The manifest's files that serve this device's platform; a build per accelerator where there are several.
	Files []*InferManifestModelFile `json:"files"`
	// The least memory it runs in, in bytes.
	MinMemoryByteCount int64 `json:"min_memory_byte_count"`
	// What it runs on.
	Accelerators []InferAccelerator `json:"accelerators"`
	// Decode rates measured on reference devices.
	DecodeRates []*InferDecodeRate `json:"decode_rates,omitempty"`
}

// A copy sharing nothing. A nil file or rate stays nil, for the entry's check to refuse, since an entry is copied
// before it is checked.
func (self *InferLocalModel) clone() *InferLocalModel {
	clone := *self
	clone.Files = make([]*InferManifestModelFile, len(self.Files))
	for i, file := range self.Files {
		if file == nil {
			continue
		}
		fileClone := *file
		fileClone.Platforms = slices.Clone(file.Platforms)
		clone.Files[i] = &fileClone
	}
	clone.Accelerators = slices.Clone(self.Accelerators)
	clone.DecodeRates = make([]*InferDecodeRate, len(self.DecodeRates))
	for i, rate := range self.DecodeRates {
		if rate == nil {
			continue
		}
		rateClone := *rate
		clone.DecodeRates[i] = &rateClone
	}
	return &clone
}

// A remote entry's own fields (§6.3), which the broker's catalog and the signed policy fill (INFER-M12-01): the
// provider's own id for the model, the network's three prices, and for a TEE label the policy profiles it may run on
// and whether the TEE's evidence leaves the provider's serving code unmeasured (§4.5).
type InferRemoteModel struct {
	// The provider's own id for the model, as the policy pins it (Chutes: its chute_id's model).
	ProviderModelId string `json:"provider_model_id"`
	// The network's prices per million tokens, in nano-USD (model.NanoCents' unit, §9.6).
	InputNanoUsdPerMillion       int64 `json:"input_nano_usd_per_million"`
	OutputNanoUsdPerMillion      int64 `json:"output_nano_usd_per_million"`
	CachedInputNanoUsdPerMillion int64 `json:"cached_input_nano_usd_per_million"`
	// For a TEE label, the ids of the policy profiles it may run on (§5.4).
	Profiles []string `json:"profiles,omitempty"`
	// For a TEE label, set where §4.5 says the provider's serving code is not measured, which every surface shows as
	// "serving code measured: no".
	ServingCodeUnmeasured bool `json:"serving_code_unmeasured,omitempty"`
}

// A copy sharing nothing.
func (self *InferRemoteModel) clone() *InferRemoteModel {
	clone := *self
	clone.Profiles = slices.Clone(self.Profiles)
	return &clone
}

// A search endpoint's own fields (§21): its kind, search/<engine>/<kind>'s last part, and its price.
type InferSearchEndpoint struct {
	// The endpoint's mode, such as fast.
	Kind string `json:"kind"`
	// The price per search, in nano-USD.
	NanoUsdPerSearch int64 `json:"nano_usd_per_search"`
}

// One entry of §6.3's catalog: a model, or a search endpoint.
type InferCatalogEntry struct {
	// The provider's slug: local for this device's models, a remote provider's, or a search endpoint's engine.
	Provider string `json:"provider"`
	// The model part of its names; empty for a search endpoint.
	Model string `json:"model,omitempty"`
	// What serves it.
	Kind InferCatalogKind `json:"kind"`
	// Its label (§4.3): local for a local entry, A1, A2 or AP for a TEE one, none for a direct one or a search.
	Label ComputeLabel `json:"label"`
	// The efforts it takes, off alone where it has no reasoning.
	Efforts []InferEffort `json:"efforts,omitempty"`
	// The effort an alias asked for none in particular runs at (Q-INFER-5), one of Efforts.
	DefaultEffort InferEffort `json:"default_effort,omitempty"`
	// Its context window, in tokens.
	ContextWindow int64 `json:"context_window,omitempty"`
	// The most tokens one answer holds.
	MaxOutput int64 `json:"max_output,omitempty"`
	// Whether it calls tools.
	Tools bool `json:"tools"`
	// The tokens a request's tool schemas and the skill may take (§7.4): its window over the settings'
	// ToolBudgetWindowDivisor, a quarter. The catalog sets it from the window, whatever an entry given to it held.
	ToolBudget int64 `json:"tool_budget,omitempty"`
	// Whether it gives structured output.
	StructuredOutput bool `json:"structured_output"`
	// What it takes in.
	Modalities []InferModality `json:"modalities,omitempty"`
	// Its weights' license.
	License string `json:"license,omitempty"`
	// A local entry's own fields.
	Local *InferLocalModel `json:"local,omitempty"`
	// A remote entry's own fields.
	Remote *InferRemoteModel `json:"remote,omitempty"`
	// A search endpoint's own fields.
	Search *InferSearchEndpoint `json:"search,omitempty"`
	// Why this device may not use it; empty when it may.
	Unavailable string `json:"unavailable,omitempty"`
}

// A copy sharing nothing.
func (self *InferCatalogEntry) clone() *InferCatalogEntry {
	clone := *self
	clone.Efforts = slices.Clone(self.Efforts)
	clone.Modalities = slices.Clone(self.Modalities)
	if self.Local != nil {
		clone.Local = self.Local.clone()
	}
	if self.Remote != nil {
		clone.Remote = self.Remote.clone()
	}
	if self.Search != nil {
		searchClone := *self.Search
		clone.Search = &searchClone
	}
	return &clone
}

// The canonical name of the model at effort, <provider>-<model>-<effort>; empty for a search endpoint.
func (self *InferCatalogEntry) Name(effort InferEffort) string {
	if self.Kind == InferCatalogKindSearch {
		return ""
	}
	return (&InferModelName{Provider: self.Provider, Model: self.Model, Effort: effort}).String()
}

// Its canonical names, one for each effort it lists, in its order; none for a search endpoint.
func (self *InferCatalogEntry) Names() []string {
	if self.Kind == InferCatalogKindSearch {
		return []string{}
	}
	names := make([]string, len(self.Efforts))
	for i, effort := range self.Efforts {
		names[i] = self.Name(effort)
	}
	return names
}

// Its alias, <provider>-<model>; empty for a search endpoint, and for a model whose model part ends in an effort
// word, which takes no alias (§6.3).
func (self *InferCatalogEntry) Alias() string {
	if self.Kind == InferCatalogKindSearch {
		return ""
	}
	if last := strings.LastIndexByte(self.Model, '-'); 0 <= last && InferEffort(self.Model[last+1:]).Valid() {
		return ""
	}
	if InferEffort(self.Model).Valid() {
		return ""
	}
	return self.Provider + "-" + self.Model
}

// A search endpoint's id, search/<engine>/<kind>; empty for a model.
func (self *InferCatalogEntry) SearchId() string {
	if self.Kind != InferCatalogKindSearch || self.Search == nil {
		return ""
	}
	return (&InferSearchId{Engine: self.Provider, Kind: self.Search.Kind}).String()
}

// The id of the disclosure whose summary line shows beside it (§2.8): inference:<provider> for a model, local's
// among them, and search:<engine> for a search endpoint. CTRUST renders the text from the signed policy.
func (self *InferCatalogEntry) DisclosureId() string {
	if self.Kind == InferCatalogKindSearch {
		return searchDisclosurePrefix + self.Provider
	}
	return inferDisclosurePrefix + self.Provider
}

// Empty when the entry is whole, else its first fault, the entry named only once its name parts are known to be in
// the grammar.
func (self *InferCatalogEntry) fault(settings *InferSettings) string {
	if self.Kind == InferCatalogKindSearch {
		if self.Search == nil || self.Local != nil || self.Remote != nil || self.Model != "" {
			return "a search entry with other than a search's fields"
		}
		id := self.SearchId()
		if _, err := InferParseSearchId(id, settings); err != nil {
			return "a search entry whose id is not search/<engine>/<kind>"
		}
		if self.Label != ComputeLabelNone || self.Search.NanoUsdPerSearch < 0 {
			return "the search entry " + id + " with a label other than none or a negative price"
		}
		return ""
	}
	if !inferValidProvider(self.Provider) {
		return "an entry whose provider is not a slug"
	}
	if fault := inferModelPartFault(self.Model); fault != "" {
		return "an entry with " + fault
	}
	// bounded before any message names it
	if settings.NameMaxByteCount < len(self.Provider)+len(self.Model)+1 {
		return fmt.Sprintf("an entry whose name passes %d bytes", settings.NameMaxByteCount)
	}
	name := self.Provider + "-" + self.Model
	switch self.Kind {
	case InferCatalogKindLocal:
		if self.Provider != computeLocalProvider || self.Label != ComputeLabelLocal || self.Local == nil ||
			self.Remote != nil || self.Search != nil {
			return "the local entry " + name + " without the local provider, label and fields alone"
		}
	case InferCatalogKindTee, InferCatalogKindDirect:
		labelFits := (self.Kind == InferCatalogKindTee && self.Label.Tee()) ||
			(self.Kind == InferCatalogKindDirect && self.Label == ComputeLabelNone)
		if self.Provider == computeLocalProvider || self.Label == ComputeLabelLocal {
			// nothing remote may pass for a model on this device
			return "the remote entry " + name + " calling itself local"
		}
		if !labelFits || self.Remote == nil || self.Local != nil || self.Search != nil {
			return "the remote entry " + name + " without a label its kind allows and remote fields alone"
		}
		if self.Label == ComputeLabelNone && inferDropTeeMarks(self.Model) != self.Model {
			// no name claims what its label denies (D-INFER-1, Q-PROV-8), whatever the broker's catalog says
			return "the entry " + name + " labeled none with a TEE mark in its name"
		}
		if self.Remote.InputNanoUsdPerMillion < 0 || self.Remote.OutputNanoUsdPerMillion < 0 ||
			self.Remote.CachedInputNanoUsdPerMillion < 0 {
			return "the remote entry " + name + " with a negative price"
		}
	default:
		return "the entry " + name + " of an unknown kind"
	}
	if len(self.Efforts) == 0 {
		return "the entry " + name + " with no effort"
	}
	for i, effort := range self.Efforts {
		if !effort.Valid() || slices.Contains(self.Efforts[:i], effort) {
			return "the entry " + name + " with an unknown or repeated effort"
		}
		if settings.NameMaxByteCount < len(self.Name(effort)) {
			return fmt.Sprintf("the entry %s with a name longer than %d bytes", name, settings.NameMaxByteCount)
		}
	}
	if !slices.Contains(self.Efforts, self.DefaultEffort) {
		return "the entry " + name + " with a default effort it does not list"
	}
	if self.ContextWindow <= 0 || self.MaxOutput <= 0 || self.ContextWindow < self.MaxOutput {
		return "the entry " + name + " whose window and output are not positive, the output within the window"
	}
	if !slices.Contains(self.Modalities, InferModalityText) {
		return "the entry " + name + " with no text modality"
	}
	for i, modality := range self.Modalities {
		if !slices.Contains(inferModalities, modality) || slices.Contains(self.Modalities[:i], modality) {
			return "the entry " + name + " with an unknown or repeated modality"
		}
	}
	return ""
}

// The catalog this device sees. Built by NewInferCatalog, NewInferLocalCatalog or Join, and never changed after.
type InferCatalog struct {
	entries []*InferCatalogEntry
	// the device its local entries were judged for; nil for a catalog with no device
	device *InferDeviceCapabilities
	// why it lists no local entry, or empty
	localUnavailable string
	// why it offers no remote entry, or empty
	remoteUnavailable string
	settings          *InferSettings
	// every canonical name, alias and search id, to the entry it names
	nameEntries map[string]*InferCatalogEntry
	// each model's entry, by <provider>-<model>
	modelEntries map[string]*InferCatalogEntry
}

// A catalog of remote entries and search endpoints, with no device and no local entry: each entry copied, checked
// whole, and its tool budget set from its window. Refused with ErrInferCatalogInvalid, whole, if any entry is not
// whole, is local, since only the release manifest names a model on a device (NewInferLocalCatalog), or two share a
// name or a model (§6.3).
func NewInferCatalog(entries []*InferCatalogEntry, settings *InferSettings) (*InferCatalog, error) {
	if err := inferRefuseLocalEntries(entries); err != nil {
		return nil, err
	}
	return newInferCatalog(entries, nil, "", settings)
}

// ErrInferCatalogInvalid where an entry given from outside the release manifest calls itself local.
func inferRefuseLocalEntries(entries []*InferCatalogEntry) error {
	for _, entry := range entries {
		if entry != nil && (entry.Kind == InferCatalogKindLocal || entry.Label == ComputeLabelLocal ||
			entry.Provider == computeLocalProvider) {
			return fmt.Errorf("%w: an entry from outside the release manifest calls itself local", ErrInferCatalogInvalid)
		}
	}
	return nil
}

// The catalog over entries, for device.
func newInferCatalog(entries []*InferCatalogEntry, device *InferDeviceCapabilities, localUnavailable string, settings *InferSettings) (*InferCatalog, error) {
	catalog := &InferCatalog{
		entries:          make([]*InferCatalogEntry, 0, len(entries)),
		localUnavailable: localUnavailable,
		settings:         settings,
		nameEntries:      map[string]*InferCatalogEntry{},
		modelEntries:     map[string]*InferCatalogEntry{},
	}
	if device != nil {
		catalog.device = device.clone()
	}
	name := func(name string, entry *InferCatalogEntry) error {
		if _, ok := catalog.nameEntries[name]; ok {
			return fmt.Errorf("%w: two entries named %s", ErrInferCatalogInvalid, name)
		}
		catalog.nameEntries[name] = entry
		return nil
	}
	for _, given := range entries {
		if given == nil {
			return nil, fmt.Errorf("%w: an empty entry", ErrInferCatalogInvalid)
		}
		entry := given.clone()
		if fault := entry.fault(settings); fault != "" {
			return nil, fmt.Errorf("%w: %s", ErrInferCatalogInvalid, fault)
		}
		if entry.Kind == InferCatalogKindSearch {
			if err := name(entry.SearchId(), entry); err != nil {
				return nil, err
			}
			catalog.entries = append(catalog.entries, entry)
			continue
		}
		entry.ToolBudget = 0
		if 0 < settings.ToolBudgetWindowDivisor {
			entry.ToolBudget = entry.ContextWindow / settings.ToolBudgetWindowDivisor
		}
		model := entry.Provider + "-" + entry.Model
		if _, ok := catalog.modelEntries[model]; ok {
			return nil, fmt.Errorf("%w: the model %s twice", ErrInferCatalogInvalid, model)
		}
		catalog.modelEntries[model] = entry
		for _, effort := range entry.Efforts {
			if err := name(entry.Name(effort), entry); err != nil {
				return nil, err
			}
		}
		if alias := entry.Alias(); alias != "" {
			if err := name(alias, entry); err != nil {
				return nil, err
			}
		}
		catalog.entries = append(catalog.entries, entry)
	}
	return catalog, nil
}

// The local view (§6.3, §6.5): manifest's models as this device sees them, each listed unavailable, with the reason,
// where the device lacks the memory, a build for its platform or an accelerator the model runs on. A platform with no
// engine build, one the manifest pins no engine for, a device whose platform is unknown, or a manifest with no model
// lists no local entry, and LocalUnavailable says which. A manifest that is not whole is refused, however it was
// made, with ErrInferManifestInvalid.
func NewInferLocalCatalog(manifest *InferManifest, device *InferDeviceCapabilities, settings *InferSettings) (*InferCatalog, error) {
	if manifest == nil {
		return nil, fmt.Errorf("%w: no manifest", ErrInferCatalogInvalid)
	}
	if err := manifest.validate(settings); err != nil {
		return nil, err
	}
	localUnavailable := ""
	switch {
	case len(manifest.Models) == 0:
		localUnavailable = "this build's release manifest lists no local model"
	case device == nil || device.Platform == "":
		localUnavailable = "this device's platform is unknown"
	case slices.Contains(inferUnbuiltPlatforms, device.Platform):
		localUnavailable = "no local engine is built for " + device.Platform + ", which gets remote models only"
	case manifest.Engine(device.Platform) == nil:
		localUnavailable = "this build pins no local engine for this device's platform"
	}
	if localUnavailable != "" {
		return newInferCatalog(nil, device, localUnavailable, settings)
	}
	// every device has a CPU, whatever else it lists
	deviceAccelerators := slices.Clone(device.Accelerators)
	if !slices.Contains(deviceAccelerators, InferAcceleratorCpu) {
		deviceAccelerators = append(deviceAccelerators, InferAcceleratorCpu)
	}
	entries := make([]*InferCatalogEntry, 0, len(manifest.Models))
	for _, model := range manifest.Models {
		files := []*InferManifestModelFile{}
		for _, file := range model.Files {
			if file.servesPlatform(device.Platform) {
				files = append(files, file)
			}
		}
		runnable := slices.ContainsFunc(files, func(file *InferManifestModelFile) bool {
			if file.Accelerator != "" {
				return slices.Contains(deviceAccelerators, file.Accelerator)
			}
			return slices.ContainsFunc(model.Accelerators, func(accelerator InferAccelerator) bool {
				return slices.Contains(deviceAccelerators, accelerator)
			})
		})
		unavailable := ""
		switch {
		case device.MemoryByteCount <= 0:
			unavailable = "this device's memory is unknown"
		case device.MemoryByteCount < model.MinMemoryByteCount:
			unavailable = fmt.Sprintf("it needs %.1f GiB of memory, and this device has %.1f GiB",
				float64(model.MinMemoryByteCount)/inferGibByteCount, float64(device.MemoryByteCount)/inferGibByteCount)
		case len(files) == 0:
			unavailable = "no build of it serves this device's platform"
		case !runnable:
			unavailable = "no build of it runs on this device's accelerators"
		}
		// newInferCatalog copies each entry, so the catalog shares none of the manifest's slices
		entries = append(entries, &InferCatalogEntry{
			Provider:         computeLocalProvider,
			Model:            model.Model,
			Kind:             InferCatalogKindLocal,
			Label:            ComputeLabelLocal,
			Efforts:          model.Efforts,
			DefaultEffort:    model.DefaultEffort,
			ContextWindow:    model.ContextWindow,
			MaxOutput:        model.MaxOutput,
			Tools:            model.Tools,
			StructuredOutput: model.StructuredOutput,
			Modalities:       model.Modalities,
			License:          model.License,
			Local: &InferLocalModel{
				Files:              files,
				MinMemoryByteCount: model.MinMemoryByteCount,
				Accelerators:       model.Accelerators,
				DecodeRates:        model.DecodeRates,
			},
			Unavailable: unavailable,
		})
	}
	return newInferCatalog(entries, device, "", settings)
}

// This catalog with entries added, its device and local view kept: how the remote catalog and the search endpoints
// join the local view (INFER-M12-01). Refused with ErrInferCatalogInvalid, whole, if an added entry is local, since
// only the release manifest names a model on this device, or the result would hold a name or a model twice.
func (self *InferCatalog) Join(entries []*InferCatalogEntry) (*InferCatalog, error) {
	if err := inferRefuseLocalEntries(entries); err != nil {
		return nil, err
	}
	return newInferCatalog(slices.Concat(self.entries, entries), self.device, self.localUnavailable, self.settings)
}

// Every entry, in order: copies.
func (self *InferCatalog) Entries() []*InferCatalogEntry {
	entries := make([]*InferCatalogEntry, len(self.entries))
	for i, entry := range self.entries {
		entries[i] = entry.clone()
	}
	return entries
}

// The device its local entries were judged for, a copy; nil for a catalog built with none.
func (self *InferCatalog) Device() *InferDeviceCapabilities {
	if self.device == nil {
		return nil
	}
	return self.device.clone()
}

// Why it lists no local entry: no build for the platform, no model in the manifest, an unknown device. Empty when it
// lists some, available or not.
func (self *InferCatalog) LocalUnavailable() string {
	return self.localUnavailable
}

// Why it offers no remote entry, where a filter or floor left none. Empty otherwise.
func (self *InferCatalog) RemoteUnavailable() string {
	return self.remoteUnavailable
}

// A name the catalog resolved for a call.
type InferCatalogResolution struct {
	// The model's entry, a copy.
	Entry *InferCatalogEntry
	// The effort the call runs at: the name's own, or for an alias the request's mapped to the nearest the model
	// lists, else the model's default. Always one the model lists.
	Effort InferEffort
	// The canonical name the call runs under, with that effort, which the record and the badge name.
	Name string
	// Whether the name asked was an alias.
	Alias bool
}

// The model name names, and the effort a call to it runs at (§6.3, Q-INFER-5). A full name's effort wins over
// requestEffort, the request's reasoning parameter, and must be one the model lists; an alias takes requestEffort
// mapped to the nearest the model lists, the lower of two equally near, or the model's default where the request asks
// none in particular. Refuses a name outside the grammar (ErrInferModelNameInvalid), one no entry answers
// (ErrInferModelUnknown), a full name's unlisted effort (ErrInferEffortUnlisted), an alias's request effort that is
// no word of §6.3's (ErrInferEffortUnknown), and a model this device may not use (ErrInferModelUnavailable, with the
// entry's reason). A search id is no model name, and is refused as one.
func (self *InferCatalog) Resolve(name string, requestEffort string) (*InferCatalogResolution, error) {
	parsed, err := InferParseModelName(name, self.settings)
	if err != nil {
		return nil, err
	}
	model := parsed.Provider + "-" + parsed.Model
	entry, ok := self.modelEntries[model]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInferModelUnknown, parsed.String())
	}
	effort := parsed.Effort
	if parsed.IsAlias() {
		asked, err := ParseInferRequestEffort(requestEffort)
		if err != nil {
			return nil, err
		}
		effort = entry.DefaultEffort
		if asked != "" {
			effort = inferNearestEffort(asked, entry.Efforts)
		}
	} else if !slices.Contains(entry.Efforts, effort) {
		return nil, fmt.Errorf("%w: %s takes no effort %s", ErrInferEffortUnlisted, model, effort)
	}
	if entry.Unavailable != "" {
		return nil, fmt.Errorf("%w: %s: %s", ErrInferModelUnavailable, model, entry.Unavailable)
	}
	return &InferCatalogResolution{
		Entry:  entry.clone(),
		Effort: effort,
		Name:   entry.Name(effort),
		Alias:  parsed.IsAlias(),
	}, nil
}

// The search endpoint id names (§21), a copy, refusing an id outside search/<engine>/<kind>
// (ErrInferSearchIdInvalid) and one the catalog does not list (ErrInferModelUnknown). A model name is no search id.
func (self *InferCatalog) SearchEndpoint(id string) (*InferCatalogEntry, error) {
	parsed, err := InferParseSearchId(id, self.settings)
	if err != nil {
		return nil, err
	}
	entry, ok := self.nameEntries[parsed.String()]
	if !ok || entry.Kind != InferCatalogKindSearch {
		return nil, fmt.Errorf("%w: %s", ErrInferModelUnknown, parsed.String())
	}
	return entry.clone(), nil
}

// The local model §6.5's defaults recommend for this device, by its class and memory, and its entry, a copy: the
// first of the settings' LocalDefaults whose classes hold the device's, whose memory floor it meets, unified where
// that is asked, and whose name resolves to a local entry the device may use. An empty name where none fits, or the
// catalog has no device, so the bot tab offers credit and a remote model instead (§15.4).
func (self *InferCatalog) Recommended() (string, *InferCatalogEntry) {
	device := self.device
	if device == nil {
		return "", nil
	}
	for _, localDefault := range self.settings.LocalDefaults {
		if localDefault == nil || !slices.Contains(localDefault.DeviceClasses, device.Class) ||
			device.MemoryByteCount < localDefault.MinMemoryByteCount ||
			(localDefault.UnifiedMemory && !device.UnifiedMemory) {
			continue
		}
		resolution, err := self.Resolve(localDefault.Name, "")
		if err != nil || resolution.Entry.Kind != InferCatalogKindLocal {
			continue
		}
		return resolution.Name, resolution.Entry
	}
	return "", nil
}

// What a list of the catalog keeps: the picker's and ur models' filters (§6.3, §15.1), and a person's or network's
// limits (§16.4).
type InferCatalogFilter struct {
	// Local entries alone.
	LocalOnly bool
	// The floor, providers and tee_only a remote entry must pass, a local one passing any (ComputeAssurance.Admits);
	// nil keeps every remote entry. Search endpoints are no inference, and pass.
	Assurance *ComputeAssurance
}

// The entries filter keeps, the catalog's device and local view with them. Where the catalog held a remote entry and
// none passes, RemoteUnavailable says why, and the local entries stay (§6.3).
func (self *InferCatalog) Filter(filter *InferCatalogFilter) *InferCatalog {
	if filter == nil {
		filter = &InferCatalogFilter{}
	}
	kept := []*InferCatalogEntry{}
	remoteHeld := false
	remoteKept := false
	for _, entry := range self.entries {
		remote := entry.Kind == InferCatalogKindTee || entry.Kind == InferCatalogKindDirect
		remoteHeld = remoteHeld || remote
		switch {
		case filter.LocalOnly && entry.Kind != InferCatalogKindLocal:
			continue
		case entry.Kind != InferCatalogKindSearch && filter.Assurance != nil &&
			!filter.Assurance.Admits(entry.Provider, entry.Label):
			continue
		}
		remoteKept = remoteKept || remote
		kept = append(kept, entry)
	}
	catalog := self.subset(kept)
	if remoteHeld && !remoteKept {
		switch {
		case filter.LocalOnly:
			catalog.remoteUnavailable = "the list holds local models alone"
		case filter.Assurance.EffectiveFloor() == "":
			catalog.remoteUnavailable = "no assurance floor allows a remote model"
		default:
			catalog.remoteUnavailable = fmt.Sprintf("no remote model meets the assurance floor %s from an allowed provider",
				filter.Assurance.EffectiveFloor())
		}
	}
	return catalog
}

// A catalog of entries already this one's, its device and its reasons kept: each entry checked and distinct, and never
// changed once a catalog holds it, so the two share them, and nothing can fail.
func (self *InferCatalog) subset(entries []*InferCatalogEntry) *InferCatalog {
	catalog := &InferCatalog{
		entries:           entries,
		device:            self.device,
		localUnavailable:  self.localUnavailable,
		remoteUnavailable: self.remoteUnavailable,
		settings:          self.settings,
		nameEntries:       map[string]*InferCatalogEntry{},
		modelEntries:      map[string]*InferCatalogEntry{},
	}
	kept := map[*InferCatalogEntry]bool{}
	for _, entry := range entries {
		kept[entry] = true
	}
	for name, entry := range self.nameEntries {
		if kept[entry] {
			catalog.nameEntries[name] = entry
		}
	}
	for model, entry := range self.modelEntries {
		if kept[entry] {
			catalog.modelEntries[model] = entry
		}
	}
	return catalog
}

// The catalog as JSON: its entries, and why it lists no local or remote entry where it says.
func (self *InferCatalog) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Entries           []*InferCatalogEntry `json:"entries"`
		LocalUnavailable  string               `json:"local_unavailable,omitempty"`
		RemoteUnavailable string               `json:"remote_unavailable,omitempty"`
	}{
		Entries:           self.entries,
		LocalUnavailable:  self.localUnavailable,
		RemoteUnavailable: self.remoteUnavailable,
	})
}
