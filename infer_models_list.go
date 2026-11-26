//go:build !ios_extension && !sidecar_http

// models_list (DESIGN-COMPUTE §7.5, §6.3; R-INFER-1, D-INFER-7; INFER-M11-09): the Harness tool an agent asks which
// models it may use, its answer the router's own: every model of the catalog whose canonical names the router's Check
// lets this agent's run call, with its label, provider, efforts, context window, whether it calls tools, its prices,
// and whether its provider's disclosure is acknowledged, a model waiting only for that listed with it unacknowledged.
// The checks are the calls' (the policy, the floor, the providers, tee_only, allow, the device's budgets and the run's
// limited_use mark), so an agent is never offered a model a call to it would refuse; in an enclave they read its
// sponsor's rules (§2.8, §16.4). A listing asks no one: a model labeled none waiting for its disclosure is listed
// unacknowledged, never put to the person attached to the run (inferCheckWithoutAsking).
//
// It is a Harness tool only, on both profiles: §15.2 lists no MCP models_list, and registerMcpTools would serve it to
// every external session (compute-plan-inference-small-readings, QD-1247). It reads nothing outside the device and
// taints nothing: every name it gives is a canonical name the release manifest or the signed policy carries, since the
// checks refuse any remote model the policy does not cover; a name that were not would be given only within §6.3's
// grammar and InferSettings.NameMaxByteCount, between the untrusted-data markers. Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// The tool's name, as the Harness registers it.
const inferModelsListToolName = "models_list"

// What the model reads of the tool.
const inferModelsListDescription = "List the models this agent may call, local and remote, each with its label (local, " +
	"A2, A1, AP or none), provider, efforts, context window, whether it calls tools, its prices per million tokens and " +
	"whether its provider's disclosure is acknowledged. Optional filter: local, tee, or a provider's name."

// The tool's arguments' schema.
const inferModelsListSchema = `{"type":"object","properties":{"filter":{"type":"string","description":"local, tee, or a provider's name"}},"additionalProperties":false}`

// The filter words beside a provider's name.
const (
	inferModelsListFilterLocal = "local"
	inferModelsListFilterTee   = "tee"
)

// Registers models_list on both profiles, built into sidecar.
func init() {
	RegisterHarnessTool(&HarnessToolSpec{
		Name:     inferModelsListToolName,
		Profiles: []HarnessProfile{HarnessProfileLocal, HarnessProfileEnclave},
		BuiltIn:  true,
		New: func(harness *Harness) (HarnessTool, error) {
			if harness == nil || harness.router == nil {
				return nil, errors.New("models_list needs the Harness's router")
			}
			return &inferModelsListTool{router: harness.router, settings: DefaultInferSettings()}, nil
		},
	})
}

// models_list over a router.
type inferModelsListTool struct {
	router   InferRouter
	settings *InferSettings
}

// One model as models_list gives it.
type inferModelsListEntry struct {
	// The canonical name at its default effort, or the first effort the agent may call it at, plain or between the
	// markers.
	Name     string       `json:"name"`
	Label    ComputeLabel `json:"label"`
	Provider string       `json:"provider"`
	// The efforts this agent may call it at.
	Efforts       []InferEffort `json:"efforts"`
	ContextWindow int64         `json:"context_window"`
	Tools         bool          `json:"tools"`
	// A remote model's prices per million tokens, in nano-USD; none for a local one, which is free (CO-9).
	InputNanoUsdPerMillion       int64 `json:"input_nano_usd_per_million,omitempty"`
	OutputNanoUsdPerMillion      int64 `json:"output_nano_usd_per_million,omitempty"`
	CachedInputNanoUsdPerMillion int64 `json:"cached_input_nano_usd_per_million,omitempty"`
	// Whether its provider's disclosure is acknowledged, or none is needed; false for a model labeled none that waits.
	DisclosureAcknowledged bool `json:"disclosure_acknowledged"`
}

// models_list's answer.
type inferModelsListAnswer struct {
	Models []*inferModelsListEntry `json:"models"`
}

func (self *inferModelsListTool) Name() string        { return inferModelsListToolName }
func (self *inferModelsListTool) Description() string { return inferModelsListDescription }
func (self *inferModelsListTool) Schema() []byte      { return []byte(inferModelsListSchema) }
func (self *inferModelsListTool) Mode() string        { return HarnessToolParallel }
func (self *inferModelsListTool) Tier() string        { return HarnessToolTierRead }

// A name as a model reads it: plain where a signed source vouches for it; else only within §6.3's grammar and the
// settings' bound, between the untrusted-data markers, and dropped otherwise.
func (self *inferModelsListTool) nameText(name string, signed bool) (string, bool) {
	if _, err := InferParseModelName(name, self.settings); err != nil {
		return "", false
	}
	if signed {
		return name, true
	}
	return (&ComputeDisplayName{Text: name, Trust: ComputeNameMarked, Writer: "broker"}).ModelText(), true
}

// Whether entry passes the filter.
func inferModelsListPasses(entry *InferCatalogEntry, filter string) bool {
	switch filter {
	case "":
		return true
	case inferModelsListFilterLocal:
		return entry.Kind == InferCatalogKindLocal
	case inferModelsListFilterTee:
		return entry.Kind == InferCatalogKindLocal || entry.Label.Tee()
	}
	return entry.Provider == filter
}

// The models this agent may use, as the router's Check lets its run call them: each model listed with the efforts it
// passes at, one waiting only for its disclosure listed unacknowledged; taints nothing.
func (self *inferModelsListTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	read := &struct {
		Filter string `json:"filter"`
	}{}
	if 0 < len(args) {
		if err := json.Unmarshal(args, read); err != nil {
			return nil, fmt.Errorf("models_list's arguments do not read: %w", err)
		}
	}
	var runId, agentId *Id
	if call, ok := HarnessCallFromContext(ctx); ok && call.Run() != nil {
		run, agent := call.Run().Id(), call.Run().AgentId()
		runId, agentId = &run, &agent
	}
	catalog, err := self.router.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	listing := inferCheckWithoutAsking(ctx)
	answer := &inferModelsListAnswer{Models: []*inferModelsListEntry{}}
	for _, entry := range catalog.Entries() {
		if entry.Kind == InferCatalogKindSearch || entry.Unavailable != "" || !inferModelsListPasses(entry, read.Filter) {
			continue
		}
		listed := &inferModelsListEntry{
			Label:                  entry.Label,
			Provider:               entry.Provider,
			Efforts:                []InferEffort{},
			ContextWindow:          entry.ContextWindow,
			Tools:                  entry.Tools,
			DisclosureAcknowledged: true,
		}
		for _, effort := range entry.Efforts {
			err := self.router.Check(listing, &InferRequest{Model: entry.Name(effort), RunId: runId, AgentId: agentId})
			switch InferErrorCodeOf(err) {
			case "":
				if err != nil {
					continue
				}
			case InferErrorDisclosureRequired:
				listed.DisclosureAcknowledged = false
			default:
				continue
			}
			listed.Efforts = append(listed.Efforts, effort)
		}
		if len(listed.Efforts) == 0 {
			continue
		}
		// named at its default effort where the agent may call it there, else at the first it may
		effort := listed.Efforts[0]
		if slices.Contains(listed.Efforts, entry.DefaultEffort) {
			effort = entry.DefaultEffort
		}
		// a model the checks pass is the manifest's or the signed policy's: a remote one the policy does not cover is
		// refused before any other check
		name, ok := self.nameText(entry.Name(effort), entry.Kind == InferCatalogKindLocal || entry.remote())
		if !ok {
			continue
		}
		listed.Name = name
		if entry.Remote != nil {
			listed.InputNanoUsdPerMillion = entry.Remote.InputNanoUsdPerMillion
			listed.OutputNanoUsdPerMillion = entry.Remote.OutputNanoUsdPerMillion
			listed.CachedInputNanoUsdPerMillion = entry.Remote.CachedInputNanoUsdPerMillion
		}
		answer.Models = append(answer.Models, listed)
	}
	slices.SortStableFunc(answer.Models, func(a *inferModelsListEntry, b *inferModelsListEntry) int {
		// local first, as the picker shows them, then by name
		aLocal, bLocal := a.Label == ComputeLabelLocal, b.Label == ComputeLabelLocal
		switch {
		case aLocal && !bLocal:
			return -1
		case !aLocal && bLocal:
			return 1
		}
		return 0
	})
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	return &HarnessToolResult{Text: string(encoded), Details: encoded, Trust: HarnessToolTrusted}, nil
}
