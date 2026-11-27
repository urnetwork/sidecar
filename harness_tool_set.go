//go:build !ios_extension && !sidecar_http

// The tool budget (DESIGN-COMPUTE §7.4, §6.3, R-CCTX-6): a request's tool schemas and the skill take at most a share
// of the model's window, the catalog's ToolBudget for the model, or HarnessSettings.ToolBudgetFraction of its window
// where the catalog gives none. An agent whose spec names no tools gets its profile's whole set where it fits, else
// the small set (HarnessSettings.SmallToolNames), each where a tool of the name serves the profile; a spec or an
// agent_launch that names more than the budget holds, or a tool its profile does not serve (bash in local among them),
// is refused before the agent starts.
//
// Tokens are estimated as Pi does, bytes over HarnessSettings.TokenEstimateByteCount, over each tool's name,
// description and schema, the recURd skill's text, and once each, the text of a skill the tools come with (§28.4).

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

var (
	// The named tools and the skill take more of the model's window than the tool budget holds.
	ErrHarnessToolBudget = errors.New("the tools and the skill pass the model's tool budget")
)

// The tokens text takes, estimated as Pi does: its bytes over settings' TokenEstimateByteCount, rounded up.
func harnessEstimateTokens(settings *HarnessSettings, byteCount int) int64 {
	perToken := settings.TokenEstimateByteCount
	if perToken < 1 {
		perToken = 1
	}
	return int64((byteCount + perToken - 1) / perToken)
}

// The tokens one tool's declaration takes in a request: its name, description and schema.
func harnessToolTokens(settings *HarnessSettings, tool HarnessTool) int64 {
	return harnessEstimateTokens(settings, len(tool.Name())+len(tool.Description())+len(tool.Schema()))
}

// The tool budget of a model: the catalog's where it gives one, else ToolBudgetFraction of its window; 0 where there
// is no window to take it from.
func harnessToolBudget(settings *HarnessSettings, entry *InferCatalogEntry) int64 {
	if entry == nil {
		return 0
	}
	if 0 < entry.ToolBudget {
		return entry.ToolBudget
	}
	if settings.ToolBudgetFraction <= 0 || entry.ContextWindow <= 0 {
		return 0
	}
	return int64(float64(entry.ContextWindow) * settings.ToolBudgetFraction)
}

// One agent's tools, in the order a request declares them.
type harnessToolSet struct {
	names []string
	tools []HarnessTool
	specs []*HarnessToolSpec
	// the skills the tools come with, each once, in the order their first tool is declared
	skills []*HarnessToolSkill
	// whether the profile's whole set did not fit and the small set was taken
	small bool
}

// The tools an agent in profile gets (§7.4): named, each served by profile and together with the skill within
// budget, else refused; or, naming none, the profile's whole set where it fits, else the small set.
func newHarnessToolSet(settings *HarnessSettings, registry *HarnessToolRegistry, profile HarnessProfile, named []string, skillText string, budget int64) (*harnessToolSet, error) {
	skillTokens := harnessEstimateTokens(settings, len(skillText))
	take := func(names []string, refuseMissing bool) (*harnessToolSet, int64, error) {
		set := &harnessToolSet{}
		tokens := skillTokens
		seen := map[string]bool{}
		skills := map[string]bool{}
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			tool, spec, ok := registry.Tool(name, profile)
			if available, offered := tool.(HarnessToolAvailable); ok && offered && !available.Available(context.Background()) {
				// not offered now: left out, never refused (web_search without a search line, §21.11)
				continue
			}
			if !ok {
				if refuseMissing {
					return nil, 0, fmt.Errorf("%w: %s is not served in %s", ErrHarnessToolOutsideProfile, name, profile)
				}
				continue
			}
			set.names = append(set.names, name)
			set.tools = append(set.tools, tool)
			set.specs = append(set.specs, spec)
			tokens += harnessToolTokens(settings, tool)
			if spec.Skill != nil && !skills[spec.Skill.Name] {
				skills[spec.Skill.Name] = true
				set.skills = append(set.skills, spec.Skill)
				tokens += harnessEstimateTokens(settings, len(spec.Skill.Text))
			}
		}
		return set, tokens, nil
	}
	if 0 < len(named) {
		set, tokens, err := take(named, true)
		if err != nil {
			return nil, err
		}
		if budget < tokens {
			return nil, fmt.Errorf("%w: %d tokens for a budget of %d", ErrHarnessToolBudget, tokens, budget)
		}
		return set, nil
	}
	whole, tokens, _ := take(registry.Names(profile), false)
	if tokens <= budget {
		return whole, nil
	}
	small, _, _ := take(settings.SmallToolNames, false)
	small.small = true
	return small, nil
}

// The tool named name in the set, and its registration.
func (self *harnessToolSet) tool(name string) (HarnessTool, *HarnessToolSpec, bool) {
	for i, setName := range self.names {
		if setName == name {
			return self.tools[i], self.specs[i], true
		}
	}
	return nil, nil, false
}
