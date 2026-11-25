//go:build !ios_extension && !sidecar_http

// The tools' registration seam (DESIGN-COMPUTE §7.5, D-HARN-2, HARN-M11-03): every area registers its Harness tools
// from an init function in its own file, as registerMcpTools does, so no shared file grows a row per tool: GIT's git,
// SRCH's web_search, FETCH's web_fetch, SKILL's agent_*, MAILCAL's mail and calendar, CONN's connections, ENC's
// enclave_*, SSH's ssh_exec, LSTN's listeners_list, INFER's models_list, BAL's compute_*, and the Harness's own.
//
// A registration names the tool, the profiles it serves (§7.5's local and enclave columns), whether it is built in
// (only a built-in may mark keep: false, §24.9), and a constructor taking the Harness, which builds the tool once per
// Harness. A second registration of a name panics at start. The local profile is §7.5's local column: no bash, no host
// path and no process (CO-6, IC-7); the enclave profile its enclave column, wired by HARN-M14-05.
//
// HarnessToolRegistry is one Harness's tools, built from the registrations; safe for concurrent use once built.

package sidecar

import (
	"fmt"
	"slices"
	"sort"
)

// A tool profile (§7.5).
type HarnessProfile string

const (
	// A person's device: the bundled tools and a temp workspace only (R-HARN-4, CO-6).
	HarnessProfileLocal HarnessProfile = "local"
	// An enclave: full Debian tools in the agents' container (R-HARN-5, CO-5).
	HarnessProfileEnclave HarnessProfile = "enclave"
)

// One tool's registration.
type HarnessToolSpec struct {
	Name string
	// The profiles it serves, one or both.
	Profiles []HarnessProfile
	// Whether it is built into sidecar, the only kind whose keep: false details are honored (§24.9).
	BuiltIn bool
	// Builds the tool for one Harness. An error leaves the tool out of that Harness, logged.
	New func(harness *Harness) (HarnessTool, error)
}

// Every registration, by name, written only during the package's init.
var harnessToolSpecs = map[string]*HarnessToolSpec{}

// Registers a tool from an init function in its area's own file. A name registered twice, an empty name, no profile,
// a profile this build does not know or a nil constructor is a build error, which panics at start.
func RegisterHarnessTool(spec *HarnessToolSpec) {
	if err := harnessToolSpecValid(spec); err != nil {
		panic(err.Error())
	}
	if _, registered := harnessToolSpecs[spec.Name]; registered {
		panic(fmt.Sprintf("harness tool %q registered twice", spec.Name))
	}
	harnessToolSpecs[spec.Name] = spec
}

// Why spec cannot register, or nil.
func harnessToolSpecValid(spec *HarnessToolSpec) error {
	if spec == nil || spec.Name == "" || spec.New == nil || len(spec.Profiles) == 0 {
		return fmt.Errorf("harness tool %v registered without a name, a profile or a constructor", spec)
	}
	for _, profile := range spec.Profiles {
		if profile != HarnessProfileLocal && profile != HarnessProfileEnclave {
			return fmt.Errorf("harness tool %q registered for profile %q", spec.Name, profile)
		}
	}
	return nil
}

// One built tool and its registration.
type harnessRegisteredTool struct {
	spec *HarnessToolSpec
	tool HarnessTool
}

// One Harness's tools.
type HarnessToolRegistry struct {
	nameTools map[string]*harnessRegisteredTool
}

// The registry of specs built for harness: each tool constructed once, one whose constructor fails left out and logged.
func newHarnessToolRegistry(harness *Harness, specs map[string]*HarnessToolSpec) *HarnessToolRegistry {
	registry := &HarnessToolRegistry{nameTools: map[string]*harnessRegisteredTool{}}
	for name, spec := range specs {
		tool, err := spec.New(harness)
		if err != nil || tool == nil {
			if harness != nil && harness.log != nil {
				harness.log.Warningf("[harness]tool %s is left out: %v", name, err)
			}
			continue
		}
		registry.nameTools[name] = &harnessRegisteredTool{spec: spec, tool: tool}
	}
	return registry
}

// The tool named name and its registration, where it serves profile; false otherwise, a tool registered for the other
// profile alone among them.
func (self *HarnessToolRegistry) Tool(name string, profile HarnessProfile) (HarnessTool, *HarnessToolSpec, bool) {
	registered, ok := self.nameTools[name]
	if !ok || !slices.Contains(registered.spec.Profiles, profile) {
		return nil, nil, false
	}
	return registered.tool, registered.spec, true
}

// The names of every tool serving profile, sorted.
func (self *HarnessToolRegistry) Names(profile HarnessProfile) []string {
	names := []string{}
	for name, registered := range self.nameTools {
		if slices.Contains(registered.spec.Profiles, profile) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
