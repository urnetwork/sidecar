//go:build !ios_extension && !sidecar_http

// The person's `models` key (DESIGN-COMPUTE §16.4; D-CACL-3, D-CACL-4; CACL-M11-01), in the member's harness config
// (MemberHarnessConfig), which acts from M11 and only narrows what the network grants:
//
//	default       a canonical name (§6.3, INFER's parser), the model a run takes where it names none
//	allow         globs within canonical names, `*` matching any run inside a name and never read as a label; absent
//	              is every model (Q-CACL-3's (a)), [] is none
//	tee_only      the person's own floor of AP, off by default (Q-CACL-3's (a))
//	sign_in_mail  withhold, the default, or allow (§23.4)
//	harness       codex's tier model; claude-code's tiers opus, sonnet and haiku: each a canonical name (§8.8)
//	agents        <label>.default: an agent's default model, its label an agent label (SidecarAgentLabelSettings)
//
// Only the person writes it, by their own act (`ur models set` on /dev/tty, `Models().SetSettings` in an app's UI;
// Q-CACL-3), through MemberHarnessConfig.Update, and no tool or MCP call does (DESIGN §16.6). A write changes only the
// fields that changed, each spliced where it stands, so the rest of the key and the file keep their bytes.
//
// A read is lenient where a later release may write more: a field, harness or tier this build does not know is passed
// over and named in the read's warnings, as unknown keys are (DESIGN §16.7). A field this build knows holding a value
// it refuses makes the key unreadable: a config_unreadable gap, and the gate refuses every model under rule allow, the
// closed reading, since the defaults would widen what the person set. A write is strict: it takes nothing this build
// does not know.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// The key's name in the harness config's object.
const harnessModelsKeyName = "models"

// The models key's fields (§16.4).
const (
	harnessModelsFieldDefault    = "default"
	harnessModelsFieldAllow      = "allow"
	harnessModelsFieldTeeOnly    = "tee_only"
	harnessModelsFieldSignInMail = "sign_in_mail"
	harnessModelsFieldHarness    = "harness"
	harnessModelsFieldAgents     = "agents"
)

// The harnesses and their tiers, as §16.4 and §8.8 name them.
const (
	HarnessModelsCodex      = "codex"
	HarnessModelsClaudeCode = "claude-code"

	HarnessModelsTierModel  = "model"
	HarnessModelsTierOpus   = "opus"
	HarnessModelsTierSonnet = "sonnet"
	HarnessModelsTierHaiku  = "haiku"
)

// Each harness's tiers.
var harnessModelsTiers = map[string][]string{
	HarnessModelsCodex:      {HarnessModelsTierModel},
	HarnessModelsClaudeCode: {HarnessModelsTierOpus, HarnessModelsTierSonnet, HarnessModelsTierHaiku},
}

// What sign_in_mail may say (§23.4).
type HarnessSignInMail string

const (
	// The default: sign-in mail's codes and links go to no model outside the device and A1 or A2 TEEs.
	HarnessSignInMailWithhold HarnessSignInMail = "withhold"
	// They go where the run's model goes.
	HarnessSignInMailAllow HarnessSignInMail = "allow"
)

// A models key with a value this build refuses: a name outside §6.3's grammar, a glob past its bounds, an unknown
// sign_in_mail, tier or field where the key must be exact, or one of the wrong JSON type.
var ErrModelsKeyInvalid = errors.New("models key invalid")

// One agent's entry under agents.
type HarnessModelsAgent struct {
	// The agent's default model, a canonical name; empty for none.
	Default string
}

// The person's models key (§16.4). The zero value is the defaults: every model, tee_only off, sign_in_mail withhold.
type HarnessModelsKey struct {
	// The default model, a canonical name; empty for none.
	Default string
	// The globs every model a call runs must match one of; nil is every model, empty is none.
	Allow []string
	// The person's floor of AP: no remote model below it.
	TeeOnly bool
	// withhold or allow; empty reads as withhold.
	SignInMail HarnessSignInMail
	// Each harness's tiers, harness to tier to canonical name; nil for none.
	Harness map[string]map[string]string
	// Each agent's entry, by its label; nil for none.
	Agents map[string]*HarnessModelsAgent
}

// sign_in_mail as it acts: withhold unless allow.
func (self *HarnessModelsKey) SignInMailMode() HarnessSignInMail {
	if self.SignInMail == HarnessSignInMailAllow {
		return HarnessSignInMailAllow
	}
	return HarnessSignInMailWithhold
}

// A copy sharing nothing.
func (self *HarnessModelsKey) Clone() *HarnessModelsKey {
	clone := *self
	if self.Allow != nil {
		clone.Allow = slices.Clone(self.Allow)
	}
	if self.Harness != nil {
		clone.Harness = map[string]map[string]string{}
		for harness, tiers := range self.Harness {
			clone.Harness[harness] = maps.Clone(tiers)
		}
	}
	if self.Agents != nil {
		clone.Agents = map[string]*HarnessModelsAgent{}
		for label, agent := range self.Agents {
			agentClone := *agent
			clone.Agents[label] = &agentClone
		}
	}
	return &clone
}

// The key as this device read it.
type HarnessModelsKeyRead struct {
	// The key: the defaults where the file or the key is absent, and where the key does not read.
	Key *HarnessModelsKey
	// The key does not read: the gate refuses every model, the closed reading, and Gap is config_unreadable.
	Unreadable bool
	// config_unreadable where the file or the key does not read.
	Gap string
	// Why it does not read, naming no value of it.
	Reason string
	// The fields, harnesses and tiers this build does not know, passed over (DESIGN §16.7's ignored with a warning).
	Warnings []string
	// The file's read.
	Config *MemberHarnessConfigRead
}

// What a models key's values are checked against.
type harnessModelsLimits struct {
	settings *ModelsKeySettings
	infer    *InferSettings
	// refuse what this build does not know, rather than pass it over with a warning
	strict bool
}

// The key value raw holds, checked: strict refuses a field, harness or tier this build does not know, which a lenient
// read passes over and names in its warnings. ErrModelsKeyInvalid, wrapped, names what failed and never a value.
func ParseHarnessModelsKey(raw json.RawMessage, strict bool, settings *ModelsKeySettings, infer *InferSettings) (*HarnessModelsKey, []string, error) {
	limits := &harnessModelsLimits{settings: settings, infer: infer, strict: strict}
	object, err := parseHarnessJsonObject(raw, 0, len(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrModelsKeyInvalid, err)
	}
	key := &HarnessModelsKey{}
	warnings := []string{}
	value := func(member harnessJsonMember) []byte {
		return raw[member.valueStart:member.valueEnd]
	}
	for _, member := range object.members {
		switch member.key {
		case harnessModelsFieldDefault:
			if key.Default, err = limits.name(value(member), "default"); err != nil {
				return nil, nil, err
			}
		case harnessModelsFieldAllow:
			if key.Allow, err = limits.allow(value(member)); err != nil {
				return nil, nil, err
			}
		case harnessModelsFieldTeeOnly:
			if err := harnessModelsDecode(value(member), &key.TeeOnly, "tee_only"); err != nil {
				return nil, nil, err
			}
		case harnessModelsFieldSignInMail:
			var mode string
			if err := harnessModelsDecode(value(member), &mode, "sign_in_mail"); err != nil {
				return nil, nil, err
			}
			key.SignInMail = HarnessSignInMail(mode)
			if key.SignInMail != HarnessSignInMailWithhold && key.SignInMail != HarnessSignInMailAllow {
				return nil, nil, fmt.Errorf("%w: sign_in_mail is withhold or allow", ErrModelsKeyInvalid)
			}
		case harnessModelsFieldHarness:
			if key.Harness, err = limits.harness(value(member), &warnings); err != nil {
				return nil, nil, err
			}
		case harnessModelsFieldAgents:
			if key.Agents, err = limits.agents(value(member), &warnings); err != nil {
				return nil, nil, err
			}
		default:
			if strict {
				return nil, nil, fmt.Errorf("%w: an unknown field", ErrModelsKeyInvalid)
			}
			warnings = append(warnings, fmt.Sprintf("models.%s is not known to this build", member.key))
		}
	}
	return key, warnings, nil
}

// value decoded into target, or ErrModelsKeyInvalid naming field.
func harnessModelsDecode(value []byte, target any, field string) error {
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, target) != nil {
		return fmt.Errorf("%w: %s holds the wrong type", ErrModelsKeyInvalid, field)
	}
	return nil
}

// A canonical name, held to §6.3's grammar by INFER's parser.
func (self *harnessModelsLimits) name(value []byte, field string) (string, error) {
	var name string
	if err := harnessModelsDecode(value, &name, field); err != nil {
		return "", err
	}
	if err := self.checkName(name, field); err != nil {
		return "", err
	}
	return name, nil
}

// Whether name is a canonical name or an alias, by §6.3's grammar.
func (self *harnessModelsLimits) checkName(name string, field string) error {
	if _, err := InferParseModelName(name, self.infer); err != nil {
		return fmt.Errorf("%w: %s is no canonical name: %w", ErrModelsKeyInvalid, field, err)
	}
	return nil
}

// allow's globs, each checked.
func (self *harnessModelsLimits) allow(value []byte) ([]string, error) {
	globs := []string{}
	if err := harnessModelsDecode(value, &globs, "allow"); err != nil {
		return nil, err
	}
	if err := self.checkAllow(globs); err != nil {
		return nil, err
	}
	return globs, nil
}

// Whether globs are allow's: at most AllowMaxCount, each a glob within a canonical name.
func (self *harnessModelsLimits) checkAllow(globs []string) error {
	if self.settings.AllowMaxCount < len(globs) {
		return fmt.Errorf("%w: allow holds more than %d globs", ErrModelsKeyInvalid, self.settings.AllowMaxCount)
	}
	for i, glob := range globs {
		if err := self.checkGlob(glob); err != nil {
			return fmt.Errorf("%w: allow[%d]: %w", ErrModelsKeyInvalid, i, err)
		}
	}
	return nil
}

// A glob within a canonical name: no longer than a name, of a name's characters [a-z0-9.-] and `*`, at most
// AllowGlobWildcardMaxCount stars; with none it is a name, held to §6.3's grammar.
func (self *harnessModelsLimits) checkGlob(glob string) error {
	if glob == "" || self.infer.NameMaxByteCount < len(glob) {
		return fmt.Errorf("a glob of 1 to %d bytes", self.infer.NameMaxByteCount)
	}
	wildcardCount := 0
	for i := 0; i < len(glob); i += 1 {
		c := glob[i]
		switch {
		case c == '*':
			wildcardCount += 1
		case !inferNameByte(c):
			return errors.New("a character outside [a-z0-9.-*]")
		}
	}
	if self.settings.AllowGlobWildcardMaxCount < wildcardCount {
		return fmt.Errorf("more than %d *", self.settings.AllowGlobWildcardMaxCount)
	}
	if wildcardCount == 0 {
		if _, err := InferParseModelName(glob, self.infer); err != nil {
			return err
		}
	}
	return nil
}

// harness's tiers, each a canonical name; a harness or tier this build does not know is refused where strict, else
// passed over with a warning.
func (self *harnessModelsLimits) harness(value []byte, warnings *[]string) (map[string]map[string]string, error) {
	object, err := parseHarnessJsonObject(value, 0, len(value))
	if err != nil {
		return nil, fmt.Errorf("%w: harness: %v", ErrModelsKeyInvalid, err)
	}
	harnesses := map[string]map[string]string{}
	for _, harnessMember := range object.members {
		tierNames, known := harnessModelsTiers[harnessMember.key]
		if !known {
			if self.strict {
				return nil, fmt.Errorf("%w: harness names an unknown harness", ErrModelsKeyInvalid)
			}
			*warnings = append(*warnings, fmt.Sprintf("models.harness.%s is not known to this build", harnessMember.key))
			continue
		}
		tierValue := value[harnessMember.valueStart:harnessMember.valueEnd]
		tierObject, err := parseHarnessJsonObject(tierValue, 0, len(tierValue))
		if err != nil {
			return nil, fmt.Errorf("%w: harness.%s: %v", ErrModelsKeyInvalid, harnessMember.key, err)
		}
		tiers := map[string]string{}
		for _, tierMember := range tierObject.members {
			if !slices.Contains(tierNames, tierMember.key) {
				if self.strict {
					return nil, fmt.Errorf("%w: harness.%s names an unknown tier", ErrModelsKeyInvalid, harnessMember.key)
				}
				*warnings = append(*warnings, fmt.Sprintf("models.harness.%s.%s is not known to this build", harnessMember.key, tierMember.key))
				continue
			}
			field := "harness." + harnessMember.key + "." + tierMember.key
			if tiers[tierMember.key], err = self.name(tierValue[tierMember.valueStart:tierMember.valueEnd], field); err != nil {
				return nil, err
			}
		}
		harnesses[harnessMember.key] = tiers
	}
	return harnesses, nil
}

// agents' entries, at most AgentMaxCount, each label an agent label and each default a canonical name.
func (self *harnessModelsLimits) agents(value []byte, warnings *[]string) (map[string]*HarnessModelsAgent, error) {
	object, err := parseHarnessJsonObject(value, 0, len(value))
	if err != nil {
		return nil, fmt.Errorf("%w: agents: %v", ErrModelsKeyInvalid, err)
	}
	if self.settings.AgentMaxCount < len(object.members) {
		return nil, fmt.Errorf("%w: agents holds more than %d", ErrModelsKeyInvalid, self.settings.AgentMaxCount)
	}
	agents := map[string]*HarnessModelsAgent{}
	for _, agentMember := range object.members {
		if err := self.settings.AgentLabel.Check(agentMember.key); err != nil {
			return nil, fmt.Errorf("%w: agents: %w", ErrModelsKeyInvalid, err)
		}
		agentValue := value[agentMember.valueStart:agentMember.valueEnd]
		agentObject, err := parseHarnessJsonObject(agentValue, 0, len(agentValue))
		if err != nil {
			return nil, fmt.Errorf("%w: an agent's entry: %v", ErrModelsKeyInvalid, err)
		}
		agent := &HarnessModelsAgent{}
		for _, field := range agentObject.members {
			if field.key != harnessModelsFieldDefault {
				if self.strict {
					return nil, fmt.Errorf("%w: an agent's entry names an unknown field", ErrModelsKeyInvalid)
				}
				*warnings = append(*warnings, fmt.Sprintf("models.agents.%s.%s is not known to this build", agentMember.key, field.key))
				continue
			}
			if agent.Default, err = self.name(agentValue[field.valueStart:field.valueEnd], "an agent's default"); err != nil {
				return nil, err
			}
		}
		agents[agentMember.key] = agent
	}
	return agents, nil
}

// Whether key is one a write takes: every value checked as a strict parse checks it.
func checkHarnessModelsKey(key *HarnessModelsKey, settings *ModelsKeySettings, infer *InferSettings) error {
	limits := &harnessModelsLimits{settings: settings, infer: infer, strict: true}
	if key == nil {
		return fmt.Errorf("%w: no key", ErrModelsKeyInvalid)
	}
	if key.Default != "" {
		if err := limits.checkName(key.Default, "default"); err != nil {
			return err
		}
	}
	if key.Allow != nil {
		if err := limits.checkAllow(key.Allow); err != nil {
			return err
		}
	}
	switch key.SignInMail {
	case "", HarnessSignInMailWithhold, HarnessSignInMailAllow:
	default:
		return fmt.Errorf("%w: sign_in_mail is withhold or allow", ErrModelsKeyInvalid)
	}
	for harness, tiers := range key.Harness {
		tierNames, known := harnessModelsTiers[harness]
		if !known {
			return fmt.Errorf("%w: harness names an unknown harness", ErrModelsKeyInvalid)
		}
		for tier, name := range tiers {
			if !slices.Contains(tierNames, tier) {
				return fmt.Errorf("%w: harness.%s names an unknown tier", ErrModelsKeyInvalid, harness)
			}
			if err := limits.checkName(name, "harness."+harness+"."+tier); err != nil {
				return err
			}
		}
	}
	if settings.AgentMaxCount < len(key.Agents) {
		return fmt.Errorf("%w: agents holds more than %d", ErrModelsKeyInvalid, settings.AgentMaxCount)
	}
	for label, agent := range key.Agents {
		if err := settings.AgentLabel.Check(label); err != nil {
			return fmt.Errorf("%w: agents: %w", ErrModelsKeyInvalid, err)
		}
		if agent == nil {
			return fmt.Errorf("%w: an agent with no entry", ErrModelsKeyInvalid)
		}
		if agent.Default != "" {
			if err := limits.checkName(agent.Default, "an agent's default"); err != nil {
				return err
			}
		}
	}
	return nil
}

// A value's JSON, compact.
func harnessModelsJson(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		// a string, a bool or a list of strings always encodes
		panic(err)
	}
	return encoded
}

// The key as one JSON object, its fields in §16.4's order and each map's keys sorted, unset fields left out: what a
// write puts where the file holds no models key it can keep, or one that does not read.
func harnessModelsKeyJson(key *HarnessModelsKey) json.RawMessage {
	members := [][]byte{}
	add := func(field string, value json.RawMessage) {
		members = append(members, append(append(harnessJsonKey(field), ':'), value...))
	}
	if key.Default != "" {
		add(harnessModelsFieldDefault, harnessModelsJson(key.Default))
	}
	if key.Allow != nil {
		add(harnessModelsFieldAllow, harnessModelsJson(key.Allow))
	}
	add(harnessModelsFieldTeeOnly, harnessModelsJson(key.TeeOnly))
	if key.SignInMail != "" {
		add(harnessModelsFieldSignInMail, harnessModelsJson(string(key.SignInMail)))
	}
	if key.Harness != nil {
		add(harnessModelsFieldHarness, harnessModelsJson(key.Harness))
	}
	if key.Agents != nil {
		agents := map[string]map[string]string{}
		for label, agent := range key.Agents {
			entry := map[string]string{}
			if agent.Default != "" {
				entry[harnessModelsFieldDefault] = agent.Default
			}
			agents[label] = entry
		}
		add(harnessModelsFieldAgents, harnessModelsJson(agents))
	}
	return append(append([]byte("{"), bytes.Join(members, []byte(","))...), '}')
}

// The edits that take the file's models key from was to now, field by field, so a field that did not change keeps
// its bytes, and so does every field, harness, tier and agent entry this build does not know. Each edit's path starts
// at models.
func harnessModelsKeyEdits(was *HarnessModelsKey, now *HarnessModelsKey) []*MemberHarnessConfigEdit {
	edits := []*MemberHarnessConfigEdit{}
	set := func(value json.RawMessage, path ...string) {
		edits = append(edits, &MemberHarnessConfigEdit{Path: append([]string{harnessModelsKeyName}, path...), Value: value})
	}
	if was.Default != now.Default {
		if now.Default == "" {
			set(nil, harnessModelsFieldDefault)
		} else {
			set(harnessModelsJson(now.Default), harnessModelsFieldDefault)
		}
	}
	if (was.Allow == nil) != (now.Allow == nil) || !slices.Equal(was.Allow, now.Allow) {
		if now.Allow == nil {
			set(nil, harnessModelsFieldAllow)
		} else {
			set(harnessModelsJson(now.Allow), harnessModelsFieldAllow)
		}
	}
	if was.TeeOnly != now.TeeOnly {
		set(harnessModelsJson(now.TeeOnly), harnessModelsFieldTeeOnly)
	}
	if was.SignInMail != now.SignInMail {
		if now.SignInMail == "" {
			set(nil, harnessModelsFieldSignInMail)
		} else {
			set(harnessModelsJson(string(now.SignInMail)), harnessModelsFieldSignInMail)
		}
	}
	harnesses := slices.Sorted(maps.Keys(harnessModelsTiers))
	for _, harness := range harnesses {
		for _, tier := range harnessModelsTiers[harness] {
			before, after := was.Harness[harness][tier], now.Harness[harness][tier]
			switch {
			case before == after:
			case after == "":
				set(nil, harnessModelsFieldHarness, harness, tier)
			default:
				set(harnessModelsJson(after), harnessModelsFieldHarness, harness, tier)
			}
		}
	}
	labels := slices.Sorted(maps.Keys(was.Agents))
	for _, label := range slices.Sorted(maps.Keys(now.Agents)) {
		if _, held := was.Agents[label]; !held {
			labels = append(labels, label)
		}
	}
	slices.Sort(labels)
	for _, label := range labels {
		before, after := was.Agents[label], now.Agents[label]
		switch {
		case after == nil:
			set(nil, harnessModelsFieldAgents, label)
		case before == nil:
			entry := map[string]string{}
			if after.Default != "" {
				entry[harnessModelsFieldDefault] = after.Default
			}
			set(harnessModelsJson(entry), harnessModelsFieldAgents, label)
		case before.Default != after.Default && after.Default == "":
			set(nil, harnessModelsFieldAgents, label, harnessModelsFieldDefault)
		case before.Default != after.Default:
			set(harnessModelsJson(after.Default), harnessModelsFieldAgents, label, harnessModelsFieldDefault)
		}
	}
	return edits
}

// The models key a read of the file holds: the defaults where the file reads as the defaults or holds no models key,
// unreadable where the file or the key does not read.
func readHarnessModelsKey(config *MemberHarnessConfigRead, settings *ModelsKeySettings, infer *InferSettings) *HarnessModelsKeyRead {
	read := &HarnessModelsKeyRead{Key: &HarnessModelsKey{}, Config: config, Warnings: []string{}}
	if config.Source == MemberHarnessConfigSourceUnreadable {
		read.Unreadable, read.Gap, read.Reason = true, config.Gap, config.Reason
		return read
	}
	raw, held := config.Key(harnessModelsKeyName)
	if !held {
		return read
	}
	key, warnings, err := ParseHarnessModelsKey(raw, false, settings, infer)
	if err != nil {
		read.Unreadable, read.Gap, read.Reason = true, MemberHarnessConfigGapUnreadable, err.Error()
		return read
	}
	read.Key, read.Warnings = key, warnings
	return read
}

// The models component's name, under which it registers.
const sidecarModelsComponentName = "models"

// A Sidecar's models component: the member's harness config store over the Sidecar's network, built at each use from
// the newest verified state and the evs client then attached, since both change over the Sidecar's life.
type sidecarModels struct {
	sidecar  *Sidecar
	settings *ModelsKeySettings
	infer    *InferSettings
	// the store, which keeps only which versions it alarmed on across calls
	store *MemberHarnessConfig
}

// Registers the component, from this file (compute_sidecar.go).
func init() {
	registerComputeComponent(sidecarModelsComponentName, newSidecarModels, nil)
}

// The component for sidecar, refusing a Sidecar with no identity: its store reads as its sidecar.
func newSidecarModels(sidecar *Sidecar) (*sidecarModels, error) {
	settings := sidecar.settings.ModelsKey
	if settings == nil {
		settings = DefaultModelsKeySettings()
	}
	infer := sidecar.settings.Infer
	if infer == nil {
		infer = DefaultInferSettings()
	}
	self := &sidecarModels{sidecar: sidecar, settings: settings, infer: infer}
	store, err := NewMemberHarnessConfig(&MemberHarnessConfigArgs{
		Self: func() (Id, error) {
			identity := sidecar.Identity()
			if identity == nil {
				return Id{}, ErrSidecarNoIdentity
			}
			return identity.SidecarId, nil
		},
		Authority: self.authority,
		Vault: func(repoId Id) MemberHarnessConfigVault {
			client := sidecar.EvsClient()
			if client == nil {
				return nil
			}
			return client.Repo(repoId)
		},
		Alarm: func(alarm *RecordAlarm) {
			logId := alarm.LogId
			sidecar.emitEvent(SidecarEvent{Kind: SidecarEventRecordAlarm, RepoId: &logId, SidecarId: alarm.SidecarId, RecordAlarm: alarm.Reason})
		},
		Settings: settings,
	})
	if err != nil {
		return nil, err
	}
	self.store = store
	return self, nil
}

// The store's judgments at the Sidecar's newest verified state.
func (self *sidecarModels) authority() (MemberHarnessConfigAuthority, error) {
	authority, ok := self.sidecar.authority().(*ConfigAuthority)
	if !ok {
		return nil, fmt.Errorf("%w: no config follower", ErrHarnessConfigUnavailable)
	}
	return NewMemberHarnessConfigAuthority(authority.client.State())
}

// The Sidecar's models component.
func (self *Sidecar) models() (*sidecarModels, error) {
	return sidecarComputeComponent[sidecarModels](self, sidecarModelsComponentName)
}

// The member's harness config store over this Sidecar's network, for the compute keys' owners (CTRUST's
// compute.disclosures, SAFE's approvals, ENC's compute.indexer_grant), each through Read and, on the person's act,
// Update.
func (self *Sidecar) MemberHarnessConfig() (*MemberHarnessConfig, error) {
	models, err := self.models()
	if err != nil {
		return nil, err
	}
	return models.store, nil
}

// The person's models key as this device reads it now (§16.4): the defaults on a sidecar that reads no vault and where
// no file or key stands, an unreadable key where the file or the key does not read. An error reads nothing: no
// verified state or evs client, or a read of the vault that failed.
func (self *Sidecar) ModelsKey(ctx context.Context) (*HarnessModelsKeyRead, error) {
	models, err := self.models()
	if err != nil {
		return nil, err
	}
	return ReadHarnessModelsKey(ctx, models.store, models.settings, models.infer)
}

// The models key store holds now, as Sidecar.ModelsKey reads it.
func ReadHarnessModelsKey(ctx context.Context, store *MemberHarnessConfig, settings *ModelsKeySettings, infer *InferSettings) (*HarnessModelsKeyRead, error) {
	config, err := store.Read(ctx)
	if err != nil {
		return nil, err
	}
	return readHarnessModelsKey(config, settings, infer), nil
}

// Changes the person's models key on their act alone (args; MemberHarnessConfig.Update), for INFER's `ur models set`
// and `Models().SetSettings`: change edits a copy of the key as it reads now, the defaults where the file holds none or
// one that does not read, and the fields it changed are written, checked strictly first. Another write landing first
// reads the key again and calls change again. Answers the key as written.
func (self *Sidecar) SetModelsKey(ctx context.Context, args *MemberHarnessConfigUpdateArgs, change func(key *HarnessModelsKey) error) (*HarnessModelsKey, error) {
	if change == nil {
		return nil, fmt.Errorf("%w: no change", ErrModelsKeyInvalid)
	}
	models, err := self.models()
	if err != nil {
		return nil, err
	}
	return SetHarnessModelsKey(ctx, models.store, models.settings, models.infer, args, change)
}

// Changes the models key in store, as Sidecar.SetModelsKey does.
func SetHarnessModelsKey(ctx context.Context, store *MemberHarnessConfig, settings *ModelsKeySettings, infer *InferSettings,
	args *MemberHarnessConfigUpdateArgs, change func(key *HarnessModelsKey) error) (*HarnessModelsKey, error) {
	if change == nil {
		return nil, fmt.Errorf("%w: no change", ErrModelsKeyInvalid)
	}
	var written *HarnessModelsKey
	_, err := store.Update(ctx, args, func(config *MemberHarnessConfigRead) ([]*MemberHarnessConfigEdit, error) {
		return harnessModelsKeyChange(config, settings, infer, change, &written)
	})
	if err != nil {
		return nil, err
	}
	return written, nil
}

// The edits change makes to the models key read holds, the key it leaves in written: field by field over a key that
// reads, the whole key over one that does not or none at all.
func harnessModelsKeyChange(config *MemberHarnessConfigRead, settings *ModelsKeySettings, infer *InferSettings, change func(key *HarnessModelsKey) error, written **HarnessModelsKey) ([]*MemberHarnessConfigEdit, error) {
	read := readHarnessModelsKey(config, settings, infer)
	was := read.Key
	_, held := config.Key(harnessModelsKeyName)
	now := was.Clone()
	if err := change(now); err != nil {
		return nil, err
	}
	if err := checkHarnessModelsKey(now, settings, infer); err != nil {
		return nil, err
	}
	*written = now.Clone()
	if !held || read.Unreadable {
		return []*MemberHarnessConfigEdit{{Path: []string{harnessModelsKeyName}, Value: harnessModelsKeyJson(now)}}, nil
	}
	return harnessModelsKeyEdits(was, now), nil
}

// A glob within a canonical name matches name: `*` takes any run of characters, the others match themselves. Linear
// in the name for each star, which AllowGlobWildcardMaxCount bounds.
func harnessModelsGlobMatch(glob string, name string) bool {
	parts := strings.Split(glob, "*")
	if len(parts) == 1 {
		return glob == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	rest := name[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(rest, part)
		if index < 0 {
			return false
		}
		rest = rest[index+len(part):]
	}
	return len(last) <= len(rest) && strings.HasSuffix(rest, last)
}
