//go:build !ios_extension && !sidecar_http

// Canonical model names (DESIGN-COMPUTE §6.3, D-INFER-1, CO-18): every model, local or remote, in a TEE or not, has one
// name, <provider>-<model>-<effort>, lowercase, such as local-gemma-4-e4b-off or chutes-qwen3.8-27b-tee-high.
//
//   - The provider is a slug of [a-z0-9]+, with no hyphen, named by team and never by netuid (D-PROV-4).
//   - The model is the provider's own id for it, normalized by InferNormalizeModelId: [a-z0-9.-], with no hyphen at
//     either end and none doubled.
//   - The effort is one of off, minimal, low, medium, high, xhigh and max, OpenAI's levels with its none written off,
//     since none is also a label, a floor and an egress mode. A request's none reads as off.
//
// A parse takes the provider before the first hyphen, the effort after the last and the model between; only the
// catalog decides that a name exists (InferCatalog.Resolve). A name without an effort is an alias, <provider>-<model>,
// which takes the request's own effort (Q-INFER-5). A name that reads both ways is a full name first, and a model whose
// own id ends in an effort word takes no alias, which is one rule seen from two sides: whenever the text after the
// last hyphen is an effort word, the name is read as a full name and never as an alias, so every name has exactly one
// reading. The parser is total and bounded: any string gets a reading or an error, and one longer than the settings'
// NameMaxByteCount is refused before any other work.
//
// Search endpoints have ids of their own, search/<engine>/<kind> (§21), outside the model namespace: no model name
// holds a slash, so neither parser reads the other's.
//
// Everything here is a function of its arguments, so safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// One of §6.3's reasoning efforts.
type InferEffort string

const (
	InferEffortOff     InferEffort = "off"
	InferEffortMinimal InferEffort = "minimal"
	InferEffortLow     InferEffort = "low"
	InferEffortMedium  InferEffort = "medium"
	InferEffortHigh    InferEffort = "high"
	InferEffortXhigh   InferEffort = "xhigh"
	InferEffortMax     InferEffort = "max"
)

// A request's word for off: OpenAI's none, which a name never carries (§6.3).
const inferRequestEffortNone = "none"

// §6.3's efforts, lowest first: the order the alias's nearest effort is measured on.
var inferEffortOrder = []InferEffort{
	InferEffortOff,
	InferEffortMinimal,
	InferEffortLow,
	InferEffortMedium,
	InferEffortHigh,
	InferEffortXhigh,
	InferEffortMax,
}

// The words that mark a model as running in a TEE (§6.3): dropped from the name of a model labeled none, whose name
// must not claim what its label denies (Q-PROV-8).
var inferTeeMarkWords = []string{"tee", "tdx", "confidential"}

// The search ids' first part (§21).
const inferSearchIdPrefix = "search/"

var (
	// A string that fails §6.3's grammar. The message says what failed and never repeats the string.
	ErrInferModelNameInvalid = errors.New("not a canonical model name")
	// A word that is not one of §6.3's efforts.
	ErrInferEffortUnknown = errors.New("unknown effort")
	// A string that is not search/<engine>/<kind>.
	ErrInferSearchIdInvalid = errors.New("not a search id")
	// A provider slug that is not [a-z0-9]+.
	ErrInferProviderInvalid = errors.New("not a provider slug")
	// More ids than one normalization reads.
	ErrInferNormalizeTooMany = errors.New("too many provider ids to normalize")
)

// The effort a name's last part names: one of §6.3's seven words, exactly. none is a request's word, never a name's.
func ParseInferEffort(word string) (InferEffort, error) {
	effort := InferEffort(word)
	if !effort.Valid() {
		return "", ErrInferEffortUnknown
	}
	return effort, nil
}

// The effort a request's reasoning parameter asks for: one of §6.3's words, none reading as off; empty for a request
// that asks for none in particular, which an alias answers with the model's default.
func ParseInferRequestEffort(word string) (InferEffort, error) {
	switch word {
	case "":
		return "", nil
	case inferRequestEffortNone:
		return InferEffortOff, nil
	}
	return ParseInferEffort(word)
}

// Whether the effort is one of §6.3's.
func (self InferEffort) Valid() bool {
	return slices.Contains(inferEffortOrder, self)
}

// Of listed, the effort nearest asked on §6.3's order, the lower of two equally near, so an alias never runs a model
// harder than its request asked when the request's own level is not listed. Empty where listed holds no effort or
// asked is none of them.
func inferNearestEffort(asked InferEffort, listed []InferEffort) InferEffort {
	askedRank := slices.Index(inferEffortOrder, asked)
	if askedRank < 0 {
		return ""
	}
	nearest := InferEffort("")
	nearestRank := -1
	for _, effort := range listed {
		rank := slices.Index(inferEffortOrder, effort)
		if rank < 0 {
			continue
		}
		if nearestRank < 0 {
			nearest, nearestRank = effort, rank
			continue
		}
		distance := max(rank-askedRank, askedRank-rank)
		nearestDistance := max(nearestRank-askedRank, askedRank-nearestRank)
		if distance < nearestDistance || (distance == nearestDistance && rank < nearestRank) {
			nearest, nearestRank = effort, rank
		}
	}
	return nearest
}

// The longest effort word, which bounds the names a model part makes.
func inferEffortMaxByteCount() int {
	byteCount := 0
	for _, effort := range inferEffortOrder {
		byteCount = max(byteCount, len(effort))
	}
	return byteCount
}

// A name as InferParseModelName read it: a full name, <provider>-<model>-<effort>, or an alias, <provider>-<model>,
// whose Effort is empty.
type InferModelName struct {
	// The provider's slug: local, or a remote provider's (D-PROV-4).
	Provider string
	// The model part, the provider's id as InferNormalizeModelId made it.
	Model string
	// The name's effort, empty in an alias.
	Effort InferEffort
}

// The name as §6.3 writes it.
func (self *InferModelName) String() string {
	if self.Effort == "" {
		return self.Provider + "-" + self.Model
	}
	return self.Provider + "-" + self.Model + "-" + string(self.Effort)
}

// Whether the name is an alias: no effort of its own, so the request's decides (Q-INFER-5).
func (self *InferModelName) IsAlias() bool {
	return self.Effort == ""
}

// Whether c may appear in a name or a model part: [a-z0-9.-].
func inferNameByte(c byte) bool {
	return ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '.' || c == '-'
}

// Whether provider is a slug, [a-z0-9]+ (§6.3).
func inferValidProvider(provider string) bool {
	if provider == "" {
		return false
	}
	for i := 0; i < len(provider); i += 1 {
		c := provider[i]
		if !(('a' <= c && c <= 'z') || ('0' <= c && c <= '9')) {
			return false
		}
	}
	return true
}

// Why model is not a model part, or empty when it is one: [a-z0-9.-] holding a letter or digit, with no hyphen at
// either end and none doubled, as InferNormalizeModelId makes every one.
func inferModelPartFault(model string) string {
	if model == "" {
		return "an empty model part"
	}
	alphanumeric := false
	for i := 0; i < len(model); i += 1 {
		c := model[i]
		if !inferNameByte(c) {
			return "a character outside [a-z0-9.-]"
		}
		alphanumeric = alphanumeric || (c != '.' && c != '-')
	}
	switch {
	case !alphanumeric:
		return "a model part with no letter or digit"
	case model[0] == '-' || model[len(model)-1] == '-':
		return "a hyphen at an end of the model part"
	case strings.Contains(model, "--"):
		return "a doubled hyphen"
	}
	return ""
}

// The one reading of name (§6.3): a full name when the text after its last hyphen is an effort word, else an alias.
// Only the catalog decides that the name exists. Refuses, with ErrInferModelNameInvalid saying why, a name past the
// settings' NameMaxByteCount, before reading it, and one outside the grammar: a character outside [a-z0-9.-], so no
// capital and no slash, a hyphen at an end or doubled, a provider that is not [a-z0-9]+, or no model part.
func InferParseModelName(name string, settings *InferSettings) (*InferModelName, error) {
	if settings.NameMaxByteCount < len(name) {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrInferModelNameInvalid, settings.NameMaxByteCount)
	}
	for i := 0; i < len(name); i += 1 {
		if !inferNameByte(name[i]) {
			return nil, fmt.Errorf("%w: a character outside [a-z0-9.-]", ErrInferModelNameInvalid)
		}
	}
	provider, rest, found := strings.Cut(name, "-")
	if !found {
		return nil, fmt.Errorf("%w: no model part", ErrInferModelNameInvalid)
	}
	if !inferValidProvider(provider) {
		return nil, fmt.Errorf("%w: a provider that is not [a-z0-9]+", ErrInferModelNameInvalid)
	}
	model := rest
	effort := InferEffort("")
	if last := strings.LastIndexByte(rest, '-'); 0 <= last {
		if word, err := ParseInferEffort(rest[last+1:]); err == nil {
			model, effort = rest[:last], word
		}
	} else if _, err := ParseInferEffort(rest); err == nil {
		// <provider>-<effort>: no model, and an effort word takes no alias
		return nil, fmt.Errorf("%w: no model part", ErrInferModelNameInvalid)
	}
	if fault := inferModelPartFault(model); fault != "" {
		return nil, fmt.Errorf("%w: %s", ErrInferModelNameInvalid, fault)
	}
	return &InferModelName{
		Provider: provider,
		Model:    model,
		Effort:   effort,
	}, nil
}

// A search endpoint's id, search/<engine>/<kind> (§21): a search, not a model, outside the model namespace.
type InferSearchId struct {
	// The search provider's slug, such as parallel.
	Engine string
	// The endpoint's mode, such as fast.
	Kind string
}

// The id as §6.3 writes it.
func (self *InferSearchId) String() string {
	return inferSearchIdPrefix + self.Engine + "/" + self.Kind
}

// The search id id names, refusing with ErrInferSearchIdInvalid one past the settings' NameMaxByteCount, before reading
// it, and one that is not search/<engine>/<kind>, its engine [a-z0-9]+ and its kind a model part's characters.
func InferParseSearchId(id string, settings *InferSettings) (*InferSearchId, error) {
	if settings.NameMaxByteCount < len(id) {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrInferSearchIdInvalid, settings.NameMaxByteCount)
	}
	rest, found := strings.CutPrefix(id, inferSearchIdPrefix)
	if !found {
		return nil, fmt.Errorf("%w: not under %s", ErrInferSearchIdInvalid, inferSearchIdPrefix)
	}
	engine, kind, found := strings.Cut(rest, "/")
	if !found || !inferValidProvider(engine) {
		return nil, fmt.Errorf("%w: an engine that is not [a-z0-9]+", ErrInferSearchIdInvalid)
	}
	if fault := inferModelPartFault(kind); fault != "" {
		return nil, fmt.Errorf("%w: a kind with %s", ErrInferSearchIdInvalid, fault)
	}
	return &InferSearchId{
		Engine: engine,
		Kind:   kind,
	}, nil
}

// One id a provider gives a model, with the label the model's catalog entry carries, which decides whether a TEE mark
// stays in its name.
type InferProviderModel struct {
	// The provider's own id, such as Qwen/Qwen3.8-27B-TEE.
	Id string
	// The label the model is offered under.
	Label ComputeLabel
}

// What InferNormalizeModelId made of one id.
type InferNormalizedModel struct {
	// The provider's id, as given.
	Id string
	// Its label, as given.
	Label ComputeLabel
	// The model part, which names it <provider>-<model>-<effort>; empty where Refused says why there is none.
	Model string
	// Why the id makes no model part: it is too long, its label is unknown or not its provider's kind, or nothing of
	// it survives normalization.
	Refused string
	// Whether another of the provider's ids makes the same model part, the ids that share Model being the collision:
	// the policy names one of them (§5.4), and a catalog holding two refuses (InferCatalog). A flag, not a list, so a
	// hostile catalog of ids that all collide costs memory linear in its size.
	Collides bool
}

// Lowercased; "/", "_", ":", whitespace and "-" made one hyphen, runs collapsed; only [a-z0-9.-] kept; no hyphen at
// either end (§6.3).
func inferNormalizeModelText(text string) string {
	var builder strings.Builder
	afterHyphen := true
	for _, r := range strings.ToLower(text) {
		switch {
		case r == '/' || r == '_' || r == ':' || r == '-' || unicode.IsSpace(r):
			if !afterHyphen {
				builder.WriteByte('-')
				afterHyphen = true
			}
		case ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') || r == '.':
			builder.WriteRune(r)
			afterHyphen = false
		}
	}
	return strings.TrimSuffix(builder.String(), "-")
}

// model with every TEE mark word taken out (§6.3; Q-PROV-8).
func inferDropTeeMarks(model string) string {
	words := slices.DeleteFunc(strings.Split(model, "-"), func(word string) bool {
		return slices.Contains(inferTeeMarkWords, word)
	})
	return strings.Join(words, "-")
}

// The model parts of one provider's ids (§6.3), one result per id in the order given:
//
//   - lowercased;
//   - an organization prefix, the text before the first "/", dropped, unless two of the provider's ids differ only by
//     it, when each of them keeps it, so deepseek-ai/DeepSeek-V3.2 alone is deepseek-v3.2 and beside
//     other/DeepSeek-V3.2 is deepseek-ai-deepseek-v3.2;
//   - "/", "_", ":" and spaces made "-", runs of "-" collapsed, only [a-z0-9.-] kept, no hyphen left at an end;
//   - a provider's own marks kept, as Chutes' -tee, but for a model labeled none every TEE mark word (tee, tdx,
//     confidential) dropped, so its name claims nothing its label denies (Q-PROV-8);
//   - an id whose model part would make a name past the settings' NameMaxByteCount refused.
//
// Two ids that still give one model part are each marked Collides, for the policy to name one (§5.4); nothing here
// picks. The work and the memory are linear in the ids, which ProviderModelIdMaxCount bounds.
// An id is refused, with the reason, when it is past ProviderModelIdMaxByteCount, its label is unknown, it pairs the
// local label with a remote provider or the reverse, or nothing of it survives. Refuses the whole call for a provider
// that is not a slug or more than ProviderModelIdMaxCount ids, so its work is bounded.
func InferNormalizeModelId(provider string, ids []*InferProviderModel, settings *InferSettings) ([]*InferNormalizedModel, error) {
	if !inferValidProvider(provider) {
		return nil, ErrInferProviderInvalid
	}
	if settings.ProviderModelIdMaxCount < len(ids) {
		return nil, fmt.Errorf("%w: more than %d", ErrInferNormalizeTooMany, settings.ProviderModelIdMaxCount)
	}
	type reading struct {
		result *InferNormalizedModel
		// the id's model part without its organization, and with it
		bare string
		full string
		// its organization, normalized; empty for none
		organization string
	}
	readings := make([]*reading, len(ids))
	for i, id := range ids {
		r := &reading{result: &InferNormalizedModel{}}
		readings[i] = r
		if id == nil {
			r.result.Refused = "no id"
			continue
		}
		r.result.Id = id.Id
		r.result.Label = id.Label
		switch {
		case settings.ProviderModelIdMaxByteCount < len(id.Id):
			r.result.Refused = fmt.Sprintf("an id longer than %d bytes", settings.ProviderModelIdMaxByteCount)
			continue
		case !id.Label.Valid():
			r.result.Refused = "an unknown label"
			continue
		case (id.Label == ComputeLabelLocal) != (provider == computeLocalProvider):
			r.result.Refused = "the local label is this device's models' alone"
			continue
		}
		if organization, model, found := strings.Cut(id.Id, "/"); found {
			r.organization = inferNormalizeModelText(organization)
			r.bare = inferNormalizeModelText(model)
		} else {
			r.bare = inferNormalizeModelText(id.Id)
		}
		r.full = inferNormalizeModelText(id.Id)
		if r.bare == "" {
			r.result.Refused = "nothing of the id survives normalization"
		}
	}

	// the organization rule: ids whose model parts without their organizations agree, while their organizations do
	// not, differ only by their organizations, and each keeps its own. A group of one bare part keeps them where its
	// ids name two organizations or more, counting none as one.
	bareOrganizations := map[string]string{}
	bareKeeps := map[string]bool{}
	for _, r := range readings {
		if r.result.Refused != "" {
			continue
		}
		if organization, ok := bareOrganizations[r.bare]; !ok {
			bareOrganizations[r.bare] = r.organization
		} else if organization != r.organization {
			bareKeeps[r.bare] = true
		}
	}
	for _, r := range readings {
		if r.result.Refused != "" {
			continue
		}
		model := r.bare
		if bareKeeps[r.bare] {
			model = r.full
		}
		if r.result.Label == ComputeLabelNone {
			model = inferDropTeeMarks(model)
		}
		if fault := inferModelPartFault(model); fault != "" {
			r.result.Refused = "nothing but a TEE mark or punctuation survives normalization"
			continue
		}
		if settings.NameMaxByteCount < len(provider)+len(model)+inferEffortMaxByteCount()+2 {
			r.result.Refused = fmt.Sprintf("a name longer than %d bytes", settings.NameMaxByteCount)
			continue
		}
		r.result.Model = model
	}

	modelCounts := map[string]int{}
	for _, r := range readings {
		if r.result.Model != "" {
			modelCounts[r.result.Model] += 1
		}
	}
	results := make([]*InferNormalizedModel, len(readings))
	for i, r := range readings {
		r.result.Collides = 1 < modelCounts[r.result.Model]
		results[i] = r.result
	}
	return results, nil
}
