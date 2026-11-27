//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §2.8's disclosures on a device (CTRUST-M11-01; R-CCTX-25, D-CTRUST-2, D-CTRUST-4): the registry every
// surface reads a disclosure's text through, the person's settings, a card's line, `ur disclosures` and the Harness's
// prompt among them.
//
//	ids      one per service and provider (Q-INFER-7: per provider), family:slug in §2.8's families, search,
//	         inference, enclave and connect taking any slug of lowercase ASCII letters, digits and inner hyphens
//	         within IdSlugMaxByteCount, and listeners, approvals and support their one id each (listeners:publish,
//	         approvals:auto, support:urnetwork); anything else is refused. §5.4's id list omits approvals:auto and
//	         inference:local, which §2.8 names, so the registry takes every family §2.8 names
//	text     the newest verified policy's disclosures line alone (§5.4, D-ATTEST-7), read through ComputeDisclosureSource,
//	         which ATTEST's ComputePolicyStore satisfies: no event, tool result, model, remote Harness or server answer
//	         can put text here. With no verified policy every read answers ErrComputeDisclosurePolicyUnavailable and
//	         nothing renders
//	taken    an entry whose id is §2.8's, whose English text comes first with a one-line summary and no empty item, and
//	         which holds none of the design's form placeholders (<provider>, <inside>, <service>, <revocation>,
//	         <retention>), so an unfilled form never shows; a translation that fails the same rules is dropped and its
//	         locale falls back to English. ATTEST's parse refuses most of this already; the registry holds it again
//	asks     search, enclave, connect, listeners:publish, approvals:auto and support:urnetwork ask before use;
//	         inference:<p> asks only where the policy labels p none (its direct line), so inference:local and TEE
//	         providers never ask, and SayGM's -tee names ask under its none label (Q-PROV-8). A provider the policy names
//	         nowhere asks, the closed side, though no model of it is usable
//	locale   the person's, matched by tag and then by language, else English, always one locale whole: never a summary
//	         from one and lists from another. An acknowledgment covers its version in every locale (CTRUST-M12-01)
//
// The view and the terminal text are disclosure_render.go's, every string through ApprovalPrintable. The registry keeps
// nothing but the snapshot of the newest policy it last read, rebuilt when the source answers another. Safe for
// concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// The families of §2.8's ids.
type ComputeDisclosureFamily string

const (
	// Web search, search:parallel (§21.6).
	ComputeDisclosureFamilySearch ComputeDisclosureFamily = "search"
	// A model provider, inference:<provider>, local's among them (§6).
	ComputeDisclosureFamilyInference ComputeDisclosureFamily = "inference"
	// An enclave provider, enclave:<provider> (§11).
	ComputeDisclosureFamilyEnclave ComputeDisclosureFamily = "enclave"
	// A connected service, connect:<service>, connect:custom for every person's own definition (§25.12).
	ComputeDisclosureFamilyConnect ComputeDisclosureFamily = "connect"
	// The listeners list, listeners:publish (§26.6).
	ComputeDisclosureFamilyListeners ComputeDisclosureFamily = "listeners"
	// Automatic approvals, approvals:auto (§27.11).
	ComputeDisclosureFamilyApprovals ComputeDisclosureFamily = "approvals"
	// The support conversation, support:urnetwork (§28.13).
	ComputeDisclosureFamilySupport ComputeDisclosureFamily = "support"
)

// The one slug of each family §2.8 names a single id of; the other families take any slug.
var computeDisclosureFixedSlugs = map[ComputeDisclosureFamily]string{
	ComputeDisclosureFamilyListeners: "publish",
	ComputeDisclosureFamilyApprovals: "auto",
	ComputeDisclosureFamilySupport:   "urnetwork",
}

// The families that take any slug.
var computeDisclosureOpenFamilies = []ComputeDisclosureFamily{
	ComputeDisclosureFamilySearch,
	ComputeDisclosureFamilyInference,
	ComputeDisclosureFamilyEnclave,
	ComputeDisclosureFamilyConnect,
}

// The local engine's id, which never asks (§2.8's table, CO-9).
const ComputeDisclosureIdLocal = "inference:local"

// The design's form placeholders (§2.8's enclave form, §25.12's connect form, §28.13's retention): a text still holding
// one is an unfilled form, which no surface shows.
var computeDisclosureFormPlaceholders = []string{"<provider>", "<inside>", "<service>", "<revocation>", "<retention>"}

// The refusals' codes, as surfaces and the sdk name them.
const (
	// No verified compute policy on this device: no disclosure shows, and every check refuses.
	ComputeDisclosureCodePolicyUnavailable = "policy_unavailable"
	// The caller must have the disclosure acknowledged first (CTRUST-M12-01).
	ComputeDisclosureCodeRequired = "disclosure_required"
	// The version shown is not the current one (CTRUST-M12-01).
	ComputeDisclosureCodeChanged = "disclosure_changed"
)

var (
	// Not one of §2.8's ids: an unknown family, capitals, an empty or oversize slug, a space, a second colon. The text
	// never repeats what was given.
	ErrComputeDisclosureIdInvalid = errors.New("not a disclosure id of §2.8's families")
	// No verified compute policy on this device, so no disclosure text can be shown: policy_unavailable.
	ErrComputeDisclosurePolicyUnavailable = errors.New(ComputeDisclosureCodePolicyUnavailable + ": this device holds no verified compute policy, so it shows no disclosure")
	// The newest verified policy carries no disclosure of the id, so nothing that waits on it can be acknowledged.
	ErrComputeDisclosureNotCarried = errors.New("the newest verified compute policy carries no such disclosure")
	// The newest verified policy carries the id, but in a form the registry refuses to render (the file header's
	// taken row), so nothing that waits on it can be acknowledged.
	ErrComputeDisclosureRefused = errors.New("the newest verified compute policy carries the disclosure in a form this device does not show")
	// The version a person was shown is not the newest verified policy's current one: disclosure_changed, and nothing
	// was recorded.
	ErrDisclosureChanged = errors.New(ComputeDisclosureCodeChanged + ": the disclosure changed since it was shown; show its current text again")
)

// One of §2.8's ids, family:slug.
type ComputeDisclosureId struct {
	Family ComputeDisclosureFamily
	Slug   string
}

// family:slug.
func (self ComputeDisclosureId) String() string {
	return string(self.Family) + ":" + self.Slug
}

// text as one of §2.8's ids (the file header's ids row), or ErrComputeDisclosureIdInvalid.
func ParseComputeDisclosureId(text string, settings *ComputeDisclosureSettings) (ComputeDisclosureId, error) {
	family, slug, found := strings.Cut(text, ":")
	if !found {
		return ComputeDisclosureId{}, fmt.Errorf("%w: no colon", ErrComputeDisclosureIdInvalid)
	}
	id := ComputeDisclosureId{Family: ComputeDisclosureFamily(family), Slug: slug}
	fixed, fixedFamily := computeDisclosureFixedSlugs[id.Family]
	if !fixedFamily && !slices.Contains(computeDisclosureOpenFamilies, id.Family) {
		return ComputeDisclosureId{}, fmt.Errorf("%w: a family §2.8 does not name", ErrComputeDisclosureIdInvalid)
	}
	if slug == "" || settings.IdSlugMaxByteCount < len(slug) {
		return ComputeDisclosureId{}, fmt.Errorf("%w: a slug empty or past %d bytes", ErrComputeDisclosureIdInvalid, settings.IdSlugMaxByteCount)
	}
	// lowercase ASCII letters and digits, hyphens only between them
	for i := 0; i < len(slug); i += 1 {
		c := slug[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '-' && 0 < i && i < len(slug)-1 && slug[i-1] != '-':
		default:
			return ComputeDisclosureId{}, fmt.Errorf("%w: a slug of other than lowercase letters, digits and inner hyphens", ErrComputeDisclosureIdInvalid)
		}
	}
	if fixedFamily && slug != fixed {
		return ComputeDisclosureId{}, fmt.Errorf("%w: §2.8 names one id of the %s family", ErrComputeDisclosureIdInvalid, family)
	}
	return id, nil
}

// What the registry reads: the newest verified compute policy, nil where the device holds none. ATTEST-M11-01's
// ComputePolicyStore satisfies it; tests fake it.
type ComputeDisclosureSource interface {
	Newest() *ComputePolicy
}

var _ ComputeDisclosureSource = (*ComputePolicyStore)(nil)

// The registry's view of one id in the newest verified policy: the entry as the policy carries it (its version, raised
// only when a fact changes; its revision, raised at any other change of its words; its grace in days and the instant
// the version took effect; per locale the summary and the lists), the policy's version, whether it asks, and the
// provider's label for an inference: or enclave: id. Not changed once built.
type ComputeDisclosure struct {
	Id ComputeDisclosureId
	// Shared with the policy, which no reader changes.
	Entry *ComputePolicyDisclosure
	// The policy's version.
	PolicyVersion uint64
	// Whether it waits for an acknowledgment before use (the file header's asks row).
	Asks bool
	// An inference: id's provider's label (local for inference:local, none for a direct provider, a TEE provider's
	// own), an enclave: id's provider's; empty for any other id, or a provider the policy does not name.
	Label ComputeLabel

	// the locales the registry takes, English first
	texts    []*ComputePolicyDisclosureText
	settings *ComputeDisclosureSettings
}

// The current version.
func (self *ComputeDisclosure) Version() uint32 {
	return self.Entry.Version
}

// The current version's revision.
func (self *ComputeDisclosure) Revision() uint32 {
	return self.Entry.Revision
}

// The instant the current version took effect, which its grace runs from (QD-1242).
func (self *ComputeDisclosure) Since() time.Time {
	return time.UnixMilli(self.Entry.SinceMs).UTC()
}

// The text to show for the person's locale (the file header's locale row), whole: never nil, English at least.
func (self *ComputeDisclosure) Text(locale string) *ComputePolicyDisclosureText {
	tag := computeDisclosureLocaleTag(locale, self.settings)
	if tag == "" {
		return self.texts[0]
	}
	for _, text := range self.texts {
		if strings.EqualFold(text.Locale, tag) {
			return text
		}
	}
	language, _, _ := strings.Cut(tag, "-")
	var sameLanguage *ComputePolicyDisclosureText
	for _, text := range self.texts {
		textLanguage, _, _ := strings.Cut(text.Locale, "-")
		if !strings.EqualFold(textLanguage, language) {
			continue
		}
		// the bare language before any of its regions, else the policy's first of that language
		if strings.EqualFold(text.Locale, language) {
			return text
		}
		if sameLanguage == nil {
			sameLanguage = text
		}
	}
	if sameLanguage != nil {
		return sameLanguage
	}
	return self.texts[0]
}

// locale as a BCP 47 tag, from the forms a person's settings and a POSIX environment give (en-US, en_US.UTF-8,
// de_DE@euro); empty for none, C, POSIX, past LocaleMaxByteCount, or anything that is no tag.
func computeDisclosureLocaleTag(locale string, settings *ComputeDisclosureSettings) string {
	tag := strings.TrimSpace(locale)
	if index := strings.IndexAny(tag, ".@"); 0 <= index {
		tag = tag[:index]
	}
	tag = strings.ReplaceAll(tag, "_", "-")
	if tag == "" || settings.LocaleMaxByteCount < len(tag) {
		return ""
	}
	for i, subtag := range strings.Split(tag, "-") {
		minimum, maximum := 1, 8
		if i == 0 {
			minimum, maximum = 2, 3
		}
		if len(subtag) < minimum || maximum < len(subtag) {
			return ""
		}
		for j := 0; j < len(subtag); j += 1 {
			c := subtag[j]
			letter := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
			if !letter && (i == 0 || c < '0' || '9' < c) {
				return ""
			}
		}
	}
	return tag
}

// Whether id asks before use in policy, and the label of its provider (the file header's asks row).
func computeDisclosureAsks(id ComputeDisclosureId, policy *ComputePolicy) (bool, ComputeLabel) {
	switch id.Family {
	case ComputeDisclosureFamilyInference:
		if id.Slug == computeLocalProvider {
			return false, ComputeLabelLocal
		}
		if policy.DirectProvider(id.Slug) != nil {
			return true, ComputeLabelNone
		}
		if provider := policy.Provider(id.Slug); provider != nil {
			return false, provider.Label
		}
		// a provider named nowhere: no model of it is usable, and asking is the closed side
		return true, ""
	case ComputeDisclosureFamilyEnclave:
		// an enclave asks although it is AP: it holds what its sponsor's devices hold (CO-43)
		if provider := policy.Provider(id.Slug); provider != nil {
			return true, provider.Label
		}
		return true, ""
	}
	return true, ""
}

// Why the registry refuses text as a disclosure's one locale, empty where it takes it.
func computeDisclosureTextFault(text *ComputePolicyDisclosureText) string {
	if text == nil {
		return "no text"
	}
	if strings.TrimSpace(text.Summary) == "" || strings.ContainsAny(text.Summary, "\r\n") {
		return "no one-line summary"
	}
	for _, item := range slices.Concat(text.Exposed, text.Private) {
		if strings.TrimSpace(item) == "" {
			return "an empty item"
		}
	}
	for _, part := range slices.Concat([]string{text.Summary}, text.Exposed, text.Private) {
		for _, placeholder := range computeDisclosureFormPlaceholders {
			if strings.Contains(part, placeholder) {
				return "an unfilled form's " + placeholder
			}
		}
	}
	return ""
}

// One policy's disclosures as the registry takes them.
type computeDisclosureSnapshot struct {
	policy      *ComputePolicy
	disclosures []*ComputeDisclosure
	// by id, why an entry the policy carries is refused
	idFaults map[string]string
}

// The disclosure of id in the snapshot, or why there is none.
func (self *computeDisclosureSnapshot) disclosure(id string) (*ComputeDisclosure, error) {
	for _, disclosure := range self.disclosures {
		if disclosure.Id.String() == id {
			return disclosure, nil
		}
	}
	if fault, refused := self.idFaults[id]; refused {
		return nil, fmt.Errorf("%w: %s", ErrComputeDisclosureRefused, fault)
	}
	return nil, ErrComputeDisclosureNotCarried
}

// What a registry is built on.
type ComputeDisclosureRegistryArgs struct {
	// The newest verified policy. Required.
	Source ComputeDisclosureSource
	// Nil takes DefaultComputeDisclosureSettings.
	Settings *ComputeDisclosureSettings
	// Nil logs nothing.
	Log Logger
}

// §2.8's disclosures as the newest verified policy carries them. See the file header.
type ComputeDisclosureRegistry struct {
	source   ComputeDisclosureSource
	settings *ComputeDisclosureSettings
	log      Logger

	stateLock sync.Mutex
	// the snapshot of the policy the source last answered, rebuilt for another
	snapshot *computeDisclosureSnapshot
}

// A registry over args.
func NewComputeDisclosureRegistry(args *ComputeDisclosureRegistryArgs) (*ComputeDisclosureRegistry, error) {
	if args == nil || args.Source == nil {
		return nil, errors.New("compute disclosure registry: a source")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultComputeDisclosureSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &ComputeDisclosureRegistry{source: args.Source, settings: settings, log: log}, nil
}

// The registry's settings.
func (self *ComputeDisclosureRegistry) Settings() *ComputeDisclosureSettings {
	return self.settings
}

// The snapshot of the newest verified policy, or ErrComputeDisclosurePolicyUnavailable with none.
func (self *ComputeDisclosureRegistry) current() (*computeDisclosureSnapshot, error) {
	policy := self.source.Newest()
	if policy == nil {
		return nil, ErrComputeDisclosurePolicyUnavailable
	}
	held := func() *computeDisclosureSnapshot {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.snapshot != nil && self.snapshot.policy == policy {
			return self.snapshot
		}
		return nil
	}()
	if held != nil {
		return held, nil
	}
	snapshot := self.take(policy)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.snapshot = snapshot
	}()
	return snapshot, nil
}

// policy's disclosures as the registry takes them, each refusal logged once, as the snapshot is built.
func (self *ComputeDisclosureRegistry) take(policy *ComputePolicy) *computeDisclosureSnapshot {
	snapshot := &computeDisclosureSnapshot{policy: policy, idFaults: map[string]string{}}
	for _, entry := range policy.Disclosures {
		if entry == nil {
			continue
		}
		fault := func() string {
			id, err := ParseComputeDisclosureId(entry.Id, self.settings)
			if err != nil {
				return err.Error()
			}
			if entry.Version == 0 {
				return "version 0"
			}
			if len(entry.Locales) == 0 || entry.Locales[0] == nil || entry.Locales[0].Locale != computePolicyEnglish {
				return "no English text first"
			}
			if fault := computeDisclosureTextFault(entry.Locales[0]); fault != "" {
				return "its English text has " + fault
			}
			texts := []*ComputePolicyDisclosureText{entry.Locales[0]}
			for _, text := range entry.Locales[1:] {
				if text == nil || computeDisclosureLocaleTag(text.Locale, self.settings) == "" || computeDisclosureTextFault(text) != "" {
					// a translation the registry does not take: its locale shows English, whole
					continue
				}
				texts = append(texts, text)
			}
			asks, label := computeDisclosureAsks(id, policy)
			snapshot.disclosures = append(snapshot.disclosures, &ComputeDisclosure{
				Id:            id,
				Entry:         entry,
				PolicyVersion: policy.Version,
				Asks:          asks,
				Label:         label,
				texts:         texts,
				settings:      self.settings,
			})
			return ""
		}()
		if fault != "" {
			snapshot.idFaults[entry.Id] = fault
			self.log.Warningf("[disclosure]policy version %d: a disclosure is not shown: %s", policy.Version, fault)
		}
	}
	return snapshot
}

// Every disclosure the newest verified policy carries that the registry takes, in the policy's order; with no policy
// ErrComputeDisclosurePolicyUnavailable.
func (self *ComputeDisclosureRegistry) Disclosures() ([]*ComputeDisclosure, error) {
	snapshot, err := self.current()
	if err != nil {
		return nil, err
	}
	return slices.Clone(snapshot.disclosures), nil
}

// The disclosure of id, or why there is none: ErrComputeDisclosurePolicyUnavailable, ErrComputeDisclosureIdInvalid,
// ErrComputeDisclosureNotCarried or ErrComputeDisclosureRefused.
func (self *ComputeDisclosureRegistry) Disclosure(id string) (*ComputeDisclosure, error) {
	if _, err := ParseComputeDisclosureId(id, self.settings); err != nil {
		return nil, err
	}
	snapshot, err := self.current()
	if err != nil {
		return nil, err
	}
	return snapshot.disclosure(id)
}

// id's summary line in the person's locale, the line every card of its service shows and which opens the whole text:
// printable, from the newest verified policy alone.
func (self *ComputeDisclosureRegistry) Line(id string, locale string) (string, error) {
	disclosure, err := self.Disclosure(id)
	if err != nil {
		return "", err
	}
	return ApprovalPrintable(disclosure.Text(locale).Summary), nil
}

// id's view in the person's locale (disclosure_render.go).
func (self *ComputeDisclosureRegistry) View(id string, locale string) (*ComputeDisclosureView, error) {
	disclosure, err := self.Disclosure(id)
	if err != nil {
		return nil, err
	}
	return NewComputeDisclosureView(disclosure, locale), nil
}

// Every disclosure's view in the person's locale, from one policy: what Sidecar.ComputeDisclosures, ur disclosures and
// the sdk's Disclosures() answer, with no policy ErrComputeDisclosurePolicyUnavailable.
func (self *ComputeDisclosureRegistry) List(locale string) (*ComputeDisclosureList, error) {
	snapshot, err := self.current()
	if err != nil {
		return nil, err
	}
	list := &ComputeDisclosureList{
		PolicyVersion: snapshot.policy.Version,
		Locale:        computeDisclosureLocaleTag(locale, self.settings),
		Disclosures:   []*ComputeDisclosureView{},
	}
	for _, disclosure := range snapshot.disclosures {
		list.Disclosures = append(list.Disclosures, NewComputeDisclosureView(disclosure, locale))
	}
	return list, nil
}

// What a list of disclosures answers, the same JSON on every surface: the daemon's compute.disclosure.list and the
// sdk's Disclosures().
type ComputeDisclosureList struct {
	// The version of the newest verified policy the list was read from; 0 where none is held.
	PolicyVersion uint64 `json:"policy_version"`
	// The locale asked for, as a tag; empty for English or none.
	Locale string `json:"locale"`
	// Each disclosure, in the policy's order.
	Disclosures []*ComputeDisclosureView `json:"disclosures"`
	// policy_unavailable where the device holds no verified policy, and then no disclosure is listed: never an empty
	// list in its place.
	Unavailable string `json:"unavailable,omitempty"`
}

// The name the registry's component registers under.
const computeDisclosureComponentName = "disclosures"

// Registers the disclosures' component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(computeDisclosureComponentName, newComputeDisclosureComponent, nil)
}

// The disclosures' parts on one Sidecar: the registry over attestation's store, the person's acknowledgments over the
// member's harness config, the changed marks in the sidecar's own store and the check (disclosure_check.go), each
// reading its sources at use.
type computeDisclosureComponent struct {
	sidecar  *Sidecar
	settings *ComputeDisclosureSettings
	registry *ComputeDisclosureRegistry
	acks     *ComputeDisclosureAcks
	marks    *computeDisclosureMarks
	check    *ComputeDisclosureCheck
}

// The component over sidecar's settings and log, reading nothing of the network or another component as it builds.
func newComputeDisclosureComponent(sidecar *Sidecar) (*computeDisclosureComponent, error) {
	settings := sidecar.settings.Disclosure
	if settings == nil {
		settings = DefaultComputeDisclosureSettings()
	}
	registry, err := NewComputeDisclosureRegistry(&ComputeDisclosureRegistryArgs{
		Source:   &computeDisclosureSidecarSource{sidecar: sidecar},
		Settings: settings,
		Log:      sidecar.log,
	})
	if err != nil {
		return nil, err
	}
	acks, marks, check, err := newComputeDisclosureParts(sidecar, registry, settings)
	if err != nil {
		return nil, err
	}
	return &computeDisclosureComponent{
		sidecar:  sidecar,
		settings: settings,
		registry: registry,
		acks:     acks,
		marks:    marks,
		check:    check,
	}, nil
}

// The newest verified policy of a Sidecar's attestation store, read at each call: nil where the store is not there,
// so the registry answers policy_unavailable.
type computeDisclosureSidecarSource struct {
	sidecar *Sidecar
}

// See ComputeDisclosureSource.
func (self *computeDisclosureSidecarSource) Newest() *ComputePolicy {
	store, err := self.sidecar.ComputePolicyStore()
	if err != nil {
		return nil
	}
	return store.Newest()
}

// The Sidecar's disclosures component.
func (self *Sidecar) computeDisclosures() (*computeDisclosureComponent, error) {
	return sidecarComputeComponent[computeDisclosureComponent](self, computeDisclosureComponentName)
}

// This Sidecar's disclosure registry, or an error wrapping ErrComputeComponentUnavailable that says why there is none.
func (self *Sidecar) ComputeDisclosureRegistry() (*ComputeDisclosureRegistry, error) {
	component, err := self.computeDisclosures()
	if err != nil {
		return nil, err
	}
	return component.registry, nil
}

// Every disclosure of the newest verified policy in the person's locale (§2.8, §15.3): what the settings list, `ur
// disclosures` and the sdk's Disclosures() show. ErrComputeDisclosurePolicyUnavailable where the device holds no
// verified policy.
func (self *Sidecar) ComputeDisclosures(ctx context.Context, locale string) (*ComputeDisclosureList, error) {
	component, err := self.computeDisclosures()
	if err != nil {
		return nil, err
	}
	return component.list(ctx, locale)
}

// The list the component answers: the registry's, with each view's acknowledgment and mark (disclosure_check.go).
func (self *computeDisclosureComponent) list(ctx context.Context, locale string) (*ComputeDisclosureList, error) {
	list, err := self.registry.List(locale)
	if err != nil {
		return nil, err
	}
	return self.withAcks(ctx, list), nil
}
