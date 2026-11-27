//go:build !ios_extension && !sidecar_http

// The compute policy's pipeline (DESIGN-COMPUTE §5.4, §14.10, D-ATTEST-2, D-ATTEST-5, D-ATTEST-8, D-ATTEST-9;
// ATTEST-M12-02): what the compute rota's sittings run, through sidecarctl's compute policy commands
// (server/sidecarctl/cmd_compute_policy*.go), and what sidecartest's fakes may build on with test keys:
//
//	ComputePolicyBuilder       a policy's canonical bytes from the policy before it and a sitting's change set, held to
//	                           the pipeline's rules and then to the devices' own parse, so what it writes every device
//	                           reads; and the checks of a signing certificate and of what comes back from signing, as a
//	                           device makes them
//	ComputeTicketBatchBuilder  a sitting's batch of freshness tickets, and each ticket's file once it is signed
//	ComputePolicyHorizon       how long the newest policy and the newest batch carry remote work: what status prints
//	                           and CSRV's monitor pages on at 14 and 7 days (§14.7)
//
// A change set (ComputePolicyChangeSet) names what a sitting changes, §14.10's list: a measurement profile as a
// provider rolls an image, with its review, reproduced or listed with the list's SHA-256 (§5.4's Review); a model id;
// a disclosure's text at a new version, a fact having changed, or at a new revision, its words alone (§2.8); a direct,
// search, services or support line; a provider or its custody; a revocation, or one withdrawn; and what leaves. The
// builder refuses a version not above the last, a not_after past PolicyMaxLifetime from the signing (the staging
// policy's StagingPolicyLifetime, §5.4's 7 days), a profile without a review record, and a disclosure whose fact
// changed without its version raised, or whose version rose with no fact changed.
//
// The canonical form, the bytes the holders sign: the policy as encoding/json writes ComputePolicy, its members in the
// format's order, every list written [] where it is empty since the format refuses null, no HTML escaping, indented
// by two spaces and ended by one newline; the raw lines (search, services, support) re-indented with the rest, their
// members and order as given. One content has one form, so a rebuild repeats its bytes.
//
// Nothing here signs or holds a private key: the holders sign with ssh-keygen -Y sign on their tokens (§14.10), and
// tests and fakes with software keys through ComputeSshsigSign. What comes back is verified by a ComputePolicyVerifier
// over this build's pins, the release key attest_policy_root.go writes, none until the key ceremony, so until then the
// pipeline verifies nothing and refuses to sign anything; a test stands in its own release key (ReleaseKeys). A device
// never verifies through a builder: its store and gate take NewComputePolicyVerifier's pins alone.
//
// The serving path's names (ComputePolicyFileName and its kin) are the fetcher's and the publishers' one layout.
//
// Safe for concurrent use: a builder is fixed once made, and a build or batch is its caller's.

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// What a builder refuses: a change, a version, a bound or a signer the pipeline does not sign. Each refusal wraps its
// reason's own error beside this one.
var ErrComputePolicyBuildRefused = errors.New("compute policy build refused")

// The reasons a builder refuses, each wrapped beside ErrComputePolicyBuildRefused.
var (
	// The version is not above the policy before it.
	errComputePolicyBuildVersion = errors.New("its version is not above the last")
	// not_after is at or before the signing, or past the lifetime from it.
	errComputePolicyBuildNotAfter = errors.New("its not_after is outside its bound from the signing")
	// A profile carries no review record (§5.4's Review).
	errComputePolicyBuildReview = errors.New("a profile has no review record")
	// A disclosure's fact changed without its version raised, or its version rose with no fact changed (§2.8).
	errComputePolicyBuildDisclosure = errors.New("a disclosure's version or revision does not follow what changed")
	// A change the policy before it cannot take: a key named twice, a removal of what is not there, a profile under a
	// provider not there.
	errComputePolicyBuildChange = errors.New("a change does not apply")
	// The devices' parse refuses what was built, or a line its owner reads does not parse.
	errComputePolicyBuildFormat = errors.New("a device would not take it")
	// The signing certificate or what came back from signing is not what the pipeline signs with.
	errComputePolicyBuildSigner = errors.New("its signer is not the certified key it must be")
	// A ticket batch outside §5.4's bounds, or one with no ticket.
	errComputePolicyBuildBatch = errors.New("the batch is outside §5.4's bounds")
)

// A refusal for reason, its message naming what was wrong in the pipeline's words.
func computePolicyBuildError(reason error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrComputePolicyBuildRefused, reason, fmt.Sprintf(format, args...))
}

// The pipeline's settings (QD-702). The format's limits and §5.4's bounds are AttestSettings', the devices' own, so
// what is built here is held to what every device takes, and changing one is a format change, never made on one side.
type ComputePolicyBuildSettings struct {
	// The devices' settings: the parse limits, the ticket window and batch bounds, the staging policy's lifetime and
	// the certificate bound everything built here is held to. Nil takes DefaultAttestSettings.
	Attest *AttestSettings
	// The latest not_after a production policy may carry from its signing: 90 days, §5.4's. A later one is refused;
	// non-positive refuses every policy. The staging policy's is Attest.StagingPolicyLifetime, §5.4's 7 days.
	PolicyMaxLifetime time.Duration
	// How near its not_after the newest policy is reported as expiring: 14 days, the page §14.7 names. Non-positive
	// reports only a policy past it.
	PolicyExpiryWarning time.Duration
	// How near its batch's expiry the newest ticket's horizon is reported as near: 7 days, the page §14.7 names, the
	// slack a missed weekly sitting leaves (§14.10). Non-positive reports only a horizon passed.
	TicketHorizonWarning time.Duration
}

// The pipeline's defaults, the only place one is set.
func DefaultComputePolicyBuildSettings() *ComputePolicyBuildSettings {
	return &ComputePolicyBuildSettings{
		Attest:               DefaultAttestSettings(),
		PolicyMaxLifetime:    90 * 24 * time.Hour,
		PolicyExpiryWarning:  14 * 24 * time.Hour,
		TicketHorizonWarning: 7 * 24 * time.Hour,
	}
}

// settings, or the defaults where nil, with the devices' settings filled in where it carries none.
func computePolicyBuildSettingsOrDefault(settings *ComputePolicyBuildSettings) *ComputePolicyBuildSettings {
	if settings == nil {
		return DefaultComputePolicyBuildSettings()
	}
	if settings.Attest == nil {
		withAttest := *settings
		withAttest.Attest = DefaultAttestSettings()
		return &withAttest
	}
	return settings
}

// What a sitting changes (§14.10), applied to the policy before it in this order: the lines replaced whole, then what
// leaves, then what is put, each entry put replacing the entry of its key or added after the others, then the
// revocations added. A key put twice, or both removed and put, is refused, as is a removal of what is not there and a
// revocation already in force.
type ComputePolicyChangeSet struct {
	// The vendor roots, replaced whole.
	Roots *ComputePolicyRoots `json:"roots,omitempty"`
	// The TCB rules, replaced whole.
	Tcb *ComputePolicyTcb `json:"tcb,omitempty"`
	// TEE providers, each put whole by its id, every profile of it carrying its review.
	Providers []*ComputePolicyProvider `json:"providers,omitempty"`
	// Measurement profiles, each put under its provider by its id, with its review: as a provider rolls an image.
	Profiles []*ComputePolicyProfileChange `json:"profiles,omitempty"`
	// Catalog models' provider ids, each put under its TEE provider by its model part.
	Models []*ComputePolicyModelChange `json:"models,omitempty"`
	// The direct line, replaced whole: its providers and limited_use.
	Direct *ComputePolicyDirectLine `json:"direct,omitempty"`
	// The raw lines, each replaced whole by the JSON its owner decodes (§21.5, §25.4, §28.10). A gated one, search and
	// a services definition, enters the staging policy first (§4.7, §19.2).
	Search   json.RawMessage `json:"search,omitempty"`
	Services json.RawMessage `json:"services,omitempty"`
	Support  json.RawMessage `json:"support,omitempty"`
	// Disclosure texts, each put by its id at a new version or a new revision.
	Disclosures []*ComputePolicyDisclosureChange `json:"disclosures,omitempty"`
	// Custody registries, each put whole by its provider.
	Custody []*ComputePolicyCustody `json:"custody,omitempty"`
	// Revocations added: profiles, chip identities and GPU serials refused whatever else passes.
	Revoke *ComputePolicyRevoked `json:"revoke,omitempty"`
	// What leaves.
	Remove *ComputePolicyRemovals `json:"remove,omitempty"`
}

// One measurement profile put under a TEE provider.
type ComputePolicyProfileChange struct {
	// The provider's id, which the policy before it or this change set's providers hold.
	Provider string `json:"provider"`
	// The profile whole, with its review: reproduced, or listed with the list's SHA-256.
	Profile *ComputePolicyProfile `json:"profile"`
}

// One catalog model's provider id put under a TEE provider (Chutes: a chute_id).
type ComputePolicyModelChange struct {
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	ProviderModelId string `json:"provider_model_id"`
}

// A catalog model of a TEE provider, by its model part.
type ComputePolicyModelRef struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// What a disclosure change is (§2.8's A new version), identifiers.
const (
	// A fact changed: the version rises by one, its revision is 0, and its grace runs from the policy's signing.
	ComputePolicyDisclosureFact = "fact"
	// Its words alone changed, a fix, a clearer sentence or a translation: the revision rises by one, and the version,
	// its grace and the instant it took effect stand.
	ComputePolicyDisclosureWords = "words"
)

// One disclosure's text put by its id.
type ComputePolicyDisclosureChange struct {
	// fact or words.
	Change string `json:"change"`
	// The disclosure as it is to read: its id, the version and revision the change gives it, its grace and its texts,
	// English first. Its since_ms is the build's to set, so a change leaves it 0.
	Disclosure *ComputePolicyDisclosure `json:"disclosure"`
}

// What leaves the policy, each by its key.
type ComputePolicyRemovals struct {
	// TEE providers by id, with their profiles and models; a custody entry naming one leaves by Custody.
	Providers []string `json:"providers,omitempty"`
	// Measurement profiles by id, from whichever provider holds each.
	Profiles []string `json:"profiles,omitempty"`
	// Catalog models of TEE providers.
	Models []*ComputePolicyModelRef `json:"models,omitempty"`
	// Disclosures by id.
	Disclosures []string `json:"disclosures,omitempty"`
	// Custody entries by provider.
	Custody []string `json:"custody,omitempty"`
	// The raw lines, each where set.
	Search   bool `json:"search,omitempty"`
	Services bool `json:"services,omitempty"`
	Support  bool `json:"support,omitempty"`
	// Revocations withdrawn, which widens what passes: the holders' review says why.
	Revoked *ComputePolicyRevoked `json:"revoked,omitempty"`
}

// A change set's JSON, as an operator writes it, read strictly as the policy is: one object of these members alone,
// each once, no null, integers as integers, within the policy's own bounds.
func ParseComputePolicyChangeSet(data []byte, settings *ComputePolicyBuildSettings) (*ComputePolicyChangeSet, error) {
	settings = computePolicyBuildSettingsOrDefault(settings)
	if settings.Attest.PolicyMaxByteCount < len(data) {
		return nil, computePolicyBuildError(errComputePolicyBuildChange, "the change set is larger than %d bytes", settings.Attest.PolicyMaxByteCount)
	}
	if err := computePolicyJsonStrict(data, reflect.TypeFor[ComputePolicyChangeSet](), settings.Attest); err != nil {
		return nil, computePolicyBuildError(errComputePolicyBuildChange, "the change set does not parse: %s", err)
	}
	changes := &ComputePolicyChangeSet{}
	if err := json.Unmarshal(data, changes); err != nil {
		return nil, computePolicyBuildError(errComputePolicyBuildChange, "the change set does not decode")
	}
	return changes, nil
}

// What NewComputePolicyBuilder builds on.
type ComputePolicyBuilderArgs struct {
	// Nil takes DefaultComputePolicyBuildSettings.
	Settings *ComputePolicyBuildSettings
	// The staging policy's pipeline: the staging namespace, compute-policy-staging.json and its 7 days (D-ATTEST-8).
	Staging bool
	// The release keys what comes back from signing is verified under. Nil takes this build's pins, ComputeReleaseKeys,
	// as a device of this tree verifies: none until the key ceremony, so every check refuses. A test stands in its own.
	ReleaseKeys []ssh.PublicKey
	// Nil reads real time.
	Clock Clock
}

// Builds policies and checks their signers and signatures for one namespace (see the file header).
type ComputePolicyBuilder struct {
	settings *ComputePolicyBuildSettings
	staging  bool
	verifier *ComputePolicyVerifier
	clock    Clock
}

// A builder over args.
func NewComputePolicyBuilder(args *ComputePolicyBuilderArgs) *ComputePolicyBuilder {
	if args == nil {
		args = &ComputePolicyBuilderArgs{}
	}
	settings := computePolicyBuildSettingsOrDefault(args.Settings)
	releaseKeys := args.ReleaseKeys
	if releaseKeys == nil {
		releaseKeys = ComputeReleaseKeys()
	}
	namespace := ComputePolicyNamespace
	if args.Staging {
		namespace = ComputePolicyStagingNamespace
	}
	return &ComputePolicyBuilder{
		settings: settings,
		staging:  args.Staging,
		verifier: newComputePolicyVerifier(settings.Attest, releaseKeys, namespace, args.Staging),
		clock:    clockOrReal(args.Clock),
	}
}

// The namespace this builder's policies and tickets are signed under.
func (self *ComputePolicyBuilder) Namespace() string {
	return self.verifier.Namespace()
}

// Whether it builds the staging policy.
func (self *ComputePolicyBuilder) Staging() bool {
	return self.staging
}

// The builder's settings, which its caller reads its bounds from; never changed through this.
func (self *ComputePolicyBuilder) Settings() *ComputePolicyBuildSettings {
	return self.settings
}

// The latest not_after a policy of this builder may carry from its signing.
func (self *ComputePolicyBuilder) lifetime() time.Duration {
	if self.staging {
		return self.settings.Attest.StagingPolicyLifetime
	}
	return self.settings.PolicyMaxLifetime
}

// What Build builds on.
type ComputePolicyBuildArgs struct {
	// The policy the new one follows, as its signature verified it; nil for the first, built from an empty policy.
	Previous *ComputePolicy
	// The new version: zero takes the one after Previous's, 1 with none.
	Version uint64
	// The sitting, when the policy is signed: zero takes the builder's clock. Kept to the millisecond.
	SignedAt time.Time
	// Zero takes SignedAt and the builder's lifetime: 90 days, or the staging policy's 7.
	NotAfter time.Time
	// Nil changes nothing but the version and not_after: the policy re-issued.
	Changes *ComputePolicyChangeSet
}

// A policy as built, before it is signed.
type ComputePolicyBuild struct {
	// The policy as every device parses Document.
	Policy *ComputePolicy
	// The canonical bytes, what the holders sign.
	Document []byte
	// The sitting the build was made for: its not_after and each new disclosure version's since_ms count from it.
	SignedAt time.Time
	// One line for each change, in the order applied, for the holders' review.
	Changes []string
}

// The policy args describe, in its canonical bytes, once every rule of the file header holds and the devices' parse
// takes it; else an error wrapping ErrComputePolicyBuildRefused and its reason's own.
func (self *ComputePolicyBuilder) Build(args *ComputePolicyBuildArgs) (*ComputePolicyBuild, error) {
	if args == nil {
		args = &ComputePolicyBuildArgs{}
	}
	signedAt := args.SignedAt
	if signedAt.IsZero() {
		signedAt = self.clock.Now()
	}
	signedAt = time.UnixMilli(signedAt.UnixMilli()).UTC()
	policy := &ComputePolicy{}
	previousVersion := uint64(0)
	if args.Previous != nil {
		copied, err := computePolicyJsonCopy(args.Previous)
		if err != nil {
			return nil, computePolicyBuildError(errComputePolicyBuildChange, "the policy before it does not copy: %s", err)
		}
		policy = copied
		previousVersion = args.Previous.Version
	}
	version := args.Version
	if version == 0 {
		version = previousVersion + 1
	}
	if version <= previousVersion {
		return nil, computePolicyBuildError(errComputePolicyBuildVersion, "version %d is not above %d", version, previousVersion)
	}
	lifetime := self.lifetime()
	notAfter := args.NotAfter
	if notAfter.IsZero() {
		notAfter = signedAt.Add(lifetime)
	}
	notAfter = time.UnixMilli(notAfter.UnixMilli()).UTC()
	if lifetime <= 0 || !signedAt.Before(notAfter) || signedAt.Add(lifetime).Before(notAfter) {
		return nil, computePolicyBuildError(errComputePolicyBuildNotAfter, "not_after %s is not after its signing at %s and within %s of it",
			notAfter.Format(time.RFC3339), signedAt.Format(time.RFC3339), lifetime)
	}
	policy.Version = version
	policy.NotAfterMs = notAfter.UnixMilli()
	notes := []string{
		fmt.Sprintf("version %d, after %d", version, previousVersion),
		fmt.Sprintf("signed at %s, not_after %s, %s later", signedAt.Format(time.RFC3339), notAfter.Format(time.RFC3339), notAfter.Sub(signedAt)),
	}
	if args.Changes != nil {
		changes, err := computePolicyJsonCopy(args.Changes)
		if err != nil {
			return nil, computePolicyBuildError(errComputePolicyBuildChange, "the change set does not copy: %s", err)
		}
		applied, err := self.apply(policy, args.Previous, changes, signedAt)
		if err != nil {
			return nil, err
		}
		notes = append(notes, applied...)
	}
	document, err := computePolicyCanonical(policy)
	if err != nil {
		return nil, computePolicyBuildError(errComputePolicyBuildFormat, "it does not encode: %s", err)
	}
	parsed, err := parseComputePolicy(document, self.settings.Attest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrComputePolicyBuildRefused, errComputePolicyBuildFormat, err)
	}
	return &ComputePolicyBuild{Policy: parsed, Document: document, SignedAt: signedAt, Changes: notes}, nil
}

// Applies changes to policy, a copy of previous (nil for the first), in the change set's order, and says what each
// did.
func (self *ComputePolicyBuilder) apply(policy *ComputePolicy, previous *ComputePolicy, changes *ComputePolicyChangeSet, signedAt time.Time) ([]string, error) {
	notes := []string{}
	note := func(format string, args ...any) {
		notes = append(notes, fmt.Sprintf(format, args...))
	}
	refuse := func(format string, args ...any) error {
		return computePolicyBuildError(errComputePolicyBuildChange, format, args...)
	}
	removals := changes.Remove
	if removals == nil {
		removals = &ComputePolicyRemovals{}
	}
	if err := computePolicyChangeKeysOnce(changes, removals); err != nil {
		return nil, err
	}

	// the lines replaced whole
	if changes.Roots != nil {
		policy.Roots = *changes.Roots
		note("roots replaced")
	}
	if changes.Tcb != nil {
		policy.Tcb = *changes.Tcb
		note("tcb replaced")
	}
	if changes.Direct != nil {
		policy.Direct = *changes.Direct
		note("direct replaced: %d providers, %d limited_use models", len(changes.Direct.Providers), len(changes.Direct.LimitedUse))
	}
	for _, line := range []struct {
		name  string
		raw   json.RawMessage
		field *json.RawMessage
	}{
		{name: "search", raw: changes.Search, field: &policy.Search},
		{name: "services", raw: changes.Services, field: &policy.Services},
		{name: "support", raw: changes.Support, field: &policy.Support},
	} {
		if len(line.raw) == 0 {
			continue
		}
		if !json.Valid(line.raw) {
			return nil, computePolicyBuildError(errComputePolicyBuildFormat, "the %s line is not JSON", line.name)
		}
		*line.field = bytes.Clone(line.raw)
		note("%s line replaced", line.name)
	}
	if len(changes.Support) != 0 {
		// the pipeline never signs a support line support's client cannot read, so no message waits for a host forever
		if _, err := ParseSupportPolicyLine(changes.Support); err != nil {
			return nil, computePolicyBuildError(errComputePolicyBuildFormat, "the support line does not parse as support's client reads it: %s", err)
		}
	}

	// what leaves
	for _, id := range removals.Providers {
		index := slices.IndexFunc(policy.Providers, func(provider *ComputePolicyProvider) bool { return provider.Id == id })
		if index < 0 {
			return nil, refuse("provider %s is removed and the policy before it holds none", id)
		}
		policy.Providers = slices.Delete(policy.Providers, index, index+1)
		note("provider %s removed, with its profiles and models", id)
	}
	for _, profileId := range removals.Profiles {
		removed := false
		for _, provider := range policy.Providers {
			index := slices.IndexFunc(provider.Profiles, func(profile *ComputePolicyProfile) bool { return profile.Id == profileId })
			if index < 0 {
				continue
			}
			provider.Profiles = slices.Delete(provider.Profiles, index, index+1)
			note("profile %s removed from %s", profileId, provider.Id)
			removed = true
			break
		}
		if !removed {
			return nil, refuse("profile %s is removed and no provider holds it", profileId)
		}
	}
	for _, model := range removals.Models {
		if model == nil {
			return nil, refuse("a model removal names nothing")
		}
		provider := policy.Provider(model.Provider)
		index := -1
		if provider != nil {
			index = slices.IndexFunc(provider.Models, func(entry *ComputePolicyModel) bool { return entry.Model == model.Model })
		}
		if index < 0 {
			return nil, refuse("model %s of %s is removed and the policy before it holds none", model.Model, model.Provider)
		}
		provider.Models = slices.Delete(provider.Models, index, index+1)
		note("model %s removed from %s", model.Model, model.Provider)
	}
	for _, id := range removals.Disclosures {
		index := slices.IndexFunc(policy.Disclosures, func(disclosure *ComputePolicyDisclosure) bool { return disclosure.Id == id })
		if index < 0 {
			return nil, refuse("disclosure %s is removed and the policy before it holds none", id)
		}
		policy.Disclosures = slices.Delete(policy.Disclosures, index, index+1)
		note("disclosure %s removed", id)
	}
	for _, providerId := range removals.Custody {
		index := slices.IndexFunc(policy.Custody, func(custody *ComputePolicyCustody) bool { return custody.Provider == providerId })
		if index < 0 {
			return nil, refuse("custody of %s is removed and the policy before it holds none", providerId)
		}
		policy.Custody = slices.Delete(policy.Custody, index, index+1)
		note("custody of %s removed", providerId)
	}
	for _, line := range []struct {
		name   string
		remove bool
		field  *json.RawMessage
	}{
		{name: "search", remove: removals.Search, field: &policy.Search},
		{name: "services", remove: removals.Services, field: &policy.Services},
		{name: "support", remove: removals.Support, field: &policy.Support},
	} {
		if !line.remove {
			continue
		}
		if len(*line.field) == 0 {
			return nil, refuse("the %s line is removed and the policy before it carries none", line.name)
		}
		*line.field = nil
		note("%s line removed", line.name)
	}
	if withdrawn := removals.Revoked; withdrawn != nil {
		for _, profileId := range withdrawn.Profiles {
			index := slices.Index(policy.Revoked.Profiles, profileId)
			if index < 0 {
				return nil, refuse("the revocation of profile %s is withdrawn and none is in force", profileId)
			}
			policy.Revoked.Profiles = slices.Delete(policy.Revoked.Profiles, index, index+1)
			note("revocation withdrawn: profile %s", profileId)
		}
		for _, chip := range withdrawn.Chips {
			if chip == nil {
				return nil, refuse("a withdrawn revocation names no chip")
			}
			index := slices.IndexFunc(policy.Revoked.Chips, func(revoked *ComputePolicyChip) bool { return *revoked == *chip })
			if index < 0 {
				return nil, refuse("the revocation of chip %s %s is withdrawn and none is in force", chip.Kind, chip.Id)
			}
			policy.Revoked.Chips = slices.Delete(policy.Revoked.Chips, index, index+1)
			note("revocation withdrawn: chip %s %s", chip.Kind, chip.Id)
		}
		for _, serial := range withdrawn.GpuSerials {
			index := slices.Index(policy.Revoked.GpuSerials, serial)
			if index < 0 {
				return nil, refuse("the revocation of GPU %s is withdrawn and none is in force", serial)
			}
			policy.Revoked.GpuSerials = slices.Delete(policy.Revoked.GpuSerials, index, index+1)
			note("revocation withdrawn: GPU %s", serial)
		}
	}

	// what is put
	for _, provider := range changes.Providers {
		if provider == nil || provider.Id == "" {
			return nil, refuse("a provider is put with no id")
		}
		for _, profile := range provider.Profiles {
			if err := computePolicyCheckReview(provider.Id, profile); err != nil {
				return nil, err
			}
		}
		verb := "added"
		if index := slices.IndexFunc(policy.Providers, func(held *ComputePolicyProvider) bool { return held.Id == provider.Id }); 0 <= index {
			policy.Providers[index] = provider
			verb = "replaced"
		} else {
			policy.Providers = append(policy.Providers, provider)
		}
		note("provider %s %s whole: label %s, %d models, %d profiles", provider.Id, verb, provider.Label, len(provider.Models), len(provider.Profiles))
	}
	for _, change := range changes.Profiles {
		if change == nil || change.Profile == nil {
			return nil, refuse("a profile change names no profile")
		}
		provider := policy.Provider(change.Provider)
		if provider == nil {
			return nil, refuse("profile %s is put under provider %s, which neither the policy before it nor the change set holds", change.Profile.Id, change.Provider)
		}
		if err := computePolicyCheckReview(provider.Id, change.Profile); err != nil {
			return nil, err
		}
		verb := "added"
		if index := slices.IndexFunc(provider.Profiles, func(profile *ComputePolicyProfile) bool { return profile.Id == change.Profile.Id }); 0 <= index {
			provider.Profiles[index] = change.Profile
			verb = "replaced"
		} else {
			provider.Profiles = append(provider.Profiles, change.Profile)
		}
		review := change.Profile.Review
		if review == ComputePolicyReviewListed {
			review += " from the list of SHA-256 " + change.Profile.ReviewListSha256
		}
		note("profile %s %s under %s: %s, guest %s, expiring %s, %s", change.Profile.Id, verb, provider.Id, change.Profile.Cpu,
			change.Profile.GuestVersion, time.UnixMilli(change.Profile.ExpiresMs).UTC().Format(time.RFC3339), review)
	}
	for _, change := range changes.Models {
		if change == nil {
			return nil, refuse("a model change names nothing")
		}
		provider := policy.Provider(change.Provider)
		if provider == nil {
			return nil, refuse("model %s is put under provider %s, which neither the policy before it nor the change set holds", change.Model, change.Provider)
		}
		entry := &ComputePolicyModel{Model: change.Model, ProviderModelId: change.ProviderModelId}
		if index := slices.IndexFunc(provider.Models, func(held *ComputePolicyModel) bool { return held.Model == change.Model }); 0 <= index {
			note("model %s of %s: its provider id %s, was %s", change.Model, provider.Id, change.ProviderModelId, provider.Models[index].ProviderModelId)
			provider.Models[index] = entry
		} else {
			provider.Models = append(provider.Models, entry)
			note("model %s added to %s: its provider id %s", change.Model, provider.Id, change.ProviderModelId)
		}
	}
	for _, change := range changes.Disclosures {
		applied, err := self.applyDisclosure(policy, previous, change, signedAt)
		if err != nil {
			return nil, err
		}
		note("%s", applied)
	}
	for _, custody := range changes.Custody {
		if custody == nil {
			return nil, refuse("a custody change names nothing")
		}
		verb := "added"
		if index := slices.IndexFunc(policy.Custody, func(held *ComputePolicyCustody) bool { return held.Provider == custody.Provider }); 0 <= index {
			policy.Custody[index] = custody
			verb = "replaced"
		} else {
			policy.Custody = append(policy.Custody, custody)
		}
		note("custody of %s %s: registry %s, %d chips", custody.Provider, verb, custody.Registry, len(custody.Chips))
	}

	// the revocations
	if revoke := changes.Revoke; revoke != nil {
		for _, profileId := range revoke.Profiles {
			if slices.Contains(policy.Revoked.Profiles, profileId) {
				return nil, refuse("profile %s is revoked and its revocation is already in force", profileId)
			}
			policy.Revoked.Profiles = append(policy.Revoked.Profiles, profileId)
			note("profile %s revoked", profileId)
		}
		for _, chip := range revoke.Chips {
			if chip == nil {
				return nil, refuse("a revocation names no chip")
			}
			if slices.ContainsFunc(policy.Revoked.Chips, func(revoked *ComputePolicyChip) bool { return *revoked == *chip }) {
				return nil, refuse("chip %s %s is revoked and its revocation is already in force", chip.Kind, chip.Id)
			}
			policy.Revoked.Chips = append(policy.Revoked.Chips, chip)
			note("chip %s %s revoked", chip.Kind, chip.Id)
		}
		for _, serial := range revoke.GpuSerials {
			if slices.Contains(policy.Revoked.GpuSerials, serial) {
				return nil, refuse("GPU %s is revoked and its revocation is already in force", serial)
			}
			policy.Revoked.GpuSerials = append(policy.Revoked.GpuSerials, serial)
			note("GPU %s revoked", serial)
		}
	}
	return notes, nil
}

// Puts one disclosure's text, its version and revision held to what changed (§2.8): a fact change raises the version
// by one, starts at revision 0 and takes the signing as the instant its grace runs from (QD-1242); a change of words
// raises the revision by one and keeps the version, its grace and its instant, and must change some word. A new id is
// a fact, at version 1. Answers what it did.
func (self *ComputePolicyBuilder) applyDisclosure(policy *ComputePolicy, previous *ComputePolicy, change *ComputePolicyDisclosureChange, signedAt time.Time) (string, error) {
	if change == nil || change.Disclosure == nil || change.Disclosure.Id == "" {
		return "", computePolicyBuildError(errComputePolicyBuildChange, "a disclosure change names no disclosure")
	}
	disclosure := change.Disclosure
	refuse := func(format string, args ...any) error {
		return computePolicyBuildError(errComputePolicyBuildDisclosure, "disclosure %s: %s", disclosure.Id, fmt.Sprintf(format, args...))
	}
	var before *ComputePolicyDisclosure
	if previous != nil {
		before = previous.Disclosure(disclosure.Id)
	}
	if disclosure.SinceMs != 0 {
		return "", refuse("since_ms is the build's to set, from the signing or the version before")
	}
	applied := ""
	switch change.Change {
	case ComputePolicyDisclosureFact:
		want := uint32(1)
		if before != nil {
			want = before.Version + 1
		}
		switch {
		case before != nil && disclosure.Version <= before.Version:
			return "", refuse("a fact changed and its version stayed at %d, where it must rise to %d", disclosure.Version, want)
		case disclosure.Version != want:
			return "", refuse("a fact change takes version %d, not %d", want, disclosure.Version)
		case disclosure.Revision != 0:
			return "", refuse("a new version starts at revision 0, not %d", disclosure.Revision)
		}
		disclosure.SinceMs = signedAt.UnixMilli()
		applied = fmt.Sprintf("disclosure %s: version %d, a fact changed, its grace %d days from %s", disclosure.Id, disclosure.Version,
			disclosure.GraceDays, signedAt.Format(time.RFC3339))
	case ComputePolicyDisclosureWords:
		switch {
		case before == nil:
			return "", refuse("a new disclosure is a fact: change fact, at version 1")
		case disclosure.Version != before.Version:
			return "", refuse("its words alone changed and its version moved from %d to %d: a version rises only when a fact changes", before.Version, disclosure.Version)
		case disclosure.GraceDays != before.GraceDays:
			return "", refuse("its grace, a fact of its version, changed from %d to %d days without a new version", before.GraceDays, disclosure.GraceDays)
		case disclosure.Revision != before.Revision+1:
			return "", refuse("a change of its words takes revision %d, not %d", before.Revision+1, disclosure.Revision)
		case computePolicyWordsEqual(disclosure.Locales, before.Locales):
			return "", refuse("revision %d changes no word", disclosure.Revision)
		}
		disclosure.SinceMs = before.SinceMs
		applied = fmt.Sprintf("disclosure %s: revision %d of version %d, its words alone changed", disclosure.Id, disclosure.Revision, disclosure.Version)
	default:
		return "", computePolicyBuildError(errComputePolicyBuildChange, "disclosure %s: a change is fact or words", disclosure.Id)
	}
	if index := slices.IndexFunc(policy.Disclosures, func(held *ComputePolicyDisclosure) bool { return held.Id == disclosure.Id }); 0 <= index {
		policy.Disclosures[index] = disclosure
	} else {
		policy.Disclosures = append(policy.Disclosures, disclosure)
	}
	return applied, nil
}

// Whether two disclosures' texts say the same words in the same locales, in order.
func computePolicyWordsEqual(a []*ComputePolicyDisclosureText, b []*ComputePolicyDisclosureText) bool {
	return slices.EqualFunc(a, b, func(x *ComputePolicyDisclosureText, y *ComputePolicyDisclosureText) bool {
		return x != nil && y != nil && x.Locale == y.Locale && x.Summary == y.Summary &&
			slices.Equal(x.Exposed, y.Exposed) && slices.Equal(x.Private, y.Private)
	})
}

// A profile's review record (§5.4's Review), which the builder refuses one without: reproduced, naming no list, or
// listed, naming the list's SHA-256.
func computePolicyCheckReview(providerId string, profile *ComputePolicyProfile) error {
	if profile == nil {
		return computePolicyBuildError(errComputePolicyBuildChange, "provider %s lists a profile that is nothing", providerId)
	}
	switch profile.Review {
	case ComputePolicyReviewReproduced:
		if profile.ReviewListSha256 == "" {
			return nil
		}
		return computePolicyBuildError(errComputePolicyBuildReview, "profile %s of %s is reproduced and names a list", profile.Id, providerId)
	case ComputePolicyReviewListed:
		if computePolicyHex(profile.ReviewListSha256, 32) {
			return nil
		}
		return computePolicyBuildError(errComputePolicyBuildReview, "profile %s of %s is listed without the list's SHA-256", profile.Id, providerId)
	}
	return computePolicyBuildError(errComputePolicyBuildReview, "profile %s of %s has no review record: reproduced, or listed with the list's SHA-256", profile.Id, providerId)
}

// The keys a change set names, each at most once among its puts and its removals, and none both put and removed.
func computePolicyChangeKeysOnce(changes *ComputePolicyChangeSet, removals *ComputePolicyRemovals) error {
	once := func(what string, keys []string) error {
		seen := map[string]bool{}
		for _, key := range keys {
			if seen[key] {
				return computePolicyBuildError(errComputePolicyBuildChange, "%s %s is named twice", what, key)
			}
			seen[key] = true
		}
		return nil
	}
	both := func(what string, put []string, removed []string) error {
		for _, key := range put {
			if slices.Contains(removed, key) {
				return computePolicyBuildError(errComputePolicyBuildChange, "%s %s is both put and removed", what, key)
			}
		}
		return nil
	}
	providerIds := []string{}
	for _, provider := range changes.Providers {
		if provider != nil {
			providerIds = append(providerIds, provider.Id)
		}
	}
	profileIds := []string{}
	for _, change := range changes.Profiles {
		if change != nil && change.Profile != nil {
			profileIds = append(profileIds, change.Profile.Id)
		}
	}
	modelKeys := []string{}
	for _, change := range changes.Models {
		if change != nil {
			modelKeys = append(modelKeys, change.Provider+"/"+change.Model)
		}
	}
	removedModelKeys := []string{}
	for _, model := range removals.Models {
		if model != nil {
			removedModelKeys = append(removedModelKeys, model.Provider+"/"+model.Model)
		}
	}
	disclosureIds := []string{}
	for _, change := range changes.Disclosures {
		if change != nil && change.Disclosure != nil {
			disclosureIds = append(disclosureIds, change.Disclosure.Id)
		}
	}
	custodyProviders := []string{}
	for _, custody := range changes.Custody {
		if custody != nil {
			custodyProviders = append(custodyProviders, custody.Provider)
		}
	}
	checks := []error{
		once("provider", providerIds), once("profile", profileIds), once("model", modelKeys),
		once("disclosure", disclosureIds), once("custody of", custodyProviders),
		once("removed provider", removals.Providers), once("removed profile", removals.Profiles),
		once("removed model", removedModelKeys), once("removed disclosure", removals.Disclosures),
		once("removed custody of", removals.Custody),
		both("provider", providerIds, removals.Providers), both("profile", profileIds, removals.Profiles),
		both("model", modelKeys, removedModelKeys), both("disclosure", disclosureIds, removals.Disclosures),
		both("custody of", custodyProviders, removals.Custody),
	}
	for _, line := range []struct {
		name   string
		put    bool
		remove bool
	}{
		{name: "search", put: 0 < len(changes.Search), remove: removals.Search},
		{name: "services", put: 0 < len(changes.Services), remove: removals.Services},
		{name: "support", put: 0 < len(changes.Support), remove: removals.Support},
	} {
		if line.put && line.remove {
			checks = append(checks, computePolicyBuildError(errComputePolicyBuildChange, "the %s line is both put and removed", line.name))
		}
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

// A deep copy of value through its JSON, with no HTML escaping, so a raw line's bytes keep their characters.
func computePolicyJsonCopy[T any](value *T) (*T, error) {
	encoded := &bytes.Buffer{}
	encoder := json.NewEncoder(encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	copied := new(T)
	if err := json.Unmarshal(encoded.Bytes(), copied); err != nil {
		return nil, err
	}
	return copied, nil
}

// policy's canonical bytes (see the file header).
func computePolicyCanonical(policy *ComputePolicy) ([]byte, error) {
	copied, err := computePolicyJsonCopy(policy)
	if err != nil {
		return nil, err
	}
	computePolicyFillLists(reflect.ValueOf(copied))
	compact := &bytes.Buffer{}
	encoder := json.NewEncoder(compact)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(copied); err != nil {
		return nil, err
	}
	indented := &bytes.Buffer{}
	if err := json.Indent(indented, bytes.TrimSuffix(compact.Bytes(), []byte("\n")), "", "  "); err != nil {
		return nil, err
	}
	indented.WriteByte('\n')
	return indented.Bytes(), nil
}

// Makes every nil list under value empty, so JSON writes [] where the format refuses null; a raw line is left as it
// is, nil where the policy carries none.
func computePolicyFillLists(value reflect.Value) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			computePolicyFillLists(value.Elem())
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				computePolicyFillLists(value.Field(i))
			}
		}
	case reflect.Slice:
		if value.Type() == computePolicyRawType {
			return
		}
		if value.IsNil() {
			if value.CanSet() {
				value.Set(reflect.MakeSlice(value.Type(), 0, 0))
			}
			return
		}
		for i := range value.Len() {
			computePolicyFillLists(value.Index(i))
		}
	}
}

// document parsed as every device parses it, once it is one the pipeline signs now: not past its not_after, nor past
// the builder's lifetime from now, so no signature carries a policy further than §5.4 lets one go.
func (self *ComputePolicyBuilder) CheckSignable(document []byte) (*ComputePolicy, error) {
	policy, err := parseComputePolicy(document, self.settings.Attest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrComputePolicyBuildRefused, errComputePolicyBuildFormat, err)
	}
	now := self.clock.Now()
	lifetime := self.lifetime()
	if lifetime <= 0 || !now.Before(policy.NotAfter()) || now.Add(lifetime).Before(policy.NotAfter()) {
		return nil, computePolicyBuildError(errComputePolicyBuildNotAfter, "not_after %s is not after now, %s, and within %s of it",
			policy.NotAfter().Format(time.RFC3339), now.UTC().Format(time.RFC3339), lifetime)
	}
	return policy, nil
}

// The certificate line holds, as <key>-cert.pub holds it, once it is one a device takes for this builder's namespace
// now (a user certificate a pinned release key signed, naming the namespace alone, with no critical option, valid now
// and for at most a year) and it stays valid until until, so what it signs verifies for as long as it is meant to be
// used: a device verifies a policy's or a ticket's signature at the instant it takes it. A bare key, a private key's
// file or another namespace's certificate is refused, and with no release key pinned every certificate is.
func (self *ComputePolicyBuilder) Signer(line []byte, until time.Time) (*ssh.Certificate, error) {
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey(line)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, computePolicyBuildError(errComputePolicyBuildSigner, "it is not one OpenSSH public key line")
	}
	certificate, ok := publicKey.(*ssh.Certificate)
	if !ok {
		return nil, computePolicyBuildError(errComputePolicyBuildSigner, "it is a bare key, and only a key the release key certified signs")
	}
	if len(self.verifier.roots) == 0 {
		return nil, fmt.Errorf("%w: %w: %w", ErrComputePolicyBuildRefused, errComputePolicyBuildSigner, errComputePolicyNoRoot)
	}
	now := self.clock.Now()
	if err := self.verifier.checkCertificate(certificate, now); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrComputePolicyBuildRefused, errComputePolicyBuildSigner, err)
	}
	// checkCertificate held the window to a year from a start before now, so valid_before is a unix time
	if untilSeconds := until.Unix(); untilSeconds < 0 || certificate.ValidBefore < uint64(untilSeconds) {
		return nil, computePolicyBuildError(errComputePolicyBuildSigner, "its certificate ends at %s, before %s, so devices would refuse what it signs from then",
			time.Unix(int64(certificate.ValidBefore), 0).UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339))
	}
	return certificate, nil
}

// document under its detached armored signature as a device of this builder's namespace verifies it now, and, where
// certificate is given, signed by that certificate's key and no other, as a sitting checks what its token signed.
func (self *ComputePolicyBuilder) Verify(document []byte, signature []byte, certificate *ssh.Certificate) (*ComputePolicy, error) {
	policy, err := self.verifier.Verify(document, signature, self.clock.Now())
	if err != nil {
		return nil, err
	}
	if certificate != nil {
		if err := computePolicySignedBy(signature, certificate); err != nil {
			return nil, err
		}
	}
	return policy, nil
}

// A ticket file as a device of this builder's namespace verifies it now, and, where certificate is given, signed by
// that certificate's key and no other. Whether it has started is not asked: a ticket host holds unstarted ones.
func (self *ComputePolicyBuilder) VerifyTicket(file []byte, certificate *ssh.Certificate) (*ComputePolicyTicket, error) {
	ticket, err := self.verifier.VerifyTicket(file, self.clock.Now())
	if err != nil {
		return nil, err
	}
	if certificate != nil {
		envelope := &protocol.ComputePolicyTicketFile{}
		if err := proto.Unmarshal(file, envelope); err != nil {
			return nil, computePolicyBuildError(errComputePolicyBuildSigner, "the ticket file does not decode")
		}
		if err := computePolicySignedBy(envelope.GetSignature(), certificate); err != nil {
			return nil, err
		}
	}
	return ticket, nil
}

// Nil when the armored SSHSIG signature carries certificate as its key, byte for byte: a token answering with another
// key, or an agent's other key, never passes for the certificate a sitting named.
func computePolicySignedBy(signature []byte, certificate *ssh.Certificate) error {
	sshsig, err := computeSshsigParse(signature)
	if err != nil {
		return computePolicyBuildError(errComputePolicyBuildSigner, "the signature is not an SSHSIG")
	}
	if !bytes.Equal(sshsig.publicKey.Marshal(), certificate.Marshal()) {
		return computePolicyBuildError(errComputePolicyBuildSigner, "it was signed by another key than the certificate named")
	}
	return nil
}

// What NewComputeTicketBatchBuilder builds on.
type ComputeTicketBatchBuilderArgs struct {
	// Nil takes DefaultComputePolicyBuildSettings: its Attest bounds every batch.
	Settings *ComputePolicyBuildSettings
	// Nil reads real time.
	Clock Clock
	// What each batch's id is drawn from; nil takes crypto/rand.
	Random io.Reader
}

// Builds a sitting's batches of freshness tickets (§5.4).
type ComputeTicketBatchBuilder struct {
	settings *ComputePolicyBuildSettings
	clock    Clock
	random   io.Reader
}

// A batch builder over args.
func NewComputeTicketBatchBuilder(args *ComputeTicketBatchBuilderArgs) *ComputeTicketBatchBuilder {
	if args == nil {
		args = &ComputeTicketBatchBuilderArgs{}
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	return &ComputeTicketBatchBuilder{
		settings: computePolicyBuildSettingsOrDefault(args.Settings),
		clock:    clockOrReal(args.Clock),
		random:   random,
	}
}

// What Build builds a batch on.
type ComputeTicketBatchArgs struct {
	// N, the policy version every ticket of the batch requires: from 1.
	PolicyVersion uint64
	// The sitting: zero takes the builder's clock. Kept to the millisecond, as the tickets keep it.
	SignedAt time.Time
	// The batch's expiry: zero takes SignedAt and TicketBatchMaxLifetime, §5.4's 14 days, which is also the latest.
	Expires time.Time
	// A revocation's batch, whose first ticket starts at the sitting (§5.4), so it binds at once.
	Revocation bool
}

// A sitting's batch as built, before its tickets are signed.
type ComputeTicketBatchBuild struct {
	Batch         ComputePolicyTicketBatch
	PolicyVersion uint64
	Revocation    bool
	// In the order of their starts.
	Tickets []*ComputePolicyTicket
}

// A sitting's batch: one ticket for each UTC day from the day after the sitting until the batch's expiry, each starting
// at 00:00 UTC of its day, or, for a revocation, a first ticket starting at the sitting; each window TicketMaxWindow,
// cut to the expiry. Refuses a batch past TicketBatchMaxLifetime, one expiring by its sitting, and one with no ticket.
func (self *ComputeTicketBatchBuilder) Build(args *ComputeTicketBatchArgs) (*ComputeTicketBatchBuild, error) {
	refuse := func(format string, args ...any) error {
		return computePolicyBuildError(errComputePolicyBuildBatch, format, args...)
	}
	if args == nil || args.PolicyVersion == 0 {
		return nil, refuse("a batch names the policy version its tickets require, from 1")
	}
	attest := self.settings.Attest
	signedAt := args.SignedAt
	if signedAt.IsZero() {
		signedAt = self.clock.Now()
	}
	signedAt = time.UnixMilli(signedAt.UnixMilli()).UTC()
	lifetime := attest.TicketBatchMaxLifetime
	expires := args.Expires
	if expires.IsZero() {
		expires = signedAt.Add(lifetime)
	}
	expires = time.UnixMilli(expires.UnixMilli()).UTC()
	if lifetime <= 0 || !signedAt.Before(expires) || signedAt.Add(lifetime).Before(expires) {
		return nil, refuse("it expires at %s, which is not after its sitting at %s and within %s of it", expires.Format(time.RFC3339),
			signedAt.Format(time.RFC3339), lifetime)
	}
	window := attest.TicketMaxWindow
	if window <= 0 {
		return nil, refuse("the ticket window is not positive")
	}
	idBytes := make([]byte, len(Id{}))
	if _, err := io.ReadFull(self.random, idBytes); err != nil {
		return nil, fmt.Errorf("a batch id: %w", err)
	}
	batchId, err := IdFromBytes(idBytes)
	if err != nil {
		return nil, err
	}
	batch := ComputePolicyTicketBatch{Id: batchId, SignedAt: signedAt, Expires: expires}
	starts := []time.Time{}
	if args.Revocation {
		starts = append(starts, signedAt)
	}
	sittingDay := time.Date(signedAt.Year(), signedAt.Month(), signedAt.Day(), 0, 0, 0, 0, time.UTC)
	for day := sittingDay.AddDate(0, 0, 1); day.Before(expires); day = day.AddDate(0, 0, 1) {
		starts = append(starts, day)
	}
	if len(starts) == 0 {
		return nil, refuse("it holds no ticket: it expires at %s, before the day after its sitting", expires.Format(time.RFC3339))
	}
	build := &ComputeTicketBatchBuild{Batch: batch, PolicyVersion: args.PolicyVersion, Revocation: args.Revocation}
	for _, start := range starts {
		ticket := &ComputePolicyTicket{
			Batch:         batch,
			PolicyVersion: args.PolicyVersion,
			NotBefore:     start,
			NotAfter:      computePolicyMinTime(start.Add(window), expires),
		}
		// the devices' own bounds, so a batch built here is one every device takes
		if err := ticket.withinBounds(attest); err != nil {
			return nil, refuse("a ticket from %s: %s", start.Format(time.RFC3339), err)
		}
		build.Tickets = append(build.Tickets, ticket)
	}
	return build, nil
}

// Each ticket's file, <day>.bin's bytes, in the order of Tickets, its bytes signed through sign, which answers an
// armored SSHSIG over the bytes it is given: a holder's ssh-keygen -Y sign on their token, or a test's software key.
// Nothing is checked here; the builder's VerifyTicket checks each file as a device would.
func (self *ComputeTicketBatchBuild) Sign(sign func(message []byte) ([]byte, error)) ([][]byte, error) {
	files := [][]byte{}
	for _, ticket := range self.Tickets {
		message, err := ticket.Marshal()
		if err != nil {
			return nil, err
		}
		signature, err := sign(message)
		if err != nil {
			return nil, fmt.Errorf("the ticket from %s: %w", ticket.NotBefore.Format(time.RFC3339), err)
		}
		file, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ComputePolicyTicketFile{
			Ticket:    message,
			Signature: signature,
		})
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

// Whether the batch is newer than other: a later sitting, or the same sitting's greater id. The ticket host releases
// from the newest batch alone and deletes what any older one holds unreleased (§5.4).
func (self ComputePolicyTicketBatch) NewerThan(other ComputePolicyTicketBatch) bool {
	if !self.SignedAt.Equal(other.SignedAt) {
		return self.SignedAt.After(other.SignedAt)
	}
	return 0 < bytes.Compare(self.Id.Bytes(), other.Id.Bytes())
}

// How long the newest policy and the newest batch carry remote work, judged at one instant (§5.4, §14.7): the
// policy's not_after, past which a device refuses remote work, and the newest batch's expiry, past which no ticket
// signed carries any. Status prints both, and CSRV's monitor pages at 14 and 7 days from the gauges the broker
// publishes from them.
type ComputePolicyHorizon struct {
	// The instant judged at.
	At time.Time
	// The newest policy, or nil where none was given.
	Policy *ComputePolicy
	// The newest batch's latest ticket, whose batch's expiry is the horizon, or nil where none was given.
	Ticket *ComputePolicyTicket
}

// The horizon at at, of policy and of the newest batch among tickets.
func NewComputePolicyHorizon(at time.Time, policy *ComputePolicy, tickets []*ComputePolicyTicket) *ComputePolicyHorizon {
	var newest *ComputePolicyTicket
	for _, ticket := range tickets {
		if ticket == nil {
			continue
		}
		if newest == nil || ticket.Batch.NewerThan(newest.Batch) ||
			(ticket.Batch.Id == newest.Batch.Id && ticket.NotBefore.After(newest.NotBefore)) {
			newest = ticket
		}
	}
	return &ComputePolicyHorizon{At: at, Policy: policy, Ticket: newest}
}

// Until the newest policy's not_after: negative once it has passed, zero with no policy.
func (self *ComputePolicyHorizon) PolicyLeft() time.Duration {
	if self.Policy == nil {
		return 0
	}
	return self.Policy.NotAfter().Sub(self.At)
}

// The newest batch's expiry, zero with no ticket.
func (self *ComputePolicyHorizon) TicketHorizon() time.Time {
	if self.Ticket == nil {
		return time.Time{}
	}
	return self.Ticket.Batch.Expires
}

// Until the newest batch's expiry: negative once it has passed, zero with no ticket.
func (self *ComputePolicyHorizon) TicketLeft() time.Duration {
	if self.Ticket == nil {
		return 0
	}
	return self.Ticket.Batch.Expires.Sub(self.At)
}

// Whether the newest policy is within settings' warning of its not_after, or past it, or there is none: §14.7's page.
func (self *ComputePolicyHorizon) PolicyExpiring(settings *ComputePolicyBuildSettings) bool {
	settings = computePolicyBuildSettingsOrDefault(settings)
	left := self.PolicyLeft()
	return self.Policy == nil || left <= 0 || left < settings.PolicyExpiryWarning
}

// Whether the newest batch is within settings' warning of its expiry, or past it, or there is none: §14.7's page.
func (self *ComputePolicyHorizon) TicketHorizonNear(settings *ComputePolicyBuildSettings) bool {
	settings = computePolicyBuildSettingsOrDefault(settings)
	left := self.TicketLeft()
	return self.Ticket == nil || left <= 0 || left < settings.TicketHorizonWarning
}

// The serving path's layout under its base (§5.4's Distribution, QD-1379), which the fetcher reads and the pipeline's
// publish and the ticket host's release write: identifiers of the layout, not limits.
const (
	// The directory a day's ticket is served from.
	ComputePolicyTicketDirectory = "tickets"
	// A policy file's suffix, after its version.
	computePolicyFileSuffix = ".json"
	// A detached signature's suffix, after the file it signs.
	computePolicySignatureSuffix = ".sig"
	// A ticket file's suffix, after its day.
	computePolicyTicketFileSuffix = ".bin"
)

// <version>.json, the policy of that version.
func ComputePolicyFileName(version uint64) string {
	return strconv.FormatUint(version, 10) + computePolicyFileSuffix
}

// <version>.json.sig, its detached SSHSIG.
func ComputePolicySignatureFileName(version uint64) string {
	return ComputePolicyFileName(version) + computePolicySignatureSuffix
}

// The version a policy file's name gives, a decimal from 1 with no leading zero, and whether name is one.
func ParseComputePolicyFileName(name string) (uint64, bool) {
	digits, ok := strings.CutSuffix(name, computePolicyFileSuffix)
	if !ok || digits == "" || digits[0] == '0' || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	version, err := strconv.ParseUint(digits, 10, 64)
	return version, err == nil
}

// tickets/<yyyy-mm-dd>.bin, the ticket the ticket host released for the UTC day day falls on.
func ComputePolicyTicketFileName(day time.Time) string {
	return path.Join(ComputePolicyTicketDirectory, ComputePolicyTicketDayFileName(day))
}

// <yyyy-mm-dd>.bin, a day's ticket file's own name, in the serving path's tickets directory and the ticket host's
// store alike.
func ComputePolicyTicketDayFileName(day time.Time) string {
	return day.UTC().Format(computePolicyTicketDayLayout) + computePolicyTicketFileSuffix
}

// The release's copy's names in attest_policy_release/ (§5.4's Distribution): a production build embeds the
// production policy's, a staging or CI build the staging policy's (attest_policy_pin.go, attest_policy_pin_staging.go).
const (
	computePolicyProductionCopyName = "compute-policy.json"
	computePolicyStagingCopyName    = "compute-policy-staging.json"
)

// The release's copy's document and signature names for a production policy, or with staging the staging policy's,
// which publish writes into attest_policy_release/ before a release.
func ComputePolicyReleaseCopyNames(staging bool) (document string, signature string) {
	if staging {
		return computePolicyStagingCopyName, computePolicyStagingCopyName + computePolicySignatureSuffix
	}
	return computePolicyProductionCopyName, computePolicyProductionCopyName + computePolicySignatureSuffix
}
