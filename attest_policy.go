//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §5.4's compute policy, compute-policy.json: one JSON document that says which vendor roots, TCB
// levels and measurement profiles pass, which providers and models a device may reach and how, the disclosure texts
// every surface renders, the connected services and web search's pins, and what is revoked (R-ATTEST-3, D-ATTEST-2,
// D-ATTEST-7). A device takes it only once ComputePolicyVerifier has verified its signature (attest_policy_verify.go)
// and parsed it here, strictly:
//
//   - exactly one JSON object in valid UTF-8, nothing after it;
//   - every member name exactly one this file declares at its place, matched by its bytes, none twice in an object,
//     and no null anywhere a value is declared; the search, services and support lines are kept as the raw JSON they
//     were, byte for byte inside the verified bytes, for SRCH, CONN and the support client to decode strictly (§21.5,
//     §25.4, §28.10), and are held here only to the same names-once, depth, size and count rules;
//   - integers written as integers, within their type; the depth, each object's and array's count, each string's
//     length and the whole document's size bounded by AttestSettings, which the pipeline that builds a policy reads
//     too (ATTEST-M12-02);
//   - then each line's own rules (ComputePolicy.check): known words where §5.3 and §5.4 name them, hashes in
//     lowercase hex of their sizes, ids unique where a reader looks them up, English first in every disclosure.
//
// The format is the plan's reading of §5.4's list, which names its lines and their contents but no member names:
// instants are integer unix milliseconds in _ms members, as compute-plan-disclosure-grace-start's since_ms (QD-1242)
// names them; hashes and measurements are lowercase hex; a line §5.4 keys "per" something is an array of objects
// carrying that key, so every member name is one this file declares. limited_use sits under direct, as §5.4 places it,
// and lists every provider's models, TEE providers' with direct ones' (the plan's reading). Nothing here is
// unknown-tolerant: a policy with a member this build does not know is refused whole, so a format change is a new
// build before it is a new policy.
//
// Devices render only text from the newest verified policy, never an event's, a tool's or a server's (D-ATTEST-7), so
// the disclosure texts here are the only source CTRUST's registry reads.
//
// A ComputePolicy is immutable once parsed: every reader shares one, and none may change it. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// What a refused policy or ticket wraps: a signature, certificate, namespace, root or format this build does not take.
// Each refusal also wraps the reason's own error, and its message names the reason, never the bytes.
var ErrComputePolicyRefused = errors.New("compute policy refused")

// A document that is not a policy of this format: errors.Is with ErrComputePolicyRefused too.
var errComputePolicyFormat = errors.New("not a compute policy of this format")

// §5.3's and §5.4's words, identifiers.
const (
	// CPU types.
	ComputePolicyCpuTdx = "tdx"
	ComputePolicyCpuSnp = "snp"
	// Binding schemes (§5.5).
	ComputePolicySchemeChutesE2e       = "chutes-e2e-v1"
	ComputePolicySchemeEnclave         = "ur-enclave-v1"
	ComputePolicySchemeEnclaveSession  = "ur-enclave-session-v1"
	ComputePolicySchemeEnclaveSshSetup = "ur-enclave-ssh-setup-v1"
	// A profile's review (§5.4's Review).
	ComputePolicyReviewReproduced = "reproduced"
	ComputePolicyReviewListed     = "listed"
	// TDX TCB statuses a policy may allow (§5.3): never OutOfDate, Revoked or ConfigurationNeeded.
	ComputePolicyTdxUpToDate          = "UpToDate"
	ComputePolicyTdxSwHardeningNeeded = "SWHardeningNeeded"
	// AMD's ARK families (§5.4's Milan, Genoa, Turin): EPYC 7003; 8004 and 9004; 8005 and 9005 (§5.3).
	ComputePolicyAmdMilan = "milan"
	ComputePolicyAmdGenoa = "genoa"
	ComputePolicyAmdTurin = "turin"
	// Collateral vendors (§5.7).
	ComputePolicyVendorIntel  = "intel"
	ComputePolicyVendorAmd    = "amd"
	ComputePolicyVendorNvidia = "nvidia"
	// Chip identities a custody registry vouches for or a revocation names (§2.6, §5.4).
	ComputePolicyChipIntelPpid = "intel_ppid"
	ComputePolicyChipAmdChipId = "amd_chip_id"
	// Methods a direct provider may be called with (§6.6).
	computePolicyMethodGet  = "GET"
	computePolicyMethodPost = "POST"
)

// The words each place takes.
var (
	computePolicyCpus           = []string{ComputePolicyCpuTdx, ComputePolicyCpuSnp}
	computePolicySchemes        = []string{ComputePolicySchemeChutesE2e, ComputePolicySchemeEnclave, ComputePolicySchemeEnclaveSession, ComputePolicySchemeEnclaveSshSetup}
	computePolicyReviews        = []string{ComputePolicyReviewReproduced, ComputePolicyReviewListed}
	computePolicyTdxStatuses    = []string{ComputePolicyTdxUpToDate, ComputePolicyTdxSwHardeningNeeded}
	computePolicyAmdFamilies    = []string{ComputePolicyAmdMilan, ComputePolicyAmdGenoa, ComputePolicyAmdTurin}
	computePolicyVendors        = []string{ComputePolicyVendorIntel, ComputePolicyVendorAmd, ComputePolicyVendorNvidia}
	computePolicyChipKinds      = []string{ComputePolicyChipIntelPpid, ComputePolicyChipAmdChipId}
	computePolicyMethods        = []string{computePolicyMethodGet, computePolicyMethodPost}
	computePolicyProviderLabels = []ComputeLabel{ComputeLabelA1, ComputeLabelAp}
)

// The patterns of §5.4's identifiers: a disclosure id, family:slug (§2.8's families, which CTRUST's registry holds to
// its list); a locale, a BCP 47 tag of letters, digits and hyphens; a register a profile replays, an RTMR or a vTPM
// PCR; an advisory, a vendor's id such as INTEL-SA-00837; a host, lowercase DNS labels.
var (
	computePolicyDisclosureIdPattern = regexp.MustCompile(`^[a-z]+:[a-z0-9]+(-[a-z0-9]+)*$`)
	computePolicyLocalePattern       = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)
	computePolicyRegisterPattern     = regexp.MustCompile(`^(rtmr[0-3]|pcr([0-9]|1[0-9]|2[0-3]))$`)
	computePolicyWordPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]*$`)
	computePolicyHostPattern         = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$`)
	computePolicyPathPattern         = regexp.MustCompile(`^/[A-Za-z0-9._~/{}-]*$`)
)

// §5.4's policy, as verified. The JSON names are the format's; Document and Signature give the verified bytes.
type ComputePolicy struct {
	// A counter: a device takes only a higher one, and never one older than its release's copy.
	Version uint64 `json:"version"`
	// 90 days after signing (§5.4). A policy past it stays the newest but answers not current, and the gate refuses
	// remote work under it (ATTEST-M12-01).
	NotAfterMs int64 `json:"not_after_ms"`
	// The vendor roots evidence chains to, by SHA-256 of the certificate.
	Roots ComputePolicyRoots `json:"roots"`
	// What firmware and TCB levels pass, and how old collateral may be.
	Tcb ComputePolicyTcb `json:"tcb"`
	// The TEE providers: their CPU types, schemes, labels, roots, model ids and measurement profiles.
	Providers []*ComputePolicyProvider `json:"providers"`
	// The providers without a TEE, labeled none, and the limited_use list.
	Direct ComputePolicyDirectLine `json:"direct"`
	// Web search's pins (§21.5), as the raw JSON the document holds, which SRCH decodes strictly; nil where the
	// policy carries no search line, as before its gate passes.
	Search json.RawMessage `json:"search,omitempty"`
	// Every disclosure's versioned text (§2.8, D-ATTEST-7).
	Disclosures []*ComputePolicyDisclosure `json:"disclosures"`
	// The services a connection may reach (§25.4), as the raw JSON the document holds, which CONN decodes strictly;
	// nil where the policy carries none.
	Services json.RawMessage `json:"services,omitempty"`
	// The support line (§5.4, §28.10): the feedback service's host, the one place a device posts to support, and each
	// subprocessor support:urnetwork names, as the raw JSON the document holds, which ParseSupportPolicyLine decodes
	// strictly (support_sources.go); nil where the policy carries none, and then no message is posted. A device posts
	// to the newest policy's host whatever that policy's not_after (ComputePolicyStore.SupportLine).
	Support json.RawMessage `json:"support,omitempty"`
	// Per provider, chip identities a custody registry vouches for: a match labels the instance A2.
	Custody []*ComputePolicyCustody `json:"custody"`
	// Refused whatever else passes.
	Revoked ComputePolicyRevoked `json:"revoked"`

	// The bytes the signature covers, exactly as verified.
	document []byte
	// The armored SSHSIG over them.
	signature []byte
	// The certified key that signed.
	signer ComputePolicySigner
}

// The vendor roots §5.4 pins, each by the lowercase hex SHA-256 of its certificate. A list per root so a vendor's
// rollover can carry both.
type ComputePolicyRoots struct {
	// Intel's SGX root, which TDX quotes chain to.
	IntelSgx []string `json:"intel_sgx"`
	// AMD's ARKs, one per family.
	AmdArks []*ComputePolicyAmdArk `json:"amd_arks"`
	// NVIDIA's device root, which GPU certificates chain to.
	NvidiaDevice []string `json:"nvidia_device"`
	// The root NRAS tokens chain to (§5.3's GPU verifier).
	NvidiaNras []string `json:"nvidia_nras"`
}

// One AMD ARK.
type ComputePolicyAmdArk struct {
	// milan, genoa or turin.
	Family string `json:"family"`
	Sha256 string `json:"sha256"`
}

// §5.4's tcb line.
type ComputePolicyTcb struct {
	Tdx ComputePolicyTdxTcb `json:"tdx"`
	Snp ComputePolicySnpTcb `json:"snp"`
	// Per vendor, the oldest collateral and revocation lists a device takes (§5.7, D-ATTEST-10).
	MaxAges []*ComputePolicyMaxAge `json:"max_ages"`
}

// TDX's TCB rules (§5.3).
type ComputePolicyTdxTcb struct {
	// The statuses that pass: UpToDate, and SWHardeningNeeded only where Advisories names each advisory.
	Statuses []string `json:"statuses"`
	// The advisories SWHardeningNeeded may name and still pass.
	Advisories []string `json:"advisories"`
	// The least TCB evaluation data number collateral may carry.
	MinTcbEvaluationDataNumber uint32 `json:"min_tcb_evaluation_data_number"`
}

// SEV-SNP's TCB rules (§5.3).
type ComputePolicySnpTcb struct {
	// The least firmware per family.
	MinFirmware []*ComputePolicySnpFirmware `json:"min_firmware"`
	// Guest policy bits that must be set, and bits that must be clear (DEBUG, MIGRATE_MA). No bit in both.
	PolicyBitsSet   uint64 `json:"policy_bits_set"`
	PolicyBitsClear uint64 `json:"policy_bits_clear"`
}

// One family's least SNP firmware.
type ComputePolicySnpFirmware struct {
	// milan, genoa or turin.
	Family string `json:"family"`
	// The firmware's build number, such as 0x1F: 0 to 255.
	Build uint32 `json:"build"`
}

// One vendor's maximum ages.
type ComputePolicyMaxAge struct {
	// intel, amd or nvidia.
	Vendor string `json:"vendor"`
	// The oldest collateral taken, in days: 7 where the vendor re-signs at least weekly.
	CollateralDays uint32 `json:"collateral_days"`
	// The oldest revocation list taken, in days.
	RevocationDays uint32 `json:"revocation_days"`
}

// One TEE provider (§5.4's providers line).
type ComputePolicyProvider struct {
	// The provider's slug, as canonical model names carry it (§6.3).
	Id string `json:"id"`
	// tdx, snp or both.
	Cpus []string `json:"cpus"`
	// The binding schemes its evidence uses (§5.5).
	Schemes []string `json:"schemes"`
	// A1 or AP; A2 comes only from custody.
	Label ComputeLabel `json:"label"`
	// The provider's own roots, such as Chutes' VM root CA.
	Roots []*ComputePolicyProviderRoot `json:"roots"`
	// Each catalog model's provider id (Chutes: its chute_id).
	Models []*ComputePolicyModel `json:"models"`
	// The measurement profiles its evidence must match one of.
	Profiles []*ComputePolicyProfile `json:"profiles"`
}

// A provider's own root.
type ComputePolicyProviderRoot struct {
	// Its name, such as sek8s-vm-root-ca.
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// One catalog model of a TEE provider.
type ComputePolicyModel struct {
	// The model part of its canonical names, <provider>-<model>-<effort> (§6.3).
	Model string `json:"model"`
	// The id the provider knows it by, which AttestationResult.provider_model_id records.
	ProviderModelId string `json:"provider_model_id"`
}

// One measurement profile (§5.4): the TD's registers or the SNP measurement a provider's image yields, reviewed before
// it was added.
type ComputePolicyProfile struct {
	// Unique in the policy, which revoked.profiles names and AttestationResult.profile_id records.
	Id string `json:"id"`
	// The guest image's version.
	GuestVersion string `json:"guest_version"`
	// tdx or snp, one of its provider's.
	Cpu string `json:"cpu"`
	// TDX: MRTD and RTMR0-3, 48 bytes each in hex; RTMR3 may be empty where Replayed names it.
	Mrtd  string `json:"mrtd"`
	Rtmr0 string `json:"rtmr0"`
	Rtmr1 string `json:"rtmr1"`
	Rtmr2 string `json:"rtmr2"`
	Rtmr3 string `json:"rtmr3"`
	// TDX: the XFAM the profile expects, 8 bytes in hex, or empty for any (§5.3).
	Xfam string `json:"xfam"`
	// SNP: MEASUREMENT, 48 bytes in hex.
	Measurement string `json:"measurement"`
	// SNP: whether SINGLE_SOCKET must be set.
	SingleSocket bool `json:"single_socket"`
	// The GPU model and count every instance has, or empty and 0 for a CPU profile.
	GpuModel string `json:"gpu_model"`
	GpuCount uint32 `json:"gpu_count"`
	// For an enclave image, the payload root hash B must carry (§11.7's step 6), 32 bytes in hex; else empty.
	PayloadRootSha256 string `json:"payload_root_sha256"`
	// When the profile stops passing.
	ExpiresMs int64 `json:"expires_ms"`
	// Registers replayed from an event log, each with its expected events in order, the last SHA-256(B) (§11.7).
	Replayed []*ComputePolicyReplayed `json:"replayed"`
	// reproduced or listed (§5.4's Review).
	Review string `json:"review"`
	// For listed, the SHA-256 of the provider's list it was taken from; empty for reproduced.
	ReviewListSha256 string `json:"review_list_sha256"`
}

// A register a profile replays.
type ComputePolicyReplayed struct {
	// rtmr0 to rtmr3, or a vTPM's pcr0 to pcr23.
	Register string `json:"register"`
	// Each event's digest, 32 to 64 bytes in hex, in order.
	Events []string `json:"events"`
}

// §5.4's direct line: the providers without a TEE, and every limited_use model.
type ComputePolicyDirectLine struct {
	Providers []*ComputePolicyDirect `json:"providers"`
	// Canonical model names without their effort, <provider>-<model>, a TEE provider's or a direct one's, whose
	// provider's written terms bar training, keeping and reading (§5.4, §25.10).
	LimitedUse []string `json:"limited_use"`
}

// One provider without a TEE, labeled none (§5.4, §6.6): a device calls no host, and the broker signs for no receiver
// or target, that this does not list.
type ComputePolicyDirect struct {
	// The provider's slug.
	Slug string `json:"slug"`
	// Its API host.
	ApiHost string `json:"api_host"`
	// Its btauth/1 receiver hotkey.
	ReceiverHotkey string `json:"receiver_hotkey"`
	// Its gamma netuid.
	Netuid uint32 `json:"netuid"`
	// The methods and paths it may be called on.
	Targets []*ComputePolicyDirectTarget `json:"targets"`
	// Each model it may serve.
	Models []*ComputePolicyDirectModel `json:"models"`
}

// One method and path a direct provider may be called on.
type ComputePolicyDirectTarget struct {
	// GET or POST.
	Method string `json:"method"`
	// An absolute path, no query.
	Path string `json:"path"`
}

// One model a direct provider may serve: its provider id, retention rule and route come from here alone, and the
// unsigned catalog adds only prices and capacity (§5.4).
type ComputePolicyDirectModel struct {
	// The model part of its canonical names.
	Model string `json:"model"`
	// The id the provider knows it by.
	ProviderModelId string `json:"provider_model_id"`
	// The aliases its gate recorded.
	Aliases []string `json:"aliases"`
	// Whether zero retention is required, as engy's provider.zdr (Q-PROV-6).
	ZeroRetention bool `json:"zero_retention"`
	// For a provider that routes to upstreams, such as SayGM, the upstreams allowed; empty for one that does not.
	Upstreams []string `json:"upstreams"`
}

// One disclosure's text (§2.8, D-ATTEST-7): its version, raised only when a fact changes; its revision, raised at any
// other change of its words; its grace; and per locale its summary and lists.
type ComputePolicyDisclosure struct {
	// family:slug, such as inference:local or search:parallel.
	Id string `json:"id"`
	// From 1, raised only when a fact changes.
	Version uint32 `json:"version"`
	// Raised at any other change of its words; 0 is the version's first wording.
	Revision uint32 `json:"revision"`
	// How long the previous version's acknowledgment counts on, in days: 14, or 0 where the change widens who reads
	// or keeps what is sent (§2.8).
	GraceDays uint32 `json:"grace_days"`
	// When this version took effect, the instant its grace runs from (compute-plan-disclosure-grace-start, QD-1242).
	SinceMs int64 `json:"since_ms"`
	// English first, then any translations.
	Locales []*ComputePolicyDisclosureText `json:"locales"`
}

// A disclosure in one locale.
type ComputePolicyDisclosureText struct {
	// A BCP 47 tag; en first.
	Locale string `json:"locale"`
	// One line every card shows.
	Summary string `json:"summary"`
	// "Could be exposed", each item a few plain sentences, rendered in this order.
	Exposed []string `json:"exposed"`
	// "Private", rendered after Exposed.
	Private []string `json:"private"`
}

// One provider's custody registry (§2.6): a chip identity it lists labels an instance A2.
type ComputePolicyCustody struct {
	// A TEE provider's id.
	Provider string `json:"provider"`
	// The registry that vouches.
	Registry string               `json:"registry"`
	Chips    []*ComputePolicyChip `json:"chips"`
}

// A chip identity.
type ComputePolicyChip struct {
	// intel_ppid or amd_chip_id.
	Kind string `json:"kind"`
	// The identity in lowercase hex.
	Id string `json:"id"`
}

// What is refused whatever else passes.
type ComputePolicyRevoked struct {
	// Profile ids, which need not still be listed.
	Profiles   []string             `json:"profiles"`
	Chips      []*ComputePolicyChip `json:"chips"`
	GpuSerials []string             `json:"gpu_serials"`
}

// The certified key a policy or ticket was signed by, for status and logs: the release key certified it.
type ComputePolicySigner struct {
	// The certificate's key id, as the ceremony named it.
	KeyId string
	// The certificate's serial.
	Serial uint64
	// SHA256:<base64> of the certified key, as ssh-keygen -l prints it.
	Fingerprint string
	// The namespace it signed under.
	Namespace string
}

// The bytes the signature covers, a copy.
func (self *ComputePolicy) Document() []byte {
	return bytes.Clone(self.document)
}

// The armored signature, a copy.
func (self *ComputePolicy) Signature() []byte {
	return bytes.Clone(self.signature)
}

// Who signed.
func (self *ComputePolicy) Signer() ComputePolicySigner {
	return self.signer
}

// The instant the policy stops being current.
func (self *ComputePolicy) NotAfter() time.Time {
	return time.UnixMilli(self.NotAfterMs).UTC()
}

// Whether the policy's own not_after is still ahead of now. A staging build cuts it further (the gate's
// PolicyCurrent); this is the document's word alone.
func (self *ComputePolicy) Current(now time.Time) bool {
	return now.Before(self.NotAfter())
}

// The TEE provider of id, or nil.
func (self *ComputePolicy) Provider(id string) *ComputePolicyProvider {
	for _, provider := range self.Providers {
		if provider.Id == id {
			return provider
		}
	}
	return nil
}

// The direct provider of slug, or nil.
func (self *ComputePolicy) DirectProvider(slug string) *ComputePolicyDirect {
	for _, provider := range self.Direct.Providers {
		if provider.Slug == slug {
			return provider
		}
	}
	return nil
}

// The disclosure of id, or nil.
func (self *ComputePolicy) Disclosure(id string) *ComputePolicyDisclosure {
	for _, disclosure := range self.Disclosures {
		if disclosure.Id == id {
			return disclosure
		}
	}
	return nil
}

// Whether the model provider-model is on the limited_use list.
func (self *ComputePolicy) LimitedUse(provider string, model string) bool {
	return slices.Contains(self.Direct.LimitedUse, provider+"-"+model)
}

// Whether a revocation names the profile.
func (self *ComputePolicy) ProfileRevoked(profileId string) bool {
	return slices.Contains(self.Revoked.Profiles, profileId)
}

// Whether a revocation names the chip.
func (self *ComputePolicy) ChipRevoked(kind string, id string) bool {
	return slices.ContainsFunc(self.Revoked.Chips, func(chip *ComputePolicyChip) bool {
		return chip.Kind == kind && chip.Id == id
	})
}

// Whether a revocation names the GPU serial.
func (self *ComputePolicy) GpuSerialRevoked(serial string) bool {
	return slices.Contains(self.Revoked.GpuSerials, serial)
}

// The profile of id under this provider, or nil.
func (self *ComputePolicyProvider) Profile(id string) *ComputePolicyProfile {
	for _, profile := range self.Profiles {
		if profile.Id == id {
			return profile
		}
	}
	return nil
}

// The provider id the policy pins for model, or empty where it lists none.
func (self *ComputePolicyProvider) ProviderModelId(model string) string {
	for _, entry := range self.Models {
		if entry.Model == model {
			return entry.ProviderModelId
		}
	}
	return ""
}

// The direct model whose model part is model, or nil.
func (self *ComputePolicyDirect) Model(model string) *ComputePolicyDirectModel {
	for _, entry := range self.Models {
		if entry.Model == model {
			return entry
		}
	}
	return nil
}

// The text in exactly locale, or nil. CTRUST's registry picks the person's locale, then its language, then English.
func (self *ComputePolicyDisclosure) Text(locale string) *ComputePolicyDisclosureText {
	for _, text := range self.Locales {
		if text.Locale == locale {
			return text
		}
	}
	return nil
}

// The English text, which every entry carries first.
func (self *ComputePolicyDisclosure) English() *ComputePolicyDisclosureText {
	return self.Text(computePolicyEnglish)
}

// The locale every disclosure carries first (§2.8: English the reference).
const computePolicyEnglish = "en"

// Parses document strictly as this format's policy, without its signature: the verifier calls it only on bytes whose
// signature it verified. The error wraps ErrComputePolicyRefused and errComputePolicyFormat and never repeats the
// document.
func parseComputePolicy(document []byte, settings *AttestSettings) (*ComputePolicy, error) {
	if settings.PolicyMaxByteCount < len(document) {
		return nil, computePolicyFormatError("larger than %d bytes", settings.PolicyMaxByteCount)
	}
	if err := computePolicyJsonStrict(document, reflect.TypeFor[ComputePolicy](), settings); err != nil {
		return nil, err
	}
	policy := &ComputePolicy{}
	if err := json.Unmarshal(document, policy); err != nil {
		return nil, computePolicyFormatError("does not decode")
	}
	if err := policy.check(settings); err != nil {
		return nil, err
	}
	policy.document = bytes.Clone(document)
	return policy, nil
}

// A format refusal: what was wrong, never a value.
func computePolicyFormatError(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrComputePolicyRefused, errComputePolicyFormat, fmt.Sprintf(format, args...))
}

// The strict walk, over a json.Decoder's tokens and the type the bytes decode into, in step.
type computePolicyJsonWalk struct {
	decoder  *json.Decoder
	settings *AttestSettings
}

// Holds document to this file's rules for target before json.Unmarshal reads it: one value of target's shape, every
// member name exactly one target declares, none twice, no null, integers as integers in range, and every bound.
func computePolicyJsonStrict(document []byte, target reflect.Type, settings *AttestSettings) error {
	if !utf8.Valid(document) {
		return computePolicyFormatError("not utf-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	walk := &computePolicyJsonWalk{decoder: decoder, settings: settings}
	if err := walk.value(target, "", 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return computePolicyFormatError("bytes after the document")
	}
	return nil
}

// The type json.RawMessage, which the walk holds only to the generic rules.
var computePolicyRawType = reflect.TypeFor[json.RawMessage]()

// The next value, which must have target's shape, at path for messages.
func (self *computePolicyJsonWalk) value(target reflect.Type, path string, depth int) error {
	if self.settings.PolicyMaxDepth < depth {
		return computePolicyFormatError("%s nests deeper than %d", computePolicyPathName(path), self.settings.PolicyMaxDepth)
	}
	if target == computePolicyRawType {
		return self.raw(path, depth, true)
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	token, err := self.decoder.Token()
	if err != nil {
		return computePolicyFormatError("%s is not json", computePolicyPathName(path))
	}
	switch target.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return computePolicyFormatError("%s is not an object", computePolicyPathName(path))
		}
		return self.object(target, path, depth)
	case reflect.Slice:
		if token != json.Delim('[') {
			return computePolicyFormatError("%s is not an array", computePolicyPathName(path))
		}
		for count := 0; self.decoder.More(); count += 1 {
			if self.settings.PolicyMaxListCount <= count {
				return computePolicyFormatError("%s holds more than %d entries", computePolicyPathName(path), self.settings.PolicyMaxListCount)
			}
			if err := self.value(target.Elem(), path+"[]", depth+1); err != nil {
				return err
			}
		}
		if _, err := self.decoder.Token(); err != nil {
			return computePolicyFormatError("%s is not json", computePolicyPathName(path))
		}
		return nil
	case reflect.String:
		text, ok := token.(string)
		if !ok {
			return computePolicyFormatError("%s is not a string", computePolicyPathName(path))
		}
		if self.settings.PolicyMaxStringByteCount < len(text) {
			return computePolicyFormatError("%s is longer than %d bytes", computePolicyPathName(path), self.settings.PolicyMaxStringByteCount)
		}
		return nil
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return computePolicyFormatError("%s is not a boolean", computePolicyPathName(path))
		}
		return nil
	case reflect.Int64, reflect.Int32, reflect.Uint64, reflect.Uint32:
		number, ok := token.(json.Number)
		if !ok || !computePolicyIntegerText(string(number)) {
			return computePolicyFormatError("%s is not an integer", computePolicyPathName(path))
		}
		var parseErr error
		switch target.Kind() {
		case reflect.Int64, reflect.Int32:
			_, parseErr = strconv.ParseInt(string(number), 10, target.Bits())
		default:
			_, parseErr = strconv.ParseUint(string(number), 10, target.Bits())
		}
		if parseErr != nil {
			return computePolicyFormatError("%s is out of range", computePolicyPathName(path))
		}
		return nil
	}
	return computePolicyFormatError("%s has a type this format does not read", computePolicyPathName(path))
}

// An object whose '{' was read, whose members must be target's declared names, each once.
func (self *computePolicyJsonWalk) object(target reflect.Type, path string, depth int) error {
	fieldTypes := map[string]reflect.Type{}
	for i := range target.NumField() {
		field := target.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !field.IsExported() || name == "" || name == "-" {
			continue
		}
		fieldTypes[name] = field.Type
	}
	seen := map[string]bool{}
	for self.decoder.More() {
		token, err := self.decoder.Token()
		if err != nil {
			return computePolicyFormatError("%s is not json", computePolicyPathName(path))
		}
		name, ok := token.(string)
		if !ok {
			return computePolicyFormatError("%s has a member name that is not a string", computePolicyPathName(path))
		}
		fieldType, known := fieldTypes[name]
		if !known {
			return computePolicyFormatError("%s has a member this format does not know", computePolicyPathName(path))
		}
		if seen[name] {
			return computePolicyFormatError("%s.%s is written twice", computePolicyPathName(path), name)
		}
		seen[name] = true
		if err := self.value(fieldType, path+"."+name, depth+1); err != nil {
			return err
		}
	}
	if _, err := self.decoder.Token(); err != nil {
		return computePolicyFormatError("%s is not json", computePolicyPathName(path))
	}
	return nil
}

// Any JSON value, for a raw line: names once in each object, no null at the line's top, and the bounds.
func (self *computePolicyJsonWalk) raw(path string, depth int, top bool) error {
	if self.settings.PolicyMaxDepth < depth {
		return computePolicyFormatError("%s nests deeper than %d", computePolicyPathName(path), self.settings.PolicyMaxDepth)
	}
	token, err := self.decoder.Token()
	if err != nil {
		return computePolicyFormatError("%s is not json", computePolicyPathName(path))
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]bool{}
			for count := 0; self.decoder.More(); count += 1 {
				if self.settings.PolicyMaxListCount <= count {
					return computePolicyFormatError("%s holds more than %d members", computePolicyPathName(path), self.settings.PolicyMaxListCount)
				}
				nameToken, err := self.decoder.Token()
				if err != nil {
					return computePolicyFormatError("%s is not json", computePolicyPathName(path))
				}
				name, ok := nameToken.(string)
				if !ok || self.settings.PolicyMaxStringByteCount < len(name) {
					return computePolicyFormatError("%s has a member name past the bounds", computePolicyPathName(path))
				}
				if seen[name] {
					return computePolicyFormatError("%s has a member written twice", computePolicyPathName(path))
				}
				seen[name] = true
				if err := self.raw(path+"{}", depth+1, false); err != nil {
					return err
				}
			}
		case '[':
			for count := 0; self.decoder.More(); count += 1 {
				if self.settings.PolicyMaxListCount <= count {
					return computePolicyFormatError("%s holds more than %d entries", computePolicyPathName(path), self.settings.PolicyMaxListCount)
				}
				if err := self.raw(path+"[]", depth+1, false); err != nil {
					return err
				}
			}
		default:
			return computePolicyFormatError("%s is not json", computePolicyPathName(path))
		}
		if _, err := self.decoder.Token(); err != nil {
			return computePolicyFormatError("%s is not json", computePolicyPathName(path))
		}
	case string:
		if self.settings.PolicyMaxStringByteCount < len(value) {
			return computePolicyFormatError("%s holds a string longer than %d bytes", computePolicyPathName(path), self.settings.PolicyMaxStringByteCount)
		}
	case nil:
		if top {
			return computePolicyFormatError("%s is null", computePolicyPathName(path))
		}
	}
	return nil
}

// A path for a message, the document itself named as such.
func computePolicyPathName(path string) string {
	if path == "" {
		return "the document"
	}
	return strings.TrimPrefix(path, ".")
}

// Whether text is an integer as this format writes one: no sign but a leading minus, no leading zero, no fraction or
// exponent.
func computePolicyIntegerText(text string) bool {
	digits := strings.TrimPrefix(text, "-")
	if digits == "" || (len(digits) > 1 && digits[0] == '0') || (digits == "0" && text != "0") {
		return false
	}
	for i := 0; i < len(digits); i += 1 {
		if digits[i] < '0' || '9' < digits[i] {
			return false
		}
	}
	return true
}

// Whether text is lowercase hex of one of byteCounts' sizes.
func computePolicyHex(text string, byteCounts ...int) bool {
	if text != strings.ToLower(text) || !slices.Contains(byteCounts, len(text)/2) || len(text)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}

// Whether text is lowercase hex of between minimum and maximum bytes.
func computePolicyHexRange(text string, minimum int, maximum int) bool {
	if len(text)%2 != 0 || len(text)/2 < minimum || maximum < len(text)/2 || text != strings.ToLower(text) {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}

// Whether text is an identifier this format takes: a word of the pattern, within the id bound.
func (self *ComputePolicy) word(text string, settings *AttestSettings) bool {
	return text != "" && len(text) <= settings.PolicyMaxIdByteCount && computePolicyWordPattern.MatchString(text)
}

// Each line's own rules, after the strict parse.
func (self *ComputePolicy) check(settings *AttestSettings) error {
	if self.Version == 0 {
		return computePolicyFormatError("version is 0")
	}
	if self.NotAfterMs <= 0 {
		return computePolicyFormatError("not_after_ms is not set")
	}
	checks := []func(settings *AttestSettings) error{
		self.checkRoots,
		self.checkTcb,
		self.checkProviders,
		self.checkDirect,
		self.checkDisclosures,
		self.checkCustody,
		self.checkRevoked,
	}
	for _, check := range checks {
		if err := check(settings); err != nil {
			return err
		}
	}
	return nil
}

// Every hash a root of its size, none twice in a list, each ARK's family known and once.
func (self *ComputePolicy) checkRoots(settings *AttestSettings) error {
	for name, hashes := range map[string][]string{
		"roots.intel_sgx":     self.Roots.IntelSgx,
		"roots.nvidia_device": self.Roots.NvidiaDevice,
		"roots.nvidia_nras":   self.Roots.NvidiaNras,
	} {
		for i, hash := range hashes {
			if !computePolicyHex(hash, 32) || slices.Contains(hashes[:i], hash) {
				return computePolicyFormatError("%s holds a hash that is not a SHA-256 in lowercase hex, or one twice", name)
			}
		}
	}
	families := []string{}
	for _, ark := range self.Roots.AmdArks {
		if !slices.Contains(computePolicyAmdFamilies, ark.Family) || !computePolicyHex(ark.Sha256, 32) {
			return computePolicyFormatError("roots.amd_arks holds an unknown family or a hash that is not a SHA-256")
		}
		families = append(families, ark.Family+"/"+ark.Sha256)
	}
	if computePolicyDuplicate(families) {
		return computePolicyFormatError("roots.amd_arks holds an ark twice")
	}
	return nil
}

// TDX's statuses §5.3's two alone, advisories only beside SWHardeningNeeded; SNP's families known and once, its bit
// masks apart; each vendor known and once, its ages at least a day.
func (self *ComputePolicy) checkTcb(settings *AttestSettings) error {
	tdx := self.Tcb.Tdx
	for i, status := range tdx.Statuses {
		if !slices.Contains(computePolicyTdxStatuses, status) || slices.Contains(tdx.Statuses[:i], status) {
			return computePolicyFormatError("tcb.tdx.statuses holds a status §5.3 never allows, or one twice")
		}
	}
	if 0 < len(tdx.Advisories) && !slices.Contains(tdx.Statuses, ComputePolicyTdxSwHardeningNeeded) {
		return computePolicyFormatError("tcb.tdx.advisories names advisories without SWHardeningNeeded")
	}
	for i, advisory := range tdx.Advisories {
		if !self.word(advisory, settings) || slices.Contains(tdx.Advisories[:i], advisory) {
			return computePolicyFormatError("tcb.tdx.advisories holds an advisory that is not an id, or one twice")
		}
	}
	families := []string{}
	for _, firmware := range self.Tcb.Snp.MinFirmware {
		if !slices.Contains(computePolicyAmdFamilies, firmware.Family) || 0xff < firmware.Build {
			return computePolicyFormatError("tcb.snp.min_firmware holds an unknown family or a build past 255")
		}
		families = append(families, firmware.Family)
	}
	if computePolicyDuplicate(families) {
		return computePolicyFormatError("tcb.snp.min_firmware names a family twice")
	}
	if self.Tcb.Snp.PolicyBitsSet&self.Tcb.Snp.PolicyBitsClear != 0 {
		return computePolicyFormatError("tcb.snp asks a policy bit both set and clear")
	}
	vendors := []string{}
	for _, maxAge := range self.Tcb.MaxAges {
		if !slices.Contains(computePolicyVendors, maxAge.Vendor) || maxAge.CollateralDays == 0 || maxAge.RevocationDays == 0 {
			return computePolicyFormatError("tcb.max_ages holds an unknown vendor or an age under a day")
		}
		vendors = append(vendors, maxAge.Vendor)
	}
	if computePolicyDuplicate(vendors) {
		return computePolicyFormatError("tcb.max_ages names a vendor twice")
	}
	return nil
}

// Each TEE provider whole: a slug, CPU types, schemes and its label known, its roots, models and profiles each
// well formed, profile ids unique across the policy.
func (self *ComputePolicy) checkProviders(settings *AttestSettings) error {
	providerIds := []string{}
	profileIds := []string{}
	for _, provider := range self.Providers {
		if !inferValidProvider(provider.Id) || settings.PolicyMaxIdByteCount < len(provider.Id) || provider.Id == computeLocalProvider {
			return computePolicyFormatError("providers holds an id that is not a provider slug")
		}
		providerIds = append(providerIds, provider.Id)
		if len(provider.Cpus) == 0 || len(provider.Schemes) == 0 {
			return computePolicyFormatError("providers.%s names no CPU type or no scheme", provider.Id)
		}
		for i, cpu := range provider.Cpus {
			if !slices.Contains(computePolicyCpus, cpu) || slices.Contains(provider.Cpus[:i], cpu) {
				return computePolicyFormatError("providers.%s.cpus holds an unknown CPU type, or one twice", provider.Id)
			}
		}
		for i, scheme := range provider.Schemes {
			if !slices.Contains(computePolicySchemes, scheme) || slices.Contains(provider.Schemes[:i], scheme) {
				return computePolicyFormatError("providers.%s.schemes holds an unknown scheme, or one twice", provider.Id)
			}
		}
		if !slices.Contains(computePolicyProviderLabels, provider.Label) {
			return computePolicyFormatError("providers.%s.label is not A1 or AP", provider.Id)
		}
		rootNames := []string{}
		for _, root := range provider.Roots {
			if !self.word(root.Name, settings) || !computePolicyHex(root.Sha256, 32) {
				return computePolicyFormatError("providers.%s.roots holds a root without a name or a SHA-256", provider.Id)
			}
			rootNames = append(rootNames, root.Name)
		}
		if computePolicyDuplicate(rootNames) {
			return computePolicyFormatError("providers.%s.roots names a root twice", provider.Id)
		}
		models := []string{}
		for _, model := range provider.Models {
			if inferModelPartFault(model.Model) != "" || settings.PolicyMaxIdByteCount < len(model.Model) ||
				model.ProviderModelId == "" || settings.PolicyMaxIdByteCount < len(model.ProviderModelId) {
				return computePolicyFormatError("providers.%s.models holds a model part outside §6.3's grammar or no provider id", provider.Id)
			}
			models = append(models, model.Model)
		}
		if computePolicyDuplicate(models) {
			return computePolicyFormatError("providers.%s.models names a model twice", provider.Id)
		}
		for _, profile := range provider.Profiles {
			if err := self.checkProfile(provider, profile, settings); err != nil {
				return err
			}
			profileIds = append(profileIds, profile.Id)
		}
	}
	if computePolicyDuplicate(providerIds) {
		return computePolicyFormatError("providers names a provider twice")
	}
	if computePolicyDuplicate(profileIds) {
		return computePolicyFormatError("providers names a profile id twice")
	}
	return nil
}

// One profile: its CPU's registers and no other's, its GPUs, its expiry, its replays and its review.
func (self *ComputePolicy) checkProfile(provider *ComputePolicyProvider, profile *ComputePolicyProfile, settings *AttestSettings) error {
	if !self.word(profile.Id, settings) || !self.word(profile.GuestVersion, settings) {
		return computePolicyFormatError("providers.%s.profiles holds a profile without an id or a guest version", provider.Id)
	}
	if !slices.Contains(provider.Cpus, profile.Cpu) {
		return computePolicyFormatError("profile %s's cpu is not one of its provider's", profile.Id)
	}
	replayed := []string{}
	for _, replay := range profile.Replayed {
		if !computePolicyRegisterPattern.MatchString(replay.Register) || len(replay.Events) == 0 {
			return computePolicyFormatError("profile %s replays an unknown register or no event", profile.Id)
		}
		for _, event := range replay.Events {
			if !computePolicyHexRange(event, 32, 64) {
				return computePolicyFormatError("profile %s replays an event that is not a digest in lowercase hex", profile.Id)
			}
		}
		replayed = append(replayed, replay.Register)
	}
	if computePolicyDuplicate(replayed) {
		return computePolicyFormatError("profile %s replays a register twice", profile.Id)
	}
	switch profile.Cpu {
	case ComputePolicyCpuTdx:
		for _, register := range []string{profile.Mrtd, profile.Rtmr0, profile.Rtmr1, profile.Rtmr2} {
			if !computePolicyHex(register, 48) {
				return computePolicyFormatError("profile %s lacks MRTD or RTMR0-2 as 48 bytes in lowercase hex", profile.Id)
			}
		}
		if !computePolicyHex(profile.Rtmr3, 48) && !(profile.Rtmr3 == "" && slices.Contains(replayed, "rtmr3")) {
			return computePolicyFormatError("profile %s lacks RTMR3, neither given nor replayed", profile.Id)
		}
		if profile.Xfam != "" && !computePolicyHex(profile.Xfam, 8) {
			return computePolicyFormatError("profile %s's xfam is not 8 bytes in lowercase hex", profile.Id)
		}
		if profile.Measurement != "" || profile.SingleSocket {
			return computePolicyFormatError("profile %s is tdx and carries SNP's fields", profile.Id)
		}
		for _, register := range replayed {
			if !strings.HasPrefix(register, "rtmr") && !strings.HasPrefix(register, "pcr") {
				return computePolicyFormatError("profile %s replays a register its CPU has not", profile.Id)
			}
		}
	case ComputePolicyCpuSnp:
		if !computePolicyHex(profile.Measurement, 48) {
			return computePolicyFormatError("profile %s lacks MEASUREMENT as 48 bytes in lowercase hex", profile.Id)
		}
		if profile.Mrtd != "" || profile.Rtmr0 != "" || profile.Rtmr1 != "" || profile.Rtmr2 != "" || profile.Rtmr3 != "" || profile.Xfam != "" {
			return computePolicyFormatError("profile %s is snp and carries TDX's fields", profile.Id)
		}
		for _, register := range replayed {
			if !strings.HasPrefix(register, "pcr") {
				return computePolicyFormatError("profile %s replays a register its CPU has not", profile.Id)
			}
		}
	}
	if (profile.GpuCount == 0) != (profile.GpuModel == "") || (profile.GpuModel != "" && !self.word(profile.GpuModel, settings)) {
		return computePolicyFormatError("profile %s names a GPU model without a count, or the reverse", profile.Id)
	}
	if profile.PayloadRootSha256 != "" && !computePolicyHex(profile.PayloadRootSha256, 32) {
		return computePolicyFormatError("profile %s's payload root hash is not a SHA-256 in lowercase hex", profile.Id)
	}
	if profile.ExpiresMs <= 0 {
		return computePolicyFormatError("profile %s has no expiry", profile.Id)
	}
	switch profile.Review {
	case ComputePolicyReviewReproduced:
		if profile.ReviewListSha256 != "" {
			return computePolicyFormatError("profile %s is reproduced and names a list", profile.Id)
		}
	case ComputePolicyReviewListed:
		if !computePolicyHex(profile.ReviewListSha256, 32) {
			return computePolicyFormatError("profile %s is listed without its list's SHA-256", profile.Id)
		}
	default:
		return computePolicyFormatError("profile %s has no review record", profile.Id)
	}
	return nil
}

// Each direct provider whole and apart from the TEE providers; limited_use naming only listed models.
func (self *ComputePolicy) checkDirect(settings *AttestSettings) error {
	slugs := []string{}
	for _, provider := range self.Direct.Providers {
		if !inferValidProvider(provider.Slug) || settings.PolicyMaxIdByteCount < len(provider.Slug) ||
			provider.Slug == computeLocalProvider || self.Provider(provider.Slug) != nil {
			return computePolicyFormatError("direct.providers holds a slug that is not a provider slug, or a TEE provider's")
		}
		slugs = append(slugs, provider.Slug)
		if settings.PolicyMaxIdByteCount < len(provider.ApiHost) || !computePolicyHostPattern.MatchString(provider.ApiHost) {
			return computePolicyFormatError("direct.providers.%s.api_host is not a host name", provider.Slug)
		}
		if !self.word(provider.ReceiverHotkey, settings) || provider.Netuid == 0 {
			return computePolicyFormatError("direct.providers.%s has no receiver hotkey or netuid", provider.Slug)
		}
		if len(provider.Targets) == 0 {
			return computePolicyFormatError("direct.providers.%s lists no target", provider.Slug)
		}
		targets := []string{}
		for _, target := range provider.Targets {
			if !slices.Contains(computePolicyMethods, target.Method) || settings.PolicyMaxIdByteCount < len(target.Path) ||
				!computePolicyPathPattern.MatchString(target.Path) {
				return computePolicyFormatError("direct.providers.%s.targets holds a method or path this format does not take", provider.Slug)
			}
			targets = append(targets, target.Method+" "+target.Path)
		}
		if computePolicyDuplicate(targets) {
			return computePolicyFormatError("direct.providers.%s.targets lists a target twice", provider.Slug)
		}
		models := []string{}
		for _, model := range provider.Models {
			if inferModelPartFault(model.Model) != "" || settings.PolicyMaxIdByteCount < len(model.Model) ||
				model.ProviderModelId == "" || settings.PolicyMaxIdByteCount < len(model.ProviderModelId) {
				return computePolicyFormatError("direct.providers.%s.models holds a model part outside §6.3's grammar or no provider id", provider.Slug)
			}
			for i, alias := range model.Aliases {
				if alias == "" || settings.PolicyMaxIdByteCount < len(alias) || slices.Contains(model.Aliases[:i], alias) {
					return computePolicyFormatError("direct.providers.%s.models holds an empty, long or repeated alias", provider.Slug)
				}
			}
			for i, upstream := range model.Upstreams {
				if !self.word(upstream, settings) || slices.Contains(model.Upstreams[:i], upstream) {
					return computePolicyFormatError("direct.providers.%s.models holds an upstream that is not an id, or one twice", provider.Slug)
				}
			}
			models = append(models, model.Model)
		}
		if computePolicyDuplicate(models) {
			return computePolicyFormatError("direct.providers.%s.models names a model twice", provider.Slug)
		}
	}
	if computePolicyDuplicate(slugs) {
		return computePolicyFormatError("direct.providers names a provider twice")
	}
	for i, name := range self.Direct.LimitedUse {
		provider, model, ok := strings.Cut(name, "-")
		listed := false
		if ok {
			if teeProvider := self.Provider(provider); teeProvider != nil {
				listed = teeProvider.ProviderModelId(model) != ""
			} else if directProvider := self.DirectProvider(provider); directProvider != nil {
				listed = directProvider.Model(model) != nil
			}
		}
		if !listed || slices.Contains(self.Direct.LimitedUse[:i], name) {
			return computePolicyFormatError("direct.limited_use names a model no provider line lists, or one twice")
		}
	}
	return nil
}

// Each disclosure whole: its id's form, a version from 1, a grace of at most §2.8's, the instant it took effect,
// English first, each locale once with a summary.
func (self *ComputePolicy) checkDisclosures(settings *AttestSettings) error {
	ids := []string{}
	for _, disclosure := range self.Disclosures {
		if settings.PolicyMaxIdByteCount < len(disclosure.Id) || !computePolicyDisclosureIdPattern.MatchString(disclosure.Id) {
			return computePolicyFormatError("disclosures holds an id that is not family:slug")
		}
		ids = append(ids, disclosure.Id)
		if disclosure.Version == 0 {
			return computePolicyFormatError("disclosure %s has version 0", disclosure.Id)
		}
		if settings.DisclosureGraceMaxDays < 0 || uint32(settings.DisclosureGraceMaxDays) < disclosure.GraceDays {
			return computePolicyFormatError("disclosure %s has a grace past %d days", disclosure.Id, settings.DisclosureGraceMaxDays)
		}
		if disclosure.SinceMs <= 0 {
			return computePolicyFormatError("disclosure %s has no instant its version took effect", disclosure.Id)
		}
		if len(disclosure.Locales) == 0 || disclosure.Locales[0].Locale != computePolicyEnglish {
			return computePolicyFormatError("disclosure %s does not carry English first", disclosure.Id)
		}
		locales := []string{}
		for _, text := range disclosure.Locales {
			if settings.PolicyMaxIdByteCount < len(text.Locale) || !computePolicyLocalePattern.MatchString(text.Locale) {
				return computePolicyFormatError("disclosure %s holds a locale that is not a language tag", disclosure.Id)
			}
			locales = append(locales, text.Locale)
			if strings.TrimSpace(text.Summary) == "" || strings.ContainsAny(text.Summary, "\r\n") {
				return computePolicyFormatError("disclosure %s has a locale without a one-line summary", disclosure.Id)
			}
			for _, item := range slices.Concat(text.Exposed, text.Private) {
				if strings.TrimSpace(item) == "" {
					return computePolicyFormatError("disclosure %s has an empty item", disclosure.Id)
				}
			}
		}
		if computePolicyDuplicate(locales) {
			return computePolicyFormatError("disclosure %s names a locale twice", disclosure.Id)
		}
	}
	if computePolicyDuplicate(ids) {
		return computePolicyFormatError("disclosures names an id twice")
	}
	return nil
}

// Each custody entry under a TEE provider, once, with a registry and known chips.
func (self *ComputePolicy) checkCustody(settings *AttestSettings) error {
	providers := []string{}
	for _, custody := range self.Custody {
		if self.Provider(custody.Provider) == nil || !self.word(custody.Registry, settings) {
			return computePolicyFormatError("custody names a provider the providers line does not, or no registry")
		}
		providers = append(providers, custody.Provider)
		if err := computePolicyCheckChips(custody.Chips, "custody."+custody.Provider); err != nil {
			return err
		}
	}
	if computePolicyDuplicate(providers) {
		return computePolicyFormatError("custody names a provider twice")
	}
	return nil
}

// The revocations: ids, known chips, serials, each once.
func (self *ComputePolicy) checkRevoked(settings *AttestSettings) error {
	for i, profileId := range self.Revoked.Profiles {
		if !self.word(profileId, settings) || slices.Contains(self.Revoked.Profiles[:i], profileId) {
			return computePolicyFormatError("revoked.profiles holds a profile id that is not an id, or one twice")
		}
	}
	if err := computePolicyCheckChips(self.Revoked.Chips, "revoked"); err != nil {
		return err
	}
	for i, serial := range self.Revoked.GpuSerials {
		if !self.word(serial, settings) || slices.Contains(self.Revoked.GpuSerials[:i], serial) {
			return computePolicyFormatError("revoked.gpu_serials holds a serial that is not an id, or one twice")
		}
	}
	return nil
}

// Chips of a known kind, as 8 to 64 bytes of lowercase hex, each once.
func computePolicyCheckChips(chips []*ComputePolicyChip, path string) error {
	keys := []string{}
	for _, chip := range chips {
		if !slices.Contains(computePolicyChipKinds, chip.Kind) || !computePolicyHexRange(chip.Id, 8, 64) {
			return computePolicyFormatError("%s.chips holds an unknown kind or an id that is not lowercase hex", path)
		}
		keys = append(keys, chip.Kind+"/"+chip.Id)
	}
	if computePolicyDuplicate(keys) {
		return computePolicyFormatError("%s.chips names a chip twice", path)
	}
	return nil
}

// Whether a value appears twice.
func computePolicyDuplicate(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}
