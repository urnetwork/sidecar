// The provider adapter (DESIGN-COMPUTE §4.6, R-PROV-6, D-PROV-1, D-PROV-4, D-PROV-7): every provider, inference and
// enclave, is one Go value behind ComputeProvider, so the Harness, the gateway and the ledger never name a provider.
// The broker's server half lives here; each provider's device half is the root's InferProviderHalf
// (infer_provider.go). A provider is reached only through its adapter, and an adapter serves only where the registry
// enables it (provider_registry.go): this deployment's settings name it for the env, and its compute_provider row
// reads gated (§4.7).
//
// Providers are named by team and endpoint, never by netuid: a ComputeProviderId is a slug, and each slug has a fixed
// code, an identifier that compute_charge.provider and every other smallint provider column hold (§9.4;
// compute-plan-inference-small-readings, QD-1247). A code never changes and is never reused: a charge written under it
// names its provider for the row's life. Code 0 names no provider, as a support credit's charge carries (§9.4). The
// netuid and the hotkeys are each deployment's settings, read again at each gate (D-PROV-4).
//
// An adapter answers ErrComputeNotOffered for what its provider does not offer: an inference provider the VM calls, an
// enclave provider the inference and direct calls (§4.6's last paragraph). ComputeProviderBase gives every method that
// answer, so an adapter embeds it and overrides what it offers. No adapter reads a host, receiver hotkey, target or
// model id from anywhere but the newest verified compute policy (§5.4): computeDirectTargetFromPolicy is the one way a
// direct target is made, and the unsigned catalog adds only prices and capacity.
//
// Values here are plain data a caller owns; an adapter is safe for concurrent use.

package computeservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
)

// A provider's stable name: its slug, [a-z0-9]+, as canonical model names carry it (§6.3). Never a netuid.
type ComputeProviderId string

// The providers CO-28 names, the reference provider of development, CI and staging (§11.3), and web search's gateway,
// whose row is SRCH's (§21): every slug this build knows.
const (
	ComputeProviderIdChutes    ComputeProviderId = "chutes"
	ComputeProviderIdEngy      ComputeProviderId = "engy"
	ComputeProviderIdSaygm     ComputeProviderId = "saygm"
	ComputeProviderIdHippius   ComputeProviderId = "hippius"
	ComputeProviderIdLium      ComputeProviderId = "lium"
	ComputeProviderIdCathedral ComputeProviderId = "cathedral"
	ComputeProviderIdReference ComputeProviderId = "reference"
	ComputeProviderIdParallel  ComputeProviderId = "parallel"
)

// A provider's fixed code, the smallint every provider column holds (§9.4).
type ComputeProviderCode int16

// The codes. Identifiers: each is fixed for good, and a new provider takes the next unused number.
const (
	// No provider: a support credit or debit (§9.4).
	ComputeProviderCodeNone      ComputeProviderCode = 0
	ComputeProviderCodeChutes    ComputeProviderCode = 1
	ComputeProviderCodeEngy      ComputeProviderCode = 2
	ComputeProviderCodeSaygm     ComputeProviderCode = 3
	ComputeProviderCodeHippius   ComputeProviderCode = 4
	ComputeProviderCodeLium      ComputeProviderCode = 5
	ComputeProviderCodeCathedral ComputeProviderCode = 6
	ComputeProviderCodeReference ComputeProviderCode = 7
	ComputeProviderCodeParallel  ComputeProviderCode = 8
)

// What a provider serves, as compute_provider.kind holds it (§14.4).
type ComputeProviderKind int16

const (
	// Remote inference, in a TEE or not (§6.6).
	ComputeProviderKindInference ComputeProviderKind = 1
	// Enclave VMs (§11).
	ComputeProviderKindEnclave ComputeProviderKind = 2
	// Web search (§21): Parallel's gateway, which has a row and no adapter.
	ComputeProviderKindSearch ComputeProviderKind = 3
)

// The kind's word, as `sidecarctl compute provider ls` prints it.
func (self ComputeProviderKind) String() string {
	switch self {
	case ComputeProviderKindInference:
		return "inference"
	case ComputeProviderKindEnclave:
		return "enclave"
	case ComputeProviderKindSearch:
		return "search"
	}
	return fmt.Sprintf("kind %d", int16(self))
}

// G-PROV-any, every provider's re-check every 90 days (§4.7).
const ComputeProviderGateAny = "G-PROV-any"

// One provider this build knows: its slug, code, kind and the gate that admits it (§4.7).
type computeProviderSpec struct {
	id   ComputeProviderId
	code ComputeProviderCode
	kind ComputeProviderKind
	// The gate whose pass admits it: G-PROV-<slug> for an inference or enclave provider, G-SRCH-parallel for web search.
	// The reference provider's is the plan's reading: ENC's gate suite run against it in staging (ENC-M14-19), which
	// §4.7 does not name.
	gate string
}

// Every provider, in code order. Identifiers only.
var computeProviderSpecs = []*computeProviderSpec{
	{id: ComputeProviderIdChutes, code: ComputeProviderCodeChutes, kind: ComputeProviderKindInference, gate: "G-PROV-chutes"},
	{id: ComputeProviderIdEngy, code: ComputeProviderCodeEngy, kind: ComputeProviderKindInference, gate: "G-PROV-engy"},
	{id: ComputeProviderIdSaygm, code: ComputeProviderCodeSaygm, kind: ComputeProviderKindInference, gate: "G-PROV-saygm"},
	{id: ComputeProviderIdHippius, code: ComputeProviderCodeHippius, kind: ComputeProviderKindEnclave, gate: "G-PROV-hippius"},
	{id: ComputeProviderIdLium, code: ComputeProviderCodeLium, kind: ComputeProviderKindEnclave, gate: "G-PROV-lium"},
	{id: ComputeProviderIdCathedral, code: ComputeProviderCodeCathedral, kind: ComputeProviderKindEnclave, gate: "G-PROV-cathedral"},
	{id: ComputeProviderIdReference, code: ComputeProviderCodeReference, kind: ComputeProviderKindEnclave, gate: "G-PROV-reference"},
	{id: ComputeProviderIdParallel, code: ComputeProviderCodeParallel, kind: ComputeProviderKindSearch, gate: "G-SRCH-parallel"},
}

// The spec of id, or nil for a slug this build does not know.
func computeProviderSpecOf(id ComputeProviderId) *computeProviderSpec {
	index := slices.IndexFunc(computeProviderSpecs, func(spec *computeProviderSpec) bool {
		return spec.id == id
	})
	if index < 0 {
		return nil
	}
	return computeProviderSpecs[index]
}

// Every slug this build knows, in code order.
func ComputeProviderIds() []ComputeProviderId {
	ids := make([]ComputeProviderId, 0, len(computeProviderSpecs))
	for _, spec := range computeProviderSpecs {
		ids = append(ids, spec.id)
	}
	return ids
}

// The slug id's fixed code, false for a slug this build does not know.
func ComputeProviderCodeOf(id ComputeProviderId) (ComputeProviderCode, bool) {
	if spec := computeProviderSpecOf(id); spec != nil {
		return spec.code, true
	}
	return ComputeProviderCodeNone, false
}

// The slug of code, false for code 0 and a code this build does not know.
func ComputeProviderIdOf(code ComputeProviderCode) (ComputeProviderId, bool) {
	for _, spec := range computeProviderSpecs {
		if spec.code == code {
			return spec.id, true
		}
	}
	return "", false
}

// What id serves, false for a slug this build does not know.
func ComputeProviderKindOf(id ComputeProviderId) (ComputeProviderKind, bool) {
	if spec := computeProviderSpecOf(id); spec != nil {
		return spec.kind, true
	}
	return 0, false
}

// The gate whose pass admits id (§4.7), false for a slug this build does not know.
func ComputeProviderGateOf(id ComputeProviderId) (string, bool) {
	if spec := computeProviderSpecOf(id); spec != nil {
		return spec.gate, true
	}
	return "", false
}

// What a provider answers for a call it does not offer (§4.6).
var ErrComputeNotOffered = errors.New("not offered by this provider")

// A provider (§4.6), the server's half. Safe for concurrent use. Each method's context bounds its I/O; the methods
// without one do none.
type ComputeProvider interface {
	// Its slug, stable whatever its netuid.
	Id() ComputeProviderId
	// What it offers now: its models or shapes, prices in gamma, and capacity (§9.6's hourly read).
	Catalog(ctx context.Context) (*ComputeProviderCatalog, error)

	// Inference in a TEE (§6.6's TEE path): a model's instances, each with its E2E public key and one-use nonces,
	// none chosen. modelId is the provider's own id for the model, as the policy binds it (Chutes: the chute_id).
	InstanceKeys(ctx context.Context, modelId string) ([]*ComputeInstanceKey, error)
	// An instance's evidence for nonce, fetched for the broker's own use (a beacon nonce, §5.6); a device fetches its
	// own over the tunnel.
	Evidence(ctx context.Context, modelId string, instanceId string, nonce []byte) (*ComputeEvidence, error)
	// One call: ciphertext in, ciphertext out, relayed byte for byte.
	Invoke(ctx context.Context, call *ComputeInvoke) (*ComputeInvokeStream, error)
	// The provider's own usage record of a call, by its request id.
	Usage(ctx context.Context, requestId string) (*ComputeUsage, error)

	// The direct path (§6.6), for a provider without a TEE: the host, method, target and receiver, and the model's
	// provider id, zero-retention rule and upstreams, as the newest verified policy pins them, never from anywhere
	// else. modelId is the model part of the model's canonical names (§6.3), which the policy's direct line keys
	// its models by.
	DirectTarget(modelId string) (*ComputeDirectTarget, error)
	// A direct call's usage, read by its btauth/1 nonce or its body's hash, never by an id only the device knows
	// (N2): unknown, in progress or finished.
	DirectUsage(ctx context.Context, nonce []byte, bodyHash []byte) (*ComputeUsage, error)
	// A receipt the provider signed over a call's body hash, its usage and its charge (engy: Ed25519), checked under
	// the key the policy pins: the usage it vouches for, or an error for a receipt that does not verify or covers
	// another body.
	VerifyReceipt(receipt []byte, bodyHash []byte) (*ComputeUsage, error)

	// Enclaves (§11): a VM made to spec, under setup over SSH answering its setup address too (§11.7).
	CreateVm(ctx context.Context, spec *ComputeVmSpec) (*ComputeVm, error)
	// A VM's evidence for nonce.
	VmEvidence(ctx context.Context, vmId string, nonce []byte) (*ComputeEvidence, error)
	// A VM as the provider reports it now.
	VmStatus(ctx context.Context, vmId string) (*ComputeVm, error)
	// Deletes a VM; deleting one already gone is no error.
	DeleteVm(ctx context.Context, vmId string) error

	// How URnetwork pays it (§10): for gamma, the netuid, the provider's service hotkey and URnetwork's API-key
	// hotkey, each this deployment's setting (D-PROV-4).
	Payment() ComputeProviderPayment
	// What URnetwork has left at the provider, in nano-USD.
	Balance(ctx context.Context) (operator.NanoCents, error)
}

// What a provider offers, as one catalog read answered it.
type ComputeProviderCatalog struct {
	// The provider whose catalog it is.
	Provider ComputeProviderId
	// What one gamma of the provider's service cost in USD at the read, in nano-USD, as read and never a constant:
	// engy's $1.05 a gamma is 1,050,000,000 (§10.2). A provider priced in dollars, such as Chutes on its API key or
	// the reference provider, reads 1,000,000,000: its "gamma" is its dollar.
	GammaNanoUsd int64
	// Its models, for an inference provider.
	Models []*ComputeProviderModel
	// Its shapes, for an enclave provider.
	Shapes []*ComputeProviderShape
}

// One model of a provider's catalog. Prices are in nano-gamma, 10^-9 gamma, per million tokens.
type ComputeProviderModel struct {
	// The provider's own id for it, which the catalog normalizes into its canonical model part (§6.3).
	ModelId string
	// The label it is offered under: none for a direct provider, AP or A1 for a TEE one (§4.3).
	Label sidecar.ComputeLabel
	// The efforts it takes (§6.3): off alone where it has no reasoning.
	Efforts []sidecar.InferEffort
	// Its context window and the most tokens one answer holds.
	ContextWindow int64
	MaxOutput     int64
	// Whether it calls tools and gives structured output.
	Tools            bool
	StructuredOutput bool
	// What it takes in.
	Modalities []sidecar.InferModality
	// Its license, as the provider names it; empty where it names none.
	License string
	// Prices per million tokens.
	InputNanoGammaPerMillion       int64
	OutputNanoGammaPerMillion      int64
	CachedInputNanoGammaPerMillion int64
	// Whether its price varies by request, its prices above then the most it charges (§6.3: SayGM's list).
	PriceVaries bool
	// Instances serving it now (E7's at least 2), where CapacityKnown.
	Capacity      int64
	CapacityKnown bool
	// For a TEE label, where §4.5 says the provider's serving code is not measured: "serving code measured: no".
	ServingCodeUnmeasured bool
}

// One enclave shape of a provider's catalog (§11.5). Prices are in nano-gamma.
type ComputeProviderShape struct {
	// The shape's name, such as cpu-2.
	ShapeId string
	// The label its enclaves carry: A1 where the provider offers it, else AP (§4.3).
	Label sidecar.ComputeLabel
	// Its vCPUs, memory and scratch disk.
	VcpuCount       int64
	MemoryByteCount int64
	DiskByteCount   int64
	// Its GPUs, empty and 0 for a CPU shape.
	GpuModel string
	GpuCount int64
	// The price of an hour.
	HourNanoGamma int64
	// The price of a GiB its enclave sends out through the provider, where the provider bills egress (§9.6's kind 4);
	// 0 where it bills none.
	EgressNanoGammaPerGib int64
	// VMs of the shape it can start now, where CapacityKnown.
	Capacity      int64
	CapacityKnown bool
}

// One TEE instance of a model (§6.6's prepare): what a device verifies against the instance's evidence, never a choice
// the broker made.
type ComputeInstanceKey struct {
	// The provider's id for the instance.
	InstanceId string
	// The instance's E2E public key (Chutes: ML-KEM-768).
	E2ePublicKey []byte
	// One-use nonces the provider issued for calls to it.
	Nonces []string
	// The provider's own load figure for it, higher meaning busier; 0 where it gives none.
	LoadHint float64
}

// Evidence a TEE published, relayed as fetched: the device verifies it (§5), the broker never does.
type ComputeEvidence struct {
	// The binding scheme it is for, one of the policy's (§5.5), such as chutes-e2e-v1 or ur-enclave-v1.
	Scheme string
	// The provider's document, byte for byte.
	Document []byte
}

// One TEE call (§6.6's step 5): ciphertext the broker relays and never reads.
type ComputeInvoke struct {
	// The provider's own id for the model (Chutes: the chute_id).
	ModelId string
	// The instance the device chose and the one-use nonce it took from prepare.
	InstanceId string
	E2eNonce   string
	// Whether the call streams.
	Stream bool
	// The sealed request, byte for byte.
	Envelope []byte
}

// A TEE call's answer as it arrives.
type ComputeInvokeStream struct {
	// The provider's answer, relayed byte for byte: read until io.EOF. Closing it ends the provider's call, as a
	// device's closed stream must (§6.6).
	Body io.ReadCloser
	// The provider's own id for the call, which Usage reads.
	RequestId string
}

// The three states of a usage lookup (N2): a call still running is never taken for one never served.
type ComputeUsageState int

const (
	// The provider has no record: refused, never served, or not yet arrived.
	ComputeUsageUnknown ComputeUsageState = 1
	// Served and still running.
	ComputeUsageInProgress ComputeUsageState = 2
	// Served and ended: the counts below are what the provider bills.
	ComputeUsageFinished ComputeUsageState = 3
)

// The state's word.
func (self ComputeUsageState) String() string {
	switch self {
	case ComputeUsageUnknown:
		return "unknown"
	case ComputeUsageInProgress:
		return "in progress"
	case ComputeUsageFinished:
		return "finished"
	}
	return fmt.Sprintf("state %d", int(self))
}

// A provider's own record of one call (§6.6, N2).
type ComputeUsage struct {
	State ComputeUsageState
	// The provider's own id for the model that served, which settlement compares with the declared one (§6.6).
	ModelId string
	// Tokens in, out (reasoning included), read from a cache, and spent reasoning.
	InputTokens       uint64
	OutputTokens      uint64
	CachedInputTokens uint64
	ReasoningTokens   uint64
	// The provider's own charge for it in nano-gamma, where it states one.
	ChargeNanoGamma int64
	// Whether every machine that received the prompt keeps no data (engy's served.zdr), where the provider says.
	ZeroRetention bool
	// The provider's own id for the call.
	RequestId string
}

// The direct path's target for one model (§6.6), every field as the newest verified policy's direct line pins it
// (§5.4): what the broker signs btauth/1 for and the device calls, and nothing a catalog said.
type ComputeDirectTarget struct {
	// The provider's slug.
	Provider ComputeProviderId
	// Its API host, which the device's TLS reaches.
	Host string
	// The method and path of the call, a target the policy lists.
	Method string
	Path   string
	// Its btauth/1 receiver hotkey.
	ReceiverHotkey string
	// Its gamma netuid, as the policy records it.
	Netuid uint32
	// The model part of the model's canonical names, and the provider's own id for it.
	Model           string
	ProviderModelId string
	// The aliases the provider's gate recorded for the model, which settlement accepts as the same model (§6.6).
	Aliases []string
	// Whether every call must carry the provider's zero-retention flag (Q-PROV-6).
	ZeroRetention bool
	// The upstreams a routing provider may send the model to (SayGM), empty for one that routes none.
	Upstreams []string
}

// The target the policy pins for provider's model and the call method and path: refused where there is no policy, the
// policy's direct line does not list the provider, the model or the target, or the line's entry is not whole. Every
// adapter's DirectTarget makes its answer here, so none reads a host, receiver, target or model id from anywhere but
// the policy (§5.4).
func computeDirectTargetFromPolicy(policy *sidecar.ComputePolicy, provider ComputeProviderId, model string, method string, path string) (*ComputeDirectTarget, error) {
	if policy == nil {
		return nil, fmt.Errorf("%s: no verified compute policy, so no direct target", provider)
	}
	direct := policy.DirectProvider(string(provider))
	if direct == nil {
		return nil, fmt.Errorf("%s: the policy's direct line does not list the provider", provider)
	}
	policyModel := direct.Model(model)
	if policyModel == nil {
		return nil, fmt.Errorf("%s: the policy's direct line does not list the model %q", provider, model)
	}
	if !slices.ContainsFunc(direct.Targets, func(target *sidecar.ComputePolicyDirectTarget) bool {
		return target != nil && target.Method == method && target.Path == path
	}) {
		return nil, fmt.Errorf("%s: the policy lists no target %s %s", provider, method, path)
	}
	if direct.ApiHost == "" || direct.ReceiverHotkey == "" || policyModel.ProviderModelId == "" {
		return nil, fmt.Errorf("%s: the policy's direct entry for %q is not whole", provider, model)
	}
	return &ComputeDirectTarget{
		Provider:        provider,
		Host:            direct.ApiHost,
		Method:          method,
		Path:            path,
		ReceiverHotkey:  direct.ReceiverHotkey,
		Netuid:          direct.Netuid,
		Model:           policyModel.Model,
		ProviderModelId: policyModel.ProviderModelId,
		Aliases:         slices.Clone(policyModel.Aliases),
		ZeroRetention:   policyModel.ZeroRetention,
		Upstreams:       slices.Clone(policyModel.Upstreams),
	}, nil
}

// What a VM is made to (§11.7's step 3).
type ComputeVmSpec struct {
	// The enclave and the incarnation the VM is for, as B binds them.
	EnclaveId   sidecar.Id
	Incarnation uint64
	// The shape, one of the provider's catalog.
	ShapeId string
	// The ur-enclave image version the VM boots (EPC-1's first form), or whose payload it runs (the second).
	ImageVersion string
	// The bootstrap bundle B, and its SHA-256, the launch data where the provider sets it (§11.7).
	Bootstrap       []byte
	BootstrapSha256 []byte
	// The per-VM token the VM's init posts its evidence with (§14.3).
	VmToken []byte
	// Under setup over SSH, the device's one-use SSH public key the provider's channel installs once (EPC-1's fourth
	// form); empty otherwise.
	SetupSshPublicKey []byte
}

// A VM's state as its provider reports it.
type ComputeVmState int

const (
	// Asked for and not yet booted.
	ComputeVmCreating ComputeVmState = 1
	// Booted.
	ComputeVmRunning ComputeVmState = 2
	// Stopped by the provider, its machine kept.
	ComputeVmStopped ComputeVmState = 3
	// Gone without a delete of URnetwork's: lost (§11.11).
	ComputeVmLost ComputeVmState = 4
	// Deleted.
	ComputeVmDeleted ComputeVmState = 5
)

// One VM as its provider reports it.
type ComputeVm struct {
	// The provider's id for it.
	VmId  string
	State ComputeVmState
	// Under setup over SSH, the setup server's address the provider reports, any port, 22 included (§11.7); empty and
	// 0 otherwise.
	SetupHost string
	SetupPort int
	// When the provider's report was read.
	ReadTime time.Time
}

// How URnetwork pays a provider (§10.4, §10.10).
type ComputeProviderPaymentMethod int

const (
	// Not paid through an adapter: the reference provider, and an adapter that offers no money calls.
	ComputeProviderPaymentNone ComputeProviderPaymentMethod = 0
	// In gamma, spent by the API-key hotkey at the provider's service (§10.4).
	ComputeProviderPaymentGamma ComputeProviderPaymentMethod = 1
	// On an API key's account, for a provider that takes no gamma yet (Chutes, §10.10), its netuid ready for the day
	// its subnet enables gamma.
	ComputeProviderPaymentApiKey ComputeProviderPaymentMethod = 2
)

// A provider's payment setup (§10.4): the triple compute_gamma.yml lists, each this deployment's setting, read again at
// each gate (D-PROV-4) and never a constant.
type ComputeProviderPayment struct {
	Method ComputeProviderPaymentMethod
	// The provider's subnet.
	Netuid uint32
	// The provider's service hotkey S_P, from its published service document.
	ServiceHotkey string
	// URnetwork's API-key hotkey K_P at the provider.
	ApiKeyHotkey string
}

// Answers ErrComputeNotOffered for every call, and its own id, so an adapter embeds it and overrides only what its
// provider offers (§4.6). Its Payment is ComputeProviderPaymentNone.
type ComputeProviderBase struct {
	// The slug Id answers.
	ProviderId ComputeProviderId
}

var _ ComputeProvider = (*ComputeProviderBase)(nil)

// The slug the adapter set.
func (self *ComputeProviderBase) Id() ComputeProviderId {
	return self.ProviderId
}

// Not offered.
func (self *ComputeProviderBase) Catalog(ctx context.Context) (*ComputeProviderCatalog, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) InstanceKeys(ctx context.Context, modelId string) ([]*ComputeInstanceKey, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) Evidence(ctx context.Context, modelId string, instanceId string, nonce []byte) (*ComputeEvidence, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) Invoke(ctx context.Context, call *ComputeInvoke) (*ComputeInvokeStream, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) Usage(ctx context.Context, requestId string) (*ComputeUsage, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) DirectTarget(modelId string) (*ComputeDirectTarget, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) DirectUsage(ctx context.Context, nonce []byte, bodyHash []byte) (*ComputeUsage, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) VerifyReceipt(receipt []byte, bodyHash []byte) (*ComputeUsage, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) CreateVm(ctx context.Context, spec *ComputeVmSpec) (*ComputeVm, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) VmEvidence(ctx context.Context, vmId string, nonce []byte) (*ComputeEvidence, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) VmStatus(ctx context.Context, vmId string) (*ComputeVm, error) {
	return nil, ErrComputeNotOffered
}

// Not offered.
func (self *ComputeProviderBase) DeleteVm(ctx context.Context, vmId string) error {
	return ErrComputeNotOffered
}

// No payment: an adapter that pays its provider overrides it.
func (self *ComputeProviderBase) Payment() ComputeProviderPayment {
	return ComputeProviderPayment{Method: ComputeProviderPaymentNone}
}

// Not offered.
func (self *ComputeProviderBase) Balance(ctx context.Context) (operator.NanoCents, error) {
	return 0, ErrComputeNotOffered
}
