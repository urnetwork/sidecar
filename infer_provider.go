//go:build !ios_extension && !sidecar_http

// A remote provider's device half (DESIGN-COMPUTE §4.6, §6.4, §6.6; R-PROV-6): what the remote paths need of one
// provider's API on the device, so the router, the direct path (INFER-M12-03) and the TEE path (INFER-M15-01) never
// name a provider. Each provider's half registers from its own infer_provider_<slug>.go at init through
// registerInferProviderHalf (engy's PROV-M12-02, SayGM's PROV-M12-03, Chutes' PROV-M15-01), and a path takes the half
// for its entry's provider through inferProviderHalfFor, which refuses a slug no half serves. A half holds:
//
//   - the provider's effort table (§6.4): §6.3's effort words to the provider's own parameter, which inferProviderEffort
//     reads, so the router never sends an effort the table lacks or the model does not list;
//   - its request builder: the provider's body for one call, its model id, zero-retention flag and route from the
//     policy alone (§5.4), never from the unsigned catalog (R1-14), the cache salt the system text's first line, and
//     on the direct path the caller value in its user field;
//   - its stream parser: the provider's answer into InferEvents, ending with what the provider reported;
//   - its receipt check: a direct provider's signed receipt read on the device, whose model and zero retention
//     inferProviderCheckReceiptModel holds to the policy's entry (§6.6);
//   - for a TEE provider, its envelope (§6.6's step 4), which seals the body to an instance's key and opens the relayed
//     answer; a direct provider has none.
//
// Nothing here dials, signs or settles: the paths do, and the half only shapes and reads the provider's bytes.
//
// The registrations are written only during the package's init, so read without a lock after it. A half is safe for
// concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// A provider's device half. See the file header.
type InferProviderHalf interface {
	// The provider's slug, as canonical names carry it (§6.3).
	Provider() string
	// The provider's own reasoning parameter for each effort it takes (§6.4). An effort the table lacks is never sent.
	Efforts() map[InferEffort]string
	// The provider's request for one call, or an *InferError where the call cannot be written for it.
	BuildRequest(args *InferProviderRequestArgs) (*InferProviderRequest, error)
	// Reads the provider's answer, emitting its events as they arrive, and answers what the stream reported at its end:
	// nil and the end, or the call's failure, an *InferError where it can say which (capacity for a busy provider,
	// model_refused for a refused model). Returns promptly once ctx ends.
	ReadStream(ctx context.Context, answer *InferProviderAnswer, emit InferEmit) (*InferProviderStreamEnd, error)
	// Reads a receipt the provider signed for a direct call, and refuses one that does not hold for the call: its
	// model not one the policy gives the entry, or zero retention not served where the policy requires it, each
	// model_refused naming the receipt (§6.6). A provider that signs no receipt answers model_refused for every one.
	CheckReceipt(args *InferProviderReceiptArgs) (*InferProviderReceipt, error)
	// The TEE path's envelope; nil for a provider without a TEE.
	Envelope() InferProviderEnvelope
}

// What a half builds one call's request from: the call the router checked, and what the policy pins for its model.
type InferProviderRequestArgs struct {
	// The call: its request, entry, effort and name, and the policy the checks read.
	Call *InferCall
	// The provider's own id for the model, from the policy alone: the direct line's models map, or a TEE provider's
	// models line (§5.4).
	ProviderModelId string
	// The provider's own parameter for the call's effort, from the half's table (inferProviderEffort).
	EffortParameter string
	// Whether the call must carry the provider's zero-retention flag (the policy's zero_retention; engy's provider.zdr,
	// Q-PROV-6).
	ZeroRetention bool
	// The upstreams the policy allows the model, for a provider that routes (SayGM's X-GM-Providers); empty for one
	// that routes none.
	Upstreams []string
	// The line the system text starts with: the cache salt, [ur:<32 hex>] (§6.6). Never appended.
	CacheSaltLine string
	// On the direct path, 16 random bytes for the API's caller field, user in OpenAI's or metadata.user_id in
	// Anthropic's, so the body's hash confirms no guess (§6.6); nil on the TEE path.
	CallerValue []byte
}

// One call's request as the provider takes it.
type InferProviderRequest struct {
	// The method and path it goes to: on the direct path a target the policy lists, which the path checks before
	// anything is signed.
	Method string
	Path   string
	// Its headers beyond btauth/1's and the transport's: the content type, and a routing provider's upstream header
	// from the policy's pins.
	Header http.Header
	// The body: on the direct path the very bytes hashed and sent once; on the TEE path what the envelope seals.
	Body []byte
}

// The provider's answer as the path received it.
type InferProviderAnswer struct {
	// Its HTTP status and headers.
	StatusCode int
	Header     http.Header
	// Its body: the provider's stream on the direct path, the plaintext the envelope's opener yields on the TEE path.
	Body io.Reader
}

// What a stream reported at its end.
type InferProviderStreamEnd struct {
	// The usage the provider reported in the stream, nil where it reported none.
	Usage *InferUsage
	// The provider's own id for the model that served, as the stream named it; empty where it named none.
	ServedModelId string
	// The receipt the provider attached, as it sent it, for CheckReceipt and the broker's settlement; nil for none.
	Receipt []byte
	// Whether the stream reached the provider's own end, rather than closing early.
	Complete bool
}

// A direct call's receipt to check.
type InferProviderReceiptArgs struct {
	// The receipt as the provider sent it.
	Receipt []byte
	// The SHA-256 of the body sent.
	BodyHash []byte
	// The policy's direct entry for the provider and for the model the call ran under.
	Provider *ComputePolicyDirect
	Model    *ComputePolicyDirectModel
}

// What a receipt vouches for.
type InferProviderReceipt struct {
	// The provider's own id for the model that served.
	ServedModelId string
	// Whether every machine that received the prompt kept no data (engy's served.zdr).
	ZeroRetention bool
	// The usage it signed.
	Usage *InferUsage
	// The provider's charge it signed, in nano-gamma; 0 where it states none.
	ChargeNanoGamma int64
}

// A TEE provider's envelope (§6.6's step 4): the provider's own construction, such as Chutes' ML-KEM-768,
// HKDF-SHA256 and ChaCha20-Poly1305 with a fresh ephemeral key a call.
type InferProviderEnvelope interface {
	// Seals body to an instance's E2E public key for one call under the provider's one-use nonce: the envelope the
	// broker relays unread, and what opens that call's answer.
	Seal(instanceKey []byte, nonce string, body []byte) ([]byte, InferProviderEnvelopeOpener, error)
}

// Opens one call's answer.
type InferProviderEnvelopeOpener interface {
	// The plaintext of the relayed answer, read as relayed arrives: its first frame (Chutes' e2e_init) and then each
	// chunk opened in order, a frame that does not open failing the read.
	Open(relayed io.Reader) (io.Reader, error)
}

// Builds a provider's half for one Sidecar's settings.
type InferProviderHalfConstructor func(settings *InferSettings) (InferProviderHalf, error)

// Every half's constructor, by slug.
var inferProviderHalfRegistrations = map[string]InferProviderHalfConstructor{}

// Registers provider's half, from an init function in its own file. A slug that is no provider's ([a-z0-9]+, and not
// local, which no remote path serves), a nil constructor and a second registration of one slug are build errors,
// which panic.
func registerInferProviderHalf(provider string, construct InferProviderHalfConstructor) {
	_, registered := inferProviderHalfRegistrations[provider]
	if !inferValidProvider(provider) || provider == computeLocalProvider || construct == nil || registered {
		panic(fmt.Sprintf("provider half %q registered twice, without a constructor, or for no remote provider", provider))
	}
	inferProviderHalfRegistrations[provider] = construct
}

// The half of provider, built for settings, or model_refused where this build has none for the slug or its
// constructor failed: a path asks for its entry's provider, and a slug no half serves is never called.
func inferProviderHalfFor(provider string, settings *InferSettings) (InferProviderHalf, error) {
	return inferProviderHalfIn(inferProviderHalfRegistrations, provider, settings)
}

// inferProviderHalfFor over registrations.
func inferProviderHalfIn(registrations map[string]InferProviderHalfConstructor, provider string, settings *InferSettings) (InferProviderHalf, error) {
	construct, registered := registrations[provider]
	if !registered {
		return nil, newInferError(InferErrorModelRefused, "this build reaches no provider %q", provider)
	}
	half, err := construct(settings)
	switch {
	case err != nil:
		return nil, newInferError(InferErrorModelRefused, "the %s provider's half did not build: %s", provider, err)
	case half == nil || half.Provider() != provider:
		return nil, newInferError(InferErrorModelRefused, "the %s provider's half did not build", provider)
	}
	return half, nil
}

// The provider's parameter for call's effort, by half's table: model_refused where the call's entry does not list the
// effort or the table lacks it, so the router never sends a model an effort it does not take (§6.4).
func inferProviderEffort(half InferProviderHalf, call *InferCall) (string, error) {
	if call == nil || call.Entry == nil || !slices.Contains(call.Entry.Efforts, call.Effort) {
		return "", newInferError(InferErrorModelRefused, "the model does not list the effort the call asks for")
	}
	parameter, ok := half.Efforts()[call.Effort]
	if !ok {
		return "", newInferError(InferErrorModelRefused, "the %s provider takes no %s effort", half.Provider(), call.Effort)
	}
	return parameter, nil
}

// The device's rule for a direct call's receipt (§6.6): its model one the policy's map gives the entry, the
// provider's id for it or an alias its gate recorded, and zero retention served where the map requires it. A receipt
// that fails is model_refused naming the receipt, never a warning; nil where it holds.
func inferProviderCheckReceiptModel(receipt *InferProviderReceipt, model *ComputePolicyDirectModel) error {
	switch {
	case receipt == nil || model == nil:
		return newInferError(InferErrorModelRefused, "the provider's receipt does not read against the policy's entry")
	case receipt.ServedModelId != model.ProviderModelId && !slices.Contains(model.Aliases, receipt.ServedModelId):
		return newInferError(InferErrorModelRefused, "the provider's receipt names a model the policy does not give %s", model.Model)
	case model.ZeroRetention && !receipt.ZeroRetention:
		return newInferError(InferErrorModelRefused, "the provider's receipt does not show zero retention, which the policy requires of %s", model.Model)
	}
	return nil
}
