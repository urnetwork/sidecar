//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// A resolved call of model, as the router hands an engine or a path one.
func testInferResolvedCall(t *testing.T, entry *InferCatalogEntry, effort InferEffort) *InferCall {
	t.Helper()
	return &InferCall{Entry: entry, Effort: effort, Name: entry.Name(effort)}
}

// A verified attestation of Chutes' AP model on profile chutes-tdx-7.
func testInferAttestation() *protocol.AttestationResult {
	return &protocol.AttestationResult{
		Provider:        "chutes",
		Label:           "AP",
		Scheme:          "chutes-e2e-v1",
		Cpu:             "tdx",
		ProfileId:       "chutes-tdx-7",
		ProfileReview:   "listed",
		PolicyVersion:   3,
		InstanceId:      "instance-1",
		ProviderModelId: "chute-qwen",
	}
}

// ModelCallBody carries §6.8's fields 11 to 14 at their numbers and types, record.proto importing attest.proto for the
// attestation, and leaves 15 to CTXH's CallContext.
func TestModelCallFieldsDescriptor(t *testing.T) {
	descriptor := (&protocol.ModelCallBody{}).ProtoReflect().Descriptor()
	fields := []struct {
		number  protoreflect.FieldNumber
		name    protoreflect.Name
		kind    protoreflect.Kind
		message protoreflect.FullName
	}{
		{number: 11, name: "attestation", kind: protoreflect.MessageKind, message: "urnetwork.sidecar.AttestationResult"},
		{number: 12, name: "route", kind: protoreflect.StringKind},
		{number: 13, name: "catalog_version", kind: protoreflect.Uint64Kind},
		{number: 14, name: "platform", kind: protoreflect.MessageKind, message: "urnetwork.sidecar.ModelField"},
	}
	for _, want := range fields {
		field := descriptor.Fields().ByNumber(want.number)
		if field == nil || field.Name() != want.name || field.Kind() != want.kind || field.Cardinality() == protoreflect.Repeated {
			t.Errorf("field %d: %v", want.number, field)
			continue
		}
		if want.message != "" && field.Message().FullName() != want.message {
			t.Errorf("field %d holds %s", want.number, field.Message().FullName())
		}
	}
	imports := descriptor.ParentFile().Imports()
	imported := false
	for i := 0; i < imports.Len(); i += 1 {
		imported = imported || imports.Get(i).Path() == "protocol/attest.proto"
	}
	if !imported {
		t.Error("record.proto does not import protocol/attest.proto")
	}
}

// A local call's receipt: route local, its tokens, no charge, no catalog version, no attestation and no platform.
func TestInferModelCallLocalRoute(t *testing.T) {
	local := &InferCatalogEntry{Provider: "local", Model: "gemma-4-e4b", Kind: InferCatalogKindLocal, Label: ComputeLabelLocal}
	started := time.Date(2027, time.March, 1, 12, 0, 0, 0, time.UTC)
	body, err := InferModelCall(&InferModelCallArgs{
		Call:           testInferResolvedCall(t, local, InferEffortOff),
		RequestId:      "local-1",
		Usage:          &InferUsage{InputTokens: 120, OutputTokens: 40, ChargeNanoUsd: 999},
		CatalogVersion: 7,
		StartedAt:      started,
		Duration:       1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if body.GetModel() != "local-gemma-4-e4b-off" || body.GetProvider() != "local" || body.GetRoute() != RecordModelCallRouteLocal {
		t.Errorf("body %v", body)
	}
	if body.GetInputTokens() != 120 || body.GetOutputTokens() != 40 || body.GetReportedMicroUsd() != 0 || body.GetCatalogVersion() != 0 {
		t.Errorf("a local call's usage or charge: %v", body)
	}
	if body.GetAttestation() != nil || body.GetPlatform() != nil {
		t.Errorf("a local call claims evidence: %v", body)
	}
	if body.GetStartedMillis() != started.UnixMilli() || body.GetDurationMillis() != 1500 {
		t.Errorf("times %d, %d", body.GetStartedMillis(), body.GetDurationMillis())
	}
}

// A direct call's receipt: route direct, the provider's usage, the charge in micro-USD rounded up, the catalog version
// it named, and no attestation: its label none is the route's.
func TestInferModelCallDirectRoute(t *testing.T) {
	direct := testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortOff, InferEffortHigh)
	body, err := InferModelCall(&InferModelCallArgs{
		Call:           testInferResolvedCall(t, direct, InferEffortHigh),
		RequestId:      "engy-req-1",
		Usage:          &InferUsage{InputTokens: 1000, OutputTokens: 200, CachedTokens: 300, ChargeNanoUsd: 1234567},
		CatalogVersion: 41,
	})
	if err != nil {
		t.Fatal(err)
	}
	if body.GetRoute() != RecordModelCallRouteDirect || body.GetModel() != "engy-glm-5.2-high" || body.GetCatalogVersion() != 41 {
		t.Errorf("body %v", body)
	}
	if body.GetReportedMicroUsd() != 1235 || body.GetCacheReadTokens() != 300 {
		t.Errorf("charge %d, cached %d", body.GetReportedMicroUsd(), body.GetCacheReadTokens())
	}
	if body.GetAttestation() != nil || body.GetPlatform() != nil {
		t.Errorf("a direct call claims evidence: %v", body)
	}
	if _, err := InferModelCall(&InferModelCallArgs{Call: testInferResolvedCall(t, direct, InferEffortOff), Attestation: testInferAttestation()}); !errors.Is(err, ErrInferModelCallInvalid) {
		t.Errorf("a direct call with an attestation: %v", err)
	}
}

// A TEE call's receipt: route tee, its attestation as verified, and the platform at evidence 4 naming the policy
// profile the TEE booted; a TEE call with no attestation is not recorded as one.
func TestInferModelCallTeeRoute(t *testing.T) {
	tee := testInferRemoteEntry("chutes", "qwen3.8-27b-tee", ComputeLabelAp, InferEffortHigh)
	attestation := testInferAttestation()
	body, err := InferModelCall(&InferModelCallArgs{
		Call:           testInferResolvedCall(t, tee, InferEffortHigh),
		RequestId:      "chutes-req-9",
		Usage:          &InferUsage{InputTokens: 10, OutputTokens: 5, ChargeNanoUsd: 3000},
		Attestation:    attestation,
		CatalogVersion: 41,
	})
	if err != nil {
		t.Fatal(err)
	}
	if body.GetRoute() != RecordModelCallRouteTee || !proto.Equal(body.GetAttestation(), attestation) {
		t.Errorf("body %v", body)
	}
	if platform := body.GetPlatform(); platform.GetValue() != "chutes-tdx-7" || platform.GetEvidence() != RecordModelEvidenceAttested {
		t.Errorf("platform %v", platform)
	}
	attestation.ProfileId = "changed"
	if body.GetAttestation().GetProfileId() != "chutes-tdx-7" {
		t.Error("the body shares the caller's attestation")
	}
	if err := RecordBodyValidate(RecordKindModelCall, body); err != nil {
		t.Errorf("the body breaks the rule: %v", err)
	}
	if _, err := InferModelCall(&InferModelCallArgs{Call: testInferResolvedCall(t, tee, InferEffortHigh)}); !errors.Is(err, ErrInferModelCallInvalid) {
		t.Errorf("a TEE call with no attestation: %v", err)
	}
}

// The platform field at evidence 4 needs the TEE route, an attestation, and the attestation's profile as its value; a
// body that claims it any other way is refused, on write and on read, so weaker evidence is never presented as attested
// (D-RECORD-11).
func TestModelCallPlatformEvidenceFourRequiresAttestation(t *testing.T) {
	attested := func(value string) *protocol.ModelField {
		return &protocol.ModelField{Value: value, Evidence: RecordModelEvidenceAttested}
	}
	refused := []struct {
		why  string
		body *protocol.ModelCallBody
	}{
		{why: "attested with no attestation", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteTee, Platform: attested("chutes-tdx-7")}},
		{why: "attested on the direct route", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteDirect, Platform: attested("chutes-tdx-7"), Attestation: testInferAttestation()}},
		{why: "attested on the local route", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteLocal, Platform: attested("chutes-tdx-7"), Attestation: testInferAttestation()}},
		{why: "attested naming another profile", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteTee, Platform: attested("chutes-tdx-8"), Attestation: testInferAttestation()}},
		{why: "attested with no route", body: &protocol.ModelCallBody{Model: "m", Platform: attested("chutes-tdx-7"), Attestation: testInferAttestation()}},
		{why: "an attestation on the direct route", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteDirect, Attestation: testInferAttestation()}},
		{why: "measured", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteTee, Platform: &protocol.ModelField{Value: "chutes-tdx-7", Evidence: RecordModelEvidenceMeasured}, Attestation: testInferAttestation()}},
		{why: "no evidence", body: &protocol.ModelCallBody{Model: "m", Route: RecordModelCallRouteTee, Platform: &protocol.ModelField{Value: "chutes-tdx-7"}, Attestation: testInferAttestation()}},
		{why: "an unknown route", body: &protocol.ModelCallBody{Model: "m", Route: "cloud"}},
		{why: "a model past its bytes", body: &protocol.ModelCallBody{Model: strings.Repeat("m", 129)}},
	}
	for _, c := range refused {
		if err := RecordBodyValidate(RecordKindModelCall, c.body); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("%s: %v", c.why, err)
		}
	}
	passed := []*protocol.ModelCallBody{
		{Model: "sonnet", Provider: "anthropic", RequestId: "req-1"},
		{Model: "m", Route: RecordModelCallRouteTee, Platform: attested("chutes-tdx-7"), Attestation: testInferAttestation()},
		{Model: "m", Route: RecordModelCallRouteTee, Platform: &protocol.ModelField{Value: "chutes-tdx-7", Evidence: RecordModelEvidenceReported}, Attestation: testInferAttestation()},
		{Model: "m", Route: RecordModelCallRouteDirect, CatalogVersion: 2},
	}
	for _, body := range passed {
		if err := RecordBodyValidate(RecordKindModelCall, body); err != nil {
			t.Errorf("%v: %v", body, err)
		}
	}
}

// Nothing but the platform is ever attested: the model stays as the provider names it, the builder writes the profile
// on the platform and never the model, and a platform attested naming the model rather than the profile is refused.
func TestModelCallModelFieldNeverAttested(t *testing.T) {
	tee := testInferRemoteEntry("chutes", "qwen3.8-27b-tee", ComputeLabelAp, InferEffortHigh)
	body, err := InferModelCall(&InferModelCallArgs{Call: testInferResolvedCall(t, tee, InferEffortHigh), Attestation: testInferAttestation()})
	if err != nil {
		t.Fatal(err)
	}
	if body.GetPlatform().GetValue() == body.GetModel() || body.GetPlatform().GetValue() != testInferAttestation().GetProfileId() {
		t.Errorf("the platform names %q", body.GetPlatform().GetValue())
	}
	attestedModel := proto.Clone(body).(*protocol.ModelCallBody)
	attestedModel.Platform = &protocol.ModelField{Value: attestedModel.GetModel(), Evidence: RecordModelEvidenceAttested}
	if err := RecordBodyValidate(RecordKindModelCall, attestedModel); !errors.Is(err, ErrRecordBodyOverCap) {
		t.Errorf("the model attested: %v", err)
	}
}

// The run's cost sums tokens and the reported amount by model, whatever fields 11 to 14 hold.
func TestRunCostUnchangedByNewFields(t *testing.T) {
	plain := []*protocol.ModelCallBody{
		{Model: "chutes-qwen3.8-27b-tee-high", InputTokens: 100, OutputTokens: 20, CacheReadTokens: 5, ReportedMicroUsd: 1500},
		{Model: "local-gemma-4-e4b-off", InputTokens: 7, OutputTokens: 3},
		{Model: "chutes-qwen3.8-27b-tee-high", InputTokens: 50, OutputTokens: 10, ReportedMicroUsd: 700},
	}
	extended := []*protocol.ModelCallBody{}
	for _, call := range plain {
		call := proto.Clone(call).(*protocol.ModelCallBody)
		call.Route = RecordModelCallRouteTee
		call.CatalogVersion = 9
		call.Attestation = testInferAttestation()
		call.Platform = &protocol.ModelField{Value: "chutes-tdx-7", Evidence: RecordModelEvidenceAttested}
		extended = append(extended, call)
	}
	sum := func(calls []*protocol.ModelCallBody) []*RecordRunCostUsage {
		cost := &RecordRunCost{}
		for _, call := range calls {
			cost.AddCall(call, nil)
		}
		return cost.Usage
	}
	if !slices.EqualFunc(sum(plain), sum(extended), func(a *RecordRunCostUsage, b *RecordRunCostUsage) bool { return *a == *b }) {
		t.Errorf("plain %v, extended %v", sum(plain), sum(extended))
	}
}
