//go:build !ios_extension && !sidecar_http && !js

// The policy pipeline (ATTEST-M12-02): a policy built from the one before it and a change set, held to the pipeline's
// rules and taken by the devices' own verifier once the test compute-policy key signs it; each refusal the plan names
// in its own test; the canonical bytes; a sitting's batches, plain and a revocation's; the staging policy under its
// own namespace; the horizon; the signer's checks; and the support line, kept verbatim and read from the store. Off
// the js test leg, as the store's tests are, since the store's case reads a Sidecar fixture.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A builder pinning the test release key, on a clock at at.
func newTestAttestBuilder(t *testing.T, staging bool, at time.Time) (*ComputePolicyBuilder, *testAttestKeys, *testAttestClock) {
	t.Helper()
	keys := newTestAttestKeys(t)
	clock := newTestAttestClock(at)
	builder := NewComputePolicyBuilder(&ComputePolicyBuilderArgs{
		Staging:     staging,
		ReleaseKeys: []ssh.PublicKey{keys.release.PublicKey()},
		Clock:       clock,
	})
	return builder, keys, clock
}

// The certificate a test signer carries.
func testAttestCertificateOf(t *testing.T, signer ssh.Signer) *ssh.Certificate {
	t.Helper()
	certificate, ok := signer.PublicKey().(*ssh.Certificate)
	if !ok {
		t.Fatal("the signer carries no certificate")
	}
	return certificate
}

// A TDX profile of id, every register synthetic, expiring a year after testAttestNow, with review.
func testAttestBuildProfile(id string, review string, listSha256 string) *ComputePolicyProfile {
	register := strings.Repeat("ab", 48)
	return &ComputePolicyProfile{
		Id:               id,
		GuestVersion:     "test-1",
		Cpu:              ComputePolicyCpuTdx,
		Mrtd:             register,
		Rtmr0:            register,
		Rtmr1:            register,
		Rtmr2:            register,
		Rtmr3:            register,
		ExpiresMs:        testAttestNow.AddDate(1, 0, 0).UnixMilli(),
		Replayed:         []*ComputePolicyReplayed{},
		Review:           review,
		ReviewListSha256: listSha256,
	}
}

// A disclosure of id at version and revision with grace, its English text naming words.
func testAttestBuildDisclosure(id string, version uint32, revision uint32, grace uint32, words string) *ComputePolicyDisclosure {
	return &ComputePolicyDisclosure{
		Id:        id,
		Version:   version,
		Revision:  revision,
		GraceDays: grace,
		Locales: []*ComputePolicyDisclosureText{{
			Locale:  "en",
			Summary: "Synthetic test text, " + words + ".",
			Exposed: []string{"What could be exposed, " + words + "."},
			Private: []string{"What stays private, " + words + "."},
		}},
	}
}

// The support line the tests sign: a synthetic host and one subprocessor.
const testAttestSupportLine = `{"host": "feedback.test.example", "subprocessors": [{"name": "Test triage", "purpose": "reads support's entries for triage", "retention": "30 days"}]}`

// The first policy's change set: a TEE provider with a model and a reproduced profile, a direct provider, two
// disclosures, the support line and the TCB rules.
func testAttestFirstChanges() *ComputePolicyChangeSet {
	return &ComputePolicyChangeSet{
		Roots: &ComputePolicyRoots{IntelSgx: []string{strings.Repeat("01", 32)}},
		Tcb: &ComputePolicyTcb{
			Tdx: ComputePolicyTdxTcb{Statuses: []string{ComputePolicyTdxUpToDate}, MinTcbEvaluationDataNumber: 17},
		},
		Providers: []*ComputePolicyProvider{{
			Id:       "teetest",
			Cpus:     []string{ComputePolicyCpuTdx},
			Schemes:  []string{ComputePolicySchemeChutesE2e},
			Label:    ComputeLabelAp,
			Models:   []*ComputePolicyModel{{Model: "test-model-27b", ProviderModelId: "chute-test-0001"}},
			Profiles: []*ComputePolicyProfile{testAttestBuildProfile("teetest-2026.12.1", ComputePolicyReviewReproduced, "")},
		}},
		Direct: &ComputePolicyDirectLine{
			Providers: []*ComputePolicyDirect{{
				Slug:           "directtest",
				ApiHost:        "api.directtest.example",
				ReceiverHotkey: "5Ctestreceiver",
				Netuid:         4201,
				Targets:        []*ComputePolicyDirectTarget{{Method: "POST", Path: "/v1/chat/completions"}},
				Models:         []*ComputePolicyDirectModel{{Model: "test-model-35b", ProviderModelId: "test/test-model-35b", ZeroRetention: true}},
			}},
			LimitedUse: []string{"teetest-test-model-27b"},
		},
		Support: json.RawMessage(testAttestSupportLine),
		Disclosures: []*ComputePolicyDisclosureChange{
			{Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("inference:teetest", 1, 0, 14, "teetest one")},
			{Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("support:urnetwork", 1, 0, 0, "support one")},
		},
	}
}

// The first policy, built at the builder's clock.
func testAttestBuildFirst(t *testing.T, builder *ComputePolicyBuilder) *ComputePolicyBuild {
	t.Helper()
	build, err := builder.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges()})
	if err != nil {
		t.Fatal(err)
	}
	return build
}

// A refusal for reason, wrapped in ErrComputePolicyBuildRefused.
func testAttestWantBuildRefused(t *testing.T, name string, err error, reason error) {
	t.Helper()
	if !errors.Is(err, ErrComputePolicyBuildRefused) || !errors.Is(err, reason) {
		t.Errorf("%s: %v; want a build refusal for %v", name, err, reason)
	}
}

// A first policy built from a change set is one the devices' own verifier takes once the certified test key signs it,
// with what the change set put, each new disclosure version in effect from the signing, and the support line as its
// client reads it.
func TestPolicyBuilderBuildsWhatADeviceTakes(t *testing.T) {
	builder, keys, _ := newTestAttestBuilder(t, false, testAttestNow)
	build := testAttestBuildFirst(t, builder)
	signature := testAttestSign(t, keys.policy, ComputePolicyNamespace, build.Document)
	policy, err := builder.Verify(build.Document, signature, testAttestCertificateOf(t, keys.policy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.verifier(false).Verify(build.Document, signature, testAttestNow); err != nil {
		t.Fatalf("a device's verifier: %v", err)
	}
	if policy.Version != 1 || !policy.NotAfter().Equal(testAttestNow.Add(90*24*time.Hour)) {
		t.Errorf("version %d, not_after %s", policy.Version, policy.NotAfter())
	}
	tee := policy.Provider("teetest")
	if tee == nil || tee.ProviderModelId("test-model-27b") != "chute-test-0001" || tee.Profile("teetest-2026.12.1") == nil {
		t.Errorf("teetest %+v", tee)
	}
	if !policy.LimitedUse("teetest", "test-model-27b") || policy.DirectProvider("directtest") == nil {
		t.Error("the direct line is not as put")
	}
	disclosure := policy.Disclosure("inference:teetest")
	if disclosure == nil || disclosure.Version != 1 || disclosure.SinceMs != testAttestNow.UnixMilli() {
		t.Errorf("disclosure %+v", disclosure)
	}
	line, err := ParseSupportPolicyLine(policy.Support)
	if err != nil || line.Host != "feedback.test.example" || len(line.Subprocessors) != 1 {
		t.Errorf("support line %+v, %v", line, err)
	}
	if len(build.Changes) < 6 || !strings.Contains(strings.Join(build.Changes, "\n"), "provider teetest added whole") {
		t.Errorf("the changes listed: %q", build.Changes)
	}
}

// A version not above the policy before it is refused; with none given, the one after it is built.
func TestPolicyBuilderRefusesLowerVersion(t *testing.T) {
	builder, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	first := testAttestBuildFirst(t, builder)
	_, err := builder.Build(&ComputePolicyBuildArgs{Previous: first.Policy, Version: 1})
	testAttestWantBuildRefused(t, "the same version", err, errComputePolicyBuildVersion)
	next, err := builder.Build(&ComputePolicyBuildArgs{Previous: first.Policy})
	if err != nil || next.Policy.Version != 2 {
		t.Fatalf("the next version: %v, %v", next, err)
	}
	_, err = builder.Build(&ComputePolicyBuildArgs{Previous: next.Policy, Version: 1})
	testAttestWantBuildRefused(t, "a lower version", err, errComputePolicyBuildVersion)
	if skipped, err := builder.Build(&ComputePolicyBuildArgs{Previous: next.Policy, Version: 5}); err != nil || skipped.Policy.Version != 5 {
		t.Errorf("a higher version: %v, %v", skipped, err)
	}
}

// A profile without a review record is refused, put alone or with its provider whole: no review, listed without its
// list's SHA-256, and reproduced naming a list; listed with its list's SHA-256 is taken.
func TestPolicyBuilderRefusesUnreviewedProfile(t *testing.T) {
	builder, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	first := testAttestBuildFirst(t, builder)
	listSha256 := strings.Repeat("cd", 32)
	cases := []struct {
		name    string
		profile *ComputePolicyProfile
	}{
		{name: "no review", profile: testAttestBuildProfile("teetest-2026.12.2", "", "")},
		{name: "listed without its list", profile: testAttestBuildProfile("teetest-2026.12.2", ComputePolicyReviewListed, "")},
		{name: "listed with a list that is no hash", profile: testAttestBuildProfile("teetest-2026.12.2", ComputePolicyReviewListed, "a-list")},
		{name: "reproduced naming a list", profile: testAttestBuildProfile("teetest-2026.12.2", ComputePolicyReviewReproduced, listSha256)},
	}
	for _, c := range cases {
		_, err := builder.Build(&ComputePolicyBuildArgs{
			Previous: first.Policy,
			Changes:  &ComputePolicyChangeSet{Profiles: []*ComputePolicyProfileChange{{Provider: "teetest", Profile: c.profile}}},
		})
		testAttestWantBuildRefused(t, c.name, err, errComputePolicyBuildReview)
		provider := testAttestFirstChanges().Providers[0]
		provider.Profiles = append(provider.Profiles, c.profile)
		_, err = builder.Build(&ComputePolicyBuildArgs{
			Previous: first.Policy,
			Changes:  &ComputePolicyChangeSet{Providers: []*ComputePolicyProvider{provider}},
		})
		testAttestWantBuildRefused(t, c.name+", its provider put whole", err, errComputePolicyBuildReview)
	}
	listed, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: first.Policy,
		Changes: &ComputePolicyChangeSet{Profiles: []*ComputePolicyProfileChange{{
			Provider: "teetest",
			Profile:  testAttestBuildProfile("teetest-2026.12.2", ComputePolicyReviewListed, listSha256),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := listed.Policy.Provider("teetest").Profile("teetest-2026.12.2")
	if profile == nil || profile.Review != ComputePolicyReviewListed || profile.ReviewListSha256 != listSha256 {
		t.Errorf("the listed profile %+v", profile)
	}
}

// A disclosure whose fact changed keeps no version it had: a fact change at the same version is refused, as is one
// past the next version or not at revision 0; a change of words alone may not raise the version, change the grace,
// skip a revision or change no word; a new disclosure is a fact at version 1. The changes that follow the rules are
// taken, a fact's version in effect from the signing and a revision keeping its version's instant.
func TestPolicyBuilderRefusesChangedFactWithoutVersion(t *testing.T) {
	builder, _, clock := newTestAttestBuilder(t, false, testAttestNow)
	first := testAttestBuildFirst(t, builder)
	refused := []struct {
		name   string
		change *ComputePolicyDisclosureChange
	}{
		{name: "a fact at the same version", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("inference:teetest", 1, 0, 14, "teetest changed")}},
		{name: "a fact past the next version", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("inference:teetest", 3, 0, 14, "teetest changed")}},
		{name: "a fact not at revision 0", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("inference:teetest", 2, 1, 14, "teetest changed")}},
		{name: "words raising the version", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("inference:teetest", 2, 0, 14, "teetest clearer")}},
		{name: "words changing the grace", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("inference:teetest", 1, 1, 0, "teetest clearer")}},
		{name: "words skipping a revision", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("inference:teetest", 1, 2, 14, "teetest clearer")}},
		{name: "words changing no word", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("inference:teetest", 1, 1, 14, "teetest one")}},
		{name: "a new disclosure as words", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("enclave:teetest", 1, 0, 14, "enclave one")}},
		{name: "a new disclosure past version 1", change: &ComputePolicyDisclosureChange{
			Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("enclave:teetest", 2, 0, 14, "enclave one")}},
	}
	for _, c := range refused {
		_, err := builder.Build(&ComputePolicyBuildArgs{
			Previous: first.Policy,
			Changes:  &ComputePolicyChangeSet{Disclosures: []*ComputePolicyDisclosureChange{c.change}},
		})
		testAttestWantBuildRefused(t, c.name, err, errComputePolicyBuildDisclosure)
	}
	since := testAttestBuildDisclosure("inference:teetest", 2, 0, 14, "teetest changed")
	since.SinceMs = testAttestNow.UnixMilli()
	_, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: first.Policy,
		Changes:  &ComputePolicyChangeSet{Disclosures: []*ComputePolicyDisclosureChange{{Change: ComputePolicyDisclosureFact, Disclosure: since}}},
	})
	testAttestWantBuildRefused(t, "a change setting since_ms", err, errComputePolicyBuildDisclosure)

	sitting := testAttestNow.Add(7 * 24 * time.Hour)
	clock.Set(sitting)
	fact, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: first.Policy,
		Changes: &ComputePolicyChangeSet{Disclosures: []*ComputePolicyDisclosureChange{{
			Change: ComputePolicyDisclosureFact, Disclosure: testAttestBuildDisclosure("inference:teetest", 2, 0, 0, "teetest changed"),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if disclosure := fact.Policy.Disclosure("inference:teetest"); disclosure.Version != 2 || disclosure.GraceDays != 0 || disclosure.SinceMs != sitting.UnixMilli() {
		t.Errorf("the new version %+v", disclosure)
	}
	clock.Set(sitting.Add(7 * 24 * time.Hour))
	words, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: fact.Policy,
		Changes: &ComputePolicyChangeSet{Disclosures: []*ComputePolicyDisclosureChange{{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("inference:teetest", 2, 1, 0, "teetest clearer"),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if disclosure := words.Policy.Disclosure("inference:teetest"); disclosure.Version != 2 || disclosure.Revision != 1 || disclosure.SinceMs != sitting.UnixMilli() {
		t.Errorf("the revision %+v", disclosure)
	}
	if disclosure := words.Policy.Disclosure("support:urnetwork"); disclosure.Version != 1 || disclosure.SinceMs != testAttestNow.UnixMilli() {
		t.Errorf("a disclosure no change named moved: %+v", disclosure)
	}
}

// not_after past 90 days from the signing is refused, as is one at or before it; at 90 days it is taken, and with
// none given it is 90 days. The staging policy's bound is 7 days.
func TestPolicyBuilderRefusesNotAfterPastNinetyDays(t *testing.T) {
	builder, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	refused := []time.Time{
		testAttestNow.Add(90*24*time.Hour + time.Millisecond),
		testAttestNow.AddDate(1, 0, 0),
		testAttestNow,
		testAttestNow.Add(-time.Hour),
	}
	for _, notAfter := range refused {
		_, err := builder.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges(), NotAfter: notAfter})
		testAttestWantBuildRefused(t, notAfter.Format(time.RFC3339Nano), err, errComputePolicyBuildNotAfter)
	}
	at, err := builder.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges(), NotAfter: testAttestNow.Add(90 * 24 * time.Hour)})
	if err != nil || !at.Policy.NotAfter().Equal(testAttestNow.Add(90*24*time.Hour)) {
		t.Fatalf("at 90 days: %v, %v", at, err)
	}
	earlier, err := builder.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges(), NotAfter: testAttestNow.Add(30 * 24 * time.Hour)})
	if err != nil || !earlier.Policy.NotAfter().Equal(testAttestNow.Add(30*24*time.Hour)) {
		t.Fatalf("at 30 days: %v, %v", earlier, err)
	}

	staging, _, _ := newTestAttestBuilder(t, true, testAttestNow)
	_, err = staging.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges(), NotAfter: testAttestNow.Add(7*24*time.Hour + time.Millisecond)})
	testAttestWantBuildRefused(t, "staging past 7 days", err, errComputePolicyBuildNotAfter)
	weekly, err := staging.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges()})
	if err != nil || !weekly.Policy.NotAfter().Equal(testAttestNow.Add(7*24*time.Hour)) {
		t.Fatalf("the staging policy's default: %v, %v", weekly, err)
	}
}

// A change set's every kind applies to the policy before it: a listed profile, a model id replaced and one added, the
// direct line, the search and services lines, custody, revocations; then removals, a line withdrawn and a revocation
// withdrawn. What does not apply is refused: a removal of what is not there, a key named twice or both put and
// removed, a profile or model under a provider not there, and a revocation already in force.
func TestPolicyBuilderAppliesChanges(t *testing.T) {
	builder, keys, _ := newTestAttestBuilder(t, false, testAttestNow)
	first := testAttestBuildFirst(t, builder)
	chip := &ComputePolicyChip{Kind: ComputePolicyChipIntelPpid, Id: strings.Repeat("ef", 16)}
	listSha256 := strings.Repeat("cd", 32)
	second, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: first.Policy,
		Changes: &ComputePolicyChangeSet{
			Profiles: []*ComputePolicyProfileChange{{
				Provider: "teetest",
				Profile:  testAttestBuildProfile("teetest-2026.12.2", ComputePolicyReviewListed, listSha256),
			}},
			Models: []*ComputePolicyModelChange{
				{Provider: "teetest", Model: "test-model-27b", ProviderModelId: "chute-test-0002"},
				{Provider: "teetest", Model: "test-model-70b", ProviderModelId: "chute-test-0003"},
			},
			Search:   json.RawMessage(`{"host": "search.test.example", "ceiling_nano_usd": 15000000}`),
			Services: json.RawMessage(`[{"service": "test", "hosts": ["issuer.test.example"]}]`),
			Custody:  []*ComputePolicyCustody{{Provider: "teetest", Registry: "test-registry", Chips: []*ComputePolicyChip{chip}}},
			Revoke: &ComputePolicyRevoked{
				Profiles:   []string{"teetest-2026.12.1"},
				Chips:      []*ComputePolicyChip{chip},
				GpuSerials: []string{"TEST-GPU-0001"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := second.Policy
	tee := policy.Provider("teetest")
	if tee.Profile("teetest-2026.12.2") == nil || tee.Profile("teetest-2026.12.1") == nil || tee.ProviderModelId("test-model-27b") != "chute-test-0002" ||
		tee.ProviderModelId("test-model-70b") != "chute-test-0003" {
		t.Errorf("teetest %+v", tee)
	}
	if !policy.ProfileRevoked("teetest-2026.12.1") || !policy.ChipRevoked(chip.Kind, chip.Id) || !policy.GpuSerialRevoked("TEST-GPU-0001") {
		t.Error("the revocations are not in force")
	}
	if len(policy.Custody) != 1 || policy.Search == nil || policy.Services == nil || policy.Support == nil {
		t.Errorf("custody %d, search %q, services %q, support %q", len(policy.Custody), policy.Search, policy.Services, policy.Support)
	}
	signature := testAttestSign(t, keys.policy, ComputePolicyNamespace, second.Document)
	if _, err := keys.verifier(false).Verify(second.Document, signature, testAttestNow); err != nil {
		t.Fatalf("a device's verifier: %v", err)
	}

	third, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: policy,
		Changes: &ComputePolicyChangeSet{Remove: &ComputePolicyRemovals{
			Profiles:    []string{"teetest-2026.12.1"},
			Models:      []*ComputePolicyModelRef{{Provider: "teetest", Model: "test-model-70b"}},
			Disclosures: []string{"inference:teetest"},
			Custody:     []string{"teetest"},
			Search:      true,
			Revoked:     &ComputePolicyRevoked{GpuSerials: []string{"TEST-GPU-0001"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy = third.Policy
	if policy.Provider("teetest").Profile("teetest-2026.12.1") != nil || policy.Provider("teetest").ProviderModelId("test-model-70b") != "" ||
		policy.Disclosure("inference:teetest") != nil || len(policy.Custody) != 0 || policy.Search != nil || policy.Services == nil ||
		policy.GpuSerialRevoked("TEST-GPU-0001") || !policy.ProfileRevoked("teetest-2026.12.1") {
		t.Errorf("after the removals: %s", third.Document)
	}

	refused := []struct {
		name    string
		changes *ComputePolicyChangeSet
	}{
		{name: "a provider not there removed", changes: &ComputePolicyChangeSet{Remove: &ComputePolicyRemovals{Providers: []string{"absent"}}}},
		{name: "a profile not there removed", changes: &ComputePolicyChangeSet{Remove: &ComputePolicyRemovals{Profiles: []string{"absent"}}}},
		{name: "a line not there removed", changes: &ComputePolicyChangeSet{Remove: &ComputePolicyRemovals{Search: true}}},
		{name: "a revocation not in force withdrawn", changes: &ComputePolicyChangeSet{Remove: &ComputePolicyRemovals{Revoked: &ComputePolicyRevoked{Profiles: []string{"absent"}}}}},
		{name: "a profile under a provider not there", changes: &ComputePolicyChangeSet{Profiles: []*ComputePolicyProfileChange{{
			Provider: "absent", Profile: testAttestBuildProfile("absent-1", ComputePolicyReviewReproduced, "")}}}},
		{name: "a model under a provider not there", changes: &ComputePolicyChangeSet{Models: []*ComputePolicyModelChange{{
			Provider: "absent", Model: "test-model-27b", ProviderModelId: "chute-test-0009"}}}},
		{name: "a profile put twice", changes: &ComputePolicyChangeSet{Profiles: []*ComputePolicyProfileChange{
			{Provider: "teetest", Profile: testAttestBuildProfile("teetest-2026.12.3", ComputePolicyReviewReproduced, "")},
			{Provider: "teetest", Profile: testAttestBuildProfile("teetest-2026.12.3", ComputePolicyReviewReproduced, "")},
		}}},
		{name: "a profile put and removed", changes: &ComputePolicyChangeSet{
			Profiles: []*ComputePolicyProfileChange{{Provider: "teetest", Profile: testAttestBuildProfile("teetest-2026.12.2", ComputePolicyReviewReproduced, "")}},
			Remove:   &ComputePolicyRemovals{Profiles: []string{"teetest-2026.12.2"}},
		}},
		{name: "a line put and removed", changes: &ComputePolicyChangeSet{
			Services: json.RawMessage(`[]`),
			Remove:   &ComputePolicyRemovals{Services: true},
		}},
		{name: "a revocation already in force", changes: &ComputePolicyChangeSet{Revoke: &ComputePolicyRevoked{Profiles: []string{"teetest-2026.12.1"}}}},
	}
	for _, c := range refused {
		_, err := builder.Build(&ComputePolicyBuildArgs{Previous: policy, Changes: c.changes})
		testAttestWantBuildRefused(t, c.name, err, errComputePolicyBuildChange)
	}
	// what the devices' parse refuses is refused, never written: a model's provider id empty
	_, err = builder.Build(&ComputePolicyBuildArgs{
		Previous: policy,
		Changes:  &ComputePolicyChangeSet{Models: []*ComputePolicyModelChange{{Provider: "teetest", Model: "test-model-27b"}}},
	})
	testAttestWantBuildRefused(t, "a model with no provider id", err, errComputePolicyBuildFormat)
	if !errors.Is(err, ErrComputePolicyRefused) {
		t.Errorf("the device's refusal is not carried: %v", err)
	}
}

// One content has one form: the same build twice gives the same bytes, a raw line written with other spacing gives
// the same bytes, the bytes parse back to a policy whose rebuild is themselves, every list is written [] where empty,
// and the document ends with one newline.
func TestPolicyBuilderBytesAreCanonical(t *testing.T) {
	builder, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	first := testAttestBuildFirst(t, builder)
	again := testAttestBuildFirst(t, builder)
	if !bytes.Equal(first.Document, again.Document) {
		t.Error("the same build gave other bytes")
	}
	spaced := testAttestFirstChanges()
	spaced.Support = json.RawMessage("{\n\"host\":\"feedback.test.example\" ,  \"subprocessors\":[{\"name\":\"Test triage\",\"purpose\":\"reads support's entries for triage\",\"retention\":\"30 days\"}]}")
	respaced, err := builder.Build(&ComputePolicyBuildArgs{Changes: spaced})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Document, respaced.Document) {
		t.Errorf("a raw line's spacing changed the bytes:\n%s\n%s", first.Document, respaced.Document)
	}
	rebuilt, err := computePolicyCanonical(first.Policy)
	if err != nil || !bytes.Equal(rebuilt, first.Document) {
		t.Errorf("the parsed policy's rebuild differs: %v", err)
	}
	if !bytes.HasSuffix(first.Document, []byte("}\n")) || bytes.HasSuffix(first.Document, []byte("\n\n")) || bytes.Contains(first.Document, []byte("null")) {
		t.Errorf("the document's form:\n%s", first.Document)
	}
	if !bytes.Contains(first.Document, []byte(`"custody": []`)) || !bytes.Contains(first.Document, []byte(`"gpu_serials": []`)) {
		t.Errorf("an empty list is not written []:\n%s", first.Document)
	}
	if bytes.Contains(first.Document, []byte(`"search"`)) || bytes.Contains(first.Document, []byte(`"services"`)) {
		t.Error("a raw line the policy does not carry is written")
	}
	escaped, err := builder.Build(&ComputePolicyBuildArgs{
		Previous: first.Policy,
		Changes: &ComputePolicyChangeSet{Disclosures: []*ComputePolicyDisclosureChange{{
			Change: ComputePolicyDisclosureWords, Disclosure: testAttestBuildDisclosure("inference:teetest", 1, 1, 14, "teetest <one> & more"),
		}}},
	})
	if err != nil || !bytes.Contains(escaped.Document, []byte("teetest <one> & more")) {
		t.Errorf("HTML escaping in the bytes: %v", err)
	}
}

// The support line is one support's client reads, or it is refused: no host, and a member the line does not declare.
func TestPolicyBuilderRefusesASupportLineItsClientCannotRead(t *testing.T) {
	builder, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	for _, line := range []string{
		`{"subprocessors": []}`,
		`{"host": "feedback.test.example", "subprocessors": [], "other": 1}`,
		`{"host": "Not A Host"}`,
	} {
		changes := testAttestFirstChanges()
		changes.Support = json.RawMessage(line)
		_, err := builder.Build(&ComputePolicyBuildArgs{Changes: changes})
		testAttestWantBuildRefused(t, line, err, errComputePolicyBuildFormat)
	}
}

// A change set's JSON is read as strictly as the policy: an unknown member, one written twice and a null are refused.
func TestComputePolicyChangeSetParsesStrictly(t *testing.T) {
	good := `{"profiles": [{"provider": "teetest", "profile": {"id": "teetest-2026.12.2", "review": "reproduced"}}],
	          "remove": {"search": true}, "support": {"host": "feedback.test.example"}}`
	changes, err := ParseComputePolicyChangeSet([]byte(good), nil)
	if err != nil || len(changes.Profiles) != 1 || !changes.Remove.Search || len(changes.Support) == 0 {
		t.Fatalf("%+v, %v", changes, err)
	}
	for _, bad := range []string{
		`{"profiles": [], "other": 1}`,
		`{"remove": {"search": true, "search": false}}`,
		`{"roots": null}`,
		`{"profiles": [{"provider": "teetest", "profile": {"id": "x", "expires_ms": 1.5}}]}`,
		`{} {}`,
	} {
		if _, err := ParseComputePolicyChangeSet([]byte(bad), nil); !errors.Is(err, ErrComputePolicyBuildRefused) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// A signing certificate is taken only where a device would take what it signs: a user certificate the pinned test
// release key signed for this namespace, valid until the document's end. A bare key, a private key's file, another
// namespace's certificate, one ending first, and any with no release key pinned, this build's own case, are refused.
func TestPolicyBuilderSignerRefusesWhatADeviceWouldNot(t *testing.T) {
	builder, keys, _ := newTestAttestBuilder(t, false, testAttestNow)
	policyLine := ssh.MarshalAuthorizedKey(keys.policy.PublicKey())
	certificate, err := builder.Signer(policyLine, testAttestNow.Add(90*24*time.Hour))
	if err != nil || certificate.ValidPrincipals[0] != ComputePolicyNamespace {
		t.Fatalf("the compute-policy key's certificate: %v", err)
	}
	_, validBefore := testAttestGoodWindow()
	refused := []struct {
		name  string
		line  []byte
		until time.Time
	}{
		{name: "a bare key", line: ssh.MarshalAuthorizedKey(keys.policyKey.PublicKey()), until: testAttestNow},
		{name: "a private key's file", line: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), until: testAttestNow},
		{name: "the staging key's certificate", line: ssh.MarshalAuthorizedKey(keys.staging.PublicKey()), until: testAttestNow},
		{name: "a certificate ending first", line: policyLine, until: validBefore.Add(time.Second)},
	}
	for _, c := range refused {
		_, err := builder.Signer(c.line, c.until)
		testAttestWantBuildRefused(t, c.name, err, errComputePolicyBuildSigner)
	}
	for _, releaseKeys := range [][]ssh.PublicKey{{}, nil} {
		unpinned := NewComputePolicyBuilder(&ComputePolicyBuilderArgs{ReleaseKeys: releaseKeys, Clock: newTestAttestClock(testAttestNow)})
		_, err := unpinned.Signer(policyLine, testAttestNow)
		if !errors.Is(err, errComputePolicyNoRoot) {
			t.Errorf("no release key pinned (%v): %v", releaseKeys, err)
		}
	}
}

// What comes back from signing is checked as a device checks it and for the certificate named: a signature by
// another certified key, or under another namespace, is refused; a document past its bounds is not signable.
func TestPolicyBuilderVerifyNamesItsSigner(t *testing.T) {
	builder, keys, clock := newTestAttestBuilder(t, false, testAttestNow)
	build := testAttestBuildFirst(t, builder)
	if _, err := builder.CheckSignable(build.Document); err != nil {
		t.Fatal(err)
	}
	validAfter, validBefore := testAttestGoodWindow()
	other := testAttestCertify(t, testAttestKey(t, "other compute policy"), keys.release, testAttestCertificate{
		principals: []string{ComputePolicyNamespace}, validAfter: validAfter, validBefore: validBefore,
	})
	signature := testAttestSign(t, other, ComputePolicyNamespace, build.Document)
	if _, err := builder.Verify(build.Document, signature, nil); err != nil {
		t.Fatalf("any certified key, as a device takes it: %v", err)
	}
	_, err := builder.Verify(build.Document, signature, testAttestCertificateOf(t, keys.policy))
	testAttestWantBuildRefused(t, "another certified key", err, errComputePolicyBuildSigner)
	_, err = builder.Verify(build.Document, testAttestSign(t, keys.policy, ComputePolicyStagingNamespace, build.Document), nil)
	if !errors.Is(err, ErrComputePolicyRefused) || !errors.Is(err, errComputePolicyNamespace) {
		t.Errorf("another namespace: %v", err)
	}
	clock.Set(build.Policy.NotAfter())
	_, err = builder.CheckSignable(build.Document)
	testAttestWantBuildRefused(t, "a document at its not_after", err, errComputePolicyBuildNotAfter)
}

// A sitting's batch holds one ticket for each UTC day from the day after the sitting until the batch's expiry, 14 days
// after it, each from 00:00 UTC for 72 hours cut to the expiry, every one verifying as a device verifies it once the
// certified key signs it, and each named for its day.
func TestTicketBatchCoversDayAfterSittingToExpires(t *testing.T) {
	builder, keys, _ := newTestAttestBuilder(t, false, testAttestSitting)
	batches := NewComputeTicketBatchBuilder(&ComputeTicketBatchBuilderArgs{Clock: newTestAttestClock(testAttestSitting), Random: testAttestRandom("batch")})
	batch, err := batches.Build(&ComputeTicketBatchArgs{PolicyVersion: 3})
	if err != nil {
		t.Fatal(err)
	}
	expires := testAttestSitting.Add(14 * 24 * time.Hour)
	if !batch.Batch.SignedAt.Equal(testAttestSitting) || !batch.Batch.Expires.Equal(expires) || batch.PolicyVersion != 3 || len(batch.Tickets) != 14 {
		t.Fatalf("batch %+v with %d tickets", batch.Batch, len(batch.Tickets))
	}
	for i, ticket := range batch.Tickets {
		start := testAttestDay(testAttestSitting).AddDate(0, 0, i+1)
		if !ticket.NotBefore.Equal(start) || !ticket.NotAfter.Equal(computePolicyMinTime(start.Add(72*time.Hour), expires)) || ticket.PolicyVersion != 3 {
			t.Errorf("ticket %d: %s to %s", i, ticket.NotBefore, ticket.NotAfter)
		}
	}
	if last := batch.Tickets[13]; !last.NotBefore.Equal(time.Date(2026, time.December, 15, 0, 0, 0, 0, time.UTC)) || !last.NotAfter.Equal(expires) {
		t.Errorf("the last ticket: %s to %s", last.NotBefore, last.NotAfter)
	}
	files, err := batch.Sign(func(message []byte) ([]byte, error) {
		return testAttestSign(t, keys.policy, ComputePolicyNamespace, message), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate := testAttestCertificateOf(t, keys.policy)
	for i, file := range files {
		ticket, err := builder.VerifyTicket(file, certificate)
		if err != nil {
			t.Fatalf("ticket %d: %v", i, err)
		}
		if _, err := keys.verifier(false).VerifyTicket(file, testAttestSitting); err != nil {
			t.Fatalf("a device's verifier, ticket %d: %v", i, err)
		}
		if !ticket.NotBefore.Equal(batch.Tickets[i].NotBefore) || ticket.Batch.Id != batch.Batch.Id {
			t.Errorf("ticket %d verified as %+v", i, ticket)
		}
	}
	if name := ComputePolicyTicketFileName(batch.Tickets[0].NotBefore); name != "tickets/2026-12-02.bin" {
		t.Errorf("the first ticket's name %s", name)
	}
}

// A revocation's batch starts its first ticket at the sitting, current at once for 72 hours, then one a day as any
// batch; a device takes the first at the sitting's instant.
func TestRevocationBatchStartsAtSignedAt(t *testing.T) {
	_, keys, _ := newTestAttestBuilder(t, false, testAttestSitting)
	batches := NewComputeTicketBatchBuilder(&ComputeTicketBatchBuilderArgs{Clock: newTestAttestClock(testAttestSitting), Random: testAttestRandom("revocation")})
	batch, err := batches.Build(&ComputeTicketBatchArgs{PolicyVersion: 4, Revocation: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Tickets) != 15 || !batch.Revocation {
		t.Fatalf("%d tickets", len(batch.Tickets))
	}
	first, second := batch.Tickets[0], batch.Tickets[1]
	if !first.NotBefore.Equal(testAttestSitting) || !first.NotAfter.Equal(testAttestSitting.Add(72*time.Hour)) ||
		!second.NotBefore.Equal(time.Date(2026, time.December, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("first %s to %s, second from %s", first.NotBefore, first.NotAfter, second.NotBefore)
	}
	files, err := batch.Sign(func(message []byte) ([]byte, error) {
		return testAttestSign(t, keys.policy, ComputePolicyNamespace, message), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := keys.verifier(false).VerifyTicket(files[0], testAttestSitting)
	if err != nil || !ticket.Current(testAttestSitting, DefaultAttestSettings()) {
		t.Errorf("the first ticket at the sitting: %v", err)
	}
}

// A batch past §5.4's 14 days, one expiring by its sitting, one holding no ticket and one naming no version are
// refused; an earlier expiry is taken and cuts the windows to it.
func TestTicketBatchBuilderRefusesPastItsBounds(t *testing.T) {
	batches := NewComputeTicketBatchBuilder(&ComputeTicketBatchBuilderArgs{Clock: newTestAttestClock(testAttestSitting), Random: testAttestRandom("bounds")})
	refused := []*ComputeTicketBatchArgs{
		{PolicyVersion: 3, Expires: testAttestSitting.Add(14*24*time.Hour + time.Millisecond)},
		{PolicyVersion: 3, Expires: testAttestSitting},
		{PolicyVersion: 3, Expires: testAttestSitting.Add(10 * time.Hour)},
		{PolicyVersion: 0},
	}
	for _, args := range refused {
		_, err := batches.Build(args)
		testAttestWantBuildRefused(t, args.Expires.Format(time.RFC3339Nano), err, errComputePolicyBuildBatch)
	}
	short, err := batches.Build(&ComputeTicketBatchArgs{PolicyVersion: 3, Expires: testAttestSitting.Add(2 * 24 * time.Hour)})
	if err != nil || len(short.Tickets) != 2 || !short.Tickets[1].NotAfter.Equal(testAttestSitting.Add(2*24*time.Hour)) {
		t.Fatalf("a two-day batch: %+v, %v", short, err)
	}
}

// The staging policy is signed under ur-compute-policy-staging by the staging key: a staging build's verifier takes
// it and a production build's refuses it, the staging builder refuses the compute-policy key's certificate, and its
// release's copy is compute-policy-staging.json.
func TestStagingPolicySignedUnderStagingNamespace(t *testing.T) {
	staging, keys, _ := newTestAttestBuilder(t, true, testAttestNow)
	if staging.Namespace() != ComputePolicyStagingNamespace || !staging.Staging() {
		t.Fatalf("namespace %s", staging.Namespace())
	}
	build, err := staging.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges()})
	if err != nil {
		t.Fatal(err)
	}
	if !build.Policy.NotAfter().Equal(testAttestNow.Add(7 * 24 * time.Hour)) {
		t.Errorf("not_after %s", build.Policy.NotAfter())
	}
	if _, err := staging.Signer(ssh.MarshalAuthorizedKey(keys.staging.PublicKey()), build.Policy.NotAfter()); err != nil {
		t.Fatalf("the staging key's certificate: %v", err)
	}
	_, err = staging.Signer(ssh.MarshalAuthorizedKey(keys.policy.PublicKey()), build.Policy.NotAfter())
	testAttestWantBuildRefused(t, "the compute-policy key for staging", err, errComputePolicyBuildSigner)
	signature := testAttestSign(t, keys.staging, ComputePolicyStagingNamespace, build.Document)
	if _, err := staging.Verify(build.Document, signature, testAttestCertificateOf(t, keys.staging)); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.verifier(true).Verify(build.Document, signature, testAttestNow); err != nil {
		t.Fatalf("a staging build: %v", err)
	}
	if _, err := keys.verifier(false).Verify(build.Document, signature, testAttestNow); !errors.Is(err, errComputePolicyNamespace) {
		t.Errorf("a production build took the staging policy: %v", err)
	}
	production, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	if _, err := production.Verify(build.Document, signature, nil); !errors.Is(err, errComputePolicyNamespace) {
		t.Errorf("the production pipeline took the staging policy: %v", err)
	}
	document, sig := ComputePolicyReleaseCopyNames(true)
	if document != "compute-policy-staging.json" || sig != "compute-policy-staging.json.sig" {
		t.Errorf("the staging copy's names %s, %s", document, sig)
	}
	if document, sig := ComputePolicyReleaseCopyNames(computePolicyStagingBuild); document != computePolicyReleaseDocumentName ||
		sig != computePolicyReleaseSignatureName {
		t.Errorf("this build embeds %s, and its pipeline writes %s", computePolicyReleaseDocumentName, document)
	}
	if document, _ := ComputePolicyReleaseCopyNames(false); document != "compute-policy.json" {
		t.Errorf("the production copy's name %s", document)
	}
}

// The horizon: days to the newest policy's not_after and to the newest batch's expiry, an older batch's later expiry
// never counted, each expiring within 14 and 7 days, past, or with nothing given.
func TestPolicyHorizon(t *testing.T) {
	builder, _, _ := newTestAttestBuilder(t, false, testAttestNow)
	build, err := builder.Build(&ComputePolicyBuildArgs{Changes: testAttestFirstChanges(), NotAfter: testAttestNow.Add(20 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	older := ComputePolicyTicketBatch{Id: testAttestBatchId("older"), SignedAt: testAttestNow.Add(-24 * time.Hour), Expires: testAttestNow.Add(13 * 24 * time.Hour)}
	newer := ComputePolicyTicketBatch{Id: testAttestBatchId("newer"), SignedAt: testAttestNow, Expires: testAttestNow.Add(10 * 24 * time.Hour)}
	tickets := []*ComputePolicyTicket{
		{Batch: newer, PolicyVersion: 1, NotBefore: testAttestNow.Add(24 * time.Hour), NotAfter: testAttestNow.Add(96 * time.Hour)},
		{Batch: older, PolicyVersion: 1, NotBefore: testAttestNow, NotAfter: testAttestNow.Add(72 * time.Hour)},
		{Batch: newer, PolicyVersion: 1, NotBefore: testAttestNow.Add(48 * time.Hour), NotAfter: testAttestNow.Add(120 * time.Hour)},
	}
	settings := DefaultComputePolicyBuildSettings()
	horizon := NewComputePolicyHorizon(testAttestNow, build.Policy, tickets)
	if horizon.PolicyLeft() != 20*24*time.Hour || horizon.TicketLeft() != 10*24*time.Hour || !horizon.TicketHorizon().Equal(newer.Expires) {
		t.Errorf("left %s and %s", horizon.PolicyLeft(), horizon.TicketLeft())
	}
	if horizon.PolicyExpiring(settings) || horizon.TicketHorizonNear(settings) || !horizon.Ticket.NotBefore.Equal(tickets[2].NotBefore) {
		t.Error("a horizon 20 and 10 days out pages")
	}
	later := NewComputePolicyHorizon(testAttestNow.Add(7*24*time.Hour), build.Policy, tickets)
	if !later.PolicyExpiring(settings) || !later.TicketHorizonNear(settings) || later.TicketLeft() != 3*24*time.Hour {
		t.Errorf("13 and 3 days out: %t, %t, %s", later.PolicyExpiring(settings), later.TicketHorizonNear(settings), later.TicketLeft())
	}
	past := NewComputePolicyHorizon(testAttestNow.Add(30*24*time.Hour), build.Policy, tickets)
	if past.PolicyLeft() != -10*24*time.Hour || !past.PolicyExpiring(settings) || !past.TicketHorizonNear(settings) {
		t.Errorf("past both: %s", past.PolicyLeft())
	}
	none := NewComputePolicyHorizon(testAttestNow, nil, nil)
	if !none.PolicyExpiring(settings) || !none.TicketHorizonNear(settings) || none.PolicyLeft() != 0 || !none.TicketHorizon().IsZero() {
		t.Error("nothing given does not page")
	}
}

// The serving path's names: <version>.json and its .sig, read back to their version, and tickets/<day>.bin.
func TestComputePolicyServingNames(t *testing.T) {
	if ComputePolicyFileName(12) != "12.json" || ComputePolicySignatureFileName(12) != "12.json.sig" {
		t.Error("the policy's names")
	}
	for name, want := range map[string]uint64{"12.json": 12, "1.json": 1} {
		if version, ok := ParseComputePolicyFileName(name); !ok || version != want {
			t.Errorf("%s: %d, %t", name, version, ok)
		}
	}
	for _, name := range []string{"0.json", "012.json", "12.json.sig", "x.json", ".json", "-1.json", "12.JSON", "1e3.json"} {
		if _, ok := ParseComputePolicyFileName(name); ok {
			t.Errorf("%s read as a policy's name", name)
		}
	}
	day := time.Date(2026, time.December, 3, 23, 59, 0, 0, time.FixedZone("test", -5*60*60))
	if name := ComputePolicyTicketFileName(day); name != "tickets/2026-12-04.bin" {
		t.Errorf("the ticket's name %s, its UTC day", name)
	}
}

// The support line is kept as the raw JSON the document holds, byte for byte, as search's and services' are.
func TestComputePolicySupportLineSurvivesVerbatim(t *testing.T) {
	support := `{"host":  "feedback.test.example", "subprocessors": [ {"name": "Test triage", "purpose": "triage", "retention": "30 days"} ]}`
	document := testAttestPolicyEdit(t, "  \"custody\": [", "  \"support\": "+support+",\n  \"custody\": [")
	policy, err := testAttestVerifyDocument(t, document)
	if err != nil {
		t.Fatal(err)
	}
	if string(policy.Support) != support || !bytes.Contains(policy.Document(), []byte(support)) {
		t.Errorf("support %q", policy.Support)
	}
	line, err := ParseSupportPolicyLine(policy.Support)
	if err != nil || line.Host != "feedback.test.example" {
		t.Errorf("%+v, %v", line, err)
	}
	plain, err := testAttestVerifyDocument(t, testAttestPolicyDocument(t))
	if err != nil || plain.Support != nil {
		t.Errorf("a policy with no support line: %q, %v", plain.Support, err)
	}
	testAttestWantFormatRefusal(t, "a null support line", testAttestPolicyEdit(t, "  \"custody\": [", "  \"support\": null,\n  \"custody\": ["))
}

// The store answers the newest policy's support line, its host for the support client, whatever that policy's
// not_after; with no policy, or one with no line, it names no host.
func TestComputePolicySupportLineFromTheStore(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	store := world.open(t, 0)
	if _, err := store.SupportLine(); !errors.Is(err, errComputePolicySupportAbsent) {
		t.Fatalf("no policy: %v", err)
	}
	builder := NewComputePolicyBuilder(&ComputePolicyBuilderArgs{ReleaseKeys: []ssh.PublicKey{world.keys.release.PublicKey()}, Clock: world.clock})
	changes := testAttestFirstChanges()
	changes.Support = nil
	without, err := builder.Build(&ComputePolicyBuildArgs{Changes: changes, NotAfter: testAttestNow.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Offer(without.Document, testAttestSign(t, world.keys.policy, ComputePolicyNamespace, without.Document)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SupportLine(); !errors.Is(err, errComputePolicySupportAbsent) {
		t.Fatalf("a policy with no line: %v", err)
	}
	with, err := builder.Build(&ComputePolicyBuildArgs{Previous: without.Policy, Changes: &ComputePolicyChangeSet{Support: json.RawMessage(testAttestSupportLine)}, NotAfter: testAttestNow.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Offer(with.Document, testAttestSign(t, world.keys.policy, ComputePolicyNamespace, with.Document)); err != nil {
		t.Fatal(err)
	}
	world.clock.Set(testAttestNow.Add(48 * time.Hour))
	line, err := store.SupportLine()
	if err != nil || line.Host != "feedback.test.example" {
		t.Fatalf("past its not_after: %+v, %v", line, err)
	}
}
