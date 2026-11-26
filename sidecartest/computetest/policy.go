// computetest.FakeComputePolicy (CTEST-M11-02; DESIGN-COMPUTE §18, §5.4, R2-11): §5.4's signed objects made with test
// keys, for ATTEST, CTRUST, INFER, SRCH and ENC, built through ATTEST's own types and signers, never a copy of the
// format, so a format change reaches the fake at once:
//
//	keys      FakePolicyKeys, every key from the fake's seed: a test release key that certifies a test compute-policy
//	          key for ur-compute-policy alone and a test staging key for ur-compute-policy-staging alone, each
//	          certificate valid CertificateLifetime from CertificateBackdate before the fake's start; and, for the
//	          refusals, a release key no build pins, which certifies the compute-policy key too (Uncertified)
//	policies  NewPolicy, a whole policy at a version in ATTEST's ComputePolicy, every line synthetic, which a test edits
//	          as it needs: its not_after, its profiles and model ids, its disclosures, direct, search and services
//	          lines, a revocation; Document writes its bytes, ATTEST's own JSON names with no null, and Sign signs them
//	          through ATTEST's SSHSIG signer, by the compute-policy key, the staging key, a key the release key did not
//	          certify, the bare key or the release key itself (FakePolicySigner)
//	tickets   NewBatch, a sitting's batch through ATTEST's ComputePolicyTicket and SignComputePolicyTicket: one ticket
//	          for each UTC day from the day after the sitting until the batch's expiry, TicketBatchMaxLifetime after
//	          the sitting, a revocation's first ticket starting at the sitting, each window TicketMaxWindow cut to the
//	          expiry, so the edges §5.4's bounds sit at are the defaults; a test asks for a longer window or batch to
//	          see a device refuse one
//	host      FakeTicketHost, the ticket host and its serving path, a sidecar.ComputePolicySource, on the test's clock:
//	          it releases each ticket at its not_before, one a day, from the newest batch, deletes every older batch's
//	          unreleased tickets when a sitting's batch arrives, keeps unreleased tickets back, and can withhold a newer
//	          policy and every ticket naming it, as a breached serving path would hold a revocation off
//
// The bounds are the verifier's to enforce, by ATTEST's AttestSettings, which the fake's settings carry: the fake only
// makes their edges. A production build trusts none of these keys: its verifier pins the release key alone
// (attest_policy_root.go). policy_testhooks.go, under sidecar_testhooks, gives the verifier a test build pins the test
// release key in, and a device's policy store, gate and fetcher over it.
//
// Safe for concurrent use: the fake's keys and settings are fixed once it is built, and the host keeps its state under
// stateLock.

package computetest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	// A signer the fake does not hold.
	ErrFakePolicySigner = errors.New("computetest: no such policy signer")
	// What the fake cannot make: no policy, a batch naming no version.
	ErrFakePolicyInvalid = errors.New("computetest: not a policy or batch the fake makes")
	// The untagged build has no seam into ATTEST's verifier (policy_testhooks.go).
	ErrFakeComputePolicyUnlinked = errors.New("computetest: ATTEST's verifier seam needs the sidecar_testhooks build")
)

// Who signs a policy or a ticket, and under which namespace.
type FakePolicySigner string

const (
	// The compute-policy key, certified by the test release key for ur-compute-policy, under that namespace: a good
	// production policy's signer.
	FakePolicySignerPolicy FakePolicySigner = "policy"
	// The staging key, certified for ur-compute-policy-staging, under that namespace: a staging policy's signer.
	FakePolicySignerStaging FakePolicySigner = "staging"
	// The compute-policy key certified by a release key no build pins, under ur-compute-policy: a key the release key
	// did not certify.
	FakePolicySignerUncertified FakePolicySigner = "uncertified"
	// The compute-policy key with no certificate, under ur-compute-policy.
	FakePolicySignerBare FakePolicySigner = "bare"
	// The test release key itself, under ur-compute-policy: a release signature presented as a policy.
	FakePolicySignerRelease FakePolicySigner = "release"
)

// The ids §2.8's table lists, each a disclosure NewPolicy carries at version 1: identifiers of the format.
var FakePolicyDisclosureIds = []string{
	"search:parallel",
	"inference:local", "inference:chutes", "inference:engy", "inference:saygm",
	"enclave:hippius", "enclave:lium", "enclave:cathedral",
	"listeners:publish",
	"connect:google", "connect:microsoft", "connect:custom",
	"approvals:auto",
	"support:urnetwork",
}

// The fake's settings (QD-702).
type FakeComputePolicySettings struct {
	// ATTEST's settings, whose format limits and §5.4 bounds the fake makes its edges at and its verifier and devices
	// enforce: each batch TicketBatchMaxLifetime long, each window TicketMaxWindow, each certificate inside
	// CertificateMaxValidity. Nil takes DefaultAttestSettings.
	Attest *sidecar.AttestSettings
	// How long a policy is current from its signing, its not_after: 90 days, §5.4's.
	PolicyLifetime time.Duration
	// How long a test key's certificate is valid: 364 days, inside ATTEST's CertificateMaxValidity of a year, so a
	// device takes it.
	CertificateLifetime time.Duration
	// How long before the fake's start a certificate's validity begins: 30 days, so a sitting a test dates before its
	// clock's start still verifies.
	CertificateBackdate time.Duration
	// How long a default measurement profile passes from the fake's start: 180 days, a reading, two policies' lives.
	ProfileLifetime time.Duration
	// The grace each default disclosure carries, in days: 14, §2.8's; a test sets 0 for a change that widens who reads.
	DisclosureGraceDays uint32
}

// The fake's defaults, the only place one is set.
func DefaultFakeComputePolicySettings() *FakeComputePolicySettings {
	return &FakeComputePolicySettings{
		Attest:              sidecar.DefaultAttestSettings(),
		PolicyLifetime:      90 * 24 * time.Hour,
		CertificateLifetime: 364 * 24 * time.Hour,
		CertificateBackdate: 30 * 24 * time.Hour,
		ProfileLifetime:     180 * 24 * time.Hour,
		DisclosureGraceDays: 14,
	}
}

// What NewFakeComputePolicy builds on.
type FakeComputePolicyArgs struct {
	// What every key, hash, id and nonce is drawn from; empty takes "computetest". Two fakes of one seed and one clock
	// start make the same bytes.
	Seed string
	// Nil takes DefaultFakeComputePolicySettings.
	Settings *FakeComputePolicySettings
	// The test's clock: the fake's start, a policy's and a sitting's default time, and the ticket host's releases. Nil
	// takes a FakeClock at sidecartest.DefaultClockStart.
	Clock sidecar.Clock
}

// The test keys, every one from the fake's seed (see the file header's keys row).
type FakePolicyKeys struct {
	// The test release key, which a test build's verifier pins (FakeComputePolicy.Verifier) and no shipped build does.
	Release ssh.Signer
	// A release key no build pins.
	OtherRelease ssh.Signer
	// The compute-policy key and the staging key, bare.
	PolicyKey  ssh.Signer
	StagingKey ssh.Signer
	// The compute-policy key with its certificate by Release for ur-compute-policy alone.
	Policy ssh.Signer
	// The staging key with its certificate by Release for ur-compute-policy-staging alone.
	Staging ssh.Signer
	// The compute-policy key with a certificate by OtherRelease for ur-compute-policy: a key the release key did not
	// certify.
	Uncertified ssh.Signer
}

// The test release key as RELEASE-KEY.pub would write it, one authorized_keys line.
func (self *FakePolicyKeys) ReleaseLine() []byte {
	return ssh.MarshalAuthorizedKey(self.Release.PublicKey())
}

// The key signer names and the namespace it signs under.
func (self *FakePolicyKeys) signer(signer FakePolicySigner) (ssh.Signer, string, error) {
	switch signer {
	case "", FakePolicySignerPolicy:
		return self.Policy, sidecar.ComputePolicyNamespace, nil
	case FakePolicySignerStaging:
		return self.Staging, sidecar.ComputePolicyStagingNamespace, nil
	case FakePolicySignerUncertified:
		return self.Uncertified, sidecar.ComputePolicyNamespace, nil
	case FakePolicySignerBare:
		return self.PolicyKey, sidecar.ComputePolicyNamespace, nil
	case FakePolicySignerRelease:
		return self.Release, sidecar.ComputePolicyNamespace, nil
	}
	return nil, "", fmt.Errorf("%w: %q", ErrFakePolicySigner, signer)
}

// A stream of bytes that repeats for its seed and label: SHA-256 of both and a counter, block after block. Every key,
// nonce and synthetic value here is drawn from one, so every vector repeats.
type fakeStream struct {
	prefix  string
	counter uint64
	buffer  []byte
}

// A stream for seed and label.
func newFakeStream(seed string, label string) io.Reader {
	return &fakeStream{prefix: "urnetwork-sidecar computetest stream " + seed + " " + label}
}

func (self *fakeStream) Read(out []byte) (int, error) {
	for len(self.buffer) < len(out) {
		block := sha256.New()
		block.Write([]byte(self.prefix))
		binary.Write(block, binary.BigEndian, self.counter)
		self.counter += 1
		self.buffer = block.Sum(self.buffer)
	}
	count := copy(out, self.buffer)
	self.buffer = self.buffer[count:]
	return count, nil
}

// byteCount bytes of seed and label's stream.
func fakeBytes(seed string, label string, byteCount int) []byte {
	out := make([]byte, byteCount)
	io.ReadFull(newFakeStream(seed, label), out)
	return out
}

// See the file header.
type FakeComputePolicy struct {
	seed     string
	settings *FakeComputePolicySettings
	clock    sidecar.Clock
	// the clock when the fake was built, from which its certificates and default profiles are dated
	start time.Time
	keys  *FakePolicyKeys
}

// A fake over args, its keys made and certified.
func NewFakeComputePolicy(args *FakeComputePolicyArgs) (*FakeComputePolicy, error) {
	if args == nil {
		args = &FakeComputePolicyArgs{}
	}
	seed := args.Seed
	if seed == "" {
		seed = "computetest"
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultFakeComputePolicySettings()
	}
	if settings.Attest == nil {
		withAttest := *settings
		withAttest.Attest = sidecar.DefaultAttestSettings()
		settings = &withAttest
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	self := &FakeComputePolicy{seed: seed, settings: settings, clock: clock, start: clock.Now().UTC()}
	keys, err := self.newKeys()
	if err != nil {
		return nil, err
	}
	self.keys = keys
	return self, nil
}

// An Ed25519 key from the seed and label.
func (self *FakeComputePolicy) key(label string) (ssh.Signer, error) {
	seed := sha256.Sum256([]byte("urnetwork-sidecar computetest policy key " + self.seed + " " + label))
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
}

// key with an OpenSSH user certificate by authority naming principal alone, valid CertificateLifetime from
// CertificateBackdate before the fake's start, as a signer whose public key is the certificate.
func (self *FakeComputePolicy) certify(key ssh.Signer, authority ssh.Signer, principal string, keyId string) (ssh.Signer, error) {
	validAfter := self.start.Add(-self.settings.CertificateBackdate)
	certificate := &ssh.Certificate{
		Key:             key.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           keyId,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validAfter.Add(self.settings.CertificateLifetime).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}
	if err := certificate.SignCert(newFakeStream(self.seed, "certificate "+keyId), authority); err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(certificate, key)
}

// The keys of the file header's keys row.
func (self *FakeComputePolicy) newKeys() (*FakePolicyKeys, error) {
	keys := &FakePolicyKeys{}
	var err error
	if keys.Release, err = self.key("release"); err != nil {
		return nil, err
	}
	if keys.OtherRelease, err = self.key("other release"); err != nil {
		return nil, err
	}
	if keys.PolicyKey, err = self.key("compute policy"); err != nil {
		return nil, err
	}
	if keys.StagingKey, err = self.key("staging"); err != nil {
		return nil, err
	}
	if keys.Policy, err = self.certify(keys.PolicyKey, keys.Release, sidecar.ComputePolicyNamespace, "computetest compute-policy key"); err != nil {
		return nil, err
	}
	if keys.Staging, err = self.certify(keys.StagingKey, keys.Release, sidecar.ComputePolicyStagingNamespace, "computetest staging key"); err != nil {
		return nil, err
	}
	if keys.Uncertified, err = self.certify(keys.PolicyKey, keys.OtherRelease, sidecar.ComputePolicyNamespace, "computetest uncertified key"); err != nil {
		return nil, err
	}
	return keys, nil
}

// The fake's keys.
func (self *FakeComputePolicy) Keys() *FakePolicyKeys {
	return self.keys
}

// The fake's settings.
func (self *FakeComputePolicy) Settings() *FakeComputePolicySettings {
	return self.settings
}

// The fake's clock.
func (self *FakeComputePolicy) Clock() sidecar.Clock {
	return self.clock
}

// The clock when the fake was built.
func (self *FakeComputePolicy) Start() time.Time {
	return self.start
}

// Synthetic lowercase hex of byteCount bytes for label.
func (self *FakeComputePolicy) hex(label string, byteCount int) string {
	return hex.EncodeToString(fakeBytes(self.seed, label, byteCount))
}

// A synthetic UUID for label, as a chute_id is written.
func (self *FakeComputePolicy) uuid(label string) string {
	value := self.hex(label, 16)
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
}

// A whole TDX measurement profile of id, every register synthetic, expiring ProfileLifetime after the fake's start and
// reviewed reproduced; a test sets what it checks.
func (self *FakeComputePolicy) TdxProfile(id string) *sidecar.ComputePolicyProfile {
	return &sidecar.ComputePolicyProfile{
		Id:           id,
		GuestVersion: "computetest-1",
		Cpu:          sidecar.ComputePolicyCpuTdx,
		Mrtd:         self.hex("profile "+id+" mrtd", 48),
		Rtmr0:        self.hex("profile "+id+" rtmr0", 48),
		Rtmr1:        self.hex("profile "+id+" rtmr1", 48),
		Rtmr2:        self.hex("profile "+id+" rtmr2", 48),
		Rtmr3:        self.hex("profile "+id+" rtmr3", 48),
		ExpiresMs:    self.start.Add(self.settings.ProfileLifetime).UnixMilli(),
		Replayed:     []*sidecar.ComputePolicyReplayed{},
		Review:       sidecar.ComputePolicyReviewReproduced,
	}
}

// A whole SEV-SNP measurement profile of id, its measurement synthetic, as TdxProfile.
func (self *FakeComputePolicy) SnpProfile(id string) *sidecar.ComputePolicyProfile {
	return &sidecar.ComputePolicyProfile{
		Id:           id,
		GuestVersion: "computetest-1",
		Cpu:          sidecar.ComputePolicyCpuSnp,
		Measurement:  self.hex("profile "+id+" measurement", 48),
		ExpiresMs:    self.start.Add(self.settings.ProfileLifetime).UnixMilli(),
		Replayed:     []*sidecar.ComputePolicyReplayed{},
		Review:       sidecar.ComputePolicyReviewReproduced,
	}
}

// A disclosure of id at version, in effect since since, with the settings' grace and a synthetic English text naming
// the id and version, so a render can be told from another.
func (self *FakeComputePolicy) Disclosure(id string, version uint32, since time.Time) *sidecar.ComputePolicyDisclosure {
	return &sidecar.ComputePolicyDisclosure{
		Id:        id,
		Version:   version,
		GraceDays: self.settings.DisclosureGraceDays,
		SinceMs:   since.UnixMilli(),
		Locales: []*sidecar.ComputePolicyDisclosureText{{
			Locale:  "en",
			Summary: fmt.Sprintf("Synthetic test text for %s, version %d.", id, version),
			Exposed: []string{fmt.Sprintf("What %s's test text says could be exposed, version %d.", id, version)},
			Private: []string{fmt.Sprintf("What %s's test text says stays private, version %d.", id, version)},
		}},
	}
}

// A whole policy at version, signed now on the fake's clock and current PolicyLifetime from then, every line
// synthetic:
//
//	roots        a synthetic SHA-256 for Intel's SGX root, each AMD family's ARK, NVIDIA's device root and NRAS's
//	tcb          TDX UpToDate alone and a least TCB evaluation data number; SNP's least firmware per family (0x1F,
//	             0x1E, 0x08, §5.3's) with DEBUG and MIGRATE_MA to be clear; 7 days of collateral per vendor
//	providers    chutes (AP, TDX, chutes-e2e-v1, its VM root CA, testmodel's chute_id, a GPU profile), and hippius
//	             (AP, TDX and SNP, the three ur-enclave schemes, a TDX profile replaying RTMR3 to a payload root hash,
//	             listed, and an SNP profile)
//	direct       engy (api.engy.example, zero retention) and saygm (api.saygm.example, an upstream, an alias), each
//	             serving testmodel, and an empty limited_use list
//	disclosures  each of FakePolicyDisclosureIds at version 1, in effect since the signing
//	search,      none: both are gated lines, off until a test sets the raw JSON its owner decodes
//	services
//	custody,     none
//	revoked
//
// The policy is ATTEST's own type, so a test edits any line before Sign.
func (self *FakeComputePolicy) NewPolicy(version uint64) *sidecar.ComputePolicy {
	signedAt := self.clock.Now().UTC()
	chutes := &sidecar.ComputePolicyProvider{
		Id:      "chutes",
		Cpus:    []string{sidecar.ComputePolicyCpuTdx},
		Schemes: []string{sidecar.ComputePolicySchemeChutesE2e},
		Label:   sidecar.ComputeLabelAp,
		Roots:   []*sidecar.ComputePolicyProviderRoot{{Name: "sek8s-vm-root-ca", Sha256: self.hex("provider root chutes", 32)}},
		Models:  []*sidecar.ComputePolicyModel{{Model: "testmodel", ProviderModelId: self.uuid("chutes testmodel")}},
	}
	chutesProfile := self.TdxProfile("chutes-tdx-computetest-1")
	chutesProfile.GpuModel = "testgpu"
	chutesProfile.GpuCount = 1
	chutes.Profiles = []*sidecar.ComputePolicyProfile{chutesProfile}
	hippiusTdx := self.TdxProfile("hippius-tdx-computetest-1")
	hippiusTdx.Rtmr3 = ""
	hippiusTdx.PayloadRootSha256 = self.hex("profile hippius payload root", 32)
	hippiusTdx.Replayed = []*sidecar.ComputePolicyReplayed{{
		Register: "rtmr3",
		Events:   []string{self.hex("profile hippius rtmr3 event 1", 48), hippiusTdx.PayloadRootSha256},
	}}
	hippiusTdx.Review = sidecar.ComputePolicyReviewListed
	hippiusTdx.ReviewListSha256 = self.hex("profile hippius list", 32)
	hippiusSnp := self.SnpProfile("hippius-snp-computetest-1")
	hippiusSnp.PayloadRootSha256 = hippiusTdx.PayloadRootSha256
	hippius := &sidecar.ComputePolicyProvider{
		Id:   "hippius",
		Cpus: []string{sidecar.ComputePolicyCpuTdx, sidecar.ComputePolicyCpuSnp},
		Schemes: []string{
			sidecar.ComputePolicySchemeEnclave,
			sidecar.ComputePolicySchemeEnclaveSession,
			sidecar.ComputePolicySchemeEnclaveSshSetup,
		},
		Label:    sidecar.ComputeLabelAp,
		Roots:    []*sidecar.ComputePolicyProviderRoot{},
		Models:   []*sidecar.ComputePolicyModel{},
		Profiles: []*sidecar.ComputePolicyProfile{hippiusTdx, hippiusSnp},
	}
	disclosures := []*sidecar.ComputePolicyDisclosure{}
	for _, id := range FakePolicyDisclosureIds {
		disclosures = append(disclosures, self.Disclosure(id, 1, signedAt))
	}
	maxAges := []*sidecar.ComputePolicyMaxAge{}
	for _, vendor := range []string{sidecar.ComputePolicyVendorIntel, sidecar.ComputePolicyVendorAmd, sidecar.ComputePolicyVendorNvidia} {
		maxAges = append(maxAges, &sidecar.ComputePolicyMaxAge{Vendor: vendor, CollateralDays: 7, RevocationDays: 7})
	}
	return &sidecar.ComputePolicy{
		Version:    version,
		NotAfterMs: signedAt.Add(self.settings.PolicyLifetime).UnixMilli(),
		Roots: sidecar.ComputePolicyRoots{
			IntelSgx: []string{self.hex("root intel sgx", 32)},
			AmdArks: []*sidecar.ComputePolicyAmdArk{
				{Family: sidecar.ComputePolicyAmdMilan, Sha256: self.hex("root amd milan", 32)},
				{Family: sidecar.ComputePolicyAmdGenoa, Sha256: self.hex("root amd genoa", 32)},
				{Family: sidecar.ComputePolicyAmdTurin, Sha256: self.hex("root amd turin", 32)},
			},
			NvidiaDevice: []string{self.hex("root nvidia device", 32)},
			NvidiaNras:   []string{self.hex("root nvidia nras", 32)},
		},
		Tcb: sidecar.ComputePolicyTcb{
			Tdx: sidecar.ComputePolicyTdxTcb{
				Statuses:                   []string{sidecar.ComputePolicyTdxUpToDate},
				Advisories:                 []string{},
				MinTcbEvaluationDataNumber: 17,
			},
			Snp: sidecar.ComputePolicySnpTcb{
				MinFirmware: []*sidecar.ComputePolicySnpFirmware{
					{Family: sidecar.ComputePolicyAmdMilan, Build: 0x1f},
					{Family: sidecar.ComputePolicyAmdGenoa, Build: 0x1e},
					{Family: sidecar.ComputePolicyAmdTurin, Build: 0x08},
				},
				// DEBUG, bit 19, and MIGRATE_MA, bit 18, of the guest policy
				PolicyBitsClear: 1<<19 | 1<<18,
			},
			MaxAges: maxAges,
		},
		Providers: []*sidecar.ComputePolicyProvider{chutes, hippius},
		Direct: sidecar.ComputePolicyDirectLine{
			Providers: []*sidecar.ComputePolicyDirect{
				{
					Slug:           "engy",
					ApiHost:        "api.engy.example",
					ReceiverHotkey: "5Ctest" + self.hex("receiver hotkey engy", 20),
					Netuid:         4201,
					Targets: []*sidecar.ComputePolicyDirectTarget{
						{Method: "POST", Path: "/v1/chat/completions"},
						{Method: "GET", Path: "/v1/usage/{nonce}"},
					},
					Models: []*sidecar.ComputePolicyDirectModel{{
						Model:           "testmodel",
						ProviderModelId: "computetest/testmodel",
						Aliases:         []string{},
						ZeroRetention:   true,
						Upstreams:       []string{},
					}},
				},
				{
					Slug:           "saygm",
					ApiHost:        "api.saygm.example",
					ReceiverHotkey: "5Ctest" + self.hex("receiver hotkey saygm", 20),
					Netuid:         4202,
					Targets:        []*sidecar.ComputePolicyDirectTarget{{Method: "POST", Path: "/v1/chat/completions"}},
					Models: []*sidecar.ComputePolicyDirectModel{{
						Model:           "testmodel",
						ProviderModelId: "computetest/testmodel",
						Aliases:         []string{"computetest-testmodel"},
						Upstreams:       []string{"computetest-upstream"},
					}},
				},
			},
			LimitedUse: []string{},
		},
		Disclosures: disclosures,
		Custody:     []*sidecar.ComputePolicyCustody{},
		Revoked: sidecar.ComputePolicyRevoked{
			Profiles:   []string{},
			Chips:      []*sidecar.ComputePolicyChip{},
			GpuSerials: []string{},
		},
	}
}

// json.RawMessage, the search and services lines' type, which a document carries as given.
var fakeRawMessageType = reflect.TypeFor[json.RawMessage]()

// Makes every nil slice under value empty, so JSON writes [] where the format refuses null; a raw line is left as is.
func fakeFillSlices(value reflect.Value) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			fakeFillSlices(value.Elem())
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				fakeFillSlices(value.Field(i))
			}
		}
	case reflect.Slice:
		if value.Type() == fakeRawMessageType {
			return
		}
		if value.IsNil() {
			if value.CanSet() {
				value.Set(reflect.MakeSlice(value.Type(), 0, 0))
			}
			return
		}
		for i := range value.Len() {
			fakeFillSlices(value.Index(i))
		}
	}
}

// compute-policy.json's bytes for policy: ATTEST's own JSON names, a copy with every nil list written [], since the
// format refuses null, and the search and services lines as given. Neither the policy nor its lines are changed.
func (self *FakeComputePolicy) Document(policy *sidecar.ComputePolicy) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("%w: no policy", ErrFakePolicyInvalid)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	copied := &sidecar.ComputePolicy{}
	if err := json.Unmarshal(encoded, copied); err != nil {
		return nil, err
	}
	fakeFillSlices(reflect.ValueOf(copied))
	document := &bytes.Buffer{}
	encoder := json.NewEncoder(document)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(copied); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(document.Bytes(), []byte("\n")), nil
}

// An armored SSHSIG over message by signer under its namespace, through ATTEST's signer (sidecar.ComputeSshsigSign),
// as ssh-keygen -Y sign writes one: for a signature over any bytes a refusal needs.
func (self *FakeComputePolicy) SignBytes(message []byte, signer FakePolicySigner) ([]byte, error) {
	key, namespace, err := self.keys.signer(signer)
	if err != nil {
		return nil, err
	}
	return sidecar.ComputeSshsigSign(newFakeStream(self.seed, "sshsig"), key, namespace, message)
}

// A policy as signed: what <version>.json and <version>.json.sig hold.
type FakeSignedPolicy struct {
	Version uint64
	// The policy as the fake wrote it, decoded from Document; what a device holds is its verifier's own parse.
	Policy *sidecar.ComputePolicy
	// compute-policy.json's bytes, exactly as signed.
	Document []byte
	// The detached armored SSHSIG.
	Signature []byte
	Signer    FakePolicySigner
}

// policy's document and its signature by signer.
func (self *FakeComputePolicy) Sign(policy *sidecar.ComputePolicy, signer FakePolicySigner) (*FakeSignedPolicy, error) {
	document, err := self.Document(policy)
	if err != nil {
		return nil, err
	}
	signature, err := self.SignBytes(document, signer)
	if err != nil {
		return nil, err
	}
	written := &sidecar.ComputePolicy{}
	if err := json.Unmarshal(document, written); err != nil {
		return nil, err
	}
	return &FakeSignedPolicy{Version: policy.Version, Policy: written, Document: document, Signature: signature, Signer: signer}, nil
}

// What NewBatch builds a sitting's batch on.
type FakeTicketBatchArgs struct {
	// The policy version N every ticket names: from 1.
	PolicyVersion uint64
	// The sitting; zero takes the fake's clock now. Kept to the millisecond, as the ticket's bytes keep it.
	SignedAt time.Time
	// A revocation's batch, whose first ticket starts at the sitting (§5.4).
	Revocation bool
	// The batch's expiry; zero takes SignedAt and the settings' TicketBatchMaxLifetime, §5.4's 14 days. A later one
	// makes a batch a device refuses.
	Expires time.Time
	// Each ticket's window before it is cut to Expires; zero takes the settings' TicketMaxWindow, §5.4's 72 hours. A
	// longer one makes tickets a device refuses.
	Window time.Duration
	// Who signs; empty takes the compute-policy key.
	Signer FakePolicySigner
}

// One ticket of a batch.
type FakeTicket struct {
	// The ticket in ATTEST's type, as signed: its batch, the version it names and its window. Its File and Signer are a
	// verified ticket's, so empty here; ComputePolicyVerifier.VerifyTicket of File gives those.
	Ticket *sidecar.ComputePolicyTicket
	// The ticket file, <day>.bin's bytes: the ticket's bytes and their SSHSIG.
	File []byte
}

// When the ticket starts.
func (self *FakeTicket) NotBefore() time.Time {
	return self.Ticket.NotBefore
}

// When the ticket's window ends.
func (self *FakeTicket) NotAfter() time.Time {
	return self.Ticket.NotAfter
}

// The UTC day the ticket starts on, the day <day>.bin is named for.
func (self *FakeTicket) Day() time.Time {
	return fakeUtcDay(self.Ticket.NotBefore)
}

// 00:00 UTC of at's day.
func fakeUtcDay(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
}

// A sitting's batch (see the file header's tickets row).
type FakeTicketBatch struct {
	Id            sidecar.Id
	SignedAt      time.Time
	Expires       time.Time
	PolicyVersion uint64
	Revocation    bool
	// In order of their starts.
	Tickets []*FakeTicket
}

// A sitting's batch over args, each ticket signed through ATTEST's SignComputePolicyTicket.
func (self *FakeComputePolicy) NewBatch(args *FakeTicketBatchArgs) (*FakeTicketBatch, error) {
	if args == nil || args.PolicyVersion == 0 {
		return nil, fmt.Errorf("%w: a batch names a policy version from 1", ErrFakePolicyInvalid)
	}
	key, namespace, err := self.keys.signer(args.Signer)
	if err != nil {
		return nil, err
	}
	signedAt := args.SignedAt
	if signedAt.IsZero() {
		signedAt = self.clock.Now()
	}
	signedAt = time.UnixMilli(signedAt.UnixMilli()).UTC()
	expires := args.Expires
	if expires.IsZero() {
		expires = signedAt.Add(self.settings.Attest.TicketBatchMaxLifetime)
	}
	expires = time.UnixMilli(expires.UnixMilli()).UTC()
	window := args.Window
	if window == 0 {
		window = self.settings.Attest.TicketMaxWindow
	}
	revocation := 0
	if args.Revocation {
		revocation = 1
	}
	batchId, err := sidecar.IdFromBytes(fakeBytes(self.seed, fmt.Sprintf("batch %d %d %d", signedAt.UnixMilli(), args.PolicyVersion, revocation), 16))
	if err != nil {
		return nil, err
	}
	batch := &FakeTicketBatch{
		Id:            batchId,
		SignedAt:      signedAt,
		Expires:       expires,
		PolicyVersion: args.PolicyVersion,
		Revocation:    args.Revocation,
	}
	starts := []time.Time{}
	if args.Revocation {
		starts = append(starts, signedAt)
	}
	for day := fakeUtcDay(signedAt).AddDate(0, 0, 1); day.Before(expires); day = day.AddDate(0, 0, 1) {
		starts = append(starts, day)
	}
	for _, start := range starts {
		notAfter := start.Add(window)
		if expires.Before(notAfter) {
			notAfter = expires
		}
		ticket := &sidecar.ComputePolicyTicket{
			Batch:         sidecar.ComputePolicyTicketBatch{Id: batchId, SignedAt: signedAt, Expires: expires},
			PolicyVersion: args.PolicyVersion,
			NotBefore:     start,
			NotAfter:      notAfter,
		}
		file, err := sidecar.SignComputePolicyTicket(newFakeStream(self.seed, "ticket"), key, namespace, ticket)
		if err != nil {
			return nil, err
		}
		batch.Tickets = append(batch.Tickets, &FakeTicket{Ticket: ticket, File: file})
	}
	return batch, nil
}

// The ticket host and its serving path on the fake's clock (see the file header's host row).
func (self *FakeComputePolicy) NewTicketHost() *FakeTicketHost {
	return &FakeTicketHost{
		clock:            self.clock,
		versionPolicies:  map[uint64]*FakeSignedPolicy{},
		withheldVersions: map[uint64]bool{},
	}
}

// See the file header's host row. A sidecar.ComputePolicySource: ATTEST's fetcher takes from it as from ur.io.
type FakeTicketHost struct {
	clock sidecar.Clock

	stateLock        sync.Mutex
	versionPolicies  map[uint64]*FakeSignedPolicy
	withheldVersions map[uint64]bool
	// the batches handed over, oldest first
	sittings []*fakeTicketSitting
}

var _ sidecar.ComputePolicySource = (*FakeTicketHost)(nil)

// One sitting's batch on the host: which of its tickets a later sitting deleted before they were released.
type fakeTicketSitting struct {
	batch   *FakeTicketBatch
	deleted []bool
}

// Serves each policy at its version, replacing one of the same version.
func (self *FakeTicketHost) Publish(policies ...*FakeSignedPolicy) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, policy := range policies {
		self.versionPolicies[policy.Version] = policy
	}
}

// Withholds the policy of version and every ticket naming it from the serving path, as a breached serving path holds a
// revocation off: what was released stays with the host, and a device fetching meets only what it served before.
func (self *FakeTicketHost) Withhold(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.withheldVersions[version] = true
}

// Serves the policy of version and the tickets naming it again.
func (self *FakeTicketHost) Serve(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.withheldVersions, version)
}

// Hands the host a sitting's batch: every older batch's tickets not yet released, their not_before still ahead on the
// clock, are deleted at once, never to be released (§5.4), so the newest batch is the one the host releases from.
func (self *FakeTicketHost) Sit(batch *FakeTicketBatch) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, sitting := range self.sittings {
		for i, ticket := range sitting.batch.Tickets {
			if now.Before(ticket.NotBefore()) {
				sitting.deleted[i] = true
			}
		}
	}
	self.sittings = append(self.sittings, &fakeTicketSitting{batch: batch, deleted: make([]bool, len(batch.Tickets))})
}

// Every ticket the host released by now, whatever the serving path withholds: each sitting's in order, the oldest
// sitting first.
func (self *FakeTicketHost) Released() []*FakeTicket {
	return self.tickets(true)
}

// Every ticket the host still keeps back, its start ahead on the clock: what a breach of the ticket host itself, and no
// other, would hold.
func (self *FakeTicketHost) Unreleased() []*FakeTicket {
	return self.tickets(false)
}

// The tickets not deleted that have started by now, or have not.
func (self *FakeTicketHost) tickets(started bool) []*FakeTicket {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	tickets := []*FakeTicket{}
	for _, sitting := range self.sittings {
		for i, ticket := range sitting.batch.Tickets {
			if !sitting.deleted[i] && started == !now.Before(ticket.NotBefore()) {
				tickets = append(tickets, ticket)
			}
		}
	}
	return tickets
}

// The policy of version and its signature, as <version>.json and its .sig serve them; ErrComputePolicySourceAbsent for
// one not published or withheld (sidecar.ComputePolicySource).
func (self *FakeTicketHost) Policy(ctx context.Context, version uint64) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	policy, ok := self.versionPolicies[version]
	if !ok || self.withheldVersions[version] {
		return nil, nil, sidecar.ErrComputePolicySourceAbsent
	}
	return bytes.Clone(policy.Document), bytes.Clone(policy.Signature), nil
}

// <day>.bin: of the tickets released by now that start on day's UTC date and name no withheld version, the newest
// sitting's; ErrComputePolicySourceAbsent for none (sidecar.ComputePolicySource). A ticket still kept back is never
// served.
func (self *FakeTicketHost) Ticket(ctx context.Context, day time.Time) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	day = fakeUtcDay(day)
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, sitting := range slices.Backward(self.sittings) {
		for i, ticket := range sitting.batch.Tickets {
			if sitting.deleted[i] || now.Before(ticket.NotBefore()) || !ticket.Day().Equal(day) ||
				self.withheldVersions[ticket.Ticket.PolicyVersion] {
				continue
			}
			return bytes.Clone(ticket.File), nil
		}
	}
	return nil, sidecar.ErrComputePolicySourceAbsent
}

// What NewDevice builds a device's policy parts on.
type FakePolicyDeviceArgs struct {
	// The device's sealed attest directory; nil takes a fresh sidecartest.FakeStore's root.
	Store sidecar.SidecarStore
	// The device's clock; nil takes the fake's.
	Clock sidecar.Clock
	// A staging or CI build's device, which verifies the staging key's policies alone; false is a production build's
	// namespace with the test release key pinned.
	Staging bool
	// The release's copy the device starts from; nil for a build that carries none.
	Release *FakeSignedPolicy
	// Where the device fetches policies and tickets; none fetches nothing.
	Sources []sidecar.ComputePolicySource
	// Nil logs nothing.
	Log sidecar.Logger
}

// A device's policy parts on the fake's keys: ATTEST's store, gate and fetcher, the gate's refresh being the fetcher's
// pass, as the attest component wires them on a Sidecar (attest_component.go).
type FakePolicyDevice struct {
	Verifier *sidecar.ComputePolicyVerifier
	Store    *sidecar.ComputePolicyStore
	Gate     *sidecar.ComputePolicyGate
	Fetcher  *sidecar.ComputePolicyFetcher

	stateLock sync.Mutex
	alarms    []*sidecar.ComputePolicyAlarm
}

// Every early-ticket alarm the gate raised, in order.
func (self *FakePolicyDevice) Alarms() []*sidecar.ComputePolicyAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.alarms)
}

// Keeps an alarm.
func (self *FakePolicyDevice) alarm(alarm *sidecar.ComputePolicyAlarm) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.alarms = append(self.alarms, alarm)
}
