//go:build sidecar_testhooks

// With the hooks linked, a scenario on the real MLS subset searches for every key the subset hands the hook and is
// handed no AEAD nonce (ledger QD-755): S3a's own run holds the keys derived beside each nonce and nothing the
// capture refuses, and one of those keys written into a store fails the run as a found secret.

package scenarios

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The key RFC 9420 derives beside each of its three nonces, from the same secret.
var mlsNonceSiblingKeyKinds = []string{"ratchet_key", "sender_data_key", "welcome_key"}

// What a privacy finding's NeedleKind reads for a hooked key found in a capture, and for a secret the capture
// would not search for.
const (
	findingKindSecret  = "secret"
	findingKindRefused = "refused"
)

// Every secret of kind any actor of the run's Net held.
func heldSecretsOfKind(run *sidecartest.ScenarioRun, kind string) [][]byte {
	held := run.Net.HeldSecrets()
	secrets := [][]byte{}
	for _, actor := range held.Actors() {
		secrets = append(secrets, held.Secrets(actor, kind)...)
	}
	return secrets
}

// Every kind of secret any actor of the run's Net held.
func heldSecretKinds(run *sidecartest.ScenarioRun) []string {
	held := run.Net.HeldSecrets()
	kinds := []string{}
	for _, actor := range held.Actors() {
		kinds = append(kinds, held.Kinds(actor)...)
	}
	slices.Sort(kinds)
	return slices.Compact(kinds)
}

func TestS3aHooksEachNoncesKeyAndNoNonce(t *testing.T) {
	var kinds []string
	keyCounts := map[string]int{}
	shortKinds := []string{}
	report := sidecartest.RunScenarioReport(t, &sidecartest.Scenario{Id: "S3a", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		if err := S3a(t).Run(ctx, run); err != nil {
			return err
		}
		kinds = heldSecretKinds(run)
		for _, kind := range kinds {
			for _, secret := range heldSecretsOfKind(run, kind) {
				// the capture's floor, the suite's AEAD key length
				if len(secret) < 16 {
					shortKinds = append(shortKinds, kind)
				}
			}
		}
		for _, kind := range mlsNonceSiblingKeyKinds {
			keyCounts[kind] = len(heldSecretsOfKind(run, kind))
		}
		return nil
	}}, nil)
	if !report.Passed() {
		t.Errorf("S3a under the hooks: flow %v, findings %v, guard %q, stored %q, problems %q", report.FlowErr, report.Findings, report.GuardFindings, report.StoredFindings, report.Problems)
	}
	for _, kind := range mlsNonceSiblingKeyKinds {
		if keyCounts[kind] == 0 {
			t.Errorf("no %s reached the hook, so the scan searched for none", kind)
		}
	}
	for _, kind := range []string{"welcome_secret", "sender_data_secret", "handshake_ratchet_secret"} {
		if !slices.Contains(kinds, kind) {
			t.Errorf("no %s reached the hook: a nonce's own secret is not searched for", kind)
		}
	}
	for _, kind := range kinds {
		if strings.Contains(kind, "nonce") {
			t.Errorf("%s reached the hook", kind)
		}
	}
	if 0 < len(shortKinds) {
		t.Errorf("secrets under 16 bytes reached the hook: %v", shortKinds)
	}
}

func TestAnMlsKeyInAStoreFailsS3a(t *testing.T) {
	leaked := map[string]bool{}
	report := sidecartest.RunScenarioReport(t, &sidecartest.Scenario{Id: "S3a", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		if err := S3a(t).Run(ctx, run); err != nil {
			return err
		}
		cluster, err := run.Host("evs").Blobs.FirstCluster()
		if err != nil {
			return err
		}
		// the newest key of each kind, as a bug that stored a key beside what it sealed would
		for _, kind := range mlsNonceSiblingKeyKinds {
			secrets := heldSecretsOfKind(run, kind)
			if len(secrets) == 0 {
				continue
			}
			body := append([]byte("sealed "), secrets[len(secrets)-1]...)
			if _, err := cluster.PutIfNoneMatch(ctx, "head/"+sidecar.EvsKeyId(sidecar.NewId())+"/_", body, nil); err != nil {
				return err
			}
			leaked[kind] = true
		}
		return nil
	}}, nil)
	if report.FlowErr != nil {
		t.Fatalf("the flow: %v", report.FlowErr)
	}
	if report.Passed() {
		t.Errorf("a run with MLS keys in a store passed")
	}
	for _, kind := range mlsNonceSiblingKeyKinds {
		if !leaked[kind] {
			t.Errorf("no %s to leak: none reached the hook", kind)
			continue
		}
		if !slices.ContainsFunc(report.Findings, func(finding *sidecartest.PrivacyFinding) bool {
			return finding.NeedleKind == findingKindSecret && finding.Needle == kind && finding.Class == sidecartest.PrivacyClassObject
		}) {
			t.Errorf("a %s in an object was not found: %v", kind, report.Findings)
		}
	}
	for _, finding := range report.Findings {
		if finding.NeedleKind == findingKindRefused {
			t.Errorf("the capture refused a secret: %s", finding)
		}
	}
}
