package sidecartest

// §22.7's admission suite on T2 (TEAM-M2-19): each row its own top-level test, on FakeApi over T2's fake first
// cluster, every reader compared with the reference after every entry. server/api/sidecar_admission_t3_test.go runs
// the same rows on server's sequencer.

import (
	"testing"

	"github.com/urnetwork/sidecar"
)

// T2's tier: a fake first cluster, and a FakeApi on the row's clock over it.
func admissionT2Tier(t *testing.T) *AdmissionTier {
	t.Helper()
	blobs := NewFakeBlobs(NewFakeClock(DefaultClockStart()), NewFaultQueue(), nil, DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return &AdmissionTier{
		Cluster: cluster,
		NewApi: func(clock sidecar.Clock, cluster sidecar.BlobCluster) AdmissionApi {
			return FakeApiAdmission(NewFakeApi(t.Context(), clock, NewFaultQueue(), nil, cluster, nil))
		},
	}
}

func TestAdmissionSigners(t *testing.T) {
	RunAdmissionRow(t, "signers", admissionT2Tier(t))
}

func TestAdmissionOutsideTheAdminSet(t *testing.T) {
	RunAdmissionRow(t, "outside the AdminSet", admissionT2Tier(t))
}

func TestAdmissionRecoveryWindow(t *testing.T) {
	RunAdmissionRow(t, "the recovery window", admissionT2Tier(t))
}

func TestAdmissionTwoFirstDevicesRacing(t *testing.T) {
	RunAdmissionRow(t, "two first devices racing", admissionT2Tier(t))
}

func TestAdmissionOwnerConsent(t *testing.T) {
	RunAdmissionRow(t, "owner consent", admissionT2Tier(t))
}

func TestAdmissionCommitters(t *testing.T) {
	RunAdmissionRow(t, "committers", admissionT2Tier(t))
}

func TestAdmissionSeats(t *testing.T) {
	RunAdmissionRow(t, "seats", admissionT2Tier(t))
}

func TestAdmissionAgentsCostNoCommit(t *testing.T) {
	RunAdmissionRow(t, "agents cost no commit", admissionT2Tier(t))
}

func TestAdmissionReadOnlyPageWorkers(t *testing.T) {
	RunAdmissionRow(t, "read-only page Workers", admissionT2Tier(t))
}

func TestAdmissionCompromiseCascade(t *testing.T) {
	RunAdmissionRow(t, "the compromise cascade", admissionT2Tier(t))
}

// DESIGN-DETAILS 5.6's cascade from the confirmation history, at every reader.
func TestTheCascadeReadsEveryConfirmation(t *testing.T) {
	RunAdmissionRow(t, "the cascade reads every confirmation", admissionT2Tier(t))
}

func TestAdmissionAuthKeys(t *testing.T) {
	RunAdmissionRow(t, "auth keys", admissionT2Tier(t))
}

// DESIGN-DETAILS 5.6's property, on real code: a new device and a gate at each base agree with the long-running
// reader after every entry of a generated log.
func TestRowsOnlyAndFullReadersAgreeOverGeneratedLogs(t *testing.T) {
	RunAdmissionRow(t, "generated logs", admissionT2Tier(t))
}

// Every row has its T2 test above: a row added without one runs nowhere.
func TestEveryAdmissionRowRunsOnT2(t *testing.T) {
	tested := []string{
		"signers", "outside the AdminSet", "the recovery window", "two first devices racing", "owner consent", "committers",
		"seats", "agents cost no commit", "read-only page Workers", "the compromise cascade", "the cascade reads every confirmation",
		"auth keys", "generated logs",
	}
	rows := AdmissionRows()
	if len(rows) != len(tested) {
		t.Fatalf("%d rows, %d tests", len(rows), len(tested))
	}
	for i, row := range rows {
		if row.Name != tested[i] {
			t.Errorf("row %d is %q, its test runs %q", i, row.Name, tested[i])
		}
	}
}
