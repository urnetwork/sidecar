package sidecartest

// §22.7's admission suite on T2 (TEAM-M2-19): each row its own top-level test, on FakeApi over T2's fake first
// cluster, every reader compared with the reference after every entry. server/api/sidecar_admission_t3_test.go runs
// the same rows on server's sequencer.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
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

// Holds a network's first device between entry 1 and its genesis, where plan-TEAM-genesis-custody #3 has every other
// api instance answer 503: the PUT of the network's position 0 waits, with entry 1 landed, until Release, or until
// reads of that network have been answered that 503 ReleaseAfterAnswerCount times. A host under load opens the same
// window by chance (tip-check at b4e2457, the leaktest leg); here it opens on every run. Nothing waits past the
// caller's context, the row's timeout. Safe for concurrent use.
type admissionGenesisHold struct {
	// How many reads answered the 503 release the hold; 0 leaves it to Release.
	ReleaseAfterAnswerCount int

	stateLock sync.Mutex
	// the network held, zero until Arm
	networkId sidecar.Id
	// closed when a write of the genesis first waits, and when the hold ends
	held     chan struct{}
	released chan struct{}
	// the writes of the genesis that waited, and the reads answered the 503
	heldCount   int
	answerCount int
}

func newAdmissionGenesisHold(releaseAfterAnswerCount int) *admissionGenesisHold {
	return &admissionGenesisHold{
		ReleaseAfterAnswerCount: releaseAfterAnswerCount,
		held:                    make(chan struct{}),
		released:                make(chan struct{}),
	}
}

// Holds networkId's genesis from here on.
func (self *admissionGenesisHold) Arm(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkId = networkId
}

// Ends the hold: the genesis held is written, and no later one waits.
func (self *admissionGenesisHold) Release() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.releaseWithLock()
}

func (self *admissionGenesisHold) releaseWithLock() {
	select {
	case <-self.released:
	default:
		close(self.released)
	}
}

// Closed once a first device stands between its entry 1 and its genesis.
func (self *admissionGenesisHold) Held() <-chan struct{} {
	return self.held
}

// How many writes of the genesis waited, and how many reads were answered the 503.
func (self *admissionGenesisHold) Counts() (heldCount int, answerCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.heldCount, self.answerCount
}

// A tier's api factory with the hold in it: each api's store holds the genesis, and each api's reads count the 503.
func (self *admissionGenesisHold) Wrap(newApi AdmissionApiFactory) AdmissionApiFactory {
	return func(clock sidecar.Clock, cluster sidecar.BlobCluster) AdmissionApi {
		return admissionGenesisHoldApi{AdmissionApi: newApi(clock, admissionGenesisHoldCluster{BlobCluster: cluster, hold: self}), hold: self}
	}
}

// Waits out the hold before a write of the armed network's genesis.
func (self *admissionGenesisHold) beforePut(ctx context.Context, key string) error {
	self.stateLock.Lock()
	if self.networkId == (sidecar.Id{}) || key != sidecar.ConfigEntryKey(self.networkId, 0) {
		self.stateLock.Unlock()
		return nil
	}
	self.heldCount += 1
	if self.heldCount == 1 {
		close(self.held)
	}
	self.stateLock.Unlock()
	select {
	case <-self.released:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Counts a read of the armed network answered the 503.
func (self *admissionGenesisHold) answered(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if networkId != self.networkId {
		return
	}
	self.answerCount += 1
	if self.answerCount == self.ReleaseAfterAnswerCount {
		self.releaseWithLock()
	}
}

// The tier's cluster as an api under the hold writes to it.
type admissionGenesisHoldCluster struct {
	sidecar.BlobCluster
	hold *admissionGenesisHold
}

func (self admissionGenesisHoldCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if err := self.hold.beforePut(ctx, key); err != nil {
		return "", err
	}
	return self.BlobCluster.PutIfNoneMatch(ctx, key, body, options)
}

// The tier's api as a device under the hold reads it.
type admissionGenesisHoldApi struct {
	AdmissionApi
	hold *admissionGenesisHold
}

func (self admissionGenesisHoldApi) ReadConfigProjection(ctx context.Context, networkId sidecar.Id, after uint64) (*sidecar.ConfigProjection, error) {
	projection, err := self.AdmissionApi.ReadConfigProjection(ctx, networkId, after)
	if errors.Is(err, ErrFakeApiGenesisMissing) {
		self.hold.answered(networkId)
	}
	return projection, err
}

// The racing row on the schedule a loaded host reaches by chance: the winner stands between entry 1 and its genesis
// until the loser has been answered the 503, so the loser always bootstraps again, and learns the genesis only because
// it waited for the winner's return.
func TestAdmissionTwoFirstDevicesRacingWithTheGenesisHeld(t *testing.T) {
	hold := newAdmissionGenesisHold(1)
	tier := admissionT2Tier(t)
	tier.NewApi = hold.Wrap(tier.NewApi)
	net := NewAdmissionNet(t, tier)
	defer net.Close()
	hold.Arm(admissionRacingNetworkId(net))
	admissionRowFirstDevicesRacing(t, net)
	if heldCount, answerCount := hold.Counts(); heldCount != 1 || answerCount != 1 {
		t.Fatalf("%d writes of the genesis held and %d reads answered the 503, each once in this schedule", heldCount, answerCount)
	}
}

// plan-TEAM-genesis-custody #3 as the racing row relies on it: while the winner stands between entry 1 and its
// genesis, a second first device is answered 503 however often it bootstraps again, three times here; once the
// winner's bootstrap has returned, one more bootstrap learns the winning genesis.
func TestAFirstDeviceLearnsTheGenesisOnlyAfterTheWinnerReturns(t *testing.T) {
	hold := newAdmissionGenesisHold(0)
	tier := admissionT2Tier(t)
	tier.NewApi = hold.Wrap(tier.NewApi)
	net := NewAdmissionNet(t, tier)
	defer net.Close()
	race := newAdmissionRace(net)
	hold.Arm(race.networkId)

	var winnerResult *sidecar.ConfigBootstrapResult
	var winnerErr error
	winnerReturned := make(chan struct{})
	go func() {
		defer close(winnerReturned)
		winnerResult, winnerErr = race.bootstrap(0)
	}()
	defer func() {
		hold.Release()
		<-winnerReturned
	}()
	select {
	case <-hold.Held():
	case <-winnerReturned:
		t.Fatalf("the first device returned without writing a genesis: %v", winnerErr)
	case <-net.Context().Done():
		t.Fatal("the first device never reached its genesis")
	}
	for try := range 3 {
		result, err := race.bootstrap(1)
		refusal := &ConfigLogRefusal{}
		if result != nil || !errors.As(err, &refusal) || refusal.Status != http.StatusServiceUnavailable || !errors.Is(err, ErrFakeApiGenesisMissing) {
			t.Fatalf("try %d before the genesis: %+v, %v", try, result, err)
		}
	}
	hold.Release()
	<-winnerReturned
	if winnerErr != nil || !winnerResult.Won {
		t.Fatalf("the first device: %+v, %v", winnerResult, winnerErr)
	}
	result, err := race.bootstrap(1)
	if err != nil || result.Won || !bytes.Equal(result.SignedGenesis, winnerResult.SignedGenesis) {
		t.Fatalf("the second device after the winner returned: %+v, %v", result, err)
	}
	if heldCount, answerCount := hold.Counts(); heldCount != 1 || answerCount != 3 {
		t.Fatalf("%d writes of the genesis held and %d reads answered the 503", heldCount, answerCount)
	}
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
