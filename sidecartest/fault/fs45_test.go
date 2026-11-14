package fault

// FS-45 (§20.6's relayed bytes, FI-13 (a); QUOTA-M2-13) on T2. sidecar.Quota carries no relayed reservation:
// the grant rule and its Redis tokens are server's (QUOTA-M2-08, QUOTA-M2-09), and they run this row at T3 in
// server's quotahost. Here the row runs on a twin of that rule over the fake Quota's balances, with FI-13's
// oracle after every step: pairs on a network near empty get grants that shrink and stop at the balance; a
// spent network refuses the next contract; a pair bound to a stream reserves and debits nothing; a contract
// settles one debit however often its close is replayed, since the debit is keyed by its contract id; and
// with the reservations lost the next grants over-admit by no more than the grants then outstanding, as a
// lease's loss is bounded by its draws.

import (
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	fs45Mib     = int64(1024 * 1024)
	fs45Request = 64 * fs45Mib
	fs45Floor   = 1 * fs45Mib
)

// The relayed reservation rule (§20.6): a grant is the request, cut to an eighth of what the balance has
// unreserved and raised to the floor; with less than the floor unreserved the contract is refused and the
// network marked spent. The settlement debits what was used, capped at the grant, once per contract id.
type fs45Twin struct {
	t         *testing.T
	quota     *sidecartest.FakeQuota
	oracle    *sidecartest.QuotaOracle
	networkId connect.Id
	// Redis: what each open contract holds
	contractHeldByteCounts map[connect.Id]int64
	// Postgres: each contract's grant, kept across a Redis loss
	contractGrantByteCounts map[connect.Id]int64
}

func newFs45Twin(t *testing.T, balanceByteCount int64) *fs45Twin {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	quota := sidecartest.NewFakeQuota(clock, sidecartest.NewFaultQueue(), nil)
	twin := &fs45Twin{
		t:                       t,
		quota:                   quota,
		oracle:                  sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		networkId:               connect.NewId(),
		contractHeldByteCounts:  map[connect.Id]int64{},
		contractGrantByteCounts: map[connect.Id]int64{},
	}
	quota.SetBalance(twin.networkId, balanceByteCount)
	twin.oracle.Grant(twin.networkId, balanceByteCount)
	return twin
}

func (self *fs45Twin) left() int64 {
	return self.quota.Balances(self.networkId)[0].ByteCount
}

func (self *fs45Twin) held() (held int64) {
	for _, byteCount := range self.contractHeldByteCounts {
		held += byteCount
	}
	return
}

func (self *fs45Twin) spent() bool {
	overLimit, err := self.quota.OverLimit(self.t.Context())
	if err != nil {
		self.t.Fatal(err)
	}
	return overLimit.SpentNetworkIdRefusals[self.networkId] != nil
}

// CreateContract for one pair: the contract and its grant, or a refusal.
func (self *fs45Twin) reserve(streamBound bool) (contractId connect.Id, grant int64, ok bool) {
	self.t.Helper()
	contractId = connect.NewId()
	if streamBound {
		// P2P bytes never count: nothing reserved, no payer
		return contractId, fs45Request, true
	}
	available := self.left() - self.held()
	if available < fs45Floor {
		self.quota.SetSpentRefusal(self.networkId, &sidecar.QuotaRefusal{LimitKey: "data", Upgrade: true})
		return contractId, 0, false
	}
	grant = min(fs45Request, max(fs45Floor, available/8))
	self.contractHeldByteCounts[contractId] = grant
	self.contractGrantByteCounts[contractId] = grant
	self.check()
	return contractId, grant, true
}

// The contract's close, replayed or not: the debit is one usage keyed by the contract id, and the rest of
// the reservation returns.
func (self *fs45Twin) settle(contractId connect.Id, usedByteCount int64) {
	self.t.Helper()
	grant, ok := self.contractGrantByteCounts[contractId]
	if !ok {
		// a stream-bound pair: no payer, no debit
		return
	}
	batch := &sidecar.UsageBatch{
		BatchId:  contractId,
		Producer: sidecar.QuotaProducerTaskworker,
		Events:   []*sidecar.UsageEvent{{NetworkId: self.networkId, Meter: sidecar.QuotaMeterRelay, TransferByteCount: min(usedByteCount, grant)}},
	}
	if err := self.quota.ReportUsage(self.t.Context(), batch); err != nil {
		self.t.Fatal(err)
	}
	delete(self.contractHeldByteCounts, contractId)
	self.check()
}

func (self *fs45Twin) loseRedis() {
	self.quota.LoseRedis()
	self.contractHeldByteCounts = map[connect.Id]int64{}
}

func (self *fs45Twin) check() {
	self.t.Helper()
	if err := self.oracle.Check(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
}

// A network near empty with N relayed pairs: grants shrink from an eighth to the floor and stop at the
// balance, the refusal marks the network spent, and spending stops at the balance: every pair using its
// whole grant leaves the balance at or above zero.
func TestFs45GrantsShrinkAndSpendingStopsAtTheBalance(t *testing.T) {
	room := 100 * fs45Mib
	twin := newFs45Twin(t, room)
	contractIds := []connect.Id{}
	grants := []int64{}
	total := int64(0)
	for range 400 {
		contractId, grant, ok := twin.reserve(false)
		if !ok {
			break
		}
		contractIds = append(contractIds, contractId)
		grants = append(grants, grant)
		total += grant
	}
	if len(grants) == 400 {
		t.Fatal("no refusal after 400 grants")
	}
	for index := 1; index < len(grants); index++ {
		if grants[index-1] < grants[index] {
			t.Fatalf("grant %d grew: %v", index, grants)
		}
	}
	if grants[0] != room/8 || grants[len(grants)-1] != fs45Floor {
		t.Fatalf("grants did not shrink from an eighth to the floor: %v", grants)
	}
	if room < total || fs45Floor <= room-total {
		t.Fatalf("grants of %d stopped short of or past the balance of %d", total, room)
	}
	if !twin.spent() {
		t.Fatal("the refusal left the network unmarked")
	}
	// spent refuses CreateContract until a balance has room
	if _, _, ok := twin.reserve(false); ok {
		t.Fatal("a spent network was granted a contract")
	}
	for index, contractId := range contractIds {
		twin.oracle.Meter(twin.networkId, sidecar.QuotaMeterRelay, grants[index])
		twin.settle(contractId, grants[index])
	}
	if err := twin.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := twin.left(); left < 0 || left != room-total {
		t.Fatalf("%d left of %d after %d granted and spent", left, room, total)
	}
}

// A P2P-bound pair is unaffected: it is granted its request on a spent network, and its close debits nothing.
func TestFs45StreamBoundPairIsUnaffected(t *testing.T) {
	twin := newFs45Twin(t, fs45Floor/2)
	if _, _, ok := twin.reserve(false); ok {
		t.Fatal("a relayed pair was granted past the balance")
	}
	contractId, grant, ok := twin.reserve(true)
	if !ok || grant != fs45Request {
		t.Fatalf("the stream-bound pair: %d, %v", grant, ok)
	}
	twin.settle(contractId, grant)
	if err := twin.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := twin.left(); left != fs45Floor/2 {
		t.Fatalf("%d left", left)
	}
}

// One debit per contract_id: a close replayed, by either side or by the deadline, debits once, capped at the
// grant.
func TestFs45OneDebitPerContract(t *testing.T) {
	room := 1024 * fs45Mib
	twin := newFs45Twin(t, room)
	contractId, grant, ok := twin.reserve(false)
	if !ok || grant != fs45Request {
		t.Fatalf("grant %d, %v", grant, ok)
	}
	used := grant / 2
	twin.oracle.Meter(twin.networkId, sidecar.QuotaMeterRelay, used)
	for range 3 {
		twin.settle(contractId, used)
	}
	if err := twin.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := twin.left(); left != room-used {
		t.Fatalf("%d left, want %d", left, room-used)
	}
	if held := twin.held(); held != 0 {
		t.Fatalf("%d still reserved after the close", held)
	}
	// a pair reporting past its grant debits the grant
	contractId, grant, _ = twin.reserve(false)
	twin.oracle.Meter(twin.networkId, sidecar.QuotaMeterRelay, grant)
	twin.settle(contractId, 3*grant)
	if left := twin.left(); left != room-used-grant {
		t.Fatalf("%d left after an over-report", left)
	}
}

// Redis loss over-admits at most as for leases: the grants outstanding at the loss are forgotten, the next
// grants are judged against the whole balance, and every contract still debits once, so the balance ends no
// further below zero than the grants the loss forgot.
func TestFs45RedisLossOverAdmitsByTheOutstandingGrants(t *testing.T) {
	room := 100 * fs45Mib
	twin := newFs45Twin(t, room)
	contractIds := []connect.Id{}
	grants := []int64{}
	reserveUntilRefused := func() {
		for range 400 {
			contractId, grant, ok := twin.reserve(false)
			if !ok {
				return
			}
			contractIds = append(contractIds, contractId)
			grants = append(grants, grant)
		}
		t.Fatal("no refusal after 400 grants")
	}
	reserveUntilRefused()
	forgotten := twin.held()
	twin.loseRedis()
	twin.quota.SetSpentRefusal(twin.networkId, nil)
	reserveUntilRefused()
	for index, contractId := range contractIds {
		twin.oracle.Meter(twin.networkId, sidecar.QuotaMeterRelay, grants[index])
		twin.settle(contractId, grants[index])
		// the replay after the loss: Postgres kept the debit's id
		twin.settle(contractId, grants[index])
	}
	if err := twin.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := twin.left(); 0 <= left || left < -forgotten {
		t.Fatalf("%d left: the loss forgot %d, which bounds the over-admission", left, forgotten)
	}
}
