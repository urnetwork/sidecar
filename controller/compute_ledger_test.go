package controller

// The ledger's calls as far as the sidecar repo sees them (BAL-M12-03): what each refuses before any store is asked,
// the refusals' answers, a hold whose row PostgreSQL refuses voided and answered capacity, and a budget refusal naming
// its line. The calls on real PostgreSQL and Redis, the real Lua, run in server/computet3/compute_ledger_t3_test.go.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// An Env over a scripted Redis and a Db that refuses or counts, with a still clock; every other service refuses.
type testLedgerEnv struct {
	operator.Env
	redis *testLedgerRedis
	db    *testLedgerDb
	clock *testLedgerClock
}

func newTestLedgerEnv() *testLedgerEnv {
	return &testLedgerEnv{
		redis: &testLedgerRedis{},
		db:    &testLedgerDb{},
		clock: &testLedgerClock{now: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)},
	}
}

func (self *testLedgerEnv) Redis() (operator.Redis, error) {
	return self.redis, nil
}

func (self *testLedgerEnv) Db() (operator.Db, error) {
	return self.db, nil
}

func (self *testLedgerEnv) Clock() (operator.Clock, error) {
	return self.clock, nil
}

// A Redis whose scripts answer from replies, by script name, and record each call.
type testLedgerRedis struct {
	operator.Redis
	replies map[string][]string
	calls   []string
}

func (self *testLedgerRedis) RunScript(ctx context.Context, script *operator.RedisScript, keys []string, args []string) (*operator.RedisReply, error) {
	self.calls = append(self.calls, script.Name)
	values, ok := self.replies[script.Name]
	if !ok {
		return nil, errors.New("no reply for the script")
	}
	reply := &operator.RedisReply{Kind: operator.RedisReplyArray}
	for _, value := range values {
		reply.Replies = append(reply.Replies, &operator.RedisReply{Kind: operator.RedisReplyBulk, Bulk: []byte(value)})
	}
	return reply, nil
}

// A Db that refuses every call, counting them.
type testLedgerDb struct {
	callCount int
}

var errTestLedgerDbRefused = errors.New("the database refuses")

func (self *testLedgerDb) Db(ctx context.Context, callback func(conn operator.DbConn) error, options ...operator.DbOption) error {
	self.callCount += 1
	return errTestLedgerDbRefused
}

func (self *testLedgerDb) Tx(ctx context.Context, callback func(tx operator.DbTx) error, options ...operator.DbOption) error {
	self.callCount += 1
	return errTestLedgerDbRefused
}

// A clock that stands still.
type testLedgerClock struct {
	now time.Time
}

func (self *testLedgerClock) Now() time.Time {
	return self.now
}

func (self *testLedgerClock) After(timeout time.Duration) <-chan time.Time {
	channel := make(chan time.Time, 1)
	channel <- self.now.Add(timeout)
	return channel
}

func (self *testLedgerClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}

// A TEE call's request on fresh ids, holding $2.58 against an agent's day and a device's ceiling.
func testLedgerTeeRequest(settings *model.ComputeLedgerSettings) *ComputeHoldRequest {
	catalogId := "chutes-qwen3.8-27b-tee-high"
	version := int64(7)
	priceRead := int64(1764000000)
	providerRef := "instance-3:nonce-91"
	agentId := testOpKeyId(0x30)
	sidecarId := testOpKeyId(0x20)
	hold := int64(2_580_000_000)
	return &ComputeHoldRequest{
		NetworkId: testOpKeyId(0x10), Kind: model.ComputeChargeKindInference, Path: model.ComputeHoldPathTee,
		SubjectRef: testOpKeyId(0x40), SidecarId: sidecarId, AgentId: &agentId, MemberId: nil,
		CatalogId: &catalogId, CatalogVersion: &version, Provider: 1, PriceRead: &priceRead, ProviderRef: &providerRef,
		HoldNanoUsd: hold, ReserveNanoUsd: hold,
		Lines: []*model.ComputeBudgetLine{
			{SubjectId: agentId, Budget: model.ComputeBudgetAgent, Period: model.ComputeBudgetPeriodDay, CapNanoUsd: settings.DefaultAgentDayNanoUsd},
			{SubjectId: sidecarId, Budget: model.ComputeBudgetCeiling, Period: model.ComputeBudgetPeriodDay, CapNanoUsd: settings.DefaultDeviceCeilingDayNanoUsd},
		},
	}
}

// Each refusal's code, status, reason and retry (§6.6), as the broker replies.
func TestComputeRefusalAnswers(t *testing.T) {
	line := &model.ComputeBudgetLine{SubjectId: testOpKeyId(1), Budget: model.ComputeBudgetAgent, Period: model.ComputeBudgetPeriodMonth, CapNanoUsd: 1}
	cases := []struct {
		refusal *ComputeRefusal
		want    *ComputeRefusalReply
	}{
		{
			refusal: &ComputeRefusal{Reason: ComputeRefusalBalance},
			want:    &ComputeRefusalReply{Status: http.StatusPaymentRequired, Code: "insufficient_quota", Reason: "balance"},
		},
		{
			refusal: &ComputeRefusal{Reason: ComputeRefusalBudget, Line: line},
			want:    &ComputeRefusalReply{Status: http.StatusPaymentRequired, Code: "insufficient_quota", Reason: "budget", Budget: "agent", Period: "month"},
		},
		{
			refusal: &ComputeRefusal{Reason: ComputeRefusalHeld, RetryAfter: 2 * time.Second},
			want:    &ComputeRefusalReply{Status: http.StatusTooManyRequests, Code: "insufficient_quota", Reason: "held", RetryAfter: 2 * time.Second},
		},
		{
			refusal: &ComputeRefusal{Reason: ComputeRefusalCapacity, RetryAfter: 5 * time.Second},
			want:    &ComputeRefusalReply{Status: http.StatusServiceUnavailable, Code: "capacity", RetryAfter: 5 * time.Second},
		},
		// a reason the ledger does not name refuses as capacity, never admits
		{
			refusal: &ComputeRefusal{Reason: "other", RetryAfter: time.Second},
			want:    &ComputeRefusalReply{Status: http.StatusServiceUnavailable, Code: "capacity", RetryAfter: time.Second},
		},
	}
	for _, c := range cases {
		got := ComputeRefusalAnswer(c.refusal)
		if *got != *c.want {
			t.Errorf("%s answers %+v, want %+v", c.refusal.Reason, got, c.want)
		}
	}
}

// What a hold refuses before Redis or PostgreSQL is asked: local inference and any hold naming no remote provider, a
// kind its path does not hold, a call carrying a derived key or a derived key with no time, a reservation that is not
// the hold, a catalog id or provider reference that is no id (a planted prompt among them), and a search with no
// attempt; and the paths not built yet, refused rather than held some other way.
func TestComputeHoldRefusesBeforeAnyStore(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	derivedKey := testOpKeyId(0x90)
	attempt := int16(1)
	prompt := "summarize my unread mail for me"
	longRef := strings.Repeat("r", settings.ProviderRefMaxByteCount+1)
	cases := []struct {
		name   string
		change func(request *ComputeHoldRequest)
		want   error
	}{
		{name: "local inference", change: func(request *ComputeHoldRequest) { request.Provider = 0 }, want: ErrComputeLedgerArgs},
		{name: "an enclave kind by the tee path", change: func(request *ComputeHoldRequest) { request.Kind = model.ComputeChargeKindEnclaveRun }, want: ErrComputeLedgerArgs},
		{name: "a reserved kind", change: func(request *ComputeHoldRequest) { request.Kind = model.ComputeChargeKindEnclaveDisk }, want: ErrComputeLedgerArgs},
		{name: "an adjustment", change: func(request *ComputeHoldRequest) { request.Kind = model.ComputeChargeKindAdjustment }, want: ErrComputeLedgerArgs},
		{name: "a call with a derived key", change: func(request *ComputeHoldRequest) { request.OpKey = &derivedKey }, want: ErrComputeLedgerArgs},
		{name: "a call with its own start", change: func(request *ComputeHoldRequest) { request.StartTime = time.Unix(1764000000, 0) }, want: ErrComputeLedgerArgs},
		{name: "a reservation past the hold", change: func(request *ComputeHoldRequest) { request.ReserveNanoUsd += 1 }, want: ErrComputeLedgerArgs},
		{name: "a prompt as the catalog id", change: func(request *ComputeHoldRequest) { request.CatalogId = &prompt }, want: model.ErrComputeOpArgs},
		{name: "a provider reference past its bound", change: func(request *ComputeHoldRequest) { request.ProviderRef = &longRef }, want: model.ErrComputeOpArgs},
		{name: "no sidecar", change: func(request *ComputeHoldRequest) { request.SidecarId = operator.Id{} }, want: ErrComputeLedgerArgs},
		{
			name: "a search with no attempt",
			change: func(request *ComputeHoldRequest) {
				request.Kind, request.Path, request.OpKey, request.StartTime = model.ComputeChargeKindWebSearch, model.ComputeHoldPathSearch, &derivedKey, time.Unix(1764000000, 0)
			},
			want: ErrComputeLedgerArgs,
		},
		{
			name: "the search path, unbuilt",
			change: func(request *ComputeHoldRequest) {
				request.Kind, request.Path, request.OpKey, request.StartTime, request.Attempt = model.ComputeChargeKindWebSearch, model.ComputeHoldPathSearch, &derivedKey, time.Unix(1764000000, 0), &attempt
			},
			want: model.ErrComputeHoldPathUnbuilt,
		},
		{
			name: "the interval path, unbuilt",
			change: func(request *ComputeHoldRequest) {
				request.Kind, request.Path, request.OpKey, request.StartTime = model.ComputeChargeKindEnclaveRun, model.ComputeHoldPathInterval, &derivedKey, time.Unix(1764000000, 0)
			},
			want: model.ErrComputeHoldPathUnbuilt,
		},
		{name: "the direct path, unbuilt", change: func(request *ComputeHoldRequest) { request.Path = model.ComputeHoldPathDirect }, want: model.ErrComputeHoldPathUnbuilt},
	}
	for _, c := range cases {
		env := newTestLedgerEnv()
		request := testLedgerTeeRequest(settings)
		c.change(request)
		answer, err := ComputeHold(env, context.Background(), settings, request)
		if !errors.Is(err, c.want) || answer != nil {
			t.Errorf("%s: %v, %+v, want %v", c.name, err, answer, c.want)
		}
		if len(env.redis.calls) != 0 || env.db.callCount != 0 {
			t.Errorf("%s reached the stores: %v and %d database calls", c.name, env.redis.calls, env.db.callCount)
		}
		if strings.Contains(err.Error(), prompt) {
			t.Errorf("%s: the refusal repeats what it refused", c.name)
		}
	}
}

// A hold whose row PostgreSQL cannot take is voided at once and answered capacity with the settings' retry; it is never
// confirmed, so nothing reaches the provider (§9.7's handoff).
func TestComputeHoldWhoseRowIsRefusedAnswersCapacity(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	env := newTestLedgerEnv()
	env.redis.replies = map[string][]string{
		"compute-projection-hold": {"taken", "0", "1764072000000"},
		"compute-projection-void": {"void"},
	}
	answer, err := ComputeHold(env, context.Background(), settings, testLedgerTeeRequest(settings))
	if err != nil {
		t.Fatal(err)
	}
	if answer.Admitted || answer.Refusal == nil || answer.Refusal.Reason != ComputeRefusalCapacity || answer.Refusal.RetryAfter != settings.CapacityRetry {
		t.Fatalf("answered %+v", answer)
	}
	if !slices.Equal(env.redis.calls, []string{"compute-projection-hold", "compute-projection-void"}) {
		t.Errorf("the scripts run were %v", env.redis.calls)
	}
	if env.db.callCount != 1 {
		t.Errorf("%d database calls, want the row's one", env.db.callCount)
	}
	reply := ComputeRefusalAnswer(answer.Refusal)
	if reply.Status != http.StatusServiceUnavailable || reply.Code != "capacity" {
		t.Errorf("the broker replies %+v", reply)
	}
}

// A budget refusal names the line that refused, its budget and its period; a balance refusal and a held one are
// answered as the script gave them, the held one with the script's retry; none reaches PostgreSQL.
func TestComputeHoldRefusalsNameWhatRefused(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	request := testLedgerTeeRequest(settings)
	cases := []struct {
		reply []string
		want  ComputeRefusal
	}{
		{reply: []string{"budget", "0", "1764072000000", "1"}, want: ComputeRefusal{Reason: ComputeRefusalBudget, Line: request.Lines[1]}},
		{reply: []string{"balance", "0", "1764072000000"}, want: ComputeRefusal{Reason: ComputeRefusalBalance}},
		{reply: []string{"held", "2000", "1764072000000"}, want: ComputeRefusal{Reason: ComputeRefusalHeld, RetryAfter: 2 * time.Second}},
	}
	for _, c := range cases {
		env := newTestLedgerEnv()
		env.redis.replies = map[string][]string{"compute-projection-hold": c.reply}
		answer, err := ComputeHold(env, context.Background(), settings, request)
		if err != nil {
			t.Fatal(err)
		}
		if answer.Admitted || answer.Refusal == nil || *answer.Refusal != c.want {
			t.Errorf("%v answered %+v", c.reply, answer.Refusal)
		}
		if env.db.callCount != 0 {
			t.Errorf("%v reached PostgreSQL", c.reply)
		}
	}
	// the budget's reply names the device's ceiling for the day
	env := newTestLedgerEnv()
	env.redis.replies = map[string][]string{"compute-projection-hold": {"budget", "0", "1764072000000", "1"}}
	answer, _ := ComputeHold(env, context.Background(), settings, request)
	reply := ComputeRefusalAnswer(answer.Refusal)
	if reply.Budget != model.ComputeBudgetCeiling || reply.Period != "day" {
		t.Errorf("the budget refusal replies %+v", reply)
	}
	// a line index the request does not have is the script's error, never a refusal of some other line
	env = newTestLedgerEnv()
	env.redis.replies = map[string][]string{"compute-projection-hold": {"budget", "0", "1764072000000", "2"}}
	if _, err := ComputeHold(env, context.Background(), settings, request); !errors.Is(err, model.ErrComputeProjectionReply) {
		t.Errorf("a line out of range: %v", err)
	}
}

// A settlement of the direct path waits for BAL-M12-21, and one with no outcome is refused, before any store is asked.
func TestComputeSettleRefusesBeforeAnyStore(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	outcome := &ComputeOutcome{AmountNanoUsd: 1, EndTime: time.Unix(1764000000, 0), SettleTime: time.Unix(1764000000, 0)}
	env := newTestLedgerEnv()
	if _, err := ComputeSettle(env, context.Background(), settings, &ComputeSettleRequest{NetworkId: testOpKeyId(1), OpKey: testOpKeyId(2), Path: model.ComputeHoldPathDirect, Outcome: outcome}); !errors.Is(err, model.ErrComputeHoldPathUnbuilt) {
		t.Errorf("a direct settlement: %v", err)
	}
	if _, err := ComputeSettle(env, context.Background(), settings, &ComputeSettleRequest{NetworkId: testOpKeyId(1), OpKey: testOpKeyId(2), Path: model.ComputeHoldPathTee}); !errors.Is(err, ErrComputeLedgerArgs) {
		t.Errorf("no outcome: %v", err)
	}
	negative := *outcome
	negative.AmountNanoUsd = -1
	if _, err := ComputeSettle(env, context.Background(), settings, &ComputeSettleRequest{NetworkId: testOpKeyId(1), OpKey: testOpKeyId(2), Path: model.ComputeHoldPathTee, Outcome: &negative}); !errors.Is(err, model.ErrComputeOpArgs) {
		t.Errorf("a negative charge: %v", err)
	}
	if len(env.redis.calls) != 0 || env.db.callCount != 0 {
		t.Errorf("a refused settlement reached the stores: %v, %d", env.redis.calls, env.db.callCount)
	}
}

// A settled write is one of §9.7's three, each held to its shape before any store is asked: a refund keyed by the
// charge it returns, an adjustment on the network's own line, a host egress hour naming its enclave and provider.
func TestComputeWriteSettledChecksItsShape(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	start := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	enclaveId := testOpKeyId(0x70)
	chargeId := testOpKeyId(0xa0)
	outcome := func(amount int64) *ComputeOutcome {
		return &ComputeOutcome{AmountNanoUsd: amount, EndTime: start, SettleTime: start}
	}
	cases := []struct {
		name  string
		write *ComputeSettledWrite
	}{
		{
			name: "a refund keyed by another charge",
			write: &ComputeSettledWrite{NetworkId: testOpKeyId(1), OpKey: ComputeOpKeyForRefund(testOpKeyId(0xa1)), Kind: model.ComputeChargeKindInference,
				SubjectRef: chargeId, SidecarId: testOpKeyId(2), Provider: 1, StartTime: start, Outcome: outcome(-5)},
		},
		{
			name: "an adjustment naming a sidecar",
			write: &ComputeSettledWrite{NetworkId: testOpKeyId(1), OpKey: ComputeOpKeyForAdjustment(testOpKeyId(3), 1), Kind: model.ComputeChargeKindAdjustment,
				SubjectRef: testOpKeyId(3), SidecarId: testOpKeyId(2), StartTime: start, Outcome: outcome(5)},
		},
		{
			name: "an egress hour naming no enclave",
			write: &ComputeSettledWrite{NetworkId: testOpKeyId(1), OpKey: testOpKeyId(4), Kind: model.ComputeChargeKindEnclaveHostEgress,
				SubjectRef: enclaveId, SidecarId: testOpKeyId(2), Provider: 4, StartTime: start, Outcome: outcome(5)},
		},
		{
			name: "a positive inference charge, which an admission holds",
			write: &ComputeSettledWrite{NetworkId: testOpKeyId(1), OpKey: testOpKeyId(4), Kind: model.ComputeChargeKindInference,
				SubjectRef: testOpKeyId(5), SidecarId: testOpKeyId(2), Provider: 1, StartTime: start, Outcome: outcome(5)},
		},
		{
			name: "a reserved kind's refund",
			write: &ComputeSettledWrite{NetworkId: testOpKeyId(1), OpKey: ComputeOpKeyForRefund(chargeId), Kind: model.ComputeChargeKindEnclaveDisk,
				SubjectRef: chargeId, SidecarId: testOpKeyId(2), Provider: 4, StartTime: start, Outcome: outcome(-5)},
		},
	}
	for _, c := range cases {
		env := newTestLedgerEnv()
		if _, err := ComputeWriteSettled(env, context.Background(), settings, c.write); !errors.Is(err, ErrComputeLedgerArgs) {
			t.Errorf("%s: %v", c.name, err)
		}
		if len(env.redis.calls) != 0 || env.db.callCount != 0 {
			t.Errorf("%s reached the stores", c.name)
		}
	}
}
