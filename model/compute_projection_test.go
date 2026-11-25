//go:build !sidecar_http && !ios_extension

package model

// The projection's calls as far as the sidecar repo sees them (BAL-M12-02): every call's keys on one slot, what each
// call refuses before Redis, §16.5's default lines, the counters' UTC periods, and the scripts' sources holding to the
// rules a script keeps. The scripts' behavior runs on the private stack's Redis, real Lua, in
// server/computet3/compute_projection_t3_test.go.

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"
	"github.com/urnetwork/sidecar"
)

// An Env whose Redis records each script call and answers it from a table, and refuses everything else.
type testProjectionEnv struct {
	operator.Env
	redis *testProjectionRedis
}

func (self *testProjectionEnv) Redis() (operator.Redis, error) {
	return self.redis, nil
}

// One script call: the script's name, its KEYS and ARGV.
type testProjectionCall struct {
	name string
	keys []string
	args []string
}

type testProjectionRedis struct {
	operator.Redis
	calls []*testProjectionCall
	// the projection's fields, for a rebuild's read of the subjects it listed
	fields map[string][]byte
}

func (self *testProjectionRedis) HashGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	return self.fields, nil
}

func (self *testProjectionRedis) RunScript(ctx context.Context, script *operator.RedisScript, keys []string, args []string) (*operator.RedisReply, error) {
	self.calls = append(self.calls, &testProjectionCall{name: script.Name, keys: keys, args: args})
	bulk := func(values ...string) *operator.RedisReply {
		reply := &operator.RedisReply{Kind: operator.RedisReplyArray}
		for _, value := range values {
			reply.Replies = append(reply.Replies, &operator.RedisReply{Kind: operator.RedisReplyBulk, Bulk: []byte(value)})
		}
		return reply
	}
	switch script {
	case computeProjectionHoldScript:
		return bulk("taken", "0", "1764000000000"), nil
	case computeProjectionConfirmScript:
		return bulk("confirmed"), nil
	case computeProjectionSettleScript:
		return bulk("settled"), nil
	case computeProjectionVoidScript:
		return bulk("void"), nil
	case computeProjectionDropScript:
		return bulk("dropped", "1", "1"), nil
	case computeProjectionRebuildScript:
		return bulk("rebuilt"), nil
	case computeProjectionMarkScript:
		return bulk("marked"), nil
	case computeProjectionReadScript:
		return bulk("7", "", "100", "10", "20", "0", "5", "0", "1"), nil
	}
	return nil, errors.New("no such script")
}

func newTestProjectionEnv() *testProjectionEnv {
	return &testProjectionEnv{redis: &testProjectionRedis{fields: map[string][]byte{}}}
}

// Every call's keys share the network's hash tag, a budget key and the unconfirmed set among them, as production's
// Redis Cluster takes a script only on one slot (§14.4).
func TestComputeScriptKeysShareOneSlot(t *testing.T) {
	env := newTestProjectionEnv()
	ctx := context.Background()
	settings := DefaultComputeLedgerSettings()
	networkId := operator.Id(sidecar.NewId())
	agentId := operator.Id(sidecar.NewId())
	sidecarId := operator.Id(sidecar.NewId())
	memberId := operator.Id(sidecar.NewId())
	opKey := operator.Id(sidecar.NewId())
	lines, err := ComputeDefaultBudgetLines(settings, &ComputeBudgetCaller{SidecarId: sidecarId, AgentId: &agentId})
	if err != nil {
		t.Fatal(err)
	}
	lines = append(lines, &ComputeBudgetLine{SubjectId: memberId, Budget: "member", Period: ComputeBudgetPeriodMonth, CapNanoUsd: 1})
	subjectIds := []operator.Id{sidecarId, agentId, memberId, networkId}
	// a subject the projection listed, which a rebuild declares too
	listed := operator.Id(sidecar.NewId())
	env.redis.fields["s:"+sidecar.EvsKeyId(sidecar.Id(listed))] = []byte("1")

	if _, err := ComputeProjectionHold(env, ctx, settings, &ComputeHoldRequest{NetworkId: networkId, OpKey: opKey, Kind: ComputeChargeKindInference,
		Path: ComputeHoldPathTee, HoldNanoUsd: 1, ReserveNanoUsd: 1, Lines: lines}); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeProjectionConfirm(env, ctx, settings, networkId, opKey, subjectIds); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeProjectionSettle(env, ctx, settings, &ComputeSettleRequest{NetworkId: networkId, OpKey: opKey, Kind: ComputeChargeKindInference,
		Path: ComputeHoldPathTee, AmountNanoUsd: 1, ReserveNanoUsd: 1, StartTime: time.Now(), Lines: lines, SubjectIds: subjectIds}); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeProjectionVoid(env, ctx, settings, networkId, opKey, subjectIds); err != nil {
		t.Fatal(err)
	}
	account := &ComputeProjectionAccount{Version: 1, State: ComputeAccountStateActive}
	if _, err := ComputeProjectionDrop(env, ctx, settings, &ComputeDropRequest{NetworkId: networkId, Account: account,
		Ops: []*ComputeDropOp{{OpKey: opKey, AmountNanoUsd: 1}}, SubjectIds: subjectIds}); err != nil {
		t.Fatal(err)
	}
	if err := ComputeProjectionRebuild(env, ctx, settings, &ComputeProjectionSnapshot{NetworkId: networkId, Account: account,
		Holds:    []*ComputeProjectionHoldRow{{OpKey: opKey, Kind: ComputeChargeKindInference, HoldNanoUsd: 1, ReserveNanoUsd: 1, StartTime: time.Now(), Lines: lines}},
		Counters: []*ComputeProjectionCounter{{SubjectId: memberId, Budget: "member", Period: ComputeBudgetPeriodMonth, At: time.Now(), ChargedNanoUsd: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ComputeProjectionMarkRebuild(env, ctx, networkId); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeProjectionRead(env, ctx, networkId); err != nil {
		t.Fatal(err)
	}
	if len(env.redis.calls) != 8 {
		t.Fatalf("%d calls", len(env.redis.calls))
	}
	for _, call := range env.redis.calls {
		if !sidecar.RedisKeysShareTag(call.keys) {
			t.Errorf("%s's keys share no tag: %v", call.name, call.keys)
		}
		if call.keys[0] != ComputeProjectionKey(networkId) {
			t.Errorf("%s's first key is %s", call.name, call.keys[0])
		}
		if 1 < len(call.keys) && call.keys[1] != computeUnconfirmedKey(networkId) {
			t.Errorf("%s's second key is %s", call.name, call.keys[1])
		}
		// each key once
		if len(slices.Compact(slices.Sorted(slices.Values(call.keys)))) != len(call.keys) {
			t.Errorf("%s declares a key twice: %v", call.name, call.keys)
		}
	}
	// the hold declares each line's subject, the rebuild the listed subject too
	if !slices.Contains(env.redis.calls[0].keys, ComputeBudgetKey(networkId, agentId)) || !slices.Contains(env.redis.calls[0].keys, ComputeBudgetKey(networkId, memberId)) {
		t.Errorf("the hold's keys lack a line's subject: %v", env.redis.calls[0].keys)
	}
	if !slices.Contains(env.redis.calls[5].keys, ComputeBudgetKey(networkId, listed)) {
		t.Errorf("the rebuild's keys lack the subject the projection listed: %v", env.redis.calls[5].keys)
	}
	// the keys as §14.4 writes them
	if key := ComputeProjectionKey(networkId); key != "{cmp_"+sidecar.EvsKeyId(sidecar.Id(networkId))+"}" {
		t.Errorf("the projection's key is %s", key)
	}
	if key := ComputeBudgetKey(networkId, agentId); key != "{cmp_"+sidecar.EvsKeyId(sidecar.Id(networkId))+"}:b:"+sidecar.EvsKeyId(sidecar.Id(agentId)) {
		t.Errorf("a budget key is %s", key)
	}
}

// §16.5's default budgets: an agent's, a tagged subject's, an untagged device's for calls naming no agent and its
// ceiling across all; and a network whose policy names budgets refused until CACL's resolver reads them.
func TestComputeDefaultBudgetLinesFollowSection165(t *testing.T) {
	settings := DefaultComputeLedgerSettings()
	sidecarId := operator.Id(sidecar.NewId())
	agentId := operator.Id(sidecar.NewId())
	type want struct {
		subject operator.Id
		budget  string
		period  ComputeBudgetPeriod
		cap     int64
	}
	usd := func(dollars int64) int64 { return dollars * ComputeCreditNanoUsd }
	check := func(label string, caller *ComputeBudgetCaller, wants []want) {
		lines, err := ComputeDefaultBudgetLines(settings, caller)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		got := []want{}
		for _, line := range lines {
			got = append(got, want{subject: line.SubjectId, budget: line.Budget, period: line.Period, cap: line.CapNanoUsd})
		}
		if !slices.Equal(got, wants) {
			t.Errorf("%s: %v, want %v", label, got, wants)
		}
	}
	check("an untagged device's call naming an agent", &ComputeBudgetCaller{SidecarId: sidecarId, AgentId: &agentId}, []want{
		{subject: agentId, budget: ComputeBudgetAgent, period: ComputeBudgetPeriodDay, cap: usd(5)},
		{subject: agentId, budget: ComputeBudgetAgent, period: ComputeBudgetPeriodMonth, cap: usd(50)},
		{subject: sidecarId, budget: ComputeBudgetCeiling, period: ComputeBudgetPeriodDay, cap: usd(50)},
	})
	check("an untagged device's call naming none", &ComputeBudgetCaller{SidecarId: sidecarId}, []want{
		{subject: sidecarId, budget: ComputeBudgetDevice, period: ComputeBudgetPeriodDay, cap: usd(20)},
		{subject: sidecarId, budget: ComputeBudgetDevice, period: ComputeBudgetPeriodMonth, cap: usd(200)},
		{subject: sidecarId, budget: ComputeBudgetCeiling, period: ComputeBudgetPeriodDay, cap: usd(50)},
	})
	check("a tagged sidecar's call naming an agent", &ComputeBudgetCaller{SidecarId: sidecarId, AgentId: &agentId, Tagged: true}, []want{
		{subject: agentId, budget: ComputeBudgetAgent, period: ComputeBudgetPeriodDay, cap: usd(5)},
		{subject: agentId, budget: ComputeBudgetAgent, period: ComputeBudgetPeriodMonth, cap: usd(50)},
		{subject: sidecarId, budget: ComputeBudgetTagged, period: ComputeBudgetPeriodDay, cap: usd(5)},
		{subject: sidecarId, budget: ComputeBudgetTagged, period: ComputeBudgetPeriodMonth, cap: usd(50)},
	})
	if _, err := ComputeDefaultBudgetLines(settings, &ComputeBudgetCaller{SidecarId: sidecarId, PolicyNamesBudgets: true}); !errors.Is(err, ErrComputeBudgetsUnread) {
		t.Errorf("a policy's budgets: %v", err)
	}
}

// What each call refuses before Redis: the paths not built, a kind a path does not hold, amounts past Lua's exact
// integers or below zero, a malformed budget name, a run's period, too many lines, a negative version.
func TestComputeProjectionRefusesBeforeRedis(t *testing.T) {
	env := newTestProjectionEnv()
	ctx := context.Background()
	settings := DefaultComputeLedgerSettings()
	networkId := operator.Id(sidecar.NewId())
	line := func(budget string, period ComputeBudgetPeriod, cap int64) []*ComputeBudgetLine {
		return []*ComputeBudgetLine{{SubjectId: operator.Id(sidecar.NewId()), Budget: budget, Period: period, CapNanoUsd: cap}}
	}
	hold := func(path ComputeHoldPath, kind ComputeChargeKind, amount int64, lines []*ComputeBudgetLine) error {
		_, err := ComputeProjectionHold(env, ctx, settings, &ComputeHoldRequest{NetworkId: networkId, OpKey: operator.Id(sidecar.NewId()),
			Kind: kind, Path: path, HoldNanoUsd: amount, ReserveNanoUsd: amount, Lines: lines})
		return err
	}
	tooMany := []*ComputeBudgetLine{}
	for range settings.ProjectionHoldMaxLineCount + 1 {
		tooMany = append(tooMany, line("agent", ComputeBudgetPeriodDay, 1)...)
	}
	for label, err := range map[string]error{
		"a direct hold":    hold(ComputeHoldPathDirect, ComputeChargeKindInference, 1, nil),
		"a search hold":    hold(ComputeHoldPathSearch, ComputeChargeKindWebSearch, 1, nil),
		"an interval hold": hold(ComputeHoldPathInterval, ComputeChargeKindEnclaveRun, 1, nil),
		"a TEE search":     hold(ComputeHoldPathTee, ComputeChargeKindWebSearch, 1, nil),
		"past 2^53":        hold(ComputeHoldPathTee, ComputeChargeKindInference, 1<<53, nil),
		"a negative hold":  hold(ComputeHoldPathTee, ComputeChargeKindInference, -1, nil),
		"a budget's name":  hold(ComputeHoldPathTee, ComputeChargeKindInference, 1, line("Agent:1", ComputeBudgetPeriodDay, 1)),
		"a long name":      hold(ComputeHoldPathTee, ComputeChargeKindInference, 1, line(strings.Repeat("a", settings.ProjectionBudgetNameMaxByteCount+1), ComputeBudgetPeriodDay, 1)),
		"a run's budget":   hold(ComputeHoldPathTee, ComputeChargeKindInference, 1, line("agent", ComputeBudgetPeriodRun, 1)),
		"a cap past 2^53":  hold(ComputeHoldPathTee, ComputeChargeKindInference, 1, line("agent", ComputeBudgetPeriodDay, 1<<53)),
		"too many lines":   hold(ComputeHoldPathTee, ComputeChargeKindInference, 1, tooMany),
		"a direct settle": func() error {
			_, err := ComputeProjectionSettle(env, ctx, settings, &ComputeSettleRequest{NetworkId: networkId, Kind: ComputeChargeKindInference, Path: ComputeHoldPathDirect})
			return err
		}(),
		"an adjustment's settle": func() error {
			_, err := ComputeProjectionSettle(env, ctx, settings, &ComputeSettleRequest{NetworkId: networkId, Kind: ComputeChargeKindAdjustment, Path: ComputeHoldPathTee})
			return err
		}(),
		"a negative version": func() error {
			_, err := ComputeProjectionDrop(env, ctx, settings, &ComputeDropRequest{NetworkId: networkId, Account: &ComputeProjectionAccount{Version: -1, State: ComputeAccountStateActive}})
			return err
		}(),
		"no state": func() error {
			return ComputeProjectionRebuild(env, ctx, settings, &ComputeProjectionSnapshot{NetworkId: networkId, Account: &ComputeProjectionAccount{Version: 1}})
		}(),
	} {
		if !errors.Is(err, ErrComputeProjectionArgs) && !errors.Is(err, ErrComputeHoldPathUnbuilt) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if len(env.redis.calls) != 0 {
		t.Errorf("a refused call reached Redis: %d calls", len(env.redis.calls))
	}
	// the unbuilt paths are their own refusal
	if err := hold(ComputeHoldPathSearch, ComputeChargeKindWebSearch, 1, nil); !errors.Is(err, ErrComputeHoldPathUnbuilt) {
		t.Errorf("a search hold: %v", err)
	}
}

// A counter's period is the UTC day or month, whatever zone names the time.
func TestComputeBudgetPeriodFieldIsUtc(t *testing.T) {
	at := time.Date(2026, 11, 30, 20, 0, 0, 0, time.FixedZone("UTC-8", -8*60*60))
	if field, err := ComputeBudgetPeriodField(ComputeBudgetPeriodDay, at); err != nil || field != "d:20261201" {
		t.Errorf("the day field is %s, %v", field, err)
	}
	if field, err := ComputeBudgetPeriodField(ComputeBudgetPeriodMonth, at); err != nil || field != "m:202612" {
		t.Errorf("the month field is %s, %v", field, err)
	}
	if _, err := ComputeBudgetPeriodField(ComputeBudgetPeriodRun, at); !errors.Is(err, ErrComputeProjectionArgs) {
		t.Errorf("a run's field: %v", err)
	}
}

// The read's figures: available for admission, the balance for the states.
func TestComputeProjectionReadsAvailableAndBalance(t *testing.T) {
	projection, err := ComputeProjectionRead(newTestProjectionEnv(), context.Background(), operator.Id(sidecar.NewId()))
	if err != nil {
		t.Fatal(err)
	}
	// settled 100, unsettled 10, holds 20, accrued 0
	if !projection.Present || projection.Marked || projection.AvailableNanoUsd() != 70 || projection.BalanceNanoUsd() != 90 ||
		projection.State != ComputeAccountStateActive || projection.Version != "7" || projection.FloorNanoUsd != 5 {
		t.Errorf("the read is %+v", projection)
	}
}

// The scripts keep their rules in their sources: each redis.call names a key from KEYS, or one a declared key was found
// as, never a key built from a literal; no global is assigned; no number reaches Redis through Lua's own formatting.
func TestComputeProjectionScriptsReadOnlyDeclaredKeys(t *testing.T) {
	call := regexp.MustCompile(`redis\.call\('(\w+)'(?:, ([^,)]+))?`)
	allowed := []string{"KEYS[1]", "KEYS[2]", "KEYS[i]", "key"}
	for _, script := range []*operator.RedisScript{
		computeProjectionHoldScript, computeProjectionConfirmScript, computeProjectionSettleScript, computeProjectionVoidScript,
		computeProjectionDropScript, computeProjectionRebuildScript, computeProjectionMarkScript, computeProjectionReadScript,
	} {
		if strings.Contains(script.Source, "{cmp") || strings.Contains(script.Source, ":b:' .. ARGV") {
			t.Errorf("%s builds a key from a literal", script.Name)
		}
		for _, match := range call.FindAllStringSubmatch(script.Source, -1) {
			if match[1] == "TIME" {
				continue
			}
			if !slices.Contains(allowed, match[2]) && !strings.HasPrefix(match[2], "cmp_budget_key(") {
				t.Errorf("%s calls %s on %s", script.Name, match[1], match[2])
			}
		}
		for _, line := range strings.Split(script.Source, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "function ") {
				t.Errorf("%s declares a global function: %s", script.Name, trimmed)
			}
			if strings.Contains(trimmed, "tostring(") && !strings.Contains(trimmed, "tostring(#hold.lines)") {
				t.Errorf("%s formats a number through tostring: %s", script.Name, trimmed)
			}
		}
	}
	if ComputeHoldPrelude() != computeHoldPrelude || !strings.Contains(computeProjectionHoldScript.Source, computeHoldPrelude) {
		t.Error("the hold script does not start with the exported prelude")
	}
}
