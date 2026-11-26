package main

// ur compute (cmd_compute.go, cmd_compute_methods.go; BAL-M12-18): each row of §15.1 parsed into its method and
// params, the acts on money and codes confirmed on /dev/tty and sent as Confirm calls, redemption refused under a
// harness at the daemon, the spend view by agent for the 7 days alone, a budget raise filed and waited on, and each
// refusal code printed with its fix; on a stand-in daemon's compute methods, no goldens on disk.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A stand-in daemon's compute methods: what each was sent, confirmed or not, and what each answers.
type testUrComputeStand struct {
	stateLock sync.Mutex
	calls     []string
	confirmed []bool
	params    []json.RawMessage
	// by method, the reply to each call in turn, the last again once they run out
	replies map[string][]any
	// whether the daemon reads the caller as under a harness
	underHarness bool
}

// The methods ur compute calls, Confirm where the root's are.
var testUrComputeConfirmMethods = []string{sidecar.DaemonMethodComputeRedeem, sidecar.DaemonMethodComputeAutoRenewSet, sidecar.DaemonMethodComputeRefund}

func (self *testUrComputeStand) methods() []*sidecar.DaemonMethod {
	methods := []*sidecar.DaemonMethod{}
	for _, name := range []string{
		sidecar.DaemonMethodComputeBalance, sidecar.DaemonMethodComputePacks, sidecar.DaemonMethodComputeCheckout,
		sidecar.DaemonMethodComputeRedeem, sidecar.DaemonMethodComputeAutoRenew, sidecar.DaemonMethodComputeAutoRenewSet,
		sidecar.DaemonMethodComputeCharges, sidecar.DaemonMethodComputeStatement, sidecar.DaemonMethodComputeSpend,
		sidecar.DaemonMethodComputeRefund, sidecar.DaemonMethodComputeBudgetRaise,
	} {
		methods = append(methods, &sidecar.DaemonMethod{
			Name:    name,
			Confirm: slices.Contains(testUrComputeConfirmMethods, name),
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.calls = append(self.calls, name)
				self.confirmed = append(self.confirmed, call.Confirmed)
				self.params = append(self.params, append(json.RawMessage{}, call.Params...))
				replies := self.replies[name]
				if len(replies) == 0 {
					return map[string]any{}, nil
				}
				reply := replies[0]
				if 1 < len(replies) {
					self.replies[name] = replies[1:]
				}
				return reply, nil
			},
		})
	}
	return urComputeGuardMethods(methods)
}

func (self *testUrComputeStand) recorded() ([]string, []bool, []json.RawMessage) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls), slices.Clone(self.confirmed), slices.Clone(self.params)
}

func (self *testUrComputeStand) reset() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls, self.confirmed, self.params = nil, nil, nil
}

// A stand-in whose balance lets this person buy, with open sales, and whose other methods answer typical replies.
func newTestUrComputeStand() *testUrComputeStand {
	lotId := sidecar.NewId()
	return &testUrComputeStand{replies: map[string][]any{
		sidecar.DaemonMethodComputeBalance: {&sidecar.ComputeBalance{
			AvailableNanoUsd: 10 * urComputeNanoUsdPerUsd, HeldNanoUsd: 2_345_000_000, BalanceNanoUsd: 12_345_000_000,
			State: sidecar.ComputeAccountStateActive, MayBuy: true, SalesOpen: true,
			AutoRenew: &sidecar.ComputeAutoRenew{Threshold: &sidecar.ComputeThreshold{OffReason: sidecar.ComputeAutoRenewOffFailed}},
		}},
		sidecar.DaemonMethodComputePacks: {&sidecar.DaemonComputePacksReply{Packs: []*sidecar.ComputePack{
			{Market: sidecar.ComputeMarketStripe, Credits: 10}, {Market: sidecar.ComputeMarketStripe, Credits: 25},
		}}},
		sidecar.DaemonMethodComputeCheckout: {&sidecar.ComputeCheckout{Url: "https://checkout.example/c/test", ExpireTime: time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)}},
		sidecar.DaemonMethodComputeRedeem:   {&sidecar.ComputeRedemption{LotId: lotId, CreditNanoUsd: 5 * urComputeNanoUsdPerUsd, ExpireTime: time.Date(2026, 12, 25, 0, 0, 0, 0, time.UTC)}},
		sidecar.DaemonMethodComputeRefund:   {&sidecar.ComputeRefund{LotId: lotId, RefundedNanoUsd: 7 * urComputeNanoUsdPerUsd}},
	}}
}

// A ur over a stand-in daemon serving stand's methods, a terminal answering yes, and the browser opened recorded.
func testUrComputeCli(t *testing.T, stand *testUrComputeStand) (*urCli, *testUrComputeOutput) {
	t.Helper()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	output := &testUrComputeOutput{stdout: stdout, stderr: stderr}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes", "yes"}}, nil }
	opened := urComputeOpenBrowser
	urComputeOpenBrowser = func(url string) error {
		output.opened = append(output.opened, url)
		return nil
	}
	// the stand-in daemon hosts no Sidecar whose runs could be the caller's ancestors: the stand says
	underHarness := urComputeUnderHarness
	urComputeUnderHarness = func(ctx context.Context, call *sidecar.DaemonCall) bool { return stand.underHarness }
	t.Cleanup(func() {
		urComputeOpenBrowser = opened
		urComputeUnderHarness = underHarness
	})
	return cli, output
}

type testUrComputeOutput struct {
	stdout interface{ String() string }
	stderr interface{ String() string }
	opened []string
}

// Each row of §15.1's compute commands goes to its method with its params, the acts on money and codes confirmed.
func TestUrComputeParsesEachRow(t *testing.T) {
	stand := newTestUrComputeStand()
	cli, output := testUrComputeCli(t, stand)
	lotId := sidecar.NewId()
	type row struct {
		args      []string
		methods   []string
		confirmed bool
		// the last call's params, as JSON object fields
		params map[string]any
	}
	rows := []row{
		{args: []string{"status"}, methods: []string{sidecar.DaemonMethodComputeBalance}, params: map[string]any{}},
		{args: []string{"status", "--network=net-a"}, methods: []string{sidecar.DaemonMethodComputeBalance}, params: map[string]any{"network": "net-a"}},
		{
			args:    []string{"buy", "25"},
			methods: []string{sidecar.DaemonMethodComputeBalance, sidecar.DaemonMethodComputePacks, sidecar.DaemonMethodComputeCheckout},
			params:  map[string]any{"pack_credits": float64(25)},
		},
		{
			args:    []string{"buy", "10", "--auto-renew=threshold"},
			methods: []string{sidecar.DaemonMethodComputeBalance, sidecar.DaemonMethodComputePacks, sidecar.DaemonMethodComputeCheckout},
			params:  map[string]any{"pack_credits": float64(10), "auto_renew": "threshold"},
		},
		{
			args:    []string{"buy", "--monthly=50"},
			methods: []string{sidecar.DaemonMethodComputeBalance, sidecar.DaemonMethodComputeCheckout},
			params:  map[string]any{"auto_renew": "monthly", "monthly_credits": float64(50)},
		},
		{args: []string{"redeem", "Spring2026Code"}, methods: []string{sidecar.DaemonMethodComputeRedeem}, confirmed: true, params: map[string]any{"code": "Spring2026Code"}},
		{args: []string{"auto-renew"}, methods: []string{sidecar.DaemonMethodComputeAutoRenew}, params: map[string]any{}},
		{
			args:    []string{"auto-renew", "threshold", "--below=5", "--pack=20", "--month-limit=200.50"},
			methods: []string{sidecar.DaemonMethodComputeAutoRenewSet}, confirmed: true,
			params: map[string]any{"mode": "threshold", "on": true, "below_nano_usd": float64(5 * urComputeNanoUsdPerUsd), "pack_credits": float64(20), "month_limit_nano_usd": float64(200_500_000_000)},
		},
		{
			args: []string{"auto-renew", "monthly", "25"}, methods: []string{sidecar.DaemonMethodComputeAutoRenewSet}, confirmed: true,
			params: map[string]any{"mode": "monthly", "on": true, "credits": float64(25)},
		},
		{
			args: []string{"auto-renew", "off", "threshold"}, methods: []string{sidecar.DaemonMethodComputeAutoRenewSet}, confirmed: true,
			params: map[string]any{"mode": "threshold", "on": false},
		},
		{args: []string{"charges", "--cursor=page-2"}, methods: []string{sidecar.DaemonMethodComputeCharges}, params: map[string]any{"cursor": "page-2"}},
		{args: []string{"statement", "--month=2026-11"}, methods: []string{sidecar.DaemonMethodComputeStatement}, params: map[string]any{"month": "2026-11"}},
		{args: []string{"refund", lotId.String()}, methods: []string{sidecar.DaemonMethodComputeRefund}, confirmed: true, params: map[string]any{"lot_id": lotId.String()}},
		{args: []string{"spend", "--by=model"}, methods: []string{sidecar.DaemonMethodComputeSpend}, params: map[string]any{"by": "model"}},
	}
	for _, r := range rows {
		stand.reset()
		args := append([]string{"ur", "compute"}, r.args...)
		if code := cli.main(context.Background(), args); code != urExitOk {
			t.Errorf("%v: exit %d, %s", r.args, code, output.stderr.String())
			continue
		}
		calls, confirmed, params := stand.recorded()
		if !slices.Equal(calls, r.methods) {
			t.Errorf("%v called %v, want %v", r.args, calls, r.methods)
			continue
		}
		if confirmed[len(confirmed)-1] != r.confirmed {
			t.Errorf("%v confirmed %v", r.args, confirmed)
		}
		sent := map[string]any{}
		if err := json.Unmarshal(params[len(params)-1], &sent); err != nil {
			t.Fatal(err)
		}
		for key, value := range r.params {
			if sent[key] != value {
				t.Errorf("%v sent %s %v, want %v (all %v)", r.args, key, sent[key], value, sent)
			}
		}
	}
	// buy printed and opened Checkout's url
	if !slices.Contains(output.opened, "https://checkout.example/c/test") || !strings.Contains(output.stdout.String(), "checkout   https://checkout.example/c/test") {
		t.Errorf("opened %v, printed:\n%s", output.opened, output.stdout.String())
	}
	// status said why threshold is off
	if !strings.Contains(output.stdout.String(), "three top-ups failed in a row") || !strings.Contains(output.stdout.String(), "balance    $12.35") {
		t.Errorf("status printed:\n%s", output.stdout.String())
	}
}

// Words outside a row's form refuse as they parse, before anything is sent: a pack that is no count, an amount past
// the cent, a period missing from a raise, an unknown dimension.
func TestUrComputeRefusesBadArgumentsBeforeSending(t *testing.T) {
	stand := newTestUrComputeStand()
	cli, _ := testUrComputeCli(t, stand)
	for _, args := range [][]string{
		{"buy", "ten"},
		{"buy", "25", "--auto-renew=monthly"},
		{"auto-renew", "threshold", "--below=5.001"},
		{"auto-renew", "monthly", "0"},
		{"budget", "raise", sidecar.NewId().String()},
		{"spend", "--by=day"},
		{"refund", "not-a-lot"},
		{"redeem", "has spaces"},
	} {
		stand.reset()
		if code := cli.main(context.Background(), append([]string{"ur", "compute"}, args...)); code == urExitOk {
			t.Errorf("%v: exit ok", args)
		}
		if calls, _, _ := stand.recorded(); slices.ContainsFunc(calls, func(call string) bool { return call != sidecar.DaemonMethodComputeBalance }) {
			t.Errorf("%v sent %v", args, calls)
		}
	}
}

// A code is never redeemed by a caller with a harness process among its ancestors: the daemon refuses it before the
// redeem method runs, however the call was confirmed.
func TestUrComputeRedeemRefusedUnderAHarness(t *testing.T) {
	stand := newTestUrComputeStand()
	stand.underHarness = true
	guard := urComputeUnderHarness
	cli, output := testUrComputeCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "compute", "redeem", "Spring2026Code"}); code == urExitOk {
		t.Fatal("redeemed under a harness")
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Errorf("the redeem method ran: %v", calls)
	}
	if !strings.Contains(output.stderr.String(), "never under a harness process") {
		t.Errorf("stderr: %s", output.stderr.String())
	}
	// the guard is the daemon's: a caller it cannot name is refused too
	if !guard(context.Background(), &sidecar.DaemonCall{}) {
		t.Error("a caller with no pid passed the harness check")
	}
}

// Redemption asks on /dev/tty: with no terminal or on a no nothing is sent; on a yes one confirmed call. The code taken
// from the terminal with - never stands in argv, and the question shows only its last characters.
func TestUrComputeRedeemNeedsTheTerminal(t *testing.T) {
	stand := newTestUrComputeStand()
	cli, _ := testUrComputeCli(t, stand)
	args := []string{"ur", "compute", "redeem", "Spring2026Code"}
	cli.openTty = func() (urTty, error) { return nil, errUrNoTty }
	if code := cli.main(context.Background(), args); code == urExitOk {
		t.Fatal("redeemed with no terminal")
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"no"}}, nil }
	if code := cli.main(context.Background(), args); code == urExitOk {
		t.Fatal("redeemed on a no")
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("unconfirmed, it sent %v", calls)
	}
	tty := &testTty{lines: []string{"Spring2026Code", "yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "compute", "redeem", "-"}); code != urExitOk {
		t.Fatal("not redeemed on a yes")
	}
	calls, confirmed, params := stand.recorded()
	if !slices.Equal(calls, []string{sidecar.DaemonMethodComputeRedeem}) || !confirmed[0] || !strings.Contains(string(params[0]), "Spring2026Code") {
		t.Errorf("sent %v %v %s", calls, confirmed, params)
	}
	if question := tty.written.String(); strings.Contains(question, "Spring2026Code") || !strings.Contains(question, "…Code") {
		t.Errorf("the terminal showed %q", question)
	}
}

// By agent the view gives each agent's 7 days alone, since no lifetime total keeps an agent (Q-BAL-10); by model each
// row's total since the first charge beside its 7 days. A name no signed source vouches for prints between the
// untrusted-data markers.
func TestUrComputeSpendByAgentOnlyForSevenDays(t *testing.T) {
	stand := newTestUrComputeStand()
	agentId := sidecar.NewId()
	days := func(amounts ...int64) []*sidecar.ComputeSpendFigures {
		figures := []*sidecar.ComputeSpendFigures{}
		for _, amount := range amounts {
			figures = append(figures, &sidecar.ComputeSpendFigures{AmountNanoUsd: amount})
		}
		return figures
	}
	view := func(by sidecar.ComputeSpendBy, name *sidecar.ComputeDisplayName, rowTotal *sidecar.ComputeSpendFigures) *sidecar.ComputeSpendView {
		return &sidecar.ComputeSpendView{
			By: by, Days: []string{"2026-11-19", "2026-11-20", "2026-11-21", "2026-11-22", "2026-11-23", "2026-11-24", "2026-11-25"},
			WindowStart: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), WindowEnd: time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC),
			FirstChargeDay: "2026-10-02", UpdateTime: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
			AllTotal: &sidecar.ComputeSpendFigures{AmountNanoUsd: 40 * urComputeNanoUsdPerUsd}, AllDays: days(urComputeNanoUsdPerUsd, 2*urComputeNanoUsdPerUsd),
			Lines: []*sidecar.ComputeSpendViewLine{{
				Service: sidecar.ComputeServiceInference, Kind: sidecar.ComputeChargeKindInference,
				Total: &sidecar.ComputeSpendFigures{AmountNanoUsd: 40 * urComputeNanoUsdPerUsd, RefundedNanoUsd: urComputeNanoUsdPerUsd},
				Days:  days(urComputeNanoUsdPerUsd, 2*urComputeNanoUsdPerUsd),
				Rows:  []*sidecar.ComputeSpendViewRow{{Name: name, Row: &sidecar.ComputeSpendRow{AgentId: &agentId, Total: rowTotal, Days: days(3*urComputeNanoUsdPerUsd/2, 0)}}},
			}},
		}
	}
	marked := &sidecar.ComputeDisplayName{Text: "nightly-builder", Trust: sidecar.ComputeNameMarked, Writer: "a member's laptop"}
	stand.replies[sidecar.DaemonMethodComputeSpend] = []any{
		view(sidecar.ComputeSpendByAgent, marked, nil),
		view(sidecar.ComputeSpendByModel, &sidecar.ComputeDisplayName{Text: "chutes-qwen3.8-27b-tee-high", Trust: sidecar.ComputeNamePlain}, &sidecar.ComputeSpendFigures{AmountNanoUsd: 39 * urComputeNanoUsdPerUsd}),
	}
	cli, output := testUrComputeCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "compute", "spend", "--by=agent"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, output.stderr.String())
	}
	byAgent := output.stdout.String()
	agentLines := []string{}
	for _, line := range strings.Split(byAgent, "\n") {
		if strings.Contains(line, "in the 7 days") && strings.HasPrefix(line, "  ") || strings.Contains(line, sidecar.ComputeUntrustedEnd) {
			agentLines = append(agentLines, line)
		}
	}
	if !strings.Contains(byAgent, sidecar.ComputeUntrustedBegin+"\nnightly-builder\n"+sidecar.ComputeUntrustedEnd+" (written by a member's laptop)  $1.50 in the 7 days") {
		t.Errorf("by agent printed:\n%s", byAgent)
	}
	for _, line := range agentLines {
		if strings.Contains(line, "in all") {
			t.Errorf("an agent's row carries a total: %q", line)
		}
	}
	// the service's own line keeps its total and its refunds, and the window says UTC
	if !strings.Contains(byAgent, "$40.00 after $1.00 refunded in all, $3.00 in the 7 days") || !strings.Contains(byAgent, "2026-11-19 to 2026-11-25 UTC") {
		t.Errorf("by agent printed:\n%s", byAgent)
	}
	before := len(byAgent)
	if code := cli.main(context.Background(), []string{"ur", "compute", "spend", "--by=model"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if byModel := output.stdout.String()[before:]; !strings.Contains(byModel, "  chutes-qwen3.8-27b-tee-high  $39.00 in all, $1.50 in the 7 days") {
		t.Errorf("by model printed:\n%s", byModel)
	}
}

// A raise files kind 21, prints the approval to decide, asks again each interval while it is pending, and ends once the
// approved raise reached the broker; the current amount comes from the device's budgets, and with no budget view
// nothing is filed.
func TestUrComputeBudgetRaiseFilesKind21AndWaits(t *testing.T) {
	stand := newTestUrComputeStand()
	approvalId := sidecar.NewId()
	stand.replies[sidecar.DaemonMethodComputeBudgetRaise] = []any{
		&sidecar.ComputeBudgetRaiseResult{Outcome: sidecar.ComputeBudgetRaisePending, ApprovalId: &approvalId},
		&sidecar.ComputeBudgetRaiseResult{Outcome: sidecar.ComputeBudgetRaisePending, ApprovalId: &approvalId},
		&sidecar.ComputeBudgetRaiseResult{Outcome: sidecar.ComputeBudgetRaiseDone},
	}
	cli, output := testUrComputeCli(t, stand)
	agentId := sidecar.NewId()
	args := []string{"ur", "compute", "budget", "raise", agentId.String(), "--day=12.50"}
	// no budget view yet: nothing filed
	if code := cli.main(context.Background(), args); code == urExitOk {
		t.Fatal("raised with no budget view")
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("filed %v with no budget view", calls)
	}
	budgets := urComputeBudgets
	urComputeBudgets = func(ctx context.Context, cli *urCli, network string) ([]*urComputeBudget, error) {
		return []*urComputeBudget{{Subject: "agent", SubjectId: agentId, Period: "day", CapNanoUsd: 5 * urComputeNanoUsdPerUsd, LeftNanoUsd: urComputeNanoUsdPerUsd}}, nil
	}
	waits := 0
	wait := urComputeWait
	urComputeWait = func(ctx context.Context, timeout time.Duration) error {
		waits += 1
		return nil
	}
	defer func() {
		urComputeBudgets = budgets
		urComputeWait = wait
	}()
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("exit %d: %s", code, output.stderr.String())
	}
	calls, confirmed, params := stand.recorded()
	if len(calls) != 3 || calls[0] != sidecar.DaemonMethodComputeBudgetRaise || confirmed[0] || waits != 2 {
		t.Fatalf("called %v, confirmed %v, waited %d", calls, confirmed, waits)
	}
	sent := &sidecar.DaemonComputeBudgetRaiseParams{}
	if err := json.Unmarshal(params[0], sent); err != nil {
		t.Fatal(err)
	}
	if sent.AgentId == nil || *sent.AgentId != agentId || sent.Period != "day" || sent.AmountNanoUsd != 12_500_000_000 || sent.CurrentNanoUsd != 5*urComputeNanoUsdPerUsd {
		t.Errorf("filed %+v", sent)
	}
	text := output.stdout.String()
	if strings.Count(text, "approval pending: run ur approve "+approvalId.String()) != 1 || !strings.Contains(text, "raised     the agent's day budget from $5.00 to $12.50") {
		t.Errorf("printed:\n%s", text)
	}
}

// Each refusal code the server answers prints with its fix, never with a message; a code the table does not have
// prints alone; and buy refuses before Checkout where this person may not buy or sales are closed.
func TestUrComputePrintsRefusalCodes(t *testing.T) {
	for _, c := range []struct {
		code string
		fix  string
	}{
		{code: "may_not_see", fix: "your role sees no charges or spend"},
		{code: "consented_device_required", fix: "your own consented device"},
		{code: "not_built", fix: "does not serve this route yet"},
		{code: "something_new", fix: ""},
	} {
		stand := newTestUrComputeStand()
		stand.replies[sidecar.DaemonMethodComputeSpend] = []any{&sidecar.DaemonComputeRefusalReply{Refusal: &sidecar.DaemonComputeRefusal{Code: c.code}}}
		cli, output := testUrComputeCli(t, stand)
		if code := cli.main(context.Background(), []string{"ur", "compute", "spend"}); code == urExitOk {
			t.Errorf("%s: exit ok", c.code)
		}
		if text := output.stderr.String(); !strings.Contains(text, "refused: "+c.code) || !strings.Contains(text, c.fix) {
			t.Errorf("%s printed %q", c.code, text)
		}
	}
	for _, c := range []struct {
		balance *sidecar.ComputeBalance
		code    string
	}{
		{balance: &sidecar.ComputeBalance{MayBuy: false, SalesOpen: true}, code: "may_not_buy"},
		{balance: &sidecar.ComputeBalance{MayBuy: true, SalesOpen: false}, code: "sales_closed"},
	} {
		stand := newTestUrComputeStand()
		stand.replies[sidecar.DaemonMethodComputeBalance] = []any{c.balance}
		cli, output := testUrComputeCli(t, stand)
		if code := cli.main(context.Background(), []string{"ur", "compute", "buy", "25"}); code == urExitOk {
			t.Errorf("%s: bought", c.code)
		}
		if calls, _, _ := stand.recorded(); slices.Contains(calls, sidecar.DaemonMethodComputeCheckout) {
			t.Errorf("%s: opened checkout", c.code)
		}
		if !strings.Contains(output.stderr.String(), "refused: "+c.code) || len(output.opened) != 0 {
			t.Errorf("%s printed %q, opened %v", c.code, output.stderr.String(), output.opened)
		}
	}
}

// The budget view is CACL's, not built yet: ur compute budget refuses, naming why, and sends nothing.
func TestUrComputeBudgetListWaitsForItsView(t *testing.T) {
	stand := newTestUrComputeStand()
	cli, output := testUrComputeCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "compute", "budget", "ls"}); code == urExitOk {
		t.Fatal("listed budgets with no view")
	}
	if !strings.Contains(output.stderr.String(), "not built yet") {
		t.Errorf("stderr: %s", output.stderr.String())
	}
}

// ur daemon serves each compute method once, on its call's network, redemption, auto-renew's change and refunds as
// Confirm methods; a target that hosts no Sidecar serves none; and ur native-host relays none of them (QD-1253).
func TestUrDaemonServesTheComputeMethodsOnce(t *testing.T) {
	methods := urDaemonMethods("default", &urDaemonNetwork{}, osKeyStoreKeyFile, nil)
	for _, name := range []string{
		sidecar.DaemonMethodComputeBalance, sidecar.DaemonMethodComputeLow, sidecar.DaemonMethodComputePacks,
		sidecar.DaemonMethodComputeCheckout, sidecar.DaemonMethodComputeRedeem, sidecar.DaemonMethodComputeAutoRenew,
		sidecar.DaemonMethodComputeAutoRenewSet, sidecar.DaemonMethodComputeCharges, sidecar.DaemonMethodComputeStatement,
		sidecar.DaemonMethodComputeSpend, sidecar.DaemonMethodComputeRefund, sidecar.DaemonMethodComputeBudgetRaise,
	} {
		served := 0
		for _, method := range methods {
			if method.Name != name {
				continue
			}
			served += 1
			if method.Confirm != slices.Contains(testUrComputeConfirmMethods, name) || !method.Network {
				t.Errorf("%s: Confirm %t, Network %t", name, method.Confirm, method.Network)
			}
		}
		if served != 1 {
			t.Errorf("%s is served %d times", name, served)
		}
		if slices.Contains(nativeHostRelayedMethods, name) {
			t.Errorf("ur native-host relays %s", name)
		}
	}
	if len(urComputeMethods(&testUrDaemonTarget{})) != 0 {
		t.Error("a target with no Sidecars serves the compute methods")
	}
}
