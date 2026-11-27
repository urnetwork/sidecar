//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The compute tools in the Harness (BAL-M12-20) over a compute client on a scripted api: compute_balance answers the
// agent's budget and whether the network can pay, never the network's balance; compute_spend answers only on the
// person's consented device, a name no signed source vouches for between the untrusted-data markers, tainting
// nothing; compute_budget_raise files kind 21 for the call's own agent and reads its approved use; and the three
// register at §7.5's rows, compute_spend in the local profile alone, none on a host without BAL's sources.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A tools host over a compute client: whether it is the person's consented device, and CACL's view where set.
type testComputeToolHost struct {
	client    *ComputeClient
	consented bool
	left      *ComputeBudgetLeft
}

func (self *testComputeToolHost) ComputeClient() (*ComputeClient, error) {
	if self.client == nil {
		return nil, ErrComputeClientClosed
	}
	return self.client, nil
}

func (self *testComputeToolHost) ComputeConsentedDevice() (bool, error) {
	return self.consented, nil
}

func (self *testComputeToolHost) ComputeBudgetLeft(ctx context.Context, agentId Id) (*ComputeBudgetLeft, error) {
	return self.left, nil
}

// A compute client whose balance route answers state with large, distinct figures, and whose spend route answers by
// model with one catalog id no signed source names and one member the config names.
func newTestComputeToolHost(t *testing.T, state ComputeAccountState, memberId Id) *testComputeToolHost {
	t.Helper()
	spend := fmt.Sprintf(`{"by":"model","days":%s,"first_charge_day":"2026-11-02","held_nano_usd":2580000000,`+
		`"update_time_ms":1795000000000,"lines":[{"kind":1,"total":%s,"days":%s,"rows":[`+
		`{"catalog_id":"engy-llama-5-70b-direct-medium","total":%s,"days":%s}]}]}`,
		testComputeSpendDays, testComputeFigures(7_250_000_000, 250_000_000, 9), testComputeSevenDays(1_000_000_000),
		testComputeFigures(7_250_000_000, 250_000_000, 9), testComputeSevenDays(1_000_000_000))
	transport := testComputeApi(map[string]func(request *http.Request, body []byte) (int, string){
		"GET /compute/balance": func(request *http.Request, body []byte) (int, string) {
			return http.StatusOK, fmt.Sprintf(`{"available_nano_usd":987654321098,"held_nano_usd":123456789,"balance_nano_usd":987777777777,`+
				`"promo_nano_usd":0,"state":%q,"version":7,"may_buy":true,"sales_open":true,"update_time_ms":1795000000000}`, state)
		},
		"GET /compute/spend": func(request *http.Request, body []byte) (int, string) {
			return http.StatusOK, spend
		},
	})
	host := newTestComputeHost(t, transport)
	sources := &ComputeLabelSources{
		Members: func(ctx context.Context) (map[Id]string, error) {
			return map[Id]string{memberId: "alice@example.com"}, nil
		},
		Catalog: func(ctx context.Context) (map[string]bool, error) { return map[string]bool{}, nil },
	}
	return &testComputeToolHost{client: newTestComputeClient(t, host, sources), consented: true}
}

// compute_balance says whether the network can pay and the agent's budget, its caps from the Harness's spec and what
// is left where CACL's view tells, and holds no figure of the network's balance, holds or auto-renew.
func TestComputeBalanceToolHidesTheNetworksBalance(t *testing.T) {
	ctx := context.Background()
	for _, state := range []ComputeAccountState{ComputeAccountStateActive, ComputeAccountStateLow, ComputeAccountStateGrace, ComputeAccountStateSuspended} {
		tools := NewComputeTools(newTestComputeToolHost(t, state, NewId()))
		answer, err := tools.BalanceAnswer(ctx, NewId(), &HarnessBudget{DayNanoUsd: 5_000_000_000, MonthNanoUsd: 50_000_000_000})
		if err != nil {
			t.Fatal(err)
		}
		if answer.State != state || answer.CanPay != state.CanPay() || answer.LeftKnown || answer.Budget.Day == nil ||
			*answer.Budget.Day.CapNanoUsd != 5_000_000_000 || answer.Budget.Day.LeftNanoUsd != nil || answer.Budget.Run != nil {
			t.Errorf("state %s answers %+v", state, answer)
		}
		encoded, _ := json.Marshal(answer)
		for _, figure := range []string{"987654321098", "123456789", "987777777777", "9,876", "9876", "1234", "available", "held", "auto_renew"} {
			if strings.Contains(string(encoded), figure) || strings.Contains(answer.ModelText(), figure) {
				t.Errorf("state %s's answer shows %q: %s | %s", state, figure, encoded, answer.ModelText())
			}
		}
	}
	host := newTestComputeToolHost(t, ComputeAccountStateActive, NewId())
	left, capNanoUsd := int64(1_500_000_000), int64(5_000_000_000)
	host.left = &ComputeBudgetLeft{Day: &ComputeBudgetPeriodLeft{CapNanoUsd: &capNanoUsd, LeftNanoUsd: &left}}
	answer, err := NewComputeTools(host).BalanceAnswer(ctx, NewId(), nil)
	if err != nil || !answer.LeftKnown || *answer.Budget.Day.LeftNanoUsd != left || !strings.Contains(answer.ModelText(), "$1.50 left") {
		t.Errorf("with CACL's view: %+v %v, %q", answer, err, answer.ModelText())
	}
}

// compute_spend answers only on the person's consented device, which the host says, before any route is asked: a
// tagged sidecar's, an enclave's, an ephemeral one's, a Delegation-admitted one's, a revoked or parked one's and one
// the ACL does not consent are none.
func TestComputeSpendToolOnlyOnTheConsentedDevice(t *testing.T) {
	member := NewId()
	device := func(change func(row *bridge.SidecarRow)) *bridge.SidecarRow {
		row := &bridge.SidecarRow{SidecarId: NewId().Bytes(), MemberId: member.Bytes()}
		if change != nil {
			change(row)
		}
		return row
	}
	if !computeConsentedDeviceRow(device(nil), true) {
		t.Error("the person's consented device is refused")
	}
	for _, c := range []struct {
		label     string
		row       *bridge.SidecarRow
		consented bool
	}{
		{label: "no row", row: nil, consented: true},
		{label: "unconsented", row: device(nil), consented: false},
		{label: "tagged", row: device(func(row *bridge.SidecarRow) { row.MemberId, row.TagIds = nil, [][]byte{NewId().Bytes()} }), consented: true},
		{label: "an enclave", row: device(func(row *bridge.SidecarRow) {
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE)
		}), consented: true},
		{label: "ephemeral", row: device(func(row *bridge.SidecarRow) { row.Ephemeral = true }), consented: true},
		{label: "Delegation-admitted", row: device(func(row *bridge.SidecarRow) { row.DelegationId = NewId().Bytes() }), consented: true},
		{label: "revoked", row: device(func(row *bridge.SidecarRow) { row.RevokedAt = 9 }), consented: true},
		{label: "parked", row: device(func(row *bridge.SidecarRow) { row.ParkedAt = 9 }), consented: true},
	} {
		if computeConsentedDeviceRow(c.row, c.consented) {
			t.Errorf("%s is taken for the consented device", c.label)
		}
	}

	ctx := context.Background()
	host := newTestComputeToolHost(t, ComputeAccountStateActive, NewId())
	host.consented = false
	if _, err := NewComputeTools(host).SpendView(ctx, ComputeSpendByModel); !errors.Is(err, ErrComputeSpendNotConsentedDevice) {
		t.Fatalf("not the consented device: %v", err)
	}
	host.consented = true
	view, err := NewComputeTools(host).SpendView(ctx, ComputeSpendByModel)
	if err != nil || len(view.Lines) != 1 {
		t.Fatalf("the consented device: %+v %v", view, err)
	}
}

// A model's label no signed source vouches for reaches the model between the untrusted-data markers, written by the
// broker, and the tool's result taints nothing; the figures are to the cent, after their refunds.
func TestComputeSpendToolMarksUnsignedLabels(t *testing.T) {
	host := newTestComputeToolHost(t, ComputeAccountStateActive, NewId())
	view, err := NewComputeTools(host).SpendView(context.Background(), ComputeSpendByModel)
	if err != nil {
		t.Fatal(err)
	}
	text := ComputeSpendViewModelText(view)
	marked := ComputeUntrustedBegin + "\nengy-llama-5-70b-direct-medium\n" + ComputeUntrustedEnd + " (written by broker)"
	if !strings.Contains(text, marked) {
		t.Errorf("the unsigned model's label is not marked:\n%s", text)
	}
	if !strings.Contains(text, "$7.25 after $0.25 refunded") || !strings.Contains(text, "UTC") {
		t.Errorf("the figures:\n%s", text)
	}
	tool := &computeHarnessTool{tools: NewComputeTools(host), name: HarnessToolComputeSpend}
	call := &HarnessCall{agentId: NewId(), profile: HarnessProfileLocal}
	result, err := tool.Execute(harnessCallContext(context.Background(), call), "call-1", []byte(`{"by":"model"}`), nil)
	if err != nil || result.Trust != HarnessToolTrusted || !strings.Contains(result.Text, marked) {
		t.Errorf("the tool's result: %+v %v", result, err)
	}
	if _, err := tool.Execute(harnessCallContext(context.Background(), call), "call-2", []byte(`{"by":"sidecar"}`), nil); err == nil {
		t.Error("a breakdown by sidecar answered")
	}
}

// compute_budget_raise files kind 21 for the call's own agent at the period and amount it asks, the reason as its
// summary, and reads what its approved use came to; its arguments are held to a period and a positive amount to the
// cent.
func TestComputeBudgetRaiseToolFilesKind21(t *testing.T) {
	registered := computeBudgetRaiseEffectSource
	t.Cleanup(func() {
		computeBudgetRaiseEffectSource = registered
	})
	computeBudgetRaiseEffectSource = func(client *ComputeClient, action *StoredCanonicalAction) SidecarEffect {
		return &testComputeEffect{}
	}
	host := newTestComputeToolHost(t, ComputeAccountStateActive, NewId())
	tool := &computeHarnessTool{tools: NewComputeTools(host), name: HarnessToolComputeBudgetRaise}
	if tool.Tier() != HarnessToolTierOutward || tool.Mode() != HarnessToolSequential {
		t.Errorf("tier %s, mode %s", tool.Tier(), tool.Mode())
	}
	agentId := NewId()
	call := &HarnessCall{agentId: agentId, profile: HarnessProfileLocal}
	request, err := tool.Outward(context.Background(), call, []byte(`{"period":"day","amount_usd":12.5,"reason":"the build needs two more runs"}`))
	if err != nil {
		t.Fatal(err)
	}
	budget := request.Action.Action.GetBudget()
	if request.Kind != SidecarActionComputeBudgetRaise || request.Effect == nil || request.Summary != "the build needs two more runs" ||
		!slices.Equal(budget.GetAgentId(), agentId.Bytes()) || budget.GetPeriod() != approvalComputeBudgetPeriodDay || budget.GetAmount() != 12_500_000_000 {
		t.Errorf("the request %+v, budget %+v", request, budget)
	}
	for _, bad := range []string{`{"period":"week","amount_usd":5}`, `{"period":"day","amount_usd":0}`, `{"period":"day","amount_usd":1.005}`,
		`{"period":"day"}`, `{"period":"day","amount_usd":5,"agent":"another"}`, ``} {
		if _, err := tool.Outward(context.Background(), call, []byte(bad)); err == nil {
			t.Errorf("%s was taken", bad)
		}
	}
	reference, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ComputeBudgetRaiseAnswer{
		ApprovalId: NewId().Bytes(), Period: approvalComputeBudgetPeriodDay, Amount: 12_500_000_000, ExpireMs: 1_795_651_200_000,
	})
	call.outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: reference}
	result, err := tool.Execute(harnessCallContext(context.Background(), call), "call-1", nil, nil)
	if err != nil || !strings.Contains(result.Text, "$12.50") || result.Trust != HarnessToolTrusted {
		t.Errorf("the approved raise: %+v %v", result, err)
	}
	call.outcome = &SidecarOutcome{State: ApprovalOutcomeUncertain}
	if _, err := tool.Execute(harnessCallContext(context.Background(), call), "call-2", nil, nil); err == nil {
		t.Error("an uncertain raise answered as done")
	}
}

// The three register at §7.5's rows: compute_spend in the local profile alone, compute_budget_raise outward; none is
// built on a Harness whose host lacks BAL's sources; BAL's sources fill the failure choice's purchase rights and kind
// 21's builder.
func TestComputeToolsRegisterAtTheirRows(t *testing.T) {
	for _, c := range []struct {
		name     string
		profiles []HarnessProfile
	}{
		{name: HarnessToolComputeBalance, profiles: []HarnessProfile{HarnessProfileLocal, HarnessProfileEnclave}},
		{name: HarnessToolComputeSpend, profiles: []HarnessProfile{HarnessProfileLocal}},
		{name: HarnessToolComputeBudgetRaise, profiles: []HarnessProfile{HarnessProfileLocal, HarnessProfileEnclave}},
	} {
		spec, ok := harnessToolSpecs[c.name]
		if !ok || !spec.BuiltIn || !slices.Equal(spec.Profiles, c.profiles) {
			t.Errorf("%s registers %+v", c.name, spec)
			continue
		}
		if _, err := spec.New(&Harness{}); !errors.Is(err, ErrHarnessToolOff) {
			t.Errorf("%s on a host without BAL's sources: %v", c.name, err)
		}
		tool, err := spec.New(&Harness{purchases: &computeHarnessHost{}})
		if err != nil || tool.Name() != c.name || !json.Valid(tool.Schema()) || tool.Description() == "" {
			t.Errorf("%s on BAL's host: %v", c.name, err)
		}
	}
	registered := slices.ContainsFunc(harnessSourcesRegistrations, func(registration *harnessSourcesRegistration) bool {
		return registration.name == computeHarnessSourcesName
	})
	if !registered {
		t.Error("BAL's Harness sources are not registered")
	}
}
