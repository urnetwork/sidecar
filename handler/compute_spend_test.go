package handler

// The read routes' shapes and refusals without a database (BAL-M12-15): every answer of GET /compute/balance, /charges,
// /statement and /spend, built from fixed figures, equals its golden in testdata/compute_read_routes, which the device's
// own parsers read back in the root package's compute_read_routes_test.go, so a field either side names differently
// fails one of the two; the spend view's lines, rows, days and UTC window; the charges' cursor and page bound; the
// statement's month form; and the frame's refusal of the spend view to every device that is not the person's consented
// one. The figures' reads, roles and filters on the real stores are server/computet3's compute_spend_t3_test.go.
// SIDECAR_REGENERATE_COMPUTE_READ_ROUTES=1 rewrites the goldens from these answers.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Where the goldens are, from this directory, and the variable that rewrites them.
const (
	testComputeReadRoutesDir        = "../testdata/compute_read_routes"
	testComputeReadRoutesRegenerate = "SIDECAR_REGENERATE_COMPUTE_READ_ROUTES"
)

// A fixed id, its last byte n, so the goldens never move.
func testComputeReadId(n byte) operator.Id {
	id := operator.Id{0x01, 0x93, 0x5f, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, n}
	return id
}

// A fixed UTC day of November 2026.
func testComputeReadDay(day int) time.Time {
	return time.Date(2026, time.November, day, 0, 0, 0, 0, time.UTC)
}

// Compares answer's JSON with its golden, or rewrites the golden where asked.
func testComputeReadGolden(t *testing.T, name string, answer any) {
	t.Helper()
	encoded, err := json.MarshalIndent(answer, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(testComputeReadRoutesDir, name+".json")
	if os.Getenv(testComputeReadRoutesRegenerate) != "" {
		if err := os.MkdirAll(testComputeReadRoutesDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (%s=1 writes it)", path, err, testComputeReadRoutesRegenerate)
	}
	if !bytes.Equal(golden, encoded) {
		t.Errorf("%s differs from the answer:\n%s\nwant\n%s", path, encoded, golden)
	}
}

// A sum of units and money.
func testComputeReadSums(amount int64, refunded int64, count int64, units model.ComputeUnits) model.ComputeSpendSums {
	return model.ComputeSpendSums{Units: units, AmountNanoUsd: amount, RefundedNanoUsd: refunded, Count: count}
}

// The spend read the goldens are built from, by by: an Owner's view of 2026-11-18 to 2026-11-24, remote inference on two
// providers and two models, one with a refund, a search, an adjustment, and an enclave's running time.
func testComputeSpendRead(by model.ComputeSpendBy) *ComputeSpendRead {
	memberA, memberB := testComputeReadId(0x0a), testComputeReadId(0x0b)
	agentA := testComputeReadId(0x1a)
	enclave := testComputeReadId(0x2e)
	firstDay := testComputeReadDay(2)
	account := &model.ComputeAccount{
		NetworkId:      testComputeReadId(0x01),
		FirstChargeDay: &firstDay,
		Version:        42,
		UpdateTime:     time.Date(2026, time.November, 24, 13, 30, 0, 0, time.UTC),
	}
	providerA, providerB, parallel, cathedral := int16(1), int16(2), int16(8), int16(9)
	modelA, modelB, shape := "chutes-qwen3.8-27b-tee-high", "engy-llama-5-70b-direct-medium", "cpu-2"
	tokens := func(n int64) model.ComputeUnits {
		return model.ComputeUnits{InputTokens: 1000 * n, OutputTokens: 200 * n}
	}
	day := func(n int) *time.Time {
		d := testComputeReadDay(n)
		return &d
	}
	inference := model.ComputeChargeKindInference
	// each group as the rollups hold it, with every key the breakdown might read
	totals := []*model.ComputeSpendGroup{
		{Kind: inference, Provider: &providerA, CatalogId: &modelA, MemberId: &memberA, Sums: testComputeReadSums(9_000_000_000, 500_000_000, 30, tokens(30))},
		{Kind: inference, Provider: &providerB, CatalogId: &modelB, MemberId: &memberB, Sums: testComputeReadSums(2_250_000_000, 0, 9, tokens(9))},
		{Kind: model.ComputeChargeKindEnclaveRun, Provider: &cathedral, CatalogId: &shape, EnclaveId: &enclave, MemberId: &memberA,
			Sums: testComputeReadSums(1_200_000_000, 0, 6, model.ComputeUnits{Seconds: 3600})},
		{Kind: model.ComputeChargeKindAdjustment, Provider: new(int16), Sums: testComputeReadSums(-2_000_000_000, 0, 1, model.ComputeUnits{})},
		{Kind: model.ComputeChargeKindWebSearch, Provider: &parallel, MemberId: &memberA, Sums: testComputeReadSums(36_000_000, 0, 3, model.ComputeUnits{Searches: 3})},
	}
	days := []*model.ComputeSpendGroup{
		{Kind: inference, Day: day(18), Provider: &providerA, CatalogId: &modelA, MemberId: &memberA, AgentId: &agentA,
			Sums: testComputeReadSums(1_000_000_000, 0, 4, tokens(4))},
		{Kind: inference, Day: day(24), Provider: &providerA, CatalogId: &modelA, MemberId: &memberA, AgentId: &agentA,
			Sums: testComputeReadSums(750_000_000, 250_000_000, 3, tokens(3))},
		{Kind: inference, Day: day(24), Provider: &providerB, CatalogId: &modelB, MemberId: &memberB,
			Sums: testComputeReadSums(250_000_000, 0, 1, tokens(1))},
		{Kind: model.ComputeChargeKindWebSearch, Day: day(21), Provider: &parallel, MemberId: &memberA, AgentId: &agentA,
			Sums: testComputeReadSums(12_000_000, 0, 1, model.ComputeUnits{Searches: 1})},
	}
	// what each breakdown's read selects: the totals and days grouped by the breakdown's key alone
	project := func(groups []*model.ComputeSpendGroup, totals bool) []*model.ComputeSpendGroup {
		projected := []*model.ComputeSpendGroup{}
		for _, group := range groups {
			copied := &model.ComputeSpendGroup{Kind: group.Kind, Day: group.Day, Sums: group.Sums}
			keyBy := by
			if totals && !by.HasTotal() {
				keyBy = model.ComputeSpendByNone
			}
			switch keyBy {
			case model.ComputeSpendByProvider:
				copied.Provider = group.Provider
			case model.ComputeSpendByModel:
				copied.CatalogId = group.CatalogId
			case model.ComputeSpendByEnclave:
				copied.EnclaveId = group.EnclaveId
			case model.ComputeSpendByMember:
				copied.MemberId = group.MemberId
			case model.ComputeSpendByAgent:
				copied.AgentId, copied.MemberId = group.AgentId, group.MemberId
			}
			projected = append(projected, copied)
		}
		return projected
	}
	return &ComputeSpendRead{
		By:          by,
		Days:        ComputeSpendWindow(time.Date(2026, time.November, 24, 23, 59, 0, 0, time.UTC), 7),
		Totals:      project(totals, true),
		DayRows:     project(days, false),
		Account:     account,
		HeldNanoUsd: 2_580_000_000,
	}
}

// Each breakdown's answer equals its golden, which the device's parser reads (compute_read_routes_test.go).
func TestComputeSpendAnswersMatchTheirGoldens(t *testing.T) {
	for _, by := range []model.ComputeSpendBy{model.ComputeSpendByNone, model.ComputeSpendByProvider, model.ComputeSpendByModel,
		model.ComputeSpendByEnclave, model.ComputeSpendByMember, model.ComputeSpendByAgent} {
		answer, err := ComputeSpendAnswerOf(testComputeSpendRead(by), model.DefaultComputeLedgerSettings().AnswerMaxRowCount)
		if err != nil {
			t.Fatalf("by %q: %v", by, err)
		}
		name := "spend_" + string(by)
		if by == model.ComputeSpendByNone {
			name = "spend"
		}
		testComputeReadGolden(t, name, answer)
	}
}

// Every line has its kind's total and the window's 7 days, every row its days; a row by agent has no total, while its
// line keeps the kind's (Q-BAL-10); a refund nets into its kind's line with the refund apart (Q-BAL-12); the window is
// 7 UTC days ending today, oldest first.
func TestComputeSpendLinesTotalsAndDays(t *testing.T) {
	answer, err := ComputeSpendAnswerOf(testComputeSpendRead(model.ComputeSpendByAgent), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2026-11-18", "2026-11-19", "2026-11-20", "2026-11-21", "2026-11-22", "2026-11-23", "2026-11-24"}
	if len(answer.Days) != len(want) {
		t.Fatalf("%d days", len(answer.Days))
	}
	for i := range want {
		if answer.Days[i] != want[i] {
			t.Errorf("day %d is %s, want %s", i, answer.Days[i], want[i])
		}
	}
	kinds := []int16{}
	for _, line := range answer.Lines {
		kinds = append(kinds, line.Kind)
		if line.Total == nil || len(line.Days) != 7 {
			t.Errorf("line %d: total %v, %d days", line.Kind, line.Total, len(line.Days))
		}
		for _, row := range line.Rows {
			if row.Total != nil || len(row.Days) != 7 || row.Provider != nil || row.CatalogId != nil || row.EnclaveId != nil {
				t.Errorf("line %d's agent row %+v", line.Kind, row)
			}
		}
	}
	if len(kinds) != 4 || kinds[0] != 1 || kinds[1] != 2 || kinds[2] != 5 || kinds[3] != 6 {
		t.Errorf("lines of kinds %v", kinds)
	}
	inference := answer.Lines[0]
	if inference.Total.AmountNanoUsd != 11_250_000_000 || inference.Total.RefundedNanoUsd != 500_000_000 || inference.Total.Count != 39 {
		t.Errorf("inference's total %+v", inference.Total)
	}
	if today := inference.Days[6]; today.AmountNanoUsd != 1_000_000_000 || today.RefundedNanoUsd != 250_000_000 || today.Count != 4 {
		t.Errorf("inference's today %+v", today)
	}
	// two agent rows: the agent's and the calls that named none
	if len(inference.Rows) != 2 || inference.Rows[0].AgentId != nil || inference.Rows[1].AgentId == nil || *inference.Rows[1].AgentId != testComputeReadId(0x1a) {
		t.Errorf("inference's agent rows %+v", inference.Rows)
	}
	// an adjustment line, net: a support credit is negative
	if adjustment := answer.Lines[2]; adjustment.Total.AmountNanoUsd != -2_000_000_000 {
		t.Errorf("the adjustments' line %+v", adjustment.Total)
	}
	if answer.HeldNanoUsd != 2_580_000_000 || answer.FirstChargeDay != "2026-11-02" || answer.UpdateTimeMs != time.Date(2026, time.November, 24, 13, 30, 0, 0, time.UTC).UnixMilli() {
		t.Errorf("held %d, first day %q, update %d", answer.HeldNanoUsd, answer.FirstChargeDay, answer.UpdateTimeMs)
	}
}

// The window is the UTC days before the route's now, whatever zone that now was read in.
func TestComputeSpendWindowIsUtcDays(t *testing.T) {
	kiritimati := time.FixedZone("UTC+14", 14*60*60)
	// 20:30 UTC on the 24th is already the 25th at UTC+14
	now := time.Date(2026, time.November, 25, 10, 30, 0, 0, kiritimati)
	days := ComputeSpendWindow(now, 7)
	if len(days) != 7 || days[6] != testComputeReadDay(24) || days[0] != testComputeReadDay(18) {
		t.Errorf("the window %v", days)
	}
	for _, day := range days {
		if day.Location() != time.UTC || day.Hour() != 0 {
			t.Errorf("%v is no UTC midnight", day)
		}
	}
}

// An answer past the bound is refused whole as too_large, never cut.
func TestComputeSpendAnswerPastItsBoundIsRefused(t *testing.T) {
	read := testComputeSpendRead(model.ComputeSpendByProvider)
	answer, err := ComputeSpendAnswerOf(read, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range answer.Lines {
		count += 1 + len(line.Rows)
	}
	if _, err := ComputeSpendAnswerOf(read, count); err != nil {
		t.Errorf("an answer of exactly its bound: %v", err)
	}
	_, err = ComputeSpendAnswerOf(read, count-1)
	var refusal *ComputeApiRefusal
	if !errors.As(err, &refusal) || refusal.Code != ComputeApiRefusalTooLarge || refusal.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("an answer past its bound: %v", err)
	}
}

// The balance, a page of charges and a statement equal their goldens, which the device's parser reads.
func TestComputeBalanceChargesAndStatementMatchTheirGoldens(t *testing.T) {
	days := int64(3)
	balance := &controller.ComputeBalanceState{
		AvailableNanoUsd: 4_920_000_000,
		HeldNanoUsd:      2_580_000_000,
		BalanceNanoUsd:   7_500_000_000,
		PromoNanoUsd:     1_000_000_000,
		State:            model.ComputeAccountStateLow,
		Version:          42,
		UpdateTime:       time.Date(2026, time.November, 24, 13, 30, 0, 0, time.UTC),
		AtRiskEnclaveIds: []operator.Id{testComputeReadId(0x2e)},
		IndexerDaysLeft:  &days,
	}
	payer := testComputeReadId(0x0a)
	autoRenew := &controller.ComputeAutoRenewState{
		Threshold: &controller.ComputeThresholdState{On: true, BelowNanoUsd: 5_000_000_000, PackCredits: 20, MonthLimitNanoUsd: 200_000_000_000, PayerMemberId: &payer, TopUpsToday: 1, MonthNanoUsd: 20_000_000_000},
		Monthly:   &controller.ComputeMonthlyState{},
	}
	testComputeReadGolden(t, "balance", ComputeBalanceAnswerOf(balance, autoRenew, true, false))

	agent, member, enclave := testComputeReadId(0x1a), testComputeReadId(0x0a), testComputeReadId(0x2e)
	modelId := "chutes-qwen3.8-27b-tee-high"
	start := time.Date(2026, time.November, 24, 13, 0, 0, 0, time.UTC)
	charges := &ComputeChargesAnswer{Charges: []*ComputeChargeBody{
		computeChargeBodyOf(&model.ComputeCharge{
			ChargeId: testComputeReadId(0x31), Kind: model.ComputeChargeKindInference, SubjectRef: testComputeReadId(0x41),
			SidecarId: testComputeReadId(0x51), AgentId: &agent, MemberId: &member, CatalogId: &modelId, Provider: 1,
			Units: model.ComputeUnits{InputTokens: 1200, OutputTokens: 300, CachedTokens: 40}, AmountNanoUsd: 25_000_000,
			StartTime: start, EndTime: start.Add(4 * time.Second), SettleTime: start.Add(5 * time.Second),
		}),
		computeChargeBodyOf(&model.ComputeCharge{
			ChargeId: testComputeReadId(0x32), Kind: model.ComputeChargeKindEnclaveRun, SubjectRef: enclave,
			SidecarId: testComputeReadId(0x51), MemberId: &member, EnclaveId: &enclave, Provider: 9,
			Units: model.ComputeUnits{Seconds: 600}, AmountNanoUsd: 200_000_000, AbsorbedNanoUsd: 0,
			StartTime: start.Add(-10 * time.Minute), EndTime: start, SettleTime: start.Add(time.Second),
		}),
	}}
	charges.NextCursor = ComputeChargesCursorText(&model.ComputeChargesCursor{StartTime: start.Add(-10 * time.Minute), ChargeId: testComputeReadId(0x32)})
	testComputeReadGolden(t, "charges", charges)

	expire := testComputeReadDay(20)
	lapsed := int64(400_000_000)
	statement := ComputeStatementAnswerOf(testComputeReadDay(1), []*model.ComputeChargeDay{
		{Day: testComputeReadDay(3), Kind: model.ComputeChargeKindInference, SidecarId: testComputeReadId(0x51), AgentId: &agent,
			CatalogId: &modelId, MemberId: &member, Provider: 1, Units: model.ComputeUnits{InputTokens: 12000, OutputTokens: 3000},
			AmountNanoUsd: 250_000_000, RefundedNanoUsd: 25_000_000, Count: 10},
		{Day: testComputeReadDay(4), Kind: model.ComputeChargeKindAdjustment, Provider: 0, AmountNanoUsd: -1_000_000_000, Count: 1},
	}, []*model.ComputeLot{
		{LotId: testComputeReadId(0x61), Kind: model.ComputeLotKindPurchase, Market: model.ComputeMarketStripe, MarketRef: "pi_synthetic",
			AmountNanoUsd: 25_000_000_000, RemainingNanoUsd: 24_000_000_000, CreateTime: testComputeReadDay(2).Add(9 * time.Hour)},
		{LotId: testComputeReadId(0x62), Kind: model.ComputeLotKindPromotion, Market: model.ComputeMarketPromotion, MarketRef: "redemption",
			AmountNanoUsd: 5_000_000_000, RemainingNanoUsd: 0, CreateTime: testComputeReadDay(2).Add(-28 * 24 * time.Hour),
			ExpireTime: &expire, LapsedNanoUsd: &lapsed},
	})
	testComputeReadGolden(t, "statement", statement)
	// no market reference reaches the answer
	encoded, _ := json.Marshal(statement)
	if bytes.Contains(encoded, []byte("pi_synthetic")) || bytes.Contains(encoded, []byte("market_ref")) {
		t.Errorf("a lot's market reference reached the statement: %s", encoded)
	}
}

// A cursor names the last row's start time to the microsecond and its charge; anything else is no cursor.
func TestComputeChargesCursorRoundTrips(t *testing.T) {
	cursor := &model.ComputeChargesCursor{StartTime: time.Date(2026, time.November, 24, 13, 0, 0, 123456000, time.UTC), ChargeId: testComputeReadId(0x77)}
	text := ComputeChargesCursorText(cursor)
	back, err := ParseComputeChargesCursor(text)
	if err != nil || !back.StartTime.Equal(cursor.StartTime) || back.ChargeId != cursor.ChargeId {
		t.Errorf("%q came back %+v, %v", text, back, err)
	}
	for _, alphabet := range text {
		if !(('a' <= alphabet && alphabet <= 'z') || ('A' <= alphabet && alphabet <= 'Z') || ('0' <= alphabet && alphabet <= '9') || alphabet == '-' || alphabet == '_') {
			t.Errorf("%q leaves the device's cursor alphabet", text)
		}
	}
	for _, bad := range []string{"next", text + "A", text[:len(text)-1], "!!!!"} {
		if _, err := ParseComputeChargesCursor(bad); err == nil {
			t.Errorf("%q read as a cursor", bad)
		}
	}
}

// The charges route refuses a cursor no page answered and a limit that is no positive integer, before any read; the
// statement route a month out of its one form; the spend route a breakdown §9.13 does not name.
func TestComputeReadRoutesRefuseBadQueries(t *testing.T) {
	refusing := []struct {
		label   string
		handler ComputeApiHandler
		query   url.Values
	}{
		{label: "a cursor no page answered", handler: NewComputeChargesHandler(nil), query: url.Values{"cursor": {"next"}}},
		{label: "a limit of zero", handler: NewComputeChargesHandler(nil), query: url.Values{"limit": {"0"}}},
		{label: "a limit in words", handler: NewComputeChargesHandler(nil), query: url.Values{"limit": {"ten"}}},
		{label: "a limit padded", handler: NewComputeChargesHandler(nil), query: url.Values{"limit": {"010"}}},
		{label: "no month", handler: NewComputeStatementHandler(nil), query: url.Values{}},
		{label: "a month of one digit", handler: NewComputeStatementHandler(nil), query: url.Values{"month": {"2026-1"}}},
		{label: "a day for a month", handler: NewComputeStatementHandler(nil), query: url.Values{"month": {"2026-11-01"}}},
		{label: "a breakdown by sidecar", handler: NewComputeSpendHandler(nil), query: url.Values{"by": {"sidecar"}}},
	}
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	for _, refused := range refusing {
		// no env: a refusal here never reaches a store
		_, err := refused.handler(nil, context.Background(), owner, &ComputeApiRequest{Query: refused.query})
		var refusal *ComputeApiRefusal
		if !errors.As(err, &refusal) || refusal.Code != ComputeApiRefusalBadRequest {
			t.Errorf("%s: %v", refused.label, err)
		}
	}
}

// The spend view is refused to a tagged sidecar, an enclave, an ephemeral and a Delegation-admitted one and the network's
// own credential, whatever role stands behind them, before any handler runs; the person's consented device reaches it.
func TestComputeSpendRouteRefusesWhatIsNoConsentedDevice(t *testing.T) {
	reached := 0
	testRegisterComputeApiHandler(t, http.MethodGet, "/compute/spend", func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		reached += 1
		return map[string]any{}, nil
	})
	route := testComputeApiRoute(t, http.MethodGet, "/compute/spend")
	devices := map[string]*ComputeApiCaller{}
	for _, label := range []string{"tagged", "enclave", "ephemeral", "delegation", "unconsented", "network credential"} {
		caller := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		switch label {
		case "tagged":
			caller.Tagged, caller.MemberId = true, nil
		case "enclave":
			caller.Enclave = true
		case "ephemeral":
			caller.Ephemeral = true
		case "delegation":
			caller.DelegationAdmitted = true
		case "unconsented":
			caller.Consented = false
		case "network credential":
			caller.Credential, caller.SidecarId = ComputeApiCredentialNetwork, nil
		}
		devices[label] = caller
	}
	for label, caller := range devices {
		answer := route.Serve(context.Background(), caller, nil, nil)
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusForbidden || code != ComputeApiRefusalConsentedDeviceRequired {
			t.Errorf("%s answers %d %s", label, answer.Status, code)
		}
	}
	if reached != 0 {
		t.Fatalf("a refused caller reached the handler")
	}
	for _, role := range []bridge.MemberRole{bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_MEMBER, bridge.MemberRole_MEMBER_ROLE_AUDITOR} {
		if answer := route.Serve(context.Background(), testComputeMemberDevice(role), url.Values{"by": {"model"}}, nil); answer.Status != http.StatusOK {
			t.Errorf("a consented device of role %v answers %d", role, answer.Status)
		}
	}
	if reached != 3 {
		t.Errorf("the consented devices reached the handler %d times", reached)
	}
}

// A Member's reads are filtered to their member and a role that sees the network's to none; the charges route takes
// the device's limit.
func TestComputeReadRoutesFilterAMembersView(t *testing.T) {
	member := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	if memberId := computeApiViewMember(member); memberId == nil || *memberId != *member.MemberId {
		t.Errorf("a Member's view is filtered to %v", memberId)
	}
	for _, role := range []bridge.MemberRole{bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN,
		bridge.MemberRole_MEMBER_ROLE_ADMIN, bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, bridge.MemberRole_MEMBER_ROLE_IT_ADMIN,
		bridge.MemberRole_MEMBER_ROLE_AUDITOR} {
		if memberId := computeApiViewMember(testComputeMemberDevice(role)); memberId != nil {
			t.Errorf("role %v's view is filtered to %v", role, memberId)
		}
	}
	answers := 0
	testRegisterComputeApiHandler(t, http.MethodGet, "/compute/charges", func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		answers += 1
		if request.Query.Get("limit") != "100" {
			t.Errorf("the handler saw limit %q", request.Query.Get("limit"))
		}
		return map[string]any{}, nil
	})
	route := testComputeApiRoute(t, http.MethodGet, "/compute/charges")
	if answer := route.Serve(context.Background(), member, url.Values{"limit": {"100"}}, nil); answer.Status != http.StatusOK || answers != 1 {
		t.Errorf("a page with the device's limit answers %d", answer.Status)
	}
}
