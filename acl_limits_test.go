package sidecar

// QUOTA-M4-04: §20.7's tls_endpoints row at grant activation, the one table the writer and api's verifier
// both run (AclCheckTlsEndpoints): the 2nd endpoint on Community refused, a Team's custom-domain alias
// counted, the mta-sts system publish uncounted, an expired grant freeing its unit, an endpoint already
// active taking none, and a downgrade judging only the next activation.

import (
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A publish rule for names, ending at expiresMs (0 none).
func testingPublishRule(expiresMs int64, names ...string) *protocol.AclRule {
	rule := &protocol.AclRule{
		RuleId:  NewId().Bytes(),
		Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_PUBLISH)},
		Expires: expiresMs,
	}
	for _, name := range names {
		rule.Targets = append(rule.Targets, &protocol.AclTarget{PublicName: name})
	}
	return rule
}

func testingPublishAsk(names ...string) *AclGrantAsk {
	ask := &AclGrantAsk{Subject: NewId(), Allow: []protocol.AclAction{protocol.AclAction_ACL_ACTION_PUBLISH}}
	for _, name := range names {
		ask.Dst = append(ask.Dst, &protocol.AclTarget{PublicName: name})
	}
	return ask
}

func testingRowsState(rules ...*protocol.AclRule) *AclState {
	return &AclState{rows: &protocol.AclRows{Rules: rules}}
}

func TestAclTlsEndpointsTable(t *testing.T) {
	const nowMs = int64(1_800_000_000_000)
	mxListen := &protocol.AclRule{
		RuleId:  NewId().Bytes(),
		Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
		Targets: []*protocol.AclTarget{{PublicName: "smtp/25/mx"}},
	}
	dial := &AclGrantAsk{Subject: NewId(), Allow: []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, Dst: []*protocol.AclTarget{{PublicName: "tls/443/c.example"}}}
	cases := []struct {
		name    string
		state   *AclState
		ask     *AclGrantAsk
		limit   int64
		refused bool
		used    int64
	}{
		{name: "the first endpoint on Community", state: testingRowsState(), ask: testingPublishAsk("tls/443/a.example"), limit: 1},
		{name: "the 2nd endpoint on Community", state: testingRowsState(testingPublishRule(0, "tls/443/a.example")), ask: testingPublishAsk("tls/443/b.example"), limit: 1, refused: true, used: 1},
		{name: "another port of one host is another endpoint", state: testingRowsState(testingPublishRule(0, "tls/443/a.example")), ask: testingPublishAsk("tls/8443/a.example"), limit: 1, refused: true, used: 1},
		{name: "an endpoint already active takes no unit", state: testingRowsState(testingPublishRule(0, "tls/443/a.example")), ask: testingPublishAsk("tls/443/a.example"), limit: 1},
		{name: "a Team alias counts", state: testingRowsState(testingPublishRule(0, "tls/443/a.example", "tls/443/shop.customer.example")), ask: testingPublishAsk("tls/443/b.example"), limit: 2, refused: true, used: 2},
		{name: "the mta-sts system publish holds no unit", state: testingRowsState(mxListen), ask: testingPublishAsk("tls/443/a.example"), limit: 1},
		{name: "an expired grant frees its unit", state: testingRowsState(testingPublishRule(nowMs, "tls/443/a.example")), ask: testingPublishAsk("tls/443/b.example"), limit: 1},
		{name: "a grant expiring later still counts", state: testingRowsState(testingPublishRule(nowMs+1, "tls/443/a.example")), ask: testingPublishAsk("tls/443/b.example"), limit: 1, refused: true, used: 1},
		{name: "two new endpoints in one grant", state: testingRowsState(), ask: testingPublishAsk("tls/443/a.example", "tls/443/b.example"), limit: 1, refused: true, used: 0},
		{name: "no limit", state: testingRowsState(testingPublishRule(0, "tls/443/a.example")), ask: testingPublishAsk("tls/443/b.example"), limit: -1},
		{name: "a downgrade to zero refuses the next activation", state: testingRowsState(testingPublishRule(0, "tls/443/a.example")), ask: testingPublishAsk("tls/443/b.example"), limit: 0, refused: true, used: 1},
		{name: "a downgrade judges no grant that publishes nothing", state: testingRowsState(testingPublishRule(0, "tls/443/a.example")), ask: dial, limit: 0},
		{name: "smtp names are no tls endpoint", state: testingRowsState(), ask: testingPublishAsk("smtp/25/mx"), limit: 0},
	}
	for _, c := range cases {
		refusal := AclCheckTlsEndpoints(c.state, c.ask, nowMs, c.limit, true)
		if (refusal != nil) != c.refused {
			t.Errorf("%s: refusal %+v", c.name, refusal)
			continue
		}
		if refusal != nil && (refusal.LimitKey != AclTlsEndpointsLimitKey || refusal.Limit != c.limit || refusal.Used != c.used || !refusal.Upgrade) {
			t.Errorf("%s: refusal %+v", c.name, refusal)
		}
	}
}

// The writer reads its limits from GET /sidecar/limits: tls_endpoints absent reads 0 and refuses, so a limit
// this build does not know fails closed; Team's refusal names no upgrade.
func TestAclCheckGrantActivateQuotaReadsTheWritersLimits(t *testing.T) {
	state := testingRowsState(testingPublishRule(0, "tls/443/a.example"))
	ask := testingPublishAsk("tls/443/b.example")
	const nowMs = int64(1_800_000_000_000)
	refusal := AclCheckTlsEndpoints(state, ask, nowMs, (&QuotaLimits{Tier: "team", Limits: map[string]int64{}}).Limits[AclTlsEndpointsLimitKey], false)
	connect.AssertEqual(t, refusal != nil && refusal.Limit == 0 && !refusal.Upgrade, true)
	if _, err := AclCheckGrantActivateQuota(state, &protocol.GrantActivate{}, nowMs, nil); err == nil {
		t.Error("a GrantActivate with no canonical action")
	}
}
