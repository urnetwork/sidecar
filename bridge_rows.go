// BridgeRows, §17's id-only section of a base's AclRows (§8.8's AclRows.bridge, §17.8): each subject's egress mode, and
// each approved route in force by its ids (QD-764). Gates read the modes to refuse Public contracts for a subject in exits
// or none (§8.10, D-BRIDGE-13), and AclState reads the routes, whose advertisers become the via subjects of the route
// rules each names that name no via of their own (QD-004's second half). No prefix, address, port, map, alias, site,
// weight or kind is ever in it (D-BRIDGE-6, I-18): a route row is what its BridgeRoute already shows at id level.
//
// The section is log-derived, as the owner's answers to plan-BRIDGE-egress-mode-at-gates and
// acl-m2-17-no-via-route-advertisers have it. Every verifier applies each entry in log order over the rows it holds, the
// statement's rule calling these:
//
//	BridgeEgress    writes its subject's mode, auto removing the row (bridgeRowsWithEgress); the mode shows in
//	                BridgeEgress.mode = 4 (QD-630), which every verifier reads without a key
//	BridgeRoute     adds its route_id, advertiser and route_rule_ids where the rows hold no row of its id; a filing of a
//	                held id activates nothing and changes none of these, so it leaves the row (bridgeRowsWithRoute)
//	BridgeWithdraw  removes the row of the id it names where it binds that row's advertiser: the advertiser's own
//	                withdrawal or an admin's, §17.8's "the rule's signer or an admin" (bridgeRowsWithoutRoute)
//
// and a base's rows carry the section at the fold (CompileBridgeRows, which ACL's CompileAcl calls for AclRows.bridge,
// C-05): the modes the log gives at the head's folded_through, and a row for each route the head's ledger holds in force
// there, active and filed under a decision or covered by a standing grant of the head's own policy (DESIGN-DETAILS
// 12.2.4's "in force"). A keyless verifier cannot judge a body, so between bases a route's id-level row stands from its
// filing, as every verifier holds it alike, and the next base keeps it only where the ledger holds it in force: a void,
// pending or uncovered body leaves the rows there, and a withdrawn one has left them already.
//
// One canonical encoding, so every reader hashes one rows_sha256: egress rows in subject order, one a subject, each
// mode exits or none, a subject in auto having no row, since auto is every subject's default; route rows in route_id
// order, one an id, each row's route_rule_ids in byte order, none twice.
//
// Pure, with no clock, network or map order. On every leg, with no connect import. Nothing here creates, derives or
// unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bytes are no BridgeRows a reader holds: a subject or id that is no id, a mode a row never carries, or rows out
// of their one order.
var ErrBridgeRowsMalformed = errors.New("bridge rows malformed")

// Parses AclRows.bridge, strictly: rows as CompileBridgeRows writes them, and no field this build cannot name, since a
// row it skipped could be the one that closes a subject's egress. Empty bytes are the empty section.
func ParseBridgeRows(data []byte) (*bridge.BridgeRows, error) {
	rows := &bridge.BridgeRows{}
	if err := proto.Unmarshal(data, rows); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeRowsMalformed, err)
	}
	if len(rows.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: a field this build cannot name", ErrBridgeRowsMalformed)
	}
	for i, row := range rows.GetEgress() {
		if err := bridgeCheckEgressRow(row); err != nil {
			return nil, fmt.Errorf("%w: egress[%d]: %w", ErrBridgeRowsMalformed, i, err)
		}
		if 0 < i && 0 <= bytes.Compare(rows.GetEgress()[i-1].GetSubject(), row.GetSubject()) {
			return nil, fmt.Errorf("%w: egress[%d] out of subject order", ErrBridgeRowsMalformed, i)
		}
	}
	for i, row := range rows.GetRoutes() {
		if err := bridgeCheckRouteRow(row); err != nil {
			return nil, fmt.Errorf("%w: routes[%d]: %w", ErrBridgeRowsMalformed, i, err)
		}
		if 0 < i && 0 <= bytes.Compare(rows.GetRoutes()[i-1].GetRouteId(), row.GetRouteId()) {
			return nil, fmt.Errorf("%w: routes[%d] out of route_id order", ErrBridgeRowsMalformed, i)
		}
	}
	return rows, nil
}

// One egress row as rows carry it: a 16-byte subject in exits or none.
func bridgeCheckEgressRow(row *bridge.BridgeEgressRow) error {
	if len(row.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("a field this build cannot name")
	}
	if len(row.GetSubject()) != len(Id{}) {
		return fmt.Errorf("a subject of %d bytes", len(row.GetSubject()))
	}
	if row.GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && row.GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE {
		return fmt.Errorf("mode %d", row.GetMode())
	}
	return nil
}

// One route row as rows carry it: a 32-byte route_id, a 16-byte advertiser, and route_rule_ids each a policy rule's 16
// bytes or a requested grant's 32 (§8.8), in byte order with none twice. A route that serves no rule has a row too: its
// filing showed its ids, and the rows hold what the log shows.
func bridgeCheckRouteRow(row *bridge.BridgeRouteRow) error {
	if len(row.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("a field this build cannot name")
	}
	if len(row.GetRouteId()) != bridgeRuleIdByteCount {
		return fmt.Errorf("a route_id of %d bytes", len(row.GetRouteId()))
	}
	if len(row.GetAdvertiser()) != len(Id{}) {
		return fmt.Errorf("an advertiser of %d bytes", len(row.GetAdvertiser()))
	}
	for i, routeRuleId := range row.GetRouteRuleIds() {
		if len(routeRuleId) != len(Id{}) && len(routeRuleId) != sha256.Size {
			return fmt.Errorf("a route_rule_id of %d bytes", len(routeRuleId))
		}
		if 0 < i && 0 <= bytes.Compare(row.GetRouteRuleIds()[i-1], routeRuleId) {
			return fmt.Errorf("route_rule_ids[%d] out of order or twice", i)
		}
	}
	return nil
}

// The section's one encoding: no bytes for the empty section.
func bridgeMarshalRows(rows *bridge.BridgeRows) ([]byte, error) {
	if len(rows.GetEgress()) == 0 && len(rows.GetRoutes()) == 0 {
		return nil, nil
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(rows)
}

// A route's row, its route_rule_ids in their one order: what a BridgeRoute shows, or a ledger's rule.
func bridgeRouteRowOf(routeId []byte, advertiser Id, routeRuleIds [][]byte) *bridge.BridgeRouteRow {
	row := &bridge.BridgeRouteRow{RouteId: bytes.Clone(routeId), Advertiser: advertiser.Bytes()}
	for _, routeRuleId := range routeRuleIds {
		row.RouteRuleIds = append(row.RouteRuleIds, bytes.Clone(routeRuleId))
	}
	slices.SortFunc(row.RouteRuleIds, bytes.Compare)
	row.RouteRuleIds = slices.CompactFunc(row.RouteRuleIds, bytes.Equal)
	return row
}

// The routes a config head's ledger may hold in force at its fold: each route rule row that is active, filed under a
// decision or with no approval, in rule id order, its body as the row holds it. None for a head with no ledger, or for
// no head. An error is a ledger no reader takes: one whose manifest, files or rows do not verify.
func BridgeHeadRoutes(head *ConfigHead) ([]*BridgeLedgerRule, error) {
	if head == nil {
		return nil, nil
	}
	rows, err := NewBridgeLedgerHeadRows(head, nil)
	if err != nil {
		return nil, err
	}
	if rows.Manifest() == nil {
		return nil, nil
	}
	// the head's rows alone, opened as every reader opens them, with no state: no statement past the fold, and no
	// address released, which no route row reads
	ledger, err := openBridgeLedger(rows, nil, &BridgeLedgerReader{}, math.MaxUint64, 0, false, 0)
	if err != nil {
		return nil, err
	}
	routes := []*BridgeLedgerRule{}
	for _, rule := range ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_ROUTE) {
		if rule.Active() && rule.Route != nil && (rule.Standing || rule.ApprovalId != (Id{})) {
			routes = append(routes, rule)
		}
	}
	return routes, nil
}

// compile for §17's section (C-05): the BridgeRows bytes a base's AclRows.bridge carries. logRows is AclRows.bridge of
// the rows compile is given, L(folded_through) (ConfigCompileRows' AclStatements), whose egress modes it keeps, since
// every BridgeEgress is a delta and a head holds no mode of its own; logRows' routes are the log's id-level rows, which
// the fold replaces. routes are the head's ledger's (BridgeHeadRoutes), of which a row is written for each in force:
// filed under a decision, or with no approval and covered by a standing grant of the head's policy, which covers
// answers (AclLocalPolicy.StandingCovers on the compile's own rows, DESIGN-DETAILS 12.2.4); covers nil covers none. An
// error is logRows no verifier could have folded.
func CompileBridgeRows(logRows []byte, routes []*BridgeLedgerRule, covers func(rule *BridgeLedgerRule) bool) ([]byte, error) {
	rows, err := ParseBridgeRows(logRows)
	if err != nil {
		return nil, err
	}
	compiled := &bridge.BridgeRows{Egress: rows.GetEgress()}
	for _, rule := range routes {
		if rule == nil || !rule.Active() || rule.Route == nil || rule.SignedType != bridge.SignedType_SIGNED_BRIDGE_ROUTE {
			continue
		}
		approved := rule.ApprovalId != (Id{}) && !rule.Standing
		if !approved && !(rule.Standing && covers != nil && covers(rule)) {
			continue
		}
		row := bridgeRouteRowOf(rule.RuleId, rule.Owner, rule.RouteRuleIds)
		if err := bridgeCheckRouteRow(row); err != nil {
			return nil, fmt.Errorf("%w: the ledger's route: %w", ErrBridgeRowsMalformed, err)
		}
		compiled.Routes = append(compiled.Routes, row)
	}
	slices.SortFunc(compiled.Routes, func(a *bridge.BridgeRouteRow, b *bridge.BridgeRouteRow) int {
		return bytes.Compare(a.GetRouteId(), b.GetRouteId())
	})
	for i := 1; i < len(compiled.Routes); i += 1 {
		if bytes.Equal(compiled.Routes[i-1].GetRouteId(), compiled.Routes[i].GetRouteId()) {
			return nil, fmt.Errorf("%w: the ledger holds a route_id twice", ErrBridgeRowsMalformed)
		}
	}
	return bridgeMarshalRows(compiled)
}

// The section with subject's mode set, as one BridgeEgress entry changes it: exits or none writes the subject's row,
// and auto removes it. The routes stand.
func bridgeRowsWithEgress(data []byte, subject Id, mode bridge.BridgeEgressMode) ([]byte, error) {
	rows, err := ParseBridgeRows(data)
	if err != nil {
		return nil, err
	}
	next := &bridge.BridgeRows{Routes: rows.GetRoutes()}
	for _, row := range rows.GetEgress() {
		if !bytes.Equal(row.GetSubject(), subject.Bytes()) {
			next.Egress = append(next.Egress, row)
		}
	}
	switch mode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO:
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		next.Egress = append(next.Egress, &bridge.BridgeEgressRow{Subject: subject.Bytes(), Mode: mode})
		slices.SortFunc(next.Egress, func(a *bridge.BridgeEgressRow, b *bridge.BridgeEgressRow) int {
			return bytes.Compare(a.GetSubject(), b.GetSubject())
		})
	default:
		return nil, fmt.Errorf("%w: mode %d", ErrBridgeRowsMalformed, mode)
	}
	return bridgeMarshalRows(next)
}

// The section with a BridgeRoute's row added, its route_id, advertiser and route_rule_ids as the statement shows them,
// where the rows hold no row of its id. A filing of a held id activates nothing (§17.8), so a row of its id stands as it
// is, whoever filed it: the advertiser and rules a route serves are its first filing's, as the ledger keeps them.
func bridgeRowsWithRoute(data []byte, statement *BridgeLogStatement) ([]byte, error) {
	rows, err := ParseBridgeRows(data)
	if err != nil {
		return nil, err
	}
	if statement.SignedType != bridge.SignedType_SIGNED_BRIDGE_ROUTE {
		return nil, fmt.Errorf("%w: a %s files no route", ErrBridgeRowsMalformed, statement.SignedType)
	}
	index, held := slices.BinarySearchFunc(rows.GetRoutes(), statement.RuleId, func(row *bridge.BridgeRouteRow, routeId []byte) int {
		return bytes.Compare(row.GetRouteId(), routeId)
	})
	if held {
		return data, nil
	}
	row := bridgeRouteRowOf(statement.RuleId, statement.Subject, statement.RouteRuleIds)
	if err := bridgeCheckRouteRow(row); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeRowsMalformed, err)
	}
	next := &bridge.BridgeRows{Egress: rows.GetEgress(), Routes: slices.Insert(slices.Clone(rows.GetRoutes()), index, row)}
	return bridgeMarshalRows(next)
}

// The section with the route row a BridgeWithdraw names removed, where the withdrawal binds it: its advertiser's own, or
// an admin's (bridgeWithdrawalBinds). A withdrawal of an id the rows hold no route of, a map's or one never filed,
// changes nothing here, and one that binds only its own signer's filings leaves another's row standing.
func bridgeRowsWithoutRoute(data []byte, statement *BridgeLogStatement) ([]byte, error) {
	rows, err := ParseBridgeRows(data)
	if err != nil {
		return nil, err
	}
	if statement.SignedType != bridge.SignedType_SIGNED_BRIDGE_WITHDRAW {
		return nil, fmt.Errorf("%w: a %s withdraws nothing", ErrBridgeRowsMalformed, statement.SignedType)
	}
	index, held := slices.BinarySearchFunc(rows.GetRoutes(), statement.RuleId, func(row *bridge.BridgeRouteRow, routeId []byte) int {
		return bytes.Compare(row.GetRouteId(), routeId)
	})
	if !held || !bridgeWithdrawalBinds(statement, Id(rows.GetRoutes()[index].GetAdvertiser())) {
		return data, nil
	}
	next := &bridge.BridgeRows{Egress: rows.GetEgress(), Routes: slices.Delete(slices.Clone(rows.GetRoutes()), index, index+1)}
	return bridgeMarshalRows(next)
}

// The egress mode rows give one subject, a sidecar_id or a keyed atom: its row's, else auto.
func BridgeRowsEgressMode(rows *bridge.BridgeRows, subject Id) bridge.BridgeEgressMode {
	for _, row := range rows.GetEgress() {
		if bytes.Equal(row.GetSubject(), subject.Bytes()) {
			return row.GetMode()
		}
	}
	return bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
}

// The route row rows hold under a route_id, nil for none.
func BridgeRowsRoute(rows *bridge.BridgeRows, routeId []byte) *bridge.BridgeRouteRow {
	index, held := slices.BinarySearchFunc(rows.GetRoutes(), routeId, func(row *bridge.BridgeRouteRow, target []byte) int {
		return bytes.Compare(row.GetRouteId(), target)
	})
	if !held {
		return nil
	}
	return rows.GetRoutes()[index]
}

// The egress modes and routes this state's rows hold, with every bridge entry since the base applied: what §8.10's gate
// and AclState read. An error is rows no verifier folded, which a gate treats as no answer and refuses on.
func (self *ConfigState) BridgeRows() (*bridge.BridgeRows, error) {
	return ParseBridgeRows(self.aclRows.GetBridge())
}
