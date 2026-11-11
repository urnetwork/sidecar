// §17.8's statements as rules of the authorization log (R-BRIDGE-3, D-BRIDGE-6): BridgeAddress, BridgeRoute, BridgeMap,
// BridgeEgress, BridgeAlias and BridgeWithdraw, SignedType 0x1902 to 0x1907, purpose bridge. BridgeBlock, 0x1901, rides a
// config head and never the log (bridge_statement_rules.go's CheckBridgeBlock).
//
// A bridge statement is judged at two depths, because api, the gates and an app's forwarding judge hold no config key
// or may lack a generation (DESIGN-DETAILS 4.2.5):
//
//	id level    here, at every reader alike, rows-only ones included, with no key: the Signed's type and purpose, the
//	            header and §7.9's read_only refusal, which the log runs before any rule, then the signer's class and
//	            the ids a statement shows. This is the entry's one verdict, the one a base's tail_verdicts carries.
//	body level  bridge_statement_rules.go's BridgeLedger, on a reader that holds the sealed body's generation: it
//	            opens the body and runs the rest. It refuses nothing in the log: a body that breaks its rule is void
//	            at every reader that opens it, and one whose generation the reader lacks is pending with its id-level
//	            effect.
//
// Signers at id level, each one standing sidecar's identity key, never a recovery key or a Delegation's:
//
//	BridgeAddress   the sidecar it names, or an admin
//	BridgeRoute     its advertiser
//	BridgeMap       its host
//	BridgeEgress    an admin, a device of the subject's own member, or one of its sponsor's
//	BridgeAlias     the accepting sidecar, which is whoever signs it: all of its row is sealed
//	BridgeWithdraw  the rule's signer, or an admin
//
// An admin is an Owner's or Admin's standing member device, the roles that sign ServiceSettings (§7.9).
//
// BridgeLog is the id-level fold a ConfigState holds: the bridge statements that took effect since the newest base's
// folded_through, in log order. A base's rows carry none of them but BridgeRows' egress modes, so a base empties the
// fold and its tail re-applies, and a new device and a long-running reader hold one BridgeLog (FS-14's shape). The
// traps that read the fold, a withdrawn id and a held id, therefore see the unfolded tail alone at id level; a full
// reader's ledger runs them over the whole history it joins from the config head (JoinBridgeLogs).
//
// A BridgeEgress shows its mode at id level, in BridgeEgress.mode = 4, which §2.8's api-7 row names (QD-630, I-18), so
// every reader, a keyless gate's included, folds each entry's mode into BridgeRows in log order; one that shows no mode,
// or a value outside the enum, is refused at every reader (bridgeEgressClearMode).
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. A BridgeLog is immutable and safe
// for concurrent use. On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	// The domain of a rule id under a decision (§17.8).
	bridgeRuleIdDomain = "urnetwork-sidecar-v1/bridge-rule"
	// A route_id or map_id: a SHA-256 under a decision, 32 random bytes under a standing grant.
	bridgeRuleIdByteCount = sha256.Size
	// The most §8 route rules one BridgeRoute names. Its ids ride every reader's fold, so the count is bounded.
	bridgeRouteRuleIdMaxCount = 64
)

// §17.8's rule id under a decision: SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key), effect_key the use's
// §16.6 ledger key (ApprovalEffectKey). Readers recompute it from the BridgeApproval a rule carries, so a retry or a
// restart files one id.
func BridgeRuleId(effectKey [sha256.Size]byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(bridgeRuleIdDomain))
	hash.Write(effectKey[:])
	var ruleId [sha256.Size]byte
	hash.Sum(ruleId[:0])
	return ruleId
}

// One bridge statement that took effect in the log, as the fold keeps it: what it shows at id level, and its sealed
// body as carried. Never changed once a BridgeLog holds it.
type BridgeLogStatement struct {
	SignedType bridge.SignedType
	// The statement's id (StatementId).
	StatementId [sha256.Size]byte
	// The entry that carried it, and that entry's time.
	N      uint64
	TimeMs int64
	// The sidecar whose identity key signed it.
	Signer Id
	// Whether the signer was an admin's device at the entry. A fold over statements whose positions' states are gone
	// passes what it knows; true is the closing answer for a withdrawal, which then binds any filer.
	SignerAdmin bool
	// What the sealed body is bound to: the statement's type and its header's network_id and nonce.
	Seal *ConfigSealContext
	// The sidecar the statement is about: a BridgeAddress's sidecar_id, a BridgeRoute's advertiser, a BridgeMap's
	// host, a BridgeEgress's subject, which may be a keyed atom. Zero for an alias or a withdrawal.
	Subject Id
	// A BridgeRoute's route_id, a BridgeMap's map_id or the rule a BridgeWithdraw names.
	RuleId []byte
	// A BridgeRoute's route_rule_ids: the §8 route rules it serves.
	RouteRuleIds [][]byte
	// A BridgeMap's expires, ms since the epoch, 0 for none.
	Expires int64
	// A BridgeWithdraw's mode.
	WithdrawMode bridge.BridgeWithdrawMode
	// A BridgeEgress's mode as it shows at id level (bridgeEgressClearMode).
	EgressMode bridge.BridgeEgressMode
	// The sealed body as carried; empty for a withdrawal.
	SealedBody []byte
}

// Whether the statement files a rule: a BridgeRoute or a BridgeMap.
func (self *BridgeLogStatement) filesRule() bool {
	return self.SignedType == bridge.SignedType_SIGNED_BRIDGE_ROUTE || self.SignedType == bridge.SignedType_SIGNED_BRIDGE_MAP
}

// One rule id as the id-level fold holds it.
type BridgeLogRule struct {
	RuleId []byte
	// SIGNED_BRIDGE_ROUTE or SIGNED_BRIDGE_MAP.
	SignedType bridge.SignedType
	// Its advertiser or host, which signed it.
	Owner Id
	// Its filings in log order: the first, then each filing of the held id.
	Filings []*BridgeLogStatement
	// The first withdrawal that binds it, nil while none does.
	Withdrawn *BridgeLogStatement
}

// §17.8's id-level fold of one ConfigState: every bridge statement that took effect since the newest base's
// folded_through, in log order. The zero log is nil, which every method takes.
type BridgeLog struct {
	statements []*BridgeLogStatement

	foldOnce sync.Once
	fold     *bridgeLogFold
}

// What the statements fold to at id level, built on first use.
type bridgeLogFold struct {
	rules map[string]*BridgeLogRule
	// every withdrawal by the rule id it names, in log order, whether or not its rule is in the fold
	withdrawals map[string][]*BridgeLogStatement
}

// A log of statements in log order, as a full reader folds the ones a config head holds (BRIDGE-M4-16). The caller
// passes only statements that took effect, each judged at its own position.
func NewBridgeLog(statements []*BridgeLogStatement) *BridgeLog {
	if len(statements) == 0 {
		return nil
	}
	return &BridgeLog{statements: slices.Clone(statements)}
}

// folded then tail: the whole history a full reader's ledger reads, the statements a config head folded and the ones
// a ConfigState holds since. A statement both hold, by its id, is taken once, from folded.
func JoinBridgeLogs(folded *BridgeLog, tail *BridgeLog) *BridgeLog {
	statements := slices.Clone(folded.Statements())
	held := map[[sha256.Size]byte]bool{}
	for _, statement := range statements {
		held[statement.StatementId] = true
	}
	for _, statement := range tail.Statements() {
		if !held[statement.StatementId] {
			statements = append(statements, statement)
		}
	}
	return NewBridgeLog(statements)
}

// The log with one more statement. The receiver is unchanged.
func (self *BridgeLog) With(statement *BridgeLogStatement) *BridgeLog {
	statements := make([]*BridgeLogStatement, 0, len(self.Statements())+1)
	statements = append(statements, self.Statements()...)
	statements = append(statements, statement)
	return &BridgeLog{statements: statements}
}

// The statements in log order. The caller must not change them.
func (self *BridgeLog) Statements() []*BridgeLogStatement {
	if self == nil {
		return nil
	}
	return self.statements
}

// How many statements the log holds.
func (self *BridgeLog) Len() int {
	return len(self.Statements())
}

// Whether a withdrawal binds a rule its filer signs: an admin's binds any filer's, and anyone else's only its own
// (§17.8's "the rule's signer or an admin").
func bridgeWithdrawalBinds(withdrawal *BridgeLogStatement, filer Id) bool {
	return withdrawal.SignerAdmin || withdrawal.Signer == filer
}

// The id-level fold, built once.
func (self *BridgeLog) index() *bridgeLogFold {
	if self == nil {
		return &bridgeLogFold{}
	}
	self.foldOnce.Do(func() {
		fold := &bridgeLogFold{rules: map[string]*BridgeLogRule{}, withdrawals: map[string][]*BridgeLogStatement{}}
		for _, statement := range self.statements {
			key := string(statement.RuleId)
			switch {
			case statement.filesRule():
				rule := fold.rules[key]
				if rule == nil {
					rule = &BridgeLogRule{RuleId: statement.RuleId, SignedType: statement.SignedType, Owner: statement.Signer}
					fold.rules[key] = rule
					// a withdrawal ahead of its rule's first filing binds it from that filing on
					for _, withdrawal := range fold.withdrawals[key] {
						if rule.Withdrawn == nil && bridgeWithdrawalBinds(withdrawal, rule.Owner) {
							rule.Withdrawn = withdrawal
						}
					}
				}
				rule.Filings = append(rule.Filings, statement)
			case statement.SignedType == bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
				fold.withdrawals[key] = append(fold.withdrawals[key], statement)
				if rule := fold.rules[key]; rule != nil && rule.Withdrawn == nil && bridgeWithdrawalBinds(statement, rule.Owner) {
					rule.Withdrawn = statement
				}
			}
		}
		self.fold = fold
	})
	return self.fold
}

// The rule the fold holds under ruleId, nil for none. The caller must not change it.
func (self *BridgeLog) Rule(ruleId []byte) *BridgeLogRule {
	return self.index().rules[string(ruleId)]
}

// The first withdrawal in the fold that binds a rule ruleId filed by filer, nil for none: a filing of that id is
// refused (§17.8's "readers refuse an id a BridgeWithdraw named").
func (self *BridgeLog) Withdrawal(ruleId []byte, filer Id) *BridgeLogStatement {
	for _, withdrawal := range self.index().withdrawals[string(ruleId)] {
		if bridgeWithdrawalBinds(withdrawal, filer) {
			return withdrawal
		}
	}
	return nil
}

// §17.8's id-level traps on a statement at the next position, over this fold:
//
//	a filing    its id not one a BridgeWithdraw that binds its signer named; a held id filed again only as the same
//	            kind by the same signer, and then it activates nothing (the ledger holds what it may change)
//	withdrawal  of a rule the fold holds, by that rule's signer or an admin; of a rule it does not hold, by any
//	            standing sidecar, binding only what that signer files unless it is an admin
func (self *BridgeLog) judge(statement *BridgeLogStatement) error {
	switch {
	case statement.filesRule():
		if withdrawal := self.Withdrawal(statement.RuleId, statement.Signer); withdrawal != nil {
			return fmt.Errorf("%w: a BridgeWithdraw at %d named this rule id", ErrConfigRule, withdrawal.N)
		}
		if rule := self.Rule(statement.RuleId); rule != nil {
			if rule.SignedType != statement.SignedType {
				return fmt.Errorf("%w: the rule id is held by a %s", ErrConfigRule, rule.SignedType)
			}
			if rule.Owner != statement.Signer {
				return fmt.Errorf("%w: the rule id is held by another signer", ErrConfigAuthority)
			}
		}
	case statement.SignedType == bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
		if rule := self.Rule(statement.RuleId); rule != nil && !bridgeWithdrawalBinds(statement, rule.Owner) {
			return fmt.Errorf("%w: a BridgeWithdraw by neither the rule's signer nor an admin", ErrConfigAuthority)
		}
	}
	return nil
}

// The bridge part of this state: the bridge statements that took effect since the newest base's folded_through. Nil
// for none, which every method of a BridgeLog takes.
func (self *ConfigState) Bridge() *BridgeLog {
	return self.bridge
}

// The mode a BridgeEgress shows at id level, BridgeEgress.mode = 4 (QD-630, §2.8's api-7), and whether it shows one:
// unspecified shows none, which the rule refuses, as it does a value outside the enum.
func bridgeEgressClearMode(egress *bridge.BridgeEgress) (bridge.BridgeEgressMode, bool) {
	mode := egress.GetMode()
	return mode, mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED
}

// Registers §17.8's six log statements. BridgeBlock has no rule: it carries no StatementHeader, so the log refuses it
// before any rule, and it rides config heads alone.
func init() {
	for _, signedType := range []bridge.SignedType{
		bridge.SignedType_SIGNED_BRIDGE_ADDRESS,
		bridge.SignedType_SIGNED_BRIDGE_ROUTE,
		bridge.SignedType_SIGNED_BRIDGE_MAP,
		bridge.SignedType_SIGNED_BRIDGE_EGRESS,
		bridge.SignedType_SIGNED_BRIDGE_ALIAS,
		bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
	} {
		registerConfigStatementRule(configStatementRule{
			signedType: signedType,
			purpose:    bridge.SignedPurposeBridge,
			check:      configCheckBridgeStatement,
			apply:      configApplyBridgeStatement,
		})
	}
}

// A bridge statement's id-level verdict at state: its shape, its signer's class, and the fold's traps.
func configCheckBridgeStatement(state *ConfigState, statement *configStatement) error {
	logStatement, err := bridgeLogStatementOf(statement)
	if err != nil {
		return err
	}
	if err := bridgeCheckSigner(state, statement, logStatement); err != nil {
		return err
	}
	logStatement.SignerAdmin = bridgeSignerAdmin(state, statement)
	return state.Bridge().judge(logStatement)
}

// A bridge statement's id-level effect: it joins the fold, and a BridgeEgress writes its subject's mode into the rows'
// BridgeRows, as gates and api apply each entry over a base's rows (bridge_rows.go). Whether its signer was an admin is
// read on the state the entry lands on, so a base's re-application follows the rebuilt rows.
func configApplyBridgeStatement(next *configStateBuilder, statement *configStatement) error {
	logStatement, err := bridgeLogStatementOf(statement)
	if err != nil {
		return err
	}
	logStatement.SignerAdmin = bridgeSignerAdmin(next.state, statement)
	if logStatement.SignedType == bridge.SignedType_SIGNED_BRIDGE_EGRESS {
		bridgeRows, err := bridgeRowsWithEgress(next.state.aclRows.GetBridge(), logStatement.Subject, logStatement.EgressMode)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrConfigRule, err)
		}
		aclRows := aclRowsCopy(next.state.aclRows)
		aclRows.Bridge = bridgeRows
		next.setAclRows(aclRows)
	}
	next.state.bridge = next.state.bridge.With(logStatement)
	return nil
}

// Whether the statement's signer is an admin's device at state: an Owner's or Admin's standing member device that is
// not read_only.
func bridgeSignerAdmin(state *ConfigState, statement *configStatement) bool {
	_, admin := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return configRoleAdmitsMembers(role)
	})
	return admin
}

// What a bridge statement shows at id level, refusing a shape no reader folds: more than one signer or a signer that
// is no sidecar's identity key, an id of the wrong size, a rule body missing where the type seals one, or a field out
// of its range. No state is read, so a base's re-application reaches the same statement.
func bridgeLogStatementOf(statement *configStatement) (*BridgeLogStatement, error) {
	if len(statement.signers) != 1 || statement.signers[0].Kind != ConfigSignerSidecar {
		return nil, fmt.Errorf("%w: %s takes one sidecar's identity signature", ErrConfigSigner, statement.signedType)
	}
	logStatement := &BridgeLogStatement{
		SignedType:  statement.signedType,
		StatementId: statement.id,
		N:           statement.n,
		TimeMs:      statement.timeMs,
		Signer:      statement.signers[0].SidecarId,
		Seal:        NewConfigSealContext(statement.signedType, statement.header),
	}
	sealed := func(sealedBody []byte) error {
		if _, err := ConfigSealedGeneration(sealedBody); err != nil {
			return fmt.Errorf("%w: %s carries no sealed body: %w", ErrConfigRule, statement.signedType, err)
		}
		logStatement.SealedBody = bytes.Clone(sealedBody)
		return nil
	}
	subject := func(name string, idBytes []byte) error {
		subjectId, err := IdFromBytes(idBytes)
		if err != nil {
			return fmt.Errorf("%w: %s of %d bytes", ErrConfigRule, name, len(idBytes))
		}
		logStatement.Subject = subjectId
		return nil
	}
	ruleId := func(name string, idBytes []byte) error {
		if len(idBytes) != bridgeRuleIdByteCount {
			return fmt.Errorf("%w: %s of %d bytes", ErrConfigRule, name, len(idBytes))
		}
		logStatement.RuleId = bytes.Clone(idBytes)
		return nil
	}
	switch body := statement.body.(type) {
	case *bridge.BridgeAddress:
		if err := subject("sidecar_id", body.GetSidecarId()); err != nil {
			return nil, err
		}
		if err := sealed(body.GetSealedBody()); err != nil {
			return nil, err
		}
	case *bridge.BridgeRoute:
		if err := ruleId("route_id", body.GetRouteId()); err != nil {
			return nil, err
		}
		if err := subject("advertiser", body.GetAdvertiser()); err != nil {
			return nil, err
		}
		if bridgeRouteRuleIdMaxCount < len(body.GetRouteRuleIds()) {
			return nil, fmt.Errorf("%w: %d route_rule_ids", ErrConfigRule, len(body.GetRouteRuleIds()))
		}
		for _, routeRuleId := range body.GetRouteRuleIds() {
			// a policy rule's id is 16 bytes and a requested grant's 32 (§8.8)
			if len(routeRuleId) != len(Id{}) && len(routeRuleId) != sha256.Size {
				return nil, fmt.Errorf("%w: a route_rule_id of %d bytes", ErrConfigRule, len(routeRuleId))
			}
			if slices.ContainsFunc(logStatement.RouteRuleIds, func(held []byte) bool { return bytes.Equal(held, routeRuleId) }) {
				return nil, fmt.Errorf("%w: a route_rule_id named twice", ErrConfigRule)
			}
			logStatement.RouteRuleIds = append(logStatement.RouteRuleIds, bytes.Clone(routeRuleId))
		}
		if err := sealed(body.GetSealedBody()); err != nil {
			return nil, err
		}
	case *bridge.BridgeMap:
		if err := ruleId("map_id", body.GetMapId()); err != nil {
			return nil, err
		}
		if err := subject("host", body.GetHost()); err != nil {
			return nil, err
		}
		if body.GetExpires() < 0 || (body.GetExpires() != 0 && body.GetExpires() <= statement.timeMs) {
			return nil, fmt.Errorf("%w: a map that expired before its entry", ErrConfigRule)
		}
		logStatement.Expires = body.GetExpires()
		if err := sealed(body.GetSealedBody()); err != nil {
			return nil, err
		}
	case *bridge.BridgeEgress:
		if err := subject("subject", body.GetSubject()); err != nil {
			return nil, err
		}
		mode, shown := bridgeEgressClearMode(body)
		if !shown {
			return nil, fmt.Errorf("%w: a BridgeEgress that shows no mode", ErrConfigRule)
		}
		switch mode {
		case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
			// like a BridgeWithdraw, it never waits on a seal
			if len(body.GetSealedBody()) != 0 {
				return nil, fmt.Errorf("%w: a BridgeEgress of mode %s carries no body", ErrConfigRule, mode)
			}
		case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
			if err := sealed(body.GetSealedBody()); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: egress mode %d", ErrConfigRule, mode)
		}
		logStatement.EgressMode = mode
	case *bridge.BridgeAlias:
		if err := sealed(body.GetSealedBody()); err != nil {
			return nil, err
		}
	case *bridge.BridgeWithdraw:
		if err := ruleId("rule_id", body.GetRuleId()); err != nil {
			return nil, err
		}
		if body.GetMode() != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET && body.GetMode() != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
			return nil, fmt.Errorf("%w: withdraw mode %d", ErrConfigRule, body.GetMode())
		}
		logStatement.WithdrawMode = body.GetMode()
	default:
		return nil, fmt.Errorf("%w: %s is no bridge statement of the log", ErrConfigRule, statement.signedType)
	}
	return logStatement, nil
}

// The signer's class at state, as the table at the top of this file says. Every signer is a standing sidecar: admitted,
// not revoked or parked, its not_after unpassed.
func bridgeCheckSigner(state *ConfigState, statement *configStatement, logStatement *BridgeLogStatement) error {
	signerId := logStatement.Signer
	if _, standing := state.standingSidecar(signerId, statement.timeMs); !standing {
		return fmt.Errorf("%w: the signer is not standing", ErrConfigAuthority)
	}
	admin := bridgeSignerAdmin(state, statement)
	switch logStatement.SignedType {
	case bridge.SignedType_SIGNED_BRIDGE_ADDRESS:
		row := state.sidecars[logStatement.Subject]
		if row == nil || row.GetRevokedAt() != 0 {
			return fmt.Errorf("%w: an address for no admitted sidecar", ErrConfigRule)
		}
		if signerId != logStatement.Subject && !admin {
			return fmt.Errorf("%w: a BridgeAddress by neither its sidecar nor an admin", ErrConfigAuthority)
		}
	case bridge.SignedType_SIGNED_BRIDGE_ROUTE:
		if signerId != logStatement.Subject {
			return fmt.Errorf("%w: a BridgeRoute its advertiser did not sign", ErrConfigAuthority)
		}
	case bridge.SignedType_SIGNED_BRIDGE_MAP:
		if signerId != logStatement.Subject {
			return fmt.Errorf("%w: a BridgeMap its host did not sign", ErrConfigAuthority)
		}
	case bridge.SignedType_SIGNED_BRIDGE_EGRESS:
		if !admin && !bridgeEgressOwnerOrSponsor(state, statement, logStatement.Subject) {
			return fmt.Errorf("%w: a BridgeEgress by no admin, owner or sponsor of its subject", ErrConfigAuthority)
		}
	case bridge.SignedType_SIGNED_BRIDGE_ALIAS, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
		// an alias's signer is the accepting sidecar, and a withdrawal's is judged against its rule by the fold
	}
	return nil
}

// Whether a signer is a standing member device of the member that owns the subject, an untagged sidecar, or of the
// member that sponsors it, a tagged one. A subject that is no admitted sidecar, a keyed atom, has neither: only an
// admin sets its mode.
func bridgeEgressOwnerOrSponsor(state *ConfigState, statement *configStatement, subjectId Id) bool {
	row := state.sidecars[subjectId]
	if row == nil || row.GetRevokedAt() != 0 {
		return false
	}
	responsible, ok := configRowMember(row)
	if !ok {
		if responsible, ok = state.Sponsor(subjectId); !ok {
			return false
		}
	}
	_, found := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return memberId == responsible
	})
	return found
}
