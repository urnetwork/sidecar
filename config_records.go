// §7.9's records as the log carries them: which body each (purpose, type) pair registers, and what names a statement.
// The chain under them, AuthChainDigest and GenesisChain, is protocol/bridge's, where the device role reaches it.
//
// Every layer keeps a statement's verbatim bytes. A signature covers a body as received and an id a Signed as received,
// so nothing here re-marshals, and a caller that did would get another id or a refused signature.
//
// On every leg, with no connect import. No key is created, derived or unwrapped here, so nothing calls testHookSecret.
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How much of an id a reader keeps for the last 4,096 entries (§7.9's retain row: 16 B each, 64 KiB).
const configRetainedIdSize = 16

var (
	// The pair registers no statement: an unknown type, a type this log does not carry, or one signed under
	// another purpose.
	ErrConfigStatementType = errors.New("config statement type refused")
	// The bytes do not parse as what they claim to be.
	ErrConfigStatementBody = errors.New("config statement body refused")
)

// What one signed type registers (§6.11).
type configStatementType struct {
	purpose string
	// typed nil: only its descriptor is read, to make the body to parse into
	body proto.Message
}

// Every type the log and config heads carry, each with its one purpose and its one body: §7.9's records, purpose
// authority; §8.8's statements, purpose acl but for AuditOptIn and AuditOptOut; §17.8's statements, purpose bridge.
// §17.9's WindowDelegation and ShareCert ride links and config files, never the log, so they stay out. Never written
// after init.
var configStatementTypes = map[bridge.SignedType]configStatementType{
	bridge.SignedType_SIGNED_GRANT_ACTIVATE:  {purpose: bridge.SignedPurposeAcl, body: (*protocol.GrantActivate)(nil)},
	bridge.SignedType_SIGNED_GRANT_REVOKE:    {purpose: bridge.SignedPurposeAcl, body: (*bridge.GrantRevoke)(nil)},
	bridge.SignedType_SIGNED_SUSPEND:         {purpose: bridge.SignedPurposeAcl, body: (*bridge.Suspend)(nil)},
	bridge.SignedType_SIGNED_UNSUSPEND:       {purpose: bridge.SignedPurposeAcl, body: (*bridge.Unsuspend)(nil)},
	bridge.SignedType_SIGNED_EVS_SHARE:       {purpose: bridge.SignedPurposeAcl, body: (*protocol.EvsShare)(nil)},
	bridge.SignedType_SIGNED_OWNER_CONFIRM:   {purpose: bridge.SignedPurposeAcl, body: (*protocol.OwnerConfirm)(nil)},
	bridge.SignedType_SIGNED_REPO_CREATE:     {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoCreate)(nil)},
	bridge.SignedType_SIGNED_REPO_ADMIN:      {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoAdmin)(nil)},
	bridge.SignedType_SIGNED_REPO_GRANT:      {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoGrant)(nil)},
	bridge.SignedType_SIGNED_REPO_REVOKE:     {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoRevoke)(nil)},
	bridge.SignedType_SIGNED_REPO_DELETE:     {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoDelete)(nil)},
	bridge.SignedType_SIGNED_REPO_RESTORE:    {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoRestore)(nil)},
	bridge.SignedType_SIGNED_REPO_VERSIONING: {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoVersioning)(nil)},
	bridge.SignedType_SIGNED_AUDIT_OPT_IN:    {purpose: bridge.SignedPurposeAuthority, body: (*protocol.AuditOptIn)(nil)},
	bridge.SignedType_SIGNED_AUDIT_OPT_OUT:   {purpose: bridge.SignedPurposeAuthority, body: (*protocol.AuditOptOut)(nil)},
	// reserved at M2 so that no verifier refuses it as unknown and forks at a repo's first set (QD-212; DESIGN-DETAILS
	// 16.2.12)
	bridge.SignedType_SIGNED_REPO_PREFIX_RULES: {purpose: bridge.SignedPurposeAcl, body: (*protocol.RepoPrefixRules)(nil)},

	bridge.SignedType_SIGNED_GENESIS:            {purpose: bridge.SignedPurposeAuthority, body: (*bridge.Genesis)(nil)},
	bridge.SignedType_SIGNED_ADMIN_SET:          {purpose: bridge.SignedPurposeAuthority, body: (*protocol.AdminSet)(nil)},
	bridge.SignedType_SIGNED_MEMBER_ADMIT:       {purpose: bridge.SignedPurposeAuthority, body: (*protocol.MemberAdmit)(nil)},
	bridge.SignedType_SIGNED_MEMBER_REVOKE:      {purpose: bridge.SignedPurposeAuthority, body: (*bridge.MemberRevoke)(nil)},
	bridge.SignedType_SIGNED_SIDECAR_ADMIT:      {purpose: bridge.SignedPurposeAuthority, body: (*protocol.SidecarAdmit)(nil)},
	bridge.SignedType_SIGNED_SIDECAR_REVOKE:     {purpose: bridge.SignedPurposeAuthority, body: (*bridge.SidecarRevoke)(nil)},
	bridge.SignedType_SIGNED_ADMISSION_CONFIRM:  {purpose: bridge.SignedPurposeAuthority, body: (*protocol.AdmissionConfirm)(nil)},
	bridge.SignedType_SIGNED_SPONSOR_SET:        {purpose: bridge.SignedPurposeAuthority, body: (*protocol.SponsorSet)(nil)},
	bridge.SignedType_SIGNED_INDEXER_SET:        {purpose: bridge.SignedPurposeAuthority, body: (*protocol.IndexerSet)(nil)},
	bridge.SignedType_SIGNED_RECOVERY_BIND:      {purpose: bridge.SignedPurposeAuthority, body: (*protocol.RecoveryBind)(nil)},
	bridge.SignedType_SIGNED_RECOVERY_REBIND:    {purpose: bridge.SignedPurposeAuthority, body: (*protocol.RecoveryRebind)(nil)},
	bridge.SignedType_SIGNED_KEY_REGISTER:       {purpose: bridge.SignedPurposeAuthority, body: (*protocol.KeyRegister)(nil)},
	bridge.SignedType_SIGNED_KEY_REVOKE:         {purpose: bridge.SignedPurposeAuthority, body: (*protocol.KeyRevoke)(nil)},
	bridge.SignedType_SIGNED_DELEGATION:         {purpose: bridge.SignedPurposeAuthority, body: (*protocol.Delegation)(nil)},
	bridge.SignedType_SIGNED_DELEGATION_REVOKE:  {purpose: bridge.SignedPurposeAuthority, body: (*protocol.DelegationRevoke)(nil)},
	bridge.SignedType_SIGNED_SERVICE_SETTINGS:   {purpose: bridge.SignedPurposeAuthority, body: (*protocol.ServiceSettings)(nil)},
	bridge.SignedType_SIGNED_VERSIONING_RULES:   {purpose: bridge.SignedPurposeAuthority, body: (*protocol.VersioningRules)(nil)},
	bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL: {purpose: bridge.SignedPurposeAuthority, body: (*protocol.AuthorityProposal)(nil)},
	bridge.SignedType_SIGNED_AUTHORITY_COSIGN:   {purpose: bridge.SignedPurposeAuthority, body: (*protocol.AuthorityCosign)(nil)},
	bridge.SignedType_SIGNED_RECOVERY_VETO:      {purpose: bridge.SignedPurposeAuthority, body: (*protocol.RecoveryVeto)(nil)},
	bridge.SignedType_SIGNED_PROJECTION_HEADER:  {purpose: bridge.SignedPurposeAuthority, body: (*bridge.ProjectionHeader)(nil)},

	bridge.SignedType_SIGNED_BRIDGE_BLOCK:    {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeBlock)(nil)},
	bridge.SignedType_SIGNED_BRIDGE_ADDRESS:  {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeAddress)(nil)},
	bridge.SignedType_SIGNED_BRIDGE_ROUTE:    {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeRoute)(nil)},
	bridge.SignedType_SIGNED_BRIDGE_MAP:      {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeMap)(nil)},
	bridge.SignedType_SIGNED_BRIDGE_EGRESS:   {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeEgress)(nil)},
	bridge.SignedType_SIGNED_BRIDGE_ALIAS:    {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeAlias)(nil)},
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW: {purpose: bridge.SignedPurposeBridge, body: (*bridge.BridgeWithdraw)(nil)},
}

// The purpose a type is signed under, which a heterogeneous list reads off Signed.type before it verifies (§6.11),
// and a proposal off its statement_type. False for a value that is no config statement.
func ConfigStatementPurpose(signedType bridge.SignedType) (string, bool) {
	statementType, ok := configStatementTypes[signedType]
	return statementType.purpose, ok
}

// Parses a body only as the message its (purpose, type) registers (§6.9), refusing any other pair whatever the body
// holds.
//
// Two statements can encode alike, so a body that parses says nothing of what it is: a GrantRevoke and an OwnerConfirm
// differ only in their signed type (§22.6). A caller passes the pair it verified with VerifySigned, and the body of
// that same Signed, as received. A new field in an older reader's body is kept as unknown, never refused (§6.4).
func ParseConfigStatement(purpose string, signedType bridge.SignedType, body []byte) (proto.Message, error) {
	statementType, ok := configStatementTypes[signedType]
	if !ok || statementType.purpose != purpose {
		return nil, fmt.Errorf("%w: %q, %d", ErrConfigStatementType, purpose, int32(signedType))
	}
	message := statementType.body.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(body, message); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigStatementBody, signedType, err)
	}
	return message, nil
}

// The one definition of what names a Signed in the log, which StatementId, ProposalId and DelegationId share, so
// changing what an id covers changes this function and nothing that calls it. expectedType narrows it to one type;
// SIGNED_TYPE_NONE takes any config statement. signedBytes must be the Signed as received.
//
// An id is bridge.SignedBytesSha256 of the statement's purpose, type and body as received, which its signature fixes
// (protos-bridge-statement-id-wrapper, decided by the owner). No signature covers a Signed's wrapper, its signer_id,
// key_id, countersignature or unknown fields, so a server could carry one statement as many Signeds that all verify;
// they all share this id, and §7.9's replay row and every id that names a proposal or a Delegation see one statement.
// A body re-encoded is another body, whose signature fails.
func configSignedId(signedBytes []byte, expectedType bridge.SignedType) ([sha256.Size]byte, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %w", ErrConfigStatementBody, err)
	}
	signedType := bridge.SignedType(signed.GetType())
	statementType, ok := configStatementTypes[signedType]
	if !ok || (expectedType != bridge.SignedType_SIGNED_TYPE_NONE && signedType != expectedType) {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %d", ErrConfigStatementType, int32(signedType))
	}
	return bridge.SignedBytesSha256(statementType.purpose, signedType, signed.GetBody()), nil
}

// A statement's id: §7.9's replay row refuses a repeat of one, and a retry of one answers with its entry. It is also a
// SidecarRow's admission_sha256 for a SidecarAdmit, which for one inside a proposal is the same hash over the
// proposal's statement bytes (configAdmissionSha256). configSignedId says what this covers.
func StatementId(signedBytes []byte) ([sha256.Size]byte, error) {
	return configSignedId(signedBytes, bridge.SignedType_SIGNED_TYPE_NONE)
}

// A proposal's proposal_id (§7.9), which cosigns and vetoes name. Refuses any other statement. configSignedId says
// what this covers.
func ProposalId(signedBytes []byte) ([sha256.Size]byte, error) {
	return configSignedId(signedBytes, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL)
}

// A Delegation's delegation_id (§10.5's d), which rows, its revocation and DelegationWraps name. Refuses any other
// statement. configSignedId says what this covers.
func DelegationId(signedBytes []byte) ([sha256.Size]byte, error) {
	return configSignedId(signedBytes, bridge.SignedType_SIGNED_DELEGATION)
}

// Whether a Delegation is a forwarding one (§7.9's forwarding row; D-TEAM-33; owner decision 197): forward set,
// whatever it holds. A reader that does not know the field sees a Delegation with no tags, no max_admits and no
// not_after, which the agent rule refuses, so an older verifier never takes one as an agent's.
func ConfigDelegationForwards(delegation *protocol.Delegation) bool {
	return delegation.GetForward() != nil
}

// How a forwarding Delegation's row names its reader key (DelegationRow.reader_key_sha256; DESIGN-DETAILS 4.2.2): the
// SHA-256 of the statement's reader_xwing_public_key as received. The row carries no key, gkm's key object must hash
// to this, and a DelegationWrap's recipient_key_sha256 is the same digest (§10.5).
func DelegationReaderKeySha256(readerXwingPublicKey []byte) [sha256.Size]byte {
	return sha256.Sum256(readerXwingPublicKey)
}

// What a reader keeps of a statement's id for the last 4,096 entries: its first 16 B (§7.9's retain row).
func RetainedStatementId(id [sha256.Size]byte) [configRetainedIdSize]byte {
	return [configRetainedIdSize]byte(id[:configRetainedIdSize])
}
