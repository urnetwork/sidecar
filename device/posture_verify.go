// The posture's offline checks (§7.9's keyless rule, §8.9, §17.8's device roles), with protocol/bridge's types alone.
//
// Rows stream: one pass reads a ProjectionRows to its end, hashing every byte, with protobuf's wire format read field
// by field, so memory holds one MemberRow or SidecarRow at a time and never the rows whole (§18.4's 1 MiB budget
// against §8.8's 4 MiB rows). has_document is AclRows' field 1, read inside rows' field 5 with protowire, an absent
// field meaning false, since acl.proto is not linkable here; protobuf's last-one-wins holds for both.
//
// A base passes as bridge.VerifyBaseKeylessDigest says, signed by a config writer: an AdminSet member's member device,
// standing and not read_only, by the rows in effect before it, or, for the first base a posture takes, by its own rows.
// A statement this role applies passes on its header, its signer's identity key in the rows and its signer class; the
// countersignature §7.9's presence row asks for is its sidecar role's to check, so such a statement is Covered.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. Package-level functions are safe for
// concurrent use.

package device

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §8.8's bound on a base's rows.
const postureRowsMaxByteCount = 4 * 1024 * 1024

// The sizes of the ids and keys the log carries.
const (
	postureIdByteCount     = 16
	postureDigestByteCount = sha256.Size
)

// ProjectionRows' fields (auth.proto) and AclRows' has_document (acl.proto, §8.8).
const (
	postureRowsFieldMembers       protowire.Number = 1
	postureRowsFieldSidecars      protowire.Number = 2
	postureRowsFieldDelegations   protowire.Number = 3
	postureRowsFieldRegisteredKey protowire.Number = 4
	postureRowsFieldAcl           protowire.Number = 5
	postureAclFieldHasDocument    protowire.Number = 1
)

// A sidecar's facts from its row that a signer check reads.
type postureSidecarRow struct {
	sidecarId         [postureIdByteCount]byte
	identityPublicKey []byte
	// the untagged admission's member, nil for a tagged one
	memberId  []byte
	sponsorId []byte
	tagged    bool
	ephemeral bool
	readOnly  bool
	// revoked_at or parked_at set
	retired    bool
	notAfterMs int64
}

// The row's facts, or false for a row with no usable id or identity key, which can sign nothing.
func newPostureSidecarRow(row *bridge.SidecarRow) (*postureSidecarRow, bool) {
	if len(row.GetSidecarId()) != postureIdByteCount || len(row.GetIdentityPublicKey()) != ed25519.PublicKeySize {
		return nil, false
	}
	if alg := row.GetIdentityAlg(); alg != "" && alg != "ed25519" {
		return nil, false
	}
	facts := &postureSidecarRow{
		sidecarId:         [postureIdByteCount]byte(row.GetSidecarId()),
		identityPublicKey: bytes.Clone(row.GetIdentityPublicKey()),
		tagged:            len(row.GetTagIds()) != 0,
		ephemeral:         row.GetEphemeral(),
		readOnly:          row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0,
		retired:           row.GetRevokedAt() != 0 || row.GetParkedAt() != 0,
		notAfterMs:        row.GetNotAfter(),
	}
	if !facts.tagged && len(row.GetMemberId()) == postureIdByteCount {
		facts.memberId = bytes.Clone(row.GetMemberId())
	}
	if len(row.GetSponsor()) == postureIdByteCount {
		facts.sponsorId = bytes.Clone(row.GetSponsor())
	}
	return facts, true
}

// Whether the row may sign at timeMs: not revoked or parked, its not_after unpassed, and either tagged or an untagged
// member's device.
func (self *postureSidecarRow) standingAt(timeMs int64) bool {
	if self.retired || (self.notAfterMs != 0 && self.notAfterMs <= timeMs) {
		return false
	}
	return self.tagged || self.memberId != nil
}

// What one pass over a ProjectionRows found.
type postureRowsScan struct {
	sha256      [postureDigestByteCount]byte
	byteCount   int64
	hasDocument bool
	// the members whose role is one of the AdminSet's four, with that role (§7.5)
	adminMemberRoles map[[postureIdByteCount]byte]bridge.MemberRole
}

// Whether a role signs config records (§7.5's AdminSet).
func postureRoleInAdminSet(role bridge.MemberRole) bool {
	switch role {
	case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN,
		bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, bridge.MemberRole_MEMBER_ROLE_IT_ADMIN:
		return true
	}
	return false
}

// Counts and hashes what passes, refusing once more than the rows bound has.
type postureRowsCounter struct {
	hash      hash.Hash
	byteCount int64
}

// Hashes p and counts it.
func (self *postureRowsCounter) Write(p []byte) (int, error) {
	self.byteCount += int64(len(p))
	if postureRowsMaxByteCount < self.byteCount {
		return 0, fmt.Errorf("%w: rows over %d bytes", ErrPostureRefused, postureRowsMaxByteCount)
	}
	return self.hash.Write(p)
}

// Reads reader to its end as a ProjectionRows, hashing every byte, calling visit with each SidecarRow when visit is
// not nil. Refuses rows over 4 MiB, a group, a known field of the wrong wire type, a row over the settings' bound or
// a field that runs past the end.
func scanPostureRows(reader io.Reader, settings *PostureSettings, visit func(row *bridge.SidecarRow) error) (*postureRowsScan, error) {
	counter := &postureRowsCounter{hash: sha256.New()}
	buffered := bufio.NewReaderSize(io.TeeReader(reader, counter), settings.ReadByteCount)
	scan := &postureRowsScan{adminMemberRoles: map[[postureIdByteCount]byte]bridge.MemberRole{}}
	malformed := func(format string, a ...any) error {
		return fmt.Errorf("%w: rows %s", ErrPostureRefused, fmt.Sprintf(format, a...))
	}
	rowBuffer := []byte{}
	readRow := func(length uint64) ([]byte, error) {
		if uint64(settings.RowMaxByteCount) < length {
			return nil, malformed("hold a row of %d bytes", length)
		}
		if uint64(cap(rowBuffer)) < length {
			rowBuffer = make([]byte, length)
		}
		row := rowBuffer[:length]
		if _, err := io.ReadFull(buffered, row); err != nil {
			return nil, malformed("end inside a row")
		}
		return row, nil
	}
	for {
		tag, err := binary.ReadUvarint(buffered)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, postureStreamError(err, malformed("hold a tag that does not decode"))
		}
		number, wireType := protowire.Number(tag>>3), protowire.Type(tag&7)
		if number < protowire.MinValidNumber {
			return nil, malformed("hold field 0")
		}
		switch number {
		case postureRowsFieldMembers, postureRowsFieldSidecars, postureRowsFieldDelegations,
			postureRowsFieldRegisteredKey, postureRowsFieldAcl:
			if wireType != protowire.BytesType {
				return nil, malformed("hold field %d of wire type %d", number, wireType)
			}
		}
		if wireType != protowire.BytesType {
			if err := skipPostureField(buffered, wireType, -1); err != nil {
				return nil, postureStreamError(err, malformed("hold a field that does not decode"))
			}
			continue
		}
		length, err := binary.ReadUvarint(buffered)
		if err != nil {
			return nil, postureStreamError(err, malformed("hold a length that does not decode"))
		}
		switch number {
		case postureRowsFieldMembers:
			rowBytes, err := readRow(length)
			if err != nil {
				return nil, err
			}
			member := &bridge.MemberRow{}
			if err := proto.Unmarshal(rowBytes, member); err != nil {
				return nil, malformed("hold a member row that does not decode")
			}
			if len(member.GetMemberId()) == postureIdByteCount && postureRoleInAdminSet(member.GetRole()) {
				scan.adminMemberRoles[[postureIdByteCount]byte(member.GetMemberId())] = member.GetRole()
			}
		case postureRowsFieldSidecars:
			rowBytes, err := readRow(length)
			if err != nil {
				return nil, err
			}
			if visit != nil {
				sidecar := &bridge.SidecarRow{}
				if err := proto.Unmarshal(rowBytes, sidecar); err != nil {
					return nil, malformed("hold a sidecar row that does not decode")
				}
				if err := visit(sidecar); err != nil {
					return nil, err
				}
			}
		case postureRowsFieldAcl:
			hasDocument, err := readPostureHasDocument(buffered, length)
			if err != nil {
				return nil, postureStreamError(err, malformed("hold acl rows that do not decode"))
			}
			// a singular bytes field: the last one stands whole
			scan.hasDocument = hasDocument
		default:
			if int64(length) < 0 {
				return nil, malformed("hold a field too long")
			}
			if _, err := io.CopyN(io.Discard, buffered, int64(length)); err != nil {
				return nil, postureStreamError(err, malformed("end inside a field"))
			}
		}
	}
	scan.byteCount = counter.byteCount
	copy(scan.sha256[:], counter.hash.Sum(nil))
	return scan, nil
}

// The error of a read: the counter's refusal over 4 MiB, else malformed.
func postureStreamError(err error, malformed error) error {
	if errors.Is(err, ErrPostureRefused) || errors.Is(err, ErrPostureStoreFailed) {
		return err
	}
	return malformed
}

// AclRows' has_document from its next length bytes, read field by field: a varint field 1, the last one standing, and
// false when absent.
func readPostureHasDocument(reader *bufio.Reader, length uint64) (bool, error) {
	if int64(length) < 0 {
		return false, errors.New("acl rows too long")
	}
	limited := &postureLimitedReader{reader: reader, remaining: int64(length)}
	hasDocument := false
	for 0 < limited.remaining {
		tag, err := binary.ReadUvarint(limited)
		if err != nil {
			return false, err
		}
		number, wireType := protowire.Number(tag>>3), protowire.Type(tag&7)
		if number < protowire.MinValidNumber {
			return false, errors.New("field 0")
		}
		if number == postureAclFieldHasDocument {
			if wireType != protowire.VarintType {
				return false, errors.New("has_document of another wire type")
			}
			value, err := binary.ReadUvarint(limited)
			if err != nil {
				return false, err
			}
			hasDocument = value != 0
			continue
		}
		if err := skipPostureField(limited, wireType, limited.remaining); err != nil {
			return false, err
		}
	}
	return hasDocument, nil
}

// Reads at most remaining bytes, one at a time or in runs, from a buffered reader.
type postureLimitedReader struct {
	reader    *bufio.Reader
	remaining int64
}

// One byte, or io.ErrUnexpectedEOF past the limit.
func (self *postureLimitedReader) ReadByte() (byte, error) {
	if self.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	b, err := self.reader.ReadByte()
	if err != nil {
		return 0, io.ErrUnexpectedEOF
	}
	self.remaining -= 1
	return b, nil
}

// Up to the limit.
func (self *postureLimitedReader) Read(p []byte) (int, error) {
	if self.remaining <= 0 {
		return 0, io.EOF
	}
	if self.remaining < int64(len(p)) {
		p = p[:self.remaining]
	}
	n, err := self.reader.Read(p)
	self.remaining -= int64(n)
	return n, err
}

// Skips one field's value of wireType. limit is the bytes left to read, or negative for none.
func skipPostureField(reader interface {
	io.Reader
	io.ByteReader
}, wireType protowire.Type, limit int64) error {
	skip := func(byteCount int64) error {
		if byteCount < 0 || (0 <= limit && limit < byteCount) {
			return io.ErrUnexpectedEOF
		}
		_, err := io.CopyN(io.Discard, reader, byteCount)
		return err
	}
	switch wireType {
	case protowire.VarintType:
		_, err := binary.ReadUvarint(reader)
		return err
	case protowire.Fixed64Type:
		return skip(8)
	case protowire.Fixed32Type:
		return skip(4)
	case protowire.BytesType:
		length, err := binary.ReadUvarint(reader)
		if err != nil {
			return err
		}
		return skip(int64(length))
	default:
		// groups are no proto3 field
		return fmt.Errorf("wire type %d", wireType)
	}
}

// The config writers among rows the scan already read once: an AdminSet member's untagged member device, standing,
// neither ephemeral nor read_only (§7.9's Repo paragraph). Their keys are what stays in memory. Rows that hash to
// anything but wantSha256 are refused, so a record changed between two passes cannot slip a writer in.
func readPostureWriters(reader io.Reader, settings *PostureSettings, wantSha256 [postureDigestByteCount]byte,
	adminMemberRoles map[[postureIdByteCount]byte]bridge.MemberRole) (map[[postureIdByteCount]byte]*postureSidecarRow, error) {
	writers := map[[postureIdByteCount]byte]*postureSidecarRow{}
	scan, err := scanPostureRows(reader, settings, func(row *bridge.SidecarRow) error {
		facts, ok := newPostureSidecarRow(row)
		if !ok || facts.retired || facts.tagged || facts.memberId == nil || facts.ephemeral || facts.readOnly {
			return nil
		}
		if _, admin := adminMemberRoles[[postureIdByteCount]byte(facts.memberId)]; admin {
			writers[facts.sidecarId] = facts
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if scan.sha256 != wantSha256 {
		return nil, fmt.Errorf("%w: rows changed between two reads", ErrPostureRefused)
	}
	return writers, nil
}

// The rows of the sidecars ids names, from rows that must hash to wantSha256.
func readPostureSidecars(reader io.Reader, settings *PostureSettings, wantSha256 [postureDigestByteCount]byte,
	ids map[[postureIdByteCount]byte]bool) (map[[postureIdByteCount]byte]*postureSidecarRow, error) {
	found := map[[postureIdByteCount]byte]*postureSidecarRow{}
	scan, err := scanPostureRows(reader, settings, func(row *bridge.SidecarRow) error {
		if len(row.GetSidecarId()) != postureIdByteCount || !ids[[postureIdByteCount]byte(row.GetSidecarId())] {
			return nil
		}
		if facts, ok := newPostureSidecarRow(row); ok {
			// a repeated row: the last stands, as protobuf merges none of a repeated field
			found[facts.sidecarId] = facts
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if scan.sha256 != wantSha256 {
		return nil, fmt.Errorf("%w: rows changed between two reads", ErrPostureRefused)
	}
	return found, nil
}

// A log entry as received, with its digest.
type postureEntry struct {
	entry *bridge.AuthEntry
	bytes []byte
	chain [postureDigestByteCount]byte
}

// Parses one entry, at most maxByteCount bytes, for networkId, and computes its A_n. The chain to the entry before it
// is the caller's to check.
func parsePostureEntry(entryBytes []byte, networkId []byte, maxByteCount int) (*postureEntry, error) {
	if maxByteCount < len(entryBytes) {
		return nil, fmt.Errorf("%w: an entry of %d bytes", ErrPostureRefused, len(entryBytes))
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return nil, fmt.Errorf("%w: an entry that does not decode", ErrPostureRefused)
	}
	if !bytes.Equal(entry.GetNetworkId(), networkId) {
		return nil, fmt.Errorf("%w: another network's entry", ErrPostureRefused)
	}
	switch entry.GetKind() {
	case bridge.AuthEntryKindBase, bridge.AuthEntryKindStatement, bridge.AuthEntryKindTick:
	default:
		return nil, fmt.Errorf("%w: an entry of kind %d", ErrPostureRefused, entry.GetKind())
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPostureRefused, err)
	}
	return &postureEntry{entry: entry, bytes: entryBytes, chain: chain}, nil
}

// A base's Signed ProjectionHeader and the sidecar that signed it by its identity key, before any signature check.
func parsePostureBase(entry *bridge.AuthEntry) (*bridge.Signed, *bridge.ProjectionHeader, [postureIdByteCount]byte, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return nil, nil, [postureIdByteCount]byte{}, fmt.Errorf("%w: a base that does not decode", ErrPostureRefused)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_PROJECTION_HEADER {
		return nil, nil, [postureIdByteCount]byte{}, fmt.Errorf("%w: a base of type %d", ErrPostureRefused, signed.GetType())
	}
	// an identity key's form: a sidecar_id and no key_id (protos-bridge-recovery-key-carrier)
	if len(signed.GetSignerId()) != postureIdByteCount || len(signed.GetKeyId()) != 0 {
		return nil, nil, [postureIdByteCount]byte{}, fmt.Errorf("%w: a base signed by other than an identity key", ErrPostureRefused)
	}
	header := &bridge.ProjectionHeader{}
	if err := proto.Unmarshal(signed.GetBody(), header); err != nil {
		return nil, nil, [postureIdByteCount]byte{}, fmt.Errorf("%w: a base header that does not decode", ErrPostureRefused)
	}
	if len(header.GetRowsSha256()) != postureDigestByteCount {
		return nil, nil, [postureIdByteCount]byte{}, fmt.Errorf("%w: a base naming no rows", ErrPostureRefused)
	}
	return signed, header, [postureIdByteCount]byte(signed.GetSignerId()), nil
}

// The statements this role applies between states, each with its purpose (§6.11).
var postureStatementPurposes = map[bridge.SignedType]string{
	bridge.SignedType_SIGNED_SIDECAR_REVOKE:  bridge.SignedPurposeAuthority,
	bridge.SignedType_SIGNED_MEMBER_REVOKE:   bridge.SignedPurposeAuthority,
	bridge.SignedType_SIGNED_SUSPEND:         bridge.SignedPurposeAcl,
	bridge.SignedType_SIGNED_UNSUSPEND:       bridge.SignedPurposeAcl,
	bridge.SignedType_SIGNED_GRANT_REVOKE:    bridge.SignedPurposeAcl,
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW: bridge.SignedPurposeBridge,
}

// One statement this role applies, parsed before its signature is checked.
type postureStatement struct {
	signed     *bridge.Signed
	signedType bridge.SignedType
	signerId   [postureIdByteCount]byte
	header     *bridge.StatementHeader
	// exactly one of these, by signedType
	sidecarRevoke  *bridge.SidecarRevoke
	memberRevoke   *bridge.MemberRevoke
	suspend        *bridge.Suspend
	unsuspend      *bridge.Unsuspend
	grantRevoke    *bridge.GrantRevoke
	bridgeWithdraw *bridge.BridgeWithdraw
}

// The statement a STATEMENT entry carries, nil when it is of a type this role does not apply, which it follows by its
// chain alone. An error for one of the six that is malformed. Its body is read as its type registers, never a
// re-marshal; the signature over it is checked later, against its signer's key.
func parsePostureStatement(entry *bridge.AuthEntry) (*postureStatement, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		// a statement this role does not read may be any shape the type allows, so only its chain counts
		return nil, nil
	}
	signedType := bridge.SignedType(signed.GetType())
	if _, applies := postureStatementPurposes[signedType]; !applies {
		return nil, nil
	}
	malformed := func(what string) error {
		return fmt.Errorf("%w: %s", ErrPostureRefused, what)
	}
	if len(signed.GetSignerId()) != postureIdByteCount || len(signed.GetKeyId()) != 0 {
		return nil, malformed("a statement signed by other than an identity key")
	}
	statement := &postureStatement{
		signed:     signed,
		signedType: signedType,
		signerId:   [postureIdByteCount]byte(signed.GetSignerId()),
	}
	var message interface {
		proto.Message
		GetHeader() *bridge.StatementHeader
	}
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_REVOKE:
		statement.sidecarRevoke = &bridge.SidecarRevoke{}
		message = statement.sidecarRevoke
	case bridge.SignedType_SIGNED_MEMBER_REVOKE:
		statement.memberRevoke = &bridge.MemberRevoke{}
		message = statement.memberRevoke
	case bridge.SignedType_SIGNED_SUSPEND:
		statement.suspend = &bridge.Suspend{}
		message = statement.suspend
	case bridge.SignedType_SIGNED_UNSUSPEND:
		statement.unsuspend = &bridge.Unsuspend{}
		message = statement.unsuspend
	case bridge.SignedType_SIGNED_GRANT_REVOKE:
		statement.grantRevoke = &bridge.GrantRevoke{}
		message = statement.grantRevoke
	case bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
		statement.bridgeWithdraw = &bridge.BridgeWithdraw{}
		message = statement.bridgeWithdraw
	}
	if err := proto.Unmarshal(signed.GetBody(), message); err != nil {
		return nil, malformed("a statement body that does not decode")
	}
	statement.header = message.GetHeader()
	if statement.header == nil {
		return nil, malformed("a statement with no header")
	}
	return statement, nil
}

// The ids a statement's signer check needs rows for: its signer, and the sidecar it is about where its class turns
// on that sidecar's member or sponsor.
func (self *postureStatement) rowIds() [][postureIdByteCount]byte {
	ids := [][postureIdByteCount]byte{self.signerId}
	subject := []byte(nil)
	switch {
	case self.sidecarRevoke != nil:
		subject = self.sidecarRevoke.GetSidecarId()
	case self.suspend != nil:
		subject = self.suspend.GetSubject()
	case self.unsuspend != nil:
		subject = self.unsuspend.GetSubject()
	}
	if len(subject) == postureIdByteCount {
		ids = append(ids, [postureIdByteCount]byte(subject))
	}
	return ids
}

// Whether this is a Signed SidecarRevoke of sidecarId, signed by sidecarId, for networkId, verifying under
// identityPublicKey: the sidecar's own sign-out, the one input that wipes a posture (plan-SDK-pending-sidecar-id).
// Another sidecar's sign-out, or an admin's revocation of this one, is not.
func (self *postureStatement) ownSignOut(networkId []byte, sidecarId []byte, identityPublicKey []byte) bool {
	if self.sidecarRevoke == nil || len(sidecarId) != postureIdByteCount || len(identityPublicKey) != ed25519.PublicKeySize {
		return false
	}
	if !bytes.Equal(self.sidecarRevoke.GetSidecarId(), sidecarId) || !bytes.Equal(self.signerId[:], sidecarId) ||
		!bytes.Equal(self.header.GetNetworkId(), networkId) {
		return false
	}
	return bridge.VerifySigned(self.signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		bridge.SignedKeyAlgEd25519, identityPublicKey) == nil
}

// A signer's class for Suspend and Unsuspend (§8.8): owner or sponsor below admin.
const (
	posturePeerClassNone  = 0
	posturePeerClassOwner = 1
	posturePeerClassAdmin = 2
)

// What a statement's signer check reads: the rows it named, the AdminSet's members, and what the overlay revoked.
type posturePeers struct {
	rows             map[[postureIdByteCount]byte]*postureSidecarRow
	adminMemberRoles map[[postureIdByteCount]byte]bridge.MemberRole
	overlay          []PostureOverlayEntry
}

// The row of a signer that may sign at timeMs: in the rows, standing, and not revoked since by the overlay, itself or
// its member.
func (self *posturePeers) standingSigner(signerId [postureIdByteCount]byte, timeMs int64) (*postureSidecarRow, bool) {
	row := self.rows[signerId]
	if row == nil || !row.standingAt(timeMs) || postureOverlayRevokes(self.overlay, row) {
		return nil, false
	}
	return row, true
}

// Whether the overlay revokes the row's sidecar or its member.
func postureOverlayRevokes(overlay []PostureOverlayEntry, row *postureSidecarRow) bool {
	for _, entry := range overlay {
		switch entry.Kind {
		case PostureOverlaySidecarRevoke:
			if bytes.Equal(entry.Id, row.sidecarId[:]) {
				return true
			}
		case PostureOverlayMemberRevoke:
			if row.memberId != nil && bytes.Equal(entry.Id, row.memberId) {
				return true
			}
		}
	}
	return false
}

// Whether the row is a member device of a member whose role is one of roles.
func (self *posturePeers) memberDeviceOf(row *postureSidecarRow, roles ...bridge.MemberRole) bool {
	if row.memberId == nil || row.ephemeral {
		return false
	}
	role, admin := self.adminMemberRoles[[postureIdByteCount]byte(row.memberId)]
	if !admin {
		return false
	}
	for _, allowed := range roles {
		if role == allowed {
			return true
		}
	}
	return false
}

// An admin device in §7.10's and §8.8's sense: a member device of an AdminSet member.
func (self *posturePeers) adminDevice(row *postureSidecarRow) bool {
	return self.memberDeviceOf(row, bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN,
		bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, bridge.MemberRole_MEMBER_ROLE_IT_ADMIN)
}

// The signer's class over subject: admin, its owner or sponsor, or none.
func (self *posturePeers) classOver(signer *postureSidecarRow, subject []byte) int {
	if self.adminDevice(signer) {
		return posturePeerClassAdmin
	}
	if len(subject) != postureIdByteCount || signer.memberId == nil {
		return posturePeerClassNone
	}
	subjectRow := self.rows[[postureIdByteCount]byte(subject)]
	if subjectRow == nil {
		return posturePeerClassNone
	}
	if subjectRow.memberId != nil && bytes.Equal(subjectRow.memberId, signer.memberId) {
		return posturePeerClassOwner
	}
	if subjectRow.tagged && subjectRow.sponsorId != nil && bytes.Equal(subjectRow.sponsorId, signer.memberId) {
		return posturePeerClassOwner
	}
	return posturePeerClassNone
}

// What one verified statement does: an overlay entry to add, or an overlay Suspend to lift.
type postureEffect struct {
	add         *PostureOverlayEntry
	liftSubject []byte
	liftId      []byte
	liftClass   int
}

// Checks a statement carried at position n and time timeMs for networkId: its header, its signer's identity key and
// its signer's class, and returns what it does. An error says it does not verify, and it is not applied.
func verifyPostureStatement(statement *postureStatement, n uint64, timeMs int64, networkId []byte, peers *posturePeers) (*postureEffect, error) {
	refused := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrPostureRefused, fmt.Sprintf(format, a...))
	}
	header := statement.header
	if !bytes.Equal(header.GetNetworkId(), networkId) {
		return nil, refused("another network's statement")
	}
	if header.GetNotAfterMs() == 0 || header.GetNotAfterMs() < timeMs {
		return nil, refused("a statement past its not_after")
	}
	signer, standing := peers.standingSigner(statement.signerId, timeMs)
	if !standing {
		return nil, refused("a statement by no standing sidecar")
	}
	purpose := postureStatementPurposes[statement.signedType]
	if err := bridge.VerifySigned(statement.signed, purpose, statement.signedType, bridge.SignedKeyAlgEd25519, signer.identityPublicKey); err != nil {
		return nil, refused("a statement whose signature does not verify: %v", err)
	}
	isSigner := func(id []byte) bool {
		return bytes.Equal(id, statement.signerId[:])
	}
	// every verifier refuses what a read_only device signs but its own sign-out (§18.8, D-TEAM-24)
	if signer.readOnly && !(statement.sidecarRevoke != nil && isSigner(statement.sidecarRevoke.GetSidecarId())) {
		return nil, refused("a statement by a read_only device")
	}

	switch {
	case statement.sidecarRevoke != nil:
		subject := statement.sidecarRevoke.GetSidecarId()
		if len(subject) != postureIdByteCount {
			return nil, refused("a SidecarRevoke naming no sidecar")
		}
		// the sidecar itself, an admin device, or the member's for its own devices (§7.10's signer row)
		allowed := isSigner(subject) || peers.adminDevice(signer)
		if subjectRow := peers.rows[[postureIdByteCount]byte(subject)]; !allowed && subjectRow != nil {
			allowed = subjectRow.memberId != nil && signer.memberId != nil && !signer.ephemeral &&
				bytes.Equal(subjectRow.memberId, signer.memberId)
		}
		if !allowed {
			return nil, refused("a SidecarRevoke by no signer of its class")
		}
		covered := !isSigner(subject) ||
			statement.sidecarRevoke.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE
		return &postureEffect{add: &PostureOverlayEntry{
			Kind: PostureOverlaySidecarRevoke, N: n, Id: bytes.Clone(subject), Covered: covered,
		}}, nil

	case statement.memberRevoke != nil:
		memberId := statement.memberRevoke.GetMemberId()
		if len(memberId) != postureIdByteCount {
			return nil, refused("a MemberRevoke naming no member")
		}
		// an Owner or Admin (§7.9's MemberAdmit row); an AdminSet member's needs k of n, a proposal this role does
		// not read, so it waits for the next state
		if !peers.memberDeviceOf(signer, bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN) {
			return nil, refused("a MemberRevoke by no Owner's or Admin's device")
		}
		return &postureEffect{add: &PostureOverlayEntry{
			Kind: PostureOverlayMemberRevoke, N: n, Id: bytes.Clone(memberId), Covered: true,
		}}, nil

	case statement.suspend != nil:
		subject, suspendId := statement.suspend.GetSubject(), statement.suspend.GetSuspendId()
		if len(subject) == 0 || len(suspendId) == 0 {
			return nil, refused("a Suspend naming no subject or suspend_id")
		}
		class := peers.classOver(signer, subject)
		if class == posturePeerClassNone {
			return nil, refused("a Suspend by no admin, owner or sponsor")
		}
		return &postureEffect{add: &PostureOverlayEntry{
			Kind: PostureOverlaySuspend, N: n, Id: bytes.Clone(subject), SuspendId: bytes.Clone(suspendId),
			Covered: !isSigner(subject), suspendClass: class,
		}}, nil

	case statement.unsuspend != nil:
		subject, suspendId := statement.unsuspend.GetSubject(), statement.unsuspend.GetSuspendId()
		if len(subject) == 0 || len(suspendId) == 0 {
			return nil, refused("an Unsuspend naming no subject or suspend_id")
		}
		// never the subject itself (§8.8)
		if isSigner(subject) {
			return nil, refused("an Unsuspend by its own subject")
		}
		class := peers.classOver(signer, subject)
		if class == posturePeerClassNone {
			return nil, refused("an Unsuspend by no admin, owner or sponsor")
		}
		return &postureEffect{liftSubject: bytes.Clone(subject), liftId: bytes.Clone(suspendId), liftClass: class}, nil

	case statement.grantRevoke != nil:
		grantId := statement.grantRevoke.GetGrantId()
		if len(grantId) == 0 {
			return nil, refused("a GrantRevoke naming no grant")
		}
		// an approver, the subject or an admin: this role knows no grant's approvers, so any standing signer's
		// revocation narrows until the next state, which judges it
		return &postureEffect{add: &PostureOverlayEntry{Kind: PostureOverlayGrantRevoke, N: n, Id: bytes.Clone(grantId)}}, nil

	case statement.bridgeWithdraw != nil:
		ruleId := statement.bridgeWithdraw.GetRuleId()
		if len(ruleId) == 0 {
			return nil, refused("a BridgeWithdraw naming no rule")
		}
		// the rule's signer or an admin: as for a grant, the next state judges the signer
		return &postureEffect{add: &PostureOverlayEntry{
			Kind: PostureOverlayBridgeWithdraw, N: n, Id: bytes.Clone(ruleId), WithdrawMode: statement.bridgeWithdraw.GetMode(),
		}}, nil
	}
	return nil, refused("a statement of no type this role applies")
}
