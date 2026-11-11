// compile (§7.9's BASE row): the ProjectionRows bytes a config head gives, whose SHA-256 a base names as rows_sha256.
// Every compiler on every leg gives the same bytes for the same head and rows, so every reader checks every base
// alike: the rows' lists are in id order, every message is encoded deterministically, and the whole is at most 4 MiB
// (§8.8).
//
// §7's rows, members, sidecars, Delegations and registered keys, with the proposals open there and the replay ring, are
// what the log gives at the head's folded_through, L(ft), so the caller passes them: a writer from its state at its fold
// or the previous base's rows, a reader from its own log alike (ConfigCompileRows; DESIGN-DETAILS 5.2.2), each less the
// superseded or ended forwarding Delegations' rows that leave at this base, which needs the base's retention point and
// so is the fold rows' to drop (config_base.go's foldRows, QD-648). The settings
// are the head's: its ServiceSettings' self_admit and scim_signer, always present, the zero value for none. The acl
// part is §8's, from the head's policy, tags, groups and files beside the log's acl statements, and ACL's CompileAcl
// gives it (ACL-M2-04). C-05 has this task declare the seam and ACL register the compile: until one is registered,
// CompileProjectionRows refuses, so no base compiles without its acl part. Lists run in id order, the ring in position
// order.
//
// On every leg, with no connect import. Nothing here creates, derives or unwraps a key, so nothing calls
// testHookSecret. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No acl compile is registered (C-05), so no rows compile.
	ErrConfigCompileUnavailable = errors.New("config compile: no acl compile is registered")
	// The rows would pass §8.8's 4 MiB.
	ErrConfigRowsTooLarge = errors.New("config compile: rows over 4 MiB")
	// The rows given are no rows: an id repeated or malformed.
	ErrConfigRowsMalformed = errors.New("config compile: rows malformed")
)

// The rows the log's records give at a head's folded_through, which compile encodes beside the head's acl part.
type ConfigCompileRows struct {
	Members        []*bridge.MemberRow
	Sidecars       []*bridge.SidecarRow
	Delegations    []*bridge.DelegationRow
	RegisteredKeys []*bridge.KeyRow
	// What the log's 0x11xx statements give at folded_through: grants, shares, suspensions and AclRepo rows, which
	// the acl compile carries into AclRows beside what the head's policy gives (§8.8).
	AclStatements *protocol.AclRows
	// Every proposal open at folded_through, its time the entry's there (DESIGN-DETAILS 5.2.3).
	Proposals []*bridge.ProposalRow
	// The statements that took effect among the 4,096 entries through folded_through, in position order
	// (DESIGN-DETAILS 5.2.3's ring).
	Ring []*bridge.RingRow
	// Every IndexerSet designation that holds at folded_through (question team-m2-07-indexer-rows).
	Indexers []*bridge.IndexerRow
}

// The rows a state holds, as compile reads them: what a writer passes for its state at its fold.
func ConfigCompileRowsOf(state *ConfigState) *ConfigCompileRows {
	rows := state.Rows()
	aclStatements := &protocol.AclRows{}
	if state.aclRows != nil {
		aclStatements = proto.Clone(state.aclRows).(*protocol.AclRows)
	}
	return &ConfigCompileRows{
		Members:        rows.GetMembers(),
		Sidecars:       rows.GetSidecars(),
		Delegations:    rows.GetDelegations(),
		RegisteredKeys: rows.GetRegisteredKeys(),
		AclStatements:  aclStatements,
		Proposals:      rows.GetProposals(),
		Ring:           rows.GetRing(),
		Indexers:       rows.GetIndexers(),
	}
}

// The log-derived part of a base's rows, as compile reads it: L(ft) when a new base keeps the previous base's fold,
// whose rows already hold the log at that point (DESIGN-DETAILS 5.2.2's recurrence).
func configCompileRowsFromRows(rows *bridge.ProjectionRows) (*ConfigCompileRows, error) {
	aclStatements := &protocol.AclRows{}
	if err := proto.Unmarshal(rows.GetAcl(), aclStatements); err != nil {
		return nil, fmt.Errorf("%w: acl: %w", ErrConfigRowsMalformed, err)
	}
	return &ConfigCompileRows{
		Members:        rows.GetMembers(),
		Sidecars:       rows.GetSidecars(),
		Delegations:    rows.GetDelegations(),
		RegisteredKeys: rows.GetRegisteredKeys(),
		AclStatements:  aclStatements,
		Proposals:      rows.GetProposals(),
		Ring:           rows.GetRing(),
		Indexers:       rows.GetIndexers(),
	}, nil
}

// L(0) for base 1, which the log before it holds nothing of: the Genesis's owner an Owner, and its first device that
// owner's member device, admitted by itself, with the identity key the Genesis names (§7.9's bootstrap).
func configGenesisCompileRows(genesis *bridge.Genesis) *ConfigCompileRows {
	return &ConfigCompileRows{
		Members: []*bridge.MemberRow{{
			MemberId: bytes.Clone(genesis.GetOwnerMemberId()),
			Role:     bridge.MemberRole_MEMBER_ROLE_OWNER,
		}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         bytes.Clone(genesis.GetOwnerSidecarId()),
			AdmissionSigners:  [][]byte{bytes.Clone(genesis.GetOwnerSidecarId())},
			IdentityPublicKey: bytes.Clone(genesis.GetOwnerIdentityPublicKey()),
			IdentityAlg:       configIdentityAlgEd25519,
			MemberId:          bytes.Clone(genesis.GetOwnerMemberId()),
		}},
		AclStatements: &protocol.AclRows{},
	}
}

// ACL's compile (C-05, ACL-M2-04's CompileAcl): the AclRows a head's policy, tags, groups and files give, with the
// log's rows at its folded_through, whose AclStatements the acl statements gave and whose members and sidecars the
// policy's atoms expand over. It must be a pure function of its input, with no clock, no network and no map order,
// since every reader hashes what it gives. rows is the compile's own copy.
type ConfigAclCompiler func(head *ConfigHead, rows *ConfigCompileRows) (*protocol.AclRows, error)

var configAclCompiler atomic.Pointer[ConfigAclCompiler]

// Registers the acl compile, replacing any, and returns a function that restores the one before. nil unregisters,
// and then CompileProjectionRows refuses.
func RegisterConfigAclCompiler(compiler ConfigAclCompiler) func() {
	var previous *ConfigAclCompiler
	if compiler == nil {
		previous = configAclCompiler.Swap(nil)
	} else {
		previous = configAclCompiler.Swap(&compiler)
	}
	return func() {
		configAclCompiler.Store(previous)
	}
}

// compile(head) with rows: the ProjectionRows bytes, at most 4 MiB, the same on every leg for the same input.
func CompileProjectionRows(head *ConfigHead, rows *ConfigCompileRows) ([]byte, error) {
	compiler := configAclCompiler.Load()
	if compiler == nil {
		return nil, ErrConfigCompileUnavailable
	}
	if head == nil || rows == nil {
		return nil, fmt.Errorf("%w: no head or rows", ErrConfigRowsMalformed)
	}
	aclStatements := rows.AclStatements
	if aclStatements == nil {
		aclStatements = &protocol.AclRows{}
	}
	compileRows := *rows
	compileRows.AclStatements = proto.Clone(aclStatements).(*protocol.AclRows)
	aclRows, err := (*compiler)(head, &compileRows)
	if err != nil {
		return nil, fmt.Errorf("config compile: acl: %w", err)
	}
	encode := proto.MarshalOptions{Deterministic: true}
	aclBytes, err := encode.Marshal(aclRows)
	if err != nil {
		return nil, fmt.Errorf("config compile: acl: %w", err)
	}
	settings, _, err := head.ServiceSettings()
	if err != nil {
		return nil, fmt.Errorf("config compile: service_settings: %w", err)
	}

	projection := &bridge.ProjectionRows{Acl: aclBytes, Settings: ConfigProjectionSettings(settings)}
	var sortErr error
	projection.Members = configSortRows(rows.Members, (*bridge.MemberRow).GetMemberId, "members", &sortErr)
	projection.Sidecars = configSortRows(rows.Sidecars, (*bridge.SidecarRow).GetSidecarId, "sidecars", &sortErr)
	projection.Delegations = configSortRows(rows.Delegations, (*bridge.DelegationRow).GetDelegationId, "delegations", &sortErr)
	projection.RegisteredKeys = configSortRows(rows.RegisteredKeys, (*bridge.KeyRow).GetKeyId, "registered_keys", &sortErr)
	projection.Proposals = configSortRows(rows.Proposals, (*bridge.ProposalRow).GetProposalId, "proposals", &sortErr)
	projection.Indexers = configSortRows(rows.Indexers, configIndexerRowKey, "indexers", &sortErr)
	projection.Ring = configSortRows(rows.Ring, configRingRowKey, "ring", &sortErr)
	if sortErr != nil {
		return nil, sortErr
	}
	for i, row := range projection.Ring {
		if len(row.GetStatementId()) != configRetainedIdSize {
			return nil, fmt.Errorf("%w: ring[%d].statement_id of %d bytes", ErrConfigRowsMalformed, i, len(row.GetStatementId()))
		}
	}
	encoded, err := encode.Marshal(projection)
	if err != nil {
		return nil, err
	}
	if configRowsMaxByteCount < len(encoded) {
		return nil, fmt.Errorf("%w: %d bytes", ErrConfigRowsTooLarge, len(encoded))
	}
	return encoded, nil
}

// A ring row's sort key, its position: the ring runs in position order, at most one statement a position.
func configRingRowKey(row *bridge.RingRow) []byte {
	return binary.BigEndian.AppendUint64(nil, row.GetN())
}

// A designation's sort key, its subject then its scope: a sidecar_id that is no 16-byte id gives none.
func configIndexerRowKey(row *bridge.IndexerRow) []byte {
	if len(row.GetSidecarId()) != len(Id{}) {
		return nil
	}
	return binary.BigEndian.AppendUint32(bytes.Clone(row.GetSidecarId()), row.GetScope())
}

// The rows, cloned, in the byte order of their ids, refusing an empty or repeated id.
func configSortRows[R proto.Message](rows []R, id func(R) []byte, name string, sortErr *error) []R {
	sorted := make([]R, 0, len(rows))
	for _, row := range rows {
		sorted = append(sorted, proto.Clone(row).(R))
	}
	slices.SortFunc(sorted, func(a R, b R) int {
		return bytes.Compare(id(a), id(b))
	})
	for i, row := range sorted {
		if len(id(row)) == 0 || (0 < i && bytes.Equal(id(sorted[i-1]), id(row))) {
			if *sortErr == nil {
				*sortErr = fmt.Errorf("%w: %s has an empty or repeated id", ErrConfigRowsMalformed, name)
			}
		}
	}
	return sorted
}
