// FI-12, recovery (§22.8; §19.10's postgres and site steps; D-OPS-14, D-OPS-18, D-TEST-10; TEST-M3-01): after a
// Postgres or site loss, the newest copy a device or dump holds comes back exactly (oids, C_v, decryptability,
// identities, labels), save what §19.10's postgres step lists in the incident (a suffixed network name, a login left
// for a reset) or keeps at the main dump's age (rows the sidecar dump does not name), and nothing erased or dropped
// (but as FI-5 allows), shredded or revoked returns; an object whose every shard exists survives a second host.
//
// A row takes a RecoverySnapshot of what it expects to survive before its fault, in this oracle's own terms, never a
// mechanism's: identities by kind and id with the values that come back with them, each ref's (v, C_v), and each
// object's content as a reader opens it, its plaintext's SHA-256, so a vault its owner's devices re-formed under new
// keys compares by what it decrypts to, never by its bytes. What must not come back goes in the same snapshot, as
// gone, keyed the same way. After the recovery the row takes the same snapshot again, as the stores then hold it,
// and hands both to the oracle with the incident's list (RecordRecoverySnapshot, RecordRecovered); server's
// sidecart3 reads the T3 half from server's Postgres and an incident's list (recovery_snapshot.go).
//
// The incident's list is the only source of exceptions: its lines in the restore frame's own kinds (server's
// sidecarrestore, xops's reconcile), and the main dump's copy of each row the sidecar dump does not name, which the
// row hands over since it took that dump. A loss the record forgot fails, which is the point. The check assumes
// neither dump is the newer: FS-42 runs them in each order, and each order's exceptions arrive as lines.
//
//	identity   each id the snapshot holds comes back, active as it was, with the values it held, unless a line
//	           excuses it: network-renamed gives a network the line's suffixed name, login-left-out a member an empty
//	           login, client-deactivated a client inactive, and orphan-log a lost network, whose members and clients
//	           go with it; a main-dump row is held to the main dump's copy. A name that comes back under another id
//	           is a changed oid, named as one
//	head       each ref comes back at its (v, C_v), unless its repo is listed orphan-repo or close-repo-not-reseeded,
//	           where it may be absent, or close-repo-under-reseed, where it may come back lower under an EvsReseed
//	content    each named object still opens to its plaintext, unless its repo is listed as above; a second host's
//	           loss is a row's snapshot of the objects whose every shard existed, each of which must still open
//	gone       an identity kept gone does not come back active, a gone ref has no head, and gone content opens to
//	           nothing, whatever the incident lists
//
// A check before the row records its recovery reads nothing, since nothing has come back yet. At the end a snapshot
// with no recovery recorded fails, and so does a Net on which nothing was recorded at all: a schedule that names FI-12
// and never shows what came back proves nothing, so the check fails closed rather than pass.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

var _ = RegisterInvariant(12, func(ctx context.Context, oracle *Oracle) error {
	return checkFi12(oracle)
})

// The kinds of identity FI-12 holds a recovery to, as api's rows name them.
const (
	RecoveryKindNetwork = "network"
	RecoveryKindMember  = "member"
	RecoveryKindClient  = "client"
	RecoveryKindLabel   = "label"
)

// The values an identity carries that come back with it.
const (
	// a network's name, a label's name
	RecoveryFieldName = "name"
	// a member's login
	RecoveryFieldLogin = "login"
	// the network a member, client or label belongs to, by id
	RecoveryFieldNetwork = "network"
)

// The incident list's kinds FI-12 reads as exceptions, as the restore frame writes them (server's sidecarrestore and
// xops's sidecar-restore-reconcile.sql), which server's sidecart3 holds equal to the frame's own.
const (
	// table network, row the network, detail the suffixed name it took
	RecoveryLineNetworkRenamed = "network-renamed"
	// table a login table, row the member's user id
	RecoveryLineLoginLeftOut = "login-left-out"
	// table network_client, row the client: created after the sidecar dump, deactivated to re-enroll
	RecoveryLineClientDeactivated = "client-deactivated"
	// table proj, row a network the restored rows lack: lost with its rows
	RecoveryLineOrphanLog = "orphan-log"
	// table repo, row one of a lost network's repos, shredded under the incident
	RecoveryLineOrphanRepo = "orphan-repo"
	// table repo, row a projected repo nothing re-seeded
	RecoveryLineCloseNotReseeded = "close-repo-not-reseeded"
	// table repo, row a repo back only under an EvsReseed, below a surviving reader's pin
	RecoveryLineCloseUnderReseed = "close-repo-under-reseed"
)

// One identity a recovery must bring back, or keep gone.
type RecoveryIdentity struct {
	Kind string
	Id   string
	// The values that come back with the id, by RecoveryField.
	Fields map[string]string
	// A client not deactivated, a member not removed, a network not deleted.
	Active bool
}

// The identity's key in a snapshot: kind/id.
func (self *RecoveryIdentity) Key() string {
	return RecoveryIdentityKey(self.Kind, self.Id)
}

// An identity's key in a snapshot.
func RecoveryIdentityKey(kind string, id string) string {
	return kind + "/" + strings.ToLower(id)
}

// One ref's head as a reader pins it.
type RecoveryHead struct {
	RepoId  sidecar.Id
	RefId   sidecar.Id
	Version uint64
	// C_v.
	Chain []byte
}

// A ref's key in a snapshot.
func RecoveryHeadKey(repoId sidecar.Id, refId sidecar.Id) string {
	return "head/" + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId)
}

// What a reader opens of one object: its repo, and its plaintext's SHA-256.
type RecoveryContent struct {
	RepoId sidecar.Id
	Sha256 []byte
}

// A content's key in a snapshot: the name the row gives it.
func RecoveryContentKey(name string) string {
	return "content/" + name
}

// What a row expects a recovery to bring back and keep gone, taken before the fault, and the same read after it.
// Not safe for concurrent use; a row takes one, then hands it over.
type RecoverySnapshot struct {
	// By RecoveryIdentityKey.
	Identities map[string]*RecoveryIdentity
	// By RecoveryHeadKey.
	Heads map[string]*RecoveryHead
	// By RecoveryContentKey.
	Contents map[string]*RecoveryContent
	// What must not come back, by any of the three keys, with why: erased, dropped, shredded, revoked or deleted.
	Gone map[string]string
}

func NewRecoverySnapshot() *RecoverySnapshot {
	return &RecoverySnapshot{
		Identities: map[string]*RecoveryIdentity{},
		Heads:      map[string]*RecoveryHead{},
		Contents:   map[string]*RecoveryContent{},
		Gone:       map[string]string{},
	}
}

// Adds an identity, its fields copied.
func (self *RecoverySnapshot) AddIdentity(identity *RecoveryIdentity) {
	copied := *identity
	copied.Id = strings.ToLower(identity.Id)
	copied.Fields = map[string]string{}
	for name, value := range identity.Fields {
		copied.Fields[name] = value
	}
	self.Identities[copied.Key()] = &copied
}

// Adds a ref's head.
func (self *RecoverySnapshot) AddHead(head *RecoveryHead) {
	copied := *head
	copied.Chain = bytes.Clone(head.Chain)
	self.Heads[RecoveryHeadKey(head.RepoId, head.RefId)] = &copied
}

// Adds what a reader opened of the object name, in repoId: its plaintext, whose digest the snapshot keeps.
func (self *RecoverySnapshot) AddContent(name string, repoId sidecar.Id, plaintext []byte) {
	digest := sha256.Sum256(plaintext)
	self.Contents[RecoveryContentKey(name)] = &RecoveryContent{RepoId: repoId, Sha256: digest[:]}
}

// Marks key as what must not come back, and why.
func (self *RecoverySnapshot) AddGone(key string, why string) {
	self.Gone[key] = why
}

// Each ref's head as view reads it now; a ref with no head is left out, which a check reads as lost.
func (self *RecoverySnapshot) AddHeadsFrom(ctx context.Context, view *StoreView, repoId sidecar.Id, refIds ...sidecar.Id) error {
	for _, refId := range refIds {
		head, err := view.Head(ctx, repoId, refId)
		if err != nil {
			// a repo no longer placed has no head
			if errors.Is(err, sidecar.ErrEvsRepoNotPlaced) || errors.Is(err, sidecar.ErrBlobNotFound) {
				continue
			}
			return err
		}
		if head == nil {
			continue
		}
		self.AddHead(&RecoveryHead{RepoId: repoId, RefId: refId, Version: head.Head.GetVersion(), Chain: head.Head.GetChain()})
	}
	return nil
}

// One line of a recovery's incident list, in the frame's four columns.
type RecoveryIncidentLine struct {
	Kind   string
	Table  string
	RowId  string
	Detail string
}

// A recovery's incident: its id, its list, and the main dump's copy of each row the sidecar dump does not name, by
// RecoveryIdentityKey, which comes back at the main dump's age.
type RecoveryIncident struct {
	Id       sidecar.Id
	Lines    []*RecoveryIncidentLine
	MainDump map[string]*RecoveryIdentity
}

// The lines of kind naming row id, in list order.
func (self *RecoveryIncident) lines(kind string, rowId string) []*RecoveryIncidentLine {
	found := []*RecoveryIncidentLine{}
	if self == nil {
		return found
	}
	for _, line := range self.Lines {
		if line.Kind == kind && strings.EqualFold(line.RowId, rowId) {
			found = append(found, line)
		}
	}
	return found
}

// Whether the incident lists a line of any of kinds naming row id.
func (self *RecoveryIncident) lists(rowId string, kinds ...string) bool {
	for _, kind := range kinds {
		if 0 < len(self.lines(kind, rowId)) {
			return true
		}
	}
	return false
}

// nil when after holds what before says a recovery brings back and keeps gone, save what incident lists; otherwise
// every difference, each naming what came back wrong.
func CheckRecovery(before *RecoverySnapshot, after *RecoverySnapshot, incident *RecoveryIncident) error {
	if before == nil || after == nil {
		return errors.New("FI-12 needs the snapshot before the fault and the one after the recovery")
	}
	errs := []error{}
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	sortedKeys := func(keys []string) []string {
		slices.Sort(keys)
		return keys
	}

	// a network the incident lists lost takes its members and clients with it
	lost := func(identity *RecoveryIdentity) bool {
		if identity.Kind == RecoveryKindNetwork {
			return incident.lists(identity.Id, RecoveryLineOrphanLog)
		}
		networkId := identity.Fields[RecoveryFieldNetwork]
		return networkId != "" && incident.lists(networkId, RecoveryLineOrphanLog)
	}
	// each network name after the recovery, by name, for a name that came back under another id
	afterNameIds := map[string][]string{}
	for _, identity := range after.Identities {
		if identity.Kind == RecoveryKindNetwork && identity.Fields[RecoveryFieldName] != "" {
			afterNameIds[identity.Fields[RecoveryFieldName]] = append(afterNameIds[identity.Fields[RecoveryFieldName]], identity.Id)
		}
	}

	identityKeys := []string{}
	for key := range before.Identities {
		identityKeys = append(identityKeys, key)
	}
	for _, key := range sortedKeys(identityKeys) {
		want := before.Identities[key]
		mainDump := false
		if copied, ok := incident.mainDumpCopy(key); ok {
			want = copied
			mainDump = true
		}
		got := after.Identities[key]
		if got == nil {
			if lost(want) {
				continue
			}
			name := want.Fields[RecoveryFieldName]
			if otherIds := afterNameIds[name]; name != "" && 0 < len(otherIds) {
				fail("%s's oid changed: %q came back as %s", key, name, strings.Join(otherIds, ", "))
				continue
			}
			fail("%s did not come back, and the incident lists no line that loses it", key)
			continue
		}
		fieldNames := []string{}
		for name := range want.Fields {
			fieldNames = append(fieldNames, name)
		}
		for _, name := range sortedKeys(fieldNames) {
			wantValue, gotValue := want.Fields[name], got.Fields[name]
			if wantValue == gotValue {
				continue
			}
			switch {
			case want.Kind == RecoveryKindNetwork && name == RecoveryFieldName && 0 < len(incident.lines(RecoveryLineNetworkRenamed, want.Id)):
				if renamed := incident.lines(RecoveryLineNetworkRenamed, want.Id); renamed[len(renamed)-1].Detail != gotValue {
					fail("%s came back named %q, and the incident lists its suffixed name as %q", key, gotValue, renamed[len(renamed)-1].Detail)
				}
			case want.Kind == RecoveryKindMember && name == RecoveryFieldLogin && gotValue == "" && incident.lists(want.Id, RecoveryLineLoginLeftOut):
			default:
				source := "it held"
				if mainDump {
					source = "the main dump holds"
				}
				fail("%s came back with %s %q, not the %q %s, and the incident lists no line for it", key, name, gotValue, wantValue, source)
			}
		}
		switch {
		case want.Active == got.Active:
		case want.Active && want.Kind == RecoveryKindClient && incident.lists(want.Id, RecoveryLineClientDeactivated):
		case want.Active:
			fail("%s came back inactive, and the incident lists no line that deactivates it", key)
		default:
			fail("%s came back active, which it was not before the loss", key)
		}
	}

	headKeys := []string{}
	for key := range before.Heads {
		headKeys = append(headKeys, key)
	}
	for _, key := range sortedKeys(headKeys) {
		want := before.Heads[key]
		repoId := want.RepoId.String()
		got := after.Heads[key]
		switch {
		case got == nil && incident.lists(repoId, RecoveryLineOrphanRepo, RecoveryLineCloseNotReseeded):
		case got == nil:
			fail("%s did not come back, and the incident lists its repo nowhere", key)
		case got.Version == want.Version && bytes.Equal(got.Chain, want.Chain):
		case got.Version < want.Version && incident.lists(repoId, RecoveryLineCloseUnderReseed):
		default:
			fail("%s came back at %d (%x), not its %d (%x)", key, got.Version, recoveryChainPrefix(got.Chain), want.Version, recoveryChainPrefix(want.Chain))
		}
	}

	contentKeys := []string{}
	for key := range before.Contents {
		contentKeys = append(contentKeys, key)
	}
	for _, key := range sortedKeys(contentKeys) {
		want := before.Contents[key]
		got := after.Contents[key]
		repoId := want.RepoId.String()
		switch {
		case got == nil && incident.lists(repoId, RecoveryLineOrphanRepo, RecoveryLineCloseNotReseeded):
		case got == nil:
			fail("%s no longer opens, and the incident lists its repo nowhere", key)
		case !bytes.Equal(got.Sha256, want.Sha256):
			fail("%s opens to other content than it held", key)
		}
	}

	goneKeys := []string{}
	for key := range before.Gone {
		goneKeys = append(goneKeys, key)
	}
	for _, key := range sortedKeys(goneKeys) {
		why := before.Gone[key]
		if identity := after.Identities[key]; identity != nil && identity.Active {
			fail("%s, %s before the loss, came back active", key, why)
		}
		if after.Heads[key] != nil {
			fail("%s, %s before the loss, has a head again", key, why)
		}
		if after.Contents[key] != nil {
			fail("%s, %s before the loss, opens again", key, why)
		}
	}
	return errors.Join(errs...)
}

// The main dump's copy of key, which it carries for a row the sidecar dump does not name.
func (self *RecoveryIncident) mainDumpCopy(key string) (*RecoveryIdentity, bool) {
	if self == nil || self.MainDump == nil {
		return nil, false
	}
	copied, ok := self.MainDump[key]
	return copied, ok && copied != nil
}

// A chain's first bytes, for a message.
func recoveryChainPrefix(chain []byte) []byte {
	if 4 < len(chain) {
		return chain[:4]
	}
	return chain
}

// What FI-12 keeps of one Net's recoveries, by the label each row gives its recovery.
type fi12Memory struct {
	stateLock sync.Mutex
	labels    []string
	befores   map[string]*RecoverySnapshot
	afters    map[string]*RecoverySnapshot
	incidents map[string]*RecoveryIncident
}

func newFi12Memory() *fi12Memory {
	return &fi12Memory{
		befores:   map[string]*RecoverySnapshot{},
		afters:    map[string]*RecoverySnapshot{},
		incidents: map[string]*RecoveryIncident{},
	}
}

var fi12Memories sync.Map

// Hands FI-12 the snapshot a row took of recovery label before its fault. A second for one label replaces the first,
// so a row that snapshots again before the fault holds the newest.
func RecordRecoverySnapshot(net *Net, label string, snapshot *RecoverySnapshot) {
	memory := netMemoryOf(&fi12Memories, net, newFi12Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	if !slices.Contains(memory.labels, label) {
		memory.labels = append(memory.labels, label)
	}
	memory.befores[label] = snapshot
}

// Hands FI-12 what recovery label brought back, read as the snapshot before it was, and its incident; every check
// from then on compares the two.
func RecordRecovered(net *Net, label string, after *RecoverySnapshot, incident *RecoveryIncident) {
	memory := netMemoryOf(&fi12Memories, net, newFi12Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	if !slices.Contains(memory.labels, label) {
		memory.labels = append(memory.labels, label)
	}
	memory.afters[label] = after
	memory.incidents[label] = incident
}

// FI-12 over what a Net's rows recorded: see the file header.
func checkFi12(oracle *Oracle) error {
	memory := netMemoryOf(&fi12Memories, oracle.Net, newFi12Memory)
	memory.stateLock.Lock()
	labels := slices.Clone(memory.labels)
	befores := map[string]*RecoverySnapshot{}
	afters := map[string]*RecoverySnapshot{}
	incidents := map[string]*RecoveryIncident{}
	for _, label := range labels {
		befores[label], afters[label], incidents[label] = memory.befores[label], memory.afters[label], memory.incidents[label]
	}
	memory.stateLock.Unlock()

	if len(labels) == 0 {
		if oracle.Final {
			return errors.New("FI-12 read no recovery: the schedule recorded no RecoverySnapshot before a fault and nothing recovered after it, so nothing shows what came back")
		}
		return nil
	}
	errs := []error{}
	for _, label := range labels {
		before, after := befores[label], afters[label]
		switch {
		case before == nil && after != nil:
			errs = append(errs, fmt.Errorf("recovery %q: recorded what came back with no snapshot before its fault", label))
		case after == nil && oracle.Final:
			errs = append(errs, fmt.Errorf("recovery %q: a snapshot before its fault, and nothing recorded as recovered", label))
		case after != nil:
			if err := CheckRecovery(before, after, incidents[label]); err != nil {
				errs = append(errs, fmt.Errorf("recovery %q: %w", label, err))
			}
		}
	}
	return errors.Join(errs...)
}
