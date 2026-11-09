// The committer identity (§11.11, R-CORE-5, R-CTX-13; owner decision 81): a git commit names its sidecar by the
// committer email <client_id>@ur.invalid, the client id of one of that sidecar's generations, under the push's own
// signature. The name is the agent's label, free-form, and author fields stay free.
//
// The writing side: Sidecar.ClientIds lists this sidecar's own client ids, every generation's, which EVS1-M2-36's
// pre-receive hook accepts as committers. The keychain keeps them in the core namespace's client_ids record, which
// each new generation's persist adds to before the identity moves (identity_keys.go), so the list is never behind the
// identity: a kill between the two leaves an id of this sidecar's own key generation, never a gap.
//
// The reading side: SidecarCommitter, which a replaying reader asks about each new commit
// (plan-CORE-client-to-sidecar-lookup). A committer equal to the push's own client passes with no lookup (#1). Any
// other is looked up through GET /sidecar/identity?client_id=<id> (#2), and passes only if the binding api returns
// verifies, both signatures over its received bytes, names that client in this network, and binds it to the push's
// signer_sidecar_id under the identity key the reader pinned for it. api stays untrusted, and what cannot be resolved
// is refused, never passed. A verified binding never changes, a client binding exactly once, so it is cached.
//
// On every leg: root Id, no connect type. A SidecarCommitter is safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// The committer email's domain (§11.11): RFC 2606's reserved .invalid, which no mail reaches.
const sidecarCommitterDomain = "ur.invalid"

// The client_ids record's format values: magic, version, a count, then each generation's number and client id,
// integers big endian. At most sidecarClientIdsMaxCount generations are kept, the newest.
const (
	sidecarClientIdsRecordName    = "client_ids"
	sidecarClientIdsRecordMagic   = "URCI"
	sidecarClientIdsRecordVersion = 1
	sidecarClientIdsMaxCount      = 4096
)

var (
	// A committer email that is not <client_id>@ur.invalid in its one form.
	ErrSidecarCommitterEmail = errors.New("the committer email is not <client_id>@ur.invalid")
	// A committer no verified binding maps to the push's signer: refused, never passed.
	ErrSidecarCommitterUnresolved = errors.New("the committer does not resolve to the push's sidecar")
	// The client_ids record does not decode: a failure, never absence (D-CORE-15).
	errSidecarClientIdsFormat = fmt.Errorf("%w: the client ids record does not decode", ErrSidecarStoreFailed)
)

// The committer email of clientId: <client_id>@ur.invalid, the id in its canonical lower-case form.
func SidecarCommitterEmail(clientId Id) string {
	return clientId.String() + "@" + sidecarCommitterDomain
}

// The client id a committer email names, refusing any form but SidecarCommitterEmail's exact one, so one client has
// one email and nothing else passes for it.
func ParseSidecarCommitterEmail(email string) (Id, error) {
	local, domain, found := strings.Cut(email, "@")
	if !found || domain != sidecarCommitterDomain {
		return Id{}, ErrSidecarCommitterEmail
	}
	clientId, err := ParseId(local)
	if err != nil || clientId == (Id{}) || SidecarCommitterEmail(clientId) != email {
		return Id{}, ErrSidecarCommitterEmail
	}
	return clientId, nil
}

// One generation's client.
type sidecarGenerationClient struct {
	generation int64
	clientId   Id
}

// The record's bytes.
func encodeSidecarClientIds(clients []sidecarGenerationClient) []byte {
	encoded := make([]byte, 0, len(sidecarClientIdsRecordMagic)+1+4+len(clients)*(8+16))
	encoded = append(encoded, sidecarClientIdsRecordMagic...)
	encoded = append(encoded, sidecarClientIdsRecordVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(clients)))
	for _, client := range clients {
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(client.generation))
		encoded = append(encoded, client.clientId[:]...)
	}
	return encoded
}

// Exactly one record, generations rising, every id set; else errSidecarClientIdsFormat, which never repeats the bytes.
func decodeSidecarClientIds(encoded []byte) ([]sidecarGenerationClient, error) {
	cursor := &wrapCursor{remaining: encoded}
	magic := cursor.take(len(sidecarClientIdsRecordMagic))
	version := cursor.takeUint8()
	count := cursor.takeUint32()
	if cursor.failed || string(magic) != sidecarClientIdsRecordMagic || version != sidecarClientIdsRecordVersion ||
		sidecarClientIdsMaxCount < count {
		return nil, errSidecarClientIdsFormat
	}
	clients := make([]sidecarGenerationClient, 0, count)
	for range count {
		generation := cursor.takeUint64()
		clientIdBytes := cursor.take(16)
		if cursor.failed || generation < 1 || 1<<62 < generation {
			return nil, errSidecarClientIdsFormat
		}
		clientId, err := IdFromBytes(clientIdBytes)
		if err != nil || clientId == (Id{}) {
			return nil, errSidecarClientIdsFormat
		}
		if 0 < len(clients) && int64(generation) <= clients[len(clients)-1].generation {
			return nil, errSidecarClientIdsFormat
		}
		clients = append(clients, sidecarGenerationClient{generation: int64(generation), clientId: clientId})
	}
	if !cursor.finished() {
		return nil, errSidecarClientIdsFormat
	}
	return clients, nil
}

// The generations' clients secrets holds, oldest first; none before the first persist.
func loadSidecarClientIds(secrets SidecarSecrets) ([]sidecarGenerationClient, error) {
	encoded, err := secrets.Get(sidecarClientIdsRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeSidecarClientIds(encoded)
}

// Adds generation's client to the record, keeping the newest sidecarClientIdsMaxCount: what each persist of a new
// generation does before its identity moves. A generation already there changes nothing.
func rememberSidecarClientId(secrets SidecarSecrets, generation int64, clientId Id) error {
	clients, err := loadSidecarClientIds(secrets)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(clients, func(client sidecarGenerationClient) bool {
		return client.generation == generation && client.clientId == clientId
	}) {
		return nil
	}
	// a generation bound again after a kill took its first try's place: its client is the one that persists
	clients = slices.DeleteFunc(clients, func(client sidecarGenerationClient) bool {
		return generation <= client.generation
	})
	clients = append(clients, sidecarGenerationClient{generation: generation, clientId: clientId})
	if sidecarClientIdsMaxCount < len(clients) {
		clients = clients[len(clients)-sidecarClientIdsMaxCount:]
	}
	return secrets.Put(sidecarClientIdsRecordName, encodeSidecarClientIds(clients))
}

// This sidecar's own client ids across its generations, oldest first, the current one last: what EVS1-M2-36's
// pre-receive hook accepts as <client_id>@ur.invalid. ErrSidecarNoIdentity before enrollment, and the keychain's own
// errors while it is locked or failed.
func (self *Sidecar) ClientIds() ([]Id, error) {
	identity := self.currentIdentity()
	secrets := self.currentCoreSecrets()
	if identity == nil || secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	clients, err := loadSidecarClientIds(secrets)
	if err != nil {
		return nil, err
	}
	clientIds := make([]Id, 0, len(clients)+1)
	for _, client := range clients {
		if client.generation < identity.Generation && client.clientId != identity.ClientId {
			clientIds = append(clientIds, client.clientId)
		}
	}
	return append(clientIds, identity.ClientId), nil
}

// What a replaying reader knows of a new commit: its committer email, and the push carrying it, whose signature the
// reader has verified.
type SidecarCommitterClaim struct {
	CommitterEmail string
	// EvsPush.client_id.
	PushClientId Id
	// The push's signer_sidecar_id.
	SignerSidecarId Id
	// The identity key the reader pinned for that signer.
	SignerIdentityPublicKey []byte
}

// SidecarCommitter's tunables.
type SidecarCommitterSettings struct {
	// How many verified clients it keeps, each about 100 bytes: 4,096, a busy network's generations. A binding never
	// changes, so a kept one needs no expiry; past the count the oldest goes and is looked up again.
	CacheCount int
}

// The defaults, a fresh value each call.
func DefaultSidecarCommitterSettings() *SidecarCommitterSettings {
	return &SidecarCommitterSettings{CacheCount: 4096}
}

// What a SidecarCommitter runs on.
type SidecarCommitterArgs struct {
	// The network every commit it checks belongs to.
	NetworkId Id
	// GET /sidecar/identity?client_id=<id>: SidecarApi.GetIdentityByClient on a reader's token.
	Lookup func(ctx context.Context, clientId Id) (*SidecarIdentityRecord, error)
	// Nil: DefaultSidecarCommitterSettings.
	Settings *SidecarCommitterSettings
}

// The reader's committer check (plan-CORE-client-to-sidecar-lookup). Construct with NewSidecarCommitter.
type SidecarCommitter struct {
	networkId Id
	lookup    func(ctx context.Context, clientId Id) (*SidecarIdentityRecord, error)
	settings  *SidecarCommitterSettings

	stateLock sync.Mutex
	// client id to the verified binding's sidecar and identity key, oldest added first
	resolved      map[Id]sidecarCommitterBinding
	resolvedOrder []Id
}

// A verified binding's who.
type sidecarCommitterBinding struct {
	sidecarId         Id
	identityPublicKey []byte
}

// A committer check over args. With no lookup, every committer but the push's own client is refused.
func NewSidecarCommitter(args *SidecarCommitterArgs) *SidecarCommitter {
	settings := args.Settings
	if settings == nil {
		settings = DefaultSidecarCommitterSettings()
	}
	return &SidecarCommitter{
		networkId: args.NetworkId,
		lookup:    args.Lookup,
		settings:  settings,
		resolved:  map[Id]sidecarCommitterBinding{},
	}
}

// Whether claim's committer is a client the push's signer bound: nil, else ErrSidecarCommitterEmail or
// ErrSidecarCommitterUnresolved, the latter wrapping the lookup's error when one ended it, so a caller can tell an
// unreachable api, which a later replay retries, from a binding that refutes the commit.
func (self *SidecarCommitter) Check(ctx context.Context, claim *SidecarCommitterClaim) error {
	clientId, err := ParseSidecarCommitterEmail(claim.CommitterEmail)
	if err != nil {
		return err
	}
	if claim.SignerSidecarId == (Id{}) || len(claim.SignerIdentityPublicKey) == 0 {
		return fmt.Errorf("%w: the push names no pinned signer", ErrSidecarCommitterUnresolved)
	}
	// #1: the push's own client, under the signature the reader verified
	if clientId == claim.PushClientId {
		return nil
	}
	binding, ok := func() (sidecarCommitterBinding, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		binding, ok := self.resolved[clientId]
		return binding, ok
	}()
	if !ok {
		if self.lookup == nil {
			return fmt.Errorf("%w: no lookup", ErrSidecarCommitterUnresolved)
		}
		record, err := self.lookup(ctx, clientId)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSidecarCommitterUnresolved, err)
		}
		verified, err := VerifySidecarIdentityBinding(record.Binding)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSidecarCommitterUnresolved, err)
		}
		if verified.ClientId != clientId || verified.NetworkId != self.networkId || verified.SidecarId != record.SidecarId {
			return fmt.Errorf("%w: the binding names another client, network or sidecar", ErrSidecarCommitterUnresolved)
		}
		binding = sidecarCommitterBinding{sidecarId: verified.SidecarId, identityPublicKey: bytes.Clone(verified.IdentityPublicKey)}
		self.remember(clientId, binding)
	}
	if binding.sidecarId != claim.SignerSidecarId || !bytes.Equal(binding.identityPublicKey, claim.SignerIdentityPublicKey) {
		return fmt.Errorf("%w: the client is another sidecar's, or another identity key's", ErrSidecarCommitterUnresolved)
	}
	return nil
}

// Keeps a verified binding, the oldest going past CacheCount.
func (self *SidecarCommitter) remember(clientId Id, binding sidecarCommitterBinding) {
	if self.settings.CacheCount <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.resolved[clientId]; ok {
		return
	}
	self.resolved[clientId] = binding
	self.resolvedOrder = append(self.resolvedOrder, clientId)
	for self.settings.CacheCount < len(self.resolvedOrder) {
		delete(self.resolved, self.resolvedOrder[0])
		self.resolvedOrder = self.resolvedOrder[1:]
	}
}
