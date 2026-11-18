// A VPN component's config head reader (DESIGN-DETAILS 4.2.5's Compile, step 3; QD-804, QD-814; owner decision 197;
// SDK-M8-16): the replaying EvsConfigHeadReader on the network's config repo, built for a forwarding role, which the
// Forwarder reads each base's head through. Every base names a head, base 1's included, so with no reader nothing
// compiles; with it the component compiles each network with no sidecar role running.
//
//	tokens   F's exchange (ForwardingClient.ConfigHeads), which api answers only for the config repo's read scope
//	keys     the generations the Forwarder's store holds (Forwarder.RepoKeyAt), opened by the forwarding reader key,
//	         each with RK_1 beside it so the ref's id derives; nothing else of gkm is asked
//	pin      the main ref's pin and read records, kept in the forwarding store under the evs- names, beside the
//	         Forwarder's records and sealed as they are
//	judging  the Forwarder starts at its newest base b each compile, so it reads b's head at the anchor, the state at
//	         b (QD-814): descent from C_0 to the C_v b names, and each push's signature under an identity key that
//	         state admits. An ordinary read judges each push at its own pin against a config state this reader never
//	         holds, so it withholds
//
// It reads and never writes: the evs client under it signs nothing, holds no identity key and no config state, and its
// keys refuse every call but the two a read makes. The head it answers is held whole in memory, under the Forwarder's
// compile cap (DefaultForwardingConfigHeadsSettings), and none is kept past its answer, since the Forwarder keeps the
// heads it reads in its own store; the replay of the ref stays in memory between reads, bounded by that head (a
// storage-backed replay is QD-641's review-phase work).
//
// On every leg an app's VPN component builds, the ios_extension leg among them (QD-839, QD-973; owner decision 491):
// the Apple network extensions build the same reader Android's VPN service and the desktop app services do, so a
// role there compiles after its hand-off as any other does. The push records the replay reads are on that leg
// (evs_push_record.go, evs_reseed_record.go), and evs_config_head.go with them. The reader links an EvsClient, which
// is most of what it costs the iOS extension: with it the forwarding leg adds 7,042,032 B stripped (make size,
// 2026-11-18; 7,009,216 B on 2026-11-15, 6,008,480 B then without it) against §18.10's 7,864,320 B. A reader over a
// read-only core of the evs client is review-phase work. A bridge_forward file, so the leg's closure seeds from it and make size keeps its exported
// surface, as the VPN component calls it. Safe for concurrent use; one read replays at a time.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A forwarding role's evs client was asked to sign: it holds no identity key and signs nothing.
var errForwardingConfigHeadsSign = errors.New("a forwarding role's head reader signs nothing")

// Tunables of a forwarding role's config head reader.
type ForwardingConfigHeadsSettings struct {
	// The most generations of the config repo the keys look through, from the first up, for the newest the forwarding
	// store holds: 4,096, past a monthly rotation and every removal over a long-lived team's life. Only the ref's id
	// is read from the current generation, and it derives from RK_1 at every generation, so a newer one past the
	// bound changes no read. Non-positive holds none current, so every read withholds.
	GenerationMaxCount int
	// The evs client's settings; nil is DefaultEvsSettings.
	Evs *EvsSettings
	// The head reader's; nil is DefaultEvsConfigHeadSettings with HeadCacheCount 0.
	Heads *EvsConfigHeadSettings
}

// The defaults for a forwarding role tuned by forwarder, nil for an Apple extension's: a head is read whole only up
// to its compile cap, CompileMemoryMaxByteCount, past which no compile of it is ever admitted here, so a head the
// admission rule refuses with compile_over_budget is still read, and one past the cap is withheld rather than held in
// memory; and no head is kept, since the Forwarder keeps the heads it reads in its own store.
func DefaultForwardingConfigHeadsSettings(forwarder *ForwarderSettings) *ForwardingConfigHeadsSettings {
	if forwarder == nil {
		forwarder = DefaultForwarderSettings(ForwarderHostApple)
	}
	heads := DefaultEvsConfigHeadSettings()
	heads.HeadMaxByteCount = forwarder.CompileMemoryMaxByteCount
	heads.HeadCacheCount = 0
	return &ForwardingConfigHeadsSettings{
		GenerationMaxCount: 4096,
		Evs:                DefaultEvsSettings(),
		Heads:              heads,
	}
}

// What a forwarding role's config head reader is built over.
type ForwardingConfigHeadsArgs struct {
	NetworkId Id
	// S: the sidecar whose forwarding role this is, the evs client's identity, which names no key.
	SidecarId Id
	// The config repo, from the hand-off, whose main ref holds the heads.
	ConfigRepoId Id
	// The config repo's key of a generation, nil for one the store does not hold: the Forwarder's RepoKeyAt.
	RepoKeyAt func(generation uint64) *EvsRepoKey
	// The forwarding store, where the reader keeps the main ref's pin under the evs- names.
	Store ForwarderStore
	// evs's url, the transport and the service tokens a read presents. ForwardingClient.ConfigHeads fills them from F.
	EvsUrl       string
	Transport    http.RoundTripper
	ServiceToken EvsServiceTokenFunction
	// Nil is DefaultForwardingConfigHeadsSettings(nil).
	Settings *ForwardingConfigHeadsSettings
	Clock    Clock
	Log      Logger
}

// The forwarding role's head reader over F (the file's comment): args with F's evs url, its transport and its exchange,
// which answers only the config repo's read scope, in place of those fields.
func (self *ForwardingClient) ConfigHeads(args *ForwardingConfigHeadsArgs) (*EvsConfigHeadReader, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: a forwarding head reader needs its args", errInvalidSettings)
	}
	withF := *args
	withF.EvsUrl = self.evsUrl
	withF.Transport = self.api.Transport()
	withF.ServiceToken = func(ctx context.Context, resource string, scopes []string) (string, error) {
		token, err := self.api.ExchangeToken(ctx, resource, scopes)
		if err != nil {
			return "", err
		}
		return token.AccessToken, nil
	}
	return NewForwardingConfigHeads(&withF)
}

// A forwarding role's head reader over args (the file's comment). The network, the sidecar, the config repo, the keys,
// the store, evs's url, a transport and a token function are required.
func NewForwardingConfigHeads(args *ForwardingConfigHeadsArgs) (*EvsConfigHeadReader, error) {
	if args == nil || args.NetworkId == (Id{}) || args.SidecarId == (Id{}) || args.ConfigRepoId == (Id{}) || args.RepoKeyAt == nil ||
		args.Store == nil || args.Transport == nil || args.ServiceToken == nil {
		return nil, fmt.Errorf("%w: a forwarding head reader needs its network, sidecar, config repo, keys, store, transport and tokens", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultForwardingConfigHeadsSettings(nil)
	}
	evsSettings := settings.Evs
	if evsSettings == nil {
		evsSettings = DefaultEvsSettings()
	}
	headSettings := settings.Heads
	if headSettings == nil {
		headSettings = DefaultEvsConfigHeadSettings()
		headSettings.HeadCacheCount = 0
	}
	identity := &SidecarIdentity{NetworkId: args.NetworkId, SidecarId: args.SidecarId}
	client, err := NewEvsClient(&EvsClientArgs{
		NetworkId:    args.NetworkId,
		EvsUrl:       args.EvsUrl,
		Transport:    args.Transport,
		ServiceToken: args.ServiceToken,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return nil, errForwardingConfigHeadsSign
		},
		Identity: func() *SidecarIdentity {
			return identity.clone()
		},
		Gkm: &forwardingConfigKeys{
			repoId:             args.ConfigRepoId,
			repoKeyAt:          args.RepoKeyAt,
			generationMaxCount: settings.GenerationMaxCount,
		},
		Store:    &forwarderSidecarStore{store: args.Store, prefix: forwardingConfigHeadsStorePrefix},
		Clock:    args.Clock,
		Log:      args.Log,
		Settings: evsSettings,
	})
	if err != nil {
		return nil, err
	}
	return NewEvsConfigHeadReader(&EvsConfigHeadReaderArgs{Repo: client.Repo(args.ConfigRepoId), Settings: headSettings})
}

// The config repo's keys as a forwarding role's head reader asks them (the file's comment). Every call but a read's two
// refuses, as the refusing client a sidecar holds before its real one does, and a new state changes nothing.
type forwardingConfigKeys struct {
	gkmRefusingClient
	repoId             Id
	repoKeyAt          func(generation uint64) *EvsRepoKey
	generationMaxCount int
}

var _ GkmClient = (*forwardingConfigKeys)(nil)

// The newest generation of the run the store holds from the first up, within generationMaxCount, with RK_1. Read only
// for the ref's id, which derives from RK_1 at every generation.
func (self *forwardingConfigKeys) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	if repoId != self.repoId {
		return nil, fmt.Errorf("%w: a forwarding role holds the config repo's keys alone", ErrGkmKeyMissing)
	}
	var newest *EvsRepoKey
	for generation := uint64(1); generation <= uint64(max(self.generationMaxCount, 0)); generation += 1 {
		key := self.repoKeyAt(generation)
		if key == nil {
			break
		}
		newest = key
	}
	if newest == nil {
		return nil, fmt.Errorf("%w: the forwarding store holds no generation of the config repo from the first", ErrGkmKeyMissing)
	}
	return self.withFirst(newest)
}

// Generation g as the store holds it, with RK_1. ErrGkmKeyMissing for one it does not hold, which the Forwarder takes
// as a generation to list from gkm at its next compile.
func (self *forwardingConfigKeys) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	if repoId != self.repoId {
		return nil, fmt.Errorf("%w: a forwarding role holds the config repo's keys alone", ErrGkmKeyMissing)
	}
	key := self.repoKeyAt(generation)
	if key == nil {
		return nil, fmt.Errorf("%w: the forwarding store holds no config generation %d", ErrGkmKeyMissing, generation)
	}
	return self.withFirst(key)
}

// key with RK_1 beside it, so `ref` derives; as it is where the store holds no first generation, which every purpose
// but `ref` still derives from.
func (self *forwardingConfigKeys) withFirst(key *EvsRepoKey) (*EvsRepoKey, error) {
	if key.HoldsFirst() {
		return key, nil
	}
	first := self.repoKeyAt(1)
	if first == nil {
		return key, nil
	}
	return key.WithFirst(first)
}

// The names a forwarding head reader's records take in the forwarding store: its pin store's "pins/<repo>" and
// "reads/<repo>" as "evs-pins/<repo>" and "evs-reads/<repo>", and a read's spilled chunks, "spill/<id>/<n>", as
// "evs-spill/<id>-<n>": at most two segments, as the store's names are, apart from the Forwarder's own.
const forwardingConfigHeadsStorePrefix = "evs-"

// A ForwarderStore as the SidecarStore an evs client keeps its pins and a read's spill in: each name's first segment
// prefixed, and every separator past the first a dash, since the forwarding store's names hold two segments at most.
// Nothing an evs read keeps lists a name with more than two, so a name only comes back flattened from List, where
// none is a spill's. It holds no directory: the head reader keeps no mirror.
type forwarderSidecarStore struct {
	store  ForwarderStore
	prefix string
}

var _ SidecarStore = (*forwarderSidecarStore)(nil)

// name as the forwarding store holds it: prefixed, and its segments past the second joined to it by dashes.
func (self *forwarderSidecarStore) storeName(name string) string {
	first, rest, nested := strings.Cut(name, "/")
	if !nested {
		return self.prefix + name
	}
	return self.prefix + first + "/" + strings.ReplaceAll(rest, "/", "-")
}

// The record name names, as the forwarding store streams it.
func (self *forwarderSidecarStore) Open(name string) (io.ReadCloser, error) {
	return self.store.Open(self.storeName(name))
}

// Starts replacing the record name names; nothing shows until Commit.
func (self *forwarderSidecarStore) Create(name string) (SidecarStoreWriter, error) {
	return self.store.Create(self.storeName(name))
}

// Takes the record name names away; absent is not an error.
func (self *forwarderSidecarStore) Remove(name string) error {
	return self.store.Remove(self.storeName(name))
}

// Each record whose name starts with prefix, its name without this store's prefix.
func (self *forwarderSidecarStore) List(prefix string) ([]SidecarStoreEntry, error) {
	entries, err := self.store.List(self.storeName(prefix))
	if err != nil {
		return nil, err
	}
	listed := make([]SidecarStoreEntry, 0, len(entries))
	for _, entry := range entries {
		name, ok := strings.CutPrefix(entry.Name, self.prefix)
		if !ok {
			continue
		}
		entry.Name = name
		listed = append(listed, entry)
	}
	return listed, nil
}

// Refuses: a forwarding head reader keeps no directory.
func (self *forwarderSidecarStore) Directory(name string, class string) (SidecarStore, error) {
	return nil, fmt.Errorf("%w: a forwarding head reader's store holds no directory", ErrSidecarStoreFailed)
}
