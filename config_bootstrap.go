//go:build !ios_extension

// BootstrapNetwork (TEAM-M2-09; §7.9's bootstrap): the network's first untagged sidecar of its owner signs the Genesis,
// the first config head and base 1, whose prev_chain is A_0 = SHA-256(Signed Genesis). api takes base 1 as entry 1
// If-None-Match, so of two first devices racing, one genesis wins. The winner creates the config repo, forms its group
// and pushes the head whose push base 1 already carries; a loser learns the winning genesis, follows it, and is admitted
// like any device (plan-TEAM-genesis-custody).
//
// The first head's push is signed before base 1, so base 1 names its chain value and carries it for api's walk from
// C_0 (plan-TEAM-api-config-head-reach #4); evs takes that push's auth {0, A_0} only on a config repo's first push. On
// evs the push is sealed under the config group's generation 1, which KF1 forms only after base 1, since GenRotate_1's
// auth pin is past position 0 and gkm's gate holds nothing before base 1. So KF1 is split here (QD-824), in this order:
//
//	draft      KF1's bootstrap draft draws the config group's id and RK_1 and keeps them (GkmGroupClient.DraftGroup)
//	prepare    the config kind's prepare seals the head's push under {group_id, 1, C_1}, signed at the genesis
//	           state's pin {0, A_0}, sending nothing (EvsClient.PrepareConfigHead)
//	base 1     published naming (1, C_1), carrying the push
//	S(1)       this device's own state at base 1: api's entry 1 over the genesis, its rows this device's and its head
//	           the one it prepared, checked as any reader checks base 1's head (CheckConfigBase); handed to the caller,
//	           whose key client takes it, since no follower can read that head from evs before the push lands
//	repo       EvsClient.CreateRepo for the config kind: placement, keying; KF1's CreateGroup signs GenRotate_1 at S(1)
//	           over the drafted RK_1, posts the group and stages generation 1's deliveries; activation
//	push       the config kind's commit sends the prepared push (EvsClient.CommitConfigHead)
//
// C_g = SHA-256("UR evs 1.0 commit" || repo_id || u64be(g) || RK_g) holds no pin, so gen/1 signed at S(1) names the C_1
// the push already carries. A kill after the draft and before base 1 drafts the same id and RK_1 again. A test's ref
// that keys and sends the head itself (Heads) takes the draft's and the commit's place.
//
// A retry posts the same base 1 only where it signs the same genesis, head and push again, which this function does not
// keep: a kill after base 1 leaves the device's own genesis at entry 0, so a retry with a new genesis answers Won false.
//
// Every leg but the iOS extension's. Nothing here creates, derives or unwraps a key: the identity key signs through
// Sign, and the draft's key is GkmClient's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What BootstrapNetwork runs on: the owner's first device and the seams it writes through.
type ConfigBootstrapArgs struct {
	NetworkId     Id
	OwnerMemberId Id
	// This device, the owner's first and untagged, and its Ed25519 identity key.
	SidecarId         Id
	IdentityPublicKey []byte
	Sign              ConfigSignFunction
	// The config repo the Genesis names, a fresh id.
	ConfigRepoId Id
	// The time the first device began its durable draft, kept across retries. Zero uses Clock.
	GenesisTime time.Time
	// The first head on evs, keyed by the config group KF1 forms after base 1 (the file header). Nil with Heads.
	First *ConfigFirstHead
	// The config repo's main ref as a test's fake keeps it, which keys, signs and sends the first head itself; nil with
	// First.
	Heads ConfigHeadRef
	// api's log: where base 1 goes, and whose genesis won.
	Publisher  ConfigBasePublisher
	Projection ConfigProjectionReader
	// Base 1 landed: this device's own S(1) (the file header's S(1) row), which the caller's key client takes
	// (GkmClient.AuthAdvanced) so KF1 signs GenRotate_1 there. Nil hands it nowhere.
	BaseLanded func(ctx context.Context, state *ConfigState) error
	// EvsClient.CreateRepo for the config kind, by ConfigRepoId and filing nothing, since the Genesis names it:
	// placement, KF1 at S(1) over the drafted RK_1 (GkmClient.CreateGroup), activation. Nil runs none.
	CreateRepo func(ctx context.Context) error
	// The first head's files beside its genesis, a policy or a ServiceSettings; nil for none.
	Files map[string][]byte
	// The Genesis's time_ms; nil is real time.
	Clock Clock
}

// The network's first config head on evs (QD-824): its push is signed before base 1, which names it, under the
// generation pin of a config group that KF1 forms only after base 1.
type ConfigFirstHead struct {
	// Adds the first Owner's starting policy before base 1 is signed. A retry must return the
	// same files once Prepare has retained a signed push. Nil keeps the supplied files.
	Initialize func(context.Context, *ConfigState, *ConfigHead) (*ConfigHead, error)
	// KF1's bootstrap draft: the config group's id and RK_1, drawn and kept before base 1, so a retry seals under the
	// same (GkmGroupClient.DraftGroup). Answers generation 1's key as the draft holds it. genesis is the genesis state,
	// S(0), the only state before base 1, which a host's key client takes to choose its leaf; the draft reads none.
	Draft func(ctx context.Context, genesis *ConfigState) (*EvsRepoKey, error)
	// The config kind's prepare: head's push sealed under key and signed at genesis's pin {0, A_0}, sent nowhere
	// (EvsClient.PrepareConfigHead).
	Prepare func(ctx context.Context, key *EvsRepoKey, genesis *ConfigState, head *ConfigHead) (*ConfigHeadPush, error)
	// The config kind's commit, once the repo is active (EvsClient.CommitConfigHead).
	Commit func(ctx context.Context, push *ConfigHeadPush) error
}

// What BootstrapNetwork came to.
type ConfigBootstrapResult struct {
	// The genesis that won, this device's or another's, verbatim, and A_0, which every device of the network trusts.
	SignedGenesis []byte
	GenesisChain  [sha256.Size]byte
	// Whether this device's genesis won; base 1's pin when it did.
	Won bool
	Pin *bridge.AuthPin
	// When it won: the first head's push as base 1 names and carries it, and this device's own S(1).
	Push  *ConfigHeadPush
	State *ConfigState
}

// §7.9's bootstrap, as the package comment says. A device whose genesis lost answers Won false with the winning
// genesis, which it follows like any device.
func BootstrapNetwork(ctx context.Context, args *ConfigBootstrapArgs) (*ConfigBootstrapResult, error) {
	if args == nil || args.Sign == nil || args.Publisher == nil || args.Projection == nil {
		return nil, errors.New("config bootstrap: missing args")
	}
	if (args.First == nil) == (args.Heads == nil) {
		return nil, errors.New("config bootstrap: the first head goes through evs's seams or a ref, exactly one")
	}
	if args.First != nil && (args.First.Draft == nil || args.First.Prepare == nil || args.First.Commit == nil) {
		return nil, errors.New("config bootstrap: missing the first head's draft, prepare or commit")
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	genesisTime := args.GenesisTime
	if genesisTime.IsZero() {
		genesisTime = clock.Now()
	}
	genesis := &bridge.Genesis{
		NetworkId:              args.NetworkId.Bytes(),
		ConfigRepoId:           args.ConfigRepoId.Bytes(),
		OwnerMemberId:          args.OwnerMemberId.Bytes(),
		OwnerSidecarId:         args.SidecarId.Bytes(),
		OwnerIdentityPublicKey: bytes.Clone(args.IdentityPublicKey),
		TimeMs:                 genesisTime.UnixMilli(),
	}
	signedGenesis, err := configSignRecord(args.Sign, bridge.SignedType_SIGNED_GENESIS, genesis)
	if err != nil {
		return nil, err
	}
	if _, err := configParseGenesis(signedGenesis); err != nil {
		return nil, err
	}
	genesisChain := bridge.GenesisChain(signedGenesis)

	files := map[string][]byte{}
	for path, data := range args.Files {
		files[path] = bytes.Clone(data)
	}
	files[ConfigHeadGenesisPath] = signedGenesis
	head, err := NewConfigHead(files)
	if err != nil {
		return nil, err
	}
	var push *ConfigHeadPush
	if args.First != nil {
		// KF1's draft, then the push sealed under it at the genesis state, before base 1 exists
		genesisLog, err := NewConfigLog(DefaultConfigLogSettings(), signedGenesis)
		if err != nil {
			return nil, err
		}
		if initialize := args.First.Initialize; initialize != nil {
			head, err = initialize(ctx, genesisLog.State(), head)
			if err != nil {
				return nil, fmt.Errorf("config bootstrap: the starting policy: %w", err)
			}
			if head == nil || !bytes.Equal(head.File(ConfigHeadGenesisPath), signedGenesis) {
				return nil, errors.New("config bootstrap: the starting policy did not preserve Genesis")
			}
		}
		key, err := args.First.Draft(ctx, genesisLog.State())
		if err != nil {
			return nil, fmt.Errorf("config bootstrap: the config group's draft: %w", err)
		}
		if push, err = args.First.Prepare(ctx, key, genesisLog.State(), head); err != nil {
			return nil, fmt.Errorf("config bootstrap: the first head: %w", err)
		}
	} else if push, err = args.Heads.PrepareConfigHead(ctx, head, 0); err != nil {
		return nil, err
	}
	if push.Version != 1 {
		return nil, fmt.Errorf("config bootstrap: the first head prepared at version %d", push.Version)
	}
	compileRows := configGenesisCompileRows(genesis, genesisChain)
	rows, err := CompileProjectionRows(head, compileRows)
	if err != nil {
		return nil, err
	}
	rowsSha256 := sha256.Sum256(rows)
	signedHeader, err := configSignRecord(args.Sign, bridge.SignedType_SIGNED_PROJECTION_HEADER, &bridge.ProjectionHeader{
		NetworkId:        args.NetworkId.Bytes(),
		Version:          1,
		PrevChain:        genesisChain[:],
		FoldedThrough:    0,
		ConfigVersion:    push.Version,
		ConfigHeadSha256: bytes.Clone(push.Chain[:]),
		RowsSha256:       rowsSha256[:],
		RowsByteCount:    uint32(len(rows)),
	})
	if err != nil {
		return nil, err
	}

	base := &ConfigBasePublish{SignedHeader: signedHeader, Rows: rows, Genesis: signedGenesis, ConfigPushes: [][]byte{push.SignedPush}}
	pin, publishErr := args.Publisher.PublishConfigBase(ctx, base)
	if publishErr != nil {
		// whose genesis won: api's entry 0, which a lost answer of this device's own base names too
		projection, err := args.Projection.ReadConfigProjection(ctx, 0)
		if err != nil {
			return nil, fmt.Errorf("config bootstrap: %w (and the log does not read: %w)", publishErr, err)
		}
		if len(projection.SignedGenesis) == 0 {
			return nil, publishErr
		}
		if !bytes.Equal(projection.SignedGenesis, signedGenesis) {
			return &ConfigBootstrapResult{SignedGenesis: projection.SignedGenesis, GenesisChain: bridge.GenesisChain(projection.SignedGenesis)}, nil
		}
		// this device's genesis holds entry 0, so its base 1 is entry 1: retrying the same base answers it
		if pin, publishErr = args.Publisher.PublishConfigBase(ctx, base); publishErr != nil {
			return nil, publishErr
		}
	}

	// the winner's steps after base 1, each one a retry repeats
	state, err := configBootstrapState(ctx, args, signedGenesis, head, push, rows, pin)
	if err != nil {
		return nil, fmt.Errorf("config bootstrap: this device's state at base 1: %w", err)
	}
	if args.BaseLanded != nil {
		if err := args.BaseLanded(ctx, state); err != nil {
			return nil, fmt.Errorf("config bootstrap: base 1's state: %w", err)
		}
	}
	if args.CreateRepo != nil {
		if err := args.CreateRepo(ctx); err != nil {
			return nil, fmt.Errorf("config bootstrap: the config repo: %w", err)
		}
	}
	commit := func(ctx context.Context, push *ConfigHeadPush) error {
		if args.First != nil {
			return args.First.Commit(ctx, push)
		}
		return args.Heads.CommitConfigHead(ctx, push)
	}
	if err := commit(ctx, push); err != nil {
		return nil, fmt.Errorf("config bootstrap: the first head: %w", err)
	}
	return &ConfigBootstrapResult{SignedGenesis: signedGenesis, GenesisChain: genesisChain, Won: true, Pin: pin, Push: push, State: state}, nil
}

// This device's S(1) (the file header's S(1) row): api's entry 1 applied over the genesis, from its own rows and head.
// Its pin must be the one api answered base 1 with.
func configBootstrapState(ctx context.Context, args *ConfigBootstrapArgs, signedGenesis []byte, head *ConfigHead, push *ConfigHeadPush, rows []byte, pin *bridge.AuthPin) (*ConfigState, error) {
	projection, err := args.Projection.ReadConfigProjection(ctx, 0)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(projection.SignedGenesis, signedGenesis) || len(projection.Entries) == 0 {
		return nil, errors.New("api's log does not begin with this device's genesis and base")
	}
	log, err := NewConfigLog(DefaultConfigLogSettings(), signedGenesis)
	if err != nil {
		return nil, err
	}
	rowsSha256 := sha256.Sum256(rows)
	verdict, err := log.Apply(projection.Entries[0], &configBootstrapRows{rows: rows, rowsSha256: rowsSha256, head: head, push: push})
	if err != nil {
		return nil, err
	}
	if !verdict.Accepted() {
		return nil, verdict.Refusal
	}
	if !proto.Equal(log.Pin(), pin) {
		return nil, fmt.Errorf("%w: base 1 applied at another pin than api's", ErrConfigFork)
	}
	return log.State(), nil
}

// Base 1 as its signer holds it: the rows it compiled and the head it prepared, which its head check holds to the
// (1, C_1) the base names and to CheckConfigBase, as any reader holds a base's head.
type configBootstrapRows struct {
	rows       []byte
	rowsSha256 [sha256.Size]byte
	head       *ConfigHead
	push       *ConfigHeadPush
}

// The rows base 1 names, this device's own.
func (self *configBootstrapRows) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	if !bytes.Equal(rowsSha256, self.rowsSha256[:]) {
		return nil, fmt.Errorf("%w: rows this device did not compile", ErrConfigHeadUnavailable)
	}
	return self.rows, nil
}

// The prepared head, checked as base 1's.
func (self *configBootstrapRows) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	if check.Header.GetConfigVersion() != self.push.Version || !bytes.Equal(check.Header.GetConfigHeadSha256(), self.push.Chain[:]) {
		return nil, fmt.Errorf("%w: base 1 names a head this device did not prepare", ErrConfigHeadMismatch)
	}
	return CheckConfigBase(self.head, check, check.CompileRows)
}
