//go:build !ios_extension

// BootstrapNetwork (TEAM-M2-09; §7.9's bootstrap): the network's first untagged sidecar of its owner signs the Genesis,
// the first config head and base 1, whose prev_chain is A_0 = SHA-256(Signed Genesis). api takes base 1 as entry 1
// If-None-Match, so of two first devices racing, one genesis wins. The winner creates the config repo, pushes the head
// whose push base 1 already carries and forms the config group; a loser learns the winning genesis, follows it, and is
// admitted like any device (plan-TEAM-genesis-custody).
//
// The first head's push is signed before base 1, so base 1 names its chain value and carries it for api's walk from
// C_0 (plan-TEAM-api-config-head-reach #4); evs takes that push's auth {0, A_0} only on a config repo's first push. A
// retry after a kill posts the same base 1, which api answers with its entry, and repeats a missing step after it.
//
// Every leg. Nothing here creates, derives or unwraps a key: the identity key signs through Sign.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

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
	// The config repo's main ref, empty until the winner pushes; and api's log, to learn whose genesis won.
	Heads      ConfigHeadRef
	Publisher  ConfigBasePublisher
	Projection ConfigProjectionReader
	// EvsClient.CreateRepo for the config kind, which the winner runs before pushing the head; nil runs none.
	CreateRepo func(ctx context.Context) error
	// GkmClient.CreateGroup for the config repo's group (KF1), which the winner forms after the head; nil forms none.
	CreateGroup func(ctx context.Context) error
	// The first head's files beside its genesis, a policy or a ServiceSettings; nil for none.
	Files map[string][]byte
	// The Genesis's time_ms; nil is real time.
	Clock Clock
}

// What BootstrapNetwork came to.
type ConfigBootstrapResult struct {
	// The genesis that won, this device's or another's, verbatim, and A_0, which every device of the network trusts.
	SignedGenesis []byte
	GenesisChain  [sha256.Size]byte
	// Whether this device's genesis won; base 1's pin when it did.
	Won bool
	Pin *bridge.AuthPin
}

// §7.9's bootstrap, as the package comment says. A device whose genesis lost answers Won false with the winning
// genesis, which it follows like any device.
func BootstrapNetwork(ctx context.Context, args *ConfigBootstrapArgs) (*ConfigBootstrapResult, error) {
	if args == nil || args.Sign == nil || args.Heads == nil || args.Publisher == nil || args.Projection == nil {
		return nil, errors.New("config bootstrap: missing args")
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	genesis := &bridge.Genesis{
		NetworkId:              args.NetworkId.Bytes(),
		ConfigRepoId:           args.ConfigRepoId.Bytes(),
		OwnerMemberId:          args.OwnerMemberId.Bytes(),
		OwnerSidecarId:         args.SidecarId.Bytes(),
		OwnerIdentityPublicKey: bytes.Clone(args.IdentityPublicKey),
		TimeMs:                 clock.Now().UnixMilli(),
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
	push, err := args.Heads.PrepareConfigHead(ctx, head, 0)
	if err != nil {
		return nil, err
	}
	rows, err := CompileProjectionRows(head, configGenesisCompileRows(genesis))
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

	pin, publishErr := args.Publisher.PublishConfigBase(ctx, &ConfigBasePublish{
		SignedHeader: signedHeader, Rows: rows, Genesis: signedGenesis, ConfigPushes: [][]byte{push.SignedPush},
	})
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
		if pin, publishErr = args.Publisher.PublishConfigBase(ctx, &ConfigBasePublish{
			SignedHeader: signedHeader, Rows: rows, Genesis: signedGenesis, ConfigPushes: [][]byte{push.SignedPush},
		}); publishErr != nil {
			return nil, publishErr
		}
	}

	// the winner's steps after base 1, each one a retry repeats
	if args.CreateRepo != nil {
		if err := args.CreateRepo(ctx); err != nil {
			return nil, fmt.Errorf("config bootstrap: the config repo: %w", err)
		}
	}
	if err := args.Heads.CommitConfigHead(ctx, push); err != nil {
		return nil, fmt.Errorf("config bootstrap: the first head: %w", err)
	}
	if args.CreateGroup != nil {
		if err := args.CreateGroup(ctx); err != nil {
			return nil, fmt.Errorf("config bootstrap: the config group: %w", err)
		}
	}
	return &ConfigBootstrapResult{SignedGenesis: signedGenesis, GenesisChain: genesisChain, Won: true, Pin: pin}, nil
}
