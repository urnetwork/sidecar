// What the oracle's store view decodes, with the format's own decoders (TEST-M2-01): protocol/EVS-FORMAT.md's keys,
// the proto messages, and the root's byte codecs for what is no proto, the batch and the slot. Nothing here runs
// evsservice's or gkmservice's behaviour, and nothing verifies a signature: an invariant that needs a signer's key
// checks one itself, against the authorization log it reads here.

package fault

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One ref's head as head/<repo>/<ref> holds it.
type StoreHead struct {
	ClusterId string
	Key       string
	// The ref id, 16 bytes.
	RefId []byte
	Etag  string
	Head  *protocol.EvsHead
}

// A key's numbers as §11.8 writes them: 20 decimal digits.
func storeKeyNumber(number uint64) string {
	return fmt.Sprintf("%020d", number)
}

// Every ref's head of a repo, on the cluster place/ names, decoded.
func (self *StoreView) Heads(ctx context.Context, repoId sidecar.Id) ([]*StoreHead, error) {
	clusterId, err := self.RepoClusterId(ctx, repoId)
	if err != nil {
		return nil, err
	}
	prefix := "head/" + sidecar.EvsKeyId(repoId) + "/"
	objects, err := self.Objects(ctx, clusterId, prefix)
	if err != nil {
		return nil, err
	}
	heads := []*StoreHead{}
	for _, object := range objects {
		refId, err := hex.DecodeString(strings.TrimPrefix(object.Key, prefix))
		if err != nil || len(refId) != 16 {
			return nil, fmt.Errorf("%s names no ref id", object.Key)
		}
		head := &protocol.EvsHead{}
		if err := proto.Unmarshal(object.Body, head); err != nil {
			return nil, fmt.Errorf("%s: %w", object.Key, err)
		}
		heads = append(heads, &StoreHead{ClusterId: clusterId, Key: object.Key, RefId: refId, Etag: object.Etag, Head: head})
	}
	return heads, nil
}

// A ref's log pages, log/<repo>/<ref>/<n>, in page order, decoded.
func (self *StoreView) Log(ctx context.Context, repoId sidecar.Id, refId []byte) ([]*protocol.EvsLogPage, error) {
	clusterId, err := self.RepoClusterId(ctx, repoId)
	if err != nil {
		return nil, err
	}
	prefix := "log/" + sidecar.EvsKeyId(repoId) + "/" + hex.EncodeToString(refId) + "/"
	objects, err := self.Objects(ctx, clusterId, prefix)
	if err != nil {
		return nil, err
	}
	pages := []*protocol.EvsLogPage{}
	for _, object := range objects {
		number, err := strconv.ParseUint(strings.TrimPrefix(object.Key, prefix), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s names no page", object.Key)
		}
		page := &protocol.EvsLogPage{}
		if err := proto.Unmarshal(object.Body, page); err != nil {
			return nil, fmt.Errorf("%s: %w", object.Key, err)
		}
		if page.GetPage() != number {
			return nil, fmt.Errorf("%s holds page %d", object.Key, page.GetPage())
		}
		pages = append(pages, page)
	}
	return pages, nil
}

// A slot, slot/<repo>/<slot_id>, decoded by the root's slot codec; nil when it is not there.
func (self *StoreView) Slot(ctx context.Context, repoId sidecar.Id, slotId sidecar.Id) (*protocol.EvsSlotObject, error) {
	clusterId, err := self.RepoClusterId(ctx, repoId)
	if err != nil {
		return nil, err
	}
	object, err := self.Object(ctx, clusterId, "slot/"+sidecar.EvsKeyId(repoId)+"/"+sidecar.EvsKeyId(slotId))
	if err != nil || object == nil {
		return nil, err
	}
	return sidecar.EvsDecodeSlotObject(object.Body)
}

// A batch on any metadata cluster, pb/<yyyymmddhh>/<mm>/<instance>-<seq>, decoded by the root's batch codec; nil
// when it is not there.
func (self *StoreView) Batch(ctx context.Context, clusterId string, key string) (*sidecar.EvsBatch, error) {
	object, err := self.Object(ctx, clusterId, key)
	if err != nil || object == nil {
		return nil, err
	}
	return sidecar.ParseEvsBatch(object.Body)
}

// Every batch under pb/ on clusterId, with its key.
func (self *StoreView) Batches(ctx context.Context, clusterId string) (map[string]*sidecar.EvsBatch, error) {
	objects, err := self.Objects(ctx, clusterId, "pb/")
	if err != nil {
		return nil, err
	}
	batches := map[string]*sidecar.EvsBatch{}
	for _, object := range objects {
		batch, err := sidecar.ParseEvsBatch(object.Body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", object.Key, err)
		}
		batches[object.Key] = batch
	}
	return batches, nil
}

// A group's generations, gkm/<group_id>/gen/<g> on the first metadata cluster, in generation order: each Signed
// GenRotate decoded, its signer named and not verified, and held to its key's group and generation.
func (self *StoreView) Generations(ctx context.Context, groupId sidecar.Id) ([]*sidecar.GkmGeneration, error) {
	clusterId, err := self.FirstClusterId()
	if err != nil {
		return nil, err
	}
	prefix := strings.TrimSuffix(sidecar.GkmGenerationPath(groupId, 0), storeKeyNumber(0))
	objects, err := self.Objects(ctx, clusterId, prefix)
	if err != nil {
		return nil, err
	}
	generations := []*sidecar.GkmGeneration{}
	for _, object := range objects {
		number, err := strconv.ParseUint(strings.TrimPrefix(object.Key, prefix), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s names no generation", object.Key)
		}
		generation, err := DecodeStoreGeneration(object.Body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", object.Key, err)
		}
		if !bytes.Equal(generation.Rotate.GetGroupId(), groupId.Bytes()) || generation.Rotate.GetGeneration() != number {
			return nil, fmt.Errorf("%s holds gen/%d of another group or generation", object.Key, generation.Rotate.GetGeneration())
		}
		generations = append(generations, generation)
	}
	return generations, nil
}

// gen/<g>'s bytes: a Signed GenRotate, decoded with no signature checked.
func DecodeStoreGeneration(objectBytes []byte) (*sidecar.GkmGeneration, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(objectBytes, signed); err != nil {
		return nil, err
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_GEN_ROTATE {
		return nil, fmt.Errorf("a Signed of type %d, not a GenRotate", signed.GetType())
	}
	signerId, err := sidecar.IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("it names no signer: %w", err)
	}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
		return nil, err
	}
	return &sidecar.GkmGeneration{Signed: signed, SignerId: signerId, Rotate: rotate}, nil
}

// A network's authorization log as proj/ holds it (§7.9): entry 0's Signed Genesis, verbatim, and the entries
// after it in position order, decoded. A missing genesis is nil.
type StoreAuthorizationLog struct {
	SignedGenesis []byte
	Entries       []*bridge.AuthEntry
}

// proj/<network_id>/ on the first metadata cluster, every position read.
func (self *StoreView) AuthorizationLog(ctx context.Context, networkId sidecar.Id) (*StoreAuthorizationLog, error) {
	clusterId, err := self.FirstClusterId()
	if err != nil {
		return nil, err
	}
	infos, err := self.List(ctx, clusterId, sidecar.ConfigEntryKeyPrefix(networkId))
	if err != nil {
		return nil, err
	}
	authorizationLog := &StoreAuthorizationLog{}
	for _, info := range infos {
		n, ok := sidecar.ParseConfigEntryKey(networkId, info.Key)
		if !ok {
			continue
		}
		object, err := self.Object(ctx, clusterId, info.Key)
		if err != nil {
			return nil, err
		}
		if object == nil {
			continue
		}
		if n == 0 {
			authorizationLog.SignedGenesis = object.Body
			continue
		}
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(object.Body, entry); err != nil {
			return nil, fmt.Errorf("%s: %w", info.Key, err)
		}
		if entry.GetN() != n {
			return nil, fmt.Errorf("%s holds entry %d", info.Key, entry.GetN())
		}
		authorizationLog.Entries = append(authorizationLog.Entries, entry)
	}
	return authorizationLog, nil
}
