// The Forwarder's generation keys (BRIDGE-M8-05; DESIGN-DETAILS 4.2.5's Compile, step 2; §10.5's DelegationWrap): the
// config repo's RK_g, opened by the forwarding reader key and by nothing else the component holds.
//
// A forwarding Delegation is no leaf of the config's group: each rotation seals RK_g to its reader key in a
// DelegationWrap, and a late one follows a setup or a supersession. A compile that lacks a generation, one a sealed
// body names or the head's read needs, lists gkm's GenRotates after the generations it holds, each verified under its
// signer's identity key in the judged state, then from the newest down opens each by a DelegationWrap to one of the
// component's reader keys, or by the ladder from the generation above. Each opened key is kept as gen/<g> with its
// Signed GenRotate, so the next compile reads it from the store. A generation with no wrap yet is asked for late,
// once a LateAskInterval; its bodies stay pending at id level and older generations still open, and config_key_waiting
// is raised once it has waited KeyWaitAlarmInterval and again each interval.
//
// The Forwarder holds a GenRotate and a wrap to their signers' identity keys in the judged state, the wrap to the
// Delegation and key it names, and RK_g to gen/<g>'s commitment. §10.9's rotation and delivery checks, who may rotate
// and deliver at each one's own state, need states a transient rows-only log does not retain, and are not run here.
//
// testHookSecret sees each RK_g where it is opened (OpenEvsRepoKey). No key reaches a log line.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One generation the store holds a key of.
type forwarderGeneration struct {
	key        *EvsRepoKey
	generation *GkmGeneration
}

// A generation as gen/<g> keeps it: the Signed GenRotate as gkm served it, the identity key it verified under and
// RK_g, each a uvarint length and its bytes.
func forwarderEncodeGeneration(signedRotate []byte, identityKey []byte, repoKey []byte) []byte {
	data := []byte{}
	for _, field := range [][]byte{signedRotate, identityKey, repoKey} {
		data = binary.AppendUvarint(data, uint64(len(field)))
		data = append(data, field...)
	}
	return data
}

// The generation a gen/<g> record holds, verified again as it was when kept: the GenRotate under the identity key
// stored beside it, naming the config's group and g, and RK_g matching its commitment.
func forwarderDecodeGeneration(data []byte, groupId Id, generation uint64) (*forwarderGeneration, error) {
	fields := [3][]byte{}
	for i := range fields {
		length, read := binary.Uvarint(data)
		if read <= 0 || uint64(len(data)-read) < length {
			return nil, errors.New("a generation record cut short")
		}
		fields[i] = data[read : read+int(length)]
		data = data[read+int(length):]
	}
	parsed, err := ParseGenRotate(fields[0], groupId, generation, func(signerId Id) ([]byte, error) {
		return fields[1], nil
	})
	if err != nil {
		return nil, err
	}
	key, err := OpenEvsRepoKey(parsed, fields[2])
	if err != nil {
		return nil, err
	}
	return &forwarderGeneration{key: key, generation: parsed}, nil
}

// The generations the store holds a record of, ascending.
func (self *forwarderRecords) generations() ([]uint64, error) {
	entries, err := self.store.List(forwarderGenerationPrefix)
	if err != nil {
		return nil, err
	}
	generations := []uint64{}
	for _, entry := range entries {
		if generation, ok := forwarderNameNumber(forwarderGenerationPrefix, entry.Name); ok && 0 < generation {
			generations = append(generations, generation)
		}
	}
	return generations, nil
}

// The stored generation g, nil for none or for a record that no longer verifies.
func (self *forwarderRecords) generation(groupId Id, generation uint64) *forwarderGeneration {
	data, err := self.read(forwarderNumberName(forwarderGenerationPrefix, generation))
	if err != nil {
		return nil
	}
	held, err := forwarderDecodeGeneration(data, groupId, generation)
	if err != nil {
		return nil
	}
	return held
}

// The config repo's key of a generation, read from the store, nil for one not held: what a host's config head reader
// opens the head with. Nothing of it stays in the Forwarder's memory.
func (self *Forwarder) RepoKeyAt(generation uint64) *EvsRepoKey {
	held := self.records.generation(self.args.ConfigGroupId, generation)
	if held == nil || held.key.RepoId() != self.args.ConfigRepoId {
		return nil
	}
	return held.key
}

// Every generation the store holds, opened, for one compile.
func (self *Forwarder) loadGenerations() (map[uint64]*forwarderGeneration, error) {
	generations, err := self.records.generations()
	if err != nil {
		return nil, err
	}
	held := map[uint64]*forwarderGeneration{}
	for _, generation := range generations {
		if opened := self.records.generation(self.args.ConfigGroupId, generation); opened != nil && opened.key.RepoId() == self.args.ConfigRepoId {
			held[generation] = opened
		}
	}
	return held, nil
}

// Step 2 of a compile: opens the generations gkm lists past those held, when the compile lacks one of wanted or holds
// none, into held and the store. Returns how many it opened. state is the judged state, whose identity keys a
// GenRotate and a wrap verify under. A read of gkm that fails is an error, which the compile retries; a generation
// with no wrap is not.
func (self *Forwarder) openGenerations(ctx context.Context, state *ConfigState, held map[uint64]*forwarderGeneration, wanted []uint64) (int, error) {
	if self.args.Gkm == nil {
		return 0, nil
	}
	lacking := len(held) == 0 || 0 < len(self.keyWaits) || slices.ContainsFunc(wanted, func(generation uint64) bool { return held[generation] == nil })
	if !lacking {
		return 0, nil
	}
	// the generations held with none missing below them: gkm lists from there, so a gap is listed again
	since := uint64(0)
	for held[since+1] != nil {
		since += 1
	}
	fetchCtx, cancel := context.WithTimeout(ctx, self.settings.FetchTimeout)
	defer cancel()
	reply, err := self.args.Gkm.Generations(fetchCtx, self.args.ConfigRepoId, self.args.ConfigGroupId, since)
	if err != nil {
		return 0, fmt.Errorf("gkm's generations after %d: %w", since, err)
	}
	identityKey := GkmIdentityKeys(state)
	listed := []*GkmGeneration{}
	signedRotates := [][]byte{}
	for i, signed := range reply.GetGenerations() {
		generation := since + 1 + uint64(i)
		signedBytes, err := forwarderMarshal(signed)
		if err != nil {
			break
		}
		parsed, err := ParseGenRotate(signedBytes, self.args.ConfigGroupId, generation, identityKey)
		if err != nil || !slices.Equal(parsed.Rotate.GetRepoId(), self.args.ConfigRepoId.Bytes()) {
			// a signer the judged state does not admit yet, or no GenRotate of this repo: the list stops here until a
			// later compile
			if self.log.V(1).Enabled() {
				self.log.Infof("[forward]%s gen/%d does not verify at %d: %v", self.args.NetworkId, generation, state.Pin().GetVersion(), err)
			}
			break
		}
		listed = append(listed, parsed)
		signedRotates = append(signedRotates, signedBytes)
	}
	readerKeys, err := self.args.Keys.ReaderKeys()
	if err != nil {
		return 0, fmt.Errorf("the forwarding reader keys: %w", err)
	}
	now := self.clock.Now()
	opened := 0
	for i := len(listed) - 1; 0 <= i; i -= 1 {
		generation := since + 1 + uint64(i)
		if held[generation] != nil {
			delete(self.keyWaits, generation)
			continue
		}
		var key *EvsRepoKey
		if above := held[generation+1]; above != nil {
			// the ladder, downward
			if parent, err := above.key.OpenParent(listed[i]); err == nil {
				key = parent
			}
		}
		if key == nil {
			key = self.openWrap(fetchCtx, state, listed[i], generation, readerKeys)
		}
		if key == nil {
			if self.keyWaits[generation] == nil {
				self.keyWaits[generation] = &forwarderKeyWait{since: now}
			}
			continue
		}
		record := forwarderEncodeGeneration(signedRotates[i], state.IdentityKey(listed[i].SignerId), key.repoKey)
		testHookBarrier("bridge_forward.generation.store", self.args.NetworkId.String())
		if err := self.records.write(forwarderNumberName(forwarderGenerationPrefix, generation), record); err != nil {
			return opened, err
		}
		held[generation] = &forwarderGeneration{key: key, generation: listed[i]}
		delete(self.keyWaits, generation)
		for _, readerKey := range readerKeys {
			self.lateAsks.Done(self.args.ConfigGroupId, generation, forwarderWrapRecipient(readerKey.DelegationId[:]))
		}
		opened += 1
	}
	// a generation gkm no longer lists past the held ones waits for nothing
	for generation := range self.keyWaits {
		if generation <= since || since+uint64(len(listed)) < generation {
			delete(self.keyWaits, generation)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generations = len(held)
	}()
	self.alarmKeyWaits(now)
	return opened, nil
}

// A Delegation as a wrap's recipient: d:<delegation_id>, as the wrap path writes it.
func forwarderWrapRecipient(delegationId []byte) string {
	return "d:" + hex.EncodeToString(delegationId)
}

// RK_g from a DelegationWrap of one generation to one of the component's reader keys, nil when gkm holds none that
// opens. A generation already found waiting is asked for late, once a LateAskInterval for each key.
func (self *Forwarder) openWrap(ctx context.Context, state *ConfigState, generation *GkmGeneration, g uint64, readerKeys []ForwarderReaderKey) *EvsRepoKey {
	identityKey := GkmIdentityKeys(state)
	for _, readerKey := range readerKeys {
		if readerKey.PrivateKey == nil {
			continue
		}
		recipient := forwarderWrapRecipient(readerKey.DelegationId[:])
		query := &GkmWrapsQuery{Recipient: recipient}
		if self.keyWaits[g] != nil {
			if since, ok := self.lateAsks.Ask(self.args.ConfigGroupId, g, recipient, self.clock.Now()); ok {
				keySha256 := sha256.Sum256(readerKey.PrivateKey.PublicKey().Bytes())
				query.Want = keySha256[:gkmDigestPrefixByteCount]
				query.Since = since
			}
		}
		reply, err := self.args.Gkm.Wraps(ctx, self.args.ConfigRepoId, self.args.ConfigGroupId, g, query)
		if err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[forward]%s the wraps of gen/%d did not read: %v", self.args.NetworkId, g, err)
			}
			continue
		}
		for _, signed := range reply.GetWraps() {
			if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_DELEGATION_WRAP {
				continue
			}
			delivery, err := ParseGkmDelivery(proto.Clone(signed).(*bridge.Signed), GkmWrapTypeDelegation, identityKey)
			if err != nil {
				continue
			}
			key, err := OpenGkmDelivery(delivery, generation, readerKey.DelegationId[:], readerKey.PrivateKey)
			if err != nil {
				continue
			}
			return key
		}
	}
	return nil
}

// Raises config_key_waiting for the newest generation that has waited KeyWaitAlarmInterval for its wrap, and again
// each interval while one waits; clears it when none waits.
func (self *Forwarder) alarmKeyWaits(now time.Time) {
	if len(self.keyWaits) == 0 {
		self.clearAlarm(SidecarBridgeAlarm(ForwarderAlarmConfigKeyWaiting))
		return
	}
	generations := []uint64{}
	for generation := range self.keyWaits {
		generations = append(generations, generation)
	}
	slices.Sort(generations)
	for _, generation := range slices.Backward(generations) {
		wait := self.keyWaits[generation]
		last := wait.since
		if !wait.alarmedAt.IsZero() {
			last = wait.alarmedAt
		}
		if now.Sub(last) < self.settings.KeyWaitAlarmInterval {
			continue
		}
		wait.alarmedAt = now
		self.emitAlarm(BridgeAlarm{
			Reason: SidecarBridgeAlarm(ForwarderAlarmConfigKeyWaiting),
			Detail: fmt.Sprintf("no DelegationWrap of config generation %d has reached the forwarding reader key in %s", generation, now.Sub(wait.since)),
		})
		return
	}
}
