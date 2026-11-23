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
// A re-form of the config's group (plan-KEYS-reform-ladder rules 7 and 8 as QD-074 decided them; §10.8) draws a new
// group, carries the old ladder into it byte for byte and claims every later generation there, so the group a hand-off
// named lists none of those, and after a site loss lists nothing. So each listing reads the repo's GroupForms first and
// lists in the group the newest makes, which it moves to only along a chain of verified forms from the group it lists
// in, or from the hand-off's while it has not followed past it, no form on it re-forming below the newest generation
// held (the pin never falls); the groups it followed are kept in the groups record, so a restart opens its keys from
// the store with no read of gkm. A listed statement stands under the rows evs resolves by (GkmParseServedGeneration,
// gkm_served_generation.go): the group's own, or one its ladder carried under the form that makes it, and it names the
// config repo and the hand-off's group or one along that chain, a copy naming any other being refused. Each chains by
// parent_commitment from the one below it, the newest held below the listing's first among them, and one at a held
// generation is the one held, so a listing that leaves this component's chain stops where it leaves it. Deliveries
// are read in the group listed, which a carried generation's name too (rule 7).
//
// The Forwarder holds a GenRotate, a GroupForm and a wrap to their signers' identity keys in the judged state, the
// wrap to the Delegation and key it names, and RK_g to gen/<g>'s commitment. §10.9's rotation and delivery checks and
// §10.6's form signer rule, who may rotate, deliver and re-form at each one's own state, need states a transient
// rows-only log does not retain, and are not run here.
//
// testHookSecret sees each RK_g where it is opened (OpenEvsRepoKey). No key reaches a log line.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The record of the config repo's groups the Forwarder followed (bridge_forward_follow.go's layout).
const forwarderGroupsName = "groups"

// One generation the store holds a key of.
type forwarderGeneration struct {
	key        *EvsRepoKey
	generation *GkmGeneration
}

// The config repo's groups as the Forwarder follows them: the one it lists generations in, those it followed past,
// oldest first, and the hand-off's.
type forwarderGroups struct {
	current Id
	past    []Id
	handOff Id
}

// Whether a statement the store or a listing holds may name groupId: the group listed in, one followed past, or the
// hand-off's.
func (self *forwarderGroups) known(groupId Id) bool {
	return groupId != (Id{}) && (groupId == self.current || groupId == self.handOff || slices.Contains(self.past, groupId))
}

// The groups record: the past groups and then the current one, 16 bytes each.
func (self *forwarderGroups) encode() []byte {
	data := []byte{}
	for _, groupId := range self.past {
		data = append(data, groupId.Bytes()...)
	}
	return append(data, self.current.Bytes()...)
}

// The groups the store holds beside the hand-off's: none before a GroupForm named another group, and none for a record
// that does not parse, which the next listing writes again. On a failed read the hand-off's alone, with the error.
func (self *forwarderRecords) groups(handOff Id) (*forwarderGroups, error) {
	groups := &forwarderGroups{current: handOff, handOff: handOff}
	data, err := self.read(forwarderGroupsName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return groups, nil
	}
	if err != nil {
		return groups, err
	}
	idByteCount := len(Id{})
	if len(data) == 0 || len(data)%idByteCount != 0 {
		return groups, nil
	}
	groupIds := []Id{}
	for offset := 0; offset < len(data); offset += idByteCount {
		groupIds = append(groupIds, Id(data[offset:offset+idByteCount]))
	}
	groups.current, groups.past = groupIds[len(groupIds)-1], groupIds[:len(groupIds)-1]
	return groups, nil
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
// stored beside it, naming g and a group known (the hand-off's, or one the Forwarder followed), and RK_g matching its
// commitment.
func forwarderDecodeGeneration(data []byte, generation uint64, known func(groupId Id) bool) (*forwarderGeneration, error) {
	fields := [3][]byte{}
	for i := range fields {
		length, read := binary.Uvarint(data)
		if read <= 0 || uint64(len(data)-read) < length {
			return nil, errors.New("a generation record cut short")
		}
		fields[i] = data[read : read+int(length)]
		data = data[read+int(length):]
	}
	groupId, err := GkmGenerationNamedGroup(fields[0])
	if err != nil {
		return nil, err
	}
	if !known(groupId) {
		return nil, errors.New("a generation record of a group the config's forms do not lead through")
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
func (self *forwarderRecords) generation(generation uint64, known func(groupId Id) bool) *forwarderGeneration {
	data, err := self.read(forwarderNumberName(forwarderGenerationPrefix, generation))
	if err != nil {
		return nil
	}
	held, err := forwarderDecodeGeneration(data, generation, known)
	if err != nil {
		return nil
	}
	return held
}

// The config repo's key of a generation, read from the store, nil for one not held: what a host's config head reader
// opens the head with. Nothing of it stays in the Forwarder's memory.
func (self *Forwarder) RepoKeyAt(generation uint64) *EvsRepoKey {
	// a groups record that does not read leaves the hand-off's group alone, whose records still open
	groups, _ := self.records.groups(self.args.ConfigGroupId)
	held := self.records.generation(generation, groups.known)
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
	groups, err := self.records.groups(self.args.ConfigGroupId)
	if err != nil {
		return nil, err
	}
	held := map[uint64]*forwarderGeneration{}
	for _, generation := range generations {
		if opened := self.records.generation(generation, groups.known); opened != nil && opened.key.RepoId() == self.args.ConfigRepoId {
			held[generation] = opened
		}
	}
	return held, nil
}

// The group a listing reads the config's generations in, and the verified GroupForm that makes it, nil where gkm
// serves none that verifies.
type forwarderListing struct {
	groupId Id
	form    *GkmGroupFormFacts
}

// Reads the config repo's GroupForms and moves groups.current to the group the newest makes where a chain of verified
// forms leads there by previous_group_id from groups.current, or from the hand-off's group while it is not one followed
// past, and no form on it re-forms at a generation below newestHeld (the file's comment). Anything else leaves the
// group as it is: a newest form naming a group followed past is an older list, and the pin never falls. The groups
// record is written before any key is kept under a group it adds. An error is a read of gkm or a write of the store
// that failed; gkm's refusal of the forms reads as no form.
func (self *Forwarder) followGroups(ctx context.Context, state *ConfigState, groups *forwarderGroups, newestHeld uint64) (*forwarderListing, error) {
	reply, err := self.args.Gkm.Forms(ctx, self.args.ConfigRepoId)
	if gkmError, ok := GkmErrorOf(err); ok && !gkmError.RefusesNothing() {
		if self.log.V(1).Enabled() {
			self.log.Infof("[forward]%s gkm refused the config's GroupForms: %v", self.args.NetworkId, err)
		}
		return &forwarderListing{groupId: groups.current}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gkm's GroupForms of the config: %w", err)
	}
	signedForms := reply.GetForms()
	if len(signedForms) == 0 {
		// a gkm that holds no form of the repo lists in the group held
		return &forwarderListing{groupId: groups.current}, nil
	}
	if self.settings.ConfigFormMaxCount < len(signedForms) {
		self.log.Warningf("[forward]%s the config's %d GroupForms are past %d: generations stay listed in %s", self.args.NetworkId, len(signedForms), self.settings.ConfigFormMaxCount, groups.current)
		return &forwarderListing{groupId: groups.current}, nil
	}
	// each form's group as its body names it, unverified, so a chain finds its next form
	formGroupIds := make([]Id, len(signedForms))
	for index, signed := range signedForms {
		body := &protocol.GroupForm{}
		if proto.Unmarshal(signed.GetBody(), body) == nil {
			if groupId, err := IdFromBytes(body.GetGroupId()); err == nil {
				formGroupIds[index] = groupId
			}
		}
	}
	// the newest form naming groupId, verified under its signer's admitted key; nil for none
	formOf := func(groupId Id) (*GkmGroupFormFacts, error) {
		for index := len(signedForms) - 1; 0 <= index; index -= 1 {
			if formGroupIds[index] != groupId {
				continue
			}
			signedBytes, err := forwarderMarshal(signedForms[index])
			if err != nil {
				return nil, err
			}
			return GkmVerifyGroupForm(state, self.args.ConfigRepoId, signedBytes)
		}
		return nil, nil
	}
	// where the group stays: its own form carries its ladder's statements, where one verifies
	stay := func(detail string) (*forwarderListing, error) {
		self.log.Warningf("[forward]%s generations stay listed in %s: %s", self.args.NetworkId, groups.current, detail)
		form, err := formOf(groups.current)
		if err != nil {
			form = nil
		}
		return &forwarderListing{groupId: groups.current, form: form}, nil
	}
	newestGroupId := formGroupIds[len(signedForms)-1]
	if newestGroupId == (Id{}) {
		return stay("the newest GroupForm names no group")
	}
	newest, err := formOf(newestGroupId)
	if err != nil {
		return stay(fmt.Sprintf("the newest GroupForm, of %s, does not verify: %v", newestGroupId, err))
	}
	if newest.GroupId == groups.current {
		// listed in already: the group it re-forms is one its ladder's statements name
		if err := self.keepGroups(groups, []*GkmGroupFormFacts{newest}); err != nil {
			return nil, err
		}
		return &forwarderListing{groupId: groups.current, form: newest}, nil
	}
	if slices.Contains(groups.past, newest.GroupId) {
		return stay(fmt.Sprintf("the newest GroupForm makes %s, a group followed past", newest.GroupId))
	}
	// the chain from the newest form back to where the Forwarder may move from, newest first
	chain := []*GkmGroupFormFacts{newest}
	for {
		previousGroupId := chain[len(chain)-1].PreviousGroupId
		if previousGroupId == groups.current || (previousGroupId == groups.handOff && !slices.Contains(groups.past, groups.handOff)) {
			break
		}
		if previousGroupId == (Id{}) || len(signedForms) <= len(chain) {
			return stay(fmt.Sprintf("the newest GroupForm, of %s, does not follow from the group listed in", newest.GroupId))
		}
		form, err := formOf(previousGroupId)
		if err != nil {
			return stay(fmt.Sprintf("the GroupForm of %s, on the chain to %s, does not verify: %v", previousGroupId, newest.GroupId, err))
		}
		if form == nil {
			return stay(fmt.Sprintf("no GroupForm makes %s, on the chain to %s", previousGroupId, newest.GroupId))
		}
		chain = append(chain, form)
	}
	for _, form := range chain {
		if form.Generation < newestHeld {
			return stay(fmt.Sprintf("the GroupForm of %s re-forms at generation %d, below the held %d", form.GroupId, form.Generation, newestHeld))
		}
	}
	if err := self.keepGroups(groups, chain); err != nil {
		return nil, err
	}
	if self.log.V(1).Enabled() {
		self.log.Infof("[forward]%s the config's generations are listed in %s from now, %d forms on", self.args.NetworkId, groups.current, len(chain))
	}
	return &forwarderListing{groupId: groups.current, form: newest}, nil
}

// Takes the groups of a chain of verified forms, newest first, into groups, each form's group after the one it
// re-forms and the newest's last, and writes the groups record when that changes them.
func (self *Forwarder) keepGroups(groups *forwarderGroups, chain []*GkmGroupFormFacts) error {
	groupIds := append(slices.Clone(groups.past), groups.current)
	take := func(groupId Id) {
		if groupId == (Id{}) {
			return
		}
		groupIds = slices.DeleteFunc(groupIds, func(held Id) bool { return held == groupId })
		groupIds = append(groupIds, groupId)
	}
	for _, form := range slices.Backward(chain) {
		take(form.PreviousGroupId)
		take(form.GroupId)
	}
	kept := &forwarderGroups{current: groupIds[len(groupIds)-1], past: groupIds[:len(groupIds)-1], handOff: groups.handOff}
	if kept.current == groups.current && slices.Equal(kept.past, groups.past) {
		return nil
	}
	testHookBarrier("bridge_forward.groups.store", self.args.NetworkId.String())
	if err := self.records.write(forwarderGroupsName, kept.encode()); err != nil {
		return fmt.Errorf("the config's groups: %w", err)
	}
	*groups = *kept
	return nil
}

// Step 2 of a compile: opens the generations gkm lists past those held, when the compile lacks one of wanted, holds
// none, or follows a head read that lacked a generation's key, into held and the store, listing them in the group the
// config's GroupForms lead to (the file's comment). Returns how many it opened. state is the judged state, whose
// identity keys a GenRotate, a GroupForm and a wrap verify under. A read of gkm that fails is an error, which the
// compile retries; a generation with no wrap is not.
func (self *Forwarder) openGenerations(ctx context.Context, state *ConfigState, held map[uint64]*forwarderGeneration, wanted []uint64) (int, error) {
	if self.args.Gkm == nil {
		return 0, nil
	}
	lacking := len(held) == 0 || 0 < len(self.keyWaits) || self.headKeysWanted || slices.ContainsFunc(wanted, func(generation uint64) bool { return held[generation] == nil })
	if !lacking {
		return 0, nil
	}
	// the generations held with none missing below them: gkm lists from there, so a gap is listed again
	since := uint64(0)
	for held[since+1] != nil {
		since += 1
	}
	newestHeld := uint64(0)
	for generation := range held {
		newestHeld = max(newestHeld, generation)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, self.settings.FetchTimeout)
	defer cancel()
	groups, err := self.records.groups(self.args.ConfigGroupId)
	if err != nil {
		return 0, fmt.Errorf("the config's groups: %w", err)
	}
	listing, err := self.followGroups(fetchCtx, state, groups, newestHeld)
	if err != nil {
		return 0, err
	}
	reply, err := self.args.Gkm.Generations(fetchCtx, self.args.ConfigRepoId, listing.groupId, since)
	if err != nil {
		return 0, fmt.Errorf("gkm's generations of %s after %d: %w", listing.groupId, since, err)
	}
	// listed: a generation the head's read lacked opens now if gkm has it, and waits for its wrap otherwise
	self.headKeysWanted = false
	identityKey := GkmIdentityKeys(state)
	formMaking := func() (*GkmGroupFormFacts, error) {
		return listing.form, nil
	}
	// the commitment the next statement chains from: the newest held below the listing's first, then each listed
	var below []byte
	if 0 < since {
		below = held[since].generation.Rotate.GetCommitment()
	}
	listed := []*GkmGeneration{}
	signedRotates := [][]byte{}
	for i, signed := range reply.GetGenerations() {
		generation := since + 1 + uint64(i)
		signedBytes, err := forwarderMarshal(signed)
		if err != nil {
			break
		}
		parsed, err := GkmParseServedGeneration(signedBytes, self.args.ConfigRepoId, listing.groupId, generation, formMaking, identityKey)
		if err == nil && !bytes.Equal(parsed.Rotate.GetRepoId(), self.args.ConfigRepoId.Bytes()) {
			err = fmt.Errorf("%w: a GenRotate of another repo", ErrGkmMalformed)
		}
		if err == nil {
			if namedGroupId, idErr := IdFromBytes(parsed.Rotate.GetGroupId()); idErr != nil || !groups.known(namedGroupId) {
				err = fmt.Errorf("%w: a ladder's GenRotate naming no group the config's forms lead through", ErrGkmMalformed)
			}
		}
		if err != nil {
			// a signer the judged state does not admit yet, no statement of this config's groups, or a ladder no
			// verified form carries: the list stops here until a later compile
			if self.log.V(1).Enabled() {
				self.log.Infof("[forward]%s gen/%d in %s does not verify at %d: %v", self.args.NetworkId, generation, listing.groupId, state.Pin().GetVersion(), err)
			}
			break
		}
		rotate := parsed.Rotate
		if 1 < generation && !bytes.Equal(rotate.GetParentCommitment(), below) {
			self.log.Warningf("[forward]%s gen/%d in %s does not chain from the generation below it: the list stops there", self.args.NetworkId, generation, listing.groupId)
			break
		}
		if kept := held[generation]; kept != nil && !bytes.Equal(rotate.GetCommitment(), kept.generation.Rotate.GetCommitment()) {
			self.log.Warningf("[forward]%s gen/%d in %s is not the statement held: the list stops there", self.args.NetworkId, generation, listing.groupId)
			break
		}
		below = rotate.GetCommitment()
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
			key = self.openWrap(fetchCtx, state, listing.groupId, listed[i], generation, readerKeys)
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
			self.lateAsks.Done(listing.groupId, generation, forwarderWrapRecipient(readerKey.DelegationId[:]))
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

// RK_g from a DelegationWrap of one generation to one of the component's reader keys, read in groupId, the group
// listed, whose id its body names, a carried generation's too (rule 7); nil when gkm holds none that opens. A
// generation already found waiting is asked for late, once a LateAskInterval for each key.
func (self *Forwarder) openWrap(ctx context.Context, state *ConfigState, groupId Id, generation *GkmGeneration, g uint64, readerKeys []ForwarderReaderKey) *EvsRepoKey {
	identityKey := GkmIdentityKeys(state)
	for _, readerKey := range readerKeys {
		if readerKey.PrivateKey == nil {
			continue
		}
		recipient := forwarderWrapRecipient(readerKey.DelegationId[:])
		query := &GkmWrapsQuery{Recipient: recipient}
		if self.keyWaits[g] != nil {
			if since, ok := self.lateAsks.Ask(groupId, g, recipient, self.clock.Now()); ok {
				keySha256 := sha256.Sum256(readerKey.PrivateKey.PublicKey().Bytes())
				query.Want = keySha256[:gkmDigestPrefixByteCount]
				query.Since = since
			}
		}
		reply, err := self.args.Gkm.Wraps(ctx, self.args.ConfigRepoId, groupId, g, query)
		if err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[forward]%s the wraps of gen/%d in %s did not read: %v", self.args.NetworkId, g, groupId, err)
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
			key, err := openGkmDelivery(delivery, generation, groupId.Bytes(), readerKey.DelegationId[:], readerKey.PrivateKey)
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
