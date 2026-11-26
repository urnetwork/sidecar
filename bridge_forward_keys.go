// The Forwarder's generation keys (BRIDGE-M8-05; DESIGN-DETAILS 4.2.5's Compile, step 2; §10.5's DelegationWrap): the
// config repo's RK_g, opened by the forwarding reader key and by nothing else the component holds.
//
// A forwarding Delegation is no leaf of the config's group: each rotation seals RK_g to its reader key in a
// DelegationWrap, and a late one follows a setup or a supersession. A compile that lacks a generation, one a sealed
// body names or the head's read needs, lists gkm's GenRotates after the generations it holds, each verified under its
// signer's identity key in the judged state, then from the newest down opens each by a DelegationWrap to one of the
// component's reader keys, or by the ladder from the generation above. Each opened key is kept as gen/<g> with its
// Signed GenRotate, so the next compile reads it from the store. A generation with no wrap yet is asked for late,
// once a LateAskInterval; its bodies stay pending at id level and older generations still open. Every generation a
// compile wants that does not open waits with its cause, whether or not gkm lists it (QD-1210): its compile retries,
// and config_key_waiting is raised once it has waited KeyWaitAlarmInterval and again each interval, its detail the
// cause: no wrap yet, gkm listing no such generation, the GroupForms not leading on, or a listing stopped short.
//
// A re-form of the config's group (plan-KEYS-reform-ladder rules 7 and 8 as QD-074 decided them; §10.8) draws a new
// group, carries the old ladder into it byte for byte and claims every later generation there, so the group a hand-off
// named lists none of those, and after a site loss lists nothing. So each listing reads the repo's GroupForms first and
// lists in the group the newest makes, which it moves to only along a chain of judged forms from the group it lists
// in, or from the hand-off's while it has not followed past it, no form on it re-forming below the newest generation
// held (the pin never falls); the groups it followed are kept in the groups record, so a restart opens its keys from
// the store with no read of gkm. A listed statement stands under the rows evs resolves by (GkmParseServedGeneration,
// gkm_served_generation.go): the group's own, or one its ladder carried under the form that makes it, and it names the
// config repo and the hand-off's group or one along that chain, a copy naming any other being refused. Each chains by
// parent_commitment from the one below it, the newest held below the listing's first among them, and one at a held
// generation is the one held, so a listing that leaves this component's chain stops where it leaves it and raises
// head_alarm (fork), as a conflicting GenRotate is a member's (QD-1210; DESIGN-DETAILS 6.2.6), with the compile's pin
// for evidence: once for that generation while the listings that retry meet it, ended by one that reads it on the
// chain, or that gkm answers whole with none off it (bridge_forward.go's conditions). Deliveries are read in the group
// listed, whose id a carried generation's body names too (rule 7).
//
// A form is judged as a member device judges one before it adopts its group (gkm_reform.go's member row; QD-643): its
// Signed verified under its signer's identity key in the judged state, and its signer held to §10.6's rule, a repo
// admin's device, in an owner-bound repo only the owner's consented device, or a network admin's outside owner-bound
// kinds (GkmFormSignerAllowed), at the auth pin the form carries: at the state there where the judged log reaches it,
// judging nothing of one before, which counts against no one; waiting for the log at one above it; and refusing one off
// its chain as a fork. The judged log reaches back to the base before its newest, as a long-running member's does
// (config_state_at.go's window; bridge_forward_compile.go's step 1), so a form pinned between the two bases is judged
// here as it is there; where the store or the admission rule keeps the judge at the newest base, such a form counts
// against no one, as at a new device. A form the rule refuses, or that waits, is not followed: the generations a compile
// wants past it wait with the forms that do not lead on as their cause, which config_key_waiting names once one has
// waited (owner decision 716), and a form pinned off the judged chain raises head_alarm (fork) as well, with the
// compile's pin and the form's, once while the walks that retry meet it. A form that makes the group listed in carries
// its ladder's statements only once it is judged so.
//
// Each generation a listing reads past those held is held to §10.9's checks as a member device holds each it takes
// (gkm_rotate.go's holdGenerationInFlow), each statement at its own pin in the judged state. The rotations are judged
// first, oldest first, each GenRotate by the rotation checks (CheckRotation) on the generation below it: who may rotate
// there, its holders, its cause, its time and its floors. One pinned above the judged state, or timed past this clock
// and its skew, waits: the list stops there for this compile. One the checks refuse poisons its generation (§10.9's
// poisoned row): its key is never kept, so a body sealed to it stays pending, though its key may still open the
// generation below by the ladder, which holds each key to its own commitment; the generation above must be REMOVE to
// stand on it, as every member judges, since every member reads the same GenRotates; its refusal is kept as
// poisoned/<g>, so the same statement is refused again with no judging after its pin has left the judged window too, as
// a member's keychain keeps a poisoned generation; and it waits with the refusal as its cause, which config_key_waiting
// names once it has waited (owner decision 716), while a body wants it or nothing past it has opened. A member holds a
// poisoned generation's key to read what was sealed to it and never seals to it; the Forwarder, which seals nothing and
// cannot rotate past it, holds none. Then the keys are opened, newest first, and each DelegationWrap the compile reads
// is held to the delivery checks (CheckDelivery), a STAGED one at gen/<g>'s state and a LATE one at its own, in the
// group listed: one they refuse opens nothing (openWrap). Any statement pinned off the judged chain raises head_alarm
// (fork) as well, with the compile's pin and its own, once while the listings that retry meet it.
//
// The Forwarder holds a GenRotate, a GroupForm and a wrap to their signers' identity keys in the judged state, the
// wrap to the Delegation and key it names, and RK_g to gen/<g>'s commitment.
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
	"strconv"
	"strings"
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

// A generation a listing read, as a compile judges it (the file's comment).
type forwarderListedGeneration struct {
	generation uint64
	parsed     *GkmGeneration
	// the Signed GenRotate as gkm served it, encoded
	signedBytes []byte
	// kept already: judged when it was kept
	held bool
	// RK_g as the ladder from the generation above or a DelegationWrap opened it, nil for none
	key *EvsRepoKey
	// the refusal of its rotation (§10.9's poisoned row), nil for none: never kept, and the parent poisoned for the
	// generation above it
	refusal *GkmVerdict
	// the refusal came from its poisoned/<g> record, so it was not judged again
	recorded bool
	// the condition and evidence of the rotation's head_alarm (fork) where its refusal is a fork, which the record keeps
	forkCondition string
	forkPin       *bridge.AuthPin
	// the first refusal of a DelegationWrap of it the compile read, nil for none: that wrap opens nothing
	deliveryRefusal *GkmVerdict
	// why a DelegationWrap of it the compile read waits, empty for none
	deliveryWait string
}

// A refused generation as poisoned/<g> keeps it: the Signed GenRotate refused, the refusal's reason and detail, its
// fork condition, empty for none, and that fork's evidence pin, encoded, each a uvarint length and its bytes.
func forwarderEncodePoisoned(entry *forwarderListedGeneration) []byte {
	pinBytes := []byte{}
	if entry.forkPin != nil {
		pinBytes, _ = forwarderMarshal(entry.forkPin)
	}
	data := []byte{}
	for _, field := range [][]byte{entry.signedBytes, []byte(entry.refusal.Reason), []byte(entry.refusal.Detail), []byte(entry.forkCondition), pinBytes} {
		data = binary.AppendUvarint(data, uint64(len(field)))
		data = append(data, field...)
	}
	return data
}

// Takes into entry the refusal poisoned/<g> keeps where it keeps one for entry's statement, the GenRotate listed at g;
// none kept, one kept for another statement or one that does not read leaves the listed one to be judged.
func (self *forwarderRecords) poisoned(entry *forwarderListedGeneration) {
	data, err := self.read(forwarderNumberName(forwarderPoisonedPrefix, entry.generation))
	if err != nil {
		return
	}
	fields := [5][]byte{}
	for i := range fields {
		length, read := binary.Uvarint(data)
		if read <= 0 || uint64(len(data)-read) < length {
			return
		}
		fields[i] = data[read : read+int(length)]
		data = data[read+int(length):]
	}
	if !bytes.Equal(fields[0], entry.signedBytes) {
		return
	}
	entry.refusal = &GkmVerdict{Refused: true, Poisoned: entry.generation, Reason: GkmRefusalReason(fields[1]), Detail: string(fields[2])}
	entry.recorded = true
	if 0 < len(fields[3]) {
		pin := &bridge.AuthPin{}
		if proto.Unmarshal(fields[4], pin) == nil {
			entry.refusal.Fork = true
			entry.forkCondition, entry.forkPin = string(fields[3]), pin
		}
	}
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

// The group a listing reads the config's generations in, and the judged GroupForm that makes it, nil where gkm serves
// none that stands.
type forwarderListing struct {
	groupId Id
	form    *GkmGroupFormFacts
	// why the group stayed where the forms did not lead it on, or could not be read to; empty where they named it
	stayed string
}

// A GroupForm that verifies and that the walk does not take: §10.6's rule does not allow its signer at its pin, or its
// pin is off the judged chain, as gkmJudgeFormSigner's verdict says (the file's comment).
type forwarderFormRefusal struct {
	detail string
}

// The verdict's detail: ids and positions only.
func (self *forwarderFormRefusal) Error() string {
	return self.detail
}

// What a GroupForm the walk does not take fails at, as a wait's cause names it: its signer or its pin under §10.6's
// rule, a pin the judged state has not reached, or its signature or shape.
func forwarderFormFailure(err error) string {
	var refusal *forwarderFormRefusal
	switch {
	case errors.As(err, &refusal):
		return "is refused: " + refusal.detail
	case errors.Is(err, ErrGkmAuthAhead):
		return fmt.Sprintf("is pinned past the judged state and waits for the log: %v", err)
	}
	return fmt.Sprintf("does not verify: %v", err)
}

// A Signed GroupForm of the config repo, judged as the walk takes one (the file's comment): verified under its signer's
// admitted key in state, the compile's judged state, and its signer held to §10.6's rule at the auth pin the form
// carries (gkmJudgeFormSigner), its facts answered where the rule allows the signer there or the pin lies before what
// the judged log reaches. ErrGkmAuthAhead, to wait on, for a pin above state; a forwarderFormRefusal for a signer the
// rule does not allow, and for a pin off the judged chain, which raises head_alarm (fork) with the compile's pin and
// the form's, its condition added to forked.
func (self *Forwarder) judgeForm(state *ConfigState, signed *bridge.Signed, forked map[string]bool) (*GkmGroupFormFacts, error) {
	form, err := gkmParseGroupForm(state, self.args.ConfigRepoId, signed)
	if err != nil {
		return nil, err
	}
	verdict, err := gkmJudgeFormSigner(state, self.args.ConfigRepoId, form)
	if err != nil {
		return nil, err
	}
	if verdict.Refused {
		self.log.Warningf("[forward]%s the GroupForm of %s by %s is refused: %s", self.args.NetworkId, form.groupId, form.signerId, verdict.Detail)
		if verdict.Fork {
			formSha256 := sha256.Sum256(form.signedBytes)
			condition := forwarderConditionForm + hex.EncodeToString(formSha256[:])
			forked[condition] = true
			self.raiseHeadAlarm(condition, SidecarHeadAlarmFork, state.Pin(), form.auth)
		}
		return nil, &forwarderFormRefusal{detail: verdict.Detail}
	}
	return &GkmGroupFormFacts{GroupId: form.groupId, PreviousGroupId: form.previousGroupId, Generation: form.generation}, nil
}

// Reads the config repo's GroupForms and moves groups.current to the group the newest makes where a chain of judged
// forms leads there by previous_group_id from groups.current, or from the hand-off's group while it is not one followed
// past, and no form on it re-forms at a generation below newestHeld (the file's comment). Anything else leaves the
// group as it is: a newest form naming a group followed past is an older list, and the pin never falls. The groups
// record is written before any key is kept under a group it adds. An error is a read of gkm or a write of the store
// that failed; gkm's refusal of the forms reads as no form. A walk over the forms gkm served ends each form's head_alarm
// condition it did not meet again, and one with no form ends them all.
func (self *Forwarder) followGroups(ctx context.Context, state *ConfigState, groups *forwarderGroups, newestHeld uint64) (*forwarderListing, error) {
	reply, err := self.args.Gkm.Forms(ctx, self.args.ConfigRepoId)
	if gkmError, ok := GkmErrorOf(err); ok && !gkmError.RefusesNothing() {
		if self.log.V(1).Enabled() {
			self.log.Infof("[forward]%s gkm refused the config's GroupForms: %v", self.args.NetworkId, err)
		}
		return &forwarderListing{groupId: groups.current, stayed: fmt.Sprintf("gkm refused the config's GroupForms: %v", err)}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gkm's GroupForms of the config: %w", err)
	}
	signedForms := reply.GetForms()
	if self.settings.ConfigFormMaxCount < len(signedForms) {
		detail := fmt.Sprintf("the config's %d GroupForms are past %d", len(signedForms), self.settings.ConfigFormMaxCount)
		self.log.Warningf("[forward]%s generations stay listed in %s: %s", self.args.NetworkId, groups.current, detail)
		return &forwarderListing{groupId: groups.current, stayed: detail}, nil
	}
	// the forms this walk met pinned off the judged chain: once it returns, every other one standing has ended
	forked := map[string]bool{}
	defer self.endHeadConditions(forwarderConditionForm, func(condition string) bool { return forked[condition] })
	if len(signedForms) == 0 {
		// a gkm that holds no form of the repo lists in the group held
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
	// the newest form naming groupId, judged (judgeForm); nil for none
	formOf := func(groupId Id) (*GkmGroupFormFacts, error) {
		for index := len(signedForms) - 1; 0 <= index; index -= 1 {
			if formGroupIds[index] == groupId {
				return self.judgeForm(state, signedForms[index], forked)
			}
		}
		return nil, nil
	}
	// where the group stays: its own form carries its ladder's statements, where one stands
	stay := func(detail string) (*forwarderListing, error) {
		self.log.Warningf("[forward]%s generations stay listed in %s: %s", self.args.NetworkId, groups.current, detail)
		form, err := formOf(groups.current)
		if err != nil {
			form = nil
		}
		return &forwarderListing{groupId: groups.current, form: form, stayed: detail}, nil
	}
	newestGroupId := formGroupIds[len(signedForms)-1]
	if newestGroupId == (Id{}) {
		return stay("the newest GroupForm names no group")
	}
	newest, err := formOf(newestGroupId)
	if err != nil {
		return stay(fmt.Sprintf("the newest GroupForm, of %s, %s", newestGroupId, forwarderFormFailure(err)))
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
			return stay(fmt.Sprintf("the GroupForm of %s, on the chain to %s, %s", previousGroupId, newest.GroupId, forwarderFormFailure(err)))
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
// config's GroupForms lead to and holding each to §10.9's rotation and delivery checks (the file's comment). Returns how
// many it opened. state is the judged state, whose identity keys a GenRotate, a GroupForm and a wrap verify under, and
// whose window each is judged in at its own pin. A read of gkm that fails is an error, which the compile retries; a
// generation with no wrap, or one the checks refuse, is not. Each generation wanted that does not open, each listed one
// no wrap opened and each refused one nothing past has opened waits with its cause, whether or not gkm lists it, and
// config_key_waiting is raised for it once it has waited KeyWaitAlarmInterval (QD-1210; owner decision 716). A gkm that
// takes the judged state (forwarderGkmJudged) is handed it before the first read.
func (self *Forwarder) openGenerations(ctx context.Context, state *ConfigState, held map[uint64]*forwarderGeneration, wanted []uint64) (int, error) {
	if self.args.Gkm == nil {
		return 0, nil
	}
	lacking := len(held) == 0 || 0 < len(self.keyWaits) || self.headKeysWanted || slices.ContainsFunc(wanted, func(generation uint64) bool { return held[generation] == nil })
	if !lacking {
		return 0, nil
	}
	now := self.clock.Now()
	// the forwarding client's reads present the scope this state gives F as a verified state's, so one the exchange
	// refuses while api's gate lags the state is ridden out (bridge_forward_client.go; QD-1230)
	if judged, ok := self.args.Gkm.(forwarderGkmJudged); ok {
		judged.judgedState(state, self.args.SidecarId, now)
	}
	// a step that failed leaves every wait standing, and each wanted generation not held waiting on that failure
	failed := func(opened int, err error) (int, error) {
		for _, generation := range wanted {
			if held[generation] != nil {
				continue
			}
			wait := self.keyWaits[generation]
			if wait == nil {
				wait = &forwarderKeyWait{since: now}
				self.keyWaits[generation] = wait
			}
			wait.cause = err.Error()
		}
		self.alarmKeyWaits(now)
		return opened, err
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
		return failed(0, fmt.Errorf("the config's groups: %w", err))
	}
	listing, err := self.followGroups(fetchCtx, state, groups, newestHeld)
	if err != nil {
		return failed(0, err)
	}
	reply, err := self.args.Gkm.Generations(fetchCtx, self.args.ConfigRepoId, listing.groupId, since)
	if err != nil {
		return failed(0, fmt.Errorf("gkm's generations of %s after %d: %w", listing.groupId, since, err))
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
	listed := []*forwarderListedGeneration{}
	// where the list stopped short of what gkm served, or of what this compile judges, and why: the cause of each
	// wanted generation from there on
	stoppedAt, stopped := uint64(0), ""
	// where a statement off the held chain stopped it, 0 for none: head_alarm (fork)'s condition (settleGenerationForks)
	forkedAt := uint64(0)
	for i, signed := range reply.GetGenerations() {
		generation := since + 1 + uint64(i)
		signedBytes, err := forwarderMarshal(signed)
		if err != nil {
			stoppedAt, stopped = generation, fmt.Sprintf("gen/%d in %s does not encode: %v", generation, listing.groupId, err)
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
			stoppedAt, stopped = generation, fmt.Sprintf("gen/%d in %s does not stand: %v", generation, listing.groupId, err)
			break
		}
		// a statement off the chain this component holds is a fork, as a conflicting GenRotate is a member's
		// (QD-1210; DESIGN-DETAILS 6.2.6), with the compile's pin for evidence as a head served in another's place
		rotate := parsed.Rotate
		if 1 < generation && !bytes.Equal(rotate.GetParentCommitment(), below) {
			self.log.Warningf("[forward]%s gen/%d in %s does not chain from the generation below it: the list stops there", self.args.NetworkId, generation, listing.groupId)
			forkedAt, stoppedAt, stopped = generation, generation, fmt.Sprintf("gen/%d in %s does not chain from the generation below it", generation, listing.groupId)
			break
		}
		if kept := held[generation]; kept != nil && !bytes.Equal(rotate.GetCommitment(), kept.generation.Rotate.GetCommitment()) {
			self.log.Warningf("[forward]%s gen/%d in %s is not the statement held: the list stops there", self.args.NetworkId, generation, listing.groupId)
			forkedAt, stoppedAt, stopped = generation, generation, fmt.Sprintf("gen/%d in %s is not the statement held", generation, listing.groupId)
			break
		}
		below = rotate.GetCommitment()
		entry := &forwarderListedGeneration{generation: generation, parsed: parsed, signedBytes: signedBytes, held: held[generation] != nil}
		if !entry.held {
			self.records.poisoned(entry)
		}
		listed = append(listed, entry)
	}
	self.settleGenerationForks(state.Pin(), stoppedAt, forkedAt)
	readerKeys, err := self.args.Keys.ReaderKeys()
	if err != nil {
		return failed(0, fmt.Errorf("the forwarding reader keys: %w", err))
	}
	// the statements this listing met pinned off the judged chain: once it is judged, every other one standing at a
	// generation it read has ended
	forked := map[string]bool{}
	for _, entry := range listed {
		if entry.recorded && entry.forkCondition != "" {
			forked[entry.forkCondition] = true
			self.raiseHeadAlarm(entry.forkCondition, SidecarHeadAlarmFork, state.Pin(), entry.forkPin)
		}
	}
	// rotations, oldest first, each at its own pin on the generation below it (§10.9's rotation checks)
	gkmSettings := self.settings.Gkm
	if gkmSettings == nil {
		gkmSettings = DefaultGkmSettings()
	}
	judgedCount := len(listed)
	var parent *GkmGeneration
	if 0 < since {
		parent = held[since].generation
	}
	parentPoisoned := false
	for i, entry := range listed {
		if !entry.held && !entry.recorded {
			verdict, err := CheckRotation(state, &GkmRotationCheckArgs{
				RepoId: self.args.ConfigRepoId, Generation: entry.parsed, Parent: parent, ParentPoisoned: parentPoisoned,
				DropKeyLifetime: gkmSettings.DropKeyLifetime, Now: now,
			})
			if err != nil {
				// pinned past the judged state, timed past this clock, or a state that cannot answer: judged again at a
				// later compile, and nothing from here on kept by this one
				if self.log.V(1).Enabled() {
					self.log.Infof("[forward]%s gen/%d in %s waits at %d: %v", self.args.NetworkId, entry.generation, listing.groupId, state.Pin().GetVersion(), err)
				}
				judgedCount = i
				if stoppedAt == 0 || entry.generation < stoppedAt {
					stoppedAt, stopped = entry.generation, fmt.Sprintf("gen/%d in %s waits: %v", entry.generation, listing.groupId, err)
				}
				break
			}
			if verdict.Refused {
				entry.refusal = &verdict
				if condition := self.refuseStatement(state, listing.groupId, entry.generation, verdict, entry.signedBytes, entry.parsed.Rotate.GetAuth(), forked); condition != "" {
					entry.forkCondition, entry.forkPin = condition, entry.parsed.Rotate.GetAuth()
				}
			}
		}
		parent, parentPoisoned = entry.parsed, entry.refusal != nil
	}
	listed = listed[:judgedCount]
	// keys, newest first: the ladder from the generation above, a refused one's included, since the ladder holds each
	// key to its own commitment; else the component's own DelegationWraps, each held to §10.9's delivery checks
	// (openWrap), but for a refused generation, which is never kept
	for i := len(listed) - 1; 0 <= i; i -= 1 {
		entry := listed[i]
		if entry.held {
			continue
		}
		var above *EvsRepoKey
		if kept := held[entry.generation+1]; kept != nil {
			above = kept.key
		} else if i+1 < len(listed) {
			above = listed[i+1].key
		}
		if above != nil {
			if parent, err := above.OpenParent(entry.parsed); err == nil {
				entry.key = parent
				continue
			}
		}
		if entry.refusal == nil {
			self.openWrap(fetchCtx, state, listing.groupId, entry, readerKeys, now, forked)
		}
	}
	self.settleStatementForks(stoppedAt, forked)
	// keeps each judged generation no refusal poisons whose key opened, and each refusal not kept yet
	opened := 0
	for i := len(listed) - 1; 0 <= i; i -= 1 {
		entry := listed[i]
		switch {
		case entry.held:
			continue
		case entry.refusal != nil:
			if !entry.recorded {
				testHookBarrier("bridge_forward.poisoned.store", self.args.NetworkId.String())
				if err := self.records.write(forwarderNumberName(forwarderPoisonedPrefix, entry.generation), forwarderEncodePoisoned(entry)); err != nil {
					// judged again at the next compile, as at this one
					self.log.Warningf("[forward]%s the refusal of gen/%d was not kept: %v", self.args.NetworkId, entry.generation, err)
				}
			}
			continue
		case entry.key == nil:
			continue
		}
		record := forwarderEncodeGeneration(entry.signedBytes, state.IdentityKey(entry.parsed.SignerId), entry.key.repoKey)
		testHookBarrier("bridge_forward.generation.store", self.args.NetworkId.String())
		if err := self.records.write(forwarderNumberName(forwarderGenerationPrefix, entry.generation), record); err != nil {
			return failed(opened, err)
		}
		held[entry.generation] = &forwarderGeneration{key: entry.key, generation: entry.parsed}
		for _, readerKey := range readerKeys {
			self.lateAsks.Done(listing.groupId, entry.generation, forwarderWrapRecipient(readerKey.DelegationId[:]))
		}
		opened += 1
	}
	// what waits, and why: each listed generation that did not open, a refused one while nothing past it has opened, and
	// each wanted one that did not open, whether or not gkm lists it (QD-1210); any other waits for nothing
	newestHeld = 0
	for generation := range held {
		newestHeld = max(newestHeld, generation)
	}
	causes := map[uint64]string{}
	refusals := map[uint64]string{}
	for _, entry := range listed {
		if held[entry.generation] != nil {
			continue
		}
		switch {
		case entry.refusal != nil:
			refusals[entry.generation] = fmt.Sprintf("gen/%d in %s is refused: %s", entry.generation, listing.groupId, entry.refusal.Detail)
			if newestHeld < entry.generation {
				causes[entry.generation] = refusals[entry.generation]
			}
		case entry.deliveryRefusal != nil:
			causes[entry.generation] = fmt.Sprintf("a DelegationWrap of gen/%d in %s is refused: %s", entry.generation, listing.groupId, entry.deliveryRefusal.Detail)
		case entry.deliveryWait != "":
			causes[entry.generation] = entry.deliveryWait
		default:
			causes[entry.generation] = "no DelegationWrap of it has reached the forwarding reader key"
		}
	}
	for _, generation := range wanted {
		if held[generation] != nil || causes[generation] != "" {
			continue
		}
		switch {
		case refusals[generation] != "":
			causes[generation] = refusals[generation]
		case 0 < stoppedAt && stoppedAt <= generation:
			causes[generation] = stopped
		case listing.stayed != "":
			causes[generation] = listing.stayed
		default:
			causes[generation] = fmt.Sprintf("gkm lists no gen/%d in %s", generation, listing.groupId)
		}
	}
	for generation := range self.keyWaits {
		if causes[generation] == "" {
			delete(self.keyWaits, generation)
		}
	}
	for generation, cause := range causes {
		wait := self.keyWaits[generation]
		if wait == nil {
			wait = &forwarderKeyWait{since: now}
			self.keyWaits[generation] = wait
		}
		wait.cause = cause
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generations = len(held)
	}()
	self.alarmKeyWaits(now)
	return opened, nil
}

// A listing's head_alarm conditions, each a generation gkm lists off the held chain (the file's comment), with the
// compile's pin for evidence (owner decision 716): the one at forkedAt, where the list stopped, raised unless it
// stands; every other one at or below stoppedAt ended, since the list read that generation and found it on the chain or
// failing otherwise; and every one ended by a list that stopped nowhere, gkm listing no statement off the chain. One
// past where the list stopped stands, unread.
func (self *Forwarder) settleGenerationForks(pin *bridge.AuthPin, stoppedAt uint64, forkedAt uint64) {
	forkCondition := forwarderConditionGeneration + strconv.FormatUint(forkedAt, 10)
	self.endHeadConditions(forwarderConditionGeneration, func(condition string) bool {
		if stoppedAt == 0 {
			return false
		}
		if 0 < forkedAt && condition == forkCondition {
			return true
		}
		generation, err := strconv.ParseUint(strings.TrimPrefix(condition, forwarderConditionGeneration), 10, 64)
		return err == nil && stoppedAt < generation
	})
	if 0 < forkedAt {
		self.raiseHeadAlarm(forkCondition, SidecarHeadAlarmFork, pin, pin)
	}
}

// A Delegation as a wrap's recipient: d:<delegation_id>, as the wrap path writes it.
func forwarderWrapRecipient(delegationId []byte) string {
	return "d:" + hex.EncodeToString(delegationId)
}

// RK_g of one listed generation into entry, from the component's own DelegationWraps of it, read in groupId, the group
// listed, whose id their bodies name, a carried generation's too (rule 7). Each wrap read that verifies under its
// signer's admitted key is held to §10.9's delivery checks at its own state (CheckDelivery), as a member holds its own,
// and the key comes only from one that passes and opens to the reader key it was read for: one the checks refuse opens
// nothing, its refusal the generation's cause where nothing else opens it, and one pinned off the judged chain raises
// head_alarm (fork) too (refuseStatement); one that waits for the log or this clock opens nothing now. Unlike a member,
// which poisons the generation and rotates past it at once, the Forwarder can rotate nothing, and the members that seal
// to the generation never read its wraps: so a wrap refused here poisons neither the generation nor the one above it,
// and an honest body sealed to it still opens by a wrap that passes or by the ladder. The reader keys are read in turn
// until the key opens. A generation already found waiting is asked for late, once a LateAskInterval for each key.
func (self *Forwarder) openWrap(ctx context.Context, state *ConfigState, groupId Id, entry *forwarderListedGeneration, readerKeys []ForwarderReaderKey, now time.Time, forked map[string]bool) {
	identityKey := GkmIdentityKeys(state)
	g := entry.generation
	for _, readerKey := range readerKeys {
		if entry.key != nil {
			return
		}
		if readerKey.PrivateKey == nil {
			continue
		}
		recipient := forwarderWrapRecipient(readerKey.DelegationId[:])
		query := &GkmWrapsQuery{Recipient: recipient}
		if self.keyWaits[g] != nil {
			if since, ok := self.lateAsks.Ask(groupId, g, recipient, now); ok {
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
				// a signer the judged state admits no key for, or a wrap that does not verify: none of this
				// component's, passed over as a member passes over one of its own
				continue
			}
			verdict, err := CheckDelivery(state, &GkmDeliveryCheckArgs{
				RepoId: self.args.ConfigRepoId, Delivery: delivery, Generation: entry.parsed, GroupId: groupId, Now: now,
			})
			if err != nil {
				entry.deliveryWait = fmt.Sprintf("a DelegationWrap of gen/%d in %s waits: %v", g, groupId, err)
				continue
			}
			if verdict.Refused {
				if entry.deliveryRefusal == nil {
					entry.deliveryRefusal = &verdict
				}
				// a LATE delivery is judged at its own pin, a STAGED one at gen/<g>'s
				pin := delivery.Body.GetAuth()
				if pin == nil {
					pin = entry.parsed.Rotate.GetAuth()
				}
				signedBytes, err := forwarderMarshal(signed)
				if err != nil {
					signedBytes = entry.signedBytes
				}
				self.refuseStatement(state, groupId, g, verdict, signedBytes, pin, forked)
				continue
			}
			if entry.key != nil {
				continue
			}
			if key, err := openGkmDelivery(delivery, entry.parsed, groupId.Bytes(), readerKey.DelegationId[:], readerKey.PrivateKey); err == nil {
				entry.key = key
			}
		}
	}
}

// Logs a statement of a generation §10.9's checks refused by verdict, a GenRotate or a DelegationWrap, signedBytes its
// Signed, and raises head_alarm (fork) where the refusal is a fork, its pin off the judged chain: with the compile's
// pin and pin, the statement's, for evidence, once while the listings that retry meet it (the file's comment). The
// fork's condition, named in forked as well, or empty for a refusal that is no fork.
func (self *Forwarder) refuseStatement(state *ConfigState, groupId Id, generation uint64, verdict GkmVerdict, signedBytes []byte, pin *bridge.AuthPin, forked map[string]bool) string {
	self.log.Warningf("[forward]%s a statement of gen/%d in %s is refused at %d: %s", self.args.NetworkId, generation, groupId, pin.GetVersion(), verdict.Detail)
	if !verdict.Fork {
		return ""
	}
	statementSha256 := sha256.Sum256(signedBytes)
	condition := forwarderConditionStatement + strconv.FormatUint(generation, 10) + "/" + hex.EncodeToString(statementSha256[:])
	forked[condition] = true
	self.raiseHeadAlarm(condition, SidecarHeadAlarmFork, state.Pin(), pin)
	return condition
}

// A listing's statement conditions (the file's comment): each standing one at a generation the listing read, below
// stoppedAt or wherever nothing stopped it, ends unless met holds it, since the listing judged that generation again
// and met no such statement; one at or past where the list stopped stands, unread, as settleGenerationForks keeps one.
func (self *Forwarder) settleStatementForks(stoppedAt uint64, met map[string]bool) {
	self.endHeadConditions(forwarderConditionStatement, func(condition string) bool {
		if met[condition] {
			return true
		}
		generationText, _, _ := strings.Cut(strings.TrimPrefix(condition, forwarderConditionStatement), "/")
		generation, err := strconv.ParseUint(generationText, 10, 64)
		return err == nil && 0 < stoppedAt && stoppedAt <= generation
	})
}

// Raises config_key_waiting for the newest generation that has waited KeyWaitAlarmInterval for its key, and again each
// interval while one waits, its detail the wait's cause; clears it when none waits.
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
			Detail: fmt.Sprintf("config generation %d has not opened in %s: %s", generation, now.Sub(wait.since), wait.cause),
		})
		return
	}
}
