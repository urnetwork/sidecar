// The generation ladder as one device holds it (KEYS-M2-22; R-KEYS-3, R-KEYS-4, D-KEYS-6; §10.5's ladder,
// DESIGN-DETAILS 6.2.5): how it learns the generations gkm holds past its own, how it first comes to hold a repo it
// reads only by wraps, and how it walks down from a generation it opened to every one below.
//
//	refresh     GET gen?since= from this device's own newest generation, which gkm must still serve with the
//	            commitment this device pinned, else a fork; each generation after it is parsed under its signer's
//	            admitted key, judged by the rotation checks on its parent (CheckRotation), opened by its leaf_wrap or
//	            by a delivery to a ReaderKey this device holds, and kept; one that fails is kept as poisoned and
//	            alarmed; one this device cannot open yet is asked for late, at most once a LateAskInterval, and a
//	            newer one it can open reaches it through the links
//	first wrap  a repo this device holds nothing of: the group gkm's newest GroupForm names, which binds nothing by
//	            itself, then the newest gen/, which names the repo, is signed by a holder the rotation checks hold
//	            to the log, and is opened only by a delivery to this device's own ReaderKey
//	walk        RK_{g-1} from RK_g's GenLink, whose AAD carries g's cause, accepted only against gen/<g-1>'s C,
//	            which gen/<g> names as its parent: each link is authenticated by the newer verified generation, and
//	            each gen/<k> below is held to its signer's key, so its cause, pin and time are its rotator's. A wrong
//	            C_g, GenLink or cause opens nothing, and the walk never skips a generation it cannot open
//
// Every RK_g opened is kept in the keychain with its Signed GenRotate (gkm_group.go's gen/<g> record), so a read
// never asks gkm twice and KF7's reads need no gkm at all. A key that is not there is refused, never defaulted.
//
// Calls testHookSecret through the ladder's own functions (gkm_keys.go) at every key opened.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How many pages of gen/ one refresh or first wrap reads before it gives up for this pass: gkm answers in pages,
// and a device asks again after the last until none comes.
const gkmGenerationPageMaxCount = 1024

// Whether an error says gkm could not be reached or would not answer now, a 429 or 503 among them, rather than
// that it refused: KF7's case, in which cached keys serve reads and deposits and everything else waits.
func gkmUnreachable(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if gkmError, refused := GkmErrorOf(err); refused {
		return gkmError.RefusesNothing()
	}
	for _, known := range []error{
		ErrGkmUnavailable, ErrGkmNotWriter, ErrGkmWait, ErrGkmKeyMissing, ErrGkmMalformed, ErrGkmAuthentication, ErrGkmAuthAhead,
		ErrGkmAuthNotRetained, ErrGkmAuthOffChain, ErrGkmTimeAhead, ErrGkmNoRepo, ErrGkmGateClosed, ErrGkmCommitRefused,
		ErrGkmResyncNeeded, ErrGkmReplyInvalid, ErrGkmForked, ErrMlsGroupUnknown, ErrMlsNotMember,
	} {
		if errors.Is(err, known) {
			return false
		}
	}
	return true
}

// The newest generation of the repo this device holds a key of, or ErrGkmKeyMissing.
func (self *GkmGroupClient) newestOpenedGeneration(repoId Id) (*gkmHeldGeneration, error) {
	names, err := self.args.Secrets.List(gkmRepoRecordName(repoId, "gen/"))
	if err != nil {
		return nil, err
	}
	// 20-digit names sort as numbers
	for index := len(names) - 1; 0 <= index; index -= 1 {
		encoded, err := self.getRecord(names[index])
		if err != nil {
			return nil, err
		}
		held, err := decodeGkmHeldGeneration(encoded)
		clear(encoded)
		if err != nil {
			return nil, err
		}
		if held.key != nil {
			return held, nil
		}
	}
	return nil, fmt.Errorf("%w: no generation of the repo is opened", ErrGkmKeyMissing)
}

// key with RK_1, so `ref` derives, once this device holds generation 1's key; key as it is until then.
func (self *GkmGroupClient) withFirst(repoId Id, key *EvsRepoKey) (*EvsRepoKey, error) {
	if key.HoldsFirst() {
		return key, nil
	}
	first, err := self.heldGeneration(repoId, 1)
	if errors.Is(err, ErrGkmKeyMissing) || err == nil && first.key == nil {
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	return key.WithFirst(first.key)
}

// One page of gen/ after since, each entry left as gkm served it.
func (self *gkmGroupManager) generationsPage(ctx context.Context, groupId Id, since uint64) ([]*bridge.Signed, error) {
	reply, err := self.client.args.Api.Generations(ctx, self.repoId, groupId, since)
	if err != nil {
		return nil, err
	}
	return reply.GetGenerations(), nil
}

// The refresh row: brings what this device holds of the repo's generations up to gkm's newest, then walks the
// ladder down from any it newly opened. ErrGkmAuthOffChain, alarmed as a fork, when gkm no longer serves this
// device's own newest generation as it pinned it; ErrGkmAuthAhead while a newer generation's pin is above state.
func (self *gkmGroupManager) refreshGenerationsInFlow(ctx context.Context, state GkmAuthView) error {
	client := self.client
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return err
	}
	yield := client.newYield()
	for pageCount := 0; pageCount < gkmGenerationPageMaxCount; pageCount += 1 {
		top, err := client.newestHeldGeneration(self.repoId)
		if err != nil {
			return err
		}
		number := top.generation.Rotate.GetGeneration()
		// from this device's own newest generation, so a store that no longer serves it shows
		page, err := self.generationsPage(ctx, pins.groupId, number-1)
		if err != nil {
			return err
		}
		standing := &protocol.GenRotate{}
		if 0 < len(page) {
			if err := proto.Unmarshal(page[0].GetBody(), standing); err != nil {
				return fmt.Errorf("%w: gen/%d", ErrGkmReplyInvalid, number)
			}
		}
		if len(page) == 0 || standing.GetGeneration() != number || !bytes.Equal(standing.GetCommitment(), top.generation.Rotate.GetCommitment()) {
			local := &protocol.GenHead{GroupId: pins.groupId.Bytes(), Generation: number, Commitment: top.generation.Rotate.GetCommitment()}
			var remote *protocol.GenHead
			if 0 < len(page) {
				remote = &protocol.GenHead{GroupId: pins.groupId.Bytes(), Generation: standing.GetGeneration(), Commitment: standing.GetCommitment()}
			}
			return client.pinForked(self.repoId, pins, HeadForkGen, local, remote, nil, true, "gkm does not serve this device's newest generation as it pinned it")
		}
		if len(page) == 1 {
			break
		}
		for _, winner := range page[1:] {
			yield.step()
			top, err = client.newestHeldGeneration(self.repoId)
			if err != nil {
				return err
			}
			next := top.generation.Rotate.GetGeneration() + 1
			// this device's own claim, landed before a kill took its answer: the draft's commitment stands there
			if draft := self.storedDraft(); draft != nil && draft.generation.Rotate.GetGeneration() == next {
				body := &protocol.GenRotate{}
				if err := proto.Unmarshal(winner.GetBody(), body); err == nil && bytes.Equal(body.GetCommitment(), draft.generation.Rotate.GetCommitment()) {
					if _, err := self.claimed(draft); err != nil {
						return err
					}
					continue
				}
			}
			if _, err := self.takeWinner(ctx, state, pins, top, winner, client.clock.Now()); err != nil && !errors.Is(err, ErrGkmKeyMissing) {
				return err
			}
			held, err := client.newestHeldGeneration(self.repoId)
			if err != nil {
				return err
			}
			if held.generation.Rotate.GetGeneration() != next {
				return fmt.Errorf("%w: gen/%d was not held", ErrGkmReplyInvalid, next)
			}
		}
	}
	// the newest generation held without its key: a late delivery may have come since
	if top, err := client.newestHeldGeneration(self.repoId); err == nil && top.key == nil {
		if err := self.openHeldGenerationInFlow(ctx, state, pins.groupId, top); err != nil {
			return err
		}
	}
	self.walkLadderForLater(ctx, state, pins.groupId)
	return nil
}

// The first wrap row: what a device that holds nothing of the repo first takes of it. ErrGkmKeyMissing when gkm
// holds no group for the repo yet or no delivery to this device, which is then asked for late.
func (self *gkmGroupManager) firstWrapInFlow(ctx context.Context, state GkmAuthView) error {
	client := self.client
	if state.Repo(self.repoId) == nil {
		return fmt.Errorf("%w: repo %s", ErrGkmNoRepo, self.repoId)
	}
	forms, err := client.args.Api.Forms(ctx, self.repoId)
	if err != nil {
		return err
	}
	signedForms := forms.GetForms()
	if len(signedForms) == 0 {
		return fmt.Errorf("%w: gkm holds no group for the repo", ErrGkmKeyMissing)
	}
	// what gkm answers here binds nothing: gen/<g> names the repo, and its signer is held to the log
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(signedForms[len(signedForms)-1].GetBody(), form); err != nil {
		return fmt.Errorf("%w: a GroupForm", ErrGkmReplyInvalid)
	}
	groupId, err := IdFromBytes(form.GetGroupId())
	if err != nil || !bytes.Equal(form.GetRepoId(), self.repoId.Bytes()) {
		return fmt.Errorf("%w: a GroupForm of another repo", ErrGkmReplyInvalid)
	}
	// the newest generation and its parent
	var newest, parent *bridge.Signed
	since := uint64(0)
	for pageCount := 0; pageCount < gkmGenerationPageMaxCount; pageCount += 1 {
		page, err := self.generationsPage(ctx, groupId, since)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		for _, signed := range page {
			parent, newest = newest, signed
		}
		since += uint64(len(page))
	}
	if newest == nil {
		return fmt.Errorf("%w: gkm holds no generation of the repo", ErrGkmKeyMissing)
	}
	parse := func(signed *bridge.Signed, number uint64) (*GkmGeneration, error) {
		signedBytes, err := gkmSignedBytes(signed)
		if err != nil {
			return nil, err
		}
		return client.parseServedGeneration(ctx, state, self.repoId, groupId, number, signedBytes)
	}
	generation, err := parse(newest, since)
	if err != nil {
		return err
	}
	var parentGeneration *GkmGeneration
	if 1 < since {
		parentGeneration, err = parse(parent, since-1)
		if err != nil {
			return err
		}
	}
	held, err := self.holdGenerationInFlow(ctx, state, groupId, generation, parentGeneration, false, client.clock.Now())
	if err != nil {
		return err
	}
	if held.key == nil {
		return fmt.Errorf("%w: no delivery of generation %d reached this device yet", ErrGkmKeyMissing, since)
	}
	if held.poisoned {
		// kept as poisoned, and no pin moved: a later rotation past it is taken at the next refresh
		return client.advancePins(self.repoId, func(pins *gkmRepoPins) { pins.groupId = groupId })
	}
	self.walkLadderForLater(ctx, state, groupId)
	return nil
}

// The walk row, from the newest generation this device opened down to through, 1 for the whole ladder; with
// through 0 it walks the whole ladder but stops at the first generation it already holds a key of, since an
// earlier walk went on from there. Each gen/<k> it does not hold is fetched and verified under its signer's key.
func (self *gkmGroupManager) walkLadderInFlow(ctx context.Context, state GkmAuthView, groupId Id, through uint64) error {
	client := self.client
	top, err := client.newestOpenedGeneration(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	stopAtHeld := through == 0
	through = max(through, 1)
	key := top.key
	// the statements gkm served for this walk, by generation
	fetched := map[uint64]*GkmGeneration{}
	fetch := func(number uint64) (*GkmGeneration, error) {
		if generation, ok := fetched[number]; ok {
			return generation, nil
		}
		// a page from the lowest generation the walk still needs, so one read serves many steps
		low := number
		for through < low && number-low < 255 {
			if _, err := client.heldGeneration(self.repoId, low-1); !errors.Is(err, ErrGkmKeyMissing) {
				break
			}
			low -= 1
		}
		page, err := self.generationsPage(ctx, groupId, low-1)
		if err != nil {
			return nil, err
		}
		for index, signed := range page {
			pageNumber := low + uint64(index)
			if number < pageNumber {
				break
			}
			signedBytes, err := gkmSignedBytes(signed)
			if err != nil {
				return nil, err
			}
			generation, err := client.parseServedGeneration(ctx, state, self.repoId, groupId, pageNumber, signedBytes)
			if err != nil {
				return nil, err
			}
			fetched[pageNumber] = generation
		}
		generation, ok := fetched[number]
		if !ok {
			return nil, fmt.Errorf("%w: gkm holds no gen/%d", ErrGkmKeyMissing, number)
		}
		return generation, nil
	}
	yield := client.newYield()
	for number := top.generation.Rotate.GetGeneration(); through < number; number -= 1 {
		yield.step()
		parent, err := client.heldGeneration(self.repoId, number-1)
		var statement *GkmGeneration
		switch {
		case err == nil && parent.key != nil:
			if stopAtHeld {
				return nil
			}
			key = parent.key
			continue
		case err == nil:
			statement = parent.generation
		case errors.Is(err, ErrGkmKeyMissing):
			statement, err = fetch(number - 1)
			if err != nil {
				return err
			}
		default:
			return err
		}
		opened, err := key.OpenParent(statement)
		if err != nil {
			return err
		}
		if err := client.putHeldGeneration(self.repoId, &gkmHeldGeneration{generation: statement, key: opened}); err != nil {
			return err
		}
		key = opened
	}
	return nil
}

// The newest generation, where this device holds it without its key, tried again: the epoch its leaf_wrap names may
// have been adopted since, or a late delivery may have come.
func (self *gkmGroupManager) openNewestInFlow(ctx context.Context, state GkmAuthView) error {
	client := self.client
	pins, err := client.repoPins(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	top, err := client.newestHeldGeneration(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) || err == nil && top.key != nil {
		return nil
	}
	if err != nil {
		return err
	}
	return self.openHeldGenerationInFlow(ctx, state, pins.groupId, top)
}

// The walk a refresh, a first wrap, a join and a sync make ahead of any read of an older generation. Its failure
// holds back nothing newer: the generation this device opened stands, and RepoKey walks again, with the error, when
// an older one is asked for.
func (self *gkmGroupManager) walkLadderForLater(ctx context.Context, state GkmAuthView, groupId Id) {
	if err := self.walkLadderInFlow(ctx, state, groupId, 0); err != nil && self.client.log.V(1).Enabled() {
		self.client.log.Infof("[gkm]the ladder walk stopped: %v", err)
	}
}

// How long before a drop key lapses a writer renews it with a SCHEDULE rotation, at its hourly resync and at gkm's
// renewal hint: 7 days (plan-KEYS-drop-key-lifetime's rule, which gkm's hint holds alike).
const gkmDropKeyRenewBefore = 7 * 24 * time.Hour
