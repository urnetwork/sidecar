//go:build !ios_extension

// A push in parts (§11.8's parts, lease and seal rows; D-EVS-20): past 1 MiB or 1,024 entry writes the statement
// signs part_count, parts_sha256 and changes_root, each part posts to .../push/<P>/<k> with the receipts of the
// segments its entry versions name, at most PartConcurrency at once, and the seal posts the statement with the
// parts' places, in part order, which evs answers as a one-part push. Git mode first takes the seal lease, after
// its segments and before its parts, so no other push lands on its tip meanwhile; an expired lease costs only a
// refused seal, since the seal still commits only by TIP.
//
// A part's answer is evs's record of it, never a commit: a part posted twice is two records and the seal names one.
// A seal answered 409 PARTS_MISSING, which records and refuses nothing, posts the parts again and seals the same
// push id again, at most PartsMissingRetryCount times. A kill between parts leaves records no seal names, which
// evacuation drops; nothing of them is visible (§11.8's linearizability).
//
// On every leg.

package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// Posts attempt's parts, then its seal, git mode's lease first.
func (self *EvsRepo) sendParts(ctx context.Context, attempt *evsPushAttempt) (*protocol.EvsPushReply, error) {
	if attempt.refMode == protocol.EvsRefMode_EVS_REF_GIT {
		if err := self.takeLease(ctx, attempt); err != nil {
			return nil, err
		}
	}
	for tries := 0; ; tries += 1 {
		places, err := self.postParts(ctx, attempt)
		if err != nil {
			return nil, err
		}
		reply, err := self.postPush(ctx, attempt.pushId, &protocol.EvsPushRequest{Statement: attempt.built.Statement.Bytes, PartPlaces: places})
		if IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING) && tries < self.client.settings.PartsMissingRetryCount {
			continue
		}
		return reply, err
	}
}

// Posts every part, at most PartConcurrency at once, and gives their places in part order. The first refusal ends the
// rest and is answered.
func (self *EvsRepo) postParts(ctx context.Context, attempt *evsPushAttempt) ([]*protocol.EvsPlace, error) {
	parts := attempt.built.Parts
	places := make([]*protocol.EvsPlace, len(parts))
	partCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan int)
	errs := make(chan error, len(parts))
	wait := sync.WaitGroup{}
	for range max(1, min(self.client.settings.PartConcurrency, len(parts))) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range work {
				place, err := self.postPart(partCtx, attempt, index)
				if err != nil {
					errs <- err
					cancel()
					continue
				}
				places[index] = place
			}
		}()
	}
	func() {
		defer close(work)
		for index := range parts {
			select {
			case work <- index:
			case <-partCtx.Done():
				return
			}
		}
	}()
	wait.Wait()
	close(errs)
	for err := range errs {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, place := range places {
		if place == nil {
			return nil, fmt.Errorf("%w: a part answered with no place", ErrEvsReplyInvalid)
		}
	}
	return places, nil
}

// POST .../push/<P>/<k> for part index (k = index + 1), retried as a push is.
func (self *EvsRepo) postPart(ctx context.Context, attempt *evsPushAttempt, index int) (*protocol.EvsPlace, error) {
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/push/{push_id}/{part}",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/push/" + evsUrlId(attempt.pushId) + "/" + strconv.Itoa(index+1),
		repoId: self.repoId,
		role:   evsScopeWrite,
		body: &protocol.EvsPartRequest{
			Statement: attempt.built.Statement.Bytes, Part: attempt.built.Parts[index], Receipts: attempt.partReceipts[index],
		},
	}
	reply := &protocol.EvsPushReply{}
	err := self.client.retryRefusingNothing(ctx, func() error {
		reply = &protocol.EvsPushReply{}
		return self.client.http.callMessage(ctx, call, reply)
	})
	if err != nil {
		return nil, err
	}
	return reply.GetPlace(), nil
}

// POST .../push/<P>/lease {ref_id, base_version, ms}: the seal lease of a git-mode push, retried while another push's
// lease answers 429.
func (self *EvsRepo) takeLease(ctx context.Context, attempt *evsPushAttempt) error {
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/push/{push_id}/lease",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/push/" + evsUrlId(attempt.pushId) + "/lease",
		repoId: self.repoId,
		role:   evsScopeWrite,
		body: &protocol.EvsLeaseRequest{
			RefId: attempt.refId.Bytes(), BaseVersion: attempt.baseVersion,
			Ms: uint32(self.client.settings.SealLeaseDuration.Milliseconds()),
		},
	}
	return self.client.retryRefusingNothing(ctx, func() error { return self.client.http.callMessage(ctx, call, nil) })
}
