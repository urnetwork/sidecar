//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// An authenticated indexer supplies a claim. The app still applies its own receipts, erasures, mail flags and
// signed log policy before showing it. All sources here are already held on this device.
func (self memberRequesterLocal) remoteRows(ctx context.Context, request *SearchRequest) (func(SearchHit) bool, func() bool) {
	engine, err := self.member.open()
	if err != nil {
		return func(SearchHit) bool { return false }, nil
	}
	source := engine.args.Scope.(*memberSearchSource)
	var previous *ConfigState
	var rules map[Id]func(SearchHit) bool
	scopes := map[Id]func() bool{}
	current := func() bool {
		for _, valid := range scopes {
			if !valid() {
				return false
			}
		}
		return true
	}
	return func(hit SearchHit) bool {
		state := source.state()
		if ctx.Err() != nil || state == nil || hit.Version == 0 || hit.Time.UnixMilli() <= 0 ||
			!request.Since.IsZero() && hit.Time.Before(request.Since) || !request.Until.IsZero() && hit.Time.After(request.Until) {
			return false
		}
		if previous != state {
			previous, rules = state, make(map[Id]func(SearchHit) bool)
		}
		accept, loaded := rules[hit.Repo]
		if !loaded {
			accept = source.remoteRowsFor(ctx, state, hit.Repo, request, scopes)
			rules[hit.Repo] = accept
		}
		return accept != nil && accept(hit)
	}, current
}

func (self *memberSearchSource) remoteRowsFor(ctx context.Context, state *ConfigState, repo Id, request *SearchRequest, scopes map[Id]func() bool) func(SearchHit) bool {
	row := state.Repo(repo)
	acl, err := state.Acl()
	if row == nil || err != nil {
		return nil
	}
	scope := &SearchScopeRepo{RepoId: repo, Kind: row.Kind, GroupInbox: AclRepoIsInbox(row)}
	subject := AclSidecarSubject(self.record.writer.sidecarId)
	var expectedRef *Id
	if name := memberSearchDefaultFileRef(row.Kind); name != "" {
		key, err := self.refKey(repo)
		if err != nil {
			return nil
		}
		if key != nil {
			ref, err := EvsRefId(key, []byte(name))
			if err != nil {
				return nil
			}
			expectedRef = &ref
		}
	}
	var prefix searchPrefixJudgeFunc
	if len(row.GetPrefixRules()) != 0 {
		prefix, err = searchPrefixJudgeOf(self.evs, repo)
		if err != nil || prefix == nil {
			return nil
		}
	}
	var valid func() bool
	var age time.Duration
	var record func(SearchHit, time.Time) bool
	mail := scope.GroupInbox || scope.Kind == protocol.RepoKind_REPO_KIND_MAILBOX
	if mail {
		valid = self.heldMail(repo)
	} else if scope.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		age, valid = self.directoryAge(repo)
	} else if memberSearchRecordKind(scope.Kind) {
		record, valid = self.remoteRecordRows(repo, scope.Kind)
	}
	if (mail || memberSearchRecordKind(scope.Kind)) && valid == nil {
		return nil
	}
	if valid != nil {
		scopes[repo] = valid
	}
	return func(hit SearchHit) bool {
		now := time.UnixMilli(max(state.timeMs, self.host.running.clock.Now().UnixMilli()))
		rights := acl.EvsAccess(subject, repo, AclTokenAudienceEvs, now).Rights
		if !rights.Has(AclEvsRead) || aclRepoKindOwnerBound(scope.Kind) && !rights.Has(AclEvsWrite) ||
			expectedRef != nil && hit.Ref != *expectedRef || valid != nil && !valid() ||
			uint64(hit.Time.Unix()) < searchSearchableSinceSeconds(now.UnixMilli(), age) {
			return false
		}
		if prefix != nil {
			answer, err := prefix(&searchPrefixAsk{refId: hit.Ref, path: hit.Path, version: hit.Version, newest: hit.Version})
			if err != nil || answer.unsearchable || answer.allowed != hit.Version {
				return false
			}
		}
		doc := &indexRow{docKind: indexDocKind(hit.DocKind), locator: hit.Path}
		if doc.docKind == IndexDocRecord {
			return record != nil && record(hit, now)
		}
		if !memberSearchIndexRow(scope, doc) {
			return false
		}
		if mail {
			keep, _, err := searchJoinMailHit(ctx, self, searchJoinAskOf(request), repo, doc)
			return err == nil && keep
		}
		return true
	}
}

// A signed stream copy fixes the entry's class, version, locator, signer and commit time. Only that class's current
// searchable_days and an entry whose key still stands can admit a record claim.
func (self *memberSearchSource) remoteRecordRows(repo Id, kind protocol.RepoKind) (func(SearchHit, time.Time) bool, func() bool) {
	reader := self.record.Reader()
	reader.stateLock.Lock()
	log := reader.logs[repo]
	if log == nil || !log.complete {
		reader.stateLock.Unlock()
		return nil, nil
	}
	revision := log.searchRevision
	reader.stateLock.Unlock()
	retention := self.record.Retention()
	policies := retention.governing(repo)
	valid := func() bool {
		reader.stateLock.Lock()
		defer reader.stateLock.Unlock()
		return log.complete && log.searchRevision == revision
	}
	return func(hit SearchHit, now time.Time) bool {
		reader.stateLock.Lock()
		defer reader.stateLock.Unlock()
		if !log.complete || log.searchRevision != revision {
			return false
		}
		class := log.remoteRecordClass(kind, hit)
		if class == RecordClassUnspecified {
			return false
		}
		policy := policies[class]
		return policy == nil || uint64(hit.Time.Unix()) >= searchSearchableSinceSeconds(now.UnixMilli(), memberSearchAge(policy.SearchableDays, retention.settings.Day))
	}, valid
}

// The verified reader lock is held. Each stream's pushes are ordered by version.
func (self *recordReadLog) remoteRecordClass(kind protocol.RepoKind, hit SearchHit) RecordClass {
	if _, ok := RecordStreamPathCounter(hit.Path); !ok {
		return RecordClassUnspecified
	}
	for writer, ref := range self.streamRefIds {
		if ref != hit.Ref {
			continue
		}
		pushes := self.streamPushes[writer]
		i, ok := slices.BinarySearchFunc(pushes, hit.Version, func(p *RecordReadPush, target uint64) int { return cmp.Compare(p.Version, target) })
		if !ok {
			break
		}
		for _, leaf := range pushes[i].Leaves {
			entry := self.leafEntries[leaf.Leaf]
			if entry == nil || entry.Header == nil || entry.State != RecordEntryLive || entry.BodyInvalid || entry.BodyGeneric ||
				!indexRecordIndexesEntry(kind, entry.Kind()) || recordIdOf(entry.Header.Header.GetWriterSidecarId()) != hit.Signer {
				continue
			}
			for _, copy := range entry.Copies {
				if copy.StreamSidecarId == writer && copy.Version == hit.Version && copy.Path == hit.Path && copy.TimeMillis/1000 == hit.Time.Unix() {
					return entry.Kind().Class()
				}
			}
		}
		break
	}
	return RecordClassUnspecified
}
