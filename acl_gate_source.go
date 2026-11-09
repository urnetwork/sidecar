//go:build !sidecar_http

// Where a gate reads a network's authorization log (§8.9, §7.9's read row). api, evs and gkm read the first metadata
// cluster themselves (AclGateDirectSource); other gate services fetch from api, whose route is question
// plan-SOCK-gate-data's (C-09), so a host with no source loads nothing and its gates stay not ready.
//
// AclGateDirectSource reads §7.9's verified read cache {acl_<networkId>}e only when the hash records {acl_}v's current
// value and holds every position a reload needs, else proj/. The cache decides nothing: AclGateCache checks every
// entry's chain from its own pin wherever it came from (ConfigLog.ApplyRun), so a stale or lost copy costs proj/ reads
// and never a lower n. Only api writes {acl_}e, in the one script that INCRs {acl_}v after each append (TEAM-M2-14);
// this file has no write path to it, and names its hash fields so that script writes what this reads:
//
//	b       the newest base's position, decimal
//	m       the tip, decimal
//	v       the {acl_}v value the hash matches, decimal, as INCR leaves it
//	<n>     entry n's AuthEntry bytes, verbatim, for n from b to m, decimal with no padding
//
// A cold start lists proj/<network_id>/ from position 1, every entry the store retains, since a base's tail before it
// is no part of {acl_}e and RestoreConfigLogRowsOnly needs it.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Every network's {acl_}v, the one family a gate process watches on ServiceHost.Redis's shared subscriber (§8.9).
const AclVersionKeyPattern = "{acl_*}v"

// {acl_}e's hash fields, but for entries, which are their decimal positions.
const (
	AclEntryCacheFieldBase    = "b"
	AclEntryCacheFieldTip     = "m"
	AclEntryCacheFieldVersion = "v"
)

// {acl_<networkId>}v: api INCRs it after every entry it appends (§8.9), class $ in the keyspace events.
func AclVersionKey(networkId Id) string {
	return "{acl_" + networkId.String() + "}v"
}

// {acl_<networkId>}e, in {acl_}v's hash tag.
func AclEntryCacheKey(networkId Id) string {
	return "{acl_" + networkId.String() + "}e"
}

// The {acl_}e field of entry n.
func AclEntryCacheField(n uint64) string {
	return strconv.FormatUint(n, 10)
}

// The network whose {acl_}v key is key, false for any other key.
func ParseAclVersionKey(key string) (Id, bool) {
	rest, found := strings.CutPrefix(key, "{acl_")
	if !found {
		return Id{}, false
	}
	idText, found := strings.CutSuffix(rest, "}v")
	if !found {
		return Id{}, false
	}
	networkId, err := ParseId(idText)
	if err != nil {
		return Id{}, false
	}
	return networkId, true
}

// Where AclGateCache reads a network's log. Safe for concurrent use; each call reads what the store holds now.
type AclGateSource interface {
	// The network's Signed Genesis, verbatim, as proj/'s entry 0 holds it (plan-TEAM-genesis-custody).
	Genesis(ctx context.Context, networkId Id) ([]byte, error)
	// The entries after after, verbatim and in position order, through the tip; for a cold start, after nil, every entry
	// the store retains from position 1 on. The caller checks every link.
	Entries(ctx context.Context, networkId Id, after *bridge.AuthPin) ([][]byte, error)
	// A base's rows by rows_sha256, verbatim (projrows/).
	Rows(ctx context.Context, networkId Id, rowsSha256 []byte) ([]byte, error)
}

// api's, evs's and gkm's AclGateSource: {acl_}e when it matches {acl_}v and holds every position needed, else proj/
// and projrows/ on the first metadata cluster. Safe for concurrent use.
type AclGateDirectSource struct {
	redis    Redis
	blobs    BlobStore
	settings *AclGateSettings
}

// The source over a host's Redis and file clusters. A nil redis reads proj/ alone.
func NewAclGateDirectSource(redis Redis, blobs BlobStore, settings *AclGateSettings) *AclGateDirectSource {
	if settings == nil {
		settings = DefaultAclGateSettings()
	}
	return &AclGateDirectSource{redis: redis, blobs: blobs, settings: settings}
}

// The bytes of one object on the first metadata cluster, ErrBlobNotFound when it is not there.
func (self *AclGateDirectSource) get(ctx context.Context, key string) ([]byte, error) {
	if self.blobs == nil {
		return nil, ErrBlobClusterUnknown
	}
	cluster, err := self.blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	return io.ReadAll(object.Body)
}

// proj/'s entry 0.
func (self *AclGateDirectSource) Genesis(ctx context.Context, networkId Id) ([]byte, error) {
	return self.get(ctx, ConfigEntryKey(networkId, 0))
}

// projrows/'s object.
func (self *AclGateDirectSource) Rows(ctx context.Context, networkId Id, rowsSha256 []byte) ([]byte, error) {
	return self.get(ctx, ConfigRowsKey(networkId, rowsSha256))
}

// {acl_}e's entries when they serve, else proj/'s.
func (self *AclGateDirectSource) Entries(ctx context.Context, networkId Id, after *bridge.AuthPin) ([][]byte, error) {
	if after != nil && self.redis != nil {
		if entries, ok := self.cachedEntries(ctx, networkId, after.GetVersion()); ok {
			return entries, nil
		}
	}
	return self.storedEntries(ctx, networkId, after)
}

// The entries after position after from {acl_}e, false when it does not record {acl_}v's current value, does not
// hold every position from after+1 to its tip, or cannot be read: §7.9's read row.
func (self *AclGateDirectSource) cachedEntries(ctx context.Context, networkId Id, after uint64) ([][]byte, bool) {
	version, found, err := self.redis.Get(ctx, AclVersionKey(networkId))
	if err != nil || !found {
		return nil, false
	}
	fieldValues, err := self.redis.HashGetAll(ctx, AclEntryCacheKey(networkId))
	if err != nil || len(fieldValues) == 0 || !bytes.Equal(fieldValues[AclEntryCacheFieldVersion], version) {
		return nil, false
	}
	parse := func(field string) (uint64, bool) {
		n, err := strconv.ParseUint(string(fieldValues[field]), 10, 64)
		return n, err == nil
	}
	base, baseOk := parse(AclEntryCacheFieldBase)
	tip, tipOk := parse(AclEntryCacheFieldTip)
	if !baseOk || !tipOk || tip < base || (after < tip && after+1 < base) {
		return nil, false
	}
	entries := [][]byte{}
	for n := after + 1; n <= tip; n += 1 {
		entryBytes, found := fieldValues[AclEntryCacheField(n)]
		if !found {
			return nil, false
		}
		entries = append(entries, entryBytes)
	}
	return entries, true
}

// The entries after after from proj/, in position order, a page of keys at a time; a cold start from position 1.
func (self *AclGateDirectSource) storedEntries(ctx context.Context, networkId Id, after *bridge.AuthPin) ([][]byte, error) {
	if self.blobs == nil {
		return nil, ErrBlobClusterUnknown
	}
	cluster, err := self.blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	startAfter := ConfigEntryKey(networkId, 0)
	if after != nil {
		startAfter = ConfigEntryKey(networkId, after.GetVersion())
	}
	pageCount := max(1, self.settings.ListPageCount)
	entries := [][]byte{}
	for {
		objects, more, err := cluster.List(ctx, ConfigEntryKeyPrefix(networkId), startAfter, pageCount)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			if _, ok := ParseConfigEntryKey(networkId, object.Key); !ok {
				continue
			}
			entryBytes, err := self.get(ctx, object.Key)
			if errors.Is(err, ErrBlobNotFound) {
				// retention deleted it between the list and the read: the run starts later, which the caller checks
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("proj/ %s: %w", object.Key, err)
			}
			entries = append(entries, entryBytes)
		}
		if !more || len(objects) == 0 {
			return entries, nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}
