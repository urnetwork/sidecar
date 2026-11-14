// §22.7's assertions on stored state (TEST-M2-09; R-TEST-3, I-1, I-2, D-KEYS-3; owner decisions 2, 136): what the
// stores may hold and who may write it, beside the scan for canaries and keys, which server's sidecart3.CaptureStores
// runs on T3's real stores (CC3).
//
//   - Every stored commit but an external commit parses as a PrivateMessage, and in S3 and S4 GkmCommitHeader carries
//     only the generation and the auth pin (D-KEYS-3): CheckStoredCommits reads every gkm/<group_id>/epoch/<n> object
//     in every metadata cluster. An external commit is a PublicMessage whose sender is new_member_commit; a member's
//     commit in the clear, any other wire format, or bytes that are no MLSMessage at all fail.
//   - evs and gkm touch no Postgres and write Redis only in {scp_} hints, {wakeq_} wake entries, {nvb_} budget
//     reports, from M10 {evsd_} drop hints and the soft state {evsq_} {evsl_} {evsc_} {evsh_} {gka_}, and only api
//     writes {acl_}e: StoredWriters wraps the host each service is built with, so the check knows the writer as it
//     writes, never after the fact. Tasks is the host's Postgres-backed service (it writes Postgres wherever a process
//     holds a pool, §19.4), so a restricted service's call of it is a Postgres touch.
//
// Safe for concurrent use.

package sidecartest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// RFC 9420's MLSMessage framing, which every stored commit carries: version mls10, the wire formats a commit may
// travel as, and the sender a joiner's external commit names (§6, §12.4.3.2).
const (
	storedMlsVersion                uint16 = 1
	storedMlsWireFormatPublic       uint16 = 1
	storedMlsWireFormatPrivate      uint16 = 2
	storedMlsSenderNewMemberCommit  uint8  = 4
	storedMlsContentTypeCommit      uint8  = 3
	storedGkmCommitHeaderGeneration        = 1
	storedGkmCommitHeaderAuth              = 2
)

// gkm/<group_id>/epoch/<n>: an epoch object (gkmservice/objects.go), whose commit the assert reads.
var storedEpochKeyPattern = regexp.MustCompile(`^gkm/[^/]+/epoch/[0-9]{20}$`)

// The tests that hold §22.7's two stored-state clauses (TEST-M2-10's registry): each assert on its mutants here, and
// on T3's real stores in server's sidecart3. A scenario that runs them on a flow's stores (TEST-M2-11) adds its own.
var (
	_ = RegisterPrivacyAssert("stored-commits", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestAnExternalCommitPassesThePrivateMessageAssertAndAPlaintextBlobFails"})
	_ = RegisterPrivacyAssert("stored-commits", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestAGkmCommitHeaderCarriesOnlyTheGenerationAndThePin"})
	_ = RegisterPrivacyAssert("stored-commits", &PrivacyAssertTest{Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: "TestT3StoredCommitsArePrivateMessages", Tags: "sidecar_testhooks,sidecar_pending,sidecar_localstack"})
	_ = RegisterPrivacyAssert("store-writes", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestAWriteToAnUnlistedFamilyFails"})
	_ = RegisterPrivacyAssert("store-writes", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestOnlyApiWritesTheAclEpoch"})
	_ = RegisterPrivacyAssert("store-writes", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestAPlantedPostgresTouchFromEvsFails"})
	_ = RegisterPrivacyAssert("store-writes", &PrivacyAssertTest{Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: "TestT3APlantedPostgresTouchFromEvsFails", Tags: "sidecar_testhooks,sidecar_pending,sidecar_localstack"})
)

// A Redis family a service may write: keys whose hash tag starts with Tag and whose rest, past the tag, starts with
// Suffix.
type StoredRedisFamily struct {
	// The tag's first word with its underscore, "scp_" for {scp_<C>}ver.
	Tag string
	// What follows the tag, "e" for {acl_<network>}e; empty for any.
	Suffix string
	// What §22.7 calls it.
	Name string
}

// Whether key is of this family.
func (self *StoredRedisFamily) matches(key string) bool {
	tag, rest, ok := storedRedisTag(key)
	return ok && strings.HasPrefix(tag, self.Tag) && strings.HasPrefix(rest, self.Suffix)
}

func (self *StoredRedisFamily) String() string {
	return "{" + self.Tag + "}" + self.Suffix
}

// key's hash tag and what follows it, and whether it has one.
func storedRedisTag(key string) (string, string, bool) {
	if !strings.HasPrefix(key, "{") {
		return "", "", false
	}
	end := strings.IndexByte(key, '}')
	if end < 0 {
		return "", "", false
	}
	return key[1:end], key[end+1:], true
}

// What the stored-state asserts hold the stores and their writers to.
type StoredStateSettings struct {
	// The families each restricted service may write, by service: evs and gkm's, as §22.7 lists them. A service not
	// named here writes any family but another's owned one.
	ServiceFamilies map[string][]StoredRedisFamily
	// Families one service alone writes, by its name: api's {acl_}e (§7.9).
	OwnedFamilies map[string][]StoredRedisFamily
	// Services that touch no Postgres: evs and gkm (owner decisions 2, 136).
	NoPostgresServices []string
	// How many keys one LIST of a metadata cluster asks for: 1,000. Positive.
	ListPageCount int
	// The longest epoch object read: 4 MiB, past a commit's path and a sealed GroupInfo. Positive.
	MaxEpochObjectByteCount int64
}

func DefaultStoredStateSettings() *StoredStateSettings {
	evsAndGkm := []StoredRedisFamily{
		{Tag: "scp_", Name: "hints"},
		{Tag: "wakeq_", Name: "wake entries (§18.7)"},
		{Tag: "nvb_", Name: "budget reports (§11.13)"},
		{Tag: "evsd_", Name: "drop hints, from M10 (§11.13)"},
		{Tag: "evsq_", Name: "soft state"},
		{Tag: "evsl_", Name: "soft state"},
		{Tag: "evsc_", Name: "soft state"},
		{Tag: "evsh_", Name: "soft state"},
		{Tag: "gka_", Name: "soft state"},
	}
	return &StoredStateSettings{
		ServiceFamilies:         map[string][]StoredRedisFamily{"evs": evsAndGkm, "gkm": evsAndGkm},
		OwnedFamilies:           map[string][]StoredRedisFamily{"api": {{Tag: "acl_", Suffix: "e", Name: "the projection's epoch (§7.9)"}}},
		NoPostgresServices:      []string{"evs", "gkm"},
		ListPageCount:           1000,
		MaxEpochObjectByteCount: 4 * 1024 * 1024,
	}
}

// Every stored commit in blobs' metadata clusters held to §22.7's assert: each gkm/<group_id>/epoch/<n> object
// decodes as a GkmEpochObject, and its commit, when it has one, is a PrivateMessage of content type commit, or an
// external commit, a PublicMessage sent by new_member_commit. headerOnly adds S3's and S4's: the object's
// GkmCommitHeader, and the one a PrivateMessage carries in its authenticated_data, hold the generation and the auth
// pin and nothing else. Reads go under InspectContext, so they take no plan. Each finding names its object; an error
// is a store that could not be read, which is no pass.
func CheckStoredCommits(ctx context.Context, blobs sidecar.BlobStore, settings *StoredStateSettings, headerOnly bool) ([]string, error) {
	if settings == nil {
		settings = DefaultStoredStateSettings()
	}
	ctx = InspectContext(ctx)
	findings := []string{}
	for _, clusterId := range blobs.MetadataClusterIds() {
		cluster, err := blobs.Cluster(clusterId)
		if err != nil {
			return nil, err
		}
		startAfter := ""
		for {
			objects, more, err := cluster.List(ctx, "gkm/", startAfter, settings.ListPageCount)
			if err != nil {
				return nil, fmt.Errorf("listing cluster %s: %w", clusterId, err)
			}
			for _, object := range objects {
				startAfter = object.Key
				if !storedEpochKeyPattern.MatchString(object.Key) {
					continue
				}
				body, err := storedRead(ctx, cluster, object.Key, settings.MaxEpochObjectByteCount)
				if errors.Is(err, sidecar.ErrBlobNotFound) {
					// retention or a shred took it since the LIST
					continue
				}
				if err != nil {
					return nil, err
				}
				for _, problem := range storedEpochProblems(body, headerOnly) {
					findings = append(findings, fmt.Sprintf("cluster %s %s: %s", clusterId, object.Key, problem))
				}
			}
			if !more {
				break
			}
		}
	}
	return findings, nil
}

// An object's bytes, up to limit, past which it fails.
func storedRead(ctx context.Context, cluster sidecar.BlobCluster, key string, limit int64) ([]byte, error) {
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	body, err := io.ReadAll(io.LimitReader(object.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if limit < int64(len(body)) {
		return nil, fmt.Errorf("%s holds over %d bytes", key, limit)
	}
	return body, nil
}

// What breaks the assert in one epoch object's bytes.
func storedEpochProblems(body []byte, headerOnly bool) []string {
	epochObject := &protocol.GkmEpochObject{}
	if err := proto.Unmarshal(body, epochObject); err != nil {
		return []string{fmt.Sprintf("no GkmEpochObject: %v", err)}
	}
	problems := []string{}
	if headerOnly && epochObject.GetHeader() != nil {
		problems = append(problems, storedHeaderProblems("its GkmCommitHeader", epochObject.GetHeader())...)
	}
	commit := epochObject.GetCommit()
	if len(commit) == 0 {
		// epoch 0's object carries no commit
		return problems
	}
	external, err := storedExternalCommit(commit)
	switch {
	case err != nil:
		return append(problems, err.Error())
	case external:
		return problems
	}
	header, err := sidecar.ParseMlsHeader(commit)
	if err != nil {
		return append(problems, fmt.Sprintf("its commit is no PrivateMessage gkm could read: %v", err))
	}
	if header.External != nil || header.ContentType != storedMlsContentTypeCommit {
		return append(problems, "its commit is no member's PrivateMessage commit")
	}
	if headerOnly {
		commitHeader := &protocol.GkmCommitHeader{}
		if err := proto.Unmarshal(header.AuthenticatedData, commitHeader); err != nil {
			return append(problems, fmt.Sprintf("its commit's authenticated_data is no GkmCommitHeader: %v", err))
		}
		problems = append(problems, storedHeaderProblems("its commit's GkmCommitHeader", commitHeader)...)
	}
	return problems
}

// Whether commit is an external commit, a PublicMessage from new_member_commit; an error for a PublicMessage from
// anyone else, which is a member's commit in the clear, and for any wire format but the two a commit travels as.
func storedExternalCommit(commit []byte) (bool, error) {
	if len(commit) < 4 || binary.BigEndian.Uint16(commit[0:2]) != storedMlsVersion {
		return false, errors.New("its commit is no MLSMessage of version mls10")
	}
	switch binary.BigEndian.Uint16(commit[2:4]) {
	case storedMlsWireFormatPrivate:
		return false, nil
	case storedMlsWireFormatPublic:
	default:
		return false, fmt.Errorf("its commit travels as wire format %d, neither a PrivateMessage nor an external commit", binary.BigEndian.Uint16(commit[2:4]))
	}
	rest := commit[4:]
	// FramedContent: group_id<V>, epoch, then the sender's type (RFC 9420 §6)
	groupIdByteCount, rest, ok := storedMlsVectorLength(rest)
	if !ok || len(rest) < groupIdByteCount+8+1 {
		return false, errors.New("its commit is a PublicMessage too short to name its sender")
	}
	if sender := rest[groupIdByteCount+8]; sender != storedMlsSenderNewMemberCommit {
		return false, fmt.Errorf("its commit is a PublicMessage from sender type %d: a member's commit in the clear", sender)
	}
	return true, nil
}

// An opaque<V>'s length (RFC 9420 §2.1.2) and what follows its prefix.
func storedMlsVectorLength(data []byte) (int, []byte, bool) {
	if len(data) == 0 {
		return 0, nil, false
	}
	switch data[0] >> 6 {
	case 0:
		return int(data[0] & 0x3f), data[1:], true
	case 1:
		if len(data) < 2 {
			return 0, nil, false
		}
		return int(binary.BigEndian.Uint16(data[0:2]) & 0x3fff), data[2:], true
	case 2:
		if len(data) < 4 {
			return 0, nil, false
		}
		return int(binary.BigEndian.Uint32(data[0:4]) & 0x3fffffff), data[4:], true
	}
	return 0, nil, false
}

// What a GkmCommitHeader holds beyond the generation and the auth pin (D-KEYS-3): any other field it was given, and
// anything unknown it carries.
func storedHeaderProblems(what string, header *protocol.GkmCommitHeader) []string {
	problems := []string{}
	header.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if number := field.Number(); number != storedGkmCommitHeaderGeneration && number != storedGkmCommitHeaderAuth {
			problems = append(problems, fmt.Sprintf("%s carries field %s", what, field.Name()))
		}
		return true
	})
	if unknown := header.ProtoReflect().GetUnknown(); 0 < len(unknown) {
		problems = append(problems, fmt.Sprintf("%s carries %d bytes beyond the generation and the auth pin", what, len(unknown)))
	}
	return problems
}

// One write a service made to Redis.
type storedRedisWrite struct {
	service string
	op      string
	key     string
}

// One call of a Postgres-backed host service a service made.
type storedPostgresTouch struct {
	service string
	call    string
}

// What each service wrote to the stores, as the hosts StoredWriters gave them told it.
type StoredWriters struct {
	settings *StoredStateSettings

	stateLock       sync.Mutex
	redisWrites     []*storedRedisWrite
	postgresTouches []*storedPostgresTouch
}

// settings nil takes the defaults.
func NewStoredWriters(settings *StoredStateSettings) *StoredWriters {
	if settings == nil {
		settings = DefaultStoredStateSettings()
	}
	return &StoredWriters{settings: settings}
}

// host as service is built with it: its Redis's writes are recorded as service's, and so is each call of its Tasks,
// the host's Postgres-backed service. Every other field is host's.
func (self *StoredWriters) Host(service string, host *sidecar.ServiceHost) *sidecar.ServiceHost {
	hostCopy := *host
	if host.Redis != nil {
		hostCopy.Redis = &storedWriterRedis{redis: host.Redis, writers: self, service: service}
	}
	if host.Tasks != nil {
		hostCopy.Tasks = &storedWriterTasks{tasks: host.Tasks, writers: self, service: service}
	}
	return &hostCopy
}

func (self *StoredWriters) redisWrite(service string, op string, keys []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, key := range keys {
		self.redisWrites = append(self.redisWrites, &storedRedisWrite{service: service, op: op, key: key})
	}
}

func (self *StoredWriters) postgresTouch(service string, call string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.postgresTouches = append(self.postgresTouches, &storedPostgresTouch{service: service, call: call})
}

// Each write or touch that breaks §22.7's assert, naming the service, the call and the key, the first of each
// service, operation and family alone.
func (self *StoredWriters) Check() []string {
	var redisWrites []*storedRedisWrite
	var postgresTouches []*storedPostgresTouch
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		redisWrites = slices.Clone(self.redisWrites)
		postgresTouches = slices.Clone(self.postgresTouches)
	}()
	findings := []string{}
	seen := map[string]bool{}
	note := func(seenKey string, finding string) {
		if !seen[seenKey] {
			seen[seenKey] = true
			findings = append(findings, finding)
		}
	}
	for _, touch := range postgresTouches {
		if slices.Contains(self.settings.NoPostgresServices, touch.service) {
			note(touch.service+" "+touch.call, fmt.Sprintf("%s touched Postgres: %s, a Postgres-backed host service, which no %s process holds (owner decisions 2, 136)", touch.service, touch.call, touch.service))
		}
	}
	for _, write := range redisWrites {
		tag, _, _ := storedRedisTag(write.key)
		for owner, families := range self.settings.OwnedFamilies {
			for _, family := range families {
				if owner != write.service && family.matches(write.key) {
					note(write.service+" "+write.op+" "+family.String(), fmt.Sprintf("%s wrote %s by %s, which %s alone writes: %s", write.service, write.key, write.op, owner, family.String()))
				}
			}
		}
		families, restricted := self.settings.ServiceFamilies[write.service]
		if !restricted {
			continue
		}
		allowed := slices.ContainsFunc(families, func(family StoredRedisFamily) bool { return family.matches(write.key) })
		if !allowed {
			note(write.service+" "+write.op+" "+tag, fmt.Sprintf("%s wrote %s by %s, outside the families §22.7 lets it write", write.service, write.key, write.op))
		}
	}
	return findings
}

// sidecar.Redis that records each write as its service's, then makes it.
type storedWriterRedis struct {
	redis   sidecar.Redis
	writers *StoredWriters
	service string
}

var _ sidecar.Redis = (*storedWriterRedis)(nil)

func (self *storedWriterRedis) wrote(op string, keys ...string) {
	self.writers.redisWrite(self.service, op, keys)
}

func (self *storedWriterRedis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return self.redis.Get(ctx, key)
}

func (self *storedWriterRedis) GetMany(ctx context.Context, keys []string) ([][]byte, error) {
	return self.redis.GetMany(ctx, keys)
}

func (self *storedWriterRedis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	self.wrote("set", key)
	return self.redis.Set(ctx, key, value, ttl)
}

func (self *storedWriterRedis) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	self.wrote("setnx", key)
	return self.redis.SetIfAbsent(ctx, key, value, ttl)
}

func (self *storedWriterRedis) CompareAndSet(ctx context.Context, key string, expected []byte, value []byte, ttl time.Duration) (bool, error) {
	self.wrote("cas", key)
	return self.redis.CompareAndSet(ctx, key, expected, value, ttl)
}

func (self *storedWriterRedis) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	self.wrote("cad", key)
	return self.redis.CompareAndDelete(ctx, key, expected)
}

func (self *storedWriterRedis) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	self.wrote("incr", key)
	return self.redis.Increment(ctx, key, ttl)
}

func (self *storedWriterRedis) Delete(ctx context.Context, keys []string) error {
	self.wrote("del", keys...)
	return self.redis.Delete(ctx, keys)
}

func (self *storedWriterRedis) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	self.wrote("expire", key)
	return self.redis.Expire(ctx, key, ttl)
}

func (self *storedWriterRedis) HashGet(ctx context.Context, key string, field string) ([]byte, bool, error) {
	return self.redis.HashGet(ctx, key, field)
}

func (self *storedWriterRedis) HashGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	return self.redis.HashGetAll(ctx, key)
}

func (self *storedWriterRedis) HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error {
	self.wrote("hset", key)
	return self.redis.HashSet(ctx, key, fieldValues)
}

func (self *storedWriterRedis) HashDelete(ctx context.Context, key string, fields []string) error {
	self.wrote("hdel", key)
	return self.redis.HashDelete(ctx, key, fields)
}

func (self *storedWriterRedis) HashExpire(ctx context.Context, key string, fields []string, ttl time.Duration) error {
	self.wrote("hexpire", key)
	return self.redis.HashExpire(ctx, key, fields, ttl)
}

func (self *storedWriterRedis) StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	self.wrote("xadd", key)
	return self.redis.StreamAdd(ctx, key, maxLength, fieldValues)
}

func (self *storedWriterRedis) StreamRange(ctx context.Context, key string, afterEntryId string, count int64) ([]*sidecar.RedisStreamEntry, error) {
	return self.redis.StreamRange(ctx, key, afterEntryId, count)
}

func (self *storedWriterRedis) StreamGroupCreate(ctx context.Context, key string, group string) error {
	self.wrote("xgroup", key)
	return self.redis.StreamGroupCreate(ctx, key, group)
}

// A group read moves the group's pending list, so it writes.
func (self *storedWriterRedis) StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) ([]*sidecar.RedisStreamEntry, error) {
	self.wrote("xreadgroup", key)
	return self.redis.StreamGroupRead(ctx, key, group, consumer, count, block)
}

func (self *storedWriterRedis) StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error {
	self.wrote("xack", key)
	return self.redis.StreamGroupAck(ctx, key, group, entryIds)
}

func (self *storedWriterRedis) StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) ([]*sidecar.RedisStreamEntry, string, error) {
	self.wrote("xautoclaim", key)
	return self.redis.StreamGroupClaim(ctx, key, group, consumer, minIdle, cursor, count)
}

// A script may write every key it names, so each counts as written.
func (self *storedWriterRedis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	name := ""
	if script != nil {
		name = script.Name
	}
	self.wrote("script:"+name, keys...)
	return self.redis.RunScript(ctx, script, keys, args)
}

func (self *storedWriterRedis) AddKeyEventCallback(keyPattern string, callback sidecar.RedisKeyEventFunction) (func(), error) {
	return self.redis.AddKeyEventCallback(keyPattern, callback)
}

// sidecar.Tasks that records each call as its service's Postgres touch, then makes it.
type storedWriterTasks struct {
	tasks   sidecar.Tasks
	writers *StoredWriters
	service string
}

var _ sidecar.Tasks = (*storedWriterTasks)(nil)

// Binding a job writes nothing, so it is no touch.
func (self *storedWriterTasks) Register(name string, function sidecar.TaskFunction) {
	self.tasks.Register(name, function)
}

func (self *storedWriterTasks) Schedule(ctx context.Context, request *sidecar.TaskRequest) error {
	call := "Tasks.Schedule"
	if request != nil {
		call += " " + request.Name
	}
	self.writers.postgresTouch(self.service, call)
	return self.tasks.Schedule(ctx, request)
}
