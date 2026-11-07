//go:build !sidecar_http

package sidecar

import (
	"context"
	"testing"
	"time"
)

// The cases of Redis Cluster's own specification, and the design's families.
func TestRedisHashTag(t *testing.T) {
	for _, c := range []struct {
		key  string
		want string
	}{
		{key: "{user1000}.following", want: "user1000"},
		{key: "{user1000}.followers", want: "user1000"},
		{key: "foo{}{bar}", want: "foo{}{bar}"},
		{key: "foo{{bar}}zap", want: "{bar"},
		{key: "foo{bar}{zap}", want: "bar"},
		{key: "no-tag", want: "no-tag"},
		{key: "open{only", want: "open{only"},
		{key: "close}only", want: "close}only"},
		{key: "", want: ""},
		{key: "{scp_c1}ver", want: "scp_c1"},
		{key: "{scp_c1}n", want: "scp_c1"},
		{key: "{sg_n1_0123456789abcdef}ix", want: "sg_n1_0123456789abcdef"},
		{key: "{dpop_c1}jti", want: "dpop_c1"},
		{key: "{dns}serial:root.example", want: "dns"},
	} {
		if got := RedisHashTag(c.key); got != c.want {
			t.Errorf("%q: %q, want %q", c.key, got, c.want)
		}
	}
}

func TestRedisKeysShareTag(t *testing.T) {
	for _, c := range []struct {
		keys []string
		want bool
	}{
		{keys: nil, want: true},
		{keys: []string{"{scp_c1}ack"}, want: true},
		// one key is no multi-key call, so §22.4 asks it for no tag
		{keys: []string{"plain"}, want: true},
		// §18.7's MGET of ack, tok and tokrev
		{keys: []string{"{scp_c1}ack", "{scp_c1}tok", "{scp_c1}tokrev"}, want: true},
		{keys: []string{"{scp_c1}ack", "{scp_c2}tok"}, want: false},
		// no tag at all: two plain keys, which production answers CROSSSLOT
		{keys: []string{"plain-a", "plain-b"}, want: false},
		{keys: []string{"{evsl_r1}", "{evsl_r1}v"}, want: true},
		// the same slot by luck: each pair hashes alike, and none shares a tag, so §22.4 refuses it
		{keys: []string{"plain", "plain"}, want: false},
		{keys: []string{"scp_c1", "{scp_c1}n"}, want: false},
		{keys: []string{"{scp_c1}n", "scp_c1"}, want: false},
		{keys: []string{"{a}x", "a"}, want: false},
		{keys: []string{"{a}x", "{a}y", "a"}, want: false},
		// an empty {} is no tag, so the whole key hashes
		{keys: []string{"a{}", "a{}"}, want: false},
	} {
		if got := RedisKeysShareTag(c.keys); got != c.want {
			t.Errorf("%q: %v, want %v", c.keys, got, c.want)
		}
	}
}

// What each design consumer calls, so a method dropped from Redis stops the build here with its
// consumer named. These are interfaces, so a Redis satisfies each with no adapter: §6.8's
// PublisherRedis in particular can be declared in pushservice as a subset of it.
type (
	// §6.8: GET, HGETALL, XRANGE, the ack script, §18.7's {scp_<C>}live refresh.
	publisherRedisConsumer interface {
		Get(ctx context.Context, key string) ([]byte, bool, error)
		HashGetAll(ctx context.Context, key string) (map[string][]byte, error)
		StreamRange(ctx context.Context, key string, afterEntryId string, count int64) ([]*RedisStreamEntry, error)
		RunScript(ctx context.Context, script *RedisScript, keys []string, args []string) (*RedisReply, error)
		Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	}
	// §18.7 and §19.4: the wake sender's consumer group and its MGET of ack, tok and tokrev.
	wakeSenderRedisConsumer interface {
		StreamGroupCreate(ctx context.Context, key string, group string) error
		StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) ([]*RedisStreamEntry, error)
		StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error
		StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) ([]*RedisStreamEntry, string, error)
		GetMany(ctx context.Context, keys []string) ([][]byte, error)
	}
	// §6.8's long-poll: SET {scp_<C>}hb 1 NX EX 300. §7.4 uses the same for a DPoP jti.
	onceOnlyRedisConsumer interface {
		SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	}
	// §9.8: hash fields with their own ttl, and one group-key script a Find.
	socketsRedisConsumer interface {
		HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error
		HashExpire(ctx context.Context, key string, fields []string, ttl time.Duration) error
		HashDelete(ctx context.Context, key string, fields []string) error
		RunScript(ctx context.Context, script *RedisScript, keys []string, args []string) (*RedisReply, error)
	}
	// §10.6: {gka_<group_id>} acks, written at most daily, read by the reconciler.
	gkmAckRedisConsumer interface {
		HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error
		HashGet(ctx context.Context, key string, field string) ([]byte, bool, error)
		HashGetAll(ctx context.Context, key string) (map[string][]byte, error)
		Expire(ctx context.Context, key string, ttl time.Duration) (bool, error)
		Delete(ctx context.Context, keys []string) error
	}
	// §4.5: cas, incr, and keyspace events only through the shared subscriber.
	leaseRedisConsumer interface {
		CompareAndSet(ctx context.Context, key string, expected []byte, value []byte, ttl time.Duration) (bool, error)
		CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error)
		Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
		AddKeyEventCallback(keyPattern string, callback RedisKeyEventFunction) (func(), error)
	}
)

var (
	_ publisherRedisConsumer  = Redis(nil)
	_ wakeSenderRedisConsumer = Redis(nil)
	_ onceOnlyRedisConsumer   = Redis(nil)
	_ socketsRedisConsumer    = Redis(nil)
	_ gkmAckRedisConsumer     = Redis(nil)
	_ leaseRedisConsumer      = Redis(nil)
)

// A script that returns nothing reads as nil with no fields set, so a caller's zero value is safe.
func TestRedisReplyZeroValueIsNil(t *testing.T) {
	if (RedisReply{}).Kind != RedisReplyNil {
		t.Error("the zero reply is not a nil reply")
	}
}
