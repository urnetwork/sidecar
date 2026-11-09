// The client's slot {scp_<C>} (§6.8, §18.7; §2.8's connect-4 and api-6) and the stores this package
// reads and writes it through. Every key of one client shares the tag {scp_<C>}, so a script on it never
// spans two slots, and no command here names two clients.
//
//	{scp_<C>}ver    hash: topic to version, raised only by the hint script
//	{scp_<C>}hint   stream: seq, topic, version, kind and hint, MAXLEN ~256
//	{scp_<C>}n      string: the INCR whose value is a hint's seq and whose event is the trigger
//	{scp_<C>}tok    §18.7's wake token projection, which the hint script only reads (absent until M8)
//	{scp_<C>}live   §18.7's resident marker, which the hint script only reads (absent until M8)
//	{scp_<C>}ack    §18.7's highest acked stream id, which the ack script raises
//	{scp_<C>}hb     §18.8's poll marker, which api's long-poll sets
//
// ver, hint and n live an hour from their creation (EXPIRE NX), so a client's n restarts at most once
// an hour, which its next hint shows it as a seq gap.

package pushservice

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What the hint writer runs on: ServiceHost.Redis, which satisfies it, or server's model adapter for
// api's own topics. Safe for concurrent use.
type HintRedis interface {
	// See sidecar.Redis.
	RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error)
}

// What a publisher reads and writes (§6.8's PublisherEnv.Redis): GET, HGETALL, XRANGE, the ack script
// and §18.7's live refresh. ServiceHost.Redis satisfies it, and so does server's model adapter. Safe for
// concurrent use.
type PublisherRedis interface {
	HintRedis
	// See sidecar.Redis.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
	// See sidecar.Redis.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// See sidecar.Redis.
	HashGetAll(ctx context.Context, key string) (fieldValues map[string][]byte, err error)
	// See sidecar.Redis.
	StreamRange(ctx context.Context, key string, afterEntryId string, count int64) (entries []*sidecar.RedisStreamEntry, err error)
}

// The tag every key of one client's slot carries: {scp_<C>}, the client id in its UUID form. Each key
// below writes its family out whole, as §2.8's rows name it (I-18).
func HintTag(clientId connect.Id) string {
	return "{" + sidecar.RedisHashTag(HintSeqKey(clientId)) + "}"
}

// {scp_<C>}ver.
func HintVersionsKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}ver"
}

// {scp_<C>}hint.
func HintStreamKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}hint"
}

// {scp_<C>}n.
func HintSeqKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}n"
}

// {scp_<C>}tok.
func HintTokenKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}tok"
}

// {scp_<C>}live.
func HintLiveKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}live"
}

// {scp_<C>}ack.
func HintAckKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}ack"
}

// {scp_<C>}hb.
func HintPollKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}hb"
}

// The family of every client's n, which a process's one shared subscriber watches: never a pattern per
// client (host_redis.go).
const HintSeqKeyPattern = "{scp_*}n"

// The client whose n key is key, or false for any other key.
func ParseHintSeqKey(key string) (connect.Id, bool) {
	rest, found := strings.CutPrefix(key, "{scp_")
	if !found {
		return connect.Id{}, false
	}
	idText, found := strings.CutSuffix(rest, "}n")
	if !found {
		return connect.Id{}, false
	}
	clientId, err := connect.ParseId(idText)
	if err != nil {
		return connect.Id{}, false
	}
	return clientId, true
}

// A hint entry's fields, as the hint script writes them (reading 5: seq is the INCR's value).
const (
	hintFieldSeq     = "seq"
	hintFieldTopic   = "topic"
	hintFieldVersion = "version"
	hintFieldKind    = "kind"
	hintFieldHint    = "hint"
)

// The PushHint one entry of a client's hint stream holds. An entry this package did not write, or one
// whose numbers do not parse, is an error, which a reader takes as a gap: the client resyncs.
func ParseHintEntry(entry *sidecar.RedisStreamEntry) (*protocol.PushHint, error) {
	field := func(name string) (string, error) {
		value, ok := entry.FieldValues[name]
		if !ok {
			return "", fmt.Errorf("push hint entry %s has no %s", entry.Id, name)
		}
		return string(value), nil
	}
	seqText, err := field(hintFieldSeq)
	if err != nil {
		return nil, err
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil || seq == 0 {
		return nil, fmt.Errorf("push hint entry %s has a malformed seq", entry.Id)
	}
	topic, err := field(hintFieldTopic)
	if err != nil {
		return nil, err
	}
	versionText, err := field(hintFieldVersion)
	if err != nil {
		return nil, err
	}
	version, err := ParseVersion(versionText)
	if err != nil {
		return nil, fmt.Errorf("push hint entry %s: %w", entry.Id, err)
	}
	kindText, err := field(hintFieldKind)
	if err != nil {
		return nil, err
	}
	kind, err := strconv.ParseUint(kindText, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("push hint entry %s has a malformed kind", entry.Id)
	}
	hint := &protocol.PushHint{
		Seq:     seq,
		Topic:   topic,
		Version: version,
		Kind:    uint32(kind),
	}
	if body := entry.FieldValues[hintFieldHint]; 0 < len(body) {
		hint.Hint = append([]byte(nil), body...)
	}
	return hint, nil
}

// The versions a client's ver hash holds, each parsed: a field whose value is not a canonical version is
// left out, as an expired one would be, and the client keeps its own.
func ParseHintVersions(fieldValues map[string][]byte) map[string]uint64 {
	topicVersions := map[string]uint64{}
	for topic, value := range fieldValues {
		if version, err := ParseVersion(string(value)); err == nil {
			topicVersions[topic] = version
		}
	}
	return topicVersions
}
