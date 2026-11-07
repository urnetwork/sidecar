// What the lint must refuse and what it must pass: every function named bad has exactly one finding, on
// itself, and every one named good has none. Never built by ./..., being under testdata.

package planted

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
)

type store struct {
	redis    sidecar.Redis
	narrow   narrowRedis
	cluster  sidecar.BlobCluster
	clientId string
	otherId  string
	ackKey   string
	tokKey   string
}

// An engine may declare the part of Redis it uses (host_redis.go).
type narrowRedis interface {
	GetMany(ctx context.Context, keys []string) ([][]byte, error)
	RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error)
}

const tagPrefix = "{scp_"

var goodScript = &sidecar.RedisScript{
	Name: "planted-good",
	Source: `
local head = KEYS[1]
redis.call('SET', KEYS[2], redis.call('GET', head))
redis.call('XGROUP', 'CREATE', KEYS[3], 'g', '$')
local now = redis.call('TIME')
return redis.pcall('INCR', head)`,
}

// Findings at package level, with no function to name: a literal key, a built one, and a key resting on
// KEYS with more on the end.
var badScript = &sidecar.RedisScript{
	Name: "planted-bad",
	Source: `
redis.call('SET', 'literal', ARGV[1])
redis.call('DEL', KEYS[1] .. ':old')
return redis.call('GET', 'prefix:' .. ARGV[1])`,
}

// So is a Source this cannot read.
var badSourceNotConstant = &sidecar.RedisScript{Name: "planted-built", Source: fmt.Sprint("return 1")}

func clientKey(clientId string, name string) string {
	return "{scp_" + clientId + "}" + name
}

func ackKey(clientId string) string {
	return fmt.Sprintf("{scp_%s}ack", clientId)
}

func tokKey(clientId string) string {
	return clientKey(clientId, "tok")
}

func (self *store) ownKey(name string) string {
	return clientKey(self.clientId, name)
}

func bothKeys(clientId string) []string {
	return []string{ackKey(clientId), tokKey(clientId)}
}

func recursiveKey(clientId string) string {
	return recursiveKey(clientId)
}

func twoStepKey(clientId string) string {
	key := clientKey(clientId, "x")
	return key + "y"
}

func goodLiterals(ctx context.Context, self *store) {
	self.redis.GetMany(ctx, []string{"{a}1", "{a}2", "{a}3"})
}

func goodOneKeyNeedsNoTag(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{"plain"})
}

func goodConstantAndConcat(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{tagPrefix + self.clientId + "}a", "{scp_" + self.clientId + "}b"})
}

func goodSprintf(ctx context.Context, self *store) {
	self.redis.GetMany(ctx, []string{
		fmt.Sprintf("{scp_%s}a", self.clientId),
		fmt.Sprintf("{scp_%s}%s", self.clientId, "b"),
		fmt.Sprintf("{scp_%s}%d%%", self.clientId, 7),
	})
}

func goodBuilders(ctx context.Context, self *store) {
	self.redis.GetMany(ctx, []string{ackKey(self.clientId), tokKey(self.clientId), self.ownKey("rev")})
}

func goodBuilderReturningAList(ctx context.Context, self *store) {
	self.redis.Delete(ctx, bothKeys(self.clientId))
}

func goodLocals(ctx context.Context, self *store) {
	first := ackKey(self.clientId)
	second := tokKey(self.clientId)
	keys := []string{first, second}
	self.redis.Delete(ctx, keys)
}

func goodAppendsInALoop(ctx context.Context, self *store, names []string) {
	keys := make([]string, 0, len(names))
	for _, name := range names {
		keys = append(keys, clientKey(self.clientId, name))
	}
	self.redis.GetMany(ctx, keys)
}

func goodVarThenAppend(ctx context.Context, self *store) {
	var keys []string
	keys = append(keys, ackKey(self.clientId))
	keys = append(keys, bothKeys(self.clientId)...)
	self.redis.GetMany(ctx, keys)
}

func goodScriptCall(ctx context.Context, self *store) {
	self.redis.RunScript(ctx, goodScript, []string{ackKey(self.clientId), tokKey(self.clientId)}, []string{"arg"})
}

func goodNoKeys(ctx context.Context, self *store) {
	self.redis.RunScript(ctx, goodScript, nil, nil)
}

// A blob cluster's Delete takes one key, and no slot means anything to it.
func goodABlobDeleteIsNoRedisCall(ctx context.Context, self *store, key string) {
	self.cluster.Delete(ctx, key)
}

func badTwoTags(ctx context.Context, self *store) {
	self.redis.GetMany(ctx, []string{"{a}1", "{b}2"})
}

func badNoTags(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{"plain-a", "plain-b"})
}

// One hash, by luck of how the key reads, and RedisKeysShareTag refuses it.
func badABareKeyBesideItsTag(ctx context.Context, self *store) {
	self.redis.GetMany(ctx, []string{"scp_c", "{scp_c}n"})
}

func badTwoClients(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{ackKey(self.clientId), ackKey(self.otherId)})
}

func badSprintfTwoTags(ctx context.Context, self *store) {
	self.redis.GetMany(ctx, []string{
		fmt.Sprintf("{scp_%s}a", self.clientId),
		fmt.Sprintf("{ack_%s}a", self.clientId),
	})
}

func badAPaddedVerbIsItsOwnValue(ctx context.Context, self *store, n int) {
	self.redis.GetMany(ctx, []string{fmt.Sprintf("{scp_%04d}a", n), fmt.Sprintf("{scp_%d}a", n)})
}

func badValuesItCannotRead(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{self.ackKey, self.tokKey})
}

func badValueBeforeTheTag(ctx context.Context, self *store, prefix string) {
	self.redis.Delete(ctx, []string{prefix + "{a}1", prefix + "{a}2"})
}

func badAKeysParameter(ctx context.Context, self *store, keys []string) {
	self.redis.GetMany(ctx, keys)
}

func badAPackageList(ctx context.Context, self *store) {
	self.redis.Delete(ctx, packageKeys)
}

var packageKeys = []string{"{a}1", "{a}2"}

func badOneKeyInALoopIsMany(ctx context.Context, self *store, names []string) {
	keys := []string{}
	for _, name := range names {
		keys = append(keys, name)
	}
	self.redis.GetMany(ctx, keys)
}

func badThroughANarrowInterface(ctx context.Context, self *store) {
	self.narrow.GetMany(ctx, []string{"{a}1", "{b}2"})
}

func badScriptCall(ctx context.Context, self *store) {
	self.redis.RunScript(ctx, goodScript, []string{"{a}1", "{b}2"}, nil)
}

func badScriptBuiltPerCall(ctx context.Context, self *store) {
	self.redis.RunScript(ctx, &sidecar.RedisScript{Name: "per-call", Source: "return 1"}, []string{"{a}1"}, nil)
}

func badARecursiveBuilderStops(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{recursiveKey(self.clientId), recursiveKey(self.otherId)})
}

// A builder of more than one statement is not followed, so its key reads as a value.
func badABuilderOfTwoStatements(ctx context.Context, self *store) {
	self.redis.Delete(ctx, []string{twoStepKey(self.clientId), ackKey(self.clientId)})
}

// Not a builder, being two statements: what it returns differs from call to call.
func (self *store) nextId() string {
	self.clientId += "x"
	return self.clientId
}

// Writes the list it is given, out of the caller's sight.
func fill(keys []string) {
	keys[0] = "{b}1"
}

// The common Go shape: a list made at its length and filled by index. An element made empty is a key
// nobody named, so the list cannot be read.
func badAListMadeAtItsLength(ctx context.Context, self *store, clientIds []string) {
	keys := make([]string, len(clientIds))
	for index, clientId := range clientIds {
		keys[index] = ackKey(clientId)
	}
	self.redis.GetMany(ctx, keys)
}

// An element set by index may replace any key, so the list holds both.
func badAnElementReplaced(ctx context.Context, self *store) {
	keys := []string{"{a}x", "{a}y"}
	keys[1] = "{b}y"
	self.redis.Delete(ctx, keys)
}

func goodAnElementReplacedUnderItsTag(ctx context.Context, self *store) {
	keys := []string{"{a}x", "{a}y"}
	keys[1] = "{a}z"
	self.redis.Delete(ctx, keys)
}

// Each pass's tag is another id's, though it reads the same in source.
func badATagFromTheLoop(ctx context.Context, self *store, clientIds []string) {
	keys := []string{}
	for _, clientId := range clientIds {
		keys = append(keys, fmt.Sprintf("{scp_%s}tok", clientId))
	}
	self.redis.GetMany(ctx, keys)
}

// A closure runs as often as it is called.
func badAClosureCalledTwice(ctx context.Context, self *store) {
	keys := []string{}
	add := func(clientId string) {
		keys = append(keys, ackKey(clientId))
	}
	add(self.clientId)
	add(self.otherId)
	self.redis.Delete(ctx, keys)
}

// A call in the loop may answer differently on each pass.
func badACallInTheLoop(ctx context.Context, self *store, names []string) {
	keys := []string{}
	for range names {
		keys = append(keys, clientKey(self.nextId(), "a"))
	}
	self.redis.GetMany(ctx, keys)
}

// Made once, before the loop: one value on every pass.
func goodACallBeforeTheLoop(ctx context.Context, self *store, names []string) {
	clientId := self.nextId()
	keys := []string{}
	for _, name := range names {
		keys = append(keys, clientKey(clientId, name))
	}
	self.redis.GetMany(ctx, keys)
}

// A list declared in the loop starts again on each pass.
func goodAListPerPass(ctx context.Context, self *store, clientIds []string) {
	for _, clientId := range clientIds {
		keys := []string{}
		keys = append(keys, ackKey(clientId))
		keys = append(keys, tokKey(clientId))
		self.redis.GetMany(ctx, keys)
	}
}

func badAListPassedToACall(ctx context.Context, self *store) {
	keys := []string{"{a}1", "{a}2"}
	fill(keys)
	self.redis.Delete(ctx, keys)
}

func badAListAliased(ctx context.Context, self *store) {
	keys := []string{"{a}1", "{a}2"}
	other := keys
	other[0] = "{b}1"
	self.redis.Delete(ctx, keys)
}

// clientId holds two values, read once each.
func badAVariableWrittenTwice(ctx context.Context, self *store) {
	clientId := self.clientId
	first := ackKey(clientId)
	clientId = self.otherId
	second := ackKey(clientId)
	self.redis.Delete(ctx, []string{first, second})
}

// The declaration's value is the one the list holds, not the later assignment's.
func badADeclaredValueHidden(ctx context.Context, self *store) {
	var key = "{b}1"
	keys := []string{key, "{a}2"}
	key = "{a}1"
	self.redis.Delete(ctx, keys)
	_ = key
}
