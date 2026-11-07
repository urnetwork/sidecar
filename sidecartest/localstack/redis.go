// sidecar.Redis on the local stack's Redis Cluster, keeping host_redis.go's promises against a real one:
// each call goes to the master of its first key's slot, a MOVED or ASK is followed, and a cross-slot
// call is sent, so the answer is the cluster's own CROSSSLOT and not this client's opinion.
//
// A transport error is returned, never retried: Redis did not answer, so the caller does not know what
// a write did. Keyed calls have their rules checked here because a real node would take many of them to
// mean something else (host_redis.go). Safe for concurrent use.

package localstack

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs in the master, since GET and SET of one value have to be one step.
var (
	redisCompareAndSetScript = &sidecar.RedisScript{
		Name: "localstack-compare-and-set",
		Source: `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if ARGV[3] == '0' then
	redis.call('SET', KEYS[1], ARGV[2])
else
	redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
end
return 1`,
	}
	redisCompareAndDeleteScript = &sidecar.RedisScript{
		Name: "localstack-compare-and-delete",
		Source: `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
return 1`,
	}
	// The value comes back as GET's string: INCR's Lua number is a double, and host_redis.go lets no
	// large number through Lua.
	redisIncrementScript = &sidecar.RedisScript{
		Name: "localstack-increment",
		Source: `
redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1], 'NX')
return redis.call('GET', KEYS[1])`,
	}
)

// What NewRedis dials, and how long it waits on a store that has stopped answering.
type RedisSettings struct {
	// Any nodes of the cluster, as host:port: one that answers finds the rest. Each must pass
	// CheckStackAddress.
	SeedAddresses []string
	// How long a dial may take. 5 s: a node on loopback answers at once, so this only bounds a dead one.
	// Not positive: no bound but ctx.
	DialTimeout time.Duration
	// How long one call may take when ctx sets nothing sooner, a blocked read's block on top. 10 s, the
	// bound §19.6 gives a store request. Not positive: every call fails at once.
	CallTimeout time.Duration
	// Sockets kept open per node between calls: a suite's concurrent cases take about 8. Past it a
	// socket closes when its call ends. Zero keeps none.
	IdleConnectionCount int
	// MOVED and ASK answers one call follows before it fails. 5: a reshard needs at most one of each, and
	// a loop must not spin. Zero follows none.
	RedirectLimit int
	// The least time between attempts to win back a lost subscription: connect.Reconnect's. 1 s, so a
	// dead node costs a dial a second. Must be positive, since that is all that paces the retry, and
	// NewRedis refuses anything else.
	ResubscribeTimeout time.Duration
	// Key events waiting for the subscriber's goroutine. 1024. A master's reader waits once it is full,
	// since a callback never blocks (host_redis.go) and a slow one here is a test's bug to see. Zero
	// hands each event straight over.
	KeyEventQueueCount int
}

// What local/docker-compose.yml binds.
func DefaultRedisSettings() *RedisSettings {
	return &RedisSettings{
		SeedAddresses:       []string{"127.0.0.1:56401", "127.0.0.1:56402", "127.0.0.1:56403"},
		DialTimeout:         5 * time.Second,
		CallTimeout:         10 * time.Second,
		IdleConnectionCount: 8,
		RedirectLimit:       5,
		ResubscribeTimeout:  1 * time.Second,
		KeyEventQueueCount:  1024,
	}
}

// One master's slots, both ends included.
type redisSlotRange struct {
	start   int
	end     int
	address string
}

// sidecar.Redis on one cluster. See the file header.
type Redis struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *RedisSettings

	stateLock       sync.Mutex
	slotRanges      []*redisSlotRange
	idleConnections map[string][]*redisConnection
	closed          bool

	subscriber *redisKeyEventSubscriber
}

// Reads the cluster's slots from the seeds, and fails when none answers. settings may be nil for the
// defaults. The caller closes it.
func NewRedis(ctx context.Context, settings *RedisSettings) (*Redis, error) {
	if settings == nil {
		settings = DefaultRedisSettings()
	}
	for _, address := range settings.SeedAddresses {
		if err := CheckStackAddress(address); err != nil {
			return nil, err
		}
	}
	if settings.ResubscribeTimeout <= 0 {
		return nil, fmt.Errorf("a resubscribe timeout of %v would spin on a dead node", settings.ResubscribeTimeout)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Redis{
		ctx:             cancelCtx,
		cancel:          cancel,
		settings:        settings,
		idleConnections: map[string][]*redisConnection{},
	}
	self.subscriber = newRedisKeyEventSubscriber(cancelCtx, self)
	if err := self.refreshSlots(ctx); err != nil {
		self.Close()
		return nil, err
	}
	return self, nil
}

// Ends the subscriber and closes every idle socket. A call in flight ends with its own ctx.
func (self *Redis) Close() {
	self.cancel()
	var idleConnections map[string][]*redisConnection
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		idleConnections = self.idleConnections
		self.idleConnections = map[string][]*redisConnection{}
	}()
	for _, connections := range idleConnections {
		for _, connection := range connections {
			connection.close()
		}
	}
}

// Every master, in slot order.
func (self *Redis) Masters() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	addresses := []string{}
	for _, slotRange := range self.slotRanges {
		if !slices.Contains(addresses, slotRange.address) {
			addresses = append(addresses, slotRange.address)
		}
	}
	return addresses
}

func (self *Redis) take(ctx context.Context, address string) (*redisConnection, error) {
	connection := func() *redisConnection {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		connections := self.idleConnections[address]
		if len(connections) == 0 {
			return nil
		}
		last := connections[len(connections)-1]
		self.idleConnections[address] = connections[:len(connections)-1]
		return last
	}()
	if connection != nil {
		return connection, nil
	}
	return dialRedis(ctx, address, self.settings.DialTimeout)
}

func (self *Redis) give(connection *redisConnection) {
	if connection.broken {
		// a reply read cleanly can still leave a cancel racing it, with the socket open
		connection.close()
		return
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.settings.IdleConnectionCount <= len(self.idleConnections[connection.address]) {
			return false
		}
		self.idleConnections[connection.address] = append(self.idleConnections[connection.address], connection)
		return true
	}()
	if !kept {
		connection.close()
	}
}

// Sends commands to one node on one socket, in order, and reads their replies.
func (self *Redis) roundTrip(ctx context.Context, address string, timeout time.Duration, commands ...[][]byte) ([]*redisValue, error) {
	connection, err := self.take(ctx, address)
	if err != nil {
		return nil, err
	}
	defer self.give(connection)
	return connection.roundTrip(ctx, timeout, commands...)
}

// Rereads who holds which slots, from the masters known and then the seeds.
func (self *Redis) refreshSlots(ctx context.Context) error {
	var failure error
	for _, address := range append(self.Masters(), self.settings.SeedAddresses...) {
		replies, err := self.roundTrip(ctx, address, self.settings.CallTimeout, redisArgs("CLUSTER", "SLOTS"))
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		slotRanges, err := parseRedisSlots(replies[0], address)
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.slotRanges = slotRanges
		}()
		return nil
	}
	return fmt.Errorf("no node gave the cluster's slots: %w", failure)
}

// CLUSTER SLOTS: for each range its first and last slot and its master's endpoint, then its replicas,
// which production and the local stack do not have. An endpoint with no host means the node just asked.
func parseRedisSlots(reply *redisValue, askedAddress string) ([]*redisSlotRange, error) {
	if reply.kind != redisArray {
		return nil, fmt.Errorf("cluster slots: %s", reply.text)
	}
	askedHost, _, err := net.SplitHostPort(askedAddress)
	if err != nil {
		return nil, err
	}
	slotRanges := []*redisSlotRange{}
	for _, row := range reply.values {
		if len(row.values) < 3 || len(row.values[2].values) < 2 {
			return nil, errors.New("a short cluster slots row")
		}
		endpoint := row.values[2]
		host := string(endpoint.values[0].text)
		if host == "" {
			host = askedHost
		}
		slotRanges = append(slotRanges, &redisSlotRange{
			start:   int(row.values[0].integer),
			end:     int(row.values[1].integer),
			address: net.JoinHostPort(host, strconv.FormatInt(endpoint.values[1].integer, 10)),
		})
	}
	if len(slotRanges) == 0 {
		return nil, errors.New("no slots are assigned: is the cluster created?")
	}
	slices.SortFunc(slotRanges, func(a *redisSlotRange, b *redisSlotRange) int {
		return a.start - b.start
	})
	return slotRanges, nil
}

// The master of key's slot, or the first master for a call that names no key.
func (self *Redis) addressOf(key string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if key == "" && 0 < len(self.slotRanges) {
		return self.slotRanges[0].address, nil
	}
	slot := sidecartest.RedisClusterSlot(key)
	for _, slotRange := range self.slotRanges {
		if slotRange.start <= slot && slot <= slotRange.end {
			return slotRange.address, nil
		}
	}
	return "", fmt.Errorf("no master holds slot %d", slot)
}

// Runs one command on key's master, following redirects. A failure reply is the call's error.
func (self *Redis) call(ctx context.Context, key string, timeout time.Duration, args [][]byte) (*redisValue, error) {
	address, err := self.addressOf(key)
	if err != nil {
		return nil, err
	}
	commands := [][][]byte{args}
	for range self.settings.RedirectLimit + 1 {
		replies, err := self.roundTrip(ctx, address, timeout, commands...)
		if err != nil {
			return nil, err
		}
		reply := replies[len(replies)-1]
		if reply.kind != redisFailure {
			return reply, nil
		}
		fields := strings.Fields(string(reply.text))
		switch {
		case len(fields) == 3 && fields[0] == "MOVED":
			address = fields[2]
			commands = [][][]byte{args}
			if err := self.refreshSlots(ctx); err != nil {
				return nil, err
			}
		case len(fields) == 3 && fields[0] == "ASK":
			// one command, on the one socket that said ASKING
			address = fields[2]
			commands = [][][]byte{redisArgs("ASKING"), args}
		default:
			return nil, redisFailureError(string(reply.text))
		}
	}
	return nil, fmt.Errorf("past %d redirects", self.settings.RedirectLimit)
}

// A node's error, on the sentinels the fake answers with so a caller reads either alike.
func redisFailureError(text string) error {
	switch {
	case strings.HasPrefix(text, "CROSSSLOT "):
		return sidecartest.ErrRedisCrossSlot
	case strings.HasPrefix(text, "WRONGTYPE "):
		return sidecartest.ErrRedisWrongType
	case strings.HasPrefix(text, "NOGROUP "):
		return fmt.Errorf("%w: %s", sidecartest.ErrRedisNoGroup, text)
	}
	return errors.New(text)
}

// A command's arguments: string, []byte or int64.
func redisArgs(parts ...any) [][]byte {
	args := make([][]byte, 0, len(parts))
	for _, part := range parts {
		switch value := part.(type) {
		case string:
			args = append(args, []byte(value))
		case []byte:
			args = append(args, value)
		case int64:
			args = append(args, strconv.AppendInt(nil, value, 10))
		default:
			panic(fmt.Sprintf("a redis argument of type %T", part))
		}
	}
	return args
}

// host_redis.go's rounding: up to the millisecond Redis keeps, so a positive ttl never reaches it as
// zero.
func redisMilliseconds(ttl time.Duration) int64 {
	return int64((ttl + time.Millisecond - 1) / time.Millisecond)
}

func checkRedisTtl(ttl time.Duration) error {
	if ttl < 0 {
		return fmt.Errorf("a ttl of %v", ttl)
	}
	return nil
}

func checkRedisPositiveTtl(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("a ttl of %v, which Redis would take as a delete", ttl)
	}
	return nil
}

func checkRedisCount(count int64) error {
	if count <= 0 {
		return fmt.Errorf("a count of %d", count)
	}
	return nil
}

func (self *Redis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("GET", key))
	if err != nil {
		return nil, false, err
	}
	if reply.nilValue {
		return nil, false, nil
	}
	return reply.text, true, nil
}

func (self *Redis) GetMany(ctx context.Context, keys []string) ([][]byte, error) {
	if len(keys) == 0 {
		return [][]byte{}, nil
	}
	args := redisArgs("MGET")
	for _, key := range keys {
		args = append(args, []byte(key))
	}
	reply, err := self.call(ctx, keys[0], self.settings.CallTimeout, args)
	if err != nil {
		return nil, err
	}
	values := make([][]byte, len(reply.values))
	for index, value := range reply.values {
		if !value.nilValue {
			values[index] = value.text
		}
	}
	return values, nil
}

func (self *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := checkRedisTtl(ttl); err != nil {
		return err
	}
	args := redisArgs("SET", key, value)
	if 0 < ttl {
		args = append(args, redisArgs("PX", redisMilliseconds(ttl))...)
	}
	_, err := self.call(ctx, key, self.settings.CallTimeout, args)
	return err
}

func (self *Redis) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := checkRedisTtl(ttl); err != nil {
		return false, err
	}
	args := redisArgs("SET", key, value, "NX")
	if 0 < ttl {
		args = append(args, redisArgs("PX", redisMilliseconds(ttl))...)
	}
	reply, err := self.call(ctx, key, self.settings.CallTimeout, args)
	if err != nil {
		return false, err
	}
	return !reply.nilValue, nil
}

func (self *Redis) CompareAndSet(ctx context.Context, key string, expected []byte, value []byte, ttl time.Duration) (bool, error) {
	if err := checkRedisTtl(ttl); err != nil {
		return false, err
	}
	reply, err := self.RunScript(ctx, redisCompareAndSetScript, []string{key}, []string{
		string(expected),
		string(value),
		strconv.FormatInt(redisMilliseconds(ttl), 10),
	})
	if err != nil {
		return false, err
	}
	return reply.Integer == 1, nil
}

func (self *Redis) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	reply, err := self.RunScript(ctx, redisCompareAndDeleteScript, []string{key}, []string{string(expected)})
	if err != nil {
		return false, err
	}
	return reply.Integer == 1, nil
}

func (self *Redis) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if err := checkRedisTtl(ttl); err != nil {
		return 0, err
	}
	if ttl == 0 {
		reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("INCR", key))
		if err != nil {
			return 0, err
		}
		return reply.integer, nil
	}
	reply, err := self.RunScript(ctx, redisIncrementScript, []string{key}, []string{strconv.FormatInt(redisMilliseconds(ttl), 10)})
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(string(reply.Bulk), 10, 64)
}

func (self *Redis) Delete(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	args := redisArgs("DEL")
	for _, key := range keys {
		args = append(args, []byte(key))
	}
	_, err := self.call(ctx, keys[0], self.settings.CallTimeout, args)
	return err
}

func (self *Redis) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if err := checkRedisPositiveTtl(ttl); err != nil {
		return false, err
	}
	reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("PEXPIRE", key, redisMilliseconds(ttl)))
	if err != nil {
		return false, err
	}
	return reply.integer == 1, nil
}

func (self *Redis) HashGet(ctx context.Context, key string, field string) ([]byte, bool, error) {
	reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("HGET", key, field))
	if err != nil {
		return nil, false, err
	}
	if reply.nilValue {
		return nil, false, nil
	}
	return reply.text, true, nil
}

func (self *Redis) HashGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("HGETALL", key))
	if err != nil {
		return nil, err
	}
	return redisFieldValues(reply.values), nil
}

// A flat field, value, field, value list, as HGETALL and a stream entry give it.
func redisFieldValues(values []*redisValue) map[string][]byte {
	fieldValues := make(map[string][]byte, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		fieldValues[string(values[index].text)] = values[index+1].text
	}
	return fieldValues
}

// fieldValues in field order, so a command is the same bytes every run.
func appendRedisFieldValues(args [][]byte, fieldValues map[string][]byte) [][]byte {
	for _, field := range slices.Sorted(maps.Keys(fieldValues)) {
		args = append(args, []byte(field), fieldValues[field])
	}
	return args
}

func (self *Redis) HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error {
	_, err := self.call(ctx, key, self.settings.CallTimeout, appendRedisFieldValues(redisArgs("HSET", key), fieldValues))
	return err
}

func (self *Redis) HashDelete(ctx context.Context, key string, fields []string) error {
	if len(fields) == 0 {
		return nil
	}
	args := redisArgs("HDEL", key)
	for _, field := range fields {
		args = append(args, []byte(field))
	}
	_, err := self.call(ctx, key, self.settings.CallTimeout, args)
	return err
}

func (self *Redis) HashExpire(ctx context.Context, key string, fields []string, ttl time.Duration) error {
	if err := checkRedisPositiveTtl(ttl); err != nil {
		return err
	}
	if len(fields) == 0 {
		return nil
	}
	args := redisArgs("HPEXPIRE", key, redisMilliseconds(ttl), "FIELDS", int64(len(fields)))
	for _, field := range fields {
		args = append(args, []byte(field))
	}
	_, err := self.call(ctx, key, self.settings.CallTimeout, args)
	return err
}

func (self *Redis) StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	if maxLength < 0 {
		return "", fmt.Errorf("a stream length of %d", maxLength)
	}
	args := redisArgs("XADD", key)
	if 0 < maxLength {
		args = append(args, redisArgs("MAXLEN", "~", maxLength)...)
	}
	args = append(args, []byte("*"))
	reply, err := self.call(ctx, key, self.settings.CallTimeout, appendRedisFieldValues(args, fieldValues))
	if err != nil {
		return "", err
	}
	return string(reply.text), nil
}

// [id, [field, value, ...]] rows. A nil row is an entry a trim removed, which a pending list can name.
func redisStreamEntries(rows []*redisValue) []*sidecar.RedisStreamEntry {
	entries := make([]*sidecar.RedisStreamEntry, 0, len(rows))
	for _, row := range rows {
		if row.nilValue || len(row.values) != 2 {
			continue
		}
		entries = append(entries, &sidecar.RedisStreamEntry{
			Id:          string(row.values[0].text),
			FieldValues: redisFieldValues(row.values[1].values),
		})
	}
	return entries
}

func (self *Redis) StreamRange(ctx context.Context, key string, afterEntryId string, count int64) ([]*sidecar.RedisStreamEntry, error) {
	if err := checkRedisCount(count); err != nil {
		return nil, err
	}
	start := "-"
	if afterEntryId != "" {
		start = "(" + afterEntryId
	}
	reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("XRANGE", key, start, "+", "COUNT", count))
	if err != nil {
		return nil, err
	}
	return redisStreamEntries(reply.values), nil
}

func (self *Redis) StreamGroupCreate(ctx context.Context, key string, group string) error {
	_, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("XGROUP", "CREATE", key, group, "$", "MKSTREAM"))
	if err != nil && strings.HasPrefix(err.Error(), "BUSYGROUP ") {
		return nil
	}
	return err
}

func (self *Redis) StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) ([]*sidecar.RedisStreamEntry, error) {
	if err := checkRedisCount(count); err != nil {
		return nil, err
	}
	if err := checkRedisTtl(block); err != nil {
		return nil, err
	}
	args := redisArgs("XREADGROUP", "GROUP", group, consumer, "COUNT", count)
	if 0 < block {
		args = append(args, redisArgs("BLOCK", redisMilliseconds(block))...)
	}
	args = append(args, redisArgs("STREAMS", key, ">")...)
	reply, err := self.call(ctx, key, self.settings.CallTimeout+block, args)
	if err != nil {
		return nil, err
	}
	if reply.nilValue || len(reply.values) == 0 {
		return []*sidecar.RedisStreamEntry{}, nil
	}
	return redisStreamEntries(reply.values[0].values[1].values), nil
}

func (self *Redis) StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error {
	if len(entryIds) == 0 {
		return nil
	}
	args := redisArgs("XACK", key, group)
	for _, entryId := range entryIds {
		args = append(args, []byte(entryId))
	}
	_, err := self.call(ctx, key, self.settings.CallTimeout, args)
	return err
}

func (self *Redis) StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) ([]*sidecar.RedisStreamEntry, string, error) {
	if err := checkRedisCount(count); err != nil {
		return nil, "", err
	}
	if err := checkRedisTtl(minIdle); err != nil {
		return nil, "", err
	}
	if cursor == "" {
		cursor = "0-0"
	}
	reply, err := self.call(ctx, key, self.settings.CallTimeout, redisArgs("XAUTOCLAIM", key, group, consumer, redisMilliseconds(minIdle), cursor, "COUNT", count))
	if err != nil {
		return nil, "", err
	}
	return redisStreamEntries(reply.values[1].values), string(reply.values[0].text), nil
}

func (self *Redis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	sum := sha1.Sum([]byte(script.Source))
	scriptArgs := redisArgs(int64(len(keys)))
	for _, text := range slices.Concat(keys, args) {
		scriptArgs = append(scriptArgs, []byte(text))
	}
	routeKey := ""
	if 0 < len(keys) {
		routeKey = keys[0]
	}
	reply, err := self.call(ctx, routeKey, self.settings.CallTimeout, slices.Concat(redisArgs("EVALSHA", hex.EncodeToString(sum[:])), scriptArgs))
	if err != nil && strings.HasPrefix(err.Error(), "NOSCRIPT ") {
		// this node has not loaded it (host_redis.go)
		reply, err = self.call(ctx, routeKey, self.settings.CallTimeout, slices.Concat(redisArgs("EVAL", script.Source), scriptArgs))
	}
	if err != nil {
		return nil, err
	}
	return redisScriptReply(reply)
}

// What a script returned, as host_redis.go's RedisReply. A status reads as a bulk.
func redisScriptReply(value *redisValue) (*sidecar.RedisReply, error) {
	switch {
	case value.kind == redisFailure:
		return nil, redisFailureError(string(value.text))
	case value.nilValue:
		return &sidecar.RedisReply{Kind: sidecar.RedisReplyNil}, nil
	case value.kind == redisInteger:
		return &sidecar.RedisReply{Kind: sidecar.RedisReplyInteger, Integer: value.integer}, nil
	case value.kind == redisArray:
		replies := make([]*sidecar.RedisReply, 0, len(value.values))
		for _, element := range value.values {
			reply, err := redisScriptReply(element)
			if err != nil {
				return nil, err
			}
			replies = append(replies, reply)
		}
		return &sidecar.RedisReply{Kind: sidecar.RedisReplyArray, Replies: replies}, nil
	}
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyBulk, Bulk: value.text}, nil
}

var _ sidecar.Redis = (*Redis)(nil)
