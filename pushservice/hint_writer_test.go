package pushservice_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A FakeRedis on its own fake clock with the scripts' twins registered.
func testPushRedis(t *testing.T) (*sidecartest.FakeRedis, *sidecartest.FakeClock) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	return redis, clock
}

// PushStoreSuite on T2's FakeRedis and the twins; server runs the same suite on real Redis and the Lua.
func TestPushStoreSuiteOnFakeRedis(t *testing.T) {
	redis, clock := testPushRedis(t)
	sidecartest.RunPushStoreSuite(t, &sidecartest.PushStoreTarget{
		Redis:      redis,
		Pass:       clock.Advance,
		KeyTimeout: time.Hour,
		WatchKeys: func(callback func(key string)) (func(), error) {
			return redis.AddKeyEventCallback("{scp_*}*", func(event sidecar.RedisKeyEvent) {
				if !event.Resync {
					callback(event.Key)
				}
			})
		},
		EventTimeout: 10 * time.Second,
	})
	if violations := redis.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}

// A resolver that answers from a map, or fails.
type testPushResolver struct {
	sidecarClientIds map[connect.Id]connect.Id
	err              error
	calls            [][]connect.Id
}

func (self *testPushResolver) PushClientIds(ctx context.Context, sidecarIds []connect.Id) (map[connect.Id]connect.Id, error) {
	self.calls = append(self.calls, slices.Clone(sidecarIds))
	if self.err != nil {
		return nil, self.err
	}
	return self.sidecarClientIds, nil
}

// Without a resolver, a hint by sidecar id is lost, counted and refused, and nothing is written
// (plan-KEYS-hint-addressing's interim).
func TestHintSidecarsWithoutResolverFailsClosed(t *testing.T) {
	redis, _ := testPushRedis(t)
	writer, err := pushservice.NewHintWriter(redis, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sidecarIds := []connect.Id{connect.NewId(), connect.NewId()}
	err = writer.HintSidecars(t.Context(), sidecarIds, &sidecar.ClientHint{Topic: sidecar.PushTopicGkm, Version: 7})
	if !errors.Is(err, pushservice.ErrHintSidecarsUnresolved) {
		t.Fatalf("err %v", err)
	}
	if stats := writer.Stats(); stats.UnresolvedCount != 2 || stats.HintedCount != 0 {
		t.Errorf("stats %+v", stats)
	}
	if keys := redis.Dump(); len(keys) != 0 {
		t.Errorf("wrote %v", keys)
	}
}

// With a resolver, each resolved sidecar's client gets the hint; one the resolver omits is counted and
// is no error, and a failed lookup is.
func TestHintSidecarsThroughResolver(t *testing.T) {
	redis, _ := testPushRedis(t)
	known := connect.NewId()
	knownClientId := connect.NewId()
	unknown := connect.NewId()
	resolver := &testPushResolver{sidecarClientIds: map[connect.Id]connect.Id{known: knownClientId}}
	metrics := sidecartest.NewFakeMetrics(nil)
	writer, err := pushservice.NewHintWriter(redis, nil, resolver, metrics)
	if err != nil {
		t.Fatal(err)
	}
	hint := &sidecar.ClientHint{Topic: sidecar.PushTopicGkm, Version: 7}
	if err := writer.HintSidecars(t.Context(), []connect.Id{known, unknown}, hint); err != nil {
		t.Fatal(err)
	}
	if stats := writer.Stats(); stats.HintedCount != 1 || stats.UnresolvedCount != 1 {
		t.Errorf("stats %+v", stats)
	}
	fieldValues, err := redis.HashGetAll(t.Context(), pushservice.HintVersionsKey(knownClientId))
	if err != nil || string(fieldValues[sidecar.PushTopicGkm]) != "7" {
		t.Errorf("the known sidecar's client holds %v, %v", fieldValues, err)
	}
	if violations := metrics.Violations(); len(violations) != 0 {
		t.Errorf("metric violations %v", violations)
	}

	resolver.err = errors.New("synthetic lookup failure")
	if err := writer.HintSidecars(t.Context(), []connect.Id{known}, hint); err == nil {
		t.Errorf("a failed lookup answered nil")
	}
	if stats := writer.Stats(); stats.UnresolvedCount != 2 {
		t.Errorf("stats %+v", stats)
	}
}

// Hint runs every client's script whatever another's did, and joins the failures.
func TestHintRunsEveryClient(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	redis := sidecartest.NewFakeRedis(t.Context(), clock, faults, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	writer, err := pushservice.NewHintWriter(redis, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	failing := connect.NewId()
	clientIds := []connect.Id{connect.NewId(), failing, connect.NewId()}
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: pushservice.HintVersionsKey(failing), Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	err = writer.Hint(t.Context(), clientIds, &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 3})
	if err == nil {
		t.Fatalf("a failed script answered nil")
	}
	for _, clientId := range clientIds {
		fieldValues, err := redis.HashGetAll(t.Context(), pushservice.HintVersionsKey(clientId))
		if err != nil {
			t.Fatal(err)
		}
		_, written := fieldValues[sidecar.PushTopicTeam]
		if written == (clientId == failing) {
			t.Errorf("client %s written %t", clientId, written)
		}
	}
	if stats := writer.Stats(); stats.HintedCount != 2 || stats.FailedCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

func TestHintWriterRefusesBadSettings(t *testing.T) {
	redis, _ := testPushRedis(t)
	for _, settings := range []*pushservice.HintWriterSettings{
		{KeyTimeout: 0, StreamMaxLength: 256, AckTimeout: time.Hour},
		{KeyTimeout: 500 * time.Millisecond, StreamMaxLength: 256, AckTimeout: time.Hour},
		{KeyTimeout: time.Hour, StreamMaxLength: 0, AckTimeout: time.Hour},
		{KeyTimeout: time.Hour, StreamMaxLength: 256, AckTimeout: 0},
	} {
		if _, err := pushservice.NewHintWriter(redis, settings, nil, nil); err == nil {
			t.Errorf("%+v taken", settings)
		}
	}
	if _, err := pushservice.NewHintWriter(nil, nil, nil, nil); err == nil {
		t.Errorf("no Redis taken")
	}
}

// The hint script's entry parses back to what the writer was given, and an entry missing a field or
// with a malformed number does not parse.
func TestParseHintEntry(t *testing.T) {
	entry := &sidecar.RedisStreamEntry{
		Id: "1700000000000-0",
		FieldValues: map[string][]byte{
			"seq": []byte("4"), "topic": []byte("core"), "version": []byte("1800000000000000001"),
			"kind": []byte("6657"), "hint": []byte{9},
		},
	}
	hint, err := pushservice.ParseHintEntry(entry)
	if err != nil || hint.Seq != 4 || hint.Topic != "core" || hint.Version != 1_800_000_000_000_000_001 || hint.Kind != 0x1A01 || string(hint.Hint) != "\x09" {
		t.Fatalf("%v, %v", hint, err)
	}
	for _, field := range []string{"seq", "topic", "version", "kind"} {
		broken := &sidecar.RedisStreamEntry{Id: entry.Id, FieldValues: map[string][]byte{}}
		for name, value := range entry.FieldValues {
			if name != field {
				broken.FieldValues[name] = value
			}
		}
		if _, err := pushservice.ParseHintEntry(broken); err == nil {
			t.Errorf("an entry without %s parsed", field)
		}
	}
	for field, value := range map[string]string{"seq": "0", "version": "007", "kind": "4294967296"} {
		broken := &sidecar.RedisStreamEntry{Id: entry.Id, FieldValues: map[string][]byte{}}
		for name, original := range entry.FieldValues {
			broken.FieldValues[name] = original
		}
		broken.FieldValues[field] = []byte(value)
		if _, err := pushservice.ParseHintEntry(broken); err == nil {
			t.Errorf("an entry with %s %q parsed", field, value)
		}
	}
}
