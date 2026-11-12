// SocketTicketKeySet (SOCK-M5-08; §9.8, D-SOCK-4): the service's Ed25519 ticket keys, from one key file among the
// block's vault secret_files, which the host rereads every ReloadInterval. Every listed key verifies until its
// expiry, and the newest key that has settled signs: a key settles SettleTime after its creation, by when every
// live listener holds it from a registration answer or GET /socket/keys, so no ticket names a key a listener has
// not been given. While no key has settled, the oldest live one signs, which is a deployment's first key. A key
// signs only while it outlives SignMargin, so no ticket outlives its key.
//
// Rotation, every RotationInterval (30 days): keygen (server/cli/sockets) adds a key to the file beside the ones
// it holds, each expiring RotationInterval and KeyOverlap after its creation, and drops the expired. The new key
// verifies at once and signs once settled, while the old one verifies through the overlap. A rotation never stops
// the service: vault's file changes and the next reread takes it.
//
// The file, YAML, the seed in standard base64:
//
//	keys:
//	  - key_id: k1762905600000-4f2a91c0
//	    seed: <32 bytes>
//	    created_millis: 1762905600000
//	    expire_millis: 1765584000000
//
// A file that does not parse, or names a key twice or a seed of the wrong size, is refused whole and the last good
// set stays; a set read from nothing has no key, which leaves the engine not ready and signing nothing. Each seed
// is a key's creation or unwrap, so it passes through testHookSecret. Nothing here logs a key. Safe for concurrent
// use.

package socketsservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar"
)

var _ SocketTicketKeys = (*SocketTicketKeySet)(nil)

// A key file that cannot be used. The text names what is wrong, never a key.
var ErrSocketTicketKeyFileRefused = errors.New("socket ticket key file refused")

// The key set's tunables (§9.8's 30-day rotation with overlap).
type SocketTicketKeySettings struct {
	// How often a key file gets a new key: 30 days. keygen reads it.
	RotationInterval time.Duration
	// How long a key verifies past RotationInterval, so a ticket under it, and the listeners that hold it, outlive
	// its successor's settling: 1 day.
	KeyOverlap time.Duration
	// How long after its creation a key starts to sign: 10 min, many registration heartbeats (§9.5's 15 s), so
	// every live listener has been given it.
	SettleTime time.Duration
	// How long a key must still verify for it to sign: 10 min, past any ticket's 30 s life and any clock skew a
	// listener tolerates.
	SignMargin time.Duration
	// How often the host rereads the file: 60 s, so a rotation in vault lands within a minute.
	ReloadInterval time.Duration
	// The most keys a file holds: 16, room for many overlaps; past it the file is refused.
	MaxKeyCount int
	// The most bytes a file holds: 64 KiB.
	MaxFileByteCount int
}

// §9.8's values.
func DefaultSocketTicketKeySettings() *SocketTicketKeySettings {
	return &SocketTicketKeySettings{
		RotationInterval: 30 * 24 * time.Hour,
		KeyOverlap:       24 * time.Hour,
		SettleTime:       10 * time.Minute,
		SignMargin:       10 * time.Minute,
		ReloadInterval:   60 * time.Second,
		MaxKeyCount:      16,
		MaxFileByteCount: 64 * 1024,
	}
}

// Whether a set can run on these. A refusal names the field.
func (self *SocketTicketKeySettings) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no ticket key settings", ErrSocketsSettingsRefused)
	}
	for _, check := range []struct {
		name     string
		positive bool
	}{
		{name: "ticket_keys.rotation_interval", positive: 0 < self.RotationInterval},
		{name: "ticket_keys.key_overlap", positive: 0 < self.KeyOverlap},
		{name: "ticket_keys.settle_time", positive: 0 < self.SettleTime && self.SettleTime < self.KeyOverlap},
		{name: "ticket_keys.sign_margin", positive: 0 < self.SignMargin && self.SignMargin < self.KeyOverlap},
		{name: "ticket_keys.reload_interval", positive: 0 < self.ReloadInterval},
		{name: "ticket_keys.max_key_count", positive: 0 < self.MaxKeyCount},
		{name: "ticket_keys.max_file_byte_count", positive: 0 < self.MaxFileByteCount},
	} {
		if !check.positive {
			return fmt.Errorf("%w: %s", ErrSocketsSettingsRefused, check.name)
		}
	}
	return nil
}

// One key as the file holds it.
type socketTicketKeyYaml struct {
	KeyId         string `yaml:"key_id"`
	Seed          string `yaml:"seed"`
	CreatedMillis int64  `yaml:"created_millis"`
	ExpireMillis  int64  `yaml:"expire_millis"`
}

// The file.
type socketTicketKeyFileYaml struct {
	Keys []*socketTicketKeyYaml `yaml:"keys"`
}

// One parsed key.
type socketTicketKey struct {
	keyId         string
	privateKey    ed25519.PrivateKey
	createdMillis int64
	expireMillis  int64
}

// The keys a file held, oldest first, never changed once published.
type socketTicketKeyView struct {
	keys []*socketTicketKey
}

// The parsed keys of a file, oldest first: every key with an id, a 32-byte seed and an expiry after its creation,
// no id twice, at most MaxKeyCount. A refusal names what is wrong.
func parseSocketTicketKeyFile(data []byte, settings *SocketTicketKeySettings) ([]*socketTicketKey, error) {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrSocketTicketKeyFileRefused, fmt.Sprintf(format, arguments...))
	}
	if settings.MaxFileByteCount < len(data) {
		return nil, refuse("%d bytes", len(data))
	}
	file := &socketTicketKeyFileYaml{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(file); err != nil {
		return nil, refuse("it does not parse")
	}
	if settings.MaxKeyCount < len(file.Keys) {
		return nil, refuse("%d keys", len(file.Keys))
	}
	keys := []*socketTicketKey{}
	keyIds := map[string]bool{}
	for index, keyYaml := range file.Keys {
		if keyYaml == nil || keyYaml.KeyId == "" || keyIds[keyYaml.KeyId] {
			return nil, refuse("key %d has no id of its own", index)
		}
		keyIds[keyYaml.KeyId] = true
		seed, err := base64.StdEncoding.DecodeString(keyYaml.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, refuse("key %d's seed is no Ed25519 seed", index)
		}
		testHookSecret("socket_ticket_seed", seed)
		if keyYaml.ExpireMillis <= keyYaml.CreatedMillis {
			return nil, refuse("key %d expires before its creation", index)
		}
		keys = append(keys, &socketTicketKey{
			keyId:         keyYaml.KeyId,
			privateKey:    ed25519.NewKeyFromSeed(seed),
			createdMillis: keyYaml.CreatedMillis,
			expireMillis:  keyYaml.ExpireMillis,
		})
	}
	slices.SortStableFunc(keys, func(a *socketTicketKey, b *socketTicketKey) int {
		switch {
		case a.createdMillis < b.createdMillis:
			return -1
		case b.createdMillis < a.createdMillis:
			return 1
		}
		return 0
	})
	return keys, nil
}

// The key file with a new key created at now added, expiring RotationInterval and KeyOverlap after it, and every
// key expired at now dropped: what keygen writes. existing may be empty for a first file, and a file that does not
// parse is refused rather than overwritten.
func SocketTicketKeyFileAdd(existing []byte, now time.Time, settings *SocketTicketKeySettings) ([]byte, error) {
	if settings == nil {
		settings = DefaultSocketTicketKeySettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	file := &socketTicketKeyFileYaml{}
	if 0 < len(bytes.TrimSpace(existing)) {
		if _, err := parseSocketTicketKeyFile(existing, settings); err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(existing, file); err != nil {
			return nil, fmt.Errorf("%w: it does not parse", ErrSocketTicketKeyFileRefused)
		}
	}
	nowMillis := now.UnixMilli()
	kept := []*socketTicketKeyYaml{}
	for _, keyYaml := range file.Keys {
		if nowMillis < keyYaml.ExpireMillis {
			kept = append(kept, keyYaml)
		}
	}
	if settings.MaxKeyCount <= len(kept) {
		return nil, fmt.Errorf("%w: %d live keys, the most a file holds", ErrSocketTicketKeyFileRefused, len(kept))
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	testHookSecret("socket_ticket_seed", seed)
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	kept = append(kept, &socketTicketKeyYaml{
		KeyId:         "k" + strconv.FormatInt(nowMillis, 10) + "-" + hex.EncodeToString(suffix),
		Seed:          base64.StdEncoding.EncodeToString(seed),
		CreatedMillis: nowMillis,
		ExpireMillis:  now.Add(settings.RotationInterval + settings.KeyOverlap).UnixMilli(),
	})
	return yaml.Marshal(&socketTicketKeyFileYaml{Keys: kept})
}

// The service's ticket keys. NewSocketTicketKeySet makes one.
type SocketTicketKeySet struct {
	read     func() ([]byte, error)
	clock    sidecar.Clock
	settings *SocketTicketKeySettings
	log      sidecar.Logger

	view atomic.Pointer[socketTicketKeyView]
	// reads finished, each counted once the wait for the next is armed
	readCount *sidecar.MonitorValue[int]
}

// A set reading its file through read, at once and then every ReloadInterval on clock until ctx ends. A first read
// that fails leaves the set empty, never ready to sign, until a later read succeeds.
func NewSocketTicketKeySet(ctx context.Context, read func() ([]byte, error), clock sidecar.Clock, log sidecar.Logger, settings *SocketTicketKeySettings) (*SocketTicketKeySet, error) {
	if read == nil {
		return nil, errors.New("a ticket key set needs its file's reader")
	}
	if settings == nil {
		settings = DefaultSocketTicketKeySettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	self := &SocketTicketKeySet{
		read:      read,
		clock:     clock,
		settings:  settings,
		log:       log,
		readCount: sidecar.NewMonitorValue(0),
	}
	self.view.Store(&socketTicketKeyView{})
	self.reload()
	go self.run(ctx)
	return self, nil
}

// Rereads every ReloadInterval until ctx ends.
func (self *SocketTicketKeySet) run(ctx context.Context) {
	for {
		wait := self.clock.After(self.settings.ReloadInterval)
		self.readCount.Update(func(count int) int { return count + 1 })
		select {
		case <-ctx.Done():
			return
		case <-wait:
		}
		self.reload()
	}
}

// One read of the file. A failure keeps the last good set, and says what failed, never a key.
func (self *SocketTicketKeySet) reload() {
	data, err := self.read()
	if err == nil {
		var keys []*socketTicketKey
		if keys, err = parseSocketTicketKeyFile(data, self.settings); err == nil {
			self.view.Store(&socketTicketKeyView{keys: keys})
			return
		}
	}
	if self.log != nil {
		self.log.Warningf("[sockets]the ticket key file kept its last keys: %v", err)
	}
}

// See SocketTicketKeys: the newest settled key that outlives SignMargin, else the oldest live one that does.
func (self *SocketTicketKeySet) SigningKey() (string, ed25519.PrivateKey, bool) {
	nowMillis := self.clock.Now().UnixMilli()
	var signing *socketTicketKey
	for _, key := range self.view.Load().keys {
		if key.expireMillis <= nowMillis+self.settings.SignMargin.Milliseconds() || nowMillis < key.createdMillis {
			continue
		}
		settled := key.createdMillis+self.settings.SettleTime.Milliseconds() <= nowMillis
		if signing == nil || settled {
			signing = key
		}
	}
	if signing == nil {
		return "", nil, false
	}
	return signing.keyId, signing.privateKey, true
}

// See SocketTicketKeys: every key not yet expired, oldest first, public halves only.
func (self *SocketTicketKeySet) VerifyKeys() []*sidecar.SocketTicketKey {
	nowMillis := self.clock.Now().UnixMilli()
	verifyKeys := []*sidecar.SocketTicketKey{}
	for _, key := range self.view.Load().keys {
		if key.expireMillis <= nowMillis {
			continue
		}
		verifyKeys = append(verifyKeys, &sidecar.SocketTicketKey{
			KeyId:            key.keyId,
			PublicKey:        bytes.Clone(key.privateKey.Public().(ed25519.PublicKey)),
			ExpireTimeMillis: uint64(key.expireMillis),
		})
	}
	return verifyKeys
}
