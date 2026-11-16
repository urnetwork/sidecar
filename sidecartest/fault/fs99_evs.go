//go:build !ios_extension

// FS-99's evs clause (§22.8, meta review F01; §11.12's directory row, §11.20, I-EVS-16; RECORD-M6-25) on the evs world
// (evs_world.go) with the repo a team directory: the legs of the row that are evs's own surface, which the authorship
// world's streams do not serve (fs99_test.go), on the real engine and the real client, so server's T3 test runs them
// through evshost's block on the real stores with tokens server's oauth mints (sidecar_directory_t3_test.go).
//
//	world     one directory repo, format 1. The admin made its group and asks for admin, which the world's exchange
//	          gives it. Writers A and B, agent X, a device parked for consent and a read_only sidecar each hold the
//	          repo's keys as a writer of it would, the strongest such forger, and every token of X's and the parked
//	          device's carries rw and no admin, the read_only sidecar's r alone, whatever its client asked for: what
//	          §7.8's exchange mints them. A, B and X each push entries to their own stream, each push with its slot
//	refused   X's ERASE naming A's entry slots, its list mixing the slot its own push introduced with A's and its
//	          ?closure=1 upload each answer 403 SCOPE at arrival, before any request reaches a slot object, and
//	          leave every slot's ETag as it was, no ERASE on the erasure ref and no uploaded segment in the store. The
//	          parked device's and the read_only sidecar's likewise. Then all of it again under a preservation hold
//	          covering the network
//	push      the ERASE each client sent to POST .../slots/delete, sent again to POST .../push under the same token,
//	          answers 403 SCOPE too, at step 5c as §11.12's directory row has a push, and so after step 4 read the
//	          slots it names where the token holds rw: no slot is written, every ETag stands and the erasure ref
//	          holds no ERASE of it. FS-99's row says 403 before any slot GET, which holds on slots/delete and the
//	          upload and not here (question record-m6-24-erase-on-push-route-reads-slots); this clause holds the
//	          push route to §11.12's row and I-EVS-16, no commit and no slot rewrite
//	twins     beside the refusals, the admin's ?closure=1 upload of the bytes X's was refused for is stored, and the
//	          admin's ERASE of one entry of A's commits and rewrites its slot without that key and no other, before
//	          the hold and under it
//	fresh     a member device that has read nothing then reads every entry A and B wrote, and every row their slots
//	          still hold but the two the admin erased
//
// Fs99EvsScopeOf's mutant gives X's tokens what its client asks for, as an exchange without §7.8's directory rule
// would, and must fail at X's first ERASE.
//
// Not here: which tokens §7.8's exchange mints a parked device under an ordinary member and under an AdminSet member
// (AclExchangeScopes over a team's state; the world's tokens are the test's, so the two read alike here and one
// device stands for both); a CLOSURE rewriting index files and the card and index cases, format 2's, at the later of
// M6-out and M10-out; the revocation, runner and reader legs, which are the authorship world's (fs99_test.go).

package fault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The world's device names.
const (
	fs99EvsAdmin    = "admin"
	fs99EvsWriterA  = "writerA"
	fs99EvsWriterB  = "writerB"
	fs99EvsAgentX   = "agentX"
	fs99EvsParked   = "parked"
	fs99EvsReadOnly = "readOnly"
	fs99EvsFresh    = "fresh"
)

// The roles a token's repo scope names (§7.8), the scope's prefix, and §11.6's segment magic and format.
const (
	fs99EvsRoleRead           = "r"
	fs99EvsRoleWrite          = "rw"
	fs99EvsRoleAdmin          = "admin"
	fs99EvsScopePrefix        = "repo:"
	fs99EvsSegmentMagic       = "URvs"
	fs99EvsSegmentFormat byte = 1
)

type Fs99EvsSettings struct {
	// The entries each of A's, B's and X's one push creates: 3, 2 and 1.
	WriterAEntryCount int
	WriterBEntryCount int
	AgentXEntryCount  int
	// The bytes a ?closure=1 upload carries past its 32 B header: 96.
	ClosureBodyByteCount int
	// How long the preservation hold placed mid-schedule lasts, on the Net's clock: 90 days.
	HoldDuration time.Duration
	// How far the clock moves once the hold is placed, past §11.13's 5 s bound on a cached hold/ read: 10 s.
	HoldReadAge time.Duration
	// How far the clock moves between two refused ERASEs on POST .../push, each of which evs records on the erasure
	// ref's head, at most one a RefusalFenceInterval, 1 s, a second inside it answering 429 WAIT: 2 s.
	RefusalSpacing time.Duration
	// X's tokens carry what its client asks for: the mutant.
	Mutant bool
}

func DefaultFs99EvsSettings() *Fs99EvsSettings {
	return &Fs99EvsSettings{
		WriterAEntryCount:    3,
		WriterBEntryCount:    2,
		AgentXEntryCount:     1,
		ClosureBodyByteCount: 96,
		HoldDuration:         90 * 24 * time.Hour,
		HoldReadAge:          10 * time.Second,
		RefusalSpacing:       2 * time.Second,
	}
}

// One entry a writer's push created: its path and bytes, and the slot key its row sits at.
type fs99EvsEntry struct {
	path     string
	content  []byte
	slotId   sidecar.Id
	keyIndex uint32
	row      []byte
}

// See the file header.
type fs99EvsWorld struct {
	world    *EvsWorld
	settings *Fs99EvsSettings

	stateLock sync.Mutex
	streams   map[string]*sidecar.RecordEvsStreams
	// by writer, in push order
	entries map[string][]*fs99EvsEntry
	// each slot's ETag as the last check that expected a change left it
	slotEtags map[sidecar.Id]string
	// the slot keys the admin's ERASEs destroyed
	erased map[sidecar.RecordSlotKey]bool
	// the body of the last POST .../slots/delete each device's client sent
	eraseBodies map[string][]byte
	// the ERASEs the erasure ref should hold
	erasureCount int
}

// A device's client's transport: every request carries a token of the role the device is held to, and the body of
// a POST .../slots/delete is kept.
type fs99EvsTransport struct {
	state  *fs99EvsWorld
	device string
	lb     http.RoundTripper
}

func (self *fs99EvsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	sent := request
	if role := self.state.heldRole(self.device); role != "" {
		token, err := self.state.token(self.device, role)
		if err != nil {
			return nil, err
		}
		sent = request.Clone(request.Context())
		sent.Header.Set("Authorization", "Bearer "+token)
	}
	if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/slots/delete") && request.Body != nil {
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		if sent == request {
			sent = request.Clone(request.Context())
		}
		sent.Body = io.NopCloser(bytes.NewReader(body))
		self.state.stateLock.Lock()
		self.state.eraseBodies[self.device] = body
		self.state.stateLock.Unlock()
	}
	return self.lb.RoundTrip(sent)
}

func newFs99EvsWorld(net *Net, settings *Fs99EvsSettings) *fs99EvsWorld {
	if settings == nil {
		settings = DefaultFs99EvsSettings()
	}
	self := &fs99EvsWorld{
		settings:    settings,
		streams:     map[string]*sidecar.RecordEvsStreams{},
		entries:     map[string][]*fs99EvsEntry{},
		slotEtags:   map[sidecar.Id]string{},
		erased:      map[sidecar.RecordSlotKey]bool{},
		eraseBodies: map[string][]byte{},
	}
	worldSettings := DefaultEvsWorldSettings()
	worldSettings.Kind = protocol.RepoKind_REPO_KIND_DIRECTORY
	worldSettings.Instances = []string{"evs1"}
	worldSettings.Devices = []*EvsWorldDeviceSettings{}
	for _, name := range []string{fs99EvsAdmin, fs99EvsWriterA, fs99EvsWriterB, fs99EvsAgentX, fs99EvsParked, fs99EvsReadOnly} {
		worldSettings.Devices = append(worldSettings.Devices, &EvsWorldDeviceSettings{
			Name: name, Instances: []string{"evs1"}, Writer: true, Admin: name == fs99EvsAdmin,
		})
	}
	worldSettings.Devices = append(worldSettings.Devices, &EvsWorldDeviceSettings{Name: fs99EvsFresh, Instances: []string{"evs1"}})
	worldSettings.DeviceTransport = func(device string, lb http.RoundTripper) http.RoundTripper {
		return &fs99EvsTransport{state: self, device: device, lb: lb}
	}
	self.world = NewEvsWorld(net, worldSettings)
	return self
}

// The role every token of device's carries, "" for what its client asks for.
func (self *fs99EvsWorld) heldRole(device string) string {
	switch device {
	case fs99EvsAgentX:
		if self.settings.Mutant {
			return ""
		}
		return fs99EvsRoleWrite
	case fs99EvsParked:
		return fs99EvsRoleWrite
	case fs99EvsReadOnly:
		return fs99EvsRoleRead
	}
	return ""
}

// A token of device's carrying role on the world's repo and nothing else.
func (self *fs99EvsWorld) token(device string, role string) (string, error) {
	return self.world.issueToken(self.world.Device(device), []string{fs99EvsScopePrefix + self.world.RepoId.String() + ":" + role})
}

// The record's binding of device, on a store of its own.
func (self *fs99EvsWorld) streamsOf(device string) (*sidecar.RecordEvsStreams, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if streams := self.streams[device]; streams != nil {
		return streams, nil
	}
	streams, err := sidecar.NewRecordEvsStreams(&sidecar.RecordEvsStreamsArgs{
		Client: self.world.Device(device).Client, Store: sidecartest.NewFakeStore().Root(),
	})
	if err != nil {
		return nil, err
	}
	self.streams[device] = streams
	return streams, nil
}

func (self *fs99EvsWorld) sidecarId(device string) sidecar.Id {
	return self.world.Device(device).Signer.SidecarId
}

// A step action: writer pushes count entries to its own stream, their rows in the push's one slot.
func (self *fs99EvsWorld) append(writer string, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		streams, err := self.streamsOf(writer)
		if err != nil {
			return err
		}
		push := &sidecar.RecordStreamPush{
			PushId: sidecar.NewEvsPushId(), WriterSidecarId: self.sidecarId(writer), SlotId: sidecar.NewEvsSlotId(),
			AuthPin: self.world.currentView().Pin(),
		}
		entries := []*fs99EvsEntry{}
		for index := range count {
			path, err := sidecar.RecordStreamPath(uint64(index + 1))
			if err != nil {
				return err
			}
			keyAndSalt := make([]byte, sidecar.RecordKeyByteCount+sidecar.RecordSaltByteCount)
			if _, err := rand.Read(keyAndSalt); err != nil {
				return err
			}
			row, err := sidecar.RecordSlotRowJoin(keyAndSalt[:sidecar.RecordKeyByteCount], keyAndSalt[sidecar.RecordKeyByteCount:])
			if err != nil {
				return err
			}
			entry := &fs99EvsEntry{
				path: path, content: []byte(fmt.Sprintf("fs99 %s entry %d", writer, index+1)),
				slotId: push.SlotId, keyIndex: uint32(index), row: row,
			}
			entries = append(entries, entry)
			push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: entry.keyIndex, Row: row})
			push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: entry.content})
		}
		if _, err := streams.Append(ctx, self.world.RepoId, push); err != nil {
			return fmt.Errorf("%s's push: %w", writer, err)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.entries[writer] = append(self.entries[writer], entries...)
		return nil
	}
}

// Every slot a push of the world introduced, in the writers' order.
func (self *fs99EvsWorld) slotIds() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	slotIds := []sidecar.Id{}
	seen := map[sidecar.Id]bool{}
	for _, writer := range []string{fs99EvsWriterA, fs99EvsWriterB, fs99EvsAgentX} {
		for _, entry := range self.entries[writer] {
			if !seen[entry.slotId] {
				seen[entry.slotId] = true
				slotIds = append(slotIds, entry.slotId)
			}
		}
	}
	return slotIds
}

// The slot keys of writer's entries from the first-th on.
func (self *fs99EvsWorld) keysOf(writer string, first int) []*sidecar.RecordSlotKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys := []*sidecar.RecordSlotKey{}
	for _, entry := range self.entries[writer][first:] {
		keys = append(keys, &sidecar.RecordSlotKey{SlotId: entry.slotId, KeyIndex: entry.keyIndex})
	}
	return keys
}

// Each slot object's ETag in the store now, read under an inspecting context.
func (self *fs99EvsWorld) readSlotEtags(ctx context.Context, net *Net) (map[sidecar.Id]string, error) {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	etags := map[sidecar.Id]string{}
	for _, slotId := range self.slotIds() {
		info, err := cluster.Head(sidecartest.InspectContext(ctx), evsservice.SlotKey(self.world.RepoId, slotId))
		if err != nil {
			return nil, fmt.Errorf("slot %s: %w", slotId, err)
		}
		etags[slotId] = info.Etag
	}
	return etags, nil
}

// A step action: every slot's ETag is kept as it stands.
func (self *fs99EvsWorld) noteSlots() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		etags, err := self.readSlotEtags(ctx, net)
		if err != nil {
			return err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.slotEtags = etags
		return nil
	}
}

// What a refusal must leave: every slot's ETag as it was kept, and the erasure ref holding only the admin's ERASEs.
func (self *fs99EvsWorld) unchanged(ctx context.Context, net *Net) error {
	etags, err := self.readSlotEtags(ctx, net)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	kept := self.slotEtags
	erasureCount := self.erasureCount
	self.stateLock.Unlock()
	for slotId, etag := range etags {
		if kept[slotId] != etag {
			return fmt.Errorf("slot %s was rewritten", slotId)
		}
	}
	admin, err := self.streamsOf(fs99EvsAdmin)
	if err != nil {
		return err
	}
	erasures, err := admin.ReadErasures(sidecartest.InspectContext(ctx), self.world.RepoId, 0)
	if err != nil {
		return fmt.Errorf("the erasure ref: %w", err)
	}
	if len(erasures) != erasureCount {
		return fmt.Errorf("the erasure ref holds %d ERASEs, not %d", len(erasures), erasureCount)
	}
	return nil
}

// The store requests since index that named a slot object of the world's, each as "<op> <key>".
func (self *fs99EvsWorld) slotRequestsSince(net *Net, index int) []string {
	slotKeys := map[string]bool{}
	for _, slotId := range self.slotIds() {
		slotKeys[evsservice.SlotKey(self.world.RepoId, slotId)] = true
	}
	requests := []string{}
	history := net.BlobHistory()
	for _, entry := range history[min(index, len(history)):] {
		if slotKeys[entry.Key] {
			requests = append(requests, fmt.Sprintf("%s %s", entry.Op, entry.Key))
		}
	}
	return requests
}

// A step action: device's ERASE of keys is refused SCOPE, with no request to a slot object, every slot as it was and
// nothing new on the erasure ref.
func (self *fs99EvsWorld) eraseRefused(device string, what string, keys func() []*sidecar.RecordSlotKey) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		streams, err := self.streamsOf(device)
		if err != nil {
			return err
		}
		mark := net.BlobHistoryCount()
		_, err = streams.Erase(ctx, self.world.RepoId, &sidecar.RecordStreamErase{
			PushId: sidecar.NewEvsPushId(), ErasureId: sidecar.NewId(), Complete: true, Keys: keys(),
		})
		if err == nil {
			return fmt.Errorf("%s was not refused", what)
		}
		if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
			return fmt.Errorf("%s: %w", what, err)
		}
		if requests := self.slotRequestsSince(net, mark); 0 < len(requests) {
			return fmt.Errorf("%s reached slot objects before its refusal: %v", what, requests)
		}
		if err := self.unchanged(ctx, net); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	}
}

// One request of device's carrying a token of role, past its client: the status, and a refusal's code.
func (self *fs99EvsWorld) send(ctx context.Context, device string, role string, method string, pathRest string, body []byte) (int, protocol.EvsRefusalCode, error) {
	token, err := self.token(device, role)
	if err != nil {
		return 0, 0, err
	}
	url := "https://evs.example/evs/v1/repos/" + hex.EncodeToString(self.world.RepoId[:]) + pathRest
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := self.world.Device(device).transport.RoundTrip(request)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	replyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, 0, err
	}
	if response.StatusCode == http.StatusOK {
		return response.StatusCode, 0, nil
	}
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(replyBytes, reply); err != nil {
		return response.StatusCode, 0, nil
	}
	return response.StatusCode, reply.GetCode(), nil
}

// A format-1 segment of the world's repo no push names, and its id: §11.6's 32 B public header and bytes after it.
func (self *fs99EvsWorld) closureSegment() ([]byte, [sha256.Size]byte, error) {
	segment := make([]byte, sidecar.EvsSegmentHeaderByteCount+self.settings.ClosureBodyByteCount)
	copy(segment[0:4], fs99EvsSegmentMagic)
	segment[4] = fs99EvsSegmentFormat
	copy(segment[8:24], self.world.RepoId[:])
	// the repo's first generation
	binary.BigEndian.PutUint64(segment[24:sidecar.EvsSegmentHeaderByteCount], 1)
	if _, err := rand.Read(segment[sidecar.EvsSegmentHeaderByteCount:]); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return segment, sha256.Sum256(segment), nil
}

// Whether the segment cluster holds the segment, read under an inspecting context.
func (self *fs99EvsWorld) segmentStored(ctx context.Context, net *Net, segmentId [sha256.Size]byte) (bool, error) {
	cluster, err := net.Host().Blobs.SegmentCluster()
	if err != nil {
		return false, err
	}
	_, err = cluster.Head(sidecartest.InspectContext(ctx), evsservice.SegmentKey(self.world.RepoId, segmentId))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return false, nil
	}
	return false, err
}

// A step action: device's ?closure=1 upload, under a token of role, is refused SCOPE with nothing stored and no slot
// reached; then, with twin, the admin's upload of the same bytes is stored.
func (self *fs99EvsWorld) closureUploadRefused(device string, role string, twin bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		segment, segmentId, err := self.closureSegment()
		if err != nil {
			return err
		}
		pushId := sidecar.NewEvsPushId()
		pathRest := "/segments/" + hex.EncodeToString(segmentId[:]) + "?push=" + hex.EncodeToString(pushId[:]) + "&closure=1"
		mark := net.BlobHistoryCount()
		status, code, err := self.send(ctx, device, role, http.MethodPut, pathRest, segment)
		if err != nil {
			return err
		}
		if status != http.StatusForbidden || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
			return fmt.Errorf("%s's ?closure=1 upload was not refused SCOPE: %d %s", device, status, code)
		}
		if requests := self.slotRequestsSince(net, mark); 0 < len(requests) {
			return fmt.Errorf("%s's ?closure=1 upload reached slot objects: %v", device, requests)
		}
		stored, err := self.segmentStored(ctx, net, segmentId)
		if err != nil {
			return err
		}
		if stored {
			return fmt.Errorf("%s's refused ?closure=1 upload was stored", device)
		}
		if err := self.unchanged(ctx, net); err != nil {
			return fmt.Errorf("%s's ?closure=1 upload: %w", device, err)
		}
		if !twin {
			return nil
		}
		status, code, err = self.send(ctx, fs99EvsAdmin, fs99EvsRoleAdmin, http.MethodPut, pathRest, segment)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("the admin's ?closure=1 upload: %d %s", status, code)
		}
		stored, err = self.segmentStored(ctx, net, segmentId)
		if err != nil {
			return err
		}
		if !stored {
			return errors.New("the admin's ?closure=1 upload was not stored")
		}
		return nil
	}
}

// A step action: the ERASE device's client last sent to POST .../slots/delete, sent to POST .../push under a token of
// role, is refused SCOPE with every slot as it was and nothing new on the erasure ref.
func (self *fs99EvsWorld) eraseOnPushRefused(device string, role string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		body := self.eraseBodies[device]
		self.stateLock.Unlock()
		if body == nil {
			return fmt.Errorf("%s sent no ERASE to send again", device)
		}
		mark := net.BlobHistoryCount()
		status, code, err := self.send(ctx, device, role, http.MethodPost, "/push", body)
		if err != nil {
			return err
		}
		if status != http.StatusForbidden || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
			return fmt.Errorf("%s's ERASE on POST .../push was not refused SCOPE: %d %s", device, status, code)
		}
		for _, request := range self.slotRequestsSince(net, mark) {
			// step 4 reads the slots an rw token's ERASE names before 5c refuses it (the file header's push row)
			if !strings.HasPrefix(request, string(sidecartest.BlobHistoryGet)+" ") {
				return fmt.Errorf("%s's ERASE on POST .../push wrote a slot object: %s", device, request)
			}
		}
		if err := self.unchanged(ctx, net); err != nil {
			return fmt.Errorf("%s's ERASE on POST .../push: %w", device, err)
		}
		return nil
	}
}

// A step action: the admin's ERASE of writer's index-th entry commits, and its slot is rewritten without that key,
// every other key and every other slot as it was.
func (self *fs99EvsWorld) adminErases(writer string, index int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		entry := self.entries[writer][index]
		before := self.slotEtags
		self.stateLock.Unlock()
		streams, err := self.streamsOf(fs99EvsAdmin)
		if err != nil {
			return err
		}
		erasureId := sidecar.NewId()
		if _, err := streams.Erase(ctx, self.world.RepoId, &sidecar.RecordStreamErase{
			PushId: sidecar.NewEvsPushId(), ErasureId: erasureId, Complete: true,
			Keys: []*sidecar.RecordSlotKey{{SlotId: entry.slotId, KeyIndex: entry.keyIndex}},
		}); err != nil {
			return fmt.Errorf("the admin's ERASE of %s's entry: %w", writer, err)
		}
		etags, err := self.readSlotEtags(ctx, net)
		if err != nil {
			return err
		}
		for slotId, etag := range etags {
			if (before[slotId] != etag) != (slotId == entry.slotId) {
				return fmt.Errorf("slot %s after the admin's ERASE of slot %s: rewritten %t", slotId, entry.slotId, before[slotId] != etag)
			}
		}
		cluster, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		object, err := cluster.Get(sidecartest.InspectContext(ctx), evsservice.SlotKey(self.world.RepoId, entry.slotId))
		if err != nil {
			return err
		}
		slotBytes, err := io.ReadAll(object.Body)
		object.Body.Close()
		if err != nil {
			return err
		}
		slot, err := sidecar.EvsDecodeSlotObject(slotBytes)
		if err != nil {
			return err
		}
		self.stateLock.Lock()
		self.slotEtags = etags
		self.erased[sidecar.RecordSlotKey{SlotId: entry.slotId, KeyIndex: entry.keyIndex}] = true
		self.erasureCount += 1
		erasureCount := self.erasureCount
		slotEntries := []*fs99EvsEntry{}
		for _, other := range self.entries[writer] {
			if other.slotId == entry.slotId {
				slotEntries = append(slotEntries, other)
			}
		}
		erased := map[sidecar.RecordSlotKey]bool{}
		for key := range self.erased {
			erased[key] = true
		}
		self.stateLock.Unlock()
		for _, other := range slotEntries {
			_, held := sidecar.EvsSlotKeyAt(slot, other.keyIndex)
			if held == erased[sidecar.RecordSlotKey{SlotId: other.slotId, KeyIndex: other.keyIndex}] {
				return fmt.Errorf("slot %s key %d after the admin's ERASE: held %t", other.slotId, other.keyIndex, held)
			}
		}
		erasures, err := streams.ReadErasures(ctx, self.world.RepoId, 0)
		if err != nil {
			return err
		}
		if len(erasures) != erasureCount {
			return fmt.Errorf("the erasure ref holds %d ERASEs, not %d", len(erasures), erasureCount)
		}
		newest := erasures[len(erasures)-1]
		if newest.ErasureId != erasureId || newest.EraserSidecarId != self.sidecarId(fs99EvsAdmin) {
			return errors.New("the erasure ref's newest ERASE is not the admin's")
		}
		return nil
	}
}

// A step action: a preservation hold covering the world's network stands from now.
func (self *fs99EvsWorld) placeHold() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		now := net.Clock().Now()
		return sidecartest.PlaceHold(sidecartest.InspectContext(ctx), net.Host().Blobs, &sidecar.HoldRecord{
			NetworkId: self.world.NetworkId, CaseId: sidecar.NewId(), Kind: sidecar.HoldKindPreserve2703f,
			Scope: sidecar.HoldScopeNetwork(), PlaceTime: now, ExpireTime: now.Add(self.settings.HoldDuration),
		})
	}
}

// A step action: device, which has read nothing, reads every entry A and B wrote and every row their slots hold,
// which are all but the ones the admin erased.
func (self *fs99EvsWorld) freshReads(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		streams, err := self.streamsOf(device)
		if err != nil {
			return err
		}
		for _, writer := range []string{fs99EvsWriterA, fs99EvsWriterB} {
			self.stateLock.Lock()
			entries := self.entries[writer]
			erased := map[sidecar.RecordSlotKey]bool{}
			for key := range self.erased {
				erased[key] = true
			}
			self.stateLock.Unlock()
			versions, err := streams.ReadStream(ctx, self.world.RepoId, self.sidecarId(writer), 0)
			if err != nil {
				return fmt.Errorf("%s's stream: %w", writer, err)
			}
			read := map[string][]byte{}
			for _, version := range versions {
				for _, entry := range version.Entries {
					read[entry.Path] = entry.Entry
				}
			}
			if len(read) != len(entries) {
				return fmt.Errorf("%s's stream reads %d entries, not %d", writer, len(read), len(entries))
			}
			slots := map[sidecar.Id]map[uint32][]byte{}
			for _, entry := range entries {
				if !bytes.Equal(read[entry.path], entry.content) {
					return fmt.Errorf("%s's entry %s does not read as written", writer, entry.path)
				}
				rows := slots[entry.slotId]
				if rows == nil {
					slot, err := streams.ReadSlot(ctx, self.world.RepoId, entry.slotId)
					if err != nil {
						return fmt.Errorf("%s's slot: %w", writer, err)
					}
					rows = map[uint32][]byte{}
					for _, row := range slot.Rows {
						rows[row.KeyIndex] = row.Row
					}
					slots[entry.slotId] = rows
				}
				row, held := rows[entry.keyIndex]
				switch {
				case erased[sidecar.RecordSlotKey{SlotId: entry.slotId, KeyIndex: entry.keyIndex}]:
					if held {
						return fmt.Errorf("%s's erased entry %s still has its key", writer, entry.path)
					}
				case !held || !bytes.Equal(row, entry.row):
					return fmt.Errorf("%s's entry %s does not open: its key is gone or changed", writer, entry.path)
				}
			}
		}
		return nil
	}
}

// The refusals of one round, before the hold and again under it.
func (self *fs99EvsWorld) refusals(steps []*Step, round string, twin bool) []*Step {
	aKeys := func() []*sidecar.RecordSlotKey { return self.keysOf(fs99EvsWriterA, 0) }
	mixedKeys := func() []*sidecar.RecordSlotKey {
		return append(self.keysOf(fs99EvsAgentX, 0), self.keysOf(fs99EvsWriterA, 0)...)
	}
	return append(steps,
		&Step{Actor: fs99EvsAgentX, Action: self.eraseRefused(fs99EvsAgentX, "X's ERASE naming A's entry slots"+round, aKeys)},
		&Step{Actor: fs99EvsAgentX, Action: self.eraseRefused(fs99EvsAgentX, "X's ERASE mixing its own slot with A's"+round, mixedKeys)},
		&Step{Actor: fs99EvsAgentX, Action: self.closureUploadRefused(fs99EvsAgentX, fs99EvsRoleWrite, twin)},
		&Step{Actor: fs99EvsAgentX, Action: self.eraseOnPushRefused(fs99EvsAgentX, fs99EvsRoleWrite)},
		&Step{Actor: fs99EvsParked, Action: self.eraseRefused(fs99EvsParked, "the parked device's ERASE naming A's entry slots"+round, aKeys)},
		&Step{Actor: fs99EvsParked, Action: self.closureUploadRefused(fs99EvsParked, fs99EvsRoleWrite, false)},
		&Step{Advance: self.settings.RefusalSpacing},
		&Step{Actor: fs99EvsParked, Action: self.eraseOnPushRefused(fs99EvsParked, fs99EvsRoleWrite)},
		&Step{Actor: fs99EvsReadOnly, Action: self.eraseRefused(fs99EvsReadOnly, "the read_only sidecar's ERASE naming A's entry slots"+round, aKeys)},
		&Step{Actor: fs99EvsReadOnly, Action: self.closureUploadRefused(fs99EvsReadOnly, fs99EvsRoleRead, false)},
		&Step{Advance: self.settings.RefusalSpacing},
		&Step{Actor: fs99EvsReadOnly, Action: self.eraseOnPushRefused(fs99EvsReadOnly, fs99EvsRoleRead)},
	)
}

// FS-99's evs clause: see the file header.
func Fs99EvsScope(net *Net) *Schedule {
	return Fs99EvsScopeOf(net, nil)
}

// FS-99's evs clause under settings, nil for the defaults.
func Fs99EvsScopeOf(net *Net, settings *Fs99EvsSettings) *Schedule {
	if settings == nil {
		settings = DefaultFs99EvsSettings()
	}
	state := newFs99EvsWorld(net, settings)
	world := state.world
	steps := []*Step{
		{Actor: fs99EvsAdmin, Action: world.Setup},
		{Actor: fs99EvsWriterA, Action: state.append(fs99EvsWriterA, settings.WriterAEntryCount)},
		{Actor: fs99EvsWriterB, Action: state.append(fs99EvsWriterB, settings.WriterBEntryCount)},
		{Actor: fs99EvsAgentX, Action: state.append(fs99EvsAgentX, settings.AgentXEntryCount)},
		{Actor: "check", Action: state.noteSlots()},
	}
	steps = state.refusals(steps, "", true)
	steps = append(steps,
		&Step{Actor: fs99EvsAdmin, Action: state.adminErases(fs99EvsWriterA, 0)},
		&Step{Actor: "counsel", Action: state.placeHold()},
		&Step{Advance: settings.HoldReadAge},
	)
	steps = state.refusals(steps, " under the hold", true)
	steps = append(steps,
		&Step{Actor: fs99EvsAdmin, Action: state.adminErases(fs99EvsWriterA, 1)},
		&Step{Actor: fs99EvsFresh, Action: state.freshReads(fs99EvsFresh)},
	)
	return &Schedule{Id: "FS-99", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
