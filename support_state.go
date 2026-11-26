//go:build !ios_extension && !sidecar_http

// The support client's state in the device's sealed store (DESIGN-COMPUTE §28.6, §28.9, §28.14): the conversation's
// view and the events' cursor, what this device sent for §28.14's limits, the person's support key, and the outbox, one
// file a message and one a message's attachment, so a body and its bundle are in the device's state before the first
// post and a crash at any step posts the message once.
//
//	state.json                 the view, the cursor, the sends of the last day and the person's key
//	outbox/<client_ref>.json   one message: its body as posted, its state and attempts, its kind-27 action
//	outbox/<client_ref>.<n>    its attachments: 0 the support log's bundle, 1 to 3 its files
//
// Each change reads, changes and writes its file under storeLock, so two changes never interleave. The view's items are
// bounded by ConversationMaxItemCount, oldest first out; the outbox by §28.14's limits.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The state's files.
const (
	supportStateFileName = "state.json"
	supportOutboxPrefix  = "outbox/"
)

// An outbox message's states.
const (
	// waiting for its post, or the next try
	supportOutboxPending = "pending"
	// waiting for kind 27's decision
	supportOutboxAwaiting = "awaiting"
	// posted, its attachments kept SentBundleRetention for the person to read
	supportOutboxPosted = "posted"
	// not sent after RetryWindow, or refused by the service: shown as not sent, never sent again but by the person
	supportOutboxGivenUp = "given_up"
)

// What an outbox lookup answers for a message it does not hold.
var errSupportOutboxItemAbsent = errors.New("support: no such message in the outbox")

// One message in the outbox.
type supportOutboxItem struct {
	ClientRef string `json:"client_ref"`
	// the SupportBody exactly as posted, which field 3 hashes: bytes, never re-encoded
	Body  []byte `json:"body"`
	Entry string `json:"entry,omitempty"`
	Seq   uint32 `json:"seq,omitempty"`
	// The agent's name, empty for the person, for the limits.
	Agent   string      `json:"agent,omitempty"`
	AgentId *Id         `json:"agent_id,omitempty"`
	RunId   *Id         `json:"run_id,omitempty"`
	Tier    SupportTier `json:"tier"`
	// Who let it go, posted beside the body with its tier (QD-1398): none, or kind 27's decider once its effect ran;
	// empty while a decision is awaited.
	Approved string `json:"approved,omitempty"`
	// whether attachment 0 is the support log's bundle, and how many files follow it
	Logs      bool     `json:"logs,omitempty"`
	FileCount int      `json:"file_count,omitempty"`
	FileTypes []uint32 `json:"file_types,omitempty"`
	// The bundle's manifest, which the vault's entry carries (§28.12): codes and counts, never an event's fields.
	Manifest *SupportLogManifest `json:"manifest,omitempty"`
	// Whether the vault's kind-30 entry of the message as it left is written (§28.12), so a retry writes none again.
	Recorded bool `json:"recorded,omitempty"`
	// kind 27's action as stored, and its request's id
	Canonical  []byte `json:"canonical,omitempty"`
	ApprovalId *Id    `json:"approval_id,omitempty"`
	State      string `json:"state"`
	Attempts   int    `json:"attempts,omitempty"`
	// Unix milliseconds
	CreatedMillis int64  `json:"created_ms"`
	NextMillis    int64  `json:"next_ms,omitempty"`
	Disclosure    uint32 `json:"disclosure"`
}

// One message this device sent, for the limits.
type supportSend struct {
	Agent  string `json:"agent,omitempty"`
	Millis int64  `json:"ms"`
}

// One message or reply of an item, in the view.
type supportItemMessage struct {
	Seq       uint32      `json:"seq"`
	ClientRef string      `json:"client_ref,omitempty"`
	Agent     string      `json:"agent,omitempty"`
	Tier      SupportTier `json:"tier,omitempty"`
	Text      string      `json:"text"`
	Millis    int64       `json:"ms"`
	Reply     bool        `json:"reply,omitempty"`
}

// One item of the member's conversation, as this device has read it.
type supportItem struct {
	Entry         string                `json:"entry"`
	Status        string                `json:"status"`
	FixedIn       string                `json:"fixed_in,omitempty"`
	Final         bool                  `json:"final"`
	FirstMillis   int64                 `json:"first_ms"`
	UpdatedMillis int64                 `json:"updated_ms"`
	Messages      []*supportItemMessage `json:"messages"`
	// the agents that sent on it, by name
	Agents []string `json:"agents,omitempty"`
	// the seq each reader, by agent name and "" for the person, has read through
	ReadThrough map[string]uint32 `json:"read_through,omitempty"`
}

// The state file.
type supportState struct {
	Cursor           string            `json:"cursor,omitempty"`
	Items            []*supportItem    `json:"items"`
	Sends            []*supportSend    `json:"sends"`
	PersonKey        *SupportPersonKey `json:"person_key"`
	LastBundleMillis int64             `json:"last_bundle_ms,omitempty"`
	// the agent of each message waiting in the outbox, by client_ref, for the outbox's limits
	Waiting map[string]string `json:"waiting,omitempty"`
}

// The item of entry, nil for none.
func (self *supportState) item(entry string) *supportItem {
	for _, item := range self.Items {
		if item.Entry == entry {
			return item
		}
	}
	return nil
}

// When entry's first message went, zero for an item this device does not hold.
func (self *supportState) itemStart(entry string) time.Time {
	if item := self.item(entry); item != nil && 0 < item.FirstMillis {
		return time.UnixMilli(item.FirstMillis)
	}
	return time.Time{}
}

// The item of entry, made where there is none, the oldest dropped past maxCount.
func (self *supportState) itemOrNew(entry string, now time.Time, maxCount int) *supportItem {
	if item := self.item(entry); item != nil {
		return item
	}
	item := &supportItem{Entry: entry, Status: "received", FirstMillis: now.UnixMilli(), UpdatedMillis: now.UnixMilli(), Messages: []*supportItemMessage{}}
	self.Items = append(self.Items, item)
	if maxCount < len(self.Items) {
		slices.SortFunc(self.Items, func(a *supportItem, b *supportItem) int { return int(a.UpdatedMillis - b.UpdatedMillis) })
		self.Items = self.Items[len(self.Items)-maxCount:]
	}
	return item
}

// Takes event into the view: the item it names, its status, and a message or reply. False where the view held its
// entry and seq already, which a repeat or a second device's copy is. An event with no time takes now.
func (self *supportState) apply(event *SupportServiceEvent, now time.Time, maxCount int) (*supportItem, bool) {
	at := event.At
	if at.IsZero() {
		at = now
	}
	item := self.itemOrNew(event.Entry, at, maxCount)
	for _, message := range item.Messages {
		if message.Seq == event.Seq {
			return item, false
		}
	}
	if event.Status != "" {
		item.Status = event.Status
	}
	if event.FixedIn != "" {
		item.FixedIn = event.FixedIn
	}
	item.Final = event.Final
	item.UpdatedMillis = max(item.UpdatedMillis, at.UnixMilli())
	switch event.Type {
	case "note":
		item.Messages = append(item.Messages, &supportItemMessage{Seq: event.Seq, Text: event.Note, Millis: at.UnixMilli(), Reply: true})
	case "submitted", "followup":
		message := &supportItemMessage{Seq: event.Seq, ClientRef: event.ClientRef, Agent: event.Agent, Tier: event.Tier, Text: event.Body, Millis: at.UnixMilli()}
		for _, held := range item.Messages {
			// this device's own message, which the view took as it was acknowledged
			if supportSameClientRef(held.ClientRef, event.ClientRef) {
				held.Seq = event.Seq
				return item, false
			}
		}
		item.Messages = append(item.Messages, message)
		if event.Agent != "" && !slices.Contains(item.Agents, event.Agent) {
			item.Agents = append(item.Agents, event.Agent)
		}
	default:
		// a status, a fixed_in, a link or a merge: its fields above, a seq held so it applies once
		item.Messages = append(item.Messages, &supportItemMessage{Seq: event.Seq, Millis: at.UnixMilli(), Reply: true})
	}
	slices.SortFunc(item.Messages, func(a *supportItemMessage, b *supportItemMessage) int { return int(a.Seq) - int(b.Seq) })
	return item, true
}

// Takes a message this device sent into the view as the service acknowledged it. False where the view held it
// already: a replay's answer, or the member's events that brought it first.
func (self *supportState) applySent(answer *supportEntryAnswer, item *supportOutboxItem, body *SupportBody, now time.Time, maxCount int) bool {
	viewed := self.itemOrNew(answer.Id, now, maxCount)
	if answer.Status != "" {
		viewed.Status = answer.Status
	}
	for _, message := range viewed.Messages {
		if supportSameClientRef(message.ClientRef, item.ClientRef) || message.Seq == answer.Seq {
			return false
		}
	}
	viewed.Messages = append(viewed.Messages, &supportItemMessage{
		Seq: answer.Seq, ClientRef: item.ClientRef, Agent: item.Agent, Tier: item.Tier, Text: body.Text, Millis: now.UnixMilli(),
	})
	viewed.UpdatedMillis = now.UnixMilli()
	if item.Agent != "" && !slices.Contains(viewed.Agents, item.Agent) {
		viewed.Agents = append(viewed.Agents, item.Agent)
	}
	return true
}

// Drops the sends past a day, which no limit counts.
func (self *supportState) prune(now time.Time, settings *SupportSettings) {
	dayAgo := now.Add(-24 * time.Hour).UnixMilli()
	self.Sends = slices.DeleteFunc(self.Sends, func(send *supportSend) bool { return send.Millis < dayAgo })
}

// An item's stub for reader, an agent's name or "" for the person.
func (self *supportItem) stub(reader string) *SupportItemStub {
	stub := &SupportItemStub{
		Entry: self.Entry, Status: self.Status, FixedIn: self.FixedIn, Final: self.Final, FirstMillis: self.FirstMillis,
		UpdatedMillis: self.UpdatedMillis, Senders: []string{},
	}
	readThrough := self.ReadThrough[reader]
	for _, message := range self.Messages {
		switch {
		case message.Reply && message.Text != "":
			stub.Replies += 1
			if readThrough < message.Seq {
				stub.UnreadReplies += 1
			}
		case !message.Reply:
			stub.Messages += 1
			sender := message.Agent
			if sender == "" {
				sender = "you"
			}
			if !slices.Contains(stub.Senders, sender) {
				stub.Senders = append(stub.Senders, sender)
			}
		}
	}
	return stub
}

// Marks every message read through the newest for reader.
func (self *supportItem) markRead(reader string) {
	newest := uint32(0)
	for _, message := range self.Messages {
		newest = max(newest, message.Seq)
	}
	if self.ReadThrough == nil {
		self.ReadThrough = map[string]uint32{}
	}
	self.ReadThrough[reader] = newest
}

// The client's store, or why there is none yet.
func (self *SupportClient) supportStore() (SidecarStore, error) {
	store, err := self.store()
	if err != nil {
		return nil, fmt.Errorf("support state: %w", err)
	}
	return store, nil
}

// The state as stored, its defaults where there is none: the person's key on, as §28.6 sets it.
func (self *SupportClient) loadState() (*supportState, error) {
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	return self.loadStateWithStoreLock()
}

// loadState's work, its caller holding storeLock.
func (self *SupportClient) loadStateWithStoreLock() (*supportState, error) {
	state := &supportState{Items: []*supportItem{}, Sends: []*supportSend{}, PersonKey: &SupportPersonKey{Agents: true, AgentLogs: true}}
	store, err := self.supportStore()
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(supportStateFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("support state: %w", err)
	}
	defer reader.Close()
	data, err := supportReadAll(reader, self.settings.StateMaxByteCount)
	if err != nil {
		return nil, fmt.Errorf("support state: %w", err)
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("support state: %w", err)
	}
	if state.PersonKey == nil {
		state.PersonKey = &SupportPersonKey{Agents: true, AgentLogs: true}
	}
	return state, nil
}

// Reads the state, changes it and writes it back, durably, under storeLock.
func (self *SupportClient) changeState(change func(state *supportState) error) error {
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	state, err := self.loadStateWithStoreLock()
	if err != nil {
		return err
	}
	if err := change(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	store, err := self.supportStore()
	if err != nil {
		return err
	}
	return supportWriteStoreFile(store, supportStateFileName, data)
}

// Writes name whole and durably.
func supportWriteStoreFile(store SidecarStore, name string, data []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return fmt.Errorf("support state: %w", err)
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("support state: %w", err)
	}
	return writer.Commit()
}

// An outbox file's name.
func supportOutboxName(clientRef string, suffix string) string {
	return supportOutboxPrefix + clientRef + suffix
}

// Writes item's attachments and then item, so a message is whole in the outbox before it can post; the waiting list
// takes it where it is pending. A message of this client_ref already there is kept: a resumed run's repeat posts once.
func (self *SupportClient) storeOutboxItem(item *supportOutboxItem, attachments [][]byte, bundle *SupportLogBundle) error {
	if _, err := self.outboxItem(item.ClientRef); err == nil {
		return nil
	}
	store, err := self.supportStore()
	if err != nil {
		return err
	}
	for index, data := range attachments {
		if data == nil {
			continue
		}
		if err := supportWriteStoreFile(store, supportOutboxName(item.ClientRef, "."+strconv.Itoa(index)), data); err != nil {
			return err
		}
	}
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if err := func() error {
		self.storeLock.Lock()
		defer self.storeLock.Unlock()
		return supportWriteStoreFile(store, supportOutboxName(item.ClientRef, ".json"), data)
	}(); err != nil {
		return err
	}
	// it counts against §28.14's limits from now, whether it waits for its post or for a decision, so a backlog the
	// service's return releases cannot pass them
	return self.changeState(func(state *supportState) error {
		state.Sends = append(state.Sends, &supportSend{Agent: item.Agent, Millis: item.CreatedMillis})
		if item.Logs {
			state.LastBundleMillis = item.CreatedMillis
		}
		if item.State == supportOutboxPending {
			if state.Waiting == nil {
				state.Waiting = map[string]string{}
			}
			state.Waiting[item.ClientRef] = item.Agent
		}
		return nil
	})
}

// A pending message into the outbox, and the loop woken to post it.
func (self *SupportClient) enqueue(item *supportOutboxItem, attachments [][]byte, bundle *SupportLogBundle) error {
	if err := self.storeOutboxItem(item, attachments, bundle); err != nil {
		return err
	}
	self.poke()
	return nil
}

// Counts a message as waiting, for the outbox's limits.
func (self *SupportClient) noteWaiting(clientRef string) error {
	item, err := self.outboxItem(clientRef)
	if err != nil {
		return err
	}
	return self.changeState(func(state *supportState) error {
		if state.Waiting == nil {
			state.Waiting = map[string]string{}
		}
		state.Waiting[clientRef] = item.Agent
		return nil
	})
}

// Stops counting a message as waiting.
func (self *SupportClient) dropWaiting(clientRef string) {
	self.changeState(func(state *supportState) error {
		delete(state.Waiting, clientRef)
		return nil
	})
}

// One outbox message, errSupportOutboxItemAbsent for none.
func (self *SupportClient) outboxItem(clientRef string) (*supportOutboxItem, error) {
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	return self.outboxItemWithStoreLock(clientRef)
}

// outboxItem's work, its caller holding storeLock.
func (self *SupportClient) outboxItemWithStoreLock(clientRef string) (*supportOutboxItem, error) {
	store, err := self.supportStore()
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(supportOutboxName(clientRef, ".json"))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, errSupportOutboxItemAbsent
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := supportReadAll(reader, self.settings.StateMaxByteCount)
	if err != nil {
		return nil, err
	}
	item := &supportOutboxItem{}
	if err := json.Unmarshal(data, item); err != nil {
		return nil, err
	}
	return item, nil
}

// Every outbox message, oldest first.
func (self *SupportClient) outboxItems() ([]*supportOutboxItem, error) {
	store, err := self.supportStore()
	if err != nil {
		return nil, err
	}
	entries, err := store.List(supportOutboxPrefix)
	if err != nil {
		return nil, err
	}
	items := []*supportOutboxItem{}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.Name, supportOutboxPrefix)
		clientRef, ok := strings.CutSuffix(name, ".json")
		if !ok {
			continue
		}
		item, err := self.outboxItem(clientRef)
		if err != nil {
			continue
		}
		items = append(items, item)
	}
	slices.SortFunc(items, func(a *supportOutboxItem, b *supportOutboxItem) int { return int(a.CreatedMillis - b.CreatedMillis) })
	return items, nil
}

// Changes one outbox message durably, under storeLock.
func (self *SupportClient) changeOutboxItem(clientRef string, change func(item *supportOutboxItem)) error {
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	item, err := self.outboxItemWithStoreLock(clientRef)
	if err != nil {
		return err
	}
	change(item)
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	store, err := self.supportStore()
	if err != nil {
		return err
	}
	return supportWriteStoreFile(store, supportOutboxName(clientRef, ".json"), data)
}

// One attachment of an outbox message: 0 its bundle, 1 to 3 its files.
func (self *SupportClient) outboxAttachment(clientRef string, index int) ([]byte, error) {
	store, err := self.supportStore()
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(supportOutboxName(clientRef, "."+strconv.Itoa(index)))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return supportReadAll(reader, max(self.settings.FileMaxByteCount, self.log.bundleMaxByteCount()))
}

// Removes a message and its attachments from the outbox.
func (self *SupportClient) removeOutboxItem(clientRef string) {
	store, err := self.supportStore()
	if err != nil {
		return
	}
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	for index := 0; index <= self.settings.FileMaxCount; index += 1 {
		store.Remove(supportOutboxName(clientRef, "."+strconv.Itoa(index)))
	}
	store.Remove(supportOutboxName(clientRef, ".json"))
}

// A bundle's bound, the largest attachment 0 can be; 0 with no log.
func (self *SupportLog) bundleMaxByteCount() int64 {
	if self == nil {
		return 0
	}
	return self.settings.BundleMaxByteCount
}
