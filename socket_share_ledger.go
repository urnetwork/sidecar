//go:build !sidecar_http && !ios_extension

// §9.9's share record (D-SOCK-16; SOCK-M5-15): one append-only sealed log per share at share/<token> in the network's
// local store, file class share (§5.9), each row fsynced before the step it guards, as §16's reserve-before-effect
// ledger is (D-MCP-11), so a crash or a lost stream never frees a Reserve. Rows are sealed JSON, never proto, so no
// server-visible field is added (§2.8):
//
//	{"row":"share","body":{"token","path","size","mtime","sha256","secret","uses","expire_millis"}}  at add, hashed
//	{"row":"reserve","body":{"get_id","use_index","getter_sidecar_id","millis"}}                   before a get's bytes
//	{"row":"done","body":{"get_id","millis"}}                                                       on its getter's done
//	{"row":"remove","body":{"millis"}}                                                              ur share rm
//
// The share row comes first, once; uses 0 is unlimited until a Remove or expire_millis (QD-241). A Reserve takes the
// next use_index and a get_id no Reserve holds, a Done names a reserved get_id once, and a Remove is kept once: the
// sharer writes nothing else, so anything else, an unknown row kind included, reads as ErrSidecarStoreFailed, and a
// share whose record fails is served to nobody (D-CORE-15). The secret lives only here, sealed under the network's
// root key, and in the link's fragment: never in a reply, a log or a server (§9.9).
//
// Safe for concurrent use: SidecarStoreLog orders appends, and the share's own mutex orders the steps (socket_share.go).

package sidecar

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// §5.9's directory and file class for shares, and the namespace a share listens in.
const (
	socketShareDirectoryName = "share"
	socketShareClass         = "share"
	socketShareNamePrefix    = "share/"
)

// A row the sharer never writes, read as a failure so nothing is served on it.
var errSocketShareRow = fmt.Errorf("%w: a share record row does not hold", ErrSidecarStoreFailed)

// What a share record's row records.
type socketShareRowKind string

const (
	socketShareRowShare   socketShareRowKind = "share"
	socketShareRowReserve socketShareRowKind = "reserve"
	socketShareRowDone    socketShareRowKind = "done"
	socketShareRowRemove  socketShareRowKind = "remove"
)

// One row as stored: its kind and its body's JSON.
type socketShareRow struct {
	Kind socketShareRowKind `json:"row"`
	Body json.RawMessage    `json:"body"`
}

// A row's body.
type socketShareRowBody interface {
	socketShareRowKind() socketShareRowKind
}

// §9.9's Share: what ur share add hashed, and what each get is held to.
type socketShareRecord struct {
	// 16 random bytes in lowercase base32, the share/<token> it listens on.
	Token string `json:"token"`
	// The file's absolute path on this device.
	Path string `json:"path"`
	Size int64  `json:"size"`
	// The file's modification time in nanoseconds, which a get compares exactly.
	MtimeNanos int64 `json:"mtime"`
	// SHA-256 over the file's bytes [0, size).
	Sha256 []byte `json:"sha256"`
	// The 256-bit secret the link's fragment carries.
	Secret []byte `json:"secret"`
	// How many gets it serves; 0 is unlimited until a Remove or the expiry (QD-241).
	Uses uint32 `json:"uses"`
	// No get starts, resumes or streams at or past this, in Unix milliseconds.
	ExpireMillis int64 `json:"expire_millis"`
}

func (self *socketShareRecord) socketShareRowKind() socketShareRowKind {
	return socketShareRowShare
}

// §9.9's Reserve: a use taken before its bytes, never given back.
type socketShareReserve struct {
	GetId Id `json:"get_id"`
	// The count of Reserves before this one.
	UseIndex uint32 `json:"use_index"`
	// The getter's verified sidecar_id: only it resumes this get.
	GetterSidecarId Id    `json:"getter_sidecar_id"`
	Millis          int64 `json:"millis"`
}

func (self *socketShareReserve) socketShareRowKind() socketShareRowKind {
	return socketShareRowReserve
}

// §9.9's Done: the getter checked the bytes and has them.
type socketShareDoneRow struct {
	GetId  Id    `json:"get_id"`
	Millis int64 `json:"millis"`
}

func (self *socketShareDoneRow) socketShareRowKind() socketShareRowKind {
	return socketShareRowDone
}

// §9.9's Remove: ur share rm, ending the share early.
type socketShareRemove struct {
	Millis int64 `json:"millis"`
}

func (self *socketShareRemove) socketShareRowKind() socketShareRowKind {
	return socketShareRowRemove
}

// A share's record folded.
type socketShareState struct {
	share *socketShareRecord
	// in use_index order
	reserves      []*socketShareReserve
	getIdReserves map[Id]*socketShareReserve
	getIdDones    map[Id]bool
	removed       bool
}

// A state with no rows.
func newSocketShareState() *socketShareState {
	return &socketShareState{getIdReserves: map[Id]*socketShareReserve{}, getIdDones: map[Id]bool{}}
}

// Whether share holds what add writes: a token of the share/ form, a path, a size and hash, a 256-bit secret and an
// expiry.
func validSocketShareRecord(share *socketShareRecord) bool {
	_, namespace, err := ParseSocketName(socketShareNamePrefix + share.Token)
	return err == nil && namespace == SocketNamespaceShare && share.Path != "" && 0 <= share.Size &&
		len(share.Sha256) == sha256.Size && len(share.Secret) == socketShareSecretByteCount && 0 < share.ExpireMillis
}

// Takes one row into the state, refusing any the sharer would not have written after those before it.
func (self *socketShareState) apply(row *socketShareRow) error {
	if self.share == nil && row.Kind != socketShareRowShare {
		return errSocketShareRow
	}
	switch row.Kind {
	case socketShareRowShare:
		share := &socketShareRecord{}
		if self.share != nil || json.Unmarshal(row.Body, share) != nil || !validSocketShareRecord(share) {
			return errSocketShareRow
		}
		self.share = share
	case socketShareRowReserve:
		reserve := &socketShareReserve{}
		if json.Unmarshal(row.Body, reserve) != nil || reserve.GetId == (Id{}) || reserve.GetterSidecarId == (Id{}) ||
			reserve.UseIndex != uint32(len(self.reserves)) || self.getIdReserves[reserve.GetId] != nil {
			return errSocketShareRow
		}
		self.reserves = append(self.reserves, reserve)
		self.getIdReserves[reserve.GetId] = reserve
	case socketShareRowDone:
		done := &socketShareDoneRow{}
		if json.Unmarshal(row.Body, done) != nil || self.getIdReserves[done.GetId] == nil || self.getIdDones[done.GetId] {
			return errSocketShareRow
		}
		self.getIdDones[done.GetId] = true
	case socketShareRowRemove:
		remove := &socketShareRemove{}
		if json.Unmarshal(row.Body, remove) != nil {
			return errSocketShareRow
		}
		self.removed = true
	default:
		return errSocketShareRow
	}
	return nil
}

// Whether the share has ended for good: a Remove, or a Done for each of its uses' Reserves. An expiry is the clock's,
// which the caller compares.
func (self *socketShareState) finished() bool {
	if self.removed {
		return true
	}
	uses := int(self.share.Uses)
	return 0 < uses && uses <= len(self.getIdDones)
}

// The uses left to reserve, -1 for unlimited.
func (self *socketShareState) remaining() int {
	if self.share.Uses == 0 {
		return -1
	}
	return max(0, int(self.share.Uses)-len(self.reserves))
}

// The network's share records, under share/, class share.
type socketShareLedger struct {
	store SidecarStore
}

// The ledger over the network's local store. ErrSidecarStoreLocked while it is locked or before enrollment.
func newSocketShareLedger(localStore SidecarStore) (*socketShareLedger, error) {
	store, err := localStore.Directory(socketShareDirectoryName, socketShareClass)
	if err != nil {
		return nil, err
	}
	return &socketShareLedger{store: store}, nil
}

// token's log.
func (self *socketShareLedger) log(token string) (SidecarStoreLog, error) {
	return OpenSidecarStoreLog(self.store, token)
}

// The tokens of every record on disk, sorted.
func (self *socketShareLedger) tokens() ([]string, error) {
	entries, err := self.store.List("")
	if err != nil {
		return nil, err
	}
	tokens := []string{}
	for _, entry := range entries {
		if !strings.Contains(entry.Name, "/") {
			tokens = append(tokens, entry.Name)
		}
	}
	return tokens, nil
}

// token's record folded. ErrSidecarStoreAbsent for none; ErrSidecarStoreFailed for one that does not hold.
func (self *socketShareLedger) read(token string) (*socketShareState, error) {
	log, err := self.log(token)
	if err != nil {
		return nil, err
	}
	state := newSocketShareState()
	err = log.Read(func(index uint64, record []byte) error {
		row := &socketShareRow{}
		if err := json.Unmarshal(record, row); err != nil {
			return errSocketShareRow
		}
		return state.apply(row)
	})
	if err != nil {
		return nil, err
	}
	if state.share == nil || state.share.Token != token {
		return nil, errSocketShareRow
	}
	return state, nil
}

// Appends body to log, fsynced before it returns, and applies it to state. After an error the row may or may not be
// there, as after a kill, and the caller takes a Reserve as spent (§9.9's burn on uncertainty).
func appendSocketShareRow(log SidecarStoreLog, state *socketShareState, body socketShareRowBody) error {
	encodedBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	row := &socketShareRow{Kind: body.socketShareRowKind(), Body: encodedBody}
	encoded, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if err := log.Append(encoded); err != nil {
		return err
	}
	return state.apply(row)
}

// Deletes token's record, once the share has ended (§9.9's end). Nothing there is not an error.
func (self *socketShareLedger) remove(token string) error {
	err := self.store.Remove(token)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	return err
}
