//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// ur share (§9.9, D-SOCK-16, R-SOCK-10, R-CTX-31; SOCK-M5-15): a live sharer on a blinded share/<token> socket, a
// fragment-borne 256-bit secret, a durable use count and an expiry, served while the sharing sidecar's daemon runs,
// which stays up while a share lives (§5.8, Daemon.busy). Bytes count on the transfer balance like any same-network
// stream (§20.6), so nothing here meters.
//
// Add. The ur process draws the token and the secret (NewShareCredentials) and hashes the file, then sends them; the
// daemon checks the file still has the size and modification time that were hashed, appends the Share row, fsynced,
// and listens exclusive on share/<token>. ur prints <net>:share/<token>#<k>, k = base64url(sidecar_id || secret), and
// no reply holds the secret (§5.8: a request may carry one, a reply never does). The fragment never reaches a server
// or a log. --expires defaults to 24 h and refuses past 30 days, and an omitted --count is one use (QD-241).
//
// A get, under the share's mutex, takes §9.9's first match exactly:
//
//	the secret differs (constant time), a Remove exists, or now >= expire_millis   reset; no use spent
//	the file's size or modification time differs from Share's                        status changed
//	the get_id is one this getter reserved                                           resume at offset; spent after
//	                                                                                 its Done
//	count(Reserve) < uses, or uses = 0                                               append Reserve, fsync: the
//	                                                                                 linearization point
//	otherwise                                                                        status spent
//
// Two readings beside that order, both refusing with a reset and spending nothing: a header that does not decode,
// and a get_id another getter reserved, which a Reserve's one getter keeps from ever resuming or doubling (§9.9: only
// its own getter resumes it); an offset past the file is refused the same way. A Reserve that may or may not have
// reached the medium is taken as spent: the share stops serving until the record is read again, so no use is served
// twice (burn on uncertainty).
//
// Ends. A Remove, a Done for each of uses' Reserves, or expire_millis, by a timer on the clock and at load for a
// sharer that was offline then: the share's streams reset, it unlistens, and its record is deleted. Records survive a
// restart, and a share whose listen cannot run yet, a locked store or sockets not ready, is tried again every
// ResumeInterval until it serves or ends.
//
// The getter's half (ShareLink, SharePart) runs in the ur process over a socket session that dialed the share holding
// the link's sidecar_id, so the dialer refused before OPEN any listener whose verified Hello names another sidecar,
// and within the sharer's network only (§9.9, socket_dial.go). It keeps <out>.part, and the get_id in
// <out>.part.id until a clean close, hashes [0, size) as the bytes come, renames into place, then sends done.
//
// Call testHookSecret on the secret where it is drawn and where a link yields it, and testHookBarrier around the
// Reserve, outside the share's mutex, since a held barrier must hold no lock. Nothing here logs a token, a path or a
// link. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// The control methods ur share calls (§5.8), each a reading: §9.9 names the commands and not the methods.
const (
	// ur share add
	DaemonMethodShareAdd = "share.add"
	// ur share, every hosted network's live shares
	DaemonMethodShareList = "share.list"
	// ur share rm
	DaemonMethodShareRemove = "share.rm"
)

// Where a getter keeps a get's id beside <out>.part, until a clean close.
const sharePartIdSuffix = ".part.id"

var (
	// A share's request that ur share add would not send: no token of the share/ form, no 256-bit secret, no hash.
	ErrShareInvalid = errors.New("not a share")
	// --expires past SidecarShareSettings.ExpiresMax, 30 days (owner decision 74).
	ErrShareExpiresTooLong = errors.New("a share expires within 30 days")
	// The file is not what was hashed: its size or modification time moved, or it is not a regular file.
	ErrShareFileChanged = errors.New("the file changed since it was hashed")
	// No live share has that token on the network.
	ErrShareNone = errors.New("no live share has that token")
	// A link that is no <net>:share/<token>#<k>.
	ErrShareLink = errors.New("not a share link")
	// The sharer reset the get: the link's secret is wrong, or the share was removed or has expired (§9.9).
	ErrShareRefused = errors.New("the share refused the get: the link is wrong, or the share was removed or has expired")
	// Every use is reserved (§9.9's status spent).
	ErrShareSpent = errors.New("the share's uses are spent")
	// The shared file changed, so the share no longer serves it (§9.9's status changed).
	ErrShareChanged = errors.New("the shared file changed")
	// The bytes did not hash to the share's SHA-256; <out>.part is cleared, and a get again resumes this get.
	ErrShareMismatch = errors.New("the bytes did not match the share's hash")
	// <out> exists, or <out>.part belongs to another share.
	ErrSharePart = errors.New("the output is in use")
)

// share.add's params: what ur share add hashed and drew. Secret is the only secret a request carries here.
type DaemonShareAddParams struct {
	Network string `json:"network,omitempty"`
	// The file's absolute path.
	Path string `json:"path"`
	Size int64  `json:"size"`
	// The modification time ur saw while it hashed, in nanoseconds.
	MtimeNanos int64 `json:"mtime"`
	// SHA-256 over the file's bytes.
	Sha256 []byte `json:"sha256"`
	// --count: 0 is unlimited until expiry; ur sends 1 for an omitted one (QD-241).
	Uses uint32 `json:"uses"`
	// --expires in milliseconds; 0 takes ExpiresDefault.
	ExpiresMillis int64 `json:"expires_millis,omitempty"`
	// NewShareCredentials's token and secret.
	Token  string `json:"token"`
	Secret []byte `json:"secret"`
}

// share.add's reply: what ur needs to print the link beside the secret it holds, and nothing secret.
type DaemonShareAddReply struct {
	Token string `json:"token"`
	// The network's 10-character label, the link's <net>.
	NetworkLabel string `json:"network_label"`
	// This sharer's sidecar_id, the link fragment's first 16 bytes.
	SidecarId    Id     `json:"sidecar_id"`
	Uses         uint32 `json:"uses"`
	ExpireMillis int64  `json:"expire_millis"`
}

// One share as ur share lists it: no secret, no link.
type DaemonShareStatus struct {
	NetworkId Id     `json:"network_id"`
	Token     string `json:"token"`
	Path      string `json:"path"`
	// 0 is unlimited.
	Uses uint32 `json:"uses"`
	// Uses reserved, and those done.
	ReservedCount int `json:"reserved_count"`
	DoneCount     int `json:"done_count"`
	// Uses left to reserve, -1 for unlimited.
	RemainingCount int   `json:"remaining_count"`
	ExpireMillis   int64 `json:"expire_millis"`
	// Its listener is up, taking gets.
	Serving bool `json:"serving"`
}

// share.list's reply.
type DaemonShareListReply struct {
	Shares []*DaemonShareStatus `json:"shares"`
	// The tokens of records that did not read, served to nobody until a person looks (D-CORE-15): ur share rm takes
	// one away.
	FailedTokens []string `json:"failed_tokens,omitempty"`
}

// share.rm's params.
type DaemonShareRemoveParams struct {
	Network string `json:"network,omitempty"`
	Token   string `json:"token"`
}

// share.rm's reply.
type DaemonShareRemoveReply struct {
	Removed bool `json:"removed"`
}

// A fresh share's token, 16 random bytes in lowercase base32, and its 256-bit secret, which the ur process draws so no
// reply carries the secret.
func NewShareCredentials() (string, []byte) {
	tokenBytes := make([]byte, socketShareGetIdByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	rand.Read(tokenBytes)
	secret := make([]byte, socketShareSecretByteCount)
	rand.Read(secret)
	testHookSecret("share_secret", secret)
	return encodeShareToken(tokenBytes), secret
}

// 16 bytes as a share token: lowercase base32, no padding, 26 characters (§9.9).
func encodeShareToken(tokenBytes []byte) string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tokenBytes))
}

// Whether token is a share token: share/<token> parses as a share/ name.
func validShareToken(token string) bool {
	_, namespace, err := ParseSocketName(socketShareNamePrefix + token)
	return err == nil && namespace == SocketNamespaceShare
}

// A share link (§9.9): <net>:share/<token>#<k>, k = base64url(sidecar_id || secret).
type ShareLink struct {
	NetworkLabel string
	Token        string
	SidecarId    Id
	// The share's 256-bit secret, which only a get's header sends. Never logged.
	Secret []byte
}

// The link's text, which holds the secret: ur prints it once for the person, and nothing logs it.
func FormatShareLink(networkLabel string, token string, sidecarId Id, secret []byte) string {
	fragment := append(sidecarId.Bytes(), secret...)
	return networkLabel + ":" + socketShareNamePrefix + token + "#" + base64.RawURLEncoding.EncodeToString(fragment)
}

// A link's parts, refusing anything but <net>:share/<token>#<k> with a 48-byte k. The error never repeats the text.
func ParseShareLink(text string) (*ShareLink, error) {
	addressText, fragment, found := strings.Cut(text, "#")
	if !found {
		return nil, ErrShareLink
	}
	networkLabel, name, err := parseSocketAddressText(addressText)
	if err != nil || networkLabel == "" {
		return nil, ErrShareLink
	}
	token, isShare := strings.CutPrefix(name, socketShareNamePrefix)
	if !isShare || !validShareToken(token) {
		return nil, ErrShareLink
	}
	k, err := base64.RawURLEncoding.DecodeString(fragment)
	if err != nil || len(k) != socketShareGetIdByteCount+socketShareSecretByteCount {
		return nil, ErrShareLink
	}
	sidecarId, err := IdFromBytes(k[:socketShareGetIdByteCount])
	if err != nil {
		return nil, ErrShareLink
	}
	secret := append([]byte(nil), k[socketShareGetIdByteCount:]...)
	testHookSecret("share_secret", secret)
	return &ShareLink{NetworkLabel: networkLabel, Token: token, SidecarId: sidecarId, Secret: secret}, nil
}

// The share's address, <net>:share/<token>, which a socket session dials.
func (self *ShareLink) Address() string {
	return self.NetworkLabel + ":" + socketShareNamePrefix + self.Token
}

// What a getter writes and hashes: <out>.part, the get's id kept beside it in <out>.part.id until a clean close, and
// the SHA-256 of what the part holds. Not safe for concurrent use.
type SharePart struct {
	outPath string
	token   string
	getId   Id
	file    *os.File
	offset  int64
	hash    hash.Hash
	// the bytes it reads and hashes at a time
	chunkByteCount int
}

// The get's id file: which share the part is of, and its get_id.
type sharePartId struct {
	Token string `json:"token"`
	GetId Id     `json:"get_id"`
}

// Opens <out>.part for a get of token, resuming one left by an earlier get of the same share under its get_id and
// hashing what it holds, or starting one under a fresh get_id. Refused when <out> exists, or when the part is
// another share's or has no id beside it.
func OpenSharePart(outPath string, token string, chunkByteCount int) (*SharePart, error) {
	if !validShareToken(token) || chunkByteCount < 1 {
		return nil, ErrShareInvalid
	}
	if _, err := os.Lstat(outPath); err == nil {
		return nil, fmt.Errorf("%w: the output exists", ErrSharePart)
	}
	partPath := outPath + ".part"
	idPath := outPath + sharePartIdSuffix
	idBytes, err := os.ReadFile(idPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(partPath); err == nil {
			return nil, fmt.Errorf("%w: a part without its get id is there", ErrSharePart)
		}
		partId := &sharePartId{Token: token, GetId: NewId()}
		encoded, err := json.Marshal(partId)
		if err != nil {
			return nil, err
		}
		if err := writeSharePartId(idPath, encoded); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(partPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		return &SharePart{outPath: outPath, token: token, getId: partId.GetId, file: file, hash: sha256.New(), chunkByteCount: chunkByteCount}, nil
	}
	if err != nil {
		return nil, err
	}
	partId := &sharePartId{}
	if err := json.Unmarshal(idBytes, partId); err != nil || partId.GetId == (Id{}) {
		return nil, fmt.Errorf("%w: the get id does not read", ErrSharePart)
	}
	if partId.Token != token {
		return nil, fmt.Errorf("%w: the part is another share's", ErrSharePart)
	}
	file, err := os.OpenFile(partPath, os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	part := &SharePart{outPath: outPath, token: token, getId: partId.GetId, file: file, hash: sha256.New(), chunkByteCount: chunkByteCount}
	// what an earlier get wrote, hashed now, so the hash is ready when the last byte arrives
	offset, err := io.CopyBuffer(part.hash, file, make([]byte, chunkByteCount))
	if err != nil {
		file.Close()
		return nil, err
	}
	part.offset = offset
	return part, nil
}

// Writes the get's id file and syncs it, so a crash keeps the get_id the sharer may have reserved.
func writeSharePartId(idPath string, encoded []byte) error {
	file, err := os.OpenFile(idPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// The get's id, which the sharer's Reserve names.
func (self *SharePart) GetId() Id {
	return self.getId
}

// Where the part ends, what the get resumes at.
func (self *SharePart) Offset() int64 {
	return self.offset
}

// Closes the part, keeping it and its id for a later get.
func (self *SharePart) Close() error {
	return self.file.Close()
}

// The getter's half over stream, a socket session past its ok (§9.9): the header, the sharer's status, the bytes from
// the offset hashed into the part, then, once SHA-256 over [0, size) matches, the rename into <out>, the id file's
// removal and done. A mismatch clears the part, keeping its id, so a get again starts over under the same Reserve.
func (self *SharePart) Get(stream io.ReadWriter, link *ShareLink) error {
	defer self.file.Close()
	if link == nil || link.Token != self.token || len(link.Secret) != socketShareSecretByteCount {
		return ErrShareLink
	}
	get := &socketShareGet{secret: link.Secret, getId: self.getId, offset: uint64(self.offset)}
	if _, err := stream.Write(get.encode()); err != nil {
		return ErrShareRefused
	}
	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil {
		return ErrShareRefused
	}
	switch status[0] {
	case socketShareStatusOk:
	case socketShareStatusSpent:
		return ErrShareSpent
	case socketShareStatusChanged:
		return ErrShareChanged
	default:
		return errSocketShareAnswer
	}
	rest := make([]byte, socketShareOkByteCount-1)
	if _, err := io.ReadFull(stream, rest); err != nil {
		return ErrShareRefused
	}
	ok, err := decodeSocketShareOk(rest)
	if err != nil || ok.size < uint64(self.offset) {
		return errSocketShareAnswer
	}
	if _, err := self.file.Seek(self.offset, io.SeekStart); err != nil {
		return err
	}
	remaining := int64(ok.size) - self.offset
	copied, err := io.CopyBuffer(io.MultiWriter(self.file, self.hash), io.LimitReader(stream, remaining), make([]byte, self.chunkByteCount))
	if err != nil || copied != remaining {
		// what arrived stays, and a get again resumes after it
		self.file.Sync()
		return ErrShareRefused
	}
	if err := self.file.Sync(); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(self.hash.Sum(nil), ok.sha256) != 1 {
		self.file.Truncate(0)
		self.file.Sync()
		return ErrShareMismatch
	}
	if err := self.file.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(self.outPath); err == nil {
		return fmt.Errorf("%w: the output appeared meanwhile", ErrSharePart)
	}
	if err := os.Rename(self.outPath+".part", self.outPath); err != nil {
		return err
	}
	os.Remove(self.outPath + sharePartIdSuffix)
	// the file is in place whatever happens to done: a lost done leaves the Reserve spent, never free
	stream.Write([]byte{socketShareDone})
	if halves, ok := stream.(interface{ CloseWrite() error }); ok {
		halves.CloseWrite()
	}
	io.Copy(io.Discard, stream)
	return nil
}

// One network's shares as its daemon serves them.
type socketShares struct {
	networkId Id
	backend   daemonSocketBackend
	settings  *SidecarShareSettings
	clock     Clock
	log       Logger
	ctx       context.Context
	cancel    context.CancelFunc
	// an admitted conn's dialer's verified sidecar_id: socketConnDialerSidecarId, unless a test stands another in
	dialerSidecarId func(conn *SocketConn) (Id, bool)

	// one load at a time, across its reads of the medium, so no record is adopted twice: the loader's own lock, held
	// across I/O and never with stateLock wanted by anything that waits on the medium
	loadLock sync.Mutex

	stateLock   sync.Mutex
	ledger      *socketShareLedger
	tokenShares map[string]*socketShare
	// records that did not read, served to nobody
	failedTokens map[string]bool
	// tokens an add is writing, which a load leaves to it
	pendingTokens map[string]bool
}

// One share, live.
type socketShare struct {
	shares *socketShares
	token  string
	log    SidecarStoreLog

	// the share's mutex: §9.9's first match and the Reserve's fsync under it, its linearization point, so it is
	// this share's own lock and never held across a stream's bytes
	holdLock sync.Mutex
	state    *socketShareState
	// ended, or stopped serving on an uncertain write
	ended  bool
	failed bool

	stateLock sync.Mutex
	listener  daemonSocketListener
	// a listen is under way, so a second waits for the next resume
	listening  bool
	conns      map[*SocketConn]bool
	stopExpiry func() bool
}

// The verified sidecar_id of an admitted conn's dialer: its Hello's, which admission held to the session's source.
// False for a conn with no Hello, which a share/ name never admits (§9.6's step 3).
func socketConnDialerSidecarId(conn *SocketConn) (Id, bool) {
	stream, ok := conn.stream.(*socketListenerStream)
	if !ok || stream.request == nil || stream.request.peer == nil {
		return Id{}, false
	}
	return stream.request.peer.SidecarId, true
}

// The network's shares, made, loading and serving on first use: whoever asks first starts them, a share method or
// the daemon's resume at its start.
func (self *DaemonSockets) shares(networkId Id) (*socketShares, error) {
	backend, err := self.backend(networkId)
	if err != nil {
		return nil, err
	}
	shares, made := func() (*socketShares, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if shares, ok := self.networkIdShares[networkId]; ok {
			return shares, false
		}
		ctx, cancel := context.WithCancel(self.ctx)
		dialerSidecarId := self.shareDialerSidecarId
		if dialerSidecarId == nil {
			dialerSidecarId = socketConnDialerSidecarId
		}
		shares := &socketShares{
			networkId:       networkId,
			backend:         backend,
			settings:        backend.settings().Share,
			clock:           self.clock,
			log:             self.log,
			ctx:             ctx,
			cancel:          cancel,
			dialerSidecarId: dialerSidecarId,
			tokenShares:     map[string]*socketShare{},
			failedTokens:    map[string]bool{},
			pendingTokens:   map[string]bool{},
		}
		self.networkIdShares[networkId] = shares
		return shares, true
	}()
	if made {
		go shares.run()
	}
	return shares, nil
}

// Starts every hosted network's shares, so records from before a restart serve again (§9.9): ur daemon calls this
// once its networks are hosted.
func (self *DaemonSockets) Resume() {
	for _, network := range self.daemon.Sidecars() {
		self.shares(network.NetworkId)
	}
}

// How many shares are live on every network, which ur status reports: each keeps the daemon up (§5.8).
func (self *DaemonSockets) LiveShareCount() int {
	shares := func() []*socketShares {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		shares := make([]*socketShares, 0, len(self.networkIdShares))
		for _, networkShares := range self.networkIdShares {
			shares = append(shares, networkShares)
		}
		return shares
	}()
	count := 0
	for _, networkShares := range shares {
		count += networkShares.liveCount()
	}
	return count
}

// Loads and listens every ResumeInterval until the daemon ends, so a share comes back after an unlock, a reconnect or
// a listener the service closed.
func (self *socketShares) run() {
	for {
		self.load()
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.ResumeInterval):
		}
	}
}

// Stops serving at the daemon's end, keeping every record for the next daemon.
func (self *socketShares) stop() {
	self.cancel()
	shares := func() []*socketShare {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		shares := make([]*socketShare, 0, len(self.tokenShares))
		for _, share := range self.tokenShares {
			shares = append(shares, share)
		}
		return shares
	}()
	for _, share := range shares {
		share.unlisten()
	}
}

// How many shares are live: loaded, and neither ended nor failed.
func (self *socketShares) liveCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.tokenShares)
}

// The ledger, opened on first use: ErrSidecarStoreLocked while the store is.
func (self *socketShares) openLedger() (*socketShareLedger, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ledger != nil {
		return self.ledger, nil
	}
	ledger, err := newSocketShareLedger(self.backend.localStore())
	if err != nil {
		return nil, err
	}
	self.ledger = ledger
	return ledger, nil
}

// Reads each record not yet read, ends what has ended, and listens each live share that is not listening.
func (self *socketShares) load() {
	self.read()
	shares := func() []*socketShare {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		shares := []*socketShare{}
		for _, share := range self.tokenShares {
			shares = append(shares, share)
		}
		return shares
	}()
	for _, share := range shares {
		share.listen(self.ctx)
	}
}

// Reads each record not yet read, one load at a time: a live one is adopted, an ended or expired one deleted.
func (self *socketShares) read() {
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	ledger, err := self.openLedger()
	if err != nil {
		return
	}
	tokens, err := ledger.tokens()
	if err != nil {
		return
	}
	nowMillis := self.clock.Now().UnixMilli()
	for _, token := range tokens {
		known := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.tokenShares[token] != nil || self.failedTokens[token] || self.pendingTokens[token]
		}()
		if known {
			continue
		}
		state, err := ledger.read(token)
		if err != nil {
			if errors.Is(err, ErrSidecarStoreFailed) || errors.Is(err, ErrSidecarStoreAbsent) {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.failedTokens[token] = true
				}()
				self.log.Warningf("[share]a share record does not read, so nothing serves it: %s", err)
			}
			continue
		}
		// a sharer offline at its expiry, or one that ended before a crash, ends now (§9.9)
		if state.finished() || state.share.ExpireMillis <= nowMillis {
			ledger.remove(token)
			continue
		}
		log, err := ledger.log(token)
		if err != nil {
			continue
		}
		self.adopt(&socketShare{shares: self, token: token, log: log, state: state, conns: map[*SocketConn]bool{}})
	}
}

// Takes share into the live set and arms its expiry.
func (self *socketShares) adopt(share *socketShare) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.tokenShares[share.token] = share
	}()
	expiresIn := time.UnixMilli(share.state.share.ExpireMillis).Sub(self.clock.Now())
	stop := self.clock.AfterFunc(expiresIn, share.end)
	func() {
		share.stateLock.Lock()
		defer share.stateLock.Unlock()
		share.stopExpiry = stop
	}()
}

// Forgets share once it has ended.
func (self *socketShares) forget(share *socketShare) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.tokenShares[share.token] == share {
		delete(self.tokenShares, share.token)
	}
}

// ur share add: see the file header.
func (self *socketShares) add(ctx context.Context, params *DaemonShareAddParams) (*DaemonShareAddReply, error) {
	if !validShareToken(params.Token) || len(params.Secret) != socketShareSecretByteCount || len(params.Sha256) != sha256.Size ||
		params.Size < 0 || params.ExpiresMillis < 0 || !filepath.IsAbs(params.Path) {
		return nil, ErrShareInvalid
	}
	testHookSecret("share_secret", params.Secret)
	expires := self.settings.ExpiresDefault
	if 0 < params.ExpiresMillis {
		expires = time.Duration(params.ExpiresMillis) * time.Millisecond
	}
	if self.settings.ExpiresMax < expires {
		return nil, ErrShareExpiresTooLong
	}
	path := filepath.Clean(params.Path)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != params.Size || info.ModTime().UnixNano() != params.MtimeNanos {
		return nil, ErrShareFileChanged
	}
	sidecarId := self.backend.sidecarId()
	label := self.backend.label()
	if sidecarId == nil || label == "" {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	ledger, err := self.openLedger()
	if err != nil {
		return nil, err
	}
	// a load leaves a token an add is writing to it, so no record is adopted twice
	claimed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.tokenShares[params.Token] != nil || self.pendingTokens[params.Token] || self.failedTokens[params.Token] {
			return false
		}
		self.pendingTokens[params.Token] = true
		return true
	}()
	if !claimed {
		return nil, fmt.Errorf("%w: the token is taken", ErrShareInvalid)
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.pendingTokens, params.Token)
	}()
	if _, err := ledger.read(params.Token); !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, fmt.Errorf("%w: the token is taken", ErrShareInvalid)
	}
	log, err := ledger.log(params.Token)
	if err != nil {
		return nil, err
	}
	record := &socketShareRecord{
		Token:        params.Token,
		Path:         path,
		Size:         params.Size,
		MtimeNanos:   params.MtimeNanos,
		Sha256:       append([]byte(nil), params.Sha256...),
		Secret:       append([]byte(nil), params.Secret...),
		Uses:         params.Uses,
		ExpireMillis: self.clock.Now().Add(expires).UnixMilli(),
	}
	share := &socketShare{shares: self, token: params.Token, log: log, state: newSocketShareState(), conns: map[*SocketConn]bool{}}
	// the Share row guards the listen: once it is fsynced, a restart serves the share
	if err := appendSocketShareRow(log, share.state, record); err != nil {
		ledger.remove(params.Token)
		return nil, err
	}
	if err := share.listenOnce(ctx); err != nil {
		appendSocketShareRow(log, share.state, &socketShareRemove{Millis: self.clock.Now().UnixMilli()})
		ledger.remove(params.Token)
		return nil, err
	}
	self.adopt(share)
	return &DaemonShareAddReply{
		Token:        params.Token,
		NetworkLabel: label,
		SidecarId:    *sidecarId,
		Uses:         record.Uses,
		ExpireMillis: record.ExpireMillis,
	}, nil
}

// ur share rm: a Remove, fsynced, then the end. A record that never read is deleted as it is, since nothing serves it.
func (self *socketShares) remove(token string) (bool, error) {
	if !validShareToken(token) {
		return false, ErrShareInvalid
	}
	share, failed := func() (*socketShare, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.tokenShares[token], self.failedTokens[token]
	}()
	if share == nil {
		if !failed {
			return false, ErrShareNone
		}
		ledger, err := self.openLedger()
		if err != nil {
			return false, err
		}
		if err := ledger.remove(token); err != nil {
			return false, err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.failedTokens, token)
		}()
		return true, nil
	}
	removed := func() bool {
		share.holdLock.Lock()
		defer share.holdLock.Unlock()
		if share.ended {
			return false
		}
		if err := appendSocketShareRow(share.log, share.state, &socketShareRemove{Millis: self.clock.Now().UnixMilli()}); err != nil {
			// the Remove may be on the medium: nothing serves the share now either way
			share.failed = true
		}
		return true
	}()
	share.end()
	return removed, nil
}

// Each live share's status, by token, and the tokens of records that did not read.
func (self *socketShares) list() ([]*DaemonShareStatus, []string) {
	shares, failedTokens := func() ([]*socketShare, []string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		shares := make([]*socketShare, 0, len(self.tokenShares))
		for _, share := range self.tokenShares {
			shares = append(shares, share)
		}
		failedTokens := make([]string, 0, len(self.failedTokens))
		for token := range self.failedTokens {
			failedTokens = append(failedTokens, token)
		}
		return shares, failedTokens
	}()
	statuses := make([]*DaemonShareStatus, 0, len(shares))
	for _, share := range shares {
		statuses = append(statuses, share.status())
	}
	slices.SortFunc(statuses, func(a *DaemonShareStatus, b *DaemonShareStatus) int { return strings.Compare(a.Token, b.Token) })
	slices.Sort(failedTokens)
	return statuses, failedTokens
}

// Listens exclusive on share/<token> once, taking gets on the listener. A listen already held or under way is left be.
func (self *socketShare) listenOnce(ctx context.Context) error {
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.listener != nil || self.listening {
			return false
		}
		self.listening = true
		return true
	}()
	if !started {
		return nil
	}
	address := &SocketAddress{Name: socketShareNamePrefix + self.token}
	listener, err := self.shares.backend.listen(ctx, address, &SocketListenSettings{Exclusive: true}, true)
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.listening = false
		if err != nil {
			return false
		}
		self.listener = listener
		return true
	}()
	if err != nil {
		return err
	}
	ended := func() bool {
		self.holdLock.Lock()
		defer self.holdLock.Unlock()
		return self.ended
	}()
	if ended || !kept {
		// an end that came while the listen was under way found no listener to close
		listener.Close()
		return nil
	}
	go self.accept(listener)
	return nil
}

// Listens when the share serves and has no listener, as a resume does, waiting at most ResumeInterval for the
// service's first answer, so a registrar that cannot reach the service holds no resume past its round. A failure
// waits for the next resume.
func (self *socketShare) listen(ctx context.Context) {
	idle := func() bool {
		self.holdLock.Lock()
		ended := self.ended || self.failed
		self.holdLock.Unlock()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return !ended && self.listener == nil
	}()
	if !idle {
		return
	}
	listenCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.shares.clock.AfterFunc(self.shares.settings.ResumeInterval, cancel)
	defer stop()
	self.listenOnce(listenCtx)
}

// Takes each admitted conn until listener closes, then drops it so a resume listens again.
func (self *socketShare) accept(listener daemonSocketListener) {
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.listener == listener {
			self.listener = nil
		}
	}()
	for {
		conn, err := listener.AcceptSocket(self.shares.ctx)
		if err != nil {
			return
		}
		getterSidecarId, ok := self.shares.dialerSidecarId(conn)
		if !ok {
			conn.Abort()
			continue
		}
		go self.serve(conn, getterSidecarId)
	}
}

// Closes the listener, at the daemon's end, leaving the share live for the next daemon.
func (self *socketShare) unlisten() {
	listener, stop := func() (daemonSocketListener, func() bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listener := self.listener
		self.listener = nil
		return listener, self.stopExpiry
	}()
	if stop != nil {
		stop()
	}
	if listener != nil {
		listener.Close()
	}
}

// The status of one share, as ur share lists it.
func (self *socketShare) status() *DaemonShareStatus {
	self.holdLock.Lock()
	state := self.state
	status := &DaemonShareStatus{
		NetworkId:      self.shares.networkId,
		Token:          self.token,
		Path:           state.share.Path,
		Uses:           state.share.Uses,
		ReservedCount:  len(state.reserves),
		DoneCount:      len(state.getIdDones),
		RemainingCount: state.remaining(),
		ExpireMillis:   state.share.ExpireMillis,
	}
	self.holdLock.Unlock()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status.Serving = self.listener != nil
	return status
}

// What a get's header decided.
type socketShareDecisionKind int

const (
	// Reset the stream, no use spent.
	socketShareDecisionReset socketShareDecisionKind = iota + 1
	socketShareDecisionChanged
	socketShareDecisionSpent
	// Stream [offset, size).
	socketShareDecisionOk
)

// One get's decision, and for ok what the bytes are held to.
type socketShareDecision struct {
	kind   socketShareDecisionKind
	getId  Id
	offset int64
	record *socketShareRecord
}

// Whether the file at record's path is what was hashed: a regular file of its size and modification time.
func socketShareFileUnchanged(record *socketShareRecord) bool {
	info, err := os.Stat(record.Path)
	return err == nil && info.Mode().IsRegular() && info.Size() == record.Size && info.ModTime().UnixNano() == record.MtimeNanos
}

// §9.9's first match for one header from getterSidecarId, under the share's mutex: see the file header.
func (self *socketShare) decide(header []byte, getterSidecarId Id) *socketShareDecision {
	testHookBarrier("socket.share.reserve.before", self.token)
	decision := func() *socketShareDecision {
		self.holdLock.Lock()
		defer self.holdLock.Unlock()
		reset := &socketShareDecision{kind: socketShareDecisionReset}
		get, err := decodeSocketShareGet(header)
		if err != nil || self.ended || self.failed {
			return reset
		}
		record := self.state.share
		if subtle.ConstantTimeCompare(get.secret, record.Secret) != 1 || self.state.removed ||
			record.ExpireMillis <= self.shares.clock.Now().UnixMilli() {
			return reset
		}
		if !socketShareFileUnchanged(record) {
			return &socketShareDecision{kind: socketShareDecisionChanged}
		}
		if record.Size < int64(get.offset) {
			return reset
		}
		ok := &socketShareDecision{kind: socketShareDecisionOk, getId: get.getId, offset: int64(get.offset), record: record}
		if reserve := self.state.getIdReserves[get.getId]; reserve != nil {
			if reserve.GetterSidecarId != getterSidecarId {
				// another getter's get_id: it neither resumes nor reserves (a reading)
				return reset
			}
			if self.state.getIdDones[get.getId] {
				return &socketShareDecision{kind: socketShareDecisionSpent}
			}
			return ok
		}
		if self.state.remaining() == 0 {
			return &socketShareDecision{kind: socketShareDecisionSpent}
		}
		err = appendSocketShareRow(self.log, self.state, &socketShareReserve{
			GetId:           get.getId,
			UseIndex:        uint32(len(self.state.reserves)),
			GetterSidecarId: getterSidecarId,
			Millis:          self.shares.clock.Now().UnixMilli(),
		})
		if err != nil {
			// the Reserve may be on the medium, so this use is spent and the share serves nobody until it is read
			// again (burn on uncertainty)
			self.failed = true
			return reset
		}
		return ok
	}()
	testHookBarrier("socket.share.reserve.after", self.token)
	return decision
}

// Serves one admitted conn from getterSidecarId: the header within HeaderTimeout, the decision, then the bytes and the
// wait for done. The conn is reset wherever the share ends meanwhile.
func (self *socketShare) serve(conn *SocketConn, getterSidecarId Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.conns[conn] = true
	}()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.conns, conn)
	}()
	// the share may have ended between the accept and the tracking
	ended := func() bool {
		self.holdLock.Lock()
		defer self.holdLock.Unlock()
		return self.ended
	}()
	if ended {
		conn.Abort()
		return
	}
	settings := self.shares.settings
	stopHeader := self.shares.clock.AfterFunc(settings.HeaderTimeout, func() { conn.Abort() })
	header := make([]byte, socketShareGetByteCount)
	_, err := io.ReadFull(conn, header)
	stopHeader()
	if err != nil {
		conn.Abort()
		return
	}
	decision := self.decide(header, getterSidecarId)
	switch decision.kind {
	case socketShareDecisionChanged:
		conn.Write([]byte{socketShareStatusChanged})
		conn.Close()
		return
	case socketShareDecisionSpent:
		conn.Write([]byte{socketShareStatusSpent})
		conn.Close()
		return
	case socketShareDecisionOk:
	default:
		conn.Abort()
		return
	}
	if !self.stream(conn, decision) {
		conn.Abort()
		return
	}
	stopDone := self.shares.clock.AfterFunc(settings.DoneTimeout, func() { conn.Abort() })
	done := make([]byte, 1)
	_, err = io.ReadFull(conn, done)
	stopDone()
	if err == nil && done[0] == socketShareDone {
		self.recordDone(decision.getId)
	}
	conn.Close()
}

// The ok answer and the file's bytes [offset, size), from a file checked again once open. False when either fails.
func (self *socketShare) stream(conn *SocketConn, decision *socketShareDecision) bool {
	record := decision.record
	file, err := os.Open(record.Path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != record.Size || info.ModTime().UnixNano() != record.MtimeNanos {
		return false
	}
	if _, err := conn.Write((&socketShareOk{size: uint64(record.Size), sha256: record.Sha256}).encode()); err != nil {
		return false
	}
	if _, err := file.Seek(decision.offset, io.SeekStart); err != nil {
		return false
	}
	remaining := record.Size - decision.offset
	copied, err := io.CopyBuffer(conn, io.LimitReader(file, remaining), make([]byte, self.shares.settings.ChunkByteCount))
	return err == nil && copied == remaining
}

// Appends getId's Done, and ends the share once each of its uses is done.
func (self *socketShare) recordDone(getId Id) {
	finished := func() bool {
		self.holdLock.Lock()
		defer self.holdLock.Unlock()
		if self.ended || self.state.getIdDones[getId] {
			return false
		}
		if err := appendSocketShareRow(self.log, self.state, &socketShareDoneRow{GetId: getId, Millis: self.shares.clock.Now().UnixMilli()}); err != nil {
			return false
		}
		return self.state.finished()
	}()
	if finished {
		self.end()
	}
}

// §9.9's end, once: a Remove, a Done for each use, or the expiry. The share's streams reset, it unlistens, and its
// record is deleted.
func (self *socketShare) end() {
	first := func() bool {
		self.holdLock.Lock()
		defer self.holdLock.Unlock()
		if self.ended {
			return false
		}
		self.ended = true
		return true
	}()
	if !first {
		return
	}
	conns, listener, stop := func() ([]*SocketConn, daemonSocketListener, func() bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		conns := make([]*SocketConn, 0, len(self.conns))
		for conn := range self.conns {
			conns = append(conns, conn)
		}
		listener := self.listener
		self.listener = nil
		return conns, listener, self.stopExpiry
	}()
	if stop != nil {
		stop()
	}
	for _, conn := range conns {
		conn.Abort()
	}
	if listener != nil {
		listener.Close()
	}
	if ledger, err := self.shares.openLedger(); err == nil {
		ledger.remove(self.token)
	}
	self.shares.forget(self)
}

// ur share's control methods (§5.8): add and rm on one network, the listing over every hosted one.
func (self *DaemonSockets) shareMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodShareAdd,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonShareAddParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				defer clear(params.Secret)
				shares, err := self.shares(call.NetworkId)
				if err != nil {
					return nil, err
				}
				return shares.add(ctx, params)
			},
		},
		{
			Name: DaemonMethodShareList,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				reply := &DaemonShareListReply{Shares: []*DaemonShareStatus{}}
				for _, network := range self.daemon.Sidecars() {
					shares, err := self.shares(network.NetworkId)
					if err != nil {
						continue
					}
					// records read now, listens left to the resume, so the call waits on no registration
					shares.read()
					statuses, failedTokens := shares.list()
					reply.Shares = append(reply.Shares, statuses...)
					reply.FailedTokens = append(reply.FailedTokens, failedTokens...)
				}
				return reply, nil
			},
		},
		{
			Name:    DaemonMethodShareRemove,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonShareRemoveParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				shares, err := self.shares(call.NetworkId)
				if err != nil {
					return nil, err
				}
				shares.read()
				removed, err := shares.remove(params.Token)
				if err != nil {
					return nil, err
				}
				return &DaemonShareRemoveReply{Removed: removed}, nil
			},
		},
	}
}
