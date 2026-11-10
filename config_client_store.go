// What a ConfigClient keeps across restarts, in §5.9's authlog/ (§7.9's retain row): one sealed file per network holding
// the Signed Genesis, the newest pin this device held, the entries it keeps verbatim, and the config heads it verified.
//
//	every sidecar   its pin and its newest entries' verbatim bytes up to 64 KiB, a base as its header, which every
//	                entry is, so it serves HeadCheckProof (PROTO-M2-03) and a restart reads the rest from api, never
//	                landing below the pin
//	full tail       a member device on §18.4's desktop and CLI hosts (ConfigClientSettings.RetainFullTail): every
//	                entry from the retention point and the rows of the current and previous bases, from which a restart
//	                stands again with no read, its newest base's head taken as verified before
//
// The file is the device's own, sealed by its store; a restart refuses a lower n wherever it reads one, the persisted
// pin included. A file that does not decode keeps nothing, and the first follow reads from api with no floor but what
// it can check.
//
// Every leg. For the client's follower, under its followLock, but for restoreFromStore at construction.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// authlog/'s file and its format.
const (
	configClientFileName        = "configlog"
	configClientDocumentVersion = 1
	// two bases' rows of 4 MiB each and two fold spans of entries, base64 in JSON, with room
	configClientDocumentMaxByteCount = 32 * 1024 * 1024
)

// The file does not decode as this format, or is another network's or genesis's.
var errConfigClientDocument = errors.New("config client: authlog file does not decode")

// authlog/'s file.
type configClientDocument struct {
	Version       int                       `json:"version"`
	NetworkId     Id                        `json:"network_id"`
	SignedGenesis []byte                    `json:"signed_genesis"`
	Pin           *sidecarConfigPinReply    `json:"pin,omitempty"`
	Entries       [][]byte                  `json:"entries"`
	Rows          [][]byte                  `json:"rows,omitempty"`
	VerifiedHeads []*configClientHeadRecord `json:"verified_heads,omitempty"`
}

// A config head this device verified: its hash, version and the ServiceSettings it held, deterministically encoded.
type configClientHeadRecord struct {
	ConfigHeadSha256 []byte `json:"config_head_sha256"`
	ConfigVersion    uint64 `json:"config_version"`
	Settings         []byte `json:"settings,omitempty"`
}

// Writes what the log keeps now to authlog/. No store keeps nothing.
func (self *ConfigClient) save() error {
	store := self.args.Store
	log := self.configLog.Load()
	if store == nil || log == nil {
		return nil
	}
	retained := log.Retained()
	state := log.State()
	document := &configClientDocument{
		Version:       configClientDocumentVersion,
		NetworkId:     self.args.NetworkId,
		SignedGenesis: retained.SignedGenesis,
		Pin:           &sidecarConfigPinReply{N: state.n, Chain: bytes.Clone(state.chain[:])},
	}
	if self.settings.RetainFullTail {
		document.Entries = retained.Entries
		for _, rows := range retained.Rows {
			document.Rows = append(document.Rows, rows)
		}
	} else {
		byteCount := 0
		first := len(retained.Entries)
		for first > 0 && byteCount+len(retained.Entries[first-1]) <= self.settings.RetainedEntryByteCount {
			first -= 1
			byteCount += len(retained.Entries[first])
		}
		document.Entries = retained.Entries[first:]
	}
	// the heads of the bases this log still stands on
	named := map[[sha256.Size]byte]bool{}
	for _, base := range []*configBase{state.base, state.previousBase} {
		if base != nil && len(base.header.GetConfigHeadSha256()) == sha256.Size {
			named[[sha256.Size]byte(base.header.GetConfigHeadSha256())] = true
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for headSha256, verified := range self.verifiedHeads {
			if !named[headSha256] {
				delete(self.verifiedHeads, headSha256)
				continue
			}
			record := &configClientHeadRecord{ConfigHeadSha256: bytes.Clone(headSha256[:]), ConfigVersion: verified.configVersion}
			if verified.settings != nil {
				settingsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(verified.settings)
				if err == nil {
					record.Settings = settingsBytes
				}
			}
			document.VerifiedHeads = append(document.VerifiedHeads, record)
		}
	}()
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	writer, err := store.Create(configClientFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Reads authlog/'s file at construction: the pin no restart may land below, the heads verified before, and, where the
// entries kept reach back to their newest base's tail, the log restored from them with no read. Nothing kept is no
// error.
func (self *ConfigClient) restoreFromStore() error {
	store := self.args.Store
	if store == nil {
		return nil
	}
	reader, err := store.Open(configClientFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, configClientDocumentMaxByteCount+1))
	if err != nil {
		return err
	}
	if configClientDocumentMaxByteCount < len(data) {
		return fmt.Errorf("%w: over %d bytes", errConfigClientDocument, configClientDocumentMaxByteCount)
	}
	document := &configClientDocument{}
	if err := json.Unmarshal(data, document); err != nil {
		return fmt.Errorf("%w: %w", errConfigClientDocument, err)
	}
	if document.Version != configClientDocumentVersion || document.NetworkId != self.args.NetworkId ||
		bridge.GenesisChain(document.SignedGenesis) != self.args.GenesisChain {
		return errConfigClientDocument
	}
	if document.Pin != nil {
		if len(document.Pin.Chain) != sha256.Size {
			return fmt.Errorf("%w: a pin of %d bytes", errConfigClientDocument, len(document.Pin.Chain))
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.floor = &bridge.AuthPin{Version: document.Pin.N, Chain: bytes.Clone(document.Pin.Chain)}
		}()
	}
	for _, record := range document.VerifiedHeads {
		if len(record.ConfigHeadSha256) != sha256.Size {
			continue
		}
		var settings *protocol.ServiceSettings
		if record.Settings != nil {
			settings = &protocol.ServiceSettings{}
			if err := proto.Unmarshal(record.Settings, settings); err != nil {
				continue
			}
		}
		self.rememberHead(record.ConfigHeadSha256, record.ConfigVersion, settings)
	}
	if len(document.Entries) == 0 {
		return nil
	}

	retained := &ConfigRetained{SignedGenesis: document.SignedGenesis, Entries: document.Entries, Rows: map[[sha256.Size]byte][]byte{}}
	for _, rows := range document.Rows {
		retained.Rows[sha256.Sum256(rows)] = rows
	}
	source := &configClientRowsSource{client: self, ctx: self.ctx, rows: retained.Rows}
	var log *ConfigLog
	first := &bridge.AuthEntry{}
	if err := proto.Unmarshal(document.Entries[0], first); err != nil {
		return fmt.Errorf("%w: %w", errConfigClientDocument, err)
	}
	if first.GetN() == 1 {
		log, err = NewConfigLog(self.logSettings, document.SignedGenesis)
		if err == nil {
			_, err = log.ApplyRun(document.Entries, source)
		}
	} else {
		log, err = restoreConfigLogAbove(self.logSettings, retained, source, nil)
	}
	if err != nil {
		// the kept 64 KiB rarely reach a base's tail: the first follow reads the rest from api, held to the pin
		return err
	}
	if err := log.checkFloor(self.floorPin()); err != nil {
		return err
	}
	if base := log.State().Base(); base != nil {
		self.startBase = base.GetVersion()
	}
	self.configLog.Store(log)
	self.position.Set(log.Pin().GetVersion())
	return nil
}
