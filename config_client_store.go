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
// The file names the authorization features the release that wrote it implemented (§16.6). A restart whose restored log
// holds a base turning on one it did not, a faulty build's, re-derives: the log is rebuilt from the newest base it keeps,
// every kept entry after it judged again under this release's rules, and nothing acts on it until the network's next
// base confirms it (ConfigLog's re-derivation's wait). A file from before the field names none.
//
// A joining device (QD-817) keeps its rows-only log here until a base is confirmed, so its pin holds across a restart
// as any pin it held does. A restart that still holds no generation of the config repo restores it rows-only, as the
// rows-only pass it was; one whose keychain took a generation meanwhile restores the entries as a full reader, every
// head judged, or, where that fails, its first full pass reads from api held to the kept pin. A rows-only log verified
// no head, so the file never names one as verified for it.
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
	// the authorization features the release that wrote the file implemented (§16.6's update row)
	AuthFeatures uint32 `json:"auth_features,omitempty"`
}

// A config head this device verified: its hash, version and the ServiceSettings and VersioningRules it held,
// deterministically encoded, each beside its Signed bytes' hash (QD-1207).
type configClientHeadRecord struct {
	ConfigHeadSha256 []byte                        `json:"config_head_sha256"`
	ConfigVersion    uint64                        `json:"config_version"`
	Settings         []byte                        `json:"settings,omitempty"`
	VersioningRules  []byte                        `json:"versioning_rules,omitempty"`
	RecoveryKnown    bool                          `json:"recovery_known,omitempty"`
	Recovery         []*configClientRecoveryRecord `json:"recovery,omitempty"`
	// SHA-256 of the head's Signed ServiceSettings and VersioningRules, each empty for a head holding none
	SettingsRecordSha256        []byte `json:"settings_record_sha256,omitempty"`
	VersioningRulesRecordSha256 []byte `json:"versioning_rules_record_sha256,omitempty"`
	// the two hashes were kept, as every head this build verifies keeps them: a record without stands for no anchor,
	// whose head is read again, since a state it anchored would judge again a record its next base carries
	RecordsKnown bool `json:"records_known,omitempty"`
	// SHA-256 of the BridgeBlock record this device held from that base on, empty for none (QD-1205): a record without
	// it anchors a state holding no block record, as a reader starting there holds where it refuses the head's
	BridgeBlockRecordSha256 []byte `json:"bridge_block_record_sha256,omitempty"`
}

// Persists a member's recovery binding statement and its effective log position with the verified head.
type configClientRecoveryRecord struct {
	MemberId Id                `json:"member_id"`
	At       uint64            `json:"at"`
	Type     bridge.SignedType `json:"type"`
	Body     []byte            `json:"body"`
}

// Writes what the log keeps now to authlog/, a joining device's rows-only log while no log is confirmed. No store keeps
// nothing.
func (self *ConfigClient) save() error {
	store := self.args.Store
	log := self.configLog.Load()
	if log == nil {
		log = self.unconfirmed.Load()
	}
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
		AuthFeatures:  uint32(log.authFeatures),
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
			if verified.versioningRules != nil {
				record.VersioningRules, _ = proto.MarshalOptions{Deterministic: true}.Marshal(verified.versioningRules)
			}
			record.SettingsRecordSha256 = bytes.Clone(verified.settingsRecordSha256)
			record.VersioningRulesRecordSha256 = bytes.Clone(verified.versioningRulesRecordSha256)
			record.BridgeBlockRecordSha256 = bytes.Clone(verified.bridgeBlockRecordSha256)
			record.RecordsKnown = true
			record.RecoveryKnown = verified.recoveryKnown
			for memberId, body := range verified.recoveryBodies {
				record.Recovery = append(record.Recovery, &configClientRecoveryRecord{MemberId: memberId, At: body.at, Type: body.kind, Body: body.body})
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
		// a head verified before its records' hashes were kept, or whose hashes are not SHA-256s, is read again
		// rather than anchoring a state that would judge again a record its next base carries (QD-1207)
		recordSha256Known := func(recordSha256 []byte) bool {
			return len(recordSha256) == 0 || len(recordSha256) == sha256.Size
		}
		if !record.RecordsKnown || !recordSha256Known(record.SettingsRecordSha256) || !recordSha256Known(record.VersioningRulesRecordSha256) {
			continue
		}
		// a record of no field set encodes as no bytes, which the document omits: its hash says the head held it
		var settings *protocol.ServiceSettings
		if record.Settings != nil || len(record.SettingsRecordSha256) != 0 {
			settings = &protocol.ServiceSettings{}
			if err := proto.Unmarshal(record.Settings, settings); err != nil {
				continue
			}
		}
		facts := &ConfigHeadFacts{Settings: settings, recoveryBodies: map[Id]*configRecoveryBody{}}
		if record.VersioningRules != nil || len(record.VersioningRulesRecordSha256) != 0 {
			facts.VersioningRules = &protocol.VersioningRules{}
			if err := proto.Unmarshal(record.VersioningRules, facts.VersioningRules); err != nil {
				continue
			}
		}
		if len(record.SettingsRecordSha256) != 0 {
			facts.settingsRecordSha256 = bytes.Clone(record.SettingsRecordSha256)
		}
		if len(record.VersioningRulesRecordSha256) != 0 {
			facts.versioningRulesRecordSha256 = bytes.Clone(record.VersioningRulesRecordSha256)
		}
		// a hash that is not a SHA-256 holds no block record (QD-1205)
		if len(record.BridgeBlockRecordSha256) == sha256.Size {
			facts.bridgeBlockRecordSha256 = bytes.Clone(record.BridgeBlockRecordSha256)
		}
		for _, binding := range record.Recovery {
			if binding != nil {
				facts.recoveryBodies[binding.MemberId] = &configRecoveryBody{at: binding.At, kind: binding.Type, body: binding.Body}
			}
		}
		self.rememberHead(record.ConfigHeadSha256, record.ConfigVersion, facts, record.RecoveryKnown)
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
	// a joining device whose keychain holds no generation of the config repo restores its rows-only pass (QD-817)
	rowsOnly := false
	configRepoId := Id{}
	if self.args.Joiner != nil {
		genesis, err := configParseGenesis(document.SignedGenesis)
		if err != nil {
			return fmt.Errorf("%w: %w", errConfigClientDocument, err)
		}
		self.genesis.CompareAndSwap(nil, genesis)
		if configRepoId, err = IdFromBytes(genesis.GetConfigRepoId()); err != nil {
			return fmt.Errorf("%w: %w", errConfigClientDocument, err)
		}
		held, _ := self.args.Joiner.RepoKeyHeld(configRepoId)
		rowsOnly = !held
	}
	switch {
	case first.GetN() == 1 && rowsOnly:
		log, err = NewConfigLogRowsOnly(self.logSettings, document.SignedGenesis)
		if err == nil {
			_, err = log.ApplyRun(document.Entries, source)
		}
	case first.GetN() == 1:
		log, err = NewConfigLog(self.logSettings, document.SignedGenesis)
		if err == nil {
			_, err = log.ApplyRun(document.Entries, source)
		}
	case rowsOnly:
		log, err = RestoreConfigLogRowsOnly(self.logSettings, retained, source, nil)
	default:
		log, err = restoreConfigLogAbove(self.logSettings, retained, source, nil)
	}
	if err != nil {
		// the kept 64 KiB rarely reach a base's tail: the first follow reads the rest from api, held to the pin
		return err
	}
	if err := log.checkFloor(self.floorPin()); err != nil {
		return err
	}
	if rowsOnly {
		// nothing is confirmed by it: the key client takes its state for the config group's join alone
		self.unconfirmed.Store(log)
		self.args.Joiner.AuthUnconfirmed(log.State(), configRepoId)
		return nil
	}
	if base := log.State().Base(); base != nil {
		self.startBase = base.GetVersion()
	}
	// a kept log turned on a feature the release that kept it did not implement: it was rebuilt here under this
	// release's rules, and waits for the network's next base before anything acts on it (§16.6's update row)
	if faulty := log.State().AuthFeatures() &^ AuthFeature(document.AuthFeatures); faulty != 0 {
		log.startRederive(faulty)
	}
	self.configLog.Store(log)
	self.position.Set(log.Pin().GetVersion())
	self.stopped.Set(self.Fork())
	return nil
}
