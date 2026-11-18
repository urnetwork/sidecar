// config/<env>/smtpedge.yml as the smtpedge block reads it (SMTP-M9-20; §14.9, §14.14, §19.4, QD-489): the
// engine's settings (settings.go) with the block's own rules over them. Every HELO name sits under helo_domain,
// since each is a sending address's PTR name and FCrDNS holds only for names the operator publishes (owner
// decision 124: o<k>.out.bringyour.com in production); and each sending address carries the fwmark that
// source-routes a dial from it, a fwmark of 0 taking the block's own WARP_FWMARK, since warp hands one mark to a
// block and W7 adds the rules for any other (plan-SMTP-small-readings#18).
//
// The file holds no secret: X-UR-Ref keys come from the block's vault secret file, which the block lays over
// the settings after this (SmtpEdgeSettings.XUrRefKeys), never from here.
//
// proof_key_sets (OPS-M9-02; DESIGN-DETAILS 3.2.7) lists the key sets the edge's verifier accepts:
//
//	proof_key_sets:
//	  - id: <SHA-256 of the set's keyset.json, 64 lowercase hex digits>
//	    directory: <the directory holding its keyset.json and verifying keys>
//	    not_after: <RFC 3339, optional: when the edge stops accepting it>
//
// A directory is absolute, or relative to the config home smtpedge.yml sits in, never climbing out of it. Its
// keyset.json must hash to its id: the id is what a release pins and a preamble names, so a directory that
// holds another set's file is refused before a verifier is built over it (ProofKeySetDirectory). A set past
// its not_after is dropped at start, its directory unread (ProofKeySetsAt). Changing the list is a config
// change and a restart. What a key set's files are and where a prover host fetches them is api_hosts.go's
// SmtpProofKeysUrl; this package links no prover or verifier, which server gives the engine.

package smtpedgeservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A key set's manifest in its directory, whose SHA-256 is the set's id (DESIGN-DETAILS 3.2.7).
const smtpProofKeySetManifestName = "keyset.json"

// One entry of smtpedge.yml's proof_key_sets, as the file writes it.
type SmtpProofKeySetEntry struct {
	// keyset.json's SHA-256, 64 lowercase hex digits.
	Id string `yaml:"id"`
	// Absolute, or relative to the config home.
	Directory string `yaml:"directory"`
	// When the edge stops accepting the set; left out for never.
	NotAfter time.Time `yaml:"not_after"`
}

// A key set the block accepts, as LoadSmtpEdgeConfig read its entry.
type SmtpEdgeProofKeySet struct {
	// keyset.json's SHA-256: what a preamble's proof_key_set names.
	Id []byte
	// As the file writes it, cleaned.
	Directory string
	// Zero for never.
	NotAfter time.Time
}

// The edge block's view of smtpedge.yml.
type SmtpEdgeConfig struct {
	Settings *SmtpEdgeSettings
	// The block's own mark, which a sending address of fwmark 0 takes.
	BlockFwmark int
	// proof_key_sets, in the file's order, each id decoded and no id or directory twice.
	ProofKeySets []*SmtpEdgeProofKeySet
}

// The config in data for a block whose WARP_FWMARK is blockFwmark (0 when warp set none). A file the engine's
// settings refuse is refused, and so is one without helo_domain, or with a HELO name not strictly under it, or
// with a proof key set whose id is not a SHA-256 in lowercase hex, whose directory is missing or climbs out of
// the config home, or which repeats another's id or directory, or with more sets than a verifier holds. A
// refusal names the field, never its value.
func LoadSmtpEdgeConfig(data []byte, blockFwmark int) (*SmtpEdgeConfig, error) {
	settings, err := LoadSmtpEdgeSettings(data)
	if err != nil {
		return nil, err
	}
	if blockFwmark < 0 {
		return nil, fmt.Errorf("%w: the block's fwmark is negative", ErrSmtpEdgeSettingsRefused)
	}
	heloDomain := strings.ToLower(settings.HeloDomain)
	if !settings.ldhName(heloDomain) || !strings.Contains(heloDomain, ".") {
		return nil, fmt.Errorf("%w: helo_domain is not a dotted LDH name", ErrSmtpEdgeSettingsRefused)
	}
	for i := range settings.SendingAddresses {
		sendingAddress := &settings.SendingAddresses[i]
		if !strings.HasSuffix(strings.ToLower(sendingAddress.HeloName), "."+heloDomain) {
			return nil, fmt.Errorf("%w: a sending address's helo is not under helo_domain", ErrSmtpEdgeSettingsRefused)
		}
		if sendingAddress.Fwmark == 0 {
			sendingAddress.Fwmark = blockFwmark
		}
	}
	proofKeySets, err := loadSmtpEdgeProofKeySets(settings)
	if err != nil {
		return nil, err
	}
	return &SmtpEdgeConfig{Settings: settings, BlockFwmark: blockFwmark, ProofKeySets: proofKeySets}, nil
}

// proof_key_sets' entries, checked by form alone: no file is read here.
func loadSmtpEdgeProofKeySets(settings *SmtpEdgeSettings) ([]*SmtpEdgeProofKeySet, error) {
	if settings.ProofKeySetMaxCount < len(settings.ProofKeySets) {
		return nil, fmt.Errorf("%w: proof_key_sets lists more sets than a verifier holds", ErrSmtpEdgeSettingsRefused)
	}
	proofKeySets := []*SmtpEdgeProofKeySet{}
	seenIds := map[string]bool{}
	seenDirectories := map[string]bool{}
	for _, entry := range settings.ProofKeySets {
		id, err := hex.DecodeString(entry.Id)
		if err != nil || len(id) != sha256.Size || entry.Id != strings.ToLower(entry.Id) {
			return nil, fmt.Errorf("%w: a proof key set's id is not a SHA-256 in lowercase hex", ErrSmtpEdgeSettingsRefused)
		}
		if seenIds[entry.Id] {
			return nil, fmt.Errorf("%w: proof_key_sets repeats an id", ErrSmtpEdgeSettingsRefused)
		}
		seenIds[entry.Id] = true
		if entry.Directory == "" || strings.ContainsRune(entry.Directory, 0) {
			return nil, fmt.Errorf("%w: a proof key set names no directory", ErrSmtpEdgeSettingsRefused)
		}
		directory := filepath.Clean(entry.Directory)
		if !filepath.IsAbs(directory) && !filepath.IsLocal(directory) {
			return nil, fmt.Errorf("%w: a proof key set's directory climbs out of the config home", ErrSmtpEdgeSettingsRefused)
		}
		if seenDirectories[directory] {
			return nil, fmt.Errorf("%w: proof_key_sets repeats a directory", ErrSmtpEdgeSettingsRefused)
		}
		seenDirectories[directory] = true
		proofKeySets = append(proofKeySets, &SmtpEdgeProofKeySet{Id: id, Directory: directory, NotAfter: entry.NotAfter})
	}
	return proofKeySets, nil
}

// The key sets the block accepts at now, in the file's order: a set at or past its not_after is dropped, as
// the verifier drops it at start, so its directory need not exist any more.
func (self *SmtpEdgeConfig) ProofKeySetsAt(now time.Time) []*SmtpEdgeProofKeySet {
	proofKeySets := []*SmtpEdgeProofKeySet{}
	for _, proofKeySet := range self.ProofKeySets {
		if !proofKeySet.NotAfter.IsZero() && !now.Before(proofKeySet.NotAfter) {
			continue
		}
		proofKeySets = append(proofKeySets, proofKeySet)
	}
	return proofKeySets
}

// The directory that holds proofKeySet, checked against its id: its own when that is absolute, else under
// configHome, with a keyset.json of at most ProofManifestMaxByteCount octets whose SHA-256 is the id.
// A directory with no keyset.json, one that is no regular file or too long, or another set's is refused,
// naming the entry by its place in the file and never a path, so the block builds no verifier over it.
func (self *SmtpEdgeConfig) ProofKeySetDirectory(proofKeySet *SmtpEdgeProofKeySet, configHome string) (string, error) {
	index := -1
	for i, listed := range self.ProofKeySets {
		if listed == proofKeySet {
			index = i
		}
	}
	if index < 0 {
		return "", fmt.Errorf("%w: a proof key set the file does not list", ErrSmtpEdgeSettingsRefused)
	}
	refuse := func(what string) (string, error) {
		return "", fmt.Errorf("%w: proof key set %d's directory %s", ErrSmtpEdgeSettingsRefused, index, what)
	}
	directory := proofKeySet.Directory
	if !filepath.IsAbs(directory) {
		if configHome == "" {
			return refuse("is relative and there is no config home")
		}
		directory = filepath.Join(configHome, directory)
	}
	manifestPath := filepath.Join(directory, smtpProofKeySetManifestName)
	info, err := os.Stat(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return refuse("holds no keyset.json")
	}
	if err != nil || !info.Mode().IsRegular() {
		return refuse("holds a keyset.json that cannot be read")
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return refuse("holds a keyset.json that cannot be read")
	}
	defer file.Close()
	maxByteCount := int64(self.Settings.ProofManifestMaxByteCount)
	encoded, err := io.ReadAll(io.LimitReader(file, maxByteCount+1))
	if err != nil {
		return refuse("holds a keyset.json that cannot be read")
	}
	if maxByteCount < int64(len(encoded)) {
		return refuse("holds a keyset.json past its bound")
	}
	sum := sha256.Sum256(encoded)
	if !bytes.Equal(sum[:], proofKeySet.Id) {
		return refuse("holds a keyset.json that is not its id's")
	}
	return directory, nil
}
