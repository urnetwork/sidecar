// VersioningRules (TEAM-M10-01; §7.9, §11.7's choose row; owner decisions 158-167, 169; D-TEAM-27): the versioning an
// honest writer gives each path it creates, at storage format 2 (M10). Existing paths keep theirs.
//
//	source    the repo's own rules, from its access log's RepoVersioning (§8.8), else the network's VersioningRules,
//	          a record that rides config heads alone, else the platform rule, versionless above 64 MiB of plaintext
//	match     ordered, first match wins, an empty selector matching all; a present rule set replaces the next source
//	          entirely, so a path none of its rules matches is created versioned (0), and the platform rule holds only
//	          where neither the repo nor the network has a record
//	cover     file-mode refs of every repo kind but config and mailcfg; never git-mode or creates-only refs, the
//	          search index's files or git-lfs's store, whose writers set their own (§11.7) and never ask here; a
//	          locked repo takes no versioning off
//	readers   only full readers: the network's record is in the head, sealed to the config's generation, and a
//	          rows-only reader answers it unknown (DESIGN-DETAILS 5.7: VersioningRules stays head-only); a repo's own
//	          rules are sealed to that repo's generation when it is owner-bound, else the config's, which the caller
//	          opens (OpenConfigBody) and passes
//
// path_glob's dialect is this file's reading, which the design leaves open: segments between '/', `*`, `?` and
// classes within one segment as Go's path.Match has them, and a whole segment `**` matching any number of segments.
//
// Nothing here creates, derives or unwraps a key. Pure, on every leg.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §11.7's settings a rule chooses.
const (
	// every version kept
	ConfigVersioningKeep = uint32(0)
	// versionless: the path keeps only its newest version's content
	ConfigVersioningVersionless = uint32(1)
)

// The platform rule's bound (owner decision 164): versionless above 64 MiB of plaintext.
const configVersioningPlatformSizeAbove = uint64(64 * 1024 * 1024)

var (
	// The network's VersioningRules ride the config head, which this reader did not open: a rows-only reader.
	ErrConfigVersioningUnknown = errors.New("the network's VersioningRules are unknown to a reader that opens no config head")
	// The rules cover no path of this repo: config and mailcfg, or a repo this state does not hold.
	ErrConfigVersioningNotCovered = errors.New("versioning rules cover no path of this repo")
	// A VersioningRules record no reader takes.
	ErrConfigVersioningMalformed = errors.New("versioning rules malformed")
)

// The platform rule, which holds where neither the repo nor the network has a record.
func ConfigPlatformVersioningRules() *protocol.VersioningRules {
	return &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{SizeAboveBytes: configVersioningPlatformSizeAbove, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
}

// Checks a record's rules: each with a known on or off, 16-byte repo ids, known repo kinds and a glob that parses.
func CheckVersioningRules(rules *protocol.VersioningRules) error {
	for i, rule := range rules.GetRules() {
		switch rule.GetVersioning() {
		case protocol.VersioningMode_VERSIONING_MODE_ON, protocol.VersioningMode_VERSIONING_MODE_OFF:
		default:
			return fmt.Errorf("%w: rule %d's versioning %d", ErrConfigVersioningMalformed, i, rule.GetVersioning())
		}
		for _, repoId := range rule.GetRepoIds() {
			if len(repoId) != len(Id{}) {
				return fmt.Errorf("%w: rule %d names a repo id of %d bytes", ErrConfigVersioningMalformed, i, len(repoId))
			}
		}
		for _, kind := range rule.GetKinds() {
			if _, known := protocol.RepoKind_name[int32(kind)]; !known {
				return fmt.Errorf("%w: rule %d names kind %d", ErrConfigVersioningMalformed, i, kind)
			}
		}
		if _, err := configGlobMatch(rule.GetPathGlob(), ""); err != nil {
			return fmt.Errorf("%w: rule %d's glob: %w", ErrConfigVersioningMalformed, i, err)
		}
	}
	return nil
}

// The setting rules give a path a writer creates, of plaintext size bytes, in a repo of kind: the first rule whose
// every selector matches, an empty one matching all; a path none matches stays versioned.
func ConfigVersioningUnder(rules *protocol.VersioningRules, repoId Id, kind protocol.RepoKind, filePath string, size uint64) uint32 {
	for _, rule := range rules.GetRules() {
		if 0 < len(rule.GetKinds()) && !configContainsKind(rule.GetKinds(), kind) {
			continue
		}
		if 0 < len(rule.GetRepoIds()) && !configContainsId(rule.GetRepoIds(), repoId) {
			continue
		}
		if rule.GetPathGlob() != "" {
			if matched, err := configGlobMatch(rule.GetPathGlob(), filePath); err != nil || !matched {
				continue
			}
		}
		if size <= rule.GetSizeAboveBytes() && rule.GetSizeAboveBytes() != 0 {
			continue
		}
		if rule.GetVersioning() == protocol.VersioningMode_VERSIONING_MODE_OFF {
			return ConfigVersioningVersionless
		}
		return ConfigVersioningKeep
	}
	return ConfigVersioningKeep
}

// Whether kinds holds kind.
func configContainsKind(kinds []uint32, kind protocol.RepoKind) bool {
	for _, candidate := range kinds {
		if candidate == uint32(kind) {
			return true
		}
	}
	return false
}

// Whether ids holds id.
func configContainsId(ids [][]byte, id Id) bool {
	for _, candidate := range ids {
		if len(candidate) == len(Id{}) && Id(candidate) == id {
			return true
		}
	}
	return false
}

// Whether pattern matches filePath: '/'-separated segments, each matched by path.Match, and a `**` segment matching
// any number of segments, none included. An empty pattern matches every path.
func configGlobMatch(pattern string, filePath string) (bool, error) {
	if pattern == "" {
		return true, nil
	}
	patternSegments := strings.Split(strings.Trim(pattern, "/"), "/")
	for _, segment := range patternSegments {
		if segment != "**" {
			if _, err := path.Match(segment, ""); err != nil {
				return false, err
			}
		}
	}
	pathSegments := strings.Split(strings.Trim(filePath, "/"), "/")
	var match func(patternIndex int, pathIndex int) bool
	match = func(patternIndex int, pathIndex int) bool {
		if patternIndex == len(patternSegments) {
			return pathIndex == len(pathSegments)
		}
		if patternSegments[patternIndex] == "**" {
			for next := pathIndex; next <= len(pathSegments); next += 1 {
				if match(patternIndex+1, next) {
					return true
				}
			}
			return false
		}
		if pathIndex == len(pathSegments) {
			return false
		}
		matched, err := path.Match(patternSegments[patternIndex], pathSegments[pathIndex])
		return err == nil && matched && match(patternIndex+1, pathIndex+1)
	}
	return match(0, 0), nil
}

// The setting an honest writer gives a path it creates in the repo (§11.7's choose row): the repo's own rules
// (repoRules, the caller's opened RepoVersioning rules, nil for none), else the network's from the newest base's
// config head, else the platform rule; versioned in a locked repo. ErrConfigVersioningNotCovered for config, mailcfg
// or a repo this state does not hold; ErrConfigVersioningUnknown at a reader that opens no config head when the repo
// has no rules of its own.
func (self *ConfigState) VersioningFor(repoId Id, filePath string, size uint64, repoRules *protocol.VersioningRules) (uint32, error) {
	repo := self.Repo(repoId)
	if repo == nil {
		return 0, fmt.Errorf("%w: no repo %s", ErrConfigVersioningNotCovered, repoId)
	}
	kind := repo.GetKind()
	switch kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		return 0, fmt.Errorf("%w: a %s repo", ErrConfigVersioningNotCovered, kind)
	}
	var setting uint32
	switch {
	case repoRules != nil:
		setting = ConfigVersioningUnder(repoRules, repoId, kind, filePath, size)
	case !self.headSettingsKnown:
		return 0, ErrConfigVersioningUnknown
	case self.headVersioningRules != nil:
		setting = ConfigVersioningUnder(self.headVersioningRules, repoId, kind, filePath, size)
	default:
		setting = ConfigVersioningUnder(ConfigPlatformVersioningRules(), repoId, kind, filePath, size)
	}
	if setting == ConfigVersioningVersionless && repo.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED {
		return ConfigVersioningKeep, nil
	}
	return setting, nil
}

// The network's VersioningRules the newest base's head holds, nil for none, and whether this reader opened the head.
func (self *ConfigState) VersioningRules() (*protocol.VersioningRules, bool) {
	return self.headVersioningRules, self.headSettingsKnown
}

// The network's VersioningRules at the newest verified state, for `ur admin versioning`: nil for none, where the
// platform rule holds, and known false at a reader that opens no config head.
func (self *Sidecar) VersioningRules() (*protocol.VersioningRules, bool, error) {
	state, err := self.configState()
	if err != nil {
		return nil, false, err
	}
	rules, known := state.VersioningRules()
	return rules, known, nil
}

// Saves the network's VersioningRules into the config head, signed by this device, as the person confirmed it (never
// MCP or a hook, D-CORE-13), through this network's config writer, which a device that runs none refuses. Every reader
// checks the record's signer is an Owner's, Admin's or Network admin's device at the base that names the head.
func (self *Sidecar) SaveVersioningRules(ctx context.Context, rules *protocol.VersioningRules, origin SidecarActOrigin) error {
	if origin != SidecarActConfirmed {
		return ErrSidecarActMode
	}
	if err := CheckVersioningRules(rules); err != nil {
		return err
	}
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return ErrAgentPlanNoState
	}
	writer := authority.client.Writer()
	if writer == nil {
		return errors.New("no config writer runs for this network on this device")
	}
	signed, err := configSignRecord(writer.args.Sign, bridge.SignedType_SIGNED_VERSIONING_RULES, rules)
	if err != nil {
		return err
	}
	_, err = writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		return head.WithFile(ConfigHeadVersioningRulesPath, signed)
	})
	return err
}
