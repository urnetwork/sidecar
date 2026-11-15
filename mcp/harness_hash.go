//go:build !js && !ios && !android && !sdk_mobile_bind

// The harness config hashes (§16.6's taint row, §16.7, D-MCP-5, I-9; QD-103, plan-MCP-config-hash-scope): what
// `ur install-harness` sealed, and the daemon's check that a harness's config still holds it, which the run binder
// calls at each run's start and SessionStart and every Ingest.ConfigCheckInterval (hook_coverage.go). A changed config
// lapses coverage: every run of the harness is tainted config_changed.
//
//	seal       one JSON file per install under <state>/harness/, the user's <harness>.json and a project's
//	           <harness>.project.<hash of its directory>.json: the template's inputs (ur's path, the agent, the
//	           instance, the outward tools, the directory, the telemetry port), each file's path and the SHA-256 of
//	           ur's entries in it as the template renders them, and config_sha256, RECORD.md's, SHA-256 over those in
//	           order. Local state, never synced, never sent. The telemetry pair itself is telemetry.json beside them
//	           (harness_telemetry.go), which no seal copies: a seal naming a port renders its template from the pair
//	           as it stands, so a pair drawn again, or gone, reads as changed
//	file hash  ur's entries in one file, extracted and rendered as RFC 8785 canonical JSON (TOML read to the same
//	           form), hashed with SHA-256: one rule for every file and no whole-file hash, so an edit elsewhere in a
//	           file changes nothing (QD-103)
//	check      for a session's harness in its working directory, the user's seal and each project seal whose
//	           directory holds it: none at all reads changed; the seal's ur path must be the daemon's own, and its
//	           hashes the template's for its inputs, so a seal edited by hand blesses nothing a genuine install would
//	           not write; then each file's entries are extracted afresh and hashed, and any other entry that can
//	           answer for a ur tool counts as changed: a hook on PermissionRequest, PreToolUse or beforeMCPExecution
//	           whose matcher covers ur's server, or an allow rule naming it, in the seal's files and in the session's
//	           working directory's own settings files
//
// Any error reads changed, the closed direction (HarnessConfigCheck). Re-running the install restores ur's entries
// and cannot bless a widened rule, since its seal comes from the template, never from the file as found.
//
// Safe for concurrent use.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The seal's format version.
const harnessSealVersion = 1

// The seals' directory under <state>.
const harnessSealDirectoryName = "harness"

// One install's seal.
type HarnessSeal struct {
	Version int    `json:"version"`
	Harness string `json:"harness"`
	// "" for the person's own files.
	ProjectDirectory string `json:"project_directory,omitempty"`
	// The home a user install's files were under.
	Home         string   `json:"home,omitempty"`
	UrPath       string   `json:"ur_path"`
	Agent        string   `json:"agent,omitempty"`
	Instance     string   `json:"instance,omitempty"`
	OutwardTools []string `json:"outward_tools"`
	// The cloud profile's key file, a path and never a key; "" for none.
	CloudKeyFile string `json:"cloud_key_file,omitempty"`
	// The fail-closed form was installed (HarnessInstallArgs.RecordRequired).
	RecordRequired bool `json:"record_required,omitempty"`
	// The telemetry pair's port the exporter's settings name, 0 for an install that wrote none (QD-822). The token is
	// the pair file's alone.
	TelemetryPort int `json:"telemetry_port,omitempty"`
	// In the install's order.
	Files []*HarnessSealFile `json:"files"`
	// SHA-256 over the files' hashes in order, hex: RECORD.md's config_sha256.
	ConfigSha256 string `json:"config_sha256"`
}

// One file of a seal: its path and the hash of ur's entries in it, hex.
type HarnessSealFile struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

// The seal of an install: the template's inputs and its entries' hashes.
func newHarnessSeal(args *HarnessInstallArgs, template *harnessTemplate, adapter harnessInstallAdapter) (*HarnessSeal, error) {
	seal := &HarnessSeal{
		Version:          harnessSealVersion,
		Harness:          args.Harness,
		ProjectDirectory: args.ProjectDirectory,
		UrPath:           template.urPath,
		Agent:            template.agent,
		Instance:         template.instance,
		OutwardTools:     slices.Clone(template.outwardTools),
		CloudKeyFile:     template.cloudKeyFile,
		RecordRequired:   template.recordRequired,
	}
	if template.telemetry != nil {
		seal.TelemetryPort = template.telemetry.Port
	}
	if args.ProjectDirectory == "" {
		seal.Home = args.Home
	}
	hashes, err := harnessTemplateHashes(adapter.files(seal.Home, seal.ProjectDirectory), template)
	if err != nil {
		return nil, err
	}
	for i, file := range adapter.files(seal.Home, seal.ProjectDirectory) {
		seal.Files = append(seal.Files, &HarnessSealFile{Path: file.path, Sha256: hex.EncodeToString(hashes[i][:])})
	}
	configSha256 := harnessConfigSha256(hashes)
	seal.ConfigSha256 = hex.EncodeToString(configSha256[:])
	return seal, nil
}

// Each file's hash of the template's entries, in order.
func harnessTemplateHashes(files []*harnessFile, template *harnessTemplate) ([][sha256.Size]byte, error) {
	hashes := [][sha256.Size]byte{}
	for _, file := range files {
		entries, err := harnessTemplateEntries(file, template)
		if err != nil {
			return nil, err
		}
		hash, err := harnessEntriesSha256(entries)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

// SHA-256 over per-file hashes in order (QD-103).
func harnessConfigSha256(hashes [][sha256.Size]byte) [sha256.Size]byte {
	digest := sha256.New()
	for _, hash := range hashes {
		digest.Write(hash[:])
	}
	var sum [sha256.Size]byte
	copy(sum[:], digest.Sum(nil))
	return sum
}

// Where a seal lives under state.
func (self *HarnessSeal) path(stateDirectory string) string {
	name := self.Harness + ".json"
	if self.ProjectDirectory != "" {
		name = harnessProjectSealName(self.Harness, self.ProjectDirectory)
	}
	return filepath.Join(stateDirectory, harnessSealDirectoryName, name)
}

// A project seal's name: its harness, then the first 16 bytes of its directory's SHA-256, hex.
func harnessProjectSealName(harness string, projectDirectory string) string {
	sum := sha256.Sum256([]byte(projectDirectory))
	return harness + ".project." + hex.EncodeToString(sum[:16]) + ".json"
}

// The seal at path, read up to byteCount bytes, past which it is no seal.
func readHarnessSeal(path string, byteCount int64) (*HarnessSeal, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, byteCount+1))
	if err != nil {
		return nil, err
	}
	if byteCount < int64(len(content)) {
		return nil, fmt.Errorf("%w: a seal past %d bytes", ErrHarnessConfig, byteCount)
	}
	seal := &HarnessSeal{}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(seal); err != nil {
		return nil, fmt.Errorf("%w: a seal that does not read", ErrHarnessConfig)
	}
	if seal.Version != harnessSealVersion {
		return nil, fmt.Errorf("%w: a seal of version %d", ErrHarnessConfig, seal.Version)
	}
	return seal, nil
}

// Writes a seal under state, private, by a temporary file renamed over it.
func writeHarnessSeal(stateDirectory string, seal *HarnessSeal) error {
	encoded, err := json.MarshalIndent(seal, "", "  ")
	if err != nil {
		return err
	}
	return harnessWriteFile(seal.path(stateDirectory), append(encoded, '\n'), 0o600, true)
}

// What the daemon's config check reads with.
type HarnessConfigHashesArgs struct {
	// The instance's <state>, where the seals are.
	StateDirectory string
	// ur's own absolute path: a seal naming another reads changed. Nil takes each seal's own.
	Executable func() (string, error)
	Ingest     *sidecar.SidecarIngestSettings
}

// The daemon's config check over the seals `ur install-harness` wrote.
type HarnessConfigHashes struct {
	args *HarnessConfigHashesArgs
}

// The check over args.
func NewHarnessConfigHashes(args *HarnessConfigHashesArgs) *HarnessConfigHashes {
	return &HarnessConfigHashes{args: args}
}

// Whether harness's config changed since its install, for a session working in cwd ("" for none known): see the
// file header. An error reads changed, and is answered beside true. The run binder's HarnessConfigCheck.
func (self *HarnessConfigHashes) Check(ctx context.Context, harness string, cwd string) (bool, error) {
	adapter, ok := harnessInstallAdapters[harness]
	if !ok {
		return true, fmt.Errorf("%w: %q", ErrHarnessUnknown, harness)
	}
	seals, err := self.seals(harness, cwd)
	if err != nil {
		return true, err
	}
	if len(seals) == 0 {
		// nothing installed for this harness here: no hash holds
		return true, nil
	}
	for _, seal := range seals {
		if changed, err := self.checkSeal(seal, adapter); changed || err != nil {
			return true, err
		}
	}
	if cwd != "" {
		template, err := self.templateOf(seals[0])
		if err != nil {
			return true, err
		}
		for _, file := range adapter.projectSettingsFiles(cwd) {
			content, _, existed, err := harnessReadFile(file.path, self.args.Ingest)
			if err != nil {
				return true, err
			}
			if !existed {
				continue
			}
			competing, err := file.kind.competing(content, template, self.args.Ingest.HarnessConfigDepthCount)
			if err != nil || 0 < competing {
				return true, err
			}
		}
	}
	return false, nil
}

// The config_sha256 a run's context entry carries (RECORD.md's ContextBody): SHA-256 over the per-file hashes of
// every seal that holds for harness in cwd, the user's first, as the check reads them. An error where none does.
func (self *HarnessConfigHashes) ConfigSha256(harness string, cwd string) ([]byte, error) {
	seals, err := self.seals(harness, cwd)
	if err != nil {
		return nil, err
	}
	if len(seals) == 0 {
		return nil, fmt.Errorf("%w: %s is not installed", ErrHarnessConfig, harness)
	}
	hashes := [][sha256.Size]byte{}
	for _, seal := range seals {
		for _, file := range seal.Files {
			hash := [sha256.Size]byte{}
			decoded, err := hex.DecodeString(file.Sha256)
			if err != nil || len(decoded) != sha256.Size {
				return nil, fmt.Errorf("%w: a seal's hash that does not read", ErrHarnessConfig)
			}
			copy(hash[:], decoded)
			hashes = append(hashes, hash)
		}
	}
	sum := harnessConfigSha256(hashes)
	return sum[:], nil
}

// The seals that hold for harness in cwd: the user's, then each project's whose directory is cwd or holds it, by
// directory.
func (self *HarnessConfigHashes) seals(harness string, cwd string) ([]*HarnessSeal, error) {
	directory := filepath.Join(self.args.StateDirectory, harnessSealDirectoryName)
	seals := []*HarnessSeal{}
	user, err := readHarnessSeal(filepath.Join(directory, harness+".json"), self.args.Ingest.HarnessConfigByteCount)
	switch {
	case err == nil:
		if user.Harness != harness || user.ProjectDirectory != "" {
			return nil, fmt.Errorf("%w: a seal under another harness's name", ErrHarnessConfig)
		}
		seals = append(seals, user)
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if cwd == "" {
		return seals, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	projects := []*HarnessSeal{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), harness+".project.") {
			continue
		}
		seal, err := readHarnessSeal(filepath.Join(directory, entry.Name()), self.args.Ingest.HarnessConfigByteCount)
		if err != nil {
			return nil, err
		}
		if seal.Harness != harness || seal.ProjectDirectory == "" ||
			entry.Name() != harnessProjectSealName(harness, seal.ProjectDirectory) {
			return nil, fmt.Errorf("%w: a seal under another project's name", ErrHarnessConfig)
		}
		if harnessDirectoryHolds(seal.ProjectDirectory, cwd) {
			projects = append(projects, seal)
		}
	}
	slices.SortFunc(projects, func(a *HarnessSeal, b *HarnessSeal) int {
		return strings.Compare(a.ProjectDirectory, b.ProjectDirectory)
	})
	return append(seals, projects...), nil
}

// Whether two absolute paths name one file: equal, or equal once their links resolve, as a ur reached through a
// link to it is. A path that does not resolve names nothing.
func harnessSameFile(a string, b string) bool {
	if a == b {
		return true
	}
	resolvedA, errA := filepath.EvalSymlinks(a)
	resolvedB, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && resolvedA == resolvedB
}

// Whether directory is path or holds it.
func harnessDirectoryHolds(directory string, path string) bool {
	directory = filepath.Clean(directory)
	path = filepath.Clean(path)
	return path == directory || strings.HasPrefix(path, directory+string(filepath.Separator))
}

// The template a seal's inputs render, its telemetry pair the one under <state> as it stands: an error where the seal
// names a port and that pair is gone, does not read, or names another port, which the check reads as changed.
func (self *HarnessConfigHashes) templateOf(seal *HarnessSeal) (*harnessTemplate, error) {
	template := newHarnessTemplate(seal.Harness, seal.UrPath, seal.Agent, seal.Instance, seal.OutwardTools, self.args.Ingest)
	template.cloudKeyFile = seal.CloudKeyFile
	template.recordRequired = seal.RecordRequired
	if seal.TelemetryPort != 0 {
		telemetry, err := ReadHarnessTelemetry(self.args.StateDirectory, self.args.Ingest.HarnessConfigByteCount)
		if err != nil {
			return nil, fmt.Errorf("%w: the telemetry pair the install wrote does not read", ErrHarnessConfig)
		}
		if telemetry.Port != seal.TelemetryPort {
			return nil, fmt.Errorf("%w: the telemetry pair was drawn again since the install", ErrHarnessConfig)
		}
		template.telemetry = telemetry
	}
	return template, nil
}

// Every seal under stateDirectory, each read up to byteCount bytes, sorted by its file's name: what `ur status`
// reads to name the harnesses installed fail-closed (MCP-M6-04). A seal that does not read is left out and counted.
func ReadHarnessSeals(stateDirectory string, byteCount int64) ([]*HarnessSeal, int, error) {
	directory := filepath.Join(stateDirectory, harnessSealDirectoryName)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	seals := []*HarnessSeal{}
	unreadable := 0
	for _, entry := range entries {
		// the telemetry pair is beside the seals and is none of them
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == harnessTelemetryFileName {
			continue
		}
		seal, err := readHarnessSeal(filepath.Join(directory, entry.Name()), byteCount)
		if err != nil {
			unreadable += 1
			continue
		}
		seals = append(seals, seal)
	}
	return seals, unreadable, nil
}

// What the fail-closed form does in a seal's harness, for `ur status`: "" for a fail-open install.
func HarnessFailClosedNote(seal *HarnessSeal) string {
	if !seal.RecordRequired {
		return ""
	}
	if seal.Harness == codexHookHarness {
		return "fail-closed only while each hook runs: Codex documents no fail-closed setting"
	}
	return "fail-closed: the harness stops while the daemon cannot take its events"
}

// Whether one seal's files no longer hold what it sealed: see the file header.
func (self *HarnessConfigHashes) checkSeal(seal *HarnessSeal, adapter harnessInstallAdapter) (bool, error) {
	if self.args.Executable != nil {
		executable, err := self.args.Executable()
		if err != nil {
			return true, err
		}
		if !harnessSameFile(executable, seal.UrPath) {
			return true, nil
		}
	}
	template, err := self.templateOf(seal)
	if err != nil {
		return true, err
	}
	files := adapter.files(seal.Home, seal.ProjectDirectory)
	if len(files) != len(seal.Files) {
		return true, nil
	}
	expected, err := harnessTemplateHashes(files, template)
	if err != nil {
		return true, err
	}
	configSha256 := harnessConfigSha256(expected)
	if hex.EncodeToString(configSha256[:]) != seal.ConfigSha256 {
		return true, nil
	}
	depth := self.args.Ingest.HarnessConfigDepthCount
	for i, file := range files {
		if file.path != seal.Files[i].Path || hex.EncodeToString(expected[i][:]) != seal.Files[i].Sha256 {
			return true, nil
		}
		content, _, _, err := harnessReadFile(file.path, self.args.Ingest)
		if err != nil {
			return true, err
		}
		found, err := file.kind.extract(content, template, depth)
		if err != nil {
			return true, err
		}
		hash, err := harnessEntriesSha256(found)
		if err != nil {
			return true, err
		}
		if hash != expected[i] {
			return true, nil
		}
		competing, err := file.kind.competing(content, template, depth)
		if err != nil || 0 < competing {
			return true, err
		}
	}
	return false, nil
}

// Whether a seal holds the plan's: the install changes nothing where it does.
func (self *HarnessSeal) equal(other *HarnessSeal) bool {
	return other != nil && reflect.DeepEqual(self, other)
}
