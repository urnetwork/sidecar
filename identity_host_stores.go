//go:build !js && !ios && !android && !sdk_mobile_bind

// D-TRUST-3's host check (§5.6, plan-CORE-host-store-refusal): by state rather than any signal, whatever the stage,
// `ur` refuses to enroll, and an enrolled daemon alarms at each start and each SyncRefetchInterval, while a store on
// this host holds a readable network by_jwt, an admin credential a same-user agent could read. A store counts only if
// this user can read it and it holds a token (QD-183): an app's .by/.auth_state whose JSON by_jwt is not empty, or a
// non-empty legacy .by/.by_jwt, under %LOCALAPPDATA%\URnetwork, $XDG_STATE_HOME/urnetwork, ~/Documents and the
// Documents of the macOS containers network.ur and com.bringyour.urnetwork; or the URnetwork extension in a Chrome,
// Chromium, Edge or Brave profile, or Firefox's, at a version below hostStoreExtensionCleanVersion, D-SDK-11's first
// release that stops persisting the token, which stays empty until that release ships, so every version counts. The
// app's releases need no such constant: one that stops persisting leaves no store, and the host passes by itself, as
// stage 2 asks (TEAM-M3-01). No extension's storage is opened. A value is read only to see that it is not empty: it
// is never copied, logged or sent, and nothing here reports a path.
//
// Desktop hosts only: a phone or a page has no ur to refuse, and its app is the host (identity_host_stores_other.go).

package sidecar

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// The format values the check reads (sdk/local_state_auth.go, extension's manifests, Firefox's extensions.json).
const (
	hostStoreAuthStateName  = ".auth_state"
	hostStoreLegacyJwtName  = ".by_jwt"
	hostStoreStateDirectory = ".by"
	// sdk's own bound on an .auth_state file
	hostStoreMaxByteCount   = 1024 * 1024
	hostStoreExtensionName  = "urnetwork"
	hostStoreFirefoxAddonId = "urnetwork@bringyour.com"
	hostStoreKindApp        = "app"
	hostStoreKindExtension  = "extension"
	// D-SDK-11's first extension release that persists no readable by_jwt, as dotted numbers: an extension at or
	// past it holds none. Empty until that release ships, so every version counts (plan-CORE-host-store-refusal
	// #2); the release that ships it sets it, and with it ur stops refusing beside the extension.
	hostStoreExtensionCleanVersion = ""
)

// Where one host keeps its stores: its home and the environment's directories, for this OS.
type hostStoreRoots struct {
	goos string
	home string
	// Windows: %LOCALAPPDATA% and %APPDATA%
	localAppData string
	appData      string
	// Linux: $XDG_STATE_HOME and $XDG_CONFIG_HOME, each defaulted as the base directory spec has it
	xdgStateHome  string
	xdgConfigHome string
	// hostStoreExtensionCleanVersion, which a test sets
	extensionCleanVersion string
}

// This host's roots.
func defaultHostStoreRoots() *hostStoreRoots {
	home, _ := os.UserHomeDir()
	roots := &hostStoreRoots{
		goos:          runtime.GOOS,
		home:          home,
		localAppData:  os.Getenv("LOCALAPPDATA"),
		appData:       os.Getenv("APPDATA"),
		xdgStateHome:  os.Getenv("XDG_STATE_HOME"),
		xdgConfigHome: os.Getenv("XDG_CONFIG_HOME"),

		extensionCleanVersion: hostStoreExtensionCleanVersion,
	}
	return roots
}

// The stores on this host holding a readable network credential, by kind, with no path. `ur status` names their
// kinds, and enrollment refuses while there is one (D-TRUST-3).
func HostCredentialStores() []SidecarHostCredentialStore {
	return hostCredentialStoresIn(defaultHostStoreRoots())
}

// The stores under roots.
func hostCredentialStoresIn(roots *hostStoreRoots) []SidecarHostCredentialStore {
	stores := []SidecarHostCredentialStore{}
	if hostAppStoreFound(roots) {
		stores = append(stores, SidecarHostCredentialStore{Kind: hostStoreKindApp})
	}
	if hostExtensionStoreFound(roots) {
		stores = append(stores, SidecarHostCredentialStore{Kind: hostStoreKindExtension})
	}
	return stores
}

// The directories an app's state may sit in: each root, and each directory one level below it, which is where an
// app's StateDir puts its .by.
func (self *hostStoreRoots) appStateRoots() []string {
	roots := []string{}
	add := func(parts ...string) {
		for _, part := range parts {
			if part == "" {
				return
			}
		}
		roots = append(roots, filepath.Join(parts...))
	}
	if self.home != "" {
		add(self.home, "Documents")
	}
	switch self.goos {
	case "windows":
		add(self.localAppData, "URnetwork")
	case "darwin":
		for _, container := range []string{"network.ur", "com.bringyour.urnetwork"} {
			add(self.home, "Library", "Containers", container, "Data", "Documents")
		}
	default:
		stateHome := self.xdgStateHome
		if stateHome == "" && self.home != "" {
			stateHome = filepath.Join(self.home, ".local", "state")
		}
		add(stateHome, "urnetwork")
	}
	return roots
}

// Whether an app's .by under any root holds a token.
func hostAppStoreFound(roots *hostStoreRoots) bool {
	for _, root := range roots.appStateRoots() {
		directories := []string{root}
		if entries, err := os.ReadDir(root); err == nil {
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != hostStoreStateDirectory {
					directories = append(directories, filepath.Join(root, entry.Name()))
				}
			}
		}
		for _, directory := range directories {
			stateDirectory := filepath.Join(directory, hostStoreStateDirectory)
			if hostAuthStateHoldsToken(filepath.Join(stateDirectory, hostStoreAuthStateName)) ||
				hostLegacyJwtHoldsToken(filepath.Join(stateDirectory, hostStoreLegacyJwtName)) {
				return true
			}
		}
	}
	return false
}

// A regular file's bytes, at most hostStoreMaxByteCount, or false when it cannot be read or is larger.
func readHostStoreFile(path string) ([]byte, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || hostStoreMaxByteCount < info.Size() {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, hostStoreMaxByteCount+1))
	if err != nil || hostStoreMaxByteCount < len(content) {
		clear(content)
		return nil, false
	}
	return content, true
}

// Whether an .auth_state's by_jwt is not empty. Every .auth_state holds the key, an empty one included
// (sdk/local_state_auth.go:33), so only a value counts.
func hostAuthStateHoldsToken(path string) bool {
	content, ok := readHostStoreFile(path)
	if !ok {
		return false
	}
	defer clear(content)
	var state struct {
		ByJwt string `json:"by_jwt"`
	}
	if json.Unmarshal(content, &state) != nil {
		return false
	}
	holds := strings.TrimSpace(state.ByJwt) != ""
	state.ByJwt = ""
	return holds
}

// Whether a legacy .by_jwt is not empty.
func hostLegacyJwtHoldsToken(path string) bool {
	content, ok := readHostStoreFile(path)
	if !ok {
		return false
	}
	defer clear(content)
	return len(bytes.TrimSpace(content)) != 0
}

// The Chromium-family user data directories on this host.
func (self *hostStoreRoots) chromiumUserDataDirectories() []string {
	directories := []string{}
	switch self.goos {
	case "windows":
		if self.localAppData != "" {
			for _, browser := range [][]string{
				{"Google", "Chrome"}, {"Chromium"}, {"Microsoft", "Edge"}, {"BraveSoftware", "Brave-Browser"},
			} {
				directories = append(directories, filepath.Join(append(append([]string{self.localAppData}, browser...), "User Data")...))
			}
		}
	case "darwin":
		if self.home != "" {
			support := filepath.Join(self.home, "Library", "Application Support")
			for _, browser := range [][]string{
				{"Google", "Chrome"}, {"Chromium"}, {"Microsoft Edge"}, {"BraveSoftware", "Brave-Browser"},
			} {
				directories = append(directories, filepath.Join(append([]string{support}, browser...)...))
			}
		}
	default:
		configHome := self.xdgConfigHome
		if configHome == "" && self.home != "" {
			configHome = filepath.Join(self.home, ".config")
		}
		if configHome != "" {
			for _, browser := range [][]string{
				{"google-chrome"}, {"chromium"}, {"microsoft-edge"}, {"BraveSoftware", "Brave-Browser"},
			} {
				directories = append(directories, filepath.Join(append([]string{configHome}, browser...)...))
			}
		}
	}
	return directories
}

// The Firefox profiles directories on this host.
func (self *hostStoreRoots) firefoxProfilesDirectories() []string {
	switch self.goos {
	case "windows":
		if self.appData != "" {
			return []string{filepath.Join(self.appData, "Mozilla", "Firefox", "Profiles")}
		}
	case "darwin":
		if self.home != "" {
			return []string{filepath.Join(self.home, "Library", "Application Support", "Firefox", "Profiles")}
		}
	default:
		if self.home != "" {
			return []string{filepath.Join(self.home, ".mozilla", "firefox")}
		}
	}
	return nil
}

// Whether a browser profile holds the URnetwork extension at a version that persists a readable by_jwt: a Chromium
// profile's Extensions/<id>/<version>/manifest.json naming URnetwork, or a Firefox profile's extensions.json naming
// its add-on id.
func hostExtensionStoreFound(roots *hostStoreRoots) bool {
	for _, userData := range roots.chromiumUserDataDirectories() {
		manifests, _ := filepath.Glob(filepath.Join(userData, "*", "Extensions", "*", "*", "manifest.json"))
		for _, manifest := range manifests {
			if hostManifestNamesExtension(manifest, roots.extensionCleanVersion) {
				return true
			}
		}
	}
	for _, profiles := range roots.firefoxProfilesDirectories() {
		extensionLists, _ := filepath.Glob(filepath.Join(profiles, "*", "extensions.json"))
		for _, extensionList := range extensionLists {
			if hostFirefoxListNamesExtension(extensionList, roots.extensionCleanVersion) {
				return true
			}
		}
	}
	return false
}

// Whether an extension at version still persists a readable by_jwt: every version while cleanVersion is empty,
// else one below it. A version that does not read as dotted numbers counts, so a doubt refuses.
func hostExtensionVersionPersists(version string, cleanVersion string) bool {
	if cleanVersion == "" {
		return true
	}
	parse := func(text string) ([]int, bool) {
		parts := strings.Split(text, ".")
		numbers := make([]int, 0, len(parts))
		for _, part := range parts {
			number, err := strconv.Atoi(part)
			if err != nil || number < 0 || part != strconv.Itoa(number) {
				return nil, false
			}
			numbers = append(numbers, number)
		}
		return numbers, true
	}
	versionNumbers, ok := parse(version)
	cleanNumbers, cleanOk := parse(cleanVersion)
	if !ok || !cleanOk {
		return true
	}
	for i := 0; i < max(len(versionNumbers), len(cleanNumbers)); i += 1 {
		a, b := 0, 0
		if i < len(versionNumbers) {
			a = versionNumbers[i]
		}
		if i < len(cleanNumbers) {
			b = cleanNumbers[i]
		}
		if a != b {
			return a < b
		}
	}
	return false
}

// Whether a Chromium manifest's name or short name is URnetwork's, at a version that persists the token.
func hostManifestNamesExtension(path string, cleanVersion string) bool {
	content, ok := readHostStoreFile(path)
	if !ok {
		return false
	}
	var manifest struct {
		Name      string `json:"name"`
		ShortName string `json:"short_name"`
		Version   string `json:"version"`
	}
	if json.Unmarshal(content, &manifest) != nil {
		return false
	}
	named := strings.Contains(strings.ToLower(manifest.Name), hostStoreExtensionName) ||
		strings.Contains(strings.ToLower(manifest.ShortName), hostStoreExtensionName)
	return named && hostExtensionVersionPersists(manifest.Version, cleanVersion)
}

// Whether a Firefox profile's extensions.json lists URnetwork's add-on at a version that persists the token.
func hostFirefoxListNamesExtension(path string, cleanVersion string) bool {
	content, ok := readHostStoreFile(path)
	if !ok {
		return false
	}
	var extensionList struct {
		Addons []struct {
			Id      string `json:"id"`
			Version string `json:"version"`
		} `json:"addons"`
	}
	if json.Unmarshal(content, &extensionList) != nil {
		return false
	}
	for _, addon := range extensionList.Addons {
		if addon.Id == hostStoreFirefoxAddonId && hostExtensionVersionPersists(addon.Version, cleanVersion) {
			return true
		}
	}
	return false
}
