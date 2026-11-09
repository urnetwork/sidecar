// §5.9's tree: where an instance's state sits on a desktop, and the path of each file in it. Paths
// here are a SidecarStoreBackend's, relative to <state> with / between segments, so nothing above the
// backend ever joins an OS path. The page Worker has no directory at all and gets the same tree in
// IndexedDB.

package sidecar

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// The name of an instance when neither --instance nor UR_INSTANCE gives one (§5.9).
const defaultSidecarInstanceName = "default"

// §5.9's environment override.
const sidecarInstanceEnvironmentName = "UR_INSTANCE"

// §5.9's files. These are format values: every build of an instance reads the same tree.
const (
	stateJsonPath       = "sidecar.json"
	unlockWrapPath      = "unlock.wrap"
	networkTreeName     = "net"
	keychainWrapName    = "keychain.wrap"
	keychainRecordsName = "keychain.ur"
)

var errInvalidInstanceName = errors.New("instance name is not [a-z0-9][a-z0-9-]{0,31}")

// Whether name fits §5.9's form, which also keeps a path out of a directory name.
func isSidecarInstanceName(name string) bool {
	if name == "" || 32 < len(name) || name[0] == '-' {
		return false
	}
	for i := 0; i < len(name); i += 1 {
		if c := name[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// The instance a process runs as: flagValue if a host read --instance, else UR_INSTANCE, else
// default. Anything that does not fit §5.9's form is refused, never trimmed into one.
func SidecarInstanceName(flagValue string) (string, error) {
	name := flagValue
	if name == "" {
		name = os.Getenv(sidecarInstanceEnvironmentName)
	}
	if name == "" {
		name = defaultSidecarInstanceName
	}
	if !isSidecarInstanceName(name) {
		return "", errInvalidInstanceName
	}
	return name, nil
}

// <state> for instance on this desktop (§5.9). A mobile or page host names its own and never calls
// this: an app has its StateDir, and the page Worker has no directory.
func SidecarStateDirectory(instance string) (string, error) {
	if !isSidecarInstanceName(instance) {
		return "", errInvalidInstanceName
	}
	return sidecarStateDirectoryFor(instance, runtime.GOOS, os.Getenv, os.UserHomeDir)
}

// The rule itself, so each platform's row is testable anywhere. getEnvironment and getHome are os's.
func sidecarStateDirectoryFor(instance string, goos string, getEnvironment func(string) string,
	getHome func() (string, error)) (string, error) {
	switch goos {
	case "windows":
		base := getEnvironment("LOCALAPPDATA")
		if base == "" {
			return "", errors.New("LOCALAPPDATA is not set")
		}
		return filepath.Join(base, "URnetwork", "ur", instance), nil
	case "darwin":
		home, err := getHome()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "ur", instance), nil
	}
	base := getEnvironment("XDG_STATE_HOME")
	// the XDG spec has a relative value ignored, and names this default
	if !filepath.IsAbs(base) {
		home, err := getHome()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "ur", instance), nil
}

// net/<network_id>
func networkDirectoryPath(networkId Id) string {
	return networkTreeName + "/" + networkId.String()
}

// net/<network_id>/keychain.wrap
func keychainWrapPath(networkId Id) string {
	return networkDirectoryPath(networkId) + "/" + keychainWrapName
}

// A path inside net/<network_id>, as it stands in a backend.
func networkFilePath(networkId Id, path string) string {
	return fmt.Sprintf("%s/%s", networkDirectoryPath(networkId), path)
}
