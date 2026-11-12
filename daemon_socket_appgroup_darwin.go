//go:build darwin && !ios && !sdk_mobile_bind && !ios_extension

// macOS's app-group sockets (§5.8's Pairing row, §5.9's socket row; QD-345; CORE-M8-02): a sandboxed URnetwork app
// reaches the daemon only through a container the app and the ur bundle share, so the daemon listens on a short-named
// socket in each group container ur claims that exists, the App Store build's 6BGU69Q742.group.network.ur
// (apple/app/network/network-macOS.entitlements:35-38) and the direct build's 6BGU69Q742.group.com.bringyour.urnetwork.
// A container is the app's to create: one that does not exist yet is passed over, and the daemon does not make it.
// Each socket takes daemon_pair.go's name and the main socket's peer check (LOCAL_PEERCRED, the caller's own uid).

package sidecar

import (
	"os"
	"path/filepath"
	"runtime"
)

// The app groups ur claims, each one container under ~/Library/Group Containers.
var daemonAppGroupIdentifiers = []string{
	"6BGU69Q742.group.network.ur",
	"6BGU69Q742.group.com.bringyour.urnetwork",
}

// Sets the app-group paths daemon_pair.go serves to macOS's containers.
func init() {
	daemonAppGroupSocketPathsOf = darwinAppGroupSocketPaths
}

// Each existing container's socket path for instance under home, a path past sun_path's bytes passed over.
func darwinAppGroupSocketPaths(instance string, home string) []string {
	if home == "" {
		return nil
	}
	paths := []string{}
	for _, group := range daemonAppGroupIdentifiers {
		directory := filepath.Join(home, "Library", "Group Containers", group)
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() {
			continue
		}
		path := filepath.Join(directory, DaemonAppGroupSocketName(instance))
		if daemonSunPathMaxByteCount(runtime.GOOS) < len(path) {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}
