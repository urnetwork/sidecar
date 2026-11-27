//go:build !ios_extension && !sidecar_http

// Linux's owners (DESIGN-COMPUTE §26.5's Linux row; LSTN-M13-02): the owner scan's source (listeners_owners.go) over
// /proc, each process's fds from /proc/<pid>/fd, whose links name a socket as socket:[<inode>], and its name from
// /proc/<pid>/comm. Another user's fd directory refuses this process unless it is root, so the scan reads only what
// the OS lets it. No OS tag: it reads a directory tree, so a fixture tree stands in for /proc on every host.

package sidecar

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The link text of a socket's fd: socket:[<inode>].
const (
	listenersProcSocketPrefix = "socket:["
	listenersProcSocketSuffix = "]"
)

// The tree at root, /proc in production.
type listenersProcSource struct {
	root string
}

// A scanner of the tree at root for a process of euid, at most maxCount links read a call.
func newListenersProcScanner(root string, euid uint32, maxCount int) *listenersOwnerScanner {
	return newListenersOwnerScanner(&listenersProcSource{root: root}, euid, maxCount)
}

// The tree's numeric directories.
func (self *listenersProcSource) pids() []int {
	entries, err := os.ReadDir(self.root)
	if err != nil {
		return []int{}
	}
	pids := []int{}
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil && 0 < pid && entry.IsDir() {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

// pid's fd directory's names.
func (self *listenersProcSource) fds(pid int) []string {
	entries, err := os.ReadDir(filepath.Join(self.root, strconv.Itoa(pid), "fd"))
	if err != nil {
		return []string{}
	}
	fds := make([]string, 0, len(entries))
	for _, entry := range entries {
		fds = append(fds, entry.Name())
	}
	return fds
}

// The inode a socket:[<inode>] link names.
func (self *listenersProcSource) identity(pid int, fd string) (uint64, bool) {
	link, err := os.Readlink(filepath.Join(self.root, strconv.Itoa(pid), "fd", fd))
	if err != nil || !strings.HasPrefix(link, listenersProcSocketPrefix) || !strings.HasSuffix(link, listenersProcSocketSuffix) {
		return 0, false
	}
	inode, err := strconv.ParseUint(link[len(listenersProcSocketPrefix):len(link)-len(listenersProcSocketSuffix)], 10, 64)
	return inode, err == nil
}

// pid's comm, its trailing newline dropped.
func (self *listenersProcSource) name(pid int) string {
	data, err := os.ReadFile(filepath.Join(self.root, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
