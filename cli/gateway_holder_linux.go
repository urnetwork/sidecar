// The gateway port's holder on Linux (gateway_holder.go): /proc/net/tcp or tcp6 for the listening socket's uid and
// inode, then /proc/<pid>/fd for the process holding that inode, which only this user's processes show.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The holder lookup over settings' bounds.
func urGatewayPortHolder(settings *sidecar.GatewaySettings) func(address string) string {
	return func(address string) string {
		ctx, cancel := context.WithTimeout(context.Background(), settings.HolderLookupTimeout)
		defer cancel()
		table := "/proc/net/tcp"
		if strings.HasPrefix(address, "[") {
			table = "/proc/net/tcp6"
		}
		file, err := os.Open(table)
		if err != nil {
			return ""
		}
		listener, found := procNetTcpListenerOf(file, address)
		file.Close()
		if !found {
			return ""
		}
		socket := "socket:[" + listener.inode + "]"
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return urGatewayHolderText(0, "", listener.uid)
		}
		read := 0
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			read += 1
			if settings.HolderProcessCount < read || ctx.Err() != nil {
				break
			}
			fds, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "fd"))
			if err != nil {
				continue
			}
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join("/proc", entry.Name(), "fd", fd.Name()))
				if err != nil || target != socket {
					continue
				}
				comm, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
				return urGatewayHolderText(pid, strings.TrimSpace(string(comm)), listener.uid)
			}
		}
		return urGatewayHolderText(0, "", listener.uid)
	}
}
