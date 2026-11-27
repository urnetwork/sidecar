// The gateway port's holder on macOS (gateway_holder.go): lsof's listing of the listening socket, which names this
// user's own processes; another user's shows nothing, and so names none.

package main

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"

	"github.com/urnetwork/sidecar"
)

// lsof's fixed path on macOS.
const darwinLsofPath = "/usr/sbin/lsof"

// The holder lookup over settings' bounds.
func urGatewayPortHolder(settings *sidecar.GatewaySettings) func(address string) string {
	return func(address string) string {
		ctx, cancel := context.WithTimeout(context.Background(), settings.HolderLookupTimeout)
		defer cancel()
		output, err := exec.CommandContext(ctx, darwinLsofPath, "-nP", "-a", "-iTCP@"+address, "-sTCP:LISTEN", "-Fpcu").Output()
		if err != nil {
			return ""
		}
		pid, uid := 0, -1
		name := ""
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			switch line[0] {
			case 'p':
				if 0 < pid {
					break
				}
				pid, _ = strconv.Atoi(line[1:])
			case 'c':
				if name == "" {
					name = line[1:]
				}
			case 'u':
				if uid < 0 {
					uid, _ = strconv.Atoi(line[1:])
				}
			}
		}
		if pid <= 0 {
			return ""
		}
		return urGatewayHolderText(pid, name, max(uid, 0))
	}
}
