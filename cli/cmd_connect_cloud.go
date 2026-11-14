// ur connect's key (§16.9; QD-041's rule; MCP-M4-02): a key comes from ur's own argument, --token, or from a file,
// --token-file, never from the environment. The file is what a cloud environment's setup step leaves for a session's
// committed SessionStart step, `ur connect --token-file <path> --ephemeral`: ur reads it once, removes it and enrolls,
// so the key is gone from the VM before the agent's first turn (mcp's harness_cloud.go). While an auth key's prefix
// appears anywhere in ur's own environment ur enrolls nothing, since the agent's processes inherit that environment.

package main

import (
	"errors"
	"os"

	"github.com/urnetwork/sidecar/mcp"
)

// ur's own environment. A test replaces it.
var urEnviron = os.Environ

// Both of --token and --token-file were given.
var errUrConnectTwoKeys = errors.New("ur connect takes --token or --token-file, not both")

// The auth key `ur connect` enrolls with: token as given, or the key tokenFile holds, read once and the file removed.
// Refused while an auth key is in ur's environment, before any file is read.
func urConnectAuthKey(token string, tokenFile string) (string, error) {
	if mcp.HarnessCloudEnvironmentHoldsKey(urEnviron()) {
		return "", mcp.ErrHarnessCloudKeyEnvironment
	}
	if tokenFile == "" {
		return token, nil
	}
	if token != "" {
		return "", errUrConnectTwoKeys
	}
	key, err := mcp.TakeHarnessCloudKeyFile(tokenFile, nil)
	if err != nil {
		return "", err
	}
	// the file's bytes are erased; the string handed to the daemon lives until the call ends
	defer clear(key)
	return string(key), nil
}
