//go:build !js && !ios && !android && !sdk_mobile_bind

// Cloud agents (§16.9, R-MCP-10, D-MCP-7, owner decision 49; QD-041's key rule; MCP-M4-02): how `ur` in a harness VM
// comes by its auth key. The rule is a key file, never an environment variable:
//
//	environment   `ur` reads no key from its environment, and refuses to enroll while an auth key's prefix appears
//	              anywhere in it, a name or a value: the agent's processes inherit that environment, so a key there is
//	              a key the agent holds (CC4). HarnessCloudEnvironmentHoldsKey is the test `ur connect` makes first.
//	key file      the environment's setup step writes the whole key string to a file only its owner can read.
//	              TakeHarnessCloudKeyFile reads it once and unlinks it before it answers, so the key is gone from the
//	              running VM before the agent's first turn; a file it cannot take whole and remove is refused and the
//	              copy read is erased, the closed direction. The caller erases what it is handed once the enrollment
//	              has it.
//	hook          HarnessCloudConnectCommand is the committed SessionStart step, `ur connect --token-file <path>
//	              --ephemeral`, which runs before any other `ur` step of a cloud session.
//
// Until a person passes a key this way `ur` in a VM stays Unenrolled and its capture spools (plan-MCP-cloud-auth-key's
// interim): nothing here enrolls by itself, and no committed file holds a key.
//
// Package-level functions are safe for concurrent use.

package mcp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The text every auth key starts with (§7.8), as `ur` looks for it in its environment. An identifier of the key's
// format, which sidecar.RedactAuthKey covers by the same text (a test holds the two together).
const harnessCloudKeyPrefix = "ur-authkey-"

// The flag `ur connect` takes a key file by.
const HarnessCloudKeyFileFlag = "--token-file"

// An auth key's prefix is in the environment, so `ur` enrolls nothing. Names no variable and no value.
var ErrHarnessCloudKeyEnvironment = errors.New("an auth key is in the environment: ur takes a key from a file or its own argument, never from the environment")

// The key file cannot be taken: missing, not a regular file its owner alone can read, too long, empty, or it could
// not be removed. Names no path and no byte of the file.
var ErrHarnessCloudKeyFile = errors.New("the auth key file cannot be used")

// Whether an auth key's prefix appears anywhere in environ, in a name or a value, as os.Environ gives it.
func HarnessCloudEnvironmentHoldsKey(environ []string) bool {
	for _, entry := range environ {
		if strings.Contains(entry, harnessCloudKeyPrefix) {
			return true
		}
	}
	return false
}

// Reads the auth key a setup step left at path and removes the file, answering the key's text with the white space
// around it cut. The file is one regular file, no link, that only its owner can read or write, at most settings'
// MaxByteCount long (nil settings are the defaults). The file is gone when this answers a key; where it cannot be
// removed the key read is erased and nothing is answered. The caller erases the answer when it is done with it.
func TakeHarnessCloudKeyFile(path string, settings *sidecar.AuthKeySettings) ([]byte, error) {
	if settings == nil {
		settings = sidecar.DefaultAuthKeySettings()
	}
	if runtime.GOOS == "windows" || !filepath.IsAbs(path) {
		// no owner-only mode to hold the file to, or a path that depends on where ur was started
		return nil, ErrHarnessCloudKeyFile
	}
	named, err := os.Lstat(path)
	if err != nil || !harnessCloudKeyFileUsable(named, settings) {
		return nil, ErrHarnessCloudKeyFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrHarnessCloudKeyFile
	}
	defer file.Close()
	// the file opened is the one judged: a link or another file put there in between is refused
	opened, err := file.Stat()
	if err != nil || !os.SameFile(named, opened) || !harnessCloudKeyFileUsable(opened, settings) {
		return nil, ErrHarnessCloudKeyFile
	}
	// one byte past the bound, so a longer file is seen as one
	content, err := io.ReadAll(io.LimitReader(file, int64(settings.MaxByteCount)+2))
	if err != nil || settings.MaxByteCount+1 < len(content) {
		clear(content)
		return nil, ErrHarnessCloudKeyFile
	}
	if err := os.Remove(path); err != nil {
		clear(content)
		return nil, ErrHarnessCloudKeyFile
	}
	key := bytes.TrimSpace(content)
	if len(key) == 0 || settings.MaxByteCount < len(key) {
		clear(content)
		return nil, ErrHarnessCloudKeyFile
	}
	taken := bytes.Clone(key)
	clear(content)
	return taken, nil
}

// Whether info is a key file TakeHarnessCloudKeyFile reads: regular, its mode owner-only, no longer than a key and
// the line end after it.
func harnessCloudKeyFileUsable(info os.FileInfo, settings *sidecar.AuthKeySettings) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && info.Size() <= int64(settings.MaxByteCount)+1
}

// The committed SessionStart step of a cloud session: `ur connect --token-file <keyFile> --ephemeral`, ur named as
// the install names it, quoted for the shell a harness runs hooks in, and the instance where it is not the default.
func HarnessCloudConnectCommand(urPath string, keyFile string, instance string) string {
	command := harnessShellQuote(urPath) + " connect " + HarnessCloudKeyFileFlag + " " + harnessShellQuote(keyFile) + " --ephemeral"
	if instance != "" && instance != sidecar.DefaultSidecarSettings().Instance {
		command += " --instance " + harnessShellQuote(instance)
	}
	return command
}
