// ur native-host's manifests (§18.8, §18.15): what lets URnetwork's extension reach the default instance's daemon by
// connectNative, and nothing else. ur install-daemon writes them and uninstall-daemon removes them, for the default
// instance alone, since a browser knows one host by its name: Chrome's, Chromium's, Edge's and Brave's in their
// per-user NativeMessagingHosts directories and Firefox's in its own on darwin and linux, and on windows one file per
// family under the instance's state with HKCU's registry key naming it, as each browser documents.
//
// A manifest names only URnetwork's extension ids: Chromium's family by allowed_origins, chrome-extension://<id>/,
// Firefox by allowed_extensions. The ids are data, native_host_ids.json, that the release supplies; with none
// configured no manifest is written, and ur native-host refuses every caller. A manifest's path is a launcher in the
// instance's state that runs this ur as `ur --instance <instance> native-host`, passing the browser's arguments,
// since a manifest can name a program and no arguments.
//
// What is written and run is planned here for every OS, so each is tested on any host, as unit.go does for units.

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

//go:embed native_host_ids.json
var nativeHostIdsJson []byte

// The native messaging host's name, which the extension's connectNative names: lowercase letters, digits, dots and
// underscores, as Chrome requires. A reading: the design names the host, not its name.
const nativeHostName = "network.ur.ur"

// The instance whose daemon the extension reaches.
const nativeHostInstance = "default"

// What a Chromium extension id is: 32 letters from a to p.
var nativeHostChromeIdPattern = regexp.MustCompile(`^[a-p]{32}$`)

// What a Firefox add-on id is: an email-like id or a braced uuid.
var nativeHostFirefoxIdPattern = regexp.MustCompile(`^([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+|\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})$`)

// URnetwork's extension ids, the only callers a manifest names.
type nativeHostIds struct {
	// Chromium's family: Chrome, Chromium, Edge, Brave.
	Chrome  []string `json:"chrome"`
	Firefox []string `json:"firefox"`
}

// The embedded ids, refusing any that is not an id.
func embeddedNativeHostIds() (*nativeHostIds, error) {
	return parseNativeHostIds(nativeHostIdsJson)
}

// The ids data holds, every one well formed.
func parseNativeHostIds(data []byte) (*nativeHostIds, error) {
	ids := &nativeHostIds{}
	if err := jsonUnmarshalStrict(data, ids); err != nil {
		return nil, fmt.Errorf("the native host's extension ids: %w", err)
	}
	for _, id := range ids.Chrome {
		if !nativeHostChromeIdPattern.MatchString(id) {
			return nil, fmt.Errorf("the native host's extension ids: %q is not a Chromium extension id", id)
		}
	}
	for _, id := range ids.Firefox {
		if !nativeHostFirefoxIdPattern.MatchString(id) {
			return nil, fmt.Errorf("the native host's extension ids: %q is not a Firefox add-on id", id)
		}
	}
	return ids, nil
}

// Whether the browser that started this host is one of ids': Chromium's family passes chrome-extension://<id>/, and
// Firefox the manifest's path and the add-on's id.
func (self *nativeHostIds) allowsCaller(arguments []string) bool {
	for _, argument := range arguments {
		if rest, ok := strings.CutPrefix(argument, "chrome-extension://"); ok {
			return slices.Contains(self.Chrome, strings.TrimSuffix(rest, "/"))
		}
	}
	if 2 <= len(arguments) && strings.HasSuffix(arguments[0], ".json") {
		return slices.Contains(self.Firefox, arguments[1])
	}
	return false
}

// One file a plan writes.
type nativeHostFile struct {
	path    string
	content []byte
	mode    os.FileMode
}

// What installing the manifests writes and runs, and what removing them runs.
type nativeHostPlan struct {
	files []nativeHostFile
	// windows: the registry keys naming each manifest, run after the files are written
	install [][]string
	// run before the files go, failures ignored, since a key may be gone
	uninstall [][]string
}

// A manifest, as the browser family reads it.
type nativeHostManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

// The manifests of env's OS for instance's state directory and executable, or nil when ids names no extension.
func nativeHostPlanFor(env *unitEnv, stateDirectory string, instance string, executable string, ids *nativeHostIds) (*nativeHostPlan, error) {
	if len(ids.Chrome) == 0 && len(ids.Firefox) == 0 {
		return nil, nil
	}
	if !filepath.IsAbs(stateDirectory) && !(env.goos == "windows" && isWindowsAbsolute(stateDirectory)) {
		return nil, errors.New("the native host's launcher needs an absolute state directory")
	}
	if !filepath.IsAbs(executable) && !(env.goos == "windows" && isWindowsAbsolute(executable)) {
		return nil, errors.New("the native host runs ur by an absolute path")
	}
	if strings.ContainsAny(executable+stateDirectory, "\"\n\r\t%\x00") {
		return nil, errors.New("a path holds a character a launcher cannot quote")
	}
	join := filepath.Join
	if env.goos == "windows" {
		join = func(elements ...string) string {
			return strings.Join(elements, `\`)
		}
	}
	directory := join(stateDirectory, "native-host")
	plan := &nativeHostPlan{}
	var launcher string
	if env.goos == "windows" {
		launcher = join(directory, "ur-native-host.bat")
		plan.files = append(plan.files, nativeHostFile{
			path:    launcher,
			content: []byte(fmt.Sprintf("@echo off\r\n\"%s\" --instance %s native-host %%*\r\n", executable, instance)),
			mode:    0o644,
		})
	} else {
		launcher = join(directory, "ur-native-host")
		plan.files = append(plan.files, nativeHostFile{
			path:    launcher,
			content: []byte(fmt.Sprintf("#!/bin/sh\nexec \"%s\" --instance %s native-host \"$@\"\n", executable, instance)),
			mode:    0o755,
		})
	}

	manifestOf := func(firefox bool) ([]byte, error) {
		manifest := &nativeHostManifest{
			Name:        nativeHostName,
			Description: "URnetwork: the sidecar daemon, for URnetwork's extension",
			Path:        launcher,
			Type:        "stdio",
		}
		if firefox {
			manifest.AllowedExtensions = slices.Clone(ids.Firefox)
		} else {
			for _, id := range ids.Chrome {
				manifest.AllowedOrigins = append(manifest.AllowedOrigins, "chrome-extension://"+id+"/")
			}
		}
		encoded, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(encoded, '\n'), nil
	}

	chromeDirectories := []string{}
	firefoxDirectories := []string{}
	switch env.goos {
	case "darwin":
		if env.home == "" {
			return nil, errors.New("no home directory for the browsers' manifests")
		}
		support := filepath.Join(env.home, "Library", "Application Support")
		chromeDirectories = []string{
			filepath.Join(support, "Google", "Chrome", "NativeMessagingHosts"),
			filepath.Join(support, "Chromium", "NativeMessagingHosts"),
			filepath.Join(support, "Microsoft Edge", "NativeMessagingHosts"),
			filepath.Join(support, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts"),
		}
		firefoxDirectories = []string{filepath.Join(support, "Mozilla", "NativeMessagingHosts")}
	case "linux":
		if env.home == "" {
			return nil, errors.New("no home directory for the browsers' manifests")
		}
		configHome := env.xdgConfigHome
		if configHome == "" {
			configHome = filepath.Join(env.home, ".config")
		}
		chromeDirectories = []string{
			filepath.Join(configHome, "google-chrome", "NativeMessagingHosts"),
			filepath.Join(configHome, "chromium", "NativeMessagingHosts"),
			filepath.Join(configHome, "microsoft-edge", "NativeMessagingHosts"),
			filepath.Join(configHome, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts"),
		}
		firefoxDirectories = []string{filepath.Join(env.home, ".mozilla", "native-messaging-hosts")}
	case "windows":
		chromeDirectories = []string{directory}
		firefoxDirectories = []string{directory}
	default:
		return nil, fmt.Errorf("no native host manifests on %s", env.goos)
	}

	if 0 < len(ids.Chrome) {
		content, err := manifestOf(false)
		if err != nil {
			return nil, err
		}
		if env.goos == "windows" {
			path := join(directory, nativeHostName+".chromium.json")
			plan.files = append(plan.files, nativeHostFile{path: path, content: content, mode: 0o644})
			for _, key := range []string{
				`HKCU\Software\Google\Chrome\NativeMessagingHosts\`,
				`HKCU\Software\Chromium\NativeMessagingHosts\`,
				`HKCU\Software\Microsoft\Edge\NativeMessagingHosts\`,
				`HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\`,
			} {
				plan.install = append(plan.install, []string{"reg", "add", key + nativeHostName, "/ve", "/t", "REG_SZ", "/d", path, "/f"})
				plan.uninstall = append(plan.uninstall, []string{"reg", "delete", key + nativeHostName, "/f"})
			}
		} else {
			for _, chromeDirectory := range chromeDirectories {
				plan.files = append(plan.files, nativeHostFile{path: filepath.Join(chromeDirectory, nativeHostName+".json"), content: content, mode: 0o644})
			}
		}
	}
	if 0 < len(ids.Firefox) {
		content, err := manifestOf(true)
		if err != nil {
			return nil, err
		}
		if env.goos == "windows" {
			path := join(directory, nativeHostName+".firefox.json")
			plan.files = append(plan.files, nativeHostFile{path: path, content: content, mode: 0o644})
			key := `HKCU\Software\Mozilla\NativeMessagingHosts\` + nativeHostName
			plan.install = append(plan.install, []string{"reg", "add", key, "/ve", "/t", "REG_SZ", "/d", path, "/f"})
			plan.uninstall = append(plan.uninstall, []string{"reg", "delete", key, "/f"})
		} else {
			for _, firefoxDirectory := range firefoxDirectories {
				plan.files = append(plan.files, nativeHostFile{path: filepath.Join(firefoxDirectory, nativeHostName+".json"), content: content, mode: 0o644})
			}
		}
	}
	return plan, nil
}

// Writes each file whose content differs, then runs the plan's install commands, so a second install changes nothing.
// A nil plan writes nothing.
func installNativeHostPlan(ctx context.Context, runner unitRunner, plan *nativeHostPlan) error {
	if plan == nil {
		return nil
	}
	for _, file := range plan.files {
		existing, err := os.ReadFile(file.path)
		if err == nil && bytes.Equal(existing, file.content) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(file.path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(file.path, file.content, file.mode); err != nil {
			return err
		}
		if err := os.Chmod(file.path, file.mode); err != nil {
			return err
		}
	}
	for _, command := range plan.install {
		if err := runner(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("%s: %w", command[0], err)
		}
	}
	return nil
}

// Runs the plan's uninstall commands, ignoring their failures, then removes its files, succeeding when they are gone.
func uninstallNativeHostPlan(ctx context.Context, runner unitRunner, plan *nativeHostPlan) error {
	if plan == nil {
		return nil
	}
	for _, command := range plan.uninstall {
		runner(ctx, command[0], command[1:]...)
	}
	for _, file := range plan.files {
		if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
