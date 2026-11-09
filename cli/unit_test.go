package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Rewrites testdata/unit's golden files from the code, for a reviewed change to a unit.
var updateUnitGoldens = flag.Bool("update-unit-goldens", false, "rewrite testdata/unit")

// A runner that records each command, never running one, answering fail for the commands a test names.
type testUnitRunner struct {
	stateLock sync.Mutex
	commands  []string
	fail      map[string]bool
}

func (self *testUnitRunner) run(ctx context.Context, name string, args ...string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	command := strings.Join(append([]string{name}, args...), " ")
	self.commands = append(self.commands, command)
	if self.fail[command] {
		return errors.New("synthetic failure")
	}
	return nil
}

func (self *testUnitRunner) ran() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.commands...)
}

// Each OS's unit for one environment, the executable at a synthetic path.
func testUnitEnvs(home string) []*unitEnv {
	return []*unitEnv{
		{goos: "darwin", home: home, uid: 501},
		{goos: "linux", home: home, uid: 1000, headless: true},
		{goos: "windows", home: home},
	}
}

// The synthetic executable path a unit runs on each OS.
func testUnitExecutable(goos string) string {
	if goos == "windows" {
		return `C:\Program Files\URnetwork\ur.exe`
	}
	return "/opt/urnetwork/bin/ur"
}

// What a unit is on each OS, held to testdata/unit's goldens: its file, and its install and uninstall commands.
func TestUnitFilesMatchGoldens(t *testing.T) {
	home := "/home/synthetic"
	for _, env := range testUnitEnvs(home) {
		plan, err := unitPlanFor(env, "work", testUnitExecutable(env.goos))
		if err != nil {
			t.Fatalf("%s: %v", env.goos, err)
		}
		var golden strings.Builder
		golden.WriteString("path: " + filepath.ToSlash(plan.path) + "\n")
		golden.WriteString("--- content\n")
		golden.Write(plan.content)
		golden.WriteString("--- install\n")
		for _, command := range append(append([][]string{}, plan.reset...), plan.install...) {
			golden.WriteString(strings.Join(command, " ") + "\n")
		}
		golden.WriteString("--- uninstall\n")
		for _, command := range append(append([][]string{}, plan.uninstall...), plan.afterUninstall...) {
			golden.WriteString(strings.Join(command, " ") + "\n")
		}
		goldenPath := filepath.Join("testdata", "unit", env.goos+".golden")
		if *updateUnitGoldens {
			if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(goldenPath, []byte(golden.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatal(err)
		}
		if golden.String() != string(want) {
			t.Errorf("%s's unit differs from %s:\n%s", env.goos, goldenPath, golden.String())
		}
	}
}

// Every unit runs ur by its absolute path with --unit, which keeps idle exit off, and names only a real instance.
func TestUnitNamesAreChecked(t *testing.T) {
	for _, env := range testUnitEnvs("/home/synthetic") {
		executable := testUnitExecutable(env.goos)
		for _, instance := range []string{"", "Work", "../x", "a b", "work;rm", strings.Repeat("a", 33), "-x"} {
			if _, err := unitPlanFor(env, instance, executable); err == nil {
				t.Errorf("%s: instance %q was taken", env.goos, instance)
			}
		}
		for _, bad := range []string{"ur", "relative/ur", "/opt/ur\"x", "/opt/%h/ur", "/opt/ur\nx"} {
			if _, err := unitPlanFor(env, "work", bad); err == nil {
				t.Errorf("%s: executable %q was taken", env.goos, bad)
			}
		}
		plan, err := unitPlanFor(env, "work", executable)
		if err != nil {
			t.Fatal(err)
		}
		text := string(plan.content) + strings.Join(plan.install[0], " ")
		if !strings.Contains(text, "--unit") || !strings.Contains(text, "work") {
			t.Errorf("%s: the unit does not run ur daemon --instance work --unit", env.goos)
		}
	}
}

// A second install leaves the same file and runs the same commands: an install is idempotent.
func TestInstallIsIdempotent(t *testing.T) {
	for _, env := range testUnitEnvs(t.TempDir()) {
		executable := testUnitExecutable(env.goos)
		first := &testUnitRunner{}
		if err := installDaemonUnit(context.Background(), env, first.run, "work", executable); err != nil {
			t.Fatalf("%s: %v", env.goos, err)
		}
		plan, _ := unitPlanFor(env, "work", executable)
		var content []byte
		if plan.path != "" {
			content, _ = os.ReadFile(plan.path)
			if string(content) != string(plan.content) {
				t.Errorf("%s: the unit file was not written", env.goos)
			}
		}
		second := &testUnitRunner{}
		if err := installDaemonUnit(context.Background(), env, second.run, "work", executable); err != nil {
			t.Fatalf("%s: %v", env.goos, err)
		}
		if strings.Join(first.ran(), "\n") != strings.Join(second.ran(), "\n") {
			t.Errorf("%s: a second install ran %v, the first %v", env.goos, second.ran(), first.ran())
		}
		if plan.path != "" {
			again, _ := os.ReadFile(plan.path)
			if string(again) != string(content) {
				t.Errorf("%s: a second install changed the unit file", env.goos)
			}
		}
	}
}

// An install whose service manager refuses reports it.
func TestInstallReportsAFailedCommand(t *testing.T) {
	env := &unitEnv{goos: "linux", home: t.TempDir()}
	runner := &testUnitRunner{fail: map[string]bool{"systemctl --user enable --now ur@work": true}}
	if err := installDaemonUnit(context.Background(), env, runner.run, "work", "/opt/urnetwork/bin/ur"); err == nil {
		t.Error("a refused enable passed")
	}
}

// Uninstall stops the unit and removes its file, and an uninstall of nothing succeeds.
func TestUninstallRemovesUnit(t *testing.T) {
	for _, env := range testUnitEnvs(t.TempDir()) {
		executable := testUnitExecutable(env.goos)
		runner := &testUnitRunner{}
		if err := installDaemonUnit(context.Background(), env, runner.run, "work", executable); err != nil {
			t.Fatal(err)
		}
		plan, _ := unitPlanFor(env, "work", executable)
		uninstall := &testUnitRunner{fail: map[string]bool{}}
		for _, command := range plan.uninstall {
			// a unit already stopped fails its stop, which an uninstall goes on from
			uninstall.fail[strings.Join(command, " ")] = true
		}
		if err := uninstallDaemonUnit(context.Background(), env, uninstall.run, "work", executable); err != nil {
			t.Fatalf("%s: %v", env.goos, err)
		}
		if len(uninstall.ran()) == 0 {
			t.Errorf("%s: uninstall ran nothing", env.goos)
		}
		if plan.path != "" {
			if _, err := os.Stat(plan.path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: the unit file stayed: %v", env.goos, err)
			}
		}
		if err := uninstallDaemonUnit(context.Background(), env, (&testUnitRunner{}).run, "work", executable); err != nil {
			t.Errorf("%s: an uninstall of nothing: %v", env.goos, err)
		}
	}
}
