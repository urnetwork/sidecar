//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// §22.9's git-lfs row (FS-73, X19; EVS2-M10-29): the version matrix a conformance run takes, what this host holds of
// it, and the report that names exactly what ran and what was skipped, since a pass on one host's versions alone is
// not §22.9's evidence.
//
//	matrix   git-lfs 3.x as Ubuntu 22.04 ships it (3.0.2, beside git 2.34.1) and as 24.04 does (3.4.1, beside git
//	         2.43.0), and the latest the host holds of 3.5 or later with the git on its PATH
//	binaries a row's git-lfs is the binary its variable names (UR_TEST_GIT_LFS_3_0_2, UR_TEST_GIT_LFS_3_4_1), and its git
//	         the one UR_TEST_GIT_2_34 or UR_TEST_GIT_2_43 names, as EVS2-M10-26's git 2.34 run reads it; the latest
//	         row's are git-lfs and git on PATH. A binary is held to the version it answers, so a row never runs on
//	         another release than it names
//	skip     a row whose binaries the host lacks, or whose binary answers another version, is skipped with its reason,
//	         and the report says so line by line
//
// Package-level functions are safe for concurrent use.

package sidecartest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// One row of the matrix: a release's git-lfs and the git it ships beside, both identifiers.
type GitLfsMatrixRow struct {
	Name string
	// The git-lfs version the row runs, and the variable naming its binary; empty for the latest row, which takes
	// the PATH's at LatestFloor or later.
	GitLfsVersion  string
	GitLfsVariable string
	// The git version the row runs beside it, and the variable naming its binary; empty for the PATH's.
	GitVersion  string
	GitVariable string
}

// The latest row's floor: a git-lfs on PATH older than this is no latest release.
const GitLfsMatrixLatestFloor = "3.5.0"

// §22.9's rows, in order.
func GitLfsMatrix() []*GitLfsMatrixRow {
	return []*GitLfsMatrixRow{
		{Name: "ubuntu-22.04", GitLfsVersion: "3.0.2", GitLfsVariable: "UR_TEST_GIT_LFS_3_0_2", GitVersion: "2.34.1", GitVariable: "UR_TEST_GIT_2_34"},
		{Name: "ubuntu-24.04", GitLfsVersion: "3.4.1", GitLfsVariable: "UR_TEST_GIT_LFS_3_4_1", GitVersion: "2.43.0", GitVariable: "UR_TEST_GIT_2_43"},
		{Name: "latest"},
	}
}

// One row as this host can run it: its binaries and the versions they answered, or why it is skipped.
type GitLfsMatrixRun struct {
	Row        *GitLfsMatrixRow
	GitLfsPath string
	GitPath    string
	// What the binaries answered to version.
	GitLfsVersion string
	GitVersion    string
	// Empty when the row runs.
	Skipped string
}

// How a plan finds binaries and their versions; the host's own by default (HostGitLfsLookup).
type GitLfsLookup struct {
	Getenv   func(name string) string
	LookPath func(name string) (string, error)
	// The version a git-lfs or git binary answers, as its first line prints it.
	Version func(ctx context.Context, path string) (string, error)
}

// The host's environment, PATH and binaries.
func HostGitLfsLookup() *GitLfsLookup {
	return &GitLfsLookup{
		Getenv:   os.Getenv,
		LookPath: exec.LookPath,
		Version: func(ctx context.Context, path string) (string, error) {
			out, err := exec.CommandContext(ctx, path, "version").Output()
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]), nil
		},
	}
}

var gitLfsVersionPattern = regexp.MustCompile(`([0-9]+)\.([0-9]+)\.([0-9]+)`)

// The x.y.z a version line names, empty for none.
func gitLfsVersionOf(line string) string {
	return gitLfsVersionPattern.FindString(line)
}

// Whether version a is at least b, both x.y.z.
func gitLfsVersionAtLeast(a string, b string) bool {
	parse := func(version string) [3]int {
		parts := [3]int{}
		match := gitLfsVersionPattern.FindStringSubmatch(version)
		for i := 0; match != nil && i < 3; i += 1 {
			fmt.Sscanf(match[i+1], "%d", &parts[i])
		}
		return parts
	}
	left, right := parse(a), parse(b)
	for i := range 3 {
		if left[i] != right[i] {
			return right[i] < left[i]
		}
	}
	return true
}

// What this host can run of each row (see the file header).
func PlanGitLfsMatrix(ctx context.Context, lookup *GitLfsLookup) []*GitLfsMatrixRun {
	runs := []*GitLfsMatrixRun{}
	for _, row := range GitLfsMatrix() {
		run := &GitLfsMatrixRun{Row: row}
		runs = append(runs, run)
		find := func(variable string, name string) (string, string) {
			if variable != "" {
				path := lookup.Getenv(variable)
				if path == "" {
					return "", fmt.Sprintf("%s is not set", variable)
				}
				return path, ""
			}
			path, err := lookup.LookPath(name)
			if err != nil {
				return "", fmt.Sprintf("no %s on PATH", name)
			}
			return path, ""
		}
		var why string
		if run.GitLfsPath, why = find(row.GitLfsVariable, "git-lfs"); why != "" {
			run.Skipped = why
			continue
		}
		if run.GitPath, why = find(row.GitVariable, "git"); why != "" {
			run.Skipped = why
			continue
		}
		lfsLine, err := lookup.Version(ctx, run.GitLfsPath)
		if err != nil {
			run.Skipped = fmt.Sprintf("git-lfs at %s answers no version: %v", run.GitLfsPath, err)
			continue
		}
		gitLine, err := lookup.Version(ctx, run.GitPath)
		if err != nil {
			run.Skipped = fmt.Sprintf("git at %s answers no version: %v", run.GitPath, err)
			continue
		}
		run.GitLfsVersion, run.GitVersion = gitLfsVersionOf(lfsLine), gitLfsVersionOf(gitLine)
		switch {
		case row.GitLfsVersion != "" && run.GitLfsVersion != row.GitLfsVersion:
			run.Skipped = fmt.Sprintf("git-lfs at %s is %s, not %s", run.GitLfsPath, run.GitLfsVersion, row.GitLfsVersion)
		case row.GitLfsVersion == "" && !gitLfsVersionAtLeast(run.GitLfsVersion, GitLfsMatrixLatestFloor):
			run.Skipped = fmt.Sprintf("git-lfs on PATH is %s, older than the latest row's %s", run.GitLfsVersion, GitLfsMatrixLatestFloor)
		case row.GitVersion != "" && run.GitVersion != row.GitVersion:
			run.Skipped = fmt.Sprintf("git at %s is %s, not %s", run.GitPath, run.GitVersion, row.GitVersion)
		}
	}
	return runs
}

// The report: one line a row, what ran with the versions it ran, and what was skipped with why.
func GitLfsMatrixReport(runs []*GitLfsMatrixRun) []string {
	lines := []string{}
	for _, run := range runs {
		if run.Skipped != "" {
			lines = append(lines, fmt.Sprintf("skipped %s: %s", run.Row.Name, run.Skipped))
			continue
		}
		lines = append(lines, fmt.Sprintf("ran %s: git-lfs %s, git %s", run.Row.Name, run.GitLfsVersion, run.GitVersion))
	}
	return lines
}

// The rows that run.
func GitLfsMatrixRunnable(runs []*GitLfsMatrixRun) []*GitLfsMatrixRun {
	runnable := []*GitLfsMatrixRun{}
	for _, run := range runs {
		if run.Skipped == "" {
			runnable = append(runnable, run)
		}
	}
	return runnable
}
