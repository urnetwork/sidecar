package model

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One of EvsCommit's scaled bounds: §22.8 scales the code's fold trigger, fold size, base range and
// window bounds down so TLC can search them, keeping their order, and the model proves the scaled
// protocol only while the code still runs the unscaled one.
type scaledBound struct {
	// the constant in EvsCommit.cfg
	name string
	// the code's value, or false while no setting of the code holds it yet
	code func() (int, bool)
	// who binds it to code when it is not yet
	binder string
}

// In §22.8's order: fold trigger, fold size, base range, window limit, window max.
var scaledBounds = []scaledBound{
	{name: "FoldTrigger", binder: "the fold's task, which adds its trigger setting (§11.7, D-EVS-31)"},
	{name: "FoldSize", binder: "the fold's task, which adds its size setting (§11.7, D-EVS-31)"},
	{name: "BaseRange", binder: "the collection windows' task, which adds the base range (§11.7)"},
	{name: "WindowLimit", binder: "the head's task, which adds the window's bound while folds keep up (§11.8)"},
	{name: "WindowMax", code: func() (int, bool) { return sidecar.EvsWindowMaxEntryCount, true }},
}

// §22.8's two lists: "scaled from 96, 64, 63, 127 and 255 to 3, 2, 5, 7 and 9".
var scaledListsPattern = regexp.MustCompile(`scaled from ((?:[0-9]+(?:, | and ))+[0-9]+) to ((?:[0-9]+(?:, | and ))+[0-9]+)`)

func parseScaledList(t *testing.T, text string) []int {
	t.Helper()
	values := []int{}
	for _, field := range strings.FieldsFunc(strings.ReplaceAll(text, " and ", ","), func(r rune) bool { return r == ',' || r == ' ' }) {
		value, err := strconv.Atoi(field)
		if err != nil {
			t.Fatalf("§22.8's scaled list %q: %v", text, err)
		}
		values = append(values, value)
	}
	return values
}

// §22.8's unscaled and scaled bounds, read from design/source/sections/22-TEST.md.
func designScaledBounds(t *testing.T) ([]int, []int) {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		data, err := os.ReadFile(filepath.Join(directory, "design", "source", "sections", "22-TEST.md"))
		if err == nil {
			match := scaledListsPattern.FindStringSubmatch(strings.Join(strings.Fields(string(data)), " "))
			if match == nil {
				t.Fatal("§22.8 no longer says what EvsCommit.tla's bounds are scaled from and to")
			}
			return parseScaledList(t, match[1]), parseScaledList(t, match[2])
		}
		if directory == filepath.Dir(directory) {
			t.Fatalf("no design/source/sections/22-TEST.md above %s", workingDirectory)
		}
	}
}

// EvsCommit.cfg's value of each constant.
func cfgConstants(t *testing.T, spec string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(spec + ".cfg")
	if err != nil {
		t.Fatal(err)
	}
	constants := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), " = ")
		if found {
			constants[name] = value
		}
	}
	return constants
}

// What the scaled bounds rule finds, and what it reports open: the cfg must run §22.8's scaled values,
// each bound the code holds must be §22.8's unscaled value, and both sides keep the order the scaling
// must keep.
func scaledBoundFindings(bounds []scaledBound, unscaled []int, scaled []int, constants map[string]string) ([]string, []string) {
	findings := []string{}
	open := []string{}
	if len(unscaled) != len(bounds) || len(scaled) != len(bounds) {
		return []string{fmt.Sprintf("§22.8 scales %v to %v, and this rule knows %d bounds", unscaled, scaled, len(bounds))}, nil
	}
	for index, bound := range bounds {
		if got := constants[bound.name]; got != strconv.Itoa(scaled[index]) {
			findings = append(findings, "EvsCommit.cfg runs "+bound.name+" = "+got+", and §22.8 scales it to "+strconv.Itoa(scaled[index]))
		}
		if bound.code == nil {
			open = append(open, bound.name+"'s unscaled "+strconv.Itoa(unscaled[index])+" is in no code setting yet; "+bound.binder+" binds it here")
			continue
		}
		if value, held := bound.code(); held && value != unscaled[index] {
			findings = append(findings, "the code's "+bound.name+" is "+strconv.Itoa(value)+", and §22.8's model scales "+strconv.Itoa(unscaled[index])+": rescale the model or restore the setting")
		}
	}
	// fold size < fold trigger < window limit < window max, and base range < window limit, on both sides
	for _, side := range [][]int{unscaled, scaled} {
		foldTrigger, foldSize, baseRange, windowLimit, windowMax := side[0], side[1], side[2], side[3], side[4]
		if !(foldSize < foldTrigger && foldTrigger < windowLimit && windowLimit < windowMax && baseRange < windowLimit) {
			findings = append(findings, fmt.Sprintf("the bounds %v lose the order the scaling keeps", side))
		}
	}
	return findings, open
}

// The cfg runs §22.8's scaled bounds and the code's settings are its unscaled side: a settings change
// that moves the unscaled side fails here, since the model would no longer stand for the code.
func TestEvsCommitScaledBoundsMatchTheCode(t *testing.T) {
	unscaled, scaled := designScaledBounds(t)
	findings, open := scaledBoundFindings(scaledBounds, unscaled, scaled, cfgConstants(t, "EvsCommit"))
	for _, finding := range findings {
		t.Error(finding)
	}
	for _, line := range open {
		t.Logf("open: %s", line)
	}
}

// The rule refuses a moved setting, a cfg that runs another scaled value, and bounds out of order.
func TestScaledBoundsRuleCatchesAMovedSetting(t *testing.T) {
	unscaled, scaled := designScaledBounds(t)
	constants := cfgConstants(t, "EvsCommit")
	moved := append([]scaledBound{}, scaledBounds...)
	moved[4] = scaledBound{name: "WindowMax", code: func() (int, bool) { return 300, true }}
	findings, _ := scaledBoundFindings(moved, unscaled, scaled, constants)
	if len(findings) != 1 || !strings.Contains(findings[0], "the code's WindowMax is 300") {
		t.Errorf("a moved window max: %v", findings)
	}
	replanted := map[string]string{}
	for name, value := range constants {
		replanted[name] = value
	}
	replanted["FoldSize"] = "3"
	findings, _ = scaledBoundFindings(scaledBounds, unscaled, scaled, replanted)
	if len(findings) != 1 || !strings.Contains(findings[0], "FoldSize = 3") {
		t.Errorf("a cfg at another fold size: %v", findings)
	}
	disordered := append([]int{}, unscaled...)
	disordered[1] = 100
	findings, _ = scaledBoundFindings(scaledBounds, disordered, scaled, constants)
	if len(findings) == 0 || !strings.Contains(findings[len(findings)-1], "lose the order") {
		t.Errorf("a fold size above its trigger: %v", findings)
	}
}
