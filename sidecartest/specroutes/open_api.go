package specroutes

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var pathParameter = regexp.MustCompile(`\{[^/}]+\}`)

// The operation methods an OpenAPI path item may hold.
var operationMethods = []string{"get", "head", "post", "put", "patch", "delete"}

// One entry of a path item's own `servers:`.
type specServer struct {
	Url string `yaml:"url"`
}

// The path items of bringyour.yml, from URNETWORK_CONNECT_OPENAPI_SPEC or else the connect checkout beside the
// module's, and the file's path.
func loadSpecPaths(t *testing.T) (map[string]map[string]yaml.Node, string) {
	t.Helper()
	path := os.Getenv("URNETWORK_CONNECT_OPENAPI_SPEC")
	if path == "" {
		path = filepath.Join("..", "..", "connect", "api", "bringyour.yml")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]yaml.Node
	}
	if err := yaml.Unmarshal(body, &spec); err != nil {
		t.Fatal(err)
	}
	return spec.Paths, path
}

// The pattern of mux that serves a request for pattern, its path values filled, or "" for none.
func muxMatch(mux *http.ServeMux, pattern string) string {
	method, path, _ := strings.Cut(pattern, " ")
	request := &http.Request{
		Method: method,
		URL:    &url.URL{Path: pathParameter.ReplaceAllString(path, "fixture-value")},
	}
	_, found := mux.Handler(request)
	return found
}

// A pattern with each path value as {}, so the spec's names and the mux's need not agree.
func normalizedPattern(pattern string) string {
	return pathParameter.ReplaceAllString(pattern, "{}")
}

// Checks a service's own operations against its serving mux and route patterns.
func Check(t *testing.T, prefix string, mux *http.ServeMux, patterns []string) {
	t.Helper()
	paths, path := loadSpecPaths(t)
	matched := func(pattern string) string {
		return muxMatch(mux, pattern)
	}

	documented := map[string]string{}
	for path, item := range paths {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		for method, node := range item {
			if !slices.Contains(operationMethods, method) {
				continue
			}
			var operation struct {
				Status string `yaml:"x-status"`
			}
			if err := node.Decode(&operation); err != nil {
				t.Fatal(err)
			}
			pattern := strings.ToUpper(method) + " " + path
			found := matched(pattern)
			documented[normalizedPattern(pattern)] = operation.Status
			if operation.Status != "planned" &&
				normalizedPattern(pattern) != normalizedPattern(found) {
				t.Errorf("%s is documented as served and matches %q in the mux", pattern, found)
			}
		}
	}
	if len(documented) == 0 {
		t.Fatalf("%s documents no %s operations", path, prefix)
	}
	active := 0
	for _, pattern := range patterns {
		if matched(pattern) != pattern {
			continue
		}
		active += 1
		status, exists := documented[normalizedPattern(pattern)]
		if !exists {
			t.Errorf("%s is registered and missing from %s", pattern, path)
		} else if status == "planned" {
			t.Errorf("%s is registered and still marked planned in %s", pattern, path)
		}
	}
	if active == 0 {
		t.Fatalf("no %s route is active", prefix)
	}
}

// Checks the operations bringyour.yml documents on host, under prefix, against a service that serves its whole route
// table on a host of its own: only the paths whose own `servers:` entry names host count, so a path of that prefix
// another host serves (api's /v1/seed.bin beside compute's /v1/) is not the service's. patterns is the service's whole
// table, every route of which its mux serves whether its handler is built or not, so the two must match both ways:
// each documented operation is one of patterns and the mux serves it, and each pattern is documented on host, and on
// host alone. An operation's `x-status: planned` mark may stay while its handler lands, the spec leading the handlers,
// since the mux answers every route of the table either way.
func CheckHost(t *testing.T, host string, prefix string, mux *http.ServeMux, patterns []string) {
	t.Helper()
	paths, path := loadSpecPaths(t)
	table := map[string]string{}
	for _, pattern := range patterns {
		if found := muxMatch(mux, pattern); found != pattern {
			t.Errorf("%s is in the table and the mux serves it as %q", pattern, found)
		}
		table[normalizedPattern(pattern)] = pattern
	}

	documented := map[string]bool{}
	for specPath, item := range paths {
		if !strings.HasPrefix(specPath, prefix) {
			continue
		}
		var servers []specServer
		if node, ok := item["servers"]; ok {
			if err := node.Decode(&servers); err != nil {
				t.Fatal(err)
			}
		}
		if !slices.Contains(servers, specServer{Url: host}) {
			continue
		}
		if len(servers) != 1 {
			t.Errorf("%s names %d servers, %s alone wanted", specPath, len(servers), host)
		}
		for method := range item {
			if !slices.Contains(operationMethods, method) {
				continue
			}
			pattern := strings.ToUpper(method) + " " + specPath
			documented[normalizedPattern(pattern)] = true
			if _, ok := table[normalizedPattern(pattern)]; !ok {
				t.Errorf("%s is documented on %s and is no route of the table", pattern, host)
				continue
			}
			if found := muxMatch(mux, pattern); normalizedPattern(found) != normalizedPattern(pattern) {
				t.Errorf("%s is documented on %s and matches %q in the mux", pattern, host, found)
			}
		}
	}
	if len(documented) == 0 {
		t.Fatalf("%s documents no %s operations on %s", path, prefix, host)
	}
	for normalized, pattern := range table {
		if !documented[normalized] {
			t.Errorf("%s is in the table and missing from %s on %s", pattern, path, host)
		}
	}
}
