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

// bringyour.yml as these checks read it: its top-level servers and its path items.
type specDocument struct {
	Servers []specServer
	Paths   map[string]map[string]yaml.Node
}

// bringyour.yml, from URNETWORK_CONNECT_OPENAPI_SPEC or else the connect checkout beside the module's, and the file's
// path.
func loadSpec(t *testing.T) (*specDocument, string) {
	t.Helper()
	path := os.Getenv("URNETWORK_CONNECT_OPENAPI_SPEC")
	if path == "" {
		path = filepath.Join("..", "..", "connect", "api", "bringyour.yml")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	spec := &specDocument{}
	if err := yaml.Unmarshal(body, spec); err != nil {
		t.Fatal(err)
	}
	return spec, path
}

// The path items of bringyour.yml, and the file's path.
func loadSpecPaths(t *testing.T) (map[string]map[string]yaml.Node, string) {
	t.Helper()
	spec, path := loadSpec(t)
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

// Checks the operations bringyour.yml documents under prefix on a host of their own against a service that serves its
// whole route table there: the paths whose own `servers:` entry names none of the document's top-level servers, as
// check-routes.sh reads another host's, so a path of that prefix api serves (its /v1/seed.bin beside compute's /v1/)
// is not the service's, and every one of them must name the same one host. patterns is the service's whole table,
// every route of which its mux serves whether its handler is built or not, so the two must match both ways: each
// documented operation is one of patterns and the mux serves it, and each pattern is documented on that host. An
// operation's `x-status: planned` mark may stay while its handler lands, the spec leading the handlers, since the mux
// answers every route of the table either way.
func CheckHost(t *testing.T, prefix string, mux *http.ServeMux, patterns []string) {
	t.Helper()
	spec, path := loadSpec(t)
	table := map[string]string{}
	for _, pattern := range patterns {
		if found := muxMatch(mux, pattern); found != pattern {
			t.Errorf("%s is in the table and the mux serves it as %q", pattern, found)
		}
		table[normalizedPattern(pattern)] = pattern
	}

	documented := map[string]bool{}
	hosts := map[string]bool{}
	for specPath, item := range spec.Paths {
		if !strings.HasPrefix(specPath, prefix) {
			continue
		}
		var servers []specServer
		if node, ok := item["servers"]; ok {
			if err := node.Decode(&servers); err != nil {
				t.Fatal(err)
			}
		}
		if len(servers) == 0 || slices.ContainsFunc(servers, func(server specServer) bool {
			return slices.Contains(spec.Servers, server)
		}) {
			// api's
			continue
		}
		if len(servers) != 1 {
			t.Errorf("%s names %d servers, one host wanted", specPath, len(servers))
		}
		for _, server := range servers {
			hosts[server.Url] = true
		}
		for method := range item {
			if !slices.Contains(operationMethods, method) {
				continue
			}
			pattern := strings.ToUpper(method) + " " + specPath
			documented[normalizedPattern(pattern)] = true
			if _, ok := table[normalizedPattern(pattern)]; !ok {
				t.Errorf("%s is documented on the service's host and is no route of the table", pattern)
				continue
			}
			if found := muxMatch(mux, pattern); normalizedPattern(found) != normalizedPattern(pattern) {
				t.Errorf("%s is documented on the service's host and matches %q in the mux", pattern, found)
			}
		}
	}
	if len(documented) == 0 {
		t.Fatalf("%s documents no %s operations on a host of their own", path, prefix)
	}
	if len(hosts) != 1 {
		t.Errorf("%s's %s operations on hosts of their own name %d hosts, one wanted", path, prefix, len(hosts))
	}
	for normalized, pattern := range table {
		if !documented[normalized] {
			t.Errorf("%s is in the table and missing from %s on the service's host", pattern, path)
		}
	}
}
