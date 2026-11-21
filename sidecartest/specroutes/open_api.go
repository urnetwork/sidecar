package specroutes

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var pathParameter = regexp.MustCompile(`\{[^/}]+\}`)

// Checks a service's own operations against its serving mux and route patterns.
func Check(t *testing.T, prefix string, mux *http.ServeMux, patterns []string) {
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
	matched := func(pattern string) string {
		method, path, _ := strings.Cut(pattern, " ")
		request := &http.Request{
			Method: method,
			URL:    &url.URL{Path: pathParameter.ReplaceAllString(path, "fixture-value")},
		}
		_, found := mux.Handler(request)
		return found
	}

	documented := map[string]bool{}
	for path, item := range spec.Paths {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		for method, node := range item {
			switch method {
			case "get", "head", "post", "put", "patch", "delete":
			default:
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
			documented[pathParameter.ReplaceAllString(pattern, "{}")] = true
			if operation.Status != "planned" &&
				pathParameter.ReplaceAllString(pattern, "{}") != pathParameter.ReplaceAllString(found, "{}") {
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
		if !documented[pathParameter.ReplaceAllString(pattern, "{}")] {
			t.Errorf("%s is registered and missing from %s", pattern, path)
		}
	}
	if active == 0 {
		t.Fatalf("no %s route is active", prefix)
	}
}
