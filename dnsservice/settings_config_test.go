package dnsservice

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// config's dns.yml for each environment beside this checkout: main's refuses, since §12.6's three
// open numbers stay unset until the benchmarks set them, and local's loads.
func TestDnsSettingsReadConfigsDnsYml(t *testing.T) {
	config := filepath.Join("..", "..", "config")
	main, err := os.ReadFile(filepath.Join(config, "main", "dns.yml"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("not read: no config checkout beside this one")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDnsSettings(main); !errors.Is(err, ErrDnsSettingsRefused) {
		t.Errorf("main's dns.yml: %v, want refused until its open numbers are set", err)
	}
	local, err := os.ReadFile(filepath.Join(config, "local", "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDnsSettings(local); err != nil {
		t.Errorf("local's dns.yml: %v", err)
	}
}
