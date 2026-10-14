package main

import "testing"

// TestPackagedConfigs keeps the configuration files the packages install
// valid.
func TestPackagedConfigs(t *testing.T) {
	for _, path := range []string{"../../packaging/etc/bootbridge.hcl", "../../packaging/macos/bootbridge.hcl"} {
		s, _, diags := loadConfig(path)
		if diags.HasErrors() {
			t.Fatalf("%s: %v", path, diags)
		}
		if _, err := s.check(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
