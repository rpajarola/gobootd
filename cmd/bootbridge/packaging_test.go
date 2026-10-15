package main

import (
	"os"
	"regexp"
	"testing"
)

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

// TestManPage keeps the manual page listing every flag.
func TestManPage(t *testing.T) {
	page, err := os.ReadFile("../../man/bootbridge.8")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bFl ([\w-]+)`).FindAllStringSubmatch(string(page), -1) {
		documented[m[1]] = true
	}
	_, usage := runCmd("-h")
	flags := regexp.MustCompile(`(?m)^  -([\w-]+)`).FindAllStringSubmatch(usage, -1)
	if len(flags) == 0 {
		t.Fatalf("no flags in usage: %s", usage)
	}
	for _, m := range flags {
		if !documented[m[1]] {
			t.Errorf("flag -%s is not in man/bootbridge.8", m[1])
		}
	}
}
