package main

import (
	"bytes"
	"strings"
	"testing"
)

func runCmd(args ...string) (code int, stderr string) {
	var errb bytes.Buffer
	code = mainCmd(args, &errb)
	return code, errb.String()
}

func TestUsage(t *testing.T) {
	code, errs := runCmd()
	if code != 2 {
		t.Fatalf("expected code 2, got %d: %s", code, errs)
	}
	if !strings.Contains(errs, "usage: bootbridge") {
		t.Errorf("expected usage output, got %s", errs)
	}
	if !strings.Contains(errs, "-stats duration") {
		t.Errorf("expected -stats in usage output, got %s", errs)
	}
}

func TestInvalidArgs(t *testing.T) {
	code, _ := runCmd("-i", "eth0", "extra_arg")
	if code != 2 {
		t.Fatalf("expected code 2 for extra arguments, got %d", code)
	}

	code, _ = runCmd("-unknown")
	if code != 2 {
		t.Fatalf("expected code 2 for unknown flag, got %d", code)
	}
}

func TestInvalidListen(t *testing.T) {
	code, errs := runCmd("-i", "eth0", "-listen", "invalid_address")
	if code != 1 {
		t.Fatalf("expected code 1 for invalid listen address, got %d: %s", code, errs)
	}
	if !strings.Contains(errs, "-listen:") {
		t.Errorf("expected -listen error, got %s", errs)
	}
}
