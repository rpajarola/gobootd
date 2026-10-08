package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rpajarola/gobootd/internal/bridge"
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

func TestPrintAndDumpFlags(t *testing.T) {
	code, errs := runCmd("-h")
	if code != 2 {
		t.Fatalf("expected code 2, got %d", code)
	}
	if !strings.Contains(errs, "-print") {
		t.Errorf("expected -print in usage, got %s", errs)
	}
	if !strings.Contains(errs, "-X") {
		t.Errorf("expected -X in usage, got %s", errs)
	}
}

func TestKeyboardCommands(t *testing.T) {
	b := &bridge.Bridge{}
	// Single key presses without enter: 'p', 'x', 's', 'h', 'q'
	input := "pxshq"
	var out bytes.Buffer
	var canceled bool
	cancel := func() { canceled = true }

	handleKeyboard(context.Background(), cancel, strings.NewReader(input), &out, b, nil)
	output := out.String()

	if !strings.Contains(output, "packet printing enabled (summary mode)") {
		t.Errorf("expected toggle print enabled message, got:\n%s", output)
	}
	if !strings.Contains(output, "extra verbose dump mode enabled") {
		t.Errorf("expected extra verbose dump message, got:\n%s", output)
	}
	if !strings.Contains(output, "keyboard commands:") {
		t.Errorf("expected help message, got:\n%s", output)
	}
	if !strings.Contains(output, "quitting...") {
		t.Errorf("expected quitting message, got:\n%s", output)
	}
	if !canceled {
		t.Error("expected cancel to be called on 'q'")
	}
}
