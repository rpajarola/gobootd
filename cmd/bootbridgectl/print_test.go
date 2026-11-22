package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestPrintFrame: a frame is its summary line and, for dump, the hex
// dump, without the JSON it came in.
func TestPrintFrame(t *testing.T) {
	var out bytes.Buffer
	c := &client{w: &out}
	v := map[string]json.RawMessage{
		"seq":       json.RawMessage(`1`),
		"time":      json.RawMessage(`"2026-11-22T20:31:36Z"`),
		"action":    json.RawMessage(`"en0 -> udp"`),
		"interface": json.RawMessage(`"en0"`),
		"frame":     json.RawMessage(`"ffffffffffff080020000009080600010800060400010800200000090a0300090000000000000a030001"`),
	}
	if err := c.print(v, opts{hexdump: true}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); strings.Contains(s, `"seq"`) || !strings.Contains(s, "00000000  ff ff") {
		t.Errorf("output:\n%s", s)
	}
}
