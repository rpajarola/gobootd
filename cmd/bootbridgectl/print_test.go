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

// TestPrintHosts: hosts show their protocols and an unanswered boot
// request.
func TestPrintHosts(t *testing.T) {
	var out bytes.Buffer
	err := printPeers(&out, []byte(`{"lan_hosts":[
		{"mac":"08:00:20:00:00:01","protocols":["RARP"],"unanswered":"RARP"},
		{"mac":"08:00:20:00:00:02","ip":"192.168.1.6","protocols":["RARP","TFTP"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"08:00:20:00:00:01  -            never      RARP (RARP request not answered)",
		"08:00:20:00:00:02  192.168.1.6  never      RARP TFTP",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
}
