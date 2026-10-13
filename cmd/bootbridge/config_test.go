package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
)

func writeConfig(t *testing.T, src string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootbridge.hcl")
	if err := os.WriteFile(path, []byte(src), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `
interface = "en0"
stats     = "1m"

raw {
  peers = ["127.0.0.1:4712"]
}

l2tp {
  listen  = "0.0.0.0:1701"
  peers   = ["192.168.1.20:1701"]
  session = 42
  cookie  = "0x0123456789abcdef"
  counter = false
}
`, 0o600)
	s, _, diags := loadConfig(path)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	o, err := s.check()
	if err != nil {
		t.Fatal(err)
	}
	if o.iface != "en0" || o.stats != time.Minute || o.listen != "127.0.0.1:4711" || len(o.peers) != 1 ||
		o.l2tp != "0.0.0.0:1701" || len(o.l2tpPeers) != 1 || o.l2tpCfg.Session != 42 || o.l2tpCfg.Counter || len(o.l2tpCfg.Cookie) != 8 {
		t.Errorf("options %+v, l2tp %+v", o, o.l2tpCfg)
	}

	// Without a raw block there is no raw listener.
	s, _, _ = loadConfig(writeConfig(t, "interface = \"en0\"\nl2tp { listen = \"0.0.0.0:1701\" }\n", 0o600))
	if s.listen != "" || s.l2tp != "0.0.0.0:1701" || s.session != 1 || !s.counter {
		t.Errorf("settings %+v", s)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		src, want string
		line      int
	}{
		{"interface = \"en0\"\n", "No listener", 0},
		{"raw {\n  listen = \"localhost\"\n}\n", "Invalid address", 2},
		{"l2tp {\n  listen = \"0.0.0.0:1701\"\n  cookie = \"secret\"\n}\n", "Invalid L2TP cookie", 3},
		{"l2tp {\n  listen = \"0.0.0.0:1701\"\n  session = 0\n}\n", "Invalid L2TP session", 3},
		{"stats = \"often\"\nraw {}\n", "Invalid duration", 1},
		{"raw {}\nbridge = true\n", "Unsupported argument", 2},
		{"l2tp {}\n", "Missing required argument", 1},
	} {
		_, _, diags := loadConfig(writeConfig(t, tc.src, 0o600))
		if !diags.HasErrors() {
			t.Errorf("%q: no error", tc.src)
			continue
		}
		d := diags.Errs()[0].(*hcl.Diagnostic)
		if !strings.Contains(d.Summary, tc.want) {
			t.Errorf("%q: %v, want %q", tc.src, d, tc.want)
		}
		if tc.line != 0 && (d.Subject == nil || d.Subject.Start.Line != tc.line) {
			t.Errorf("%q: error at %v, want line %d", tc.src, d.Subject, tc.line)
		}
	}
}

func TestConfigCookieReadable(t *testing.T) {
	_, _, diags := loadConfig(writeConfig(t, "l2tp {\n  listen = \"0.0.0.0:1701\"\n  cookie = \"01234567\"\n}\n", 0o644))
	if diags.HasErrors() || len(diags) != 1 || !strings.Contains(diags[0].Summary, "readable by everyone") {
		t.Errorf("diags %v", diags)
	}
}

// TestConfigFlags: flags given override the file; others keep its values.
func TestConfigFlags(t *testing.T) {
	path := writeConfig(t, "interface = \"en0\"\nl2tp {\n  listen = \"0.0.0.0:1701\"\n  cookie = \"01234567\"\n}\n", 0o600)
	var errb bytes.Buffer
	// eth-nonexistent makes run fail after the settings are checked.
	code := mainCmdWithIO([]string{"-c", path, "-i", "eth-nonexistent", "-l2tp-peer", "10.0.0.1:1701"}, nil, &errb, &errb)
	if code != 1 || !strings.Contains(errb.String(), "eth-nonexistent") {
		t.Errorf("code %d: %s", code, errb.String())
	}

	errb.Reset()
	if code := mainCmdWithIO([]string{"-c", path, "-peer", "10.0.0.1:4712"}, nil, &errb, &errb); code != 2 ||
		!strings.Contains(errb.String(), "raw peers need a raw listener") {
		t.Errorf("code %d: %s", code, errb.String())
	}

	errb.Reset()
	bad := writeConfig(t, "raw {\n  listen = \"nowhere\"\n}\n", 0o600)
	if code := mainCmdWithIO([]string{"-c", bad}, nil, &errb, &errb); code != 2 || !strings.Contains(errb.String(), "bootbridge.hcl line 2") {
		t.Errorf("code %d: %s", code, errb.String())
	}
}

// TestExampleConfig keeps etc/bootbridge.hcl valid.
func TestExampleConfig(t *testing.T) {
	s, _, diags := loadConfig("../../etc/bootbridge.hcl")
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	if _, err := s.check(); err != nil {
		t.Fatal(err)
	}
}
