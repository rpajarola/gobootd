package config

import (
	"strings"
	"testing"
)

func TestParseDefaults(t *testing.T) {
	cfg, _, diags := Parse([]byte(`
service "tftp" { listen = [":69"] }
host "kali" {
  disk "boot" { path = "boot" }
}
`), "/etc/bootd/bootd.hcl")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if cfg.Root != "/etc/bootd" {
		t.Errorf("Root = %q, want config directory", cfg.Root)
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "text" || cfg.Log.File != "stderr" {
		t.Errorf("Log = %+v", cfg.Log)
	}
	if *cfg.Resolve.Ethers != "/etc/ethers" || !*cfg.Resolve.DNS {
		t.Errorf("Resolve = %+v", cfg.Resolve)
	}
	if got := cfg.Hosts[0].Disks[0].Mode; got != DiskImage {
		t.Errorf("disk mode = %q, want %q", got, DiskImage)
	}
}

func TestParseRelativeRoot(t *testing.T) {
	cfg, _, diags := Parse([]byte(`root = "netboot"`), "/etc/bootd.hcl")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if cfg.Root != "/etc/netboot" {
		t.Errorf("Root = %q", cfg.Root)
	}
}

func TestParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
		line            int
	}{
		{"unknown service block", `service "bootp" {}`, `"bootp" is not a known service`, 1},
		{"duplicate service", "service \"tftp\" {}\nservice \"tftp\" {}", "already configured", 2},
		{"unknown host service", "host \"a\" {\n  services = [\"rarp\", \"tfpt\"]\n}", `"tfpt" is not a known service`, 2},
		{"unknown file service", "host \"a\" {\n  file \"x\" {\n    services = [\"all\"]\n  }\n}", `"all" is not a known service`, 3},
		{"bad log level", "log {\n  level = \"loud\"\n}", "not one of", 2},
		{"bad disk mode", "host \"a\" {\n  disk \"d\" {\n    path = \"x\"\n    mode = \"tape\"\n  }\n}", "Disk mode", 4},
		{"boot2 without bootfile", "host \"a\" {\n  disk \"d\" {\n    path = \"x\"\n    boot2 = \"y\"\n  }\n}", "bootfile", 4},
		{"writable bootfile", "host \"a\" {\n  disk \"d\" {\n    path = \"x\"\n    mode = \"bootfile\"\n    writable = true\n  }\n}", "cannot be writable", 2},
		{"unknown attribute", "host \"a\" {\n  macaddr = \"1\"\n}", "Unsupported argument", 2},
		{"syntax", "host \"a\" {", "Unclosed configuration block", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, diags := Parse([]byte(tc.src), "test.hcl")
			if !diags.HasErrors() {
				t.Fatal("no error")
			}
			d := diags[0]
			if msg := d.Summary + ": " + d.Detail; !strings.Contains(msg, tc.want) {
				t.Errorf("error %q does not contain %q", msg, tc.want)
			}
			if d.Subject == nil || d.Subject.Start.Line != tc.line {
				t.Errorf("error at %v, want line %d", d.Subject, tc.line)
			}
		})
	}
}
