package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `
resolve {
  ethers = ""
  dns    = false
}
service "rarp" {}
service "tftp" {}
service "rmp" {}

host "kali" {
  mac      = "8:0:20:1:2:3"
  ip       = "192.0.2.5"
  services = ["rarp", "tftp"]
  file "sparc/solaris" { name = "*" }
  file "sparc/openbsd" { name = "openbsd-2.8" }
}

host "nesta" {
  mac      = "8:0:9:1:2:3"
  ip       = "192.0.2.6"
  services = ["rmp"]
  file "hp300/netbsd" {
    name    = "netbsd"
    aliases = ["netbsd-uboot"]
  }
}
`

func setup(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"sparc/solaris", "sparc/openbsd", "hp300/netbsd"} {
		p := filepath.Join(dir, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("boot"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "bootd.hcl")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCmd(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCheck(t *testing.T) {
	path := setup(t, testConfig)
	code, out, errs := runCmd("check", "-c", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(errs, "0 errors, 0 warnings") {
		t.Errorf("stderr = %q", errs)
	}
	for _, want := range []string{
		"services  rarp rmp tftp",
		"host kali (",
		"mac       08:00:20:01:02:03 (config)",
		"netbsd | netbsd-uboot",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

func TestCheckErrors(t *testing.T) {
	path := setup(t, testConfig+`host "kali" {}`)
	code, _, errs := runCmd("check", "-c", path)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(errs, `Host "kali" is already defined`) || !strings.Contains(errs, "1 errors") {
		t.Errorf("stderr = %q", errs)
	}
}

func TestExplain(t *testing.T) {
	path := setup(t, testConfig)
	for _, tc := range []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"08:00:20:01:02:03"}, 0, []string{`matches host "kali" (by MAC address 08:00:20:01:02:03)`}},
		{[]string{"192.0.2.6", "rmp", "netbsd-uboot"}, 0, []string{
			`matches host "nesta" (by IP address 192.0.2.6)`,
			"rmp: allowed for nesta",
			`file "netbsd-uboot" matches by alias: hp300/netbsd`,
			"(4 bytes)",
		}},
		{[]string{"kali", "tftp", "C0000205.SUN4C"}, 0, []string{"matches by wildcard: sparc/solaris"}},
		{[]string{"kali", "rmp"}, 1, []string{"rmp request from kali denied (rmp not allowed for this host)"}},
		{[]string{"kali", "nd"}, 1, []string{`nd: not enabled (no service "nd" block)`}},
		{[]string{"nesta", "rmp", "openbsd"}, 1, []string{
			`denied (file "openbsd" not configured for this host)`,
			"names available over rmp: netbsd netbsd-uboot",
		}},
		{[]string{"8:0:20:9:9:9"}, 1, []string{"denied (client unknown)", "known hosts: kali, nesta"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			code, out, errs := runCmd(append([]string{"explain", "-c", path}, tc.args...)...)
			if code != tc.code {
				t.Errorf("exit %d, want %d; stderr %s", code, tc.code, errs)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output does not contain %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestUsage(t *testing.T) {
	if code, _, _ := runCmd("frobnicate"); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
	if code, _, _ := runCmd("explain"); code != 2 {
		t.Errorf("explain without client: exit %d", code)
	}
}
