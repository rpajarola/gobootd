package resolve

import (
	"strings"
	"testing"
)

func TestParseMAC(t *testing.T) {
	for in, want := range map[string]string{
		"08:00:20:01:02:03": "08:00:20:01:02:03",
		"8:0:20:1:2:3":      "08:00:20:01:02:03",
		"08-00-20-01-02-03": "08:00:20:01:02:03",
		"0800.2001.0203":    "08:00:20:01:02:03",
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
	} {
		mac, err := ParseMAC(in)
		if err != nil {
			t.Errorf("ParseMAC(%q): %v", in, err)
			continue
		}
		if mac.String() != want {
			t.Errorf("ParseMAC(%q) = %s, want %s", in, mac, want)
		}
	}
	for _, in := range []string{"", "08:00:20:01:02", "08:00:20:01:02:003", "zz:00:20:01:02:03", "00:00:5e:00:53:00:00:01"} {
		if _, err := ParseMAC(in); err == nil {
			t.Errorf("ParseMAC(%q) succeeded, want error", in)
		}
	}
}

func TestParseEthers(t *testing.T) {
	m, err := ParseEthers(strings.NewReader(`
# comment
8:0:20:1:2:3	kali	# trailing comment
08:00:09:aa:bb:cc Nesta
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := m["kali"].String(); got != "08:00:20:01:02:03" {
		t.Errorf("kali = %s", got)
	}
	if got := m["nesta"].String(); got != "08:00:09:aa:bb:cc" {
		t.Errorf("nesta = %s", got)
	}
	if _, err := ParseEthers(strings.NewReader("08:00:20:01:02:03\n")); err == nil {
		t.Error("missing host name accepted")
	}
}
