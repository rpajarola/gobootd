package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
)

func TestParseAnnounce(t *testing.T) {
	for _, tc := range []struct {
		in     string
		on     bool
		ifaces []string
		err    bool
	}{
		{"auto", true, nil, false},
		{"", true, nil, false},
		{"OFF", false, nil, false},
		{"en0", true, []string{"en0"}, false},
		{"en0, eth1", true, []string{"en0", "eth1"}, false},
		{"en0,", false, nil, true},
	} {
		on, ifaces, err := parseAnnounce(tc.in)
		if on != tc.on || !slices.Equal(ifaces, tc.ifaces) || (err != nil) != tc.err {
			t.Errorf("%q: %v %v %v", tc.in, on, ifaces, err)
		}
	}
}

func TestServices(t *testing.T) {
	listen := func(a string, l2 *link.L2TPv3) *link.UDP {
		u, err := link.ListenUDPConfig(netip.MustParseAddrPort(a), link.UDPConfig{L2TP: l2})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { u.Close() })
		return u
	}
	l2 := &link.L2TPv3{Session: 7, Cookie: make([]byte, 8), Counter: true}
	got := services("pc", "eth0.100", []*link.UDP{listen("127.0.0.1:0", nil), listen("0.0.0.0:0", l2)}, l2)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	s := got[0]
	if s.Instance != "bootbridge on pc (eth0-100, L2TPv3)" || !s.Addr.IsUnspecified() || s.Port == 0 ||
		!slices.Contains(s.TXT, "session=7") || !slices.Contains(s.TXT, "cookie=64") || !slices.Contains(s.TXT, "lan=eth0.100") {
		t.Errorf("%+v", s)
	}
	for _, kv := range s.TXT {
		if strings.Contains(kv, "0000000000000000") {
			t.Errorf("cookie announced: %q", kv)
		}
	}
	if n := instanceName(strings.Repeat("h", 80), "en0", "raw"); len(n) > 63 || !strings.HasSuffix(n, " (en0, raw)") {
		t.Errorf("long host: %q (%d)", n, len(n))
	}
}
