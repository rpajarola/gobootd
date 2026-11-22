package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rpajarola/gobootd/internal/mdns"
)

func TestConnectHint(t *testing.T) {
	l2 := mdns.Found{Host: "pc.local.", Port: 1701, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")},
		TXT: map[string]string{"encap": "l2tpv3", "session": "3", "cookie": "64", "counter": "0"}}
	if h := connectHint(l2, false); !strings.Contains(h, "dst=10.0.0.5,dstport=1701,txsession=3,rxsession=3,cookie64=on,txcookie=COOKIE") || !strings.HasSuffix(h, "counter=off") {
		t.Errorf("qemu l2tp: %s", h)
	}
	l2.TXT["cookie"] = "0"
	if h := connectHint(l2, false); strings.Contains(h, "cookie") {
		t.Errorf("no cookie: %s", h)
	}
	raw := mdns.Found{Host: "pc.local.", Port: 4711, TXT: map[string]string{"encap": "raw"}}
	if h := connectHint(raw, true); h != "attach xq udp:4712:pc.local:4711" {
		t.Errorf("simh raw: %s", h)
	}
	if h := connectHint(raw, false); !strings.Contains(h, "remote.host=pc.local,remote.port=4711") {
		t.Errorf("qemu raw: %s", h)
	}
}
