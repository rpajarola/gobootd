package mdns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func testResponder() (*Responder, Interface) {
	r := &Responder{Host: "pc", Services: []Service{
		{Instance: "bootbridge on pc (en0, L2TPv3)", Type: "_bootbridge._udp", Port: 1701, Addr: netip.IPv4Unspecified(), TXT: []string{"encap=l2tpv3", "session=1"}},
		{Instance: "bootbridge on pc (en0, raw)", Type: "_bootbridge._udp", Port: 4711, Addr: netip.MustParseAddr("10.9.9.9")},
	}}
	return r, Interface{Index: 2, Name: "en0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}}
}

func query(t *testing.T, id uint16, qs ...dnsmessage.Question) []byte {
	t.Helper()
	b, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id}, Questions: qs}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func q(name string, typ dnsmessage.Type, class dnsmessage.Class) dnsmessage.Question {
	return dnsmessage.Question{Name: mustName(name), Type: typ, Class: class}
}

func TestRecords(t *testing.T) {
	r, ifi := testResponder()
	recs := r.records(ifi)
	// The raw service listens on an address en0 does not have.
	if len(recs) != 5 {
		t.Fatalf("%d records: %v", len(recs), recs)
	}
	ifi.Addrs = append(ifi.Addrs, netip.MustParsePrefix("10.9.9.9/8"))
	if n := len(r.records(ifi)); n != 1+3+3+2 {
		t.Errorf("with the raw service: %d records", n)
	}
	if r.records(Interface{Name: "x", Addrs: nil}) == nil {
		t.Error("unspecified address: no records")
	}
	r.Services = r.Services[1:]
	if r.records(Interface{Name: "x"}) != nil {
		t.Error("records for a service not on the interface")
	}
}

func TestAnswer(t *testing.T) {
	r, ifi := testResponder()
	recs := r.records(ifi)
	mdnsPeer := netip.MustParseAddrPort("192.168.1.5:5353")
	legacy := netip.MustParseAddrPort("192.168.1.5:40000")

	// A browse gets the PTR and, as additionals, SRV, TXT and A.
	out, unicast := answer(query(t, 0, q("_bootbridge._udp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)), mdnsPeer, recs)
	if out == nil || unicast {
		t.Fatalf("browse: %v %v", out, unicast)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 1 || len(m.Additionals) != 3 || !m.Header.Response || !m.Header.Authoritative || m.Header.ID != 0 || len(m.Questions) != 0 {
		t.Fatalf("browse: %+v", m)
	}

	// Case does not matter; QU asks for a unicast answer.
	out, unicast = answer(query(t, 0, q("_BOOTBRIDGE._udp.LOCAL.", dnsmessage.TypePTR, dnsmessage.ClassINET|unicastResponse)), mdnsPeer, recs)
	if out == nil || !unicast {
		t.Errorf("QU: %v %v", out, unicast)
	}

	// Legacy: unicast, ID and question echoed, short TTLs, no cache flush.
	out, unicast = answer(query(t, 77, q("bootbridge on pc (en0, L2TPv3)._bootbridge._udp.local.", dnsmessage.TypeALL, dnsmessage.ClassINET)), legacy, recs)
	if out == nil || !unicast {
		t.Fatalf("legacy: %v %v", out, unicast)
	}
	m = dnsmessage.Message{}
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if m.Header.ID != 77 || len(m.Questions) != 1 || len(m.Answers) != 2 || len(m.Additionals) != 1 {
		t.Fatalf("legacy: %+v", m)
	}
	for _, rr := range append(m.Answers, m.Additionals...) {
		if rr.Header.TTL > 10 || rr.Header.Class&cacheFlush != 0 {
			t.Errorf("legacy record %v", rr.Header)
		}
	}

	// Service enumeration.
	if out, _ := answer(query(t, 0, q("_services._dns-sd._udp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)), mdnsPeer, recs); out == nil {
		t.Error("no service enumeration")
	}

	// Nothing for other names, other types, or responses.
	for _, b := range [][]byte{
		query(t, 0, q("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)),
		query(t, 0, q("pc.local.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)),
		response(0, nil, recs, nil),
		[]byte("junk"),
	} {
		if out, _ := answer(b, mdnsPeer, recs); out != nil {
			t.Errorf("answered %x", b)
		}
	}
}

func TestCollector(t *testing.T) {
	r, ifi := testResponder()
	recs := r.records(ifi)
	c := newCollector("_bootbridge._udp.local.")
	// The PTR alone leaves SRV and TXT to ask for.
	c.add(recs[1:2], "en0")
	if qs := c.missing(); len(qs) != 1 || qs[0].Type != dnsmessage.TypeALL {
		t.Errorf("missing %v", qs)
	}
	c.add(recs, "en0")
	got := c.results()
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	f := got[0]
	if f.Instance != "bootbridge on pc (en0, L2TPv3)" || f.Host != "pc.local." || f.Port != 1701 || f.TXT["encap"] != "l2tpv3" ||
		len(f.Addrs) != 1 || f.Addrs[0] != netip.MustParseAddr("192.168.1.10") || f.Interface != "en0" {
		t.Errorf("%+v", f)
	}
	if qs := c.missing(); len(qs) != 0 {
		t.Errorf("missing %v", qs)
	}
	// Goodbye.
	c.add(goodbye(recs), "en0")
	if got := c.results(); len(got) != 0 {
		t.Errorf("after goodbye: %+v", got)
	}
}

func TestChanges(t *testing.T) {
	r, ifi := testResponder()
	a := r.records(ifi)
	ifi.Addrs = []netip.Prefix{netip.MustParsePrefix("192.168.1.11/24")}
	b := r.records(ifi)
	if sameRecords(a, b) || !sameRecords(a, r.records(Interface{Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}})) {
		t.Error("sameRecords")
	}
	if gone := missing(a, b); len(gone) != 1 || typeOf(gone[0].Body) != dnsmessage.TypeA {
		t.Errorf("gone: %v", gone)
	}
}
