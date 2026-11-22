package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rpajarola/gobootd/internal/mdns"
)

// findOpts are the flags of find.
type findOpts struct {
	wait       time.Duration
	qemu, simh bool
	json       bool
}

// find lists the bridges that announce themselves on the networks this
// machine is on, and with -qemu or -simh, how to connect an emulator.
func find(ctx context.Context, w io.Writer, o findOpts) error {
	found, err := mdns.Browse(ctx, "_bootbridge._udp", o.wait)
	if err != nil && ctx.Err() == nil {
		return err
	}
	if o.json {
		for _, f := range found {
			b, _ := json.Marshal(f)
			fmt.Fprintln(w, string(b))
		}
		return nil
	}
	if len(found) == 0 {
		return fmt.Errorf("no bridge answered within %v (bootbridge announces listeners that are not on loopback, unless -announce off)", o.wait)
	}
	if o.qemu || o.simh {
		for i, f := range found {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "# %s\n%s\n", f.Instance, connectHint(f, o.simh))
		}
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tPORT\tENCAP\tSESSION\tCOOKIE\tCOUNTER\tLAN\tVIA")
	for _, f := range found {
		enc := f.TXT["encap"]
		sess, cookie, counter := "-", "-", "-"
		if enc == "l2tpv3" {
			sess, cookie, counter = f.TXT["session"], cookieDesc(f.TXT["cookie"]), onOff(f.TXT["counter"])
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Instance, addrs(f), f.Port, enc, sess, cookie, counter, f.TXT["lan"], f.Interface)
	}
	return tw.Flush()
}

func addrs(f mdns.Found) string {
	if len(f.Addrs) == 0 {
		return strings.TrimSuffix(f.Host, ".")
	}
	var s []string
	for _, a := range f.Addrs {
		s = append(s, a.String())
	}
	return strings.Join(s, ",")
}

func cookieDesc(bits string) string {
	if bits == "" || bits == "0" {
		return "none"
	}
	return bits + "-bit"
}

func onOff(bit string) string {
	if bit == "1" {
		return "on"
	}
	return "off"
}

// connectHint is the QEMU -netdev, or the simh attach command, that
// connects an emulator on this machine to the bridge f. The cookie is
// not announced: COOKIE stands for it.
func connectHint(f mdns.Found, simh bool) string {
	host := strings.TrimSuffix(f.Host, ".")
	if len(f.Addrs) > 0 {
		host = f.Addrs[0].String()
	}
	switch f.TXT["encap"] {
	case "raw":
		if simh {
			return fmt.Sprintf("attach xq udp:4712:%s:%d", host, f.Port)
		}
		return fmt.Sprintf("-netdev dgram,id=n0,local.type=inet,local.host=0.0.0.0,local.port=4712,remote.type=inet,remote.host=%s,remote.port=%d", host, f.Port)
	case "l2tpv3":
		if simh {
			return "# simh speaks raw UDP only; this bridge needs a raw listener on an address simh can reach"
		}
		s := fmt.Sprintf("-netdev l2tpv3,id=n0,udp=on,src=0.0.0.0,srcport=%d,dst=%s,dstport=%d,txsession=%s,rxsession=%s",
			f.Port, host, f.Port, f.TXT["session"], f.TXT["session"])
		switch f.TXT["cookie"] {
		case "64":
			s += ",cookie64=on,txcookie=COOKIE,rxcookie=COOKIE"
		case "32":
			s += ",txcookie=COOKIE,rxcookie=COOKIE"
		}
		return s + ",counter=" + onOff(f.TXT["counter"])
	}
	return "# unknown encapsulation " + f.TXT["encap"]
}
