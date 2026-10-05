package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/hashicorp/hcl/v2"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/resolve"
)

func check(path string, quiet bool, stdout, stderr io.Writer) int {
	l := daemon.Load(path)
	l.WriteDiags(stderr)
	errs, warns := count(l.Diags)
	fmt.Fprintf(stderr, "%s: %d errors, %d warnings\n", path, errs, warns)
	if l.Inventory == nil {
		return 1
	}
	if !quiet {
		inv := l.Inventory
		fmt.Fprintf(stdout, "root      %s\nservices  %s\n", inv.Root, strings.Join(inv.ServiceNames(), " "))
		for _, h := range inv.Hosts {
			fmt.Fprintln(stdout)
			printHost(stdout, h)
		}
	}
	return 0
}

func count(diags hcl.Diagnostics) (errs, warns int) {
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			errs++
		} else {
			warns++
		}
	}
	return errs, warns
}

func printHost(w io.Writer, h *inventory.Host) {
	fmt.Fprintf(w, "host %s (%s)\n", h.Name, h.Origin)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintf(tw, "  mac\t%s\n", addr(h.MAC.String(), h.MACSource))
	fmt.Fprintf(tw, "  ip\t%s\n", addr(ipString(h.IP), h.IPSource))
	if h.Class != nil {
		fmt.Fprintf(tw, "  class\t%s\n", h.Class.Name)
	}
	fmt.Fprintf(tw, "  services\t%s\n", strings.Join(h.Services, " "))
	for _, f := range h.Files {
		names := append([]string{f.Name}, f.Aliases...)
		svcs := ""
		if f.Services != nil {
			svcs = "\t[" + strings.Join(f.Services, " ") + "]"
		}
		fmt.Fprintf(tw, "  file\t%s\t%s%s%s\n", strings.Join(names, " | "), f.Path, missing(f.Path), svcs)
	}
	for _, d := range h.Disks {
		fmt.Fprintf(tw, "  disk\t%s (unit %d, %s%s)\t%s%s\n", d.Name, d.Unit, d.Mode, rw(d.Writable), d.Path, missing(d.Path))
		if d.Boot2 != "" {
			fmt.Fprintf(tw, "  \t  boot2\t%s%s\n", d.Boot2, missing(d.Boot2))
		}
	}
	for _, e := range h.Exports {
		server := ""
		if e.Server != "" {
			server = " on " + e.Server
		}
		fmt.Fprintf(tw, "  export\t%s%s%s\t%s%s\n", e.Name, server, rw(e.Writable), e.Path, missing(e.Path))
	}
	for _, s := range h.Shares {
		fmt.Fprintf(tw, "  share\t%s%s\t%s%s\n", s.Name, rw(s.Writable), s.Path, missing(s.Path))
	}
}

func addr(a, source string) string {
	if source == "" {
		return "unknown"
	}
	return fmt.Sprintf("%s (%s)", a, source)
}

func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func rw(writable bool) string {
	if writable {
		return ", writable"
	}
	return ""
}

func missing(path string) string {
	if _, err := os.Stat(path); err != nil {
		return " (missing)"
	}
	return ""
}

func explain(path string, args []string, stdout, stderr io.Writer) int {
	l := daemon.Load(path)
	if l.Inventory == nil {
		l.WriteDiags(stderr)
		fmt.Fprintf(stderr, "%s has errors; run bootd check\n", path)
		return 1
	}
	inv := l.Inventory
	client := args[0]
	h, how, err := findClient(inv, client)
	if err != nil {
		fmt.Fprintf(stdout, "request from %s denied (%v)\n", client, err)
		fmt.Fprintf(stdout, "  no host has %s; known hosts: %s\n", how, hostNames(inv))
		return 1
	}
	fmt.Fprintf(stdout, "client %s matches host %q (by %s)\n\n", client, h.Name, how)
	printHost(stdout, h)
	if len(args) < 2 {
		return 0
	}

	svc := args[1]
	fmt.Fprintln(stdout)
	s, enabled := inv.Services[svc]
	if !enabled {
		fmt.Fprintf(stdout, "%s: not enabled (no service %q block), requests are not answered\n", svc, svc)
		return 1
	}
	fmt.Fprintf(stdout, "%s: enabled (%s)\n", svc, s.DefRange)
	if err := h.Allows(svc); err != nil {
		fmt.Fprintf(stdout, "%s request from %s denied (%v)\n", svc, h.Name, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: allowed for %s\n", svc, h.Name)

	name := ""
	if len(args) == 3 {
		name = args[2]
	}
	f, kind, err := h.FileIgnoringDir(svc, name)
	if err != nil {
		fmt.Fprintf(stdout, "%s request from %s denied (%v)\n", svc, h.Name, err)
		if fs := h.FilesFor(svc); len(fs) > 0 {
			fmt.Fprintf(stdout, "  names available over %s:", svc)
			for _, f := range fs {
				fmt.Fprintf(stdout, " %s", strings.Join(append([]string{f.Name}, f.Aliases...), " "))
			}
			fmt.Fprintln(stdout)
		}
		return 1
	}
	fmt.Fprintf(stdout, "file %q matches by %s: %s (%s)\n", name, kind, f.Label, f.Origin)
	st, err := os.Stat(f.Path)
	if err != nil {
		fmt.Fprintf(stdout, "  %s: %v\n", f.Path, err)
		return 1
	}
	fmt.Fprintf(stdout, "  serves %s (%d bytes)\n", f.Path, st.Size())
	return 0
}

// findClient looks the client up the way a protocol would: by MAC or IP
// address if it is one, by name otherwise. It returns how it matched.
func findClient(inv *inventory.Inventory, client string) (*inventory.Host, string, error) {
	if mac, err := resolve.ParseMAC(client); err == nil {
		h, err := inv.ByMAC(mac)
		return h, "MAC address " + mac.String(), err
	}
	if ip, err := netip.ParseAddr(client); err == nil {
		h, err := inv.ByIP(ip)
		return h, "IP address " + ip.String(), err
	}
	h, err := inv.ByName(client)
	return h, "name " + client, err
}

func hostNames(inv *inventory.Inventory) string {
	var names []string
	for _, h := range inv.Hosts {
		names = append(names, h.Name)
	}
	return strings.Join(names, ", ")
}
