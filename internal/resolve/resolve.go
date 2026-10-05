// Package resolve looks up MAC and IP addresses for host names that the
// configuration does not spell out.
package resolve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Resolver finds addresses by host name. Besides the address, lookups return
// a short description of the source that answered, for diagnostics.
type Resolver interface {
	LookupMAC(name string) (net.HardwareAddr, string, error)
	LookupIP(name string) (netip.Addr, string, error)
}

// ErrNotFound is returned when no source knows the name.
var ErrNotFound = errors.New("not found")

// System resolves MAC addresses from an ethers(5) file and IPv4 addresses
// with the system resolver.
type System struct {
	ethersPath string
	ethers     map[string]net.HardwareAddr // lower case host name -> MAC
	dns        bool
	timeout    time.Duration
}

// NewSystem reads the ethers file (if path is not empty). A missing ethers
// file is not an error; it simply knows no hosts.
func NewSystem(ethersPath string, dns bool) (*System, error) {
	s := &System{ethersPath: ethersPath, dns: dns, timeout: 5 * time.Second}
	if ethersPath == "" {
		return s, nil
	}
	f, err := os.Open(ethersPath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s.ethers, err = ParseEthers(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ethersPath, err)
	}
	return s, nil
}

// LookupMAC looks name up in the ethers file.
func (s *System) LookupMAC(name string) (net.HardwareAddr, string, error) {
	if mac, ok := s.ethers[strings.ToLower(name)]; ok {
		return mac, s.ethersPath, nil
	}
	return nil, "", ErrNotFound
}

// LookupIP looks name up with the system resolver, IPv4 only.
func (s *System) LookupIP(name string) (netip.Addr, string, error) {
	if !s.dns {
		return netip.Addr{}, "", ErrNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return netip.Addr{}, "", ErrNotFound
		}
		return netip.Addr{}, "", err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, "", ErrNotFound
	}
	return addrs[0].Unmap(), "dns", nil
}

// ParseEthers parses ethers(5) content: "<mac> <hostname>" per line, with
// '#' comments.
func ParseEthers(r io.Reader) (map[string]net.HardwareAddr, error) {
	m := map[string]net.HardwareAddr{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: expected \"<mac> <hostname>\"", n)
		}
		mac, err := ParseMAC(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		m[strings.ToLower(fields[1])] = mac
	}
	return m, sc.Err()
}

// ParseMAC parses a 6 byte Ethernet address. Unlike net.ParseMAC it accepts
// the leading-zero-less form used by ethers(5), e.g. "8:0:20:1:2:3".
func ParseMAC(s string) (net.HardwareAddr, error) {
	for _, sep := range []string{":", "-"} {
		parts := strings.Split(s, sep)
		if len(parts) != 6 {
			continue
		}
		mac := make(net.HardwareAddr, 6)
		for i, p := range parts {
			if len(p) < 1 || len(p) > 2 {
				return nil, fmt.Errorf("invalid MAC address %q", s)
			}
			b, err := strconv.ParseUint(p, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid MAC address %q", s)
			}
			mac[i] = byte(b)
		}
		return mac, nil
	}
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("invalid MAC address %q", s)
	}
	return mac, nil
}
