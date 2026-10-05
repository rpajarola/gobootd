# gobootd

A boot server for network-booting old and unusual machines with many boot
protocols, all set up from one configuration file.

gobootd is a Go reimplementation of [bootd](https://github.com/rpajarola/bootd).
It is not a drop-in replacement, but it follows the same idea: describe each
client once (its addresses, the protocols it may use, and the files it may
load), and let every protocol answer from that one description. Every
request that is refused is logged with the reason.

## Status

Under development. The configuration and diagnostics tools work, and so do
the first protocols. They are tested against recorded traffic and simulated
clients, but not yet against real hardware.

| Protocol | Clients | Status |
|---|---|---|
| RARP | Sun, DEC, HP and others | works |
| RMP | HP 9000/300 and /400 | works |
| ND | Sun-2 | works (boot only; no writes yet) |
| TFTP | most | works (read only; blksize, tsize, timeout options) |
| bootparam | SunOS, NetBSD, Solaris | planned |
| NFSv2 | diskless root/swap | planned |
| RPL | IBM, 3Com DOS boot ROMs | planned |
| MOP | DEC VAX, Alpha | planned |
| BOOTP/DHCP | most | planned |
| SMB1 | DOS clients after RPL | planned |
| RBCS | 3Com 3Station | needs reverse engineering |

## Configuration

The configuration is [HCL](https://github.com/hashicorp/hcl). A short
example (see [`etc/bootd.hcl`](etc/bootd.hcl) for more):

```hcl
root = "/srv/netboot"

service "rarp" { interfaces = ["en0"] }
service "tftp" { listen = [":69"] }
service "bootparam" {}
service "nfs" {}

host "kali" {
  # mac and ip are optional: they are looked up in /etc/ethers and DNS.
  services = ["rarp", "tftp", "bootparam", "nfs"]

  file "files/sparc/solaris-2.5.1-sun4c" { name = "*" }
  export "root" { path = "/export/hosts/kali/root" }
}
```

## Usage

```
bootd [run] [-c config]                        run the boot server
bootd check [-c config] [-q]                   validate the configuration and show what is served
bootd explain [-c config] <client> [service [file]]
                                               show how a request from client would be handled
```

`bootd check` reports errors and warnings with file and line, then lists
every host with its addresses (and where they came from), services and
files. `bootd explain` follows one request through the same lookups the
protocols use, for example:

```
$ bootd explain kali tftp C0A80105.SUN4C
```

The default configuration file is `/etc/bootd.hcl`. Send SIGHUP to reload
hosts and files; service and log settings take effect on restart.

RARP, RMP and ND send and receive raw Ethernet frames through libpcap, so
bootd needs root, `CAP_NET_RAW` on Linux, or access to `/dev/bpf*` on BSD
and macOS. TFTP needs root only to listen on port 69.

## Protocol notes

- **RARP** answers with the server address on the client's subnet.
- **RMP**: clients without a host entry are matched to a class by the machine
  type their boot ROM sends (`match = { rmp_machtype = "HPS300" }`). The boot
  ROM's file list shows the host's RMP files in configuration order.
- **ND**: the Sun-2 PROM boots from public unit 0 (`ndp0`) before it knows its
  IP address, so the host needs a MAC address. A disk with
  `mode = "bootfile"` works like NetBSD's ndbootd: the file in `path` is the
  first-stage program (at most 15 blocks, e.g. `bootyy`), and `boot2`
  (e.g. `netboot`) starts at block 16. Disks in `image` mode are matched by
  ND minor number in `unit` (64 + n for `ndp<n>`).
- **TFTP** identifies clients by IP address. A request for a path such as
  `/tftpboot/name` also matches a file named `name`. Requests sent to a
  broadcast address are answered from the server's address on the client's
  subnet; refusals of broadcast requests are logged but not sent, so another
  server can answer.

Options for each protocol are listed in [`etc/bootd.hcl`](etc/bootd.hcl).

## Building

bootd needs libpcap and cgo.

```
go build ./cmd/bootd
go test ./...
```

The filter tests use `tcpdump` and are skipped if it is not installed.

## License

GPLv3, see [LICENSE](LICENSE).
