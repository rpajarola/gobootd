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

network "lab" {
  address = "192.168.1.250/24"   # bootd's own address on the network
  udp     = "127.0.0.1:4712"     # frames to and from bootbridge, simh or QEMU
}

service "rarp" {}
service "tftp" {}
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

## Networks

bootd works on Ethernet frames and runs its own IP stack
([gVisor netstack](https://gvisor.dev/docs/user_guide/networking/)) with
its own MAC and IP address on each network. It answers ARP itself, and
knows the MAC address of every configured host, so clients that do not
answer ARP before their operating system runs can still be reached. It
needs no privileges and does not touch the host's addresses or ports.

A network carries frames over UDP, one Ethernet frame per datagram with no
header. This is the format of the HECnet bridge, which simh and QEMU speak:

- **Real machines**: `bootbridge` connects an interface to UDP. It is the
  only part that needs root (or `CAP_NET_RAW`, or access to `/dev/bpf*`):

  ```
  sudo bootbridge -i en0 -listen 127.0.0.1:4711 -peer 127.0.0.1:4712
  ```

  bootd then uses `udp = "127.0.0.1:4712"` and `peers = ["127.0.0.1:4711"]`.
  Several peers (bootd, simh, QEMU) can share one bridge.
- **simh**: `attach xq udp:4713:127.0.0.1:4712`
- **QEMU**: `-netdev dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port=4713,remote.type=inet,remote.host=127.0.0.1,remote.port=4712`

bootd learns peers that send to it, so several emulators can talk to one
bootd without a bridge.

A network can also capture directly with `pcap = "en0"`, which needs
privileges. On Wi-Fi, where the access point drops frames from unknown MAC
addresses, add `mac = "interface"` to use the interface's own address (with
an IP address of bootd's own).

## Protocol notes

- **RARP** answers with bootd's address on the network.
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
  broadcast address are answered too, but refusals of broadcast requests are
  only logged, so another server can answer.

Options for each protocol are listed in [`etc/bootd.hcl`](etc/bootd.hcl).

## Building

bootd and bootbridge need libpcap and cgo.

```
go build ./cmd/bootd ./cmd/bootbridge
go test ./...
```

The tests need no privileges: protocols run on an in-memory segment, and an
end-to-end test boots a client through the daemon over UDP.
[`test/emulator`](test/emulator) boots emulated machines with their real
boot PROMs (not included) against bootd, e.g. a SPARCstation 5 in QEMU.

## License

GPLv3, see [LICENSE](LICENSE).
