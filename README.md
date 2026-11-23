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
| ND | Sun-2 | works (diskless SunOS 2.0) |
| TFTP | most | works (read only; blksize, tsize, timeout options) |
| bootparam | SunOS, NetBSD, Solaris | works (with a built-in portmapper) |
| NFSv2 | diskless root/swap | works (read only, MOUNT v1) |
| NIS | SunOS and other YP clients | works (read only, no map transfer) |
| RPL | IBM, 3Com DOS boot ROMs | planned |
| MOP | DEC VAX, Alpha | planned |
| BOOTP/DHCP | most | works (fixed addresses for configured hosts) |
| HTTP | NetBSD, Solaris installers | works (read only, GET and HEAD with ranges) |
| FTP | NetBSD, Solaris installers | works (anonymous, read only, passive and active) |
| SMB1 | DOS clients after RPL | planned |
| RBCS | 3Com 3Station | needs reverse engineering |

## Install

Packages are attached to each [release](https://github.com/rpajarola/gobootd/releases),
and available from:

- **Debian and Ubuntu** (amd64, arm64): the [apt repository](https://rpajarola.github.io/apt/),
  then `sudo apt install gobootd`
- **macOS**: the [Homebrew tap](https://github.com/rpajarola/homebrew-tap),
  `brew install rpajarola/tap/gobootd`, or the installer package from a
  release, which needs no Homebrew

[packaging](packaging/README.md) describes what is installed, how to set
up the services, and how the packages are built.

Or build it with Go: `go install github.com/rpajarola/gobootd/cmd/...@latest`
(bootd and bootbridge need libpcap's headers).

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
  Several peers (bootd, simh, QEMU) can share one bridge. While it runs,
  `bootbridgectl peers` and `bootbridgectl dump` show who is attached and
  what passes through. bootbridge announces its listeners that are not on
  loopback over DNS-SD/mDNS; `bootbridgectl find -qemu` (or `-simh`) on
  another machine lists them with the line to connect an emulator.
- **simh**: `attach xq udp:4713:127.0.0.1:4712`
- **QEMU**: `-netdev dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port=4713,remote.type=inet,remote.host=127.0.0.1,remote.port=4712`

bootd learns peers that send to it, so several emulators can talk to one
bootd without a bridge.

Instead of raw frames, a network can use static L2TPv3 (RFC 3931), which
Linux and QEMU also speak. Its cookie keeps out anyone who does not know
it, so bootd and bootbridge can run on different machines:

```hcl
network "lab" {
  address = "192.168.1.250/24"
  udp     = "0.0.0.0:1701"
  peers   = ["192.168.1.10:1701"]   # sudo bootbridge -i en0 -l2tp 0.0.0.0:1701 -cookie 0x0123456789abcdef
  l2tp { cookie = "0x0123456789abcdef" }
}
```

bootd sends its fixed peers a keepalive every minute, so bootbridge needs
no `-peer` for it. See [bootbridge](cmd/bootbridge/README.md) for details.

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
- **bootparam** tells a client its host name and where its exports are:
  `GETFILE root` answers with the host's `export "root"`, so bootparam and
  NFS always agree. Exports with a `server` point to another NFS server.
  The portmapper is built in and answers broadcast `CALLIT` requests;
  unknown clients and unknown keys get no answer, so another server can
  answer. `dump` gets an empty answer when not configured, as SunOS expects;
  `gateway` gets the router and netmask, which NetBSD needs.
- **NFS** serves the host's `export` blocks over NFSv2 and MOUNT v1 (UDP);
  a client may only mount its own exports. A root file system extracted
  without root privileges lacks device nodes and root-owned files: give
  the export a `spec`, an mtree(5) file such as
  `tar -cf root.mtree --format=mtree @root.tgz` makes, and bootd serves the
  owners, modes, devices and symlinks it lists. `export_path` sets the path
  clients see; NetBSD keeps `server:path` in 90 bytes. Writes are not
  supported yet.
- **NIS** serves one domain to hosts that may use `nis`. The maps are made
  from files in `/etc` format in the `maps` directory (`passwd`, `group`,
  `hosts`, `ethers`, `netgroup`, `services`, `protocols`, `rpc`,
  `networks`, `netmasks`, `aliases`, `publickey`, `bootparams`), keyed as
  SunOS's `/var/yp/Makefile` keys them; a missing file means no map. The
  configured hosts are added to `hosts.*` and `ethers.*`, and bootd's own
  `server_name` with its address on each network. ypbind finds the server
  by broadcast; `ypcat` works over TCP. bootparam announces the NIS domain
  to hosts that may use `nis`, so SunOS sets its domain name and starts
  ypbind. The files are read again on SIGHUP. `netgroup.byuser` and
  `netgroup.byhost` are not made, and maps cannot be pushed to slaves.
- **BOOTP/DHCP** gives each host that may use `dhcp` its configured IP
  address, with bootd as the TFTP server (`siaddr`), the host's first file
  as the boot file (or the file matching the name the client asks for),
  its name, the subnet mask and broadcast address, the routers on its
  subnet, DNS servers and domain, and its `export "root"` as root path
  (`server:path`, as Linux and the BSDs expect). Hosts that may use `nis`
  also get the NIS domain and server. There is no address pool: unknown
  clients get no answer, so bootd can share a network with another DHCP
  server, and requests naming another server are left to it. Replies go
  straight to the client's Ethernet address, or are broadcast if it asks.
  Relay agents are not supported.
- **TFTP** identifies clients by IP address. A request for a path such as
  `/tftpboot/name` also matches a file named `name`, and a request with an
  empty name, which 187Bug sends when it has no boot file name set, gets
  the host's first file. Requests sent to a
  broadcast address are answered too, but refusals of broadcast requests are
  only logged, so another server can answer.

- **HTTP** and **FTP** serve the same read-only tree, for installers that
  fetch their sets or archives by URL. As with WebNFS, paths are the ones
  NFS clients mount: `export "sets" { path = "/srv/netbsd-10.1",
  export_path = "/pub/netbsd-10.1" }` is
  `http://server/pub/netbsd-10.1/` and `ftp://server/pub/netbsd-10.1/`.
  The host's files are at the top under their names and aliases (not under
  `"*"`), and directories are listed down to the exports. Clients are
  identified by IP address, like everywhere else. HTTP answers GET and
  HEAD, with ranges; there is no CGI, so Solaris WAN boot's `wanboot-cgi`
  is not supported. FTP logs in `anonymous` or `ftp` with any password,
  and has passive and active mode (active only to the client itself),
  SIZE, MDTM and REST.

Guides for particular machines: [MVME187](docs/mvme187.md).

Options for each protocol are listed in [`etc/bootd.hcl`](etc/bootd.hcl).
The manual pages [bootd(8)](man/bootd.8), [bootbridge(8)](man/bootbridge.8),
[bootbridgectl(1)](man/bootbridgectl.1) and [bootd.hcl(5)](man/bootd.hcl.5)
describe every command, flag and setting (`man ./man/bootd.8` reads one
from the source tree).

## Building

bootd and bootbridge need libpcap and cgo; bootbridgectl does not.

```
go build ./cmd/bootd ./cmd/bootbridge ./cmd/bootbridgectl
go test ./...
```

The tests need no privileges: protocols run on an in-memory segment, and an
end-to-end test boots a client through the daemon over UDP.
[`test/emulator`](test/emulator) boots emulated machines with their real
boot PROMs (not included) against bootd, e.g. a SPARCstation 5 in QEMU
that boots NetBSD diskless: RARP, TFTP, bootparam and NFS.

## License

GPLv3, see [LICENSE](LICENSE).
