# gobootd

A boot server for network-booting old and unusual machines with many boot
protocols, all set up from one configuration file.

gobootd is a Go reimplementation of [bootd](https://github.com/rpajarola/bootd).
It is not a drop-in replacement, but it follows the same idea: describe each
client once (its addresses, the protocols it may use, and the files it may
load), and let every protocol answer from that one description. Every
request that is refused is logged with the reason.

## Status

Under development. The configuration, inventory and diagnostics tools work;
no boot protocol is implemented yet.

| Protocol | Clients | Status |
|---|---|---|
| RARP | Sun, DEC, HP and others | planned |
| RMP | HP 9000/300 | planned |
| ND | Sun-2 | planned |
| TFTP | most | planned |
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

## Building

```
go build ./cmd/bootd
go test ./...
```

## License

GPLv3, see [LICENSE](LICENSE).
