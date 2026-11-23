# Netbooting a Motorola MVME187

The MVME187 (and other 88k boards running 187Bug) boots over the network
from its firmware monitor: it asks for its address with BOOTP or RARP,
then loads a boot file over TFTP and jumps to it. bootd answers all three
from one host entry.

This was tested with OpenBSD/mvme88k's `bsd.rd` on gxemul's MVME187
emulation, connected through bootbridge over L2TPv3. The 187Bug commands
below are as the Motorola manuals describe them; check your board's
manual, since BUG versions differ in the details.

## bootd

```hcl
network "lab" {
  address = "10.3.0.250/24"     # bootd's address: on the same subnet as the board
  udp     = "127.0.0.1:4712"
  peers   = ["127.0.0.1:4711"]  # bootbridge
}

service "rarp" {}
service "dhcp" {}
service "tftp" {}

host "moto88obsd55" {
  mac      = "08:00:3e:xx:xx:xx"   # the board's Ethernet address
  ip       = "10.3.0.92"
  services = ["rarp", "dhcp", "tftp"]

  # The first file is the one the board gets when it names none.
  file "moto88obsd55/bsd.rd" {}
}
```

bootd's `address` must be on the board's subnet. bootd hands out its own
address as the TFTP server and its subnet's mask, and gives no router
unless `routers` says so; with bootd on another subnet the board has no way
to reach it, and keeps sending `ARP who-has 0.0.0.0` for the missing
gateway.

## 187Bug

`NIOT` (network I/O teach) sets the boot parameters, and keeps them in
NVRAM. The ones that matter:

| Parameter | Value |
|---|---|
| Controller LUN, Device LUN | `0`, `0` for the on-board Ethernet |
| Client IP, Server IP, Subnet mask, Broadcast, Gateway | `0.0.0.0` to get them from BOOTP/RARP, or set them by hand |
| Boot File Name | the file to load, such as `bsd.rd`; `NULL` for none (see below) |
| BOOTP/RARP Request Control | `A`lways, to ask every time |
| BOOTP/RARP Reply Update Control | `Y`es, to keep what the reply said |

Then boot:

```
187-Bug> NBO 0 0
```

`NBH` loads the file and stops in the monitor instead of jumping to it,
which helps to see whether the load itself worked.

## The empty file name

If NIOT's boot file name is empty, the TFTP read request names no file at
all, even though the BOOTP reply said `bsd.rd`. Most TFTP servers refuse
such a request. bootd answers it with the host's **first** file that TFTP
may serve, and logs it as the default file:

```
tftp request from moto88obsd55 for "": sending /tftpboot/moto88obsd55/bsd.rd ... match="default file"
```

So either:

- keep the file to boot first in the host's `file` list, or
- set NIOT's boot file name to the file's name (`bsd.rd`), and bootd
  matches it by name.

`name = "*"` is not needed for this: an empty name already gets the first
file. The wildcard is for clients that ask for a name bootd does not know,
such as a SPARCstation asking for its address in hex.

## Seeing what the board asks for

With bootbridge in between, watch the exchange from another terminal:

```
$ bootbridgectl dump
... BOOTP Request from 08:00:3e:xx:xx:xx
... BOOTP Reply 08:00:3e:xx:xx:xx at 10.3.0.92
... TFTP Read "" (octet)
```

The quoted name is what the board asked for. A request that bootd turns
down is logged with the reason:
`tftp request from moto88obsd55 for "..." denied (...)`.

If bootbridge shows nothing from the board at all, while `tcpdump` on the
bridge host does see L2TPv3 datagrams arriving, the host firewall is
dropping them; see the limits in
[bootbridge's README](../cmd/bootbridge/README.md#limits).
