# bootbridge

bootbridge connects a network interface to bootd, simh or QEMU over UDP,
either raw (one Ethernet frame per datagram) or with static L2TPv3, whose
cookie works as a password.
It is the only part of gobootd that needs capture privileges (root,
`CAP_NET_RAW` on Linux, or access to `/dev/bpf*` on BSD and macOS); bootd
itself runs unprivileged.

```
sudo bootbridge -i en0 -listen 127.0.0.1:4711 -peer 127.0.0.1:4712
```

To reach bootd or QEMU on other machines, add an L2TPv3 listener. It
needs no peers: endpoints that know the session and cookie are learned
when they send, and bootd sends a keepalive every minute so it is learned
before any client boots.

```
sudo bootbridge -i en0 -l2tp 0.0.0.0:1701 -cookie 0x0123456789abcdef
```

| Flag | Default | Meaning |
|---|---|---|
| `-i` | (required) | network interface to bridge |
| `-listen` | `127.0.0.1:4711` | UDP address to exchange raw frames on (`""` for none) |
| `-peer` | none | raw UDP peer that always receives frames (repeatable) |
| `-l2tp` | none | UDP address to exchange L2TPv3 frames on |
| `-l2tp-peer` | none | L2TPv3 peer that always receives frames (repeatable) |
| `-session` | `1` | L2TPv3 session ID, the same in both directions |
| `-cookie` | none | L2TPv3 cookie: 8 or 16 hex digits, the same in both directions |
| `-counter` | `true` | L2TPv3 L2-specific sublayer with a sequence number |
| `-stats` | `30s` | interval to log interface statistics (0 to disable) |
| `-v` | off | log every forwarding error |
| `-print` / `-p` | off | print packets as they pass through the bridge |
| `-X` / `-dump` | off | dump very verbose packet info (hex/ASCII dump, like tcpdump -X) |
| `-print-iface` | `all` | limit packet printing to an interface (`udp`, `lan`, `all`, or interface name) |

### Interactive keyboard controls

While running interactively in a terminal, press any key directly (no need to press Enter):
- `p` (or `[Space]` / `[Enter]`): toggle packet printing on and off.
- `x` (or `v` / `d`): toggle extra verbose packet dumping (`tcpdump -X` format).
- `i`: cycle interface print filter (`all` &rarr; `udp` &rarr; `lan` &rarr; `all`).
- `u`: limit packet printing to the UDP transport only.
- `l`: limit packet printing to the LAN interface only.
- `a`: print packets from all interfaces.
- `s`: print current interface statistics on demand.
- `q`: quit cleanly.
- `h` or `?`: show keyboard help.

bootd then uses a network block such as:

```hcl
network "lab" {
  address = "192.168.1.250/24"
  udp     = "127.0.0.1:4712"
  peers   = ["127.0.0.1:4711"]
}
```

or, over L2TPv3 from another machine:

```hcl
network "lab" {
  address = "192.168.1.250/24"
  udp     = "0.0.0.0:1701"
  peers   = ["192.168.1.10:1701"]   # bootbridge
  l2tp {
    session = 1                     # default 1
    cookie  = "0x0123456789abcdef"
    # counter = true                # default true
  }
}
```

Both listeners can run at once: a raw one on loopback for a local simh,
and an L2TPv3 one for everything else. Frames pass between them as between
any other peers.

## The UDP protocols

### Raw

Ethernet over UDP, with nothing added: each UDP datagram carries exactly
one raw Ethernet frame. This is the format of Johnny Billquist's HECnet
bridge, and the same format simh (`attach xq udp:…`) and QEMU
(`-netdev dgram`) use.

#### Wire format

- **No header and no checksum.** The datagram payload is the frame
  itself, from the destination MAC to the end of the payload. There is no
  version, length, sequence number or frame check sequence.
- **Frame size** is 14 to 1514 bytes. Frames sent are padded to
  Ethernet's 60-byte minimum; frames shorter than 14 bytes are dropped on
  receipt.
- **No delivery guarantees**, like real Ethernet. Frames can be lost,
  duplicated or reordered; the protocols above cope with that, as boot
  protocols always have.

### L2TPv3

Static L2TPv3 over UDP (RFC 3931) carrying Ethernet (RFC 4719), as Linux
(`ip l2tp`) and QEMU (`-netdev l2tpv3,udp=on`) speak it, without the
control connection. Each datagram is

```
00 03 00 00 | session ID (4) | cookie (0, 4 or 8) | [40 + sequence (4)] | Ethernet frame
```

Both ends must agree on the session ID, the cookie and whether the
L2-specific sublayer (`-counter`) is used; bootd and bootbridge use the
same values in both directions. A datagram with the wrong session or
cookie is dropped before anything is learned from it, and the first one
from each address is logged.

The cookie keeps out anyone who cannot see the traffic. It is sent in
clear, so it is no protection against someone who can: across untrusted
networks, carry the UDP over WireGuard or an SSH tunnel.

To connect QEMU (Linux only; macOS builds lack l2tpv3):

```
-netdev l2tpv3,id=n0,udp=on,src=0.0.0.0,srcport=1701,dst=192.168.1.10,dstport=1701,
        txsession=1,rxsession=1,cookie64=on,txcookie=0x0123456789abcdef,rxcookie=0x0123456789abcdef,counter=on
```

A Linux machine can join without bootbridge, with an `l2tpeth` interface
bridged to a NIC:

```
ip l2tp add tunnel tunnel_id 1 peer_tunnel_id 1 encap udp local 192.168.1.20 remote 192.168.1.10 udp_sport 1701 udp_dport 1701
ip l2tp add session tunnel_id 1 session_id 1 peer_session_id 1 cookie 0123456789abcdef peer_cookie 0123456789abcdef l2spec_type default
```

These two have not been tried against bootbridge yet; the format follows
the RFC and is tested against hand-built datagrams.

### Keepalives

bootd and bootbridge send their fixed peers a keepalive every 60 seconds,
so a peer that has no fixed peers of its own learns them before they have
anything to send. A keepalive is an Ethernet loopback frame (ethertype
0x9000) addressed to its sender; receivers learn the peer from it and
drop it. Raw transports send them too; to simh or QEMU they look like
frames for another machine.

### Who receives a frame

Each endpoint has a UDP address, and frames go to its peers:

- **Fixed peers** (`-peer`, or `peers` in bootd) always receive frames.
- **Learned peers:** any address that sends a frame (with the right
  cookie, for L2TPv3) becomes a peer for 180 seconds, the same timeout as the HECnet bridge's passive peers. So
  simh or QEMU can point at bootd or bootbridge without being configured
  there.
- **Unicast** frames go only to the peer whose datagrams last carried
  that MAC address as their source, as a learning switch would.
- **Broadcast, multicast and unknown destinations** go to every peer.
- **Relaying:** bootbridge also passes frames between peers, never back
  to the peer a frame came from. Unicast frames between two machines on
  the LAN stay on the LAN. bootd does not relay; it is an endpoint.

### Limits

- **Any frame is carried:** Ethernet II with any ethertype, and 802.3
  with LLC (RMP, RPL). The original HECnet bridge only forwards DEC
  ethertypes, so it cannot stand in for bootbridge, even though the
  format is the same.
- **No loop protection.** Two bridges joined twice would pass frames
  around forever. The HECnet bridge drops repeats of recently seen
  headers; bootbridge does not, since its setups are star-shaped.
- **IP fragmentation:** a full frame is about 1542 bytes as a UDP/IPv4
  datagram, so across a real network with a 1500-byte MTU it is
  fragmented. On loopback, where bootd and emulators normally talk, that
  does not matter.
- **No authentication or privacy in raw mode.** Anyone who can send UDP
  to the port can put frames on the segment and receive its broadcasts.
  That is why bootbridge listens on 127.0.0.1 by default and warns about
  any other address. Use L2TPv3 with a cookie for anything else.
- **Wired Ethernet only** for bootd's own MAC address: Wi-Fi access
  points drop frames from MAC addresses that have not associated. On
  Wi-Fi, use a `pcap` network in bootd with `mac = "interface"` instead.

The format is deliberately the lowest common denominator. That lets bootd,
bootbridge, simh, QEMU, PyDECnet and the HECnet bridge all interoperate
without any of them knowing about the others.
