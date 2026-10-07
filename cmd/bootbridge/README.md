# bootbridge

bootbridge connects a network interface to bootd, simh or QEMU over UDP.
It is the only part of gobootd that needs capture privileges (root,
`CAP_NET_RAW` on Linux, or access to `/dev/bpf*` on BSD and macOS); bootd
itself runs unprivileged.

```
sudo bootbridge -i en0 -listen 127.0.0.1:4711 -peer 127.0.0.1:4712
```

| Flag | Default | Meaning |
|---|---|---|
| `-i` | (required) | network interface to bridge |
| `-listen` | `127.0.0.1:4711` | UDP address to exchange frames on |
| `-peer` | none | UDP peer that always receives frames (repeatable) |
| `-stats` | `30s` | interval to log interface statistics (0 to disable) |
| `-v` | off | log every forwarding error |

bootd then uses a network block such as:

```hcl
network "lab" {
  address = "192.168.1.250/24"
  udp     = "127.0.0.1:4712"
  peers   = ["127.0.0.1:4711"]
}
```

## The UDP protocol

Ethernet over UDP, with nothing added: each UDP datagram carries exactly
one raw Ethernet frame. This is the format of Johnny Billquist's HECnet
bridge, and the same format simh (`attach xq udp:…`) and QEMU
(`-netdev dgram`) use.

### Wire format

- **No header and no checksum.** The datagram payload is the frame
  itself, from the destination MAC to the end of the payload. There is no
  version, length, sequence number or frame check sequence.
- **Frame size** is 14 to 1514 bytes. Frames sent are padded to
  Ethernet's 60-byte minimum; frames shorter than 14 bytes are dropped on
  receipt.
- **No delivery guarantees**, like real Ethernet. Frames can be lost,
  duplicated or reordered; the protocols above cope with that, as boot
  protocols always have.

### Who receives a frame

Each endpoint has a UDP address, and frames go to its peers:

- **Fixed peers** (`-peer`, or `peers` in bootd) always receive frames.
- **Learned peers:** any address that sends a frame becomes a peer for
  180 seconds, the same timeout as the HECnet bridge's passive peers. So
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
- **No authentication or privacy.** Anyone who can send UDP to the port
  can put frames on the segment and receive its broadcasts. That is why
  bootbridge listens on 127.0.0.1 by default and warns about any other
  address.
- **Wired Ethernet only** for bootd's own MAC address: Wi-Fi access
  points drop frames from MAC addresses that have not associated. On
  Wi-Fi, use a `pcap` network in bootd with `mac = "interface"` instead.

The format is deliberately the lowest common denominator. That lets bootd,
bootbridge, simh, QEMU, PyDECnet and the HECnet bridge all interoperate
without any of them knowing about the others.
