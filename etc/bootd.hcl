# bootd configuration
#
# Networks say how bootd reaches its clients, services which protocols it
# offers, and hosts which services they may use and which files they may
# load. Host addresses that are not given are looked up in /etc/ethers (MAC)
# and DNS / /etc/hosts (IP).
#
# Check a configuration with:   bootd check -c bootd.hcl
# Trace a single request with:  bootd explain -c bootd.hcl kali tftp C0A80105.SUN4C

# Base directory for relative paths.
root = "/srv/netboot"

log {
  level = "info"
  # file   = "/var/log/bootd.log"
  # format = "json"
  services = { rmp = "debug" }
}

resolve {
  ethers = "/etc/ethers"
  dns    = true
}

# bootd has its own Ethernet and IP address on each network and runs its
# own IP stack there, so it needs no privileges and does not use the host's
# addresses. Frames travel over UDP, one frame per datagram (the HECnet
# bridge format), to and from:
#   - bootbridge, which connects a real interface:
#       sudo bootbridge -i en0 -listen 127.0.0.1:4711 -peer 127.0.0.1:4712
#   - simh:  attach xq udp:4713:127.0.0.1:4712
#   - QEMU:  -netdev dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port=4713,
#              remote.type=inet,remote.host=127.0.0.1,remote.port=4712
# Peers that send to bootd are learned, so several emulators can share it.
network "lab" {
  address = "192.168.1.250/24"
  udp     = "127.0.0.1:4712"
  peers   = ["127.0.0.1:4711"]   # bootbridge
  # mac   = "02:00:00:00:00:01"  # default: derived from the network name
}
# A network can also capture directly with libpcap, which needs root:
# network "wired" {
#   address = "192.168.2.250/24"
#   pcap    = "en0"
#   mac     = "interface"        # use the interface's own address (needed on Wi-Fi)
# }

# Services are offered on every network unless networks = [...] says
# otherwise.
service "rarp" {}
service "rmp" {
  # server_name = "aiax"   # sent to clients asking for the server; default: host name
}
service "nd" {
  # window     = 6         # 1 KB packets per acknowledgement
  # send_delay = 10        # milliseconds before each packet
}
service "tftp" {
  # port        = 69
  # timeout     = 2        # seconds before retransmitting
  # retries     = 5
  # max_blksize = 1468     # largest blksize option accepted
}
service "bootparam" {
  # server_name = "aiax"         # announced as the NFS server; default: host name
  # domain      = ""             # NIS domain
  # router      = "192.168.1.1"  # default: bootd's address on the network
}
service "nfs" {}

# HP 9000/300 and /400: RMP picks the class by the machine type the boot
# ROM sends (an HP 425t sends "HPS300"), so new machines boot without a host
# entry. The boot ROM lists the files by their names.
class "hp300" {
  match    = { rmp_machtype = "HPS300" }
  services = ["rmp", "rarp", "bootparam", "nfs"]

  file "files/hp300/hp300-netbsd-1.5.2-uboot" {
    name    = "netbsd-1.5.2"
    aliases = ["netbsd-1.5.2-uboot"]
  }
  file "files/hp300/hp300-netbsd-1.5.2-inst" { name = "netbsd-1.5.2-inst" }
  file "files/hp300/hp300-openbsd-3.0" { name = "openbsd-3.0" }
}

host "nesta" {
  class = "hp300"
  # mac = "08:00:09:12:34:56"   # otherwise from /etc/ethers

  export "root" { path = "/export/hosts/nesta/root" }
  export "swap" {
    path     = "/export/hosts/nesta/swap"
    writable = true
  }
}

# SPARCstation: RARP for the address, TFTP for the boot program (which asks
# for its IP address in hex, hence the wildcard), bootparam and NFS for root.
host "kali" {
  services = ["rarp", "tftp", "bootparam", "nfs"]

  file "files/sparc/sparc-solaris-2.5.1-sun4c" { name = "*" }
  file "files/sparc/sparc-openbsd-2.8" { name = "openbsd-2.8" }

  export "root" {
    path   = "/export/hosts/kali/root"
    server = "aiax"
  }
  export "swap" {
    path     = "/export/hosts/kali/swap"
    server   = "aiax"
    writable = true
  }
}

# Sun-2: the PROM reads blocks 0-15 of ND public unit 0 (ndp0) without
# knowing its IP address; ND identifies it by MAC and tells it. A bootfile
# disk serves the first-stage program in blocks 1-15 and boot2 from block 16
# on, like NetBSD's ndbootd. The second stage then uses RARP, bootparam and
# NFS.
host "sun2" {
  services = ["rarp", "nd", "bootparam", "nfs"]

  disk "boot" {
    path  = "files/sun2/bootyy"
    boot2 = "files/sun2/netboot"
    mode  = "bootfile"
  }
  export "root" { path = "/export/hosts/sun2/root" }
}

# NCD X terminal: TFTP only.
host "kismet" {
  services = ["tftp"]
  file "files/ncd/xncd19-ncdware-3.2.1" { name = "*" }
}
