# bootd configuration
#
# Hosts say which services they may use and which files they may load.
# Services say where bootd listens. Addresses that are not given are looked
# up in /etc/ethers (MAC) and DNS / /etc/hosts (IP).
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

# Link level services (rarp, rmp, nd) capture with libpcap and need root,
# or CAP_NET_RAW on Linux. interfaces defaults to all Ethernet interfaces.
service "rarp" { interfaces = ["en0"] }
service "rmp" {
  interfaces = ["all"]
  # server_name = "aiax"   # sent to clients asking for the server; default: host name
}
service "nd" {
  interfaces = ["en0"]
  # window     = 6         # 1 KB packets per acknowledgement
  # send_delay = 10        # milliseconds before each packet
}
service "tftp" {
  listen = [":69"]
  # timeout     = 2        # seconds before retransmitting
  # retries     = 5
  # max_blksize = 1468     # largest blksize option accepted
}
service "bootparam" {}
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
