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

service "rarp" { interfaces = ["en0"] }
service "rmp" { interfaces = ["all"] }
service "nd" { interfaces = ["en0"] }
service "tftp" { listen = [":69"] }
service "bootparam" {}
service "nfs" {}

# HP 9000/300: RMP picks the class by the machine type the boot ROM sends,
# so new machines boot without a host entry.
class "hp300" {
  match    = { rmp_machtype = "HP9000/425" }
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

# Sun-2: RARP, then the PROM reads the boot program over ND.
host "sun2" {
  services = ["rarp", "nd", "bootparam", "nfs"]

  disk "boot" {
    path = "files/sun2/netbsd-netboot"
    mode = "bootfile"
  }
  export "root" { path = "/export/hosts/sun2/root" }
}

# NCD X terminal: TFTP only.
host "kismet" {
  services = ["tftp"]
  file "files/ncd/xncd19-ncdware-3.2.1" { name = "*" }
}
