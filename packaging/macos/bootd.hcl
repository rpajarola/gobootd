# bootd configuration. See /usr/local/share/gobootd/examples/bootd.hcl for
# every option, and check changes with:  sudo bootd check -c /usr/local/etc/bootd.hcl
#
# This file can hold an L2TPv3 cookie, so it is readable only by root and
# the nobody group, which bootd runs as.

# Base directory for relative paths: boot files, exports.
root = "/usr/local/var/bootd"

# bootd has its own Ethernet and IP address and reaches its clients over
# UDP: through bootbridge (see /usr/local/etc/bootbridge.hcl), or straight from simh
# or QEMU.
network "lab" {
  address = "192.168.1.250/24"
  udp     = "127.0.0.1:4712"
  peers   = ["127.0.0.1:4711"]   # bootbridge's raw listener
}

# service "rarp" {}
# service "tftp" {}
# service "bootparam" {}
# service "nfs" {}

# host "kali" {
#   mac      = "08:00:20:01:02:03"
#   ip       = "192.168.1.5"
#   services = ["rarp", "tftp", "bootparam", "nfs"]
#   file "sparc/boot.net" { name = "*" }
#   export "root" { path = "/usr/local/var/bootd/kali/root" }
# }
