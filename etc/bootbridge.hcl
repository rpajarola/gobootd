# bootbridge configuration
#
#   sudo bootbridge -c /etc/bootbridge.hcl
#
# Flags given on the command line override the values here. Only the
# listeners declared below are opened. If this file holds an L2TPv3
# cookie, keep it readable by root only (chmod 600).

interface = "en0"
# stats   = "30s"     # interval for interface statistics; "0" to disable
# verbose = false     # log every forwarding error
# print   = false     # print packets as they pass through the bridge
# dump    = false     # print them with a hex dump, like tcpdump -X
# print_interface = "all"   # udp, lan, all, or an interface name

# Raw Ethernet frames over UDP (the HECnet bridge format), for bootd, simh
# and QEMU on this machine. There is no authentication, so keep it on
# loopback.
raw {
  listen = "127.0.0.1:4711"     # the default
  # peers = ["127.0.0.1:4712"]  # always receive frames; others are learned
}

# Static L2TPv3, for bootd, QEMU, Linux or emulators on other machines.
# Peers that know the session and cookie are learned when they send.
# l2tp {
#   listen  = "0.0.0.0:1701"
#   cookie  = "0x0123456789abcdef"   # 8 or 16 hex digits
#   # session = 1
#   # counter = true                 # L2-specific sublayer
#   # peers   = ["192.168.1.20:1701"]
# }
