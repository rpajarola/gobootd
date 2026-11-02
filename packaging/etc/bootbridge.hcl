# bootbridge configuration. See /usr/share/doc/gobootd/examples/bootbridge.hcl.
#
# Set the interface, then:  sudo systemctl enable --now bootbridge
#
# If this file holds an L2TPv3 cookie, it must stay readable only by root
# and the bootd group.

interface = "eth0"

# Control socket for bootbridgectl. The systemd service gives the bootd
# user /run/bootbridge; the socket is group-writable, so only members of
# the bootd group may query the bridge and watch the frames it forwards.
# ctl      = "/run/bootbridge/bootbridge.sock"
# ctl_mode = "0660"

# Raw frames for bootd, simh and QEMU on this machine.
raw {
  listen = "127.0.0.1:4711"
  peers  = ["127.0.0.1:4712"]   # bootd
}

# L2TPv3 for machines elsewhere.
# l2tp {
#   listen = "0.0.0.0:1701"
#   cookie = "0x0123456789abcdef"
# }
