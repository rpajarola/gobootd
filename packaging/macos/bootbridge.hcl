# bootbridge configuration. See /usr/local/share/gobootd/examples/bootbridge.hcl.
#
# Set the interface, then:  sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rpajarola.bootbridge.plist
#
# If this file holds an L2TPv3 cookie, keep it readable only by root.

interface = "en0"

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
