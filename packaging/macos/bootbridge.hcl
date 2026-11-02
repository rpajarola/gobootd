# bootbridge configuration. See /usr/local/share/gobootd/examples/bootbridge.hcl.
#
# Set the interface, then:  sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rpajarola.bootbridge.plist
#
# If this file holds an L2TPv3 cookie, keep it readable only by root.

interface = "en0"

# Control socket for bootbridgectl. The launchd job runs as root, whose
# default is /var/run/bootbridge/bootbridge.sock (macOS has no /run); the
# daemon logs the path it listens on and bootbridgectl looks for it there.
# Anyone able to write the socket sees every forwarded frame, so keep the
# mode at 0600 unless you create a group for it.
# ctl      = "/var/run/bootbridge.sock"
# ctl_mode = "0600"

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
