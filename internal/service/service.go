// Package service lists the boot protocol services bootd knows about.
package service

import "slices"

// Names of all services that may appear in a configuration. A name being
// known does not mean it is implemented; see daemon.Register.
const (
	RARP      = "rarp"
	RMP       = "rmp"
	MOP       = "mop"
	ND        = "nd"
	RPL       = "rpl"
	TFTP      = "tftp"
	Bootparam = "bootparam"
	NFS       = "nfs"
	DHCP      = "dhcp"
	SMB       = "smb"
	RBCS      = "rbcs"
)

// All lists every known service name in a stable order.
var All = []string{RARP, RMP, MOP, ND, RPL, TFTP, Bootparam, NFS, DHCP, SMB, RBCS}

// Known reports whether name is a service name bootd understands.
func Known(name string) bool { return slices.Contains(All, name) }
