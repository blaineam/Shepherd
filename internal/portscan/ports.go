// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

// DefaultPorts is the built-in list a scan checks when no configuration
// overrides it: the ports that actually matter for home-network exposure
// awareness, not an exhaustive sweep. See docs/PORTSCAN.md for the reasoning
// behind the list.
var DefaultPorts = []int{
	21,   // FTP
	22,   // SSH
	23,   // Telnet
	25,   // SMTP
	53,   // DNS
	80,   // HTTP
	110,  // POP3
	111,  // rpcbind
	135,  // Windows RPC endpoint mapper
	139,  // NetBIOS session service
	143,  // IMAP
	389,  // LDAP
	443,  // HTTPS
	445,  // SMB
	465,  // SMTPS
	515,  // LPD printing
	548,  // AFP (Apple file sharing)
	554,  // RTSP (cameras, media servers)
	587,  // SMTP submission
	631,  // IPP printing
	873,  // rsync
	993,  // IMAPS
	995,  // POP3S
	1433, // Microsoft SQL Server
	1723, // PPTP VPN
	1883, // MQTT (smart-home brokers)
	2049, // NFS
	2375, // Docker API, unencrypted
	2376, // Docker API, TLS
	3000, // common admin/dev web UI
	3306, // MySQL
	3389, // RDP
	5000, // common NAS/admin web UI
	5432, // PostgreSQL
	5900, // VNC
	6379, // Redis
	8000, // common web admin
	8080, // common web admin or proxy
	8443, // common HTTPS admin
	8888, // common web admin
	9100, // raw/JetDirect printing
}

// RiskyPorts are ports worth flagging whenever they are found open at all,
// not only when newly opened: well-known high-value targets on a home
// network, or protocols with a history of weak or absent authentication.
// Every key here also appears in DefaultPorts (checked by TestRiskyPortsAreScanned).
var RiskyPorts = map[int]string{
	21:   "FTP: often unencrypted, with weak or default credentials",
	23:   "Telnet: unencrypted remote login, a classic IoT-botnet target",
	111:  "rpcbind: legacy RPC portmapper, frequently exploited",
	139:  "NetBIOS: legacy Windows file sharing",
	445:  "SMB: Windows file sharing, a common ransomware and worm target",
	1723: "PPTP: a broken, deprecated VPN protocol",
	2375: "Docker API without TLS: can grant full control of the host",
	3389: "RDP: Windows Remote Desktop, a frequent target for credential attacks",
	5900: "VNC: remote screen control, often reachable with no authentication at all",
}

// IsRisky reports whether port is on the risky list, and why.
func IsRisky(port int) (reason string, risky bool) {
	reason, risky = RiskyPorts[port]
	return reason, risky
}
