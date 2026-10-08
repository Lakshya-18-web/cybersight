"""Static reference data for the port and service tools.

A curated subset of the IANA service-name and port-number registry, with short descriptions written for this project.
It is not exhaustive. A port that is not listed is reported as "not in the curated table", never guessed.
It holds no dataset knowledge (no addresses, no attack names, no labels). It is the same for every alert.
"""

SOURCE_NOTE = "curated subset of the IANA service-name and port-number registry; not exhaustive"

# name, aliases, [(port, protocol)], description
_ROWS = [
    ("ftp-data", [], [(20, "tcp")], "File Transfer Protocol, data channel."),
    ("ftp", [], [(21, "tcp")], "File Transfer Protocol, control channel. Clear-text logins unless wrapped in TLS."),
    ("ssh", ["sftp", "scp"], [(22, "tcp")], "Secure Shell: encrypted remote login and file transfer."),
    ("telnet", [], [(23, "tcp")], "Telnet: clear-text remote terminal."),
    ("smtp", [], [(25, "tcp")], "Simple Mail Transfer Protocol: mail relay between servers."),
    ("dns", ["domain"], [(53, "tcp"), (53, "udp")], "Domain Name System: name resolution. UDP for most queries, TCP for large answers and zone transfers."),
    ("dhcp", ["bootps", "bootpc"], [(67, "udp"), (68, "udp")], "Dynamic Host Configuration Protocol: address assignment on a local network."),
    ("tftp", [], [(69, "udp")], "Trivial File Transfer Protocol: unauthenticated file transfer."),
    ("http", ["www"], [(80, "tcp")], "Hypertext Transfer Protocol: unencrypted web traffic."),
    ("kerberos", ["kerberos-sec"], [(88, "tcp"), (88, "udp")], "Kerberos authentication."),
    ("pop3", [], [(110, "tcp")], "Post Office Protocol v3: mail retrieval, clear text."),
    ("rpc", ["msrpc", "epmap"], [(135, "tcp"), (135, "udp")], "Microsoft RPC endpoint mapper."),
    ("ntp", [], [(123, "udp")], "Network Time Protocol."),
    ("netbios-ns", [], [(137, "udp")], "NetBIOS name service."),
    ("netbios-dgm", [], [(138, "udp")], "NetBIOS datagram service."),
    ("netbios-ssn", [], [(139, "tcp")], "NetBIOS session service (older Windows file sharing)."),
    ("imap", [], [(143, "tcp")], "Internet Message Access Protocol: mail access, clear text."),
    ("snmp", [], [(161, "udp")], "Simple Network Management Protocol."),
    ("ldap", [], [(389, "tcp"), (389, "udp")], "Lightweight Directory Access Protocol: directory queries."),
    ("https", ["http-tls", "ssl"], [(443, "tcp")], "HTTP over TLS: encrypted web traffic."),
    ("microsoft-ds", ["smb", "cifs"], [(445, "tcp")], "Server Message Block over TCP: Windows file and printer sharing."),
    ("syslog", [], [(514, "udp")], "Syslog message transport."),
    ("ldaps", [], [(636, "tcp")], "LDAP over TLS."),
    ("imaps", [], [(993, "tcp")], "IMAP over TLS."),
    ("pop3s", [], [(995, "tcp")], "POP3 over TLS."),
    ("ms-sql-s", ["mssql"], [(1433, "tcp")], "Microsoft SQL Server database."),
    ("mysql", [], [(3306, "tcp")], "MySQL database."),
    ("ms-wbt-server", ["rdp"], [(3389, "tcp")], "Remote Desktop Protocol: Windows remote desktop."),
    ("postgresql", ["postgres"], [(5432, "tcp")], "PostgreSQL database."),
    ("vnc", [], [(5900, "tcp")], "Virtual Network Computing: remote desktop, port 5900 and up."),
    ("redis", [], [(6379, "tcp")], "Redis key-value store."),
    ("http-alt", ["http-proxy"], [(8080, "tcp")], "Alternative HTTP port, often a web application server or proxy."),
    ("https-alt", [], [(8443, "tcp")], "Alternative HTTPS port."),
    ("mongodb", [], [(27017, "tcp")], "MongoDB database."),
]

SERVICES = {}
PORTS = {}
ALIASES = {}
for _name, _aliases, _ports, _desc in _ROWS:
    SERVICES[_name] = {"name": _name, "aliases": list(_aliases), "ports": [{"port": p, "protocol": t} for p, t in _ports], "description": _desc}
    for _alias in _aliases:
        ALIASES[_alias] = _name
    for _port, _proto in _ports:
        PORTS.setdefault((_port, _proto), []).append(_name)

PROTOCOL_NUMBERS = {1: "icmp", 6: "tcp", 17: "udp"}

# IANA port ranges
WELL_KNOWN_MAX = 1023
REGISTERED_MAX = 49151
