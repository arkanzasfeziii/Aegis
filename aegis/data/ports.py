"""Port lists, service mappings, and default credentials."""

from __future__ import annotations

from typing import Dict, List, Tuple

TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587,
    631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2181, 3306, 3389, 3690,
    4444, 4848, 5432, 5900, 5985, 5986, 6379, 6443, 7001, 7077, 8080, 8443,
    8888, 9042, 9200, 9300, 9999, 10250, 11211, 27017, 27018, 50000,
]

PORT_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS5", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4444: "Metasploit", 4848: "GlassFish",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic", 7077: "Spark",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter", 9042: "Cassandra",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster", 9999: "Icecast",
    10250: "kubelet", 11211: "Memcached", 27017: "MongoDB", 50000: "DB2",
}

DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("root", "root"), ("root", "password"), ("root", ""),
    ("user", "user"), ("guest", "guest"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "1234"), ("test", "test"),
    ("oracle", "oracle"), ("sa", ""), ("postgres", "postgres"),
    ("mysql", "mysql"), ("redis", ""), ("mongo", ""),
    ("ftp", "ftp"), ("anonymous", ""),
]

SSH_USERNAMES: List[str] = [
    "root", "admin", "ubuntu", "ec2-user", "centos", "kali", "pi", "vagrant",
    "oracle", "postgres", "mysql", "jenkins", "gitlab", "git", "deploy", "backup",
]

SSH_PASSWORDS: List[str] = [
    "password", "123456", "root", "admin", "toor", "pass", "changeme", "letmein",
    "raspberry", "vagrant", "ubuntu", "1234", "admin123", "Password1",
]

SNMP_COMMUNITY_STRINGS: List[str] = [
    "public", "private", "community", "manager", "admin", "monitor",
    "read", "write", "snmpd", "cisco", "SNMP", "default",
]

SNMP_OIDS: Dict[str, str] = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "ifTable": "1.3.6.1.2.1.2.2.1.2",
    "hrSWInstalled": "1.3.6.1.2.1.25.6.3.1.2",
}

WORDLIST_SUBDOMAINS: List[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote", "intranet",
    "internal", "dev", "staging", "test", "api", "admin", "portal", "webmail",
    "git", "gitlab", "jenkins", "jira", "confluence", "uat", "prod", "beta",
    "cdn", "static", "assets", "img", "images", "files", "docs", "wiki",
    "dashboard", "monitor", "log", "backup", "db", "database", "mysql", "redis",
]

IOT_DEFAULT_CREDS: Dict[str, List[Tuple[str, str]]] = {
    "HTTP": [("admin", "admin"), ("admin", "password"), ("admin", "1234"),
             ("admin", ""), ("root", "root"), ("user", "user")],
    "MQTT": [("", ""), ("admin", "admin"), ("mqtt", "mqtt"), ("guest", "guest")],
    "Telnet": [("admin", "admin"), ("root", "root"), ("root", ""), ("admin", ""),
               ("user", "user"), ("guest", "guest")],
    "Modbus": [],
    "FTP": [("anonymous", ""), ("admin", "admin"), ("admin", ""), ("ftp", "ftp")],
}

WEB_ADMIN_PATHS: List[str] = [
    "/", "/admin", "/admin.php", "/admin/", "/login", "/login.php",
    "/manager/html", "/phpmyadmin", "/wp-admin", "/xmlrpc.php",
    "/console", "/dashboard", "/setup", "/config",
    "/cgi-bin/luci", "/webman/index.cgi", "/ui/",
]

DNS_QUERY_TYPES: List[str] = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]

C2_DNS_CHUNK_SIZE: int = 20
