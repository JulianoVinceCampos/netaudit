"""
netaudit.constants
~~~~~~~~~~~~~~~~~~
Centralised port/service knowledge base.
Kept separate so it can be extended or overridden by users.
"""

from __future__ import annotations

from typing import Dict, FrozenSet

VERSION = "2.0.0"

# ── Port → service hint ────────────────────────────────────────────────────────

PORT_HINTS: Dict[int, str] = {
    # Remote access
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    # Mail
    25:    "SMTP",
    110:   "POP3",
    143:   "IMAP",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    993:   "IMAPS",
    995:   "POP3S",
    # DNS
    53:    "DNS",
    # Web
    80:    "HTTP",
    443:   "HTTPS",
    8000:  "HTTP-Dev",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP/Jupyter",
    # Windows
    135:   "MS-RPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    445:   "SMB",
    3389:  "RDP",
    5985:  "WinRM-HTTP",
    5986:  "WinRM-HTTPS",
    # Databases
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL/MariaDB",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    27019: "MongoDB-Config",
    9042:  "Cassandra",
    7000:  "Cassandra-Cluster",
    # Search / analytics
    9200:  "Elasticsearch-HTTP",
    9300:  "Elasticsearch-Cluster",
    5601:  "Kibana",
    # Containers / orchestration
    2375:  "Docker-API (unencrypted!)",
    2376:  "Docker-API-TLS",
    4243:  "Docker-Alt",
    6443:  "Kubernetes-API",
    10250: "Kubelet-API",
    10255: "Kubelet-readonly",
    2379:  "etcd-client",
    2380:  "etcd-peer",
    # Message queues
    5672:  "AMQP (RabbitMQ)",
    15672: "RabbitMQ-Mgmt",
    9092:  "Kafka",
    4369:  "Erlang-Port-Mapper",
    # Remote desktop / VNC
    5900:  "VNC",
    5901:  "VNC-1",
    # Monitoring
    9090:  "Prometheus",
    9093:  "Alertmanager",
    3000:  "Grafana/Dev-HTTP",
    # LDAP
    389:   "LDAP",
    636:   "LDAPS",
    # Other
    111:   "RPCbind",
    2049:  "NFS",
    6000:  "X11",
    11211: "Memcached",
    50000: "SAP",
    50070: "Hadoop-HDFS",
    8161:  "ActiveMQ-Web",
    61616: "ActiveMQ",
}

# ── Risk classification by port ────────────────────────────────────────────────

CRITICAL_PORTS: FrozenSet[int] = frozenset({
    23,     # Telnet — plaintext
    2375,   # Docker API (unencrypted) — full host RCE
    4243,   # Docker alt
    2379,   # etcd (often unauthenticated, holds cluster secrets)
    10255,  # Kubelet read-only (unauthenticated)
})

HIGH_RISK_PORTS: FrozenSet[int] = frozenset({
    22,     # SSH — expose to internet only if required
    3389,   # RDP — common ransomware vector
    445,    # SMB — EternalBlue / ransomware
    5900,   # VNC — often weak auth
    6379,   # Redis — often no auth
    9200,   # Elasticsearch — often no auth
    27017,  # MongoDB — often no auth
    11211,  # Memcached — no auth + amplification DDoS
    6000,   # X11 — remote display hijack
    50070,  # Hadoop — often no auth
})

MEDIUM_RISK_PORTS: FrozenSet[int] = frozenset({
    21,     # FTP — plaintext credentials
    25,     # SMTP — open relay check
    110,    # POP3 — plaintext
    143,    # IMAP — plaintext
    389,    # LDAP — cleartext (use 636/LDAPS)
    1433,   # MSSQL
    1521,   # Oracle
    3306,   # MySQL
    5432,   # PostgreSQL
    5672,   # AMQP
    8080,   # HTTP-Alt — proxy/admin interfaces
    9090,   # Prometheus — metrics exposure
    9092,   # Kafka — no auth by default
    15672,  # RabbitMQ management
})

# ── Protocol classification ────────────────────────────────────────────────────

TLS_PORTS: FrozenSet[int] = frozenset({
    443, 465, 636, 993, 995, 2376, 5986, 6443, 8443,
})

HTTP_PORTS: FrozenSet[int] = frozenset({
    80, 8000, 8080, 8888, 3000, 5601, 9090, 15672, 8161,
})

# Ports that expose management / admin interfaces
MGMT_PORTS: FrozenSet[int] = frozenset({
    15672, 8161, 5601, 9090, 3000, 10250, 10255, 2379, 8443,
})

# ── Default port preset ────────────────────────────────────────────────────────

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,389,443,445,"
    "465,587,636,993,995,1433,1521,2049,2375,2376,2379,2380,"
    "3000,3306,3389,4243,4369,5432,5601,5672,5900,5901,"
    "5985,5986,6000,6379,6443,7000,8000,8080,8161,8443,8888,"
    "9042,9090,9092,9093,9200,9300,10250,10255,11211,"
    "15672,27017,27018,27019,50000,50070,61616"
)
