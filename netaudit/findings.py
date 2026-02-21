"""
netaudit.findings
~~~~~~~~~~~~~~~~~
Rule-based findings engine.

Each rule inspects a ScanReport and appends Finding objects with
structured risk level, detail, and actionable recommendations.

Design: pure functions — no I/O, no side effects, fully testable.
"""

from __future__ import annotations

from typing import List

from .models import Finding, RiskLevel, ScanReport, ScanStatus
from .constants import (
    CRITICAL_PORTS, HIGH_RISK_PORTS, MEDIUM_RISK_PORTS,
    PORT_HINTS, TLS_PORTS,
)


def analyse(report: ScanReport) -> List[Finding]:
    """
    Run all analysis rules against *report*.
    Returns a list of Finding objects, sorted by risk (critical first).
    """
    findings: List[Finding] = []
    open_ports = report.open_ports()
    open_port_numbers = {r.port for r in open_ports}

    for rule in _RULES:
        findings.extend(rule(open_port_numbers, open_ports, report))

    # Deduplicate (same port + title)
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.port, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    _order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 4,
    }
    unique.sort(key=lambda f: (_order[f.risk], f.port))
    return unique


# ── Rule helpers ───────────────────────────────────────────────────────────────

def _f(port, risk, title, detail, recommendation, refs=None) -> Finding:
    return Finding(
        port=port,
        risk=risk,
        title=title,
        detail=detail,
        recommendation=recommendation,
        references=refs or [],
    )


# ── Rules ─────────────────────────────────────────────────────────────────────

def _rule_critical_ports(open_set, open_results, report) -> List[Finding]:
    findings = []
    specs = {
        23: (
            "Telnet Service Exposed",
            "Telnet transmits all data — including credentials — in plaintext. "
            "Any network observer can capture sessions trivially.",
            "Disable Telnet immediately. Replace with SSH (port 22) with key-based "
            "authentication. If legacy devices require Telnet, isolate them on a "
            "dedicated VLAN with strict access controls.",
            ["https://cwe.mitre.org/data/definitions/319.html",
             "https://attack.mitre.org/techniques/T1040/"],
        ),
        2375: (
            "Docker API Exposed Without TLS",
            "The Docker daemon API (port 2375) is accessible without authentication "
            "or encryption. This is equivalent to unauthenticated root on the host: "
            "an attacker can run privileged containers, read all files, pivot, and "
            "establish persistence trivially.",
            "Immediately bind Docker to a Unix socket (default). If remote access "
            "is required, enable TLS client certificates on port 2376. Apply firewall "
            "rules to whitelist only authorised management IPs.",
            ["https://docs.docker.com/engine/security/protect-access/",
             "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker+api"],
        ),
        4243: (
            "Docker Daemon Alternative Port Exposed",
            "An alternative Docker daemon port is open and likely unauthenticated. "
            "Carries the same risk profile as port 2375.",
            "See remediation for port 2375. Ensure Docker is not listening on any "
            "TCP port without mutual TLS authentication.",
            ["https://docs.docker.com/engine/security/protect-access/"],
        ),
        2379: (
            "etcd Client Port Exposed",
            "The etcd key-value store is accessible. etcd stores Kubernetes cluster "
            "secrets, certificates, and configuration. Unauthenticated access allows "
            "full cluster takeover including extraction of all secrets.",
            "Bind etcd to localhost or a private interface only. Enable client "
            "certificate authentication. Restrict access via firewall to only the "
            "Kubernetes API server IPs.",
            ["https://etcd.io/docs/v3.5/op-guide/security/",
             "https://attack.mitre.org/techniques/T1552/007/"],
        ),
        10255: (
            "Kubelet Read-Only API Exposed (Unauthenticated)",
            "The Kubernetes kubelet read-only API is open. It allows unauthenticated "
            "listing of pods, environment variables (which may contain secrets), and "
            "container metadata.",
            "Disable the read-only port: set --read-only-port=0 in kubelet config. "
            "Use the authenticated port (10250) with RBAC for any required access.",
            ["https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
             "https://attack.mitre.org/techniques/T1613/"],
        ),
    }
    for port in open_set & CRITICAL_PORTS:
        if port in specs:
            title, detail, rec, refs = specs[port]
            findings.append(_f(port, RiskLevel.CRITICAL, title, detail, rec, refs))
    return findings


def _rule_high_risk_ports(open_set, open_results, report) -> List[Finding]:
    findings = []
    specs = {
        3389: (
            "RDP Exposed to Network",
            "Remote Desktop Protocol (3389) is accessible. RDP is a top ransomware "
            "and brute-force target. Credential-stuffing and BlueKeep-class vulns "
            "make internet-exposed RDP extremely high risk.",
            "If RDP is required: restrict by IP via firewall, enforce Network Level "
            "Authentication (NLA), mandate MFA (e.g. Duo), disable for all accounts "
            "not requiring it, enable account lockout, and monitor with failed-logon "
            "alerting.",
            ["https://attack.mitre.org/techniques/T1021/001/",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
        ),
        445: (
            "SMB Service Exposed",
            "Server Message Block (445) is accessible. SMB is the vector for "
            "EternalBlue (MS17-010), WannaCry, NotPetya, and lateral movement. "
            "Exposure outside a controlled LAN is extremely dangerous.",
            "Block SMB at the perimeter firewall (no inbound 445 from internet). "
            "Ensure MS17-010 and all SMB patches are applied. Disable SMBv1 "
            "(Set-SmbServerConfiguration -EnableSMB1Protocol $false). Use SMB "
            "signing to prevent relay attacks.",
            ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
             "https://attack.mitre.org/techniques/T1021/002/"],
        ),
        22: (
            "SSH Exposed to Network",
            "SSH (22) is accessible. While SSH is generally secure, broad exposure "
            "invites brute-force, credential-stuffing, and exploitation of software "
            "vulnerabilities in the SSH daemon.",
            "Restrict SSH access by IP via firewall or security group. Disable "
            "password authentication (PasswordAuthentication no). Disable root login "
            "(PermitRootLogin no). Use fail2ban or equivalent. Consider non-standard "
            "port or port-knocking if stealth is required.",
            ["https://www.ssh.com/academy/ssh/security",
             "https://attack.mitre.org/techniques/T1021/004/"],
        ),
        5900: (
            "VNC Service Exposed",
            "VNC (5900) provides remote graphical desktop access and is often "
            "configured with weak or no authentication. Widely exploited in "
            "mass-scanning campaigns.",
            "Restrict VNC by firewall to authorised IPs only. Enforce strong "
            "VNC password (8+ chars). Prefer SSH tunnel over VNC: "
            "ssh -L 5900:localhost:5900 user@host. Disable if not actively used.",
            ["https://attack.mitre.org/techniques/T1021/005/"],
        ),
        6379: (
            "Redis Exposed — Likely Unauthenticated",
            "Redis (6379) is accessible. Redis defaults to no authentication and "
            "no encryption. Exposed Redis instances are actively mass-exploited for "
            "data exfiltration, crypto-mining, and as a foothold for deeper access.",
            "Bind Redis to 127.0.0.1 only (bind 127.0.0.1 in redis.conf). Enable "
            "AUTH with a strong password (requirepass). Enable TLS (Redis 6+). "
            "Firewall port 6379 from all external access.",
            ["https://redis.io/docs/management/security/",
             "https://attack.mitre.org/techniques/T1190/"],
        ),
        9200: (
            "Elasticsearch HTTP API Exposed",
            "Elasticsearch (9200) is accessible. Versions prior to 8.0 have no "
            "authentication by default. Mass data breaches have repeatedly resulted "
            "from publicly exposed Elasticsearch instances.",
            "Enable X-Pack security (xpack.security.enabled: true). Require TLS "
            "(xpack.security.http.ssl.enabled: true). Bind to localhost or internal "
            "interface. Apply network-level firewall rules restricting to app servers.",
            ["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
             "https://attack.mitre.org/techniques/T1190/"],
        ),
        27017: (
            "MongoDB Exposed — Likely Unauthenticated",
            "MongoDB (27017) is accessible. Older MongoDB deployments default to "
            "no authentication. This is one of the most commonly breached database "
            "exposures found in bug bounty and incident response.",
            "Enable MongoDB authentication (security.authorization: enabled). "
            "Bind to localhost (net.bindIp: 127.0.0.1). Enable TLS. "
            "Create least-privilege users per application.",
            ["https://www.mongodb.com/docs/manual/security/",
             "https://attack.mitre.org/techniques/T1190/"],
        ),
        11211: (
            "Memcached Exposed — Unauthenticated + DDoS Risk",
            "Memcached (11211) is accessible. Memcached has no authentication "
            "by default and is a well-known DDoS amplification vector "
            "(amplification factor up to 51,000x).",
            "Bind Memcached to localhost (--listen 127.0.0.1). Block port 11211 "
            "at the firewall. Enable SASL authentication if remote access is required.",
            ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115",
             "https://www.cloudflare.com/learning/ddos/memcached-ddos-attack/"],
        ),
    }
    for port in open_set & HIGH_RISK_PORTS:
        if port in specs:
            title, detail, rec, refs = specs[port]
            findings.append(_f(port, RiskLevel.HIGH, title, detail, rec, refs))
    return findings


def _rule_tls_issues(open_set, open_results, report) -> List[Finding]:
    findings = []
    for r in open_results:
        if r.cert is None:
            continue
        c = r.cert
        if c.expired:
            findings.append(_f(
                r.port, RiskLevel.HIGH,
                "TLS Certificate Expired",
                f"The certificate on port {r.port} has expired. Expired certificates "
                f"cause browser warnings and may indicate certificate lifecycle mismanagement.",
                "Renew the certificate immediately. Consider automated renewal with "
                "Certbot/ACME or your CA's auto-renewal feature. Implement monitoring "
                "with alerting 30/15/7 days before expiry.",
                ["https://letsencrypt.org/docs/faq/"],
            ))
        elif 0 < c.days_remaining <= 14:
            findings.append(_f(
                r.port, RiskLevel.HIGH,
                f"TLS Certificate Expires in {c.days_remaining} Days",
                f"Certificate expiry is imminent ({c.days_remaining} days). "
                f"Services will present warnings to users very soon.",
                "Renew immediately. Verify automated renewal pipeline is working.",
            ))
        elif 14 < c.days_remaining <= 30:
            findings.append(_f(
                r.port, RiskLevel.MEDIUM,
                f"TLS Certificate Expires in {c.days_remaining} Days",
                f"Certificate expiry is approaching ({c.days_remaining} days). "
                f"This is within the recommended renewal window.",
                "Initiate certificate renewal. Validate ACME/auto-renewal is configured.",
            ))
        if c.self_signed:
            findings.append(_f(
                r.port, RiskLevel.MEDIUM,
                "Self-Signed TLS Certificate",
                f"Port {r.port} presents a self-signed certificate. "
                f"Clients cannot verify the identity of the server, making MITM trivial.",
                "Replace with a certificate issued by a trusted CA. "
                "For internal services, use an internal PKI (CFSSL, Vault PKI, "
                "Microsoft CA). For internet-facing services, use Let's Encrypt.",
                ["https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"],
            ))
        # Weak signature algorithm
        sig = c.signature_algorithm.lower()
        if "md5" in sig or "sha1" in sig:
            findings.append(_f(
                r.port, RiskLevel.HIGH,
                "Weak Certificate Signature Algorithm",
                f"Certificate uses {c.signature_algorithm}, which is cryptographically "
                f"broken and susceptible to collision attacks.",
                "Reissue the certificate using SHA-256 or better (RSA-SHA256, ECDSA-SHA256). "
                "Ensure your CA is not using deprecated algorithms.",
                ["https://nvd.nist.gov/vuln/search/results?query=sha1+collision"],
            ))
    return findings


def _rule_plaintext_alternatives(open_set, open_results, report) -> List[Finding]:
    """Flag plaintext protocols where an encrypted alternative exists."""
    findings = []
    pairs = [
        (80, 443, "HTTP", "HTTPS",
         "HTTP transmits data in plaintext. Even if login is on HTTPS, mixed "
         "content and cookie handling issues can expose sessions.",
         "Configure HTTP-to-HTTPS redirect. Enable HSTS "
         "(Strict-Transport-Security: max-age=31536000; includeSubDomains; preload). "
         "Obtain a valid TLS certificate.",
         ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"]),
        (21, None, "FTP", "SFTP/FTPS",
         "FTP transmits credentials and data in plaintext.",
         "Replace FTP with SFTP (SSH file transfer, port 22) or FTPS (FTP over TLS). "
         "If FTP cannot be removed, require FTPS and restrict source IPs.",
         ["https://cwe.mitre.org/data/definitions/319.html"]),
        (110, 995, "POP3", "POP3S",
         "POP3 on port 110 transmits email credentials in plaintext.",
         "Require POP3S (995) with TLS. Disable plaintext POP3.",
         []),
        (143, 993, "IMAP", "IMAPS",
         "IMAP on port 143 transmits email and credentials in plaintext.",
         "Require IMAPS (993). Disable plaintext IMAP.",
         []),
        (389, 636, "LDAP", "LDAPS",
         "LDAP on port 389 transmits directory queries and credentials in plaintext. "
         "LDAP pass-back and NTLM relay attacks are common.",
         "Enable LDAPS (636) or StartTLS. Disable unsigned LDAP binding. "
         "Set domain controller policy: Domain controller: LDAP server signing requirements = Require signing.",
         ["https://attack.mitre.org/techniques/T1557/001/"]),
    ]
    for plain_port, secure_port, proto, secure_proto, detail, rec, refs in pairs:
        if plain_port in open_set:
            risk = RiskLevel.MEDIUM
            if secure_port and secure_port not in open_set:
                risk = RiskLevel.HIGH
                detail += f" No encrypted alternative ({secure_proto}) detected on port {secure_port}."
            findings.append(_f(plain_port, risk,
                f"{proto} Plaintext Protocol Exposed",
                detail, rec, refs))
    return findings


def _rule_http_no_https(open_set, open_results, report) -> List[Finding]:
    """HTTP open but no HTTPS."""
    if 80 in open_set and 443 not in open_set and 8443 not in open_set:
        return [_f(80, RiskLevel.MEDIUM,
            "HTTP Exposed — No HTTPS Detected",
            "Port 80 is open but no HTTPS service was found on common ports. "
            "All web traffic is transmitted in plaintext.",
            "Deploy TLS with a valid certificate. Configure HTTP→HTTPS redirect. "
            "Implement HSTS.",
            ["https://https.cio.gov/"])]
    return []


def _rule_management_interfaces(open_set, open_results, report) -> List[Finding]:
    findings = []
    mgmt = {
        15672: ("RabbitMQ Management Console", "RabbitMQ"),
        8161:  ("ActiveMQ Web Console", "ActiveMQ"),
        5601:  ("Kibana Dashboard", "Kibana/Elasticsearch"),
        9090:  ("Prometheus Metrics Endpoint", "Prometheus"),
        3000:  ("Grafana Dashboard", "Grafana"),
        10250: ("Kubernetes Kubelet API", "Kubernetes"),
        2380:  ("etcd Peer Port", "Kubernetes etcd"),
    }
    for port, (title, product) in mgmt.items():
        if port in open_set:
            findings.append(_f(
                port, RiskLevel.MEDIUM,
                f"Management Interface Exposed: {title}",
                f"{product} management interface is network-accessible. "
                f"Management UIs often have weaker authentication and expose "
                f"sensitive operational data.",
                f"Restrict {title} to authorised management IPs only. "
                f"Enable authentication if not already set. "
                f"Consider binding to localhost and using SSH tunnels for access.",
            ))
    return findings


def _rule_smtp_open_relay(open_set, open_results, report) -> List[Finding]:
    """Flag SMTP presence for open relay testing reminder."""
    if 25 in open_set:
        return [_f(25, RiskLevel.INFO,
            "SMTP Service Detected — Verify Not Open Relay",
            "An SMTP server is accessible on port 25. SMTP servers misconfigured "
            "as open relays allow anyone to send email through them, enabling spam "
            "and phishing campaigns.",
            "Test for open relay: attempt to relay mail from a non-local domain. "
            "Ensure SPF, DKIM, and DMARC records are configured. "
            "Tools: swaks --to test@external.com --server <target>",
            ["https://www.spamhaus.org/statistics/asns/"])]
    return []


def _rule_nfs_rpc(open_set, open_results, report) -> List[Finding]:
    findings = []
    if 2049 in open_set:
        findings.append(_f(2049, RiskLevel.HIGH,
            "NFS Service Exposed",
            "Network File System (NFS) is accessible. NFS often has weak access "
            "controls and can be mounted by any host on the network if exports "
            "are misconfigured (no_root_squash, *).",
            "Review /etc/exports — remove wildcards (*). Enable Kerberos authentication "
            "(sec=krb5p). Restrict NFS exports to specific client IPs. "
            "Command to check: showmount -e <target>",
            ["https://attack.mitre.org/techniques/T1135/"]))
    if 111 in open_set:
        findings.append(_f(111, RiskLevel.MEDIUM,
            "RPCbind/Portmapper Exposed",
            "RPC portmapper is accessible. This allows enumeration of all RPC "
            "services running on the host (NFS, NIS, etc.) and was historically "
            "a source of remote vulnerabilities.",
            "Block port 111 at the firewall. If NFS is required, restrict NFS "
            "ports and block portmapper from external access.",
            []))
    return findings


def _rule_x11(open_set, open_results, report) -> List[Finding]:
    if 6000 in open_set:
        return [_f(6000, RiskLevel.CRITICAL,
            "X11 Display Server Exposed",
            "X11 (port 6000) is accessible. An unauthenticated X11 connection "
            "allows an attacker to capture all keystrokes, take screenshots of "
            "the desktop, and inject mouse/keyboard input — full graphical session hijack.",
            "Disable TCP listening in X11 (add -nolisten tcp to Xorg startup flags). "
            "Use X11 forwarding over SSH instead (ForwardX11 yes in ssh_config).",
            ["https://attack.mitre.org/techniques/T1021/006/"])]
    return []


def _rule_banner_version_exposure(open_set, open_results, report) -> List[Finding]:
    """Detect verbose version strings in banners."""
    findings = []
    for r in open_results:
        if not r.banner:
            continue
        # Check for version numbers in banners
        import re
        version_pattern = re.compile(r'(\d+\.\d+[\.\d]*)', re.IGNORECASE)
        if version_pattern.search(r.banner):
            findings.append(_f(
                r.port, RiskLevel.LOW,
                "Service Version Disclosed in Banner",
                f"Port {r.port} ({r.service or 'unknown'}) reveals version information "
                f"in its banner: '{r.banner[:100]}'. Version disclosure helps attackers "
                f"identify known CVEs without probing.",
                "Configure the service to suppress or genericise its version banner. "
                "For Apache: ServerTokens Prod. For Nginx: server_tokens off. "
                "For OpenSSH: VersionAddendum none. Cross-reference disclosed version "
                "against NVD/CVE databases.",
                ["https://cwe.mitre.org/data/definitions/200.html"],
            ))
    return findings


# ── Rule registry ─────────────────────────────────────────────────────────────

_RULES = [
    _rule_critical_ports,
    _rule_high_risk_ports,
    _rule_tls_issues,
    _rule_plaintext_alternatives,
    _rule_http_no_https,
    _rule_management_interfaces,
    _rule_smtp_open_relay,
    _rule_nfs_rpc,
    _rule_x11,
    _rule_banner_version_exposure,
]
