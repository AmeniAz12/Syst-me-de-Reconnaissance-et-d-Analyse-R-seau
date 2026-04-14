"""
Services Detection Module - Identifies services based on port numbers.

This module provides service detection functionality by mapping well-known port numbers
to their corresponding services. This is a basic form of service fingerprinting.

SECURITY CONCEPTS:
- Service Detection: The process of identifying what service is running on an open port.
- Port-to-Service Mapping: Using IANA-assigned port numbers to identify common services.
- Service Fingerprinting: Advanced techniques to identify services even on non-standard ports.
- Security Implications: Knowing the service helps identify potential vulnerabilities.

NOTE: This is basic service detection. Advanced tools like Nmap use more sophisticated
methods including banner analysis, protocol-specific probes, and version detection.
"""

from typing import Dict


# Well-known port to service mapping
# Based on IANA port assignments and common usage
SERVICE_MAP = {
    # File Transfer Services
    20: "ftp-data",      # FTP Data Connection
    21: "ftp",           # File Transfer Protocol
    22: "ssh",           # Secure Shell
    23: "telnet",        # Telnet
    69: "tftp",          # Trivial FTP
    
    # Email Services
    25: "smtp",          # Simple Mail Transfer Protocol
    110: "pop3",         # Post Office Protocol v3
    143: "imap",         # Internet Message Access Protocol
    465: "smtps",        # SMTP over SSL/TLS
    587: "smtp-submission", # SMTP Submission
    993: "imaps",        # IMAP over SSL/TLS
    995: "pop3s",        # POP3 over SSL/TLS
    
    # Web Services
    80: "http",          # Hypertext Transfer Protocol
    443: "https",        # HTTP over SSL/TLS
    8080: "http-proxy",  # HTTP Proxy
    8443: "https-alt",   # HTTPS Alternate
    
    # DNS Services
    53: "dns",           # Domain Name System
    853: "dns-tls",      # DNS over TLS
    
    # Database Services
    3306: "mysql",       # MySQL Database
    5432: "postgresql",  # PostgreSQL Database
    1433: "mssql",       # Microsoft SQL Server
    1521: "oracle",      # Oracle Database
    27017: "mongodb",     # MongoDB
    6379: "redis",       # Redis
    
    # Remote Access Services
    3389: "rdp",         # Remote Desktop Protocol
    5900: "vnc",         # Virtual Network Computing
    
    # Directory Services
    389: "ldap",         # Lightweight Directory Access Protocol
    636: "ldaps",        # LDAP over SSL/TLS
    
    # Windows Services
    135: "rpc",          # Remote Procedure Call
    139: "netbios-ssn",  # NetBIOS Session Service
    445: "smb",          # Server Message Block
    
    # Network Management
    161: "snmp",         # Simple Network Management Protocol
    162: "snmp-trap",    # SNMP Trap
    
    # VPN Services
    1723: "pptp",        # Point-to-Point Tunneling Protocol
    1194: "openvpn",     # OpenVPN
    500: "ike",          # Internet Key Exchange (IPsec)
    
    # Time Services
    123: "ntp",          # Network Time Protocol
    37: "time",          # Time Protocol
    
    # Mail/Message Services
    143: "imap",         # Internet Message Access Protocol
    993: "imaps",        # IMAP over SSL/TLS
    
    # Other Common Services
    111: "rpcbind",      # RPC Portmapper
    512: "rexec",        # Remote Execution
    513: "rlogin",       # Remote Login
    514: "rsh",          # Remote Shell
    1433: "mssql",       # Microsoft SQL Server
    1521: "oracle",      # Oracle Database
    2049: "nfs",         # Network File System
    5060: "sip",         # Session Initiation Protocol
    5061: "sips",        # SIP over SSL/TLS
    
    # Gaming/Entertainment
    25565: "minecraft",  # Minecraft Server
    27015: "srcds",      # Source Dedicated Server
    
    # Development/Version Control
    9418: "git",         # Git Protocol
    
    # Proxy Services
    3128: "squid-http",  # Squid HTTP Proxy
    1080: "socks",       # SOCKS Proxy
    
    # IoT/Embedded
    1883: "mqtt",        # Message Queuing Telemetry Transport
    8883: "mqtts",       # MQTT over SSL/TLS
    502: "modbus",       # Modbus TCP
    2404: "iec104",      # IEC 104 Protocol
}


def detect_service(port: int) -> str:
    """
    Detect service based on port number.
    
    Args:
        port: Port number to identify
        
    Returns:
        Service name as string, or 'unknown' if not found
    """
    # Validate port range
    if not 1 <= port <= 65535:
        return "invalid"
    
    # Look up service in mapping
    service = SERVICE_MAP.get(port, "unknown")
    
    return service


def get_service_info(service_name: str) -> Dict:
    """
    Get detailed information about a service.
    
    Args:
        service_name: Name of the service
        
    Returns:
        Dictionary with service information
    """
    # Service descriptions and common vulnerabilities
    SERVICE_INFO = {
        "http": {
            "description": "Hypertext Transfer Protocol - Web server",
            "common_vulnerabilities": ["SQL Injection", "XSS", "Directory Traversal"],
            "security_considerations": "Keep web server updated, use HTTPS, implement WAF"
        },
        "https": {
            "description": "HTTP over SSL/TLS - Secure web server",
            "common_vulnerabilities": ["SSL/TLS Misconfiguration", "Heartbleed", "POODLE"],
            "security_considerations": "Use strong TLS ciphers, keep certificates valid"
        },
        "ssh": {
            "description": "Secure Shell - Remote administration",
            "common_vulnerabilities": ["Weak Passwords", "Brute Force", "SSH Key Issues"],
            "security_considerations": "Use key-based auth, disable root login, use fail2ban"
        },
        "ftp": {
            "description": "File Transfer Protocol - File transfer",
            "common_vulnerabilities": ["Anonymous Access", "Plain Text Credentials", "Bounce Attacks"],
            "security_considerations": "Use SFTP instead, disable anonymous access"
        },
        "telnet": {
            "description": "Telnet - Remote terminal (insecure)",
            "common_vulnerabilities": ["Plain Text Transmission", "No Authentication"],
            "security_considerations": "Replace with SSH, disable if not needed"
        },
        "smtp": {
            "description": "Simple Mail Transfer Protocol - Email sending",
            "common_vulnerabilities": ["Open Relay", "Spam, Spoofing"],
            "security_considerations": "Disable open relay, use authentication"
        },
        "mysql": {
            "description": "MySQL Database Server",
            "common_vulnerabilities": ["SQL Injection", "Weak Passwords", "Privilege Escalation"],
            "security_considerations": "Use strong passwords, limit network access, encrypt connections"
        },
        "rdp": {
            "description": "Remote Desktop Protocol - Windows remote access",
            "common_vulnerabilities": ["BlueKeep", "Brute Force", "Man-in-the-Middle"],
            "security_considerations": "Use strong passwords, enable NLA, keep updated"
        },
        "smb": {
            "description": "Server Message Block - Windows file sharing",
            "common_vulnerabilities": ["EternalBlue", "WannaCry", "SMB Relay"],
            "security_considerations": "Disable SMBv1, use firewalls, keep updated"
        }
    }
    
    return SERVICE_INFO.get(service_name, {
        "description": f"{service_name} service",
        "common_vulnerabilities": ["Service-specific vulnerabilities"],
        "security_considerations": "Keep service updated and properly configured"
    })


def get_all_services() -> Dict[int, str]:
    """
    Get all known port-to-service mappings.
    
    Returns:
        Dictionary mapping port numbers to service names
    """
    return SERVICE_MAP.copy()


def get_services_by_category() -> Dict[str, List[int]]:
    """
    Group services by category for better organization.
    
    Returns:
        Dictionary with service categories and their ports
    """
    categories = {
        "Web Services": [20, 21, 80, 443, 8080, 8443],
        "Email Services": [25, 110, 143, 465, 587, 993, 995],
        "Database Services": [3306, 5432, 1433, 1521, 27017, 6379],
        "Remote Access": [22, 23, 3389, 5900, 1723],
        "File Transfer": [20, 21, 69],
        "Directory Services": [389, 636],
        "Windows Services": [135, 139, 445],
        "Network Management": [161, 162],
        "DNS Services": [53, 853],
        "Security/VPN": [500, 1194],
        "Development": [9418],
        "IoT/Industrial": [1883, 8883, 502, 2404]
    }
    
    return categories


def is_high_risk_port(port: int) -> bool:
    """
    Determine if a port is commonly associated with high-risk services.
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is considered high risk
    """
    high_risk_ports = [
        23,    # telnet (insecure)
        135,   # rpc (Windows vulnerabilities)
        139,   # netbios (Windows file sharing)
        445,   # smb (EternalBlue, WannaCry)
        1433,  # mssql (database)
        3389,  # rdp (BlueKeep)
        5900,  # vnc (remote access)
    ]
    
    return port in high_risk_ports


def get_port_security_recommendations(port: int) -> List[str]:
    """
    Get security recommendations for a specific port.
    
    Args:
        port: Port number
        
    Returns:
        List of security recommendations
    """
    service = detect_service(port)
    
    recommendations = {
        "telnet": ["Disable telnet, use SSH instead", "Block port 23 at firewall"],
        "ftp": ["Use SFTP/FTPS instead", "Disable anonymous access", "Use strong passwords"],
        "smb": ["Disable SMBv1", "Block port 445 from internet", "Apply latest patches"],
        "rdp": ["Enable Network Level Authentication", "Use strong passwords", "Enable 2FA"],
        "ssh": ["Use key-based authentication", "Disable root login", "Change default port"],
        "http": ["Redirect to HTTPS", "Implement security headers", "Use WAF"],
        "mysql": ["Restrict network access", "Use strong passwords", "Encrypt connections"],
        "unknown": ["Investigate unknown service", "Consider blocking if not needed"]
    }
    
    return recommendations.get(service, ["Keep service updated", "Monitor for suspicious activity"])
