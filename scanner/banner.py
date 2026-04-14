"""
Banner Grabbing Module - Service banner detection and analysis.

This module implements banner grabbing functionality to identify service versions,
configurations, and potential vulnerabilities. Banner grabbing is a reconnaissance
technique used to gather information about running services.

SECURITY CONCEPTS:
- Banner Grabbing: The process of capturing service identification information
  (banners) from open ports to determine service type and version.
- Service Fingerprinting: Using banner information to identify specific software
  versions and potential vulnerabilities.
- Information Disclosure: Many services reveal too much information in their banners,
  which can aid attackers in exploitation.
- Security Hardening: Configuring services to limit banner information disclosure.

NOTE: Banner grabbing should only be performed on networks you own or have
explicit permission to test. This is for educational purposes only.
"""

import socket
import ssl
import re
from typing import Optional, Dict, List


def grab_banner(target_ip: str, port: int, timeout: float = 5.0) -> str:
    """
    Grab service banner from a target port.
    
    Args:
        target_ip: Target IP address
        port: Target port number
        timeout: Connection timeout in seconds
        
    Returns:
        Banner string or empty string if failed
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect to target
        sock.connect((target_ip, port))
        
        # For HTTPS ports, establish SSL connection
        if port in [443, 8443, 9443]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            except ssl.SSLError:
                # Fall back to regular socket if SSL fails
                pass
        
        # Send appropriate probe based on port
        probe = get_port_probe(port)
        if probe:
            sock.send(probe.encode())
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        sock.close()
        
        return banner if banner else ""
        
    except Exception:
        return ""


def get_port_probe(port: int) -> str:
    """
    Get appropriate probe string for a given port.
    
    Args:
        port: Port number
        
    Returns:
        Probe string to send
    """
    probes = {
        # Web servers
        80: "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        8080: "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        443: "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        8443: "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        
        # FTP
        21: "",
        
        # SSH
        22: "",
        
        # SMTP
        25: "EHLO test\r\n",
        587: "EHLO test\r\n",
        
        # POP3
        110: "USER test\r\n",
        995: "USER test\r\n",
        
        # IMAP
        143: "A001 CAPABILITY\r\n",
        993: "A001 CAPABILITY\r\n",
        
        # Telnet
        23: "",
        
        # Database
        3306: "",
        5432: "",
        1433: "",
        1521: "",
        
        # VNC
        5900: "",
        
        # RDP
        3389: "",
        
        # Default probe
    }
    
    probe = probes.get(port, "")
    if "{}" in probe:
        probe = probe.format("test")
    
    return probe


def parse_banner(banner: str, port: int) -> Dict:
    """
    Parse and analyze service banner.
    
    Args:
        banner: Raw banner string
        port: Port number
        
    Returns:
        Dictionary with parsed information
    """
    if not banner:
        return {
            'raw_banner': '',
            'service': 'unknown',
            'version': 'unknown',
            'additional_info': '',
            'potential_vulnerabilities': []
        }
    
    parsed = {
        'raw_banner': banner,
        'service': 'unknown',
        'version': 'unknown',
        'additional_info': '',
        'potential_vulnerabilities': []
    }
    
    # HTTP banners
    if port in [80, 8080, 443, 8443]:
        http_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
        if http_match:
            server_info = http_match.group(1)
            parsed['additional_info'] = server_info
            
            # Extract server name and version
            server_parts = server_info.split('/')
            if len(server_parts) >= 2:
                server_name = server_parts[0]
                parsed['service'] = server_name
                parsed['version'] = server_parts[1]
                
                # Add full service name for common servers
                if server_name.lower() == 'apache':
                    parsed['service'] = 'Apache HTTP Server'
                elif server_name.lower() == 'nginx':
                    parsed['service'] = 'Nginx'
                elif 'iis' in server_name.lower():
                    parsed['service'] = 'Microsoft IIS'
            else:
                parsed['service'] = server_parts[0]
            
            # Check for common vulnerable versions
            parsed['potential_vulnerabilities'] = check_http_vulnerabilities(server_info)
    
    # SSH banners
    elif port == 22:
        ssh_match = re.search(r'SSH-(\d+\.\d+)-([^\r\n]+)', banner)
        if ssh_match:
            parsed['service'] = 'SSH'
            parsed['version'] = f"{ssh_match.group(1)}-{ssh_match.group(2)}"
            parsed['potential_vulnerabilities'] = check_ssh_vulnerabilities(ssh_match.group(2))
    
    # FTP banners
    elif port == 21:
        ftp_match = re.search(r'220[^\r\n]*([^\r\n]+)', banner)
        if ftp_match:
            ftp_info = ftp_match.group(1)
            parsed['service'] = 'FTP'
            parsed['additional_info'] = ftp_info
            
            # Extract version if available
            version_match = re.search(r'(\d+\.\d+\.\d+)', ftp_info)
            if version_match:
                parsed['version'] = version_match.group(1)
            
            parsed['potential_vulnerabilities'] = check_ftp_vulnerabilities(ftp_info)
    
    # SMTP banners
    elif port in [25, 587]:
        smtp_match = re.search(r'220[^\r\n]*([^\r\n]+)', banner)
        if smtp_match:
            smtp_info = smtp_match.group(1)
            parsed['service'] = 'SMTP'
            parsed['additional_info'] = smtp_info
            
            # Extract version if available
            version_match = re.search(r'(\d+\.\d+\.\d+)', smtp_info)
            if version_match:
                parsed['version'] = version_match.group(1)
            
            parsed['potential_vulnerabilities'] = check_smtp_vulnerabilities(smtp_info)
    
    # Generic parsing for other services
    else:
        # Try to extract version information
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # Semantic versioning
            r'(\d+\.\d+)',       # Major.Minor
            r'v(\d+\.\d+\.\d+)', # Version prefixed with v
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                parsed['version'] = match.group(1)
                break
        
        # Try to identify service from banner
        service_keywords = {
            'Apache': 'Apache HTTP Server',
            'nginx': 'Nginx',
            'IIS': 'Microsoft IIS',
            'OpenSSH': 'OpenSSH',
            'vsftpd': 'vsftpd',
            'ProFTPD': 'ProFTPD',
            'MySQL': 'MySQL',
            'PostgreSQL': 'PostgreSQL',
            'Redis': 'Redis',
        }
        
        for keyword, service_name in service_keywords.items():
            if keyword.lower() in banner.lower():
                parsed['service'] = service_name
                break
    
    return parsed


def check_http_vulnerabilities(server_info: str) -> List[str]:
    """
    Check for known HTTP server vulnerabilities.
    
    Args:
        server_info: HTTP server string from banner
        
    Returns:
        List of potential vulnerabilities
    """
    vulnerabilities = []
    server_lower = server_info.lower()
    
    # Apache vulnerabilities
    if 'apache' in server_lower:
        if '2.4.' in server_lower:
            version_match = re.search(r'apache/2\.4\.(\d+)', server_lower)
            if version_match:
                version_num = int(version_match.group(1))
                if version_num < 41:
                    vulnerabilities.append("Apache 2.4.x < 2.4.41 - Multiple vulnerabilities")
        
        elif '2.2.' in server_lower:
            vulnerabilities.append("Apache 2.2.x - End of life, upgrade required")
    
    # Nginx vulnerabilities
    elif 'nginx' in server_lower:
        version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_lower)
        if version_match:
            version_parts = version_match.group(1).split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            
            if major == 1 and minor < 18:
                vulnerabilities.append("Nginx < 1.18.0 - Multiple security issues")
    
    # IIS vulnerabilities
    elif 'iis' in server_lower:
        version_match = re.search(r'iis/(\d+\.\d+)', server_lower)
        if version_match:
            version_num = float(version_match.group(1))
            if version_num < 8.5:
                vulnerabilities.append("IIS < 8.5 - End of life, upgrade required")
    
    # Generic vulnerabilities
    if 'php' in server_lower:
        php_match = re.search(r'php/(\d+\.\d+\.\d+)', server_lower)
        if php_match:
            php_version = php_match.group(1)
            if php_version.startswith('7.4') or php_version.startswith('7.3'):
                vulnerabilities.append(f"PHP {php_version} - Potential security issues")
    
    return vulnerabilities


def check_ssh_vulnerabilities(ssh_version: str) -> List[str]:
    """
    Check for known SSH vulnerabilities.
    
    Args:
        ssh_version: SSH version string
        
    Returns:
        List of potential vulnerabilities
    """
    vulnerabilities = []
    
    # OpenSSH vulnerabilities
    if 'openssh' in ssh_version.lower():
        version_match = re.search(r'(\d+\.\d+)', ssh_version)
        if version_match:
            version_parts = version_match.group(1).split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            
            if major < 7:
                vulnerabilities.append("OpenSSH < 7.0 - Multiple CVEs, upgrade required")
            elif major == 7 and minor < 4:
                vulnerabilities.append("OpenSSH 7.x < 7.4 - User enumeration vulnerability")
    
    return vulnerabilities


def check_ftp_vulnerabilities(ftp_info: str) -> List[str]:
    """
    Check for known FTP vulnerabilities.
    
    Args:
        ftp_info: FTP banner information
        
    Returns:
        List of potential vulnerabilities
    """
    vulnerabilities = []
    ftp_lower = ftp_info.lower()
    
    # vsftpd vulnerabilities
    if 'vsftpd' in ftp_lower:
        version_match = re.search(r'vsftpd\s+(\d+\.\d+\.\d+)', ftp_lower)
        if version_match:
            version = version_match.group(1)
            if version.startswith('2.3.4'):
                vulnerabilities.append("vsftpd 2.3.4 - Backdoor vulnerability")
    
    # ProFTPD vulnerabilities
    elif 'proftpd' in ftp_lower:
        version_match = re.search(r'proftpd\s+(\d+\.\d+\.\d+)', ftp_lower)
        if version_match:
            version = version_match.group(1)
            if version.startswith('1.3.3'):
                vulnerabilities.append("ProFTPD 1.3.3 - Multiple vulnerabilities")
    
    # Generic FTP issues
    if 'anonymous' in ftp_lower:
        vulnerabilities.append("Anonymous FTP access enabled")
    
    return vulnerabilities


def check_smtp_vulnerabilities(smtp_info: str) -> List[str]:
    """
    Check for known SMTP vulnerabilities.
    
    Args:
        smtp_info: SMTP banner information
        
    Returns:
        List of potential vulnerabilities
    """
    vulnerabilities = []
    smtp_lower = smtp_info.lower()
    
    # Check for open relay indicators
    if 'open' in smtp_lower and 'relay' in smtp_lower:
        vulnerabilities.append("Potential open SMTP relay")
    
    # Sendmail vulnerabilities
    if 'sendmail' in smtp_lower:
        version_match = re.search(r'sendmail\s+(\d+\.\d+\.\d+)', smtp_lower)
        if version_match:
            version = version_match.group(1)
            if version.startswith('8.12.') or version.startswith('8.13.'):
                vulnerabilities.append(f"Sendmail {version} - Potential vulnerabilities")
    
    return vulnerabilities


def get_banner_security_recommendations(parsed_banner: Dict) -> List[str]:
    """
    Get security recommendations based on banner analysis.
    
    Args:
        parsed_banner: Parsed banner information
        
    Returns:
        List of security recommendations
    """
    recommendations = []
    
    # Generic recommendations
    if parsed_banner['version'] != 'unknown':
        recommendations.append("Consider hiding or limiting version information in banners")
    
    if parsed_banner['potential_vulnerabilities']:
        recommendations.append("Upgrade to latest stable version to address known vulnerabilities")
    
    # Service-specific recommendations
    service = parsed_banner['service'].lower()
    
    if 'http' in service or 'apache' in service or 'nginx' in service:
        recommendations.extend([
            "Implement security headers (X-Frame-Options, CSP, etc.)",
            "Use Web Application Firewall (WAF)",
            "Disable directory listing"
        ])
    
    elif 'ssh' in service:
        recommendations.extend([
            "Disable root login",
            "Use key-based authentication",
            "Change default SSH port"
        ])
    
    elif 'ftp' in service:
        recommendations.extend([
            "Use SFTP instead of FTP",
            "Disable anonymous access",
            "Implement connection limits"
        ])
    
    elif 'smtp' in service:
        recommendations.extend([
            "Disable open relay",
            "Implement SMTP authentication",
            "Use TLS encryption"
        ])
    
    return recommendations
