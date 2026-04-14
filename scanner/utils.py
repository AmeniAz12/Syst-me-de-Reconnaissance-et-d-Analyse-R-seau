"""
Utilities Module - Helper functions for network scanning operations.

This module provides utility functions for IP validation, host discovery,
subnet calculations, and other common operations needed by the network scanner.

SECURITY CONCEPTS:
- IP Address Validation: Ensuring target addresses are properly formatted
- Host Discovery: Determining if a target is alive before scanning
- Subnet Scanning: Scanning entire network segments for active hosts
- Network Enumeration: The process of discovering network resources

NOTE: These utilities are designed for legitimate security testing and
educational purposes only.
"""

import socket
import subprocess
import platform
import re
import ipaddress
from typing import List, Tuple, Optional, Dict
import concurrent.futures


def validate_ip(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port_range(start_port: int, end_port: int) -> bool:
    """
    Validate port range.
    
    Args:
        start_port: Starting port number
        end_port: Ending port number
        
    Returns:
        True if valid port range, False otherwise
    """
    return (1 <= start_port <= 65535 and 
            1 <= end_port <= 65535 and 
            start_port <= end_port)


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation for subnet.
    
    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid CIDR, False otherwise
    """
    try:
        # Must contain '/' to be valid CIDR
        if '/' not in cidr:
            return False
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_host_alive(target_ip: str, timeout: float = 3.0) -> bool:
    """
    Check if a host is alive using multiple methods.
    
    Args:
        target_ip: Target IP address
        timeout: Timeout for connection attempts
        
    Returns:
        True if host appears to be alive, False otherwise
    """
    # Method 1: Try common ports (most reliable)
    common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout / len(common_ports))  # Divide timeout by number of ports
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                return True  # Host is alive
        except Exception:
            continue
    
    # Method 2: ICMP ping (fallback)
    return ping_host(target_ip, timeout)


def ping_host(target_ip: str, timeout: float = 3.0) -> bool:
    """
    Ping a host using system's ping command.
    
    Args:
        target_ip: Target IP address
        timeout: Timeout in seconds
        
    Returns:
        True if ping succeeds, False otherwise
    """
    try:
        # Determine ping command based on OS
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), target_ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(int(timeout)), target_ip]
        
        # Execute ping command
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 1
        )
        
        return result.returncode == 0
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False


def generate_ip_range(start_ip: str, end_ip: str) -> List[str]:
    """
    Generate IP addresses in a range.
    
    Args:
        start_ip: Starting IP address
        end_ip: Ending IP address
        
    Returns:
        List of IP addresses in the range
    """
    try:
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        
        if start > end:
            return []
        
        ip_list = []
        current = start
        while current <= end:
            ip_list.append(str(current))
            current += 1
        
        return ip_list
        
    except ValueError:
        return []


def generate_subnet_ips(cidr: str) -> List[str]:
    """
    Generate all IP addresses in a subnet.
    
    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        List of IP addresses in the subnet
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def discover_hosts(subnet: str, max_threads: int = 50, timeout: float = 3.0) -> List[str]:
    """
    Discover alive hosts in a subnet.
    
    Args:
        subnet: Subnet in CIDR notation
        max_threads: Maximum number of concurrent threads
        timeout: Timeout per host check
        
    Returns:
        List of alive host IP addresses
    """
    if not validate_cidr(subnet):
        raise ValueError(f"Invalid subnet: {subnet}")
    
    ip_list = generate_subnet_ips(subnet)
    alive_hosts = []
    
    print(f"[*] Discovering hosts in {subnet} ({len(ip_list)} addresses)")
    
    def check_host(ip: str) -> Optional[str]:
        """Check if a single host is alive."""
        if is_host_alive(ip, timeout):
            return ip
        return None
    
    # Multi-threaded host discovery
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all host checks
        future_to_ip = {executor.submit(check_host, ip): ip for ip in ip_list}
        
        # Process results
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            ip = future_to_ip[future]
            
            try:
                result = future.result()
                if result:
                    alive_hosts.append(result)
                    print(f"[+] Host {result} is alive")
            except Exception:
                pass
            
            # Progress indicator
            if completed % 50 == 0 or completed == len(ip_list):
                print(f"[*] Host discovery progress: {completed}/{len(ip_list)}")
    
    print(f"[*] Found {len(alive_hosts)} alive hosts in {subnet}")
    return alive_hosts


def parse_port_range(port_range_str: str) -> Tuple[int, int]:
    """
    Parse port range string into start and end ports.
    
    Args:
        port_range_str: Port range string (e.g., "80-443", "22", "20-1000", "22,80,443")
        
    Returns:
        Tuple of (start_port, end_port)
    """
    port_range_str = port_range_str.strip()
    
    # Handle comma-separated ports (convert to range)
    if ',' in port_range_str:
        ports = []
        for port_str in port_range_str.split(','):
            port_str = port_str.strip()
            if port_str.isdigit():
                port = int(port_str)
                if validate_port_range(port, port):
                    ports.append(port)
                else:
                    raise ValueError(f"Invalid port: {port}")
            elif '-' in port_str:
                # Handle range within comma-separated list
                parts = port_str.split('-')
                if len(parts) == 2:
                    start_port = int(parts[0].strip())
                    end_port = int(parts[1].strip())
                    if validate_port_range(start_port, end_port):
                        ports.extend(range(start_port, end_port + 1))
                    else:
                        raise ValueError(f"Invalid port range: {start_port}-{end_port}")
                else:
                    raise ValueError(f"Invalid port range format: {port_str}")
            else:
                raise ValueError(f"Invalid port format: {port_str}")
        
        if not ports:
            raise ValueError(f"No valid ports found in: {port_range_str}")
        
        return min(ports), max(ports)
    
    # Single port
    elif port_range_str.isdigit():
        port = int(port_range_str)
        if validate_port_range(port, port):
            return port, port
        else:
            raise ValueError(f"Invalid port: {port}")
    
    # Port range
    elif '-' in port_range_str:
        parts = port_range_str.split('-')
        if len(parts) == 2:
            start_port = int(parts[0].strip())
            end_port = int(parts[1].strip())
            
            if validate_port_range(start_port, end_port):
                return start_port, end_port
            else:
                raise ValueError(f"Invalid port range: {start_port}-{end_port}")
    
    raise ValueError(f"Invalid port range format: {port_range_str}")


def get_local_ip() -> str:
    """
    Get local IP address.
    
    Returns:
        Local IP address as string
    """
    try:
        # Create a socket and connect to a remote address
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_network_info() -> Dict:
    """
    Get basic network information.
    
    Returns:
        Dictionary with network information
    """
    try:
        hostname = socket.gethostname()
        local_ip = get_local_ip()
        
        # Try to get network interface info (limited approach)
        network_info = {
            'hostname': hostname,
            'local_ip': local_ip,
            'platform': platform.system(),
            'architecture': platform.architecture()[0]
        }
        
        # Try to determine if we're on a private network
        try:
            ip_obj = ipaddress.ip_address(local_ip)
            network_info['is_private'] = ip_obj.is_private
            network_info['is_loopback'] = ip_obj.is_loopback
        except:
            network_info['is_private'] = True
            network_info['is_loopback'] = False
        
        return network_info
        
    except Exception as e:
        return {
            'error': str(e),
            'hostname': 'unknown',
            'local_ip': 'unknown'
        }


def format_scan_results(results: Dict) -> str:
    """
    Format scan results for display.
    
    Args:
        results: Scan results dictionary
        
    Returns:
        Formatted string for display
    """
    formatted = []
    
    # Header
    formatted.append("=" * 60)
    formatted.append(f"SCAN RESULTS FOR: {results.get('target', 'Unknown')}")
    formatted.append("=" * 60)
    
    # Summary
    formatted.append(f"Total ports scanned: {results.get('total_scanned', 0)}")
    formatted.append(f"Open ports: {results.get('open_count', 0)}")
    formatted.append(f"Closed ports: {results.get('closed_count', 0)}")
    formatted.append(f"Filtered ports: {results.get('filtered_count', 0)}")
    formatted.append("")
    
    # Open ports
    open_ports = results.get('open_ports', [])
    if open_ports:
        formatted.append("OPEN PORTS:")
        formatted.append("-" * 40)
        for port_info in sorted(open_ports, key=lambda x: x['port']):
            port = port_info['port']
            service = port_info['service']
            banner = port_info.get('banner', '')
            
            line = f"Port {port:5d}/{service:15s}"
            if banner:
                # Truncate long banners
                banner_short = banner[:50] + "..." if len(banner) > 50 else banner
                line += f" - {banner_short}"
            formatted.append(line)
        formatted.append("")
    
    # Filtered ports (limit display)
    filtered_ports = results.get('filtered_ports', [])
    if filtered_ports:
        formatted.append("FILTERED PORTS (showing first 10):")
        formatted.append("-" * 40)
        for port_info in sorted(filtered_ports[:10], key=lambda x: x['port']):
            formatted.append(f"Port {port_info['port']:5d}")
        
        if len(filtered_ports) > 10:
            formatted.append(f"... and {len(filtered_ports) - 10} more")
        formatted.append("")
    
    return "\n".join(formatted)


def calculate_scan_time(start_time: float, end_time: float, ports_scanned: int) -> Dict:
    """
    Calculate scan statistics.
    
    Args:
        start_time: Scan start timestamp
        end_time: Scan end timestamp
        ports_scanned: Number of ports scanned
        
    Returns:
        Dictionary with scan statistics
    """
    total_time = end_time - start_time
    ports_per_second = ports_scanned / total_time if total_time > 0 else 0
    
    return {
        'total_time': total_time,
        'ports_scanned': ports_scanned,
        'ports_per_second': ports_per_second,
        'minutes': total_time / 60,
        'seconds': total_time % 60
    }
