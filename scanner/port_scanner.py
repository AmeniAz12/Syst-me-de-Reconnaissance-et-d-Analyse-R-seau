"""
Port Scanner Module - Core TCP connect scanning functionality.

This module implements the fundamental port scanning capabilities of the network scanner.
It provides TCP connect scanning which is the most basic and reliable scanning method.

SECURITY CONCEPTS:
- TCP Connect Scan: Completes the full three-way handshake to determine port status.
  This is the most reliable but also the most easily detectable scanning method.
- Port States: 
  * OPEN: Port is accepting connections and running a service
  * CLOSED: Port is reachable but no service is listening
  * FILTERED: Port status cannot be determined due to firewall filtering
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
from .utils import validate_ip, validate_port_range
from .services import detect_service
from .banner import grab_banner


class PortScanner:
    """Advanced port scanner with multi-threading support."""
    
    def __init__(self, timeout: float = 3.0, max_threads: int = 100, stealth_delay: float = 0.0):
        """
        Initialize the port scanner.
        
        Args:
            timeout: Connection timeout in seconds
            max_threads: Maximum number of concurrent threads
            stealth_delay: Delay between scans in seconds (for stealth)
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.stealth_delay = stealth_delay
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
    def scan_port(self, target_ip: str, port: int, grab_banner: bool = False) -> Dict:
        """
        Scan a single port on a target IP.
        
        Args:
            target_ip: Target IP address
            port: Port number to scan
            grab_banner: Whether to attempt banner grabbing
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Create socket for TCP connect scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection (TCP connect scan)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                # Port is OPEN
                service = detect_service(port)
                banner = ""
                
                if grab_banner:
                    try:
                        banner = grab_banner(target_ip, port)
                    except Exception:
                        pass
                
                scan_result = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner
                }
                self.open_ports.append(scan_result)
                
            elif result == 10035:  # Windows timeout
                # Port is FILTERED
                scan_result = {
                    'port': port,
                    'status': 'filtered',
                    'service': 'unknown',
                    'banner': ''
                }
                self.filtered_ports.append(scan_result)
                
            else:
                # Port is CLOSED
                scan_result = {
                    'port': port,
                    'status': 'closed',
                    'service': 'unknown',
                    'banner': ''
                }
                self.closed_ports.append(scan_result)
                
            sock.close()
            
        except socket.timeout:
            # Port is FILTERED (timeout)
            scan_result = {
                'port': port,
                'status': 'filtered',
                'service': 'unknown',
                'banner': ''
            }
            self.filtered_ports.append(scan_result)
            
        except Exception as e:
            # Other errors - treat as filtered
            scan_result = {
                'port': port,
                'status': 'filtered',
                'service': 'unknown',
                'banner': f'Error: {str(e)}'
            }
            self.filtered_ports.append(scan_result)
        
        # Apply stealth delay if configured
        if self.stealth_delay > 0:
            time.sleep(self.stealth_delay)
            
        return scan_result
    
    def scan_port_range(self, target_ip: str, start_port: int, end_port: int, 
                       grab_banner: bool = False) -> Dict:
        """
        Scan a range of ports on a target IP.
        
        Args:
            target_ip: Target IP address
            start_port: Starting port number
            end_port: Ending port number
            grab_banner: Whether to attempt banner grabbing
            
        Returns:
            Dictionary with complete scan results
        """
        # Validate inputs
        if not validate_ip(target_ip):
            raise ValueError(f"Invalid IP address: {target_ip}")
            
        if not validate_port_range(start_port, end_port):
            raise ValueError(f"Invalid port range: {start_port}-{end_port}")
        
        print(f"[*] Scanning {target_ip} from port {start_port} to {end_port}")
        print(f"[*] Using {self.max_threads} threads with {self.timeout}s timeout")
        
        # Reset previous results
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
        # Create list of ports to scan
        ports_to_scan = list(range(start_port, end_port + 1))
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all scan tasks
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port, grab_banner): port 
                for port in ports_to_scan
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_port):
                completed += 1
                port = future_to_port[future]
                
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        print(f"[+] Port {port}/{result['service']} - OPEN")
                except Exception as e:
                    print(f"[-] Error scanning port {port}: {e}")
                
                # Progress indicator
                if completed % 50 == 0 or completed == len(ports_to_scan):
                    print(f"[*] Progress: {completed}/{len(ports_to_scan)} ports scanned")
        
        return {
            'target': target_ip,
            'open_ports': self.open_ports,
            'closed_ports': self.closed_ports,
            'filtered_ports': self.filtered_ports,
            'total_scanned': len(ports_to_scan),
            'open_count': len(self.open_ports),
            'closed_count': len(self.closed_ports),
            'filtered_count': len(self.filtered_ports)
        }
    
    def scan_common_ports(self, target_ip: str, grab_banner: bool = False) -> Dict:
        """
        Scan common ports only (fast scan).
        
        Args:
            target_ip: Target IP address
            grab_banner: Whether to attempt banner grabbing
            
        Returns:
            Dictionary with scan results
        """
        # Validate IP address
        if not validate_ip(target_ip):
            raise ValueError(f"Invalid IP address: {target_ip}")
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
        ]
        
        print(f"[*] Performing fast scan on common ports for {target_ip}")
        
        # Reset previous results
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
        # Scan common ports
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(common_ports))) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port, grab_banner): port 
                for port in common_ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        print(f"[+] Port {port}/{result['service']} - OPEN")
                except Exception as e:
                    print(f"[-] Error scanning port {port}: {e}")
        
        return {
            'target': target_ip,
            'open_ports': self.open_ports,
            'closed_ports': self.closed_ports,
            'filtered_ports': self.filtered_ports,
            'total_scanned': len(common_ports),
            'open_count': len(self.open_ports),
            'closed_count': len(self.closed_ports),
            'filtered_count': len(self.filtered_ports)
        }
    
    def get_scan_summary(self) -> Dict:
        """
        Get a summary of the last scan.
        
        Returns:
            Dictionary with scan summary
        """
        return {
            'open_ports': len(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'filtered_ports': len(self.filtered_ports),
            'total_scanned': len(self.open_ports) + len(self.closed_ports) + len(self.filtered_ports)
        }
