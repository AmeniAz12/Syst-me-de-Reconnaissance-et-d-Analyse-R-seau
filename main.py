#!/usr/bin/env python3
"""
Cyber Network Scanner - Main CLI Interface

A simplified Nmap-like tool for educational purposes that provides:
- Port scanning with TCP connect scans
- Service detection and banner grabbing
- Multi-threaded scanning for performance
- Host discovery and subnet scanning
- Export results to multiple formats

SECURITY DISCLAIMER:
This tool is for EDUCATIONAL PURPOSES ONLY. Only scan networks you own
or have explicit written permission to test. Unauthorized network scanning
is illegal and unethical. Use responsibly and in compliance with all applicable
laws and regulations.

Author: Ameni Azouz
Version: 1.0.0
"""

import argparse
import sys
import time
from typing import List, Dict
import signal

# Import scanner modules
from scanner.port_scanner import PortScanner
from scanner.utils import (
    validate_ip, validate_cidr, parse_port_range, 
    discover_hosts, format_scan_results, get_network_info
)
from scanner.exporter import ResultExporter
from scanner.banner import parse_banner


class NetworkScannerCLI:
    """Main CLI interface for the network scanner."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.scanner = None
        self.exporter = ResultExporter()
        self.setup_signal_handlers()
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            print("\n[!] Scan interrupted by user")
            print("[!] Exiting gracefully...")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create command line argument parser."""
        parser = argparse.ArgumentParser(
            description="Cyber Network Scanner - Educational Port Scanning Tool",
            epilog="SECURITY WARNING: Only scan networks you own or have permission to test.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            usage="""
python main.py [OPTIONS] TARGET

Examples:
  python main.py 192.168.1.1                           # Scan common ports
  python main.py 192.168.1.1 -p 80-443                  # Scan port range
  python main.py 192.168.1.0/24 --discover             # Discover hosts in subnet
  python main.py 192.168.1.1 -p 1-1000 -t 200         # Full scan with 200 threads
  python main.py 192.168.1.1 --full --export json     # Full scan with export
            """
        )
        
        # Target arguments
        parser.add_argument(
            'target',
            nargs='?',  # Make target optional
            help='Target IP address or CIDR network (e.g., 192.168.1.1 or 192.168.1.0/24)'
        )
        
        # Scanning options
        parser.add_argument(
            '-p', '--ports',
            default='common',
            help='Port range to scan (e.g., 80, 80-443, common, full) [default: common]'
        )
        
        parser.add_argument(
            '-t', '--threads',
            type=int,
            default=100,
            help='Number of concurrent threads [default: 100]'
        )
        
        parser.add_argument(
            '--timeout',
            type=float,
            default=3.0,
            help='Connection timeout in seconds [default: 3.0]'
        )
        
        parser.add_argument(
            '--stealth',
            type=float,
            default=0.0,
            help='Delay between scans in seconds for stealth [default: 0.0]'
        )
        
        # Scan types
        parser.add_argument(
            '--fast',
            action='store_true',
            help='Fast scan (common ports only)'
        )
        
        parser.add_argument(
            '--full',
            action='store_true',
            help='Full scan (ports 1-1000)'
        )
        
        parser.add_argument(
            '--discover',
            action='store_true',
            help='Host discovery mode (find alive hosts in subnet)'
        )
        
        # Output options
        parser.add_argument(
            '--export',
            choices=['json', 'txt', 'csv', 'all'],
            help='Export results to specified format'
        )
        
        parser.add_argument(
            '--no-banner',
            action='store_true',
            help='Skip banner grabbing'
        )
        
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Verbose output'
        )
        
        # Information options
        parser.add_argument(
            '--info',
            action='store_true',
            help='Show network information and exit'
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='Cyber Network Scanner v1.0.0'
        )
        
        return parser
    
    def validate_arguments(self, args) -> bool:
        """Validate command line arguments."""
        # Check if target is valid (only if target is provided)
        if args.target is not None:
            if not validate_ip(args.target) and not validate_cidr(args.target):
                print(f"[-] Invalid target: {args.target}")
                print("[-] Target must be a valid IP address or CIDR network")
                return False
        
        # Validate thread count
        if args.threads < 1 or args.threads > 1000:
            print("[-] Thread count must be between 1 and 1000")
            return False
        
        # Validate timeout
        if args.timeout < 0.1 or args.timeout > 30.0:
            print("[-] Timeout must be between 0.1 and 30.0 seconds")
            return False
        
        # Validate stealth delay
        if args.stealth < 0.0 or args.stealth > 10.0:
            print("[-] Stealth delay must be between 0.0 and 10.0 seconds")
            return False
        
        # Check for conflicting options
        if args.fast and args.full:
            print("[-] Cannot use both --fast and --full options")
            return False
        
        return True
    
    def get_port_range(self, args) -> tuple:
        """Get port range based on arguments."""
        if args.fast or args.ports == 'common':
            return 'common'
        elif args.full or args.ports == 'full':
            return (1, 1000)
        else:
            try:
                return parse_port_range(args.ports)
            except ValueError as e:
                print(f"[-] Invalid port range: {e}")
                return None
    
    def scan_single_target(self, target: str, args) -> Dict:
        """Scan a single target."""
        print(f"[*] Starting scan on {target}")
        print(f"[*] Scan type: {'Fast' if args.fast else 'Full' if args.full else 'Custom'}")
        print(f"[*] Threads: {args.threads}, Timeout: {args.timeout}s")
        if args.stealth > 0:
            print(f"[*] Stealth mode: {args.stealth}s delay")
        print("=" * 60)
        
        # Initialize scanner
        self.scanner = PortScanner(
            timeout=args.timeout,
            max_threads=args.threads,
            stealth_delay=args.stealth
        )
        
        # Get port range
        port_range = self.get_port_range(args)
        if port_range is None:
            return None
        
        # Perform scan
        start_time = time.time()
        
        try:
            if port_range == 'common':
                results = self.scanner.scan_common_ports(
                    target, 
                    grab_banner=not args.no_banner
                )
                results['scan_type'] = 'common_ports'
            else:
                start_port, end_port = port_range
                results = self.scanner.scan_port_range(
                    target, 
                    start_port, 
                    end_port,
                    grab_banner=not args.no_banner
                )
                results['scan_type'] = 'port_range'
            
            end_time = time.time()
            results['scan_duration'] = end_time - start_time
            
            # Display results
            if args.verbose or results['open_count'] > 0:
                print(format_scan_results(results))
            else:
                print(f"[*] Scan completed. No open ports found on {target}")
            
            return results
            
        except Exception as e:
            print(f"[-] Scan error: {e}")
            return None
    
    def discover_subnet(self, subnet: str, args) -> List[str]:
        """Discover alive hosts in subnet."""
        print(f"[*] Discovering hosts in {subnet}")
        print("=" * 60)
        
        try:
            alive_hosts = discover_hosts(
                subnet,
                max_threads=args.threads,
                timeout=args.timeout
            )
            
            if alive_hosts:
                print(f"\n[+] Found {len(alive_hosts)} alive hosts:")
                for host in sorted(alive_hosts):
                    print(f"    {host}")
            else:
                print(f"[*] No alive hosts found in {subnet}")
            
            return alive_hosts
            
        except Exception as e:
            print(f"[-] Host discovery error: {e}")
            return []
    
    def export_results(self, results: Dict, target: str, export_format: str):
        """Export scan results."""
        if not results:
            return
        
        try:
            if export_format == 'all':
                exported_files = self.exporter.export_all_formats(results, target)
                if exported_files:
                    print(f"\n[+] Results exported to {len(exported_files)} files:")
                    for file in exported_files:
                        print(f"    {file}")
            else:
                exported_file = ""
                if export_format == 'json':
                    exported_file = self.exporter.export_json(results, target)
                elif export_format == 'txt':
                    exported_file = self.exporter.export_txt(results, target)
                elif export_format == 'csv':
                    exported_file = self.exporter.export_csv(results, target)
                
                if exported_file:
                    print(f"\n[+] Results exported to: {exported_file}")
        
        except Exception as e:
            print(f"[-] Export error: {e}")
    
    def show_network_info(self):
        """Display network information."""
        print("NETWORK INFORMATION")
        print("=" * 60)
        
        try:
            info = get_network_info()
            
            print(f"Hostname: {info.get('hostname', 'Unknown')}")
            print(f"Local IP: {info.get('local_ip', 'Unknown')}")
            print(f"Platform: {info.get('platform', 'Unknown')}")
            print(f"Architecture: {info.get('architecture', 'Unknown')}")
            print(f"Private Network: {info.get('is_private', 'Unknown')}")
            print(f"Loopback: {info.get('is_loopback', 'Unknown')}")
            
        except Exception as e:
            print(f"[-] Error getting network info: {e}")
    
    def run(self, args=None):
        """Run the CLI application."""
        parser = self.create_parser()
        
        if args is None:
            args = parser.parse_args()
        
        # Show network info if requested
        if args.info:
            self.show_network_info()
            return
        
        # Validate arguments
        if not self.validate_arguments(args):
            sys.exit(1)
        
        # Check if target is provided when needed
        if not args.target and not args.info:
            print("[-] Target is required when not using --info")
            sys.exit(1)
        
        # Show disclaimer
        print("CYBER NETWORK SCANNER v1.0.0")
        print("=" * 60)
        print("SECURITY DISCLAIMER: This tool is for educational purposes only.")
        print("Only scan networks you own or have explicit permission to test.")
        print("Unauthorized scanning is illegal and unethical.")
        print("=" * 60)
        print()
        
        # Host discovery mode
        if args.discover:
            if not validate_cidr(args.target):
                print("[-] Host discovery requires a CIDR network (e.g., 192.168.1.0/24)")
                sys.exit(1)
            
            alive_hosts = self.discover_subnet(args.target, args)
            
            # Optionally scan discovered hosts
            if alive_hosts and input("\n[?] Scan discovered hosts? (y/N): ").lower() == 'y':
                all_results = []
                for host in alive_hosts:
                    print(f"\n[*] Scanning {host}")
                    results = self.scan_single_target(host, args)
                    if results:
                        all_results.append(results)
                
                # Export all results if requested
                if args.export and all_results:
                    if args.export == 'all':
                        self.exporter.export_multiple_targets(all_results, alive_hosts)
                    else:
                        for i, (host, results) in enumerate(zip(alive_hosts, all_results)):
                            self.export_results(results, host, args.export)
            
            return
        
        # Single target scan
        if validate_ip(args.target):
            results = self.scan_single_target(args.target, args)
            
            # Export results if requested
            if args.export and results:
                self.export_results(results, args.target, args.export)
        
        elif validate_cidr(args.target):
            # For CIDR networks, first discover hosts
            print(f"[*] Target is a network, performing host discovery first...")
            alive_hosts = self.discover_subnet(args.target, args)
            
            if alive_hosts:
                print(f"\n[*] Scanning discovered hosts...")
                all_results = []
                
                for host in alive_hosts:
                    results = self.scan_single_target(host, args)
                    if results:
                        all_results.append(results)
                
                # Export results
                if args.export and all_results:
                    if args.export == 'all':
                        self.exporter.export_multiple_targets(all_results, alive_hosts)
                    else:
                        for i, (host, results) in enumerate(zip(alive_hosts, all_results)):
                            self.export_results(results, host, args.export)
            else:
                print("[*] No hosts to scan")


def main():
    """Main entry point."""
    try:
        cli = NetworkScannerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
