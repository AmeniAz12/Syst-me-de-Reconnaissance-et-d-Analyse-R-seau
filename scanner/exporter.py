"""
Exporter Module - Save scan results to various formats.

This module provides functionality to export scan results to different file formats
including JSON and plain text. This is essential for documentation and analysis
of security assessments.

SECURITY CONCEPTS:
- Result Documentation: Keeping records of security assessments for analysis
  and compliance purposes.
- Data Persistence: Saving scan results for later analysis and comparison.
- Report Generation: Creating professional security reports.
- Evidence Collection: Maintaining audit trails of security testing activities.

NOTE: Exported data may contain sensitive information about network infrastructure.
Handle exported files with appropriate security measures.
"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any
import os


class ResultExporter:
    """Export scan results to various formats."""
    
    def __init__(self, output_dir: str = "scan_results"):
        """
        Initialize the exporter.
        
        Args:
            output_dir: Directory to save exported files
        """
        self.output_dir = output_dir
        self.ensure_output_dir()
    
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_filename(self, target: str, format_type: str) -> str:
        """
        Generate filename for exported results.
        
        Args:
            target: Target IP or network
            format_type: File format (json, txt, csv)
            
        Returns:
            Generated filename
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Clean target name for filename
        clean_target = target.replace('/', '_').replace('.', '_')
        return f"scan_{clean_target}_{timestamp}.{format_type}"
    
    def export_json(self, results: Dict, target: str = None) -> str:
        """
        Export scan results to JSON format.
        
        Args:
            results: Scan results dictionary
            target: Target IP or network (for filename)
            
        Returns:
            Path to exported file
        """
        if target is None:
            target = results.get('target', 'unknown')
        
        filename = self.generate_filename(target, 'json')
        filepath = os.path.join(self.output_dir, filename)
        
        # Prepare data for JSON export
        export_data = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scanner': 'Cyber Network Scanner v1.0',
                'scan_type': results.get('scan_type', 'port_scan')
            },
            'scan_results': results,
            'summary': {
                'total_ports_scanned': results.get('total_scanned', 0),
                'open_ports': results.get('open_count', 0),
                'closed_ports': results.get('closed_count', 0),
                'filtered_ports': results.get('filtered_count', 0),
                'scan_success_rate': self.calculate_success_rate(results)
            }
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"[+] Results exported to: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"[-] Error exporting to JSON: {e}")
            return ""
    
    def export_txt(self, results: Dict, target: str = None) -> str:
        """
        Export scan results to text format.
        
        Args:
            results: Scan results dictionary
            target: Target IP or network (for filename)
            
        Returns:
            Path to exported file
        """
        if target is None:
            target = results.get('target', 'unknown')
        
        filename = self.generate_filename(target, 'txt')
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # Write header
                f.write("=" * 80 + "\n")
                f.write("CYBER NETWORK SCANNER - SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Write metadata
                f.write("SCAN METADATA:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scanner: Cyber Network Scanner v1.0\n")
                f.write(f"Scan Type: {results.get('scan_type', 'port_scan')}\n\n")
                
                # Write summary
                f.write("SCAN SUMMARY:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Total Ports Scanned: {results.get('total_scanned', 0)}\n")
                f.write(f"Open Ports: {results.get('open_count', 0)}\n")
                f.write(f"Closed Ports: {results.get('closed_count', 0)}\n")
                f.write(f"Filtered Ports: {results.get('filtered_count', 0)}\n")
                f.write(f"Success Rate: {self.calculate_success_rate(results):.1f}%\n\n")
                
                # Write open ports
                open_ports = results.get('open_ports', [])
                if open_ports:
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 40 + "\n")
                    for port_info in sorted(open_ports, key=lambda x: x['port']):
                        f.write(f"Port {port_info['port']}/{port_info['service']}\n")
                        if port_info.get('banner'):
                            f.write(f"  Banner: {port_info['banner']}\n")
                    f.write("\n")
                
                # Write filtered ports (limited)
                filtered_ports = results.get('filtered_ports', [])
                if filtered_ports:
                    f.write("FILTERED PORTS:\n")
                    f.write("-" * 40 + "\n")
                    for port_info in sorted(filtered_ports, key=lambda x: x['port']):
                        f.write(f"Port {port_info['port']}\n")
                    f.write("\n")
                
                # Write security recommendations
                f.write("SECURITY RECOMMENDATIONS:\n")
                f.write("-" * 40 + "\n")
                recommendations = self.generate_security_recommendations(results)
                for rec in recommendations:
                    f.write(f"• {rec}\n")
                f.write("\n")
                
                # Write disclaimer
                f.write("DISCLAIMER:\n")
                f.write("-" * 40 + "\n")
                f.write("This scan was performed for educational purposes only.\n")
                f.write("Only scan networks you own or have explicit permission to test.\n")
                f.write("Unauthorized scanning is illegal and unethical.\n")
            
            print(f"[+] Results exported to: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"[-] Error exporting to TXT: {e}")
            return ""
    
    def export_csv(self, results: Dict, target: str = None) -> str:
        """
        Export scan results to CSV format.
        
        Args:
            results: Scan results dictionary
            target: Target IP or network (for filename)
            
        Returns:
            Path to exported file
        """
        if target is None:
            target = results.get('target', 'unknown')
        
        filename = self.generate_filename(target, 'csv')
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['Target', 'Port', 'Status', 'Service', 'Banner', 'Timestamp'])
                
                # Write open ports
                open_ports = results.get('open_ports', [])
                for port_info in open_ports:
                    writer.writerow([
                        target,
                        port_info['port'],
                        port_info['status'],
                        port_info['service'],
                        port_info.get('banner', ''),
                        datetime.now().isoformat()
                    ])
                
                # Write closed ports
                closed_ports = results.get('closed_ports', [])
                for port_info in closed_ports:
                    writer.writerow([
                        target,
                        port_info['port'],
                        port_info['status'],
                        port_info['service'],
                        '',
                        datetime.now().isoformat()
                    ])
                
                # Write filtered ports
                filtered_ports = results.get('filtered_ports', [])
                for port_info in filtered_ports:
                    writer.writerow([
                        target,
                        port_info['port'],
                        port_info['status'],
                        port_info['service'],
                        '',
                        datetime.now().isoformat()
                    ])
            
            print(f"[+] Results exported to: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"[-] Error exporting to CSV: {e}")
            return ""
    
    def export_all_formats(self, results: Dict, target: str = None) -> List[str]:
        """
        Export results to all available formats.
        
        Args:
            results: Scan results dictionary
            target: Target IP or network
            
        Returns:
            List of exported file paths
        """
        exported_files = []
        
        # Export to all formats
        json_file = self.export_json(results, target)
        if json_file:
            exported_files.append(json_file)
        
        txt_file = self.export_txt(results, target)
        if txt_file:
            exported_files.append(txt_file)
        
        csv_file = self.export_csv(results, target)
        if csv_file:
            exported_files.append(csv_file)
        
        return exported_files
    
    def calculate_success_rate(self, results: Dict) -> float:
        """
        Calculate scan success rate.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Success rate as percentage
        """
        total = results.get('total_scanned', 0)
        if total == 0:
            return 0.0
        
        open_count = results.get('open_count', 0)
        closed_count = results.get('closed_count', 0)
        
        # Success rate = (open + closed) / total * 100
        # (filtered ports indicate scanning issues)
        success_rate = ((open_count + closed_count) / total) * 100
        return success_rate
    
    def generate_security_recommendations(self, results: Dict) -> List[str]:
        """
        Generate security recommendations based on scan results.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        open_ports = results.get('open_ports', [])
        
        if not open_ports:
            recommendations.append("No open ports detected - system appears secure")
            return recommendations
        
        # Analyze open ports
        port_numbers = [p['port'] for p in open_ports]
        
        # Check for risky ports
        risky_ports = {
            23: "Telnet - Replace with SSH, disable if not needed",
            21: "FTP - Use SFTP instead, disable anonymous access",
            135: "RPC - Restrict access, apply latest patches",
            139: "NetBIOS - Disable if not needed, use firewall",
            445: "SMB - Disable SMBv1, restrict network access",
            3389: "RDP - Enable NLA, use strong passwords",
            5900: "VNC - Use encryption, strong authentication"
        }
        
        for port in port_numbers:
            if port in risky_ports:
                recommendations.append(f"Port {port}: {risky_ports[port]}")
        
        # General recommendations
        if 80 in port_numbers and 443 not in port_numbers:
            recommendations.append("Port 80 (HTTP) open but 443 (HTTPS) not detected - Consider implementing HTTPS")
        
        if any(p in port_numbers for p in [3306, 5432, 1433]):
            recommendations.append("Database ports open - Restrict to trusted networks only")
        
        if len(open_ports) > 10:
            recommendations.append(f"Many open ports ({len(open_ports)}) - Review and close unnecessary services")
        
        # Add generic recommendations
        recommendations.extend([
            "Implement firewall rules to restrict access",
            "Keep all services updated with latest security patches",
            "Monitor logs for suspicious activity",
            "Regularly scan for vulnerabilities"
        ])
        
        return recommendations
    
    def export_multiple_targets(self, all_results: List[Dict], targets: List[str]) -> str:
        """
        Export results for multiple targets to a single file.
        
        Args:
            all_results: List of scan results dictionaries
            targets: List of target IPs/networks
            
        Returns:
            Path to exported file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"multi_target_scan_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        export_data = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'targets': targets,
                'scanner': 'Cyber Network Scanner v1.0',
                'scan_type': 'multi_target_scan'
            },
            'individual_results': dict(zip(targets, all_results)),
            'summary': {
                'total_targets': len(targets),
                'total_open_ports': sum(r.get('open_count', 0) for r in all_results),
                'total_ports_scanned': sum(r.get('total_scanned', 0) for r in all_results)
            }
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"[+] Multi-target results exported to: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"[-] Error exporting multi-target results: {e}")
            return ""
