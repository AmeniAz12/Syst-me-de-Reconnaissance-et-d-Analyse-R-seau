"""
Test suite for the Cyber Network Scanner.

This module contains comprehensive tests for all scanner components including:
- IP validation and utility functions
- Port scanning functionality
- Service detection
- Banner grabbing
- Export functionality

SECURITY NOTE: These tests use safe targets and local testing methods.
No actual network scanning of external systems is performed.
"""

import pytest
import unittest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock

# Import scanner modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.utils import (
    validate_ip, validate_port_range, validate_cidr,
    parse_port_range, get_local_ip, format_scan_results
)
from scanner.services import detect_service, get_service_info, is_high_risk_port
from scanner.banner import parse_banner, grab_banner, get_port_probe
from scanner.port_scanner import PortScanner
from scanner.exporter import ResultExporter


class TestUtils(unittest.TestCase):
    """Test utility functions."""
    
    def test_validate_ip(self):
        """Test IP address validation."""
        # Valid IPs
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("127.0.0.1"))
        self.assertTrue(validate_ip("::1"))  # IPv6
        
        # Invalid IPs
        self.assertFalse(validate_ip("256.1.1.1"))
        self.assertFalse(validate_ip("192.168.1"))
        self.assertFalse(validate_ip("invalid"))
        self.assertFalse(validate_ip(""))
        self.assertFalse(validate_ip("192.168.1.1.1"))
    
    def test_validate_port_range(self):
        """Test port range validation."""
        # Valid ranges
        self.assertTrue(validate_port_range(80, 80))
        self.assertTrue(validate_port_range(1, 65535))
        self.assertTrue(validate_port_range(20, 100))
        
        # Invalid ranges
        self.assertFalse(validate_port_range(0, 80))
        self.assertFalse(validate_port_range(80, 65536))
        self.assertFalse(validate_port_range(100, 50))  # Start > end
        self.assertFalse(validate_port_range(-1, 80))
    
    def test_validate_cidr(self):
        """Test CIDR validation."""
        # Valid CIDR
        self.assertTrue(validate_cidr("192.168.1.0/24"))
        self.assertTrue(validate_cidr("10.0.0.0/8"))
        self.assertTrue(validate_cidr("172.16.0.0/12"))
        
        # Invalid CIDR
        self.assertFalse(validate_cidr("192.168.1.0/33"))
        self.assertFalse(validate_cidr("invalid/24"))
        self.assertFalse(validate_cidr("192.168.1.0"))
        self.assertFalse(validate_cidr(""))
    
    def test_parse_port_range(self):
        """Test port range parsing."""
        # Single port
        self.assertEqual(parse_port_range("80"), (80, 80))
        self.assertEqual(parse_port_range("443"), (443, 443))
        
        # Port range
        self.assertEqual(parse_port_range("80-443"), (80, 443))
        self.assertEqual(parse_port_range("20-1000"), (20, 1000))
        
        # Invalid ranges
        with self.assertRaises(ValueError):
            parse_port_range("invalid")
        with self.assertRaises(ValueError):
            parse_port_range("80-443-1000")
        with self.assertRaises(ValueError):
            parse_port_range("1000-80")
    
    def test_get_local_ip(self):
        """Test local IP retrieval."""
        ip = get_local_ip()
        self.assertTrue(validate_ip(ip))
        self.assertNotEqual(ip, "127.0.0.1")  # Should not be loopback
    
    def test_format_scan_results(self):
        """Test scan results formatting."""
        results = {
            'target': '192.168.1.1',
            'total_scanned': 100,
            'open_count': 5,
            'closed_count': 90,
            'filtered_count': 5,
            'open_ports': [
                {'port': 80, 'service': 'http', 'banner': 'Apache/2.4.41'},
                {'port': 443, 'service': 'https', 'banner': ''}
            ],
            'filtered_ports': [
                {'port': 22, 'service': 'unknown', 'banner': ''}
            ]
        }
        
        formatted = format_scan_results(results)
        
        self.assertIn("192.168.1.1", formatted)
        self.assertIn("Total ports scanned: 100", formatted)
        self.assertIn("Open ports: 5", formatted)
        self.assertIn("Port    80/http", formatted)


class TestServices(unittest.TestCase):
    """Test service detection functionality."""
    
    def test_detect_service(self):
        """Test service detection by port."""
        self.assertEqual(detect_service(80), "http")
        self.assertEqual(detect_service(443), "https")
        self.assertEqual(detect_service(22), "ssh")
        self.assertEqual(detect_service(21), "ftp")
        self.assertEqual(detect_service(3306), "mysql")
        self.assertEqual(detect_service(9999), "unknown")  # Unknown port
        self.assertEqual(detect_service(0), "invalid")  # Invalid port
        self.assertEqual(detect_service(65536), "invalid")  # Invalid port
    
    def test_get_service_info(self):
        """Test service information retrieval."""
        http_info = get_service_info("http")
        
        self.assertIn("description", http_info)
        self.assertIn("common_vulnerabilities", http_info)
        self.assertIn("security_considerations", http_info)
        self.assertEqual(http_info["description"], "Hypertext Transfer Protocol - Web server")
        
        # Test unknown service
        unknown_info = get_service_info("unknown_service")
        self.assertEqual(unknown_info["description"], "unknown_service service")
    
    def test_is_high_risk_port(self):
        """Test high-risk port identification."""
        self.assertTrue(is_high_risk_port(23))   # telnet
        self.assertTrue(is_high_risk_port(445))  # smb
        self.assertTrue(is_high_risk_port(3389)) # rdp
        
        self.assertFalse(is_high_risk_port(80))   # http
        self.assertFalse(is_high_risk_port(443))  # https
        self.assertFalse(is_high_risk_port(9999)) # unknown


class TestBanner(unittest.TestCase):
    """Test banner grabbing functionality."""
    
    def test_get_port_probe(self):
        """Test port probe generation."""
        # HTTP ports
        self.assertIn("GET / HTTP/1.1", get_port_probe(80))
        self.assertIn("GET / HTTP/1.1", get_port_probe(443))
        
        # FTP
        self.assertEqual(get_port_probe(21), "")
        
        # SSH
        self.assertEqual(get_port_probe(22), "")
        
        # SMTP
        self.assertIn("EHLO", get_port_probe(25))
    
    def test_parse_banner(self):
        """Test banner parsing."""
        # HTTP banner
        http_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html"
        parsed = parse_banner(http_banner, 80)
        
        self.assertEqual(parsed['service'], 'Apache HTTP Server')
        self.assertEqual(parsed['version'], '2.4.41')
        self.assertIn('Apache/2.4.41', parsed['additional_info'])
        
        # SSH banner
        ssh_banner = "SSH-2.0-OpenSSH_8.2p1"
        parsed = parse_banner(ssh_banner, 22)
        
        self.assertEqual(parsed['service'], 'SSH')
        self.assertEqual(parsed['version'], '2.0-OpenSSH_8.2p1')
        
        # Empty banner
        parsed = parse_banner("", 80)
        self.assertEqual(parsed['service'], 'unknown')
        self.assertEqual(parsed['version'], 'unknown')
    
    @patch('socket.socket')
    def test_grab_banner(self, mock_socket):
        """Test banner grabbing with mock."""
        # Setup mock
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.recv.return_value = b"Test Server 1.0"
        
        # Test banner grabbing
        banner = grab_banner("127.0.0.1", 80)
        
        self.assertEqual(banner, "Test Server 1.0")
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 80))
        mock_sock.close.assert_called_once()


class TestPortScanner(unittest.TestCase):
    """Test port scanner functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = PortScanner(timeout=1.0, max_threads=10)
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        self.assertEqual(self.scanner.timeout, 1.0)
        self.assertEqual(self.scanner.max_threads, 10)
        self.assertEqual(self.scanner.stealth_delay, 0.0)
        self.assertEqual(len(self.scanner.open_ports), 0)
    
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        """Test scanning an open port."""
        # Setup mock for open port
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0  # Success
        
        result = self.scanner.scan_port("127.0.0.1", 80)
        
        self.assertEqual(result['status'], 'open')
        self.assertEqual(result['port'], 80)
        mock_sock.close.assert_called_once()
    
    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        """Test scanning a closed port."""
        # Setup mock for closed port
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1  # Connection refused
        
        result = self.scanner.scan_port("127.0.0.1", 81)
        
        self.assertEqual(result['status'], 'closed')
        self.assertEqual(result['port'], 81)
        mock_sock.close.assert_called_once()
    
    def test_scan_common_ports_invalid_ip(self):
        """Test scanning with invalid IP."""
        with self.assertRaises(ValueError):
            self.scanner.scan_common_ports("invalid.ip.address")
    
    def test_scan_port_range_invalid_range(self):
        """Test scanning with invalid port range."""
        with self.assertRaises(ValueError):
            self.scanner.scan_port_range("127.0.0.1", 1000, 80)  # Start > end


class TestExporter(unittest.TestCase):
    """Test result export functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.exporter = ResultExporter(output_dir=self.temp_dir)
        
        # Sample scan results
        self.sample_results = {
            'target': '192.168.1.1',
            'total_scanned': 100,
            'open_count': 2,
            'closed_count': 95,
            'filtered_count': 3,
            'open_ports': [
                {'port': 80, 'status': 'open', 'service': 'http', 'banner': 'Apache/2.4.41'},
                {'port': 443, 'status': 'open', 'service': 'https', 'banner': ''}
            ],
            'closed_ports': [],
            'filtered_ports': []
        }
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up temporary files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_export_json(self):
        """Test JSON export."""
        filepath = self.exporter.export_json(self.sample_results, "192.168.1.1")
        
        self.assertTrue(os.path.exists(filepath))
        
        # Verify JSON content
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.assertIn('scan_metadata', data)
        self.assertIn('scan_results', data)
        self.assertEqual(data['scan_results']['target'], '192.168.1.1')
        self.assertEqual(data['scan_results']['open_count'], 2)
    
    def test_export_txt(self):
        """Test text export."""
        filepath = self.exporter.export_txt(self.sample_results, "192.168.1.1")
        
        self.assertTrue(os.path.exists(filepath))
        
        # Verify text content
        with open(filepath, 'r') as f:
            content = f.read()
        
        self.assertIn("CYBER NETWORK SCANNER", content)
        self.assertIn("192.168.1.1", content)
        self.assertIn("Open Ports: 2", content)
        self.assertIn("Port 80/http", content)
    
    def test_export_csv(self):
        """Test CSV export."""
        filepath = self.exporter.export_csv(self.sample_results, "192.168.1.1")
        
        self.assertTrue(os.path.exists(filepath))
        
        # Verify CSV content
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # Header
        self.assertIn("Target,Port,Status,Service,Banner", lines[0])
        
        # Data rows
        self.assertIn("192.168.1.1,80,open,http", lines[1])
        self.assertIn("192.168.1.1,443,open,https", lines[2])
    
    def test_calculate_success_rate(self):
        """Test success rate calculation."""
        # Test with sample results
        success_rate = self.exporter.calculate_success_rate(self.sample_results)
        expected = ((2 + 95) / 100) * 100  # 97%
        self.assertEqual(success_rate, expected)
        
        # Test with empty results
        empty_results = {'total_scanned': 0, 'open_count': 0, 'closed_count': 0}
        success_rate = self.exporter.calculate_success_rate(empty_results)
        self.assertEqual(success_rate, 0.0)
    
    def test_generate_security_recommendations(self):
        """Test security recommendation generation."""
        recommendations = self.exporter.generate_security_recommendations(self.sample_results)
        
        self.assertIsInstance(recommendations, list)
        self.assertTrue(len(recommendations) > 0)
        
        # Check for specific recommendations
        rec_text = ' '.join(recommendations)
        self.assertIn("firewall", rec_text.lower())
    
    def test_export_all_formats(self):
        """Test exporting to all formats."""
        exported_files = self.exporter.export_all_formats(self.sample_results, "192.168.1.1")
        
        self.assertEqual(len(exported_files), 3)  # JSON, TXT, CSV
        
        for filepath in exported_files:
            self.assertTrue(os.path.exists(filepath))
            self.assertTrue(filepath.endswith(('.json', '.txt', '.csv')))


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete scanner."""
    
    def test_complete_scan_workflow(self):
        """Test complete scan workflow with mocked components."""
        # This would test the integration of all components
        # For now, we'll test the basic workflow structure
        
        # Test that all modules can be imported
        from scanner import port_scanner, services, banner, utils, exporter
        
        # Test that classes can be instantiated
        scanner = PortScanner()
        exporter = ResultExporter()
        
        self.assertIsNotNone(scanner)
        self.assertIsNotNone(exporter)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [TestUtils, TestServices, TestBanner, TestPortScanner, TestExporter, TestIntegration]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
