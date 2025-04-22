#!/usr/bin/env python3
# network_monitor.py - Main entry point for terminal-based network monitoring

import argparse
import getpass
import json
import logging
import os
import sys
import time
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from config import settings
from core.scanner import NetworkScanner
from core.detector import ThreatDetector
from core.fingerprint import DeviceFingerprinter
from core.device_identifier import DeviceIdentifier
from core.models import Device, PortInfo, ThreatAlert, VulnerabilityReport
from config import vendors
from utils.helpers import save_results, load_whitelist, save_whitelist, analyze_vulnerability_severity
from utils.network import get_my_ip_address, get_my_mac_address, get_network_cidr, get_default_gateway

# Set up colorful terminal output if available
try:
    from colorama import init, Fore, Back, Style
    init()  # Initialize colorama
    COLOR_AVAILABLE = True
except ImportError:
    # Create dummy color constants if colorama not available
    class DummyColors:
        def __getattr__(self, name):
            return ""
    Fore = DummyColors()
    Back = DummyColors()
    Style = DummyColors()
    COLOR_AVAILABLE = False

class NetworkMonitorCLI:
    """Terminal-based Network Monitor with enhanced detection capabilities"""
    
    def __init__(self):
        """Initialize the application"""
        # Process command line arguments
        self.args = self._parse_arguments()
        
        # Set up logging first
        self._setup_logging()

        # Initialized state values
        self.scanner = NetworkScanner()
        self.detector = ThreatDetector()
        self.fingerprinter = DeviceFingerprinter()
        self.device_identifier = DeviceIdentifier()
        self.my_ip = get_my_ip_address()
        self.my_mac = get_my_mac_address()
        self.my_gateway = get_default_gateway()
        self.network_range = self.args.network or settings.DEFAULT_NETWORK_RANGE
        self.output_dir = self.args.output or settings.OUTPUT_DIR
        
        # Auto-detect network if not specified
        if self.network_range == settings.DEFAULT_NETWORK_RANGE:
            detected_network = get_network_cidr()
            if detected_network:
                self.network_range = detected_network
                self.logger.info(f"Auto-detected network range: {self.network_range}")
        
        # Load existing data
        self._load_data()
                
        # Log initialization details
        self._log_system_info()
    
    def _parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="Enhanced Network Monitoring and Threat Detection",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Basic options
        parser.add_argument('-n', '--network', help='Network range to scan (CIDR notation)', default=None)
        parser.add_argument('-o', '--output', help='Output directory for results', default=None)
        parser.add_argument('-p', '--port', type=int, help='Port to use for operation (used for security validation)', default=None)
        parser.add_argument('-i', '--interval', type=int, help='Scan interval in seconds', default=settings.SCAN_INTERVAL)
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        
        # Scan modes
        mode_group = parser.add_argument_group('Scan Modes')
        mode_group.add_argument('--monitor', action='store_true', help='Run continuous monitoring')
        mode_group.add_argument('--quick-scan', action='store_true', help='Perform a quick scan and exit')
        mode_group.add_argument('--threat-scan', action='store_true', help='Focus on threat detection')
        mode_group.add_argument('--vuln-scan', action='store_true', help='Perform vulnerability scanning')
        mode_group.add_argument('--full-scan', action='store_true', help='Run a comprehensive scan with all detection features')
        
        # Management options
        manage_group = parser.add_argument_group('Management')
        manage_group.add_argument('--add-to-whitelist', metavar='ADDRESS', help='Add IP or MAC to whitelist')
        manage_group.add_argument('--show-whitelist', action='store_true', help='Show current whitelist')
        manage_group.add_argument('--show-device', metavar='IP', help='Show detailed info for a specific device')
        manage_group.add_argument('--config-setup', action='store_true', help='Set up security configuration for authorized access')
        
        # Threat detection options
        threat_group = parser.add_argument_group('Threat Detection')
        threat_group.add_argument('--dhcp-detect', action='store_true', help='Detect DHCP servers')
        threat_group.add_argument('--arp-detect', action='store_true', help='Detect ARP spoofing')
        threat_group.add_argument('--dns-detect', action='store_true', help='Detect DNS spoofing')
        threat_group.add_argument('--port-scan-detect', action='store_true', help='Detect port scanning activity')
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('--no-color', action='store_true', help='Disable colored output')
        output_group.add_argument('--json', action='store_true', help='Output in JSON format where applicable')
        
        return parser.parse_args()
    
    def _setup_logging(self):
        """Set up logging based on verbosity level"""
        log_level = logging.DEBUG if self.args.verbose else logging.INFO
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(f"logs/network_monitor_{datetime.now().strftime('%Y%m%d')}.log"),
                logging.StreamHandler() if self.args.verbose else logging.NullHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Logging initialized")
    
    def _load_data(self):
        """Load existing data from files"""
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Load whitelist
        self.whitelist = load_whitelist(self.output_dir)
        self.logger.info(f"Loaded whitelist: {len(self.whitelist.get('mac_addresses', []))} MAC addresses, {len(self.whitelist.get('ip_addresses', []))} IP addresses")
        
        # Initialize device tracking
        self.known_devices = {}
        self.threats = []
        
        # Try to load most recent scan if available
        scan_files = self._get_recent_scans()
        if scan_files:
            try:
                import json
                with open(os.path.join(self.output_dir, scan_files[0])) as f:
                    last_scan = json.load(f)
                    
                self.logger.info(f"Loaded previous scan from {scan_files[0]}")
                
                # Convert to device objects
                for device_data in last_scan.get('devices', []):
                    ip = device_data.get('ip_address')
                    if ip:
                        self.known_devices[ip] = Device(**device_data)
            except Exception as e:
                self.logger.error(f"Failed to load previous scan: {str(e)}")
        
    def _get_recent_scans(self, limit: int = 1):
        """Get list of recent scan files"""
        from utils.helpers import get_file_list
        return get_file_list(self.output_dir, prefix="network_scan", suffix=".json", max_files=limit)
    
    def _log_system_info(self):
        """Log system and network information"""
        self.logger.info(f"System: {platform.system()} {platform.release()}")
        self.logger.info(f"My IP: {self.my_ip}, My MAC: {self.my_mac}")
        self.logger.info(f"Gateway: {self.my_gateway}")
        self.logger.info(f"Network range: {self.network_range}")
        
        # Log color support for terminal output
        if self.args.no_color:
            self.logger.info("Color output disabled by user")
        else:
            self.logger.info(f"Color support: {'Available' if COLOR_AVAILABLE else 'Not available'}")
    
    def _get_security_config_path(self) -> Path:
        """Get the path to the security configuration file"""
        # Use Path to handle directory traversal properly
        script_dir = Path(__file__).parent
        config_dir = script_dir / "config"
        config_dir.mkdir(exist_ok=True)
        return config_dir / "security_config.json"
    
    def _setup_security_config(self):
        """Set up security configuration for the network monitor"""
        print("\nSECURITY CONFIGURATION SETUP")
        print("=" * 60)
        print("This tool will create a security configuration file that restricts")
        print("access to only authorized machines. This helps ensure the network")
        print("monitoring tool can't be used on unauthorized systems.")
        print("\nYou'll need to provide the following information:")
        
        # Get current IP and MAC for reference
        print(f"\nCurrent system information (for reference):")
        print(f"IP Address: {self.my_ip}")
        print(f"MAC Address: {self.my_mac}")
        
        # Collect authorized IP address
        auth_ip = input("\nEnter authorized IP address [default: current IP]: ").strip()
        if not auth_ip:
            auth_ip = self.my_ip
            print(f"Using current IP: {auth_ip}")
            
        # Collect authorized MAC address
        auth_mac = input("Enter authorized MAC address [default: current MAC]: ").strip()
        if not auth_mac:
            auth_mac = self.my_mac
            print(f"Using current MAC: {auth_mac}")
            
        # Ask about token requirement
        require_token = input("Require access token for additional security? (y/n) [default: n]: ").strip().lower()
        require_token = require_token == 'y'
        
        # Get token if required
        access_token = None
        if require_token:
            while True:
                access_token = getpass.getpass("Enter access token (will not be displayed): ")
                confirm_token = getpass.getpass("Confirm access token: ")
                
                if access_token == confirm_token:
                    break
                print("Tokens do not match. Please try again.")
        
        # Ask for authorized port
        auth_port = input("Enter authorized port (leave blank to allow any port) [default: any]: ").strip()
        if auth_port:
            try:
                auth_port = int(auth_port)
                print(f"Port {auth_port} will be required for access")
            except ValueError:
                print("Invalid port number. Using default (any port allowed).")
                auth_port = None
        else:
            auth_port = None
            print("No port restriction configured. Any port allowed.")
            
        # Create config object
        config = {
            "authorized_ip": auth_ip,
            "authorized_mac": auth_mac,
            "require_token": require_token,
            "authorized_port": auth_port
        }
        
        if require_token and access_token:
            config["access_token"] = access_token
            
        # Save config
        config_path = self._get_security_config_path()
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"\nSecurity configuration saved to {config_path}")
        print("This machine is now authorized to run the network monitoring tool.")
        print("=" * 60)

    def _validate_security_config(self) -> bool:
        """Validate the current machine against security configuration"""
        config_path = self._get_security_config_path()
        
        # If no config exists, allow access (not restricted yet)
        if not config_path.exists():
            self.logger.warning("No security configuration found. Access not restricted.")
            print("No security configuration found. Access not restricted.")
            return True
            
        try:
            # Load the config
            with open(config_path, 'r') as f:
                config = json.load(f)
                
            # Check IP and MAC address
            ip_match = config.get("authorized_ip") == self.my_ip
            mac_match = config.get("authorized_mac") == self.my_mac
            
            # If IP and MAC don't match, deny access
            if not (ip_match and mac_match):
                self.logger.warning("IP or MAC address doesn't match authorized values")
                if COLOR_AVAILABLE and not self.args.no_color:
                    print(f"\n{Fore.RED}[ACCESS DENIED]{Style.RESET_ALL}")
                else:
                    print("\n[ACCESS DENIED]")
                print(f"\nIP: {self.my_ip}, MAC: {self.my_mac} Are not authorized")
                return False
            
            # Check port restriction if configured
            if config.get("authorized_port") is not None:
                authorized_port = config.get("authorized_port")
                # Get the current listening port (implementation depends on how the tool is configured)
                current_port = self.args.port if hasattr(self.args, 'port') else None
                
                if current_port is None:
                    # If port argument wasn't provided but is required, deny access
                    self.logger.warning(f"Port is required but not specified")
                    if COLOR_AVAILABLE and not self.args.no_color:
                        print(f"\n{Fore.RED}[ACCESS DENIED]{Style.RESET_ALL}")
                    else:
                        print("\n[ACCESS DENIED]")
                    print(f"\nPort is required but not specified")
                    return False
                
                if current_port != authorized_port:
                    self.logger.warning(f"Port {current_port} doesn't match authorized port")
                    if COLOR_AVAILABLE and not self.args.no_color:
                        print(f"\n{Fore.RED}[ACCESS DENIED]{Style.RESET_ALL}")
                    else:
                        print("\n[ACCESS DENIED]")
                    print(f"\nPort {current_port} doesn't match authorized port")
                    return False
                
                self.logger.info(f"Port validation successful: {current_port}")
                
            # Check if token is required
            if config.get("require_token", False):
                print("\nAccess token required for this installation.")
                token = getpass.getpass("Enter access token: ")
                
                # Compare token
                if token != config.get("access_token", ""):
                    self.logger.warning("Invalid access token provided")
                    if COLOR_AVAILABLE and not self.args.no_color:
                        print(f"\n{Fore.RED}[ACCESS DENIED]{Style.RESET_ALL}")
                    else:
                        print("\n[ACCESS DENIED]")
                    print(f"\nInvalid access token")  
                    return False
            
            # If we get here, all checks passed
            self.logger.info("Security validation successful")
            return True
                
        except Exception as e:
            self.logger.error(f"Error validating security configuration: {str(e)}")
            # Default to allowing access if there's an error reading config
            return True
    
    def run(self):
        """Main entry point to run the monitor"""
        # Print header
        self._print_header()
        
        # Handle management operations
        if self.args.config_setup:
            self._setup_security_config()
            return
            
        if self.args.add_to_whitelist:
            self._add_to_whitelist(self.args.add_to_whitelist)
            return
            
        if self.args.show_whitelist:
            self._show_whitelist()
            return
            
        if self.args.show_device:
            self._show_device(self.args.show_device)
            return
            
        # Check security configuration
        if not self._validate_security_config():
            return
        
        # Handle specific detection options
        if self.args.dhcp_detect:
            self._run_dhcp_detection()
            return
            
        if self.args.arp_detect:
            self._run_arp_detection()
            return
            
        if self.args.dns_detect:
            self._run_dns_detection()
            return
            
        if self.args.port_scan_detect:
            self._run_port_scan_detection()
            return
        
        # Handle different scan modes
        if self.args.quick_scan:
            self._run_quick_scan()
            return
            
        if self.args.threat_scan:
            self._run_threat_scan()
            return
            
        if self.args.vuln_scan:
            self._run_vulnerability_scan()
            return
            
        if self.args.full_scan:
            self._run_full_scan()
            return
            
        if self.args.monitor:
            self._run_continuous_monitoring()
            return
            
        # Default behavior if no specific mode is selected
        self._run_quick_scan()
    
    def _print_header(self):
        """Print application header"""
        if self.args.json:
            return
        
        header = f"""
{'=' * 70}
   NETWORK MONITORING SYSTEM {'(COLOR ENABLED)' if COLOR_AVAILABLE and not self.args.no_color else ''}
   Real-time Network Security & Device Detection
{'=' * 70}
"""
        if COLOR_AVAILABLE and not self.args.no_color:
            print(Fore.CYAN + header + Style.RESET_ALL)
        else:
            print(header)
    
    def _add_to_whitelist(self, address: str):
        """Add an IP or MAC address to the whitelist"""
        # Determine if the input is an IP or MAC address
        import re
        
        # Simple check for MAC format
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        # Simple check for IP format
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        if mac_pattern.match(address):
            # It's a MAC address
            address = address.upper()  # Normalize to uppercase
            if address not in self.whitelist['mac_addresses']:
                self.whitelist['mac_addresses'].append(address)
                save_whitelist(self.whitelist, self.output_dir)
                print(f"Added MAC address {address} to whitelist")
            else:
                print(f"MAC address {address} already in whitelist")
        elif ip_pattern.match(address):
            # It's an IP address
            if address not in self.whitelist['ip_addresses']:
                self.whitelist['ip_addresses'].append(address)
                save_whitelist(self.whitelist, self.output_dir)
                print(f"Added IP address {address} to whitelist")
            else:
                print(f"IP address {address} already in whitelist")
        else:
            print(f"Invalid address format: {address}")
            print("Please use format XX:XX:XX:XX:XX:XX for MAC or XXX.XXX.XXX.XXX for IP")
    
    def _show_whitelist(self):
        """Show the current whitelist"""
        if self.args.json:
            import json
            print(json.dumps(self.whitelist, indent=2))
            return
            
        print("\nCURRENT WHITELIST")
        print("=" * 50)
        
        if not self.whitelist['mac_addresses'] and not self.whitelist['ip_addresses']:
            print("Whitelist is empty")
            return
            
        if self.whitelist['mac_addresses']:
            print("\nMAC Addresses:")
            for mac in sorted(self.whitelist['mac_addresses']):
                print(f"  {mac}")
                
        if self.whitelist['ip_addresses']:
            print("\nIP Addresses:")
            for ip in sorted(self.whitelist['ip_addresses']):
                print(f"  {ip}")
                
        print("=" * 50)
    
    def _show_device(self, ip: str):
        """Show detailed information for a specific device"""
        # First check if we have this device in known devices
        device = self.known_devices.get(ip)
        
        if not device:
            print(f"Device {ip} not found in known devices. Scanning now...")
            # Scan the specific IP
            host_info = self.scanner.get_host_info(ip)
            
            if host_info['status'] == 'down':
                print(f"Device {ip} is not reachable")
                return
                
            # Get fingerprint information
            fingerprint = self.fingerprinter.os_fingerprint(ip)
            
            # Get vendor information
            vendor = None
            if host_info.get('mac_address'):
                vendor = self.fingerprinter.get_vendor_from_mac(host_info['mac_address'])
                
            # Create temporary device object
            from core.models import Device, PortInfo
            from datetime import datetime
            
            ports = []
            for port_dict in host_info.get('ports', []):
                ports.append(
                    PortInfo(port=port_dict.get('port'),
                             protocol=port_dict.get('protocol', 'tcp'),
                             service=port_dict.get('service', 'unknown'),
                             version=port_dict.get('version', ''),
                             cpe=port_dict.get('cpe', '')))
                             
            device = Device(
                ip_address=ip,
                status=host_info.get('status', 'unknown'),
                hostname=host_info.get('hostname'),
                mac_address=host_info.get('mac_address'),
                vendor=vendor,
                os=host_info.get('os') or str(fingerprint.get('data', {})),
                ports=ports,
                device_type=self._determine_device_type(host_info, fingerprint),
                confidence=fingerprint.get('confidence', 'low'),
                is_new=True,
                is_authorized=self._check_authorization(ip, host_info.get('mac_address')),
                whitelisted=self._check_authorization(ip, host_info.get('mac_address')),
                last_seen=datetime.now().isoformat(),
                is_scanner=ip == self.my_ip,
                first_seen=datetime.now().isoformat(),
                fingerprint_method=fingerprint.get('method', 'unknown'))
        
        # Output device information
        if self.args.json:
            print(device.to_json())
            return
            
        # Pretty print device details
        self._print_device_details(device)
        
        # Run vulnerability scan if requested
        if self.args.vuln_scan:
            print("\nRunning vulnerability scan...")
            vuln_results = self.scanner.perform_vulnerability_scan(ip)
            self._print_vulnerability_results(ip, vuln_results)
    
    def _determine_device_type(self, host_info, fingerprint):
        """Determine the device type based on enhanced device identification"""
        # Use the new device identifier for more accurate detection
        device_info = self.device_identifier.identify_device_type(
            host_info, 
            fingerprint,
            my_ip=self.my_ip,
            my_gateway=self.my_gateway
        )
        
        # Add to the log if high-confidence identification
        if device_info['confidence'] in ['medium', 'high']:
            self.logger.debug(f"Device {host_info.get('ip_address')} identified as {device_info['device_type']} " +
                           f"with {device_info['confidence']} confidence using {device_info['methods_used']}")
        
        # Get a more readable device name for display
        readable_name = self.device_identifier.get_readable_device_name(device_info['device_type'])
        
        # Add device type to host_info for future reference
        host_info['detected_device_type'] = device_info['device_type']
        host_info['readable_device_type'] = readable_name
        host_info['detection_confidence'] = device_info['confidence']
        
        return device_info['device_type']
    
    def _check_authorization(self, ip, mac):
        """Check if a device is authorized"""
        # Always authorize our device
        if ip == self.my_ip or mac == self.my_mac:
            return True
            
        # Always authorize the gateway
        if ip == self.my_gateway:
            return True
            
        # Check whitelist
        return (mac in self.whitelist.get('mac_addresses', [])
                or ip in self.whitelist.get('ip_addresses', []))
    
    def _print_device_details(self, device):
        """Print details of a device"""
        print("\n" + "=" * 60)
        
        # Header with basic info
        if COLOR_AVAILABLE and not self.args.no_color:
            status_color = Fore.GREEN if device.status == 'up' else Fore.RED
            auth_color = Fore.GREEN if device.is_authorized else Fore.RED
            print(f"{Fore.CYAN}DEVICE:{Style.RESET_ALL} {device.ip_address} ({device.hostname or 'Unknown hostname'})")
            print(f"{Fore.CYAN}Status:{Style.RESET_ALL} {status_color}{device.status}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Authorized:{Style.RESET_ALL} {auth_color}{device.is_authorized}{Style.RESET_ALL}")
        else:
            print(f"DEVICE: {device.ip_address} ({device.hostname or 'Unknown hostname'})")
            print(f"Status: {device.status}")
            print(f"Authorized: {device.is_authorized}")
            
        # Hardware info
        print("\nHARDWARE INFORMATION")
        print(f"MAC Address: {device.mac_address or 'Unknown'}")
        print(f"Vendor: {device.vendor or 'Unknown'}")
        
        # Software info
        print("\nSOFTWARE INFORMATION")
        print(f"OS: {device.os or 'Unknown'}")
        
        # Get a readable device type
        device_type = device.device_type
        readable_type = self.device_identifier.get_readable_device_name(device_type)
        
        print(f"Device Type: {readable_type}")
        print(f"Detection Confidence: {device.confidence}")
        
        # History
        print("\nHISTORY")
        print(f"First Seen: {device.first_seen}")
        print(f"Last Seen: {device.last_seen}")
        
        # Open ports
        print("\nOPEN PORTS")
        if not device.ports:
            print("No open ports detected")
        else:
            try:
                for port in device.ports:
                    # Check if this is a PortInfo object or a dictionary
                    if isinstance(port, dict):
                        # Handle dictionary format
                        port_num = port.get('port', 'Unknown')
                        protocol = port.get('protocol', 'tcp')
                        service = port.get('service', 'unknown')
                        version = port.get('version', '')
                        service_info = f"{service} {version}".strip()
                    else:
                        # Handle PortInfo object format
                        port_num = port.port
                        protocol = port.protocol
                        service_info = f"{port.service} {port.version}".strip()
                    
                    if COLOR_AVAILABLE and not self.args.no_color:
                        # Highlight potentially risky ports
                        port_color = Fore.GREEN
                        # Check for potentially vulnerable services
                        for service_name, service_ports in vendors.VULNERABLE_SERVICES.items():
                            if port_num in service_ports:
                                port_color = Fore.YELLOW
                                if service_name in ['smb', 'telnet', 'ftp']:
                                    port_color = Fore.RED
                        print(f"{port_color}{port_num}/{protocol}: {service_info}{Style.RESET_ALL}")
                    else:
                        print(f"{port_num}/{protocol}: {service_info}")
            except Exception as e:
                print(f"Error displaying port information: {str(e)}")
        
        print("=" * 60)
        
    def _print_vulnerability_results(self, ip, results):
        """Print vulnerability scan results"""
        if 'error' in results:
            print(f"Error: {results['error']}")
            return
            
        print("\nVULNERABILITY SCAN RESULTS")
        print("=" * 60)
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print("No vulnerabilities detected")
        else:
            print(f"Found {len(vulnerabilities)} potential vulnerabilities")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln.get('id', 'Unknown')}")
                if 'port' in vuln:
                    print(f"   Port: {vuln['port']}/{vuln['protocol']}")
                print(f"   Output: {vuln['output']}")
                
        print("=" * 60)
    
    def _run_dhcp_detection(self):
        """Run DHCP server detection with enhanced details"""
        print("\nDHCP SERVER DETECTION")
        print("=" * 60)
        print("Scanning for DHCP servers on the network...")
        print("This may take a few moments...")

        # Run detection
        dhcp_servers, dhcp_servers_details = self.detector.detect_dhcp_spoofing()
        rogue_servers = self.detector.detect_rogue_dhcp_servers()

        # Print results
        print(f"\nDHCP servers found: {len(dhcp_servers)}")
        save_results(list(dhcp_servers), self.output_dir, "dhcp_servers")
        save_results(list(dhcp_servers_details), self.output_dir, "dhcp_servers_details")

        # Display basic server information
        for server in dhcp_servers:
            is_rogue = server != self.my_gateway
            status = "ROGUE (Unauthorized)" if is_rogue else "Authorized"

            if COLOR_AVAILABLE and not self.args.no_color:
                status_color = Fore.RED if is_rogue else Fore.GREEN
                print(f" - {server} {status_color}{status}{Style.RESET_ALL}")
            else:
                print(f" - {server} {status}")

        # Display detailed rogue server information
        print(f"\nRogue DHCP servers detected: {len(rogue_servers)}")   
        if rogue_servers:
            print(f"\nDetailed information on {len(rogue_servers)} rogue DHCP servers:")
            save_results(list(rogue_servers), self.output_dir, "rogue_dhcp_servers")

            for server in rogue_servers:
                print("\n" + "-" * 50)
                print(f"ROGUE DHCP SERVER DETAILS:")
                print(f" - IP Address: {server.get('ip')}")
                print(f" - MAC Address: {server.get('mac')}")
                print(f" - Attack Type: {server.get('attack_type', 'Unknown')}")
                print(f" - Severity: {server.get('severity', 'medium').upper()}")
                print(f" - Activity Rate: {server.get('frequency', 'Unknown')}")

                # Show offered IPs
                offered_ips = server.get('offered_ips', [])
                if offered_ips:
                    print(f" - Offered IP addresses ({len(offered_ips)}):")
                    for ip in offered_ips[:5]:  # Show first 5
                        print(f"   * {ip}")
                    if len(offered_ips) > 5:
                        print(f"   * ...and {len(offered_ips) - 5} more")

                # Show network configuration offered
                print(f" - Gateway offered: {', '.join(server.get('gateway_offered', ['None']))}")
                print(f" - DNS servers offered: {', '.join(server.get('dns_offered', ['None']))}")
                print(f" - Subnet mask: {', '.join(server.get('subnet_mask', ['Unknown']))}")
                print(f" - Lease time: {', '.join(server.get('lease_time', ['Unknown']))}")

                # Show attack details
                print(f" - Details: {server.get('details')}")

                # Show mitigation advice
                print("\nMITIGATION ADVICE:")
                print(" - Locate and disconnect the rogue DHCP server immediately")
                print(" - Check for compromised devices on the network")
                print(" - Consider implementing DHCP snooping on managed switches")
                print(" - Monitor for ARP spoofing which often accompanies DHCP attacks")

        print("=" * 60)
    
    def _run_arp_detection(self):
        """Run ARP spoofing detection"""
        print("\nARP SPOOFING DETECTION")
        print("=" * 60)
        print("Scanning for ARP spoofing attacks...")
        print("This may take a few moments...")
        
        # Run detection
        duration = 120  # Duration to scan in seconds
        results = self.detector.detect_arp_spoofing(duration)
        
        # Print results
        if not results:
            print("\nNo ARP spoofing detected")
        else:
            print(f"\nDetected {len(results)} potential ARP spoofing incidents:")
            save_results(results, self.output_dir, "arp_spoofing")
            for incident in results:
                ip = incident.get('ip')
                legit_mac = incident.get('legit_mac')
                spoofed_macs = incident.get('spoofed_macs', [])
                victims = incident.get('victims', [])

                print(f"\n⚠️  ARP Spoofing Detected for IP: {ip}")

                if victims:
                    print(f" - Victim(s) targeted by spoof: {', '.join(victims)}")

                if legit_mac:
                    print(f" - Legitimate MAC: {legit_mac}")

                if spoofed_macs:
                    print(" - Spoofed MAC(s):")
                    for mac in spoofed_macs:
                        print(f"   - {mac}")

                    
        print("=" * 60)
    
    def _run_dns_detection(self):
        """Run DNS spoofing detection"""
        print("\nDNS SPOOFING DETECTION")
        print("=" * 60)
        print("Scanning for DNS spoofing attacks...")
        print("This may take a few moments...")
        
        # Run detection
        duration = 60  # Duration to scan in seconds
        results = self.detector.detect_dns_spoofing(duration)
        
        # Print results
        if not results:
            print("\nNo DNS spoofing detected")
        else:
            print(f"\nDetected {len(results)} potential DNS spoofing incidents:")
            save_results(results, self.output_dir, "dns_spoofing")
            for incident in results:
                domain = incident.get('domain')
                ips = incident.get('ip_addresses', [])
                
                if COLOR_AVAILABLE and not self.args.no_color:
                    print(f"{Fore.RED}Domain {domain} resolves to multiple IPs:{Style.RESET_ALL}")
                else:
                    print(f"Domain {domain} resolves to multiple IPs:")
                    
                for ip in ips:
                    print(f" - {ip}")
                    
        print("=" * 60)
    
    def _run_port_scan_detection(self):
        """Run port scanning detection"""
        print("\nPORT SCANNING DETECTION")
        print("=" * 60)
        print("Monitoring for port scanning activity...")
        print("This may take a few moments...")
        
        # Run a quick network scan first to get baseline
        print("Performing initial network scan...")
        hosts = self.scanner.scan_network(self.network_range)
        
        # Build initial state
        device_ports = {}
        for host in hosts:
            if host == self.my_ip:
                continue  # Skip our own device
                
            info = self.scanner.get_host_info(host)
            ports = [p.get('port') for p in info.get('ports', [])]
            device_ports[host] = ports
            
        # Now monitor for a while
        duration = 60  # Duration to monitor in seconds
        interval = 10  # Check every 10 seconds
        rounds = duration // interval
        
        for i in range(rounds):
            print(f"Monitoring round {i+1}/{rounds}...")
            time.sleep(interval)
            
            # Scan again
            hosts = self.scanner.scan_network(self.network_range)
            
            # Check for port scanning behavior
            alerts = []
            for host in hosts:
                if host == self.my_ip:
                    continue  # Skip our own device
                    
                info = self.scanner.get_host_info(host)
                new_ports = [p.get('port') for p in info.get('ports', [])]
                
                # Check if this host is port scanning
                alert = self.detector.detect_port_scanning(
                    host, 
                    new_ports, 
                    timeframe=duration, 
                    threshold=15
                )
                
                if alert:
                    alerts.append(alert)
                    
                # Update our tracking
                device_ports[host] = new_ports
        
        # Print results
        if not alerts:
            print("\nNo port scanning activity detected")
        else:
            print(f"\nDetected {len(alerts)} potential port scanning incidents:")
            for alert in alerts:
                ip = alert.get('ip')
                ports = alert.get('ports', [])
                
                if COLOR_AVAILABLE and not self.args.no_color:
                    print(f"{Fore.RED}Host {ip} scanned {len(ports)} ports:{Style.RESET_ALL}")
                else:
                    print(f"Host {ip} scanned {len(ports)} ports:")
                    
                print(f"Ports: {', '.join(str(p) for p in ports[:20])}{'...' if len(ports) > 20 else ''}")
                    
        print("=" * 60)
    
    def _run_quick_scan(self):
        """Run a quick network scan"""
        print("\nQUICK NETWORK SCAN")
        print("=" * 60)
        print(f"Scanning network: {self.network_range}")
        print("This may take a few moments...")
        
        # Run the scan
        hosts = self.scanner.scan_network(self.network_range)
        
        # Process each host
        devices = []
        for host in hosts:
            # Get basic host info
            host_info = self.scanner.get_host_info(host)
            
            # Get fingerprint
            fingerprint = self.fingerprinter.os_fingerprint(host)
            
            # Get vendor information
            vendor = None
            if host_info.get('mac_address'):
                vendor = self.fingerprinter.get_vendor_from_mac(host_info['mac_address'])
                
            # Create device object
            from core.models import Device, PortInfo
            
            ports = []
            for port_dict in host_info.get('ports', []):
                ports.append(
                    PortInfo(port=port_dict.get('port'),
                             protocol=port_dict.get('protocol', 'tcp'),
                             service=port_dict.get('service', 'unknown'),
                             version=port_dict.get('version', ''),
                             cpe=port_dict.get('cpe', '')))
                             
            # Check if this is a new device
            is_new = host not in self.known_devices
            first_seen = datetime.now().isoformat() if is_new else self.known_devices.get(host, Device(
                ip_address=host,
                status="unknown",
                hostname=None,
                mac_address=None,
                vendor=None,
                os=None,
                ports=[],
                device_type="unknown",
                confidence="low",
                is_new=True,
                is_authorized=False,
                whitelisted=False,
                last_seen=datetime.now().isoformat(),
                is_scanner=False
            )).first_seen
            
            is_authorized = self._check_authorization(host, host_info.get('mac_address'))
            
            device = Device(
                ip_address=host,
                status=host_info.get('status', 'unknown'),
                hostname=host_info.get('hostname'),
                mac_address=host_info.get('mac_address'),
                vendor=vendor,
                os=host_info.get('os') or str(fingerprint.get('data', {})),
                ports=ports,
                device_type=self._determine_device_type(host_info, fingerprint),
                confidence=fingerprint.get('confidence', 'low'),
                is_new=is_new,
                is_authorized=is_authorized,
                whitelisted=is_authorized,
                last_seen=datetime.now().isoformat(),
                is_scanner=host == self.my_ip,
                first_seen=first_seen,
                fingerprint_method=fingerprint.get('method', 'unknown'))
                
            devices.append(device)
            
            # Update known devices
            self.known_devices[host] = device
        
        # Calculate statistics
        stats = self._calculate_stats(devices)
        
        # Save results
        results = {
            "scan_time": datetime.now().isoformat(),
            "platform": platform.system(),
            "network_range": self.network_range,
            "devices": [d.to_dict() for d in devices],
            "stats": stats
        }
        
        filename = save_results(results, self.output_dir, "network_scan")
        
        # Print summary
        self._print_scan_summary(devices, stats)
        
        # Output JSON if requested
        if self.args.json:
            import json
            print(json.dumps(results, indent=2))
    
    def _run_full_scan(self):
        """Run a comprehensive scan with all detection features
        Combines all 8 scan modes:
        - Quick network scan
        - Threat detection scan
        - Vulnerability scan
        - DHCP server detection
        - ARP spoofing detection
        - DNS spoofing detection 
        - Port scanning detection
        - Device identification
        """
        print("\nCOMPREHENSIVE NETWORK SECURITY SCAN")
        print("=" * 80)
        print(f"Scanning network: {self.network_range}")
        print("Running all scan modes and threat detection modules")
        print("This may take several minutes to complete...")
        print("-" * 80)
        
        # Start with a basic device scan to discover network hosts
        print("\n[1/8] DEVICE DISCOVERY")
        hosts = self.scanner.scan_network(self.network_range)
        print(f"Found {len(hosts)} active devices on the network")
        
        # Process each host and collect device information
        devices = []
        vulnerability_reports = []
        
        # Store scan start time
        scan_start_time = datetime.now()
        
        # Tracking detected threats
        all_threats = []
        
        # Run DHCP detection in parallel (doesn't require host list)
        print("\n[2/8] DHCP SERVER DETECTION")
        print("Scanning for DHCP servers on the network...")
        dhcp_servers = self.detector.detect_dhcp_spoofing()
        rogue_dhcp_servers = self.detector.detect_rogue_dhcp_servers()
        
        if dhcp_servers:
            print(f"Found {len(dhcp_servers)} DHCP servers")
            for server in dhcp_servers:
                print(f"  - DHCP Server: {server}")
                
            # Check for rogue DHCP servers
            if rogue_dhcp_servers:
                print(f"WARNING: Detected {len(rogue_dhcp_servers)} potential rogue DHCP servers!")
                for rogue in rogue_dhcp_servers:
                    print(f"  - Rogue DHCP: {rogue.get('ip')} ({rogue.get('description', 'Unauthorized server')})")
                    all_threats.append({
                        'type': 'rogue_dhcp',
                        'ip': rogue.get('ip'),
                        'description': rogue.get('description', 'Unauthorized DHCP server'),
                        'severity': 'high'
                    })
        else:
            print("No DHCP servers detected")
            
        # Run ARP spoofing detection
        print("\n[3/8] ARP SPOOFING DETECTION")
        print("Monitoring for ARP spoofing attacks...")
        arp_threats = self.detector.detect_arp_spoofing()
        
        if arp_threats:
            print(f"WARNING: Detected {len(arp_threats)} potential ARP spoofing incidents!")
            for threat in arp_threats:
                print(f"  - {threat.get('description', 'ARP spoofing incident')}")
                all_threats.append(threat)
        else:
            print("No ARP spoofing detected")
        
        # Run DNS spoofing detection
        print("\n[4/8] DNS SPOOFING DETECTION")
        print("Monitoring for DNS spoofing attacks...")
        dns_threats = self.detector.detect_dns_spoofing()
        
        if dns_threats:
            print(f"WARNING: Detected {len(dns_threats)} potential DNS spoofing incidents!")
            for threat in dns_threats:
                print(f"  - {threat.get('description', 'DNS spoofing incident')}")
                all_threats.append(threat)
        else:
            print("No DNS spoofing detected")
        
        # Process each host for detailed information
        print("\n[5/8] DEVICE FINGERPRINTING")
        print(f"Fingerprinting {len(hosts)} devices...")
        
        for i, host in enumerate(hosts, 1):
            print(f"Processing device {i}/{len(hosts)}: {host}")
            
            # Get basic host info
            host_info = self.scanner.get_host_info(host)
            
            # Get fingerprint
            fingerprint = self.fingerprinter.os_fingerprint(host)
            
            # Get vendor information
            vendor = None
            if host_info.get('mac_address'):
                vendor = self.fingerprinter.get_vendor_from_mac(host_info['mac_address'])
            
            # Create device object    
            from core.models import Device, PortInfo
            
            ports = []
            for port_dict in host_info.get('ports', []):
                ports.append(
                    PortInfo(port=port_dict.get('port'),
                             protocol=port_dict.get('protocol', 'tcp'),
                             service=port_dict.get('service', 'unknown'),
                             version=port_dict.get('version', ''),
                             cpe=port_dict.get('cpe', '')))
            
            # Determine if device is new
            is_new = host not in self.known_devices
            previous_device = self.known_devices.get(host)
            
            # Determine device type
            device_type = self._determine_device_type(host_info, fingerprint)
            
            # Check authorization
            is_authorized = self._check_authorization(host, host_info.get('mac_address'))
            
            # Create device object
            device = Device(
                ip_address=host,
                status=host_info.get('status', 'unknown'),
                hostname=host_info.get('hostname'),
                mac_address=host_info.get('mac_address'),
                vendor=vendor,
                os=host_info.get('os') or str(fingerprint.get('data', {})),
                ports=ports,
                device_type=device_type,
                confidence=fingerprint.get('confidence', 'low'),
                is_new=is_new,
                is_authorized=is_authorized,
                whitelisted=is_authorized,
                last_seen=datetime.now().isoformat(),
                is_scanner=host == self.my_ip,
                first_seen=previous_device.first_seen if previous_device else datetime.now().isoformat(),
                fingerprint_method=fingerprint.get('method', 'unknown')
            )
            
            # Add to device list
            devices.append(device)
            
            # Update known devices
            self.known_devices[host] = device
            
            # Report new devices
            if is_new:
                self._report_new_device(device)
                
            # Check if not authorized
            if not is_authorized:
                all_threats.append({
                    'type': 'unauthorized_device',
                    'ip': host,
                    'mac': host_info.get('mac_address', 'Unknown'),
                    'description': f"Unauthorized device: {host} ({device_type})",
                    'severity': 'medium',
                    'time': datetime.now().isoformat()
                })
        
        # Run port scanning detection
        print("\n[6/8] PORT SCANNING DETECTION")
        print("Analyzing traffic for port scanning activity...")
        
        # Track potential scanners by IP address
        potential_scanners = {}
        
        # Check each device's open ports for scanning behavior
        for device in devices:
            # Skip our own IP
            if device.ip_address == self.my_ip:
                continue
                
            # Get a list of recent ports from device object
            recent_ports = [p.port for p in device.ports] if device.ports else []
            
            # Detect if this might be a port scanner
            scan_result = self.detector.detect_port_scanning(
                device.ip_address, 
                recent_ports,
                timeframe=60,  # Consider a shorter timeframe for demo
                threshold=5    # Lower threshold to increase detection chance
            )
            
            if scan_result:
                all_threats.append(scan_result)
                print(f"WARNING: Possible port scanning from {device.ip_address}")
        
        # Run vulnerability scanning on each device
        print("\n[7/8] VULNERABILITY SCANNING")
        print("Performing vulnerability scans on all devices...")
        
        for device in devices:
            # Skip vulnerability scans for our own device 
            if device.ip_address == self.my_ip:
                continue
                
            print(f"Scanning {device.ip_address} ({device.hostname or 'Unknown'}) for vulnerabilities...")
            vuln_results = self.scanner.perform_vulnerability_scan(device.ip_address)
            
            if vuln_results and 'vulnerabilities' in vuln_results and vuln_results['vulnerabilities']:
                print(f"  Found {len(vuln_results['vulnerabilities'])} potential vulnerabilities on {device.ip_address}")
                vulnerability_reports.append({
                    'ip': device.ip_address,
                    'hostname': device.hostname,
                    'mac': device.mac_address,
                    'device_type': device.device_type,
                    'scan_time': datetime.now().isoformat(),
                    'results': vuln_results
                })
                
                # Add significant vulnerabilities to the threats list
                for vuln in vuln_results['vulnerabilities']:
                    if vuln.get('severity', 'low') in ['high', 'critical']:
                        all_threats.append({
                            'type': 'vulnerability',
                            'ip': device.ip_address,
                            'description': f"Vulnerability: {vuln.get('id', 'Unknown')}",
                            'details': vuln.get('output', ''),
                            'severity': vuln.get('severity', 'medium'),
                            'time': datetime.now().isoformat()
                        })
        
        # Advanced threat analysis on discovered devices and threat data
        print("\n[8/8] THREAT ANALYSIS")
        print("Performing comprehensive threat analysis...")
        
        # Create a mapping of previous device information for comparison
        previous_devices = {}
        scan_files = self._get_recent_scans()
        if scan_files:
            try:
                import json
                with open(os.path.join(self.output_dir, scan_files[0])) as f:
                    last_scan = json.load(f)
                    
                # Convert to device mapping
                for device_data in last_scan.get('devices', []):
                    ip = device_data.get('ip_address')
                    if ip:
                        previous_devices[ip] = device_data
            except Exception as e:
                self.logger.error(f"Failed to load previous scan: {str(e)}")
        
        # Convert current devices to mapping for comparison
        current_devices = {d.ip_address: d.to_dict() for d in devices}
        
        # Detect network changes
        if previous_devices:
            network_changes = self.detector.detect_network_changes(current_devices, previous_devices)
            if network_changes:
                print(f"Detected {len(network_changes)} significant network changes")
                for change in network_changes:
                    print(f"  - {change.get('description', 'Unknown change')}")
                    if change.get('severity', 'low') in ['medium', 'high']:
                        all_threats.append(change)
        
        # Analyze open ports for security risks
        port_alerts = self.detector.analyze_open_ports([d.to_dict() for d in devices])
        if port_alerts:
            print(f"Detected {len(port_alerts)} potential security risks from open ports")
            for alert in port_alerts:
                print(f"  - {alert.get('description', 'Unknown port risk')}")
                all_threats.append(alert)
        
        # Calculate statistics
        stats = self._calculate_stats(devices)
        stats['threats_found'] = len(all_threats)
        stats['vulnerability_count'] = sum(len(r['results'].get('vulnerabilities', [])) 
                                          for r in vulnerability_reports) if vulnerability_reports else 0
        stats['scan_duration_seconds'] = (datetime.now() - scan_start_time).total_seconds()
        
        # Save comprehensive results
        results = {
            "scan_time": datetime.now().isoformat(),
            "scan_duration_seconds": stats['scan_duration_seconds'],
            "platform": platform.system(),
            "network_range": self.network_range,
            "devices": [d.to_dict() for d in devices],
            "threats": all_threats,
            "dhcp_servers": list(dhcp_servers) if dhcp_servers else [],
            "rogue_dhcp_servers": rogue_dhcp_servers if rogue_dhcp_servers else [],
            "vulnerability_reports": vulnerability_reports,
            "stats": stats
        }
        
        # Save results to file
        filename = save_results(results, self.output_dir, "full_network_scan")
        print(f"\nFull scan results saved to {filename}")
        
        # Print summary
        self._print_scan_summary(devices, stats)
        
        # Print threat summary if there are threats
        if all_threats:
            self._print_threat_summary(all_threats)
            
        # Print vulnerability summary if available
        if vulnerability_reports:
            self._print_vulnerability_summary(vulnerability_reports)
            
        # Output JSON if requested
        if self.args.json:
            import json
            print(json.dumps(results, indent=2))
    
    def _run_threat_scan(self):
        """Run a more thorough threat-focused scan"""
        print("\nTHREAT DETECTION SCAN")
        print("=" * 60)
        print(f"Scanning network {self.network_range} for potential threats...")
        print("This may take a few moments...")
        
        # Run quick scan first to get devices
        devices = []
        hosts = self.scanner.scan_network(self.network_range)
        
        for host in hosts:
            host_info = self.scanner.get_host_info(host)
            fingerprint = self.fingerprinter.os_fingerprint(host)
            
            # Get vendor information
            vendor = None
            if host_info.get('mac_address'):
                vendor = self.fingerprinter.get_vendor_from_mac(host_info['mac_address'])
            
            # Create device object    
            from core.models import Device, PortInfo
            
            ports = []
            for port_dict in host_info.get('ports', []):
                ports.append(
                    PortInfo(port=port_dict.get('port'),
                             protocol=port_dict.get('protocol', 'tcp'),
                             service=port_dict.get('service', 'unknown'),
                             version=port_dict.get('version', ''),
                             cpe=port_dict.get('cpe', '')))
                             
            # Check if this is a new device
            is_new = host not in self.known_devices
            first_seen = datetime.now().isoformat() if is_new else self.known_devices.get(host, Device(
                ip_address=host,
                status="unknown",
                hostname=None,
                mac_address=None,
                vendor=None,
                os=None,
                ports=[],
                device_type="unknown",
                confidence="low",
                is_new=True,
                is_authorized=False,
                whitelisted=False,
                last_seen=datetime.now().isoformat(),
                is_scanner=False
            )).first_seen
            
            is_authorized = self._check_authorization(host, host_info.get('mac_address'))
            
            device = Device(
                ip_address=host,
                status=host_info.get('status', 'unknown'),
                hostname=host_info.get('hostname'),
                mac_address=host_info.get('mac_address'),
                vendor=vendor,
                os=host_info.get('os') or str(fingerprint.get('data', {})),
                ports=ports,
                device_type=self._determine_device_type(host_info, fingerprint),
                confidence=fingerprint.get('confidence', 'low'),
                is_new=is_new,
                is_authorized=is_authorized,
                whitelisted=is_authorized,
                last_seen=datetime.now().isoformat(),
                is_scanner=host == self.my_ip,
                first_seen=first_seen,
                fingerprint_method=fingerprint.get('method', 'unknown'))
                
            devices.append(device)
            
            # Update known devices
            self.known_devices[host] = device
            
        # Now run threat detection
        print("\nChecking for network threats...")
        
        # Check for unauthorized devices
        threats = self.detector.detect_unauthorized_devices([d.to_dict() for d in devices], self.whitelist)
        
        # Run DHCP detection
        print("Checking for rogue DHCP servers...")
        rogue_dhcp = self.detector.detect_rogue_dhcp_servers()
        threats.extend(rogue_dhcp)
        
        # Run ARP spoofing detection
        print("Checking for ARP spoofing...")
        arp_threats = self.detector.detect_arp_spoofing(10)  # Quick 10-second scan
        threats.extend(arp_threats)
        
        # Run additional port analysis
        print("Analyzing open ports for security issues...")
        port_threats = self.detector.analyze_open_ports([d.to_dict() for d in devices])
        threats.extend(port_threats)
        
        # Calculate statistics
        stats = self._calculate_stats(devices)
        
        # Save results
        results = {
            "scan_time": datetime.now().isoformat(),
            "platform": platform.system(),
            "network_range": self.network_range,
            "devices": [d.to_dict() for d in devices],
            "threats": threats,
            "stats": stats
        }
        
        filename = save_results(results, self.output_dir, "threat_scan")
        
        # Print summary
        self._print_scan_summary(devices, stats)
        self._print_threat_summary(threats)
        
        # Output JSON if requested
        if self.args.json:
            import json
            print(json.dumps(results, indent=2))
    
    def _run_vulnerability_scan(self):
        """Run a vulnerability-focused scan on the network"""
        print("\nVULNERABILITY SCAN")
        print("=" * 60)
        print(f"Scanning network {self.network_range} for vulnerabilities...")
        print("This may take a significant amount of time...")
        
        # Run quick scan first to get devices
        hosts = self.scanner.scan_network(self.network_range)
        
        # Create device objects and track vulnerability reports
        devices = []
        vulnerability_reports = []
        
        for host in hosts:
            # Skip scanning our own device
            if host == self.my_ip:
                print(f"Skipping vulnerability scan on our device ({host})")
                continue
                
            print(f"Scanning {host} for vulnerabilities...")
            
            # Get basic host info
            host_info = self.scanner.get_host_info(host)
            
            # Get fingerprint
            fingerprint = self.fingerprinter.os_fingerprint(host)
            
            # Get vendor information
            vendor = None
            if host_info.get('mac_address'):
                vendor = self.fingerprinter.get_vendor_from_mac(host_info['mac_address'])
                
            # Run vulnerability scan
            vuln_data = self.scanner.perform_vulnerability_scan(host)
            
            # Create device object
            from core.models import Device, PortInfo
            
            ports = []
            for port_dict in host_info.get('ports', []):
                ports.append(
                    PortInfo(port=port_dict.get('port'),
                             protocol=port_dict.get('protocol', 'tcp'),
                             service=port_dict.get('service', 'unknown'),
                             version=port_dict.get('version', ''),
                             cpe=port_dict.get('cpe', '')))
                             
            # Check if this is a new device
            is_new = host not in self.known_devices
            first_seen = datetime.now().isoformat() if is_new else self.known_devices.get(host, Device(
                ip_address=host,
                status="unknown",
                hostname=None,
                mac_address=None,
                vendor=None,
                os=None,
                ports=[],
                device_type="unknown",
                confidence="low",
                is_new=True,
                is_authorized=False,
                whitelisted=False,
                last_seen=datetime.now().isoformat(),
                is_scanner=False
            )).first_seen
            
            is_authorized = self._check_authorization(host, host_info.get('mac_address'))
            
            # Analyze vulnerability severity
            vuln_analysis = analyze_vulnerability_severity([p.to_dict() for p in ports])
            
            device = Device(
                ip_address=host,
                status=host_info.get('status', 'unknown'),
                hostname=host_info.get('hostname'),
                mac_address=host_info.get('mac_address'),
                vendor=vendor,
                os=host_info.get('os') or str(fingerprint.get('data', {})),
                ports=ports,
                device_type=self._determine_device_type(host_info, fingerprint),
                confidence=fingerprint.get('confidence', 'low'),
                is_new=is_new,
                is_authorized=is_authorized,
                whitelisted=is_authorized,
                last_seen=datetime.now().isoformat(),
                is_scanner=host == self.my_ip,
                first_seen=first_seen,
                fingerprint_method=fingerprint.get('method', 'unknown'),
                vulnerability_score=vuln_analysis.get('risk_score', 0))
                
            devices.append(device)
            
            # Update known devices
            self.known_devices[host] = device
            
            # Create vulnerability report
            from core.models import VulnerabilityReport
            
            # Combine port vulnerabilities with nmap script results
            high_risk = vuln_analysis.get('high_risk', [])
            medium_risk = vuln_analysis.get('medium_risk', [])
            low_risk = vuln_analysis.get('low_risk', [])
            
            # Add any vulnerabilities from nmap scripts
            for vuln in vuln_data.get('vulnerabilities', []):
                vuln_id = vuln.get('id', '')
                vuln_output = vuln.get('output', '')
                
                # Categorize based on script id
                if 'critical' in vuln_id or 'high' in vuln_id:
                    high_risk.append(f"{vuln_id}: {vuln_output[:100]}...")
                elif 'medium' in vuln_id:
                    medium_risk.append(f"{vuln_id}: {vuln_output[:100]}...")
                else:
                    low_risk.append(f"{vuln_id}: {vuln_output[:100]}...")
            
            # Group ports by protocol
            port_groups = {}
            for p in ports:
                proto = p.protocol
                if proto not in port_groups:
                    port_groups[proto] = []
                port_groups[proto].append(p.port)
            
            report = VulnerabilityReport(
                ip_address=host,
                mac_address=host_info.get('mac_address'),
                hostname=host_info.get('hostname'),
                timestamp=datetime.now().isoformat(),
                risk_level=vuln_analysis.get('risk_level', 'Low'),
                risk_score=vuln_analysis.get('risk_score', 0),
                high_risk_issues=high_risk,
                medium_risk_issues=medium_risk,
                low_risk_issues=low_risk,
                open_ports=port_groups,
                recommendations=[
                    "Keep all systems updated with the latest security patches",
                    "Disable or secure unnecessary open ports",
                    "Use firewall rules to restrict access to sensitive services",
                    "Implement network segmentation to isolate high-risk devices"
                ]
            )
            
            vulnerability_reports.append(report)
            
        # Calculate statistics
        stats = self._calculate_stats(devices)
        
        # Save results
        results = {
            "scan_time": datetime.now().isoformat(),
            "platform": platform.system(),
            "network_range": self.network_range,
            "devices": [d.to_dict() for d in devices],
            "vulnerability_reports": [r.to_dict() for r in vulnerability_reports],
            "stats": stats
        }
        
        filename = save_results(results, self.output_dir, "vulnerability_scan")
        
        # Print summary
        self._print_scan_summary(devices, stats)
        self._print_vulnerability_summary(vulnerability_reports)
        
        # Output JSON if requested
        if self.args.json:
            import json
            print(json.dumps(results, indent=2))
    
    def _run_continuous_monitoring(self):
        """Run continuous monitoring until interrupted"""
        interval = self.args.interval
        
        print("\nCONTINUOUS NETWORK MONITORING")
        print("=" * 60)
        print(f"Monitoring network: {self.network_range}")
        print(f"Scan interval: {interval} seconds")
        print(f"Press Ctrl+C to stop monitoring")
        print("=" * 60)
        
        scan_count = 0
        try:
            while True:
                scan_count += 1
                print(f"\nScan #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Run a quick scan
                hosts = self.scanner.scan_network(self.network_range)
                
                # Process each host
                devices = []
                for host in hosts:
                    host_info = self.scanner.get_host_info(host)
                    fingerprint = self.fingerprinter.os_fingerprint(host)
                    
                    # Get vendor information
                    vendor = None
                    if host_info.get('mac_address'):
                        vendor = self.fingerprinter.get_vendor_from_mac(host_info['mac_address'])
                        
                    # Create device object
                    from core.models import Device, PortInfo
                    
                    ports = []
                    for port_dict in host_info.get('ports', []):
                        ports.append(
                            PortInfo(port=port_dict.get('port'),
                                     protocol=port_dict.get('protocol', 'tcp'),
                                     service=port_dict.get('service', 'unknown'),
                                     version=port_dict.get('version', ''),
                                     cpe=port_dict.get('cpe', '')))
                                     
                    # Check if this is a new device
                    is_new = host not in self.known_devices
                    first_seen = datetime.now().isoformat() if is_new else self.known_devices.get(host, Device(
                        ip_address=host,
                        status="unknown",
                        hostname=None,
                        mac_address=None,
                        vendor=None,
                        os=None,
                        ports=[],
                        device_type="unknown",
                        confidence="low",
                        is_new=True,
                        is_authorized=False,
                        whitelisted=False,
                        last_seen=datetime.now().isoformat(),
                        is_scanner=False
                    )).first_seen
                    
                    is_authorized = self._check_authorization(host, host_info.get('mac_address'))
                    
                    device = Device(
                        ip_address=host,
                        status=host_info.get('status', 'unknown'),
                        hostname=host_info.get('hostname'),
                        mac_address=host_info.get('mac_address'),
                        vendor=vendor,
                        os=host_info.get('os') or str(fingerprint.get('data', {})),
                        ports=ports,
                        device_type=self._determine_device_type(host_info, fingerprint),
                        confidence=fingerprint.get('confidence', 'low'),
                        is_new=is_new,
                        is_authorized=is_authorized,
                        whitelisted=is_authorized,
                        last_seen=datetime.now().isoformat(),
                        is_scanner=host == self.my_ip,
                        first_seen=first_seen,
                        fingerprint_method=fingerprint.get('method', 'unknown'))
                        
                    devices.append(device)
                    
                    # Update known devices
                    self.known_devices[host] = device
                    
                    # Report new devices immediately
                    if is_new:
                        self._report_new_device(device)
                
                # Check for threats using previous scan data
                previous_scan_files = self._get_recent_scans(1)
                previous_scan = None
                
                if previous_scan_files:
                    try:
                        import json
                        with open(os.path.join(self.output_dir, previous_scan_files[0])) as f:
                            previous_scan = json.load(f)
                    except Exception as e:
                        self.logger.error(f"Failed to load previous scan: {str(e)}")
                
                # Detect threats
                threats = self.detector.analyze_scan_results(
                    {"devices": [d.to_dict() for d in devices]},
                    self.whitelist,
                    previous_scan
                )
                
                # Calculate statistics
                stats = self._calculate_stats(devices)
                
                # Save results
                results = {
                    "scan_time": datetime.now().isoformat(),
                    "platform": platform.system(),
                    "network_range": self.network_range,
                    "devices": [d.to_dict() for d in devices],
                    "threats": threats,
                    "stats": stats
                }
                
                filename = save_results(results, self.output_dir, "network_scan")
                
                # Print summary
                self._print_scan_summary(devices, stats)
                
                # Report any threats
                if threats:
                    self._report_threats(threats)
                
                # Wait for next scan
                for i in range(interval, 0, -1):
                    if i % 10 == 0 or i < 5:
                        print(f"Next scan in {i} seconds...\r", end="")
                    time.sleep(1)
                    
                print(" " * 40, end="\r")  # Clear the status line
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")
    
    def _report_new_device(self, device):
        """Report a newly discovered device"""
        print("\n" + "=" * 60)
        print("NEW DEVICE DETECTED")
        
        status = "Authorized" if device.is_authorized else "UNAUTHORIZED"
        if COLOR_AVAILABLE and not self.args.no_color:
            status_color = Fore.GREEN if device.is_authorized else Fore.RED
            print(f"IP: {device.ip_address} - Status: {status_color}{status}{Style.RESET_ALL}")
        else:
            print(f"IP: {device.ip_address} - Status: {status}")
            
        print(f"Hostname: {device.hostname or 'Unknown'}")
        print(f"MAC: {device.mac_address or 'Unknown'}")
        print(f"Vendor: {device.vendor or 'Unknown'}")
        print(f"Type: {device.device_type}")
        
        if not device.is_authorized:
            print("\nAdd to whitelist:")
            if device.mac_address:
                print(f"  ./network_monitor.py --add-to-whitelist {device.mac_address}")
            else:
                print(f"  ./network_monitor.py --add-to-whitelist {device.ip_address}")
            
        print("=" * 60)
    
    def _report_threats(self, threats):
        """Report detected threats"""
        if not threats:
            return
            
        print("\n" + "=" * 60)
        print("SECURITY THREATS DETECTED")
        
        for threat in threats:
            threat_type = threat.get('threat_type', 'unknown')
            severity = threat.get('severity', 'medium').upper()
            
            # Format the heading based on severity
            if COLOR_AVAILABLE and not self.args.no_color:
                severity_color = Fore.RED if severity == 'HIGH' else (Fore.YELLOW if severity == 'MEDIUM' else Fore.WHITE)
                print(f"\n{severity_color}{severity} {threat_type.upper()}{Style.RESET_ALL}")
            else:
                print(f"\n{severity} {threat_type.upper()}")
                
            # Print details based on threat type
            print(f"  IP: {threat.get('ip', 'Unknown')}")
            
            if 'mac' in threat:
                print(f"  MAC: {threat.get('mac')}")
                
            if 'timestamp' in threat:
                print(f"  Detected: {threat.get('timestamp')}")
                
            if 'details' in threat:
                print(f"  Details: {threat.get('details')}")
                
            # Type-specific details
            if threat_type == 'port_scan' and 'ports' in threat:
                ports = threat.get('ports', [])
                print(f"  Scanned ports: {', '.join(str(p) for p in ports[:10])}")
                if len(ports) > 10:
                    print(f"  ...and {len(ports) - 10} more")
                    
            elif threat_type == 'mac_changed':
                print(f"  Old MAC: {threat.get('old_mac')}")
                print(f"  New MAC: {threat.get('new_mac')}")
                
            elif threat_type == 'unauthorized_device':
                print(f"  Hostname: {threat.get('hostname', 'Unknown')}")
                
            elif threat_type == 'rogue_dhcp':
                print(f"  Server IP: {threat.get('ip')}")
                print(f"  Server MAC: {threat.get('mac')}")
                
        print("=" * 60)
    
    def _calculate_stats(self, devices):
        """Calculate statistics from scan results"""
        stats = {
            'total_hosts': len(devices),
            'alive_hosts': sum(1 for d in devices if d.status == 'up'),
            'new_devices': sum(1 for d in devices if d.is_new),
            'unauthorized_devices': sum(1 for d in devices if not d.is_authorized),
            'device_types': {},
            'open_ports': {}
        }
        
        # Count device types
        for device in devices:
            device_type = device.device_type
            if device_type in stats['device_types']:
                stats['device_types'][device_type] += 1
            else:
                stats['device_types'][device_type] = 1
                
        # Count common open ports/services
        for device in devices:
            for port in device.ports:
                service = port.service or f"port-{port.port}"
                if service in stats['open_ports']:
                    stats['open_ports'][service] += 1
                else:
                    stats['open_ports'][service] = 1
                    
        return stats
    
    def _print_scan_summary(self, devices, stats):
        """Print a summary of scan results"""
        if self.args.json:
            return
            
        print("\nSCAN SUMMARY")
        print("-" * 60)
        
        # Device counts
        print(f"Total hosts: {stats['total_hosts']}")
        print(f"Alive hosts: {stats['alive_hosts']}")
        
        # Highlight new or unauthorized devices
        if COLOR_AVAILABLE and not self.args.no_color:
            if stats['new_devices'] > 0:
                print(f"New devices: {Fore.YELLOW}{stats['new_devices']}{Style.RESET_ALL}")
            else:
                print(f"New devices: 0")
                
            if stats['unauthorized_devices'] > 0:
                print(f"Unauthorized devices: {Fore.RED}{stats['unauthorized_devices']}{Style.RESET_ALL}")
            else:
                print(f"Unauthorized devices: 0")
        else:
            print(f"New devices: {stats['new_devices']}")
            print(f"Unauthorized devices: {stats['unauthorized_devices']}")
        
        # Device types
        if stats['device_types']:
            print("\nDevice Types:")
            for dtype, count in sorted(stats['device_types'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {dtype}: {count}")
                
        # Common ports
        if stats['open_ports']:
            print("\nCommon Services:")
            common_ports = sorted(stats['open_ports'].items(), key=lambda x: x[1], reverse=True)[:10]
            for service, count in common_ports:
                print(f"  {service}: {count}")
                
        print("-" * 60)
    
    def _print_threat_summary(self, threats):
        """Print a summary of detected threats"""
        if self.args.json:
            return
            
        if not threats:
            print("\nNo threats detected.")
            return
            
        print("\nTHREAT SUMMARY")
        print("-" * 60)
        
        # Group threats by type and severity
        threat_types = {}
        for threat in threats:
            ttype = threat.get('threat_type', 'unknown')
            severity = threat.get('severity', 'medium')
            
            if ttype not in threat_types:
                threat_types[ttype] = {'high': 0, 'medium': 0, 'low': 0}
                
            threat_types[ttype][severity] += 1
        
        # Print threat summary
        for ttype, counts in threat_types.items():
            total = sum(counts.values())
            
            if COLOR_AVAILABLE and not self.args.no_color:
                severity_color = Fore.RED if counts['high'] > 0 else (Fore.YELLOW if counts['medium'] > 0 else Fore.WHITE)
                print(f"{severity_color}{ttype.replace('_', ' ').title()}{Style.RESET_ALL}: {total} total")
            else:
                print(f"{ttype.replace('_', ' ').title()}: {total} total")
                
            print(f"  High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']}")
        
        print("-" * 60)
    
    def _print_vulnerability_summary(self, vulnerability_reports):
        """Print a summary of vulnerability reports"""
        if self.args.json:
            return
            
        if not vulnerability_reports:
            print("\nNo vulnerability reports generated.")
            return
            
        print("\nVULNERABILITY SUMMARY")
        print("-" * 60)
        
        try:
            # Detect whether reports are in VulnerabilityReport format or dictionary format
            first_report = vulnerability_reports[0] if vulnerability_reports else None
            is_dict_format = isinstance(first_report, dict)
            
            # Count vulnerability levels and issues based on the format
            if is_dict_format:
                # Dictionary format as used in full_scan
                high_risk = 0
                medium_risk = 0
                low_risk = 0
                total_high = 0
                total_medium = 0
                total_low = 0
                
                for r in vulnerability_reports:
                    if 'results' in r and 'vulnerabilities' in r['results']:
                        # Count by severity from the vulnerabilities list
                        for vuln in r['results']['vulnerabilities']:
                            severity = vuln.get('severity', 'low').lower()
                            if severity in ['high', 'critical']:
                                total_high += 1
                                high_risk = high_risk or 1  # Count device once
                            elif severity == 'medium':
                                total_medium += 1
                                medium_risk = medium_risk or 1
                            else:
                                total_low += 1
                                low_risk = low_risk or 1
            else:
                # VulnerabilityReport object format as used in vulnerability_scan
                high_risk = sum(1 for r in vulnerability_reports if r.risk_level.upper() == 'HIGH')
                medium_risk = sum(1 for r in vulnerability_reports if r.risk_level.upper() == 'MEDIUM')
                low_risk = sum(1 for r in vulnerability_reports if r.risk_level.upper() == 'LOW')
                
                # Count total issues
                total_high = sum(len(r.high_risk_issues) for r in vulnerability_reports)
                total_medium = sum(len(r.medium_risk_issues) for r in vulnerability_reports)
                total_low = sum(len(r.low_risk_issues) for r in vulnerability_reports)
            
            # Print summary counts
            print(f"Devices scanned: {len(vulnerability_reports)}")
            
            if COLOR_AVAILABLE and not self.args.no_color:
                print(f"\nRisk levels:")
                print(f"  {Fore.RED}High risk devices:{Style.RESET_ALL} {high_risk}")
                print(f"  {Fore.YELLOW}Medium risk devices:{Style.RESET_ALL} {medium_risk}")
                print(f"  {Fore.GREEN}Low risk devices:{Style.RESET_ALL} {low_risk}")
                
                print(f"\nVulnerabilities found:")
                print(f"  {Fore.RED}High severity issues:{Style.RESET_ALL} {total_high}")
                print(f"  {Fore.YELLOW}Medium severity issues:{Style.RESET_ALL} {total_medium}")
                print(f"  {Fore.GREEN}Low severity issues:{Style.RESET_ALL} {total_low}")
            else:
                print(f"\nRisk levels:")
                print(f"  High risk devices: {high_risk}")
                print(f"  Medium risk devices: {medium_risk}")
                print(f"  Low risk devices: {low_risk}")
                
                print(f"\nVulnerabilities found:")
                print(f"  High severity issues: {total_high}")
                print(f"  Medium severity issues: {total_medium}")
                print(f"  Low severity issues: {total_low}")
            
            # Print detailed info for high-risk devices
            if high_risk > 0 and not is_dict_format:
                # Only show detailed high risk issues for VulnerabilityReport objects
                print("\nHigh Risk Devices:")
                for report in vulnerability_reports:
                    if report.risk_level.upper() != 'HIGH':
                        continue
                        
                    print(f"  {report.ip_address} ({report.hostname or 'Unknown'}):")
                    
                    # Show the first few high risk issues
                    if report.high_risk_issues:
                        for i, issue in enumerate(report.high_risk_issues[:3]):
                            print(f"    - {issue[:80]}...")
                        if len(report.high_risk_issues) > 3:
                            print(f"    - ...and {len(report.high_risk_issues) - 3} more high risk issues")
            
            print("-" * 60)
            
            # Recommendations - only show for VulnerabilityReport objects
            if vulnerability_reports and not is_dict_format:
                print("\nGeneral Security Recommendations:")
                recommendations = vulnerability_reports[0].recommendations
                for rec in recommendations:
                    print(f"  - {rec}")
                
            print("-" * 60)
            
        except Exception as e:
            print(f"Error processing vulnerability reports: {str(e)}")
            print("-" * 60)

def main():
    """Main entry point"""
    monitor = NetworkMonitorCLI()
    try:
        monitor.run()
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"Error: {str(e)}")
        if monitor.args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())