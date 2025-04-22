#!/usr/bin/env python3
"""
Network Monitor - Terminal Command Line Utility

Provides real-time network device detection, monitoring, and security analysis.
Run as an administrative/root user for full functionality.
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Optional, List, Dict, Any

from core.scanner import NetworkScanner
from core.detector import ThreatDetector
from core.fingerprint import DeviceFingerprinter
from core.models import Device, PortInfo, ScanResult, ThreatAlert, VulnerabilityReport
from config import vendors
from utils.helpers import save_results, load_whitelist, analyze_vulnerability_severity, save_whitelist
from utils.network import get_default_gateway, get_my_mac_address, get_my_ip_address, get_network_cidr
from config import settings

def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Set up logging configuration"""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters and handlers
    console_format = '%(asctime)s [%(levelname)s] %(message)s'
    file_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(console_format))
    
    handlers = [console_handler]
    
    # Add file handler if requested
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(file_format))
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=console_format,
        handlers=handlers
    )
    
    return logging.getLogger(__name__)

def print_header():
    """Print the application header"""
    print("\n" + "=" * 70)
    print(" " * 20 + "NETWORK MONITORING SYSTEM")
    print(" " * 16 + "Real-time Security & Device Analysis")
    print("=" * 70)
    
def print_scan_summary(scan_result: Dict[str, Any]):
    """Print a summary of the scan results"""
    devices = scan_result.get('devices', [])
    stats = scan_result.get('stats', {})
    
    print("\n" + "=" * 70)
    print(f"SCAN SUMMARY - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 70)
    print(f"Total devices: {stats.get('total_hosts', 0)}")
    print(f"Active devices: {stats.get('alive_hosts', 0)}")
    print(f"New devices: {stats.get('new_devices', 0)}")
    
    if stats.get('unauthorized_devices', 0) > 0:
        print(f"⚠️ Unauthorized devices: {stats.get('unauthorized_devices', 0)}")
    
    # Device types breakdown
    if 'device_types' in stats:
        print("\nDEVICE TYPES:")
        for dtype, count in stats['device_types'].items():
            print(f"  {dtype.ljust(15)}: {count}")
    
    # Most common open ports
    if 'open_ports' in stats:
        print("\nMost Common Services:")
        common_ports = sorted(stats['open_ports'].items(), key=lambda x: x[1], reverse=True)[:5]
        for service, count in common_ports:
            print(f"  {service.ljust(15)}: {count}")
    
    print("=" * 70 + "\n")

def print_device_details(device: Dict[str, Any], vuln_check: bool = False):
    """Print details about a specific device"""
    print("\n" + "-" * 50)
    print(f"DEVICE: {device.get('ip_address')} ({device.get('hostname') or 'Unknown'})")
    print("-" * 50)
    print(f"MAC Address: {device.get('mac_address') or 'Unknown'}")
    print(f"Vendor: {device.get('vendor') or 'Unknown'}")
    print(f"OS: {device.get('os') or 'Unknown'}")
    print(f"Status: {device.get('status') or 'Unknown'}")
    print(f"Device Type: {device.get('device_type') or 'Unknown'}")
    print(f"First Seen: {device.get('first_seen') or 'Unknown'}")
    print(f"Last Seen: {device.get('last_seen') or 'Unknown'}")
    print(f"Authorized: {'Yes' if device.get('is_authorized') else 'No'}")
    
    # Print open ports
    ports = device.get('ports', [])
    if ports:
        print("\nOpen Ports:")
        for port in ports:
            version = f" ({port.get('version')})" if port.get('version') else ""
            print(f"  {port.get('port')}/{port.get('protocol')}: {port.get('service')}{version}")
    else:
        print("\nNo open ports detected")
    
    # Add vulnerability assessment if requested
    if vuln_check and ports:
        vuln_report = analyze_vulnerability_severity(ports)
        print(f"\nVulnerability Assessment: {vuln_report.get('risk_level', 'Low')} Risk")
        
        if vuln_report.get('high_risk'):
            print("\n⚠️ High Risk Issues:")
            for issue in vuln_report.get('high_risk', []):
                print(f"  - {issue}")
                
        if vuln_report.get('medium_risk'):
            print("\n⚠️ Medium Risk Issues:")
            for issue in vuln_report.get('medium_risk', []):
                print(f"  - {issue}")
                
    print("-" * 50)

def print_threat_details(threats: List[Dict[str, Any]]):
    """Print details about detected threats"""
    if not threats:
        print("\nNo threats detected.")
        return
    
    print("\n" + "=" * 70)
    print("THREAT DETECTION RESULTS")
    print("=" * 70)
    
    for i, threat in enumerate(threats, 1):
        severity = threat.get('severity', 'medium').upper()
        severity_marker = '🔴' if severity == 'HIGH' else '🟠' if severity == 'MEDIUM' else '🟡'
        
        print(f"\n{i}. {severity_marker} {threat.get('threat_type', 'Unknown Threat')} - {severity} severity")
        print(f"   IP: {threat.get('ip')}")
        if 'mac' in threat:
            print(f"   MAC: {threat.get('mac')}")
        if 'hostname' in threat and threat['hostname']:
            print(f"   Hostname: {threat.get('hostname')}")
        print(f"   Details: {threat.get('details', 'No details available')}")
        
        # Print specific threat details
        if threat.get('threat_type') == 'port_scan' and 'ports' in threat:
            print(f"   Ports scanned: {', '.join(str(p) for p in threat['ports'][:10])}{'...' if len(threat['ports']) > 10 else ''}")
        elif threat.get('threat_type') == 'mac_changed':
            print(f"   Old MAC: {threat.get('old_mac')}")
            print(f"   New MAC: {threat.get('new_mac')}")
        elif threat.get('threat_type') == 'new_ports' and 'new_ports' in threat:
            print(f"   New ports: {', '.join(str(p) for p in threat['new_ports'])}")
            
    print("\n" + "=" * 70)

def run_scan(network_range: str, output_dir: str, whitelist: Dict[str, List], 
           previous_results: Optional[Dict[str, Any]] = None,
           vuln_check: bool = False) -> Dict[str, Any]:
    """
    Run a complete network scan and analyze results
    
    Args:
        network_range: Network CIDR to scan
        output_dir: Directory to save results
        whitelist: Whitelist dictionary
        previous_results: Optional previous scan results
        vuln_check: Whether to perform vulnerability checks
    
    Returns:
        Dictionary with scan results
    """
    scanner = NetworkScanner()
    detector = ThreatDetector()
    fingerprinter = DeviceFingerprinter()
    
    my_ip = get_my_ip_address()
    my_mac = get_my_mac_address()
    
    print(f"Scanning network {network_range}...")
    hosts = scanner.scan_network(network_range)
    print(f"Found {len(hosts)} hosts")
    
    # Process each host
    devices = []
    for host in hosts:
        print(f"Processing host: {host}")
        host_info = scanner.get_host_info(host)
        
        # Get fingerprint
        fingerprint = fingerprinter.os_fingerprint(host)
        
        # Get vendor information
        vendor = None
        if host_info.get('mac_address'):
            vendor = fingerprinter.get_vendor_from_mac(host_info['mac_address'])
            
        # Determine if this is a new device
        is_new = True
        first_seen = datetime.now().isoformat()
        
        if previous_results and 'devices' in previous_results:
            # Check if we've seen this device before
            for prev_device in previous_results['devices']:
                if prev_device.get('ip_address') == host:
                    is_new = False
                    first_seen = prev_device.get('first_seen', first_seen)
                    break
        
        # Check if device is authorized
        is_authorized = (
            host == my_ip or
            host_info.get('mac_address') == my_mac or
            host_info.get('mac_address') in whitelist.get('mac_addresses', []) or
            host in whitelist.get('ip_addresses', [])
        )
        
        # Determine device type
        device_type = "unknown"
        
        # Check if this is our own device
        if host == my_ip:
            device_type = "this_device"
        # Check if it's a gateway
        elif host == get_default_gateway():
            device_type = "router"
        else:
            # Get ports for classification
            ports = [p.get('port', 0) for p in host_info.get('ports', [])]
            
            # Check for device types based on open ports
            for device_type_name, signature_ports in vendors.DEVICE_TYPE_PORT_MAPPING.items():
                # Check if the signature ports are a subset of the device's open ports
                matches = sum(1 for port in signature_ports if port in ports)
                if matches >= 2 or (matches == 1 and len(signature_ports) == 1):
                    device_type = device_type_name
                    break
                    
            # If still unknown, check OS fingerprint for hints
            if device_type == "unknown":
                os_data = str(fingerprint.get('data', {})).lower()
                if 'windows' in os_data:
                    device_type = 'windows'
                elif 'linux' in os_data or 'unix' in os_data:
                    device_type = 'linux'
                elif 'mac' in os_data or 'apple' in os_data or 'ios' in os_data:
                    device_type = 'apple'
        
        # Create device dictionary
        device = {
            'ip_address': host,
            'status': host_info.get('status', 'unknown'),
            'hostname': host_info.get('hostname'),
            'mac_address': host_info.get('mac_address'),
            'vendor': vendor,
            'os': host_info.get('os') or str(fingerprint.get('data', {})),
            'ports': host_info.get('ports', []),
            'device_type': device_type,
            'confidence': fingerprint.get('confidence', 'low'),
            'is_new': is_new,
            'is_authorized': is_authorized,
            'whitelisted': is_authorized,
            'last_seen': datetime.now().isoformat(),
            'is_scanner': host == my_ip,
            'first_seen': first_seen,
            'fingerprint_method': fingerprint.get('method', 'unknown')
        }
        
        # Run vulnerability scan if requested
        if vuln_check:
            print(f"Running vulnerability scan on {host}...")
            vuln_results = scanner.perform_vulnerability_scan(host)
            
            # Add vulnerability assessment
            if 'vulnerabilities' in vuln_results:
                vuln_analysis = analyze_vulnerability_severity(host_info.get('ports', []))
                device['vulnerability_score'] = vuln_analysis.get('risk_score', 0)
                device['vulnerability_report'] = vuln_results
        
        devices.append(device)
        
        # Alert on new unauthorized devices
        if is_new and not is_authorized:
            print(f"\n⚠️ NEW UNAUTHORIZED DEVICE: {host} ({host_info.get('hostname') or 'Unknown hostname'})")
            print(f"MAC: {host_info.get('mac_address') or 'Unknown'}")
            print(f"Vendor: {vendor or 'Unknown'}")
    
    # Detect threats
    print("\nAnalyzing for potential threats...")
    threats = detector.analyze_scan_results({'devices': devices}, whitelist, previous_results)
    
    # Calculate statistics
    stats = calculate_statistics(devices)
    
    # Create results dictionary
    results = {
        'scan_time': datetime.now().isoformat(),
        'platform': platform.system(),
        'network_range': network_range,
        'devices': devices,
        'threats': threats,
        'stats': stats
    }
    
    # Save results to file
    filename = save_results(results, output_dir, "network_scan")
    print(f"Results saved to {filename}")
    
    return results

def calculate_statistics(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate statistics from scan results
    
    Args:
        devices: List of device dictionaries
        
    Returns:
        Dictionary with statistics
    """
    stats = {
        'total_hosts': len(devices),
        'alive_hosts': sum(1 for d in devices if d.get('status') == 'up'),
        'new_devices': sum(1 for d in devices if d.get('is_new', False)),
        'unauthorized_devices': sum(1 for d in devices if not d.get('is_authorized', False)),
        'device_types': {},
        'open_ports': {}
    }
    
    # Count device types
    for device in devices:
        device_type = device.get('device_type', 'unknown')
        if device_type in stats['device_types']:
            stats['device_types'][device_type] += 1
        else:
            stats['device_types'][device_type] = 1
            
    # Count common open ports/services
    for device in devices:
        for port in device.get('ports', []):
            service = port.get('service', f"port-{port.get('port')}")
            if service in stats['open_ports']:
                stats['open_ports'][service] += 1
            else:
                stats['open_ports'][service] = 1
                
    return stats

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Network Monitoring System - Terminal Client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Basic options
    parser.add_argument('-n', '--network', help='Network range to scan (CIDR notation)', default=None)
    parser.add_argument('-o', '--output', help='Output directory for results', default=settings.OUTPUT_DIR)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Scan modes
    mode_group = parser.add_argument_group('Scan Modes')
    mode_group.add_argument('--monitor', action='store_true', help='Run continuous monitoring')
    mode_group.add_argument('--interval', type=int, help='Scan interval for monitoring (seconds)', default=300)
    mode_group.add_argument('--threat-scan', action='store_true', help='Focus on threat detection')
    mode_group.add_argument('--vuln-scan', action='store_true', help='Perform vulnerability scanning')
    mode_group.add_argument('--full-scan', action='store_true', help='Run a comprehensive scan with all detection features')
    
    # Management options
    manage_group = parser.add_argument_group('Management')
    manage_group.add_argument('--add-whitelist', metavar='ADDRESS', help='Add IP or MAC to whitelist')
    manage_group.add_argument('--show-whitelist', action='store_true', help='Show current whitelist')
    manage_group.add_argument('--show-device', metavar='IP', help='Show detailed info for a specific device')
    
    args = parser.parse_args()
    
    # Set up logging
    logger = setup_logging(
        verbose=args.verbose,
        log_file=os.path.join('logs', f"monitor_{datetime.now().strftime('%Y%m%d')}.log")
    )
    
    # Ensure output directory exists
    os.makedirs(args.output, exist_ok=True)
    
    # Load whitelist
    whitelist = load_whitelist(args.output)
    
    # Determine network range
    network_range = args.network or settings.DEFAULT_NETWORK_RANGE
    
    # Auto-detect network if not specified
    if network_range == settings.DEFAULT_NETWORK_RANGE:
        detected_network = get_network_cidr()
        if detected_network:
            network_range = detected_network
            logger.info(f"Auto-detected network range: {network_range}")
    
    # Print header
    print_header()
    
    try:
        # Handle management operations
        if args.add_whitelist:
            add_to_whitelist(args.add_whitelist, whitelist, args.output)
            return
            
        if args.show_whitelist:
            show_whitelist(whitelist)
            return
            
        if args.show_device:
            show_device_details(args.show_device, args.output, whitelist, args.vuln_scan)
            return
        
        # Load previous results if available
        previous_results = load_previous_results(args.output)
        
        # Handle continuous monitoring
        if args.monitor:
            run_continuous_monitoring(
                network_range, args.output, whitelist, 
                interval=args.interval,
                vuln_check=args.vuln_scan
            )
            return
        
        # Run a scan based on mode
        if args.full_scan:
            # Run comprehensive scan with all features
            print("\nRunning comprehensive full scan with all detection features...")
            
            # First run a regular scan to get devices
            results = run_scan(network_range, args.output, whitelist, previous_results, True)
            print_scan_summary(results)
            
            # Additionally run all threat detection modules
            print("\nRunning all threat detection modules...")
            
            # Create required objects
            detector = ThreatDetector()
            
            # Run DHCP detection
            print("\n[1/4] DHCP SERVER DETECTION")
            dhcp_servers = detector.detect_dhcp_spoofing()
            rogue_dhcp_servers = detector.detect_rogue_dhcp_servers()
            
            if dhcp_servers:
                print(f"Found {len(dhcp_servers)} DHCP servers:")
                for server in dhcp_servers:
                    print(f"  - {server}")
                    
                if rogue_dhcp_servers:
                    print(f"WARNING: Detected {len(rogue_dhcp_servers)} potential rogue DHCP servers!")
                    for rogue in rogue_dhcp_servers:
                        print(f"  - Rogue DHCP: {rogue.get('ip', 'Unknown')} ({rogue.get('description', 'Unauthorized server')})")
            else:
                print("No DHCP servers detected")
            
            # Run ARP spoofing detection
            print("\n[2/4] ARP SPOOFING DETECTION")
            arp_threats = detector.detect_arp_spoofing()
            
            if arp_threats:
                print(f"WARNING: Detected {len(arp_threats)} potential ARP spoofing incidents!")
                for threat in arp_threats:
                    print(f"  - {threat.get('description', 'ARP spoofing incident')}")
            else:
                print("No ARP spoofing detected")
            
            # Run DNS spoofing detection
            print("\n[3/4] DNS SPOOFING DETECTION")
            dns_threats = detector.detect_dns_spoofing()
            
            if dns_threats:
                print(f"WARNING: Detected {len(dns_threats)} potential DNS spoofing incidents!")
                for threat in dns_threats:
                    print(f"  - {threat.get('description', 'DNS spoofing incident')}")
            else:
                print("No DNS spoofing detected")
            
            # Run port scanning detection
            print("\n[4/4] PORT SCANNING DETECTION")
            # This would use data from the scan results to detect possible scanners
            # For each device with many open ports on other hosts, check if it might be scanning
            
            for device in results.get('devices', []):
                # Get a list of recent ports
                ip = device.get('ip_address')
                if not ip:
                    continue
                    
                # Skip our own IP
                if ip == get_my_ip_address():
                    continue
                    
                ports = [p.get('port') for p in device.get('ports', [])]
                if len(ports) > 10:  # Simple heuristic for demo
                    port_scan_result = detector.detect_port_scanning(
                        ip, 
                        ports,
                        timeframe=60,  # Consider a shorter timeframe for demo
                        threshold=5    # Lower threshold to increase detection chance
                    )
                    
                    if port_scan_result:
                        print(f"WARNING: Possible port scanning from {ip}")
            
            # Print a summary of all detected threats
            all_threats = results.get('threats', [])
            if all_threats:
                print_threat_details(all_threats)
            
            # Save a special full scan report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"full_scan_{timestamp}.json"
            filepath = os.path.join(args.output, filename)
            
            # Add the additional threat detection results
            full_results = results.copy()
            full_results['dhcp_servers'] = list(dhcp_servers) if dhcp_servers else []
            full_results['rogue_dhcp_servers'] = rogue_dhcp_servers if rogue_dhcp_servers else []
            full_results['arp_threats'] = arp_threats if arp_threats else []
            full_results['dns_threats'] = dns_threats if dns_threats else []
            
            # Save to file
            with open(filepath, 'w') as f:
                json.dump(full_results, f, indent=2)
                
            print(f"\nFull scan report saved to {filepath}")
            
        elif args.threat_scan:
            results = run_scan(network_range, args.output, whitelist, previous_results, False)
            print_scan_summary(results)
            print_threat_details(results.get('threats', []))
        elif args.vuln_scan:
            results = run_scan(network_range, args.output, whitelist, previous_results, True)
            print_scan_summary(results)
            
            # Print details about vulnerabilities
            for device in results.get('devices', []):
                if 'vulnerability_report' in device and device.get('vulnerability_score', 0) > 5:
                    print_device_details(device, True)
        else:
            # Default to basic scan
            results = run_scan(network_range, args.output, whitelist, previous_results, False)
            print_scan_summary(results)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

def add_to_whitelist(address: str, whitelist: Dict[str, List], output_dir: str):
    """Add an IP or MAC address to the whitelist"""
    import re
    
    # Simple check for MAC format
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    # Simple check for IP format
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    if mac_pattern.match(address):
        # It's a MAC address
        address = address.upper()  # Normalize to uppercase
        if address not in whitelist['mac_addresses']:
            whitelist['mac_addresses'].append(address)
            save_whitelist(whitelist, output_dir)
            print(f"Added MAC address {address} to whitelist")
        else:
            print(f"MAC address {address} already in whitelist")
    elif ip_pattern.match(address):
        # It's an IP address
        if address not in whitelist['ip_addresses']:
            whitelist['ip_addresses'].append(address)
            save_whitelist(whitelist, output_dir)
            print(f"Added IP address {address} to whitelist")
        else:
            print(f"IP address {address} already in whitelist")
    else:
        print(f"Invalid address format: {address}")
        print("Please use format XX:XX:XX:XX:XX:XX for MAC or XXX.XXX.XXX.XXX for IP")

def show_whitelist(whitelist: Dict[str, List]):
    """Display the current whitelist"""
    print("\n" + "=" * 50)
    print("CURRENT WHITELIST")
    print("=" * 50)
    
    if not whitelist['mac_addresses'] and not whitelist['ip_addresses']:
        print("Whitelist is empty")
        return
        
    if whitelist['mac_addresses']:
        print("\nMAC Addresses:")
        for mac in sorted(whitelist['mac_addresses']):
            print(f"  {mac}")
            
    if whitelist['ip_addresses']:
        print("\nIP Addresses:")
        for ip in sorted(whitelist['ip_addresses']):
            print(f"  {ip}")
            
    print("=" * 50)

def show_device_details(ip: str, output_dir: str, whitelist: Dict[str, List], vuln_check: bool = False):
    """Show detailed information about a specific device"""
    # First try to find the device in previous scans
    prev_device = None
    prev_results = load_previous_results(output_dir)
    
    if prev_results and 'devices' in prev_results:
        for device in prev_results['devices']:
            if device.get('ip_address') == ip:
                prev_device = device
                break
    
    if prev_device:
        print_device_details(prev_device, vuln_check)
    else:
        # Device not found in previous results, scan it now
        scanner = NetworkScanner()
        fingerprinter = DeviceFingerprinter()
        
        print(f"Scanning device {ip}...")
        host_info = scanner.get_host_info(ip)
        
        if host_info['status'] == 'down':
            print(f"Device {ip} is not reachable")
            return
            
        # Get fingerprint
        fingerprint = fingerprinter.os_fingerprint(ip)
        
        # Get vendor
        vendor = None
        if host_info.get('mac_address'):
            vendor = fingerprinter.get_vendor_from_mac(host_info['mac_address'])
            
        # Create device dictionary
        device = {
            'ip_address': ip,
            'status': host_info.get('status', 'unknown'),
            'hostname': host_info.get('hostname'),
            'mac_address': host_info.get('mac_address'),
            'vendor': vendor,
            'os': host_info.get('os') or str(fingerprint.get('data', {})),
            'ports': host_info.get('ports', []),
            'device_type': 'unknown',  # Simple version for one-off scan
            'is_authorized': is_authorized(ip, host_info.get('mac_address'), whitelist),
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }
        
        # Perform vulnerability scan if requested
        if vuln_check:
            print("Running vulnerability scan...")
            vuln_results = scanner.perform_vulnerability_scan(ip)
            device['vulnerability_report'] = vuln_results
            
        print_device_details(device, vuln_check)

def is_authorized(ip: str, mac: Optional[str], whitelist: Dict[str, List]) -> bool:
    """Check if a device is authorized based on whitelist"""
    my_ip = get_my_ip_address()
    my_mac = get_my_mac_address()
    
    # Always authorize our device
    if ip == my_ip or mac == my_mac:
        return True
        
    # Check whitelist
    return (
        mac in whitelist.get('mac_addresses', []) or
        ip in whitelist.get('ip_addresses', [])
    )

def load_previous_results(output_dir: str) -> Optional[Dict[str, Any]]:
    """Load the most recent scan results"""
    import os
    import json
    
    # Look for scan files
    scan_files = []
    if os.path.exists(output_dir):
        for filename in os.listdir(output_dir):
            if filename.startswith('network_scan_') and filename.endswith('.json'):
                scan_files.append(filename)
    
    if not scan_files:
        return None
        
    # Sort by name (which includes timestamp)
    scan_files.sort(reverse=True)
    
    # Load the most recent file
    try:
        with open(os.path.join(output_dir, scan_files[0])) as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load previous results: {str(e)}")
        return None

def run_continuous_monitoring(network_range: str, output_dir: str, whitelist: Dict[str, List],
                            interval: int = 300, vuln_check: bool = False):
    """Run continuous monitoring with the specified interval"""
    print(f"\nStarting continuous monitoring of {network_range}")
    print(f"Scan interval: {interval} seconds")
    print("Press Ctrl+C to stop monitoring\n")
    
    scan_count = 0
    previous_results = None
    
    try:
        while True:
            scan_count += 1
            print(f"\nScan #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Run the scan
            results = run_scan(network_range, output_dir, whitelist, previous_results, vuln_check)
            
            # Update previous results for next scan
            previous_results = results
            
            # Print summary
            print_scan_summary(results)
            
            # Show threats if any
            threats = results.get('threats', [])
            if threats:
                print_threat_details(threats)
            
            # Wait for next scan
            if scan_count > 0:  # Skip wait on first run
                print(f"Next scan in {interval} seconds. Press Ctrl+C to stop.")
                for i in range(interval, 0, -1):
                    if i % 10 == 0 or i <= 5:  # Show countdown at intervals
                        sys.stdout.write(f"\rNext scan in {i} seconds...  ")
                        sys.stdout.flush()
                    time.sleep(1)
                print("\r" + " " * 40)  # Clear the countdown line
    
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")

if __name__ == "__main__":
    # Import platform here to avoid circular import when imported by other modules
    import platform
    sys.exit(main())