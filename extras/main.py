#!/usr/bin/env python3
"""
Network Monitoring System
A cross-platform tool for real-time network device detection and security analysis
Terminal-only version without web dashboard

This file provides a Flask app bridge for Replit's workflow system.
The actual terminal app functionality is in network_monitor.py and run_monitor.py.
"""

import logging
import os
import sys
import platform
import argparse
from datetime import datetime
import time

# Core components
from core.scanner import NetworkScanner
from core.detector import ThreatDetector
from core.fingerprint import DeviceFingerprinter
from utils.network import get_my_ip_address, get_my_mac_address, get_network_cidr, get_default_gateway
from utils.helpers import load_whitelist, save_whitelist, save_results
from config import settings

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_monitor.log"),
        logging.StreamHandler()
    ])
logger = logging.getLogger(__name__)

# Create output directory
os.makedirs(settings.OUTPUT_DIR, exist_ok=True)


class NetworkMonitor:
    """Main monitoring class that coordinates scanning and detection"""

    def __init__(self, network_range=None, terminal_mode=False):
        """Initialize the network monitor"""
        self.scanner = NetworkScanner()
        self.detector = ThreatDetector()
        self.fingerprinter = DeviceFingerprinter()
        self.my_mac = get_my_mac_address()
        self.my_ip = get_my_ip_address()
        self.network_range = network_range or settings.DEFAULT_NETWORK_RANGE
        self.whitelist = load_whitelist(settings.OUTPUT_DIR)
        self.known_devices = {}
        self.terminal_mode = terminal_mode

        # Auto-detect network if not specified
        if not self.network_range:
            detected_network = get_network_cidr()
            if detected_network:
                self.network_range = detected_network
                logger.info(
                    f"Auto-detected network range: {self.network_range}")
            else:
                logger.warning(
                    "Could not auto-detect network range, using default")

        logger.info(
            f"Monitor initialized - IP: {self.my_ip}, MAC: {self.my_mac}")
        logger.info(f"Network range: {self.network_range}")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        logger.info(f"Terminal mode: {terminal_mode}")

    def run_scan(self):
        """Run a network scan and process results"""
        logger.info(f"Starting scan on {self.network_range}")

        try:
            # Scan the network
            hosts = self.scanner.scan_network(self.network_range)
            logger.info(f"Found {len(hosts)} hosts")

            # Process each host
            devices = []
            for host in hosts:
                device = self._process_host(host)
                devices.append(device.to_dict())

            # Check for threats
            threats = self.detector.analyze_scan_results({
                "devices": devices
            }, self.whitelist, {
                "devices": [d.to_dict() for d in self.known_devices.values()]
            } if self.known_devices else None)

            # Create results dictionary
            results = {
                "scan_time": datetime.now().isoformat(),
                "platform": platform.system(),
                "network_range": self.network_range,
                "devices": devices,
                "threats": threats,
                "stats": self._calculate_stats(devices, threats)
            }

            # Save results
            filename = save_results(results, settings.OUTPUT_DIR,
                                    "network_scan")
            logger.info(f"Scan results saved to {filename}")

            return results
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {"error": str(e), "scan_time": datetime.now().isoformat()}

    def _process_host(self, host):
        """Process a single host and get its information"""
        from core.models import Device, PortInfo

        # Get host information from scanner
        host_info = self.scanner.get_host_info(host)

        # Get OS fingerprint information
        fingerprint = self.fingerprinter.os_fingerprint(host)

        # Get vendor information
        vendor = None
        if host_info.get('mac_address'):
            vendor = self.fingerprinter.get_vendor_from_mac(
                host_info['mac_address'])

        # Check if device is new
        is_new = host not in self.known_devices
        first_seen = datetime.now().isoformat(
        ) if is_new else self.known_devices.get(host, {}).get('first_seen')

        # Check if device is authorized
        is_authorized = self._check_authorization(host,
                                                  host_info.get('mac_address'))

        # Convert port information to PortInfo objects
        ports = []
        for port_dict in host_info.get('ports', []):
            ports.append(
                PortInfo(port=port_dict.get('port'),
                         protocol=port_dict.get('protocol', 'tcp'),
                         service=port_dict.get('service', 'unknown'),
                         version=port_dict.get('version', ''),
                         cpe=port_dict.get('cpe', '')))

        # Create Device object
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

        # Log if new device detected
        if is_new:
            status = "Authorized" if is_authorized else "⚠️ UNAUTHORIZED"
            logger.info(
                f"New device: {host} ({device.mac_address or 'Unknown MAC'}) - {status}"
            )

        # Update known devices
        self.known_devices[host] = device
        return device

    def _check_authorization(self, ip, mac):
        """Check if a device is authorized"""
        # Always authorize our device
        if ip == self.my_ip or mac == self.my_mac:
            return True

        # Check whitelist
        return (mac in self.whitelist.get('mac_addresses', [])
                or ip in self.whitelist.get('ip_addresses', []))

    def _determine_device_type(self, host_info, fingerprint):
        """Determine the device type based on fingerprint and port data"""
        # Start with a default type
        device_type = "unknown"

        # Check if this is our own device
        if host_info.get('ip_address') == self.my_ip:
            return "this_device"

        # Check if this might be a router/gateway
        if host_info.get('ip_address') == get_default_gateway():
            return "router"

        # Check for OS-specific device types
        os_info = host_info.get('os', '').lower()
        if 'linux' in os_info or 'ubuntu' in os_info or 'debian' in os_info:
            device_type = "linux_server"
        elif 'windows' in os_info:
            if 'server' in os_info:
                device_type = "windows_server"
            else:
                device_type = "windows_host"
        elif 'mac' in os_info or 'darwin' in os_info:
            device_type = "mac_host"
        elif 'ios' in os_info or 'iphone' in os_info or 'ipad' in os_info:
            device_type = "mobile"
        elif 'android' in os_info:
            device_type = "mobile"

        # Check fingerprint data for more clues
        fingerprint_data = fingerprint.get('data', {})

        # Look for clues in MDNS data (for Apple, Chromecast devices)
        if 'mdns_services' in fingerprint_data and fingerprint_data[
                'mdns_services']:
            services = fingerprint_data['mdns_services']
            if any('_airplay' in s for s in services):
                device_type = "apple_tv"
            elif any('_spotify' in s for s in services):
                device_type = "media_player"
            elif any('_googlecast' in s for s in services):
                device_type = "chromecast"

        # Check port signatures
        ports = [p.get('port') for p in host_info.get('ports', [])]
        if 22 in ports and 80 in ports and 443 in ports:
            device_type = "server"
        elif 80 in ports and 443 in ports and 8080 in ports:
            device_type = "web_server"
        elif 22 in ports and 5432 in ports:
            device_type = "database_server"
        elif 53 in ports:
            device_type = "dns_server"
        elif 21 in ports or 20 in ports:
            device_type = "ftp_server"
        elif 25 in ports or 587 in ports or 465 in ports:
            device_type = "mail_server"
        elif 3389 in ports:
            device_type = "windows_rdp"
        elif any(p in ports for p in [515, 631, 9100]):
            device_type = "printer"
        elif any(p in ports for p in [1883, 8883, 5683]):
            device_type = "iot_device"
        elif 554 in ports or 10554 in ports:
            device_type = "camera"

        # Check hostname for clues
        hostname = host_info.get('hostname', '').lower()
        if hostname:
            if any(n in hostname
                   for n in ['router', 'gateway', 'modem', 'ap']):
                device_type = "router"
            elif any(n in hostname for n in ['printer', 'prt', 'print']):
                device_type = "printer"
            elif any(n in hostname for n in ['cam', 'camera', 'ipcam']):
                device_type = "camera"
            elif any(n in hostname
                     for n in ['phone', 'mobile', 'ipad', 'tablet']):
                device_type = "mobile"
            elif 'server' in hostname:
                device_type = "server"

        return device_type

    def _calculate_stats(self, devices, threats):
        """Calculate statistics from scan results"""
        stats = {
            "total_hosts":
            len(devices),
            "alive_hosts":
            sum(1 for d in devices if d.get('status') == 'up'),
            "new_devices":
            sum(1 for d in devices if d.get('is_new')),
            "unauthorized_devices":
            sum(1 for d in devices if not d.get('is_authorized')),
            "device_types": {},
            "os_distribution": {},
            "threats": {
                "total": len(threats),
                "by_type": {}
            }
        }

        # Count device types
        for device in devices:
            dtype = device.get('device_type', 'unknown')
            stats["device_types"][dtype] = stats["device_types"].get(dtype,
                                                                     0) + 1

            # Track OS distribution
            if device.get('os'):
                os_name = device['os'].split(
                )[0] if device['os'] else "unknown"
                stats["os_distribution"][
                    os_name] = stats["os_distribution"].get(os_name, 0) + 1

        # Count threat types
        for threat in threats:
            threat_type = threat.get('threat_type', 'unknown')
            stats["threats"][
                "by_type"][threat_type] = stats["threats"]["by_type"].get(
                    threat_type, 0) + 1

        return stats

    def start_monitoring(self, interval=None):
        """Start continuous monitoring"""
        scan_interval = interval or settings.SCAN_INTERVAL

        logger.info(
            f"Starting continuous monitoring (interval: {scan_interval}s)")
        try:
            previous_results = None
            scan_count = 0

            while True:
                scan_count += 1
                logger.info(f"Starting scan cycle #{scan_count}")

                # Run scan
                results = self.run_scan()
                previous_results = results

                # Wait for next scan
                next_scan = time.time() + scan_interval
                logger.info(
                    f"Next scan at {datetime.fromtimestamp(next_scan).strftime('%H:%M:%S')}"
                )
                time.sleep(scan_interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            print("\nMonitoring stopped.")


def run_terminal_mode():
    """Run in terminal mode (redirects to the run_monitor.py script)"""
    import run_monitor
    logger.info("Starting in terminal mode")
    run_monitor.main()


def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(description='Network Monitoring System')
    parser.add_argument('-n',
                        '--network',
                        help='Network range to scan (CIDR notation)')
    parser.add_argument('-i',
                        '--interval',
                        type=int,
                        help='Scan interval in seconds')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('-s',
                        '--single',
                        action='store_true',
                        help='Run a single scan and exit')
    parser.add_argument('-m',
                        '--monitor',
                        action='store_true',
                        help='Run continuous monitoring')
    parser.add_argument('-t',
                        '--threats',
                        action='store_true',
                        help='Focus on threat detection')

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run terminal mode
    run_terminal_mode()


if __name__ == "__main__":
    main()