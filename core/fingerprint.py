# core/fingerprint.py
import platform
import subprocess
import re
import logging
import time
import os
from typing import Optional, Dict, List, Any
import socket
from config import vendors


class DeviceFingerprinter:
    """
    Enhanced device fingerprinting using multiple methods across platforms
    Handles OS detection, vendor identification, and device capability analysis
    """

    def __init__(self):
        """Initialize the fingerprinter with system detection and setup"""
        self.system = platform.system()
        self._setup_logging()

        # Check for mac vendor lookup availability
        try:
            from mac_vendor_lookup import MacLookup
            self.mac_lookup = MacLookup()
            self.mac_lookup_available = True

            # Update vendor database if not exists
            if not os.path.exists(
                    os.path.expanduser('~/.cache/mac-vendors.txt')):
                try:
                    self.mac_lookup.update_vendors()
                except Exception as e:
                    self.logger.warning(
                        f"Failed to update MAC vendor database: {str(e)}")
        except ImportError:
            self.logger.warning(
                "MAC vendor lookup not available. Using local database only.")
            self.mac_lookup = None
            self.mac_lookup_available = False

        # Check if p0f is available on Linux
        self.p0f_available = self._check_p0f_availability()

        # Check for zeroconf availability for macOS and mDNS
        try:
            import zeroconf
            self.zeroconf_available = True
        except ImportError:
            self.zeroconf_available = False
            self.logger.warning(
                "Zeroconf not available. mDNS discovery will be limited.")

    def _check_p0f_availability(self) -> bool:
        """Check if p0f is available on Linux"""
        if self.system != 'Linux':
            return False

        try:
            subprocess.run(['p0f', '-h'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           timeout=2)
            self.logger.info("p0f available for advanced fingerprinting")
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.info(
                "p0f not available, using fallback fingerprinting")
            return False

    def _setup_logging(self):
        """Initialize logging for the fingerprint module"""
        self.logger = logging.getLogger(__name__)

        # Only add handlers if none exist to avoid duplicates
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        self.logger.setLevel(logging.INFO)

    def get_vendor_from_mac(self, mac: str) -> Optional[str]:
        """
        Get vendor from MAC using multiple methods with fallbacks:
        1. Local vendor database
        2. mac-vendor-lookup package
        3. Online API as last resort
        
        Args:
            mac: MAC address to look up
            
        Returns:
            Vendor name or None if not identifiable
        """
        if not mac:
            return None

        # Normalize MAC for database lookup
        mac_norm = mac.upper().replace(':', '').replace('-', '')[:6]

        # 1. Check local OUI database
        if mac_norm in vendors.VENDOR_OUI:
            return vendors.VENDOR_OUI[mac_norm]

        # 2. Try mac-vendor-lookup package if available
        if self.mac_lookup_available and self.mac_lookup:
            try:
                return self.mac_lookup.lookup(mac)
            except Exception as e:
                self.logger.debug(f"MAC vendor lookup failed: {str(e)}")

        # 3. Fallback to online API if all else fails
        try:
            import requests
            response = requests.get(f"https://api.macvendors.com/{mac_norm}",
                                    timeout=2)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.debug(f"MAC vendor online API failed: {str(e)}")

        return None

    def os_fingerprint(self, ip: str) -> Dict:
        """
        Platform-specific OS fingerprinting with guaranteed dict return
        
        Args:
            ip: IP address to fingerprint
            
        Returns:
            Dictionary with fingerprinting results
        """
        try:
            # Route to appropriate platform-specific method
            if self.system == 'Linux':
                if self.p0f_available:
                    return self._p0f_fingerprint(ip)
                else:
                    return self._linux_fingerprint(ip)
            elif self.system == 'Windows':
                return self._windows_fingerprint(ip)
            elif self.system == 'Darwin':  # macOS
                return self._macos_fingerprint(ip)
            else:
                return {'method': 'unknown', 'data': {}, 'confidence': 'none'}
        except Exception as e:
            self.logger.error(f"OS fingerprinting failed for {ip}: {str(e)}")

        # Default fallback
        return {'method': 'failed', 'data': {}, 'confidence': 'low'}

    def _linux_fingerprint(self, ip: str) -> Dict:
        """
        Linux: Use combination of methods when p0f is unavailable
        
        Args:
            ip: IP address to fingerprint
            
        Returns:
            Fingerprint data dictionary
        """
        result = {'method': 'linux', 'data': {}, 'confidence': 'low'}

        try:
            # Try TTL-based OS detection (simple but sometimes effective)
            ttl = self._get_ttl(ip)
            if ttl:
                result['data']['ttl'] = ttl
                os_guess = self._guess_os_from_ttl(ttl)
                if os_guess:
                    result['data']['os_family'] = os_guess
                    result['confidence'] = 'medium'

            # Try port scan fingerprinting (relies on OS behavior differences)
            open_ports = self._scan_common_ports(ip)
            if open_ports:
                result['data']['open_ports'] = open_ports

                # Check for OS-specific port signatures
                if 3389 in open_ports:  # RDP
                    result['data']['os_hints'] = 'Windows'
                    result['confidence'] = 'medium'
                elif 22 in open_ports and 631 in open_ports:  # SSH + CUPS
                    result['data']['os_hints'] = 'Linux/Unix'
                    result['confidence'] = 'medium'
                elif 548 in open_ports or 5009 in open_ports:  # AFP or AirPlay
                    result['data']['os_hints'] = 'macOS'
                    result['confidence'] = 'medium'
        except Exception as e:
            self.logger.debug(f"Linux fingerprinting error: {str(e)}")

        return result

    def _p0f_fingerprint(self, ip: str) -> Dict:
        """
        Linux: Use p0f for advanced OS fingerprinting if available
        
        Args:
            ip: IP address to fingerprint
            
        Returns:
            p0f fingerprint data
        """
        result = {'method': 'p0f', 'data': {}, 'confidence': 'high'}

        try:
            # Run p0f for this IP
            output = subprocess.check_output(
                ['p0f', '-o', '/dev/stdout', '-s', ip],
                universal_newlines=True,
                timeout=5)

            # Parse results
            if 'os =' in output:
                os_match = re.search(r'os = ([^\n]+)', output)
                if os_match:
                    result['data']['os'] = os_match.group(1).strip()

            if 'dist =' in output:
                dist_match = re.search(r'dist = ([^\n]+)', output)
                if dist_match:
                    result['data']['dist'] = dist_match.group(1).strip()

            # Full output for reference
            result['data']['raw'] = output
        except Exception as e:
            self.logger.debug(f"p0f fingerprinting error: {str(e)}")
            result['confidence'] = 'low'

        return result

    def _windows_fingerprint(self, ip: str) -> Dict:
        """
        Windows: Use NetBIOS and ARP for identifying hosts
        
        Args:
            ip: IP address to fingerprint
            
        Returns:
            Windows fingerprint data
        """
        result = {'method': 'windows', 'data': {}, 'confidence': 'low'}

        try:
            # Try NetBIOS name lookup
            output = subprocess.check_output(['nbtstat', '-A', ip],
                                             universal_newlines=True,
                                             timeout=5)

            # Parse results for computer name and OS/service info
            host_match = re.search(r'<00>\s+UNIQUE\s+([^\s]+)', output)
            if host_match:
                result['data']['netbios_name'] = host_match.group(1)
                result['confidence'] = 'medium'

            # Look for workgroup/domain
            domain_match = re.search(r'<00>\s+GROUP\s+([^\s]+)', output)
            if domain_match:
                result['data']['domain'] = domain_match.group(1)

            # Check for server service (indicates Windows Server)
            if '<20>' in output:
                result['data']['os_hints'] = 'Windows Server'
                result['confidence'] = 'medium'
        except Exception as e:
            self.logger.debug(
                f"Windows NetBIOS fingerprinting error: {str(e)}")

        # Fall back to TTL detection
        if 'os_hints' not in result['data']:
            ttl = self._get_ttl(ip)
            if ttl:
                result['data']['ttl'] = ttl
                os_guess = self._guess_os_from_ttl(ttl)
                if os_guess:
                    result['data']['os_family'] = os_guess

        return result

    def _macos_fingerprint(self, ip: str) -> Dict:
        """
        macOS: Use arp + mDNS for enhanced fingerprinting
        
        Args:
            ip: IP address to fingerprint
            
        Returns:
            macOS fingerprint data
        """
        result = {'method': 'macos', 'data': {}, 'confidence': 'low'}

        # First try mDNS if zeroconf is available
        if self.zeroconf_available:
            try:
                import zeroconf
                from zeroconf import ServiceBrowser, Zeroconf

                listener = MyListener()
                zc = Zeroconf()

                # Browse for services on target IP
                browser = ServiceBrowser(zc, "_services._dns-sd._udp.local.",
                                         listener)

                # Wait for responses
                time.sleep(3)
                zc.close()

                # Process results
                services = listener.get_results()
                if services:
                    result['data']['mdns_services'] = services
                    result['confidence'] = 'medium'

                    # If we find Apple-specific services, flag as probable macOS/iOS
                    apple_services = [
                        s for s in services
                        if any(x in s.lower()
                               for x in ('apple', 'airplay', 'airport'))
                    ]
                    if apple_services:
                        result['data']['os_hints'] = 'Apple (macOS/iOS)'
                        result['confidence'] = 'high'
            except Exception as e:
                self.logger.debug(f"mDNS fingerprinting error: {str(e)}")

        # Fall back to TTL detection
        if 'os_hints' not in result['data']:
            ttl = self._get_ttl(ip)
            if ttl:
                result['data']['ttl'] = ttl
                os_guess = self._guess_os_from_ttl(ttl)
                if os_guess:
                    result['data']['os_family'] = os_guess

        return result

    def dhcp_fingerprint(self, pkt) -> Optional[Dict]:
        """
        Extract fingerprinting information from DHCP packets
        
        Args:
            pkt: Packet from scapy with DHCP layer
            
        Returns:
            Dictionary with DHCP fingerprint info or None
        """
        try:
            from scapy.all import DHCP

            if not DHCP in pkt:
                return None

            options = dict([(opt[0], opt[1:]) for opt in pkt[DHCP].options
                            if isinstance(opt, tuple)])

            # Get hostname from DHCP request
            hostname = None
            if 'hostname' in options:
                hostname = options['hostname'][0]

            # Get vendor class identifier
            vendor_class = None
            if 'vendor_class_id' in options:
                vendor_class = options['vendor_class_id'][0]

            # Get parameter request list (useful for OS fingerprinting)
            param_list = None
            if 'param_req_list' in options:
                param_list = options['param_req_list']

            # Build fingerprint
            result = {
                'timestamp': time.time(),
                'hostname': hostname,
                'vendor_class': vendor_class,
                'param_list': param_list
            }

            # Try to guess OS from DHCP parameters
            os_hint = self._dhcp_os_hint(result)
            if os_hint:
                result['os_hint'] = os_hint

            return result
        except Exception as e:
            self.logger.debug(f"DHCP fingerprinting error: {str(e)}")
            return None

    def _dhcp_os_hint(self, dhcp_fingerprint: Dict) -> Optional[str]:
        """
        Extract OS hints from DHCP parameters
        
        Args:
            dhcp_fingerprint: DHCP fingerprint dictionary
            
        Returns:
            OS family hint or None
        """
        vendor_class = dhcp_fingerprint.get('vendor_class')
        if not vendor_class:
            return None

        vendor_class = vendor_class.lower()

        # Common OS signatures
        if 'msft' in vendor_class or 'windows' in vendor_class:
            return 'Windows'
        elif 'android' in vendor_class:
            return 'Android'
        elif 'darwin' in vendor_class or 'mac' in vendor_class or 'ios' in vendor_class:
            return 'Apple'
        elif 'linux' in vendor_class or 'ubuntu' in vendor_class or 'debian' in vendor_class:
            return 'Linux'

        return None

    def _get_ttl(self, ip: str) -> Optional[int]:
        """
        Get TTL value from ping response for OS detection
        
        Args:
            ip: IP address to ping
            
        Returns:
            TTL value or None if not available
        """
        try:
            # Different ping commands for different platforms
            if self.system == 'Windows':
                output = subprocess.check_output(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    universal_newlines=True,
                    timeout=2)
                ttl_match = re.search(r'TTL=(\d+)', output)
            else:  # Linux, macOS
                output = subprocess.check_output(
                    ['ping', '-c', '1', '-W', '1', ip],
                    universal_newlines=True,
                    timeout=2)
                ttl_match = re.search(r'ttl=(\d+)', output)

            if ttl_match:
                return int(ttl_match.group(1))
        except Exception as e:
            self.logger.debug(f"TTL detection error for {ip}: {str(e)}")

        return None

    def _guess_os_from_ttl(self, ttl: int) -> Optional[str]:
        """
        Guess OS from TTL value (very approximate)
        
        Args:
            ttl: TTL value from ping
            
        Returns:
            OS family guess or None
        """
        # TTL values are often set to these defaults by different OSes
        # but can be changed by users, so this is approximate
        if ttl <= 64:
            return 'Linux/Unix'
        elif ttl <= 128:
            return 'Windows'
        elif ttl <= 255:
            return 'Cisco/Network'

        return None

    def _scan_common_ports(self, ip: str) -> List[int]:
        """
        Quick scan of common ports for fingerprinting
        
        Args:
            ip: IP address to scan
            
        Returns:
            List of open ports
        """
        open_ports = []
        common_ports = [21, 22, 23, 25, 80, 139, 443, 445, 3389, 5900, 8080]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)  # Very short timeout for quick scanning
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        return open_ports


class MyListener:
    """Helper for mDNS discovery on macOS"""

    def __init__(self):
        self.services = []

    def add_service(self, zeroconf, type, name):
        """
        Service discovered callback
        
        Args:
            zeroconf: Zeroconf instance
            type: Service type
            name: Service name
        """
        self.services.append(name)

    def get_results(self):
        """
        Get discovered services
        
        Returns:
            List of service names or None
        """
        return self.services if self.services else None
