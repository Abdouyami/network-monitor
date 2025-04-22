# core/detector.py
import logging
import time
from typing import List, Dict, Any, Set, Optional, Tuple
from collections import defaultdict
from scapy.all import ARP, sniff, sr1, sendp, Ether, IP, UDP, BOOTP, DHCP, srp, DNS, DNSRR
from datetime import datetime
from config import settings
from utils.network import get_default_gateway

class ThreatDetector:
    """
    Detect various network threats including rogue DHCP servers,
    unauthorized devices, port scans, and other suspicious activity
    """
    
    def __init__(self):
        """Initialize the threat detector"""
        self.logger = logging.getLogger(__name__)
        self.dhcp_servers = set()
        self.authorized_dhcp = None  # Will be populated with default gateway
        self.port_scan_alerts = {}
        self.previous_scans = {}
    
    def detect_dhcp_spoofing(self, duration: int = None) -> Set[str]:
     """
     Detect DHCP spoofing by sniffing DHCP offers and tracking servers

     Args:
         duration: How long to sniff for DHCP packets (seconds)

     Returns:
         Set of detected DHCP server IPs
     """
     if not settings.ENABLE_DHCP_DETECTION:
         self.logger.info("DHCP detection disabled in settings")
         return set()

     if duration is None:
         duration = settings.DHCP_SNIFF_DURATION

     try:
         from scapy.all import sniff, DHCP, IP, Ether

         self.logger.info(f"Starting DHCP server detection (duration: {duration}s)")

         # Get authorized DHCP server (usually the default gateway)
         if not self.authorized_dhcp:
             self.authorized_dhcp = get_default_gateway()
             self.logger.info(f"Assuming default gateway as authorized DHCP: {self.authorized_dhcp}")

         # Track detailed information about DHCP servers
         self.dhcp_server_details = {}

         # Set up callback for DHCP packets
         def callback(pkt):
             if DHCP in pkt:
                 # Get DHCP message type
                 msg_type = None
                 for option in pkt[DHCP].options:
                     if isinstance(option, tuple) and option[0] == 'message-type':
                         msg_type = option[1]
                         break
                        
                 server_ip = pkt[IP].src
                 server_mac = pkt[Ether].src

                 # Initialize server details if not seen before
                 if server_ip not in self.dhcp_server_details:
                     self.dhcp_server_details[server_ip] = {
                         'ip': server_ip,
                         'mac': server_mac,
                         'offered_ips': set(),
                         'timestamps': [],
                         'message_types': set(),
                         'options': {},
                         'count': 0,
                         'is_authorized': server_ip == self.authorized_dhcp
                     }

                 # Add this timestamp
                 self.dhcp_server_details[server_ip]['timestamps'].append(time.time())
                 self.dhcp_server_details[server_ip]['count'] += 1

                 # Track message types seen
                 if msg_type:
                     self.dhcp_server_details[server_ip]['message_types'].add(msg_type)

                 # For DHCP offers, track the offered IP
                 if msg_type == 2:  # DHCP Offer
                     self.dhcp_servers.add(server_ip)
                     offered_ip = pkt[BOOTP].yiaddr
                     self.dhcp_server_details[server_ip]['offered_ips'].add(offered_ip)

                     # Get gateway and DNS options
                     for option in pkt[DHCP].options:
                         if isinstance(option, tuple):
                             option_name, option_value = option[0], option[1]

                             # Store options of interest
                             if option_name in ['router', 'name_server', 'lease_time', 'subnet_mask']:
                                 if option_name not in self.dhcp_server_details[server_ip]['options']:
                                     self.dhcp_server_details[server_ip]['options'][option_name] = set()

                                 # Convert to string for sets if needed
                                 if isinstance(option_value, list):
                                     for val in option_value:
                                         self.dhcp_server_details[server_ip]['options'][option_name].add(str(val))
                                 else:
                                     self.dhcp_server_details[server_ip]['options'][option_name].add(str(option_value))

                     self.logger.info(f"Detected DHCP server: {server_ip} offering {offered_ip}")
                     if server_ip != self.authorized_dhcp:
                         self.logger.warning(f"Potential rogue DHCP server: {server_ip}")
                         print(f"⚠️-- Potential rogue DHCP server: {server_ip} detected offering {offered_ip}!")

         # Sniff for DHCP traffic
         sniff(filter="udp and (port 67 or 68)", prn=callback, timeout=duration)

         # Calculate frequency of packets for each server
         for ip, details in self.dhcp_server_details.items():
             if len(details['timestamps']) > 1:
                 time_diff = details['timestamps'][-1] - details['timestamps'][0]
                 if time_diff > 0:
                     details['frequency'] = details['count'] / time_diff
                 else:
                     details['frequency'] = details['count']
             else:
                 details['frequency'] = 0

         self.logger.info(f"DHCP detection completed. Found {len(self.dhcp_servers)} servers")
         return self.dhcp_servers, self.dhcp_server_details
     except ImportError:
         self.logger.error("Scapy not available for DHCP detection")
         return set()
     except Exception as e:
         self.logger.error(f"DHCP detection failed: {str(e)}")
         return set()
        
    def detect_rogue_dhcp_servers(self) -> List[Dict[str, Any]]:
        """
        Advanced method to actively detect rogue DHCP servers

        Returns:
            List of rogue DHCP server details
        """
        if not settings.ENABLE_DHCP_DETECTION:
            return []

        try:
            from utils.network import detect_rogue_dhcp_servers
            from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, RandMAC

            # Get default gateway (legitimate DHCP server)
            gw = get_default_gateway()
            legitimate_servers = [gw] if gw else []

            # Send a few DHCP discovers to stimulate responses
            self._send_dhcp_discover_probes()

            # Use the detailed information collected during detect_dhcp_spoofing
            results = []
            for ip, details in getattr(self, 'dhcp_server_details', {}).items():
                if ip != self.authorized_dhcp:
                    # Calculate attack characteristics
                    attack_type = "Unknown"
                    threat_level = "medium"

                    # Determine attack type and severity
                    if details.get('frequency', 0) > 1.0:  # More than 1 packet per second
                        attack_type = "Aggressive flooding"
                        threat_level = "high"
                    elif len(details.get('offered_ips', set())) > 5:
                        attack_type = "Multiple IP offerings"
                        threat_level = "high"

                    # Add detailed information from the detected server
                    result_entry = {
                        'ip': ip,
                        'mac': details.get('mac', 'Unknown'),
                        'timestamp': datetime.now().isoformat(),
                        'threat_type': 'rogue_dhcp',
                        'attack_type': attack_type,
                        'severity': threat_level,
                        'frequency': f"{details.get('frequency', 0):.2f} packets/sec",
                        'offered_ips': list(details.get('offered_ips', [])),
                        'message_types': list(details.get('message_types', [])),
                        'gateway_offered': list(details.get('options', {}).get('router', ['None'])),
                        'dns_offered': list(details.get('options', {}).get('name_server', ['None'])),
                        'lease_time': list(details.get('options', {}).get('lease_time', ['Unknown'])),
                        'subnet_mask': list(details.get('options', {}).get('subnet_mask', ['Unknown'])),
                        'details': 'Unauthorized DHCP server detected - may cause network disruption or facilitate man-in-the-middle attacks'
                    }

                    results.append(result_entry)

            return results
        except Exception as e:
            self.logger.error(f"Rogue DHCP server detection failed: {str(e)}")
            return []


    def detect_port_scanning(self, ip: str, recent_ports: List[int], 
                          timeframe: int = 60, threshold: int = 15) -> Optional[Dict[str, Any]]:
        """
        Detect if a host is potentially port scanning the network
        
        Args:
            ip: IP address of the potential scanner
            recent_ports: List of ports this host has connected to recently
            timeframe: Timeframe to consider for port scan detection (seconds)
            threshold: Number of distinct ports within timeframe to trigger alert
            
        Returns:
            Alert dictionary if port scan detected, None otherwise
        """
        current_time = time.time()
        
        # Check if we've seen this IP before
        if ip not in self.port_scan_alerts:
            self.port_scan_alerts[ip] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'alert_generated': False,
                'ports': set(recent_ports)
            }
            return None
        
        # Update tracking info
        self.port_scan_alerts[ip]['last_seen'] = current_time
        self.port_scan_alerts[ip]['ports'].update(recent_ports)
        
        # Check if still within detection timeframe
        time_diff = current_time - self.port_scan_alerts[ip]['first_seen']
        
        # If we've exceeded our timeframe, reset the counter
        if time_diff > timeframe:
            self.port_scan_alerts[ip]['first_seen'] = current_time
            self.port_scan_alerts[ip]['ports'] = set(recent_ports)
            self.port_scan_alerts[ip]['alert_generated'] = False
            return None
            
        # Check if enough unique ports have been accessed to trigger alert
        if (len(self.port_scan_alerts[ip]['ports']) >= threshold and 
                not self.port_scan_alerts[ip]['alert_generated']):
            self.port_scan_alerts[ip]['alert_generated'] = True
            
            return {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'threat_type': 'port_scan',
                'severity': 'medium',
                'details': f"Host accessed {len(self.port_scan_alerts[ip]['ports'])} unique ports in {time_diff:.1f} seconds",
                'ports': list(self.port_scan_alerts[ip]['ports'])
            }
            
        return None
        
    def detect_unauthorized_device(self, device_data: Dict[str, Any], 
                                whitelist: Dict[str, List]) -> Optional[Dict[str, Any]]:
        """
        Check if a device is authorized according to the whitelist
        
        Args:
            device_data: Device information dictionary
            whitelist: Whitelist of allowed IPs and MACs
            
        Returns:
            Alert dictionary if unauthorized, None otherwise
        """
        ip = device_data.get('ip_address')
        mac = device_data.get('mac_address')
        hostname = device_data.get('hostname')
        
        # Skip if no identifiers
        if not ip and not mac:
            return None
            
        # Check whitelist
        if (ip in whitelist.get('ip_addresses', []) or 
                (mac and mac in whitelist.get('mac_addresses', []))):
            return None
            
        # Create alert for unauthorized device
        return {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'timestamp': datetime.now().isoformat(),
            'threat_type': 'unauthorized_device',
            'severity': 'medium',
            'details': f"Unauthorized device detected with hostname: {hostname or 'Unknown'}"
        }
    
    def detect_unauthorized_devices(self, devices: List[Dict[str, Any]], 
                                 whitelist: Dict[str, List]) -> List[Dict[str, Any]]:
        """
        Check multiple devices against the whitelist
        
        Args:
            devices: List of device information dictionaries
            whitelist: Whitelist of allowed IPs and MACs
            
        Returns:
            List of unauthorized device alerts
        """
        unauthorized = []
        
        for device in devices:
            result = self.detect_unauthorized_device(device, whitelist)
            if result:
                unauthorized.append(result)
                
        return unauthorized
        
    def detect_network_changes(self, current_devices: Dict[str, Dict], 
                             previous_devices: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """
        Detect significant network changes between scans
        
        Args:
            current_devices: Current scan results (IP -> device info)
            previous_devices: Previous scan results (IP -> device info)
            
        Returns:
            List of change alerts
        """
        if not previous_devices:
            return []
            
        changes = []
        
        # Check for MAC changes (potential spoofing)
        for ip, device in current_devices.items():
            if ip in previous_devices:
                # Check if MAC changed for same IP
                prev_mac = previous_devices[ip].get('mac_address')
                curr_mac = device.get('mac_address')
                
                if prev_mac and curr_mac and prev_mac != curr_mac:
                    changes.append({
                        'ip': ip,
                        'old_mac': prev_mac,
                        'new_mac': curr_mac,
                        'timestamp': datetime.now().isoformat(),
                        'threat_type': 'mac_changed',
                        'severity': 'high',
                        'details': f"MAC address changed for {ip} from {prev_mac} to {curr_mac}"
                    })
                
                # Check for new open ports on existing device
                prev_ports = set(p.get('port') for p in previous_devices[ip].get('ports', []))
                curr_ports = set(p.get('port') for p in device.get('ports', []))
                
                new_ports = curr_ports - prev_ports
                if new_ports:
                    changes.append({
                        'ip': ip,
                        'mac': curr_mac,
                        'timestamp': datetime.now().isoformat(),
                        'threat_type': 'new_ports',
                        'severity': 'medium',
                        'details': f"New ports detected on {ip}: {new_ports}",
                        'new_ports': list(new_ports)
                    })
        
        return changes
        
    def analyze_scan_results(self, scan_results: Dict[str, Any], 
                          whitelist: Dict[str, List],
                          previous_results: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Analyze a full scan for potential threats/issues
        
        Args:
            scan_results: Complete scan results
            whitelist: Whitelist of allowed devices
            previous_results: Prior scan results for comparison
            
        Returns:
            List of threats/issues detected
        """
        threats = []
        
        # Get device list
        devices = scan_results.get('devices', [])
        
        # Convert to IP-keyed dictionaries for easier comparison
        current_devices = {d.get('ip_address'): d for d in devices}
        prev_devices = {}
        
        if previous_results and 'devices' in previous_results:
            prev_devices = {d.get('ip_address'): d for d in previous_results['devices']}
        
        # Check for unauthorized devices
        unauthorized = self.detect_unauthorized_devices(devices, whitelist)
        threats.extend(unauthorized)
        
        # Check for network changes
        changes = self.detect_network_changes(current_devices, prev_devices)
        threats.extend(changes)
        
        # Scan devices for port scan behavior
        for device in devices:
            # Skip our own device
            if device.get('is_scanner', False):
                continue
                
            # Get a list of ports that this device has open
            recent_ports = [p.get('port') for p in device.get('ports', [])]
            
            # Check if the device is port scanning
            if recent_ports:
                port_scan = self.detect_port_scanning(
                    device.get('ip_address'),
                    recent_ports
                )
                
                if port_scan:
                    threats.append(port_scan)
        
        return threats


    def detect_arp_spoofing(self, duration: int = 60) -> List[Dict[str, Any]]:
        """
        Detect ARP spoofing activity by sniffing and tracking IP->MAC mappings,
        and identifying victims that were targeted with fake responses.

        Returns:
            List of spoofing incidents with IPs, MACs, and victims
        """
        def resolve_real_mac(ip: str) -> str:
            """Actively fetch the real MAC of a device before scanning"""
            try:
                ans = sr1(ARP(pdst=ip), timeout=2, verbose=0)
                if ans:
                    return ans[ARP].hwsrc
            except:
                return None
            return None
        
        self.logger.info(f"Starting ARP spoofing detection (duration: {duration}s)")

        try:
            ip_mac_mappings = defaultdict(set)       # Tracks which MACs claim each IP
            victim_targets = defaultdict(set)        # Tracks which devices were targeted per spoofed IP
            known_legit_macs = {}                    # Optional: Preload legit MACs

            # 🔐 Step 1: Actively resolve legit MACs for critical IPs (like your router)
            critical_ips = ["192.168.100.1"]  # You can add more if needed
            for ip in critical_ips:
                real_mac = resolve_real_mac(ip)
                if real_mac:
                    known_legit_macs[ip] = real_mac
                    self.logger.info(f"Resolved legit MAC for {ip}: {real_mac}")

            # 📡 Step 2: Sniff ARP traffic
            def arp_monitor_callback(pkt):
                if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has / is-at
                    ip_src = pkt[ARP].psrc     # Claimed IP (e.g., router)
                    mac_src = pkt[ARP].hwsrc   # Claimed MAC
                    ip_dst = pkt[ARP].pdst     # Victim being told this claim

                    if ip_src and mac_src:
                        ip_mac_mappings[ip_src].add(mac_src)

                    if ip_dst:
                        victim_targets[ip_src].add(ip_dst)

            sniff(filter="arp", prn=arp_monitor_callback, timeout=duration)

            # 🔎 Step 3: Analyze results
            results = []
            for ip, macs in ip_mac_mappings.items():
                if len(macs) > 1:
                    legit_mac = known_legit_macs.get(ip)
                    spoofed_macs = [mac for mac in macs if mac != legit_mac] if legit_mac else list(macs)
                    victims = list(victim_targets.get(ip, []))

                    results.append({
                        'ip': ip,
                        'legit_mac': legit_mac,
                        'spoofed_macs': spoofed_macs,
                        'mac_addresses': list(macs),
                        'victims': victims,
                        'timestamp': datetime.now().isoformat(),
                        'threat_type': 'arp_spoofing',
                        'severity': 'high',
                        'details': f"{ip} has multiple MACs. Victims: {', '.join(victims)}"
                    })

            self.logger.info(f"ARP spoofing detection completed. Found {len(results)} potential incidents.")
            return results

        except Exception as e:
            self.logger.error(f"ARP spoofing detection failed: {str(e)}")
            return []
    
    def detect_dns_spoofing(self, duration: int = 60) -> List[Dict[str, Any]]:
        """
        Detect DNS spoofing by monitoring DNS replies and comparing IP mappings.

        Args:
            duration (int): How long to sniff for DNS traffic in seconds.

        Returns:
            List[Dict[str, Any]]: List of spoofing incidents
        """
        self.logger.info(f"Starting DNS spoofing detection (duration: {duration}s)")

        try:
            # ✅ Store domain → set of (ip, source_ip)
            domain_ip_sources = defaultdict(set)

            # ✅ (Optional) define known trusted DNS servers
            trusted_dns_servers = {"8.8.8.8", "1.1.1.1", "9.9.9.9"}

            # Callback to process DNS responses
            def dns_monitor_callback(pkt):
                if DNS in pkt and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:  # Response
                    for i in range(pkt[DNS].ancount):
                        rr = pkt[DNSRR][i]
                        domain = rr.rrname.decode('utf-8').rstrip('.')
                        ip = rr.rdata
                        src_ip = pkt[IP].src  # Who sent the DNS reply

                        if domain and ip:
                            domain_ip_sources[domain].add((str(ip), src_ip))

                            # Debug output
                            print(f"📡 DNS reply: {domain} → {ip} (from {src_ip})")
                            if src_ip not in trusted_dns_servers:
                                print(f"⚠️  Untrusted DNS source detected: {src_ip}")

            # 🔍 Pick a sniffing interface manually if needed
            # You can use get_if_list() to find yours
            interface = "Wi-Fi"  # Or "Ethernet", "Local Area Connection", etc.

            sniff(filter="udp port 53", prn=dns_monitor_callback, iface=interface, timeout=duration)

            # Analyze collected DNS data
            results = []
            for domain, ip_info_set in domain_ip_sources.items():
                ips = set(ip for ip, _ in ip_info_set)
                sources = set(src for _, src in ip_info_set)

                if len(ips) > 1:
                    results.append({
                        'domain': domain,
                        'ip_addresses': list(ips),
                        'source_ips': list(sources),
                        'timestamp': datetime.now().isoformat(),
                        'threat_type': 'dns_spoofing',
                        'severity': 'high',
                        'details': f"Domain {domain} resolved to multiple IPs from different sources: {', '.join(ips)}"
                    })

            self.logger.info(f"DNS spoofing detection completed. Found {len(results)} incidents.")
            return results

        except Exception as e:
            self.logger.error(f"DNS spoofing detection failed: {str(e)}")
            return []
    
    def analyze_open_ports(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze open ports for potential security risks
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            List of port-related security issues
        """
        from config import vendors
        
        results = []
        
        for device in devices:
            ip = device.get('ip_address')
            mac = device.get('mac_address')
            ports = device.get('ports', [])
            
            # Skip if no ports open
            if not ports:
                continue
            
            # Check for high-risk services
            for service, service_ports in vendors.VULNERABLE_SERVICES.items():
                for port_info in ports:
                    port_num = port_info.get('port')
                    
                    if port_num in service_ports:
                        results.append({
                            'ip': ip,
                            'mac': mac,
                            'port': port_num,
                            'service': service,
                            'timestamp': datetime.now().isoformat(),
                            'threat_type': 'vulnerable_service',
                            'severity': 'medium',
                            'details': f"Potentially vulnerable service {service} running on port {port_num}"
                        })
            
            # Check for unusual port combinations
            open_ports = [p.get('port') for p in ports]
            
            # Check for remote access services
            if 22 in open_ports and 3389 in open_ports:
                results.append({
                    'ip': ip,
                    'mac': mac,
                    'ports': [22, 3389],
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': 'multiple_remote_access',
                    'severity': 'medium',
                    'details': f"Multiple remote access services (SSH and RDP) on {ip}"
                })
        
        return results