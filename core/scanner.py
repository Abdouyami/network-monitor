# core/scanner.py
import nmap
import logging
from typing import List, Dict, Any, Optional
from config import settings
from utils.network import get_mac_via_arp

class NetworkScanner:
    """Network scanner using python-nmap"""
    
    def __init__(self):
        """Initialize the network scanner"""
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initializing NetworkScanner")
        
        try:
            self.nm = nmap.PortScanner()
            self.logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize nmap scanner: {str(e)}")
            raise
        
    def scan_network(self, network_range: str) -> List[str]:
        """
        Scan a network range for active hosts
        
        Args:
            network_range: Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            List of active host IPs
        """
        self.logger.info(f"Starting network scan on {network_range}")
        
        try:
            # Use nmap arguments from settings (supports custom scan types)
            self.nm.scan(hosts=network_range, arguments=settings.NMAP_ARGUMENTS)
            hosts = self.nm.all_hosts()
            self.logger.info(f"Scan completed. Found {len(hosts)} hosts.")
            return hosts
        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            return []
    
    def get_host_info(self, host: str) -> Dict[str, Any]:
        """
        Get detailed information about a host
        
        Args:
            host: IP address of the host
            
        Returns:
            Dictionary with host information
        """
        self.logger.debug(f"Getting info for host: {host}")
        
        try:
            if host not in self.nm.all_hosts():
                self.logger.warning(f"Host {host} not in scan results, scanning now...")
                self.nm.scan(hosts=host, arguments=settings.NMAP_ARGUMENTS)
            
            info = {
                'status': self.nm[host].state(),
                'hostname': self.nm[host].hostname() if 'hostname' in self.nm[host] else None,
                'mac_address': None,
                'os': None,
                'ports': []
            }
            
            # Try to get MAC address from nmap results
            if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                info['mac_address'] = self.nm[host]['addresses']['mac'].upper()
            
            # If MAC not found, try ARP
            if not info['mac_address']:
                self.logger.debug(f"MAC not found in nmap results for {host}, trying ARP")
                info['mac_address'] = get_mac_via_arp(host)
                
            # Extract OS information if available
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                # Get the OS match with highest accuracy
                best_os = max(self.nm[host]['osmatch'], key=lambda x: int(x['accuracy']))
                info['os'] = f"{best_os['name']} (Accuracy: {best_os['accuracy']}%)"
                
            # Extract open port information
            for proto in self.nm[host].all_protocols():
                for port, port_info in self.nm[host][proto].items():
                    if port_info['state'] == 'open':
                        info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'service': port_info.get('name', 'unknown'),
                            'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                            'cpe': port_info.get('cpe', '')
                        })
                        
            self.logger.debug(f"Host info retrieved for {host}: {len(info['ports'])} open ports")
            return info
        except Exception as e:
            self.logger.error(f"Failed to get host info for {host}: {str(e)}")
            return {
                'status': 'unknown',
                'hostname': None,
                'mac_address': None,
                'os': None,
                'ports': []
            }

    def perform_vulnerability_scan(self, host: str) -> Dict[str, Any]:
        """
        Perform a vulnerability scan on a specific host
        
        Args:
            host: IP address of the host
            
        Returns:
            Dictionary with vulnerability information
        """
        if not settings.ENABLE_VULNERABILITY_SCAN:
            return {'error': 'Vulnerability scanning disabled in settings'}
            
        self.logger.info(f"Starting vulnerability scan on {host}")
        
        try:
            # Run nmap with vulnerability scripts
            vuln_arguments = f"-sV --script={settings.VULN_SCAN_NSE_SCRIPTS}"
            self.nm.scan(hosts=host, arguments=vuln_arguments)
            
            results = {
                'timestamp': '',
                'vulnerabilities': [],
                'potential_issues': []
            }
            
            # Extract vulnerability information from script results
            if 'hostscript' in self.nm[host]:
                for script in self.nm[host]['hostscript']:
                    results['vulnerabilities'].append({
                        'id': script['id'],
                        'output': script['output']
                    })
            
            # Check for service-specific vulnerabilities
            for proto in self.nm[host].all_protocols():
                for port, port_info in self.nm[host][proto].items():
                    if 'script' in port_info:
                        for script_id, output in port_info['script'].items():
                            if 'vuln' in script_id:
                                results['vulnerabilities'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'service': port_info.get('name', 'unknown'),
                                    'id': script_id,
                                    'output': output
                                })
            
            # Count vulnerabilities
            results['total_vulnerabilities'] = len(results['vulnerabilities'])
            self.logger.info(f"Vulnerability scan completed for {host}: {results['total_vulnerabilities']} issues found")
            return results
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed for {host}: {str(e)}")
            return {'error': str(e)}