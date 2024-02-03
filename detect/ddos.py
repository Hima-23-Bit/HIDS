from scapy.all import *  
from collections import defaultdict  
import time  
  
def detect_ddos(packet):  
    if packet.haslayer(TCP) and packet.getlayer(TCP).flags == 'S':  
        src_ip = packet.getlayer(IP).src  
        packet_counts[src_ip] += 1  
  
        # If the count of packets from this source IP exceeds the threshold (100 in 10 seconds), print a message  
        if packet_counts[src_ip] > 100:  
            print("Possible DDoS Attack from IP: ", src_ip)  
            packet_counts[src_ip] = 0  
  
        # Reset the count for this source IP after 10 seconds  
        if time.time() - timestamps[src_ip] > 10:  
            packet_counts[src_ip] = 0  
  
packet_counts = defaultdict(int)  
timestamps = defaultdict(time.time)  
  
# Use the sniff function from scapy to capture network packets  
sniff(prn=detect_ddos)  
