import json  
import netfilterqueue  
from datetime import datetime  
from scapy.all import *  
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from collections import Counter  
from math import log2  
import socket  


# Add iptables rules  
os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')  
os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')  

# Get the IP address of your machine  
def get_my_ip():  
    return [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]  
  
MY_IP = get_my_ip()  


recent_src_ips = [] 

# Define maximum size for the queue  
MAX_QUEUE_SIZE = 5000  # Adjust as needed  
  
# Global variables  
src_ips_queue = deque(maxlen=1000)  # Adjust queue size as needed  
icmp_counter = 0  
syn_counter = 0  
ICMP_THRESHOLD = 1000  # Adjust as needed  
SYN_THRESHOLD = 1000  # Adjust as needed  
ENTROPY_THRESHOLD = 100.0  # Adjust as needed  
src_ips_ports = defaultdict(set)  
PORT_SCAN_THRESHOLD = 100  # Adjust as needed 
  
def calculate_entropy(scapy_packet):  
    global src_ips_queue  
    global icmp_counter  
    global syn_counter  
  
    # Check if the packet is incoming  
    if scapy_packet.haslayer('IP') and scapy_packet['IP'].dst == MY_IP:  
  
        # Add source IP to queue  
        src_ips_queue.append(scapy_packet['IP'].src)  
  
        # Check if the packet is ICMP  
        if scapy_packet.haslayer(ICMP):  
            icmp_counter += 1  
            if icmp_counter > ICMP_THRESHOLD:  
                print("Potential Ping Flood attack detected! Blocking packet.")  
                icmp_counter = 0  # Reset counter  
                return True  
  
        # Check if the packet is TCP and has the SYN flag set  
        if scapy_packet.haslayer(TCP) and 'S' in str(scapy_packet.sprintf('%TCP.flags%')):  
            syn_counter += 1  
            if syn_counter > SYN_THRESHOLD:  
                print("Potential SYN Flood attack detected! Blocking packet.")  
                syn_counter = 0  # Reset counter  
                return True  
        
        # Check if the packet is TCP  
        if scapy_packet.haslayer(TCP):  
            src_ip = scapy_packet['IP'].src  
            dst_port = scapy_packet[TCP].dport  
  
            # Add the destination port to the set of ports accessed by the source IP  
            src_ips_ports[src_ip].add(dst_port)  
  
            # Check if the number of ports accessed by the source IP exceeds the threshold  
            if len(src_ips_ports[src_ip]) > PORT_SCAN_THRESHOLD:  
                print("Potential Port Scan detected! Blocking packet.")  
                src_ips_ports[src_ip].clear()  # Reset ports for the IP  
                return True  
  
        # Calculate frequency of each IP  
        ip_freq = Counter(src_ips_queue)  
  
        # Calculate probabilities  
        probs = [f / len(src_ips_queue) for f in ip_freq.values()]  
  
        # Calculate and return entropy  
        entropy = -sum(p * log2(p) for p in probs)  
        if entropy < ENTROPY_THRESHOLD:  
            # print(f"Potential DDoS attack detected from IP: {scapy_packet['IP'].src}! Blocking packet.")  
            return True  
  
    return False  

    
# Function to load blocked IPs from blocked_ips.json  
def load_blocked_ips():  
    try:  
        with open('config/blocked_ips.json', 'r') as f:  
            data = json.load(f)  
            return set(data.get('blocked_ips', []))  
    except FileNotFoundError:  
        return set()  
  
# Function to load blocked URLs from blocked_domains.json  
def load_blocked_urls():  
    try:  
        with open('config/blocked_domains.json', 'r') as f:  
            data = json.load(f)  
            return set(data.get('blocked_domains', []))  
    except FileNotFoundError:  
        return set()  
  
# Function to load blocked ports from blocked_ports.json  
def load_blocked_ports():    
    try:    
        with open('config/blocked_ports.json', 'r') as f:    
            data = json.load(f)    
            blocked_ports = set()    
            for entry in data:    
                port_number = int(entry)  # Convert port_number to integer directly  
                blocked_ports.add(port_number)    
            return blocked_ports    
    except FileNotFoundError:    
        return set()    

  
# Function to load blocked services from blocked_services.json  
def load_blocked_services():  
    try:  
        with open('config/blocked_services.json', 'r') as f:  
            data = json.load(f)  
            return set(data.get('blocked_services', []))  
    except FileNotFoundError:  
        return set()  
  
# Define blocked IPs, URLs, ports, and services  
blocked_ips = load_blocked_ips()  
blocked_urls = load_blocked_urls()  
blocked_ports = load_blocked_ports()  
blocked_services = load_blocked_services()  
  
# Function to check if a packet matches any blocked criteria  
def is_blocked(scapy_packet):      
    if IP in scapy_packet:      
        src_ip = scapy_packet[IP].src      
        dst_ip = scapy_packet[IP].dst      
        if src_ip in blocked_ips or dst_ip in blocked_ips:  
            # print("test IP")    
            print(f"Blocking IP: {src_ip if src_ip in blocked_ips else dst_ip}")  
            return True, f"Blocked IP: {src_ip if src_ip in blocked_ips else dst_ip}", "IP"      
    if DNS in scapy_packet and scapy_packet[DNS].qr == 0:  # Only check queries, not responses      
        domain = scapy_packet[DNSQR].qname.decode("utf-8")      
        if any(blocked_domain in domain for blocked_domain in blocked_urls):      
            # print("test Domain")    
            print(f"Blocking URL: {domain}")  
            return True, f"Blocked URL: {domain}", "DNS"     
    if TCP in scapy_packet:      
        src_port = scapy_packet[TCP].sport      
        dst_port = scapy_packet[TCP].dport      
        if src_port in blocked_ports or dst_port in blocked_ports:      
            # print("test Port")    
            print(f"Blocking Port: {src_port if src_port in blocked_ports else dst_port}")  
            return True, f"Blocked Port: {src_port if src_port in blocked_ports else dst_port}", "TCP"      
    if UDP in scapy_packet:      
        # Handle UDP payloads as binary data      
        payload = bytes(scapy_packet[UDP].payload)      
        # Convert blocked services to bytes-like objects      
        blocked_services_bytes = [service.encode() for service in blocked_services]      
        if any(service_bytes.lower() in payload.lower() for service_bytes in blocked_services_bytes):  
            # print("test Service")        
            print("Blocking Service in Payload")  
            return True, f"Blocked Service in Payload", "UDP"      
    return False, "", ""    


# IP address of your "blocked" page  
BLOCKED_PAGE_IP = "20.197.9.50"  # Replace with the actual IP address 

# Modified function to handle packets  
def handle_packet(packet):  
    global icmp_counter  
    global syn_counter  
  
    scapy_packet = IP(packet.get_payload())  
  
    # Add source IP to recent IPs list  
    if IP in scapy_packet:  
        src_ip = scapy_packet[IP].src  
        recent_src_ips.append(src_ip)  
  
        # If the list gets too large, remove the oldest IP  
        if len(recent_src_ips) > 10000:  # Adjust this number as needed  
            recent_src_ips.pop(0)  
  
    # Check for ICMP or SYN flood  
    if ICMP in scapy_packet:  
        icmp_counter += 1  
        if icmp_counter > ICMP_THRESHOLD:  
            print("Potential Ping Flood attack detected! Blocking packet.")  
            packet.drop()  
            return  
  
    if TCP in scapy_packet and 'S' in str(scapy_packet.sprintf('%TCP.flags%')):  
        syn_counter += 1  
        if syn_counter > SYN_THRESHOLD:  
            print("Potential SYN Flood attack detected! Blocking packet.")  
            packet.drop()  
            return  
  
    # Check entropy  
    entropy = calculate_entropy(scapy_packet)    
    if entropy:    
        # print("Potential DDoS attack detected! Blocking packet.")    
        packet.drop()    
        return  
 
  
    # Check if this is a DNS query  
    if DNS in scapy_packet and scapy_packet[DNS].qr == 0:  # Only check queries, not responses  
        domain = scapy_packet[DNSQR].qname.decode("utf-8")  
  
        # Check if the domain is blocked  
        if any(blocked_domain in domain for blocked_domain in blocked_urls):  
            print(f"Blocked URL: {domain}")  
  
            # Create a DNS answer packet  
            dns_answer = DNSRR(rrname=domain, rdata=BLOCKED_PAGE_IP)  
  
            # Modify the original packet to be our answer packet  
            scapy_packet[DNS].an = dns_answer  
            scapy_packet[DNS].ancount = 1  
  
            # Delete checksums and lengths so they get recalculated  
            del scapy_packet[IP].len  
            del scapy_packet[IP].chksum  
            del scapy_packet[UDP].len  
            del scapy_packet[UDP].chksum  
  
            # Set the packet payload to our modified packet  
            packet.set_payload(bytes(scapy_packet))  
            packet.accept()  
            return  
  
    # Check other blocking criteria  
    blocked, log_message, protocol = is_blocked(scapy_packet)  
    if blocked:  
        # Write log to file  
        with open('config/blocking_logs.json', 'a') as log_file:  
            log_entry = {  
                "timestamp": str(datetime.now()),  
                "message": log_message,  
                "protocol": protocol,  
                "src": scapy_packet[IP].src if IP in scapy_packet else None,  
                "dst": scapy_packet[IP].dst if IP in scapy_packet else None  
            }  
            json.dump(log_entry, log_file)  
            print("Blocked packet:", scapy_packet.summary())  
            log_file.write('\n')  
            # Drop the packet  
            packet.drop()  
    else:  
        # Allow the packet to pass through  
        packet.accept()  
        
          
queue = netfilterqueue.NetfilterQueue()  
queue.bind(0, handle_packet)  # Bind to queue number 0  
try:  
    print("[*] Waiting for packets...")  
    queue.run()  
except KeyboardInterrupt:  
    print("[*] Stopping...")  

# Flush iptables rules  
os.system('iptables --flush')  
